// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP `push` delivery (RFC 9635 sections 4.2.2 and 11.34), slice G4.
//!
//! [`validate_push_target`](super::gnap_interaction::validate_push_target) refuses a push URI that is wrong on
//! its face when a transaction opens. A host *name* can still resolve to an address the server must not
//! call, and can resolve differently a moment later (DNS rebinding), so the check that matters is made at
//! delivery: [`deliver_push`] resolves the host once, refuses if **any** answer is a blocked address, and then
//! connects to the one address it checked (the [`PushSender`] is handed that address and must not resolve the
//! name again). The default sender, [`ReqwestPushSender`], pins the connection to it, follows no redirects
//! (a 3xx to an internal address would defeat the check), uses no proxy (`HTTP_PROXY` and friends are
//! ignored: a proxy re-resolves the name and voids the pin, so the pin holds only on a path with no proxy)
//! and has a timeout.
//!
//! Resolution and sending are traits so an integrator can use its own resolver or HTTP stack, and so the
//! tests can prove the order of the steps without a network.

use super::gnap_interaction::{callback_push_body, push_address_allowed, validate_push_target};
use async_trait::async_trait;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::{Host, Url};

/// Why a push was not delivered. Carries no request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The URI is not one the server may call (see `validate_push_target`).
    TargetNotAllowed,
    /// The host name did not resolve.
    ResolutionFailed,
    /// The host name resolved to no address.
    NoAddress,
    /// At least one address the name resolved to is one the server must not call (loopback, private,
    /// link-local, metadata, shared or documentation range). Nothing was sent.
    AddressNotAllowed,
    /// The request could not be sent (connect error, timeout, TLS failure).
    SendFailed,
    /// The client answered with a status other than 2xx.
    Rejected(u16),
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(status) => write!(f, "push refused by the client: HTTP {status}"),
            other => write!(f, "push not delivered: {other:?}"),
        }
    }
}

impl std::error::Error for PushError {}

/// Resolves a host name to the addresses a connection could use.
#[async_trait]
pub trait PushResolver: Send + Sync {
    /// Every address `host` resolves to. `Err` and an empty list both refuse the push.
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver (`tokio::net::lookup_host`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPushResolver;

#[async_trait]
impl PushResolver for SystemPushResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .map(|a| a.ip())
            .collect())
    }
}

/// Sends the callback to the address [`deliver_push`] checked.
#[async_trait]
pub trait PushSender: Send + Sync {
    /// `POST` `body` as JSON to `uri`, connecting to `pinned` and to nothing else: the name in `uri` is
    /// only for the `Host` header and TLS. Follow no redirect. Return the HTTP status.
    async fn post(&self, uri: &Url, pinned: SocketAddr, body: &Value) -> Result<u16, PushError>;
}

/// The default sender: `reqwest`, pinned to the checked address, no redirects, a timeout.
#[derive(Debug, Clone)]
pub struct ReqwestPushSender {
    timeout: Duration,
}

impl ReqwestPushSender {
    /// Ten seconds is long enough for a client's callback and short enough not to hold a worker.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// A sender with the default timeout.
    pub fn new() -> Self {
        Self {
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// A sender with another timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for ReqwestPushSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PushSender for ReqwestPushSender {
    async fn post(&self, uri: &Url, pinned: SocketAddr, body: &Value) -> Result<u16, PushError> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // A proxy would receive the name and resolve it again, voiding the pin.
            .no_proxy()
            .timeout(self.timeout);
        if let Some(Host::Domain(name)) = uri.host() {
            // The name stays in the URL for `Host` and TLS; the connection goes to the checked address.
            builder = builder.resolve(name, pinned);
        }
        let client = builder.build().map_err(|_| PushError::SendFailed)?;
        let response = client
            .post(uri.clone())
            .json(body)
            .send()
            .await
            .map_err(|_| PushError::SendFailed)?;
        Ok(response.status().as_u16())
    }
}

/// Deliver the `push` callback (section 4.2.2) to `uri`: check the URI, resolve the host, refuse if any
/// answer is a blocked address, then send to the checked addresses in order until one can be reached. `Ok`
/// means the client answered 2xx.
pub async fn deliver_push(
    uri: &Url,
    hash: &str,
    interact_ref: &str,
    resolver: &dyn PushResolver,
    sender: &dyn PushSender,
) -> Result<(), PushError> {
    validate_push_target(uri).map_err(|_| PushError::TargetNotAllowed)?;
    let port = uri
        .port_or_known_default()
        .ok_or(PushError::TargetNotAllowed)?;
    let addresses: Vec<IpAddr> = match uri.host() {
        Some(Host::Ipv4(ip)) => vec![IpAddr::V4(ip)],
        Some(Host::Ipv6(ip)) => vec![IpAddr::V6(ip)],
        Some(Host::Domain(name)) => resolver
            .resolve(name, port)
            .await
            .map_err(|_| PushError::ResolutionFailed)?,
        None => return Err(PushError::TargetNotAllowed),
    };
    if addresses.is_empty() {
        return Err(PushError::NoAddress);
    }
    // One blocked answer among several is enough to refuse: a client that controls its DNS can list a
    // public address first and an internal one second, and a resolver or connector is free to pick either.
    if !addresses.iter().copied().all(push_address_allowed) {
        return Err(PushError::AddressNotAllowed);
    }
    let body = callback_push_body(hash, interact_ref);
    // Every address was checked above, so trying the next one after a failed send widens nothing. Only a
    // failure to send moves on; any HTTP answer (even a refusal) is the client's and ends the attempt.
    let mut last = PushError::SendFailed;
    for address in addresses {
        match sender
            .post(uri, SocketAddr::new(address, port), &body)
            .await
        {
            Ok(status) if (200..300).contains(&status) => return Ok(()),
            Ok(status) => return Err(PushError::Rejected(status)),
            Err(e @ PushError::SendFailed) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    pub(crate) struct FakeResolver(std::io::Result<Vec<IpAddr>>, Mutex<Vec<String>>);

    impl FakeResolver {
        pub(crate) fn answering(ips: &[&str]) -> Self {
            Self(
                Ok(ips.iter().map(|s| s.parse().unwrap()).collect()),
                Mutex::new(Vec::new()),
            )
        }
        pub(crate) fn asked(&self) -> Vec<String> {
            self.1.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PushResolver for FakeResolver {
        async fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
            self.1.lock().unwrap().push(host.to_string());
            match &self.0 {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(std::io::Error::new(e.kind(), "resolution failed")),
            }
        }
    }

    #[derive(Default)]
    pub(crate) struct FakeSender {
        pub(crate) calls: Mutex<Vec<(String, SocketAddr, Value)>>,
        pub(crate) status: Option<u16>,
    }

    #[async_trait]
    impl PushSender for FakeSender {
        async fn post(
            &self,
            uri: &Url,
            pinned: SocketAddr,
            body: &Value,
        ) -> Result<u16, PushError> {
            self.calls
                .lock()
                .unwrap()
                .push((uri.to_string(), pinned, body.clone()));
            Ok(self.status.unwrap_or(204))
        }
    }

    fn uri(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_public_address_is_sent_to_that_address() {
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender::default(),
        );
        deliver_push(&uri("https://client.example/cb"), "H", "REF", &r, &s)
            .await
            .unwrap();
        let calls = s.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1,
            "93.184.216.34:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            calls[0].2,
            serde_json::json!({"hash": "H", "interact_ref": "REF"})
        );
        assert_eq!(r.asked(), vec!["client.example".to_string()]);
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_blocked_address_is_refused_and_nothing_is_sent() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            let (r, s) = (FakeResolver::answering(&[ip]), FakeSender::default());
            let out = deliver_push(&uri("https://rebind.example/cb"), "H", "R", &r, &s).await;
            assert_eq!(out, Err(PushError::AddressNotAllowed), "{ip}");
            assert!(s.calls.lock().unwrap().is_empty(), "{ip}: nothing was sent");
        }
    }

    #[tokio::test]
    async fn one_blocked_answer_among_public_ones_refuses_the_push() {
        // DNS rebinding: a public address first, an internal one second (and the other way round).
        for answers in [["93.184.216.34", "10.0.0.5"], ["10.0.0.5", "93.184.216.34"]] {
            let (r, s) = (FakeResolver::answering(&answers), FakeSender::default());
            let out = deliver_push(&uri("https://rebind.example/cb"), "H", "R", &r, &s).await;
            assert_eq!(out, Err(PushError::AddressNotAllowed), "{answers:?}");
            assert!(s.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn the_name_is_resolved_once_and_the_sender_gets_the_checked_address() {
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34", "93.184.216.35"]),
            FakeSender::default(),
        );
        deliver_push(&uri("https://client.example:8443/cb"), "H", "R", &r, &s)
            .await
            .unwrap();
        assert_eq!(r.asked().len(), 1, "resolved exactly once");
        let calls = s.calls.lock().unwrap();
        assert_eq!(
            calls[0].1,
            "93.184.216.34:8443".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn a_target_that_fails_the_open_time_guard_never_reaches_the_resolver() {
        for u in [
            "http://client.example/cb",
            "https://localhost/cb",
            "https://127.0.0.1/cb",
            "https://user:pw@client.example/cb",
        ] {
            let (r, s) = (
                FakeResolver::answering(&["93.184.216.34"]),
                FakeSender::default(),
            );
            let out = deliver_push(&uri(u), "H", "R", &r, &s).await;
            assert_eq!(out, Err(PushError::TargetNotAllowed), "{u}");
            assert!(r.asked().is_empty(), "{u}: not resolved");
            assert!(s.calls.lock().unwrap().is_empty());
        }
    }

    /// Fails to send to `bad`, answers 204 elsewhere.
    struct FailsOn(SocketAddr, Mutex<Vec<SocketAddr>>);

    #[async_trait]
    impl PushSender for FailsOn {
        async fn post(&self, _: &Url, pinned: SocketAddr, _: &Value) -> Result<u16, PushError> {
            self.1.lock().unwrap().push(pinned);
            if pinned == self.0 {
                Err(PushError::SendFailed)
            } else {
                Ok(204)
            }
        }
    }

    #[tokio::test]
    async fn a_failed_send_moves_on_to_the_next_checked_address() {
        let r = FakeResolver::answering(&["93.184.216.34", "93.184.216.35"]);
        let s = FailsOn("93.184.216.34:443".parse().unwrap(), Mutex::new(Vec::new()));
        deliver_push(&uri("https://client.example/cb"), "H", "REF", &r, &s)
            .await
            .unwrap();
        assert_eq!(s.1.lock().unwrap().len(), 2);
        // every address failing is a send failure; a blocked sibling still refuses before any send
        let s = FailsOn("93.184.216.34:443".parse().unwrap(), Mutex::new(Vec::new()));
        let r = FakeResolver::answering(&["93.184.216.34"]);
        let e = deliver_push(&uri("https://client.example/cb"), "H", "REF", &r, &s)
            .await
            .unwrap_err();
        assert_eq!(e, PushError::SendFailed);
        let r = FakeResolver::answering(&["93.184.216.34", "10.0.0.1"]);
        let s = FailsOn("93.184.216.34:443".parse().unwrap(), Mutex::new(Vec::new()));
        assert_eq!(
            deliver_push(&uri("https://client.example/cb"), "H", "REF", &r, &s)
                .await
                .unwrap_err(),
            PushError::AddressNotAllowed
        );
        assert!(s.1.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_or_empty_resolution_and_a_rejecting_client_are_errors() {
        let s = FakeSender::default();
        let failing = FakeResolver(
            Err(std::io::Error::other("nxdomain")),
            Mutex::new(Vec::new()),
        );
        assert_eq!(
            deliver_push(&uri("https://a.example/cb"), "H", "R", &failing, &s).await,
            Err(PushError::ResolutionFailed)
        );
        let empty = FakeResolver::answering(&[]);
        assert_eq!(
            deliver_push(&uri("https://a.example/cb"), "H", "R", &empty, &s).await,
            Err(PushError::NoAddress)
        );
        let ok = FakeResolver::answering(&["93.184.216.34"]);
        let rejecting = FakeSender {
            status: Some(403),
            ..Default::default()
        };
        assert_eq!(
            deliver_push(&uri("https://a.example/cb"), "H", "R", &ok, &rejecting).await,
            Err(PushError::Rejected(403))
        );
        assert!(s.calls.lock().unwrap().is_empty());
    }

    /// A one-shot HTTP server on loopback: records the request head, answers with `reply`.
    async fn serve_once(reply: &'static str) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(reply.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn the_default_sender_connects_to_the_pinned_address_and_keeps_the_name_for_host() {
        // The name does not resolve anywhere; only the pin can make this connect.
        let (addr, server) =
            serve_once("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        let target = uri(&format!("http://pinned.invalid:{}/cb", addr.port()));
        let status = ReqwestPushSender::new()
            .post(
                &target,
                addr,
                &serde_json::json!({"hash": "H", "interact_ref": "R"}),
            )
            .await
            .unwrap();
        assert_eq!(status, 204);
        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("post /cb "), "{head}");
        assert!(
            head.contains(&format!("host: pinned.invalid:{}", addr.port())),
            "{head}"
        );
        assert!(
            head.contains("\"interact_ref\":\"r\"") || head.contains("interact_ref"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn the_default_sender_ignores_proxy_variables_and_still_uses_the_pin() {
        // A proxy would receive the name and resolve it again, voiding the pin. The decoy stands in for one.
        let (proxy, proxy_seen) =
            serve_once("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
        let (addr, server) =
            serve_once("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
        let target = uri(&format!("http://pinned.invalid:{}/cb", addr.port()));
        let proxy_url = format!("http://{proxy}");
        // SAFETY: only this test sets these two variables, and it removes them before it ends.
        unsafe {
            std::env::set_var("HTTP_PROXY", &proxy_url);
            std::env::set_var("http_proxy", &proxy_url);
        }
        let out = ReqwestPushSender::with_timeout(Duration::from_secs(3))
            .post(&target, addr, &serde_json::json!({}))
            .await;
        // SAFETY: same two variables, same single test as above.
        unsafe {
            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("http_proxy");
        }
        assert_eq!(
            out,
            Ok(204),
            "the request went to the pinned address, not the proxy"
        );
        assert!(server.await.is_ok());
        assert!(!proxy_seen.is_finished(), "the proxy was never contacted");
        proxy_seen.abort();
    }

    #[tokio::test]
    async fn the_default_sender_does_not_follow_a_redirect() {
        let (addr, server) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let target = uri(&format!("http://pinned.invalid:{}/cb", addr.port()));
        let status = ReqwestPushSender::new()
            .post(&target, addr, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(status, 302, "the 3xx is returned, not followed");
        let _ = server.await;
        // deliver_push reports a 3xx as a refusal, not a success
        let (r, redirecting) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender {
                status: Some(302),
                ..Default::default()
            },
        );
        assert_eq!(
            deliver_push(
                &uri("https://client.example/cb"),
                "H",
                "R",
                &r,
                &redirecting
            )
            .await,
            Err(PushError::Rejected(302))
        );
    }

    #[tokio::test]
    async fn the_default_sender_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let target = uri(&format!("http://pinned.invalid:{}/cb", addr.port()));
        let started = std::time::Instant::now();
        let out = ReqwestPushSender::with_timeout(Duration::from_millis(200))
            .post(&target, addr, &serde_json::json!({}))
            .await;
        assert_eq!(out, Err(PushError::SendFailed));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
