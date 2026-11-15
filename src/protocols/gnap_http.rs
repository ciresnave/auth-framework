// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport-neutral HTTP handling for the GNAP RS-facing API (RFC 9767 section 3).
//!
//! [`GnapRsHttp::handle`] takes a request already read off the wire (method, URI, headers, body
//! bytes) and returns the response to send. The axum and actix adapters are thin wrappers around it,
//! so the routing, status codes and headers are decided once, here.
//!
//! Every error from the RS-facing API is HTTP 400 with a JSON `error` member (RFC 9767 section 3.5),
//! and introspection and registration responses carry `Cache-Control: no-store` (sections 3.3 and
//! 3.4).

use crate::protocols::gnap_rs::{DISCOVERY_PATH, GnapResourceServerApi, RsCall, RsError};
use serde_json::{Value, json};
use std::sync::Arc;

/// The largest request body this handler reads; a larger one is refused as malformed.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

static NULL: Value = Value::Null;

/// A request as read off the wire.
#[derive(Clone)]
pub struct GnapHttpRequest {
    /// HTTP method, for example `POST`.
    pub method: String,
    /// The request target: an absolute URI or just a path, with or without a query.
    pub uri: String,
    /// Request headers, in the order received.
    pub headers: Vec<(String, String)>,
    /// The request body.
    pub body: Vec<u8>,
}

/// `Debug` prints the body's length, never its bytes: an introspection request body carries the access token it asks
/// about, and a response body describes a token (tests/debug_field_review.txt asks for a redacting `Debug`).
impl std::fmt::Debug for GnapHttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnapHttpRequest")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A response to send.
#[derive(Clone, PartialEq, Eq)]
pub struct GnapHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// The response body (JSON, or empty).
    pub body: Vec<u8>,
}

/// `Debug` prints the body's length, never its bytes; see [`GnapHttpRequest`].
impl std::fmt::Debug for GnapHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GnapHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl GnapHttpResponse {
    fn json(status: u16, body: &Value, no_store: bool) -> Self {
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        if no_store {
            headers.push(("Cache-Control".to_string(), "no-store".to_string()));
        }
        Self {
            status,
            headers,
            body: body.to_string().into_bytes(),
        }
    }

    /// A 400 `invalid_request` answer, for an adapter that refuses a request before it reaches
    /// [`GnapRsHttp::handle`] (for example a body over [`MAX_BODY_BYTES`]).
    pub fn invalid_request(description: &str) -> Self {
        Self::error("invalid_request", description)
    }

    fn error(code: &str, description: &str) -> Self {
        let body = json!({"error": {"code": code, "description": description}});
        Self::json(400, &body, true)
    }

    fn empty(status: u16, headers: Vec<(String, String)>) -> Self {
        Self {
            status,
            headers,
            body: Vec::new(),
        }
    }

    /// The value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The path part of a URL or request target: no scheme, authority, query or fragment.
fn path_of(target: &str) -> &str {
    let rest = match target.find("://") {
        Some(i) => {
            let after = &target[i + 3..];
            after.find('/').map_or("/", |j| &after[j..])
        }
        None => target,
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[..end];
    if path.is_empty() { "/" } else { path }
}

/// Routes the RS-facing API: the discovery document, introspection and, when the API offers it,
/// resource set registration.
pub struct GnapRsHttp {
    api: Arc<GnapResourceServerApi>,
    introspection_path: String,
    registration_path: Option<String>,
}

impl GnapRsHttp {
    /// Wrap an API; the introspection route is the path of its configured introspection endpoint,
    /// and the registration route (when the API offers registration) the path of its registration
    /// endpoint.
    pub fn new(api: Arc<GnapResourceServerApi>) -> Self {
        let introspection_path = path_of(api.introspection_endpoint()).to_string();
        let registration_path = api.registration_endpoint().map(|u| path_of(u).to_string());
        Self {
            api,
            introspection_path,
            registration_path,
        }
    }

    /// The path of the registration route, or `None` when the API does not offer registration. An
    /// adapter registers it in addition to [`paths`](Self::paths).
    pub fn registration_path(&self) -> Option<&str> {
        self.registration_path.as_deref()
    }

    /// The discovery path and the introspection path this handler answers on, so an adapter can
    /// register them.
    pub fn paths(&self) -> (&'static str, &str) {
        (DISCOVERY_PATH, &self.introspection_path)
    }

    /// Answer one request.
    pub async fn handle(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let path = path_of(&req.uri);
        let method = req.method.to_ascii_uppercase();
        if path == DISCOVERY_PATH {
            return match method.as_str() {
                "GET" => GnapHttpResponse::json(200, &self.api.discovery_document(), false),
                _ => GnapHttpResponse::empty(405, vec![("Allow".into(), "GET".into())]),
            };
        }
        if path == self.introspection_path {
            return match method.as_str() {
                "POST" => self.introspect(req).await,
                _ => GnapHttpResponse::empty(405, vec![("Allow".into(), "POST".into())]),
            };
        }
        if self.registration_path.as_deref() == Some(path) {
            return match method.as_str() {
                "POST" => self.register(req).await,
                _ => GnapHttpResponse::empty(405, vec![("Allow".into(), "POST".into())]),
            };
        }
        GnapHttpResponse::empty(404, Vec::new())
    }

    async fn introspect(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let endpoint = self.api.introspection_endpoint();
        let result = match RsRequest::read(req, endpoint) {
            Ok(r) => self.api.introspect(&r.call(), &r.body).await,
            Err(refused) => return refused,
        };
        answer(result)
    }

    async fn register(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        // The route exists only when the API offers registration.
        let Some(endpoint) = self.api.registration_endpoint() else {
            return GnapHttpResponse::empty(404, Vec::new());
        };
        let result = match RsRequest::read(req, endpoint) {
            Ok(r) => self.api.register(&r.call(), &r.body).await,
            Err(refused) => return refused,
        };
        answer(result)
    }
}

/// A request body and headers, read once for an RS call.
struct RsRequest<'a> {
    method: &'a str,
    uri: &'a str,
    body: Value,
    headers: Vec<(String, String)>,
}

impl<'a> RsRequest<'a> {
    /// Read the body (size-capped JSON) and lower-case the header names, which the authenticator
    /// is given that way. `endpoint` is the AS's own URL for the call: a request target does not
    /// carry the scheme and host a proof is bound to.
    fn read(req: &'a GnapHttpRequest, endpoint: &'a str) -> Result<Self, GnapHttpResponse> {
        if req.body.len() > MAX_BODY_BYTES {
            return Err(GnapHttpResponse::error(
                "invalid_request",
                "request body too large",
            ));
        }
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            return Err(GnapHttpResponse::error(
                "invalid_request",
                "request body is not JSON",
            ));
        };
        Ok(Self {
            method: &req.method,
            uri: endpoint,
            body,
            headers: req
                .headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
                .collect(),
        })
    }

    fn call(&self) -> RsCall<'_> {
        RsCall {
            http_method: self.method,
            http_uri: self.uri,
            resource_server: self.body.get("resource_server").unwrap_or(&NULL),
            headers: &self.headers,
        }
    }
}

/// The response for an RS-facing API result: 200 and `no-store`, or 400 with the error code.
fn answer(result: Result<Value, RsError>) -> GnapHttpResponse {
    match result {
        Ok(answer) => GnapHttpResponse::json(200, &answer, true),
        Err(RsError::Unauthenticated) => GnapHttpResponse::error(
            "invalid_resource_server",
            "resource server not recognized or its proof did not verify",
        ),
        Err(RsError::BadRequest(why)) => GnapHttpResponse::error("invalid_request", &why),
        Err(RsError::InvalidAccess(why)) => GnapHttpResponse::error("invalid_access", &why),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocols::gnap_rs::{
        AuthenticatedRs, GnapRsConfig, RegisteredResources, ResourceRegistration, ResourceRegistry,
        ResourceServerAuthenticator, RsTokenInfo, TokenInfoSource,
    };
    use async_trait::async_trait;

    struct OneToken;

    #[async_trait]
    impl TokenInfoSource for OneToken {
        async fn token_info(&self, value: &str) -> Option<RsTokenInfo> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (value == "tok-1").then(|| RsTokenInfo {
                access: vec![json!("dolphin-metadata")],
                key: None,
                proof: None,
                expires_at: now + 600,
                issued_at: now,
                grant_endpoint: "https://as.example.test/tx".into(),
                instance_id: None,
                flags: vec![],
                audience: vec![],
            })
        }
    }

    /// Knows one RS, called by the `X-Test-Rs` header (seen in lower case).
    struct HeaderRs;

    #[async_trait]
    impl ResourceServerAuthenticator for HeaderRs {
        async fn authenticate(&self, call: &RsCall<'_>) -> Option<AuthenticatedRs> {
            let known = call
                .headers
                .iter()
                .any(|(k, v)| k == "x-test-rs" && v == "rs-1");
            // A proof is bound to the AS's own URL, not to whatever target the request carried.
            let uri_ok = call.http_uri == "https://as.example.test/gnap/introspect";
            (known && uri_ok).then(|| AuthenticatedRs { id: "rs-1".into() })
        }
    }

    /// Knows one RS, called by the `X-Test-Rs` header, and names it by the URL the call was made to.
    struct UriRs;

    #[async_trait]
    impl ResourceServerAuthenticator for UriRs {
        async fn authenticate(&self, call: &RsCall<'_>) -> Option<AuthenticatedRs> {
            let known = call
                .headers
                .iter()
                .any(|(k, v)| k == "x-test-rs" && v == "rs-1");
            known.then(|| AuthenticatedRs {
                id: call.http_uri.to_string(),
            })
        }
    }

    /// Refuses the access value `"forbidden"`; answers with the caller's identity as instance id.
    struct Registry;

    #[async_trait]
    impl ResourceRegistry for Registry {
        async fn register(
            &self,
            rs: &AuthenticatedRs,
            request: &ResourceRegistration,
        ) -> Result<RegisteredResources, RsError> {
            if request.access.contains(&json!("forbidden")) {
                return Err(RsError::InvalidAccess("not permitted".into()));
            }
            Ok(RegisteredResources {
                resource_reference: "ref-1".into(),
                instance_id: Some(rs.id.clone()),
            })
        }
    }

    pub(crate) const REGISTRATION_URL: &str = "https://as.example.test/gnap/resource";

    /// A handler whose API offers registration at [`REGISTRATION_URL`]; its authenticator names the
    /// RS by the URL it was called with.
    pub(crate) fn handler_with_registry() -> GnapRsHttp {
        let config = GnapRsConfig {
            grant_request_endpoint: "https://as.example.test/tx".into(),
            introspection_endpoint: "https://as.example.test/gnap/introspect".into(),
            key_proofs_supported: vec![],
            token_formats_supported: vec![],
        };
        let api = GnapResourceServerApi::new(config, Arc::new(OneToken), Arc::new(UriRs))
            .unwrap()
            .with_registry(REGISTRATION_URL, Arc::new(Registry))
            .unwrap();
        GnapRsHttp::new(Arc::new(api))
    }

    pub(crate) fn handler() -> GnapRsHttp {
        let config = GnapRsConfig {
            grant_request_endpoint: "https://as.example.test/tx".into(),
            introspection_endpoint: "https://as.example.test/gnap/introspect".into(),
            key_proofs_supported: vec![],
            token_formats_supported: vec![],
        };
        let api =
            GnapResourceServerApi::new(config, Arc::new(OneToken), Arc::new(HeaderRs)).unwrap();
        GnapRsHttp::new(Arc::new(api))
    }

    pub(crate) fn post(uri: &str, rs: bool, body: &str) -> GnapHttpRequest {
        let headers = if rs {
            vec![("X-Test-Rs".to_string(), "rs-1".to_string())]
        } else {
            vec![]
        };
        GnapHttpRequest {
            method: "POST".into(),
            uri: uri.into(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    fn json_body(r: &GnapHttpResponse) -> Value {
        serde_json::from_slice(&r.body).expect("a JSON body")
    }

    const INTROSPECT: &str = "/gnap/introspect";
    const GOOD: &str = r#"{"access_token":"tok-1","resource_server":"rs-1"}"#;

    #[tokio::test]
    async fn discovery_is_served_on_get() {
        let h = handler();
        let req = GnapHttpRequest {
            method: "GET".into(),
            uri: DISCOVERY_PATH.into(),
            headers: vec![],
            body: vec![],
        };
        let r = h.handle(&req).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        let doc = json_body(&r);
        assert_eq!(doc["grant_request_endpoint"], "https://as.example.test/tx");
        assert_eq!(
            doc["introspection_endpoint"],
            "https://as.example.test/gnap/introspect"
        );
    }

    #[tokio::test]
    async fn an_active_token_is_answered_200_with_no_store() {
        let r = handler().handle(&post(INTROSPECT, true, GOOD)).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        assert_eq!(json_body(&r)["active"], true);
    }

    #[tokio::test]
    async fn an_unknown_token_is_200_inactive() {
        let body = r#"{"access_token":"nope","resource_server":"rs-1"}"#;
        let r = handler().handle(&post(INTROSPECT, true, body)).await;
        assert_eq!(r.status, 200);
        assert_eq!(json_body(&r), json!({"active": false}));
    }

    #[tokio::test]
    async fn an_unrecognized_rs_is_400_invalid_resource_server() {
        let r = handler().handle(&post(INTROSPECT, false, GOOD)).await;
        assert_eq!(r.status, 400);
        assert_eq!(json_body(&r)["error"]["code"], "invalid_resource_server");
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        assert!(!String::from_utf8_lossy(&r.body).contains("tok-1"));
    }

    #[tokio::test]
    async fn a_malformed_request_is_400_invalid_request() {
        let h = handler();
        for body in [
            "not json",
            r#"{"resource_server":"rs-1"}"#,
            r#"{"access_token":"tok-1"}"#,
            r#"{"access_token":5,"resource_server":"rs-1"}"#,
        ] {
            let r = h.handle(&post(INTROSPECT, true, body)).await;
            assert_eq!(r.status, 400, "{body}");
            assert_eq!(json_body(&r)["error"]["code"], "invalid_request", "{body}");
        }
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let big = format!(
            r#"{{"access_token":"tok-1","resource_server":"rs-1","pad":"{}"}}"#,
            "x".repeat(MAX_BODY_BYTES)
        );
        let r = handler().handle(&post(INTROSPECT, true, &big)).await;
        assert_eq!(r.status, 400);
        assert_eq!(json_body(&r)["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn the_wrong_method_is_405_with_allow() {
        let h = handler();
        let mut get = post(INTROSPECT, true, "");
        get.method = "GET".into();
        let r = h.handle(&get).await;
        assert_eq!((r.status, r.header("Allow")), (405, Some("POST")));
        let mut p = post(DISCOVERY_PATH, true, "");
        p.method = "POST".into();
        let r = h.handle(&p).await;
        assert_eq!((r.status, r.header("Allow")), (405, Some("GET")));
    }

    #[tokio::test]
    async fn an_unknown_path_is_404() {
        let r = handler().handle(&post("/gnap/other", true, GOOD)).await;
        assert_eq!(r.status, 404);
    }

    #[tokio::test]
    async fn the_authenticator_is_given_the_configured_endpoint_url() {
        // HeaderRs refuses any other URI, so a request that came in as a bare path still passes.
        let r = handler()
            .handle(&post("/gnap/introspect", true, GOOD))
            .await;
        assert_eq!(r.status, 200);
    }

    #[tokio::test]
    async fn routing_ignores_the_query_and_the_authority() {
        let h = handler();
        let r = h
            .handle(&post(
                "https://as.example.test/gnap/introspect?x=1",
                true,
                GOOD,
            ))
            .await;
        assert_eq!(r.status, 200);
    }

    const REGISTER: &str = "/gnap/resource";
    const REGISTRATION: &str = r#"{"access":["dolphin-metadata"],"resource_server":"rs-1"}"#;

    #[tokio::test]
    async fn registration_is_answered_200_with_no_store() {
        let r = handler_with_registry()
            .handle(&post(REGISTER, true, REGISTRATION))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        assert_eq!(r.header("Content-Type"), Some("application/json"));
        let body = json_body(&r);
        assert_eq!(body["resource_reference"], "ref-1");
        assert_eq!(
            body["introspection_endpoint"],
            "https://as.example.test/gnap/introspect"
        );
        // The authenticator names the RS by the URL it was called with: the registration
        // endpoint, not the introspection endpoint.
        assert_eq!(body["instance_id"], REGISTRATION_URL);
    }

    #[tokio::test]
    async fn introspection_is_still_authenticated_against_its_own_url() {
        let h = handler_with_registry();
        let r = h.handle(&post(INTROSPECT, true, GOOD)).await;
        assert_eq!(r.status, 200);
        assert_eq!(json_body(&r)["active"], true);
    }

    #[tokio::test]
    async fn registration_errors_are_400_with_their_codes() {
        let h = handler_with_registry();
        let cases = [
            (
                true,
                r#"{"access":["forbidden"],"resource_server":"rs-1"}"#,
                "invalid_access",
            ),
            (false, REGISTRATION, "invalid_resource_server"),
            (true, r#"{"resource_server":"rs-1"}"#, "invalid_request"),
            (true, "not json", "invalid_request"),
        ];
        for (rs, body, code) in cases {
            let r = h.handle(&post(REGISTER, rs, body)).await;
            assert_eq!(r.status, 400, "{body}");
            assert_eq!(json_body(&r)["error"]["code"], code, "{body}");
        }
    }

    #[tokio::test]
    async fn an_oversized_registration_body_is_refused() {
        let big = format!(
            r#"{{"access":["a"],"resource_server":"rs-1","pad":"{}"}}"#,
            "x".repeat(MAX_BODY_BYTES)
        );
        let r = handler_with_registry()
            .handle(&post(REGISTER, true, &big))
            .await;
        assert_eq!(r.status, 400);
        assert_eq!(json_body(&r)["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn registration_is_a_post() {
        let mut get = post(REGISTER, true, "");
        get.method = "GET".into();
        let r = handler_with_registry().handle(&get).await;
        assert_eq!((r.status, r.header("Allow")), (405, Some("POST")));
    }

    #[tokio::test]
    async fn without_a_registry_there_is_no_registration_route() {
        let h = handler();
        assert_eq!(h.registration_path(), None);
        let r = h.handle(&post(REGISTER, true, REGISTRATION)).await;
        assert_eq!(r.status, 404);
        assert_eq!(
            handler_with_registry().registration_path(),
            Some("/gnap/resource")
        );
    }

    #[test]
    fn path_of_cases() {
        assert_eq!(path_of("/a/b?c=d#e"), "/a/b");
        assert_eq!(path_of("https://h.test"), "/");
        assert_eq!(path_of("https://h.test:8443/a?b"), "/a");
        assert_eq!(path_of("/"), "/");
    }

    #[test]
    fn paths_reports_what_to_register() {
        assert_eq!(handler().paths(), (DISCOVERY_PATH, "/gnap/introspect"));
    }
}
