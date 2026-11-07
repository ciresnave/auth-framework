// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport-neutral HTTP handling for the GNAP RS-facing API (RFC 9767 section 3).
//!
//! [`GnapRsHttp::handle`] takes a request already read off the wire (method, URI, headers, body
//! bytes) and returns the response to send. The axum and actix adapters are thin wrappers around it,
//! so the routing, status codes and headers are decided once, here.
//!
//! Every error from the RS-facing API is HTTP 400 with a JSON `error` member (RFC 9767 section 3.5),
//! and introspection responses carry `Cache-Control: no-store` (section 3.3).

use crate::protocols::gnap_rs::{DISCOVERY_PATH, GnapResourceServerApi, RsCall, RsError};
use serde_json::{Value, json};
use std::sync::Arc;

/// The largest request body this handler reads; a larger one is refused as malformed.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

static NULL: Value = Value::Null;

/// A request as read off the wire.
#[derive(Debug, Clone)]
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

/// A response to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnapHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// The response body (JSON, or empty).
    pub body: Vec<u8>,
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

/// Routes the RS-facing API: the discovery document and introspection.
pub struct GnapRsHttp {
    api: Arc<GnapResourceServerApi>,
    introspection_path: String,
}

impl GnapRsHttp {
    /// Wrap an API; the introspection route is the path of its configured introspection endpoint.
    pub fn new(api: Arc<GnapResourceServerApi>) -> Self {
        let introspection_path = path_of(api.introspection_endpoint()).to_string();
        Self {
            api,
            introspection_path,
        }
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
        GnapHttpResponse::empty(404, Vec::new())
    }

    async fn introspect(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        if req.body.len() > MAX_BODY_BYTES {
            return GnapHttpResponse::error("invalid_request", "request body too large");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            return GnapHttpResponse::error("invalid_request", "request body is not JSON");
        };
        let call = RsCall {
            http_method: &req.method,
            http_uri: &req.uri,
            resource_server: body.get("resource_server").unwrap_or(&NULL),
            headers: &req.headers,
        };
        match self.api.introspect(&call, &body).await {
            Ok(answer) => GnapHttpResponse::json(200, &answer, true),
            Err(RsError::Unauthenticated) => GnapHttpResponse::error(
                "invalid_resource_server",
                "resource server not recognized or its proof did not verify",
            ),
            Err(RsError::BadRequest(why)) => GnapHttpResponse::error("invalid_request", &why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::gnap_rs::{
        AuthenticatedRs, GnapRsConfig, ResourceServerAuthenticator, RsTokenInfo, TokenInfoSource,
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

    /// Knows one RS, called by the `X-Test-Rs` header.
    struct HeaderRs;

    #[async_trait]
    impl ResourceServerAuthenticator for HeaderRs {
        async fn authenticate(&self, call: &RsCall<'_>) -> Option<AuthenticatedRs> {
            call.headers
                .iter()
                .any(|(k, v)| k == "X-Test-Rs" && v == "rs-1")
                .then(|| AuthenticatedRs { id: "rs-1".into() })
        }
    }

    fn handler() -> GnapRsHttp {
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

    fn post(uri: &str, rs: bool, body: &str) -> GnapHttpRequest {
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
