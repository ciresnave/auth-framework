// SPDX-License-Identifier: MIT OR Apache-2.0
//! axum routes for the GNAP RS-facing API (RFC 9767 section 3): the discovery document and token
//! introspection. All routing, status codes and headers come from [`GnapRsHttp`]; this module only
//! moves a request in and a response out.
//!
//! ```rust,ignore
//! let http = Arc::new(GnapRsHttp::new(Arc::new(api)));
//! let app = axum::Router::new().merge(gnap_router(http));
//! ```

use crate::protocols::gnap_http::{GnapHttpRequest, GnapHttpResponse, GnapRsHttp, MAX_BODY_BYTES};
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
    routing::any,
};
use std::sync::Arc;

/// A router with the discovery and introspection routes registered at the paths `http` reports.
pub fn gnap_router(http: Arc<GnapRsHttp>) -> Router {
    let (discovery, introspection) = {
        let (d, i) = http.paths();
        (d.to_string(), i.to_string())
    };
    let for_discovery = http.clone();
    let for_introspection = http;
    Router::new()
        .route(
            &discovery,
            any(move |req: Request| serve(for_discovery.clone(), req)),
        )
        .route(
            &introspection,
            any(move |req: Request| serve(for_introspection.clone(), req)),
        )
}

async fn serve(http: Arc<GnapRsHttp>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => return to_response(GnapHttpResponse::invalid_request("request body too large")),
    };
    let headers = parts
        .headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let request = GnapHttpRequest {
        method: parts.method.to_string(),
        uri: parts.uri.to_string(),
        headers,
        body: bytes.to_vec(),
    };
    to_response(http.handle(&request).await)
}

fn to_response(r: GnapHttpResponse) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (k, v) in &r.headers {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v))
        {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(Body::from(r.body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::gnap_http::tests::handler;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    async fn call(
        method: &str,
        uri: &str,
        rs: bool,
        body: &str,
    ) -> (StatusCode, Option<String>, serde_json::Value) {
        let mut b = HttpRequest::builder().method(method).uri(uri);
        if rs {
            b = b.header("X-Test-Rs", "rs-1");
        }
        let app = gnap_router(Arc::new(handler()));
        let resp = app
            .oneshot(b.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let cache = resp
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, cache, json)
    }

    const GOOD: &str = r#"{"access_token":"tok-1","resource_server":"rs-1"}"#;

    #[tokio::test]
    async fn discovery_is_served() {
        let (status, _, doc) = call("GET", "/.well-known/gnap-as-rs", false, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(doc["grant_request_endpoint"], "https://as.example.test/tx");
    }

    #[tokio::test]
    async fn introspection_answers_through_the_router() {
        let (status, cache, body) = call("POST", "/gnap/introspect", true, GOOD).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cache.as_deref(), Some("no-store"));
        assert_eq!(body["active"], true);
    }

    #[tokio::test]
    async fn headers_reach_the_authenticator() {
        let (status, _, body) = call("POST", "/gnap/introspect", false, GOOD).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_resource_server");
    }

    #[tokio::test]
    async fn the_wrong_method_is_405() {
        let (status, _, _) = call("GET", "/gnap/introspect", true, "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn an_oversized_body_is_a_400_not_a_hang() {
        let big = "x".repeat(MAX_BODY_BYTES + 10);
        let (status, _, body) = call("POST", "/gnap/introspect", true, &big).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn an_unregistered_path_is_not_ours() {
        let (status, _, _) = call("POST", "/elsewhere", true, GOOD).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
