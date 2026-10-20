//! `ApiServer::build_router` must build, and its path-parameter routes must be reachable.
//!
//! The paths were registered in the axum 0.7 `:param` form, which axum 0.8 (this crate's version)
//! rejects with a panic while the router is being built, so no server could start.

#![cfg(feature = "api-server")]

use auth_framework::api::ApiServer;
use auth_framework::{AuthConfig, AuthFramework};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

async fn status(method: Method, uri: &str) -> StatusCode {
    let server = ApiServer::new(Arc::new(AuthFramework::new(AuthConfig::default())));
    let router = server.build_router().await.expect("router builds");
    router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn the_router_builds_and_serves_a_plain_route() {
    assert_eq!(status(Method::GET, "/health").await, StatusCode::OK);
}

/// Each of these registers a path parameter. A 404 would mean the route did not match its `{param}`
/// form; anything else (here 401/403/501, depending on the handler) means it matched.
#[tokio::test]
async fn path_parameter_routes_match() {
    for (method, uri) in [
        (Method::GET, "/oauth/clients/abc"),
        (Method::DELETE, "/users/sessions/abc"),
        (Method::GET, "/users/abc/profile"),
        (Method::PUT, "/admin/users/abc/roles"),
        (Method::DELETE, "/admin/users/abc"),
        (Method::PUT, "/admin/users/abc/activate"),
    ] {
        let got = status(method.clone(), uri).await;
        assert_ne!(
            got,
            StatusCode::NOT_FOUND,
            "{method} {uri} did not match a route"
        );
    }
    // Control: a path that is not registered at all is a 404, so the check above can fail.
    assert_eq!(
        status(Method::GET, "/no/such/route").await,
        StatusCode::NOT_FOUND
    );
}
