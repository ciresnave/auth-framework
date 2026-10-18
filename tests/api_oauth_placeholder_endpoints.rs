//! The OAuth endpoints of the API server must not answer with placeholder data.
//!
//! (`ApiServer::build_router` panics on this line before it can serve anything, so these handlers
//! are reachable only to an application that mounts them itself; they are tested mounted that way.)
//!
//! On this line `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/introspect` and
//! `/oauth/clients/{id}` were placeholders: they reported success for any input (an introspection
//! said `active: true` for any string, the token endpoint handed out made-up tokens without
//! checking the client, the authorization endpoint redirected anywhere with a made-up code) and
//! two of them sliced `token[..10]`, which panics on a short token. A caller that trusted them
//! was told that things were valid that never were. They now answer `501 Not Implemented`,
//! whatever the input; the working OAuth server is `server::oauth` (library API) and the
//! 0.5/0.6 lines' `api` module.

#![cfg(feature = "api-server")]

use auth_framework::api::ApiState;
use auth_framework::api::oauth;
use auth_framework::{AuthConfig, AuthFramework};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::{get, post};
use std::sync::Arc;
use tower::ServiceExt;

/// The five handlers mounted at the paths `ApiServer` gives them. `ApiServer::build_router` itself
/// cannot be used here: on this line it panics while building (it registers `/oauth/clients/:client_id`
/// with axum 0.8, which wants `{client_id}`), so the handlers are mounted directly.
async fn router() -> Router {
    let state = ApiState::new(Arc::new(AuthFramework::new(AuthConfig::default())))
        .await
        .expect("api state");
    Router::new()
        .route("/ping", get(|| async { "pong" }))
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/revoke", post(oauth::revoke_token))
        .route("/oauth/introspect", post(oauth::introspect_token))
        .route("/oauth/clients/{client_id}", get(oauth::get_client_info))
        .with_state(state)
}

/// Sends one request; returns the status, the Location header if any, and the body text.
async fn send(
    method: Method,
    uri: &str,
    json: Option<&str>,
) -> (StatusCode, Option<String>, String) {
    let mut request = Request::builder().method(method).uri(uri);
    let body = match json {
        Some(json) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    let response = router()
        .await
        .oneshot(request.body(body).unwrap())
        .await
        .expect("the router answers (a handler panic would surface here)");
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Control: the router works and a real route answers, so a 501 below comes from the OAuth
/// handlers and not from a router that answers everything the same way.
#[tokio::test]
async fn control_the_router_serves_real_routes() {
    let (status, _, body) = send(Method::GET, "/ping", None).await;
    assert_eq!(status, StatusCode::OK, "ping: {body}");
    let (status, _, _) = send(Method::GET, "/no/such/route", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn introspection_never_reports_a_token_as_active() {
    for token in ["anything-at-all", "x", "not.a.jwt.at.all.but.long"] {
        let (status, _, body) = send(
            Method::POST,
            "/oauth/introspect",
            Some(&format!(r#"{{"token":"{token}"}}"#)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "token {token:?}: {body}"
        );
        assert!(!body.contains("\"active\":true"), "token {token:?}: {body}");
    }
}

#[tokio::test]
async fn revocation_does_not_claim_to_revoke_and_does_not_panic_on_a_short_token() {
    for token in ["a", "short", "exactly-ten", "a longer token value"] {
        let (status, _, body) = send(
            Method::POST,
            "/oauth/revoke",
            Some(&format!(r#"{{"token":"{token}"}}"#)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "token {token:?}: {body}"
        );
        assert!(
            !body.contains("revoked successfully"),
            "token {token:?}: {body}"
        );
    }
}

#[tokio::test]
async fn the_token_endpoint_issues_nothing_for_any_grant() {
    let grants = [
        r#"{"grant_type":"authorization_code","client_id":"c","code":"x","redirect_uri":"https://e.example/cb"}"#,
        r#"{"grant_type":"refresh_token","client_id":"c","refresh_token":"anything"}"#,
        r#"{"grant_type":"client_credentials","client_id":"c","client_secret":"wrong"}"#,
    ];
    for grant in grants {
        let (status, _, body) = send(Method::POST, "/oauth/token", Some(grant)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{grant}: {body}");
        assert!(!body.contains("access_token"), "{grant}: {body}");
    }
}

#[tokio::test]
async fn the_authorization_endpoint_does_not_redirect() {
    let (status, location, body) = send(
        Method::GET,
        "/oauth/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&state=s",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(location.is_none(), "redirected to {location:?}");
}

#[tokio::test]
async fn client_information_is_not_made_up() {
    let (status, _, body) = send(Method::GET, "/oauth/clients/some-client", None).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(!body.contains("example.com"), "{body}");
}
