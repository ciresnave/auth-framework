//! `AuthRouterExt::require_auth_with` validates the bearer token; `require_auth` has no
//! framework to check against and refuses every request.
#![cfg(feature = "axum-integration")]
#![allow(deprecated)]

use auth_framework::integrations::axum::AuthRouterExt;
use auth_framework::{AuthConfig, AuthFramework};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

async fn framework() -> Arc<AuthFramework> {
    let config = AuthConfig::new()
        .secret("test_axum_require_auth_secret_key_long_enough_for_jwt".to_string());
    let mut f = AuthFramework::new(config);
    f.initialize().await.unwrap();
    Arc::new(f)
}

async fn status(app: Router, authorization: Option<&str>) -> StatusCode {
    let mut req = Request::builder().uri("/p");
    if let Some(v) = authorization {
        req = req.header("authorization", v);
    }
    app.oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn require_auth_with_admits_only_a_valid_token() {
    let f = framework().await;
    let app = || {
        Router::new()
            .route("/p", get(|| async { "ok" }))
            .require_auth_with(f.clone())
    };
    let name = format!("ra_{}", uuid::Uuid::new_v4().simple());
    let uid = f
        .register_user(
            &name,
            &format!("{name}@test.example.com"),
            "SecurePass123!x",
        )
        .await
        .unwrap();
    let jwt = f
        .token_manager()
        .create_jwt_token(
            &uid,
            vec!["read".to_string()],
            Some(Duration::from_secs(600)),
        )
        .unwrap();

    assert_eq!(status(app(), None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        status(app(), Some("Bearer not-a-token")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app(), Some("Bearer ")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app(), Some(&format!("Bearer {jwt}"))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn bare_require_auth_refuses_every_request() {
    let app = Router::new()
        .route("/p", get(|| async { "ok" }))
        .require_auth();
    let code = status(app, Some("Bearer anything-at-all")).await;
    assert_ne!(code, StatusCode::OK);
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
}
