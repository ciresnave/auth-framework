//! Integration tests for WebAuthn and SAML API endpoints

use auth_framework::api::ApiServer;
use auth_framework::{AuthConfig, AuthFramework};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn create_test_app() -> axum::Router {
    let auth_framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    let server = ApiServer::new(auth_framework);
    server
        .build_router()
        .await
        .expect("Failed to build router for tests")
}

#[cfg(feature = "saml")]
async fn create_test_app_with_saml_sp_config() -> axum::Router {
    let auth_framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    auth_framework
        .storage()
        .store_kv(
            "saml_sp:config",
            serde_json::json!({
                "entity_id": "https://sp.example.com",
                "acs_url": "https://sp.example.com/api/saml/acs",
                "slo_url": "https://sp.example.com/api/saml/slo"
            })
            .to_string()
            .as_bytes(),
            None,
        )
        .await
        .unwrap();

    ApiServer::new(auth_framework)
        .build_router()
        .await
        .expect("Failed to build router for tests")
}

#[tokio::test]
async fn test_webauthn_registration_init() {
    let app = create_test_app().await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/webauthn/registration/init")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "username": "testuser",
                "display_name": "Test User",
                "authenticator_attachment": "platform",
                "user_verification": "preferred"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    // Registration is an account-security operation: it requires an
    // authenticated session (the authenticated flow is covered in
    // `webauthn_ceremony_tests`).
    let response_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_json["success"], false);
    assert_eq!(response_json["error"]["code"], "UNAUTHORIZED");
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn test_saml_metadata_requires_sp_config() {
    let app = create_test_app().await;

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/saml/metadata")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn test_saml_metadata() {
    let app = create_test_app_with_saml_sp_config().await;

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/saml/metadata")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    assert!(body_str.contains("<?xml"));
    assert!(body_str.contains("EntityDescriptor"));
    assert!(body_str.contains("SPSSODescriptor"));
    assert!(body_str.contains("https://sp.example.com"));
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn test_saml_sso_initiation() {
    // Build app with pre-populated IdP config so the endpoint can look it up.
    let auth_framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    auth_framework
        .storage()
        .store_kv(
            "saml_sp:config",
            serde_json::json!({
                "entity_id": "https://sp.example.com",
                "acs_url": "https://sp.example.com/api/saml/acs",
                "slo_url": "https://sp.example.com/api/saml/slo"
            })
            .to_string()
            .as_bytes(),
            None,
        )
        .await
        .unwrap();
    let idp_config = serde_json::json!({
        "entity_id": "https://idp.example.com",
        "sso_url": "https://idp.example.com/sso",
        "slo_url": "https://idp.example.com/slo",
        "certificate": ""
    });
    auth_framework
        .storage()
        .store_kv(
            "saml_idp:https://idp.example.com",
            idp_config.to_string().as_bytes(),
            None,
        )
        .await
        .unwrap();

    let app = ApiServer::new(auth_framework)
        .build_router()
        .await
        .expect("Failed to build router for tests");

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/saml/sso")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "idp_entity_id": "https://idp.example.com",
                "relay_state": "test_state",
                "force_authn": false
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    let response_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_json["success"], true);
    assert!(response_json["data"]["redirect_url"].is_string());
    assert!(response_json["data"]["saml_request"].is_string());
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn test_saml_sso_requires_sp_config() {
    let auth_framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    let idp_config = serde_json::json!({
        "entity_id": "https://idp.example.com",
        "sso_url": "https://idp.example.com/sso",
        "slo_url": "https://idp.example.com/slo",
        "certificate": ""
    });
    auth_framework
        .storage()
        .store_kv(
            "saml_idp:https://idp.example.com",
            idp_config.to_string().as_bytes(),
            None,
        )
        .await
        .unwrap();

    let app = ApiServer::new(auth_framework)
        .build_router()
        .await
        .expect("Failed to build router for tests");

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/saml/sso")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "idp_entity_id": "https://idp.example.com"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["success"], false);
    assert_eq!(response_json["error"]["code"], "SAML_CONFIG_ERROR");
}

#[tokio::test]
async fn test_webauthn_credential_list() {
    let app = create_test_app().await;

    // Requesting without authentication should be rejected
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/webauthn/credentials/testuser")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    let response_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    // Endpoint now requires authentication — unauthenticated access returns error
    assert_eq!(response_json["success"], false);
    assert_eq!(response_json["error"]["code"], "UNAUTHORIZED");
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn test_saml_idp_list() {
    let app = create_test_app().await;

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/saml/idps")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();

    let response_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(response_json["success"], true);
    assert!(response_json["data"].is_array());
}
