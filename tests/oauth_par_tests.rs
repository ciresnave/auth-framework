// SPDX-License-Identifier: MIT OR Apache-2.0
//! OAuth 2.0 Pushed Authorization Requests (PAR) Tests - RFC 9126
//!
//! Comprehensive tests for the PAR endpoint

use auth_framework::server::oauth::par::{PARManager, PushedAuthorizationRequest};
use auth_framework::{AuthConfig, AuthFramework};
use std::collections::HashMap;
use std::sync::Arc;

/// Helper to create a test AuthFramework instance
async fn create_test_framework() -> Arc<AuthFramework> {
    let _env = auth_framework::testing::test_infrastructure::TestEnvironmentGuard::new()
        .with_jwt_secret("test_secret_key_for_par_tests_1234567890");

    let config = AuthConfig::default();
    let mut auth = AuthFramework::new(config);
    auth.initialize().await.unwrap();
    Arc::new(auth)
}

#[tokio::test]
async fn test_par_store_and_consume() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: Some("openid profile".to_string()),
        state: Some("test_state".to_string()),
        code_challenge: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        code_challenge_method: Some("S256".to_string()),
        additional_params: HashMap::new(),
    };

    // Store request
    let response = par_manager.store_request(request.clone()).await.unwrap();

    assert!(
        response
            .request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:")
    );
    assert_eq!(response.expires_in, 90); // Default expiration

    // Consume request
    let consumed = par_manager
        .consume_request(&response.request_uri)
        .await
        .unwrap();
    assert_eq!(consumed.client_id, "test_client");
    assert_eq!(consumed.response_type, "code");
    assert_eq!(consumed.redirect_uri, "https://example.com/callback");
    assert_eq!(consumed.scope, Some("openid profile".to_string()));
}

#[tokio::test]
async fn test_par_single_use() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: None,
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let response = par_manager.store_request(request).await.unwrap();

    // First consumption should succeed
    let _ = par_manager
        .consume_request(&response.request_uri)
        .await
        .unwrap();

    // Second consumption should fail (single use)
    let result = par_manager.consume_request(&response.request_uri).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_par_invalid_request_uri() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let result = par_manager
        .consume_request("urn:ietf:params:oauth:request_uri:invalid")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_par_validation_missing_client_id() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "".to_string(), // Empty client_id
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: None,
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let result = par_manager.store_request(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_par_validation_invalid_redirect_uri() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "not_a_valid_uri".to_string(), // Invalid URI
        scope: None,
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let result = par_manager.store_request(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_par_with_pkce() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: Some("openid".to_string()),
        state: Some("xyz".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        additional_params: HashMap::new(),
    };

    let response = par_manager.store_request(request.clone()).await.unwrap();
    let consumed = par_manager
        .consume_request(&response.request_uri)
        .await
        .unwrap();

    assert_eq!(
        consumed.code_challenge,
        Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string())
    );
    assert_eq!(consumed.code_challenge_method, Some("S256".to_string()));
}

#[tokio::test]
async fn test_par_expiration() {
    let auth = create_test_framework().await;

    // Create PAR manager with very short expiration
    let par_manager = PARManager::with_expiration(
        auth.storage().clone(),
        std::time::Duration::from_millis(100),
    );

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: None,
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let response = par_manager.store_request(request).await.unwrap();

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Consumption should fail due to expiration
    let result = par_manager.consume_request(&response.request_uri).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_par_multiple_scopes() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: Some("openid profile email phone address".to_string()),
        state: Some("state123".to_string()),
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let response = par_manager.store_request(request).await.unwrap();
    let consumed = par_manager
        .consume_request(&response.request_uri)
        .await
        .unwrap();

    assert_eq!(
        consumed.scope,
        Some("openid profile email phone address".to_string())
    );
}

#[tokio::test]
async fn test_par_additional_params() {
    let auth = create_test_framework().await;
    let par_manager = PARManager::new(auth.storage().clone());

    let mut additional = HashMap::new();
    additional.insert("nonce".to_string(), "nonce_value".to_string());
    additional.insert("display".to_string(), "page".to_string());

    let request = PushedAuthorizationRequest {
        client_id: "test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        scope: Some("openid".to_string()),
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: additional.clone(),
    };

    let response = par_manager.store_request(request).await.unwrap();
    let consumed = par_manager
        .consume_request(&response.request_uri)
        .await
        .unwrap();

    assert_eq!(
        consumed.additional_params.get("nonce"),
        Some(&"nonce_value".to_string())
    );
    assert_eq!(
        consumed.additional_params.get("display"),
        Some(&"page".to_string())
    );
}
