// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security Validation Comprehensive Tests
//!
//! Comprehensive test suite covering all security validation paths
//! identified in the security audit. These tests replace the PowerShell
//! tests and ensure proper security validation throughout AuthFramework.

use auth_framework::{
    AuthFramework,
    api::{ApiServer, server::ApiServerConfig},
    config::AuthConfig,
    storage::memory::InMemoryStorage,
};
use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Helper to create test API server
async fn create_test_server() -> ApiServer {
    let _storage = Arc::new(InMemoryStorage::new());

    let auth_config = AuthConfig::new()
        .secret("test_secret_key_for_security_validation_minimum_32_chars".to_string())
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7)); // 7 days

    let mut auth_framework_mut = AuthFramework::new(auth_config);
    auth_framework_mut.initialize().await.unwrap();
    let auth_framework = Arc::new(auth_framework_mut);

    let api_config = ApiServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // Random port for testing
        cors: auth_framework::CorsConfig {
            enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            ..auth_framework::CorsConfig::default()
        },
        max_body_size: 1024 * 1024,
        enable_tracing: false,
    };

    ApiServer::with_config(auth_framework, api_config)
}

fn unique_registration_password() -> String {
    format!("AuthFramework!A9{}", uuid::Uuid::new_v4().simple())
}

// =============================================================================
// AUTHENTICATION SECURITY TESTS
// =============================================================================

#[tokio::test]
async fn test_login_requires_username() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "",
            "password": "TestPassword123!"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], false);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("required")
    );
}

#[tokio::test]
async fn test_login_requires_password() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "testuser",
            "password": ""
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_with_invalid_credentials() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "nonexistent_user",
            "password": "WrongPassword123!"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], false);
    // Should not leak information about whether user exists
    assert!(
        body["error"]["code"]
            .as_str()
            .unwrap()
            .contains("AUTHENTICATION_FAILED")
            || body["error"]["code"]
                .as_str()
                .unwrap()
                .contains("INVALID_CREDENTIALS")
    );
}

#[tokio::test]
async fn test_successful_login_flow() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    // First register a user
    let username = format!("testuser_{}", uuid::Uuid::new_v4());
    let password = unique_registration_password();

    let register_response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": username,
            "password": password.clone(),
            "email": format!("{}@test.com", username)
        }))
        .await;

    assert_eq!(register_response.status_code(), StatusCode::OK);

    // Now try to login
    let login_response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .await;

    assert_eq!(login_response.status_code(), StatusCode::OK);
    let body: serde_json::Value = login_response.json();
    assert_eq!(body["success"], true);
    assert!(body["data"]["access_token"].is_string());
    assert!(body["data"]["refresh_token"].is_string());
    assert_eq!(body["data"]["token_type"], "Bearer");
    assert!(body["data"]["expires_in"].as_u64().unwrap() > 0);
}

// =============================================================================
// REFRESH TOKEN SECURITY TESTS
// =============================================================================

#[tokio::test]
async fn test_refresh_token_requires_token() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/refresh")
        .json(&json!({
            "refresh_token": ""
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_refresh_token_rejects_invalid_token() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/refresh")
        .json(&json!({
            "refresh_token": "invalid_token_here"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_token_rejects_access_token() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    // Register and login to get tokens
    let username = format!("testuser_{}", uuid::Uuid::new_v4());
    let password = unique_registration_password();

    client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": username,
            "password": password.clone(),
            "email": format!("{}@test.com", username)
        }))
        .await;

    let login_response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .await;

    let login_body: serde_json::Value = login_response.json();
    let access_token = login_body["data"]["access_token"].as_str().unwrap();

    // Try to use access token as refresh token (should fail)
    let response = client
        .post("/api/v1/auth/refresh")
        .json(&json!({
            "refresh_token": access_token
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = response.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("refresh token")
    );
}

#[tokio::test]
async fn test_refresh_token_success() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    // Register and login
    let username = format!("testuser_{}", uuid::Uuid::new_v4());
    let password = unique_registration_password();

    client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": username,
            "password": password.clone(),
            "email": format!("{}@test.com", username)
        }))
        .await;

    let login_response = client
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .await;

    let login_body: serde_json::Value = login_response.json();
    let refresh_token = login_body["data"]["refresh_token"].as_str().unwrap();

    // Use refresh token to get new access token
    let refresh_response = client
        .post("/api/v1/auth/refresh")
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .await;

    assert_eq!(refresh_response.status_code(), StatusCode::OK);
    let body: serde_json::Value = refresh_response.json();
    assert_eq!(body["success"], true);
    assert!(body["data"]["access_token"].is_string());
    assert_ne!(body["data"]["access_token"].as_str().unwrap(), "");
}

// =============================================================================
// REGISTRATION SECURITY TESTS
// =============================================================================

#[tokio::test]
async fn test_registration_requires_username() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "",
            "password": "SecurePassword123!",
            "email": "test@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_registration_requires_password() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "password": "",
            "email": "test@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_registration_requires_email() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "password": "SecurePassword123!",
            "email": ""
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_registration_rejects_weak_password() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "password": "short",
            "email": "test@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("8 characters")
    );
}

#[tokio::test]
async fn test_registration_rejects_duplicate_username() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();
    let client = axum_test::TestServer::new(app);
    let first_password = unique_registration_password();
    let second_password = unique_registration_password();

    // First registration should succeed
    let first_response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "duplicate_test",
            "password": first_password,
            "email": "first@example.com"
        }))
        .await;
    assert_eq!(first_response.status_code(), StatusCode::OK);

    // Second registration with same username should fail
    let second_response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "duplicate_test",
            "password": second_password,
            "email": "second@example.com"
        }))
        .await;
    assert_eq!(second_response.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_registration_rejects_duplicate_email() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();
    let client = axum_test::TestServer::new(app);
    let first_password = unique_registration_password();
    let second_password = unique_registration_password();

    // First registration should succeed
    let first_response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "user_one",
            "password": first_password,
            "email": "duplicate@example.com"
        }))
        .await;
    assert_eq!(first_response.status_code(), StatusCode::OK);

    // Second registration with same email should fail
    let second_response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "user_two",
            "password": second_password,
            "email": "duplicate@example.com"
        }))
        .await;
    assert_eq!(second_response.status_code(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_registration_rejects_invalid_email() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);
    let password = unique_registration_password();

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "testuser",
            "password": password,
            "email": "not_an_email"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("email")
    );
}

#[tokio::test]
async fn test_registration_success() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let username = format!("testuser_{}", uuid::Uuid::new_v4());
    let password = unique_registration_password();

    let response = client
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": username,
            "password": password,
            "email": format!("{}@example.com", username)
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["username"], username);
    assert!(body["data"]["user_id"].is_string());
}

// =============================================================================
// API KEY SECURITY TESTS
// =============================================================================

#[tokio::test]
async fn test_api_key_creation_requires_auth() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/api-keys")
        .json(&json!({
            "name": "Test Key",
            "expires_in_days": 30
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_oauth2_authorize_invalid_response_type() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .get("/api/v1/oauth/authorize?response_type=token&client_id=test&redirect_uri=http://localhost")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth2_authorize_requires_client_id() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .get("/api/v1/oauth/authorize?response_type=code&redirect_uri=http://localhost")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth2_authorize_requires_redirect_uri() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .get("/api/v1/oauth/authorize?response_type=code&client_id=test")
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth2_token_exchange_invalid_grant_type() {
    let server = create_test_server().await;
    let app = server.build_router().await.unwrap();

    let client = axum_test::TestServer::new(app);

    let response = client
        .post("/api/v1/oauth/token")
        .json(&json!({
            "grant_type": "password",
            "username": "test",
            "password": "test"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}
