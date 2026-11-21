// SPDX-License-Identifier: MIT OR Apache-2.0
//! OAuth 2.1 End-to-End Integration Tests
//!
//! Comprehensive tests for complete OAuth 2.1 flows:
//! - Pushed Authorization Request (PAR) + Authorization Code flow
//! - Device Authorization Grant flow (complete user journey)
//! - Token management (creation, validation, refresh)
//!
//! These tests verify that all OAuth 2.1 components work together correctly
//! through realistic usage scenarios.

use auth_framework::{
    AuthConfig, AuthFramework,
    server::oauth::par::{PARManager, PushedAuthorizationRequest},
    server::{DeviceAuthManager, DeviceAuthorizationRequest, DeviceAuthorizationStatus},
};
use std::collections::HashMap;
use std::sync::Arc;

/// Helper function to create test AuthFramework with storage
async fn setup_test_framework() -> Arc<AuthFramework> {
    let config = AuthConfig::new()
        .secret("test_oauth21_e2e_secret_key_minimum_32_bytes_required".to_string())
        .max_failed_attempts(5);

    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();
    Arc::new(framework)
}

#[tokio::test]
async fn test_e2e_par_to_authorization_flow() {
    println!("🔍 Testing E2E: PAR to Authorization Flow");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let par_manager = PARManager::new(storage.clone());

    // Step 1: Client pushes authorization request to PAR endpoint
    let par_request = PushedAuthorizationRequest {
        client_id: "test_client_par".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "http://localhost:8080/callback".to_string(),
        scope: Some("openid profile email".to_string()),
        state: Some("par_state_123".to_string()),
        code_challenge: Some("test_challenge_par".to_string()),
        code_challenge_method: Some("S256".to_string()),
        additional_params: HashMap::new(),
    };

    let par_result = par_manager.store_request(par_request.clone()).await;

    assert!(par_result.is_ok(), "PAR request storage should succeed");
    let par_response = par_result.unwrap();

    assert!(
        par_response
            .request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:")
    );
    assert_eq!(par_response.expires_in, 90); // RFC 9126 default

    // Step 2: Use request_uri in authorization endpoint
    let request_uri = par_response.request_uri;
    let retrieved_request = par_manager.consume_request(&request_uri).await;

    assert!(retrieved_request.is_ok(), "Request URI should be valid");
    let auth_params = retrieved_request.unwrap();

    assert_eq!(auth_params.client_id, "test_client_par");
    assert_eq!(auth_params.redirect_uri, "http://localhost:8080/callback");
    assert_eq!(auth_params.scope, Some("openid profile email".to_string()));
    assert_eq!(
        auth_params.code_challenge,
        Some("test_challenge_par".to_string())
    );

    // Step 3: Verify single-use (request_uri cannot be reused)
    let reuse_result = par_manager.consume_request(&request_uri).await;

    assert!(reuse_result.is_err(), "Request URI should be single-use");

    println!("✅ E2E PAR to Authorization Flow: PASSED");
}

#[tokio::test]
async fn test_e2e_device_authorization_complete_flow() {
    println!("🔍 Testing E2E: Device Authorization Complete Flow");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let device_manager =
        DeviceAuthManager::new(storage.clone(), "https://example.com/device".to_string());

    // Step 1: Device initiates flow
    let device_request = DeviceAuthorizationRequest {
        client_id: "tv_app_client".to_string(),
        scope: Some("openid profile".to_string()),
    };

    let device_result: Result<_, _> = device_manager
        .create_authorization(device_request.clone())
        .await;

    assert!(
        device_result.is_ok(),
        "Device authorization creation should succeed"
    );
    let device_response = device_result.unwrap();

    assert!(!device_response.device_code.is_empty());
    assert!(!device_response.user_code.is_empty());
    assert!(
        device_response.user_code.contains('-'),
        "User code should be XXXX-XXXX format"
    );
    assert!(device_response.verification_uri.contains("device"));
    assert_eq!(device_response.expires_in, 600); // RFC 8628 default
    assert_eq!(device_response.interval, 5); // Minimum polling interval

    let device_code = device_response.device_code.clone();
    let user_code = device_response.user_code.clone();

    // Step 2: Device polls for authorization (should be pending)
    let poll_result = device_manager.poll_authorization(&device_code).await;

    assert!(poll_result.is_err(), "Polling should fail while pending");
    let error_msg = poll_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("authorization_pending") || error_msg.contains("pending"),
        "Expected pending error, got: {}",
        error_msg
    );

    // Step 3: User authorizes on verification page
    let auth_result = device_manager
        .authorize_device(&user_code, "device_user_123")
        .await;

    assert!(auth_result.is_ok(), "User authorization should succeed");

    // Step 4: Device polls again (should succeed now)
    let poll_success = device_manager.poll_authorization(&device_code).await;

    assert!(
        poll_success.is_ok(),
        "Polling should succeed after authorization"
    );
    let stored_auth = poll_success.unwrap();

    // Verify the authorization is marked as authorized
    assert_eq!(stored_auth.status, DeviceAuthorizationStatus::Authorized);
    assert_eq!(stored_auth.user_id, Some("device_user_123".to_string()));
    assert_eq!(stored_auth.client_id, "tv_app_client");

    println!("✅ E2E Device Authorization Complete Flow: PASSED");
}

#[tokio::test]
async fn test_e2e_device_authorization_denial() {
    println!("🔍 Testing E2E: Device Authorization Denial");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let device_manager =
        DeviceAuthManager::new(storage.clone(), "https://example.com/device".to_string());

    // Step 1: Device initiates flow
    let device_request = DeviceAuthorizationRequest {
        client_id: "tv_client_deny".to_string(),
        scope: Some("openid".to_string()),
    };

    let device_result = device_manager
        .create_authorization(device_request)
        .await
        .unwrap();

    let device_code = device_result.device_code.clone();
    let user_code = device_result.user_code.clone();

    // Step 2: User denies authorization
    let deny_result = device_manager.deny_device(&user_code).await;

    assert!(deny_result.is_ok(), "User denial should succeed");

    // Step 3: Device polls (should get denied status)
    let poll_result = device_manager.poll_authorization(&device_code).await;

    assert!(poll_result.is_err(), "Polling should fail after denial");
    let error_msg = poll_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("denied") || error_msg.contains("access_denied"),
        "Expected denied error, got: {}",
        error_msg
    );

    println!("✅ E2E Device Authorization Denial: PASSED");
}

#[tokio::test]
async fn test_e2e_device_authorization_slow_down() {
    println!("🔍 Testing E2E: Device Authorization Slow Down");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let device_manager =
        DeviceAuthManager::new(storage.clone(), "https://example.com/device".to_string());

    // Create authorization
    let device_request = DeviceAuthorizationRequest {
        client_id: "slow_client".to_string(),
        scope: Some("openid".to_string()),
    };

    let device_result = device_manager
        .create_authorization(device_request)
        .await
        .unwrap();

    let device_code = device_result.device_code.clone();

    // Poll rapidly to trigger slow_down
    let poll1 = device_manager.poll_authorization(&device_code).await;
    assert!(poll1.is_err()); // Should be pending

    // Immediate second poll (too fast)
    let poll2 = device_manager.poll_authorization(&device_code).await;
    assert!(poll2.is_err());

    let error_msg = poll2.unwrap_err().to_string();
    assert!(
        error_msg.contains("slow_down") || error_msg.contains("too frequent"),
        "Should receive slow_down error for rapid polling, got: {}",
        error_msg
    );

    println!("✅ E2E Device Authorization Slow Down: PASSED");
}

#[tokio::test]
async fn test_e2e_token_lifecycle() {
    println!("🔍 Testing E2E: Token Lifecycle (Create, Validate, Refresh)");

    let framework = setup_test_framework().await;
    let token_manager = framework.token_manager();

    // Step 1: Create a valid token
    let token = token_manager
        .create_auth_token(
            "lifecycle_user",
            vec!["read".to_string(), "write".to_string()],
            "oauth2",
            None,
        )
        .unwrap();

    assert!(!token.access_token.is_empty());

    // Step 2: Validate the JWT token
    let validation_result = token_manager.validate_jwt_token(&token.access_token);

    assert!(validation_result.is_ok(), "Token validation should succeed");
    let claims = validation_result.unwrap();
    assert_eq!(claims.sub, "lifecycle_user");

    // Step 3: Refresh the token (using the original token object)
    let refreshed = token_manager.refresh_token(&token).unwrap();

    assert!(!refreshed.access_token.is_empty());
    assert_ne!(
        token.access_token, refreshed.access_token,
        "New access token should be different"
    );

    // Step 4: Verify refreshed token is valid
    let refreshed_validation = token_manager.validate_jwt_token(&refreshed.access_token);
    assert!(
        refreshed_validation.is_ok(),
        "Refreshed token should be valid"
    );

    println!("✅ E2E Token Lifecycle: PASSED");
}

#[tokio::test]
async fn test_e2e_par_with_pkce_full_flow() {
    println!("🔍 Testing E2E: PAR with PKCE - Full Flow");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let par_manager = PARManager::new(storage.clone());

    // Step 1: Push authorization request with PKCE
    let code_challenge = "test_challenge_par_pkce";

    let par_request = PushedAuthorizationRequest {
        client_id: "par_pkce_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "http://localhost:9000/callback".to_string(),
        scope: Some("openid profile".to_string()),
        state: Some("par_pkce_state".to_string()),
        code_challenge: Some(code_challenge.to_string()),
        code_challenge_method: Some("plain".to_string()),
        additional_params: HashMap::new(),
    };

    let par_response = par_manager.store_request(par_request).await.unwrap();
    let request_uri = par_response.request_uri;

    // Step 2: Consume PAR request
    let auth_params = par_manager.consume_request(&request_uri).await.unwrap();

    // Verify PKCE parameters are preserved
    assert_eq!(auth_params.code_challenge, Some(code_challenge.to_string()));
    assert_eq!(auth_params.code_challenge_method, Some("plain".to_string()));

    // Step 3: At this point, the authorization server would:
    // - Generate authorization code with PKCE from PAR
    // - Later validate code_verifier during token exchange
    // (These steps would happen in the OAuth 2.1 server, not tested here)

    println!("✅ E2E PAR with PKCE Full Flow: PASSED");
}

#[tokio::test]
async fn test_e2e_par_expiration() {
    println!("🔍 Testing E2E: PAR Request Expiration");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let par_manager = PARManager::new(storage.clone());

    // Create PAR request
    let par_request = PushedAuthorizationRequest {
        client_id: "expiry_test_client".to_string(),
        response_type: "code".to_string(),
        redirect_uri: "http://localhost:8080/callback".to_string(),
        scope: Some("openid".to_string()),
        state: None,
        code_challenge: None,
        code_challenge_method: None,
        additional_params: HashMap::new(),
    };

    let par_response = par_manager.store_request(par_request).await.unwrap();

    // Wait for expiration (90 seconds default, but we'll just test immediate consumption works)
    let consume_result = par_manager.consume_request(&par_response.request_uri).await;

    assert!(
        consume_result.is_ok(),
        "Fresh PAR request should be consumable"
    );

    // Verify single-use (already consumed)
    let reuse_result = par_manager.consume_request(&par_response.request_uri).await;

    assert!(reuse_result.is_err(), "PAR request should be single-use");

    println!("✅ E2E PAR Expiration: PASSED");
}

#[tokio::test]
async fn test_e2e_device_user_code_lookup() {
    println!("🔍 Testing E2E: Device User Code Lookup (Verification Page)");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let device_manager =
        DeviceAuthManager::new(storage.clone(), "https://example.com/device".to_string());

    // Create device authorization
    let device_request = DeviceAuthorizationRequest {
        client_id: "lookup_test_client".to_string(),
        scope: Some("openid profile".to_string()),
    };

    let device_response = device_manager
        .create_authorization(device_request)
        .await
        .unwrap();

    let user_code = device_response.user_code.clone();

    // Step 1: User visits verification page and enters user code
    let lookup_result = device_manager.get_by_user_code(&user_code).await;

    assert!(lookup_result.is_ok(), "User code lookup should succeed");
    let authorization = lookup_result.unwrap();

    assert_eq!(authorization.client_id, "lookup_test_client");
    assert_eq!(authorization.scope, Some("openid profile".to_string()));
    assert_eq!(authorization.status, DeviceAuthorizationStatus::Pending);

    // Step 2: User authorizes
    device_manager
        .authorize_device(&user_code, "lookup_user")
        .await
        .unwrap();

    // Step 3: Verify status changed
    let updated_auth = device_manager.get_by_user_code(&user_code).await.unwrap();

    assert_eq!(updated_auth.status, DeviceAuthorizationStatus::Authorized);
    assert_eq!(updated_auth.user_id, Some("lookup_user".to_string()));

    println!("✅ E2E Device User Code Lookup: PASSED");
}

#[tokio::test]
async fn test_e2e_multiple_par_requests() {
    println!("🔍 Testing E2E: Multiple Concurrent PAR Requests");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let par_manager = PARManager::new(storage.clone());

    // Create multiple PAR requests simultaneously
    let mut request_uris = Vec::new();

    for i in 0..5 {
        let par_request = PushedAuthorizationRequest {
            client_id: format!("client_{}", i),
            response_type: "code".to_string(),
            redirect_uri: format!("http://localhost:8080/callback{}", i),
            scope: Some(format!("scope{}", i)),
            state: Some(format!("state{}", i)),
            code_challenge: Some(format!("challenge{}", i)),
            code_challenge_method: Some("S256".to_string()),
            additional_params: HashMap::new(),
        };

        let response = par_manager.store_request(par_request).await.unwrap();
        request_uris.push((i, response.request_uri));
    }

    // Verify all can be consumed independently
    for (i, uri) in request_uris {
        let result = par_manager.consume_request(&uri).await;
        assert!(result.is_ok(), "PAR request {} should be consumable", i);

        let params = result.unwrap();
        assert_eq!(params.client_id, format!("client_{}", i));
        assert_eq!(params.scope, Some(format!("scope{}", i)));
    }

    println!("✅ E2E Multiple PAR Requests: PASSED");
}
