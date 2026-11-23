// SPDX-License-Identifier: MIT OR Apache-2.0
//! OAuth 2.0 Device Authorization Grant Tests - RFC 8628
//!
//! Comprehensive tests for the Device Authorization endpoint

use auth_framework::server::oauth::device::{
    DeviceAuthManager, DeviceAuthorizationRequest, DeviceAuthorizationStatus,
};
use auth_framework::{AuthConfig, AuthFramework};
use std::sync::Arc;

/// Helper to create a test AuthFramework instance
async fn create_test_framework() -> Arc<AuthFramework> {
    let _env = auth_framework::testing::test_infrastructure::TestEnvironmentGuard::new()
        .with_jwt_secret("test_secret_key_for_device_tests_1234567890");

    let config = AuthConfig::default();
    let mut auth = AuthFramework::new(config);
    auth.initialize().await.unwrap();
    Arc::new(auth)
}

#[tokio::test]
async fn test_device_auth_creation() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: Some("openid profile".to_string()),
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    assert!(response.device_code.starts_with("dc_"));
    assert_eq!(response.user_code.len(), 9); // XXXX-XXXX format
    assert!(response.user_code.contains('-'));
    assert_eq!(response.verification_uri, "https://example.com/device");
    assert!(response.verification_uri_complete.is_some());
    assert_eq!(response.interval, 5); // Default 5 seconds
    assert_eq!(response.expires_in, 600); // Default 10 minutes
}

#[tokio::test]
async fn test_device_auth_pending_status() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Poll should return authorization_pending error
    let result = device_manager
        .poll_authorization(&response.device_code)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("authorization_pending"));
}

#[tokio::test]
async fn test_device_auth_authorize_flow() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: Some("openid email".to_string()),
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Authorize the device
    device_manager
        .authorize_device(&response.user_code, "user_123")
        .await
        .unwrap();

    // Poll should now succeed
    let stored = device_manager
        .poll_authorization(&response.device_code)
        .await
        .unwrap();
    assert_eq!(stored.status, DeviceAuthorizationStatus::Authorized);
    assert_eq!(stored.user_id, Some("user_123".to_string()));
    assert_eq!(stored.scope, Some("openid email".to_string()));
}

#[tokio::test]
async fn test_device_auth_deny_flow() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Deny the device
    device_manager
        .deny_device(&response.user_code)
        .await
        .unwrap();

    // Poll should return access_denied error
    let result = device_manager
        .poll_authorization(&response.device_code)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("access_denied"));
}

#[tokio::test]
async fn test_device_auth_slow_down() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // First poll
    let _ = device_manager
        .poll_authorization(&response.device_code)
        .await;

    // Immediate second poll should return slow_down error
    let result = device_manager
        .poll_authorization(&response.device_code)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("slow_down"));
}

#[tokio::test]
async fn test_device_auth_expiration() {
    let auth = create_test_framework().await;

    // Create manager with very short expiration
    let device_manager = DeviceAuthManager::with_settings(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
        std::time::Duration::from_millis(100),
        std::time::Duration::from_secs(1),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Poll should return expired error
    let result = device_manager
        .poll_authorization(&response.device_code)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("expired"));
}

#[tokio::test]
async fn test_device_auth_get_by_user_code() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: Some("profile email".to_string()),
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Get authorization by user code
    let stored = device_manager
        .get_by_user_code(&response.user_code)
        .await
        .unwrap();

    assert_eq!(stored.device_code, response.device_code);
    assert_eq!(stored.user_code, response.user_code);
    assert_eq!(stored.client_id, "test_client");
    assert_eq!(stored.scope, Some("profile email".to_string()));
    assert_eq!(stored.status, DeviceAuthorizationStatus::Pending);
}

#[tokio::test]
async fn test_device_auth_invalid_user_code() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let result = device_manager.get_by_user_code("INVALID-CODE").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_device_auth_invalid_device_code() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let result = device_manager.poll_authorization("dc_invalid_code").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_device_auth_validation_missing_client_id() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "".to_string(), // Empty client_id
        scope: None,
    };

    let result = device_manager.create_authorization(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_device_auth_user_code_format() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    // Generate multiple user codes and verify format
    for _ in 0..10 {
        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = device_manager.create_authorization(request).await.unwrap();

        // Verify user code format: XXXX-XXXX
        assert_eq!(response.user_code.len(), 9);
        assert!(response.user_code.contains('-'));
        assert_eq!(response.user_code.chars().nth(4).unwrap(), '-');

        // Verify only allowed characters (no ambiguous characters)
        for ch in response.user_code.chars() {
            if ch != '-' {
                assert!(ch.is_ascii_alphanumeric());
                assert!(ch.is_ascii_uppercase() || ch.is_ascii_digit());
                // Should not contain: 0, O, I, 1
                assert!(ch != '0' && ch != 'O' && ch != 'I' && ch != '1');
            }
        }
    }
}

#[tokio::test]
async fn test_device_auth_multiple_scopes() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: Some("openid profile email phone address".to_string()),
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    let stored = device_manager
        .get_by_user_code(&response.user_code)
        .await
        .unwrap();

    assert_eq!(
        stored.scope,
        Some("openid profile email phone address".to_string())
    );
}

#[tokio::test]
async fn test_device_auth_verification_uri_complete() {
    let auth = create_test_framework().await;
    let device_manager = DeviceAuthManager::new(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Verify complete URI format
    assert!(response.verification_uri_complete.is_some());
    let complete_uri = response.verification_uri_complete.unwrap();
    assert!(complete_uri.starts_with("https://example.com/device?user_code="));
    assert!(complete_uri.contains(&response.user_code));
}

#[tokio::test]
async fn test_device_auth_authorize_expired_code() {
    let auth = create_test_framework().await;

    // Create manager with very short expiration
    let device_manager = DeviceAuthManager::with_settings(
        auth.storage().clone(),
        "https://example.com/device".to_string(),
        std::time::Duration::from_millis(100),
        std::time::Duration::from_secs(1),
    );

    let request = DeviceAuthorizationRequest {
        client_id: "test_client".to_string(),
        scope: None,
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Attempt to authorize expired code should fail
    let result = device_manager
        .authorize_device(&response.user_code, "user_123")
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    // After expiration, the entry may be cleaned up, resulting in "Invalid user_code"
    // or it may still exist and return an expiration error
    let err_str = err.to_string().to_lowercase();
    assert!(
        err_str.contains("expired") || err_str.contains("invalid"),
        "Expected error to contain 'expired' or 'invalid' but got: {}",
        err
    );
}
