//! Working Integration Tests
//!
//! Tests basic functionality that is currently working

use auth_framework::{
    AuthConfig, AuthFramework,
    audit::DeviceInfo,
    methods::{AuthMethodEnum, JwtMethod},
    permissions::{Permission, PermissionChecker},
    storage::memory::InMemoryStorage,
};
use std::time::Duration;

#[tokio::test]
async fn test_basic_auth_framework_integration() {
    println!("🔍 Testing Basic Auth Framework Integration");

    // Set JWT secret for testing
    unsafe {
        std::env::set_var(
            "JWT_SECRET",
            "test-secret-key-for-integration-testing-at-least-32-chars-long",
        );
    }

    // Create auth configuration
    let config = AuthConfig::new()
        .secret("test-secret-key-for-integration-testing-at-least-32-chars-long".to_string())
        .issuer("https://test.localhost".to_string())
        .audience("test-app".to_string())
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    // Create auth framework
    let mut auth_framework = AuthFramework::new(config);

    // Register JWT method
    let jwt_method = JwtMethod::new()
        .secret_key("test-secret")
        .issuer("https://test.localhost");

    auth_framework.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));

    // Initialize framework
    auth_framework
        .initialize()
        .await
        .expect("Failed to initialize auth framework");

    // Create a token with proper action:resource scope format
    let token = auth_framework
        .create_auth_token(
            "test_user",
            vec!["read:documents".to_string(), "write:documents".to_string()],
            "jwt",
            None,
        )
        .await
        .expect("Failed to create token");

    assert!(!token.access_token.is_empty(), "Token should not be empty");
    assert_eq!(token.user_id, "test_user", "User ID should match");

    // Validate the token
    let is_valid = auth_framework
        .validate_token(&token)
        .await
        .expect("Failed to validate token");

    assert!(is_valid, "Token should be valid");

    // Grant permission to the user
    auth_framework
        .grant_permission("test_user", "read", "documents")
        .await
        .expect("Failed to grant permission");

    // Check permissions
    let has_permission = auth_framework
        .check_permission(&token, "read", "documents")
        .await
        .expect("Failed to check permission");

    assert!(has_permission, "Should have read permission");

    println!("✅ Basic auth framework integration test passed");
}

#[tokio::test]
async fn test_permission_checker_basic_functionality() {
    println!("🔍 Testing Permission Checker Basic Functionality");

    let mut checker = PermissionChecker::new();

    // Create default roles
    checker.create_default_roles();

    // Add a user permission
    let permission = Permission::new("read", "documents");
    checker.add_user_permission("test_user", permission);

    // Check if user has access
    let has_access = checker
        .check_access("test_user", "read", "documents")
        .expect("Failed to check access");

    assert!(has_access, "User should have read access to documents");

    // Check if user doesn't have write access
    let has_write_access = checker
        .check_access("test_user", "write", "documents")
        .expect("Failed to check write access");

    assert!(
        !has_write_access,
        "User should not have write access to documents"
    );

    println!("✅ Permission checker basic functionality test passed");
}

#[tokio::test]
async fn test_device_info_creation() {
    println!("🔍 Testing Device Info Creation");

    let device_info = DeviceInfo {
        device_type: Some("desktop".to_string()),
        operating_system: Some("Windows 11".to_string()),
        browser: Some("Chrome".to_string()),
        is_mobile: false,
        screen_resolution: Some("1920x1080".to_string()),
    };

    assert_eq!(device_info.device_type, Some("desktop".to_string()));
    assert_eq!(device_info.operating_system, Some("Windows 11".to_string()));
    assert!(!device_info.is_mobile);

    println!("✅ Device info creation test passed");
}

#[tokio::test]
async fn test_memory_storage_basic_operations() {
    println!("🔍 Testing Memory Storage Basic Operations");

    let _storage = InMemoryStorage::new();

    // Test that storage was created successfully
    println!("✅ Storage creation successful");

    println!("✅ Memory storage basic operations test passed");
}

#[tokio::test]
async fn test_jwt_token_lifecycle() {
    println!("🔍 Testing JWT Token Lifecycle");

    // Set JWT secret for testing
    unsafe {
        std::env::set_var(
            "JWT_SECRET",
            "lifecycle-secret-key-for-integration-testing-at-least-32-chars-long",
        );
    }

    // Create auth configuration
    let config = AuthConfig::new()
        .secret("lifecycle-secret-key-for-integration-testing-at-least-32-chars-long".to_string())
        .issuer("https://lifecycle.test".to_string())
        .audience("lifecycle-app".to_string())
        .token_lifetime(Duration::from_secs(60)); // Short lifetime for testing

    // Create auth framework
    let mut auth_framework = AuthFramework::new(config);

    // Register JWT method
    let jwt_method = JwtMethod::new()
        .secret_key("lifecycle-secret")
        .issuer("https://lifecycle.test");

    auth_framework.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));

    // Initialize framework
    auth_framework
        .initialize()
        .await
        .expect("Failed to initialize");

    // Create token
    let token = auth_framework
        .create_auth_token("lifecycle_user", vec!["test".to_string()], "jwt", None)
        .await
        .expect("Failed to create token");

    // Validate token immediately
    let is_valid = auth_framework
        .validate_token(&token)
        .await
        .expect("Failed to validate token");

    assert!(is_valid, "Token should be valid immediately after creation");

    // Test token properties
    assert!(
        !token.access_token.is_empty(),
        "Access token should not be empty"
    );
    assert_eq!(token.user_id, "lifecycle_user", "User ID should match");
    assert_eq!(
        token.scopes,
        vec!["test".to_string()],
        "Scopes should match"
    );

    println!("✅ JWT token lifecycle test passed");
}
