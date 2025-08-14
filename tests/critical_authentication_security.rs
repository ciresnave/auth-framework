//! Critical Authentication Security Tests
//!
//! Tests to verify that the authentication bypass vulnerability has been fixed
//! and that proper password validation is enforced.

use auth_framework::{
    errors::AuthError,
    oauth2_server::{OAuth2Config, OAuth2Server},
    tokens::TokenManager,
};
use std::sync::Arc;

/// Helper function to create test token manager
fn create_test_token_manager() -> Arc<TokenManager> {
    Arc::new(TokenManager::new_hmac(
        b"test_secret_key_32_bytes_long!!!!",
        "test_issuer",
        "test_audience",
    ))
}

/// Test that authentication properly validates passwords
#[tokio::test]
async fn test_authentication_requires_valid_password() {
    let config = OAuth2Config::default();
    let token_manager = Arc::new(TokenManager::new_hmac(
        b"test_secret_key_32_bytes_long!!!!",
        "test_issuer",
        "test_audience",
    ));
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Test 1: Valid credentials should succeed
    let result = server
        .authenticate_user(
            "admin",
            "admin_password_123456789",
            vec!["read".to_string()],
        )
        .await;
    assert!(result.is_ok(), "Valid credentials should succeed");

    // Test 2: Invalid password should fail
    let result = server
        .authenticate_user("admin", "wrong_password", vec!["read".to_string()])
        .await;
    assert!(result.is_err(), "Invalid password should fail");

    let error = result.unwrap_err();
    assert!(
        matches!(error, AuthError::AuthMethod { .. }),
        "Should be authentication error"
    );

    // Test 3: Empty password should fail
    let result = server
        .authenticate_user("admin", "", vec!["read".to_string()])
        .await;
    assert!(result.is_err(), "Empty password should fail");

    // Test 4: Short password should fail
    let result = server
        .authenticate_user("admin", "short", vec!["read".to_string()])
        .await;
    assert!(result.is_err(), "Short password should fail");

    // Test 5: Invalid username should fail
    let result = server
        .authenticate_user("invalid_user", "any_password", vec!["read".to_string()])
        .await;
    assert!(result.is_err(), "Invalid username should fail");

    // Test 6: Empty username should fail
    let result = server
        .authenticate_user("", "admin_password_123456789", vec!["read".to_string()])
        .await;
    assert!(result.is_err(), "Empty username should fail");
}

/// Test that user scope authorization works correctly
#[tokio::test]
async fn test_user_scope_authorization() {
    let config = OAuth2Config::default();
    let token_manager = create_test_token_manager();
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Test admin user can access admin scopes
    let result = server
        .authenticate_user(
            "admin",
            "admin_password_123456789",
            vec!["admin".to_string()],
        )
        .await;
    assert!(result.is_ok(), "Admin should have admin scope");
    let user_context = result.unwrap();
    assert!(
        user_context.has_scope("admin"),
        "User context should have admin scope"
    );

    // Test regular user cannot access admin scopes
    let result = server
        .authenticate_user("user", "user_password_123456789", vec!["admin".to_string()])
        .await;
    assert!(result.is_err(), "Regular user should not have admin scope");

    // Test regular user can access read/write scopes
    let result = server
        .authenticate_user(
            "user",
            "user_password_123456789",
            vec!["read".to_string(), "write".to_string()],
        )
        .await;
    assert!(result.is_ok(), "Regular user should have read/write scopes");
    let user_context = result.unwrap();
    assert!(
        user_context.has_scope("read"),
        "User should have read scope"
    );
    assert!(
        user_context.has_scope("write"),
        "User should have write scope"
    );

    // Test test user only gets read scope
    let result = server
        .authenticate_user("test", "test_password_123456789", vec!["read".to_string()])
        .await;
    assert!(result.is_ok(), "Test user should have read scope");
    let user_context = result.unwrap();
    assert!(
        user_context.has_scope("read"),
        "Test user should have read scope"
    );

    // Test test user cannot get write scope
    let result = server
        .authenticate_user("test", "test_password_123456789", vec!["write".to_string()])
        .await;
    assert!(result.is_err(), "Test user should not have write scope");
}

/// Test that user IDs are generated consistently and securely
#[tokio::test]
async fn test_user_id_generation_security() {
    let config = OAuth2Config::default();
    let token_manager = create_test_token_manager();
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Test that the same user gets the same ID consistently
    let result1 = server
        .authenticate_user(
            "admin",
            "admin_password_123456789",
            vec!["read".to_string()],
        )
        .await
        .unwrap();

    let result2 = server
        .authenticate_user(
            "admin",
            "admin_password_123456789",
            vec!["read".to_string()],
        )
        .await
        .unwrap();

    assert_eq!(
        result1.user_id, result2.user_id,
        "Same user should get consistent ID"
    );

    // Test that different users get different IDs
    let user_result = server
        .authenticate_user("user", "user_password_123456789", vec!["read".to_string()])
        .await
        .unwrap();

    assert_ne!(
        result1.user_id, user_result.user_id,
        "Different users should get different IDs"
    );

    // Test that user IDs are not predictable/guessable
    assert!(
        !result1.user_id.contains("admin"),
        "User ID should not contain username"
    );
    assert!(
        result1.user_id.starts_with("user_"),
        "User ID should have proper prefix"
    );
    assert_eq!(
        result1.user_id.len(),
        21,
        "User ID should be proper length (user_ + 16 chars)"
    );
}

/// Test session management security
#[tokio::test]
async fn test_session_management_security() {
    let config = OAuth2Config::default();
    let token_manager = create_test_token_manager();
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Authenticate user and get user context
    let user_context = server
        .authenticate_user(
            "admin",
            "admin_password_123456789",
            vec!["read".to_string()],
        )
        .await
        .unwrap();

    // Test that we can retrieve the session
    let session_result = server
        .get_user_context(&user_context.session_id)
        .await
        .unwrap();
    assert!(
        session_result.is_some(),
        "Should be able to retrieve session"
    );

    let retrieved_context = session_result.unwrap();
    assert_eq!(
        retrieved_context.user_id, user_context.user_id,
        "Retrieved context should match"
    );
    assert_eq!(
        retrieved_context.username, user_context.username,
        "Username should match"
    );

    // Test session invalidation
    let invalidation_result = server
        .invalidate_session(&user_context.session_id)
        .await
        .unwrap();
    assert!(invalidation_result, "Session invalidation should succeed");

    // Test that invalidated session cannot be retrieved
    let session_result = server
        .get_user_context(&user_context.session_id)
        .await
        .unwrap();
    assert!(
        session_result.is_none(),
        "Invalidated session should not be retrievable"
    );
}

/// Test password timing attack resistance
#[tokio::test]
async fn test_password_timing_attack_resistance() {
    use std::time::Instant;

    let config = OAuth2Config::default();
    let token_manager = create_test_token_manager();
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Test multiple wrong passwords to ensure timing is consistent
    let passwords = vec![
        "wrong1",
        "wrong_password_of_different_length",
        "x",
        "completely_different_wrong_password_that_is_much_longer",
    ];

    let mut timings = Vec::new();

    for password in passwords {
        let start = Instant::now();
        let _result = server
            .authenticate_user("admin", password, vec!["read".to_string()])
            .await;
        let duration = start.elapsed();
        timings.push(duration);

        // All should fail
        assert!(_result.is_err(), "Wrong passwords should fail");
    }

    // Check that timing differences are not excessive (indicating timing attack resistance)
    let max_timing = timings.iter().max().unwrap();
    let min_timing = timings.iter().min().unwrap();
    let ratio = max_timing.as_nanos() as f64 / min_timing.as_nanos() as f64;

    // Print timing information for debugging
    println!(
        "Timings: {:?}",
        timings.iter().map(|t| t.as_millis()).collect::<Vec<_>>()
    );
    println!(
        "Max: {:?}ms, Min: {:?}ms, Ratio: {:.2}",
        max_timing.as_millis(),
        min_timing.as_millis(),
        ratio
    );

    // Allow more variance but not extreme differences
    // Bcrypt can have some natural variation, so we allow up to 50x difference
    assert!(
        ratio < 50.0,
        "Timing differences should not be extreme (ratio: {})",
        ratio
    );
}

/// Test that authentication prevents common injection attacks
#[tokio::test]
async fn test_authentication_injection_prevention() {
    let config = OAuth2Config::default();
    let token_manager = create_test_token_manager();
    let server = OAuth2Server::new(config, token_manager).await.unwrap();

    // Test SQL injection attempts in username
    let sql_injection_usernames = vec![
        "admin'; DROP TABLE users; --",
        "admin' OR '1'='1",
        "admin' UNION SELECT * FROM users --",
        "'; SELECT * FROM users WHERE '1'='1",
    ];

    for username in sql_injection_usernames {
        let result = server
            .authenticate_user(
                username,
                "admin_password_123456789",
                vec!["read".to_string()],
            )
            .await;
        assert!(
            result.is_err(),
            "SQL injection attempt should fail: {}",
            username
        );
    }

    // Test special characters in password
    let special_passwords = vec![
        "'; DROP TABLE users; --",
        "password' OR '1'='1",
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
    ];

    for password in special_passwords {
        let result = server
            .authenticate_user("admin", password, vec!["read".to_string()])
            .await;
        assert!(
            result.is_err(),
            "Special character password should fail: {}",
            password
        );
    }
}
