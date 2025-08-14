use auth_framework::auth::AuthFramework;
use auth_framework::config::AuthConfig;
use auth_framework::credentials::Credential;
use auth_framework::test_infrastructure::TestEnvironmentGuard;
use auth_framework::tokens::AuthToken;
use std::sync::Arc;
use std::time::Duration;

/// Comprehensive error path testing to ensure robust error handling
/// These tests verify that the framework fails gracefully in all error scenarios

#[tokio::test]
async fn test_uninitialized_framework_operations() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let framework = AuthFramework::new(config);
    // Deliberately NOT calling framework.initialize()

    // Test authenticate on uninitialized framework
    let credential = Credential::password("user", "pass");
    match framework.authenticate("password", credential).await {
        Ok(_) => panic!("Uninitialized framework should not allow authentication"),
        Err(e) => assert!(
            e.to_string().contains("not initialized") || e.to_string().contains("Internal error")
        ),
    }

    // Test session creation on uninitialized framework
    match framework
        .create_session("user", Duration::from_secs(3600), None, None)
        .await
    {
        Ok(_) => panic!("Uninitialized framework should not allow session creation"),
        Err(e) => assert!(
            e.to_string().contains("not initialized") || e.to_string().contains("Internal error")
        ),
    }

    // Test token validation on uninitialized framework
    let token = AuthToken::new(
        "test_user",
        "test_token",
        Duration::from_secs(3600),
        "test_method",
    );
    match framework.validate_token(&token).await {
        Ok(_) => panic!("Uninitialized framework should not allow token validation"),
        Err(e) => assert!(
            e.to_string().contains("not initialized") || e.to_string().contains("Internal error")
        ),
    }
}

#[tokio::test]
async fn test_malformed_input_handling() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test extreme input sizes
    let long_string = "a".repeat(10000);
    let long_string2 = "b".repeat(10000);

    let extreme_inputs = vec![
        ("", ""),                                                 // Empty strings
        (long_string.as_str(), long_string2.as_str()),            // Very long strings
        ("user\0with\0nulls", "pass\0with\0nulls"),               // Null bytes
        ("👤🚀💻", "🔐🌟⚡"),                                     // Unicode emoji
        ("\x01\x02\x03", "\x04\x05\x06"),                         // Control characters
        ("user\r\nwith\r\nnewlines", "pass\r\nwith\r\nnewlines"), // Newlines
        ("user\twith\ttabs", "pass\twith\ttabs"),                 // Tabs
    ];

    for (username, password) in extreme_inputs {
        let credential = Credential::password(username, password);

        // Should handle gracefully without panicking
        let result = framework.authenticate("password", credential).await;
        match result {
            Ok(_) => (), // Might be valid depending on implementation
            Err(e) => {
                // Error should be descriptive, not a panic
                assert!(!e.to_string().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn test_invalid_jwt_token_handling() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various malformed JWT tokens as token values
    let malformed_tokens = vec![
        "",                                                       // Empty token
        "invalid",                                                // Not a JWT
        "header.payload",                                         // Missing signature
        "header.payload.signature.extra",                         // Too many parts
        "invalid.header.here",                                    // Invalid format
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid.signature", // Invalid payload
        "header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid", // Invalid signature
    ];

    for malformed_token in malformed_tokens {
        // Create a token object with malformed access token
        let token = AuthToken::new(
            "test_user",
            malformed_token,
            Duration::from_secs(3600),
            "jwt",
        );
        match framework.validate_token(&token).await {
            Ok(false) => (), // Correctly rejected
            Ok(true) => {
                if !malformed_token.is_empty() {
                    panic!("Malformed token '{}' should not validate", malformed_token);
                }
            }
            Err(_) => (), // Error is acceptable for malformed input
        }
    }
}

#[tokio::test]
async fn test_concurrent_operation_safety() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);
    let mut handles = vec![];

    // Test many concurrent operations to detect race conditions
    for i in 0..50 {
        let framework = framework.clone();
        let handle = tokio::spawn(async move {
            let user_id = format!("user_{}", i);

            // Create session
            let session_result = framework
                .create_session(&user_id, Duration::from_secs(3600), None, None)
                .await;

            if let Ok(session_id) = session_result {
                // Get session
                let get_result = framework.get_session(&session_id).await;

                // Delete session
                let delete_result = framework.delete_session(&session_id).await;

                // Verify operations completed
                (get_result.is_ok(), delete_result.is_ok())
            } else {
                (false, false)
            }
        });
        handles.push(handle);
    }

    // Wait for all operations with timeout to detect deadlocks
    let mut success_count = 0;
    for handle in handles {
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(Ok((get_ok, delete_ok))) => {
                if get_ok && delete_ok {
                    success_count += 1;
                }
            }
            Ok(Err(_)) => panic!("Task panicked during concurrent operations"),
            Err(_) => panic!("Deadlock detected in concurrent operations"),
        }
    }

    // Most operations should succeed (allowing for some contention)
    assert!(
        success_count > 40,
        "Too many concurrent operations failed: {}/50",
        success_count
    );
}

#[tokio::test]
async fn test_session_storage_error_recovery() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test session operations with invalid session IDs
    let long_id = "a".repeat(1000);
    let newline_id = format!("sess_{}", "\r\n".repeat(100));
    let long_sess_id = format!("sess_{}", long_id);

    let invalid_session_ids = vec![
        "",                // Empty
        "invalid-format",  // Wrong format
        &long_sess_id,     // Too long
        "sess_\0\x01\x02", // Control characters
        "sess_👤🚀💻",     // Unicode
        &newline_id,       // Newlines
    ];

    for invalid_id in invalid_session_ids {
        // Get session should handle gracefully
        match framework.get_session(invalid_id).await {
            Ok(None) => (), // Correctly returns None for invalid ID
            Ok(Some(_)) => panic!("Invalid session ID '{}' should not return data", invalid_id),
            Err(_) => (), // Error is acceptable for malformed input
        }

        // Delete session should handle gracefully
        let _ = framework.delete_session(invalid_id).await;
        // Might succeed (idempotent delete) or error is acceptable for malformed input
    }
}

#[tokio::test]
async fn test_authentication_method_error_paths() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test non-existent authentication methods
    let invalid_methods = vec![
        "",                   // Empty method name
        "nonexistent",        // Non-existent method
        "password\0",         // Method with null byte
        "method with spaces", // Method with spaces
        "🔐method",           // Unicode method
    ];

    for method in invalid_methods {
        let credential = Credential::password("user", "pass");
        match framework.authenticate(method, credential).await {
            Ok(_) => panic!("Invalid method '{}' should not succeed", method),
            Err(e) => {
                // Error should be descriptive
                assert!(!e.to_string().is_empty());
                // Should mention method not found or similar
                let error_msg = e.to_string().to_lowercase();
                assert!(
                    error_msg.contains("not found")
                        || error_msg.contains("invalid")
                        || error_msg.contains("unknown")
                        || error_msg.contains("method")
                );
            }
        }
    }
}

#[tokio::test]
async fn test_token_expiration_edge_cases() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test token with zero duration (immediate expiration)
    let expired_token = AuthToken::new("test_user", "test_token", Duration::from_secs(0), "test");

    // Wait a tiny bit to ensure expiration
    tokio::time::sleep(Duration::from_millis(1)).await;

    match framework.validate_token(&expired_token).await {
        Ok(false) => (), // Correctly identified as invalid/expired
        Ok(true) => panic!("Expired token should not validate"),
        Err(_) => (), // Error is acceptable for expired token
    }

    // Test token with very long duration (potential overflow)
    let long_token = AuthToken::new(
        "test_user",
        "test_token",
        Duration::from_secs(u64::MAX / 2),
        "test",
    );

    let _ = framework.validate_token(&long_token).await;
    // Any result is acceptable - error is acceptable for extreme values
}

#[tokio::test]
async fn test_cleanup_operations_error_handling() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test cleanup operations multiple times to ensure idempotency
    for _ in 0..5 {
        // Cleanup should not fail even when there's nothing to clean
        match framework.cleanup_expired_data().await {
            Ok(_) => (), // Success is expected
            Err(e) => panic!("Cleanup should not fail: {}", e),
        }
    }

    // Create some data and immediately clean it up
    let session_result = framework
        .create_session("user", Duration::from_secs(1), None, None)
        .await;
    if let Ok(session_id) = session_result {
        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup should handle expired data gracefully
        match framework.cleanup_expired_data().await {
            Ok(_) => (), // Success expected
            Err(e) => panic!("Cleanup of expired data failed: {}", e),
        }

        // Session should now be gone
        match framework.get_session(&session_id).await {
            Ok(None) => (),    // Correctly cleaned up
            Ok(Some(_)) => (), // Might still exist depending on cleanup timing
            Err(_) => (),      // Error is acceptable
        }
    }
}

#[tokio::test]
async fn test_credential_validation_edge_cases() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various credential edge cases
    let edge_case_credentials = vec![
        Credential::password("", ""),                 // Empty username/password
        Credential::password("user", ""),             // Empty password
        Credential::password("", "password"),         // Empty username
        Credential::password("👤", "🔐"),             // Unicode
        Credential::password("user\0", "pass\0"),     // Null bytes
        Credential::password("user\r\n", "pass\r\n"), // Newlines
    ];

    for credential in edge_case_credentials {
        // Should handle gracefully without panicking
        match framework.authenticate("password", credential).await {
            Ok(_) => (), // Might be valid
            Err(e) => {
                // Error should be descriptive
                assert!(!e.to_string().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn test_memory_pressure_scenarios() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Create many sessions to test memory handling
    let mut session_ids = Vec::new();

    for i in 0..1000 {
        let user_id = format!("user_{}", i);
        match framework
            .create_session(&user_id, Duration::from_secs(3600), None, None)
            .await
        {
            Ok(session_id) => session_ids.push(session_id),
            Err(_) => break, // Stop if we hit limits
        }
    }

    // Framework should handle many sessions without crashing
    assert!(
        session_ids.len() > 100,
        "Should be able to create at least 100 sessions"
    );

    // Cleanup
    for session_id in session_ids {
        let _ = framework.delete_session(&session_id).await;
    }
}

#[tokio::test]
async fn test_boundary_conditions() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test session duration boundaries
    let boundary_durations = vec![
        Duration::from_secs(0),               // Zero duration
        Duration::from_secs(1),               // Minimal duration
        Duration::from_secs(u32::MAX as u64), // Large duration
    ];

    for duration in boundary_durations {
        if let Ok(session_id) = framework
            .create_session("test_user", duration, None, None)
            .await
        {
            // Verify session exists
            match framework.get_session(&session_id).await {
                Ok(Some(_)) => (),
                Ok(None) => (), // Might have expired immediately
                Err(_) => (),
            }
            // Cleanup
            let _ = framework.delete_session(&session_id).await;
        }
        // Error is acceptable for boundary values
    }
}

#[tokio::test]
async fn test_double_initialization_error() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);

    // First initialization should succeed
    framework.initialize().await.unwrap();

    // Second initialization should either succeed (idempotent) or fail gracefully
    match framework.initialize().await {
        Ok(_) => (), // Idempotent initialization is acceptable
        Err(e) => {
            // Error should be descriptive and not a panic
            assert!(!e.to_string().is_empty());
            let error_msg = e.to_string().to_lowercase();
            assert!(
                error_msg.contains("already initialized")
                    || error_msg.contains("initialized")
                    || error_msg.contains("duplicate")
            );
        }
    }

    // Framework should still be functional after double init attempt
    let session_result = framework
        .create_session("test_user", Duration::from_secs(3600), None, None)
        .await;
    assert!(session_result.is_ok(), "Framework should remain functional");
}

#[tokio::test]
async fn test_invalid_config_handling() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    // Test framework creation with potentially problematic configs
    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);

    // Initialization should handle any config issues gracefully
    match framework.initialize().await {
        Ok(_) => (), // Success is expected for default config
        Err(e) => {
            // Any error should be descriptive
            assert!(!e.to_string().is_empty());
        }
    }
}

#[tokio::test]
async fn test_resource_exhaustion_recovery() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Try to exhaust session storage
    let mut session_ids = Vec::new();
    let mut creation_failed = false;

    for i in 0..5000 {
        match framework
            .create_session(
                &format!("stress_user_{}", i),
                Duration::from_secs(3600),
                None,
                None,
            )
            .await
        {
            Ok(session_id) => session_ids.push(session_id),
            Err(_) => {
                creation_failed = true;
                break;
            }
        }
    }

    // Framework should either handle all sessions or fail gracefully
    if creation_failed {
        println!(
            "Session creation failed at {} sessions (acceptable)",
            session_ids.len()
        );
    } else {
        println!("Created {} sessions successfully", session_ids.len());
    }

    // Framework should still be responsive after stress
    let test_session = framework
        .create_session("recovery_test", Duration::from_secs(3600), None, None)
        .await;

    // Should either succeed or fail gracefully (not hang/crash)
    if let Ok(session_id) = test_session {
        // Verify we can still operate normally
        assert!(framework.get_session(&session_id).await.is_ok());
        let _ = framework.delete_session(&session_id).await;
    }
    // Acceptable if resource constrained

    // Cleanup what we can
    for session_id in session_ids.into_iter().take(100) {
        let _ = framework.delete_session(&session_id).await;
    }
}

#[tokio::test]
async fn test_error_message_consistency() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test that similar error conditions produce consistent error messages
    let test_cases = vec![
        ("", "empty_input"),
        ("nonexistent", "nonexistent_user"),
        ("user\0", "null_byte_input"),
        ("👤", "unicode_input"),
    ];

    for (input, description) in test_cases {
        let credential = Credential::password(input, "test_password");

        // Test the same error condition multiple times
        let mut error_messages = Vec::new();
        for _ in 0..3 {
            match framework.authenticate("password", credential.clone()).await {
                Ok(_) => error_messages.push("SUCCESS".to_string()),
                Err(e) => error_messages.push(e.to_string()),
            }
        }

        // All error messages should be identical for the same input
        let first_message = &error_messages[0];
        let all_same = error_messages.iter().all(|msg| msg == first_message);

        assert!(
            all_same,
            "Inconsistent error messages for {}: {:?}",
            description, error_messages
        );
    }
}
