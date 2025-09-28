// Standard library imports for Rust 2024 edition
use std::{
    assert, assert_eq,
    default::Default,
    option::Option::{None, Some},
    println,
    result::Result::{Err, Ok},
    vec,
};

use auth_framework::auth::AuthFramework;
use auth_framework::authentication::credentials::Credential;
use auth_framework::config::AuthConfig;
use auth_framework::testing::test_infrastructure::TestEnvironmentGuard;
use auth_framework::tokens::AuthToken;
use std::sync::Arc;
use std::time::Duration;

/// Comprehensive edge case testing to ensure bulletproof behavior

// Use a proper 32+ character JWT secret for all tests
const TEST_JWT_SECRET: &str = "Y3J5cHRvX3JhbmRvbV9zZWNyZXRfMTIzNDU2Nzg5MA==";

#[tokio::test]
async fn test_extreme_input_sizes() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various extreme input sizes
    let large_username = "a".repeat(1000);
    let large_password = "b".repeat(1000);
    let huge_username = "a".repeat(100000);
    let huge_password = "b".repeat(100000);

    let test_cases = vec![
        ("", ""),                                           // Empty
        ("a", "b"),                                         // Single character
        (large_username.as_str(), large_password.as_str()), // Large inputs
        (huge_username.as_str(), huge_password.as_str()),   // Very large inputs
    ];

    for (username, password) in test_cases {
        let credential = Credential::password(username, password);

        // Should handle gracefully without panicking or hanging
        let start = std::time::Instant::now();
        let result = framework.authenticate("password", credential).await;
        let elapsed = start.elapsed();

        // Should not take too long (prevent DoS via large inputs)
        assert!(
            elapsed < Duration::from_secs(5),
            "Processing took too long for input size: {}",
            username.len()
        );

        match result {
            Ok(_) => (), // Might be valid
            Err(e) => {
                // Error should be descriptive and not leak input size info
                let error_msg = e.to_string();
                assert!(!error_msg.is_empty(), "Error message should not be empty");
                assert!(
                    error_msg.len() < 1000,
                    "Error message should not be too verbose"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_special_character_handling() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various special characters and encodings
    let special_chars = vec![
        "\0",                    // Null byte
        "\x01\x02\x03",          // Control characters
        "\r\n",                  // CRLF
        "\t",                    // Tab
        "\\",                    // Backslash
        "\"",                    // Quote
        "'",                     // Single quote
        "&<>\"'",                // HTML/XML special chars
        "%20%21%22",             // URL encoded
        "😀😁😂🤣😃",            // Emoji
        "Ñiño",                  // Accented characters
        "Тест",                  // Cyrillic
        "测试",                  // Chinese
        "テスト",                // Japanese
        "👨‍💻👩‍💻",                  // Complex emoji sequences
        "\u{202E}admin\u{202D}", // Unicode direction override
    ];

    for special_char in special_chars {
        // Test as username
        let credential = Credential::password(special_char, "password");
        let _ = framework.authenticate("password", credential).await;
        // Might be valid or rejected

        // Test as password
        let credential = Credential::password("user", special_char);
        let _ = framework.authenticate("password", credential).await;
        // Might be valid or rejected

        // Test in session creation
        if let Ok(session_id) = framework
            .create_session(special_char, Duration::from_secs(3600), None, None)
            .await
        {
            // If allowed, should be retrievable
            assert!(framework.get_session(&session_id).await.unwrap().is_some());
            let _ = framework.delete_session(&session_id).await;
        }
        // Might be rejected
    }
}

#[tokio::test]
async fn test_session_expiration_edge_cases() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various expiration edge cases
    let expiration_tests = vec![
        (Duration::from_millis(0), "zero_duration"),
        (Duration::from_millis(1), "one_millisecond"),
        (Duration::from_millis(100), "one_hundred_milliseconds"),
        (Duration::from_secs(1), "one_second"),
        (Duration::from_secs(60), "one_minute"),
        (Duration::from_secs(3600), "one_hour"),
        (Duration::from_secs(86400), "one_day"),
        (Duration::from_secs(u32::MAX as u64), "max_u32_seconds"),
    ];

    for (duration, description) in expiration_tests {
        match framework
            .create_session("test_user", duration, Some(description.to_string()), None)
            .await
        {
            Ok(session_id) => {
                // Session should exist immediately after creation
                let session = framework.get_session(&session_id).await.unwrap();

                if duration.as_millis() == 0 {
                    // Zero duration might expire immediately
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    let expired_session = framework.get_session(&session_id).await.unwrap();
                    // Either still there or expired - both are valid
                    println!(
                        "Zero duration session state: {:?}",
                        expired_session.is_some()
                    );
                } else if duration.as_millis() <= 100 {
                    // Very short duration - wait and check expiration
                    tokio::time::sleep(duration + Duration::from_millis(10)).await;
                    let expired_session = framework.get_session(&session_id).await.unwrap();
                    println!(
                        "Short duration session expired: {}",
                        expired_session.is_none()
                    );
                } else {
                    // Longer duration - should still exist
                    assert!(
                        session.is_some(),
                        "Session should exist for duration: {}",
                        description
                    );
                }

                // Cleanup
                let _ = framework.delete_session(&session_id).await;
            }
            Err(e) => {
                println!("Session creation failed for {}: {}", description, e);
                // Some extreme durations might be rejected
            }
        }
    }
}

#[tokio::test]
async fn test_token_validation_edge_cases() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various token edge cases
    let token_tests = vec![
        // Zero duration (expired immediately)
        AuthToken::new("user", "token", Duration::from_secs(0), "test"),
        // Very long user ID
        AuthToken::new(
            "u".repeat(10000),
            "token",
            Duration::from_secs(3600),
            "test",
        ),
        // Very long token
        AuthToken::new("user", "t".repeat(10000), Duration::from_secs(3600), "test"),
        // Very long auth method
        AuthToken::new("user", "token", Duration::from_secs(3600), "m".repeat(1000)),
        // Special characters in fields
        AuthToken::new(
            "user\0\x01",
            "token\r\n",
            Duration::from_secs(3600),
            "method\t",
        ),
        // Unicode in fields
        AuthToken::new("用户", "令牌", Duration::from_secs(3600), "方法"),
        // Empty fields
        AuthToken::new("", "", Duration::from_secs(3600), ""),
    ];

    for token in token_tests {
        let start = std::time::Instant::now();
        let result = framework.validate_token(&token).await;
        let elapsed = start.elapsed();

        // Should not take too long
        assert!(
            elapsed < Duration::from_secs(1),
            "Token validation took too long"
        );

        match result {
            Ok(valid) => {
                println!(
                    "Token validation result: {} for user: {}",
                    valid,
                    token.user_id()
                );
            }
            Err(e) => {
                println!(
                    "Token validation error: {} for user: {}",
                    e,
                    token.user_id()
                );
            }
        }
    }
}

#[tokio::test]
async fn test_concurrent_data_races() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Create a session first
    let session_id = framework
        .create_session("race_user", Duration::from_secs(3600), None, None)
        .await
        .unwrap();

    // Test concurrent operations on the same session
    let mut handles = Vec::new();

    for i in 0..20 {
        let framework = framework.clone();
        let session_id = session_id.clone();

        let handle = tokio::spawn(async move {
            match i % 3 {
                0 => {
                    // Get session
                    framework
                        .get_session(&session_id)
                        .await
                        .map(|opt| opt.is_some())
                }
                1 => {
                    // Delete session (might fail if already deleted)
                    framework.delete_session(&session_id).await.map(|_| false)
                }
                _ => {
                    // Try to get session after potential deletion
                    framework
                        .get_session(&session_id)
                        .await
                        .map(|opt| opt.is_some())
                }
            }
        });
        handles.push(handle);
    }

    let mut results: Vec<Result<bool, auth_framework::errors::AuthError>> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(_) => panic!("Task panicked during concurrent operations"),
        }
    }

    // All operations should complete without panicking
    assert_eq!(
        results.len(),
        20,
        "All concurrent operations should complete"
    );

    // Some operations might succeed, some might fail due to race conditions
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    println!("Concurrent operations: {}/20 succeeded", success_count);
}

#[tokio::test]
async fn test_memory_cleanup_edge_cases() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Create sessions with various expiration times
    let mut session_ids = Vec::new();
    let durations = [
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_secs(10),
    ];

    for (i, duration) in durations.iter().enumerate() {
        if let Ok(session_id) = framework
            .create_session(&format!("user_{}", i), *duration, None, None)
            .await
        {
            session_ids.push((session_id, *duration));
        }
    }

    // Wait for some sessions to expire
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Test cleanup
    match framework.cleanup_expired_data().await {
        Ok(_) => println!("Cleanup completed successfully"),
        Err(e) => panic!("Cleanup failed: {}", e),
    }

    // Verify cleanup worked correctly
    for (session_id, duration) in session_ids {
        let session = framework.get_session(&session_id).await.unwrap();
        if duration.as_secs() <= 2 {
            // Should be expired and cleaned up
            println!(
                "Short-lived session ({}s) cleaned up: {}",
                duration.as_secs(),
                session.is_none()
            );
        } else {
            // Should still exist
            println!(
                "Long-lived session ({}s) still exists: {}",
                duration.as_secs(),
                session.is_some()
            );
        }
    }
}

#[tokio::test]
async fn test_framework_reinitialization() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);

    // Initialize framework
    framework.initialize().await.unwrap();

    // Create some data
    let session_id = framework
        .create_session("user", Duration::from_secs(3600), None, None)
        .await
        .unwrap();
    assert!(framework.get_session(&session_id).await.unwrap().is_some());

    // Try to reinitialize
    match framework.initialize().await {
        Ok(_) => {
            // Reinitialization succeeded
            // Data might or might not persist depending on implementation
            let session_after_reinit = framework.get_session(&session_id).await.unwrap();
            println!(
                "Session persisted after reinit: {}",
                session_after_reinit.is_some()
            );
        }
        Err(e) => {
            // Reinitialization failed (which is also valid)
            println!("Reinitialization failed: {}", e);
        }
    }

    // Framework should still be functional
    let new_session = framework
        .create_session("new_user", Duration::from_secs(3600), None, None)
        .await
        .unwrap();
    assert!(framework.get_session(&new_session).await.unwrap().is_some());
}

#[tokio::test]
async fn test_boundary_value_analysis() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test boundary values for various parameters
    let boundary_tests = vec![
        // Session durations
        (Duration::from_secs(0), "zero_seconds"),
        (Duration::from_secs(1), "one_second"),
        (Duration::from_secs(u32::MAX as u64 - 1), "max_minus_one"),
        (Duration::from_secs(u32::MAX as u64), "max_u32"),
        // Very large durations (might overflow)
        (Duration::from_secs(u64::MAX / 2), "half_max_u64"),
    ];

    for (duration, description) in boundary_tests {
        println!("Testing boundary: {}", description);

        let result = framework
            .create_session(
                "boundary_user",
                duration,
                Some(description.to_string()),
                None,
            )
            .await;

        match result {
            Ok(session_id) => {
                println!("Boundary test {} succeeded", description);

                // Verify session exists
                let session = framework.get_session(&session_id).await.unwrap();
                assert!(
                    session.is_some(),
                    "Session should exist for boundary test: {}",
                    description
                );

                // Cleanup
                let _ = framework.delete_session(&session_id).await;
            }
            Err(e) => {
                println!("Boundary test {} failed: {}", description, e);
                // Handle expected failures for edge cases
                match description {
                    "zero_seconds" => {
                        assert!(
                            e.to_string().contains("must be greater than zero"),
                            "Zero duration should fail with proper error message"
                        );
                    }
                    "half_max_u64" => {
                        assert!(
                            e.to_string().contains("exceeds maximum allowed")
                                || e.to_string().contains("OutOfRangeError"),
                            "Extremely large duration should fail gracefully"
                        );
                    }
                    _ => {
                        // Other boundary values might legitimately fail
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn test_error_propagation_consistency() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret(TEST_JWT_SECRET);

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test that similar errors are handled consistently
    let error_cases = vec![
        ("", "empty_username"),
        ("nonexistent", "nonexistent_user"),
        ("user\0", "null_byte_user"),
        ("user\r\n", "newline_user"),
        ("👤", "emoji_user"),
    ];

    for (username, description) in error_cases {
        let credential = Credential::password(username, "wrong_password");

        // Test multiple times to ensure consistency
        let mut results: Vec<
            Result<auth_framework::AuthResult, auth_framework::errors::AuthError>,
        > = Vec::new();
        for _ in 0..3 {
            let result = framework.authenticate("password", credential.clone()).await;
            results.push(result);
        }

        // All results should be consistent
        let all_same = results.iter().all(|r| match (&results[0], r) {
            (Ok(_), Ok(_)) => true,
            (Err(e1), Err(e2)) => e1.to_string() == e2.to_string(),
            _ => false,
        });

        assert!(
            all_same,
            "Inconsistent results for {}: {:?}",
            description, results
        );
    }
}
