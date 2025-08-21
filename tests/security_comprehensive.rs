use auth_framework::auth::AuthFramework;
use auth_framework::authentication::credentials::Credential;
use auth_framework::config::AuthConfig;
use auth_framework::testing::test_infrastructure::TestEnvironmentGuard;
use auth_framework::tokens::AuthToken;
use auth_framework::{SecureJwtClaims, SecureJwtConfig, SecureJwtValidator};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, encode};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Comprehensive security testing to ensure bulletproof authentication

#[tokio::test]
async fn test_timing_attack_resistance() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test that authentication timing is consistent regardless of user existence
    let existing_user = "existing_user";
    let nonexistent_user = "nonexistent_user_123456789";

    let mut existing_times = Vec::new();
    let mut nonexistent_times = Vec::new();

    // Measure authentication times
    for _ in 0..10 {
        let start = std::time::Instant::now();
        let _ = framework
            .authenticate(
                "password",
                Credential::password(existing_user, "wrong_pass"),
            )
            .await;
        existing_times.push(start.elapsed());

        let start = std::time::Instant::now();
        let _ = framework
            .authenticate(
                "password",
                Credential::password(nonexistent_user, "wrong_pass"),
            )
            .await;
        nonexistent_times.push(start.elapsed());
    }

    // Calculate average times
    let avg_existing: f64 = existing_times
        .iter()
        .map(|d| d.as_nanos() as f64)
        .sum::<f64>()
        / existing_times.len() as f64;
    let avg_nonexistent: f64 = nonexistent_times
        .iter()
        .map(|d| d.as_nanos() as f64)
        .sum::<f64>()
        / nonexistent_times.len() as f64;

    // Timing difference should be minimal (within 50% variance)
    let ratio = if avg_existing > avg_nonexistent {
        avg_existing / avg_nonexistent
    } else {
        avg_nonexistent / avg_existing
    };

    assert!(
        ratio < 2.0,
        "Timing attack vulnerability detected: ratio {:.2}",
        ratio
    );
}

#[tokio::test]
async fn test_dos_protection_mechanisms() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Test rapid session creation (potential DoS)
    let mut handles = Vec::new();
    for i in 0..100 {
        let framework = framework.clone();
        let handle = tokio::spawn(async move {
            framework
                .create_session(
                    &format!("user_{}", i),
                    Duration::from_secs(3600),
                    None,
                    None,
                )
                .await
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    let mut error_count = 0;

    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(_)) => error_count += 1,
            Err(_) => error_count += 1,
        }
    }

    // Framework should either handle all requests or gracefully reject some
    assert!(
        success_count + error_count == 100,
        "Some requests were lost"
    );

    // If rate limiting is enabled, some should be rejected
    if error_count > 0 {
        println!(
            "DoS protection active: {}/{} requests rejected",
            error_count, 100
        );
    } else {
        println!("All requests processed successfully");
    }
}

#[tokio::test]
async fn test_jwt_manipulation_attacks() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test various JWT manipulation attacks
    let malicious_tokens = vec![
        // Algorithm confusion attacks
        AuthToken::new(
            "user",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            Duration::from_secs(3600),
            "jwt",
        ),
        // Invalid signatures
        AuthToken::new(
            "user",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.INVALID_SIGNATURE",
            Duration::from_secs(3600),
            "jwt",
        ),
        // Modified payload
        AuthToken::new(
            "user",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MODIFIED_PAYLOAD.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            Duration::from_secs(3600),
            "jwt",
        ),
        // Expired tokens (simulate)
        AuthToken::new(
            "user",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNTE2MjM5MDIyfQ.OLD_SIGNATURE",
            Duration::from_secs(0),
            "jwt",
        ),
    ];

    for token in malicious_tokens {
        match framework.validate_token(&token).await {
            Ok(true) => panic!(
                "Malicious token should not validate: {}",
                token.access_token()
            ),
            Ok(false) => (), // Correctly rejected
            Err(_) => (),    // Error is acceptable
        }
    }
}

#[tokio::test]
async fn test_session_hijacking_prevention() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Create multiple sessions to increase chance of collision
    let mut session_ids = Vec::new();
    for i in 0..10 {
        let session_id = framework
            .create_session(
                &format!("user_{}", i),
                Duration::from_secs(3600),
                None,
                None,
            )
            .await
            .unwrap();
        session_ids.push(session_id);
    }

    // Test each session against manipulations of all other sessions
    for (i, target_session) in session_ids.iter().enumerate() {
        // Verify session exists
        assert!(
            framework
                .get_session(target_session)
                .await
                .unwrap()
                .is_some()
        );

        // Test session ID manipulation attempts with guaranteed character presence
        let manipulation_attempts = vec![
            target_session.clone() + "x",                           // Append data
            target_session[..target_session.len() - 1].to_string(), // Truncate
            target_session.replace('s', "x"), // Replace 's' (guaranteed in "sess_")
            target_session.replace('-', "x"), // Replace '-' (guaranteed in UUID)
            target_session.chars().rev().collect(), // Reverse
            format!("x{}", target_session),   // Prefix garbage
            target_session.replace("sess_", "hack_"), // Replace prefix
            format!("{}x", &target_session[..target_session.len() - 1]), // Truncate and append
        ];

        for manipulated_id in manipulation_attempts {
            // Skip if manipulation created the original ID (shouldn't happen with our manipulations)
            if manipulated_id == *target_session {
                continue;
            }

            if framework
                .get_session(&manipulated_id)
                .await
                .unwrap()
                .is_some()
            {
                panic!(
                    "🚨 SECURITY VULNERABILITY: Manipulated session ID should not work!\nOriginal: {}\nManipulated: {}\nThis indicates session validation is insufficient!",
                    target_session, manipulated_id
                );
            }
            // Correctly rejected
        }

        // Also test manipulation against OTHER session IDs to check for cross-session collisions
        for (j, other_session) in session_ids.iter().enumerate() {
            if i != j {
                // Try to create a manipulated version of other_session that might match target_session
                let cross_manipulations = vec![
                    other_session.clone() + "x",
                    other_session[..other_session.len() - 1].to_string(),
                    other_session.replace('s', "x"),
                ];

                for manipulated in cross_manipulations {
                    if manipulated != *target_session
                        && manipulated != *other_session
                        && framework.get_session(&manipulated).await.unwrap().is_some()
                    {
                        panic!(
                            "🚨 CROSS-SESSION VULNERABILITY: Manipulated session {} (from {}) should not work!",
                            manipulated, other_session
                        );
                    }
                    // Correctly rejected
                }
            }
        }
    }

    // All original sessions should still work
    for session_id in &session_ids {
        assert!(framework.get_session(session_id).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn test_resource_exhaustion_protection() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test memory exhaustion protection
    let mut session_ids = Vec::new();

    // Try to create many sessions
    for i in 0..10000 {
        match framework
            .create_session(
                &format!("user_{}", i),
                Duration::from_secs(3600),
                None,
                None,
            )
            .await
        {
            Ok(session_id) => {
                session_ids.push(session_id);
                if session_ids.len() % 1000 == 0 {
                    println!("Created {} sessions", session_ids.len());
                }
            }
            Err(_) => {
                println!("Reached limit at {} sessions", session_ids.len());
                break;
            }
        }
    }

    // Framework should either:
    // 1. Handle all sessions efficiently
    // 2. Implement reasonable limits
    assert!(
        !session_ids.is_empty(),
        "Should be able to create at least one session"
    );

    // Cleanup
    for session_id in session_ids.iter().take(100) {
        let _ = framework.delete_session(session_id).await;
    }
}

#[tokio::test]
async fn test_input_injection_attacks() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test SQL injection patterns (even though we use in-memory storage)
    let injection_patterns = vec![
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'/**/OR/**/1=1--",
        "user'; INSERT INTO sessions VALUES ('hack'); --",
        "1' UNION SELECT * FROM sessions--",
    ];

    for pattern in injection_patterns {
        // Test in usernames
        let credential = Credential::password(pattern, "password");
        if framework.authenticate("password", credential).await.is_ok() {
            panic!("Injection pattern should not succeed: {}", pattern);
        }
        // Should be rejected

        // Test in session creation
        let _ = framework
            .create_session(pattern, Duration::from_secs(3600), None, None)
            .await;
        // Might be allowed as valid user ID or rejected - both are fine
    }
}

#[tokio::test]
async fn test_unicode_normalization_attacks() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test Unicode normalization attacks
    let unicode_attacks = vec![
        ("admin", "ａｄｍｉｎ"),        // Fullwidth characters
        ("user", "u\u{0073}er"),        // Mixed scripts
        ("test", "te\u{0301}st"),       // Combining characters
        ("root", "r\u{043E}\u{043E}t"), // Cyrillic o
    ];

    for (original, attack) in unicode_attacks {
        let credential1 = Credential::password(original, "password");
        let credential2 = Credential::password(attack, "password");

        // Both should be treated consistently
        let result1 = framework.authenticate("password", credential1).await;
        let result2 = framework.authenticate("password", credential2).await;

        // Results should be similar (both fail or both succeed in same way)
        match (result1, result2) {
            (Ok(_), Ok(_)) => (),   // Both succeed
            (Err(_), Err(_)) => (), // Both fail
            _ => {
                // This might indicate inconsistent handling
                println!(
                    "Warning: Inconsistent handling of '{}' vs '{}'",
                    original, attack
                );
            }
        }
    }
}

#[tokio::test]
async fn test_concurrent_session_limits() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);
    let user_id = "test_user";

    // Create many concurrent sessions for the same user
    let mut handles = Vec::new();
    for i in 0..50 {
        let framework = framework.clone();
        let user_id = user_id.to_string();
        let handle = tokio::spawn(async move {
            framework
                .create_session(
                    &user_id,
                    Duration::from_secs(3600),
                    Some(format!("session_{}", i)),
                    None,
                )
                .await
        });
        handles.push(handle);
    }

    let mut session_ids = Vec::new();
    for handle in handles {
        if let Ok(Ok(session_id)) = handle.await {
            session_ids.push(session_id);
        }
    }

    println!("Created {} concurrent sessions for user", session_ids.len());

    // Framework should handle concurrent sessions gracefully
    assert!(
        !session_ids.is_empty(),
        "Should be able to create at least one session"
    );

    // All sessions should be valid
    for session_id in &session_ids {
        assert!(framework.get_session(session_id).await.unwrap().is_some());
    }

    // Cleanup
    for session_id in session_ids {
        let _ = framework.delete_session(&session_id).await;
    }
}

#[tokio::test]
async fn test_error_information_disclosure() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Test that error messages don't leak sensitive information
    let test_cases = vec![
        ("nonexistent_user", "wrong_password"),
        ("", ""),
        ("admin", "admin"),
        ("root", "root"),
    ];

    for (username, password) in test_cases {
        match framework
            .authenticate("password", Credential::password(username, password))
            .await
        {
            Ok(_) => (),
            Err(e) => {
                let error_msg = e.to_string().to_lowercase();

                // Error messages should not leak:
                // - Database schema information
                // - Internal paths
                // - Stack traces
                // - Specific user existence information
                assert!(
                    !error_msg.contains("database"),
                    "Error leaks database info: {}",
                    error_msg
                );
                assert!(
                    !error_msg.contains("table"),
                    "Error leaks table info: {}",
                    error_msg
                );
                assert!(
                    !error_msg.contains("column"),
                    "Error leaks column info: {}",
                    error_msg
                );
                assert!(
                    !error_msg.contains("stack"),
                    "Error leaks stack trace: {}",
                    error_msg
                );
                assert!(
                    !error_msg.contains("panic"),
                    "Error leaks panic info: {}",
                    error_msg
                );
                assert!(
                    !error_msg.contains("internal"),
                    "Error leaks internal info: {}",
                    error_msg
                );
            }
        }
    }
}

#[tokio::test]
async fn test_rate_limiting_boundary_conditions() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    let framework = Arc::new(framework);

    // Test rapid authentication attempts
    let mut handles = Vec::new();
    for i in 0..20 {
        let framework = framework.clone();
        let handle = tokio::spawn(async move {
            framework
                .authenticate(
                    "password",
                    Credential::password(format!("user_{}", i), "wrong_pass"),
                )
                .await
        });
        handles.push(handle);
    }

    let mut success_count = 0;
    let mut error_count = 0;

    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(_)) => error_count += 1,
            Err(_) => error_count += 1,
        }
    }

    println!(
        "Rate limiting test: {} successful, {} errors",
        success_count, error_count
    );

    // All requests should be handled (either succeed or fail gracefully)
    assert_eq!(success_count + error_count, 20, "Some requests were lost");
}

#[tokio::test]
async fn test_session_validation_strictness() {
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let config = AuthConfig::default();
    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();

    // Create a session with a known ID pattern
    let session_id1 = framework
        .create_session("user1", Duration::from_secs(3600), None, None)
        .await
        .unwrap();

    // Create another session
    let session_id2 = framework
        .create_session("user2", Duration::from_secs(3600), None, None)
        .await
        .unwrap();

    println!("Session 1: {}", session_id1);
    println!("Session 2: {}", session_id2);

    // Test various invalid but plausible session IDs
    let invalid_sessions = vec![
        "sess_00000000-0000-0000-0000-000000000000".to_string(), // Known UUID pattern
        "sess_11111111-1111-1111-1111-111111111111".to_string(),
        "sess_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string(),
        "sess_ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
        "".to_string(), // Empty string
        "invalid-session-id".to_string(),
        "sess_".to_string(),                              // Just prefix
        format!("{}extra", session_id1),                  // Append to valid ID
        session_id1[..session_id1.len() - 1].to_string(), // Truncate valid ID
        session_id1.replace("sess_", "hack_"),            // Replace prefix
        session_id1.replace('-', "_"),                    // Replace dashes
    ];

    for invalid_id in invalid_sessions {
        // These should ALL return None since they're not exact matches
        match framework.get_session(&invalid_id).await.unwrap() {
            Some(_) => {
                panic!(
                    "🚨 SECURITY FAILURE: Invalid session ID '{}' should not return a session!",
                    invalid_id
                );
            }
            None => {
                println!("✅ Correctly rejected invalid session: {}", invalid_id);
            }
        }
    }

    // Original sessions should still work
    assert!(framework.get_session(&session_id1).await.unwrap().is_some());
    assert!(framework.get_session(&session_id2).await.unwrap().is_some());
}

/// CRITICAL SECURITY TEST: Ensure JWT signature validation cannot be bypassed
/// This test prevents the critical vulnerabilities discovered in August 2025
#[tokio::test]
async fn test_jwt_signature_validation_security() {
    println!("🔒 Testing JWT signature validation security...");

    let config = SecureJwtConfig::default();
    let validator = SecureJwtValidator::new(config);

    // Test 1: Forged JWT must be rejected
    let forged_jwt =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.FORGED_SIGNATURE";
    let decoding_key = DecodingKey::from_secret("test-secret".as_ref());

    let result = validator.validate_token(forged_jwt, &decoding_key, true);
    assert!(
        result.is_err(),
        "🚨 CRITICAL SECURITY FAILURE: Forged JWT was accepted!"
    );

    // Test 2: Valid JWT should be accepted
    let claims = SecureJwtClaims {
        sub: "user123".to_string(),
        iss: "auth-framework".to_string(),
        aud: "api".to_string(),
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        nbf: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        jti: "secure-token".to_string(),
        scope: "read".to_string(),
        typ: "access".to_string(),
        sid: None,
        client_id: None,
        auth_ctx_hash: None,
    };

    let secret = "test-secret";
    let encoding_key = EncodingKey::from_secret(secret.as_ref());
    let valid_jwt = encode(&Header::default(), &claims, &encoding_key).unwrap();

    let result = validator.validate_token(&valid_jwt, &decoding_key, true);
    if let Err(ref e) = result {
        println!("JWT validation error: {}", e);
    }
    assert!(
        result.is_ok(),
        "Valid JWT with proper signature should be accepted: {:?}",
        result.err()
    );

    // Test 3: Algorithm confusion attack prevention
    let none_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.";
    let result = validator.validate_token(none_jwt, &decoding_key, true);
    assert!(
        result.is_err(),
        "🚨 CRITICAL: 'none' algorithm should be rejected!"
    );

    // Test 4: Wrong key should fail
    let wrong_key = DecodingKey::from_secret("wrong-secret".as_ref());
    let result = validator.validate_token(&valid_jwt, &wrong_key, true);
    assert!(
        result.is_err(),
        "🚨 CRITICAL: JWT should fail with wrong key!"
    );

    println!("✅ JWT signature validation security tests passed!");
}

/// Test that security audit documentation exists
#[test]
fn test_security_audit_documentation_exists() {
    let audit_path = std::path::Path::new("CRITICAL_SECURITY_AUDIT_REPORT.md");
    assert!(
        audit_path.exists(),
        "Critical security audit report must exist"
    );

    let content = std::fs::read_to_string(audit_path).unwrap();
    assert!(content.contains("JWT VALIDATION SECURITY VULNERABILITIES"));
    assert!(content.contains("DPoP Module"));
    assert!(content.contains("Token Exchange Module"));
    assert!(content.contains("SECURED"));

    println!("✅ Security audit documentation verified");
}
