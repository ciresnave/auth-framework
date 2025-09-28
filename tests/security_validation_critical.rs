//! Critical security validation test to ensure JWT signature bypass vulnerability is fixed

use auth_framework::{AuthConfig, AuthFramework};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    scope: String,
}

#[tokio::test]
async fn test_jwt_signature_validation() {
    println!("🔒 Testing JWT signature validation...");

    let config = AuthConfig::new()
        .secret("Y3J5cHRvX3JhbmRvbV9zZWNyZXRfMTIzNDU2Nzg5MA==".to_string())
        .issuer("auth-framework".to_string())
        .audience("auth-framework".to_string());

    let auth_framework = AuthFramework::new(config);

    let now = Utc::now().timestamp();
    let claims = TestClaims {
        sub: "admin".to_string(),
        iss: "auth-framework".to_string(),
        aud: "auth-framework".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        iat: now,
        nbf: now,
        jti: "test-jwt-id".to_string(),
        scope: "read write".to_string(),
    };

    // Test 1: JWT with WRONG signature key (should fail)
    let wrong_key = EncodingKey::from_secret(b"wrong-key");
    let malicious_jwt = encode(&Header::default(), &claims, &wrong_key).unwrap();

    let validation_result = auth_framework
        .token_manager()
        .validate_jwt_token(&malicious_jwt);

    assert!(
        validation_result.is_err(),
        "🚨 SECURITY FAILURE: Malicious JWT was accepted!"
    );
    println!("✅ SECURITY PASS: JWT with wrong signature rejected");

    // Test 2: Create a proper JWT using the framework's TokenManager (should pass)
    let token_manager = auth_framework.token_manager();
    let valid_jwt = token_manager
        .create_jwt_token("admin", vec!["read".to_string(), "write".to_string()], None)
        .unwrap();

    let valid_result = token_manager.validate_jwt_token(&valid_jwt);

    match &valid_result {
        Ok(claims) => {
            println!("✅ Valid JWT accepted with subject: {}", claims.sub);
        }
        Err(e) => {
            println!("❌ Valid JWT was rejected with error: {:?}", e);
        }
    }

    assert!(
        valid_result.is_ok(),
        "❌ Valid JWT was incorrectly rejected: {:?}",
        valid_result.err()
    );
    println!("✅ SECURITY PASS: Valid JWT with correct signature accepted");

    println!("🎉 JWT signature validation working correctly!");
}

#[tokio::test]
async fn test_no_insecure_payload_extraction() {
    println!("🔍 Verifying dangerous extract_validated_context function was removed...");

    let source_code = std::fs::read_to_string("src/integrations/actix_web.rs").unwrap();

    if source_code.contains("extract_validated_context") {
        assert!(
            source_code.contains("SECURITY NOTE: This function was removed"),
            "🚨 CRITICAL: extract_validated_context function still exists!"
        );
        println!("✅ SECURITY PASS: Dangerous function properly removed and documented");
    } else {
        println!("✅ SECURITY PASS: No dangerous payload extraction functions found");
    }

    assert!(
        source_code.contains("validate_jwt_token"),
        "❌ Missing secure JWT validation in ActixWeb integration"
    );
    println!("✅ SECURITY PASS: Secure JWT validation function is being used");

    println!("🎉 Code audit passed - no insecure JWT payload extraction found!");
}
