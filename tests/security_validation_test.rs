//! Critical security validation test to ensure JWT signature bypass vulnerability is fixed
//!
//! This test verifies that the authentication framework properly validates JWT signatures
//! and does not allow bypass through unsigned tokens.

use auth_framework::{
    AuthConfig, AuthFramework,
    errors::{AuthError, TokenError},
};
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct MaliciousJwtClaims {
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
async fn test_jwt_signature_bypass_prevention() {
    println!("🔒 Testing JWT signature bypass prevention...");

    // Create a secure authentication framework
    let config = AuthConfig::new()
        .secret("test-secret-for-security-validation-32chars".to_string())
        .issuer("auth-framework".to_string())
        .audience("auth-framework".to_string());

    let auth_framework = AuthFramework::new(config);
    println!("✅ AuthFramework initialized with secure configuration");

    // Test 1: Attempt to create a malicious JWT without proper signing
    let now = Utc::now().timestamp();
    let malicious_claims = MaliciousJwtClaims {
        sub: "admin".to_string(),
        iss: "auth-framework".to_string(),
        aud: "auth-framework".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
        iat: now,
        nbf: now,
        jti: "malicious-jwt-id".to_string(),
        scope: "admin super_admin".to_string(),
    };

    // Create a JWT with WRONG key (attacker scenario)
    let wrong_key = EncodingKey::from_secret(b"wrong-key-for-attack");
    let malicious_jwt = encode(&Header::default(), &malicious_claims, &wrong_key).unwrap();

    println!(
        "🚨 Created malicious JWT with wrong signing key: {}",
        &malicious_jwt[0..50]
    );

    // Test 2: Verify the framework REJECTS the malicious JWT
    let validation_result = auth_framework
        .token_manager()
        .validate_jwt_token(&malicious_jwt);

    match validation_result {
        Ok(_) => {
            panic!("🚨 CRITICAL SECURITY FAILURE: Malicious JWT was accepted!");
        }
        Err(AuthError::Token(TokenError::Invalid { message })) => {
            println!("✅ SECURITY PASS: JWT with wrong signature properly rejected");
            println!("   Error message: {}", message);
            // Accept any "Invalid token format" or signature-related error
            assert!(
                message.contains("signature")
                    || message.contains("validation")
                    || message.contains("Invalid token format")
            );
        }
        Err(other_error) => {
            println!("✅ SECURITY PASS: JWT rejected with error: {}", other_error);
        }
    }

    // Test 3: Test unsigned JWT (no signature)
    let header_payload = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&malicious_claims).unwrap())
    );
    let unsigned_jwt = format!("{}.FAKE_SIGNATURE", header_payload);

    println!("🚨 Testing unsigned JWT: {}", &unsigned_jwt[0..50]);

    let unsigned_result = auth_framework
        .token_manager()
        .validate_jwt_token(&unsigned_jwt);

    match unsigned_result {
        Ok(_) => {
            panic!("🚨 CRITICAL SECURITY FAILURE: Unsigned JWT was accepted!");
        }
        Err(_) => {
            println!("✅ SECURITY PASS: Unsigned JWT properly rejected");
        }
    }

    // Test 4: Test properly signed JWT using framework's TokenManager (should pass)
    println!("✅ Testing properly signed JWT...");

    let token_manager = auth_framework.token_manager();
    let valid_jwt = token_manager
        .create_jwt_token("admin", vec!["read".to_string(), "write".to_string()], None)
        .unwrap();

    let valid_result = token_manager.validate_jwt_token(&valid_jwt);

    match valid_result {
        Ok(claims) => {
            println!(
                "✅ SECURITY PASS: Valid JWT accepted with claims for user: {}",
                claims.sub
            );
            assert_eq!(claims.sub, "admin");
        }
        Err(e) => {
            panic!("❌ UNEXPECTED: Valid JWT was rejected: {}", e);
        }
    }

    println!("🎉 ALL SECURITY TESTS PASSED - JWT signature bypass vulnerability is FIXED!");
}

#[tokio::test]
async fn test_no_insecure_payload_extraction() {
    println!("🔍 Verifying no direct payload extraction functions exist...");

    // This test ensures that the dangerous extract_validated_context function
    // has been completely removed and replaced with secure validation

    let source_code = std::fs::read_to_string("src/integrations/actix_web.rs").unwrap();

    if source_code.contains("extract_validated_context") {
        if source_code.contains("SECURITY NOTE: This function was removed") {
            println!("✅ SECURITY PASS: Dangerous function properly removed and documented");
        } else {
            panic!(
                "🚨 CRITICAL SECURITY FAILURE: extract_validated_context function still exists!"
            );
        }
    } else {
        println!("✅ SECURITY PASS: No dangerous payload extraction functions found");
    }

    // Verify JWT validation is used instead
    if source_code.contains("validate_jwt_token") {
        println!("✅ SECURITY PASS: Secure JWT validation function is being used");
    } else {
        panic!("❌ Missing secure JWT validation in ActixWeb integration");
    }
}
