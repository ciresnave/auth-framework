//! A JWT introspection response signed with a key that was ever the same in every deployment must
//! not verify.

use auth_framework::server::{
    BasicIntrospectionResponse, JwtIntrospectionConfig, JwtIntrospectionManager,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::collections::HashMap;

/// The fixed key older releases used for every `JwtIntrospectionManager`.
const OLD_FIXED_KEY: &[u8] = b"introspection_jwt_secret_key_change_in_production";

fn forged_active_response(config: &JwtIntrospectionConfig, key: &[u8]) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": config.issuer,
        "aud": config.default_audience,
        "jti": "forged",
        "iat": now,
        "exp": now + 300,
        "active": true,
        "scope": "admin",
        "sub": "attacker",
    });
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key),
    )
    .unwrap()
}

fn basic_active() -> BasicIntrospectionResponse {
    BasicIntrospectionResponse {
        active: true,
        scope: Some("read".to_string()),
        client_id: Some("c".to_string()),
        username: Some("u".to_string()),
        token_type: Some("access_token".to_string()),
        exp: None,
        iat: None,
        nbf: None,
        sub: Some("u".to_string()),
        aud: None,
        iss: None,
        jti: None,
        additional_claims: HashMap::new(),
    }
}

#[test]
fn a_response_forged_with_the_old_fixed_key_is_rejected() {
    let config = JwtIntrospectionConfig::default();
    let manager = JwtIntrospectionManager::new(config.clone()).unwrap();
    let forged = forged_active_response(&config, OLD_FIXED_KEY);
    assert!(
        manager.verify_jwt_response(&forged).is_err(),
        "a response signed with the published fixed key verified"
    );
}

#[test]
fn the_forgery_check_is_not_vacuous() {
    // Control: the same forging code with the key the manager really uses would verify, so the
    // rejection above is about the key. Use a manager's own response to prove verification works.
    let config = JwtIntrospectionConfig::default();
    let manager = JwtIntrospectionManager::new(config).unwrap();
    let own = manager
        .create_jwt_response(basic_active(), None, None)
        .unwrap();
    assert!(manager.verify_jwt_response(&own).is_ok());
}

#[test]
fn two_managers_do_not_share_a_signing_key() {
    let a = JwtIntrospectionManager::new(JwtIntrospectionConfig::default()).unwrap();
    let b = JwtIntrospectionManager::new(JwtIntrospectionConfig::default()).unwrap();
    let from_a = a.create_jwt_response(basic_active(), None, None).unwrap();
    assert!(
        a.verify_jwt_response(&from_a).is_ok(),
        "control: own response verifies"
    );
    assert!(
        b.verify_jwt_response(&from_a).is_err(),
        "a response from one manager verified under another: they share a key"
    );
}

#[test]
fn managers_given_the_same_secret_verify_each_others_responses() {
    let secret = [7u8; 32];
    let a = JwtIntrospectionManager::with_hmac_secret(JwtIntrospectionConfig::default(), &secret)
        .unwrap();
    let b = JwtIntrospectionManager::with_hmac_secret(JwtIntrospectionConfig::default(), &secret)
        .unwrap();
    let from_a = a.create_jwt_response(basic_active(), None, None).unwrap();
    assert!(b.verify_jwt_response(&from_a).is_ok());
}

#[test]
fn managers_given_different_secrets_do_not() {
    let a =
        JwtIntrospectionManager::with_hmac_secret(JwtIntrospectionConfig::default(), &[1u8; 32])
            .unwrap();
    let b =
        JwtIntrospectionManager::with_hmac_secret(JwtIntrospectionConfig::default(), &[2u8; 32])
            .unwrap();
    let from_a = a.create_jwt_response(basic_active(), None, None).unwrap();
    assert!(b.verify_jwt_response(&from_a).is_err());
}

#[test]
fn a_short_secret_is_refused() {
    let config = JwtIntrospectionConfig::default();
    assert!(JwtIntrospectionManager::with_hmac_secret(config.clone(), &[9u8; 31]).is_err());
    assert!(JwtIntrospectionManager::with_hmac_secret(config, &[]).is_err());
}

#[test]
fn a_response_forged_with_the_old_key_is_rejected_by_a_shared_secret_manager_too() {
    let config = JwtIntrospectionConfig::default();
    let manager = JwtIntrospectionManager::with_hmac_secret(config.clone(), &[5u8; 32]).unwrap();
    let forged = forged_active_response(&config, OLD_FIXED_KEY);
    assert!(manager.verify_jwt_response(&forged).is_err());
}
