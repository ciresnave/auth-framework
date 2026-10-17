//! The JARM manager must not sign with a key that is the same in every deployment.

use auth_framework::server::oidc::oidc_advanced_jarm::{
    AdvancedJarmConfig, AdvancedJarmManager, AuthorizationResponse, JarmDeliveryMode,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

/// The fixed development key older releases always signed with.
const OLD_FIXED_KEY: &[u8] = b"test_key_for_development_only";

fn hs256_config() -> AdvancedJarmConfig {
    AdvancedJarmConfig {
        supported_algorithms: vec![Algorithm::HS256],
        ..Default::default()
    }
}

fn sample_response() -> AuthorizationResponse {
    AuthorizationResponse {
        code: Some("auth_code_abc".into()),
        state: Some("state_xyz".into()),
        access_token: None,
        token_type: None,
        expires_in: None,
        scope: None,
        id_token: None,
        error: None,
        error_description: None,
    }
}

/// Whether `token` verifies under the old fixed key (signature only; claims are not checked).
fn verifies_under_old_key(token: &str) -> bool {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(OLD_FIXED_KEY),
        &validation,
    )
    .is_ok()
}

#[test]
fn the_check_can_tell_a_token_signed_with_the_old_key() {
    // Positive control for `verifies_under_old_key`.
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({"sub": "x"}),
        &EncodingKey::from_secret(OLD_FIXED_KEY),
    )
    .unwrap();
    assert!(verifies_under_old_key(&token));
}

#[tokio::test]
async fn the_signing_key_is_not_the_old_constant() {
    let manager = AdvancedJarmManager::new(hs256_config());
    let response = manager
        .create_jarm_response(
            "client-1",
            &sample_response(),
            JarmDeliveryMode::Query,
            None,
        )
        .await
        .expect("create");
    assert!(
        !verifies_under_old_key(&response.response_token),
        "the token verifies under the published fixed key"
    );
    // (`validate_jarm_response` returns Ok with `valid: false` for a bad token, so check the flag.)
    let own = manager
        .validate_jarm_response(&response.response_token)
        .await
        .expect("validation runs");
    assert!(own.valid, "own token rejected: {:?}", own.errors);
}

#[tokio::test]
async fn two_managers_do_not_share_a_signing_key() {
    let a = AdvancedJarmManager::new(hs256_config());
    let b = AdvancedJarmManager::new(hs256_config());
    let token = a
        .create_jarm_response(
            "client-1",
            &sample_response(),
            JarmDeliveryMode::Query,
            None,
        )
        .await
        .unwrap()
        .response_token;
    // Control: the issuing manager accepts its own token, so a rejection by `b` is about the key.
    let own = a
        .validate_jarm_response(&token)
        .await
        .expect("validation runs");
    assert!(own.valid, "own token rejected: {:?}", own.errors);
    let other = b
        .validate_jarm_response(&token)
        .await
        .expect("validation runs");
    assert!(
        !other.valid,
        "a token from one manager validated under another: they share a key"
    );
}
