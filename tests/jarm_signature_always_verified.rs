//! A JARM response token's signature is always verified, whatever the caller says about the transport.

use auth_framework::server::oidc::oidc_advanced_jarm::{
    AdvancedJarmConfig, AdvancedJarmManager, AuthorizationResponse, JarmDeliveryMode,
};
use jsonwebtoken::Algorithm;

fn config() -> AdvancedJarmConfig {
    AdvancedJarmConfig {
        supported_algorithms: vec![Algorithm::HS256],
        ..Default::default()
    }
}

fn response() -> AuthorizationResponse {
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

#[tokio::test]
async fn a_token_signed_by_another_key_is_refused_whatever_the_transport_flag() {
    let issuer = AdvancedJarmManager::new(config());
    let verifier = AdvancedJarmManager::new(config()); // its own, different signing key
    let token = issuer
        .create_jarm_response("client-1", &response(), JarmDeliveryMode::Query, None)
        .await
        .expect("create")
        .response_token;

    // Controls: the issuing manager accepts its own token with either flag value, so a refusal
    // by the other manager is about the key and not about the token or the flag.
    for flag in [true, false] {
        let own = issuer
            .validate_jarm_response_with_transport(&token, flag)
            .await
            .expect("validation runs");
        assert!(
            own.valid,
            "own token refused (flag {flag}): {:?}",
            own.errors
        );
    }

    for flag in [true, false] {
        let other = verifier
            .validate_jarm_response_with_transport(&token, flag)
            .await
            .expect("validation runs");
        assert!(
            !other.valid,
            "a token signed with another key was accepted (transport_secure = {flag})"
        );
        assert!(
            other.errors.iter().any(|e| e.contains("InvalidSignature")),
            "refused, but not for its signature (transport_secure = {flag}): {:?}",
            other.errors
        );
    }
}
