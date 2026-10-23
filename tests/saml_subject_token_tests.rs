//! A SAML subject token is not accepted by a release line that cannot verify its signature.
use auth_framework::server::token_exchange::core::TokenType;
use auth_framework::server::token_exchange::{
    TokenExchangeManager, TokenExchangePolicy, TokenExchangeRequest, TokenExchangeService,
};
use auth_framework::{SecureJwtConfig, SecureJwtValidator};

fn manager() -> TokenExchangeManager {
    TokenExchangeManager::new(SecureJwtValidator::new(SecureJwtConfig::default()))
}

const FORGED: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>admin@example</saml:NameID></saml:Subject></saml:Assertion>"#;

#[tokio::test]
async fn an_unsigned_saml_subject_token_is_not_exchanged() {
    let manager = manager();
    manager
        .register_policy(
            "client".to_string(),
            TokenExchangePolicy {
                allowed_subject_token_types: vec![TokenType::Saml2],
                require_actor_for_delegation: false,
                ..TokenExchangePolicy::default()
            },
        )
        .await;
    let request = TokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: FORGED.to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:saml2".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        audience: None,
        scope: None,
        resource: None,
    };
    let err = manager.exchange_token(request, "client").await.unwrap_err();
    assert!(err.to_string().contains("SAML"), "{err}");
}

#[tokio::test]
async fn a_saml_token_is_never_reported_valid() {
    let result = TokenExchangeService::validate_token(
        &manager(),
        FORGED,
        "urn:ietf:params:oauth:token-type:saml2",
    )
    .await
    .unwrap();
    assert!(!result.is_valid);
}
