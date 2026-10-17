#![cfg(feature = "saml")]

//! `SamlAuthMethod::default()` must not sign tokens with a key that is the same in every deployment.

use auth_framework::methods::SamlAuthMethod;
use auth_framework::tokens::TokenManager;
use std::time::Duration;

/// The fixed HMAC secret older releases used for every default `SamlAuthMethod`.
const OLD_DEFAULT_SECRET: &[u8] = b"default-saml-secret";

fn token_from(manager: &TokenManager) -> String {
    manager
        .create_jwt_token(
            "alice",
            vec!["read".to_string()],
            Some(Duration::from_secs(300)),
        )
        .expect("create token")
}

#[test]
fn a_token_signed_with_the_old_default_secret_is_rejected_by_the_default_method() {
    let method = SamlAuthMethod::default();
    let forged = token_from(&TokenManager::new_hmac(
        OLD_DEFAULT_SECRET,
        "saml-issuer",
        "saml-audience",
    ));
    assert!(
        method.token_manager.validate_jwt_token(&forged).is_err(),
        "a token signed with the published default secret validated"
    );
}

#[test]
fn the_old_secret_check_is_not_vacuous() {
    // Control: a manager built from the old secret does validate tokens signed with it.
    let old = TokenManager::new_hmac(OLD_DEFAULT_SECRET, "saml-issuer", "saml-audience");
    assert!(old.validate_jwt_token(&token_from(&old)).is_ok());
    // And the default method validates its own tokens.
    let method = SamlAuthMethod::default();
    assert!(
        method
            .token_manager
            .validate_jwt_token(&token_from(&method.token_manager))
            .is_ok()
    );
}

#[test]
fn two_default_methods_do_not_share_a_secret() {
    let a = SamlAuthMethod::default();
    let b = SamlAuthMethod::default();
    let token = token_from(&a.token_manager);
    assert!(b.token_manager.validate_jwt_token(&token).is_err());
}
