//! Production validation refuses a signing secret that is a known placeholder.

use auth_framework::{AuthConfig, config::AppConfig};

/// The constant older releases shipped in `AppConfig::default()`.
const OLD_DEFAULT: &str = "development-only-secret-change-in-production";

/// A configuration built the way `AppConfig` users build it (so its storage passes the production
/// checks), carrying `secret`, in production mode.
fn production(secret: &str) -> AuthConfig {
    let mut app = AppConfig::default();
    app.jwt.secret_key = secret.to_string().into();
    app.to_auth_config().force_production_mode()
}

#[test]
fn production_refuses_the_old_default_secret() {
    let error = production(OLD_DEFAULT)
        .validate()
        .expect_err("a published placeholder must not validate in production");
    assert!(
        error.to_string().contains("placeholder"),
        "unexpected error: {error}"
    );
}

#[test]
fn production_refuses_placeholder_spellings() {
    for secret in [
        "Development-Only-Secret-Change-In-Production",
        "  development-only-secret-change-in-production  ",
        "please-change-in-production-0123456789abcdef",
        "your-secret-here-your-secret-here-your-secret",
        "changeme-changeme-changeme-changeme-changeme",
        "replace-with-a-32-char-random-secret!!",
    ] {
        let error = production(secret)
            .validate()
            .expect_err(&format!("{secret:?} must not validate in production"));
        assert!(
            error.to_string().contains("placeholder"),
            "{secret:?}: unexpected error: {error}"
        );
    }
}

#[test]
fn production_does_not_flag_a_random_secret_as_a_placeholder() {
    let secret = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    // Control: the same configuration shape validates when the secret is a real one, so the
    // refusals above are about the secret and not about the rest of the configuration.
    if let Err(error) = production(&secret).validate() {
        panic!("a random secret must validate in production, got: {error}");
    }
}

#[test]
fn outside_production_a_placeholder_is_not_refused() {
    // Development convenience: the rule is production-only.
    let mut app = AppConfig::default();
    app.jwt.secret_key = OLD_DEFAULT.to_string().into();
    if let Err(error) = app.to_auth_config().validate() {
        assert!(
            !error.to_string().contains("placeholder"),
            "placeholder refused outside production: {error}"
        );
    }
}
