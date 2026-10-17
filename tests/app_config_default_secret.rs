//! The default configuration must not carry a signing secret that is the same in every deployment.

use auth_framework::config::app_config::AppConfig;

/// The constant older releases put in `AppConfig::default()`.
const OLD_CONSTANT: &str = "development-only-secret-change-in-production";

#[test]
fn default_configuration_generates_a_per_process_signing_secret() {
    let first = AppConfig::default();
    let secret = first.jwt.secret_key.as_str();

    assert_ne!(
        secret, OLD_CONSTANT,
        "the default secret is a published constant"
    );
    assert!(
        secret.len() >= 32,
        "generated secret is too short: {}",
        secret.len()
    );
    assert!(
        secret.chars().all(|c| c.is_ascii_hexdigit()),
        "expected a hex-encoded random secret"
    );

    // One secret per process: two defaults built in the same process agree, so a token signed under
    // one is verified under the other.
    let second = AppConfig::default();
    assert_eq!(secret, second.jwt.secret_key.as_str());
}

#[test]
fn the_generated_default_secret_reaches_the_auth_config() {
    let config = AppConfig::default();
    let auth = config.to_auth_config();
    assert_eq!(auth.secret.as_deref(), Some(config.jwt.secret_key.as_str()));
}
