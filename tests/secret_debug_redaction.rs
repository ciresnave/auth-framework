//! `{:?}` of a config or credential value must not print its secret.
//!
//! Each case builds the value with a marker as the secret, formats it with `{:?}`, and checks three
//! things: the marker is absent, `<redacted>` is present (the output really came from the redacting
//! impl and the secret was set), and a non-secret field is still shown (the impl did not simply
//! print nothing). `tests/code_quality_audit.rs::test_secret_fields_are_not_derived_debug` covers
//! the types this file does not build.

use auth_framework::api::admin::CreateUserRequest;
use auth_framework::api::auth::{CreateApiKeyResponse, LoginRequest, RegisterRequest};
use auth_framework::api::mfa::{MfaDisableRequest, MfaVerifyRequest};
use auth_framework::api::oauth_advanced::IntrospectRequest;
use auth_framework::api::users::ChangePasswordRequest;
use auth_framework::config::AuthConfig;
use auth_framework::deployment::config::DatabaseConfig;
use auth_framework::deployment::monitoring::{BasicAuth, HttpConfig};
use auth_framework::methods::hardware_token::HardwareOtpTokenConfig;
use auth_framework::oauth2_server::TokenRequest;
use auth_framework::protocols::opa::OpaConfig;
use auth_framework::protocols::scim::ScimClientConfig;
use auth_framework::{ClientConfig, ClientType};
use serde_json::json;

const S: &str = "SECRET-MARKER-7f3a9c";

#[track_caller]
fn redacts(name: &str, debug: String, visible: &str) {
    assert!(!debug.contains(S), "{name} prints its secret: {debug}");
    assert!(
        debug.contains("<redacted>"),
        "{name} shows no redaction marker: {debug}"
    );
    assert!(
        debug.contains(visible),
        "{name} dropped a non-secret field ({visible:?}): {debug}"
    );
}

fn from_json<T: serde::de::DeserializeOwned>(v: serde_json::Value) -> T {
    serde_json::from_value(v).expect("fixture deserializes")
}

#[test]
fn config_and_credential_types_do_not_print_secrets() {
    let c = AuthConfig::new()
        .secret(S)
        .issuer("issuer-visible")
        .audience("aud");
    redacts("AuthConfig", format!("{c:?}"), "issuer-visible");

    let mut c = ClientConfig::builder("client-visible", ClientType::Confidential).build();
    c.client_secret = Some(S.to_string());
    redacts("ClientConfig", format!("{c:?}"), "client-visible");

    redacts(
        "BasicAuth",
        format!(
            "{:?}",
            BasicAuth {
                username: "user-visible".into(),
                password: S.into()
            }
        ),
        "user-visible",
    );

    redacts(
        "DatabaseConfig",
        format!(
            "{:?}",
            DatabaseConfig {
                host: "host-visible".into(),
                port: 1,
                database: "d".into(),
                username: "u".into(),
                password: S.into(),
                ssl_mode: "s".into(),
                pool_size: 1,
                timeout: 1,
            }
        ),
        "host-visible",
    );

    redacts(
        "HttpConfig",
        format!(
            "{:?}",
            HttpConfig {
                basic_auth: None,
                bearer_token: Some(S.into()),
                tls_config: None,
            }
        ),
        "basic_auth",
    );

    redacts(
        "HardwareOtpTokenConfig",
        format!(
            "{:?}",
            HardwareOtpTokenConfig {
                yubico_client_id: Some("yubico-visible".into()),
                yubico_secret_key: Some(S.into()),
                yubico_validation_url: "u".into(),
            }
        ),
        "yubico-visible",
    );

    let o = OpaConfig {
        auth_token: Some(S.into()),
        ..Default::default()
    };
    redacts("OpaConfig", format!("{o:?}"), "localhost:8181");

    redacts(
        "ScimClientConfig",
        format!(
            "{:?}",
            ScimClientConfig {
                base_url: "https://scim-visible".into(),
                bearer_token: S.into(),
                timeout_secs: 1,
            }
        ),
        "scim-visible",
    );
}

#[test]
fn request_and_response_bodies_do_not_print_secrets() {
    let t: TokenRequest = from_json(json!({
        "grant_type": "grant-visible",
        "client_secret": S,
        "code": S,
        "refresh_token": S,
        "code_verifier": S,
        "password": S,
    }));
    redacts("TokenRequest", format!("{t:?}"), "grant-visible");

    let r: CreateUserRequest = from_json(json!({
        "username": "name-visible", "password": S, "email": "e@example.com"
    }));
    redacts("CreateUserRequest", format!("{r:?}"), "name-visible");

    let r: LoginRequest = from_json(json!({"username": "name-visible", "password": S}));
    redacts("api LoginRequest", format!("{r:?}"), "name-visible");

    let r: RegisterRequest =
        from_json(json!({"username": "name-visible", "email": "e@example.com", "password": S}));
    redacts("RegisterRequest", format!("{r:?}"), "name-visible");

    let r: ChangePasswordRequest = from_json(json!({"current_password": S, "new_password": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S),
        "ChangePasswordRequest prints a password: {shown}"
    );
    assert!(shown.contains("<redacted>"));

    let r: MfaDisableRequest = from_json(json!({"password": S, "totp_code": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S),
        "MfaDisableRequest prints a secret: {shown}"
    );

    let r: MfaVerifyRequest = from_json(json!({"totp_code": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S),
        "MfaVerifyRequest prints a code: {shown}"
    );

    let r: IntrospectRequest = from_json(json!({
        "token": "token-visible", "client_id": "cid", "client_secret": S
    }));
    redacts("IntrospectRequest", format!("{r:?}"), "cid");

    let r = CreateApiKeyResponse {
        api_key: S.into(),
        token_type: "ApiKey".into(),
    };
    redacts("CreateApiKeyResponse", format!("{r:?}"), "ApiKey");
}

/// A secret that is not configured must read as not configured, not as redacted.
#[test]
fn an_absent_secret_still_reads_as_none() {
    let c = ClientConfig::builder("c", ClientType::Public).build();
    let shown = format!("{c:?}");
    assert!(shown.contains("client_secret: None"), "{shown}");
}

/// Bodies that carry issued tokens: a `tracing` call or panic that formats one must not print them.
#[test]
fn token_carrying_bodies_do_not_print_tokens() {
    use auth_framework::api::auth::{LogoutRequest, RefreshRequest};
    use auth_framework::api::oauth2::RevokeRequest;
    use auth_framework::providers::OAuthTokenResponse;
    use auth_framework::server::oauth::device::DeviceTokenRequest;
    use auth_framework::server::oauth::oauth2_server::TokenResponse;
    use auth_framework::server::token_exchange::token_introspection::TokenIntrospectionRequest;

    let t: TokenResponse = from_json(json!({
        "access_token": S, "token_type": "type-visible", "expires_in": 60,
        "refresh_token": S, "scope": null, "id_token": S
    }));
    redacts("TokenResponse", format!("{t:?}"), "type-visible");

    let t: OAuthTokenResponse = from_json(json!({
        "access_token": S, "token_type": "type-visible", "expires_in": 60,
        "refresh_token": S, "scope": null, "id_token": null
    }));
    redacts("OAuthTokenResponse", format!("{t:?}"), "type-visible");

    let r: RefreshRequest = from_json(json!({"refresh_token": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S) && shown.contains("<redacted>"),
        "{shown}"
    );

    let r: LogoutRequest = from_json(json!({"refresh_token": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S) && shown.contains("<redacted>"),
        "{shown}"
    );

    let r: RevokeRequest = from_json(json!({"token": S, "token_type_hint": "hint-visible"}));
    redacts("RevokeRequest", format!("{r:?}"), "hint-visible");

    let r: TokenIntrospectionRequest =
        from_json(json!({"token": S, "token_type_hint": "hint-visible"}));
    redacts(
        "TokenIntrospectionRequest",
        format!("{r:?}"),
        "hint-visible",
    );

    let r: DeviceTokenRequest = from_json(json!({
        "grant_type": "grant-visible", "device_code": S, "client_id": "c"
    }));
    redacts("DeviceTokenRequest", format!("{r:?}"), "grant-visible");
}
