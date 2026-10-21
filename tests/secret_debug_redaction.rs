//! `{:?}` of a config, credential or request value must not print its secret.
//!
//! Each case builds the value with a marker as the secret, formats it with `{:?}`, and checks the
//! marker is absent, `<redacted>` (or the type's own redaction text) is present, and a non-secret
//! field is still shown. `tests/code_quality_audit.rs::test_derived_debug_plain_fields_are_reviewed`
//! covers the types this file does not build.

use auth_framework::api::admin::CreateUserRequest;
use auth_framework::api::auth::{LoginRequest, LogoutRequest, RefreshRequest};
use auth_framework::api::mfa::{BackupCodeVerifyRequest, MfaDisableRequest, MfaVerifyRequest};
use auth_framework::api::oauth::{IntrospectRequest, RevokeRequest, TokenRequest};
use auth_framework::api::users::ChangePasswordRequest;
use auth_framework::config::AuthConfig;
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
fn config_and_request_bodies_do_not_print_secrets() {
    let c = AuthConfig::new()
        .secret(S)
        .issuer("issuer-visible")
        .audience("aud");
    redacts("AuthConfig", format!("{c:?}"), "issuer-visible");

    let t: TokenRequest = from_json(json!({
        "grant_type": "grant-visible",
        "client_id": "cid",
        "client_secret": S,
        "code": S,
        "refresh_token": S,
        "code_verifier": S,
    }));
    redacts("TokenRequest", format!("{t:?}"), "grant-visible");

    let r: CreateUserRequest = from_json(json!({
        "username": "name-visible", "password": S, "email": "e@example.com"
    }));
    redacts("CreateUserRequest", format!("{r:?}"), "name-visible");

    let r: LoginRequest = from_json(json!({"username": "name-visible", "password": S}));
    redacts("LoginRequest", format!("{r:?}"), "name-visible");

    for (name, shown) in [
        (
            "ChangePasswordRequest",
            format!(
                "{:?}",
                from_json::<ChangePasswordRequest>(
                    json!({"current_password": S, "new_password": S})
                )
            ),
        ),
        (
            "MfaDisableRequest",
            format!(
                "{:?}",
                from_json::<MfaDisableRequest>(json!({"password": S, "totp_code": S}))
            ),
        ),
        (
            "MfaVerifyRequest",
            format!(
                "{:?}",
                from_json::<MfaVerifyRequest>(json!({"totp_code": S}))
            ),
        ),
        (
            "BackupCodeVerifyRequest",
            format!(
                "{:?}",
                from_json::<BackupCodeVerifyRequest>(json!({"backup_code": S}))
            ),
        ),
        (
            "RefreshRequest",
            format!(
                "{:?}",
                from_json::<RefreshRequest>(json!({"refresh_token": S}))
            ),
        ),
        (
            "LogoutRequest",
            format!(
                "{:?}",
                from_json::<LogoutRequest>(json!({"refresh_token": S}))
            ),
        ),
        (
            "RevokeRequest",
            format!("{:?}", from_json::<RevokeRequest>(json!({"token": S}))),
        ),
    ] {
        assert!(!shown.contains(S), "{name} prints a secret: {shown}");
        assert!(shown.contains("<redacted>"), "{name}: {shown}");
    }

    let r: IntrospectRequest = from_json(json!({
        "token": S, "token_type_hint": "hint-visible"
    }));
    redacts("IntrospectRequest", format!("{r:?}"), "hint-visible");
}

#[test]
fn enum_credentials_and_connector_secrets_are_not_printed() {
    use auth_framework::auth_modular::mfa::email::ProviderConfig;
    use auth_framework::authentication::credentials::Credential;
    use auth_framework::builders::{QuickStartAuth, QuickStartStorage};
    use auth_framework::monitoring::alerts::NotificationChannel;
    use auth_framework::server::oidc::oidc_enhanced_ciba::UserIdentifierHint;

    let shown = format!("{:?}", Credential::password("alice", S));
    assert!(!shown.contains(S) && shown.contains("alice"), "{shown}");
    let shown = format!("{:?}", Credential::oauth_code_with_pkce(S, S));
    assert!(!shown.contains(S), "{shown}");

    redacts(
        "QuickStartAuth::Jwt",
        format!("{:?}", QuickStartAuth::Jwt { secret: S.into() }),
        "Jwt",
    );
    redacts(
        "QuickStartAuth::OAuth2",
        format!(
            "{:?}",
            QuickStartAuth::OAuth2 {
                client_id: "cid-visible".into(),
                client_secret: S.into()
            }
        ),
        "cid-visible",
    );
    redacts(
        "ProviderConfig::Smtp",
        format!(
            "{:?}",
            ProviderConfig::Smtp {
                host: "smtp-visible".into(),
                port: 25,
                username: "u".into(),
                password: S.into(),
                use_tls: true
            }
        ),
        "smtp-visible",
    );
    redacts(
        "ProviderConfig::SendGrid",
        format!(
            "{:?}",
            ProviderConfig::SendGrid {
                api_key: S.into(),
                endpoint: None
            }
        ),
        "SendGrid",
    );

    let shown = format!(
        "{:?}",
        QuickStartStorage::Postgres(format!("postgres://u:{S}@h/db"))
    );
    assert!(!shown.contains(S) && shown.contains("Postgres"), "{shown}");
    let shown = format!("{:?}", QuickStartStorage::Redis(format!("redis://:{S}@h")));
    assert!(!shown.contains(S) && shown.contains("Redis"), "{shown}");

    let shown = format!(
        "{:?}",
        NotificationChannel::Slack {
            webhook_url: format!("https://hooks.example/{S}")
        }
    );
    assert!(!shown.contains(S) && shown.contains("Slack"), "{shown}");

    let shown = format!("{:?}", UserIdentifierHint::IdTokenHint(S.into()));
    assert!(!shown.contains(S), "{shown}");
    // Control: a hint that is not a bearer value (an e-mail address) is still printed.
    assert!(
        format!("{:?}", UserIdentifierHint::Email("mail-visible".into())).contains("mail-visible")
    );
}

/// Enum variants written on one line (`Variant { a: String, b: String },`), which the derive audit
/// used to skip.
#[test]
fn one_line_enum_variants_do_not_print_secrets() {
    use auth_framework::config::AuditStorage;
    use auth_framework::server::security::caep_continuous_access::CaepRuleAction;

    redacts(
        "AuditStorage::External",
        format!(
            "{:?}",
            AuditStorage::External {
                endpoint: "endpoint-visible".into(),
                api_key: S.into()
            }
        ),
        "endpoint-visible",
    );
    redacts(
        "AuditStorage::Database",
        format!(
            "{:?}",
            AuditStorage::Database {
                connection_string: format!("postgres://u:{S}@h/db")
            }
        ),
        "Database",
    );
    redacts(
        "CaepRuleAction::TriggerWebhook",
        format!(
            "{:?}",
            CaepRuleAction::TriggerWebhook {
                url: format!("https://hooks.example/{S}")
            }
        ),
        "TriggerWebhook",
    );
    // Controls: variants with no secret still print their payload.
    assert!(
        format!(
            "{:?}",
            AuditStorage::File {
                path: "path-visible".into()
            }
        )
        .contains("path-visible")
    );
}

/// In-memory stores and managers keep maps keyed by tokens and session ids; a map's `Debug` prints
/// every key, so none of them may be formatted with `{:?}`.
#[tokio::test]
async fn maps_keyed_by_tokens_and_session_ids_are_not_printed() {
    use auth_framework::storage::AuthStorage;
    use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
    use auth_framework::testing::MockStorage;
    use auth_framework::user_context::{SessionStore, UserContext};

    let storage = DashMapMemoryStorage::new();
    storage.store_kv(S, b"value", None).await.unwrap();
    let shown = format!("{storage:?}");
    assert!(
        !shown.contains(S),
        "DashMapMemoryStorage prints a key: {shown}"
    );
    assert!(
        shown.contains("default_ttl"),
        "dropped a plain field: {shown}"
    );
    // Control: the key really is stored, so the absence above is the redaction's doing.
    assert!(storage.get_kv(S).await.unwrap().is_some());

    let mock = MockStorage::new();
    mock.store_kv(S, b"value", None).await.unwrap();
    let shown = format!("{mock:?}");
    assert!(!shown.contains(S), "MockStorage prints a key: {shown}");
    assert!(mock.get_kv(S).await.unwrap().is_some());

    let mut sessions = SessionStore::new();
    let mut ctx = UserContext::new("user-visible".to_string(), "name".to_string(), None);
    ctx.session_id = S.to_string();
    sessions.create_session(ctx);
    let shown = format!("{sessions:?}");
    assert!(
        !shown.contains(S),
        "SessionStore prints a session id: {shown}"
    );
    assert!(sessions.validate_session(S));
}

/// Values that look like identifiers but are bearer or secret-equivalent here: the `sid` claim
/// (filled from the session id in this crate) and parameter bags that can carry credentials.
#[test]
fn session_ids_and_parameter_bags_are_not_printed() {
    use auth_framework::providers::OAuthTokenResponse;
    use auth_framework::server::oidc::oidc_backchannel_logout::LogoutTokenClaims;
    use auth_framework::server::token_exchange::token_introspection::TokenIntrospectionRequest;

    let l: LogoutTokenClaims = from_json(json!({
        "iss": "iss-visible", "sub": null, "aud": ["a"], "iat": 1, "jti": "j",
        "events": {}, "sid": S, "exp": 2
    }));
    redacts("LogoutTokenClaims", format!("{l:?}"), "iss-visible");

    let r: TokenIntrospectionRequest =
        from_json(json!({"token": "t", "token_type_hint": "hint-visible", "client_secret": S}));
    redacts(
        "TokenIntrospectionRequest",
        format!("{r:?}"),
        "hint-visible",
    );

    let r: OAuthTokenResponse = from_json(json!({
        "access_token": "a", "token_type": "token-type-visible", "id_token": S
    }));
    redacts("OAuthTokenResponse", format!("{r:?}"), "token-type-visible");
}
