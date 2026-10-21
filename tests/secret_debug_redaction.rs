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

/// MFA enrolment material: backup codes, the `otpauth://` URI / QR payload (it embeds the TOTP secret).
#[test]
fn mfa_enrolment_material_is_not_printed() {
    use auth_framework::api::mfa::{BackupCodeVerifyRequest, MfaSetupResponse};
    use auth_framework::authentication::mfa::MfaMethodData;

    let r = MfaSetupResponse {
        qr_code: format!("otpauth://totp/x?secret={S}"),
        secret: "zeroized".to_string(),
        backup_codes: vec![S.into(), S.into()],
    };
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S) && shown.contains("<redacted>"),
        "{shown}"
    );
    // The TOTP secret is a `Zeroizing<String>`: pin that its Debug hides the value too, so a
    // change in the zeroize crate (Cargo.toml requires >= 1.9.1) cannot expose it unnoticed.
    assert!(!shown.contains("zeroized"), "TOTP secret printed: {shown}");

    let r: BackupCodeVerifyRequest = from_json(json!({"backup_code": S}));
    let shown = format!("{r:?}");
    assert!(
        !shown.contains(S) && shown.contains("<redacted>"),
        "{shown}"
    );

    let m = MfaMethodData::Totp {
        secret_key: "zeroized".to_string(),
        qr_code_url: format!("otpauth://totp/x?secret={S}"),
    };
    let shown = format!("{m:?}");
    assert!(!shown.contains(S) && shown.contains("Totp"), "{shown}");
    assert!(!shown.contains("zeroized"), "TOTP secret printed: {shown}");

    let m = MfaMethodData::BackupCodes {
        codes: vec![S.into()],
        used_count: 7,
    };
    let shown = format!("{m:?}");
    assert!(
        !shown.contains(S) && shown.contains("used_count: 7"),
        "{shown}"
    );

    // Control: a variant with no secret still prints its data.
    let m = MfaMethodData::Email {
        email: "visible@example.com".into(),
        is_verified: true,
    };
    assert!(format!("{m:?}").contains("visible@example.com"));
}

/// Types the name-based audit missed: a password in a field called `value`, and OAuth codes and
/// refresh-token ids, which are also the keys of the storage maps (so formatting the store printed
/// every live code and token id twice).
#[tokio::test]
async fn ws_security_password_and_oauth_codes_are_not_printed() {
    use auth_framework::protocols::ws_security::{PasswordType, UsernamePassword};
    use auth_framework::server::oauth::oauth2_enhanced_storage::{
        EnhancedAuthorizationCode, EnhancedTokenStorage, RefreshToken, UserCredentials,
    };
    use std::time::Duration;

    let p = UsernamePassword {
        value: S.into(),
        password_type: PasswordType::PasswordText,
    };
    let shown = format!("{p:?}");
    assert!(
        !shown.contains(S) && shown.contains("<redacted>"),
        "{shown}"
    );
    assert!(
        shown.contains("PasswordText"),
        "non-secret field lost: {shown}"
    );

    let code = EnhancedAuthorizationCode::new(
        "client-visible".into(),
        "user".into(),
        "https://rp.example/cb".into(),
        vec!["read".into()],
        None,
        None,
        Duration::from_secs(60),
    );
    let refresh = RefreshToken::new(
        "client-visible".into(),
        "user".into(),
        vec!["read".into()],
        Duration::from_secs(60),
    );
    let shown = format!("{code:?}");
    assert!(
        !shown.contains(&code.code),
        "authorization code printed: {shown}"
    );
    assert!(
        shown.contains("client-visible"),
        "non-secret field lost: {shown}"
    );
    let shown = format!("{refresh:?}");
    assert!(
        !shown.contains(&refresh.token_id),
        "refresh token id printed: {shown}"
    );
    assert!(
        shown.contains("client-visible"),
        "non-secret field lost: {shown}"
    );

    let creds = UserCredentials {
        username: "name-visible".into(),
        password_hash: S.into(),
        scopes: vec![],
        is_active: true,
        email: None,
    };
    let shown = format!("{creds:?}");
    assert!(
        !shown.contains(S) && shown.contains("name-visible"),
        "{shown}"
    );

    // The store: its maps are keyed by the code / token id.
    let (code_value, refresh_value) = (code.code.clone(), refresh.token_id.clone());
    let mut store = EnhancedTokenStorage::new();
    store.store_authorization_code(code).await.unwrap();
    store.store_refresh_token(refresh).await.unwrap();
    let shown = format!("{store:?}");
    assert!(
        !shown.contains(&code_value),
        "store prints an authorization code: {shown}"
    );
    assert!(
        !shown.contains(&refresh_value),
        "store prints a refresh token id: {shown}"
    );
    // Control: the store really holds them (so the absence above is not an empty store).
    assert!(
        store
            .get_authorization_code(&code_value)
            .await
            .unwrap()
            .is_some()
    );
}

/// Types redacted when the audit was changed from a name blacklist to reviewed field lists: tuple
/// payloads, enum variants and connection strings.
#[test]
fn enum_payloads_and_connection_strings_are_not_printed() {
    use auth_framework::builders::QuickStartStorage;
    use auth_framework::monitoring::alerts::NotificationChannel;
    use auth_framework::protocols::caep::SubjectIdentifier;
    use auth_framework::protocols::ciba::LoginHint;
    use auth_framework::server::oidc::oidc_advanced_jarm::DeliveryResult;

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
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Trace".to_string(), S.to_string());
    let shown = format!(
        "{:?}",
        NotificationChannel::Webhook {
            url: format!("https://hooks.example/{S}"),
            headers
        }
    );
    assert!(!shown.contains(S) && shown.contains("X-Trace"), "{shown}");

    let shown = format!(
        "{:?}",
        SubjectIdentifier::SessionId {
            session_id: S.into(),
            iss: Some("iss-visible".into())
        }
    );
    assert!(
        !shown.contains(S) && shown.contains("iss-visible"),
        "{shown}"
    );
    // Control: a variant whose payload is public still prints it.
    let shown = format!(
        "{:?}",
        SubjectIdentifier::Opaque {
            id: "id-visible".into()
        }
    );
    assert!(shown.contains("id-visible"), "{shown}");

    let shown = format!("{:?}", LoginHint::IdTokenHint(S.into()));
    assert!(!shown.contains(S), "{shown}");
    assert!(format!("{:?}", LoginHint::LoginHint("hint-visible".into())).contains("hint-visible"));

    let shown = format!(
        "{:?}",
        DeliveryResult::Redirect(format!("https://rp/cb?response={S}"))
    );
    assert!(!shown.contains(S), "{shown}");
}

#[cfg(feature = "performance-optimization")]
#[test]
fn unified_storage_keys_are_not_printed() {
    use auth_framework::storage::unified::StorageKey;
    let shown = format!("{:?}", StorageKey::AccessToken(S.into()));
    assert!(
        !shown.contains(S) && shown.contains("AccessToken"),
        "{shown}"
    );
}

/// Types whose secret fields were plain `String`s on this line (they are `Zeroizing` on newer lines).
#[test]
fn enum_credentials_and_connector_secrets_are_not_printed() {
    use auth_framework::auth_modular::mfa::email::ProviderConfig;
    use auth_framework::authentication::credentials::Credential;
    use auth_framework::builders::QuickStartAuth;
    use auth_framework::protocols::oauth1::OAuthConsumer;
    use auth_framework::protocols::spiffe::SvidResponse;

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
    redacts(
        "OAuthConsumer",
        format!(
            "{:?}",
            OAuthConsumer {
                key: "key-visible".into(),
                secret: S.into()
            }
        ),
        "key-visible",
    );

    let shown = format!(
        "{:?}",
        SvidResponse::Jwt {
            spiffe_id: "spiffe-visible".into(),
            token: S.into(),
            expires_at: 1
        }
    );
    assert!(
        !shown.contains(S) && shown.contains("spiffe-visible"),
        "{shown}"
    );
    let shown = format!(
        "{:?}",
        SvidResponse::X509 {
            spiffe_id: "spiffe-visible".into(),
            cert_chain: vec![],
            private_key: S.bytes().collect(),
            bundle: vec![],
            expires_at: 1
        }
    );
    assert!(
        !shown.contains(&format!("{:?}", S.bytes().collect::<Vec<u8>>()))
            && shown.contains("spiffe-visible"),
        "{shown}"
    );
}

/// Enum variants written on one line (`Variant { a: String, b: String },`), which the derive audit
/// used to skip.
#[test]
fn one_line_enum_variants_do_not_print_secrets() {
    use auth_framework::config::AuditStorage;
    use auth_framework::server::core::additional_modules::device_flow_server::DeviceAuthState;
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
        "DeviceAuthState::Authorized",
        format!(
            "{:?}",
            DeviceAuthState::Authorized {
                access_token: S.into()
            }
        ),
        "Authorized",
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
    assert!(
        format!(
            "{:?}",
            CaepRuleAction::LogEvent {
                level: "level-visible".into()
            }
        )
        .contains("level-visible")
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

/// Values that look like identifiers but are bearer or secret-equivalent here: session ids, the
/// `sid` claim (filled from the session id in this crate), hashes of MFA codes and client secrets,
/// and request/response parameter bags that can carry credentials.
#[test]
fn session_ids_code_hashes_and_parameter_bags_are_not_printed() {
    use auth_framework::methods::MfaChallenge;
    use auth_framework::providers::OAuthTokenResponse;
    use auth_framework::server::oidc::oidc_backchannel_logout::LogoutTokenClaims;
    use auth_framework::server::token_exchange::token_introspection::TokenIntrospectionRequest;

    let c: MfaChallenge = from_json(json!({
        "id": "challenge-visible", "mfa_type": "Totp", "user_id": "u",
        "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:05:00Z",
        "attempts": 0, "max_attempts": 3, "code_hash": S, "message": null, "data": {"k": S}
    }));
    redacts("MfaChallenge", format!("{c:?}"), "challenge-visible");

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
