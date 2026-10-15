# Protocol & Feature Configuration Guide

This guide covers how to enable and configure each protocol and feature available
in AuthFramework. Each section documents the relevant feature flag (if any),
configuration struct, key fields, and a minimal working example.

> **Tip:** Most protocols listed here are enabled by default.
> Only SAML 2.0, WebAuthn/Passkeys, enhanced RBAC, and OTP have opt-in feature
> flags. See [Feature Flags Summary](#feature-flags-summary) at the bottom.

---

## Table of Contents

- [OAuth 2.0 Server](#oauth-20-server)
- [OpenID Connect Provider](#openid-connect-provider)
- [SAML 2.0](#saml-20)
- [WebAuthn / Passkeys](#webauthn--passkeys)
- [DPoP (Proof-of-Possession)](#dpop-proof-of-possession)
- [Pushed Authorization Requests (PAR)](#pushed-authorization-requests-par)
- [Device Authorization Grant](#device-authorization-grant)
- [Token Exchange (RFC 8693)](#token-exchange-rfc-8693)
- [CIBA (Backchannel Authentication)](#ciba-backchannel-authentication)
- [JARM (JWT-Secured Authorization Responses)](#jarm-jwt-secured-authorization-responses)
- [Additional Implemented Protocol Modules](#additional-implemented-protocol-modules)
- [Rate Limiting](#rate-limiting)
- [Multi-Factor Authentication](#multi-factor-authentication)
- [Session Management](#session-management)
- [RBAC / ABAC Authorization](#rbac--abac-authorization)
- [Feature Flags Summary](#feature-flags-summary)

---

## OAuth 2.0 Server

**Source:** `src/server/oauth/oauth2.rs`, `src/server/oauth/oauth2_server.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,no_run
use auth_framework::server::oauth::OAuth2Config;
use std::time::Duration;

let config = OAuth2Config::builder()
    .issuer("https://auth.example.com")
    .access_token_lifetime(Duration::from_secs(1800))
    .refresh_token_lifetime(Duration::from_secs(604800))
    .require_pkce(true)
    .enable_introspection(true)     // RFC 7662
    .enable_revocation(true)        // RFC 7009
    .build();
```

### Key Fields

| Field                         | Default | Description                                |
| ----------------------------- | ------- | ------------------------------------------ |
| `issuer`                      | —       | Authorization server identifier (required) |
| `authorization_code_lifetime` | 10 min  | Code validity window                       |
| `access_token_lifetime`       | 1 hour  | Access token TTL                           |
| `refresh_token_lifetime`      | 7 days  | Refresh token TTL                          |
| `require_pkce`                | `true`  | Require PKCE for public clients            |
| `enable_introspection`        | `true`  | Token introspection endpoint               |
| `enable_revocation`           | `true`  | Token revocation endpoint                  |
| `default_scope`               | `None`  | Default scope when none requested          |

### Server Initialization

```rust,no_run
use auth_framework::server::oauth::OAuth2Server;
# use std::sync::Arc;
# let storage: Arc<dyn auth_framework::storage::AuthStorage> = unimplemented!();

// With default config
let server = OAuth2Server::new(storage.clone()).await?;

// With custom config
let server = OAuth2Server::new_with_config(storage, config).await?;
# Ok::<(), auth_framework::errors::AuthError>(())
```

---

## OpenID Connect Provider

**Source:** `src/server/oidc/core.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,no_run
use auth_framework::server::oidc::OidcConfig;
use auth_framework::server::oauth::OAuth2Config;
use std::time::Duration;

let config = OidcConfig::builder()
    .issuer("https://auth.example.com")
    .oauth2_config(OAuth2Config::builder().build())
    .id_token_expiry(Duration::from_secs(3600))
    .build();
```

### Key Fields

| Field                      | Default    | Description                     |
| -------------------------- | ---------- | ------------------------------- |
| `issuer`                   | —          | HTTPS issuer URL (required)     |
| `oauth2_config`            | —          | Wrapped OAuth 2.0 configuration |
| `jwks_uri`                 | —          | JWK Set endpoint URL            |
| `userinfo_endpoint`        | —          | UserInfo endpoint URL           |
| `id_token_expiry`          | 1 hour     | ID token lifetime               |
| `response_types_supported` | `["code"]` | Supported response types        |
| `subject_types_supported`  | —          | Public / pairwise subject types |
| `scopes_supported`         | —          | openid, profile, email, etc.    |
| `claims_supported`         | —          | sub, name, email, etc.          |

---

## SAML 2.0

**Source:** `src/api/saml.rs`, `src/server/core/additional_modules.rs`
**Feature flag:** `saml` (adds `bergshamra`, `p256`, `p384`, `quick-xml`)

### Cargo.toml

```toml
[dependencies]
auth_framework = { version = "0.5", features = ["saml"] }
```

### Identity Provider Configuration

```rust,ignore
use auth_framework::server::core::SamlIdpConfig;
use auth_framework::server::core::SamlIdentityProvider;

let idp_config = SamlIdpConfig {
    entity_id: "https://idp.example.com".to_string(),
};

let idp = SamlIdentityProvider::new(idp_config, storage).await?;
idp.initialize()?;
```

### Service Provider Registration

SP configuration is stored in the storage backend at key `saml_sp:config`:

```rust,ignore
use serde_json::json;

let sp_config = json!({
    "entity_id": "https://sp.example.com",
    "acs_url": "https://sp.example.com/acs",
    "slo_url": "https://sp.example.com/slo"
});

storage.store_kv(
    "saml_sp:config",
    &serde_json::to_vec(&sp_config)?,
    None,
).await?;
```

### Auth Method Configuration

Register SAML via `AuthConfig::method_config()`:

```rust,ignore
use auth_framework::config::AuthConfig;

let config = AuthConfig::new()
    .method_config("saml", serde_json::json!({
        "entity_id": "https://sp.example.com",
        "acs_url": "https://sp.example.com/acs",
        "max_assertion_age": 300
    }))?;
```

---

## WebAuthn / Passkeys

**Source:** `src/api/webauthn.rs`, `src/auth_modular/mfa/mod.rs`
**Feature flag:** `passkeys` (adds `coset`, `passkey`, `passkey-client`)

### Cargo.toml

```toml
[dependencies]
auth_framework = { version = "0.5", features = ["passkeys"] }
```

### Auth Method Configuration

```rust,ignore
use auth_framework::config::AuthConfig;

let config = AuthConfig::new()
    .method_config("passkey", serde_json::json!({
        "rp_id": "example.com",
        "rp_name": "Example Corp",
        "origin": "https://example.com",
        "timeout_ms": 60000,
        "user_verification": "preferred"
    }))?;
```

### Key Fields

| Field               | Description                                     |
| ------------------- | ----------------------------------------------- |
| `rp_id`             | Relying Party identifier (your domain)          |
| `rp_name`           | Human-readable RP name                          |
| `origin`            | Allowed origin URL                              |
| `timeout_ms`        | Ceremony timeout in milliseconds                |
| `user_verification` | `"required"`, `"preferred"`, or `"discouraged"` |

### REST API Endpoints

| Method | Path                                | Purpose                       |
| ------ | ----------------------------------- | ----------------------------- |
| POST   | `/webauthn/registration/init`       | Start passkey registration    |
| POST   | `/webauthn/registration/complete`   | Finish passkey registration   |
| POST   | `/webauthn/authentication/init`     | Start passkey authentication  |
| POST   | `/webauthn/authentication/complete` | Finish passkey authentication |

---

## DPoP (Proof-of-Possession)

**Source:** `src/server/security/dpop.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::security::DpopManager;
use auth_framework::security::SecureJwtValidator;

let jwt_validator = SecureJwtValidator::new(jwt_config)?;
let dpop_manager = DpopManager::new(jwt_validator);
```

### Validating a DPoP Proof

```rust,ignore
let result = dpop_manager
    .validate_dpop_proof(
        dpop_proof,                                 // DPoP JWT from client
        "POST",                                     // HTTP method
        "https://api.example.com/resource",         // Request URI
        Some(access_token),                         // Bound access token
        expected_nonce,                             // Server-provided nonce
    )
    .await?;
```

### Key Settings

| Field              | Default | Description         |
| ------------------ | ------- | ------------------- |
| `proof_expiration` | 60 sec  | DPoP proof TTL      |
| `clock_skew`       | 30 sec  | Allowed clock drift |

---

## Pushed Authorization Requests (PAR)

**Source:** `src/server/oauth/par.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::oauth::PARManager;
use std::time::Duration;

// Default 90-second expiration (per RFC 9126)
let par_manager = PARManager::new(storage);

// Custom expiration
let par_manager = PARManager::with_expiration(
    storage,
    Duration::from_secs(120),
);
```

### Storing & Retrieving a PAR Request

```rust,ignore
// Store a pushed authorization request
let response = par_manager.store_request(authorization_request).await?;
// response.request_uri — the generated request_uri
// response.expires_in  — seconds until expiration

// Retrieve by request_uri
let stored = par_manager.get_request(&response.request_uri).await?;
```

---

## Device Authorization Grant

**Source:** `src/server/core/additional_modules.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::core::DeviceFlowConfig;
use auth_framework::server::core::DeviceFlowManager;

let config = DeviceFlowConfig {
    user_code_length: 8,
    device_code_ttl_secs: 1800,           // 30 minutes
    polling_interval_secs: 5,
    verification_uri: "https://auth.example.com/device".to_string(),
};

// In-memory only
let mgr = DeviceFlowManager::new(config.clone());

// With persistent storage
let mgr = DeviceFlowManager::new_with_storage(config, storage);
```

### Key Fields

| Field                   | Default | Description                        |
| ----------------------- | ------- | ---------------------------------- |
| `user_code_length`      | 8       | User-facing code length            |
| `device_code_ttl_secs`  | 1800    | Device code lifetime (seconds)     |
| `polling_interval_secs` | 5       | Minimum polling interval (seconds) |
| `verification_uri`      | —       | User verification URI (required)   |

---

## Token Exchange (RFC 8693)

**Source:** `src/server/token_exchange/advanced_token_exchange.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::token_exchange::AdvancedTokenExchangeConfig;
use auth_framework::server::token_exchange::AdvancedTokenExchangeManager;
use std::time::Duration;

let config = AdvancedTokenExchangeConfig {
    enable_multi_party_chains: true,
    max_delegation_depth: 5,
    require_audit_trail: true,
    default_token_lifetime: Duration::from_secs(3600),
    supported_subject_token_types: vec![
        "urn:ietf:params:oauth:token-type:access_token".into(),
        "urn:ietf:params:oauth:token-type:jwt".into(),
    ],
    supported_requested_token_types: vec![
        "urn:ietf:params:oauth:token-type:access_token".into(),
    ],
    exchange_policies: vec![],
    jwt_signing_key: signing_key,
    jwt_verification_key: verification_key,
    ..Default::default()
};

let manager = AdvancedTokenExchangeManager::new(config);
```

### Key Fields

| Field                             | Default | Description                |
| --------------------------------- | ------- | -------------------------- |
| `enable_multi_party_chains`       | `false` | Allow delegation chains    |
| `max_delegation_depth`            | 3       | Maximum chain depth        |
| `require_audit_trail`             | `false` | Mandate audit logging      |
| `default_token_lifetime`          | 1 hour  | Exchanged token TTL        |
| `supported_subject_token_types`   | —       | Accepted input token types |
| `supported_requested_token_types` | —       | Output token types         |

---

## CIBA (Backchannel Authentication)

**Source:** `src/server/oidc/oidc_enhanced_ciba.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::oidc::EnhancedCibaConfig;
use auth_framework::server::oidc::EnhancedCibaManager;
use auth_framework::security::SecureJwtConfig;
use std::time::Duration;

let ciba_config = EnhancedCibaConfig {
    supported_modes: vec![AuthenticationMode::OOB],
    default_auth_req_expiry: Duration::from_secs(600),
    max_polling_interval: 120,
    min_polling_interval: 5,
    enable_consent: true,
    enable_device_binding: true,
    issuer: "https://auth.example.com".to_string(),
    access_token_lifetime: 3600,
    id_token_lifetime: 3600,
    refresh_token_lifetime: 86400,
    jwt_config: SecureJwtConfig::default(),
    ..Default::default()
};

let ciba_manager = EnhancedCibaManager::new(ciba_config, storage)?;
```

### Key Fields

| Field                     | Default | Description             |
| ------------------------- | ------- | ----------------------- |
| `supported_modes`         | —       | OOB, push, poll modes   |
| `default_auth_req_expiry` | 10 min  | Auth request expiration |
| `min_polling_interval`    | 5 sec   | Minimum poll interval   |
| `max_polling_interval`    | 120 sec | Maximum poll interval   |
| `enable_consent`          | `true`  | Require user consent    |
| `enable_device_binding`   | `false` | Bind to device          |
| `issuer`                  | —       | Token issuer URL        |

---

## JARM (JWT-Secured Authorization Responses)

**Source:** `src/server/oidc/oidc_advanced_jarm.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::server::oidc::AdvancedJarmConfig;
use auth_framework::server::oidc::AdvancedJarmManager;
use jsonwebtoken::Algorithm;

let jarm_config = AdvancedJarmConfig {
    supported_algorithms: vec![Algorithm::HS256],  // or RS256
    default_token_expiry: Duration::from_secs(600),
    enable_jwe_encryption: false,
    supported_delivery_modes: vec![JarmDeliveryMode::FormPost],
    enable_custom_claims: true,
    max_custom_claims: 10,
    enable_response_validation: true,
    jarm_issuer: "https://auth.example.com".to_string(),
    enable_audit_logging: true,
    ..Default::default()
};

let jarm_manager = AdvancedJarmManager::new(jarm_config)?;
```

> **Note:** `AdvancedJarmConfig::default()` uses RS256. If you don't have RSA
> keys configured, override `supported_algorithms` to `[Algorithm::HS256]`.

### Key Fields

| Field                      | Default   | Description               |
| -------------------------- | --------- | ------------------------- |
| `supported_algorithms`     | `[RS256]` | Signing algorithms        |
| `default_token_expiry`     | 10 min    | Response JWT TTL          |
| `enable_jwe_encryption`    | `false`   | Encrypt responses         |
| `supported_delivery_modes` | —         | form_post, fragment, etc. |
| `jarm_issuer`              | —         | Response token issuer     |
| `enable_audit_logging`     | `true`    | Log JARM operations       |

---

## Additional Implemented Protocol Modules

The sections above cover the first-class server and runtime features that have
top-level configuration paths in the framework. AuthFramework also ships a
broader set of implemented protocol modules under `auth_framework::protocols::*`
and selected API endpoints under `auth_framework::api::advanced_protocols`.

Use these modules directly when you need lower-level protocol building blocks or
specialized integration points that are not routed through `AuthConfig`.

### Modern Identity, Credential, and Authorization Protocols

| Protocol   | Source                        | Entry Point                                                     | Enablement / Configuration                                                                                     |
| ---------- | ----------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| OpenID4VCI | `src/protocols/openid4vci.rs` | `auth_framework::protocols::openid4vci`                         | Always enabled; construct protocol types directly. API endpoints also live in `src/api/advanced_protocols.rs`. |
| OpenID4VP  | `src/protocols/openid4vp.rs`  | `auth_framework::protocols::openid4vp`                          | Always enabled; direct module usage. API endpoints also live in `src/api/advanced_protocols.rs`.               |
| SD-JWT     | `src/protocols/sd_jwt.rs`     | `auth_framework::protocols::sd_jwt::{SdJwtIssuer, SdJwtConfig}` | Always enabled; create issuer / verifier types directly from the module.                                       |
| GNAP       | `src/protocols/gnap.rs`       | `auth_framework::protocols::gnap`                               | Always enabled; use the GNAP module APIs directly.                                                             |
| UMA        | `src/protocols/uma.rs`        | `auth_framework::protocols::uma`                                | Always enabled; use the UMA types and handlers directly.                                                       |
| SCIM       | `src/protocols/scim.rs`       | `auth_framework::protocols::scim`                               | Always enabled; integrate through the SCIM module for provisioning flows.                                      |
| SIWE       | `src/protocols/siwe.rs`       | `auth_framework::protocols::siwe`                               | Always enabled; direct module integration for Sign-In with Ethereum.                                           |

### Token, Credential, and Capability Formats

| Protocol         | Source                             | Entry Point                                  | Enablement / Configuration                                                               |
| ---------------- | ---------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------- |
| PASETO           | `src/protocols/paseto.rs`          | `auth_framework::protocols::paseto`          | Always enabled; use the PASETO module directly.                                          |
| Macaroons        | `src/protocols/macaroons.rs`       | `auth_framework::protocols::macaroons`       | Always enabled; direct module integration.                                               |
| HOTP             | `src/protocols/hotp.rs`            | `auth_framework::protocols::hotp`            | Always enabled; direct module usage for HOTP generation / verification.                  |
| FIDO U2F / FIDO1 | `src/protocols/fido1.rs`           | `auth_framework::protocols::fido1`           | Always enabled; use alongside passkeys when legacy U2F support is required.              |
| SAML Assertions  | `src/protocols/saml_assertions.rs` | `auth_framework::protocols::saml_assertions` | Always enabled; lower-level assertion handling separate from the top-level SAML feature. |

### Infrastructure, Federation, and Enterprise Protocols

| Protocol      | Source                           | Entry Point                                                 | Enablement / Configuration                                                                                                  |
| ------------- | -------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| SPIFFE        | `src/protocols/spiffe.rs`        | `auth_framework::protocols::spiffe`                         | Always enabled; API endpoint support also exists in `src/api/advanced_protocols.rs`.                                        |
| ACME          | `src/protocols/acme.rs`          | `auth_framework::protocols::acme::{AcmeClient, AcmeConfig}` | Always enabled; direct module configuration. API directory endpoint support also exists in `src/api/advanced_protocols.rs`. |
| CAEP          | `src/protocols/caep.rs`          | `auth_framework::protocols::caep`                           | Always enabled; continuous access event APIs also exist in `src/api/advanced_protocols.rs`.                                 |
| Kerberos      | `src/protocols/kerberos.rs`      | `auth_framework::protocols::kerberos`                       | Always enabled; use the Kerberos module directly.                                                                           |
| RADIUS        | `src/protocols/radius.rs`        | `auth_framework::protocols::radius`                         | Always enabled; direct module usage.                                                                                        |
| TACACS+       | `src/protocols/tacacs.rs`        | `auth_framework::protocols::tacacs`                         | Always enabled; direct module usage.                                                                                        |
| WS-Federation | `src/protocols/ws_federation.rs` | `auth_framework::protocols::ws_federation`                  | Always enabled; direct module usage.                                                                                        |
| WS-Trust      | `src/protocols/ws_trust.rs`      | `auth_framework::protocols::ws_trust`                       | Always enabled; direct module usage.                                                                                        |
| WS-Security   | `src/protocols/ws_security.rs`   | `auth_framework::protocols::ws_security`                    | Always enabled; direct module usage.                                                                                        |
| CAS           | `src/protocols/cas.rs`           | `auth_framework::protocols::cas`                            | Always enabled; direct module usage.                                                                                        |
| OAuth 1.0     | `src/protocols/oauth1.rs`        | `auth_framework::protocols::oauth1`                         | Always enabled; direct module usage for legacy interop.                                                                     |
| IndieAuth     | `src/protocols/indieauth.rs`     | `auth_framework::protocols::indieauth`                      | Always enabled; direct module usage.                                                                                        |

### Usage Pattern

When a protocol is listed in this section rather than in a top-level config
section above, the usual integration pattern is:

```rust,ignore
use auth_framework::protocols::acme::{AcmeClient, AcmeConfig};

let config = AcmeConfig::default();
let client = AcmeClient::new(config)?;
```

For Kerberos, use the builder or an environment preset:

```rust,ignore
use auth_framework::protocols::kerberos::KerberosConfig;

let config = KerberosConfig::builder("HTTP/server@EXAMPLE.COM", "EXAMPLE.COM")
    .keytab_path("/etc/krb5.keytab")
    .add_kdc("kdc.example.com:88")
    .build();

// Active Directory shorthand:
let config = KerberosConfig::active_directory("HTTP/server@CORP.COM", "CORP.COM");
```

For RADIUS, use the convenience constructor (validates the shared secret):

```rust,ignore
use auth_framework::protocols::radius::RadiusConfig;

let config = RadiusConfig::with_server("radius.corp:1812", "s3cret-key")?;
```

For exact constructors and configuration structs, use the rustdoc on the module
named in the table. These modules are implemented in the codebase and are part
of the library surface even when they are not yet wired through `AuthConfig`.

---

## Rate Limiting

**Source:** `src/config/mod.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust
use auth_framework::config::RateLimitConfig;
use std::time::Duration;

// Custom rate limiting
let config = RateLimitConfig {
    enabled: true,
    max_requests: 100,
    window: Duration::from_secs(60),
    burst: 20,
};

// Or use defaults (100 req/min, burst 10)
let config = RateLimitConfig::default();

// Convenience constructors — set max requests with a standard window
let config = RateLimitConfig::per_second(50);  // 50 req/s
let config = RateLimitConfig::per_minute(500); // 500 req/min
let config = RateLimitConfig::per_hour(10000); // 10 000 req/h
```

### Via the Builder

```rust,no_run
use auth_framework::prelude::*;
use std::time::Duration;

# #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
let auth = AuthFramework::builder()
    .with_jwt().secret("long-secret-key-at-least-32-chars!!").done()
    .with_storage().memory().done()
    .with_rate_limiting()
        .per_ip((200, Duration::from_secs(60)))
        .done()
    .build().await?;
# Ok(()) }
```

### Key Fields

| Field          | Default | Description             |
| -------------- | ------- | ----------------------- |
| `enabled`      | `true`  | Toggle rate limiting    |
| `max_requests` | 100     | Requests per window     |
| `window`       | 60 sec  | Sliding window duration |
| `burst`        | 10      | Burst allowance         |

---

## Multi-Factor Authentication

**Source:** `src/auth_modular/mfa/mod.rs`, `src/api/mfa.rs`
**Feature flag:** `otp-auth` (optional, for OTP library support)

### Enabling MFA

```rust,no_run
use auth_framework::config::AuthConfig;

let config = AuthConfig::new()
    .enable_multi_factor(true);
```

### TOTP Setup

```rust,ignore
// Generate TOTP secret for a user
let secret = mfa_manager.totp.generate_secret(&user_id).await?;
// secret is a Base32-encoded string (RFC 4648 with padding)

// Verify a TOTP code
let valid = mfa_manager.totp.verify_code(&user_id, "123456").await?;
```

### SMS MFA (via SMSKit)

```rust,ignore
use auth_framework::auth_modular::mfa::SmsKitConfig;
use auth_framework::auth_modular::mfa::SmsKitProvider;

let sms_config = SmsKitConfig {
    provider: SmsKitProvider::Twilio,
    config: SmsKitProviderConfig::Twilio {
        account_sid: "AC...".to_string(),
        auth_token: "...".to_string(),
        from_number: "+15551234567".to_string(),
        webhook_url: None,
    },
    fallback_provider: None,
    rate_limiting: Default::default(),
};

let mfa = MfaManager::new_with_smskit_config(storage, sms_config)?;
```

### Backup Codes

```rust,ignore
// Generate backup codes
let codes = mfa_manager.backup_codes.generate(&user_id).await?;

// Verify a backup code (consumes it)
let valid = mfa_manager.backup_codes.verify(&user_id, "ABCD-EFGH").await?;
```

### KV Storage Keys

| Key Pattern                          | TTL    | Description                       |
| ------------------------------------ | ------ | --------------------------------- |
| `mfa_enabled:{user_id}`              | —      | `b"true"` when MFA is active      |
| `mfa_secret:{user_id}`               | —      | TOTP secret (Base32)              |
| `mfa_backup_codes:{user_id}`         | —      | SHA-256 hashed codes (JSON array) |
| `mfa_pending_secret:{user_id}`       | 10 min | Secret during setup flow          |
| `mfa_pending_backup_codes:{user_id}` | 10 min | Codes during setup flow           |

---

## Session Management

**Source:** `src/session/manager.rs`
**Feature flag:** None (always enabled)

### Configuration

```rust,ignore
use auth_framework::session::SessionConfig;
use std::time::Duration;

let config = SessionConfig::builder()
    .default_duration(Duration::from_secs(3600))
    .max_duration(Duration::from_secs(86400))
    .idle_timeout(Duration::from_secs(900))
    .rotate_on_privilege_escalation(true)
    .rotate_periodically(true)
    .rotation_interval(Duration::from_secs(3600))
    .max_concurrent_sessions(5)
    .build();

let session_manager = SessionManager::new(config, storage).await?;
```

### Presets

For common deployment scenarios you can start from a preset and override individual fields:

```rust,ignore
use auth_framework::session::manager::SessionConfigBuilder;

// Typical web application (1h default, 24h max, 30min idle, 5 concurrent)
let config = SessionConfigBuilder::for_web_app().build();

// Stateless API / SPA backend (15min default, no fingerprinting, unlimited sessions)
let config = SessionConfigBuilder::for_api_service().build();

// High-security (30min default, 5min idle, single session, MFA on new devices)
let config = SessionConfigBuilder::for_high_security()
    .allowed_countries(vec!["US".into(), "GB".into()])
    .build();
```

### Key Fields

| Field                             | Default  | Description              |
| --------------------------------- | -------- | ------------------------ |
| `default_duration`                | 1 hour   | Default session lifetime |
| `max_duration`                    | 24 hours | Maximum session lifetime |
| `idle_timeout`                    | 15 min   | Inactivity timeout       |
| `rotate_on_privilege_escalation`  | `true`   | Rotate ID on escalation  |
| `rotate_periodically`             | `false`  | Enable periodic rotation |
| `rotation_interval`               | 1 hour   | Rotation period          |
| `max_concurrent_sessions`         | `None`   | Per-user session limit   |
| `track_device_fingerprints`       | `false`  | Enable device tracking   |
| `enforce_geographic_restrictions` | `false`  | Enable geo-fencing       |
| `allowed_countries`               | `[]`     | ISO country codes        |

### Geographic Restrictions

```rust,ignore
let config = SessionConfig::builder()
    .enforce_geographic_restrictions(true)
    .allowed_countries(vec!["US".into(), "CA".into(), "GB".into()])
    .build();
```

---

## RBAC / ABAC Authorization

**Source:** `src/authorization.rs`
**Feature flag:** `enhanced-rbac` (optional, upgrades to `role-system` v1.0)

### Basic RBAC Setup

```rust,ignore
use auth_framework::authorization::{AuthorizationEngine, AbacRole, AbacPermission};

let auth_engine = AuthorizationEngine::new(storage);

// Create a role with permissions
let mut admin_role = AbacRole::new("admin", "Administrator");
admin_role.add_permission(AbacPermission {
    name: "manage_users".to_string(),
    resource: "users".to_string(),
    action: "create".to_string(),
    conditions: None,
});
auth_engine.store_role(&admin_role).await?;
```

### Assigning Roles

```rust,ignore
use auth_framework::authorization::UserRole;
use std::time::SystemTime;

let user_role = UserRole {
    user_id: "user123".to_string(),
    role_id: "admin".to_string(),
    assigned_at: SystemTime::now(),
    expires_at: None,            // or Some(expiry_time)
    assigned_by: "system".to_string(),
};
auth_engine.assign_role(&user_role).await?;
```

### ABAC Access Control

```rust,ignore
use auth_framework::authorization::{AccessContext, AccessCondition};

// Build context with attributes
let context = AccessContext::new("user123")
    .with_resource("document_456")
    .with_resource_attribute("classification", "confidential")
    .with_user_attribute("department", "engineering")
    .with_user_attribute("clearance", "secret");

// Check permission
let allowed = auth_engine.check_permission(&context, &permission).await?;
```

### Access Conditions

```rust,ignore
// Time-based access
let condition = AccessCondition::TimeRange {
    start_hour: 9,
    end_hour: 17,
    timezone: "America/New_York".to_string(),
};

// IP allowlist
let condition = AccessCondition::IpWhitelist(vec![
    "10.0.0.0/8".to_string(),
    "192.168.1.0/24".to_string(),
]);

// Attribute-based
let condition = AccessCondition::UserAttribute {
    attribute: "department".to_string(),
    value: "engineering".to_string(),
    operator: "eq".to_string(),
};

// Logical combinations
let condition = AccessCondition::And(vec![time_condition, ip_condition]);
```

---

## Feature Flags Summary

### Always Enabled (Core)

These protocols and features are compiled into every build:

- OAuth 2.0 Server (authorization code, client credentials, PKCE, introspection, revocation)
- OpenID Connect Provider (ID tokens, UserInfo, discovery)
- DPoP (Proof-of-Possession)
- PAR (Pushed Authorization Requests)
- Device Authorization Grant (RFC 8628)
- Token Exchange (RFC 8693)
- CIBA (Backchannel Authentication)
- JARM (JWT-Secured Authorization Responses)
- Rate Limiting
- Session Management
- Basic MFA (TOTP, email, backup codes)
- Basic RBAC/ABAC

### Optional Feature Flags

| Feature         | Purpose                               | Key Dependencies                          |
| --------------- | ------------------------------------- | ----------------------------------------- |
| `saml`          | SAML 2.0 IdP/SP support               | `bergshamra`, `p256`, `p384`, `quick-xml` |
| `passkeys`      | WebAuthn / FIDO2 passkey support      | `coset`, `passkey`, `passkey-client`      |
| `enhanced-rbac` | Enterprise RBAC with role hierarchies | `role-system` v1.0                        |
| `otp-auth`      | OTP library for TOTP generation       | `totp-lite`                               |

### Storage Backends

| Feature            | Backend                      |
| ------------------ | ---------------------------- |
| *(default)*        | In-memory (development only) |
| `postgres-storage` | PostgreSQL via `sqlx`        |
| `redis-storage`    | Redis via `redis`            |
| `sqlite-storage`   | SQLite via `sqlx`            |

### Web Framework Integrations

| Feature              | Framework        |
| -------------------- | ---------------- |
| `axum-integration`   | Axum             |
| `actix-integration`  | Actix Web        |
| `warp-integration`   | Warp             |
| `rocket-integration` | Rocket           |
| `tower-integration`  | Tower middleware |

### Admin & Tooling

| Feature      | Purpose                                                                        |
| ------------ | ------------------------------------------------------------------------------ |
| `web-gui`    | Admin web GUI (login via `ADMIN_GUI_USERNAME` / `ADMIN_GUI_PASSWORD` env vars) |
| `cli-admin`  | Command-line administration tools                                              |
| `prometheus` | Prometheus metrics export                                                      |
| `hot-reload` | Runtime configuration reloading                                                |

### SMS Providers

| Feature         | Provider               |
| --------------- | ---------------------- |
| `smskit-twilio` | Twilio SMS integration |
| `smskit-plivo`  | Plivo SMS integration  |

---

## Related Documentation

- [Quick Start Guide](QUICK_START.md) — Get running in 5 minutes
- [OAuth 2.1 Security Guide](oauth21-security.md) — OAuth 2.1 hardening and security notes
- [WebAuthn and SAML Guide](WEBAUTHN_SAML_GUIDE.md) — WebAuthn and SAML deep dive
- [Storage Backends](storage-backends.md) — Storage configuration details
- [Security Configuration](guides/security-configuration.md) — Hardening guide
- [Administrator Setup](guides/administrator-setup.md) — Deployment and operations
