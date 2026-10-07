# Auth Framework

![Auth Framework](auth-framework.png)

## 🏆 The Most Complete Authentication & Authorization Framework for Rust

Security-first • Feature-rich • Batteries-included • Release candidate

[![Crates.io](https://img.shields.io/crates/v/auth-framework.svg)](https://crates.io/crates/auth-framework)
[![Documentation](https://docs.rs/auth-framework/badge.svg)](https://docs.rs/auth-framework)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1-blue.svg)](https://oauth.net/2.1/)
[![CI](https://github.com/ciresnave/auth-framework/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/ciresnave/auth-framework/actions/workflows/ci-cd.yml)

## ⚡ Quick Start - Get Running in Seconds

**No Rust installation required!** Use our precompiled binaries:

```bash
# Linux/macOS - One-line installation
curl -sSL https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.sh | bash

# Windows PowerShell - One command
iwr -useb https://raw.githubusercontent.com/ciresnave/auth-framework/main/scripts/install.ps1 | iex

# Docker - Instant deployment
# No `:latest` tag is published yet (every release so far has been a
# pre-release, which the image-tagging workflow doesn't tag `latest`) --
# pin to a real published tag; check
# https://github.com/ciresnave/auth-framework/pkgs/container/auth-framework
# for the current one.
docker run -p 8080:8080 ghcr.io/ciresnave/auth-framework:0.5.0-rc24
```

**That's it!** Server running at `http://localhost:8080` 🎉

The `auth-framework` executable now starts the standalone REST API server directly. Build the separate admin tool as `auth-framework-admin` with the `admin-binary` feature when you need the operational UI and CLI.

📖 [Full Deployment Guide](docs/DEPLOYMENT_GUIDE.md) • 🐳 [Docker Deployment](docker-compose.yml) • 🛠️ [Configuration Guide](docs/DEPLOYMENT_GUIDE.md#configuration) • 🧰 [Maintenance Operations Guide](docs/guides/maintenance-operations.md)

📚 [Feature Flags Guide](FEATURE_FLAGS.md) • [Supported Protocols](PROTOCOLS.md)

---

**Auth Framework** is a comprehensive authentication and authorization framework for Rust applications. The project is aimed at production deployments, but as an active release candidate it should still be validated against your environment, storage, TLS, and operational requirements before rollout.

## API Orientation

If you are integrating the Rust library directly, start with these entry points:

- `auth_framework::AuthFramework`: recommended default entry point for most applications.
- `auth_framework::ModularAuthFramework`: advanced entry point when you need direct access to individual managers.
- `auth_framework::prelude::*`: ergonomic imports for application code.
- `auth_framework::AppConfigBuilder`: simple in-process configuration builder.
- `auth_framework::LayeredConfigBuilder` and `auth_framework::ConfigManager`: layered configuration from files and environment variables.

This split exists to support both simple app integration and advanced composition, but new users should usually start with `AuthFramework` plus the prelude.

## 🚀 Why Auth Framework is the Best Choice

- **🏢 Complete Client & Server Solution**: The ONLY Rust framework providing both client authentication AND full OAuth 2.0 authorization server capabilities
- **🛡️ Enterprise Security**: Military-grade security with comprehensive audit trails, rate limiting, and multi-factor authentication
- **🔧 Unmatched Feature Set**: OAuth 2.0 server, OIDC provider, JWT server, SAML SP, WebAuthn RP, API gateway, and more
- **📊 Test Suite**: extensive test suite; recorded results in `docs/development/TESTING_RESULTS.md` are a **historical rc18 snapshot**, not the current CI state — read the CI badge above for that
- **⚡ High Performance**: Optimized for speed with async-first design and efficient memory usage
- **🌍 Framework Agnostic**: Seamless integration with Axum, Actix Web, Warp, and any Rust web framework
- **🔒 Zero-Trust Architecture**: Built from the ground up with security-first principles and defense in depth
- **📚 Developer Experience**: Comprehensive documentation, examples, and testing utilities for rapid development

> 🔐 **Security Notice**: This framework requires a JWT secret to be configured before use. See [`SECURITY_GUIDE.md`](docs/guides/SECURITY_GUIDE.md) for critical security requirements and best practices.
>
> ⚠️ **MySQL storage removed**: `mysql-storage` has been removed entirely (it was the last path to the RUSTSEC-2023-0071 RSA timing sidechannel in this crate). Use `postgres-storage`, `sqlite-storage`, or `redis-storage` instead. See [`SECURITY.md`](SECURITY.md) for details.

## 🆕 What's New in Latest Version

Historical release notes below include the test counts and quality metrics reported at the time of each release candidate. The current authoritative test status lives in `docs/development/TESTING_RESULTS.md` and the CI workflow.

**v0.5.0-rc24** - Release Publication Repair:

- **📝 Release notes now come from the committed changelog** - The release workflow extracts the current version section directly from `CHANGELOG.md` instead of trying to build the obsolete `orhun/git-cliff-action@v3` container
- **🐳 Prebuilt-musl Docker publishing retained** - The rc23 split runtime-image path remains in place, so release images still package prebuilt `auth-framework` musl binaries rather than compiling Rust in Docker publish jobs
- **🦾 Native arm64 musl release path retained** - The `aarch64-unknown-linux-musl` release build continues to use native `cargo` plus host `musl-gcc` on `ubuntu-24.04-arm`

**Previous: v0.5.0-rc6** - Storage Backend Correctness (audit cycle 13):

- **🐛 PostgreSQL `migrate()` DDL fixes** - The existing `migrate()` method contained two bugs: all three `CREATE TABLE` statements were passed to a single `sqlx::query()` call (sqlx accepts exactly one statement per call), and inline `INDEX` clauses were used inside `CREATE TABLE` (valid MySQL syntax but not PostgreSQL). Fixed by splitting into individual `execute()` calls and replacing inline indexes with separate `CREATE INDEX IF NOT EXISTS` statements.
- **🆕 MySQL `migrate()` added** - `MySqlStorage` lacked a `migrate()` method entirely; a new empty database would immediately fail on first use ("Table doesn't exist"). Added `MySqlStorage::migrate()` with proper MySQL DDL (`DATETIME(6)`, `JSON`, `LONGTEXT`, `ENGINE=InnoDB utf8mb4`), matching the PostgreSQL API exactly.
- **🧪 1,900+ tests, 0 clippy warnings**

**Previous: v0.5.0-rc5** - Integration Fixes & Lint Compliance (audit cycle 12):

- **🐛 Integration compile fixes** - `Permission` → `AbacPermission` in actix-web and warp integration modules (broken since rc2 type rename; previously hidden by feature gates)
- **📅 CHANGELOG date corrections** - rc3 and rc4 entries were dated 2025-10-07 (before rc2); all corrected to 2026-03-12
- **🔧 Idiomatic `_config` fields** - Removed `#[allow(dead_code)]` suppressions in analytics structs; replaced with underscore-prefix convention
- **📝 `.markdownlint.json`** - Added project-level config to allow repeated subsection headings across CHANGELOG version sections (Keep a Changelog standard)
- **🧪 1,900+ tests, 0 clippy warnings**

**Previous: v0.5.0-rc4** - Code Quality & Version Sync (audit cycle 11):

- **🔧 Mutex Safety** - All `.lock().unwrap()` calls in production code replaced with `.expect("mutex poisoned")` for clearer diagnostics if a mutex is poisoned
- **📚 Documented Initialize Stubs** - `initialize()` methods in `JwtServer`, `ApiGateway`, and `SamlIdentityProvider` now have doc comments explaining they are intentionally empty (all async setup is done in `new()`)
- **🔢 Version Consistency** - `Cargo.toml` and `README.md` now correctly reflect the current release candidate (were stale at rc1)
- **📝 README Fix** - Corrected a markdown fence that was touching a blockquote on the same line, causing MD040 lint errors
- **🧪 1,900+ tests, 0 clippy warnings**

**Previous: v0.5.0-rc3** - CIBA Spec Compliance & Quality Improvements:

- **🔐 CIBA Spec §7.1 / §11 Conformance** - `client_notification_token` is now forwarded as `Authorization: Bearer` in ping/push mode notifications, with validation that the token is present when required
- **🔧 Production-Grade Implementations** - Replaced all development stubs in auth.rs and authorization.rs with real implementations (TOTP secret retrieval, security metrics, instance ID, UTC time-range checks)
- **📚 Doc-Test Completeness** - 41 documentation examples now compiled with `no_run` (up from 0 passing doc-tests in rc2)
- **🧪 Test Suite Excellence** - **1,900+ tests total, 100% passing** (unit + integration + 41 doctests)
- **🔒 Code Quality** - All production `.unwrap()` calls replaced with `.expect()` with descriptive messages; `initialize()` stubs documented

**Previous: v0.5.0-rc2** - Security Audit Cycle:

- Comprehensive security audit with 9 audit cycles; all critical/high findings resolved
- 483 tests, 0 clippy warnings, full OWASP Top 10 compliance

**Previous: v0.5.0-rc1** - OAuth 2.1 Complete Implementation & Enhanced Security:

- **🔐 OAuth 2.1 Full Compliance** - Complete OAuth 2.1 authorization server implementation
  - Token Introspection (RFC 7662) - 9 comprehensive tests
  - Pushed Authorization Requests / PAR (RFC 9126) - 9 comprehensive tests
  - Device Authorization Flow (RFC 8628) - 14 comprehensive tests
  - End-to-end OAuth 2.1 flows - 9 integration tests
  - **41 OAuth tests total, 100% passing**
- **🛡️ Advanced Security Features** - Production-grade security enhancements
  - Rate Limiting - 12 tests covering burst protection and distributed systems
  - DoS Protection - 10 tests including Slowloris defense and resource exhaustion
  - IP Blacklisting - 12 tests for threat prevention and geolocation blocking
  - MFA Flows - 18 tests covering TOTP, enrollment, and recovery
  - **52 security tests total, 100% passing**
- **📊 Test Suite Excellence** - **93 comprehensive tests (100% passing)**
- **🏗️ Production Ready** - Complete authorization server capabilities

**Previous Release (v0.5.0-alpha)** - Phase 2: Password & Email Validation Complete:

- **🔐 Enhanced Password Validation** - Completely overhauled password validation system with granular complexity requirements
  - Added 8 new SecurityConfig fields for fine-grained password policy control
  - Advanced minimum complexity criteria system (meet N of 4 possible criteria)
  - Individual requirement toggles for maximum flexibility
  - Maintains full backward compatibility
- **� RFC 5322 Email Validation** - Industry-standard email validation using `email_address` crate
  - Full RFC 5322 compliance for professional-grade email format validation
  - Advanced parsing with configurable options
  - Comprehensive edge case handling for production use
- **⚙️ Configuration System Overhaul** - Enhanced SecurityConfig with comprehensive security controls
  - Added `LockoutConfig` structure for account lockout management
  - Added `OAuth2SecurityConfig` for OAuth2-specific security settings
  - Enhanced helper methods with all new security fields
- **🧪 Enhanced Test Suite** - **405 passing tests** with comprehensive validation coverage
  - 12 new validation tests covering all enhancement scenarios
  - Password complexity criteria testing with various combinations
  - Email validation testing with valid/invalid cases and edge cases

**Previous Release (v0.4.2)**:

- **393 passing tests** with 100% success rate, comprehensive error handling improvements
- Security utilities rebuild, enhanced email validation, improved password security

**Previous Major Features (v0.3.0)**:

- **🔧 Flexible Configuration Management** - Complete integration with `config` crate for multi-format configuration support
- **📁 Modular Configuration System** - Include directives for breaking configuration into logical components
- **🌍 Environment Variable Support** - Comprehensive environment variable mapping with precedence control
- **⚙️ CLI Integration** - Command-line argument parsing with clap integration
- **🏗️ Parent App Integration** - Seamless nesting of auth-framework config into larger applications
- **🔄 Configuration Layering** - Smart precedence: CLI → Environment → Files → Defaults
- **🚨 Automated Threat Intelligence** - Real-time threat feed updates with MaxMind GeoIP2 integration
- **🛡️ Enhanced Security Features** - Advanced rate limiting, IP geolocation tracking, and threat detection
- **📚 Comprehensive Documentation** - Configuration guides, integration examples, and best practices
- **🧪 Deployment Examples** - Docker, Kubernetes, and multi-environment configuration patterns

**Configuration Highlights**:

- **Multiple Format Support**: TOML, YAML, JSON configuration files
- **Environment Integration**: Full environment variable mapping with customizable prefixes
- **Modular Architecture**: Include files for organized, maintainable configuration
- **Parent App Friendly**: Easy integration into existing application configuration systems

## Features

### 🔐 Complete Authentication Arsenal

- **Client & Server Capabilities**: Full OAuth 2.0/2.1 client AND authorization server, OpenID Connect provider, JWT server
- **Multiple Authentication Methods**: OAuth 2.0/OIDC, JWT, API keys, password-based, SAML, WebAuthn, and custom methods
- **Enhanced Device Flow**: Complete OAuth device flow support (client & server) with [`oauth-device-flows`](https://crates.io/crates/oauth-device-flows) integration
- **Multi-Factor Authentication**: TOTP, SMS, email, hardware keys, and backup codes with configurable policies
- **Enterprise Identity Providers**: GitHub, Google, Microsoft, Discord, and custom OAuth providers with automatic profile mapping

### 🏢 Authorization Server Capabilities

- **OAuth 2.0 Authorization Server**: Complete RFC 6749 implementation with all grant types (authorization code, client credentials, refresh token, device flow)
- **OpenID Connect Provider**: Full OIDC 1.0 provider with ID tokens, UserInfo endpoint, and discovery
- **Dynamic Client Registration**: RFC 7591 compliant client registration and management
- **Advanced Grant Types**: Device authorization flow (RFC 8628), JWT bearer tokens (RFC 7523), SAML bearer assertions (RFC 7522)
- **Enterprise Features**: Token introspection (RFC 7662), token revocation (RFC 7009), PKCE (RFC 7636), and consent management

### 🛡️ Enterprise-Grade Security

- **Advanced Token Management**: Secure issuance, validation, refresh, and revocation with JWT/JWE support
- **Zero-Trust Session Management**: Secure session handling with rotation, fingerprinting, and concurrent session limits
- **Comprehensive Rate Limiting**: Built-in protection against brute force, credential stuffing, and abuse
- **Audit & Compliance**: Detailed audit logging, GDPR compliance features, and security event monitoring
- **Cryptographic Security**: bcrypt password hashing, secure random generation, and constant-time comparisons

### 🏗️ Production Infrastructure

- **Complete Server Stack**: OAuth 2.0 server, OIDC provider, JWT server, SAML SP ([Linux/macOS only for now](https://github.com/ciresnave/auth-framework/issues/106) -- we're looking for a way to support Windows too), WebAuthn RP, and API gateway
- **Multiple Storage Backends**: PostgreSQL (recommended), Redis (high-performance), SQLite, in-memory (development) with connection pooling
- **Framework Integration**: Native middleware for Axum, Actix Web, Warp, and extensible for any framework
- **Distributed Architecture**: Cross-node authentication validation and distributed rate limiting
- **Permission System**: Role-based access control (RBAC) with fine-grained permissions and attribute-based access control (ABAC)
- **Performance Optimized**: Async-first design, efficient memory usage, and optimized for high-throughput applications

### 🧪 Developer Excellence

- **Comprehensive Testing**: **1,900+ passing tests** with extensive coverage of OAuth 2.1, security, and integration scenarios
- **Mock Testing Framework**: Built-in testing utilities with configurable mocks and test helpers
- **Rich Documentation**: Complete API docs, security guides, and real-world examples
- **Type Safety**: Leverages Rust's type system for compile-time security guarantees
- **Error Handling**: Comprehensive error types with detailed context and recovery suggestions
- **Enhanced Reliability**: OAuth 2.1 compliance, advanced security features, and comprehensive validation

### 🆕 Grouped Operation Accessors

`AuthFramework` exposes its surface through focused, discoverable accessor methods so common operations
are easy to find and autocomplete works effectively:

```rust
use auth_framework::prelude::*;

# async fn example(auth: &AuthFramework) -> Result<(), Box<dyn std::error::Error>> {
// User management
let user_id = auth.users().register("alice", "alice@example.com", "hunter2").await?;
let profile = auth.users().profile(&user_id).await?;

// Token lifecycle
let token = auth.tokens().create(&user_id, vec!["read".into()], "jwt", None).await?;
let valid = auth.tokens().validate(&token).await?;

// Authorization
let allowed = auth.authorization().check(&token, "read", "documents").await?;

// Multi-factor authentication
let secret = auth.mfa().generate_totp_secret(&user_id).await?;

// Monitoring and health
let health = auth.monitoring().health_check().await?;

// Audit log
let logs = auth.audit().permission_logs(&user_id, "read", "documents", Some(20)).await?;
# Ok(())
# }
```

The full set of accessor groups is:

| Accessor               | Purpose                                                  |
| ---------------------- | -------------------------------------------------------- |
| `auth.users()`         | Register, look up, and manage user accounts              |
| `auth.sessions()`      | Create, retrieve, and delete sessions                    |
| `auth.tokens()`        | Issue, validate, refresh, and revoke tokens and API keys |
| `auth.authorization()` | Permission checks, role and policy management            |
| `auth.mfa()`           | TOTP, SMS, email, and backup-code MFA flows              |
| `auth.monitoring()`    | Health, metrics, rate-limit status                       |
| `auth.audit()`         | Permission logs and security statistics                  |
| `auth.admin()`         | ABAC policies, role inheritance, resource delegation     |

Import `auth_framework::prelude::*` to bring all types into scope at once.

### Device Flow Credential Constructors

### Security & Reliability

- **🔒 Security Audited**: Comprehensive security review with no critical vulnerabilities
- **🧪 Battle Tested**: 1,900+ passing tests with extensive integration and security testing
- **⚡ Performance Validated**: Benchmarked for high-throughput production environments
- **🛡️ CVE-Free**: Clean security record with proactive vulnerability management
- **📋 Compliance Ready**: GDPR, SOC 2, and enterprise compliance features built-in

### Industry Recognition

- **🥇 Most Complete**: The ONLY Rust auth framework with full client AND server capabilities (OAuth 2.0 server, OIDC provider, SAML SP)
- **🏢 Enterprise Ready**: Complete authorization server solution rivaling commercial products like Auth0, Okta, and AWS Cognito
- **🔧 Developer Friendly**: Extensive documentation, examples, and testing utilities for both client and server implementations
- **🌍 Production Scale**: Designed for enterprise-grade mission-critical applications requiring custom authorization servers
- **📈 Performance Leader**: Engineered for performance — designed to compete with commercial solutions using Rust's speed and memory efficiency
- **🔄 Future Proof**: Designed for extensibility with support for emerging standards and protocols

### 🆕 Enhanced Device Flow (Now More Convenient)

Convenience constructors for device flow credentials:

```rust
use auth_framework::{Credential, OAuthProvider};

// Create device flow credential with minimal code
let credential = Credential::enhanced_device_flow(
    OAuthProvider::GitHub,
    "client_id",
    vec!["user", "repo"]
);

// Or with a client secret if needed
let credential = Credential::enhanced_device_flow_with_secret(
    OAuthProvider::Google,
    "client_id",
    "client_secret",
    vec!["email", "profile"]
);

// Complete a device flow with a device code
let credential = Credential::enhanced_device_flow_complete(
    OAuthProvider::Microsoft,
    "client_id",
    "device_code",
    vec!["user.read"]
);
```

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = "0.5.0-rc24"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::{JwtMethod, AuthMethodEnum};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set environment for development/testing (allows memory storage)
    // SAFETY: Must not be called concurrently with other env mutations.
    unsafe { std::env::set_var("ENVIRONMENT", "development"); }

    // Configure the auth framework with required JWT secret
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secure-jwt-secret-at-least-32-characters-long".to_string());

    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7))
        .secret(jwt_secret);

    // Create the auth framework (storage is handled internally)
    let mut auth = AuthFramework::new(config);

    // Register the JWT method marker. AuthFramework validates JWTs with the
    // configured TokenManager when `authenticate("jwt", ...)` is called.
    auth.register_method("jwt", AuthMethodEnum::Jwt(JwtMethod::new()));

    // Initialize the framework
    auth.initialize().await?;

    // Create a JWT token for testing
    let token = auth.create_auth_token(
        "user123",
        vec!["read".to_string(), "write".to_string()],
        "jwt",
        None,
    ).await?;

    // Validate the token
    if auth.validate_token(&token).await? {
        println!("Token is valid!");

        // Check permissions
        if auth.check_permission(&token, "read", "documents").await? {
            println!("User has permission to read documents");
        }
    }

    Ok(())
}
```

## 🏢 OAuth 2.0 Authorization Server

Build your own OAuth 2.0 authorization server in minutes:

```rust
use auth_framework::{
    server::oauth::oauth2::{OAuth2Server, OAuth2ServerConfig},
    storage::memory::InMemoryStorage,
    client::ClientConfig,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the OAuth 2.0 authorization server
    let oauth2_config = OAuth2ServerConfig {
        issuer: "https://auth.yourcompany.com".to_string(),
        supported_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        supported_response_types: vec!["code".to_string()],
        supported_grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
    };

    // Create storage backend
    let storage = Arc::new(InMemoryStorage::new());

    // Create the OAuth 2.0 server with custom configuration
    let oauth2_server = OAuth2Server::new_with_config(
        storage.clone(),
        oauth2_config,
    ).await?;

    // Register a client application
    let client_config = ClientConfig {
        client_id: uuid::Uuid::new_v4().to_string(),
        client_secret: Some("my-client-secret".to_string()),
        client_type: auth_framework::ClientType::Confidential,
        redirect_uris: vec!["https://myapp.com/callback".to_string()],
        authorized_scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        authorized_grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        authorized_response_types: vec!["code".to_string()],
        client_name: Some("My Web App".to_string()),
        client_description: Some("My company's web application".to_string()),
        ..Default::default()
    };

    let registered = oauth2_server.register_client(client_config).await?;
    println!("Client registered: {}", registered.client_id);

    // Get server discovery metadata
    let discovery = oauth2_server.get_server_configuration().await?;
    println!("Discovery: {}", discovery);

    Ok(())
}
```

## 🔐 OpenID Connect Provider

Provide OpenID Connect authentication for your applications:

```rust
use auth_framework::{
    server::oidc::core::{OidcConfig, OidcProvider, SubjectType},
    storage::memory::InMemoryStorage,
    tokens::TokenManager,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(InMemoryStorage::new());

    let oidc_config = OidcConfig {
        issuer: "https://oidc.yourcompany.com".to_string(),
        subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "address".to_string(),
            "phone".to_string(),
        ],
        ..Default::default()
    };

    // Create token manager and OIDC provider
    let token_manager = Arc::new(TokenManager::new("your-jwt-secret-at-least-32-chars-long!"));
    let oidc_provider = OidcProvider::new(oidc_config, token_manager, storage).await?;

    // Get OpenID Connect discovery document
    let discovery = oidc_provider.get_discovery_document();
    println!("Issuer: {}", discovery["issuer"]);

    Ok(())
}
```

### OAuth Authentication

> **Note**: OAuth authentication is currently implemented through provider configurations and server components.
> For complete OAuth client flows, see the server examples in `examples/oauth2_authorization_server.rs` and `examples/complete_oauth2_server_axum.rs`.

```rust
use auth_framework::providers::OAuthProvider;

// OAuth providers are available for server implementations
let github_provider = OAuthProvider::GitHub;
let google_provider = OAuthProvider::Google;

// Build authorization URLs for OAuth flows
let auth_url = github_provider.build_authorization_url(
    "your-client-id",
    "<https://your-app.com/callback>",
    "random-state",
    Some(&["user:email".to_string()]),
    None
)?;

println!("Authorization URL: {}", auth_url);

// Exchange code for tokens (server-side)
let token_response = github_provider.exchange_code(
    "your-client-id",
    "your-client-secret",
    "authorization-code-from-callback",
    "<https://your-app.com/callback>",
    None
).await?;

println!("Access token: {}", token_response.access_token);

```

### API Key Authentication

```rust
use auth_framework::methods::{ApiKeyMethod, AuthMethodEnum};

// Set up API key authentication
auth.register_method("api_key", AuthMethodEnum::ApiKey(ApiKeyMethod::new()));

// Create a user and mint an API key for that user
let user_id = auth
    .register_user("user123", "user123@example.com", "StrongPassword123!")
    .await?;

// Create an API key for a user
let api_key = auth
    .create_api_key(&user_id, Some(Duration::from_secs(86400 * 30)))
    .await?;
println!("New API key: {}", api_key);

// Authenticate with API key
let credential = auth_framework::credentials::Credential::api_key(&api_key);
let result = auth.authenticate("api_key", credential).await?;
```

### Multi-Factor Authentication

```rust
// Enable MFA in configuration
let config = AuthConfig::new()
    .enable_multi_factor(true);

// Authentication with MFA
let credential = auth_framework::credentials::Credential::password("username", "password");
let result = auth.authenticate("password", credential).await?;

match result {
    auth_framework::AuthResult::MfaRequired(challenge) => {
        println!("MFA required. Challenge ID: {}", challenge.id());

        // User provides MFA code
        let mfa_code = "123456";
        let token = auth.complete_mfa(challenge, mfa_code).await?;
        println!("MFA successful!");
    }
    auth_framework::AuthResult::Success(token) => {
        println!("Direct authentication successful!");
    }
    auth_framework::AuthResult::Failure(reason) => {
        println!("Authentication failed: {}", reason);
    }
}
```

### Permission Management

```rust
use auth_framework::permissions::{Permission, Role, PermissionChecker};

// Permission checking is built into the AuthFramework
// Create a test token first
let token = auth.create_auth_token(
    "user123",
    vec!["read".to_string(), "write".to_string()],
    "jwt",
    None,
).await?;

// Check permissions
let can_read = auth.check_permission(&token, "read", "documents").await?;
let can_write = auth.check_permission(&token, "write", "documents").await?;
let can_delete = auth.check_permission(&token, "delete", "documents").await?;

println!("Can read: {}, Can write: {}, Can delete: {}", can_read, can_write, can_delete);
```

### Storage Configuration

> **Note**: MySQL storage (`mysql-storage`) has been removed entirely -- it was the last path to the RUSTSEC-2023-0071 RSA timing sidechannel in this crate. Use PostgreSQL, SQLite, or Redis instead.

#### PostgreSQL Storage (Recommended)

```rust
use auth_framework::config::{AuthConfig, StorageConfig};

let config = AuthConfig::new()
    .storage(StorageConfig::PostgreSQL {
        url: "postgresql://user:password@localhost:5432/auth_db".to_string(),
        max_connections: 100,
    });
```

#### Redis Storage

```rust
use auth_framework::config::{AuthConfig, StorageConfig};

let config = AuthConfig::new()
    .storage(StorageConfig::Redis {
        url: "redis://localhost:6379".to_string(),
        key_prefix: "auth:".to_string(),
    });
```

#### Custom Storage

```rust
use auth_framework::storage::AuthStorage;
use auth_framework::tokens::AuthToken;

#[derive(Clone)]
struct MyCustomStorage;

#[async_trait::async_trait]
impl AuthStorage for MyCustomStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        // Your custom storage implementation
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        // Your implementation
        Ok(None)
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        // Your implementation
        Ok(())
    }

    // Implement other required methods...
}

// Use your custom storage
let storage = Arc::new(MyCustomStorage);
let auth = AuthFramework::new_with_storage(config, storage);
```

### Rate Limiting

```rust
use auth_framework::config::RateLimitConfig;

let config = AuthConfig::new()
    .rate_limiting(RateLimitConfig::new(
        100, // max requests
        Duration::from_secs(60), // per minute
    ));
```

### Middleware Integration

#### Axum Integration

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

async fn auth_middleware(
    State(auth): State<Arc<AuthFramework>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    if let Some(token_str) = auth_header {
        // In a real implementation, you'd need to parse the token string back to AuthToken
        // This is simplified for demonstration
        if token_str.starts_with("valid_") {
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
```

#### Actix Web Integration

```rust
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;

async fn auth_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, Error> {
    let auth = req.app_data::<web::Data<AuthFramework>>().unwrap();

    if let Ok(Some(token)) = auth.storage.get_token_by_access_token(credentials.token()).await {
        if auth.validate_token(&token).await.unwrap_or(false) {
            req.extensions_mut().insert(token);
            return Ok(req);
        }
    }

    Err(AuthError::auth_method("bearer", "Invalid token").into())
}
```

### Device Flow Authentication

Device flow is supported through the provider implementations. See the OAuth server examples for complete device flow implementations:

```rust
use auth_framework::providers::OAuthProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Device flow is available through provider implementations
    // For complete examples, see:
    // - examples/oauth2_authorization_server.rs
    // - examples/complete_oauth2_server_axum.rs

    let provider = OAuthProvider::GitHub;

    // Device flow methods are available on providers:
    // provider.start_device_authorization()
    // provider.poll_device_token()
    // See server examples for complete implementation

    println!("Check server examples for complete device flow implementation");
    Ok(())
}
```

## Configuration

Auth-framework provides flexible configuration management using the `config` crate, supporting multiple formats, environment variables, and modular organization.

### Configuration Methods

1. **Configuration Files** - TOML, YAML, JSON formats supported
2. **Environment Variables** - Automatic mapping with customizable prefixes
3. **Command Line Arguments** - CLI overrides using clap integration
4. **Include Directives** - Modular configuration organization

### Quick Start Configuration

```toml
# auth-framework.toml
[jwt]
secret_key = "${JWT_SECRET_KEY:development-secret}"
algorithm = "HS256"
expiry = "1h"

[session]
name = "AUTH_SESSION"
secure = true
domain = "myapp.com"

# Include method-specific configurations
include = [
    "methods/oauth2.toml",
    "methods/mfa.toml",
    "methods/jwt.toml"
]
```

### Using ConfigManager in Code

```rust
use auth_framework::config::{ConfigManager, AuthFrameworkConfigManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from files and environment
    let config = AuthFrameworkConfigManager::builder()
        .with_file("config/auth-framework.toml")
        .with_env_prefix("AUTH")  // Maps AUTH_JWT_SECRET_KEY etc.
        .with_cli_args()         // Command line overrides
        .build()?;

    // Use the configuration in your auth service
    let auth_service = AuthService::new(config);

    Ok(())
}
```

### Environment Variable Mapping

The framework automatically maps environment variables:

```bash
# JWT Configuration
export AUTH_JWT_SECRET_KEY="production-secret"
export AUTH_JWT_ALGORITHM="RS256"
export AUTH_JWT_EXPIRY="15m"

# OAuth2 Configuration
export AUTH_OAUTH2_GOOGLE_CLIENT_ID="your-client-id"
export AUTH_OAUTH2_GOOGLE_CLIENT_SECRET="your-secret"

# Session Configuration
export AUTH_SESSION_SECURE="true"
export AUTH_SESSION_DOMAIN="myapp.com"
```

### Modular Configuration Structure

Organize configuration into logical modules:

```text
config/
├── auth-framework.toml    # Main configuration with includes
├── threat-intel.toml      # Threat intelligence settings
├── session.toml          # Session management configuration
└── methods/              # Authentication method configs
    ├── oauth2.toml       # OAuth2 provider settings
    ├── jwt.toml          # JWT method configuration
    ├── mfa.toml          # Multi-factor authentication
    └── api_key.toml      # API key authentication
```

### Parent Application Integration

Auth-framework configuration seamlessly integrates into larger application configs:

```toml
# your-app.toml
[app]
name = "MyApplication"
version = "1.0.0"

# Include auth-framework configuration
[auth]
include = ["auth-framework.toml"]

# Override specific auth settings
[auth.jwt]
secret_key = "production-secret"
issuer = "myapp.com"
```

For complete configuration documentation, see:

- [`config/INTEGRATION_GUIDE.md`](config/INTEGRATION_GUIDE.md) - Parent app integration patterns
- [`config/EXAMPLES.md`](config/EXAMPLES.md) - Practical configuration examples
- [`config/`](config/) directory - Example modular configuration files

## Security Considerations

1. **Secret Management**: Never hardcode secrets. Use environment variables or secure vaults.
2. **Token Storage**: Use secure storage backends in production (PostgreSQL recommended, Redis for sessions).
3. **HTTPS**: Always use HTTPS in production to protect tokens in transit.
4. **Rate Limiting**: Enable rate limiting to prevent brute force attacks.
5. **Token Expiration**: Set appropriate token lifetimes based on your security requirements.
6. **Audit Logging**: Enable comprehensive audit logging for security monitoring.
7. **Storage Encryption at Rest**: On by default for every persistent storage
   backend — set `AUTH_STORAGE_ENCRYPTION_KEY` (initialization fails closed
   without it). The key source is currently an environment variable or local
   file, not a KMS — see [Encrypted Storage](docs/storage-backends.md#encrypted-storage)
   for the full picture, including that limitation and the migration tool for
   existing plaintext data.

## RSA Key Format Support

When using RSA keys for JWT signing and verification, the framework supports both standard PEM formats:

### Supported Formats

- **PKCS#1 Format** (Traditional RSA format):

  ```text
  -----BEGIN RSA PRIVATE KEY-----
  -----END RSA PRIVATE KEY-----
  ```

- **PKCS#8 Format** (Modern standard format, **recommended**):

  ```text
  -----BEGIN PRIVATE KEY-----
  -----END PRIVATE KEY-----
  ```

### Usage

Both formats are automatically detected and work seamlessly with the `TokenManager`:

```rust
use auth_framework::tokens::TokenManager;

// Load your RSA keys (either PKCS#1 or PKCS#8 format)
let private_key = std::fs::read("private.pem")?;
let public_key = std::fs::read("public.pem")?;

// Create token manager - format is auto-detected
let token_manager = TokenManager::new_rsa(
    &private_key,
    &public_key,
    "your-issuer",
    "your-audience"
)?;
```

### Key Generation

Generate RSA keys in your preferred format:

```bash
# Generate PKCS#1 format (traditional)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Generate PKCS#8 format (recommended)
openssl genpkey -algorithm RSA -out private_pkcs8.pem -pkcs8
openssl pkey -in private_pkcs8.pem -pubout -out public_spki.pem
```

**Note**: No format conversion is required - the framework handles both formats automatically.

## 📚 Examples

### 🔧 Client Examples (Ready to Use)

See the `examples/` directory for complete client examples:

- `basic_usage_corrected.rs` - Basic authentication setup (✅ working)
- `cli_auth_tool.rs` - Complete CLI authentication tool (✅ working)

### 🚀 Server Examples (NEW - Complete Authorization Server)

**Full OAuth 2.0 Authorization Server Examples:**

- `oauth2_authorization_server.rs` - Complete OAuth 2.0 server setup with client registration
- `complete_oauth2_server_axum.rs` - Axum server reference implementation with AuthFramework integration
- `production_deployments.rs` - Enterprise deployment configurations for different environments

**Server Features Demonstrated:**

- ✅ **OAuth 2.0 Authorization Server** - Complete RFC 6749 implementation with all grant types
- ✅ **OpenID Connect Provider** - Full OIDC 1.0 support with UserInfo endpoint
- ✅ **Dynamic Client Registration** - RFC 7591 compliant client management
- ✅ **Device Authorization Grant** - RFC 8628 device flow for CLI applications
- ✅ **Token Introspection** - RFC 7662 token introspection endpoint
- ✅ **PKCE Support** - RFC 7636 for enhanced security
- ✅ **Web Framework Integration** - Ready-to-use Axum, Actix Web, and Warp examples
- ✅ **Production Deployments** - Enterprise, high-availability, and microservices configurations

### 🏢 Deployment Examples

Choose the deployment that fits your needs:

| Deployment Type       | Use Case           | Storage                    | Features                        |
| --------------------- | ------------------ | -------------------------- | ------------------------------- |
| **Development**       | Local testing      | In-memory                  | Relaxed security, test clients  |
| **Single Server**     | Small-medium apps  | PostgreSQL + Redis         | Standard production features    |
| **High Availability** | Large applications | PostgreSQL cluster + Redis | Load balancing, shared state    |
| **Enterprise**        | Fortune 500        | Encrypted storage + HSM    | Advanced security, compliance   |
| **Microservices**     | Service mesh       | Service discovery          | Health checks, circuit breakers |

### 🚀 Quick Start Server

```bash
# Run a complete OAuth 2.0 authorization server
cargo run --example oauth2_authorization_server

# Run with Axum web framework integration
cargo run --example complete_oauth2_server_axum --features axum-integration

# Run enterprise deployment
DEPLOYMENT_TYPE=enterprise cargo run --example production_deployments
```

**Note**: Server examples are reference implementations. Review secrets management, storage, TLS, deployment topology, and compliance settings before treating an example as production-ready.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our development process, coding standards, and how to submit pull requests.

## Security

Security is our top priority. Please review our [Security Policy](SECURITY.md) for:

- Reporting security vulnerabilities
- Security best practices
- Supported versions
- Compliance information

For security issues, please email [ciresnave@gmail.com](mailto:ciresnave@gmail.com) instead of using the issue tracker.

## License

This project is licensed under the MIT OR Apache-2.0 license.

### Testing Your Authentication Code

The framework provides comprehensive testing utilities to make testing your authentication logic easy:

```toml
[dev-dependencies]
auth-framework = { version = "0.5.0-rc24", features = ["testing"] }
```

```rust
use auth_framework::{
    testing::{MockAuthMethod, MockStorage, helpers},
    AuthFramework, AuthConfig, Credential,
};

#[tokio::test]
async fn test_user_authentication() {
    // Create a test auth framework
    let mut auth = helpers::create_test_auth_framework();

    // Set up a mock authentication method
    let mock_method = MockAuthMethod::new_success()
        .with_user("testuser".to_string(), helpers::create_test_user_profile("testuser"));

    auth.register_method("mock", Box::new(mock_method));
    auth.initialize().await.unwrap();

    // Test authentication
    let credential = Credential::password("testuser", "password");
    let result = auth.authenticate("mock", credential).await.unwrap();

    match result {
        auth_framework::AuthResult::Success(token) => {
            assert_eq!(token.user_id, "testuser");
            assert!(token.scopes.contains(&"read".to_string()));
        }
        _ => panic!("Expected successful authentication"),
    }
}

#[tokio::test]
async fn test_authentication_failure() {
    let mut auth = helpers::create_test_auth_framework();

    // Mock method that always fails
    let mock_method = MockAuthMethod::new_failure();
    auth.register_method("mock", Box::new(mock_method));
    auth.initialize().await.unwrap();

    let credential = Credential::password("testuser", "wrong_password");
    let result = auth.authenticate("mock", credential).await.unwrap();

    match result {
        auth_framework::AuthResult::Failure(_) => {
            // Expected
        }
        _ => panic!("Expected authentication failure"),
    }
}

#[tokio::test]
async fn test_token_storage() {
    let storage = MockStorage::new();
    let token = helpers::create_test_token("testuser");

    // Store and retrieve token
    storage.store_token(&token).await.unwrap();
    let retrieved = storage.get_token(&token.id).await.unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().user_id, "testuser");
}
```

**Testing Features:**

- `MockAuthMethod` - Configurable mock authentication
- `MockStorage` - In-memory storage for testing
- `helpers::create_test_*` - Helper functions for test data
- Configurable delays and failures for testing edge cases
- Comprehensive test coverage examples

## Error Handling

The framework provides specific error types for better error handling:

```rust
use auth_framework::{AuthError, DeviceFlowError, OAuthProviderError};

async fn handle_auth_errors() {
    // Device flow specific errors
    match some_device_flow_operation().await {
        Err(AuthError::DeviceFlow(DeviceFlowError::AuthorizationPending)) => {
            println!("User hasn't completed authorization yet");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::SlowDown)) => {
            println!("Polling too frequently, slowing down");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::ExpiredToken)) => {
            println!("Device code expired, need to restart flow");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::AccessDenied)) => {
            println!("User denied authorization");
        }
        _ => {}
    }

    // OAuth provider specific errors
    match some_oauth_operation().await {
        Err(AuthError::OAuthProvider(OAuthProviderError::InvalidAuthorizationCode)) => {
            println!("Authorization code is invalid or expired");
        }
        Err(AuthError::OAuthProvider(OAuthProviderError::InsufficientScope { required, granted })) => {
            println!("Insufficient permissions: need '{}', got '{}'", required, granted);
        }
        Err(AuthError::OAuthProvider(OAuthProviderError::RateLimited { message })) => {
            println!("Rate limited by provider: {}", message);
        }
        _ => {}
    }

    // General auth errors
    match some_auth_operation().await {
        Err(AuthError::InvalidCredential { credential_type, message }) => {
            println!("Invalid {}: {}", credential_type, message);
        }
        Err(AuthError::Timeout { timeout_seconds }) => {
            println!("Operation timed out after {} seconds", timeout_seconds);
        }
        Err(AuthError::ProviderNotConfigured { provider }) => {
            println!("Provider '{}' is not configured", provider);
        }
        _ => {}
    }
}
```

## Provider Configuration

OAuth providers are available for server-side implementations. See the server examples for complete provider usage:

```rust
use auth_framework::providers::{OAuthProvider, OAuthProviderConfig, UserProfile};
use std::collections::HashMap;

// Available providers for OAuth server implementations
let github_provider = OAuthProvider::GitHub;
let google_provider = OAuthProvider::Google;
let microsoft_provider = OAuthProvider::Microsoft;

// Custom provider configuration
let custom_provider = OAuthProvider::Custom {
    name: "My Provider".to_string(),
    config: OAuthProviderConfig {
        authorization_url: "https://auth.example.com/authorize".to_string(),
        token_url: "https://auth.example.com/token".to_string(),
        device_authorization_url: Some("https://auth.example.com/device".to_string()),
        userinfo_url: Some("https://auth.example.com/userinfo".to_string()),
        revocation_url: Some("https://auth.example.com/revoke".to_string()),
        default_scopes: vec!["read".to_string(), "profile".to_string()],
        supports_pkce: true,
        supports_refresh: true,
        supports_device_flow: true,
        additional_params: HashMap::new(),
    },
};

// For complete OAuth server implementation examples, see:
// - examples/oauth2_authorization_server.rs
// - examples/complete_oauth2_server_axum.rs
```

## User Profile Standardization

The framework provides a standardized `UserProfile` type that works across all providers:

```rust
use auth_framework::providers::UserProfile;

// Creating user profiles
let profile = UserProfile::new("user123", "github")
    .with_name("John Doe")
    .with_email("john@example.com")
    .with_email_verified(true)
    .with_picture("https://github.com/avatar.jpg")
    .with_locale("en-US")
    .with_additional_data("github_login".to_string(), serde_json::Value::String("johndoe".to_string()));

// Converting to your application's user type
#[derive(serde::Deserialize)]
struct AppUser {
    id: String,
    name: String,
    email: String,
    avatar_url: Option<String>,
}

impl From<UserProfile> for AppUser {
    fn from(profile: UserProfile) -> Self {
        Self {
            id: profile.id,
            name: profile.name.unwrap_or_default(),
            email: profile.email.unwrap_or_default(),
            avatar_url: profile.picture,
        }
    }
}

// Usage
let app_user: AppUser = user_profile.into();
```

## Credential Types Guide

Understanding the relationship between credentials and authentication methods:

```rust
use auth_framework::Credential;

// Password credentials -> PasswordMethod
let password_cred = Credential::password("username", "password");

// API key -> ApiKeyMethod
let api_key_cred = Credential::api_key("your_api_key_here");

// JWT token -> JwtMethod
let jwt_cred = Credential::jwt("jwt.token.string");

// OAuth flows are handled by the OAuth server implementation
// See server examples for complete OAuth credential handling
let device_cred = Credential::Custom {
    method: "device_code".to_string(),
    data: {
        let mut data = HashMap::new();
        data.insert("device_code".to_string(), "device_code_string".to_string());
        data.insert("client_id".to_string(), "your_client_id".to_string());
        data
    }
};

// Multi-factor authentication
let mfa_cred = Credential::Mfa {
    primary_credential: Box::new(password_cred),
    mfa_code: "123456".to_string(),
    challenge_id: "mfa_challenge_id".to_string(),
};

// Custom credentials for custom auth methods
let custom_cred = Credential::Custom {
    method: "custom_auth".to_string(),
    data: {
        let mut data = HashMap::new();
        data.insert("token".to_string(), "custom_token".to_string());
        data.insert("signature".to_string(), "signature_string".to_string());
        data
    }
};
```

## CLI Integration

Helper utilities for integrating with CLI frameworks:

```toml
[dependencies]
auth-framework = "0.5.0-rc24"
clap = "4.0"
tokio = { version = "1.0", features = ["full"] }
```

```rust
use auth_framework::{AuthFramework, AuthConfig, Credential};
use auth_framework::providers::OAuthProvider;
use clap::{Arg, Command};

fn create_auth_command() -> Command {
    Command::new("myapp")
        .subcommand(
            Command::new("auth")
                .about("Authenticate with OAuth provider")
                .arg(
                    Arg::new("provider")
                        .short('p')
                        .long("provider")
                        .value_name("PROVIDER")
                        .help("OAuth provider (github, google, microsoft)")
                        .default_value("github")
                )
                .arg(
                    Arg::new("client-id")
                        .long("client-id")
                        .value_name("CLIENT_ID")
                        .help("OAuth client ID")
                        .env("OAUTH_CLIENT_ID")
                        .required(true)
                )
                .arg(
                    Arg::new("device-flow")
                        .long("device-flow")
                        .help("Use device flow authentication")
                        .action(clap::ArgAction::SetTrue)
                )
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = create_auth_command().get_matches();

    if let Some(auth_matches) = matches.subcommand_matches("auth") {
        let provider = auth_matches.get_one::<String>("provider").unwrap();
        let client_id = auth_matches.get_one::<String>("client-id").unwrap();
        let use_device_flow = auth_matches.get_flag("device-flow");

        if use_device_flow {
            perform_device_flow_auth(provider, client_id).await?;
        } else {
            perform_web_flow_auth(provider, client_id).await?;
        }
    }

    Ok(())
}

async fn perform_device_flow_auth(provider: &str, client_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Starting device flow authentication with {}...", provider);

    // Set up auth framework
    let config = AuthConfig::new();
    let mut auth = AuthFramework::new(config);

    // OAuth providers are available for server-side implementations
    let oauth_provider = match provider {
        "github" => OAuthProvider::GitHub,
        "google" => OAuthProvider::Google,
        "microsoft" => OAuthProvider::Microsoft,
        _ => return Err("Unsupported provider".into()),
    };

    println!("Selected provider: {:?}", oauth_provider);

    // For complete OAuth server implementation, see:
    // - examples/oauth2_authorization_server.rs
    // - examples/complete_oauth2_server_axum.rs
    println!("✅ Provider configuration complete!");

    Ok(())
}

async fn perform_web_flow_auth(provider: &str, client_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Starting web flow authentication with {}...", provider);

    // Generate authorization URL and open browser
    // Implementation details...

    Ok(())
}
```

AuthFramework includes protocol implementations for:

- PASETO (v4.local tokens)
- Macaroons (HMAC-SHA256 chained caveats)
- TACACS+ (RFC 8907 packet construction and obfuscation)
- SIWE (Sign-In with Ethereum, ERC-4361)
- IndieAuth (OAuth 2.0 with PKCE for IndieWeb)
- OAuth 1.0a (RFC 5849 request signing)
- FIDO1 / U2F (Universal 2nd Factor registration and authentication)
- UMA 2.0 (User-Managed Access)
- SAML 2.0 (Assertion builder and validator)
- SCIM 2.0 (Cross-domain identity management)
- CAS (Central Authentication Service)
- RADIUS (Remote Authentication Dial-In User Service)
- WS-Federation, WS-Security, WS-Trust
- ACME, SPIFFE, CAEP, OpenID4VCI, OpenID4VP, GNAP, Kerberos, HOTP
