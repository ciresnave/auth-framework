#![deny(clippy::unwrap_used)]

/*!
# Auth Framework

A comprehensive authentication and authorization framework for Rust applications.

This crate provides a unified interface for various authentication methods,
token management, permission checking, and secure credential handling with
a focus on distributed systems.

## API Orientation

- Use [`AuthFramework`] as the default entry point for most applications.
- Use [`ModularAuthFramework`] only when you explicitly want manager-level
  composition and lifecycle control.
- Use [`prelude`] when you want ergonomic imports for application code.
- Use [`AppConfigBuilder`] for simple application-owned configuration values.
- Use [`LayeredConfigBuilder`] and [`ConfigManager`] when you need layered
  configuration from files and environment variables.

## Features

- Multiple authentication methods (OAuth, API keys, JWT, etc.)
- Token issuance, validation, and refresh with RSA and HMAC signing
- RSA key format support: PKCS#1 and PKCS#8 formats auto-detected
- Role-based access control integration
- Permission checking and enforcement
- Secure credential storage
- Authentication middleware for web frameworks
- Distributed authentication with cross-node validation
- Single sign-on capabilities
- Multi-factor authentication support
- Audit logging of authentication events
- Rate limiting and brute force protection
- Session management
- Password hashing and validation
- Customizable authentication flows

## Quick Start

```rust,no_run
use auth_framework::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build configuration.  JWT secret must be at least 32 characters.
    let config = AuthConfig::new()
        .token_lifetime(std::time::Duration::from_secs(3600))
        .secret(std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "replace-with-a-32-char-random-secret!!".to_string()));

    let mut auth = AuthFramework::new(config);
    auth.initialize().await?;

    // Register a user.
    let user_id = auth.users().register("alice", "alice@example.com", "s3cr3t!").await?;

    // Issue a token via the grouped token accessor.
    let token = auth.tokens().create(&user_id, &["read"], "jwt", None).await?;

    // Validate and authorize.
    if auth.tokens().validate(&token).await? {
        if auth.authorization().check(&token, "read", "documents").await? {
            println!("Alice may read documents.");
        }
    }

    Ok(())
}
```

See [`prelude`] for the full set of re-exported types, and the accessor groups
[`AuthFramework::users`], [`AuthFramework::sessions`], [`AuthFramework::tokens`],
[`AuthFramework::authorization`], [`AuthFramework::mfa`], [`AuthFramework::monitoring`],
[`AuthFramework::audit`], and [`AuthFramework::admin`] for organized entry points
into each capability area.

## Security Considerations

- Always use HTTPS in production
- Use strong, unique secrets for token signing
- Enable rate limiting to prevent brute force attacks
- Regularly rotate secrets and keys
- Monitor authentication events for suspicious activity
- Follow the principle of least privilege for permissions

See the [Security Policy](https://github.com/ciresnave/auth-framework/blob/main/SECURITY.md)
for comprehensive security guidelines.
*/

// REST API Server
#[cfg(feature = "api-server")]
pub mod api;

// Admin interface (conditional on admin-binary feature)
#[cfg(feature = "admin-binary")]
pub mod admin;

// ────────────────────────────────────────────────────────────────────────────
// Core framework modules
// ────────────────────────────────────────────────────────────────────────────

/// Primary authentication framework — start here.
///
/// Contains [`AuthFramework`], the main entry point for most applications.
/// Access grouped operations via [`AuthFramework::users`], [`AuthFramework::tokens`],
/// [`AuthFramework::sessions`], etc.
pub mod auth;

/// Advanced component-oriented framework.
///
/// Use [`ModularAuthFramework`](auth_modular::AuthFramework) only when you need
/// direct access to individual manager instances (user, session, MFA) for custom
/// composition. Most applications should use [`auth::AuthFramework`] instead.
pub mod auth_modular;

/// Grouped operation facades over [`AuthFramework`].
///
/// Light reference wrappers (e.g. [`UserOperations`], [`TokenOperations`]) returned
/// by the accessor methods on `AuthFramework`. Not usually imported directly —
/// use `auth.users()`, `auth.tokens()`, etc.
pub mod auth_operations;

/// Supporting authentication data types.
///
/// Credentials, metadata, and MFA primitives used as inputs to the core
/// framework. Import specific types rather than the module wildcard.
pub mod authentication;

/// Domain-specific newtypes (`Roles`, `Scopes`, `Permissions`, etc.).
pub mod types;

/// Error types and the crate-wide [`Result`](errors::Result) alias.
pub mod errors;

/// Authentication method implementations (JWT, OAuth2, API keys, passwords, SAML).
pub mod methods;

/// Permission and role definitions for access control.
pub mod permissions;

/// Token creation, validation, rotation, and JWKS support.
pub mod tokens;

// ────────────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────────────

/// Configuration types and management.
///
/// - [`AuthConfig`](config::AuthConfig) — main config struct (use [`AuthConfig::new()`]
///   for fluent setters or [`AuthConfig::builder()`] for the full builder).
/// - [`ConfigManager`](config::ConfigManager) — layered config from files + env.
/// - [`AppConfig`](config::AppConfig) — simple app-owned config values.
pub mod config;

// ────────────────────────────────────────────────────────────────────────────
// Storage & persistence
// ────────────────────────────────────────────────────────────────────────────

/// Storage backends and the [`AuthStorage`](storage::AuthStorage) trait.
///
/// See the trait documentation for available backends (Memory, PostgreSQL,
/// MySQL, Redis, SQLite, Encrypted) and guidance on writing custom backends.
pub mod storage;

// ────────────────────────────────────────────────────────────────────────────
// Security
// ────────────────────────────────────────────────────────────────────────────

/// Audit logging of authentication and authorization events.
pub mod audit;

/// Role-based and attribute-based access control (RBAC/ABAC).
pub mod authorization;
#[cfg(feature = "role-system")]
pub mod authorization_enhanced;
/// Security utilities: rate limiting, DoS protection, IP blocking, and JWT hardening.
pub mod security;

// ────────────────────────────────────────────────────────────────────────────
// Session & distributed state
// ────────────────────────────────────────────────────────────────────────────

/// Session lifecycle, device fingerprinting, and risk scoring.
pub mod session;

/// Distributed authentication: cross-node token validation and cluster coordination.
pub mod distributed;

// ────────────────────────────────────────────────────────────────────────────
// Server-side protocol implementations
// ────────────────────────────────────────────────────────────────────────────

/// Server-side OAuth 2.0 / OIDC / FAPI protocol implementations.
pub mod server;

// oauth2_server and oauth2_enhanced_storage now live under server::oauth.
pub use server::oauth::oauth2_enhanced_storage;
pub use server::oauth::oauth2_server;

/// OAuth 2.0 client type definitions (RFC 6749 §2.1).
pub mod client;

// ────────────────────────────────────────────────────────────────────────────
// Integrations, providers & transport
// ────────────────────────────────────────────────────────────────────────────

/// OAuth 2.0 provider configuration and PKCE helpers.
pub mod providers;

/// Helpers for extracting user profiles from tokens and provider responses.
pub mod profile_utils;

/// Multi-tenant support for native multi-tenant deployments.
pub mod tenant;

/// User context and session enrichment.
pub mod user_context;

// ────────────────────────────────────────────────────────────────────────────
// Monitoring, analytics & operations
// ────────────────────────────────────────────────────────────────────────────

/// Monitoring, health checks, and performance metrics.
pub mod monitoring;

/// Analytics collection and reporting.
pub mod analytics;

/// Deployment, scaling, and infrastructure management.
pub mod deployment;

/// Threat intelligence feeds and IP reputation services.
pub mod threat_intelligence;

// ────────────────────────────────────────────────────────────────────────────
// Migration & maintenance
// ────────────────────────────────────────────────────────────────────────────

/// Schema migration utilities for role-system v1.0 integration.
pub mod migration;

/// SQL migration scripts for database backends.
pub mod migrations;

/// Backup, restore, and reset utilities.
pub mod maintenance;

// ────────────────────────────────────────────────────────────────────────────
// Developer tools
// ────────────────────────────────────────────────────────────────────────────

/// Ergonomic builders and prelude for better developer experience.
pub mod builders;

/// Convenience re-exports for common types — `use auth_framework::prelude::*`.
pub mod prelude;

/// Internal utility functions.
pub mod utils;

/// Test helpers and mock implementations for downstream testing.
pub mod testing;

/// Protocol-level types shared across OAuth, OIDC, and SAML flows.
pub mod protocols;

/// Command-line interface utilities.
pub mod cli;

// ────────────────────────────────────────────────────────────────────────────
// Feature-gated optional modules
// ────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "enhanced-observability")]
pub mod observability;

#[cfg(feature = "event-sourcing")]
pub mod architecture;

// SDK generation for multiple languages
#[cfg(feature = "enhanced-rbac")]
pub mod sdks;

// ────────────────────────────────────────────────────────────────────────────
// Web framework integrations
// ────────────────────────────────────────────────────────────────────────────

/// Ready-made middleware and extractors for popular web frameworks.
///
/// Enable the appropriate feature flag to pull in the integration you need:
///
/// | Feature | Module |
/// |---------|--------|
/// | `axum-integration` | [`integrations::axum`] |
/// | `actix-integration` | [`integrations::actix_web`] |
/// | `warp-integration` | [`integrations::warp`] |
pub mod integrations {
    #[cfg(feature = "axum-integration")]
    pub mod axum;

    #[cfg(feature = "actix-integration")]
    pub mod actix_web;

    #[cfg(feature = "warp-integration")]
    pub mod warp;
}

// ────────────────────────────────────────────────────────────────────────────
// Re-exports — public API surface
// ────────────────────────────────────────────────────────────────────────────

// Re-exports - Main modular auth framework components
pub use crate::auth::{
    AdminOperations, AuditOperations, AuthFramework, AuthResult, AuthStats,
    AuthorizationOperations, MaintenanceOperations, MfaOperations, MonitoringOperations,
    SessionOperations, TokenOperations, UserInfo, UserOperations,
};

/// Deprecated alias — use [`UserInfo`] directly.
#[deprecated(
    since = "0.5.0",
    note = "Use `UserInfo` directly — the `Core` prefix is redundant"
)]
pub type CoreUserInfo = UserInfo;
pub use crate::auth_modular::AuthFramework as ModularAuthFramework;
pub use crate::maintenance::{
    BackupReport, MaintenanceSnapshot, MigrationFileReport, ResetReport, RestoreReport,
    SnapshotManifest,
};
pub use authentication::credentials::Credential;
pub use config::app_config::ConfigBuilder as AppConfigBuilder;
pub use config::config_manager::{
    ApiServerSettings, AuthFrameworkSettings, ConfigBuilder as LayeredConfigBuilder, ConfigManager,
};
pub use config::{AuthConfig, AuthConfigBuilder, CorsConfig, app_config::AppConfig};
pub use errors::{AuthError, Result};
pub use methods::{
    ApiKeyMethod, AuthMethod, JwtMethod, MethodResult, OAuth2Method, PasswordMethod,
};

// REST API Server exports
#[cfg(feature = "api-server")]
pub use api::{ApiError, ApiResponse, ApiServer, ApiState};

// SAML support (feature-gated)
#[cfg(feature = "saml")]
pub use methods::saml;

// PKCE support functions
pub use providers::generate_pkce;

pub use permissions::{Permission, PermissionChecker, Role};
pub use profile_utils::{ExtractProfile, TokenToProfile};
pub use providers::{
    DeviceAuthorizationResponse, OAuthProvider, OAuthProviderConfig, ProviderProfile,
};
pub use tokens::AuthToken;

// WS-Security 1.1 and WS-Trust — enterprise XML security protocols.
// Hidden from root docs; access via `auth_framework::protocols::ws_security` / `ws_trust`.
#[doc(hidden)]
pub use protocols::ws_security::{
    UsernameToken, WsSecurityClient, WsSecurityConfig, WsSecurityHeader,
};
#[doc(hidden)]
pub use protocols::ws_trust::RequestSecurityToken;

// Server-side OIDC types.
//
// Note: the OIDC spec defines its own `UserInfo` struct (the /userinfo endpoint
// response). It is re-exported here as `OidcUserInfo` to avoid collision with
// the framework-level [`UserInfo`] (the internal user record).
pub use server::oidc::{
    Address, AuthorizationValidationResult, IdTokenClaims, Jwk, JwkSet, LogoutResponse,
    OidcAuthorizationRequest, OidcConfig, OidcDiscoveryDocument, OidcProvider, SubjectType,
    UserInfo as OidcUserInfo,
};

// Phase 2: Logout & Security Ecosystem specifications (advanced OIDC logout protocols).
// Hidden from root docs; access via `auth_framework::server::oidc::oidc_backchannel_logout`
// and `auth_framework::server::oidc::oidc_frontchannel_logout`.
#[doc(hidden)]
pub use server::oidc::oidc_backchannel_logout::{
    BackChannelLogoutConfig, BackChannelLogoutManager, BackChannelLogoutRequest,
    BackChannelLogoutResponse, LogoutEvents, LogoutTokenClaims, NotificationResult,
    RpBackChannelConfig,
};
#[doc(hidden)]
pub use server::oidc::oidc_frontchannel_logout::{
    FailedNotification, FrontChannelLogoutConfig, FrontChannelLogoutManager,
    FrontChannelLogoutRequest, FrontChannelLogoutResponse, RpFrontChannelConfig,
};
#[doc(hidden)]
pub use server::oidc::oidc_rp_initiated_logout::{
    ClientLogoutConfig, LogoutNotificationTarget, RpInitiatedLogoutConfig,
    RpInitiatedLogoutManager, RpInitiatedLogoutRequest, RpInitiatedLogoutResponse,
};

// OAuth2 server types and configurations
pub use oauth2_server::{
    AuthorizationRequest, GrantType, OAuth2Config, OAuth2Server, ResponseType, TokenRequest,
    TokenResponse,
};

// Server configuration types — ClientType and ClientConfig come from the canonical `client` module.
pub use client::{ClientConfig, ClientConfigBuilder, ClientType};
pub use server::{ClientRegistrationRequest, WorkingServerConfig};

/// Deprecated alias for [`ClientRegistrationRequest`].
#[deprecated(since = "0.5.0", note = "Use `ClientRegistrationRequest` instead")]
pub type ServerClientRegistrationRequest =
    server::core::client_registration::ClientRegistrationRequest;

// Advanced server modules and RFC implementations.
// Hidden from top-level docs/autocomplete to avoid cluttering the onboarding path;
// access via `auth_framework::server::*` for advanced use.
#[doc(hidden)]
pub use server::DpopManager;
#[doc(hidden)]
pub use server::MetadataProvider;
#[doc(hidden)]
pub use server::OAuth2Server as ServerOAuth2Server;
#[doc(hidden)]
pub use server::PARManager;
#[doc(hidden)]
pub use server::PrivateKeyJwtManager;
#[doc(hidden)]
pub use server::TokenIntrospectionService;

// Security and authentication module re-exports
pub use audit::{AuditEvent, AuditEventType, AuditLogger, EventOutcome, RiskLevel};
/// Deprecated alias for `authentication::mfa::MfaManager`. Use `auth_modular` MFA operations instead.
#[deprecated(
    since = "0.5.0",
    note = "Use `AuthFramework::mfa()` accessor or `auth_modular::MfaManager` instead"
)]
pub use authentication::mfa::MfaManager as LegacyMfaManager;
pub use authentication::mfa::{MfaMethodType, TotpProvider};
pub use authorization::{
    AbacPermission as AuthzPermission, AbacRole as AuthzRole, AccessCondition, AuthorizationEngine,
};
pub use security::secure_jwt::{SecureJwtClaims, SecureJwtConfig, SecureJwtValidator};
pub use security::secure_mfa::SecureMfaService;
pub use security::secure_session::{
    DeviceFingerprint, SecureSession, SecureSessionConfig, SecureSessionManager, SecurityFlags,
};
pub use security::secure_utils::{SecureComparison, SecureRandomGen};
/// Deprecated alias for [`SessionManager`]. Use `SessionManager` directly.
#[deprecated(since = "0.5.0", note = "Use `SessionManager` instead")]
pub use session::manager::SessionManager as LegacySessionManager;
pub use session::manager::{DeviceInfo, Session, SessionConfig, SessionManager, SessionState};
pub use utils::rate_limit::RateLimiter;

// Multi-tenant support
pub use tenant::{TenantContext, TenantId, TenantMetadata, TenantRegistry, TenantRegistryBuilder};

// Monitoring and metrics
pub use monitoring::{
    HealthCheckResult, HealthStatus, MetricDataPoint, MetricType, MonitoringConfig,
    MonitoringManager, PerformanceMetrics, SecurityEvent, SecurityEventSeverity, SecurityEventType,
};

// Session coordination stats from auth module
pub use auth::SessionCoordinationStats;

// Re-export testing utilities when available
#[cfg(test)]
pub use testing::{MockAuthMethod, MockStorage}; // Removed helpers temporarily

// Re-export test infrastructure for bulletproof testing
#[cfg(test)]
pub use testing::{
    test_infrastructure::{TestEnvironmentGuard, test_data},
    utilities::*,
};
