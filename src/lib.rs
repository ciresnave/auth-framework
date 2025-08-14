/*!
# Auth Framework

A comprehensive authentication and authorization framework for Rust applications.

This crate provides a unified interface for various authentication methods,
token management, permission checking, and secure credential handling with
a focus on distributed systems.

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
use auth_framework::{AuthFramework, AuthConfig, methods::JwtMethod};
use std::time::Duration;

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));

    // Create the auth framework
    let mut auth = AuthFramework::new(config);

    // Register a JWT authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("your-secret-key")
        .issuer("your-service");

    auth.register_method("jwt", auth_framework::methods::AuthMethodEnum::Jwt(jwt_method));

    // Initialize the framework
    auth.initialize().await?;

    // Create a token
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
# Ok(())
# }
```

## Security Considerations

- Always use HTTPS in production
- Use strong, unique secrets for token signing
- Enable rate limiting to prevent brute force attacks
- Regularly rotate secrets and keys
- Monitor authentication events for suspicious activity
- Follow the principle of least privilege for permissions

See the [Security Policy](https://github.com/yourusername/auth-framework/blob/main/SECURITY.md)
for comprehensive security guidelines.
*/

pub mod advanced_auth;

// ## Quick Start
//
// ```rust,no_run
// use auth_framework::{AuthFramework, AuthConfig};
// use auth_framework::methods::JwtMethod;
// use std::time::Duration;
//
// # #[tokio::main]
// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
// // Configure the auth framework
// let config = AuthConfig::new()
//     .token_lifetime(Duration::from_secs(3600))
//     .refresh_token_lifetime(Duration::from_secs(86400 * 7));
//
// // Create the auth framework
// let mut auth = AuthFramework::new(config);
//
// // Register a JWT authentication method
// let jwt_method = JwtMethod::new()
//     .secret_key("your-secret-key")
//     .issuer("your-service");
//
// auth.register_method("jwt", Box::new(jwt_method));
//
// // Initialize the framework
// auth.initialize().await?;
//
// // Create a token
// let token = auth.create_auth_token(
//     "user123",
//     vec!["read".to_string(), "write".to_string()],
//     "jwt",
//     None,
// ).await?;
//
// // Validate the token
// if auth.validate_token(&token).await? {
//     println!("Token is valid!");
//
//     // Check permissions
//     if auth.check_permission(&token, "read", "documents").await? {
//         println!("User has permission to read documents");
//     }
// }
// # Ok(())
// # }
// ```
//
// ## Security Considerations
//
// - Always use HTTPS in production
// - Use strong, unique secrets for token signing
// - Enable rate limiting to prevent brute force attacks
// - Regularly rotate secrets and keys
// - Monitor authentication events for suspicious activity
// - Follow the principle of least privilege for permissions
//
// See the [Security Policy](https://github.com/yourusername/auth-framework/blob/main/SECURITY.md)
// for comprehensive security guidelines.

// Admin interface (conditional on admin-binary feature)
#[cfg(feature = "admin-binary")]
pub mod admin;

pub mod auth;
pub mod auth_modular; // Modular authentication components
pub mod credentials;
pub mod errors;
pub mod methods;
pub mod permissions;
pub mod profile_utils;
pub mod providers;
pub mod server;
pub mod storage;
pub mod test_infrastructure; // Bulletproof test isolation
pub mod testing;
pub mod threat_intelligence; // Automated threat intelligence feed management
pub mod tokens;
pub mod utils;

// User context and session management
pub mod user_context;

// Enhanced OAuth2 storage with proper validation
pub mod oauth2_enhanced_storage;

// OAuth2 server implementation
// Secure OAuth2 server implementation
pub mod oauth2_server;

// Consolidated security modules
pub mod audit;
pub mod authorization;
pub mod distributed_rate_limiting; // Advanced distributed rate limiting
pub mod mfa;
pub mod secure_jwt; // Secure JWT validation
pub mod secure_mfa; // Secure MFA implementation
pub mod secure_session; // Secure session management
pub mod secure_session_config; // Enhanced session security configuration
pub mod secure_utils; // Secure utility functions
pub mod security;
pub mod session;

// Configuration management
pub mod config;

// Monitoring and metrics collection
pub mod monitoring;

// Web framework integrations
pub mod integrations {
    #[cfg(feature = "axum-integration")]
    pub mod axum;

    #[cfg(feature = "actix-integration")]
    pub mod actix_web;

    #[cfg(feature = "warp-integration")]
    pub mod warp;
}

// Database migrations
pub mod migrations;

// CLI tools
pub mod cli;

// WS-Security 1.1 and SAML 2.0 support
pub mod saml_assertions;
pub mod ws_security;
pub mod ws_trust;

// Re-exports - Main modular auth framework components
pub use crate::auth::{AuthFramework, AuthResult, AuthStats, UserInfo};
pub use config::{
    AuthConfig,
    app_config::{AppConfig, ConfigBuilder},
};
pub use credentials::Credential;
pub use errors::{AuthError, Result};
pub use methods::{
    ApiKeyMethod, AuthMethod, JwtMethod, MethodResult, OAuth2Method, PasswordMethod,
};

// SAML support (feature-gated)
#[cfg(feature = "saml")]
pub use methods::saml;

// PKCE support functions
pub use providers::generate_pkce;

// WS-Security and WS-Trust support
pub use permissions::{Permission, PermissionChecker, Role};
pub use profile_utils::{ExtractProfile, TokenToProfile};
pub use providers::{DeviceAuthorizationResponse, OAuthProvider, OAuthProviderConfig, UserProfile};
pub use tokens::AuthToken;
pub use ws_security::{UsernameToken, WsSecurityClient, WsSecurityConfig, WsSecurityHeader};
pub use ws_trust::RequestSecurityToken;

// Server-side authentication and authorization - Now working!
pub use server::oidc::{
    Address, AuthorizationValidationResult, IdTokenClaims, Jwk, JwkSet, LogoutResponse,
    OidcAuthorizationRequest, OidcConfig, OidcDiscoveryDocument, OidcProvider, SubjectType,
    UserInfo as OidcUserInfo,
};

// Phase 2: Logout & Security Ecosystem specifications
pub use server::oidc::{
    oidc_backchannel_logout::{
        BackChannelLogoutConfig, BackChannelLogoutManager, BackChannelLogoutRequest,
        BackChannelLogoutResponse, LogoutEvents, LogoutTokenClaims, NotificationResult,
        RpBackChannelConfig,
    },
    oidc_frontchannel_logout::{
        FailedNotification, FrontChannelLogoutConfig, FrontChannelLogoutManager,
        FrontChannelLogoutRequest, FrontChannelLogoutResponse, RpFrontChannelConfig,
    },
};

// OAuth2 server types and configurations
pub use oauth2_server::{
    AuthorizationRequest, GrantType, OAuth2Config, OAuth2Server, ResponseType, TokenRequest,
    TokenResponse,
};

// Server configuration types
pub use server::{
    ClientRegistrationRequest, ClientType, WorkingServerConfig,
    core::{
        client_registration::ClientRegistrationRequest as ServerClientRegistrationRequest,
        client_registry::ClientType as ServerClientType,
    },
};

// Advanced server modules and RFC implementations
pub use server::{
    DpopManager, MetadataProvider, OAuth2Server as ServerOAuth2Server, PARManager,
    PrivateKeyJwtManager, TokenIntrospectionService,
};

// Security and authentication module re-exports
pub use audit::{AuditEvent, AuditEventType, AuditLogger, EventOutcome, RiskLevel};
pub use authorization::{
    AccessCondition, AuthorizationEngine, Permission as AuthzPermission, Role as AuthzRole,
};
pub use mfa::{MfaManager as LegacyMfaManager, MfaMethodType, TotpProvider};
pub use secure_jwt::{SecureJwtClaims, SecureJwtConfig, SecureJwtValidator};
pub use secure_mfa::SecureMfaService;
pub use secure_session::{
    DeviceFingerprint, SecureSession, SecureSessionConfig, SecureSessionManager, SecurityFlags,
    SessionState as SecureSessionState,
};
pub use secure_utils::{SecureComparison, SecureRandomGen};
pub use session::{
    DeviceInfo, Session, SessionConfig, SessionManager as LegacySessionManager, SessionState,
};
pub use utils::rate_limit::RateLimiter;

// Monitoring and metrics
pub use monitoring::{
    HealthCheckResult, HealthStatus, MetricDataPoint, MetricType, MonitoringConfig,
    MonitoringManager, PerformanceMetrics, SecurityEvent, SecurityEventSeverity, SecurityEventType,
};

// Session coordination stats from auth module
pub use auth::SessionCoordinationStats;

// Re-export testing utilities when available
#[cfg(any(test, feature = "testing"))]
pub use testing::{MockAuthMethod, MockStorage}; // Removed helpers temporarily

// Re-export test infrastructure for bulletproof testing
#[cfg(any(test, feature = "testing"))]
pub use test_infrastructure::{TestEnvironmentGuard, test_data};
