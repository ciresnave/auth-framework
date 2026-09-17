//! Auth Framework Prelude
//!
//! This module provides a convenient way to import the most commonly used types
//! and traits from the auth framework. Instead of importing individual types,
//! you can simply use:
//!
//! ```rust
//! use auth_framework::prelude::*;
//! ```
//!
//! This imports all the essential types you need to get started with authentication
//! and authorization in your application.
//!
//! # Recommended Entry Points
//!
//! - Use [`AuthFramework`] for the normal library entry point.
//! - Use [`ModularAuthFramework`] only when you need direct access to the
//!   component managers from `auth_modular`.
//! - Use [`AuthFramework::users`], [`AuthFramework::sessions`],
//!   [`AuthFramework::tokens`], and [`AuthFramework::authorization`] when you
//!   want grouped operations instead of the full façade.
//! - Use [`AppConfigBuilder`] for simple app-defined configuration.
//! - Use [`LayeredConfigBuilder`] and [`ConfigManager`] for layered config
//!   sourced from files and environment variables.
//! - Use [`SessionManager`] for the standard session engine and
//!   [`SecureSessionManager`] when you need the hardened secure-session layer.
//!
//! # What's Included
//!
//! ## Core Framework Types
//! - [`AuthFramework`] - Main authentication framework
//! - [`AuthConfig`] - Configuration builder
//! - [`AuthError`] - Error type with detailed error variants
//! - [`AuthFrameworkResult`] - Convenient Result type alias
//!
//! ## Authentication Methods
//! - [`JwtMethod`] - JWT authentication
//! - [`OAuth2Method`] - OAuth 2.0 authentication
//! - [`ApiKeyMethod`] - API key authentication
//! - [`PasswordMethod`] - Password-based authentication
//!
//! ## Tokens and Sessions
//! - [`AuthToken`] - Authentication token representation
//! - [`SessionData`] - Session data structure
//! - [`ProviderProfile`] - Provider-backed user profile information
//!
//! ## Permissions and Authorization
//! - [`Permission`] - Permission representation
//! - [`Role`] - Role representation with builder methods
//! - [`AbacPolicy`] - Attribute-based access control policy with builder methods
//! - [`Delegation`] - Permission delegation with builder methods
//! - [`PermissionChecker`] - Permission validation trait
//!
//! ## Storage Abstractions
//! - [`AuthStorage`] - Storage trait for persistence
//! - [`MemoryStorage`] - In-memory storage implementation
//!
//! ## Web Framework Integration
//! - `RequireAuth` - Middleware for requiring authentication
//! - `AuthenticatedUser` - Extractor for authenticated users
//! - `RequirePermission` - Middleware for permission checking
//!
//! ## Builder Patterns and Helpers
//! - [`AuthBuilder`] - Fluent builder for framework setup
//! - [`AuthConfigBuilder`] - Organized builder for AuthConfig with grouped settings
//! - [`SecurityPreset`] - Pre-configured security levels
//! - [`AppConfigBuilder`] - Simple application configuration builder
//! - [`LayeredConfigBuilder`] - Layered configuration builder
//! - [`AdvancedPermissionCheck`] - Builder for multi-source permission checks
//! - [`ExecutionMode`] - `DryRun` vs `Execute` for maintenance operations
//! - [`UserStatus`] - `Active` vs `Inactive` for user account state
//! - [`SessionFilter`] - `ActiveOnly` vs `IncludeInactive` for session listing
//!
//! ## Time and Rate Limiting Helpers
//! - Time duration helpers: [`hours`], [`minutes`], [`days`], [`weeks`]
//! - Rate limiting helpers: [`requests`], [`RequestCount::per_second`],
//!   [`RequestCount::per_minute`], [`RequestCount::per_hour`]
//!
//! # Quick Start Example
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> AuthFrameworkResult<()> {
//!     // Create auth framework with sensible defaults
//!     let auth = AuthFramework::quick_start()
//!         .jwt_auth_from_env()
//!         .with_postgres_from_env()
//!         .build().await?;
//!
//!     // Create a token
//!     let token = auth.create_auth_token(
//!         "user123",
//!         vec!["read".to_string()],
//!         "jwt",
//!         None
//!     ).await?;
//!
//!     // Validate token
//!     if auth.validate_token(&token).await? {
//!         println!("Token is valid!");
//!     }
//!
//!     Ok(())
//! }
//! ```

// Re-export core framework types
pub use crate::AuthFramework;
pub use crate::ModularAuthFramework;
pub use crate::auth::{
    AdminOperations, AuditOperations, AuthStats, AuthorizationOperations, MfaOperations,
    MonitoringOperations, SessionOperations, TokenOperations, UserInfo, UserOperations,
};

// Re-export request / query structs for operations facades
pub use crate::auth_operations::{
    AuditLogQuery, DelegationRequest, ExecutionMode, PermissionContext, SessionCreateRequest,
    SessionFilter, TokenCreateRequest, UserListQuery, UserStatus,
};

// Re-export configuration types
pub use crate::config::app_config::{AppConfig, ConfigBuilder as AppConfigBuilder};
pub use crate::config::config_manager::{
    ApiServerSettings, AuthFrameworkSettings, ConfigBuilder as LayeredConfigBuilder, ConfigManager,
};
pub use crate::config::{
    AuditConfig, AuthConfig, AuthConfigBuilder, CookieSameSite, CorsConfig, JwtAlgorithm,
    PasswordHashAlgorithm, RateLimitConfig, SecurityConfig, StorageConfig,
};

// Re-export error types
pub use crate::errors::{
    AuthError, DeviceFlowError, MfaError, OAuthProviderError, PermissionError, Result,
    StorageError, TokenError,
};

// Re-export authentication methods
pub use crate::methods::{
    ApiKeyMethod, AuthMethod, AuthMethodEnum, JwtMethod, MethodResult, OAuth2Method, PasswordMethod,
};

// Re-export common domain types
pub use crate::types::{
    AdditionalParams, GrantTypes, IpList, Permissions, RedirectUris, ResponseTypes, Roles, Scopes,
    UserAttributes, UserAttributesString,
};

// Re-export SAML if available
#[cfg(feature = "saml")]
pub use crate::methods::saml;

// Re-export tokens and user data
pub use crate::authentication::credentials::Credential;
pub use crate::providers::{
    OAuthProvider, OAuthProviderConfig, OAuthProviderConfigBuilder, ProviderProfile,
};
pub use crate::tokens::{AuthToken, AuthTokenBuilder, TokenMetadata, TokenMetadataBuilder};

// Re-export permissions and roles
pub use crate::permissions::{
    AbacPolicy, AdvancedPermissionCheck, Delegation, Permission, PermissionChecker, Role,
};

// Re-export authorization if enhanced RBAC is enabled
#[cfg(feature = "enhanced-rbac")]
pub use crate::authorization::{
    AbacPermission as AuthzPermission, AbacRole as AuthzRole, AccessCondition, AuthorizationEngine,
};

// Re-export storage abstractions
pub use crate::storage::{AuthStorage, MemoryStorage, SessionData};

// Re-export session management
pub use crate::security::secure_session::{
    DeviceFingerprint, SecureSession, SecureSessionConfig, SecureSessionManager, SecurityFlags,
};
pub use crate::session::manager::{
    DeviceInfo, Session, SessionConfig, SessionManager, SessionState,
};

// Re-export middleware and extractors for web frameworks
#[cfg(feature = "axum-integration")]
pub use crate::integrations::axum::{
    AuthMiddleware, AuthenticatedUser, RequireAuth, RequirePermission,
};

#[cfg(feature = "actix-integration")]
pub use crate::integrations::actix_web::AuthMiddleware as ActixAuthMiddleware;

#[cfg(feature = "warp-integration")]
pub use crate::integrations::warp::{with_auth, with_permission};

// Re-export monitoring and observability
pub use crate::monitoring::{
    HealthCheckResult, HealthStatus, MonitoringManager, PerformanceMetrics, SecurityEvent,
    SecurityEventBuilder, SecurityEventSeverity, SecurityEventType,
};

// Re-export audit logging
pub use crate::audit::{
    AuditEvent, AuditEventBuilder, AuditEventType, AuditLogger, AuditQuery, AuditQueryBuilder,
    EventOutcome, RiskLevel,
};

// Re-export security utilities
pub use crate::security::secure_jwt::{SecureJwtClaims, SecureJwtConfig, SecureJwtValidator};
pub use crate::security::secure_utils::{SecureComparison, SecureRandomGen};
pub use crate::security::{
    SecurityAuditReport, SecurityAuditStatus, SecurityIssue, SecuritySeverity,
};

// Re-export rate limiting
pub use crate::utils::rate_limit::RateLimiter;

// Re-export testing utilities
#[cfg(test)]
pub use crate::testing::{MockAuthMethod, MockStorage};

// Re-export CLI tools if available
#[cfg(feature = "cli")]
pub use crate::cli;

// Re-export API server if available
#[cfg(feature = "api-server")]
pub use crate::api::{ApiError, ApiResponse, ApiServer, ApiState};

// Re-export OIDC server components
pub use crate::server::oidc::core::{IdTokenRequest, OidcConfigBuilder};
pub use crate::server::oidc::{
    IdTokenClaims, Jwk, JwkSet, OidcConfig, OidcDiscoveryDocument, OidcProvider,
    UserInfo as OidcUserInfo,
};

// Re-export OAuth2 server
pub use crate::oauth2_server::{
    AuthorizationRequest, GrantType, OAuth2Config, OAuth2ConfigBuilder, OAuth2Server, ResponseType,
    TokenRequest, TokenResponse,
};

// Builder patterns and ergonomic helpers
pub use crate::builders::*;

// Time duration helpers for ergonomic configuration
pub mod time {
    use std::time::Duration;

    /// Create a duration representing the specified number of hours
    pub fn hours(h: u64) -> Duration {
        Duration::from_secs(h * 3600)
    }

    /// Create a duration representing the specified number of minutes
    pub fn minutes(m: u64) -> Duration {
        Duration::from_secs(m * 60)
    }

    /// Create a duration representing the specified number of days
    pub fn days(d: u64) -> Duration {
        Duration::from_secs(d * 86400)
    }

    /// Create a duration representing the specified number of weeks
    pub fn weeks(w: u64) -> Duration {
        Duration::from_secs(w * 604800)
    }

    /// Create a duration representing the specified number of seconds
    pub fn seconds(s: u64) -> Duration {
        Duration::from_secs(s)
    }
}

// Rate limiting helpers for ergonomic configuration
pub mod rate {
    use std::time::Duration;

    /// Helper for specifying request counts in rate limiting
    pub struct RequestCount(pub u32);

    /// Helper for creating request count specifications
    pub fn requests(count: u32) -> RequestCount {
        RequestCount(count)
    }

    impl RequestCount {
        /// Specify rate limit as "per second"
        pub fn per_second(self) -> (u32, Duration) {
            (self.0, Duration::from_secs(1))
        }

        /// Specify rate limit as "per minute"
        pub fn per_minute(self) -> (u32, Duration) {
            (self.0, Duration::from_secs(60))
        }

        /// Specify rate limit as "per hour"
        pub fn per_hour(self) -> (u32, Duration) {
            (self.0, Duration::from_secs(3600))
        }

        /// Specify rate limit as "per day"
        pub fn per_day(self) -> (u32, Duration) {
            (self.0, Duration::from_secs(86400))
        }

        /// Specify custom rate limit window
        pub fn per(self, duration: Duration) -> (u32, Duration) {
            (self.0, duration)
        }
    }
}

// Re-export time and rate helpers at the top level for convenience
pub use rate::{RequestCount, requests};
pub use time::{days, hours, minutes, seconds, weeks};

// Common type aliases for ergonomics
/// Convenience alias for `Result<T, AuthError>`.
pub type AuthFrameworkResult<T> = Result<T, AuthError>;

/// A boxed, `Send`-safe async future returning `AuthFrameworkResult<()>`.
///
/// Useful for storing async handler callbacks in collections.
pub type AsyncAuthHandler =
    std::pin::Pin<Box<dyn std::future::Future<Output = AuthFrameworkResult<()>> + Send>>;

// Import security presets from the security module
pub use crate::security::SecurityPreset; // Performance presets for optimization
#[derive(Debug, Clone)]
pub enum PerformancePreset {
    /// Optimized for high request throughput
    HighThroughput,
    /// Optimized for low latency responses
    LowLatency,
    /// Optimized for minimal memory usage
    LowMemory,
    /// Balanced performance settings
    Balanced,
}

// Use case presets for common application types
#[derive(Debug, Clone)]
pub enum UseCasePreset {
    /// Web application with sessions and cookies
    WebApp,
    /// REST API service with JWT tokens
    ApiService,
    /// Microservices with distributed auth
    Microservices,
    /// Mobile app backend
    MobileBackend,
    /// Enterprise application with RBAC
    Enterprise,
}
