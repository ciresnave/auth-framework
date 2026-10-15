//! Configuration types for the authentication framework.

pub mod app_config;
pub mod config_manager;

// Re-export for easy access
pub use app_config::{AppConfig, ConfigBuilder as AppConfigBuilder};
pub use config_manager::{
    ApiServerSettings, AuthFrameworkSettings, ConfigBuilder as LayeredConfigBuilder,
    ConfigIntegration, ConfigManager, SessionCookieSettings, SessionSettings,
};

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main configuration for the authentication framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Default token lifetime
    pub token_lifetime: Duration,

    /// Refresh token lifetime
    pub refresh_token_lifetime: Duration,

    /// Whether multi-factor authentication is enabled
    pub enable_multi_factor: bool,

    /// JWT issuer for token validation
    pub issuer: String,

    /// JWT audience for token validation
    pub audience: String,

    /// JWT secret key (optional - can be set via environment)
    pub secret: Option<String>,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// CORS configuration used by all web framework integrations.
    #[serde(default)]
    pub cors: CorsConfig,

    /// Audit logging configuration
    pub audit: AuditConfig,

    /// Whether framework-level caching helpers are enabled.
    #[serde(default)]
    pub enable_caching: bool,

    /// Maximum failed authentication attempts before a client should be blocked.
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,

    /// Whether RBAC helpers are enabled in the configuration model.
    #[serde(default)]
    pub enable_rbac: bool,

    /// Whether framework middleware helpers are enabled in the configuration model.
    #[serde(default)]
    pub enable_middleware: bool,

    /// Custom settings for different auth methods
    pub method_configs: HashMap<String, serde_json::Value>,

    /// Force production validation regardless of environment variables.
    /// Used in tests that explicitly verify production-mode error handling.
    #[serde(default)]
    pub force_production_mode: bool,
}

/// Storage configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageConfig {
    /// In-memory storage (not recommended for production)
    Memory,

    /// Redis storage
    #[cfg(feature = "redis-storage")]
    Redis { url: String, key_prefix: String },

    /// PostgreSQL storage
    #[cfg(feature = "postgres-storage")]
    Postgres {
        connection_string: String,
        table_prefix: String,
    },

    /// MySQL storage
    #[cfg(feature = "mysql-storage")]
    MySQL {
        connection_string: String,
        table_prefix: String,
    },

    /// SQLite storage
    #[cfg(feature = "sqlite-storage")]
    Sqlite { connection_string: String },

    /// Custom storage backend
    Custom(String),
}

/// Rate limiting configuration.
///
/// Controls how many requests each client can make within a sliding time
/// window.  Use [`RateLimitConfig::new`] for quick construction or
/// [`Default::default()`] for sensible production defaults (100 req/min).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Maximum requests per window
    pub max_requests: u32,

    /// Time window for rate limiting
    pub window: Duration,

    /// Burst allowance
    pub burst: u32,
}

/// Security configuration options.
///
/// Governs password policy, JWT signing, cookie flags, CSRF protection,
/// and session timeouts.  Two named constructors cover the most common
/// scenarios:
///
/// - [`SecurityConfig::secure()`] — hardened production defaults.
/// - [`SecurityConfig::development()`] — relaxed settings for local work.
///
/// For anything in between, start from [`Default::default()`] and
/// override individual fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Minimum password length
    pub min_password_length: usize,

    /// Require password complexity
    pub require_password_complexity: bool,

    /// Password hash algorithm
    pub password_hash_algorithm: PasswordHashAlgorithm,

    /// JWT signing algorithm
    pub jwt_algorithm: JwtAlgorithm,

    /// Secret key for signing (should be loaded from environment)
    pub secret_key: Option<String>,

    /// Previous secret key to maintain validation capabilities during rotation
    pub previous_secret_key: Option<String>,

    /// Enable secure cookies
    pub secure_cookies: bool,

    /// Cookie SameSite policy
    pub cookie_same_site: CookieSameSite,

    /// CSRF protection
    pub csrf_protection: bool,

    /// Session timeout
    pub session_timeout: Duration,
}

/// Password hashing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordHashAlgorithm {
    /// Argon2id — recommended for new applications (memory-hard, side-channel resistant).
    Argon2,
    /// bcrypt — widely supported, suitable when Argon2 is unavailable.
    Bcrypt,
    /// scrypt — memory-hard alternative to bcrypt.
    Scrypt,
}

/// JWT signing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256 (symmetric).
    HS256,
    /// HMAC-SHA384 (symmetric).
    HS384,
    /// HMAC-SHA512 (symmetric).
    HS512,
    /// RSA-SHA256 (asymmetric) — recommended for multi-service deployments.
    RS256,
    /// RSA-SHA384 (asymmetric).
    RS384,
    /// RSA-SHA512 (asymmetric).
    RS512,
    /// ECDSA-SHA256 (asymmetric) — compact signatures.
    ES256,
    /// ECDSA-SHA384 (asymmetric).
    ES384,
}

/// Cookie SameSite policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CookieSameSite {
    /// Cookies sent only in first-party (same-site) requests.
    Strict,
    /// Cookies sent in same-site requests and top-level cross-site navigations.
    Lax,
    /// Cookies sent in all contexts; requires the `Secure` flag.
    None,
}

/// Cross-Origin Resource Sharing (CORS) configuration.
///
/// This is the centralized CORS policy used by all web framework integrations
/// (API server, admin GUI, warp/axum helpers). Individual integrations may
/// further restrict (but never relax) these settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Whether CORS headers are emitted at all.
    pub enabled: bool,

    /// Explicit list of allowed origins, e.g. `["https://app.example.com"]`.
    ///
    /// An empty list with `enabled = true` means no cross-origin requests are
    /// accepted. Never put `"*"` here — use specific origins.
    pub allowed_origins: Vec<String>,

    /// HTTP methods that cross-origin requests may use.
    pub allowed_methods: Vec<String>,

    /// HTTP headers that cross-origin requests may include.
    pub allowed_headers: Vec<String>,

    /// `Access-Control-Max-Age` value in seconds.
    pub max_age_secs: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_origins: Vec::new(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "Accept".to_string(),
            ],
            max_age_secs: 3600,
        }
    }
}

impl CorsConfig {
    /// Enable CORS for the given origin(s).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::CorsConfig;
    ///
    /// let cors = CorsConfig::for_origins(["https://app.example.com"]);
    /// assert!(cors.enabled);
    /// ```
    pub fn for_origins<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            enabled: true,
            allowed_origins: origins.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }
}

/// Audit logging configuration.
///
/// Controls which authentication events are recorded and where the
/// records are stored.  Enabled by default with [`AuditStorage::Tracing`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,

    /// Log successful authentications
    pub log_success: bool,

    /// Log failed authentications
    pub log_failures: bool,

    /// Log permission checks
    pub log_permissions: bool,

    /// Log token operations
    pub log_tokens: bool,

    /// Audit log storage
    pub storage: AuditStorage,
}

/// Audit log storage backend.
///
/// Pairs with [`AuditConfig`] to specify *where* audit events are persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStorage {
    /// Standard logging (via tracing)
    Tracing,

    /// File-based storage
    File { path: String },

    /// Database storage
    Database { connection_string: String },

    /// External service
    External { endpoint: String, api_key: String },
}

const fn default_max_failed_attempts() -> u32 {
    5
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(3600), // 1 hour
            refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
            enable_multi_factor: false,
            issuer: "auth-framework".to_string(),
            audience: "api".to_string(),
            secret: None,
            storage: StorageConfig::Memory,
            rate_limiting: RateLimitConfig::default(),
            security: SecurityConfig::default(),
            cors: CorsConfig::default(),
            audit: AuditConfig::default(),
            enable_caching: false,
            max_failed_attempts: default_max_failed_attempts(),
            enable_rbac: false,
            enable_middleware: false,
            method_configs: HashMap::new(),
            force_production_mode: false,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_requests: 100,
            window: Duration::from_secs(60), // 1 minute
            burst: 10,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            require_password_complexity: true,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2,
            jwt_algorithm: JwtAlgorithm::HS256,
            secret_key: None,
            previous_secret_key: None,
            secure_cookies: true,
            cookie_same_site: CookieSameSite::Lax,
            csrf_protection: true,
            session_timeout: Duration::from_secs(3600 * 24), // 24 hours
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_success: true,
            log_failures: true,
            log_permissions: true,
            log_tokens: false, // Tokens can be sensitive
            storage: AuditStorage::Tracing,
        }
    }
}

// ---------------------------------------------------------------------------
// Display implementations — human-readable summaries for logging / debugging
// ---------------------------------------------------------------------------

impl std::fmt::Display for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthConfig {{ tokens: {}s/{}s refresh, storage: {}, mfa: {}, rbac: {}, rate_limit: {}, security: {}, cors: {}, audit: {} }}",
            self.token_lifetime.as_secs(),
            self.refresh_token_lifetime.as_secs(),
            self.storage,
            if self.enable_multi_factor {
                "on"
            } else {
                "off"
            },
            if self.enable_rbac { "on" } else { "off" },
            self.rate_limiting,
            self.security,
            self.cors,
            self.audit,
        )
    }
}

impl std::fmt::Display for StorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            #[cfg(feature = "redis-storage")]
            Self::Redis { url, .. } => write!(f, "redis({})", url),
            #[cfg(feature = "postgres-storage")]
            Self::Postgres { .. } => write!(f, "postgres"),
            #[cfg(feature = "mysql-storage")]
            Self::MySQL { .. } => write!(f, "mysql"),
            #[cfg(feature = "sqlite-storage")]
            Self::Sqlite { .. } => write!(f, "sqlite"),
            Self::Custom(name) => write!(f, "custom({})", name),
        }
    }
}

impl std::fmt::Display for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Security {{ pw≥{}, hash: {}, jwt: {}, cookies: {}, csrf: {}, session: {}s }}",
            self.min_password_length,
            self.password_hash_algorithm,
            self.jwt_algorithm,
            if self.secure_cookies {
                "secure"
            } else {
                "plain"
            },
            if self.csrf_protection { "on" } else { "off" },
            self.session_timeout.as_secs(),
        )
    }
}

impl std::fmt::Display for PasswordHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2 => write!(f, "argon2id"),
            Self::Bcrypt => write!(f, "bcrypt"),
            Self::Scrypt => write!(f, "scrypt"),
        }
    }
}

impl std::fmt::Display for JwtAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HS256 => write!(f, "HS256"),
            Self::HS384 => write!(f, "HS384"),
            Self::HS512 => write!(f, "HS512"),
            Self::RS256 => write!(f, "RS256"),
            Self::RS384 => write!(f, "RS384"),
            Self::RS512 => write!(f, "RS512"),
            Self::ES256 => write!(f, "ES256"),
            Self::ES384 => write!(f, "ES384"),
        }
    }
}

impl std::fmt::Display for RateLimitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.enabled {
            write!(
                f,
                "{} req/{}s (burst {})",
                self.max_requests,
                self.window.as_secs(),
                self.burst,
            )
        } else {
            write!(f, "disabled")
        }
    }
}

impl std::fmt::Display for CorsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.enabled {
            if self.allowed_origins.is_empty() {
                write!(f, "cors(no origins)")
            } else {
                write!(f, "cors({})", self.allowed_origins.join(", "))
            }
        } else {
            write!(f, "cors(off)")
        }
    }
}

impl std::fmt::Display for AuditConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.enabled {
            write!(f, "audit({})", self.storage)
        } else {
            write!(f, "audit(off)")
        }
    }
}

impl std::fmt::Display for AuditStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tracing => write!(f, "tracing"),
            Self::File { path } => write!(f, "file:{}", path),
            Self::Database { .. } => write!(f, "database"),
            Self::External { endpoint, .. } => write!(f, "external:{}", endpoint),
        }
    }
}

/// Runtime-mutable configuration subset.
///
/// These fields can be updated via the admin API without restarting the server.
/// Security-sensitive settings (JWT secret, algorithm, storage backend) are
/// intentionally excluded and require a process restart to change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Token lifetime in seconds.
    pub token_lifetime_secs: u64,
    /// Refresh token lifetime in seconds.
    pub refresh_token_lifetime_secs: u64,
    /// Whether MFA is globally enabled.
    pub enable_multi_factor: bool,
    /// Whether rate limiting is active.
    pub rate_limiting_enabled: bool,
    /// Maximum requests per rate-limit window.
    pub rate_limit_max_requests: u32,
    /// Rate-limit window in seconds.
    pub rate_limit_window_secs: u64,
    /// Rate-limit burst allowance.
    pub rate_limit_burst: u32,
    /// Minimum accepted password length.
    pub min_password_length: usize,
    /// Whether password complexity requirements are enforced.
    pub require_password_complexity: bool,
    /// Whether the `Secure` flag is set on session cookies.
    pub secure_cookies: bool,
    /// Whether CSRF protection middleware is active.
    pub csrf_protection: bool,
    /// Session timeout in seconds.
    pub session_timeout_secs: u64,
    /// Whether audit logging is active.
    pub audit_enabled: bool,
    /// Log successful authentication events.
    pub audit_log_success: bool,
    /// Log failed authentication events.
    pub audit_log_failures: bool,
    /// Log permission-check events.
    pub audit_log_permissions: bool,
    /// Log token issuance/revocation events.
    pub audit_log_tokens: bool,
}

impl RuntimeConfig {
    /// Initialise from a full [`AuthConfig`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, RuntimeConfig};
    ///
    /// let auth_cfg = AuthConfig::new();
    /// let rt = RuntimeConfig::from_auth_config(&auth_cfg);
    /// assert_eq!(rt.token_lifetime_secs, auth_cfg.token_lifetime.as_secs());
    /// ```
    pub fn from_auth_config(cfg: &AuthConfig) -> Self {
        Self {
            token_lifetime_secs: cfg.token_lifetime.as_secs(),
            refresh_token_lifetime_secs: cfg.refresh_token_lifetime.as_secs(),
            enable_multi_factor: cfg.enable_multi_factor,
            rate_limiting_enabled: cfg.rate_limiting.enabled,
            rate_limit_max_requests: cfg.rate_limiting.max_requests,
            rate_limit_window_secs: cfg.rate_limiting.window.as_secs(),
            rate_limit_burst: cfg.rate_limiting.burst,
            min_password_length: cfg.security.min_password_length,
            require_password_complexity: cfg.security.require_password_complexity,
            secure_cookies: cfg.security.secure_cookies,
            csrf_protection: cfg.security.csrf_protection,
            session_timeout_secs: cfg.security.session_timeout.as_secs(),
            audit_enabled: cfg.audit.enabled,
            audit_log_success: cfg.audit.log_success,
            audit_log_failures: cfg.audit.log_failures,
            audit_log_permissions: cfg.audit.log_permissions,
            audit_log_tokens: cfg.audit.log_tokens,
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::from_auth_config(&AuthConfig::default())
    }
}

impl AuthConfig {
    /// Create a new configuration with default values.
    ///
    /// `AuthConfig` supports two construction styles:
    ///
    /// ## Fluent setter chain (simple cases)
    ///
    /// ```rust,no_run
    /// use auth_framework::config::AuthConfig;
    /// use std::time::Duration;
    ///
    /// let config = AuthConfig::new()
    ///     .token_lifetime(Duration::from_secs(3600))
    ///     .secret("my-secret-key-at-least-32-chars-long!!");
    /// ```
    ///
    /// ## Full builder (complex / multi-backend setups)
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = AuthFramework::builder()
    ///     .with_jwt().secret("...").issuer("myapp").done()
    ///     .with_storage().memory().done()
    ///     .security_preset(SecurityPreset::HighSecurity)
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// See [`AuthFramework::builder`] and [`AuthFramework::quick_start`] for
    /// the full builder APIs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a configuration from common environment variables.
    ///
    /// Reads the following environment variables (all optional):
    ///
    /// | Variable | Maps to |
    /// |----------|---------|
    /// | `JWT_SECRET` | `secret` / `security.secret_key` |
    /// | `DATABASE_URL` | PostgreSQL storage (requires `postgres-storage` feature) |
    /// | `REDIS_URL` | Redis storage (requires `redis-storage` feature) |
    /// | `AUTH_ISSUER` | `issuer` |
    /// | `AUTH_AUDIENCE` | `audience` |
    ///
    /// Missing variables are silently ignored and fall back to defaults.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// // In tests or CI you can set the env vars beforehand:
    /// // std::env::set_var("JWT_SECRET", "my-long-secret-key-for-jwt-signing!!");
    /// let config = AuthConfig::from_env();
    /// ```
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(secret) = std::env::var("JWT_SECRET") {
            config.secret = Some(secret.clone());
            config.security.secret_key = Some(secret);
        }

        if let Ok(issuer) = std::env::var("AUTH_ISSUER") {
            config.issuer = issuer;
        }

        if let Ok(audience) = std::env::var("AUTH_AUDIENCE") {
            config.audience = audience;
        }

        // Storage: DATABASE_URL → Postgres, REDIS_URL → Redis (first match wins)
        #[cfg(feature = "postgres-storage")]
        if let Ok(url) = std::env::var("DATABASE_URL") {
            config.storage = StorageConfig::Postgres {
                connection_string: url,
                table_prefix: "auth_".to_string(),
            };
        }

        #[cfg(feature = "redis-storage")]
        if matches!(config.storage, StorageConfig::Memory)
            && let Ok(url) = std::env::var("REDIS_URL")
        {
            config.storage = StorageConfig::Redis {
                url,
                key_prefix: "auth:".to_string(),
            };
        }

        config
    }

    /// Start the full [`AuthBuilder`](crate::builders::AuthBuilder) workflow.
    ///
    /// This is a convenience alias for [`AuthFramework::builder()`] — use it
    /// when you want to configure storage, security presets, and sub-builders
    /// from a single fluent chain.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = AuthConfig::builder()
    ///     .with_jwt().secret("...").done()
    ///     .with_storage().memory().done()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    ///
    /// For more organized configuration, consider [`AuthConfigBuilder`] which
    /// groups settings by concern (tokens, security, storage, features, etc.).
    pub fn builder() -> crate::builders::AuthBuilder {
        crate::builders::AuthBuilder::new()
    }

    /// Set the token lifetime.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    /// use std::time::Duration;
    ///
    /// let config = AuthConfig::new().token_lifetime(Duration::from_secs(1800));
    /// assert_eq!(config.token_lifetime.as_secs(), 1800);
    /// ```
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;
        self
    }

    /// Set the refresh token lifetime.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    /// use std::time::Duration;
    ///
    /// let config = AuthConfig::new().refresh_token_lifetime(Duration::from_secs(86400));
    /// assert_eq!(config.refresh_token_lifetime.as_secs(), 86400);
    /// ```
    pub fn refresh_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.refresh_token_lifetime = lifetime;
        self
    }

    /// Enable or disable multi-factor authentication.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().enable_multi_factor(true);
    /// assert!(config.enable_multi_factor);
    /// ```
    pub fn enable_multi_factor(mut self, enabled: bool) -> Self {
        self.enable_multi_factor = enabled;
        self
    }

    /// Set the JWT issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Set the JWT audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Set the JWT secret key.
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Require MFA for all users.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().require_mfa(true);
    /// assert!(config.enable_multi_factor);
    /// ```
    pub fn require_mfa(mut self, required: bool) -> Self {
        self.enable_multi_factor = required;
        self
    }

    /// Enable caching.
    pub fn enable_caching(mut self, enabled: bool) -> Self {
        self.enable_caching = enabled;
        self
    }

    /// Set maximum failed attempts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().max_failed_attempts(10);
    /// assert_eq!(config.max_failed_attempts, 10);
    /// ```
    pub fn max_failed_attempts(mut self, max: u32) -> Self {
        self.max_failed_attempts = max;
        self
    }

    /// Enable RBAC.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().enable_rbac(true);
    /// assert!(config.enable_rbac);
    /// ```
    pub fn enable_rbac(mut self, enabled: bool) -> Self {
        self.enable_rbac = enabled;
        self
    }

    /// Enable security audit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().enable_security_audit(true);
    /// assert!(config.audit.enabled);
    /// ```
    pub fn enable_security_audit(mut self, enabled: bool) -> Self {
        self.audit.enabled = enabled;
        self
    }

    /// Enable middleware.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().enable_middleware(true);
    /// assert!(config.enable_middleware);
    /// ```
    pub fn enable_middleware(mut self, enabled: bool) -> Self {
        self.enable_middleware = enabled;
        self
    }

    /// Force production-mode validation, bypassing test-environment detection.
    ///
    /// Used exclusively in tests that verify production-specific error handling without
    /// polluting the process-wide environment with `ENVIRONMENT=production`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().force_production_mode();
    /// ```
    pub fn force_production_mode(mut self) -> Self {
        self.force_production_mode = true;
        self
    }

    /// Set the storage configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, StorageConfig};
    ///
    /// let config = AuthConfig::new().storage(StorageConfig::Memory);
    /// ```
    pub fn storage(mut self, storage: StorageConfig) -> Self {
        self.storage = storage;
        self
    }

    /// Configure Redis storage.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new().redis_storage("redis://127.0.0.1:6379");
    /// ```
    #[cfg(feature = "redis-storage")]
    pub fn redis_storage(mut self, url: impl Into<String>) -> Self {
        self.storage = StorageConfig::Redis {
            url: url.into(),
            key_prefix: "auth:".to_string(),
        };
        self
    }

    /// Set rate limiting configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, RateLimitConfig};
    ///
    /// let config = AuthConfig::new().rate_limiting(RateLimitConfig::default());
    /// ```
    pub fn rate_limiting(mut self, config: RateLimitConfig) -> Self {
        self.rate_limiting = config;
        self
    }

    /// Set security configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, SecurityConfig};
    ///
    /// let config = AuthConfig::new().security(SecurityConfig::secure());
    /// ```
    pub fn security(mut self, config: SecurityConfig) -> Self {
        self.security = config;
        self
    }

    /// Set CORS configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, CorsConfig};
    ///
    /// let config = AuthConfig::new()
    ///     .cors(CorsConfig::for_origins(["https://app.example.com"]));
    /// ```
    pub fn cors(mut self, config: CorsConfig) -> Self {
        self.cors = config;
        self
    }

    /// Set audit configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::{AuthConfig, AuditConfig};
    ///
    /// let config = AuthConfig::new().audit(AuditConfig::default());
    /// ```
    pub fn audit(mut self, config: AuditConfig) -> Self {
        self.audit = config;
        self
    }

    /// Add configuration for a specific auth method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new()
    ///     .method_config("oauth2", serde_json::json!({
    ///         "client_id": "my-client",
    ///         "client_secret": "my-secret"
    ///     }))
    ///     .unwrap();
    /// ```
    pub fn method_config(
        mut self,
        method_name: impl Into<String>,
        config: impl Serialize,
    ) -> Result<Self> {
        let value = serde_json::to_value(config)
            .map_err(|e| AuthError::config(format!("Failed to serialize method config: {e}")))?;

        self.method_configs.insert(method_name.into(), value);
        Ok(self)
    }

    /// Get configuration for a specific auth method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new();
    /// let oauth: Option<serde_json::Value> = config.get_method_config("oauth2").unwrap();
    /// assert!(oauth.is_none()); // no oauth2 config set yet
    /// ```
    pub fn get_method_config<T>(&self, method_name: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if let Some(value) = self.method_configs.get(method_name) {
            let config = serde_json::from_value(value.clone()).map_err(|e| {
                AuthError::config(format!("Failed to deserialize method config: {e}"))
            })?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Validate the configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::AuthConfig;
    ///
    /// let config = AuthConfig::new();
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<()> {
        // Validate token lifetimes
        if self.token_lifetime.as_secs() == 0 {
            return Err(AuthError::config("Token lifetime must be greater than 0"));
        }

        if self.refresh_token_lifetime.as_secs() == 0 {
            return Err(AuthError::config(
                "Refresh token lifetime must be greater than 0",
            ));
        }

        if self.refresh_token_lifetime <= self.token_lifetime {
            return Err(AuthError::config(
                "Refresh token lifetime must be greater than token lifetime",
            ));
        }

        // Validate JWT secret configuration
        self.validate_jwt_secret()?;

        // Validate security settings
        if self.security.min_password_length < 4 {
            return Err(AuthError::config(
                "Minimum password length must be at least 4 characters",
            ));
        }

        // Enhanced security validation for production
        if self.is_production_environment() && !self.is_test_environment() {
            self.validate_production_security()?;
        }

        // Validate rate limiting
        if self.rate_limiting.enabled && self.rate_limiting.max_requests == 0 {
            return Err(AuthError::config(
                "Rate limit max requests must be greater than 0 when enabled",
            ));
        }

        // Validate storage configuration
        self.validate_storage_config()?;

        // Validate built-in auth method configuration blobs eagerly so invalid
        // method settings fail during startup instead of at first use.
        self.validate_method_configs()?;

        Ok(())
    }

    fn validate_method_configs(&self) -> Result<()> {
        for (method_name, raw_config) in &self.method_configs {
            match method_name.as_str() {
                #[cfg(feature = "saml")]
                "saml" => {
                    let config: crate::methods::saml::SamlConfig =
                        serde_json::from_value(raw_config.clone()).map_err(|e| {
                            AuthError::config(format!(
                                "Failed to deserialize SAML method config: {e}"
                            ))
                        })?;

                    if config.entity_id.trim().is_empty() {
                        return Err(AuthError::config("SAML entity_id cannot be empty"));
                    }
                    if config.acs_url.trim().is_empty() {
                        return Err(AuthError::config("SAML acs_url cannot be empty"));
                    }
                    if config.max_assertion_age == 0 {
                        return Err(AuthError::config(
                            "SAML max_assertion_age must be greater than 0",
                        ));
                    }
                }
                #[cfg(not(feature = "saml"))]
                "saml" => {
                    return Err(AuthError::config(
                        "SAML method config is present but the 'saml' feature is not enabled",
                    ));
                }
                #[cfg(feature = "passkeys")]
                "passkey" => {
                    let config: crate::methods::passkey::PasskeyConfig =
                        serde_json::from_value(raw_config.clone()).map_err(|e| {
                            AuthError::config(format!(
                                "Failed to deserialize passkey method config: {e}"
                            ))
                        })?;

                    if config.rp_id.trim().is_empty() {
                        return Err(AuthError::config("Passkey RP ID cannot be empty"));
                    }
                    if config.origin.trim().is_empty() {
                        return Err(AuthError::config("Passkey origin cannot be empty"));
                    }
                    if config.timeout_ms == 0 {
                        return Err(AuthError::config("Passkey timeout must be greater than 0"));
                    }
                    match config.user_verification.as_str() {
                        "required" | "preferred" | "discouraged" => {}
                        _ => {
                            return Err(AuthError::config(
                                "Invalid passkey user_verification value",
                            ));
                        }
                    }
                    url::Url::parse(&config.origin).map_err(|e| {
                        AuthError::config(format!("Invalid passkey origin URL: {e}"))
                    })?;
                }
                #[cfg(not(feature = "passkeys"))]
                "passkey" => {
                    return Err(AuthError::config(
                        "Passkey method config is present but the 'passkeys' feature is not enabled",
                    ));
                }
                "enhanced_device_flow" => {
                    let client_id = raw_config
                        .get("client_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let auth_url = raw_config
                        .get("auth_url")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let token_url = raw_config
                        .get("token_url")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    let device_auth_url = raw_config
                        .get("device_auth_url")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();

                    if client_id.trim().is_empty()
                        || auth_url.trim().is_empty()
                        || token_url.trim().is_empty()
                        || device_auth_url.trim().is_empty()
                    {
                        return Err(AuthError::config(
                            "Enhanced device flow config requires non-empty client_id, auth_url, token_url, and device_auth_url",
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Validate JWT secret configuration for security
    fn validate_jwt_secret(&self) -> Result<()> {
        // Check multiple sources for JWT secret
        let env_secret = std::env::var("JWT_SECRET").ok();
        let jwt_secret = self
            .security
            .secret_key
            .as_ref()
            .or(self.secret.as_ref())
            .or(env_secret.as_ref());

        if let Some(secret) = jwt_secret {
            // Enforce minimum length only outside test environments.
            // In tests, short secrets are acceptable for convenience.
            if !self.is_test_environment() && secret.len() < 32 {
                return Err(AuthError::config(
                    "JWT secret must be at least 32 characters for security. \
                     Generate with: openssl rand -base64 32",
                ));
            }

            // Check for low-entropy secrets using Shannon entropy measurement
            // rather than pattern matching, which is trivially bypassed.
            if !self.is_test_environment() {
                let mut char_counts = std::collections::HashMap::new();
                for c in secret.chars() {
                    *char_counts.entry(c).or_insert(0u32) += 1;
                }
                let len = secret.len() as f64;
                let entropy: f64 = char_counts
                    .values()
                    .map(|&count| {
                        let p = count as f64 / len;
                        -p * p.log2()
                    })
                    .sum();
                if entropy < 3.5 {
                    return Err(AuthError::config(
                        "JWT secret has insufficient entropy (too predictable). \
                         Use a cryptographically secure random string.",
                    ));
                }
            }

            // Warn if secret looks like it might be base64 but too short
            if secret.len() < 44
                && secret
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                tracing::warn!(
                    "JWT secret may be too short for optimal security. \
                     Consider using at least 44 characters (32 bytes base64-encoded)."
                );
            }
        } else if self.is_production_environment() {
            return Err(AuthError::config(
                "JWT secret is required for production environments. \
                 Set JWT_SECRET environment variable or configure security.secret_key",
            ));
        }

        Ok(())
    }

    /// Validate production-specific security requirements
    fn validate_production_security(&self) -> Result<()> {
        // Require strong password policies in production
        if self.security.min_password_length < 8 {
            return Err(AuthError::config(
                "Production environments require minimum password length of 8 characters",
            ));
        }

        if !self.security.require_password_complexity {
            tracing::warn!("Production deployment should enable password complexity requirements");
        }

        // Require secure cookies in production
        if !self.security.secure_cookies {
            return Err(AuthError::config(
                "Production environments must use secure cookies (HTTPS required)",
            ));
        }

        // Ensure rate limiting is enabled
        if !self.rate_limiting.enabled {
            tracing::warn!("Production deployment should enable rate limiting for security");
        }

        // Validate audit configuration for compliance
        if !self.audit.enabled {
            return Err(AuthError::config(
                "Production environments require audit logging for compliance",
            ));
        }

        Ok(())
    }

    /// Validate storage configuration
    fn validate_storage_config(&self) -> Result<()> {
        match &self.storage {
            StorageConfig::Memory => {
                if self.is_production_environment() && !self.is_test_environment() {
                    return Err(AuthError::config(
                        "Memory storage is not suitable for production environments. \
                         Use PostgreSQL, Redis, MySQL, or SQLite storage.",
                    ));
                }
            }
            #[cfg(feature = "mysql-storage")]
            StorageConfig::MySQL { .. } => {
                tracing::warn!(
                    "MySQL storage has known RSA vulnerability (RUSTSEC-2023-0071). \
                     Consider using PostgreSQL for enhanced security."
                );
            }
            _ => {} // PostgreSQL and Redis are production-ready
        }

        Ok(())
    }

    /// Detect production environment
    fn is_production_environment(&self) -> bool {
        // An explicit config flag always wins — used by tests that need production behaviour.
        if self.force_production_mode {
            return true;
        }

        // Check common production environment indicators
        if let Ok(env) = std::env::var("ENVIRONMENT")
            && (env.to_lowercase() == "production" || env.to_lowercase() == "prod")
        {
            return true;
        }

        if let Ok(env) = std::env::var("ENV")
            && (env.to_lowercase() == "production" || env.to_lowercase() == "prod")
        {
            return true;
        }

        if let Ok(env) = std::env::var("NODE_ENV")
            && env.to_lowercase() == "production"
        {
            return true;
        }

        if let Ok(env) = std::env::var("RUST_ENV")
            && env.to_lowercase() == "production"
        {
            return true;
        }

        // Check for containerized environments
        if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            return true;
        }

        if std::env::var("DOCKER_CONTAINER").is_ok() {
            return true;
        }

        false
    }

    /// Detect test environment
    fn is_test_environment(&self) -> bool {
        // An explicit config flag forces production mode — never treat it as a test environment.
        if self.force_production_mode {
            return false;
        }
        // Check if we're running in a test environment
        cfg!(test)
            || std::thread::current()
                .name()
                .is_some_and(|name| name.contains("test"))
            || std::env::var("RUST_TEST").is_ok()
            || std::env::var("ENVIRONMENT").as_deref() == Ok("test")
            || std::env::var("ENV").as_deref() == Ok("test")
            || std::env::args().any(|arg| arg.contains("test"))
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::RateLimitConfig;
    /// use std::time::Duration;
    ///
    /// let rl = RateLimitConfig::new(100, Duration::from_secs(60));
    /// assert!(rl.enabled);
    /// assert_eq!(rl.max_requests, 100);
    /// ```
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            enabled: true,
            max_requests,
            window,
            burst: max_requests / 10, // 10% of max as burst
        }
    }

    /// Disable rate limiting.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::RateLimitConfig;
    ///
    /// let rl = RateLimitConfig::disabled();
    /// assert!(!rl.enabled);
    /// ```
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Shorthand: allow `max` requests per second.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::RateLimitConfig;
    ///
    /// let rl = RateLimitConfig::per_second(50);
    /// assert_eq!(rl.max_requests, 50);
    /// ```
    pub fn per_second(max: u32) -> Self {
        Self::new(max, Duration::from_secs(1))
    }

    /// Shorthand: allow `max` requests per minute.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::RateLimitConfig;
    ///
    /// let rl = RateLimitConfig::per_minute(100);
    /// assert_eq!(rl.max_requests, 100);
    /// ```
    pub fn per_minute(max: u32) -> Self {
        Self::new(max, Duration::from_secs(60))
    }

    /// Shorthand: allow `max` requests per hour.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::RateLimitConfig;
    ///
    /// let rl = RateLimitConfig::per_hour(1000);
    /// assert_eq!(rl.max_requests, 1000);
    /// ```
    pub fn per_hour(max: u32) -> Self {
        Self::new(max, Duration::from_secs(3600))
    }
}

impl SecurityConfig {
    /// Create a new security configuration with secure defaults.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::SecurityConfig;
    ///
    /// let sec = SecurityConfig::secure();
    /// assert!(sec.secure_cookies);
    /// assert!(sec.csrf_protection);
    /// assert_eq!(sec.min_password_length, 12);
    /// ```
    pub fn secure() -> Self {
        Self {
            min_password_length: 12,
            require_password_complexity: true,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2,
            jwt_algorithm: JwtAlgorithm::RS256,
            secret_key: None,
            previous_secret_key: None,
            secure_cookies: true,
            cookie_same_site: CookieSameSite::Strict,
            csrf_protection: true,
            session_timeout: Duration::from_secs(3600 * 8), // 8 hours
        }
    }

    /// Create a development-friendly configuration.
    /// WARNING: You MUST set a secret key before using this configuration!
    /// Use either config.security.secret_key or JWT_SECRET environment variable.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::config::SecurityConfig;
    ///
    /// let sec = SecurityConfig::development();
    /// assert_eq!(sec.min_password_length, 6);
    /// assert!(!sec.secure_cookies);
    /// ```
    pub fn development() -> Self {
        Self {
            min_password_length: 6,
            require_password_complexity: false,
            password_hash_algorithm: PasswordHashAlgorithm::Bcrypt,
            jwt_algorithm: JwtAlgorithm::HS256,
            secret_key: None, // Must be set by developer for security
            previous_secret_key: None,
            secure_cookies: false,
            cookie_same_site: CookieSameSite::Lax,
            csrf_protection: false,
            session_timeout: Duration::from_secs(3600 * 24), // 24 hours
        }
    }
}

/// A comprehensive builder for `AuthConfig` that organizes configuration into logical groups.
///
/// This builder provides better developer experience by grouping related settings
/// and providing sensible defaults for each category. Use this when you need fine-grained
/// control over the configuration but want better organization than the flat setter API.
///
/// # Example
///
/// ```rust,no_run
/// use auth_framework::config::{AuthConfig, AuthConfigBuilder};
/// use std::time::Duration;
///
/// let builder = AuthConfigBuilder::new()
///     .tokens()
///         .lifetime(Duration::from_secs(3600))
///         .refresh_lifetime(Duration::from_secs(86400 * 7))
///         .issuer("myapp")
///         .audience("myapp-users")
///         .secret("my-32-char-secret-key-here!!!!!")
///         .done()
///     .security()
///         .min_password_length(8)
///         .require_complexity(true)
///         .secure_cookies(true)
///         .done()
///     .storage()
///         .memory()
///         .done()
///     .features()
///         .enable_multi_factor(true)
///         .enable_rbac(true)
///         .enable_caching(true)
///         .done();
///
/// let config = builder.build().expect("Failed to build config");
/// ```
#[derive(Debug)]
pub struct AuthConfigBuilder {
    config: AuthConfig,
}

impl Default for AuthConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthConfigBuilder {
    /// Create a new builder with sensible defaults.
    pub fn new() -> Self {
        Self {
            config: AuthConfig::default(),
        }
    }

    /// Configure token-related settings.
    pub fn tokens(self) -> TokenConfigBuilder {
        TokenConfigBuilder { builder: self }
    }

    /// Configure security-related settings.
    pub fn security(self) -> SecurityConfigBuilder {
        SecurityConfigBuilder { builder: self }
    }

    /// Configure storage settings.
    pub fn storage(self) -> StorageConfigBuilder {
        StorageConfigBuilder { builder: self }
    }

    /// Configure feature flags and capabilities.
    pub fn features(self) -> FeatureConfigBuilder {
        FeatureConfigBuilder { builder: self }
    }

    /// Configure rate limiting.
    pub fn rate_limiting(self) -> RateLimitConfigBuilder {
        RateLimitConfigBuilder { builder: self }
    }

    /// Configure CORS settings.
    pub fn cors(self) -> CorsConfigBuilder {
        CorsConfigBuilder { builder: self }
    }

    /// Configure audit logging.
    pub fn audit(self) -> AuditConfigBuilder {
        AuditConfigBuilder { builder: self }
    }

    /// Build the final configuration, validating it in the process.
    pub fn build(self) -> Result<AuthConfig> {
        let config = self.config;
        config.validate()?;
        Ok(config)
    }
}

/// Builder for token-related configuration.
#[derive(Debug)]
pub struct TokenConfigBuilder {
    builder: AuthConfigBuilder,
}

impl TokenConfigBuilder {
    /// Set the access token lifetime.
    pub fn lifetime(mut self, duration: Duration) -> Self {
        self.builder.config.token_lifetime = duration;
        self
    }

    /// Set the refresh token lifetime.
    pub fn refresh_lifetime(mut self, duration: Duration) -> Self {
        self.builder.config.refresh_token_lifetime = duration;
        self
    }

    /// Set the JWT issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.builder.config.issuer = issuer.into();
        self
    }

    /// Set the JWT audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.builder.config.audience = audience.into();
        self
    }

    /// Set the JWT secret key.
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.builder.config.secret = Some(secret.into());
        self
    }

    /// Finish token configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for security-related configuration.
#[derive(Debug)]
pub struct SecurityConfigBuilder {
    builder: AuthConfigBuilder,
}

impl SecurityConfigBuilder {
    /// Set minimum password length.
    pub fn min_password_length(mut self, length: usize) -> Self {
        self.builder.config.security.min_password_length = length;
        self
    }

    /// Require password complexity.
    pub fn require_complexity(mut self, required: bool) -> Self {
        self.builder.config.security.require_password_complexity = required;
        self
    }

    /// Set password hash algorithm.
    pub fn password_algorithm(mut self, algorithm: PasswordHashAlgorithm) -> Self {
        self.builder.config.security.password_hash_algorithm = algorithm;
        self
    }

    /// Set JWT algorithm.
    pub fn jwt_algorithm(mut self, algorithm: JwtAlgorithm) -> Self {
        self.builder.config.security.jwt_algorithm = algorithm;
        self
    }

    /// Enable secure cookies.
    pub fn secure_cookies(mut self, enabled: bool) -> Self {
        self.builder.config.security.secure_cookies = enabled;
        self
    }

    /// Set cookie SameSite policy.
    pub fn cookie_same_site(mut self, policy: CookieSameSite) -> Self {
        self.builder.config.security.cookie_same_site = policy;
        self
    }

    /// Enable CSRF protection.
    pub fn csrf_protection(mut self, enabled: bool) -> Self {
        self.builder.config.security.csrf_protection = enabled;
        self
    }

    /// Set session timeout.
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.builder.config.security.session_timeout = timeout;
        self
    }

    /// Finish security configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for storage configuration.
#[derive(Debug)]
pub struct StorageConfigBuilder {
    builder: AuthConfigBuilder,
}

impl StorageConfigBuilder {
    /// Use in-memory storage (development only).
    pub fn memory(mut self) -> Self {
        self.builder.config.storage = StorageConfig::Memory;
        self
    }

    /// Use Redis storage.
    #[cfg(feature = "redis-storage")]
    pub fn redis(mut self, url: impl Into<String>) -> Self {
        self.builder.config.storage = StorageConfig::Redis {
            url: url.into(),
            key_prefix: "auth:".to_string(),
        };
        self
    }

    /// Use PostgreSQL storage.
    #[cfg(feature = "postgres-storage")]
    pub fn postgres(mut self, connection_string: impl Into<String>) -> Self {
        self.builder.config.storage = StorageConfig::Postgres {
            connection_string: connection_string.into(),
            table_prefix: "auth_".to_string(),
        };
        self
    }

    /// Use MySQL storage.
    #[cfg(feature = "mysql-storage")]
    pub fn mysql(mut self, connection_string: impl Into<String>) -> Self {
        self.builder.config.storage = StorageConfig::MySQL {
            connection_string: connection_string.into(),
            table_prefix: "auth_".to_string(),
        };
        self
    }

    /// Use SQLite storage.
    #[cfg(feature = "sqlite-storage")]
    pub fn sqlite(mut self, connection_string: impl Into<String>) -> Self {
        self.builder.config.storage = StorageConfig::Sqlite {
            connection_string: connection_string.into(),
        };
        self
    }

    /// Finish storage configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for feature flags and capabilities.
#[derive(Debug)]
pub struct FeatureConfigBuilder {
    builder: AuthConfigBuilder,
}

impl FeatureConfigBuilder {
    /// Enable multi-factor authentication.
    pub fn enable_multi_factor(mut self, enabled: bool) -> Self {
        self.builder.config.enable_multi_factor = enabled;
        self
    }

    /// Enable RBAC (Role-Based Access Control).
    pub fn enable_rbac(mut self, enabled: bool) -> Self {
        self.builder.config.enable_rbac = enabled;
        self
    }

    /// Enable caching.
    pub fn enable_caching(mut self, enabled: bool) -> Self {
        self.builder.config.enable_caching = enabled;
        self
    }

    /// Enable middleware helpers.
    pub fn enable_middleware(mut self, enabled: bool) -> Self {
        self.builder.config.enable_middleware = enabled;
        self
    }

    /// Set maximum failed authentication attempts.
    pub fn max_failed_attempts(mut self, max: u32) -> Self {
        self.builder.config.max_failed_attempts = max;
        self
    }

    /// Finish feature configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for rate limiting configuration.
#[derive(Debug)]
pub struct RateLimitConfigBuilder {
    builder: AuthConfigBuilder,
}

impl RateLimitConfigBuilder {
    /// Enable rate limiting with specified limits.
    pub fn enabled(mut self, max_requests: u32, window: Duration) -> Self {
        self.builder.config.rate_limiting = RateLimitConfig::new(max_requests, window);
        self
    }

    /// Disable rate limiting.
    pub fn disabled(mut self) -> Self {
        self.builder.config.rate_limiting = RateLimitConfig::disabled();
        self
    }

    /// Set maximum requests per window.
    pub fn max_requests(mut self, max: u32) -> Self {
        self.builder.config.rate_limiting.max_requests = max;
        self
    }

    /// Set rate limiting window.
    pub fn window(mut self, window: Duration) -> Self {
        self.builder.config.rate_limiting.window = window;
        self
    }

    /// Set burst allowance.
    pub fn burst(mut self, burst: u32) -> Self {
        self.builder.config.rate_limiting.burst = burst;
        self
    }

    /// Finish rate limiting configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for CORS configuration.
#[derive(Debug)]
pub struct CorsConfigBuilder {
    builder: AuthConfigBuilder,
}

impl CorsConfigBuilder {
    /// Enable CORS for specific origins.
    pub fn allow_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.builder.config.cors = CorsConfig::for_origins(origins);
        self
    }

    /// Disable CORS.
    pub fn disabled(mut self) -> Self {
        self.builder.config.cors.enabled = false;
        self
    }

    /// Allow specific HTTP methods.
    pub fn allow_methods<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.builder.config.cors.allowed_methods = methods.into_iter().map(Into::into).collect();
        self
    }

    /// Allow specific headers.
    pub fn allow_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.builder.config.cors.allowed_headers = headers.into_iter().map(Into::into).collect();
        self
    }

    /// Set max age for preflight requests.
    pub fn max_age(mut self, seconds: u32) -> Self {
        self.builder.config.cors.max_age_secs = seconds;
        self
    }

    /// Finish CORS configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}

/// Builder for audit configuration.
#[derive(Debug)]
pub struct AuditConfigBuilder {
    builder: AuthConfigBuilder,
}

impl AuditConfigBuilder {
    /// Enable audit logging.
    pub fn enabled(mut self) -> Self {
        self.builder.config.audit.enabled = true;
        self
    }

    /// Disable audit logging.
    pub fn disabled(mut self) -> Self {
        self.builder.config.audit.enabled = false;
        self
    }

    /// Log successful authentications.
    pub fn log_success(mut self, enabled: bool) -> Self {
        self.builder.config.audit.log_success = enabled;
        self
    }

    /// Log failed authentications.
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.builder.config.audit.log_failures = enabled;
        self
    }

    /// Log permission checks.
    pub fn log_permissions(mut self, enabled: bool) -> Self {
        self.builder.config.audit.log_permissions = enabled;
        self
    }

    /// Log token operations.
    pub fn log_tokens(mut self, enabled: bool) -> Self {
        self.builder.config.audit.log_tokens = enabled;
        self
    }

    /// Finish audit configuration and return to the main builder.
    pub fn done(self) -> AuthConfigBuilder {
        self.builder
    }
}
