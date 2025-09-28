//! Builder patterns and ergonomic helpers for the Auth Framework
//!
//! This module provides fluent builder APIs and helper functions to make
//! common authentication setup tasks easier and more discoverable.
//!
//! # Quick Start Builders
//!
//! For the most common setups, use the quick start builders:
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Simple JWT auth with environment variables
//! let auth = AuthFramework::quick_start()
//!     .jwt_auth_from_env()
//!     .build().await?;
//!
//! // Web app with database  
//! let auth2 = AuthFramework::quick_start()
//!     .jwt_auth("your-secret-key")
//!     .with_postgres("postgresql://...")
//!     .with_axum()
//!     .build().await?;
//! Ok(())
//! }
//! ```
//!
//! # Preset Configurations
//!
//! Use presets for common security and performance configurations:
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = AuthFramework::builder()
//!     .security_preset(SecurityPreset::HighSecurity)
//!     .performance_preset(PerformancePreset::LowLatency)
//!     .build().await?;
//! Ok(())
//! }
//! ```
//!
//! # Use Case Templates
//!
//! Get started quickly with templates for common use cases:
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure for web application
//! let auth = AuthFramework::for_use_case(UseCasePreset::WebApp)
//!     .customize(|config| {
//!         config.token_lifetime = hours(24);
//!         config
//!     })
//!     .build().await?;
//! Ok(())
//! }
//! ```

use crate::{
    AuthConfig, AuthError, AuthFramework,
    config::{RateLimitConfig, SecurityConfig, StorageConfig},
    prelude::{PerformancePreset, UseCasePreset, days, hours, minutes},
    security::SecurityPreset,
};
use std::time::Duration;

/// Main builder for AuthFramework with fluent API
pub struct AuthBuilder {
    config: AuthConfig,
    security_preset: Option<SecurityPreset>,
    performance_preset: Option<PerformancePreset>,
    use_case_preset: Option<UseCasePreset>,
    /// Optional custom storage instance supplied by caller (Arc<dyn AuthStorage>)
    custom_storage: Option<std::sync::Arc<dyn crate::storage::AuthStorage>>,
}

/// Quick start builder for common authentication setups
#[derive(Debug)]
pub struct QuickStartBuilder {
    auth_method: Option<QuickStartAuth>,
    storage: Option<QuickStartStorage>,
    framework: Option<QuickStartFramework>,
    security_level: SecurityPreset,
}

/// Authentication method configuration for quick start
#[derive(Debug)]
pub enum QuickStartAuth {
    Jwt {
        secret: String,
    },
    JwtFromEnv,
    OAuth2 {
        client_id: String,
        client_secret: String,
    },
    Combined {
        jwt_secret: String,
        oauth_client_id: String,
        oauth_client_secret: String,
    },
}

/// Storage configuration for quick start
#[derive(Debug)]
pub enum QuickStartStorage {
    Memory,
    Postgres(String),
    PostgresFromEnv,
    Redis(String),
    RedisFromEnv,
}

/// Web framework integration for quick start
#[derive(Debug)]
pub enum QuickStartFramework {
    Axum,
    ActixWeb,
    Warp,
}

impl AuthFramework {
    /// Create a new builder for the authentication framework
    pub fn builder() -> AuthBuilder {
        AuthBuilder::new()
    }

    /// Quick start builder for common setups
    pub fn quick_start() -> QuickStartBuilder {
        QuickStartBuilder::new()
    }

    /// Create a builder for a specific use case
    pub fn for_use_case(use_case: UseCasePreset) -> AuthBuilder {
        AuthBuilder::new().use_case_preset(use_case)
    }

    /// Create an authentication framework with preset configuration
    pub fn preset(preset: SecurityPreset) -> AuthBuilder {
        AuthBuilder::new().security_preset(preset)
    }
}

impl AuthBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config: AuthConfig::default(),
            security_preset: None,
            performance_preset: None,
            use_case_preset: None,
            custom_storage: None,
        }
    }

    /// Apply a security preset
    pub fn security_preset(mut self, preset: SecurityPreset) -> Self {
        self.security_preset = Some(preset);
        self
    }

    /// Apply a performance preset
    pub fn performance_preset(mut self, preset: PerformancePreset) -> Self {
        self.performance_preset = Some(preset);
        self
    }

    /// Apply a use case preset
    pub fn use_case_preset(mut self, preset: UseCasePreset) -> Self {
        self.use_case_preset = Some(preset);
        self
    }

    /// Configure JWT authentication
    pub fn with_jwt(self) -> JwtBuilder {
        JwtBuilder::new(self)
    }

    /// Configure OAuth2 authentication
    pub fn with_oauth2(self) -> OAuth2Builder {
        OAuth2Builder::new(self)
    }

    /// Configure storage backend
    pub fn with_storage(self) -> StorageBuilder {
        StorageBuilder::new(self)
    }

    /// Configure rate limiting
    pub fn with_rate_limiting(self) -> RateLimitBuilder {
        RateLimitBuilder::new(self)
    }

    /// Configure security settings
    pub fn with_security(self) -> SecurityBuilder {
        SecurityBuilder::new(self)
    }

    /// Configure audit logging
    pub fn with_audit(self) -> AuditBuilder {
        AuditBuilder::new(self)
    }

    /// Customize configuration with a closure
    pub fn customize<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut AuthConfig) -> &mut AuthConfig,
    {
        f(&mut self.config);
        self
    }

    /// Build the authentication framework
    pub async fn build(mut self) -> Result<AuthFramework, AuthError> {
        // Apply presets before building
        if let Some(preset) = self.security_preset.take() {
            self.config.security = self.apply_security_preset(preset);
        }

        if let Some(preset) = self.performance_preset.take() {
            self.apply_performance_preset(preset);
        }

        if let Some(preset) = self.use_case_preset.take() {
            self.apply_use_case_preset(preset);
        }

        // Validate configuration
        self.config.validate()?;

        // Create and initialize framework
        // If a custom storage was provided via the builder, we'll construct a framework
        // and replace its storage before initialization so managers use the custom storage.
        let mut framework = AuthFramework::new(self.config);
        if let Some(storage) = self.custom_storage.take() {
            framework.replace_storage(storage);
        }
        framework.initialize().await?;

        Ok(framework)
    }

    fn apply_security_preset(&self, preset: SecurityPreset) -> SecurityConfig {
        match preset {
            SecurityPreset::Development => SecurityConfig::development(),
            SecurityPreset::Balanced => SecurityConfig::default(),
            SecurityPreset::HighSecurity | SecurityPreset::Paranoid => SecurityConfig::secure(),
        }
    }

    fn apply_performance_preset(&mut self, preset: PerformancePreset) {
        match preset {
            PerformancePreset::HighThroughput => {
                // Optimize for throughput
                self.config.rate_limiting.max_requests = 1000;
                self.config.rate_limiting.window = Duration::from_secs(60);
            }
            PerformancePreset::LowLatency => {
                // Optimize for latency
                self.config.token_lifetime = hours(1);
                self.config.rate_limiting.max_requests = 100;
                self.config.rate_limiting.window = Duration::from_secs(60);
            }
            PerformancePreset::LowMemory => {
                // Optimize for memory usage
                self.config.token_lifetime = minutes(15);
                self.config.refresh_token_lifetime = hours(2);
            }
            PerformancePreset::Balanced => {
                // Keep defaults
            }
        }
    }

    fn apply_use_case_preset(&mut self, preset: UseCasePreset) {
        match preset {
            UseCasePreset::WebApp => {
                self.config.token_lifetime = hours(24);
                self.config.refresh_token_lifetime = days(7);
                self.config.security.secure_cookies = true;
                self.config.security.csrf_protection = true;
            }
            UseCasePreset::ApiService => {
                self.config.token_lifetime = hours(1);
                self.config.refresh_token_lifetime = hours(24);
                self.config.rate_limiting.enabled = true;
                self.config.rate_limiting.max_requests = 1000;
            }
            UseCasePreset::Microservices => {
                self.config.token_lifetime = minutes(15);
                self.config.refresh_token_lifetime = hours(1);
                self.config.audit.enabled = true;
            }
            UseCasePreset::MobileBackend => {
                self.config.token_lifetime = hours(1);
                self.config.refresh_token_lifetime = days(30);
                self.config.security.secure_cookies = false; // Mobile doesn't use cookies
            }
            UseCasePreset::Enterprise => {
                self.config.enable_multi_factor = true;
                self.config.security = SecurityConfig::secure();
                self.config.audit.enabled = true;
                self.config.audit.log_success = true;
                self.config.audit.log_failures = true;
            }
        }
    }
}

impl QuickStartBuilder {
    fn new() -> Self {
        Self {
            auth_method: None,
            storage: None,
            framework: None,
            security_level: SecurityPreset::Balanced,
        }
    }

    /// Configure JWT authentication with a secret key
    pub fn jwt_auth(mut self, secret: impl Into<String>) -> Self {
        self.auth_method = Some(QuickStartAuth::Jwt {
            secret: secret.into(),
        });
        self
    }

    /// Configure JWT authentication from JWT_SECRET environment variable
    pub fn jwt_auth_from_env(mut self) -> Self {
        self.auth_method = Some(QuickStartAuth::JwtFromEnv);
        self
    }

    /// Configure OAuth2 authentication
    pub fn oauth2_auth(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.auth_method = Some(QuickStartAuth::OAuth2 {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        });
        self
    }

    /// Configure both JWT and OAuth2 authentication
    pub fn combined_auth(
        mut self,
        jwt_secret: impl Into<String>,
        oauth_client_id: impl Into<String>,
        oauth_client_secret: impl Into<String>,
    ) -> Self {
        self.auth_method = Some(QuickStartAuth::Combined {
            jwt_secret: jwt_secret.into(),
            oauth_client_id: oauth_client_id.into(),
            oauth_client_secret: oauth_client_secret.into(),
        });
        self
    }

    /// Use PostgreSQL storage with connection string
    pub fn with_postgres(mut self, connection_string: impl Into<String>) -> Self {
        self.storage = Some(QuickStartStorage::Postgres(connection_string.into()));
        self
    }

    /// Use PostgreSQL storage from DATABASE_URL environment variable
    pub fn with_postgres_from_env(mut self) -> Self {
        self.storage = Some(QuickStartStorage::PostgresFromEnv);
        self
    }

    /// Use Redis storage with connection string
    pub fn with_redis(mut self, connection_string: impl Into<String>) -> Self {
        self.storage = Some(QuickStartStorage::Redis(connection_string.into()));
        self
    }

    /// Use Redis storage from REDIS_URL environment variable
    pub fn with_redis_from_env(mut self) -> Self {
        self.storage = Some(QuickStartStorage::RedisFromEnv);
        self
    }

    /// Use in-memory storage (development only)
    pub fn with_memory_storage(mut self) -> Self {
        self.storage = Some(QuickStartStorage::Memory);
        self
    }

    /// Configure for Axum web framework
    pub fn with_axum(mut self) -> Self {
        self.framework = Some(QuickStartFramework::Axum);
        self
    }

    /// Configure for Actix Web framework
    pub fn with_actix(mut self) -> Self {
        self.framework = Some(QuickStartFramework::ActixWeb);
        self
    }

    /// Configure for Warp web framework
    pub fn with_warp(mut self) -> Self {
        self.framework = Some(QuickStartFramework::Warp);
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityPreset) -> Self {
        self.security_level = level;
        self
    }

    /// Build the authentication framework
    pub async fn build(self) -> Result<AuthFramework, AuthError> {
        let mut builder = AuthBuilder::new().security_preset(self.security_level);

        // Configure authentication method
        match self.auth_method {
            Some(QuickStartAuth::Jwt { secret }) => {
                builder = builder.with_jwt().secret(secret).done();
            }
            Some(QuickStartAuth::JwtFromEnv) => {
                let secret = std::env::var("JWT_SECRET").map_err(|_| {
                    AuthError::config("JWT_SECRET environment variable is required")
                })?;
                builder = builder.with_jwt().secret(secret).done();
            }
            Some(QuickStartAuth::OAuth2 {
                client_id,
                client_secret,
            }) => {
                builder = builder
                    .with_oauth2()
                    .client_id(client_id)
                    .client_secret(client_secret)
                    .done();
            }
            Some(QuickStartAuth::Combined {
                jwt_secret,
                oauth_client_id,
                oauth_client_secret,
            }) => {
                builder = builder
                    .with_jwt()
                    .secret(jwt_secret)
                    .done()
                    .with_oauth2()
                    .client_id(oauth_client_id)
                    .client_secret(oauth_client_secret)
                    .done();
            }
            None => {
                return Err(AuthError::config("Authentication method is required"));
            }
        }

        // Configure storage
        match self.storage {
            Some(QuickStartStorage::Memory) => {
                builder = builder.with_storage().memory().done();
            }
            Some(QuickStartStorage::Postgres(conn_str)) => {
                builder = builder.with_storage().postgres(conn_str).done();
            }
            Some(QuickStartStorage::PostgresFromEnv) => {
                let conn_str = std::env::var("DATABASE_URL").map_err(|_| {
                    AuthError::config("DATABASE_URL environment variable is required")
                })?;
                builder = builder.with_storage().postgres(conn_str).done();
            }
            Some(QuickStartStorage::Redis(_conn_str)) => {
                // Redis storage not yet implemented, fallback to memory
                builder = builder.with_storage().memory().done();
            }
            Some(QuickStartStorage::RedisFromEnv) => {
                // Redis storage not yet implemented, fallback to memory
                builder = builder.with_storage().memory().done();
            }
            None => {
                // Default to memory storage for quick start
                builder = builder.with_storage().memory().done();
            }
        }

        builder.build().await
    }
}

/// JWT configuration builder
pub struct JwtBuilder {
    parent: AuthBuilder,
    secret: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    token_lifetime: Option<Duration>,
}

impl JwtBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self {
            parent,
            secret: None,
            issuer: None,
            audience: None,
            token_lifetime: None,
        }
    }

    /// Set JWT secret key
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Load JWT secret from environment variable
    pub fn secret_from_env(mut self, env_var: &str) -> Self {
        if let Ok(secret) = std::env::var(env_var) {
            self.secret = Some(secret);
        }
        self
    }

    /// Set JWT issuer
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set JWT audience
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set token lifetime
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = Some(lifetime);
        self
    }

    /// Complete JWT configuration and return to main builder
    pub fn done(mut self) -> AuthBuilder {
        if let Some(secret) = self.secret {
            self.parent.config.secret = Some(secret);
        }
        if let Some(issuer) = self.issuer {
            self.parent.config.issuer = issuer;
        }
        if let Some(audience) = self.audience {
            self.parent.config.audience = audience;
        }
        if let Some(lifetime) = self.token_lifetime {
            self.parent.config.token_lifetime = lifetime;
        }
        self.parent
    }
}

// Provide a custom Debug implementation for AuthBuilder that omits the
// `custom_storage` field (trait object) to avoid requiring Debug on all
// storage implementations.
impl std::fmt::Debug for AuthBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBuilder")
            .field("config", &"<AuthConfig>")
            .field("security_preset", &self.security_preset)
            .field("performance_preset", &self.performance_preset)
            .field("use_case_preset", &self.use_case_preset)
            .field("custom_storage", &"<custom storage omitted>")
            .finish()
    }
}

/// OAuth2 configuration builder
pub struct OAuth2Builder {
    parent: AuthBuilder,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
}

impl OAuth2Builder {
    fn new(parent: AuthBuilder) -> Self {
        Self {
            parent,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }
    }

    /// Set OAuth2 client ID
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set OAuth2 client secret
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set redirect URI
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Configure Google OAuth2
    pub fn google_client_id(self, client_id: impl Into<String>) -> Self {
        self.client_id(client_id)
    }

    /// Configure GitHub OAuth2
    pub fn github_client_id(self, client_id: impl Into<String>) -> Self {
        self.client_id(client_id)
    }

    /// Complete OAuth2 configuration and return to main builder
    pub fn done(self) -> AuthBuilder {
        // OAuth2 configuration would be stored in method_configs
        // This is a simplified version
        self.parent
    }
}

/// Storage configuration builder
pub struct StorageBuilder {
    parent: AuthBuilder,
}

impl StorageBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Use a custom storage instance (already initialized) instead of configuring via enums.
    ///
    /// Example:
    ///
    /// let storage = Arc::new(MySurrealStorage::connect(...).await?);
    /// let auth = AuthFramework::builder()
    ///     .with_storage()
    ///     .custom(storage)
    ///     .done()
    ///     .build()
    ///     .await?;
    pub fn custom(mut self, storage: std::sync::Arc<dyn crate::storage::AuthStorage>) -> Self {
        self.parent.custom_storage = Some(storage);
        self
    }

    /// Configure in-memory storage
    pub fn memory(mut self) -> Self {
        self.parent.config.storage = StorageConfig::Memory;
        self
    }

    /// Configure PostgreSQL storage
    #[cfg(feature = "postgres-storage")]
    pub fn postgres(mut self, connection_string: impl Into<String>) -> Self {
        self.parent.config.storage = StorageConfig::Postgres {
            connection_string: connection_string.into(),
            table_prefix: "auth_".to_string(),
        };
        self
    }

    /// Configure PostgreSQL storage from environment
    #[cfg(feature = "postgres-storage")]
    pub fn postgres_from_env(mut self) -> Self {
        if let Ok(conn_str) = std::env::var("DATABASE_URL") {
            self = self.postgres(conn_str);
        }
        self
    }

    /// Configure Redis storage
    #[cfg(feature = "redis-storage")]
    pub fn redis(mut self, url: impl Into<String>) -> Self {
        self.parent.config.storage = StorageConfig::Redis {
            url: url.into(),
            key_prefix: "auth:".to_string(),
        };
        self
    }

    /// Configure Redis storage from environment
    #[cfg(feature = "redis-storage")]
    pub fn redis_from_env(mut self) -> Self {
        if let Ok(url) = std::env::var("REDIS_URL") {
            self = self.redis(url);
        }
        self
    }

    /// Set connection pool size
    pub fn connection_pool_size(self, _size: u32) -> Self {
        // This would be implemented when storage supports connection pooling
        self
    }

    /// Complete storage configuration and return to main builder
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Rate limiting configuration builder
pub struct RateLimitBuilder {
    parent: AuthBuilder,
}

impl RateLimitBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Configure rate limiting per IP
    pub fn per_ip(mut self, (requests, window): (u32, Duration)) -> Self {
        self.parent.config.rate_limiting = RateLimitConfig {
            enabled: true,
            max_requests: requests,
            window,
            burst: requests / 10,
        };
        self
    }

    /// Disable rate limiting
    pub fn disabled(mut self) -> Self {
        self.parent.config.rate_limiting.enabled = false;
        self
    }

    /// Complete rate limiting configuration and return to main builder
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Security configuration builder
pub struct SecurityBuilder {
    parent: AuthBuilder,
}

impl SecurityBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Set minimum password length
    pub fn min_password_length(mut self, length: usize) -> Self {
        self.parent.config.security.min_password_length = length;
        self
    }

    /// Enable/disable password complexity requirements
    pub fn require_password_complexity(mut self, required: bool) -> Self {
        self.parent.config.security.require_password_complexity = required;
        self
    }

    /// Enable/disable secure cookies
    pub fn secure_cookies(mut self, enabled: bool) -> Self {
        self.parent.config.security.secure_cookies = enabled;
        self
    }

    /// Complete security configuration and return to main builder
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Audit configuration builder
pub struct AuditBuilder {
    parent: AuthBuilder,
}

impl AuditBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Enable audit logging
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.parent.config.audit.enabled = enabled;
        self
    }

    /// Log successful authentications
    pub fn log_success(mut self, enabled: bool) -> Self {
        self.parent.config.audit.log_success = enabled;
        self
    }

    /// Log failed authentications
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.parent.config.audit.log_failures = enabled;
        self
    }

    /// Complete audit configuration and return to main builder
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

impl Default for AuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}
