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
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_framework::prelude::*;
//!
//! // Simple JWT auth with environment variables
//! let auth = AuthFramework::quick_start()
//!     .jwt_auth_from_env()
//!     .build().await?;
//!
//! // Web app with database
//! let auth = AuthFramework::quick_start()
//!     .jwt_auth("your-secret-key")
//!     .with_postgres("postgresql://...")
//!     .with_axum()
//!     .build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Preset Configurations
//!
//! Use presets for common security and performance configurations:
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_framework::prelude::*;
//!
//! let auth = AuthFramework::builder()
//!     .security_preset(SecurityPreset::HighSecurity)
//!     .performance_preset(PerformancePreset::LowLatency)
//!     .build().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Use Case Templates
//!
//! Get started quickly with templates for common use cases:
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_framework::prelude::*;
//!
//! // Configure for web application
//! let auth = AuthFramework::for_use_case(UseCasePreset::WebApp)
//!     .customize(|config| {
//!         config.token_lifetime = hours(24);
//!         config
//!     })
//!     .build().await?;
//! # Ok(())
//! # }
//! ```

use crate::{
    AuthConfig, AuthError, AuthFramework,
    config::{RateLimitConfig, SecurityConfig, StorageConfig},
    prelude::{PerformancePreset, UseCasePreset, days, hours, minutes},
    security::SecurityPreset,
};
use std::time::Duration;
#[cfg(not(feature = "redis-storage"))]
use tracing::warn;
use zeroize::Zeroizing;

/// Main builder for constructing an [`AuthFramework`] instance.
///
/// Start with [`AuthFramework::builder()`] and chain sub-builders for
/// JWT, storage, security, rate limiting, and audit configuration.
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use auth_framework::prelude::*;
///
/// let auth = AuthFramework::builder()
///     .with_jwt().secret("my-secret-key-that-is-long-enough!!").issuer("myapp").done()
///     .with_storage().memory().done()
///     .security_preset(SecurityPreset::Balanced)
///     .build().await?;
/// # Ok(())
/// # }
/// ```
pub struct AuthBuilder {
    config: AuthConfig,
    security_preset: Option<SecurityPreset>,
    performance_preset: Option<PerformancePreset>,
    use_case_preset: Option<UseCasePreset>,
    storage_pool_size: Option<u32>,
    /// Optional custom storage instance supplied by caller (`Arc<dyn AuthStorage>`)
    custom_storage: Option<std::sync::Arc<dyn crate::storage::AuthStorage>>,
}

/// Quick start builder for common authentication setups.
///
/// Provides the fastest path to a working [`AuthFramework`] by combining
/// authentication method, storage, and framework integrations in a single
/// fluent chain.  Start via [`AuthFramework::quick_start()`].
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use auth_framework::prelude::*;
///
/// let auth = AuthFramework::quick_start()
///     .jwt_auth("my-secret-key-that-is-long-enough!!")
///     .build().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct QuickStartBuilder {
    auth_method: Option<QuickStartAuth>,
    storage: Option<QuickStartStorage>,
    framework: Option<QuickStartFramework>,
    security_level: SecurityPreset,
}

/// Authentication method selection for [`QuickStartBuilder`].
#[derive(Debug)]
pub enum QuickStartAuth {
    Jwt {
        secret: Zeroizing<String>,
    },
    JwtFromEnv,
    OAuth2 {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
    Combined {
        jwt_secret: Zeroizing<String>,
        oauth_client_id: String,
        oauth_client_secret: Zeroizing<String>,
    },
}

/// Storage backend selection for [`QuickStartBuilder`].
#[derive(Debug)]
pub enum QuickStartStorage {
    Memory,
    Postgres(String),
    PostgresFromEnv,
    Redis(String),
    RedisFromEnv,
}

/// Web framework integration selection for [`QuickStartBuilder`].
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
    /// Create a new builder with default configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::builders::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            config: AuthConfig::default(),
            security_preset: None,
            performance_preset: None,
            use_case_preset: None,
            storage_pool_size: None,
            custom_storage: None,
        }
    }

    /// Apply a security preset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .security_preset(SecurityPreset::HighSecurity);
    /// ```
    pub fn security_preset(mut self, preset: SecurityPreset) -> Self {
        self.security_preset = Some(preset);
        self
    }

    /// Apply a performance preset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .performance_preset(PerformancePreset::LowLatency);
    /// ```
    pub fn performance_preset(mut self, preset: PerformancePreset) -> Self {
        self.performance_preset = Some(preset);
        self
    }

    /// Apply a use case preset.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .use_case_preset(UseCasePreset::WebApp);
    /// ```
    pub fn use_case_preset(mut self, preset: UseCasePreset) -> Self {
        self.use_case_preset = Some(preset);
        self
    }

    /// Configure JWT authentication.
    ///
    /// Returns a [`JwtBuilder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret("my-long-secret-key-32-chars-min!!").done();
    /// ```
    pub fn with_jwt(self) -> JwtBuilder {
        JwtBuilder::new(self)
    }

    /// Configure OAuth2 authentication.
    ///
    /// Returns an [`OAuth2Builder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().client_id("id").client_secret("secret").done();
    /// ```
    pub fn with_oauth2(self) -> OAuth2Builder {
        OAuth2Builder::new(self)
    }

    /// Configure storage backend.
    ///
    /// Returns a [`StorageBuilder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().memory().done();
    /// ```
    pub fn with_storage(self) -> StorageBuilder {
        StorageBuilder::new(self)
    }

    /// Configure rate limiting.
    ///
    /// Returns a [`RateLimitBuilder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use std::time::Duration;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_rate_limiting().per_ip((200, Duration::from_secs(60))).done();
    /// ```
    pub fn with_rate_limiting(self) -> RateLimitBuilder {
        RateLimitBuilder::new(self)
    }

    /// Configure security settings.
    ///
    /// Returns a [`SecurityBuilder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_security().min_password_length(12).secure_cookies(true).done();
    /// ```
    pub fn with_security(self) -> SecurityBuilder {
        SecurityBuilder::new(self)
    }

    /// Configure audit logging.
    ///
    /// Returns an [`AuditBuilder`] sub-builder. Call `.done()` to return.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_audit().enabled(true).log_success(true).done();
    /// ```
    pub fn with_audit(self) -> AuditBuilder {
        AuditBuilder::new(self)
    }

    /// Customize configuration with a closure.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use std::time::Duration;
    ///
    /// let builder = AuthFramework::builder()
    ///     .customize(|config| {
    ///         config.token_lifetime = Duration::from_secs(7200);
    ///         config
    ///     });
    /// ```
    pub fn customize<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut AuthConfig) -> &mut AuthConfig,
    {
        f(&mut self.config);
        self
    }

    /// Build the authentication framework.
    ///
    /// Applies presets, validates configuration, initializes storage,
    /// and returns a ready-to-use [`AuthFramework`] instance.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::builder()
    ///     .with_jwt().secret("my-long-secret-key-32-chars-min!!").done()
    ///     .with_storage().memory().done()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
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
        let config = self.config.clone();
        let mut framework = AuthFramework::new(self.config);
        if let Some(storage) = self.custom_storage.take() {
            framework.replace_storage(storage);
        } else if let Some(pool_size) = self.storage_pool_size {
            let storage = crate::storage::factory::build_storage_backend_with_encryption(
                &config.storage,
                Some(pool_size),
                &config.storage_encryption,
            )
            .await?;
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

    /// Configure JWT authentication with a secret key.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn jwt_auth(mut self, secret: impl Into<String>) -> Self {
        self.auth_method = Some(QuickStartAuth::Jwt {
            secret: secret.into().into(),
        });
        self
    }

    /// Configure JWT authentication from `JWT_SECRET` environment variable.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// // Reads JWT_SECRET from the environment
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth_from_env()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn jwt_auth_from_env(mut self) -> Self {
        self.auth_method = Some(QuickStartAuth::JwtFromEnv);
        self
    }

    /// Configure OAuth2 authentication.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .oauth2_auth("client-id", "client-secret")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn oauth2_auth(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.auth_method = Some(QuickStartAuth::OAuth2 {
            client_id: client_id.into(),
            client_secret: client_secret.into().into(),
        });
        self
    }

    /// Configure both JWT and OAuth2 authentication.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .combined_auth("jwt-secret-long-enough-32chars!!", "client-id", "secret")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn combined_auth(
        mut self,
        jwt_secret: impl Into<String>,
        oauth_client_id: impl Into<String>,
        oauth_client_secret: impl Into<String>,
    ) -> Self {
        self.auth_method = Some(QuickStartAuth::Combined {
            jwt_secret: jwt_secret.into().into(),
            oauth_client_id: oauth_client_id.into(),
            oauth_client_secret: oauth_client_secret.into().into(),
        });
        self
    }

    /// Use PostgreSQL storage with connection string.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_postgres("postgresql://user:pass@localhost/auth")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_postgres(mut self, connection_string: impl Into<String>) -> Self {
        self.storage = Some(QuickStartStorage::Postgres(connection_string.into()));
        self
    }

    /// Use PostgreSQL storage from `DATABASE_URL` environment variable.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_postgres_from_env()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_postgres_from_env(mut self) -> Self {
        self.storage = Some(QuickStartStorage::PostgresFromEnv);
        self
    }

    /// Use Redis storage with connection string.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_redis("redis://localhost:6379")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_redis(mut self, connection_string: impl Into<String>) -> Self {
        self.storage = Some(QuickStartStorage::Redis(connection_string.into()));
        self
    }

    /// Use Redis storage from `REDIS_URL` environment variable.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_redis_from_env()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_redis_from_env(mut self) -> Self {
        self.storage = Some(QuickStartStorage::RedisFromEnv);
        self
    }

    /// Use in-memory storage (development only).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_memory_storage()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_memory_storage(mut self) -> Self {
        self.storage = Some(QuickStartStorage::Memory);
        self
    }

    /// Configure for Axum web framework.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_axum()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_axum(mut self) -> Self {
        self.framework = Some(QuickStartFramework::Axum);
        self
    }

    /// Configure for Actix Web framework.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_actix()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_actix(mut self) -> Self {
        self.framework = Some(QuickStartFramework::ActixWeb);
        self
    }

    /// Configure for Warp web framework.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .with_warp()
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn with_warp(mut self) -> Self {
        self.framework = Some(QuickStartFramework::Warp);
        self
    }

    /// Set security level.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .security_level(SecurityPreset::HighSecurity)
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn security_level(mut self, level: SecurityPreset) -> Self {
        self.security_level = level;
        self
    }

    /// Build the authentication framework.
    ///
    /// Applies the configured auth method, storage, and security level,
    /// then delegates to [`AuthBuilder::build`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use auth_framework::prelude::*;
    ///
    /// let auth = AuthFramework::quick_start()
    ///     .jwt_auth("my-long-secret-key-32-chars-min!!")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub async fn build(self) -> Result<AuthFramework, AuthError> {
        let mut builder = AuthBuilder::new().security_preset(self.security_level);

        // Configure authentication method
        match self.auth_method {
            Some(QuickStartAuth::Jwt { secret }) => {
                builder = builder.with_jwt().secret(secret.to_string()).done();
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
                    .client_secret(client_secret.to_string())
                    .done();
            }
            Some(QuickStartAuth::Combined {
                jwt_secret,
                oauth_client_id,
                oauth_client_secret,
            }) => {
                builder = builder
                    .with_jwt()
                    .secret(jwt_secret.to_string())
                    .done()
                    .with_oauth2()
                    .client_id(oauth_client_id)
                    .client_secret(oauth_client_secret.to_string())
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
            Some(QuickStartStorage::Postgres(_conn_str)) => {
                #[cfg(feature = "postgres-storage")]
                {
                    builder = builder.with_storage().postgres(_conn_str).done();
                }
                #[cfg(not(feature = "postgres-storage"))]
                {
                    warn!(
                        "PostgreSQL storage requested but the `postgres-storage` feature is not enabled; \
                         falling back to in-memory storage"
                    );
                    builder = builder.with_storage().memory().done();
                }
            }
            Some(QuickStartStorage::PostgresFromEnv) => {
                #[cfg(feature = "postgres-storage")]
                {
                    let conn_str = std::env::var("DATABASE_URL").map_err(|_| {
                        AuthError::config("DATABASE_URL environment variable is required")
                    })?;
                    builder = builder.with_storage().postgres(conn_str).done();
                }
                #[cfg(not(feature = "postgres-storage"))]
                {
                    warn!(
                        "PostgreSQL storage requested but the `postgres-storage` feature is not enabled; \
                         falling back to in-memory storage"
                    );
                    builder = builder.with_storage().memory().done();
                }
            }
            Some(QuickStartStorage::Redis(_conn_str)) => {
                #[cfg(feature = "redis-storage")]
                {
                    builder = builder.with_storage().redis(_conn_str).done();
                }
                #[cfg(not(feature = "redis-storage"))]
                {
                    warn!(
                        "Redis storage requested but the `redis-storage` feature is not enabled; \
                         falling back to in-memory storage"
                    );
                    builder = builder.with_storage().memory().done();
                }
            }
            Some(QuickStartStorage::RedisFromEnv) => {
                #[cfg(feature = "redis-storage")]
                {
                    builder = builder.with_storage().redis_from_env().done();
                }
                #[cfg(not(feature = "redis-storage"))]
                {
                    warn!(
                        "Redis storage requested but the `redis-storage` feature is not enabled; \
                         falling back to in-memory storage"
                    );
                    builder = builder.with_storage().memory().done();
                }
            }
            None => {
                // Default to memory storage for quick start
                builder = builder.with_storage().memory().done();
            }
        }

        builder.build().await
    }
}

/// Sub-builder for JWT settings.
///
/// Entered via [`AuthBuilder::with_jwt()`]; call [`done()`](JwtBuilder::done)
/// to return to the parent builder.
pub struct JwtBuilder {
    parent: AuthBuilder,
    secret: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
    token_lifetime: Option<Duration>,
    refresh_token_lifetime: Option<Duration>,
    algorithm: Option<crate::config::JwtAlgorithm>,
}

impl JwtBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self {
            parent,
            secret: None,
            issuer: None,
            audience: None,
            token_lifetime: None,
            refresh_token_lifetime: None,
            algorithm: None,
        }
    }

    /// Set JWT secret key.
    ///
    /// Must be at least 32 characters for HMAC algorithms.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret("my-long-secret-key-32-chars-min!!").done();
    /// ```
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Set JWT secret from environment variable.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret_from_env("MY_JWT_SECRET").done();
    /// ```
    pub fn secret_from_env(mut self, env_var: &str) -> Self {
        if let Ok(secret) = std::env::var(env_var) {
            self.secret = Some(secret);
        }
        self
    }

    /// Set JWT issuer.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret("secret-key-at-least-32-characters!!").issuer("my-service").done();
    /// ```
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set JWT audience.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret("secret-key-at-least-32-characters!!").audience("my-api").done();
    /// ```
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set token lifetime.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use std::time::Duration;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt()
    ///     .secret("secret-key-at-least-32-characters!!")
    ///     .token_lifetime(Duration::from_secs(1800))
    ///     .done();
    /// ```
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = Some(lifetime);
        self
    }

    /// Set refresh token lifetime (defaults to 7 days).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use std::time::Duration;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt()
    ///     .secret("secret-key-at-least-32-characters!!")
    ///     .refresh_token_lifetime(Duration::from_secs(86400))
    ///     .done();
    /// ```
    pub fn refresh_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.refresh_token_lifetime = Some(lifetime);
        self
    }

    /// Set the JWT signing algorithm (defaults to HS256).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use auth_framework::config::JwtAlgorithm;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt()
    ///     .secret("secret-key-at-least-32-characters!!")
    ///     .algorithm(JwtAlgorithm::HS512)
    ///     .done();
    /// ```
    pub fn algorithm(mut self, algorithm: crate::config::JwtAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Complete JWT configuration and return to main builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_jwt().secret("secret-key-at-least-32-characters!!").done()
    ///     .with_storage().memory().done();
    /// ```
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
        if let Some(lifetime) = self.refresh_token_lifetime {
            self.parent.config.refresh_token_lifetime = lifetime;
        }
        if let Some(algorithm) = self.algorithm {
            self.parent.config.security.jwt_algorithm = algorithm;
        }
        self.parent
    }
}

/// Sub-builder for OAuth 2.0 client credentials.
///
/// Entered via [`AuthBuilder::with_oauth2()`]; call [`done()`](OAuth2Builder::done)
/// to return to the parent builder.
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

    /// Set OAuth2 client ID.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().client_id("my-client-id").done();
    /// ```
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set OAuth2 client secret.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().client_id("id").client_secret("secret").done();
    /// ```
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set redirect URI.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2()
    ///     .client_id("id")
    ///     .redirect_uri("https://example.com/callback")
    ///     .done();
    /// ```
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    /// Configure Google OAuth2.
    ///
    /// Alias for [`client_id`](Self::client_id).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().google_client_id("123.apps.googleusercontent.com").done();
    /// ```
    pub fn google_client_id(self, client_id: impl Into<String>) -> Self {
        self.client_id(client_id)
    }

    /// Configure GitHub OAuth2.
    ///
    /// Alias for [`client_id`](Self::client_id).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().github_client_id("Iv1.abc123").done();
    /// ```
    pub fn github_client_id(self, client_id: impl Into<String>) -> Self {
        self.client_id(client_id)
    }

    /// Complete OAuth2 configuration and return to main builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_oauth2().client_id("id").client_secret("secret").done();
    /// ```
    pub fn done(mut self) -> AuthBuilder {
        let mut oauth2_config = serde_json::Map::new();
        if let Some(client_id) = self.client_id {
            oauth2_config.insert(
                "client_id".to_string(),
                serde_json::Value::String(client_id),
            );
        }
        if let Some(client_secret) = self.client_secret {
            oauth2_config.insert(
                "client_secret".to_string(),
                serde_json::Value::String(client_secret),
            );
        }
        if let Some(redirect_uri) = self.redirect_uri {
            oauth2_config.insert(
                "redirect_uri".to_string(),
                serde_json::Value::String(redirect_uri),
            );
        }
        self.parent.config.method_configs.insert(
            "oauth2".to_string(),
            serde_json::Value::Object(oauth2_config),
        );
        self.parent
    }
}

/// Sub-builder for storage backend selection.
///
/// Entered via [`AuthBuilder::with_storage()`]; call [`done()`](StorageBuilder::done)
/// to return to the parent builder.
pub struct StorageBuilder {
    parent: AuthBuilder,
}

impl StorageBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Use a custom storage instance (already initialized) instead of
    /// the built-in storage backends.
    ///
    /// Pass any type that implements [`AuthStorage`](crate::storage::AuthStorage)
    /// wrapped in an `Arc`. This is the extension point for third-party or
    /// proprietary databases (SurrealDB, FoundationDB, DynamoDB, etc.).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use auth_framework::prelude::*;
    /// use auth_framework::storage::AuthStorage;
    ///
    /// // Implement `AuthStorage` for your backend, then:
    /// let storage: Arc<dyn AuthStorage> = Arc::new(
    ///     MySurrealStorage::connect("ws://localhost:8000").await?,
    /// );
    ///
    /// let auth = AuthFramework::builder()
    ///     .with_storage()
    ///     .custom(storage)
    ///     .done()
    ///     .build()
    ///     .await?;
    /// ```
    pub fn custom(mut self, storage: std::sync::Arc<dyn crate::storage::AuthStorage>) -> Self {
        self.parent.custom_storage = Some(storage);
        self
    }

    /// Configure in-memory storage.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().memory().done();
    /// ```
    pub fn memory(mut self) -> Self {
        self.parent.config.storage = StorageConfig::Memory;
        self
    }

    /// Configure PostgreSQL storage.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().postgres("postgresql://user:pass@localhost/db").done();
    /// ```
    #[cfg(feature = "postgres-storage")]
    pub fn postgres(mut self, connection_string: impl Into<String>) -> Self {
        self.parent.config.storage = StorageConfig::Postgres {
            connection_string: connection_string.into(),
            table_prefix: "auth_".to_string(),
        };
        self
    }

    /// Configure PostgreSQL storage from environment.
    ///
    /// Reads `DATABASE_URL` from the environment.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().postgres_from_env().done();
    /// ```
    #[cfg(feature = "postgres-storage")]
    pub fn postgres_from_env(mut self) -> Self {
        if let Ok(conn_str) = std::env::var("DATABASE_URL") {
            self = self.postgres(conn_str);
        }
        self
    }

    /// Configure Redis storage.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().redis("redis://localhost:6379").done();
    /// ```
    #[cfg(feature = "redis-storage")]
    pub fn redis(mut self, url: impl Into<String>) -> Self {
        self.parent.config.storage = StorageConfig::Redis {
            url: url.into(),
            key_prefix: "auth:".to_string(),
        };
        self
    }

    /// Configure Redis storage from environment.
    ///
    /// Reads `REDIS_URL` from the environment.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().redis_from_env().done();
    /// ```
    #[cfg(feature = "redis-storage")]
    pub fn redis_from_env(mut self) -> Self {
        if let Ok(url) = std::env::var("REDIS_URL") {
            self = self.redis(url);
        }
        self
    }

    /// Configure SQLite storage
    #[cfg(feature = "sqlite-storage")]
    pub fn sqlite(mut self, connection_string: impl Into<String>) -> Self {
        self.parent.config.storage = StorageConfig::Sqlite {
            connection_string: connection_string.into(),
        };
        self
    }

    /// Set connection pool size.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_storage().memory().connection_pool_size(20).done();
    /// ```
    pub fn connection_pool_size(mut self, size: u32) -> Self {
        self.parent.storage_pool_size = Some(size);
        self
    }

    /// Complete storage configuration and return to main builder.
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Sub-builder for rate limiting policy.
///
/// Entered via [`AuthBuilder::with_rate_limit()`]; call
/// [`done()`](RateLimitBuilder::done) to return to the parent builder.
pub struct RateLimitBuilder {
    parent: AuthBuilder,
}

impl RateLimitBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Configure rate limiting per IP.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    /// use std::time::Duration;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_rate_limiting().per_ip((200, Duration::from_secs(60))).done();
    /// ```
    pub fn per_ip(mut self, (requests, window): (u32, Duration)) -> Self {
        self.parent.config.rate_limiting = RateLimitConfig {
            enabled: true,
            max_requests: requests,
            window,
            burst: requests / 10,
        };
        self
    }

    /// Disable rate limiting.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_rate_limiting().disabled().done();
    /// ```
    pub fn disabled(mut self) -> Self {
        self.parent.config.rate_limiting.enabled = false;
        self
    }

    /// Complete rate limiting configuration and return to main builder.
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Sub-builder for security settings (passwords, cookies, CSRF).
///
/// Entered via [`AuthBuilder::with_security()`]; call
/// [`done()`](SecurityBuilder::done) to return to the parent builder.
pub struct SecurityBuilder {
    parent: AuthBuilder,
}

impl SecurityBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Set minimum password length.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_security().min_password_length(12).done();
    /// ```
    pub fn min_password_length(mut self, length: usize) -> Self {
        self.parent.config.security.min_password_length = length;
        self
    }

    /// Enable/disable password complexity requirements.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_security().require_password_complexity(false).done();
    /// ```
    pub fn require_password_complexity(mut self, required: bool) -> Self {
        self.parent.config.security.require_password_complexity = required;
        self
    }

    /// Enable/disable secure cookies.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_security().secure_cookies(true).done();
    /// ```
    pub fn secure_cookies(mut self, enabled: bool) -> Self {
        self.parent.config.security.secure_cookies = enabled;
        self
    }

    /// Complete security configuration and return to main builder.
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

/// Sub-builder for audit logging settings.
///
/// Entered via [`AuthBuilder::with_audit()`]; call
/// [`done()`](AuditBuilder::done) to return to the parent builder.
pub struct AuditBuilder {
    parent: AuthBuilder,
}

impl AuditBuilder {
    fn new(parent: AuthBuilder) -> Self {
        Self { parent }
    }

    /// Enable audit logging.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_audit().enabled(true).done();
    /// ```
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.parent.config.audit.enabled = enabled;
        self
    }

    /// Log successful authentications.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_audit().log_success(true).done();
    /// ```
    pub fn log_success(mut self, enabled: bool) -> Self {
        self.parent.config.audit.log_success = enabled;
        self
    }

    /// Log failed authentications.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::prelude::*;
    ///
    /// let builder = AuthFramework::builder()
    ///     .with_audit().log_failures(true).done();
    /// ```
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.parent.config.audit.log_failures = enabled;
        self
    }

    /// Complete audit configuration and return to main builder.
    pub fn done(self) -> AuthBuilder {
        self.parent
    }
}

impl Default for AuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}
