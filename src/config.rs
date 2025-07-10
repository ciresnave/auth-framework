//! Configuration types for the authentication framework.

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main configuration for the authentication framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Default token lifetime
    pub token_lifetime: Duration,
    
    /// Refresh token lifetime
    pub refresh_token_lifetime: Duration,
    
    /// Whether multi-factor authentication is enabled
    pub enable_multi_factor: bool,
    
    /// Storage configuration
    pub storage: StorageConfig,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Audit logging configuration
    pub audit: AuditConfig,
    
    /// Custom settings for different auth methods
    pub method_configs: HashMap<String, serde_json::Value>,
}

/// Storage configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageConfig {
    /// In-memory storage (not recommended for production)
    Memory,
    
    /// Redis storage
    #[cfg(feature = "redis-storage")]
    Redis {
        url: String,
        key_prefix: String,
    },
    
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
    
    /// Custom storage backend
    Custom(String),
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Argon2,
    Bcrypt,
    Scrypt,
}

/// JWT signing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
}

/// Cookie SameSite policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CookieSameSite {
    Strict,
    Lax,
    None,
}

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Audit log storage options.
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

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_lifetime: Duration::from_secs(3600), // 1 hour
            refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
            enable_multi_factor: false,
            storage: StorageConfig::Memory,
            rate_limiting: RateLimitConfig::default(),
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
            method_configs: HashMap::new(),
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

impl AuthConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the token lifetime.
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = lifetime;
        self
    }

    /// Set the refresh token lifetime.
    pub fn refresh_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.refresh_token_lifetime = lifetime;
        self
    }

    /// Enable or disable multi-factor authentication.
    pub fn enable_multi_factor(mut self, enabled: bool) -> Self {
        self.enable_multi_factor = enabled;
        self
    }

    /// Require MFA for all users.
    pub fn require_mfa(mut self, required: bool) -> Self {
        self.enable_multi_factor = required;
        self
    }

    /// Enable caching.
    pub fn enable_caching(self, _enabled: bool) -> Self {
        // This would set a caching flag in a real implementation
        self
    }

    /// Set maximum failed attempts.
    pub fn max_failed_attempts(self, _max: u32) -> Self {
        // This would set max failed attempts in security config
        self
    }

    /// Enable RBAC.
    pub fn enable_rbac(self, _enabled: bool) -> Self {
        // This would enable role-based access control
        self
    }

    /// Enable security audit.
    pub fn enable_security_audit(self, _enabled: bool) -> Self {
        // This would enable security auditing
        self
    }

    /// Enable middleware.
    pub fn enable_middleware(self, _enabled: bool) -> Self {
        // This would enable middleware support
        self
    }

    /// Set the storage configuration.
    pub fn storage(mut self, storage: StorageConfig) -> Self {
        self.storage = storage;
        self
    }

    /// Configure Redis storage.
    #[cfg(feature = "redis-storage")]
    pub fn redis_storage(mut self, url: impl Into<String>) -> Self {
        self.storage = StorageConfig::Redis {
            url: url.into(),
            key_prefix: "auth:".to_string(),
        };
        self
    }

    /// Set rate limiting configuration.
    pub fn rate_limiting(mut self, config: RateLimitConfig) -> Self {
        self.rate_limiting = config;
        self
    }

    /// Set security configuration.
    pub fn security(mut self, config: SecurityConfig) -> Self {
        self.security = config;
        self
    }

    /// Set audit configuration.
    pub fn audit(mut self, config: AuditConfig) -> Self {
        self.audit = config;
        self
    }

    /// Add configuration for a specific auth method.
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
    pub fn get_method_config<T>(&self, method_name: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if let Some(value) = self.method_configs.get(method_name) {
            let config = serde_json::from_value(value.clone())
                .map_err(|e| AuthError::config(format!("Failed to deserialize method config: {e}")))?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate token lifetimes
        if self.token_lifetime.as_secs() == 0 {
            return Err(AuthError::config("Token lifetime must be greater than 0"));
        }

        if self.refresh_token_lifetime.as_secs() == 0 {
            return Err(AuthError::config("Refresh token lifetime must be greater than 0"));
        }

        if self.refresh_token_lifetime <= self.token_lifetime {
            return Err(AuthError::config(
                "Refresh token lifetime must be greater than token lifetime"
            ));
        }

        // Validate security settings
        if self.security.min_password_length < 4 {
            return Err(AuthError::config(
                "Minimum password length must be at least 4 characters"
            ));
        }

        // Validate rate limiting
        if self.rate_limiting.enabled && self.rate_limiting.max_requests == 0 {
            return Err(AuthError::config(
                "Rate limit max requests must be greater than 0 when enabled"
            ));
        }

        Ok(())
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            enabled: true,
            max_requests,
            window,
            burst: max_requests / 10, // 10% of max as burst
        }
    }

    /// Disable rate limiting.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

impl SecurityConfig {
    /// Create a new security configuration with secure defaults.
    pub fn secure() -> Self {
        Self {
            min_password_length: 12,
            require_password_complexity: true,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2,
            jwt_algorithm: JwtAlgorithm::RS256,
            secret_key: None,
            secure_cookies: true,
            cookie_same_site: CookieSameSite::Strict,
            csrf_protection: true,
            session_timeout: Duration::from_secs(3600 * 8), // 8 hours
        }
    }

    /// Create a development-friendly configuration.
    pub fn development() -> Self {
        Self {
            min_password_length: 6,
            require_password_complexity: false,
            password_hash_algorithm: PasswordHashAlgorithm::Bcrypt,
            jwt_algorithm: JwtAlgorithm::HS256,
            secret_key: Some("development-secret-key".to_string()),
            secure_cookies: false,
            cookie_same_site: CookieSameSite::Lax,
            csrf_protection: false,
            session_timeout: Duration::from_secs(3600 * 24), // 24 hours
        }
    }
}
