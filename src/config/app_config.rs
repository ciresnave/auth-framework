/// Configuration management with environment variable support.
///
/// This module provides easy configuration loading from environment
/// variables, config files, and other sources.
use super::SecurityConfig;
use serde::{Deserialize, Serialize};
use std::{env, time::Duration};

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Database configuration
    pub database: DatabaseConfig,
    /// Redis configuration
    pub redis: Option<RedisConfig>,
    /// JWT configuration
    pub jwt: JwtConfig,
    /// OAuth providers
    pub oauth: OAuthConfig,
    /// Security settings
    pub security: SecuritySettings,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Database connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database connection URL (PostgreSQL, MySQL, SQLite, etc.)
    pub url: String,
    /// Maximum number of concurrent database connections
    pub max_connections: u32,
    /// Minimum number of idle connections to maintain
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout_seconds: u64,
}

/// Redis cache and session storage settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,
    /// Number of connections in the Redis connection pool
    pub pool_size: u32,
}

/// JWT authentication settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Cryptographic secret key used to sign and verify JWTs
    pub secret_key: String,
    /// The 'iss' (issuer) claim to embed in generated tokens
    pub issuer: String,
    /// The 'aud' (audience) claim to embed in generated tokens
    pub audience: String,
    /// Primary access token lifetime in seconds
    pub access_token_ttl_seconds: u64,
    /// Refresh token lifetime in seconds
    pub refresh_token_ttl_seconds: u64,
}

/// Supported OAuth provider identities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, std::hash::Hash)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProvider {
    /// Google OAuth identity provider
    Google,
    /// GitHub OAuth identity provider
    GitHub,
    /// Microsoft OAuth identity provider
    Microsoft,
    /// Other custom OAuth provider
    Custom(String),
}

/// OAuth 2.0 configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// OAuth provider configurations, keyed by provider
    pub providers: std::collections::HashMap<String, OAuthProviderConfig>,
}

/// Individual OAuth provider settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// OAuth client ID provided by the Identity Provider
    pub client_id: String,
    /// OAuth client secret provided by the Identity Provider
    pub client_secret: String,
    /// The redirect URI where the IDP will send the user post-authentication
    pub redirect_uri: String,
    /// List of scopes to request during authentication
    pub scopes: Vec<String>,
}

/// Application-wide security policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Minimum character length for new passwords
    pub password_min_length: usize,
    /// Whether to require at least one special character in new passwords
    pub password_require_special_chars: bool,
    /// Maximum number of requests allowed per minute per IP
    pub rate_limit_requests_per_minute: u32,
    /// Maximum hours a session token remains valid without activity
    pub session_timeout_hours: u64,
    /// Maximum number of simultaneous active sessions a user can have
    pub max_concurrent_sessions: u32,
    /// Whether Multi-Factor Authentication is globally required
    pub require_mfa: bool,
}

/// System logging and auditing settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (e.g., "info", "debug", "warn")
    pub level: String,
    /// True if audit logging for security events is enabled
    pub audit_enabled: bool,
    /// Location to store audit events ("database", "file", "syslog")
    pub audit_storage: String,
}

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .map_err(|_| ConfigError::MissingEnvVar("DATABASE_URL"))?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .map_err(|_| ConfigError::InvalidValue("DB_MAX_CONNECTIONS"))?,
                min_connections: 1,
                connect_timeout_seconds: 30,
            },
            redis: if let Ok(redis_url) = env::var("REDIS_URL") {
                Some(RedisConfig {
                    url: redis_url,
                    pool_size: 10,
                })
            } else {
                None
            },
            jwt: JwtConfig {
                secret_key: env::var("JWT_SECRET")
                    .map_err(|_| ConfigError::MissingEnvVar("JWT_SECRET"))?,
                issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "auth-framework".to_string()),
                audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "api".to_string()),
                access_token_ttl_seconds: 3600,
                refresh_token_ttl_seconds: 86400 * 7,
            },
            oauth: OAuthConfig {
                providers: {
                    let mut map = std::collections::HashMap::new();
                    if let Some(cfg) = Self::load_oauth_provider("GOOGLE") {
                        map.insert("google".to_string(), cfg);
                    }
                    if let Some(cfg) = Self::load_oauth_provider("GITHUB") {
                        map.insert("github".to_string(), cfg);
                    }
                    if let Some(cfg) = Self::load_oauth_provider("MICROSOFT") {
                        map.insert("microsoft".to_string(), cfg);
                    }
                    map
                },
            },
            security: SecuritySettings {
                password_min_length: 8,
                password_require_special_chars: true,
                rate_limit_requests_per_minute: 60,
                session_timeout_hours: 24,
                max_concurrent_sessions: 5,
                require_mfa: env::var("REQUIRE_MFA").unwrap_or_default() == "true",
            },
            logging: LoggingConfig {
                level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
                audit_enabled: true,
                audit_storage: env::var("AUDIT_STORAGE").unwrap_or_else(|_| "database".to_string()),
            },
        })
    }

    fn load_oauth_provider(provider: &str) -> Option<OAuthProviderConfig> {
        let client_id = env::var(format!("{}_CLIENT_ID", provider)).ok()?;
        let client_secret = env::var(format!("{}_CLIENT_SECRET", provider)).ok()?;

        Some(OAuthProviderConfig {
            client_id,
            client_secret,
            redirect_uri: env::var(format!("{}_REDIRECT_URI", provider))
                .unwrap_or_else(|_| format!("/auth/{}/callback", provider.to_lowercase())),
            scopes: env::var(format!("{}_SCOPES", provider))
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    /// Convert to AuthConfig
    pub fn to_auth_config(&self) -> super::AuthConfig {
        let mut config = super::AuthConfig::new()
            .token_lifetime(Duration::from_secs(self.jwt.access_token_ttl_seconds))
            .refresh_token_lifetime(Duration::from_secs(self.jwt.refresh_token_ttl_seconds))
            .issuer(&self.jwt.issuer)
            .audience(&self.jwt.audience)
            .secret(&self.jwt.secret_key)
            .security(self.to_security_config());

        config.storage = self.primary_storage_config();
        config.enable_multi_factor = self.security.require_mfa;
        config.rate_limiting = super::RateLimitConfig {
            enabled: self.security.rate_limit_requests_per_minute > 0,
            max_requests: self.security.rate_limit_requests_per_minute,
            window: Duration::from_secs(60),
            burst: (self.security.rate_limit_requests_per_minute / 10).max(1),
        };
        config.audit.enabled = self.logging.audit_enabled;
        config
    }

    /// Convert to SecurityConfig
    pub fn to_security_config(&self) -> SecurityConfig {
        SecurityConfig {
            min_password_length: self.security.password_min_length,
            require_password_complexity: self.security.password_require_special_chars,
            secret_key: Some(self.jwt.secret_key.clone()),
            session_timeout: Duration::from_secs(self.security.session_timeout_hours * 3600),
            ..Default::default()
        }
    }

    /// Build an initialized AuthFramework using the configured storage backend.
    pub async fn build_auth_framework(&self) -> crate::errors::Result<crate::AuthFramework> {
        let auth_config = self.to_auth_config();
        let pool_size = self.primary_storage_pool_size();

        let mut framework = crate::AuthFramework::new(auth_config.clone());
        let storage =
            crate::storage::factory::build_storage_backend(&auth_config.storage, pool_size).await?;
        framework.replace_storage(storage);
        framework.initialize().await?;
        Ok(framework)
    }

    pub(crate) fn primary_storage_config(&self) -> super::StorageConfig {
        let database_url = self.database.url.trim();

        if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
            #[cfg(feature = "postgres-storage")]
            {
                return super::StorageConfig::Postgres {
                    connection_string: database_url.to_string(),
                    table_prefix: "auth_".to_string(),
                };
            }

            #[cfg(not(feature = "postgres-storage"))]
            {
                return super::StorageConfig::Custom(
                    "postgres-storage feature is required for PostgreSQL DATABASE_URL".to_string(),
                );
            }
        }

        if database_url.starts_with("mysql://") {
            #[cfg(feature = "mysql-storage")]
            {
                return super::StorageConfig::MySQL {
                    connection_string: database_url.to_string(),
                    table_prefix: "auth_".to_string(),
                };
            }

            #[cfg(not(feature = "mysql-storage"))]
            {
                return super::StorageConfig::Custom(
                    "mysql-storage feature is required for MySQL DATABASE_URL".to_string(),
                );
            }
        }

        if database_url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite-storage")]
            {
                return super::StorageConfig::Sqlite {
                    connection_string: database_url.to_string(),
                };
            }

            #[cfg(not(feature = "sqlite-storage"))]
            {
                return super::StorageConfig::Custom(
                    "sqlite-storage feature is required for SQLite DATABASE_URL".to_string(),
                );
            }
        }

        super::StorageConfig::Memory
    }

    fn primary_storage_pool_size(&self) -> Option<u32> {
        let database_url = self.database.url.trim();
        if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
            || database_url.starts_with("mysql://")
            || database_url.starts_with("sqlite:")
        {
            return Some(self.database.max_connections);
        }

        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(&'static str),
    #[error("Invalid value for: {0}")]
    InvalidValue(&'static str),
    #[error("Configuration validation error: {0}")]
    Validation(String),
}

/// Configuration builder for easy setup
pub struct ConfigBuilder {
    config: AppConfig,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: AppConfig::from_env().unwrap_or_else(|_| AppConfig::default()),
        }
    }

    pub fn with_database_url(mut self, url: impl Into<String>) -> Self {
        self.config.database.url = url.into();
        self
    }

    pub fn with_database_max_connections(mut self, max_connections: u32) -> Self {
        self.config.database.max_connections = max_connections;
        self
    }

    pub fn with_database_min_connections(mut self, min_connections: u32) -> Self {
        self.config.database.min_connections = min_connections;
        self
    }

    pub fn with_database_connect_timeout(mut self, seconds: u64) -> Self {
        self.config.database.connect_timeout_seconds = seconds;
        self
    }

    pub fn with_jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.jwt.secret_key = secret.into();
        self
    }

    pub fn with_jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.jwt.issuer = issuer.into();
        self
    }

    pub fn with_jwt_audience(mut self, audience: impl Into<String>) -> Self {
        self.config.jwt.audience = audience.into();
        self
    }

    pub fn with_access_token_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.config.jwt.access_token_ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_refresh_token_ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.config.jwt.refresh_token_ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_redis_url(mut self, url: impl Into<String>) -> Self {
        self.config.redis = Some(RedisConfig {
            url: url.into(),
            pool_size: 10,
        });
        self
    }

    pub fn with_redis_pool_size(mut self, pool_size: u32) -> Self {
        let redis = self.config.redis.get_or_insert(RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            pool_size: 10,
        });
        redis.pool_size = pool_size;
        self
    }

    /// Set password policy constraints.
    ///
    /// # Arguments
    /// * `min_length` - minimum password length (typically 8+)
    /// * `require_special` - require at least one special character (!@#$%^&* etc.)
    pub fn with_password_policy(mut self, min_length: usize, require_special: bool) -> Self {
        self.config.security.password_min_length = min_length;
        self.config.security.password_require_special_chars = require_special;
        self
    }

    pub fn with_rate_limit_requests_per_minute(mut self, requests: u32) -> Self {
        self.config.security.rate_limit_requests_per_minute = requests;
        self
    }

    pub fn with_session_timeout_hours(mut self, hours: u64) -> Self {
        self.config.security.session_timeout_hours = hours;
        self
    }

    pub fn with_require_mfa(mut self, require_mfa: bool) -> Self {
        self.config.security.require_mfa = require_mfa;
        self
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.config.logging.level = level.into();
        self
    }

    pub fn build(self) -> AppConfig {
        self.config
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                url: "postgresql://localhost/auth_framework".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout_seconds: 30,
            },
            redis: None,
            jwt: JwtConfig {
                secret_key: "development-only-secret-change-in-production".to_string(),
                issuer: "auth-framework".to_string(),
                audience: "api".to_string(),
                access_token_ttl_seconds: 3600,
                refresh_token_ttl_seconds: 86400 * 7,
            },
            oauth: OAuthConfig {
                providers: std::collections::HashMap::new(),
            },
            security: SecuritySettings {
                password_min_length: 8,
                password_require_special_chars: true,
                rate_limit_requests_per_minute: 60,
                session_timeout_hours: 24,
                max_concurrent_sessions: 5,
                require_mfa: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                audit_enabled: true,
                audit_storage: "database".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .with_database_url("postgresql://test")
            .with_database_max_connections(25)
            .with_jwt_secret("test-secret")
            .with_jwt_issuer("issuer")
            .with_jwt_audience("audience")
            .with_rate_limit_requests_per_minute(120)
            .build();

        assert_eq!(config.database.url, "postgresql://test");
        assert_eq!(config.database.max_connections, 25);
        assert_eq!(config.jwt.secret_key, "test-secret");
        assert_eq!(config.jwt.issuer, "issuer");
        assert_eq!(config.jwt.audience, "audience");
        assert_eq!(config.security.rate_limit_requests_per_minute, 120);
    }
}
