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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret_key: String,
    pub issuer: String,
    pub audience: String,
    pub access_token_ttl_seconds: u64,
    pub refresh_token_ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
    pub microsoft: Option<OAuthProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub password_min_length: usize,
    pub password_require_special: bool,
    pub rate_limit_requests_per_minute: u32,
    pub session_timeout_hours: u64,
    pub max_concurrent_sessions: u32,
    pub require_mfa: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub audit_enabled: bool,
    pub audit_storage: String, // "database", "file", "syslog"
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
                google: Self::load_oauth_provider("GOOGLE"),
                github: Self::load_oauth_provider("GITHUB"),
                microsoft: Self::load_oauth_provider("MICROSOFT"),
            },
            security: SecuritySettings {
                password_min_length: 8,
                password_require_special: true,
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
        super::AuthConfig::new()
            .token_lifetime(Duration::from_secs(self.jwt.access_token_ttl_seconds))
            .refresh_token_lifetime(Duration::from_secs(self.jwt.refresh_token_ttl_seconds))
            .issuer(&self.jwt.issuer)
            .audience(&self.jwt.audience)
            .secret(&self.jwt.secret_key)
    }

    /// Convert to SecurityConfig
    pub fn to_security_config(&self) -> SecurityConfig {
        SecurityConfig::default() // Would customize based on security settings
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

    pub fn with_jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.jwt.secret_key = secret.into();
        self
    }

    pub fn with_redis_url(mut self, url: impl Into<String>) -> Self {
        self.config.redis = Some(RedisConfig {
            url: url.into(),
            pool_size: 10,
        });
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
                google: None,
                github: None,
                microsoft: None,
            },
            security: SecuritySettings {
                password_min_length: 8,
                password_require_special: true,
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
            .with_jwt_secret("test-secret")
            .build();

        assert_eq!(config.database.url, "postgresql://test");
        assert_eq!(config.jwt.secret_key, "test-secret");
    }
}
