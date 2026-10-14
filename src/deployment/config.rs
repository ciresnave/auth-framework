// Configuration management for production deployment
// Comprehensive configuration system with environment-specific settings, validation, and hot-reload

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    FileNotFound(String),
    #[error("Invalid configuration format: {0}")]
    InvalidFormat(String),
    #[error("Configuration validation error: {0}")]
    Validation(String),
    #[error("Environment variable error: {0}")]
    Environment(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Configuration format types
#[derive(Debug, Clone)]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
    Environment,
}

/// Environment-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
    pub variables: HashMap<String, String>,
    pub overrides: HashMap<String, serde_json::Value>,
    pub secrets: Vec<String>,
    pub required_vars: Vec<String>,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub ssl_mode: String,
    pub pool_size: u32,
    pub timeout: u64,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: u32,
    pub max_connections: u32,
    pub timeout: u64,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: Vec<String>,
    pub rotation: Option<LogRotationConfig>,
    pub structured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    pub size: String,
    pub keep: u32,
    pub compress: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub session_timeout: u64,
    pub bcrypt_cost: u32,
    pub rate_limiting: RateLimitConfig,
    pub cors: CorsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub max_age: u32,
}

/// Complete application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub environment: String,
    pub debug: bool,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    pub features: HashMap<String, bool>,
    pub custom: HashMap<String, serde_json::Value>,
}

/// Configuration manager with hot-reload support
pub struct ConfigManager {
    config: AppConfig,
    config_path: PathBuf,
    format: ConfigFormat,
    environments: HashMap<String, EnvironmentConfig>,
    watchers: Vec<Box<dyn ConfigWatcher>>,
}

/// Trait for configuration change watchers
pub trait ConfigWatcher: Send + Sync {
    fn on_config_changed(&self, config: &AppConfig) -> Result<(), ConfigError>;
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    /// Create new configuration manager
    pub fn new() -> Self {
        Self {
            config: AppConfig::default(),
            config_path: PathBuf::from("config.toml"),
            format: ConfigFormat::Toml,
            environments: HashMap::new(),
            watchers: Vec::new(),
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ConfigError> {
        let path = path.as_ref();
        self.config_path = path.to_path_buf();

        // Determine format from file extension
        self.format = match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => ConfigFormat::Json,
            Some("toml") => ConfigFormat::Toml,
            Some("yaml") | Some("yml") => ConfigFormat::Yaml,
            _ => ConfigFormat::Toml,
        };

        let content = fs::read_to_string(path)
            .map_err(|_| ConfigError::FileNotFound(path.display().to_string()))?;

        self.config = self.parse_config(&content)?;
        self.validate_config()?;

        Ok(())
    }

    /// Load configuration from environment variables
    pub fn load_from_env(&mut self) -> Result<(), ConfigError> {
        self.format = ConfigFormat::Environment;

        let mut config = AppConfig::default();

        // Load server configuration from environment
        if let Ok(host) = std::env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|_| ConfigError::Environment("Invalid SERVER_PORT".to_string()))?;
        }

        // Load database configuration from environment
        if let Ok(host) = std::env::var("DATABASE_HOST") {
            config.database.host = host;
        }
        if let Ok(port) = std::env::var("DATABASE_PORT") {
            config.database.port = port
                .parse()
                .map_err(|_| ConfigError::Environment("Invalid DATABASE_PORT".to_string()))?;
        }
        if let Ok(database) = std::env::var("DATABASE_NAME") {
            config.database.database = database;
        }
        if let Ok(username) = std::env::var("DATABASE_USER") {
            config.database.username = username;
        }
        if let Ok(password) = std::env::var("DATABASE_PASSWORD") {
            config.database.password = password;
        }

        // Load security configuration from environment
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            config.security.jwt_secret = jwt_secret;
        }

        // Load environment name
        if let Ok(env) = std::env::var("ENVIRONMENT") {
            config.environment = env;
        }

        self.config = config;
        self.validate_config()?;

        Ok(())
    }

    /// Parse configuration content based on format
    fn parse_config(&self, content: &str) -> Result<AppConfig, ConfigError> {
        match self.format {
            ConfigFormat::Json => {
                serde_json::from_str(content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))
            }
            ConfigFormat::Toml => {
                toml::from_str(content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))
            }
            ConfigFormat::Yaml => {
                serde_yaml::from_str(content).map_err(|e| ConfigError::InvalidFormat(e.to_string()))
            }
            ConfigFormat::Environment => Err(ConfigError::InvalidFormat(
                "Environment loading not supported here".to_string(),
            )),
        }
    }

    /// Validate configuration
    fn validate_config(&self) -> Result<(), ConfigError> {
        // Validate server configuration
        if self.config.server.host.is_empty() {
            return Err(ConfigError::Validation(
                "Server host cannot be empty".to_string(),
            ));
        }
        if self.config.server.port == 0 {
            return Err(ConfigError::Validation(
                "Server port must be greater than 0".to_string(),
            ));
        }
        if self.config.server.workers == 0 {
            return Err(ConfigError::Validation(
                "Server workers must be greater than 0".to_string(),
            ));
        }

        // Validate database configuration
        if self.config.database.host.is_empty() {
            return Err(ConfigError::Validation(
                "Database host cannot be empty".to_string(),
            ));
        }
        if self.config.database.port == 0 {
            return Err(ConfigError::Validation(
                "Database port must be greater than 0".to_string(),
            ));
        }
        if self.config.database.database.is_empty() {
            return Err(ConfigError::Validation(
                "Database name cannot be empty".to_string(),
            ));
        }

        // Validate security configuration
        if self.config.security.jwt_secret.is_empty() {
            return Err(ConfigError::Validation(
                "JWT secret cannot be empty".to_string(),
            ));
        }
        if self.config.security.jwt_secret.len() < 32 {
            return Err(ConfigError::Validation(
                "JWT secret must be at least 32 characters".to_string(),
            ));
        }
        if self.config.security.bcrypt_cost < 4 || self.config.security.bcrypt_cost > 31 {
            return Err(ConfigError::Validation(
                "Bcrypt cost must be between 4 and 31".to_string(),
            ));
        }

        // Validate logging configuration
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.config.logging.level.as_str()) {
            return Err(ConfigError::Validation("Invalid logging level".to_string()));
        }

        Ok(())
    }

    /// Get current configuration
    pub fn get_config(&self) -> &AppConfig {
        &self.config
    }

    /// Update configuration value
    pub fn set_value(&mut self, key: &str, value: serde_json::Value) -> Result<(), ConfigError> {
        // Parse key path (e.g., "server.port" or "database.host")
        let parts: Vec<&str> = key.split('.').collect();

        match parts.as_slice() {
            ["server", "host"] => {
                if let Some(host) = value.as_str() {
                    self.config.server.host = host.to_string();
                } else {
                    return Err(ConfigError::Validation(
                        "Server host must be a string".to_string(),
                    ));
                }
            }
            ["server", "port"] => {
                if let Some(port) = value.as_u64() {
                    self.config.server.port = port as u16;
                } else {
                    return Err(ConfigError::Validation(
                        "Server port must be a number".to_string(),
                    ));
                }
            }
            ["database", "host"] => {
                if let Some(host) = value.as_str() {
                    self.config.database.host = host.to_string();
                } else {
                    return Err(ConfigError::Validation(
                        "Database host must be a string".to_string(),
                    ));
                }
            }
            ["database", "port"] => {
                if let Some(port) = value.as_u64() {
                    self.config.database.port = port as u16;
                } else {
                    return Err(ConfigError::Validation(
                        "Database port must be a number".to_string(),
                    ));
                }
            }
            ["features", feature] => {
                if let Some(feature_value) = value.as_bool() {
                    self.config
                        .features
                        .insert(feature.to_string(), feature_value);
                } else {
                    return Err(ConfigError::Validation(
                        "Feature value must be boolean".to_string(),
                    ));
                }
            }
            ["custom", custom_key] => {
                self.config.custom.insert(custom_key.to_string(), value);
            }
            _ => {
                return Err(ConfigError::Validation(format!(
                    "Unknown configuration key: {}",
                    key
                )));
            }
        }

        self.validate_config()?;
        self.notify_watchers()?;

        Ok(())
    }

    /// Add environment configuration
    pub fn add_environment(&mut self, name: String, env_config: EnvironmentConfig) {
        self.environments.insert(name, env_config);
    }

    /// Switch to specific environment
    pub fn switch_environment(&mut self, env_name: &str) -> Result<(), ConfigError> {
        let overrides = if let Some(env_config) = self.environments.get(env_name) {
            env_config.overrides.clone()
        } else {
            return Err(ConfigError::Validation(format!(
                "Environment not found: {}",
                env_name
            )));
        };

        // Apply environment overrides
        for (key, value) in &overrides {
            self.set_value(key, value.clone())?;
        }

        self.config.environment = env_name.to_string();
        self.notify_watchers()?;

        Ok(())
    }

    /// Add configuration watcher
    pub fn add_watcher(&mut self, watcher: Box<dyn ConfigWatcher>) {
        self.watchers.push(watcher);
    }

    /// Notify all watchers of configuration changes
    fn notify_watchers(&self) -> Result<(), ConfigError> {
        for watcher in &self.watchers {
            watcher.on_config_changed(&self.config)?;
        }
        Ok(())
    }

    /// Save current configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = match self.format {
            ConfigFormat::Json => serde_json::to_string_pretty(&self.config)?,
            ConfigFormat::Toml => toml::to_string(&self.config)
                .map_err(|e| ConfigError::InvalidFormat(e.to_string()))?,
            ConfigFormat::Yaml => serde_yaml::to_string(&self.config)
                .map_err(|e| ConfigError::InvalidFormat(e.to_string()))?,
            ConfigFormat::Environment => {
                return Err(ConfigError::InvalidFormat(
                    "Cannot save environment config to file".to_string(),
                ));
            }
        };

        fs::write(path, content)?;
        Ok(())
    }

    /// Reload configuration from file
    pub fn reload(&mut self) -> Result<(), ConfigError> {
        let config_path = self.config_path.clone();
        if config_path.exists() {
            self.load_from_file(&config_path)?;
            self.notify_watchers()?;
        }
        Ok(())
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            environment: "development".to_string(),
            debug: true,
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: 4,
                max_connections: 1000,
                timeout: 30,
                tls_cert: None,
                tls_key: None,
            },
            database: DatabaseConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "authframework".to_string(),
                username: "postgres".to_string(),
                password: "password".to_string(),
                ssl_mode: "prefer".to_string(),
                pool_size: 10,
                timeout: 30,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output: vec!["stdout".to_string()],
                rotation: Some(LogRotationConfig {
                    size: "10MB".to_string(),
                    keep: 7,
                    compress: true,
                }),
                structured: true,
            },
            security: SecurityConfig {
                jwt_secret: "your-super-secret-jwt-key-change-this-in-production".to_string(),
                session_timeout: 3600,
                bcrypt_cost: 12,
                rate_limiting: RateLimitConfig {
                    enabled: true,
                    requests_per_minute: 100,
                    burst_size: 20,
                    whitelist: vec!["127.0.0.1".to_string()],
                },
                cors: CorsConfig {
                    enabled: true,
                    allowed_origins: vec!["*".to_string()],
                    allowed_methods: vec![
                        "GET".to_string(),
                        "POST".to_string(),
                        "PUT".to_string(),
                        "DELETE".to_string(),
                    ],
                    allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
                    max_age: 3600,
                },
            },
            features: HashMap::new(),
            custom: HashMap::new(),
        }
    }
}

/// Simple configuration watcher implementation
pub struct SimpleConfigWatcher {
    name: String,
}

impl SimpleConfigWatcher {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl ConfigWatcher for SimpleConfigWatcher {
    fn on_config_changed(&self, _config: &AppConfig) -> Result<(), ConfigError> {
        println!("Configuration changed for watcher: {}", self.name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::write;
    use tempfile::tempdir;

    #[test]
    fn test_config_manager_creation() {
        let manager = ConfigManager::new();
        assert_eq!(manager.config.environment, "development");
    }

    #[test]
    fn test_load_from_env() {
        unsafe {
            std::env::set_var("SERVER_HOST", "0.0.0.0");
            std::env::set_var("SERVER_PORT", "9090");
        }

        let mut manager = ConfigManager::new();
        let result = manager.load_from_env();

        assert!(result.is_ok());
        assert_eq!(manager.config.server.host, "0.0.0.0");
        assert_eq!(manager.config.server.port, 9090);

        unsafe {
            std::env::remove_var("SERVER_HOST");
            std::env::remove_var("SERVER_PORT");
        }
    }

    #[test]
    fn test_load_from_toml_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("config.toml");

        let toml_content = r#"
environment = "test"
debug = false

[server]
host = "0.0.0.0"
port = 9000
workers = 8
max_connections = 2000
timeout = 60

[database]
host = "db.example.com"
port = 5432
database = "test_db"
username = "test_user"
password = "test_pass"
ssl_mode = "require"
pool_size = 20
timeout = 60

[logging]
level = "debug"
format = "text"
output = ["stdout", "file"]
structured = false

[security]
jwt_secret = "test-secret-key-that-is-long-enough-for-validation"
session_timeout = 7200
bcrypt_cost = 10

[security.rate_limiting]
enabled = true
requests_per_minute = 200
burst_size = 40
whitelist = ["192.168.1.1"]

[security.cors]
enabled = true
allowed_origins = ["https://example.com"]
allowed_methods = ["GET", "POST"]
allowed_headers = ["Content-Type"]
max_age = 1800

[features]
# Add some example features
mfa = true
oauth = false

[custom]
# Custom configuration values
app_version = "1.0.0"
        "#;

        write(&file_path, toml_content).unwrap();

        let mut manager = ConfigManager::new();
        let result = manager.load_from_file(&file_path);

        if let Err(ref e) = result {
            eprintln!("Config load error: {:?}", e);
        }
        assert!(
            result.is_ok(),
            "Failed to load config: {:?}",
            result.unwrap_err()
        );
        assert_eq!(manager.config.environment, "test");
        assert_eq!(manager.config.server.host, "0.0.0.0");
        assert_eq!(manager.config.server.port, 9000);
        assert_eq!(manager.config.database.host, "db.example.com");
        assert_eq!(manager.config.security.bcrypt_cost, 10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = AppConfig::default();
        config.security.jwt_secret = "short".to_string(); // Too short

        let manager = ConfigManager {
            config,
            config_path: PathBuf::new(),
            format: ConfigFormat::Toml,
            environments: HashMap::new(),
            watchers: Vec::new(),
        };

        let result = manager.validate_config();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::Validation(_)));
    }

    #[test]
    fn test_set_value() {
        let mut manager = ConfigManager::new();

        let result = manager.set_value(
            "server.port",
            serde_json::Value::Number(serde_json::Number::from(9999)),
        );
        assert!(result.is_ok());
        assert_eq!(manager.config.server.port, 9999);
    }

    #[test]
    fn test_config_watcher() {
        let mut manager = ConfigManager::new();
        let watcher = Box::new(SimpleConfigWatcher::new("test".to_string()));
        manager.add_watcher(watcher);

        let result = manager.set_value(
            "server.port",
            serde_json::Value::Number(serde_json::Number::from(8888)),
        );
        assert!(result.is_ok());
    }
}
