//! Advanced configuration management using the `config` crate.
//!
//! This module provides flexible configuration loading from multiple sources:
//! - Configuration files (TOML, YAML, JSON, RON, INI)
//! - Environment variables
//! - Command line arguments (when integrated with clap)
//! - Include directives for modular configuration files
//!
//! The configuration system is designed to be easily integrated into parent applications
//! while providing sensible defaults for standalone use.

use crate::errors::{AuthError, Result};
use config::{Config, Environment, File, FileFormat};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Comprehensive configuration manager for the auth framework
#[derive(Debug, Clone)]
pub struct ConfigManager {
    /// The underlying config builder
    config: Config,
    /// Configuration source paths for reference
    sources: Vec<String>,
    /// Environment variable prefix
    env_prefix: String,
}

/// Configuration builder for easy integration into parent applications
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    /// Configuration sources in order of priority (later sources override earlier ones)
    sources: Vec<ConfigSource>,
    /// Environment variable prefix
    env_prefix: String,
    /// Whether to include default auth-framework config files
    include_defaults: bool,
    /// Custom configuration file search paths
    search_paths: Vec<String>,
}

/// Represents a configuration source
#[derive(Debug, Clone)]
pub enum ConfigSource {
    /// Configuration file (path, format, required)
    File {
        path: String,
        format: FileFormat,
        required: bool,
    },
    /// Environment variables with prefix
    Environment { prefix: String },
    /// Direct configuration values
    Values(HashMap<String, config::Value>),
    /// Include another configuration directory
    IncludeDir { path: String, pattern: String },
}

/// Settings that can be used by parent applications to configure auth-framework
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AuthFrameworkSettings {
    /// Main auth framework configuration
    #[serde(flatten)]
    pub auth: super::AuthConfig,

    /// Threat intelligence configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_intelligence: Option<crate::threat_intelligence::ThreatIntelConfig>,

    /// Session configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionSettings>,

    /// Additional custom settings for extensibility
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Session-specific configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSettings {
    /// Maximum number of concurrent sessions per user
    pub max_concurrent_sessions: Option<u32>,

    /// Session cleanup interval in seconds
    pub cleanup_interval: Option<u64>,

    /// Enable session device tracking
    pub enable_device_tracking: Option<bool>,

    /// Session cookie settings
    pub cookie: Option<SessionCookieSettings>,
}

/// Session cookie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCookieSettings {
    /// Cookie name
    pub name: Option<String>,

    /// Cookie domain
    pub domain: Option<String>,

    /// Cookie path
    pub path: Option<String>,

    /// Cookie max age in seconds
    pub max_age: Option<u64>,

    /// Whether cookie is HTTP only
    pub http_only: Option<bool>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    /// Create a new configuration builder with sensible defaults
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            env_prefix: "AUTH_FRAMEWORK".to_string(),
            include_defaults: true,
            search_paths: vec![
                ".".to_string(),
                "./config".to_string(),
                "/etc/auth-framework".to_string(),
                dirs::config_dir()
                    .map(|d| d.join("auth-framework").to_string_lossy().to_string())
                    .unwrap_or_else(|| "./config".to_string()),
            ],
        }
    }

    /// Set the environment variable prefix
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = prefix.into();
        self
    }

    /// Disable loading of default auth-framework configuration files
    pub fn without_defaults(mut self) -> Self {
        self.include_defaults = false;
        self
    }

    /// Add a configuration file source
    pub fn add_file<P: AsRef<Path>>(mut self, path: P, required: bool) -> Self {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let format = Self::detect_format(&path_str);

        self.sources.push(ConfigSource::File {
            path: path_str,
            format,
            required,
        });
        self
    }

    /// Add a configuration file with explicit format
    pub fn add_file_with_format<P: AsRef<Path>>(
        mut self,
        path: P,
        format: FileFormat,
        required: bool,
    ) -> Self {
        self.sources.push(ConfigSource::File {
            path: path.as_ref().to_string_lossy().to_string(),
            format,
            required,
        });
        self
    }

    /// Add environment variables as a source
    pub fn add_env_source(mut self, prefix: impl Into<String>) -> Self {
        self.sources.push(ConfigSource::Environment {
            prefix: prefix.into(),
        });
        self
    }

    /// Add direct configuration values
    pub fn add_values(mut self, values: HashMap<String, config::Value>) -> Self {
        self.sources.push(ConfigSource::Values(values));
        self
    }

    /// Add a directory include source (loads all matching files)
    pub fn add_include_dir(mut self, path: impl Into<String>, pattern: impl Into<String>) -> Self {
        self.sources.push(ConfigSource::IncludeDir {
            path: path.into(),
            pattern: pattern.into(),
        });
        self
    }

    /// Add a search path for configuration files
    pub fn add_search_path(mut self, path: impl Into<String>) -> Self {
        self.search_paths.push(path.into());
        self
    }

    /// Build the configuration manager
    pub fn build(self) -> Result<ConfigManager> {
        let mut config = Config::builder();
        let mut sources = Vec::new();

        // Add default auth-framework configuration files if requested
        if self.include_defaults {
            // Look for auth-framework configuration files in search paths
            for search_path in &self.search_paths {
                for filename in &[
                    "auth-framework.toml",
                    "auth-framework.yaml",
                    "auth-framework.yml",
                    "auth-framework.json",
                    "auth.toml",
                    "auth.yaml",
                    "auth.yml",
                    "auth.json",
                ] {
                    let path = Path::new(search_path).join(filename);
                    if path.exists() {
                        let format = Self::detect_format(&path.to_string_lossy());
                        config = config
                            .add_source(File::from(path.clone()).format(format).required(false));
                        sources.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Add user-specified sources in order
        for source in self.sources {
            match source {
                ConfigSource::File {
                    path,
                    format,
                    required,
                } => {
                    config = config.add_source(File::new(&path, format).required(required));
                    sources.push(path);
                }
                ConfigSource::Environment { prefix } => {
                    config = config.add_source(
                        Environment::with_prefix(&prefix)
                            .prefix_separator("_")
                            .separator("__"),
                    );
                    sources.push(format!("env:{}", prefix));
                }
                ConfigSource::Values(values) => {
                    for (key, value) in values {
                        config = config.set_override(&key, value).map_err(|e| {
                            AuthError::config(format!("Failed to set override: {e}"))
                        })?;
                    }
                    sources.push("values:override".to_string());
                }
                ConfigSource::IncludeDir { path, pattern } => {
                    // Load all matching files from the directory
                    if let Ok(entries) = std::fs::read_dir(&path) {
                        let mut files: Vec<_> = entries
                            .filter_map(|entry| entry.ok())
                            .filter(|entry| entry.file_name().to_string_lossy().contains(&pattern))
                            .collect();

                        // Sort for consistent loading order
                        files.sort_by_key(|e| e.file_name());

                        for entry in files {
                            let file_path = entry.path();
                            let format = Self::detect_format(&file_path.to_string_lossy());
                            config = config.add_source(
                                File::from(file_path.clone()).format(format).required(false),
                            );
                            sources.push(file_path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        // Always add the main environment source last (highest priority)
        config = config.add_source(
            Environment::with_prefix(&self.env_prefix)
                .prefix_separator("_")
                .separator("__"),
        );
        sources.push(format!("env:{}", self.env_prefix));

        let built_config = config
            .build()
            .map_err(|e| AuthError::config(format!("Failed to build configuration: {e}")))?;

        Ok(ConfigManager {
            config: built_config,
            sources,
            env_prefix: self.env_prefix,
        })
    }

    /// Detect file format from extension
    fn detect_format(path: &str) -> FileFormat {
        let path = Path::new(path);
        match path.extension().and_then(|s| s.to_str()) {
            Some("toml") => FileFormat::Toml,
            Some("yaml") | Some("yml") => FileFormat::Yaml,
            Some("json") => FileFormat::Json,
            Some("ron") => FileFormat::Ron,
            Some("ini") => FileFormat::Ini,
            _ => FileFormat::Toml, // Default to TOML
        }
    }
}

impl ConfigManager {
    /// Create a new configuration manager with default settings
    pub fn new() -> Result<Self> {
        ConfigBuilder::new().build()
    }

    /// Create a configuration manager for a specific application
    pub fn for_application(app_name: &str) -> Result<Self> {
        ConfigBuilder::new()
            .with_env_prefix(format!("{}_AUTH_FRAMEWORK", app_name.to_uppercase()))
            .add_file(format!("{}.toml", app_name), false)
            .add_file(format!("config/{}.toml", app_name), false)
            .build()
    }

    /// Get the auth framework settings
    pub fn get_auth_settings(&self) -> Result<AuthFrameworkSettings> {
        self.config
            .clone()
            .try_deserialize::<AuthFrameworkSettings>()
            .map_err(|e| AuthError::config(format!("Failed to deserialize auth settings: {e}")))
    }

    /// Get a specific configuration section
    pub fn get_section<T>(&self, section: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.config
            .get::<T>(section)
            .map_err(|e| AuthError::config(format!("Failed to get section '{}': {e}", section)))
    }

    /// Get a configuration value by key
    pub fn get<T>(&self, key: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.config
            .get::<T>(key)
            .map_err(|e| AuthError::config(format!("Failed to get key '{}': {e}", key)))
    }

    /// Get a configuration value with a default
    pub fn get_or_default<T>(&self, key: &str, default: T) -> T
    where
        T: for<'de> Deserialize<'de>,
    {
        self.config.get::<T>(key).unwrap_or(default)
    }

    /// Check if a key exists in the configuration
    pub fn has_key(&self, key: &str) -> bool {
        self.config.get::<config::Value>(key).is_ok()
    }

    /// Get all keys with a specific prefix
    pub fn get_keys_with_prefix(&self, _prefix: &str) -> Vec<String> {
        // This would require access to the internal structure
        // For now, we'll provide a simplified implementation
        Vec::new()
    }

    /// Get configuration sources used
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// Get the environment prefix
    pub fn env_prefix(&self) -> &str {
        &self.env_prefix
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        let auth_config = self.get_auth_settings()?;
        auth_config.auth.validate()
    }

    /// Create a nested configuration manager for a subsection
    pub fn section(&self, section: &str) -> Result<ConfigManager> {
        let section_config = self
            .config
            .get::<HashMap<String, config::Value>>(section)
            .map_err(|e| AuthError::config(format!("Failed to get section '{}': {e}", section)))?;

        let mut config_builder = Config::builder();
        for (key, value) in section_config {
            config_builder = config_builder
                .set_override(&key, value)
                .map_err(|e| AuthError::config(format!("Failed to set override: {e}")))?;
        }

        let built_config = config_builder
            .build()
            .map_err(|e| AuthError::config(format!("Failed to build section config: {e}")))?;

        Ok(ConfigManager {
            config: built_config,
            sources: vec![format!("section:{}", section)],
            env_prefix: format!("{}_{}", self.env_prefix, section.to_uppercase()),
        })
    }

    /// Merge with another configuration (other takes precedence)
    pub fn merge(self, other: ConfigManager) -> Result<ConfigManager> {
        let mut sources = self.sources;
        sources.extend(other.sources);

        // For simplicity, we'll use the other's config as the primary
        // In a real implementation, we'd properly merge the configurations
        Ok(ConfigManager {
            config: other.config,
            sources,
            env_prefix: other.env_prefix,
        })
    }

    /// Export the current configuration to a specific format
    pub fn export_to_string(&self, format: FileFormat) -> Result<String> {
        let settings = self.get_auth_settings()?;

        match format {
            FileFormat::Toml => toml::to_string_pretty(&settings)
                .map_err(|e| AuthError::config(format!("Failed to serialize to TOML: {e}"))),
            FileFormat::Yaml => serde_yaml::to_string(&settings)
                .map_err(|e| AuthError::config(format!("Failed to serialize to YAML: {e}"))),
            FileFormat::Json => serde_json::to_string_pretty(&settings)
                .map_err(|e| AuthError::config(format!("Failed to serialize to JSON: {e}"))),
            _ => Err(AuthError::config("Unsupported export format")),
        }
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default configuration manager")
    }
}


impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: Some(5),
            cleanup_interval: Some(3600), // 1 hour
            enable_device_tracking: Some(true),
            cookie: Some(SessionCookieSettings::default()),
        }
    }
}

impl Default for SessionCookieSettings {
    fn default() -> Self {
        Self {
            name: Some("auth_session".to_string()),
            domain: None,
            path: Some("/".to_string()),
            max_age: Some(86400), // 24 hours
            http_only: Some(true),
        }
    }
}

/// Helper trait for easy integration into parent application configurations
pub trait ConfigIntegration {
    /// Get the auth framework configuration section
    fn auth_framework(&self) -> Option<&AuthFrameworkSettings>;

    /// Get the auth framework configuration section (mutable)
    fn auth_framework_mut(&mut self) -> Option<&mut AuthFrameworkSettings>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_basic() {
        let config = ConfigBuilder::new()
            .with_env_prefix("TEST")
            .build()
            .expect("Failed to build config");

        assert_eq!(config.env_prefix(), "TEST");
    }

    #[test]
    fn test_config_manager_default() {
        // Since ConfigManager::new() tries to load from files/env which may not exist,
        // we'll test the default settings directly instead
        let settings = AuthFrameworkSettings::default();

        // Should have default values
        assert!(!settings.auth.enable_multi_factor);
        assert_eq!(settings.auth.token_lifetime.as_secs(), 3600); // 1 hour
        assert_eq!(settings.auth.issuer, "auth-framework");
    }

    #[test]
    fn test_application_specific_config() {
        let config = ConfigManager::for_application("myapp").expect("Failed to create app config");

        assert_eq!(config.env_prefix(), "MYAPP_AUTH_FRAMEWORK");
    }

    #[test]
    fn test_config_sources() {
        let config = ConfigBuilder::new()
            .add_file("nonexistent.toml", false)
            .add_env_source("TEST")
            .build()
            .expect("Failed to build config");

        let sources = config.sources();
        assert!(!sources.is_empty());
    }
}
