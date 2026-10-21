//! Common Configuration Framework
//!
//! This module provides shared configuration patterns and utilities
//! to eliminate duplication across server modules.

use crate::errors::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Base configuration trait that all server configs must implement.
pub trait ServerConfig {
    /// Validate the configuration.
    ///
    /// Implementors **must** override this method to perform meaningful validation.
    /// The default returns `Ok(())` only for backward compatibility with existing
    /// implementors; new types should always provide a real check.
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// Get configuration name for logging/debugging
    fn config_name(&self) -> &'static str;

    /// Check if configuration is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Common timeout configuration used across modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// Common security configuration patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TLS
    pub enable_tls: bool,
    /// Minimum TLS version
    pub min_tls_version: String,
    /// Allowed cipher suites
    pub cipher_suites: Vec<String>,
    /// Certificate validation mode
    pub cert_validation: CertificateValidation,
    /// Whether to verify certificates (legacy compatibility)
    pub verify_certificates: bool,
    /// Accept invalid TLS certificates on outbound connections.
    /// Default: `false`. Only enable for development/testing — never in production.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_tls: true,
            min_tls_version: "1.2".to_string(),
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
            cert_validation: CertificateValidation::Full,
            verify_certificates: true,
            accept_invalid_certs: false,
        }
    }
}

/// Certificate validation modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateValidation {
    /// Full certificate chain validation
    Full,
    /// Skip hostname verification
    SkipHostname,
    /// Skip all certificate validation (insecure)
    None,
}

/// Common endpoint configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Base URL
    pub base_url: String,
    /// API version
    pub api_version: Option<String>,
    /// Custom headers
    pub headers: HashMap<String, String>,
    /// Timeout configuration
    pub timeout: TimeoutConfig,
    /// Security configuration
    pub security: SecurityConfig,
}

impl std::fmt::Debug for EndpointConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("EndpointConfig");
        d.field("base_url", &self.base_url);
        d.field("api_version", &self.api_version);
        d.field("headers", &crate::utils::redact::redacted(&self.headers));
        d.field("timeout", &self.timeout);
        d.field("security", &self.security);
        d.finish()
    }
}

impl EndpointConfig {
    /// Create a new endpoint config with defaults
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_version: None,
            headers: HashMap::new(),
            timeout: TimeoutConfig::default(),
            security: SecurityConfig::default(),
        }
    }

    /// Add a custom header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set API version
    pub fn with_api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = Some(version.into());
        self
    }
}

/// Common retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 to 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

/// Common logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Enable debug logging
    pub debug: bool,
    /// Log request/response bodies
    pub log_bodies: bool,
    /// Log sensitive fields (tokens, keys)
    pub log_sensitive: bool,
    /// Maximum log message size
    pub max_log_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            debug: false,
            log_bodies: false,
            log_sensitive: false,
            max_log_size: 4096,
        }
    }
}

/// Configuration validation utilities
pub mod validation {
    use super::*;

    /// Validate URL format
    pub fn validate_url(url: &str) -> Result<()> {
        if url.is_empty() {
            return Err(crate::errors::AuthError::config(
                "URL cannot be empty".to_string(),
            ));
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(crate::errors::AuthError::config(format!(
                "Invalid URL format: {}",
                url
            )));
        }

        Ok(())
    }

    /// Validate duration is positive
    pub fn validate_positive_duration(duration: &Duration, field_name: &str) -> Result<()> {
        if duration.is_zero() {
            return Err(crate::errors::AuthError::config(format!(
                "{} must be greater than zero",
                field_name
            )));
        }
        Ok(())
    }

    /// Validate port number
    pub fn validate_port(port: u16) -> Result<()> {
        if port == 0 {
            return Err(crate::errors::AuthError::config(
                "Port cannot be zero".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate required field is not empty
    pub fn validate_required_field(value: &str, field_name: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(crate::errors::AuthError::config(format!(
                "{} is required and cannot be empty",
                field_name
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_config_default() {
        let tc = TimeoutConfig::default();
        assert_eq!(tc.connect_timeout, Duration::from_secs(30));
        assert_eq!(tc.read_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_security_config_default() {
        let sc = SecurityConfig::default();
        assert!(sc.enable_tls);
        assert!(sc.verify_certificates);
    }

    #[test]
    fn test_retry_config_default() {
        let rc = RetryConfig::default();
        assert!(rc.max_attempts > 0);
    }

    #[test]
    fn test_logging_config_default() {
        let lc = LoggingConfig::default();
        assert!(!lc.debug);
        assert!(!lc.log_bodies);
        assert!(!lc.log_sensitive);
        assert!(lc.max_log_size > 0);
    }

    #[test]
    fn test_endpoint_config_new() {
        let ec = EndpointConfig::new("https://api.example.com");
        assert_eq!(ec.base_url, "https://api.example.com");
        assert!(ec.api_version.is_none());
    }

    #[test]
    fn test_endpoint_config_with_header() {
        let ec = EndpointConfig::new("https://api.example.com")
            .with_header("Authorization", "Bearer xxx");
        assert_eq!(ec.headers.get("Authorization").unwrap(), "Bearer xxx");
    }

    #[test]
    fn test_endpoint_config_with_api_version() {
        let ec = EndpointConfig::new("https://api.example.com").with_api_version("2024-01-01");
        assert_eq!(ec.api_version.as_deref(), Some("2024-01-01"));
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validation::validate_url("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_empty() {
        assert!(validation::validate_url("").is_err());
    }

    #[test]
    fn test_validate_url_no_scheme() {
        assert!(validation::validate_url("example.com").is_err());
    }

    #[test]
    fn test_validate_positive_duration() {
        assert!(validation::validate_positive_duration(&Duration::from_secs(1), "timeout").is_ok());
    }

    #[test]
    fn test_validate_zero_duration() {
        assert!(validation::validate_positive_duration(&Duration::ZERO, "timeout").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validation::validate_port(8080).is_ok());
        assert!(validation::validate_port(0).is_err());
    }

    #[test]
    fn test_validate_required_field() {
        assert!(validation::validate_required_field("value", "name").is_ok());
        assert!(validation::validate_required_field("", "name").is_err());
        assert!(validation::validate_required_field("  ", "name").is_err());
    }

    #[test]
    fn test_security_config_accept_invalid_certs_defaults_false() {
        let sc = SecurityConfig::default();
        assert!(
            !sc.accept_invalid_certs,
            "accept_invalid_certs must default to false"
        );
    }

    #[test]
    fn test_security_config_accept_invalid_certs_deserialization_default() {
        // A JSON object missing accept_invalid_certs should deserialize to false
        let json = r#"{"enable_tls":true,"min_tls_version":"1.2","cipher_suites":[],"cert_validation":"Full","verify_certificates":true}"#;
        let sc: SecurityConfig = serde_json::from_str(json).unwrap();
        assert!(!sc.accept_invalid_certs);
    }
}
