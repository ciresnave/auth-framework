//! Security presets for the Auth Framework
//!
//! This module provides pre-configured security levels that automatically
//! apply appropriate security settings for different environments and use cases.
//!
//! # Security Presets
//!
//! - **Development**: Convenient settings for development environments
//! - **Balanced**: Good security with reasonable performance (default)
//! - **HighSecurity**: Strong security for sensitive applications
//! - **Paranoid**: Maximum security settings for high-risk environments
//!
//! # Usage
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! // Quick setup with security preset
//! let auth = AuthFramework::quick_start()
//!     .jwt_auth_from_env()
//!     .security_level(SecurityPreset::HighSecurity)
//!     .build().await?;
//!
//! // Or apply to existing configuration
//! let config = AuthConfig::new()
//!     .security(SecurityPreset::Paranoid.to_config());
//! ```
//!
//! # Security Validation
//!
//! Each preset includes built-in validation to ensure security requirements
//! are met for the target environment:
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//!
//! // Validate security configuration
//! let issues = SecurityPreset::HighSecurity
//!     .validate_environment()
//!     .await?;
//!
//! for issue in issues {
//!     println!("⚠️  {}: {}", issue.severity, issue.description);
//!     println!("💡 Fix: {}", issue.suggestion);
//! }
//! ```

use crate::{
    config::{
        AuditConfig, AuditStorage, CookieSameSite, JwtAlgorithm, PasswordHashAlgorithm,
        RateLimitConfig, SecurityConfig,
    },
    prelude::{AuthFrameworkResult, hours, minutes},
};
use std::time::Duration;

/// Security presets for common configurations
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityPreset {
    /// Development-friendly settings (lower security, more convenient)
    ///
    /// **USE ONLY FOR DEVELOPMENT - NOT PRODUCTION SAFE**
    ///
    /// - Shorter passwords allowed (6+ chars)
    /// - Weaker password requirements
    /// - Less strict cookie settings
    /// - Disabled CSRF protection for easier testing
    /// - Longer session timeouts for convenience
    Development,

    /// Balanced settings for most applications
    ///
    /// Good balance of security and usability suitable for most production
    /// applications that don't handle highly sensitive data.
    ///
    /// - Standard password requirements (8+ chars)
    /// - Secure cookies and CSRF protection
    /// - Reasonable rate limiting
    /// - Basic audit logging
    Balanced,

    /// High security settings for sensitive applications
    ///
    /// Strong security settings suitable for applications handling
    /// sensitive data like financial information, healthcare records,
    /// or personal data subject to compliance requirements.
    ///
    /// - Strict password requirements (12+ chars, complexity)
    /// - Strong JWT algorithms (RSA-256)
    /// - Aggressive rate limiting
    /// - Comprehensive audit logging
    /// - Short session timeouts
    HighSecurity,

    /// Maximum security (paranoid mode)
    ///
    /// Extremely strict security settings for high-risk environments
    /// where security is paramount over convenience.
    ///
    /// - Very strict password requirements (16+ chars)
    /// - Strongest cryptographic algorithms
    /// - Very aggressive rate limiting
    /// - Extensive audit logging and monitoring
    /// - Very short session timeouts
    /// - Constant-time operations
    Paranoid,
}

/// Security validation issue
#[derive(Debug, Clone)]
pub struct SecurityIssue {
    /// Severity level of the issue
    pub severity: SecuritySeverity,
    /// Component that has the issue
    pub component: String,
    /// Description of the security issue
    pub description: String,
    /// Suggested fix for the issue
    pub suggestion: String,
    /// Whether this issue blocks production deployment
    pub blocks_production: bool,
}

/// Security issue severity levels
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum SecuritySeverity {
    /// Information about security configuration
    Info,
    /// Security recommendation that should be addressed
    Warning,
    /// Security issue that should be fixed
    Error,
    /// Critical security issue that must be fixed
    Critical,
}

impl SecurityPreset {
    /// Convert the security preset to a SecurityConfig
    pub fn to_config(&self) -> SecurityConfig {
        match self {
            SecurityPreset::Development => SecurityConfig {
                min_password_length: 6,
                require_password_complexity: false,
                password_hash_algorithm: PasswordHashAlgorithm::Bcrypt, // Faster for development
                jwt_algorithm: JwtAlgorithm::HS256,
                secret_key: None,      // Must be set externally
                secure_cookies: false, // Allow HTTP for local development
                cookie_same_site: CookieSameSite::Lax,
                csrf_protection: false,     // Easier API testing
                session_timeout: hours(24), // Long timeout for development convenience
            },
            SecurityPreset::Balanced => SecurityConfig {
                min_password_length: 8,
                require_password_complexity: true,
                password_hash_algorithm: PasswordHashAlgorithm::Argon2,
                jwt_algorithm: JwtAlgorithm::HS256,
                secret_key: None,
                secure_cookies: true,
                cookie_same_site: CookieSameSite::Lax,
                csrf_protection: true,
                session_timeout: hours(8),
            },
            SecurityPreset::HighSecurity => SecurityConfig {
                min_password_length: 12,
                require_password_complexity: true,
                password_hash_algorithm: PasswordHashAlgorithm::Argon2,
                jwt_algorithm: JwtAlgorithm::RS256, // RSA for better security
                secret_key: None,
                secure_cookies: true,
                cookie_same_site: CookieSameSite::Strict,
                csrf_protection: true,
                session_timeout: hours(2), // Shorter sessions
            },
            SecurityPreset::Paranoid => SecurityConfig {
                min_password_length: 16,
                require_password_complexity: true,
                password_hash_algorithm: PasswordHashAlgorithm::Argon2,
                jwt_algorithm: JwtAlgorithm::RS512, // Strongest RSA
                secret_key: None,
                secure_cookies: true,
                cookie_same_site: CookieSameSite::Strict,
                csrf_protection: true,
                session_timeout: minutes(30), // Very short sessions
            },
        }
    }

    /// Get rate limiting configuration for this security preset
    pub fn to_rate_limit_config(&self) -> RateLimitConfig {
        match self {
            SecurityPreset::Development => RateLimitConfig {
                enabled: false, // Disabled for easier development
                max_requests: 1000,
                window: Duration::from_secs(60),
                burst: 100,
            },
            SecurityPreset::Balanced => RateLimitConfig {
                enabled: true,
                max_requests: 100,
                window: Duration::from_secs(60),
                burst: 20,
            },
            SecurityPreset::HighSecurity => RateLimitConfig {
                enabled: true,
                max_requests: 60, // 1 per second average
                window: Duration::from_secs(60),
                burst: 10,
            },
            SecurityPreset::Paranoid => RateLimitConfig {
                enabled: true,
                max_requests: 30, // 0.5 per second average
                window: Duration::from_secs(60),
                burst: 5,
            },
        }
    }

    /// Get audit configuration for this security preset
    pub fn to_audit_config(&self) -> AuditConfig {
        match self {
            SecurityPreset::Development => AuditConfig {
                enabled: false, // Disabled for cleaner development logs
                log_success: false,
                log_failures: true, // Still log failures for debugging
                log_permissions: false,
                log_tokens: false,
                storage: AuditStorage::Tracing,
            },
            SecurityPreset::Balanced => AuditConfig {
                enabled: true,
                log_success: false, // Don't log every success to reduce noise
                log_failures: true,
                log_permissions: true,
                log_tokens: false, // Tokens can be sensitive
                storage: AuditStorage::Tracing,
            },
            SecurityPreset::HighSecurity => AuditConfig {
                enabled: true,
                log_success: true,
                log_failures: true,
                log_permissions: true,
                log_tokens: false,
                storage: AuditStorage::Tracing, // Should be database in real deployment
            },
            SecurityPreset::Paranoid => AuditConfig {
                enabled: true,
                log_success: true,
                log_failures: true,
                log_permissions: true,
                log_tokens: true,               // Log everything in paranoid mode
                storage: AuditStorage::Tracing, // Should be secure external service
            },
        }
    }

    /// Validate the current environment against this security preset
    pub async fn validate_environment(&self) -> AuthFrameworkResult<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        // Check environment type
        let is_production = self.is_production_environment();
        let is_development = self.is_development_environment();

        // Validate preset appropriateness for environment
        match (self, is_production, is_development) {
            (SecurityPreset::Development, true, false) => {
                issues.push(SecurityIssue {
                    severity: SecuritySeverity::Critical,
                    component: "Security Preset".to_string(),
                    description: "Development security preset used in production environment".to_string(),
                    suggestion: "Use SecurityPreset::HighSecurity or SecurityPreset::Paranoid for production".to_string(),
                    blocks_production: true,
                });
            }
            (SecurityPreset::Balanced, true, false) => {
                issues.push(SecurityIssue {
                    severity: SecuritySeverity::Warning,
                    component: "Security Preset".to_string(),
                    description:
                        "Balanced security preset in production - consider higher security"
                            .to_string(),
                    suggestion: "Consider SecurityPreset::HighSecurity for better protection"
                        .to_string(),
                    blocks_production: false,
                });
            }
            _ => {} // Other combinations are acceptable
        }

        // Check JWT secret
        self.validate_jwt_secret(&mut issues);

        // Check HTTPS in production
        if is_production && self.requires_secure_cookies() {
            self.validate_https_requirement(&mut issues);
        }

        // Check database configuration
        self.validate_storage_security(&mut issues);

        // Check environment variables
        self.validate_environment_variables(&mut issues);

        Ok(issues)
    }

    /// Perform a security audit of the current configuration
    pub async fn security_audit(&self) -> AuthFrameworkResult<SecurityAuditReport> {
        let issues = self.validate_environment().await?;

        let critical_count = issues
            .iter()
            .filter(|i| i.severity == SecuritySeverity::Critical)
            .count();
        let error_count = issues
            .iter()
            .filter(|i| i.severity == SecuritySeverity::Error)
            .count();
        let warning_count = issues
            .iter()
            .filter(|i| i.severity == SecuritySeverity::Warning)
            .count();

        let overall_status = if critical_count > 0 {
            SecurityAuditStatus::Critical
        } else if error_count > 0 {
            SecurityAuditStatus::Failed
        } else if warning_count > 0 {
            SecurityAuditStatus::Warning
        } else {
            SecurityAuditStatus::Passed
        };

        Ok(SecurityAuditReport {
            preset: self.clone(),
            status: overall_status,
            issues,
            critical_count,
            error_count,
            warning_count,
            recommendations: self.get_security_recommendations(),
        })
    }

    /// Get security recommendations for this preset
    pub fn get_security_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        match self {
            SecurityPreset::Development => {
                recommendations.push(
                    "⚠️  Development preset detected - ensure this is not used in production"
                        .to_string(),
                );
                recommendations
                    .push("🔐 Set JWT_SECRET environment variable with a secure value".to_string());
                recommendations
                    .push("📝 Enable audit logging when moving to production".to_string());
            }
            SecurityPreset::Balanced => {
                recommendations.push(
                    "🔒 Consider upgrading to HighSecurity for sensitive applications".to_string(),
                );
                recommendations
                    .push("📊 Monitor authentication patterns for suspicious activity".to_string());
                recommendations.push("🔄 Regularly rotate JWT secrets and API keys".to_string());
            }
            SecurityPreset::HighSecurity => {
                recommendations
                    .push("✅ Good security configuration for production use".to_string());
                recommendations
                    .push("🔐 Ensure RSA keys are properly managed and rotated".to_string());
                recommendations.push("📈 Monitor failed authentication attempts".to_string());
                recommendations.push(
                    "🛡️  Consider multi-factor authentication for admin accounts".to_string(),
                );
            }
            SecurityPreset::Paranoid => {
                recommendations
                    .push("🛡️  Maximum security enabled - monitor performance impact".to_string());
                recommendations.push(
                    "⚡ Consider connection pooling to handle strict rate limits".to_string(),
                );
                recommendations.push("🔍 Implement comprehensive security monitoring".to_string());
                recommendations
                    .push("🚨 Set up alerting for all authentication failures".to_string());
            }
        }

        recommendations
    }

    // Helper methods for validation

    fn is_production_environment(&self) -> bool {
        std::env::var("ENVIRONMENT").as_deref() == Ok("production")
            || std::env::var("ENV").as_deref() == Ok("production")
            || std::env::var("NODE_ENV").as_deref() == Ok("production")
            || std::env::var("RUST_ENV").as_deref() == Ok("production")
            || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
    }

    fn is_development_environment(&self) -> bool {
        std::env::var("ENVIRONMENT").as_deref() == Ok("development")
            || std::env::var("ENV").as_deref() == Ok("development")
            || std::env::var("NODE_ENV").as_deref() == Ok("development")
            || std::env::var("RUST_ENV").as_deref() == Ok("development")
            || cfg!(debug_assertions)
    }

    fn requires_secure_cookies(&self) -> bool {
        matches!(
            self,
            SecurityPreset::Balanced | SecurityPreset::HighSecurity | SecurityPreset::Paranoid
        )
    }

    fn validate_jwt_secret(&self, issues: &mut Vec<SecurityIssue>) {
        if let Ok(secret) = std::env::var("JWT_SECRET") {
            let min_length = match self {
                SecurityPreset::Development => 16,
                SecurityPreset::Balanced => 32,
                SecurityPreset::HighSecurity => 64,
                SecurityPreset::Paranoid => 128,
            };

            if secret.len() < min_length {
                issues.push(SecurityIssue {
                    severity: if matches!(self, SecurityPreset::Development) {
                        SecuritySeverity::Warning
                    } else {
                        SecuritySeverity::Error
                    },
                    component: "JWT Secret".to_string(),
                    description: format!(
                        "JWT secret too short ({} chars, need {}+)",
                        secret.len(),
                        min_length
                    ),
                    suggestion: format!(
                        "Generate a longer secret: `openssl rand -base64 {}`",
                        min_length * 3 / 4
                    ),
                    blocks_production: !matches!(self, SecurityPreset::Development),
                });
            }

            // Check for weak patterns
            if secret.to_lowercase().contains("secret")
                || secret.to_lowercase().contains("password")
                || secret.contains("123")
            {
                issues.push(SecurityIssue {
                    severity: SecuritySeverity::Error,
                    component: "JWT Secret".to_string(),
                    description: "JWT secret contains weak patterns or common words".to_string(),
                    suggestion:
                        "Use a cryptographically secure random string: `openssl rand -base64 64`"
                            .to_string(),
                    blocks_production: true,
                });
            }
        } else {
            issues.push(SecurityIssue {
                severity: SecuritySeverity::Critical,
                component: "JWT Secret".to_string(),
                description: "JWT_SECRET environment variable not set".to_string(),
                suggestion: "Set JWT_SECRET environment variable with a secure random value"
                    .to_string(),
                blocks_production: true,
            });
        }
    }

    fn validate_https_requirement(&self, issues: &mut Vec<SecurityIssue>) {
        // In a real implementation, this would check if HTTPS is properly configured
        // For now, we'll check for common HTTPS indicators
        let has_tls_cert =
            std::env::var("TLS_CERT_PATH").is_ok() || std::env::var("SSL_CERT_PATH").is_ok();
        let behind_proxy = std::env::var("HTTPS").as_deref() == Ok("on")
            || std::env::var("HTTP_X_FORWARDED_PROTO").as_deref() == Ok("https");

        if !has_tls_cert && !behind_proxy {
            issues.push(SecurityIssue {
                severity: SecuritySeverity::Warning,
                component: "HTTPS".to_string(),
                description: "HTTPS configuration not detected".to_string(),
                suggestion: "Ensure HTTPS is properly configured for secure cookie transmission"
                    .to_string(),
                blocks_production: false,
            });
        }
    }

    fn validate_storage_security(&self, issues: &mut Vec<SecurityIssue>) {
        // Check for database connection security
        if let Ok(db_url) = std::env::var("DATABASE_URL")
            && db_url.starts_with("postgresql://")
            && !db_url.contains("sslmode=require")
        {
            issues.push(SecurityIssue {
                severity: SecuritySeverity::Warning,
                component: "Database".to_string(),
                description: "Database connection may not be using SSL".to_string(),
                suggestion: "Add sslmode=require to DATABASE_URL for encrypted connections"
                    .to_string(),
                blocks_production: false,
            });
        }

        if let Ok(redis_url) = std::env::var("REDIS_URL")
            && !redis_url.starts_with("rediss://")
            && !redis_url.contains("tls")
        {
            issues.push(SecurityIssue {
                severity: SecuritySeverity::Info,
                component: "Redis".to_string(),
                description: "Redis connection may not be using TLS".to_string(),
                suggestion: "Consider using rediss:// URL or enabling TLS for Redis connections"
                    .to_string(),
                blocks_production: false,
            });
        }
    }

    fn validate_environment_variables(&self, issues: &mut Vec<SecurityIssue>) {
        let sensitive_vars = [
            "JWT_SECRET",
            "DATABASE_URL",
            "REDIS_URL",
            "OAUTH_CLIENT_SECRET",
        ];

        for var in &sensitive_vars {
            if let Ok(value) = std::env::var(var)
                && value.len() < 20
            {
                issues.push(SecurityIssue {
                    severity: SecuritySeverity::Warning,
                    component: "Environment Variables".to_string(),
                    description: format!("{} appears to be too short", var),
                    suggestion: format!(
                        "Ensure {} contains a sufficiently long, secure value",
                        var
                    ),
                    blocks_production: false,
                });
            }
        }
    }
}

/// Security audit report
#[derive(Debug, Clone)]
pub struct SecurityAuditReport {
    pub preset: SecurityPreset,
    pub status: SecurityAuditStatus,
    pub issues: Vec<SecurityIssue>,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub recommendations: Vec<String>,
}

/// Overall security audit status
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityAuditStatus {
    /// All security checks passed
    Passed,
    /// Non-critical warnings found
    Warning,
    /// Security errors found that should be addressed
    Failed,
    /// Critical security issues that block production deployment
    Critical,
}

impl SecurityAuditReport {
    /// Print a formatted security report to stdout
    pub fn print_report(&self) {
        println!("🔒 Security Audit Report");
        println!("========================");
        println!("Preset: {:?}", self.preset);
        println!("Status: {}", self.status_emoji());
        println!();

        if self.issues.is_empty() {
            println!("✅ No security issues found!");
        } else {
            println!("📊 Issues Summary:");
            println!("   Critical: {}", self.critical_count);
            println!("   Errors: {}", self.error_count);
            println!("   Warnings: {}", self.warning_count);
            println!();

            for issue in &self.issues {
                println!(
                    "{} {}: {}",
                    issue.severity.emoji(),
                    issue.component,
                    issue.description
                );
                println!("   💡 {}", issue.suggestion);
                println!();
            }
        }

        if !self.recommendations.is_empty() {
            println!("📋 Recommendations:");
            for rec in &self.recommendations {
                println!("   {}", rec);
            }
            println!();
        }

        println!("{}", self.get_summary_message());
    }

    fn status_emoji(&self) -> &str {
        match self.status {
            SecurityAuditStatus::Passed => "✅ Passed",
            SecurityAuditStatus::Warning => "⚠️  Warning",
            SecurityAuditStatus::Failed => "❌ Failed",
            SecurityAuditStatus::Critical => "🚨 Critical",
        }
    }

    fn get_summary_message(&self) -> String {
        match self.status {
            SecurityAuditStatus::Passed => "🎉 Security audit passed! Your configuration meets security requirements.".to_string(),
            SecurityAuditStatus::Warning => "⚠️  Security audit completed with warnings. Consider addressing the issues above.".to_string(),
            SecurityAuditStatus::Failed => "❌ Security audit failed. Please address the errors before deploying to production.".to_string(),
            SecurityAuditStatus::Critical => "🚨 Critical security issues found! Do not deploy to production until these are resolved.".to_string(),
        }
    }

    /// Check if the configuration is safe for production deployment
    pub fn is_production_ready(&self) -> bool {
        matches!(
            self.status,
            SecurityAuditStatus::Passed | SecurityAuditStatus::Warning
        )
    }

    /// Get all blocking issues that prevent production deployment
    pub fn get_blocking_issues(&self) -> Vec<&SecurityIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.blocks_production)
            .collect()
    }
}

impl SecuritySeverity {
    fn emoji(&self) -> &str {
        match self {
            SecuritySeverity::Info => "ℹ️ ",
            SecuritySeverity::Warning => "⚠️ ",
            SecuritySeverity::Error => "❌",
            SecuritySeverity::Critical => "🚨",
        }
    }
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "INFO"),
            SecuritySeverity::Warning => write!(f, "WARNING"),
            SecuritySeverity::Error => write!(f, "ERROR"),
            SecuritySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}
