use serde::{Deserialize, Serialize};

/// Multi-Factor Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    /// TOTP configuration
    pub totp_config: TotpConfig,
    /// SMS configuration (optional)
    pub sms_config: Option<SmsConfig>,
    /// Email configuration (optional)
    pub email_config: Option<EmailConfig>,
    /// Backup codes configuration
    pub backup_codes_config: BackupCodesConfig,
    /// Challenge timeout in seconds
    pub challenge_timeout_seconds: u64,
    /// Maximum verification attempts
    pub max_verification_attempts: u32,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            totp_config: TotpConfig::default(),
            sms_config: None,
            email_config: None,
            backup_codes_config: BackupCodesConfig::default(),
            challenge_timeout_seconds: 300, // 5 minutes
            max_verification_attempts: 3,
        }
    }
}

/// TOTP (Time-based One-Time Password) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Issuer name for TOTP apps
    pub issuer: String,
    /// Number of digits in the TOTP code
    pub digits: u8,
    /// Time period in seconds
    pub period: u64,
    /// Number of time windows to allow (for clock skew)
    pub skew: u8,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "Auth Framework".to_string(),
            digits: 6,
            period: 30,
            skew: 1,
        }
    }
}

/// Backup codes configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCodesConfig {
    /// Number of backup codes to generate
    pub count: usize,
    /// Length of each backup code
    pub length: usize,
}

impl Default for BackupCodesConfig {
    fn default() -> Self {
        Self {
            count: 8,
            length: 8,
        }
    }
}

/// Password strength assessment result
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

/// Password validation result
#[derive(Debug, Clone)]
pub struct PasswordValidation {
    pub is_valid: bool,
    pub strength: PasswordStrength,
    pub issues: Vec<String>,
    pub suggestions: Vec<String>,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_success: bool,
    pub log_failures: bool,
    pub log_permission_changes: bool,
    pub log_admin_actions: bool,
    pub retention_days: u32,
    pub include_metadata: bool,
}

/// Account lockout configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockoutConfig {
    pub enabled: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_seconds: u64,
    pub progressive_lockout: bool,
    pub max_lockout_duration_seconds: u64,
}

/// SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    pub provider: String,
    pub api_key: String,
    pub from_number: String,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: "twilio".to_string(),
            api_key: String::new(),
            from_number: String::new(),
        }
    }
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub use_tls: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_server: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            username: String::new(),
            password: String::new(),
            from_email: String::new(),
            use_tls: true,
        }
    }
}

/// Security context for authentication operations
#[derive(Debug, Clone, Default)]
pub struct SecurityContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
}

/// Password validator
pub struct PasswordValidator {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_special_chars: bool,
    pub min_special_chars: usize,
    pub forbidden_patterns: Vec<String>,
}

impl Default for PasswordValidator {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special_chars: true,
            min_special_chars: 1,
            forbidden_patterns: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
                "admin".to_string(),
            ],
        }
    }
}

impl PasswordValidator {
    /// Validate password strength and return detailed results
    pub fn validate(&self, password: &str) -> PasswordValidation {
        let mut is_valid = true;
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();

        // Check minimum length
        if password.len() < self.min_length {
            is_valid = false;
            issues.push(format!(
                "Password must be at least {} characters long",
                self.min_length
            ));
            suggestions.push("Use a longer password".to_string());
        }

        // Check character requirements
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            is_valid = false;
            issues.push("Password must contain at least one uppercase letter".to_string());
            suggestions.push("Add uppercase letters".to_string());
        }

        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            is_valid = false;
            issues.push("Password must contain at least one lowercase letter".to_string());
            suggestions.push("Add lowercase letters".to_string());
        }

        if self.require_digits && !password.chars().any(|c| c.is_numeric()) {
            is_valid = false;
            issues.push("Password must contain at least one digit".to_string());
            suggestions.push("Add numbers".to_string());
        }

        if self.require_special_chars {
            let special_count = password.chars().filter(|c| !c.is_alphanumeric()).count();
            if special_count < self.min_special_chars {
                is_valid = false;
                issues.push(format!(
                    "Password must contain at least {} special characters",
                    self.min_special_chars
                ));
                suggestions.push("Add special characters like !@#$%^&*".to_string());
            }
        }

        // Check forbidden patterns
        for pattern in &self.forbidden_patterns {
            if password.to_lowercase().contains(&pattern.to_lowercase()) {
                is_valid = false;
                issues.push(format!("Password contains forbidden pattern: {}", pattern));
                suggestions.push("Avoid common passwords and patterns".to_string());
            }
        }

        // Assess strength
        let strength = self.assess_strength(password);

        PasswordValidation {
            is_valid,
            strength,
            issues,
            suggestions,
        }
    }

    /// Assess password strength
    fn assess_strength(&self, password: &str) -> PasswordStrength {
        let mut score = 0;

        // Length scoring
        if password.len() >= 8 {
            score += 1;
        }
        if password.len() >= 12 {
            score += 1;
        }
        if password.len() >= 16 {
            score += 1;
        }

        // Character variety scoring
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_numeric()) {
            score += 1;
        }
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 1;
        }

        // Complexity bonus
        if password.len() >= 20 {
            score += 1;
        }

        match score {
            0..=2 => PasswordStrength::VeryWeak,
            3..=4 => PasswordStrength::Weak,
            5 => PasswordStrength::Fair,
            6 => PasswordStrength::Good,
            7 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        let validator = PasswordValidator::default();

        // Test weak password
        let result = validator.validate("weak");
        assert!(!result.is_valid);
        assert_eq!(result.strength, PasswordStrength::VeryWeak);
        assert!(!result.issues.is_empty());

        // Test strong password
        let result = validator.validate("Strong@Secure123!");
        assert!(result.is_valid);
        assert!(matches!(
            result.strength,
            PasswordStrength::Strong | PasswordStrength::VeryStrong
        ));
        assert!(result.issues.is_empty());
    }

    #[test]
    fn test_forbidden_patterns() {
        let validator = PasswordValidator::default();
        let result = validator.validate("Password123!");
        assert!(!result.is_valid);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.contains("forbidden pattern"))
        );
    }
}
