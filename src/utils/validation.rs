// SPDX-License-Identifier: MIT OR Apache-2.0
//! Validation utilities for the AuthFramework.
//!
//! This module provides comprehensive input validation functions for
//! authentication-related data including passwords, usernames, emails, and more.

use crate::errors::{AuthError, Result};
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

// Compiled once at first use; regex compilation is non-trivial and running it
// on every request wastes CPU and could be exploited for minor Denial-of-Service.
static USERNAME_RE: OnceLock<Regex> = OnceLock::new();
static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
static API_KEY_RE: OnceLock<Regex> = OnceLock::new();

/// Enhanced password validation configuration
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    /// Maximum password length  
    pub max_length: usize,
    /// Require at least one uppercase letter
    pub require_uppercase: bool,
    /// Require at least one lowercase letter
    pub require_lowercase: bool,
    /// Require at least one digit
    pub require_digit: bool,
    /// Require at least one special character
    pub require_special: bool,
    /// List of banned common passwords
    pub banned_passwords: HashSet<String>,
    /// Minimum entropy requirement
    pub min_entropy: f64,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        let mut banned_passwords = HashSet::new();
        // Add common weak passwords
        for password in [
            "password",
            "123456",
            "password123",
            "admin",
            "qwerty",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "password1",
            "123456789",
            "1234567890",
            "abc123",
            "iloveyou",
        ] {
            banned_passwords.insert(password.to_string());
        }

        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            banned_passwords,
            min_entropy: 3.0,
        }
    }
}

impl PasswordPolicy {
    /// NIST SP 800-63B compliant policy.
    ///
    /// Follows modern NIST guidance: no arbitrary composition rules,
    /// focus on length and entropy. Banned password list still applies.
    ///
    /// ```rust
    /// use auth_framework::utils::validation::PasswordPolicy;
    /// let policy = PasswordPolicy::nist_800_63b();
    /// assert_eq!(policy.min_length, 8);
    /// assert!(!policy.require_special);
    /// ```
    pub fn nist_800_63b() -> Self {
        Self {
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            ..Default::default()
        }
    }

    /// High-security policy with strict composition requirements.
    ///
    /// Suitable for admin accounts and sensitive systems.
    ///
    /// ```rust
    /// use auth_framework::utils::validation::PasswordPolicy;
    /// let policy = PasswordPolicy::high_security();
    /// assert_eq!(policy.min_length, 12);
    /// assert!(policy.require_special);
    /// ```
    pub fn high_security() -> Self {
        Self {
            min_length: 12,
            min_entropy: 4.0,
            ..Default::default()
        }
    }

    /// Add custom banned passwords on top of the existing list.
    ///
    /// Words are lowercased before insertion.
    pub fn with_banned_words(mut self, words: &[&str]) -> Self {
        for word in words {
            self.banned_passwords.insert(word.to_lowercase());
        }
        self
    }

    /// Create a builder starting from the default policy.
    pub fn builder() -> PasswordPolicyBuilder {
        PasswordPolicyBuilder {
            policy: PasswordPolicy::default(),
        }
    }
}

/// Fluent builder for [`PasswordPolicy`].
///
/// # Example
///
/// ```rust
/// use auth_framework::utils::validation::PasswordPolicy;
///
/// let policy = PasswordPolicy::builder()
///     .min_length(10)
///     .require_special(false)
///     .min_entropy(3.5)
///     .build();
///
/// assert_eq!(policy.min_length, 10);
/// assert!(!policy.require_special);
/// ```
#[derive(Debug, Clone)]
pub struct PasswordPolicyBuilder {
    policy: PasswordPolicy,
}

impl PasswordPolicyBuilder {
    /// Set minimum password length.
    pub fn min_length(mut self, len: usize) -> Self {
        self.policy.min_length = len;
        self
    }

    /// Set maximum password length.
    pub fn max_length(mut self, len: usize) -> Self {
        self.policy.max_length = len;
        self
    }

    /// Whether to require at least one uppercase letter.
    pub fn require_uppercase(mut self, require: bool) -> Self {
        self.policy.require_uppercase = require;
        self
    }

    /// Whether to require at least one lowercase letter.
    pub fn require_lowercase(mut self, require: bool) -> Self {
        self.policy.require_lowercase = require;
        self
    }

    /// Whether to require at least one digit.
    pub fn require_digit(mut self, require: bool) -> Self {
        self.policy.require_digit = require;
        self
    }

    /// Whether to require at least one special character.
    pub fn require_special(mut self, require: bool) -> Self {
        self.policy.require_special = require;
        self
    }

    /// Set the minimum entropy threshold.
    pub fn min_entropy(mut self, entropy: f64) -> Self {
        self.policy.min_entropy = entropy;
        self
    }

    /// Consume the builder and produce the policy.
    pub fn build(self) -> PasswordPolicy {
        self.policy
    }
}

/// Enhanced password validation with configurable policy
pub fn validate_password_enhanced(password: &str, policy: &PasswordPolicy) -> Result<()> {
    // Check length requirements
    if password.len() < policy.min_length {
        return Err(AuthError::validation(format!(
            "Password must be at least {} characters long",
            policy.min_length
        )));
    }

    if password.len() > policy.max_length {
        return Err(AuthError::validation(format!(
            "Password must be no more than {} characters long",
            policy.max_length
        )));
    }

    // Check character requirements
    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::validation(
            "Password must contain at least one uppercase letter".to_string(),
        ));
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(AuthError::validation(
            "Password must contain at least one lowercase letter".to_string(),
        ));
    }

    if policy.require_digit && !password.chars().any(|c| c.is_numeric()) {
        return Err(AuthError::validation(
            "Password must contain at least one digit".to_string(),
        ));
    }

    if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(AuthError::validation(
            "Password must contain at least one special character".to_string(),
        ));
    }

    // Check against banned passwords
    if policy.banned_passwords.contains(&password.to_lowercase()) {
        return Err(AuthError::validation(
            "Password is too common and not allowed".to_string(),
        ));
    }

    // Calculate entropy and check minimum requirement
    let entropy = calculate_password_entropy(password);
    if entropy < policy.min_entropy {
        return Err(AuthError::validation(format!(
            "Password entropy ({:.2}) is below minimum requirement ({:.2})",
            entropy, policy.min_entropy
        )));
    }

    // Detect sequential character patterns (e.g. "abc", "123", "cba", "321")
    // and keyboard walks (e.g. "qwerty", "asdf") that Shannon entropy misses
    // because each character is unique.
    if has_sequential_patterns(password) {
        return Err(AuthError::validation(
            "Password contains sequential or keyboard-pattern characters that are easily guessed"
                .to_string(),
        ));
    }

    Ok(())
}

/// Simple password validation with default policy
pub fn validate_password(password: &str) -> Result<()> {
    validate_password_enhanced(password, &PasswordPolicy::default())
}

/// Calculate password entropy using Shannon entropy formula
fn calculate_password_entropy(password: &str) -> f64 {
    let mut char_counts = std::collections::HashMap::new();

    for c in password.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let length = password.len() as f64;
    let mut entropy = 0.0;

    for &count in char_counts.values() {
        let probability = count as f64 / length;
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Detect passwords dominated by sequential runs, keyboard walks, or repeated characters.
///
/// Returns `true` when more than half of the password's characters participate
/// in a sequential run of 3+ or match a common keyboard walk pattern.
fn has_sequential_patterns(password: &str) -> bool {
    if password.len() < 6 {
        return false; // too short for pattern detection to be meaningful
    }

    // Common keyboard walk sequences (lowercase)
    const KEYBOARD_ROWS: &[&str] = &["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

    let lower = password.to_lowercase();

    // Count characters that are part of a 3+ ascending/descending codepoint run
    let chars: Vec<char> = lower.chars().collect();
    let mut sequential_count: usize = 0;
    let mut run = 1usize;
    for i in 1..chars.len() {
        let diff = chars[i] as i32 - chars[i - 1] as i32;
        if diff == 1 || diff == -1 {
            run += 1;
        } else {
            if run >= 3 {
                sequential_count += run;
            }
            run = 1;
        }
    }
    if run >= 3 {
        sequential_count += run;
    }

    // Also count characters that belong to a keyboard-walk substring of length >= 4
    let mut walk_count: usize = 0;
    for row in KEYBOARD_ROWS {
        let rev: String = row.chars().rev().collect();
        for window_len in (4..=lower.len()).rev() {
            for start in 0..=lower.len().saturating_sub(window_len) {
                let slice = &lower[start..start + window_len];
                if row.contains(slice) || rev.contains(slice) {
                    walk_count = walk_count.max(window_len);
                }
            }
        }
    }

    let dominated = sequential_count.max(walk_count);
    // If more than half the password is sequential/walk characters, reject
    dominated * 2 > password.len()
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AuthError::validation(
            "Username cannot be empty".to_string(),
        ));
    }

    if username.len() < 3 {
        return Err(AuthError::validation(
            "Username must be at least 3 characters long".to_string(),
        ));
    }

    if username.len() > 50 {
        return Err(AuthError::validation(
            "Username must be no more than 50 characters long".to_string(),
        ));
    }

    // Username must start with a letter and may then contain letters, digits,
    // underscores, and hyphens (3–50 chars total).
    let username_regex =
        USERNAME_RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]+$").expect("valid username regex"));
    if !username_regex.is_match(username) {
        return Err(AuthError::validation(
            "Username can only contain letters, numbers, underscores, and hyphens".to_string(),
        ));
    }

    // Must start with a letter
    if !username.chars().next().is_some_and(|c| c.is_alphabetic()) {
        return Err(AuthError::validation(
            "Username must start with a letter".to_string(),
        ));
    }

    Ok(())
}

/// Validate email format
pub fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AuthError::validation("Email cannot be empty".to_string()));
    }

    // Check length before running the regex to avoid matching against overlong strings.
    if email.len() > 254 {
        return Err(AuthError::validation(
            "Email address is too long".to_string(),
        ));
    }

    // Basic email validation regex (compiled once for performance).
    let email_regex = EMAIL_RE.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").expect("valid email regex")
    });
    if !email_regex.is_match(email) {
        return Err(AuthError::validation("Invalid email format".to_string()));
    }

    Ok(())
}

/// Validate API key format
pub fn validate_api_key(api_key: &str) -> Result<()> {
    if api_key.is_empty() {
        return Err(AuthError::validation("API key cannot be empty".to_string()));
    }

    if api_key.len() < 32 {
        return Err(AuthError::validation(
            "API key must be at least 32 characters long".to_string(),
        ));
    }

    if api_key.len() > 128 {
        return Err(AuthError::validation(
            "API key must be no more than 128 characters long".to_string(),
        ));
    }

    // API key should be alphanumeric
    let api_key_regex =
        API_KEY_RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9]+$").expect("valid api key regex"));
    if !api_key_regex.is_match(api_key) {
        return Err(AuthError::validation(
            "API key can only contain letters and numbers".to_string(),
        ));
    }

    Ok(())
}

/// Validate user-supplied input against common injection patterns.
///
/// Returns `true` when the input is safe to process. Rejects HTML/XML angle brackets,
/// URL-encoded angle brackets, null bytes, dangerous URI schemes (`javascript:`, `data:`,
/// `file:`, `jndi:`), template injection markers, path traversal sequences, and trivial
/// SQL injection patterns.
pub fn validate_user_input(input: &str) -> bool {
    if input.is_empty() || input.len() > 1000 {
        return false;
    }
    if !input.chars().all(|c| {
        if c.is_control() {
            matches!(c, ' ' | '\t' | '\n' | '\r')
        } else {
            !matches!(c, '<' | '>')
        }
    }) {
        return false;
    }
    let lower = input.to_ascii_lowercase();
    if lower.contains("%3c") || lower.contains("%3e") || lower.contains("%00") {
        return false;
    }
    if lower.contains("javascript:")
        || lower.contains("data:")
        || lower.contains("file:")
        || lower.contains("jndi:")
    {
        return false;
    }
    if input.contains("${") || input.contains("{{") {
        return false;
    }
    if input.contains("../") || input.contains("..\\") {
        return false;
    }
    if input.contains('\0') {
        return false;
    }
    if lower.contains("; drop")
        || lower.contains(";drop")
        || lower.contains("' drop")
        || lower.contains("'; drop")
        || lower.contains("--")
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        let policy = PasswordPolicy::default();

        // Valid password
        assert!(validate_password_enhanced("StrongP@ssw0rd!", &policy).is_ok());

        // Too short
        assert!(validate_password_enhanced("Short1!", &policy).is_err());

        // No uppercase
        assert!(validate_password_enhanced("lowercase123!", &policy).is_err());

        // No lowercase
        assert!(validate_password_enhanced("UPPERCASE123!", &policy).is_err());

        // No digit
        assert!(validate_password_enhanced("NoDigitPass!", &policy).is_err());

        // No special character
        assert!(validate_password_enhanced("NoSpecialChar123", &policy).is_err());

        // Banned password
        assert!(validate_password_enhanced("password", &policy).is_err());
    }

    #[test]
    fn test_username_validation() {
        // Valid usernames
        assert!(validate_username("validuser").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("test-user").is_ok());

        // Invalid usernames
        assert!(validate_username("").is_err()); // Empty
        assert!(validate_username("ab").is_err()); // Too short
        assert!(validate_username("123user").is_err()); // Starts with number
        assert!(validate_username("user@test").is_err()); // Invalid character
    }

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("user.name+tag@domain.co.uk").is_ok());

        // Invalid emails
        assert!(validate_email("").is_err()); // Empty
        assert!(validate_email("invalid.email").is_err()); // No @
        assert!(validate_email("@domain.com").is_err()); // No local part
        assert!(validate_email("test@").is_err()); // No domain
    }

    #[test]
    fn test_password_policy_nist_preset() {
        let policy = PasswordPolicy::nist_800_63b();
        assert_eq!(policy.min_length, 8);
        assert!(!policy.require_uppercase);
        assert!(!policy.require_lowercase);
        assert!(!policy.require_digit);
        assert!(!policy.require_special);
        // NIST doesn't require composition rules, so a long lowercase-only password should pass
        assert!(validate_password_enhanced("alongpasswordthatisonly lowercase", &policy).is_ok());
    }

    #[test]
    fn test_password_policy_high_security_preset() {
        let policy = PasswordPolicy::high_security();
        assert_eq!(policy.min_length, 12);
        assert!(policy.require_uppercase);
        assert!(policy.require_special);
        assert!(policy.min_entropy > 3.0);
    }

    #[test]
    fn test_password_policy_builder() {
        let policy = PasswordPolicy::builder()
            .min_length(10)
            .require_special(false)
            .min_entropy(3.5)
            .build();
        assert_eq!(policy.min_length, 10);
        assert!(!policy.require_special);
        assert_eq!(policy.min_entropy, 3.5);
        // Other defaults should remain
        assert!(policy.require_uppercase);
        assert!(policy.require_digit);
    }

    #[test]
    fn test_password_policy_with_banned_words() {
        let policy = PasswordPolicy::default().with_banned_words(&["CompanyName", "SecretWord"]);
        assert!(policy.banned_passwords.contains("companyname"));
        assert!(policy.banned_passwords.contains("secretword"));
        // Original banned passwords should still be present
        assert!(policy.banned_passwords.contains("password"));
    }
}
