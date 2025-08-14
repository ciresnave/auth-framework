//! Utility functions for the authentication framework.
use crate::errors::{AuthError, Result};
use rand::Rng;
pub use rate_limit::RateLimiter;
use ring::digest;
use std::time::{SystemTime, UNIX_EPOCH};

/// Password hashing utilities.
pub mod password {
    use super::*;

    /// Hash a password using bcrypt.
    pub fn hash_password(password: &str) -> Result<String> {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::crypto(format!("Password hashing failed: {e}")))
    }

    /// Verify a password against a hash.
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        bcrypt::verify(password, hash)
            .map_err(|e| AuthError::crypto(format!("Password verification failed: {e}")))
    }

    /// Generate a secure random password.
    pub fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    }

    /// Check password strength.
    pub fn check_password_strength(password: &str) -> PasswordStrength {
        let mut score = 0;
        let mut feedback = Vec::new();

        // Length check
        if password.len() >= 8 {
            score += 1;
        } else {
            feedback.push("Password should be at least 8 characters long".to_string());
        }

        if password.len() >= 12 {
            score += 1;
        }

        // Character variety checks
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        } else {
            feedback.push("Password should contain lowercase letters".to_string());
        }

        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        } else {
            feedback.push("Password should contain uppercase letters".to_string());
        }

        if password.chars().any(|c| c.is_ascii_digit()) {
            score += 1;
        } else {
            feedback.push("Password should contain numbers".to_string());
        }

        if password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            score += 1;
        } else {
            feedback.push("Password should contain special characters".to_string());
        }

        // Common password check (basic)
        let common_passwords = ["password", "123456", "password123", "admin", "letmein"];
        if common_passwords.contains(&password.to_lowercase().as_str()) {
            score = 0;
            feedback.push("Password is too common".to_string());
        }

        let strength = match score {
            0..=2 => PasswordStrengthLevel::Weak,
            3..=4 => PasswordStrengthLevel::Medium,
            5..=6 => PasswordStrengthLevel::Strong,
            _ => PasswordStrengthLevel::VeryStrong,
        };

        PasswordStrength {
            level: strength,
            score,
            feedback,
        }
    }

    /// Password strength assessment.
    #[derive(Debug, Clone)]
    pub struct PasswordStrength {
        pub level: PasswordStrengthLevel,
        pub score: u8,
        pub feedback: Vec<String>,
    }

    /// Password strength levels.
    #[derive(Debug, Clone, PartialEq)]
    pub enum PasswordStrengthLevel {
        Weak,
        Medium,
        Strong,
        VeryStrong,
    }
}

/// Cryptographic utilities.
pub mod crypto {
    use super::*;

    /// Generate a secure random string.
    pub fn generate_random_string(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate a secure random byte array.
    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    /// Compute SHA256 hash.
    pub fn sha256(data: &[u8]) -> Vec<u8> {
        let digest = digest::digest(&digest::SHA256, data);
        digest.as_ref().to_vec()
    }

    /// Compute SHA256 hash and return as hex string.
    pub fn sha256_hex(data: &[u8]) -> String {
        hex::encode(sha256(data))
    }

    /// Generate a secure token.
    pub fn generate_token(length: usize) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(generate_random_bytes(length))
    }

    /// Constant-time string comparison.
    pub fn constant_time_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        // Use a simple constant-time comparison
        let mut result = 0u8;
        for (byte_a, byte_b) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
            result |= byte_a ^ byte_b;
        }
        result == 0
    }
}

/// Time utilities.
pub mod time {
    use super::*;
    use std::time::Duration;

    /// Get current Unix timestamp.
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Get current Unix timestamp in milliseconds.
    pub fn current_timestamp_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Convert duration to seconds.
    pub fn duration_to_seconds(duration: Duration) -> u64 {
        duration.as_secs()
    }

    /// Convert seconds to duration.
    pub fn seconds_to_duration(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    /// Check if a timestamp is expired.
    pub fn is_expired(expires_at: u64) -> bool {
        current_timestamp() > expires_at
    }

    /// Get time remaining until expiration.
    pub fn time_until_expiry(expires_at: u64) -> Option<Duration> {
        let now = current_timestamp();
        if expires_at > now {
            Some(Duration::from_secs(expires_at - now))
        } else {
            None
        }
    }
}

/// String utilities.
pub mod string {
    /// Mask a string for safe logging.
    pub fn mask_string(input: &str, visible_chars: usize) -> String {
        if input.len() <= visible_chars * 2 {
            "*".repeat(input.len().min(8))
        } else {
            format!(
                "{}{}{}",
                &input[..visible_chars],
                "*".repeat(input.len() - visible_chars * 2),
                &input[input.len() - visible_chars..]
            )
        }
    }

    /// Truncate a string to a maximum length.
    pub fn truncate(input: &str, max_length: usize) -> String {
        if input.len() <= max_length {
            input.to_string()
        } else {
            format!("{}...", &input[..max_length.saturating_sub(3)])
        }
    }

    /// Check if a string is a valid email address (basic check).
    pub fn is_valid_email(email: &str) -> bool {
        email.contains('@') && email.contains('.') && email.len() > 5
    }

    /// Normalize an email address.
    pub fn normalize_email(email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Generate a random identifier.
    pub fn generate_id(prefix: Option<&str>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        match prefix {
            Some(prefix) => format!("{prefix}_{id}"),
            None => id,
        }
    }
}

/// Validation utilities.
pub mod validation {
    use super::*;

    /// Validate username format.
    pub fn validate_username(username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(AuthError::validation("Username cannot be empty"));
        }

        if username.len() < 3 {
            return Err(AuthError::validation(
                "Username must be at least 3 characters long",
            ));
        }

        if username.len() > 50 {
            return Err(AuthError::validation(
                "Username cannot be longer than 50 characters",
            ));
        }

        // Check for valid characters (alphanumeric, underscore, hyphen)
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(AuthError::validation(
                "Username can only contain letters, numbers, underscores, and hyphens",
            ));
        }

        // Cannot start or end with special characters
        if username.starts_with('_')
            || username.starts_with('-')
            || username.ends_with('_')
            || username.ends_with('-')
        {
            return Err(AuthError::validation(
                "Username cannot start or end with underscore or hyphen",
            ));
        }

        Ok(())
    }

    /// Validate email format.
    pub fn validate_email(email: &str) -> Result<()> {
        if email.is_empty() {
            return Err(AuthError::validation("Email cannot be empty"));
        }

        if !string::is_valid_email(email) {
            return Err(AuthError::validation("Invalid email format"));
        }

        if email.len() > 254 {
            return Err(AuthError::validation("Email address is too long"));
        }

        Ok(())
    }

    /// Validate password according to policy.
    pub fn validate_password(
        password: &str,
        min_length: usize,
        require_complexity: bool,
    ) -> Result<()> {
        if password.is_empty() {
            return Err(AuthError::validation("Password cannot be empty"));
        }

        if password.len() < min_length {
            return Err(AuthError::validation(format!(
                "Password must be at least {min_length} characters long"
            )));
        }

        if require_complexity {
            let strength = password::check_password_strength(password);
            if matches!(strength.level, password::PasswordStrengthLevel::Weak) {
                return Err(AuthError::validation(format!(
                    "Password is too weak: {}",
                    strength.feedback.join(", ")
                )));
            }
        }

        Ok(())
    }

    /// Validate API key format.
    pub fn validate_api_key(api_key: &str, expected_prefix: Option<&str>) -> Result<()> {
        if api_key.is_empty() {
            return Err(AuthError::validation("API key cannot be empty"));
        }

        if let Some(prefix) = expected_prefix
            && !api_key.starts_with(prefix) {
                return Err(AuthError::validation(format!(
                    "API key must start with '{prefix}'"
                )));
            }

        // Basic length check
        if api_key.len() < 16 {
            return Err(AuthError::validation("API key is too short"));
        }

        if api_key.len() > 128 {
            return Err(AuthError::validation("API key is too long"));
        }

        Ok(())
    }
}

/// Rate limiting utilities.
pub mod rate_limit {
    use dashmap::DashMap;

    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Simple in-memory rate limiter.
    #[derive(Debug)]
    pub struct RateLimiter {
        buckets: Arc<DashMap<String, Bucket>>,
        max_requests: u32,
        window: Duration,
    }

    #[derive(Debug)]
    struct Bucket {
        count: u32,
        window_start: Instant,
    }

    impl RateLimiter {
        /// Create a new rate limiter.
        pub fn new(max_requests: u32, window: Duration) -> Self {
            Self {
                buckets: Arc::new(DashMap::new()),
                max_requests,
                window,
            }
        }

        /// Check if a request is allowed for the given key.
        pub fn is_allowed(&self, key: &str) -> bool {
            let now = Instant::now();

            // Get or create bucket with deadlock-safe pattern
            let mut bucket = self.buckets.entry(key.to_string()).or_insert(Bucket {
                count: 0,
                window_start: now,
            });

            // Reset bucket if window has passed
            if now.duration_since(bucket.window_start) >= self.window {
                bucket.count = 0;
                bucket.window_start = now;
            }

            // Check if under limit
            if bucket.count < self.max_requests {
                bucket.count += 1;
                true
            } else {
                false
            }
        }

        /// Get remaining requests for a key.
        pub fn remaining_requests(&self, key: &str) -> u32 {
            if let Some(bucket_ref) = self.buckets.get(key) {
                let bucket = bucket_ref.value();
                let now = Instant::now();
                if now.duration_since(bucket.window_start) >= self.window {
                    self.max_requests
                } else {
                    self.max_requests.saturating_sub(bucket.count)
                }
            } else {
                self.max_requests
            }
        }

        /// Clean up expired buckets.
        pub fn cleanup(&self) {
            let now = Instant::now();
            self.buckets
                .retain(|_, bucket| now.duration_since(bucket.window_start) < self.window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = password::hash_password(password).unwrap();

        assert!(password::verify_password(password, &hash).unwrap());
        assert!(!password::verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_password_strength() {
        let weak = password::check_password_strength("123");
        assert!(matches!(weak.level, password::PasswordStrengthLevel::Weak));

        let strong = password::check_password_strength("MySecureP@ssw0rd!");
        assert!(matches!(
            strong.level,
            password::PasswordStrengthLevel::Strong | password::PasswordStrengthLevel::VeryStrong
        ));
    }

    #[test]
    fn test_crypto_utils() {
        let random_string = crypto::generate_random_string(16);
        assert_eq!(random_string.len(), 16);

        let data = b"test data";
        let hash = crypto::sha256_hex(data);
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 characters
    }

    #[test]
    fn test_string_utils() {
        let masked = string::mask_string("secret123456", 2);
        assert!(masked.starts_with("se"));
        assert!(masked.ends_with("56"));
        assert!(masked.contains("*"));

        assert!(string::is_valid_email("test@example.com"));
        assert!(!string::is_valid_email("invalid_email"));
    }

    #[test]
    fn test_validation() {
        // Valid username
        assert!(validation::validate_username("test_user").is_ok());

        // Invalid usernames
        assert!(validation::validate_username("").is_err());
        assert!(validation::validate_username("ab").is_err());
        assert!(validation::validate_username("_invalid").is_err());
        assert!(validation::validate_username("invalid@").is_err());

        // Valid email
        assert!(validation::validate_email("test@example.com").is_ok());

        // Invalid emails
        assert!(validation::validate_email("").is_err());
        assert!(validation::validate_email("invalid").is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = rate_limit::RateLimiter::new(3, std::time::Duration::from_secs(1));

        // First 3 requests should be allowed
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));

        // 4th request should be blocked
        assert!(!limiter.is_allowed("user1"));

        // Different user should still be allowed
        assert!(limiter.is_allowed("user2"));
    }
}
