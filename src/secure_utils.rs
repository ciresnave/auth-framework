// Secure utility functions with constant-time operations
use crate::errors::{AuthError, Result};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string that is automatically zeroized when dropped
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SecureString {
    data: String,
}

impl SecureString {
    /// Create a new secure string
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Get the string data (use carefully)
    pub fn as_str(&self) -> &str {
        &self.data
    }

    /// Get the string data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<String> for SecureString {
    fn from(data: String) -> Self {
        Self::new(data)
    }
}

impl From<&str> for SecureString {
    fn from(data: &str) -> Self {
        Self::new(data.to_string())
    }
}

/// Secure comparison utilities
pub struct SecureComparison;

impl SecureComparison {
    /// Constant-time string comparison
    pub fn constant_time_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }

    /// Constant-time byte comparison
    pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Compare strings with timing attack protection
    /// This function always takes the same amount of time regardless of where differences occur
    pub fn secure_string_compare(a: &str, b: &str) -> bool {
        // Normalize lengths to prevent length-based timing attacks
        let max_len = a.len().max(b.len()).min(1024); // Cap at reasonable length

        let mut a_padded = vec![0u8; max_len];
        let mut b_padded = vec![0u8; max_len];

        // Copy actual data
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();

        a_padded[..a_bytes.len().min(max_len)]
            .copy_from_slice(&a_bytes[..a_bytes.len().min(max_len)]);
        b_padded[..b_bytes.len().min(max_len)]
            .copy_from_slice(&b_bytes[..b_bytes.len().min(max_len)]);

        // Constant-time comparison
        let result = a_padded.ct_eq(&b_padded).into() && a.len() == b.len();

        // Explicitly clear sensitive data
        a_padded.zeroize();
        b_padded.zeroize();

        result
    }

    /// Verify that two tokens match using constant-time comparison
    pub fn verify_token(provided: &str, expected: &str) -> bool {
        Self::secure_string_compare(provided, expected)
    }

    /// Verify API key or session token with timing attack protection
    pub fn verify_api_key(provided: &str, stored_hash: &str) -> Result<bool> {
        // For API keys, we typically compare against a hash
        // This assumes the stored value is already hashed
        if provided.is_empty() || stored_hash.is_empty() {
            return Ok(false);
        }

        // Use bcrypt for API key verification if stored as bcrypt hash
        if stored_hash.starts_with("$2") {
            bcrypt::verify(provided, stored_hash)
                .map_err(|e| AuthError::crypto(format!("API key verification failed: {}", e)))
        } else {
            // For direct comparison (not recommended for production)
            Ok(Self::secure_string_compare(provided, stored_hash))
        }
    }
}

/// Secure random generation utilities
pub struct SecureRandomGen;

impl SecureRandomGen {
    /// Generate secure random bytes
    pub fn generate_bytes(len: usize) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes)
            .map_err(|_| AuthError::crypto("Failed to generate random bytes".to_string()))?;
        Ok(bytes)
    }

    /// Generate secure random string (base64url encoded)
    pub fn generate_string(byte_len: usize) -> Result<String> {
        let bytes = Self::generate_bytes(byte_len)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Generate secure random token for sessions/API keys
    pub fn generate_token() -> Result<String> {
        Self::generate_string(32) // 256 bits of entropy
    }

    /// Generate secure session ID
    pub fn generate_session_id() -> Result<String> {
        Self::generate_string(24) // 192 bits of entropy
    }

    /// Generate secure challenge ID
    pub fn generate_challenge_id() -> Result<String> {
        Self::generate_string(16) // 128 bits of entropy
    }
}

/// Input validation with security considerations
pub struct SecureValidation;

impl SecureValidation {
    /// Validate username with security checks
    pub fn validate_username(username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(AuthError::validation(
                "Username cannot be empty".to_string(),
            ));
        }

        if username.len() > 320 {
            return Err(AuthError::validation("Username too long".to_string()));
        }

        // Check for potentially dangerous characters
        if username.contains('\0') || username.contains('\r') || username.contains('\n') {
            return Err(AuthError::validation(
                "Username contains invalid characters".to_string(),
            ));
        }

        // Unicode normalization to prevent bypass attacks
        #[cfg(feature = "unicode-support")]
        {
            let normalized = unicode_normalization::UnicodeNormalization::nfc(username.chars())
                .collect::<String>();
            if normalized != username {
                return Err(AuthError::validation(
                    "Username must be in NFC form".to_string(),
                ));
            }
        }

        #[cfg(not(feature = "unicode-support"))]
        {
            // Basic checks without unicode normalization
            if username.chars().any(|c| c.is_control()) {
                return Err(AuthError::validation(
                    "Username contains invalid control characters".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate password with security considerations
    pub fn validate_password(password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(AuthError::validation(
                "Password cannot be empty".to_string(),
            ));
        }

        if password.len() > 1000 {
            return Err(AuthError::validation("Password too long".to_string()));
        }

        // Check for null bytes
        if password.contains('\0') {
            return Err(AuthError::validation(
                "Password contains null bytes".to_string(),
            ));
        }

        Ok(())
    }

    /// Sanitize user input to prevent injection attacks
    pub fn sanitize_input(input: &str) -> String {
        // Remove null bytes and control characters except newlines/tabs
        input
            .chars()
            .filter(|&c| !c.is_control() || c == '\n' || c == '\t')
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Validate and sanitize email address
    pub fn validate_email(email: &str) -> Result<String> {
        let sanitized = Self::sanitize_input(email);

        if sanitized.is_empty() {
            return Err(AuthError::validation("Email cannot be empty".to_string()));
        }

        if sanitized.len() > 320 {
            return Err(AuthError::validation("Email too long".to_string()));
        }

        // Basic email validation
        if !sanitized.contains('@') || sanitized.starts_with('@') || sanitized.ends_with('@') {
            return Err(AuthError::validation("Invalid email format".to_string()));
        }

        Ok(sanitized)
    }
}

/// Convenience functions for compatibility with existing code
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    SecureComparison::constant_time_eq_bytes(a, b)
}

pub fn generate_secure_token(byte_len: usize) -> String {
    SecureRandomGen::generate_string(byte_len).unwrap_or_else(|_| {
        // Fallback to UUID if secure random fails
        uuid::Uuid::new_v4().to_string()
    })
}

pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AuthError::crypto(format!("Password hashing failed: {}", e)))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash)
        .map_err(|e| AuthError::crypto(format!("Password verification failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string() {
        let secret = SecureString::new("password123".to_string());
        assert_eq!(secret.as_str(), "password123");
        assert_eq!(secret.len(), 11);
        // SecureString will be zeroized when dropped
    }

    #[test]
    fn test_constant_time_comparison() {
        assert!(SecureComparison::constant_time_eq("hello", "hello"));
        assert!(!SecureComparison::constant_time_eq("hello", "world"));
        assert!(!SecureComparison::constant_time_eq("hello", "hello world"));
    }

    #[test]
    fn test_secure_string_compare() {
        assert!(SecureComparison::secure_string_compare("test", "test"));
        assert!(!SecureComparison::secure_string_compare(
            "test",
            "different"
        ));
        assert!(!SecureComparison::secure_string_compare("short", "longer"));
    }

    #[test]
    fn test_token_verification() {
        let token = "abc123def456";
        assert!(SecureComparison::verify_token(token, token));
        assert!(!SecureComparison::verify_token(token, "different"));
    }

    #[test]
    fn test_secure_random_generation() {
        let token1 = SecureRandomGen::generate_token().unwrap();
        let token2 = SecureRandomGen::generate_token().unwrap();

        assert_ne!(token1, token2);
        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
    }

    #[test]
    fn test_input_validation() {
        assert!(SecureValidation::validate_username("user123").is_ok());
        assert!(SecureValidation::validate_username("").is_err());
        assert!(SecureValidation::validate_username("user\0name").is_err());

        assert!(SecureValidation::validate_password("password123").is_ok());
        assert!(SecureValidation::validate_password("").is_err());
        assert!(SecureValidation::validate_password("pass\0word").is_err());
    }

    #[test]
    fn test_email_validation() {
        assert!(SecureValidation::validate_email("user@example.com").is_ok());
        assert!(SecureValidation::validate_email("invalid").is_err());
        assert!(SecureValidation::validate_email("@example.com").is_err());
        assert!(SecureValidation::validate_email("user@").is_err());
    }

    #[test]
    fn test_input_sanitization() {
        let dirty = "hello\0world\x01test";
        let clean = SecureValidation::sanitize_input(dirty);
        assert_eq!(clean, "helloworldtest");

        let with_newlines = "line1\nline2\tline3";
        let cleaned = SecureValidation::sanitize_input(with_newlines);
        assert_eq!(cleaned, "line1\nline2\tline3");
    }
}
