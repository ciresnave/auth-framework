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
    pub fn verify_token(token1: &str, token2: &str) -> bool {
        Self::secure_string_compare(token1, token2)
    }
}

/// Generate secure random values
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

        // Check for potentially dangerous characters including control characters
        if username.contains('\0') || username.contains('\r') || username.contains('\n') {
            return Err(AuthError::validation(
                "Username contains invalid characters".to_string(),
            ));
        }

        // Check for control characters (0x01-0x1F and 0x7F-0x9F)
        if username.chars().any(|c| c.is_control()) {
            return Err(AuthError::validation(
                "Username contains control characters".to_string(),
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
        // Remove null bytes and control characters except newlines/tabs and spaces
        input
            .chars()
            .filter(|&c| !c.is_control() || c == '\n' || c == '\t' || c == ' ')
            .collect()
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

        // Check for multiple @ symbols
        if sanitized.matches('@').count() != 1 {
            return Err(AuthError::validation("Invalid email format".to_string()));
        }

        let parts: Vec<&str> = sanitized.split('@').collect();
        let local_part = parts[0];
        let domain_part = parts[1];

        // Check local part
        if local_part.is_empty() || local_part.starts_with('.') || local_part.ends_with('.') {
            return Err(AuthError::validation("Invalid email format".to_string()));
        }

        // Check domain part
        if domain_part.is_empty()
            || domain_part.starts_with('.')
            || domain_part.ends_with('.')
            || domain_part.contains("..")
            || !domain_part.contains('.')
        {
            return Err(AuthError::validation("Invalid email format".to_string()));
        }

        // Check for spaces in email
        if sanitized.contains(' ') {
            return Err(AuthError::validation("Invalid email format".to_string()));
        }

        Ok(sanitized)
    }
}

/// Performs constant-time comparison of two byte slices to prevent timing attacks.
///
/// This function compares two byte slices in constant time, meaning the execution
/// time does not depend on where the first difference occurs. This is crucial for
/// security-sensitive comparisons like tokens, passwords, or MAC verification.
///
/// # Arguments
///
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
///
/// * `true` if the byte slices are equal, `false` otherwise
///
/// # Security Notes
///
/// This function is designed to prevent timing attacks by ensuring that the
/// comparison time remains constant regardless of input values.
///
/// # Example
///
/// ```rust
/// use auth_framework::security::secure_utils::constant_time_compare;
///
/// let token1 = b"secure_token_value";
/// let token2 = b"secure_token_value";
/// let token3 = b"different_token";
///
/// assert!(constant_time_compare(token1, token2));
/// assert!(!constant_time_compare(token1, token3));
/// ```
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    SecureComparison::constant_time_eq_bytes(a, b)
}

/// Generates a cryptographically secure random token as a base64-encoded string.
///
/// This function creates a secure random token suitable for use as session tokens,
/// API keys, or other security-sensitive identifiers. The token is base64url-encoded
/// for safe use in URLs and HTTP headers.
///
/// # Arguments
///
/// * `byte_length` - The number of random bytes to generate before encoding
///
/// # Returns
///
/// * `Ok(String)` - A base64url-encoded random token
/// * `Err(AuthError)` - If random number generation fails
///
/// # Security Notes
///
/// - Uses cryptographically secure random number generation
/// - The output length will be approximately 4/3 times the input byte length due to base64 encoding
/// - Tokens are suitable for cryptographic purposes
///
/// # Example
///
/// ```rust
/// use auth_framework::security::secure_utils::generate_secure_token;
///
/// // Generate a 256-bit (32-byte) token
/// let token = generate_secure_token(32).unwrap();
/// println!("Generated token: {}", token);
/// ```
pub fn generate_secure_token(byte_length: usize) -> Result<String> {
    SecureRandomGen::generate_string(byte_length)
}

/// Hashes a password using bcrypt with a secure cost factor.
///
/// This function uses the bcrypt algorithm to hash passwords with a predefined
/// cost factor. Bcrypt is designed to be computationally expensive to prevent
/// brute-force attacks and includes automatic salt generation.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash
///
/// # Returns
///
/// * `Ok(String)` - The bcrypt hash including salt and cost parameters
/// * `Err(AuthError)` - If hashing fails or password is invalid
///
/// # Security Notes
///
/// - Uses bcrypt's default cost factor (currently 12)
/// - Each hash includes a unique random salt
/// - The same password will produce different hashes due to random salting
/// - Empty passwords are rejected for security
///
/// # Example
///
/// ```rust
/// use auth_framework::security::secure_utils::hash_password;
///
/// let password = "user_password_123";
/// let hash = hash_password(password).unwrap();
/// println!("Password hash: {}", hash);
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    if password.is_empty() {
        return Err(AuthError::validation(
            "Password cannot be empty".to_string(),
        ));
    }

    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AuthError::crypto(format!("Password hashing failed: {}", e)))
}

/// Verifies a plaintext password against a bcrypt hash.
///
/// This function uses bcrypt to verify that a plaintext password matches
/// a previously generated hash. The verification is performed in constant
/// time to prevent timing attacks.
///
/// # Arguments
///
/// * `password` - The plaintext password to verify
/// * `hash` - The bcrypt hash to verify against
///
/// # Returns
///
/// * `Ok(true)` if the password matches the hash
/// * `Ok(false)` if the password does not match the hash
/// * `Err(AuthError)` if verification fails due to an invalid hash format
///
/// # Security Notes
///
/// - Verification is performed in constant time
/// - The hash must be a valid bcrypt hash including salt and cost parameters
/// - Invalid hash formats will result in an error rather than false
///
/// # Example
///
/// ```rust
/// use auth_framework::security::secure_utils::{hash_password, verify_password};
///
/// let password = "user_password_123";
/// let hash = hash_password(password).unwrap();
///
/// assert!(verify_password(password, &hash).unwrap());
/// assert!(!verify_password("wrong_password", &hash).unwrap());
/// ```
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
    }

    #[test]
    fn test_email_validation() {
        assert!(SecureValidation::validate_email("test@example.com").is_ok());
        assert!(SecureValidation::validate_email("").is_err());
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

    #[test]
    fn test_secure_string_zeroization() {
        let secret = SecureString::new("sensitive_data".to_string());
        let _ptr = secret.as_str().as_ptr();

        // Verify content before drop
        assert_eq!(secret.as_str(), "sensitive_data");
        drop(secret);

        // After drop, we can't verify zeroization directly due to Rust safety,
        // but this test ensures the SecureString type is working correctly
    }

    #[test]
    fn test_constant_time_comparison_edge_cases() {
        // Test empty strings
        assert!(SecureComparison::constant_time_eq("", ""));
        assert!(!SecureComparison::constant_time_eq("", "nonempty"));
        assert!(!SecureComparison::constant_time_eq("nonempty", ""));

        // Test very long strings
        let long1 = "a".repeat(1000);
        let long2 = "a".repeat(1000);
        let long3 = "b".repeat(1000);

        assert!(SecureComparison::constant_time_eq(&long1, &long2));
        assert!(!SecureComparison::constant_time_eq(&long1, &long3));

        // Test strings that differ only in the last character
        let almost_same1 = "verylongstringtestX";
        let almost_same2 = "verylongstringtestY";
        assert!(!SecureComparison::constant_time_eq(
            almost_same1,
            almost_same2
        ));
    }

    #[test]
    fn test_secure_random_generation_uniqueness() {
        let mut tokens = std::collections::HashSet::new();

        // Generate multiple tokens and ensure they're unique
        for _ in 0..100 {
            let token = SecureRandomGen::generate_token().unwrap();
            assert!(!tokens.contains(&token), "Generated duplicate token");
            tokens.insert(token);
        }
    }

    #[test]
    fn test_secure_random_generation_length() {
        // Test different lengths
        for byte_len in [8, 16, 32, 64] {
            let token = SecureRandomGen::generate_string(byte_len).unwrap();
            // Base64url encoding: 4 chars per 3 bytes, no padding
            let expected_len = (byte_len * 4 + 2) / 3;
            assert!(
                token.len() >= expected_len - 2 && token.len() <= expected_len + 2,
                "Token length {} not in expected range for {} bytes",
                token.len(),
                byte_len
            );
        }
    }

    #[test]
    fn test_input_validation_edge_cases() {
        // Test various edge cases for username validation
        let long_username = "a".repeat(320);
        assert!(SecureValidation::validate_username(&long_username).is_ok());
        let too_long_username = "a".repeat(321);
        assert!(SecureValidation::validate_username(&too_long_username).is_err());

        // Control characters
        assert!(SecureValidation::validate_username("user\x01").is_err());
        assert!(SecureValidation::validate_username("user\x1f").is_err());

        // Unicode considerations (basic test)
        assert!(SecureValidation::validate_username("user_ñ").is_ok());
    }

    #[test]
    fn test_email_validation_comprehensive() {
        // Valid emails
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user123@example-domain.com",
            "a@b.co",
            "very.long.email.address@very.long.domain.name.com",
        ];

        for email in valid_emails {
            assert!(
                SecureValidation::validate_email(email).is_ok(),
                "Should accept valid email: {}",
                email
            );
        }

        // Invalid emails
        let invalid_emails = vec![
            "",
            "user",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@example",
            "user @example.com", // Space
            "user@exam ple.com", // Space in domain
            "user@.example.com", // Leading dot
            "user@example..com", // Double dot
            ".user@example.com", // Leading dot in local part
            "user.@example.com", // Trailing dot in local part
        ];

        for email in invalid_emails {
            assert!(
                SecureValidation::validate_email(email).is_err(),
                "Should reject invalid email: {}",
                email
            );
        }
    }

    #[test]
    fn test_input_sanitization_comprehensive() {
        // Test various control characters
        let test_cases = vec![
            ("hello\0world", "helloworld"),             // Null byte
            ("test\x01\x02\x03", "test"),               // Control chars
            ("normal text", "normal text"),             // No change
            ("\x7f", ""),                               // DEL character
            ("mix\0ed\x01cont\x02rol", "mixedcontrol"), // Mixed
            ("", ""),                                   // Empty
            ("   spaced   ", "   spaced   "),           // Preserve normal spaces
        ];

        for (input, expected) in test_cases {
            let result = SecureValidation::sanitize_input(input);
            assert_eq!(result, expected, "Sanitization failed for: {:?}", input);
        }
    }

    #[test]
    fn test_password_hashing_security() {
        let password = "test_password_123";

        // Hash the same password multiple times
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different (due to salt)
        assert_ne!(
            hash1, hash2,
            "Password hashes should be different due to random salt"
        );

        // Both hashes should verify correctly
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());

        // Wrong password should not verify
        assert!(!verify_password("wrong_password", &hash1).unwrap());
        assert!(!verify_password("wrong_password", &hash2).unwrap());
    }

    #[test]
    fn test_password_hashing_edge_cases() {
        // Test empty password
        let result = hash_password("");
        assert!(result.is_err(), "Should reject empty password");

        // Test very long password
        let long_password = "a".repeat(100);
        let hash = hash_password(&long_password).unwrap();
        assert!(verify_password(&long_password, &hash).unwrap());

        // Test password with special characters
        let special_password = "p@ssw0rd!#$%^&*()";
        let hash = hash_password(special_password).unwrap();
        assert!(verify_password(special_password, &hash).unwrap());

        // Test password with Unicode
        let unicode_password = "пароль123测试";
        let hash = hash_password(unicode_password).unwrap();
        assert!(verify_password(unicode_password, &hash).unwrap());
    }

    #[test]
    fn test_secure_comparison_timing() {
        // This test can't verify timing directly, but ensures the function works correctly
        // with various input sizes to ensure it's implemented properly

        let short_a = "a";
        let short_b = "a";
        let long_a = "a".repeat(1000);
        let long_b = "a".repeat(1000);

        assert!(SecureComparison::constant_time_eq(short_a, short_b));
        assert!(SecureComparison::secure_string_compare(short_a, short_b));
        assert!(SecureComparison::verify_token(short_a, short_b));

        assert!(SecureComparison::constant_time_eq(&long_a, &long_b));
        assert!(SecureComparison::secure_string_compare(&long_a, &long_b));
        assert!(SecureComparison::verify_token(&long_a, &long_b));

        let different_short_a = "a";
        let different_short_b = "b";
        let different_long_a = "a".repeat(1000);
        let different_long_b = "b".repeat(1000);

        assert!(!SecureComparison::constant_time_eq(
            different_short_a,
            different_short_b
        ));
        assert!(!SecureComparison::secure_string_compare(
            different_short_a,
            different_short_b
        ));
        assert!(!SecureComparison::verify_token(
            different_short_a,
            different_short_b
        ));

        assert!(!SecureComparison::constant_time_eq(
            &different_long_a,
            &different_long_b
        ));
        assert!(!SecureComparison::secure_string_compare(
            &different_long_a,
            &different_long_b
        ));
        assert!(!SecureComparison::verify_token(
            &different_long_a,
            &different_long_b
        ));
    }

    #[test]
    fn test_secure_string_multiple_operations() {
        let secret1 = SecureString::new("password1".to_string());
        let secret2 = SecureString::new("password2".to_string());

        assert_ne!(secret1.as_str(), secret2.as_str());
        assert!(SecureComparison::verify_token(
            secret1.as_str(),
            secret1.as_str()
        ));
        assert!(!SecureComparison::verify_token(
            secret1.as_str(),
            secret2.as_str()
        ));

        // Test operations
        assert_eq!(secret1.len(), 9);
        assert_eq!(secret2.len(), 9);
        assert!(!secret1.is_empty());
        assert!(!secret2.is_empty());
    }

    #[test]
    fn test_token_verification_false_positives() {
        let token = "secure_token_123";
        let similar_token = "secure_token_124"; // Only last char different
        let prefix_token = "secure_token_12"; // Shorter
        let longer_token = "secure_token_1234"; // Longer

        assert!(SecureComparison::verify_token(token, token));
        assert!(!SecureComparison::verify_token(token, similar_token));
        assert!(!SecureComparison::verify_token(token, prefix_token));
        assert!(!SecureComparison::verify_token(token, longer_token));
    }
}
