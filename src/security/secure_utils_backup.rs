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
        // Remove null bytes and control characters except newlines/tabs and spaces
        input
            .chars()
            .filter(|&c| !char::is_control(c) || c == '\n' || c == '\t' || c == ' ')
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
            || !domain_part.contains('.') {
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
/// use auth_framework::secure_utils::constant_time_compare;
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
/// CSRF tokens, or other security-sensitive identifiers. The token is generated
/// using a cryptographically secure random number generator.
///
/// # Arguments
///
/// * `byte_len` - Number of random bytes to generate before base64 encoding
///
/// # Returns
///
/// A base64-encoded string containing the secure random token. If secure random
/// generation fails, falls back to generating a UUID.
///
/// # Security Notes
///
/// The generated token has sufficient entropy for cryptographic use. A 32-byte
/// input produces a token with 256 bits of entropy.
///
/// # Example
///
/// ```rust
/// use auth_framework::secure_utils::generate_secure_token;
///
/// // Generate a 32-byte secure token (256 bits of entropy)
/// let token = generate_secure_token(32);
/// println!("Secure token: {}", token);
///
/// // Generate a shorter token for less critical uses
/// let csrf_token = generate_secure_token(16);
/// ```
pub fn generate_secure_token(byte_len: usize) -> String {
    SecureRandomGen::generate_string(byte_len).unwrap_or_else(|_| {
        // Fallback to UUID if secure random fails
        uuid::Uuid::new_v4().to_string()
    })
}

/// Hashes a password using bcrypt with a secure cost factor.
///
/// This function uses bcrypt to hash passwords with a default cost factor that
/// provides good security while maintaining reasonable performance. The bcrypt
/// algorithm includes salt generation automatically.
///
/// # Arguments
///
/// * `password` - The plaintext password to hash
///
/// # Returns
///
/// * `Ok(String)` containing the bcrypt hash of the password
/// * `Err(AuthError)` if hashing fails
///
/// # Security Notes
///
/// - Uses bcrypt's default cost factor (currently 12)
/// - Automatically generates a unique salt for each password
/// - The resulting hash includes the salt and cost parameters
///
/// # Example
///
/// ```rust
/// use auth_framework::secure_utils::hash_password;
///
/// let password = "user_password_123";
/// let hash = hash_password(password)?;
/// println!("Password hash: {}", hash);
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AuthError::crypto(format!("Password hashing failed: {}", e)))
}

/// Verifies a plaintext password against a bcrypt hash.
///     .map_err(|e| AuthError::crypto(format!("Password hashing failed: {}", e)))
/// This function uses bcrypt to verify that a plaintext password matches
/// a previously generated hash. The verification is performed in constant
/// time to prevent timing attacks.gainst a bcrypt hash.
///
/// # Argumentson uses bcrypt to verify that a plaintext password matches
/// a previously generated hash. The verification is performed in constant
/// * `password` - The plaintext password to verify
/// * `hash` - The bcrypt hash to verify against
/// # Arguments
/// # Returns
/// * `password` - The plaintext password to verify
/// * `Ok(true)` if the password matches the hash
/// * `Ok(false)` if the password does not match the hash
/// * `Err(AuthError)` if verification fails due to an invalid hash format
///
/// # Security Notesthe password matches the hash
/// * `Ok(false)` if the password does not match the hash
/// - Verification is performed in constant time to an invalid hash format
/// - The hash must be a valid bcrypt hash including salt and cost parameters
/// - Invalid hash formats will result in an error rather than false
///
/// # Exampleation is performed in constant time
/// - The hash must be a valid bcrypt hash including salt and cost parameters
/// ```rustid hash formats will result in an error rather than false
/// use auth_framework::secure_utils::{hash_password, verify_password};
/// # Example
/// let password = "user_password_123";
/// let hash = hash_password(password)?;
/// use auth_framework::secure_utils::{hash_password, verify_password};
/// // Verify correct password
/// assert!(verify_password(password, &hash)?);
/// let hash = hash_password(password)?;
/// // Verify incorrect password
/// assert!(!verify_password("wrong_password", &hash)?);
/// ```ert!(verify_password(password, &hash)?);
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    bcrypt::verify(password, hash)
        .map_err(|e| AuthError::crypto(format!("Password verification failed: {}", e)))
}// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
#[cfg(test)]verify(password, hash)
mod tests {p_err(|e| AuthError::crypto(format!("Password verification failed: {}", e)))
    use super::*;

    #[test]]
    fn test_secure_string() {
        let secret = SecureString::new("password123".to_string());
        assert_eq!(secret.as_str(), "password123");
        assert_eq!(secret.len(), 11);
        // SecureString will be zeroized when dropped
    }   let secret = SecureString::new("password123".to_string());
        assert_eq!(secret.as_str(), "password123");
    #[test]ert_eq!(secret.len(), 11);
    fn test_constant_time_comparison() { when dropped
        assert!(SecureComparison::constant_time_eq("hello", "hello"));
        assert!(!SecureComparison::constant_time_eq("hello", "world"));
        assert!(!SecureComparison::constant_time_eq("hello", "hello world"));
    }n test_constant_time_comparison() {
        assert!(SecureComparison::constant_time_eq("hello", "hello"));
    #[test]ert!(!SecureComparison::constant_time_eq("hello", "world"));
    fn test_secure_string_compare() {nstant_time_eq("hello", "hello world"));
        assert!(SecureComparison::secure_string_compare("test", "test"));
        assert!(!SecureComparison::secure_string_compare(
            "test",
            "different"ng_compare() {
        ));ert!(SecureComparison::secure_string_compare("test", "test"));
        assert!(!SecureComparison::secure_string_compare("short", "longer"));
    }       "test",
            "different"
    #[test]
    fn test_token_verification() {:secure_string_compare("short", "longer"));
        let token = "abc123def456";
        assert!(SecureComparison::verify_token(token, token));
        assert!(!SecureComparison::verify_token(token, "different"));
    }n test_token_verification() {
        let token = "abc123def456";
    #[test]ert!(SecureComparison::verify_token(token, token));
    fn test_secure_random_generation() {y_token(token, "different"));
        let token1 = SecureRandomGen::generate_token().unwrap();
        let token2 = SecureRandomGen::generate_token().unwrap();
    #[test]
        assert_ne!(token1, token2);n() {
        assert!(!token1.is_empty());::generate_token().unwrap();
        assert!(!token2.is_empty());::generate_token().unwrap();
    }
        assert_ne!(token1, token2);
    #[test]ert!(!token1.is_empty());
    fn test_input_validation() {());
        assert!(SecureValidation::validate_username("user123").is_ok());
        assert!(SecureValidation::validate_username("").is_err());
        assert!(SecureValidation::validate_username("user\0name").is_err());
    fn test_input_validation() {
        assert!(SecureValidation::validate_password("password123").is_ok());
        assert!(SecureValidation::validate_password("").is_err());
        assert!(SecureValidation::validate_password("pass\0word").is_err());
    }
        assert!(SecureValidation::validate_password("password123").is_ok());
    #[test]ert!(SecureValidation::validate_password("").is_err());
    fn test_email_validation() {::validate_password("pass\0word").is_err());
        assert!(SecureValidation::validate_email("user@example.com").is_ok());
        assert!(SecureValidation::validate_email("invalid").is_err());
        assert!(SecureValidation::validate_email("@example.com").is_err());
        assert!(SecureValidation::validate_email("user@").is_err());
    }   assert!(SecureValidation::validate_email("user@example.com").is_ok());
        assert!(SecureValidation::validate_email("invalid").is_err());
    #[test]ert!(SecureValidation::validate_email("@example.com").is_err());
    fn test_input_sanitization() {validate_email("user@").is_err());
        let dirty = "hello\0world\x01test";
        let clean = SecureValidation::sanitize_input(dirty);
        assert_eq!(clean, "helloworldtest");
    fn test_input_sanitization() {
        let with_newlines = "line1\nline2\tline3";
        let cleaned = SecureValidation::sanitize_input(with_newlines);
        assert_eq!(cleaned, "line1\nline2\tline3");
    }
        let with_newlines = "line1\nline2\tline3";
    #[test] cleaned = SecureValidation::sanitize_input(with_newlines);
    fn test_secure_string_zeroization() {\tline3");
        let secret = SecureString::new("sensitive_data".to_string());
        let _ptr = secret.as_str().as_ptr();
    #[test]
        // Verify content before drop() {
        assert_eq!(secret.as_str(), "sensitive_data");".to_string());
        let _ptr = secret.as_str().as_ptr();
        drop(secret);
        // Verify content before drop
        // After drop, we can't verify zeroization directly due to Rust safety,
        // but this test ensures the SecureString type is working correctly
    }   drop(secret);

    #[test]After drop, we can't verify zeroization directly due to Rust safety,
    fn test_constant_time_comparison_edge_cases() {ype is working correctly
        // Test empty strings
        assert!(SecureComparison::constant_time_eq("", ""));
        assert!(!SecureComparison::constant_time_eq("", "nonempty"));
        assert!(!SecureComparison::constant_time_eq("nonempty", ""));
        // Test empty strings
        // Test very long strings:constant_time_eq("", ""));
        let long1 = "a".repeat(1000);nstant_time_eq("", "nonempty"));
        let long2 = "a".repeat(1000);nstant_time_eq("nonempty", ""));
        let long3 = "b".repeat(1000);
        // Test very long strings
        assert!(SecureComparison::constant_time_eq(&long1, &long2));
        assert!(!SecureComparison::constant_time_eq(&long1, &long3));
        let long3 = "b".repeat(1000);
        // Test strings that differ only in the last character
        assert!(!SecureComparison::constant_time_eq(long1, &long2));
            "password1",omparison::constant_time_eq(&long1, &long3));
            "password2"
        ));Test strings that differ only in the last character
        assert!(!SecureComparison::constant_time_eq(
            "verylongpassword1",
            "verylongpassword2"
        ));
    }   assert!(!SecureComparison::constant_time_eq(
            "verylongpassword1",
    #[test] "verylongpassword2"
    fn test_secure_random_generation_uniqueness() {
        // Generate multiple tokens and ensure they're all unique
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..1000 {
            let token = SecureRandomGen::generate_token().unwrap();
            assert!(multiple tokens and ensure they're all unique
                !tokens.contains(&token),::HashSet::new();
                "Generated duplicate token: {}",
                token = SecureRandomGen::generate_token().unwrap();
            );sert!(
            tokens.insert(token);&token),
        }       "Generated duplicate token: {}",
    }           token
            );
    #[test] tokens.insert(token);
    fn test_secure_random_generation_length() {
        let token = SecureRandomGen::generate_token().unwrap();
        // Base64 encoding of 32 bytes should be 44 characters (with potential padding)
        assert!(
            token.len() >= 40 && token.len() <= 48,
            "Token length unexpected: {}",ate_token().unwrap();
            token.len()ing of 32 bytes should be 44 characters (with potential padding)
        );sert!(
            token.len() >= 40 && token.len() <= 48,
        // Verify it's valid base64d: {}",
        assert!(n.len()
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&token)
                .is_ok(),lid base64
            "Token should be valid base64"
        );  base64::engine::general_purpose::URL_SAFE_NO_PAD
    }           .decode(&token)
                .is_ok(),
    #[test] "Token should be valid base64"
    fn test_input_validation_edge_cases() {
        // Test username edge cases
        assert!(SecureValidation::validate_username("a").is_ok()); // Minimum length
        assert!(SecureValidation::validate_username(&"a".repeat(255)).is_ok()); // Long but valid
        assert!(SecureValidation::validate_username("user-name_123").is_ok()); // Special chars
        assert!(SecureValidation::validate_username("user.name@domain").is_err()); // Invalid chars
        assert!(SecureValidation::validate_username(&"a".repeat(256)).is_err()); // Too long
        assert!(SecureValidation::validate_username(&"a".repeat(255)).is_ok()); // Long but valid
        // Test password edge casesalidate_username("user-name_123").is_ok()); // Special chars
        assert!(SecureValidation::validate_password("a").is_err()); // Too short); // Invalid chars
        assert!(SecureValidation::validate_password("password").is_ok()); // Minimum validng
        assert!(SecureValidation::validate_password(&"a".repeat(1000)).is_ok()); // Very long
        // Test password edge cases
        // Test with Unicode charactersate_password("a").is_err()); // Too short
        assert!(SecureValidation::validate_username("用户123").is_err()); // Unicode in username
        assert!(SecureValidation::validate_password("пароль123").is_ok()); // Unicode in password OK
    }
        // Test with Unicode characters
    #[test]ert!(SecureValidation::validate_username("用户123").is_err()); // Unicode in username
    fn test_email_validation_comprehensive() {sword("пароль123").is_ok()); // Unicode in password OK
        // Valid emails
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",ensive() {
            "user+tag@example.com",
            "user123@example-domain.com",
            "a@b.co",mple.com",
            "very.long.email.address@very.long.domain.name.com",
        ];  "user+tag@example.com",
            "user123@example-domain.com",
        for email in valid_emails {
            assert!(ng.email.address@very.long.domain.name.com",
                SecureValidation::validate_email(email).is_ok(),
                "Should accept valid email: {}",
                emailvalid_emails {
            );sert!(
        }       SecureValidation::validate_email(email).is_ok(),
                "Should accept valid email: {}",
        // Invalid emails
        let invalid_emails = vec![
            "",
            "user",
            "@example.com",
            "user@",emails = vec![
            "user@@example.com",
            "user@example",
            "user @example.com", // Space
            "user@exam ple.com", // Space in domain
            "user@.example.com", // Leading dot
            "user@example..com", // Double dot
            ".user@example.com", // Leading dot in local part
            "user.@example.com", // Trailing dot in local part
        ];  "user@.example.com", // Leading dot
            "user@example..com", // Double dot
        for email in invalid_emails {eading dot in local part
            assert!(xample.com", // Trailing dot in local part
                SecureValidation::validate_email(email).is_err(),
                "Should reject invalid email: {}",
                emailinvalid_emails {
            );sert!(
        }       SecureValidation::validate_email(email).is_err(),
    }           "Should reject invalid email: {}",
                email
    #[test] );
    fn test_input_sanitization_comprehensive() {
        // Test various control characters
        let test_cases = vec![
            ("hello\0world", "helloworld"),             // Null byte
            ("test\x01\x02\x03", "test"),               // Control chars
            ("normal text", "normal text"),             // No change
            ("\x7f", ""),                               // DEL character
            ("mix\0ed\x01cont\x02rol", "mixedcontrol"), // Mixedbyte
            ("", ""),                                   // Emptyol chars
            ("   spaced   ", "   spaced   "),           // Preserve normal spaces
        ];  ("\x7f", ""),                               // DEL character
            ("mix\0ed\x01cont\x02rol", "mixedcontrol"), // Mixed
        for (input, expected) in test_cases {           // Empty
            let result = SecureValidation::sanitize_input(input);ve normal spaces
            assert_eq!(result, expected, "Sanitization failed for: {:?}", input);
        }
    }   for (input, expected) in test_cases {
            let result = SecureValidation::sanitize_input(input);
    #[test] assert_eq!(result, expected, "Sanitization failed for: {:?}", input);
    fn test_password_hashing_security() {
        let password = "test_password_123";

        // Hash the same password multiple times
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Hashes should be different (due to salt)
        assert_ne!( hash_password(password).unwrap();
            hash1, hash2,password(password).unwrap();
            "Password hashes should be different due to random salt"
        ); Hashes should be different (due to salt)
        assert_ne!(
        // Both hashes should verify correctly
        assert!(verify_password(password, &hash1).unwrap());om salt"
        assert!(verify_password(password, &hash2).unwrap());

        // Wrong password should not verifytly
        assert!(!verify_password("wrong_password", &hash1).unwrap());
        assert!(!verify_password("wrong_password", &hash2).unwrap());
    }
        // Wrong password should not verify
    #[test]ert!(!verify_password("wrong_password", &hash1).unwrap());
    fn test_password_hashing_edge_cases() {sword", &hash2).unwrap());
        // Test empty password
        let result = hash_password("");
        assert!(result.is_err(), "Should reject empty password");
    fn test_password_hashing_edge_cases() {
        // Test very long password
        let long_password = "a".repeat(100);
        let hash = hash_password(&long_password).unwrap();word");
        assert!(verify_password(&long_password, &hash).unwrap());
        // Test very long password
        // Test password with special characters
        let special_password = "p@ssw0rd!#$%^&*()";wrap();
        let hash = hash_password(special_password).unwrap();p());
        assert!(verify_password(special_password, &hash).unwrap());
        // Test password with special characters
        // Test password with Unicode0rd!#$%^&*()";
        let unicode_password = "пароль123测试";word).unwrap();
        let hash = hash_password(unicode_password).unwrap();rap());
        assert!(verify_password(unicode_password, &hash).unwrap());
    }   // Test password with Unicode
        let unicode_password = "пароль123测试";
    #[test] hash = hash_password(unicode_password).unwrap();
    fn test_secure_comparison_timing() {password, &hash).unwrap());
        // This test can't verify timing directly, but ensures the function works correctly
        // with various input sizes to ensure it's implemented properly
    #[test]
        let short_a = "a";son_timing() {
        let short_b = "a"; verify timing directly, but ensures the function works correctly
        let long_a = "a".repeat(1000); ensure it's implemented properly
        let long_b = "a".repeat(1000);
        let short_a = "a";
        assert!(SecureComparison::constant_time_eq(short_a, short_b));
        assert!(SecureComparison::secure_string_compare(short_a, short_b));
        assert!(SecureComparison::verify_token(short_a, short_b));

        assert!(SecureComparison::constant_time_eq(&long_a, &long_b));
        assert!(SecureComparison::secure_string_compare(&long_a, &long_b));
        assert!(SecureComparison::verify_token(&long_a, &long_b));

        let different_short_a = "a";nstant_time_eq(&long_a, &long_b));
        let different_short_b = "b";cure_string_compare(&long_a, &long_b));
        let different_long_a = "a".repeat(1000);long_a, &long_b));
        let different_long_b = "b".repeat(1000);
        let different_short_a = "a";
        assert!(!SecureComparison::constant_time_eq(
            different_short_a, "a".repeat(1000);
            different_short_b= "b".repeat(1000);
        ));
        assert!(!SecureComparison::secure_string_compare(
            different_short_a,
            different_short_b
        ));
        assert!(!SecureComparison::verify_token(_compare(
            different_short_a,
            different_short_b
        ));
        assert!(!SecureComparison::verify_token(
        assert!(!SecureComparison::constant_time_eq(
            &different_long_a,
            &different_long_b
        ));
        assert!(!SecureComparison::secure_string_compare(
            &different_long_a,
            &different_long_b
        ));
        assert!(!SecureComparison::verify_token(_compare(
            &different_long_a,
            &different_long_b
        ));
    }   assert!(!SecureComparison::verify_token(
            &different_long_a,
    #[test] &different_long_b
    fn test_secure_string_multiple_operations() {
        let secret = SecureString::new("initial_secret".to_string());

        // Test multiple access operations
        assert_eq!(secret.as_str(), "initial_secret");
        assert_eq!(secret.len(), 14);w("initial_secret".to_string());

        // Test that the string contents remain consistent
        let content1 = secret.as_str();itial_secret");
        let content2 = secret.as_str();
        assert_eq!(content1, content2);
        // Test that the string contents remain consistent
        // The secret should be zeroized when dropped
        drop(secret);= secret.as_str();
    }   assert_eq!(content1, content2);

    #[test]The secret should be zeroized when dropped
    fn test_token_verification_false_positives() {
        // Ensure token verification doesn't have false positives
        let original_token = "secure_token_12345";
    #[test]
        let similar_tokens = vec![se_positives() {
            "secure_token_12346",  // Last digit differentsitives
            "Secure_token_12345",  // Case different
            "secure_token_123456", // Extra character
            "secure_token_1234",   // Missing character
            "",                    // Emptydigit different
            "completely_different",// Case different
        ];  "secure_token_123456", // Extra character
            "secure_token_1234",   // Missing character
        for similar in similar_tokens {mpty
            assert!(ely_different",
                !SecureComparison::verify_token(original_token, similar),
                "Should not verify similar token: {}",
                similarsimilar_tokens {
            );sert!(
        }       !SecureComparison::verify_token(original_token, similar),
    }           "Should not verify similar token: {}",
}               similar
            );
        }
    }
}
