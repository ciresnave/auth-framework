//! Password utility functions for the AuthFramework.

use crate::errors::{AuthError, Result};
use argon2::{
    Argon2, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Maximum password length to prevent denial-of-service via hashing.
const MAX_PASSWORD_LENGTH: usize = 128;

/// Password strength levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrengthLevel {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

/// Password strength result with level and feedback
#[derive(Debug, Clone)]
pub struct PasswordStrength {
    pub level: PasswordStrengthLevel,
    pub feedback: Vec<String>,
}

/// Hash a password using Argon2id with OWASP-minimum parameters.
pub fn hash_password_argon2id(password: &str) -> Result<String> {
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(AuthError::validation(format!(
            "Password exceeds maximum length of {} bytes",
            MAX_PASSWORD_LENGTH
        )));
    }
    let salt = SaltString::generate(&mut OsRng);
    // OWASP minimum: 46 MiB memory, 1 iteration, 1 degree of parallelism
    let params = Params::new(46 * 1024, 1, 1, None)
        .map_err(|e| AuthError::internal(format!("Invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::internal(format!("Failed to hash password: {}", e)))?;

    Ok(password_hash.to_string())
}

/// Verify a password against its hash.
///
/// The Argon2 parameters are read from the hash itself, so verification
/// works for hashes created with any parameter set.
pub fn verify_password_argon2id(password: &str, hash: &str) -> Result<bool> {
    if password.len() > MAX_PASSWORD_LENGTH {
        return Ok(false);
    }
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AuthError::internal(format!("Invalid password hash: {}", e)))?;

    // Argon2::default() extracts algorithm/params from the PHC string
    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check password strength based on various criteria
pub fn check_password_strength(password: &str) -> PasswordStrength {
    let length = password.len();
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let criteria_met = [has_lowercase, has_uppercase, has_digit, has_special]
        .iter()
        .map(|&b| if b { 1 } else { 0 })
        .sum::<i32>();

    let mut feedback = Vec::new();

    if length < 8 {
        feedback.push("Password should be at least 8 characters long".to_string());
    }
    if !has_lowercase {
        feedback.push("Add lowercase letters".to_string());
    }
    if !has_uppercase {
        feedback.push("Add uppercase letters".to_string());
    }
    if !has_digit {
        feedback.push("Add numbers".to_string());
    }
    if !has_special {
        feedback.push("Add special characters".to_string());
    }

    let level = match (length, criteria_met) {
        (0..=6, _) => PasswordStrengthLevel::Weak,
        (7..=10, 0..=2) => PasswordStrengthLevel::Weak,
        (7..=10, 3) => PasswordStrengthLevel::Medium,
        (7..=10, 4) => PasswordStrengthLevel::Medium,
        (11..=14, 0..=2) => PasswordStrengthLevel::Medium,
        (11..=14, 3..=4) => PasswordStrengthLevel::Strong,
        (15.., 0..=2) => PasswordStrengthLevel::Strong,
        (15.., 3..=4) => PasswordStrengthLevel::VeryStrong,
        _ => PasswordStrengthLevel::VeryStrong,
    };

    PasswordStrength { level, feedback }
}

/// Returns `true` when `level` satisfies the production minimum (Strong or VeryStrong).
pub fn meets_production_strength(level: PasswordStrengthLevel) -> bool {
    matches!(
        level,
        PasswordStrengthLevel::Strong | PasswordStrengthLevel::VeryStrong
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "testpassword123";
        let hash = hash_password_argon2id(password).unwrap();

        assert!(verify_password_argon2id(password, &hash).unwrap());
        assert!(!verify_password_argon2id("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_password_strength() {
        assert_eq!(
            check_password_strength("weak").level,
            PasswordStrengthLevel::Weak
        );
        assert_eq!(
            check_password_strength("Medium123").level,
            PasswordStrengthLevel::Medium
        );
        assert_eq!(
            check_password_strength("Strong123!").level,
            PasswordStrengthLevel::Medium
        );
        assert_eq!(
            check_password_strength("VeryStrong123!@#").level,
            PasswordStrengthLevel::VeryStrong
        );
    }
}
