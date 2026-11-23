// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cryptographic utility functions for the AuthFramework.

use crate::errors::Result;
use rand::{RngExt, rng};

/// Generate a random alphanumeric token of specified length.
///
/// Delegates to [`generate_secure_token`] internally — both use the same
/// cryptographically secure RNG (`rand::rng()`).  Prefer
/// `generate_secure_token` in new code so callers handle errors explicitly.
pub fn generate_token(length: usize) -> String {
    // Unwrap is safe: generate_secure_token currently cannot fail,
    // but if it ever does we want to surface the panic rather than
    // silently returning a short/empty token.
    generate_secure_token(length).expect("CSPRNG token generation failed")
}

/// Generate a cryptographically secure random string
pub fn generate_secure_token(length: usize) -> Result<String> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789";
    let token: String = (0..length)
        .map(|_| {
            let idx = rng().random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    Ok(token)
}
/// Generate a hex-encoded random token
pub fn generate_hex_token(byte_length: usize) -> Result<String> {
    let mut bytes = vec![0u8; byte_length];
    rng().fill(&mut bytes[..]);
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token = generate_token(32);
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_secure_token() {
        let token = generate_secure_token(32).unwrap();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_hex_token() {
        let token = generate_hex_token(16).unwrap();
        assert_eq!(token.len(), 32); // 16 bytes = 32 hex chars
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
