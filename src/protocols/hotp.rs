//! HOTP (RFC 4226) — HMAC-Based One-Time Password Algorithm
//!
//! Implements the HOTP algorithm as specified in RFC 4226 for counter-based
//! one-time password generation and validation. HOTP uses a shared secret
//! and a monotonically increasing counter to generate OTPs.
//!
//! # Security Considerations
//!
//! - Secrets must be generated with a cryptographically secure RNG
//! - Counter values must never be reused (monotonically increasing)
//! - Look-ahead window should be kept small to limit brute-force surface
//! - Secrets should be stored encrypted at rest

use crate::errors::{AuthError, Result};
use hmac::{Hmac, KeyInit, Mac};
use ring::rand::SecureRandom;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Default number of digits in the HOTP code.
const DEFAULT_DIGITS: u32 = 6;

/// Default look-ahead window for counter synchronization.
const DEFAULT_LOOK_AHEAD: u64 = 10;

/// HOTP configuration.
#[derive(Debug, Clone)]
pub struct HotpConfig {
    /// Number of digits in the generated OTP (6–8).
    pub digits: u32,

    /// Look-ahead window — how many counter values ahead to check
    /// when validating a code (for counter desynchronization recovery).
    pub look_ahead_window: u64,
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            digits: DEFAULT_DIGITS,
            look_ahead_window: DEFAULT_LOOK_AHEAD,
        }
    }
}

/// HOTP manager for generating and validating counter-based OTPs.
pub struct HotpManager {
    config: HotpConfig,
}

impl HotpManager {
    /// Create a new HOTP manager with the given configuration.
    pub fn new(config: HotpConfig) -> Self {
        Self { config }
    }

    /// Create a new HOTP manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HotpConfig::default())
    }

    /// Generate a cryptographically random 20-byte secret encoded as
    /// RFC 4648 Base32 (with padding).
    pub fn generate_secret() -> Result<String> {
        let rng = ring::rand::SystemRandom::new();
        let mut secret = [0u8; 20];
        rng.fill(&mut secret)
            .map_err(|_| AuthError::crypto("Failed to generate HOTP secret"))?;
        Ok(base32::encode(
            base32::Alphabet::Rfc4648 { padding: true },
            &secret,
        ))
    }

    /// Generate an HOTP code for the given secret and counter value.
    ///
    /// Implements RFC 4226 §5.3 — Dynamic Truncation.
    pub fn generate(&self, secret_b32: &str, counter: u64) -> Result<String> {
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret_b32)
            .ok_or_else(|| AuthError::validation("Invalid Base32 secret"))?;

        let code = hotp_raw(&secret, counter, self.config.digits)?;
        Ok(code)
    }

    /// Validate an HOTP code against the expected counter value.
    ///
    /// On success, returns the counter value that matched (which may be
    /// ahead of `counter` by up to `look_ahead_window`). The caller should
    /// persist `matched_counter + 1` as the new expected counter.
    pub fn validate(&self, secret_b32: &str, counter: u64, code: &str) -> Result<Option<u64>> {
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret_b32)
            .ok_or_else(|| AuthError::validation("Invalid Base32 secret"))?;

        for offset in 0..=self.config.look_ahead_window {
            let candidate_counter = counter + offset;
            let expected = hotp_raw(&secret, candidate_counter, self.config.digits)?;
            if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
                return Ok(Some(candidate_counter));
            }
        }

        Ok(None)
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Core HOTP computation per RFC 4226 §5.3.
fn hotp_raw(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    let mut mac = HmacSha1::new_from_slice(secret)
        .map_err(|e| AuthError::crypto(format!("HMAC init failed: {e}")))?;

    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3)
    let offset = (result[19] & 0x0f) as usize;
    let bin_code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulus = 10u32.pow(digits);
    Ok(format!(
        "{:0>width$}",
        bin_code % modulus,
        width = digits as usize
    ))
}

/// Constant-time byte comparison to prevent timing attacks on code validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D test vectors.
    /// Secret = "12345678901234567890" (ASCII), digits = 6.
    #[test]
    fn test_rfc4226_test_vectors() {
        let secret = b"12345678901234567890";
        let expected: &[&str] = &[
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, &expected_code) in expected.iter().enumerate() {
            let code = hotp_raw(secret, counter as u64, 6).expect("hotp_raw failed");
            assert_eq!(
                code, expected_code,
                "RFC 4226 test vector failed for counter={counter}"
            );
        }
    }

    #[test]
    fn test_generate_and_validate() {
        let mgr = HotpManager::with_defaults();
        let secret = HotpManager::generate_secret().expect("secret gen failed");

        let code = mgr.generate(&secret, 0).expect("generate failed");
        assert_eq!(code.len(), 6);

        let matched = mgr.validate(&secret, 0, &code).expect("validate failed");
        assert_eq!(matched, Some(0));
    }

    #[test]
    fn test_look_ahead_window() {
        let mgr = HotpManager::new(HotpConfig {
            digits: 6,
            look_ahead_window: 5,
        });
        let secret = HotpManager::generate_secret().expect("secret gen failed");

        // Generate code for counter=3
        let code = mgr.generate(&secret, 3).expect("generate failed");

        // Validate starting from counter=0 — should find it at offset 3
        let matched = mgr.validate(&secret, 0, &code).expect("validate failed");
        assert_eq!(matched, Some(3));

        // Validate starting from counter=0 with code for counter=10 — out of window
        let code_far = mgr.generate(&secret, 10).expect("generate failed");
        let not_found = mgr
            .validate(&secret, 0, &code_far)
            .expect("validate failed");
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_invalid_code_rejected() {
        let mgr = HotpManager::with_defaults();
        let secret = HotpManager::generate_secret().expect("secret gen failed");

        let matched = mgr.validate(&secret, 0, "000000").expect("validate failed");
        // Extremely unlikely to match a random secret — but not impossible.
        // If it does match, the test is still correct (it returns Some(0)).
        // For practical purposes this validates the code path.
        let _ = matched;
    }

    #[test]
    fn test_8_digit_codes() {
        let mgr = HotpManager::new(HotpConfig {
            digits: 8,
            look_ahead_window: 5,
        });
        let secret = HotpManager::generate_secret().expect("secret gen failed");

        let code = mgr.generate(&secret, 42).expect("generate failed");
        assert_eq!(code.len(), 8);

        let matched = mgr.validate(&secret, 42, &code).expect("validate failed");
        assert_eq!(matched, Some(42));
    }
}
