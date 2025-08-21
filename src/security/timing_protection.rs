//! Timing attack protection utilities
//!
//! This module provides utilities to prevent timing side-channel attacks,
//! particularly important for authentication frameworks where attackers
//! could exploit timing differences to extract sensitive information.

use crate::errors::Result;
use rand::Rng;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Perform constant-time comparison of byte arrays
///
/// This function provides protection against timing attacks by ensuring
/// the comparison takes the same amount of time regardless of where the
/// first difference occurs.
///
/// # Arguments
/// * `a` - First byte array to compare
/// * `b` - Second byte array to compare
///
/// # Returns
/// `true` if arrays are equal, `false` otherwise
///
/// # Security
/// Uses the `subtle` crate's constant-time comparison to prevent
/// timing side-channel attacks.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Add a small random delay to mask timing patterns
///
/// This function adds a small, random delay to help mask timing patterns
/// that could be exploited by attackers. Useful for authentication
/// operations where you want to prevent timing analysis.
///
/// # Arguments
/// * `base_delay_ms` - Base delay in milliseconds (default: 0)
/// * `max_random_ms` - Maximum additional random delay in milliseconds (default: 10)
///
/// # Security
/// The random delay helps prevent attackers from using timing analysis
/// to determine success/failure patterns or extract sensitive information.
pub async fn random_delay(base_delay_ms: u64, max_random_ms: u64) {
    let base_delay = Duration::from_millis(base_delay_ms);
    let random_delay = Duration::from_millis(rand::thread_rng().gen_range(0..max_random_ms));
    let total_delay = base_delay + random_delay;

    tokio::time::sleep(total_delay).await;
}

/// Perform a constant-time string comparison
///
/// Compares two strings in constant time to prevent timing attacks.
///
/// # Arguments
/// * `a` - First string to compare
/// * `b` - Second string to compare
///
/// # Returns
/// `true` if strings are equal, `false` otherwise
pub fn constant_time_string_compare(a: &str, b: &str) -> bool {
    constant_time_compare(a.as_bytes(), b.as_bytes())
}

/// Wrapper for sensitive authentication operations with timing protection
///
/// This function wraps sensitive operations with timing protection,
/// ensuring that both success and failure cases take similar amounts of time.
///
/// # Arguments
/// * `operation` - The async operation to perform
/// * `min_duration_ms` - Minimum time the operation should take
///
/// # Returns
/// The result of the operation
///
/// # Security
/// Ensures that timing differences don't leak information about the
/// success or failure of the operation.
pub async fn timing_safe_operation<T, F, Fut>(operation: F, min_duration_ms: u64) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let start = std::time::Instant::now();
    let result = operation().await;
    let elapsed = start.elapsed();

    let min_duration = Duration::from_millis(min_duration_ms);
    if elapsed < min_duration {
        let remaining = min_duration - elapsed;
        tokio::time::sleep(remaining).await;
    }

    result
}

/// RSA operation wrapper with blinding protection
///
/// This is a placeholder for RSA operations that need timing protection.
/// In a real implementation, this would use RSA blinding techniques
/// to prevent timing attacks on RSA operations.
///
/// # Security Note
/// This is a placeholder implementation. For production use with RSA
/// operations, consider using the `ring` crate or other cryptographic
/// libraries that implement proper RSA blinding.
pub async fn rsa_operation_protected<T, F, Fut>(operation: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    // Add random delay before operation
    random_delay(1, 5).await;

    // Perform the operation with minimum timing
    timing_safe_operation(operation, 10).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hi"));
    }

    #[test]
    fn test_constant_time_string_compare() {
        assert!(constant_time_string_compare("hello", "hello"));
        assert!(!constant_time_string_compare("hello", "world"));
        assert!(!constant_time_string_compare("hello", "hi"));
    }

    #[tokio::test]
    async fn test_random_delay() {
        let start = std::time::Instant::now();
        random_delay(0, 5).await;
        let elapsed = start.elapsed();

        // Should take at least some time but less than 50ms
        assert!(elapsed >= Duration::from_millis(0));
        assert!(elapsed < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_timing_safe_operation() {
        let start = std::time::Instant::now();

        let result = timing_safe_operation(
            || async { Ok::<_, crate::errors::AuthError>("success") },
            50,
        )
        .await;

        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed >= Duration::from_millis(50));
    }
}


