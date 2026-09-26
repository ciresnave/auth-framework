//! Rate limiting utilities for the AuthFramework.

use crate::errors::{AuthError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate limiter implementation.
///
/// # Example
/// ```rust
/// use auth_framework::utils::rate_limit::RateLimiter;
/// use std::time::Duration;
/// let limiter = RateLimiter::new(5, Duration::from_secs(60));
/// assert!(limiter.is_allowed("client-1"));
/// ```
#[derive(Clone)]
pub struct RateLimiter {
    max_requests: u32,
    window: Duration,
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("max_requests", &self.max_requests)
            .field("window", &self.window)
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(100, Duration::from_secs(60));
    /// ```
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self::with_clock(max_requests, window, Instant::now)
    }

    /// Create a new rate limiter with an injectable clock.
    ///
    /// This is a genuine testing seam, not a workaround: it lets callers
    /// (this crate's own tests, or a consumer's) assert window-expiry
    /// behavior by advancing a controlled clock instead of racing real
    /// wall-clock sleeps against unpredictable scheduling or
    /// instrumentation overhead.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::{Duration, Instant};
    /// let limiter = RateLimiter::with_clock(100, Duration::from_secs(60), Instant::now);
    /// ```
    pub fn with_clock(
        max_requests: u32,
        window: Duration,
        now: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            max_requests,
            window,
            requests: Arc::new(Mutex::new(HashMap::new())),
            now: Arc::new(now),
        }
    }

    /// Check if a request is allowed for the given key.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(2, Duration::from_secs(60));
    /// assert_eq!(limiter.check_rate_limit("k").unwrap(), true);
    /// assert_eq!(limiter.check_rate_limit("k").unwrap(), true);
    /// assert_eq!(limiter.check_rate_limit("k").unwrap(), false);
    /// ```
    pub fn check_rate_limit(&self, key: &str) -> Result<bool> {
        let mut requests = self
            .requests
            .lock()
            .map_err(|_| AuthError::internal("Failed to acquire rate limiter lock".to_string()))?;

        let now = (self.now)();
        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove expired requests
        entry.retain(|&request_time| now.duration_since(request_time) < self.window);

        if entry.len() >= self.max_requests as usize {
            return Ok(false); // Rate limit exceeded
        }

        // Add current request
        entry.push(now);
        Ok(true)
    }

    /// Alias for check_rate_limit for compatibility.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(1, Duration::from_secs(60));
    /// assert!(limiter.is_allowed("k"));
    /// assert!(!limiter.is_allowed("k"));
    /// ```
    pub fn is_allowed(&self, key: &str) -> bool {
        self.check_rate_limit(key).unwrap_or(false)
    }

    /// Alias for get_remaining_requests for compatibility.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(5, Duration::from_secs(60));
    /// assert_eq!(limiter.remaining_requests("k").unwrap(), 5);
    /// ```
    pub fn remaining_requests(&self, key: &str) -> Result<u32> {
        self.get_remaining_requests(key)
    }

    /// Get the number of requests for a key.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(10, Duration::from_secs(60));
    /// limiter.is_allowed("k");
    /// assert_eq!(limiter.get_request_count("k").unwrap(), 1);
    /// ```
    pub fn get_request_count(&self, key: &str) -> Result<usize> {
        let requests = self
            .requests
            .lock()
            .map_err(|_| AuthError::internal("Failed to acquire rate limiter lock".to_string()))?;

        let now = (self.now)();
        if let Some(entry) = requests.get(key) {
            let valid_requests = entry
                .iter()
                .filter(|&&request_time| now.duration_since(request_time) < self.window)
                .count();
            Ok(valid_requests)
        } else {
            Ok(0)
        }
    }

    /// Clean up expired entries.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(10, Duration::from_secs(60));
    /// let removed = limiter.cleanup().unwrap();
    /// assert_eq!(removed, 0);
    /// ```
    pub fn cleanup(&self) -> Result<usize> {
        let mut requests = self
            .requests
            .lock()
            .map_err(|_| AuthError::internal("Failed to acquire rate limiter lock".to_string()))?;

        let now = (self.now)();
        let mut removed_count = 0;

        requests.retain(|_, entry| {
            entry.retain(|&request_time| now.duration_since(request_time) < self.window);
            if entry.is_empty() {
                removed_count += 1;
                false
            } else {
                true
            }
        });

        Ok(removed_count)
    }

    /// Reset rate limit for a specific key.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(1, Duration::from_secs(60));
    /// limiter.is_allowed("k");
    /// limiter.reset("k").unwrap();
    /// assert!(limiter.is_allowed("k"));
    /// ```
    pub fn reset(&self, key: &str) -> Result<()> {
        let mut requests = self
            .requests
            .lock()
            .map_err(|_| AuthError::internal("Failed to acquire rate limiter lock".to_string()))?;

        requests.remove(key);
        Ok(())
    }

    /// Get remaining requests for a key.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::utils::rate_limit::RateLimiter;
    /// use std::time::Duration;
    /// let limiter = RateLimiter::new(5, Duration::from_secs(60));
    /// limiter.is_allowed("k");
    /// assert_eq!(limiter.get_remaining_requests("k").unwrap(), 4);
    /// ```
    pub fn get_remaining_requests(&self, key: &str) -> Result<u32> {
        let count = self.get_request_count(key)?;
        Ok(self.max_requests.saturating_sub(count as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(3, Duration::from_secs(1));
        let key = "test_key";

        // First 3 requests should be allowed
        assert!(limiter.check_rate_limit(key).unwrap());
        assert!(limiter.check_rate_limit(key).unwrap());
        assert!(limiter.check_rate_limit(key).unwrap());

        // 4th request should be denied
        assert!(!limiter.check_rate_limit(key).unwrap());

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check_rate_limit(key).unwrap());
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimiter::new(10, Duration::from_millis(100));

        limiter.check_rate_limit("key1").unwrap();
        limiter.check_rate_limit("key2").unwrap();

        thread::sleep(Duration::from_millis(150));

        let removed = limiter.cleanup().unwrap();
        assert_eq!(removed, 2);
    }

    #[test]
    fn test_zero_max_requests_denies_all() {
        let limiter = RateLimiter::new(0, Duration::from_secs(60));
        assert!(!limiter.check_rate_limit("key").unwrap());
        assert!(!limiter.is_allowed("key"));
    }

    #[test]
    fn test_single_request_limit() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_rate_limit("key").unwrap());
        assert!(!limiter.check_rate_limit("key").unwrap());
    }

    #[test]
    fn test_independent_keys() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_rate_limit("key1").unwrap());
        assert!(limiter.check_rate_limit("key2").unwrap());
        // key1 is exhausted, key2 is exhausted
        assert!(!limiter.check_rate_limit("key1").unwrap());
        assert!(!limiter.check_rate_limit("key2").unwrap());
    }

    #[test]
    fn test_empty_key() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_rate_limit("").unwrap());
        assert!(limiter.check_rate_limit("").unwrap());
        assert!(!limiter.check_rate_limit("").unwrap());
    }

    #[test]
    fn test_remaining_requests_decrements() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert_eq!(limiter.get_remaining_requests("k").unwrap(), 3);
        limiter.check_rate_limit("k").unwrap();
        assert_eq!(limiter.get_remaining_requests("k").unwrap(), 2);
        limiter.check_rate_limit("k").unwrap();
        assert_eq!(limiter.get_remaining_requests("k").unwrap(), 1);
        limiter.check_rate_limit("k").unwrap();
        assert_eq!(limiter.get_remaining_requests("k").unwrap(), 0);
    }

    #[test]
    fn test_remaining_requests_for_unknown_key() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        assert_eq!(limiter.get_remaining_requests("unknown").unwrap(), 5);
    }

    #[test]
    fn test_get_request_count_unknown_key() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        assert_eq!(limiter.get_request_count("unknown").unwrap(), 0);
    }

    #[test]
    fn test_reset_clears_count() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        limiter.check_rate_limit("k").unwrap();
        limiter.check_rate_limit("k").unwrap();
        assert!(!limiter.is_allowed("k"));

        limiter.reset("k").unwrap();
        assert!(limiter.is_allowed("k"));
        assert_eq!(limiter.get_request_count("k").unwrap(), 1);
    }

    #[test]
    fn test_reset_nonexistent_key_is_ok() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        assert!(limiter.reset("nonexistent").is_ok());
    }

    #[test]
    fn test_cleanup_empty_limiter() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        assert_eq!(limiter.cleanup().unwrap(), 0);
    }

    #[test]
    fn test_clone_shares_state() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let limiter2 = limiter.clone();
        limiter.check_rate_limit("k").unwrap();
        // Clone should see the same request count
        assert_eq!(limiter2.get_request_count("k").unwrap(), 1);
    }

    #[test]
    fn test_concurrent_access() {
        let limiter = RateLimiter::new(100, Duration::from_secs(60));
        let mut handles = vec![];

        for i in 0..10 {
            let l = limiter.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    let _ = l.check_rate_limit(&format!("thread-{}", i));
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Each thread made 10 requests under its own key
        for i in 0..10 {
            assert_eq!(
                limiter.get_request_count(&format!("thread-{}", i)).unwrap(),
                10
            );
        }
    }

    #[test]
    fn test_remaining_alias_matches() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        limiter.check_rate_limit("k").unwrap();
        assert_eq!(
            limiter.remaining_requests("k").unwrap(),
            limiter.get_remaining_requests("k").unwrap()
        );
    }

    #[test]
    fn test_is_allowed_alias_matches() {
        // is_allowed is an alias for check_rate_limit that returns false on error
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        // Both should return true for fresh key
        assert!(limiter.is_allowed("a"));
        assert!(limiter.check_rate_limit("b").unwrap());
    }

    #[test]
    fn test_many_keys_cleanup() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        for i in 0..100 {
            limiter.check_rate_limit(&format!("key-{}", i)).unwrap();
        }
        thread::sleep(Duration::from_millis(100));
        let removed = limiter.cleanup().unwrap();
        assert_eq!(removed, 100);
    }
}
