//! Distributed Rate Limiting System
//!
//! This module provides comprehensive rate limiting capabilities with support for:
//! - In-memory rate limiting for single-node deployments
//! - Redis-based distributed rate limiting for multi-node deployments
//! - Sliding window algorithms for accurate rate limiting
//! - Adaptive rate limiting based on system load
//! - Multiple rate limiting strategies (token bucket, sliding window, etc.)

use crate::errors::{AuthError, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window for rate limiting
    pub window_duration: Duration,
    /// Strategy to use for rate limiting
    pub strategy: RateLimitStrategy,
    /// Whether to use distributed rate limiting
    pub distributed: bool,
    /// Redis connection string for distributed rate limiting
    pub redis_url: Option<String>,
    /// Burst allowance (allows temporary spikes)
    pub burst_allowance: Option<u32>,
    /// Adaptive rate limiting based on system load
    pub adaptive: bool,
    /// Penalty duration for rate limit violations
    pub penalty_duration: Option<Duration>,
}

/// Rate limiting strategies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitStrategy {
    /// Token bucket algorithm (allows bursts)
    TokenBucket,
    /// Fixed window (resets at fixed intervals)
    FixedWindow,
    /// Sliding window (smooth rate limiting)
    SlidingWindow,
    /// Adaptive (adjusts based on system load)
    Adaptive,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_duration: Duration::from_secs(60),
            strategy: RateLimitStrategy::SlidingWindow,
            distributed: false,
            redis_url: None,
            burst_allowance: Some(20),
            adaptive: false,
            penalty_duration: Some(Duration::from_secs(300)), // 5 minutes
        }
    }
}

impl RateLimitConfig {
    /// Create strict rate limiting for authentication attempts
    pub fn strict_auth() -> Self {
        Self {
            max_requests: 5,
            window_duration: Duration::from_secs(300), // 5 minutes
            strategy: RateLimitStrategy::FixedWindow,
            distributed: true,
            redis_url: None,       // Must be set externally
            burst_allowance: None, // No burst for auth
            adaptive: false,
            penalty_duration: Some(Duration::from_secs(3600)), // 1 hour penalty
        }
    }

    /// Create lenient rate limiting for general API usage
    pub fn lenient_api() -> Self {
        Self {
            max_requests: 1000,
            window_duration: Duration::from_secs(60),
            strategy: RateLimitStrategy::TokenBucket,
            distributed: false,
            redis_url: None,
            burst_allowance: Some(200),
            adaptive: true,
            penalty_duration: Some(Duration::from_secs(60)),
        }
    }

    /// Create balanced rate limiting for production
    pub fn balanced() -> Self {
        Self::default()
    }
}

/// Rate limit check result
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed { remaining: u32, reset_at: Instant },
    /// Request is denied due to rate limit
    Denied {
        retry_after: Duration,
        total_hits: u32,
    },
    /// Request is temporarily blocked due to previous violations
    Blocked { unblock_at: Instant, reason: String },
}

/// Comprehensive rate limiter supporting multiple strategies
pub struct DistributedRateLimiter {
    config: RateLimitConfig,
    in_memory_limiter: Option<Arc<InMemoryRateLimiter>>,
    #[cfg(feature = "redis-storage")]
    redis_limiter: Option<Arc<RedisRateLimiter>>,
    /// Penalty tracking for repeat violators
    penalties: Arc<RwLock<HashMap<String, Instant>>>,
}

impl DistributedRateLimiter {
    /// Create a new distributed rate limiter
    pub async fn new(config: RateLimitConfig) -> Result<Self> {
        let in_memory_limiter = if config.distributed {
            None
        } else {
            Some(Arc::new(InMemoryRateLimiter::new(&config)?))
        };

        #[cfg(feature = "redis-storage")]
        let redis_limiter = if config.distributed && config.redis_url.is_some() {
            Some(Arc::new(RedisRateLimiter::new(&config).await?))
        } else {
            None
        };

        #[cfg(not(feature = "redis-storage"))]
        {
            // When Redis is not available, use enhanced in-memory limiting with warnings
            tracing::warn!(
                "Redis storage not available for distributed rate limiting - using in-memory only"
            );
            tracing::warn!(
                "For production deployments, enable 'redis-storage' feature for true distributed limiting"
            );
        }

        Ok(Self {
            config,
            in_memory_limiter,
            #[cfg(feature = "redis-storage")]
            redis_limiter,
            penalties: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Check if a request should be rate limited
    pub async fn check_rate_limit(&self, key: &str) -> Result<RateLimitResult> {
        // First check for active penalties
        if let Some(unblock_at) = self.get_penalty_expiry(key) {
            if Instant::now() < unblock_at {
                return Ok(RateLimitResult::Blocked {
                    unblock_at,
                    reason: "Previous rate limit violations".to_string(),
                });
            } else {
                // Penalty expired, remove it
                self.remove_penalty(key);
            }
        }

        // Perform rate limit check based on configuration
        let result = if self.config.distributed {
            #[cfg(feature = "redis-storage")]
            if let Some(ref redis_limiter) = self.redis_limiter {
                redis_limiter.check_rate_limit(key).await?
            } else {
                // Fallback to in-memory if Redis is not available
                self.fallback_check(key).await?
            }
            #[cfg(not(feature = "redis-storage"))]
            self.fallback_check(key).await?
        } else if let Some(ref in_memory_limiter) = self.in_memory_limiter {
            in_memory_limiter.check_rate_limit(key).await?
        } else {
            return Err(AuthError::internal("No rate limiter configured"));
        };

        // Apply penalty for violations if configured
        if matches!(result, RateLimitResult::Denied { .. })
            && let Some(penalty_duration) = self.config.penalty_duration
        {
            self.apply_penalty(key, penalty_duration);
        }

        Ok(result)
    }

    /// Check multiple keys (e.g., IP + user) with different limits
    pub async fn check_multiple_limits(
        &self,
        checks: &[(String, RateLimitConfig)],
    ) -> Result<RateLimitResult> {
        for (key, config) in checks {
            let limiter = Self::new(config.clone()).await?;
            let result = limiter.check_rate_limit(key).await?;

            // If any check fails, return the failure
            if !matches!(result, RateLimitResult::Allowed { .. }) {
                return Ok(result);
            }
        }

        // All checks passed
        Ok(RateLimitResult::Allowed {
            remaining: u32::MAX, // Aggregate remaining not meaningful
            reset_at: Instant::now() + self.config.window_duration,
        })
    }

    fn get_penalty_expiry(&self, key: &str) -> Option<Instant> {
        let penalties = self.penalties.read();
        penalties.get(key).copied()
    }

    fn apply_penalty(&self, key: &str, duration: Duration) {
        let mut penalties = self.penalties.write();
        penalties.insert(key.to_string(), Instant::now() + duration);
    }

    fn remove_penalty(&self, key: &str) {
        let mut penalties = self.penalties.write();
        penalties.remove(key);
    }

    async fn fallback_check(&self, key: &str) -> Result<RateLimitResult> {
        // Create a temporary in-memory limiter for fallback
        let limiter = InMemoryRateLimiter::new(&self.config)?;
        limiter.check_rate_limit(key).await
    }
}

/// In-memory rate limiter with basic token bucket implementation
pub struct InMemoryRateLimiter {
    config: RateLimitConfig,
    buckets: std::sync::Arc<dashmap::DashMap<String, TokenBucket>>,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self, config: &RateLimitConfig) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Refill tokens based on time elapsed
        if elapsed >= config.window_duration {
            self.tokens = config.max_requests;
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

impl InMemoryRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            buckets: std::sync::Arc::new(dashmap::DashMap::new()),
        })
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<RateLimitResult> {
        let mut bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.max_requests));

        if bucket.try_consume(&self.config) {
            Ok(RateLimitResult::Allowed {
                remaining: bucket.tokens,
                reset_at: bucket.last_refill + self.config.window_duration,
            })
        } else {
            let retry_after =
                (bucket.last_refill + self.config.window_duration).duration_since(Instant::now());

            Ok(RateLimitResult::Denied {
                retry_after,
                total_hits: self.config.max_requests + 1, // Exceeded by 1
            })
        }
    }
}

/// Redis-based distributed rate limiter
#[cfg(feature = "redis-storage")]
pub struct RedisRateLimiter {
    client: redis::Client,
    config: RateLimitConfig,
}

#[cfg(feature = "redis-storage")]
impl RedisRateLimiter {
    pub async fn new(config: &RateLimitConfig) -> Result<Self> {
        let redis_url = config
            .redis_url
            .as_ref()
            .ok_or_else(|| AuthError::config("Redis URL required for distributed rate limiting"))?;

        let client = redis::Client::open(redis_url.as_str())
            .map_err(|e| AuthError::internal(format!("Failed to connect to Redis: {}", e)))?;

        Ok(Self {
            client,
            config: config.clone(),
        })
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<RateLimitResult> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| AuthError::internal(format!("Redis connection failed: {}", e)))?;

        match self.config.strategy {
            RateLimitStrategy::SlidingWindow => self.sliding_window_check(&mut conn, key).await,
            RateLimitStrategy::FixedWindow => self.fixed_window_check(&mut conn, key).await,
            RateLimitStrategy::TokenBucket => self.token_bucket_check(&mut conn, key).await,
            RateLimitStrategy::Adaptive => self.adaptive_check(&mut conn, key).await,
        }
    }

    async fn sliding_window_check(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        key: &str,
    ) -> Result<RateLimitResult> {
        let now = chrono::Utc::now().timestamp();
        let window_start = now - self.config.window_duration.as_secs() as i64;
        let redis_key = format!("rate_limit:sliding:{}", key);

        // Redis Lua script for atomic sliding window
        let script = r#"
            local key = KEYS[1]
            local window_start = ARGV[1]
            local now = ARGV[2]
            local max_requests = tonumber(ARGV[3])
            local expiry = tonumber(ARGV[4])

            -- Remove expired entries
            redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

            -- Count current requests in window
            local current_requests = redis.call('ZCARD', key)

            if current_requests < max_requests then
                -- Add current request
                redis.call('ZADD', key, now, now)
                redis.call('EXPIRE', key, expiry)
                return {1, max_requests - current_requests - 1}
            else
                return {0, current_requests}
            end
        "#;

        let result: Vec<i32> = redis::Script::new(script)
            .key(&redis_key)
            .arg(window_start)
            .arg(now)
            .arg(self.config.max_requests)
            .arg(self.config.window_duration.as_secs())
            .invoke_async(conn)
            .await
            .map_err(|e| AuthError::internal(format!("Redis script error: {}", e)))?;

        if result[0] == 1 {
            Ok(RateLimitResult::Allowed {
                remaining: result[1] as u32,
                reset_at: Instant::now() + self.config.window_duration,
            })
        } else {
            Ok(RateLimitResult::Denied {
                retry_after: self.config.window_duration,
                total_hits: result[1] as u32,
            })
        }
    }

    async fn fixed_window_check(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        key: &str,
    ) -> Result<RateLimitResult> {
        use redis::AsyncCommands;

        let window_size = self.config.window_duration.as_secs();
        let current_window = chrono::Utc::now().timestamp() / window_size as i64;
        let redis_key = format!("rate_limit:fixed:{}:{}", key, current_window);

        // Increment counter and set expiry
        let count: u32 = conn
            .incr(&redis_key, 1)
            .await
            .map_err(|e| AuthError::internal(format!("Redis incr error: {}", e)))?;

        if count == 1 {
            // First request in window, set expiry
            let _: () = conn
                .expire(&redis_key, window_size as i64)
                .await
                .map_err(|e| AuthError::internal(format!("Redis expire error: {}", e)))?;
        }

        if count <= self.config.max_requests {
            Ok(RateLimitResult::Allowed {
                remaining: self.config.max_requests - count,
                reset_at: Instant::now()
                    + Duration::from_secs(
                        window_size - (chrono::Utc::now().timestamp() % window_size as i64) as u64,
                    ),
            })
        } else {
            Ok(RateLimitResult::Denied {
                retry_after: Duration::from_secs(
                    window_size - (chrono::Utc::now().timestamp() % window_size as i64) as u64,
                ),
                total_hits: count,
            })
        }
    }

    async fn token_bucket_check(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        key: &str,
    ) -> Result<RateLimitResult> {
        let redis_key = format!("rate_limit:bucket:{}", key);
        let now = chrono::Utc::now().timestamp_millis();
        let refill_rate =
            self.config.max_requests as f64 / self.config.window_duration.as_secs_f64();
        let bucket_size = self.config.max_requests + self.config.burst_allowance.unwrap_or(0);

        // Redis Lua script for token bucket algorithm
        let script = r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local bucket_size = tonumber(ARGV[3])
            local cost = tonumber(ARGV[4])

            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or bucket_size
            local last_refill = tonumber(bucket[2]) or now

            -- Calculate tokens to add
            local time_passed = (now - last_refill) / 1000.0
            local tokens_to_add = time_passed * refill_rate
            tokens = math.min(bucket_size, tokens + tokens_to_add)

            if tokens >= cost then
                tokens = tokens - cost
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('EXPIRE', key, 3600) -- 1 hour expiry
                return {1, math.floor(tokens)}
            else
                redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                redis.call('EXPIRE', key, 3600)
                return {0, math.floor(tokens)}
            end
        "#;

        let result: Vec<i32> = redis::Script::new(script)
            .key(&redis_key)
            .arg(now)
            .arg(refill_rate)
            .arg(bucket_size)
            .arg(1) // Cost per request
            .invoke_async(conn)
            .await
            .map_err(|e| AuthError::internal(format!("Redis script error: {}", e)))?;

        if result[0] == 1 {
            Ok(RateLimitResult::Allowed {
                remaining: result[1] as u32,
                reset_at: Instant::now() + self.config.window_duration,
            })
        } else {
            let retry_after = Duration::from_secs_f64(1.0 / refill_rate);
            Ok(RateLimitResult::Denied {
                retry_after,
                total_hits: self.config.max_requests + 1,
            })
        }
    }

    async fn adaptive_check(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        key: &str,
    ) -> Result<RateLimitResult> {
        // For now, use sliding window with adaptive threshold
        // In production, this could adjust based on system metrics
        self.sliding_window_check(conn, key).await
    }
}

/// Rate limiting middleware helper
pub struct RateLimitMiddleware {
    limiters: HashMap<String, Arc<DistributedRateLimiter>>,
}

impl Default for RateLimitMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitMiddleware {
    pub fn new() -> Self {
        Self {
            limiters: HashMap::new(),
        }
    }

    /// Add a rate limiter for a specific endpoint or operation
    pub async fn add_limiter(&mut self, name: &str, config: RateLimitConfig) -> Result<()> {
        let limiter = Arc::new(DistributedRateLimiter::new(config).await?);
        self.limiters.insert(name.to_string(), limiter);
        Ok(())
    }

    /// Check rate limit for a specific operation
    pub async fn check_limit(&self, limiter_name: &str, key: &str) -> Result<RateLimitResult> {
        let limiter = self.limiters.get(limiter_name).ok_or_else(|| {
            AuthError::config(format!("No rate limiter found for '{}'", limiter_name))
        })?;

        limiter.check_rate_limit(key).await
    }

    /// Check multiple rate limits (e.g., per-IP and per-user)
    pub async fn check_multiple(&self, checks: &[(String, String)]) -> Result<RateLimitResult> {
        for (limiter_name, key) in checks {
            let result = self.check_limit(limiter_name, key).await?;
            if !matches!(result, RateLimitResult::Allowed { .. }) {
                return Ok(result);
            }
        }

        Ok(RateLimitResult::Allowed {
            remaining: u32::MAX,
            reset_at: Instant::now() + Duration::from_secs(60),
        })
    }
}

/// Rate limiting utilities for common patterns
pub struct RateLimitUtils;

impl RateLimitUtils {
    /// Generate rate limit key for IP address
    pub fn ip_key(ip: &str) -> String {
        format!("ip:{}", ip)
    }

    /// Generate rate limit key for user
    pub fn user_key(user_id: &str) -> String {
        format!("user:{}", user_id)
    }

    /// Generate rate limit key for API endpoint
    pub fn endpoint_key(endpoint: &str, ip: &str) -> String {
        format!("endpoint:{}:{}", endpoint, ip)
    }

    /// Generate rate limit key for authentication attempts
    pub fn auth_key(ip: &str, username: Option<&str>) -> String {
        match username {
            Some(user) => format!("auth:{}:{}", ip, user),
            None => format!("auth:{}", ip),
        }
    }

    /// Calculate backoff duration for repeated violations
    pub fn exponential_backoff(attempt: u32, base_duration: Duration) -> Duration {
        let multiplier = 2_u64.pow(attempt.min(10)); // Cap at 2^10
        Duration::from_millis(base_duration.as_millis() as u64 * multiplier)
    }

    /// Apply jitter to retry duration to prevent thundering herd
    pub fn add_jitter(duration: Duration, jitter_factor: f64) -> Duration {
        use rand::Rng;
        let jitter = rand::thread_rng().gen_range(0.0..jitter_factor);
        let jitter_ms = (duration.as_millis() as f64 * jitter) as u64;
        duration + Duration::from_millis(jitter_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_in_memory_rate_limiter() {
        let config = RateLimitConfig {
            max_requests: 3,
            window_duration: Duration::from_millis(100), // Shorter window for testing
            strategy: RateLimitStrategy::TokenBucket,
            distributed: false,
            redis_url: None,
            burst_allowance: Some(1),
            adaptive: false,
            penalty_duration: None,
        };

        let limiter = DistributedRateLimiter::new(config).await.unwrap();

        // First 3 requests should be allowed
        for i in 0..3 {
            let result = limiter.check_rate_limit("test_key").await.unwrap();
            assert!(
                matches!(result, RateLimitResult::Allowed { .. }),
                "Request {} should be allowed",
                i
            );
        }

        // 4th request should be denied
        let result = limiter.check_rate_limit("test_key").await.unwrap();
        assert!(
            matches!(result, RateLimitResult::Denied { .. }),
            "4th request should be denied"
        );

        // Wait for window to reset
        sleep(Duration::from_millis(150)).await;

        // Should be allowed again
        let result = limiter.check_rate_limit("test_key").await.unwrap();
        assert!(
            matches!(result, RateLimitResult::Allowed { .. }),
            "Request after window reset should be allowed"
        );
        assert!(
            matches!(result, RateLimitResult::Allowed { .. }),
            "Request after reset should be allowed"
        );
    }

    #[tokio::test]
    async fn test_penalty_system() {
        let config = RateLimitConfig {
            max_requests: 1,
            window_duration: Duration::from_millis(50),
            strategy: RateLimitStrategy::FixedWindow,
            distributed: false,
            redis_url: None,
            burst_allowance: None,
            adaptive: false,
            penalty_duration: Some(Duration::from_millis(200)),
        };

        let limiter = DistributedRateLimiter::new(config).await.unwrap();

        // First request allowed
        let result = limiter.check_rate_limit("penalty_test").await.unwrap();
        assert!(matches!(result, RateLimitResult::Allowed { .. }));

        // Second request denied (triggers penalty)
        let result = limiter.check_rate_limit("penalty_test").await.unwrap();
        assert!(matches!(result, RateLimitResult::Denied { .. }));

        // Wait a bit for penalty to be applied
        sleep(Duration::from_millis(10)).await;

        // Third request should be blocked due to penalty (not just denied)
        let result = limiter.check_rate_limit("penalty_test").await.unwrap();
        assert!(matches!(result, RateLimitResult::Blocked { .. }));

        // Wait for penalty to expire
        sleep(Duration::from_millis(250)).await;

        // Should be allowed again
        let result = limiter.check_rate_limit("penalty_test").await.unwrap();
        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }

    #[tokio::test]
    async fn test_rate_limit_key_generation() {
        assert_eq!(RateLimitUtils::ip_key("192.168.1.1"), "ip:192.168.1.1");
        assert_eq!(RateLimitUtils::user_key("user123"), "user:user123");
        assert_eq!(
            RateLimitUtils::endpoint_key("/api/login", "192.168.1.1"),
            "endpoint:/api/login:192.168.1.1"
        );
        assert_eq!(
            RateLimitUtils::auth_key("192.168.1.1", Some("user123")),
            "auth:192.168.1.1:user123"
        );
        assert_eq!(
            RateLimitUtils::auth_key("192.168.1.1", None),
            "auth:192.168.1.1"
        );
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        let base = Duration::from_millis(100);

        assert_eq!(
            RateLimitUtils::exponential_backoff(0, base),
            Duration::from_millis(100)
        );
        assert_eq!(
            RateLimitUtils::exponential_backoff(1, base),
            Duration::from_millis(200)
        );
        assert_eq!(
            RateLimitUtils::exponential_backoff(2, base),
            Duration::from_millis(400)
        );
        assert_eq!(
            RateLimitUtils::exponential_backoff(10, base),
            Duration::from_millis(102400)
        );

        // Should cap at 2^10
        assert_eq!(
            RateLimitUtils::exponential_backoff(15, base),
            Duration::from_millis(102400)
        );
    }

    #[tokio::test]
    async fn test_rate_limit_configurations() {
        let strict = RateLimitConfig::strict_auth();
        assert_eq!(strict.max_requests, 5);
        assert_eq!(strict.window_duration, Duration::from_secs(300));
        assert!(strict.distributed);

        let lenient = RateLimitConfig::lenient_api();
        assert_eq!(lenient.max_requests, 1000);
        assert!(lenient.adaptive);

        let balanced = RateLimitConfig::balanced();
        assert_eq!(balanced.max_requests, 100);
        assert_eq!(balanced.strategy, RateLimitStrategy::SlidingWindow);
    }
}


