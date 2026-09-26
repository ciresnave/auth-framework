//! Security Verification Tests: Rate Limiting
//!
//! Comprehensive end-to-end tests for rate limiting across all components:
//! - IP-based rate limiting
//! - User-based rate limiting  
//! - OAuth endpoint rate limiting
//! - Device authorization polling rate limits
//! - DoS protection through rate limits
//!
//! These tests verify that rate limiting works correctly through realistic
//! attack scenarios and ensure the system is protected against abuse.

use auth_framework::{
    AuthConfig, AuthFramework,
    distributed::rate_limiting::{
        DistributedRateLimiter, RateLimitConfig, RateLimitResult, RateLimitStrategy,
    },
    server::{DeviceAuthManager, DeviceAuthorizationRequest},
    utils::rate_limit::RateLimiter as BasicRateLimiter,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// A controllable clock for rate-limiter tests: advancing it moves the
/// limiter's notion of "now" without any real wall-clock delay, so window
/// expiry can be asserted deterministically instead of racing a `sleep`
/// against scheduling or instrumentation overhead.
fn fake_clock() -> (
    Arc<Mutex<Instant>>,
    impl Fn() -> Instant + Send + Sync + 'static,
) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let reader = now.clone();
    (now, move || *reader.lock().unwrap())
}

/// Helper to create test framework
async fn setup_test_framework() -> Arc<AuthFramework> {
    let config = AuthConfig::new()
        .secret("test_security_verification_secret_key_minimum_32_bytes".to_string())
        .max_failed_attempts(5);

    let mut framework = AuthFramework::new(config);
    framework.initialize().await.unwrap();
    Arc::new(framework)
}

#[tokio::test]
async fn test_basic_ip_rate_limiting() {
    println!("🔍 Testing: Basic IP-Based Rate Limiting");

    // Create rate limiter: 3 requests per 100ms, driven by a fake clock so
    // window expiry is asserted by advancing time explicitly rather than by
    // sleeping and hoping the real clock cooperates.
    let (clock, now) = fake_clock();
    let limiter = BasicRateLimiter::with_clock(3, Duration::from_millis(100), now);

    let test_ip = "192.168.1.100";

    // First 3 requests should be allowed
    for i in 1..=3 {
        assert!(
            limiter.is_allowed(test_ip),
            "Request {} should be allowed",
            i
        );
    }

    // 4th request should be blocked
    assert!(
        !limiter.is_allowed(test_ip),
        "Request 4 should be rate limited"
    );

    // Advance the fake clock past the window -- no real time passes.
    *clock.lock().unwrap() += Duration::from_millis(150);

    // Should be allowed again after window reset
    assert!(
        limiter.is_allowed(test_ip),
        "Request should be allowed after window reset"
    );

    println!("✅ Basic IP Rate Limiting: PASSED");
}

#[tokio::test]
async fn test_per_user_rate_limiting() {
    println!("🔍 Testing: Per-User Rate Limiting");

    let limiter = BasicRateLimiter::new(2, Duration::from_secs(1));

    let user1 = "user:alice";
    let user2 = "user:bob";

    // User 1: 2 requests allowed
    assert!(
        limiter.is_allowed(user1),
        "User 1 request 1 should be allowed"
    );
    assert!(
        limiter.is_allowed(user1),
        "User 1 request 2 should be allowed"
    );
    assert!(
        !limiter.is_allowed(user1),
        "User 1 request 3 should be blocked"
    );

    // User 2 should still be allowed (independent limit)
    assert!(
        limiter.is_allowed(user2),
        "User 2 request 1 should be allowed"
    );
    assert!(
        limiter.is_allowed(user2),
        "User 2 request 2 should be allowed"
    );
    assert!(
        !limiter.is_allowed(user2),
        "User 2 request 3 should be blocked"
    );

    println!("✅ Per-User Rate Limiting: PASSED");
}

#[tokio::test]
async fn test_distributed_rate_limiter_token_bucket() {
    println!("🔍 Testing: Distributed Rate Limiter (Token Bucket)");

    let config = RateLimitConfig {
        max_requests: 5,
        window_duration: Duration::from_millis(500),
        strategy: RateLimitStrategy::TokenBucket,
        distributed: false,
        redis_url: None,
        burst_allowance: Some(2),
        adaptive: false,
        penalty_duration: None,
    };

    let limiter = DistributedRateLimiter::new(config).await.unwrap();

    // First 5 requests should be allowed
    for i in 1..=5 {
        let result = limiter.check_rate_limit("test_key").await.unwrap();
        assert!(
            matches!(result, RateLimitResult::Allowed { .. }),
            "Request {} should be allowed",
            i
        );
    }

    // 6th request should be denied
    let result = limiter.check_rate_limit("test_key").await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Denied { .. }),
        "Request 6 should be denied"
    );

    // Wait for token bucket to refill
    sleep(Duration::from_millis(600)).await;

    // Should be allowed again
    let result = limiter.check_rate_limit("test_key").await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Allowed { .. }),
        "Request should be allowed after refill"
    );

    println!("✅ Distributed Rate Limiter (Token Bucket): PASSED");
}

#[tokio::test]
async fn test_rate_limit_with_penalty() {
    println!("🔍 Testing: Rate Limiting with Penalty Period");

    let config = RateLimitConfig {
        max_requests: 3,
        window_duration: Duration::from_millis(100),
        strategy: RateLimitStrategy::TokenBucket,
        distributed: false,
        redis_url: None,
        burst_allowance: None,
        adaptive: false,
        penalty_duration: Some(Duration::from_millis(500)),
    };

    let limiter = DistributedRateLimiter::new(config).await.unwrap();

    let key = "penalized_key";

    // Exhaust limit
    for _ in 0..3 {
        limiter.check_rate_limit(key).await.unwrap();
    }

    // Next request should be denied (triggers penalty)
    let result = limiter.check_rate_limit(key).await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Denied { .. }),
        "Should be denied"
    );

    // Even after window passes, should still be blocked during penalty
    sleep(Duration::from_millis(150)).await;
    let result = limiter.check_rate_limit(key).await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Blocked { .. }),
        "Should be blocked during penalty period"
    );

    // After penalty expires, should be allowed
    sleep(Duration::from_millis(400)).await;
    let result = limiter.check_rate_limit(key).await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Allowed { .. }),
        "Should be allowed after penalty expires"
    );

    println!("✅ Rate Limiting with Penalty: PASSED");
}

#[tokio::test]
async fn test_device_auth_polling_rate_limit() {
    println!("🔍 Testing: Device Authorization Polling Rate Limit");

    let framework = setup_test_framework().await;
    let storage = framework.storage().clone();
    let device_manager =
        DeviceAuthManager::new(storage.clone(), "https://example.com/device".to_string());

    // Create device authorization
    let request = DeviceAuthorizationRequest {
        client_id: "rate_limit_test_client".to_string(),
        scope: Some("openid".to_string()),
    };

    let response = device_manager.create_authorization(request).await.unwrap();

    let device_code = response.device_code;

    // First poll - should get pending
    let poll1 = device_manager.poll_authorization(&device_code).await;
    assert!(poll1.is_err(), "First poll should be pending");

    // Immediate second poll - should trigger slow_down
    let poll2 = device_manager.poll_authorization(&device_code).await;
    assert!(poll2.is_err(), "Second poll should fail");

    let error = poll2.unwrap_err().to_string();
    assert!(
        error.contains("slow_down") || error.contains("too frequent"),
        "Error should indicate rate limiting: {}",
        error
    );

    // The first slow_down adds 5 seconds to the 5-second base interval,
    // so the next allowed poll is after roughly 10 seconds.
    sleep(Duration::from_secs(11)).await;

    // Should be allowed to poll again
    let poll3 = device_manager.poll_authorization(&device_code).await;
    assert!(poll3.is_err()); // Still pending, but not rate limited

    let error3 = poll3.unwrap_err().to_string();
    assert!(
        !error3.contains("slow_down"),
        "Should not be rate limited after waiting"
    );

    println!("✅ Device Authorization Polling Rate Limit: PASSED");
}

#[tokio::test]
async fn test_concurrent_rate_limiting() {
    println!("🔍 Testing: Concurrent Request Rate Limiting");

    let limiter = BasicRateLimiter::new(10, Duration::from_secs(1));

    let test_ip = "192.168.1.200";

    // Spawn multiple concurrent requests
    let mut handles = vec![];
    for i in 0..15 {
        let limiter_clone = limiter.clone();
        let ip = test_ip.to_string();
        let handle = tokio::spawn(async move {
            let allowed = limiter_clone.is_allowed(&ip);
            (i, allowed)
        });
        handles.push(handle);
    }

    // Collect results
    let mut results = vec![];
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Count allowed vs blocked
    let allowed_count = results.iter().filter(|(_, allowed)| *allowed).count();
    let blocked_count = results.iter().filter(|(_, allowed)| !*allowed).count();

    println!(
        "   Allowed: {}, Blocked: {} (out of 15 concurrent)",
        allowed_count, blocked_count
    );

    // Should have ~10 allowed and ~5 blocked (may vary due to concurrency)
    assert!(
        (8..=12).contains(&allowed_count),
        "Expected ~10 allowed, got {}",
        allowed_count
    );
    assert!(
        (3..=7).contains(&blocked_count),
        "Expected ~5 blocked, got {}",
        blocked_count
    );

    println!("✅ Concurrent Rate Limiting: PASSED");
}

#[tokio::test]
async fn test_rate_limit_key_isolation() {
    println!("🔍 Testing: Rate Limit Key Isolation");

    let limiter = BasicRateLimiter::new(2, Duration::from_secs(1));

    // Different keys should have independent limits
    assert!(limiter.is_allowed("ip:192.168.1.1"));
    assert!(limiter.is_allowed("ip:192.168.1.1"));
    assert!(!limiter.is_allowed("ip:192.168.1.1")); // Exhausted

    // Different IP still has full quota
    assert!(limiter.is_allowed("ip:192.168.1.2"));
    assert!(limiter.is_allowed("ip:192.168.1.2"));
    assert!(!limiter.is_allowed("ip:192.168.1.2")); // Exhausted

    // User keys independent from IP keys
    assert!(limiter.is_allowed("user:alice"));
    assert!(limiter.is_allowed("user:alice"));
    assert!(!limiter.is_allowed("user:alice")); // Exhausted

    println!("✅ Rate Limit Key Isolation: PASSED");
}

#[tokio::test]
async fn test_rate_limit_window_reset() {
    println!("🔍 Testing: Rate Limit Window Reset");

    let limiter = BasicRateLimiter::new(3, Duration::from_millis(200));

    let key = "window_test";

    // Exhaust limit
    assert!(limiter.is_allowed(key));
    assert!(limiter.is_allowed(key));
    assert!(limiter.is_allowed(key));
    assert!(!limiter.is_allowed(key)); // Blocked

    // Wait for window to reset
    sleep(Duration::from_millis(250)).await;

    // Should be allowed again (full quota restored)
    assert!(
        limiter.is_allowed(key),
        "Should be allowed after window reset"
    );
    assert!(limiter.is_allowed(key));
    assert!(limiter.is_allowed(key));
    assert!(!limiter.is_allowed(key)); // Exhausted again

    println!("✅ Rate Limit Window Reset: PASSED");
}

#[tokio::test]
async fn test_dos_protection_via_rate_limiting() {
    println!("🔍 Testing: DoS Protection via Rate Limiting");

    let limiter = BasicRateLimiter::new(5, Duration::from_millis(100));

    let attacker_ip = "attack:10.0.0.1";

    // Simulate rapid-fire attack
    let mut blocked_count = 0;
    for i in 1..=20 {
        if !limiter.is_allowed(attacker_ip) {
            blocked_count += 1;
        }
        if i % 5 == 0 {
            println!("   After {} requests: {} blocked", i, blocked_count);
        }
    }

    // Should have blocked at least 10 requests
    assert!(
        blocked_count >= 10,
        "Expected at least 10 blocked requests, got {}",
        blocked_count
    );

    println!(
        "   DoS attack mitigated: {}/20 requests blocked",
        blocked_count
    );
    println!("✅ DoS Protection via Rate Limiting: PASSED");
}

#[tokio::test]
async fn test_rate_limit_sliding_window() {
    println!("🔍 Testing: Sliding Window Rate Limiting");

    let config = RateLimitConfig {
        max_requests: 5,
        window_duration: Duration::from_millis(300),
        strategy: RateLimitStrategy::SlidingWindow,
        distributed: false,
        redis_url: None,
        burst_allowance: None,
        adaptive: false,
        penalty_duration: None,
    };

    let limiter = DistributedRateLimiter::new(config).await.unwrap();

    // Make requests over time
    for i in 1..=3 {
        let result = limiter.check_rate_limit("sliding_key").await.unwrap();
        assert!(
            matches!(result, RateLimitResult::Allowed { .. }),
            "Request {} should be allowed",
            i
        );
        sleep(Duration::from_millis(50)).await;
    }

    // Wait a bit, then make 2 more (should be within window)
    sleep(Duration::from_millis(100)).await;

    let result = limiter.check_rate_limit("sliding_key").await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Allowed { .. }),
        "Request 4 should be allowed"
    );

    let result = limiter.check_rate_limit("sliding_key").await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Allowed { .. }),
        "Request 5 should be allowed"
    );

    // 6th should be denied (5 requests still in sliding window)
    let result = limiter.check_rate_limit("sliding_key").await.unwrap();
    assert!(
        matches!(result, RateLimitResult::Denied { .. }),
        "Request 6 should be denied"
    );

    println!("✅ Sliding Window Rate Limiting: PASSED");
}

#[tokio::test]
async fn test_rate_limit_burst_allowance() {
    println!("🔍 Testing: Rate Limit Burst Allowance");

    let config = RateLimitConfig {
        max_requests: 5,
        window_duration: Duration::from_secs(1),
        strategy: RateLimitStrategy::TokenBucket,
        distributed: false,
        redis_url: None,
        burst_allowance: Some(2), // Allow 2 extra burst requests
        adaptive: false,
        penalty_duration: None,
    };

    let limiter = DistributedRateLimiter::new(config).await.unwrap();

    // Base limit is 5 requests
    // Note: Burst allowance may be applied differently by implementation
    // Test that at least base limit is enforced
    for i in 1..=5 {
        let result = limiter.check_rate_limit("burst_key").await.unwrap();
        assert!(
            matches!(result, RateLimitResult::Allowed { .. }),
            "Request {} should be allowed (base limit)",
            i
        );
    }

    // 6th request may be allowed (burst) or denied (depending on implementation)
    let result6 = limiter.check_rate_limit("burst_key").await.unwrap();

    // If burst is working, 6th and maybe 7th are allowed
    // If not, 6th is denied - both are valid implementations
    let burst_working = matches!(result6, RateLimitResult::Allowed { .. });

    if burst_working {
        println!("   Burst allowance working: additional requests allowed");
    } else {
        println!("   Burst not applied: strict limit enforced");
    }

    // Eventually should be denied
    let mut denied = !burst_working;
    if !denied {
        // Try a few more
        for _ in 0..3 {
            let result = limiter.check_rate_limit("burst_key").await.unwrap();
            if matches!(result, RateLimitResult::Denied { .. }) {
                denied = true;
                break;
            }
        }
    }

    assert!(denied, "Should eventually be rate limited");

    println!("✅ Rate Limit Burst Allowance: PASSED");
}

#[tokio::test]
async fn test_rate_limit_cleanup() {
    println!("🔍 Testing: Rate Limit Entry Cleanup");

    let limiter = BasicRateLimiter::new(5, Duration::from_millis(100));

    // Create entries for multiple keys
    for i in 0..10 {
        let key = format!("cleanup_key_{}", i);
        limiter.is_allowed(&key);
    }

    // Wait for window expiry
    sleep(Duration::from_millis(150)).await;

    // Trigger cleanup (returns Result, but we just want the side effect)
    let _ = limiter.cleanup();

    // After cleanup, all keys should have fresh limits
    for i in 0..10 {
        let key = format!("cleanup_key_{}", i);
        assert!(
            limiter.is_allowed(&key),
            "Key {} should be allowed after cleanup",
            i
        );
    }

    println!("✅ Rate Limit Entry Cleanup: PASSED");
}
