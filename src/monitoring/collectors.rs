// SPDX-License-Identifier: MIT OR Apache-2.0
//! Metrics collectors for various authentication framework components
//!
//! This module provides atomic counters that can be incremented from anywhere in the
//! framework, and collector structs that read from those counters to produce metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// ── Global atomic counters ──────────────────────────────────────────────────

/// Total authentication requests processed.
pub static AUTH_TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);
/// Successful authentication requests.
pub static AUTH_SUCCESSFUL_REQUESTS: AtomicU64 = AtomicU64::new(0);
/// Failed authentication requests.
pub static AUTH_FAILED_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Currently active sessions.
pub static SESSION_ACTIVE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Sessions that have expired.
pub static SESSION_EXPIRED_COUNT: AtomicU64 = AtomicU64::new(0);
/// Cumulative sessions created (used to derive creation rate).
pub static SESSION_CREATED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Tokens created.
pub static TOKEN_CREATION_COUNT: AtomicU64 = AtomicU64::new(0);
/// Tokens validated.
pub static TOKEN_VALIDATION_COUNT: AtomicU64 = AtomicU64::new(0);
/// Tokens expired.
pub static TOKEN_EXPIRATION_COUNT: AtomicU64 = AtomicU64::new(0);

// ── Collector structs ───────────────────────────────────────────────────────

/// Collector for authentication metrics.
pub struct AuthMetricsCollector;

/// Collector for session metrics.
///
/// Tracks the last snapshot of `SESSION_CREATED_TOTAL` and the timestamp so
/// that `session_creation_rate` can be reported as creations-per-second.
pub struct SessionMetricsCollector {
    last_created_snapshot: AtomicU64,
    last_snapshot_time: std::sync::Mutex<Instant>,
}

/// Collector for token metrics.
pub struct TokenMetricsCollector;

impl AuthMetricsCollector {
    /// Collect authentication-related metrics from the global atomic counters.
    pub async fn collect(&self) -> std::collections::HashMap<String, f64> {
        let mut metrics = std::collections::HashMap::new();
        metrics.insert(
            "auth_total_requests".to_string(),
            AUTH_TOTAL_REQUESTS.load(Ordering::Relaxed) as f64,
        );
        metrics.insert(
            "auth_successful_requests".to_string(),
            AUTH_SUCCESSFUL_REQUESTS.load(Ordering::Relaxed) as f64,
        );
        metrics.insert(
            "auth_failed_requests".to_string(),
            AUTH_FAILED_REQUESTS.load(Ordering::Relaxed) as f64,
        );
        metrics
    }
}

impl Default for SessionMetricsCollector {
    fn default() -> Self {
        Self {
            last_created_snapshot: AtomicU64::new(0),
            last_snapshot_time: std::sync::Mutex::new(Instant::now()),
        }
    }
}

impl SessionMetricsCollector {
    /// Create a new session metrics collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect session-related metrics from the global atomic counters.
    ///
    /// `session_creation_rate` is computed as the delta in
    /// `SESSION_CREATED_TOTAL` divided by the elapsed seconds since the
    /// previous call.
    pub async fn collect(&self) -> std::collections::HashMap<String, f64> {
        let mut metrics = std::collections::HashMap::new();
        metrics.insert(
            "session_active_count".to_string(),
            SESSION_ACTIVE_COUNT.load(Ordering::Relaxed) as f64,
        );
        metrics.insert(
            "session_expired_count".to_string(),
            SESSION_EXPIRED_COUNT.load(Ordering::Relaxed) as f64,
        );

        // Compute creation rate from delta.
        let current_total = SESSION_CREATED_TOTAL.load(Ordering::Relaxed);
        let previous = self
            .last_created_snapshot
            .swap(current_total, Ordering::Relaxed);
        let delta = current_total.saturating_sub(previous);

        let rate = {
            let mut last_time = match self.last_snapshot_time.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let elapsed = last_time.elapsed().as_secs_f64();
            *last_time = Instant::now();
            if elapsed > 0.0 {
                delta as f64 / elapsed
            } else {
                0.0
            }
        };
        metrics.insert("session_creation_rate".to_string(), rate);

        metrics
    }
}

impl TokenMetricsCollector {
    /// Collect token-related metrics from the global atomic counters.
    pub async fn collect(&self) -> std::collections::HashMap<String, f64> {
        let mut metrics = std::collections::HashMap::new();
        metrics.insert(
            "token_creation_count".to_string(),
            TOKEN_CREATION_COUNT.load(Ordering::Relaxed) as f64,
        );
        metrics.insert(
            "token_validation_count".to_string(),
            TOKEN_VALIDATION_COUNT.load(Ordering::Relaxed) as f64,
        );
        metrics.insert(
            "token_expiration_count".to_string(),
            TOKEN_EXPIRATION_COUNT.load(Ordering::Relaxed) as f64,
        );
        metrics
    }
}
