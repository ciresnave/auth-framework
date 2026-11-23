// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security Features - Rate Limiting, DoS Protection, IP Blacklisting
//!
//! Advanced security features for API protection

use crate::api::{ApiResponse, ApiState};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration
    pub window_duration: Duration,
    /// Penalty duration for exceeding limit
    pub penalty_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_duration: Duration::from_secs(60),
            penalty_duration: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// DoS protection configuration
#[derive(Debug, Clone)]
pub struct DosProtectionConfig {
    /// Maximum request rate (requests per second) before triggering protection
    pub max_rate: f64,
    /// Duration to monitor for DoS attacks
    pub monitor_duration: Duration,
    /// Duration to block suspected DoS attackers
    pub block_duration: Duration,
}

impl Default for DosProtectionConfig {
    fn default() -> Self {
        Self {
            max_rate: 50.0, // 50 requests per second
            monitor_duration: Duration::from_secs(10),
            block_duration: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// IP blacklist configuration
#[derive(Debug, Clone)]
pub struct IpBlacklistConfig {
    /// Duration to keep IPs in blacklist
    pub blacklist_duration: Duration,
    /// Maximum failed attempts before blacklisting
    pub max_failed_attempts: u32,
    /// Time window for counting failed attempts
    pub attempt_window: Duration,
}

impl Default for IpBlacklistConfig {
    fn default() -> Self {
        Self {
            blacklist_duration: Duration::from_secs(3600), // 1 hour
            max_failed_attempts: 10,
            attempt_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Request tracking information
#[derive(Debug, Clone)]
struct RequestInfo {
    count: u32,
    first_request: Instant,
    last_request: Instant,
    penalty_until: Option<Instant>,
}

/// DoS tracking information
#[derive(Debug, Clone)]
struct DosInfo {
    request_times: Vec<Instant>,
    blocked_until: Option<Instant>,
}

/// Failed attempt tracking
#[derive(Debug, Clone)]
struct FailureInfo {
    attempts: u32,
    first_attempt: Instant,
    blacklisted_until: Option<Instant>,
}

/// Security manager for handling rate limiting, DoS protection, and IP blacklisting
pub struct SecurityManager {
    rate_limit_config: RateLimitConfig,
    dos_config: DosProtectionConfig,
    blacklist_config: IpBlacklistConfig,

    // Rate limiting state
    rate_limits: Arc<RwLock<HashMap<IpAddr, RequestInfo>>>,

    // DoS protection state
    dos_tracking: Arc<RwLock<HashMap<IpAddr, DosInfo>>>,

    // IP blacklisting state
    failure_tracking: Arc<RwLock<HashMap<IpAddr, FailureInfo>>>,
    manual_blacklist: Arc<RwLock<Vec<IpAddr>>>,
}

impl SecurityManager {
    /// Create a new security manager with default configuration
    pub fn new() -> Self {
        Self::with_config(
            RateLimitConfig::default(),
            DosProtectionConfig::default(),
            IpBlacklistConfig::default(),
        )
    }

    /// Create a new security manager with custom configuration
    pub fn with_config(
        rate_limit_config: RateLimitConfig,
        dos_config: DosProtectionConfig,
        blacklist_config: IpBlacklistConfig,
    ) -> Self {
        Self {
            rate_limit_config,
            dos_config,
            blacklist_config,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            dos_tracking: Arc::new(RwLock::new(HashMap::new())),
            failure_tracking: Arc::new(RwLock::new(HashMap::new())),
            manual_blacklist: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check if IP is rate limited
    pub async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut rate_limits = self.rate_limits.write().await;

        // Clean expired entries
        rate_limits.retain(|_, info| {
            now.duration_since(info.first_request) < self.rate_limit_config.window_duration * 2
        });

        let info = rate_limits.entry(ip).or_insert_with(|| RequestInfo {
            count: 0,
            first_request: now,
            last_request: now,
            penalty_until: None,
        });

        // Check if still under penalty
        if let Some(penalty_until) = info.penalty_until {
            if now < penalty_until {
                return false; // Still penalized
            } else {
                info.penalty_until = None; // Clear expired penalty
            }
        }

        // Reset window if needed
        if now.duration_since(info.first_request) > self.rate_limit_config.window_duration {
            info.count = 0;
            info.first_request = now;
        }

        info.count += 1;
        info.last_request = now;

        // Check if limit exceeded
        if info.count > self.rate_limit_config.max_requests {
            info.penalty_until = Some(now + self.rate_limit_config.penalty_duration);
            return false;
        }

        true
    }

    /// Check for DoS attacks
    pub async fn check_dos_protection(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut dos_tracking = self.dos_tracking.write().await;

        // Clean expired entries
        dos_tracking.retain(|_, info| {
            if let Some(blocked_until) = info.blocked_until {
                now < blocked_until
            } else {
                info.request_times.first().is_some_and(|first| {
                    now.duration_since(*first) < self.dos_config.monitor_duration * 2
                })
            }
        });

        let info = dos_tracking.entry(ip).or_insert_with(|| DosInfo {
            request_times: Vec::new(),
            blocked_until: None,
        });

        // Check if still blocked
        if let Some(blocked_until) = info.blocked_until {
            if now < blocked_until {
                return false; // Still blocked
            } else {
                info.blocked_until = None; // Clear expired block
                info.request_times.clear(); // Reset tracking
            }
        }

        // Add current request
        info.request_times.push(now);

        // Remove old requests outside monitor window
        info.request_times
            .retain(|&time| now.duration_since(time) <= self.dos_config.monitor_duration);

        // Check if DoS threshold exceeded
        let rate = info.request_times.len() as f64 / self.dos_config.monitor_duration.as_secs_f64();
        if rate > self.dos_config.max_rate {
            info.blocked_until = Some(now + self.dos_config.block_duration);
            return false;
        }

        true
    }

    /// Check if IP is blacklisted
    pub async fn check_blacklist(&self, ip: IpAddr) -> bool {
        // Check manual blacklist
        let manual_blacklist = self.manual_blacklist.read().await;
        if manual_blacklist.contains(&ip) {
            return false;
        }
        drop(manual_blacklist);

        // Check automatic blacklist
        let now = Instant::now();
        let mut failure_tracking = self.failure_tracking.write().await;

        // Clean expired entries
        failure_tracking.retain(|_, info| {
            if let Some(blacklisted_until) = info.blacklisted_until {
                now < blacklisted_until
            } else {
                now.duration_since(info.first_attempt) < self.blacklist_config.attempt_window * 2
            }
        });

        if let Some(info) = failure_tracking.get(&ip)
            && let Some(blacklisted_until) = info.blacklisted_until
        {
            return now >= blacklisted_until;
        }

        true
    }

    /// Record a failed authentication attempt
    pub async fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut failure_tracking = self.failure_tracking.write().await;

        let info = failure_tracking.entry(ip).or_insert_with(|| FailureInfo {
            attempts: 0,
            first_attempt: now,
            blacklisted_until: None,
        });

        // Reset window if needed
        if now.duration_since(info.first_attempt) > self.blacklist_config.attempt_window {
            info.attempts = 0;
            info.first_attempt = now;
        }

        info.attempts += 1;

        // Check if should blacklist
        if info.attempts >= self.blacklist_config.max_failed_attempts {
            info.blacklisted_until = Some(now + self.blacklist_config.blacklist_duration);
        }
    }

    /// Manually add IP to blacklist
    pub async fn add_to_blacklist(&self, ip: IpAddr) {
        let mut manual_blacklist = self.manual_blacklist.write().await;
        if !manual_blacklist.contains(&ip) {
            manual_blacklist.push(ip);
        }
    }

    /// Remove IP from manual blacklist
    pub async fn remove_from_blacklist(&self, ip: IpAddr) {
        let mut manual_blacklist = self.manual_blacklist.write().await;
        manual_blacklist.retain(|&x| x != ip);
    }

    /// Get security statistics
    pub async fn get_stats(&self) -> SecurityStats {
        let rate_limits = self.rate_limits.read().await;
        let dos_tracking = self.dos_tracking.read().await;
        let failure_tracking = self.failure_tracking.read().await;
        let manual_blacklist = self.manual_blacklist.read().await;

        let now = Instant::now();

        SecurityStats {
            total_rate_limited_ips: rate_limits.len(),
            currently_penalized_ips: rate_limits
                .values()
                .filter(|info| info.penalty_until.is_some_and(|until| now < until))
                .count(),
            total_dos_tracked_ips: dos_tracking.len(),
            currently_blocked_ips: dos_tracking
                .values()
                .filter(|info| info.blocked_until.is_some_and(|until| now < until))
                .count(),
            total_failure_tracked_ips: failure_tracking.len(),
            currently_blacklisted_ips: failure_tracking
                .values()
                .filter(|info| info.blacklisted_until.is_some_and(|until| now < until))
                .count()
                + manual_blacklist.len(),
            manual_blacklist_size: manual_blacklist.len(),
        }
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Security statistics
#[derive(Debug, Serialize)]
pub struct SecurityStats {
    pub total_rate_limited_ips: usize,
    pub currently_penalized_ips: usize,
    pub total_dos_tracked_ips: usize,
    pub currently_blocked_ips: usize,
    pub total_failure_tracked_ips: usize,
    pub currently_blacklisted_ips: usize,
    pub manual_blacklist_size: usize,
}

/// Security middleware
pub async fn security_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<ApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = addr.ip();

    // Get security manager
    let security_manager = match state.auth_framework.security_manager() {
        Some(manager) => manager,
        None => return Ok(next.run(request).await), // No security manager, allow request
    };

    // Check blacklist first
    if !security_manager.check_blacklist(ip).await {
        return Err(StatusCode::FORBIDDEN);
    }

    // Check DoS protection
    if !security_manager.check_dos_protection(ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Check rate limiting
    if !security_manager.check_rate_limit(ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Allow request
    Ok(next.run(request).await)
}

// ============================================================================
// API Endpoints
// ============================================================================

/// Get security statistics
pub async fn get_security_stats(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<SecurityStats>>, StatusCode> {
    let security_manager = match state.auth_framework.security_manager() {
        Some(manager) => manager,
        None => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    let stats = security_manager.get_stats().await;
    Ok(Json(ApiResponse::success(stats)))
}

/// Blacklist management request
#[derive(Debug, Deserialize)]
pub struct BlacklistRequest {
    pub ip: IpAddr,
}

/// Add IP to blacklist
pub async fn add_to_blacklist(
    State(state): State<ApiState>,
    Json(request): Json<BlacklistRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let security_manager = match state.auth_framework.security_manager() {
        Some(manager) => manager,
        None => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    security_manager.add_to_blacklist(request.ip).await;
    Ok(Json(ApiResponse::success_with_message(
        (),
        "IP added to blacklist",
    )))
}

/// Remove IP from blacklist
pub async fn remove_from_blacklist(
    State(state): State<ApiState>,
    Json(request): Json<BlacklistRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let security_manager = match state.auth_framework.security_manager() {
        Some(manager) => manager,
        None => return Err(StatusCode::SERVICE_UNAVAILABLE),
    };

    security_manager.remove_from_blacklist(request.ip).await;
    Ok(Json(ApiResponse::success_with_message(
        (),
        "IP removed from blacklist",
    )))
}
