// SPDX-License-Identifier: MIT OR Apache-2.0
//! Simple Security Management API Endpoints
//!
//! This module provides basic endpoints for managing security features:
//! - IP blacklisting and whitelisting
//! - Security statistics and monitoring

use crate::api::{ApiResponse, ApiState};
use axum::{
    Form,
    extract::{Path, State},
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;

// Global IP blacklist (in production, this should be persistent storage)
lazy_static! {
    static ref IP_BLACKLIST: RwLock<HashSet<IpAddr>> = RwLock::new(HashSet::new());
    static ref SECURITY_STATS: RwLock<SecurityStats> = RwLock::new(SecurityStats::default());
}

#[derive(Debug, Default, Clone, Serialize)]
struct SecurityStats {
    blocked_requests: u64,
    failed_auth_attempts: u64,
    suspicious_activity: u64,
    last_updated: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct BlacklistIpForm {
    pub ip: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecurityStatsResponse {
    pub blocked_requests: u64,
    pub failed_auth_attempts: u64,
    pub suspicious_activity: u64,
    pub blacklisted_ips: usize,
    pub last_updated: Option<i64>,
}

/// POST /api/v1/security/blacklist
/// Add an IP address to the blacklist
pub async fn blacklist_ip_endpoint(
    State(_state): State<ApiState>,
    Form(form): Form<BlacklistIpForm>,
) -> ApiResponse<serde_json::Value> {
    let ip: IpAddr = match form.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::error_typed("invalid_ip", "Invalid IP address format"),
    };

    {
        let Ok(mut blacklist) = IP_BLACKLIST.write() else {
            return ApiResponse::error_typed("internal_error", "Security subsystem unavailable");
        };
        blacklist.insert(ip);
    }

    // Update security stats
    {
        if let Ok(mut stats) = SECURITY_STATS.write() {
            stats.blocked_requests += 1;
            stats.last_updated = Some(chrono::Utc::now().timestamp());
        }
    }

    let data = json!({
        "ip": ip.to_string(),
        "reason": form.reason.unwrap_or_else(|| "Manual blacklist".to_string())
    });

    ApiResponse::success_with_message(data, format!("IP {} added to blacklist", ip))
}

/// DELETE /api/v1/security/blacklist/{ip}
/// Remove an IP address from the blacklist
pub async fn unblock_ip_endpoint(
    State(_state): State<ApiState>,
    Path(ip_str): Path<String>,
) -> ApiResponse<serde_json::Value> {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return ApiResponse::error_typed("invalid_ip", "Invalid IP address format"),
    };

    let removed = {
        let Ok(mut blacklist) = IP_BLACKLIST.write() else {
            return ApiResponse::error_typed("internal_error", "Security subsystem unavailable");
        };
        blacklist.remove(&ip)
    };

    if removed {
        // Update security stats
        {
            if let Ok(mut stats) = SECURITY_STATS.write() {
                stats.last_updated = Some(chrono::Utc::now().timestamp());
            }
        }

        let data = json!({
            "ip": ip.to_string(),
            "status": "unblocked"
        });

        ApiResponse::success_with_message(data, format!("IP {} removed from blacklist", ip))
    } else {
        let data = json!({
            "ip": ip.to_string(),
            "status": "not_found"
        });

        ApiResponse::success_with_message(data, format!("IP {} was not in blacklist", ip))
    }
}

/// GET /api/v1/security/stats
/// Get security statistics
pub async fn stats_endpoint(State(_state): State<ApiState>) -> ApiResponse<SecurityStatsResponse> {
    let stats = SECURITY_STATS.read().map(|s| s.clone()).unwrap_or_default();
    let blacklist_size = IP_BLACKLIST.read().map(|b| b.len()).unwrap_or(0);

    let response_data = SecurityStatsResponse {
        blocked_requests: stats.blocked_requests,
        failed_auth_attempts: stats.failed_auth_attempts,
        suspicious_activity: stats.suspicious_activity,
        blacklisted_ips: blacklist_size,
        last_updated: stats.last_updated,
    };

    ApiResponse::success(response_data)
}

/// Check if an IP address is blacklisted (for middleware use)
pub fn is_ip_blacklisted(ip: &IpAddr) -> bool {
    IP_BLACKLIST.read().map(|b| b.contains(ip)).unwrap_or(false)
}

/// Increment failed authentication attempts (for middleware use)
pub fn increment_failed_auth() {
    if let Ok(mut stats) = SECURITY_STATS.write() {
        stats.failed_auth_attempts += 1;
        stats.last_updated = Some(chrono::Utc::now().timestamp());
    }
}

/// Increment suspicious activity counter (for middleware use)
pub fn increment_suspicious_activity() {
    if let Ok(mut stats) = SECURITY_STATS.write() {
        stats.suspicious_activity += 1;
        stats.last_updated = Some(chrono::Utc::now().timestamp());
    }
}
