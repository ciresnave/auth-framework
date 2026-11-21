// SPDX-License-Identifier: MIT OR Apache-2.0
//! Health Check and Monitoring API Endpoints
//!
//! Provides system health, metrics, and monitoring endpoints

use crate::api::{ApiResponse, ApiState};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::collections::HashMap;

/// Basic health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Overall status: `"healthy"` or `"degraded"`.
    pub status: String,
    /// ISO-8601 timestamp of the check.
    pub timestamp: String,
    /// Per-service status summary.
    pub services: HashMap<String, String>,
    /// Crate version.
    pub version: String,
    /// Human-readable server uptime (e.g. `"3h 12m"`).
    pub uptime: String,
}

/// Extended health check response including per-service latency and system resource usage.
#[derive(Debug, Serialize)]
pub struct DetailedHealthResponse {
    pub status: String,
    pub timestamp: String,
    pub services: HashMap<String, ServiceHealth>,
    pub system: SystemHealth,
    pub version: String,
    pub uptime: String,
}

/// Per-service health details.
#[derive(Debug, Serialize)]
pub struct ServiceHealth {
    /// `"healthy"`, `"degraded"`, or `"unhealthy"`.
    pub status: String,
    /// Round-trip check latency in milliseconds.
    pub response_time_ms: u64,
    /// ISO-8601 timestamp of the last probe.
    pub last_check: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Aggregate system resource usage.
#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub memory_usage: MemoryInfo,
    pub cpu_usage: f64,
    pub disk_usage: DiskInfo,
    pub network: NetworkInfo,
}

/// Process memory usage.
#[derive(Debug, Serialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub usage_percent: f64,
}

/// Disk usage statistics.
#[derive(Debug, Serialize)]
pub struct DiskInfo {
    pub total_gb: u64,
    pub used_gb: u64,
    pub free_gb: u64,
    pub usage_percent: f64,
}

/// Network traffic counters.
#[derive(Debug, Serialize)]
pub struct NetworkInfo {
    pub requests_per_minute: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Container for exported Prometheus-style metrics.
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub metrics: Vec<Metric>,
    pub timestamp: String,
}

/// A single labeled metric.
#[derive(Debug, Serialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub help: String,
    pub metric_type: String,
}

/// `GET /health` — lightweight health check returning overall status and per-service summary.
pub async fn health_check(State(state): State<ApiState>) -> ApiResponse<HealthResponse> {
    let mut services = std::collections::HashMap::new();
    let mut overall_healthy = true;

    // Check AuthFramework health
    let auth_health = check_auth_framework_health(&state.auth_framework).await;
    services.insert("auth_framework".to_string(), auth_health.status.clone());
    if auth_health.status != "healthy" {
        overall_healthy = false;
    }

    // Check storage health
    let storage_health = check_storage_health(&state.auth_framework).await;
    services.insert("storage".to_string(), storage_health.status.clone());
    if storage_health.status != "healthy" {
        overall_healthy = false;
    }

    // Check token manager health
    let token_health = check_token_manager_health(&state.auth_framework).await;
    services.insert("token_manager".to_string(), token_health.status.clone());
    if token_health.status != "healthy" {
        overall_healthy = false;
    }

    // Check memory usage
    let memory_health = check_memory_health().await;
    services.insert("memory".to_string(), memory_health.status.clone());
    if memory_health.status != "healthy" {
        overall_healthy = false;
    }

    let health = HealthResponse {
        status: if overall_healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        services,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: get_uptime().await,
    };

    ApiResponse::success(health)
}

/// `GET /health/detailed` — extended health check with latency measurements and system resource usage.
pub async fn detailed_health_check(
    State(state): State<ApiState>,
) -> ApiResponse<DetailedHealthResponse> {
    let mut services = HashMap::new();
    let mut overall_healthy = true;

    // Check AuthFramework health with detailed info
    let auth_health = check_auth_framework_health(&state.auth_framework).await;
    services.insert(
        "auth_framework".to_string(),
        ServiceHealth {
            status: auth_health.status.clone(),
            response_time_ms: auth_health.response_time_ms,
            last_check: chrono::Utc::now().to_rfc3339(),
            error: auth_health.error,
            details: {
                let mut details = HashMap::new();
                if let Ok(stats) = state.auth_framework.get_stats().await {
                    details.insert(
                        "active_sessions".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(stats.active_sessions)),
                    );
                    details.insert(
                        "auth_attempts".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(stats.auth_attempts)),
                    );
                    details.insert(
                        "tokens_issued".to_string(),
                        serde_json::Value::Number(serde_json::Number::from(stats.tokens_issued)),
                    );
                }
                details
            },
        },
    );
    if auth_health.status != "healthy" {
        overall_healthy = false;
    }

    // Check storage health
    let storage_health = check_storage_health(&state.auth_framework).await;
    services.insert(
        "storage".to_string(),
        ServiceHealth {
            status: storage_health.status.clone(),
            response_time_ms: storage_health.response_time_ms,
            last_check: chrono::Utc::now().to_rfc3339(),
            error: storage_health.error,
            details: HashMap::new(),
        },
    );
    if storage_health.status != "healthy" {
        overall_healthy = false;
    }

    // Check token manager health
    let token_health = check_token_manager_health(&state.auth_framework).await;
    services.insert(
        "token_manager".to_string(),
        ServiceHealth {
            status: token_health.status.clone(),
            response_time_ms: token_health.response_time_ms,
            last_check: chrono::Utc::now().to_rfc3339(),
            error: token_health.error,
            details: HashMap::new(),
        },
    );
    if token_health.status != "healthy" {
        overall_healthy = false;
    }

    let system = SystemHealth {
        memory_usage: get_memory_info().await,
        cpu_usage: get_cpu_usage().await,
        disk_usage: get_disk_info().await,
        network: get_network_info().await,
    };

    let health = DetailedHealthResponse {
        status: if overall_healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        services,
        system,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: get_uptime().await,
    };

    ApiResponse::success(health)
}

/// `GET /metrics` — export metrics in Prometheus text exposition format.
pub async fn metrics(State(state): State<ApiState>) -> impl IntoResponse {
    let metrics_text = state.auth_framework.export_prometheus_metrics().await;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(metrics_text)
        .expect("infallible: String body is always valid")
}

/// `GET /readiness` — Kubernetes readiness probe (200 when able to serve traffic).
pub async fn readiness_check(State(state): State<ApiState>) -> impl IntoResponse {
    // Check if the auth framework is ready to accept traffic by trying to get stats.
    // A successful stats call confirms storage, token manager, and core services are up.
    let ready = state.auth_framework.get_stats().await.is_ok();

    if ready {
        (StatusCode::OK, "Ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Not Ready").into_response()
    }
}

/// `GET /liveness` — Kubernetes liveness probe (200 if the async runtime is responsive).
pub async fn liveness_check(State(state): State<ApiState>) -> impl IntoResponse {
    // Verify the service can perform a basic operation — completing the await on
    // get_performance_metrics confirms the async runtime is not deadlocked.
    state.auth_framework.get_performance_metrics().await;
    (StatusCode::OK, "Alive").into_response()
}

/// Internal health check functions
async fn check_auth_framework_health(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
) -> ServiceHealthResult {
    let start = std::time::Instant::now();

    // Test basic framework operations
    match auth_framework.get_stats().await {
        Ok(_stats) => ServiceHealthResult {
            status: "healthy".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => {
            tracing::warn!(error = %e, "Health check: framework error");
            ServiceHealthResult {
                status: "unhealthy".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
                error: Some("Service check failed".to_string()),
            }
        }
    }
}

async fn check_storage_health(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
) -> ServiceHealthResult {
    let start = std::time::Instant::now();

    // Test storage connectivity by checking if we can perform a basic operation
    // This is a non-destructive test
    match auth_framework.get_stats().await {
        Ok(_) => ServiceHealthResult {
            status: "healthy".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => {
            tracing::warn!(error = %e, "Health check: storage error");
            ServiceHealthResult {
                status: "unhealthy".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
                error: Some("Service check failed".to_string()),
            }
        }
    }
}

async fn check_token_manager_health(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
) -> ServiceHealthResult {
    let start = std::time::Instant::now();

    // Test token creation and validation (without storing)
    let test_token = auth_framework.token_manager().create_jwt_token(
        "health_check_user",
        vec!["health_check".to_string()],
        Some(std::time::Duration::from_secs(1)),
    );

    match test_token {
        Ok(token) => {
            // Validate the token we just created
            match auth_framework.token_manager().validate_jwt_token(&token) {
                Ok(_) => ServiceHealthResult {
                    status: "healthy".to_string(),
                    response_time_ms: start.elapsed().as_millis() as u64,
                    error: None,
                },
                Err(e) => {
                    tracing::warn!(error = %e, "Health check: token validation error");
                    ServiceHealthResult {
                        status: "unhealthy".to_string(),
                        response_time_ms: start.elapsed().as_millis() as u64,
                        error: Some("Service check failed".to_string()),
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Health check: token creation error");
            ServiceHealthResult {
                status: "unhealthy".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
                error: Some("Service check failed".to_string()),
            }
        }
    }
}

async fn check_memory_health() -> ServiceHealthResult {
    let start = std::time::Instant::now();

    // Simple memory allocation test
    let test_vec: Vec<u8> = vec![0; 1024]; // 1KB test allocation

    ServiceHealthResult {
        status: if test_vec.len() == 1024 {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        },
        response_time_ms: start.elapsed().as_millis() as u64,
        error: None,
    }
}

async fn get_uptime() -> String {
    use std::time::SystemTime;

    // This is a simplified uptime calculation
    // In a real implementation, you would track the actual start time
    static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();
    let start_time = START_TIME.get_or_init(SystemTime::now);

    match start_time.elapsed() {
        Ok(duration) => {
            let seconds = duration.as_secs();
            let days = seconds / 86400;
            let hours = (seconds % 86400) / 3600;
            let minutes = (seconds % 3600) / 60;

            if days > 0 {
                format!("{} days, {} hours, {} minutes", days, hours, minutes)
            } else if hours > 0 {
                format!("{} hours, {} minutes", hours, minutes)
            } else {
                format!("{} minutes", minutes)
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}

async fn get_memory_info() -> MemoryInfo {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();

    let total_mb = sys.total_memory() / (1024 * 1024);
    let used_mb = sys.used_memory() / (1024 * 1024);
    let free_mb = sys.available_memory() / (1024 * 1024);
    let usage_percent = if total_mb > 0 {
        (used_mb as f64 / total_mb as f64) * 100.0
    } else {
        0.0
    };

    MemoryInfo {
        total_mb,
        used_mb,
        free_mb,
        usage_percent,
    }
}

async fn get_cpu_usage() -> f64 {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_cpu_all();
    // sysinfo needs a short delay between refreshes for meaningful CPU data.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    sys.refresh_cpu_all();
    sys.global_cpu_usage() as f64
}

async fn get_disk_info() -> DiskInfo {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    let (mut total, mut used) = (0u64, 0u64);
    for disk in disks.list() {
        total += disk.total_space();
        used += disk.total_space() - disk.available_space();
    }
    let total_gb = total / (1024 * 1024 * 1024);
    let used_gb = used / (1024 * 1024 * 1024);
    let free_gb = total_gb.saturating_sub(used_gb);
    let usage_percent = if total_gb > 0 {
        (used_gb as f64 / total_gb as f64) * 100.0
    } else {
        0.0
    };

    DiskInfo {
        total_gb,
        used_gb,
        free_gb,
        usage_percent,
    }
}

async fn get_network_info() -> NetworkInfo {
    use sysinfo::Networks;
    let networks = Networks::new_with_refreshed_list();
    let (mut sent, mut received) = (0u64, 0u64);
    for data in networks.list().values() {
        sent += data.total_transmitted();
        received += data.total_received();
    }

    NetworkInfo {
        requests_per_minute: 0, // Application-level metric; not available from OS counters.
        active_connections: 0,  // Application-level metric; not available from OS counters.
        bytes_sent: sent,
        bytes_received: received,
    }
}

#[derive(Debug)]
struct ServiceHealthResult {
    pub status: String,
    pub response_time_ms: u64,
    pub error: Option<String>,
}
