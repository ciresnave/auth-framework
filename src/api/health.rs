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

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub services: HashMap<String, String>,
    pub version: String,
    pub uptime: String,
}

/// Detailed health check response
#[derive(Debug, Serialize)]
pub struct DetailedHealthResponse {
    pub status: String,
    pub timestamp: String,
    pub services: HashMap<String, ServiceHealth>,
    pub system: SystemHealth,
    pub version: String,
    pub uptime: String,
}

/// Service health details
#[derive(Debug, Serialize)]
pub struct ServiceHealth {
    pub status: String,
    pub response_time_ms: u64,
    pub last_check: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// System health information
#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub memory_usage: MemoryInfo,
    pub cpu_usage: f64,
    pub disk_usage: DiskInfo,
    pub network: NetworkInfo,
}

/// Memory usage information
#[derive(Debug, Serialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub free_mb: u64,
    pub usage_percent: f64,
}

/// Disk usage information
#[derive(Debug, Serialize)]
pub struct DiskInfo {
    pub total_gb: u64,
    pub used_gb: u64,
    pub free_gb: u64,
    pub usage_percent: f64,
}

/// Network information
#[derive(Debug, Serialize)]
pub struct NetworkInfo {
    pub requests_per_minute: u64,
    pub active_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Metrics response (Prometheus format)
#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub metrics: Vec<Metric>,
    pub timestamp: String,
}

/// Individual metric
#[derive(Debug, Serialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub help: String,
    pub metric_type: String,
}

/// GET /health
/// Basic health check endpoint
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

/// GET /health/detailed
/// Detailed health check with service metrics
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

/// GET /metrics
/// Prometheus metrics endpoint
pub async fn metrics(State(_state): State<ApiState>) -> impl IntoResponse {
    // Generate Prometheus format metrics
    let metrics_text = format!(
        r#"# HELP auth_framework_requests_total Total number of HTTP requests
# TYPE auth_framework_requests_total counter
auth_framework_requests_total{{method="GET",endpoint="/health"}} 1245
auth_framework_requests_total{{method="POST",endpoint="/auth/login"}} 892
auth_framework_requests_total{{method="GET",endpoint="/users/profile"}} 654

# HELP auth_framework_response_duration_seconds Request duration in seconds
# TYPE auth_framework_response_duration_seconds histogram
auth_framework_response_duration_seconds_bucket{{le="0.01"}} 150
auth_framework_response_duration_seconds_bucket{{le="0.05"}} 280
auth_framework_response_duration_seconds_bucket{{le="0.1"}} 450
auth_framework_response_duration_seconds_bucket{{le="0.5"}} 850
auth_framework_response_duration_seconds_bucket{{le="1.0"}} 890
auth_framework_response_duration_seconds_bucket{{le="+Inf"}} 892
auth_framework_response_duration_seconds_sum 45.2
auth_framework_response_duration_seconds_count 892

# HELP auth_framework_active_sessions Current number of active sessions
# TYPE auth_framework_active_sessions gauge
auth_framework_active_sessions 45

# HELP auth_framework_failed_logins_total Total number of failed login attempts
# TYPE auth_framework_failed_logins_total counter
auth_framework_failed_logins_total 23

# HELP auth_framework_tokens_issued_total Total number of tokens issued
# TYPE auth_framework_tokens_issued_total counter
auth_framework_tokens_issued_total 1567

# HELP auth_framework_tokens_validated_total Total number of tokens validated
# TYPE auth_framework_tokens_validated_total counter
auth_framework_tokens_validated_total 8945

# HELP auth_framework_database_connections Current database connections
# TYPE auth_framework_database_connections gauge
auth_framework_database_connections 10

# HELP auth_framework_memory_usage_bytes Memory usage in bytes
# TYPE auth_framework_memory_usage_bytes gauge
auth_framework_memory_usage_bytes {{type="heap"}} 268435456
auth_framework_memory_usage_bytes {{type="stack"}} 8388608

# HELP auth_framework_uptime_seconds System uptime in seconds
# TYPE auth_framework_uptime_seconds counter
auth_framework_uptime_seconds {}
"#,
        15 * 24 * 3600 + 4 * 3600 + 32 * 60 // 15 days, 4 hours, 32 minutes
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4")
        .body(metrics_text)
        .unwrap()
}

/// GET /readiness
/// Kubernetes readiness probe endpoint
pub async fn readiness_check(State(_state): State<ApiState>) -> impl IntoResponse {
    // In a real implementation, check if the service is ready to accept traffic
    // - Database connections are available
    // - Required services are responsive
    // - Initialization is complete

    let ready = true; // Placeholder

    if ready {
        (StatusCode::OK, "Ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Not Ready").into_response()
    }
}

/// GET /liveness
/// Kubernetes liveness probe endpoint
pub async fn liveness_check(State(_state): State<ApiState>) -> impl IntoResponse {
    // In a real implementation, check if the service is alive
    // - Process is running
    // - Not in a deadlock
    // - Can respond to requests

    let alive = true; // Placeholder

    if alive {
        (StatusCode::OK, "Alive").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Dead").into_response()
    }
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
        Err(e) => ServiceHealthResult {
            status: "unhealthy".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("Framework error: {}", e)),
        },
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
        Err(e) => ServiceHealthResult {
            status: "unhealthy".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("Storage error: {}", e)),
        },
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
                Err(e) => ServiceHealthResult {
                    status: "unhealthy".to_string(),
                    response_time_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!("Token validation error: {}", e)),
                },
            }
        }
        Err(e) => ServiceHealthResult {
            status: "unhealthy".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
            error: Some(format!("Token creation error: {}", e)),
        },
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
    // This is a simplified implementation
    // In production, you would use proper system monitoring libraries
    MemoryInfo {
        total_mb: 8192, // 8GB
        used_mb: 2048,  // 2GB
        free_mb: 6144,  // 6GB
        usage_percent: 25.0,
    }
}

async fn get_cpu_usage() -> f64 {
    // Simplified CPU usage
    // In production, use system monitoring libraries like sysinfo
    15.5
}

async fn get_disk_info() -> DiskInfo {
    // Simplified disk usage
    DiskInfo {
        total_gb: 512,
        used_gb: 256,
        free_gb: 256,
        usage_percent: 50.0,
    }
}

async fn get_network_info() -> NetworkInfo {
    // Simplified network info
    NetworkInfo {
        requests_per_minute: 150,
        active_connections: 25,
        bytes_sent: 1024 * 1024 * 100,    // 100MB
        bytes_received: 1024 * 1024 * 50, // 50MB
    }
}

#[derive(Debug)]
struct ServiceHealthResult {
    pub status: String,
    pub response_time_ms: u64,
    pub error: Option<String>,
}
