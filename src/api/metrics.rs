//! API Metrics and Observability
//!
//! Provides comprehensive metrics collection for API endpoints

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Metrics collector for API endpoints
#[derive(Debug, Clone)]
pub struct ApiMetrics {
    inner: Arc<Mutex<ApiMetricsInner>>,
}

#[derive(Debug)]
struct ApiMetricsInner {
    request_counts: HashMap<String, u64>,
    response_times: HashMap<String, Vec<Duration>>,
    error_counts: HashMap<String, u64>,
    active_requests: u64,
    start_time: Instant,
}

impl ApiMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ApiMetricsInner {
                request_counts: HashMap::new(),
                response_times: HashMap::new(),
                error_counts: HashMap::new(),
                active_requests: 0,
                start_time: Instant::now(),
            })),
        }
    }

    pub fn record_request(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        *inner.request_counts.entry(path.to_string()).or_insert(0) += 1;
        inner.active_requests += 1;
    }

    pub fn record_response(&self, path: &str, duration: Duration, status: StatusCode) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .response_times
            .entry(path.to_string())
            .or_default()
            .push(duration);

        if status.is_client_error() || status.is_server_error() {
            *inner.error_counts.entry(path.to_string()).or_insert(0) += 1;
        }

        inner.active_requests = inner.active_requests.saturating_sub(1);
    }

    pub fn get_metrics(&self) -> MetricsSnapshot {
        let inner = self.inner.lock().unwrap();
        let mut endpoint_metrics = HashMap::new();

        for (path, &count) in &inner.request_counts {
            let response_times = inner.response_times.get(path).cloned().unwrap_or_default();
            let error_count = inner.error_counts.get(path).copied().unwrap_or(0);

            let avg_response_time = if !response_times.is_empty() {
                response_times.iter().sum::<Duration>() / response_times.len() as u32
            } else {
                Duration::ZERO
            };

            let p95_response_time = calculate_percentile(&response_times, 95.0);
            let p99_response_time = calculate_percentile(&response_times, 99.0);

            endpoint_metrics.insert(
                path.clone(),
                EndpointMetrics {
                    request_count: count,
                    error_count,
                    error_rate: if count > 0 {
                        error_count as f64 / count as f64
                    } else {
                        0.0
                    },
                    avg_response_time,
                    p95_response_time,
                    p99_response_time,
                },
            );
        }

        MetricsSnapshot {
            uptime: inner.start_time.elapsed(),
            total_requests: inner.request_counts.values().sum(),
            active_requests: inner.active_requests,
            endpoint_metrics,
        }
    }

    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.request_counts.clear();
        inner.response_times.clear();
        inner.error_counts.clear();
        inner.start_time = Instant::now();
    }
}

impl Default for ApiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub uptime: Duration,
    pub total_requests: u64,
    pub active_requests: u64,
    pub endpoint_metrics: HashMap<String, EndpointMetrics>,
}

#[derive(Debug, Clone)]
pub struct EndpointMetrics {
    pub request_count: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub avg_response_time: Duration,
    pub p95_response_time: Duration,
    pub p99_response_time: Duration,
}

/// Calculate percentile from a sorted list of durations
fn calculate_percentile(durations: &[Duration], percentile: f64) -> Duration {
    if durations.is_empty() {
        return Duration::ZERO;
    }

    let mut sorted = durations.to_vec();
    sorted.sort();

    let index = ((percentile / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted.get(index).copied().unwrap_or(Duration::ZERO)
}

/// Middleware for collecting API metrics
pub async fn metrics_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let start_time = Instant::now();
    let path = request.uri().path().to_string();

    // Get metrics collector from extensions or create new one
    let metrics = request
        .extensions()
        .get::<ApiMetrics>()
        .cloned()
        .unwrap_or_default();

    metrics.record_request(&path);

    let response = next.run(request).await;
    let duration = start_time.elapsed();

    metrics.record_response(&path, duration, response.status());

    Ok(response)
}

/// Prometheus metrics format output
impl MetricsSnapshot {
    pub fn to_prometheus_format(&self) -> String {
        let mut output = String::new();

        // System metrics
        output.push_str(&format!(
            "# HELP auth_framework_uptime_seconds Total uptime in seconds\n\
             # TYPE auth_framework_uptime_seconds counter\n\
             auth_framework_uptime_seconds {}\n\n",
            self.uptime.as_secs()
        ));

        output.push_str(&format!(
            "# HELP auth_framework_requests_total Total number of requests\n\
             # TYPE auth_framework_requests_total counter\n\
             auth_framework_requests_total {}\n\n",
            self.total_requests
        ));

        output.push_str(&format!(
            "# HELP auth_framework_active_requests Current number of active requests\n\
             # TYPE auth_framework_active_requests gauge\n\
             auth_framework_active_requests {}\n\n",
            self.active_requests
        ));

        // Endpoint metrics
        for (endpoint, metrics) in &self.endpoint_metrics {
            let _safe_endpoint = endpoint.replace(['/', '-'], "_");

            output.push_str(&format!(
                "auth_framework_endpoint_requests_total{{endpoint=\"{}\"}} {}\n",
                endpoint, metrics.request_count
            ));

            output.push_str(&format!(
                "auth_framework_endpoint_errors_total{{endpoint=\"{}\"}} {}\n",
                endpoint, metrics.error_count
            ));

            output.push_str(&format!(
                "auth_framework_endpoint_response_time_avg{{endpoint=\"{}\"}} {}\n",
                endpoint,
                metrics.avg_response_time.as_secs_f64()
            ));

            output.push_str(&format!(
                "auth_framework_endpoint_response_time_p95{{endpoint=\"{}\"}} {}\n",
                endpoint,
                metrics.p95_response_time.as_secs_f64()
            ));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let metrics = ApiMetrics::new();

        metrics.record_request("/api/login");
        metrics.record_response("/api/login", Duration::from_millis(100), StatusCode::OK);

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.total_requests, 1);
        assert_eq!(snapshot.endpoint_metrics["/api/login"].request_count, 1);
        assert_eq!(snapshot.endpoint_metrics["/api/login"].error_count, 0);
    }

    #[test]
    fn test_error_tracking() {
        let metrics = ApiMetrics::new();

        metrics.record_request("/api/test");
        metrics.record_response(
            "/api/test",
            Duration::from_millis(50),
            StatusCode::BAD_REQUEST,
        );

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.endpoint_metrics["/api/test"].error_count, 1);
        assert!(snapshot.endpoint_metrics["/api/test"].error_rate > 0.0);
    }

    #[test]
    fn test_percentile_calculation() {
        let durations = vec![
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(30),
            Duration::from_millis(40),
            Duration::from_millis(100),
        ];

        let p95 = calculate_percentile(&durations, 95.0);
        assert_eq!(p95, Duration::from_millis(100));
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = ApiMetrics::new();
        metrics.record_request("/api/test");
        metrics.record_response("/api/test", Duration::from_millis(100), StatusCode::OK);

        let snapshot = metrics.get_metrics();
        let prometheus = snapshot.to_prometheus_format();

        assert!(prometheus.contains("auth_framework_requests_total"));
        assert!(prometheus.contains("auth_framework_active_requests"));
        assert!(prometheus.contains("endpoint=\"/api/test\""));
    }
}
