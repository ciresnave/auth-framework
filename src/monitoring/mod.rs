//! Monitoring and Metrics Collection Module
//!
//! This module provides comprehensive monitoring capabilities for the authentication framework,
//! including metrics collection, performance monitoring, security event tracking, and
//! integration with external monitoring systems.
//!
//! # Features
//!
//! - **Performance Metrics**: Track authentication performance, latency, and throughput
//! - **Security Monitoring**: Monitor security events, failed attempts, and anomalies
//! - **Health Checks**: Provide health status for all authentication components
//! - **Custom Metrics**: Support for application-specific metrics
//! - **Integration**: Export metrics to Prometheus, Grafana, DataDog, etc.
//! - **Alerting**: Configuration-based alerting for critical events

use crate::errors::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub mod alerts;
pub mod collectors;
pub mod exporters;
pub mod health;

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable monitoring system
    pub enabled: bool,
    /// Collection interval in seconds
    pub collection_interval: u64,
    /// Maximum metrics history size
    pub max_history_size: usize,
    /// Enable performance monitoring
    pub enable_performance_metrics: bool,
    /// Enable security monitoring
    pub enable_security_metrics: bool,
    /// Enable health checks
    pub enable_health_checks: bool,
    /// External monitoring endpoints
    pub external_endpoints: Vec<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval: 60, // 1 minute
            max_history_size: 1000,
            enable_performance_metrics: true,
            enable_security_metrics: true,
            enable_health_checks: true,
            external_endpoints: vec![],
        }
    }
}

/// Metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    /// Metric name
    pub name: String,
    /// Metric value
    pub value: f64,
    /// Timestamp
    pub timestamp: u64,
    /// Labels/tags
    pub labels: HashMap<String, String>,
    /// Metric type
    pub metric_type: MetricType,
}

/// Types of metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    /// Counter - monotonically increasing
    Counter,
    /// Gauge - can go up and down
    Gauge,
    /// Histogram - distribution of values
    Histogram,
    /// Summary - like histogram with quantiles
    Summary,
}

/// Security event for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event type
    pub event_type: SecurityEventType,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// Event details
    pub details: HashMap<String, String>,
    /// Severity level
    pub severity: SecurityEventSeverity,
    /// Timestamp
    pub timestamp: u64,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    /// Failed login attempt
    FailedLogin,
    /// Account lockout
    AccountLockout,
    /// Privilege escalation
    PrivilegeEscalation,
    /// Unusual activity pattern
    UnusualActivity,
    /// Token manipulation
    TokenManipulation,
    /// Configuration change
    ConfigurationChange,
    /// System error
    SystemError,
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum SecurityEventSeverity {
    /// Low severity
    Low = 1,
    /// Medium severity
    Medium = 2,
    /// High severity
    High = 3,
    /// Critical severity
    Critical = 4,
}

/// Performance metrics
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Authentication request count
    pub auth_requests: Arc<AtomicU64>,
    /// Successful authentications
    pub auth_successes: Arc<AtomicU64>,
    /// Failed authentications
    pub auth_failures: Arc<AtomicU64>,
    /// Token creation count
    pub token_creations: Arc<AtomicU64>,
    /// Token validation count
    pub token_validations: Arc<AtomicU64>,
    /// Session count
    pub active_sessions: Arc<AtomicU64>,
    /// MFA challenges
    pub mfa_challenges: Arc<AtomicU64>,
    /// Average response time (microseconds)
    pub avg_response_time: Arc<AtomicU64>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            auth_requests: Arc::new(AtomicU64::new(0)),
            auth_successes: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            token_creations: Arc::new(AtomicU64::new(0)),
            token_validations: Arc::new(AtomicU64::new(0)),
            active_sessions: Arc::new(AtomicU64::new(0)),
            mfa_challenges: Arc::new(AtomicU64::new(0)),
            avg_response_time: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Minor issues, still functional
    Degraded,
    /// Major issues, limited functionality
    Unhealthy,
    /// System down
    Critical,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Component name
    pub component: String,
    /// Health status
    pub status: HealthStatus,
    /// Status message
    pub message: String,
    /// Last check timestamp
    pub timestamp: u64,
    /// Response time in milliseconds
    pub response_time: u64,
}

/// Main monitoring manager
pub struct MonitoringManager {
    /// Configuration
    config: MonitoringConfig,
    /// Performance metrics
    performance: PerformanceMetrics,
    /// Metric history
    metrics_history: Arc<RwLock<Vec<MetricDataPoint>>>,
    /// Security events
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Health check results
    health_results: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
}

impl MonitoringManager {
    /// Create new monitoring manager
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            config,
            performance: PerformanceMetrics::default(),
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            security_events: Arc::new(RwLock::new(Vec::new())),
            health_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record authentication request
    pub async fn record_auth_request(&self) {
        self.performance
            .auth_requests
            .fetch_add(1, Ordering::Relaxed);

        if self.config.enable_performance_metrics {
            self.record_metric(MetricDataPoint {
                name: "auth_requests_total".to_string(),
                value: self.performance.auth_requests.load(Ordering::Relaxed) as f64,
                timestamp: current_timestamp(),
                labels: HashMap::new(),
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Record successful authentication
    pub async fn record_auth_success(&self, user_id: &str, duration: Duration) {
        self.performance
            .auth_successes
            .fetch_add(1, Ordering::Relaxed);
        self.update_avg_response_time(duration).await;

        if self.config.enable_performance_metrics {
            let mut labels = HashMap::new();
            labels.insert("result".to_string(), "success".to_string());
            labels.insert("user_id".to_string(), user_id.to_string());

            self.record_metric(MetricDataPoint {
                name: "auth_attempts_total".to_string(),
                value: 1.0,
                timestamp: current_timestamp(),
                labels,
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Record failed authentication
    pub async fn record_auth_failure(&self, user_id: Option<&str>, reason: &str) {
        self.performance
            .auth_failures
            .fetch_add(1, Ordering::Relaxed);

        if self.config.enable_security_metrics {
            let mut details = HashMap::new();
            details.insert("reason".to_string(), reason.to_string());
            if let Some(user) = user_id {
                details.insert("user_id".to_string(), user.to_string());
            }

            let security_event = SecurityEvent {
                event_type: SecurityEventType::FailedLogin,
                user_id: user_id.map(|s| s.to_string()),
                ip_address: None, // Would be populated from request context
                details,
                severity: SecurityEventSeverity::Medium,
                timestamp: current_timestamp(),
            };

            self.record_security_event(security_event).await;
        }

        if self.config.enable_performance_metrics {
            let mut labels = HashMap::new();
            labels.insert("result".to_string(), "failure".to_string());
            labels.insert("reason".to_string(), reason.to_string());

            self.record_metric(MetricDataPoint {
                name: "auth_attempts_total".to_string(),
                value: 1.0,
                timestamp: current_timestamp(),
                labels,
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Record token creation
    pub async fn record_token_creation(&self, token_type: &str) {
        self.performance
            .token_creations
            .fetch_add(1, Ordering::Relaxed);

        if self.config.enable_performance_metrics {
            let mut labels = HashMap::new();
            labels.insert("token_type".to_string(), token_type.to_string());

            self.record_metric(MetricDataPoint {
                name: "tokens_created_total".to_string(),
                value: 1.0,
                timestamp: current_timestamp(),
                labels,
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Record token validation
    pub async fn record_token_validation(&self, valid: bool) {
        self.performance
            .token_validations
            .fetch_add(1, Ordering::Relaxed);

        if self.config.enable_performance_metrics {
            let mut labels = HashMap::new();
            labels.insert(
                "result".to_string(),
                if valid { "valid" } else { "invalid" }.to_string(),
            );

            self.record_metric(MetricDataPoint {
                name: "tokens_validated_total".to_string(),
                value: 1.0,
                timestamp: current_timestamp(),
                labels,
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Update session count
    pub async fn update_session_count(&self, count: u64) {
        self.performance
            .active_sessions
            .store(count, Ordering::Relaxed);

        if self.config.enable_performance_metrics {
            self.record_metric(MetricDataPoint {
                name: "active_sessions".to_string(),
                value: count as f64,
                timestamp: current_timestamp(),
                labels: HashMap::new(),
                metric_type: MetricType::Gauge,
            })
            .await;
        }
    }

    /// Record MFA challenge
    pub async fn record_mfa_challenge(&self, method: &str) {
        self.performance
            .mfa_challenges
            .fetch_add(1, Ordering::Relaxed);

        if self.config.enable_performance_metrics {
            let mut labels = HashMap::new();
            labels.insert("method".to_string(), method.to_string());

            self.record_metric(MetricDataPoint {
                name: "mfa_challenges_total".to_string(),
                value: 1.0,
                timestamp: current_timestamp(),
                labels,
                metric_type: MetricType::Counter,
            })
            .await;
        }
    }

    /// Record security event
    pub async fn record_security_event(&self, event: SecurityEvent) {
        if !self.config.enable_security_metrics {
            return;
        }

        let mut events = self.security_events.write().await;
        events.push(event.clone());

        // Keep only recent events
        if events.len() > self.config.max_history_size {
            events.remove(0);
        }

        tracing::warn!(
            "Security event: {:?} - User: {:?}, Severity: {:?}",
            event.event_type,
            event.user_id,
            event.severity
        );

        // Alert on critical events
        if event.severity == SecurityEventSeverity::Critical {
            // Would trigger external alerting system
            tracing::error!("CRITICAL security event: {:?}", event);
        }
    }

    /// Record generic metric
    async fn record_metric(&self, metric: MetricDataPoint) {
        if !self.config.enabled {
            return;
        }

        let mut metrics = self.metrics_history.write().await;
        metrics.push(metric);

        // Keep history size manageable
        if metrics.len() > self.config.max_history_size {
            metrics.remove(0);
        }
    }

    /// Update average response time
    async fn update_avg_response_time(&self, duration: Duration) {
        let current_avg = self.performance.avg_response_time.load(Ordering::Relaxed);
        let new_time = duration.as_micros() as u64;

        // Simple moving average
        let updated_avg = if current_avg == 0 {
            new_time
        } else {
            (current_avg + new_time) / 2
        };

        self.performance
            .avg_response_time
            .store(updated_avg, Ordering::Relaxed);
    }

    /// Get current performance metrics
    pub fn get_performance_metrics(&self) -> HashMap<String, u64> {
        let mut metrics = HashMap::new();
        metrics.insert(
            "auth_requests".to_string(),
            self.performance.auth_requests.load(Ordering::Relaxed),
        );
        metrics.insert(
            "auth_successes".to_string(),
            self.performance.auth_successes.load(Ordering::Relaxed),
        );
        metrics.insert(
            "auth_failures".to_string(),
            self.performance.auth_failures.load(Ordering::Relaxed),
        );
        metrics.insert(
            "token_creations".to_string(),
            self.performance.token_creations.load(Ordering::Relaxed),
        );
        metrics.insert(
            "token_validations".to_string(),
            self.performance.token_validations.load(Ordering::Relaxed),
        );
        metrics.insert(
            "active_sessions".to_string(),
            self.performance.active_sessions.load(Ordering::Relaxed),
        );
        metrics.insert(
            "mfa_challenges".to_string(),
            self.performance.mfa_challenges.load(Ordering::Relaxed),
        );
        metrics.insert(
            "avg_response_time_us".to_string(),
            self.performance.avg_response_time.load(Ordering::Relaxed),
        );
        metrics
    }

    /// Get security events
    pub async fn get_security_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        let events = self.security_events.read().await;
        let limit = limit.unwrap_or(100);

        if events.len() <= limit {
            events.clone()
        } else {
            events.iter().rev().take(limit).cloned().collect()
        }
    }

    /// Get metrics history
    pub async fn get_metrics_history(&self, metric_name: Option<&str>) -> Vec<MetricDataPoint> {
        let metrics = self.metrics_history.read().await;

        if let Some(name) = metric_name {
            metrics.iter().filter(|m| m.name == name).cloned().collect()
        } else {
            metrics.clone()
        }
    }

    /// Perform health check
    pub async fn health_check(&self) -> Result<HashMap<String, HealthCheckResult>> {
        if !self.config.enable_health_checks {
            return Ok(HashMap::new());
        }

        let mut results = HashMap::new();
        let start_time = SystemTime::now();

        // Check authentication system health
        let auth_health = self.check_auth_health().await;
        results.insert("authentication".to_string(), auth_health);

        // Check storage health
        let storage_health = self.check_storage_health().await;
        results.insert("storage".to_string(), storage_health);

        // Check token system health
        let token_health = self.check_token_health().await;
        results.insert("tokens".to_string(), token_health);

        // Update health results cache
        let mut health_cache = self.health_results.write().await;
        for (component, result) in &results {
            health_cache.insert(component.clone(), result.clone());
        }

        let elapsed = start_time.elapsed().unwrap_or_default();
        tracing::debug!("Health check completed in {:?}", elapsed);

        Ok(results)
    }

    /// Check authentication system health
    async fn check_auth_health(&self) -> HealthCheckResult {
        let start_time = SystemTime::now();

        // Check basic metrics
        let auth_requests = self.performance.auth_requests.load(Ordering::Relaxed);
        let auth_failures = self.performance.auth_failures.load(Ordering::Relaxed);

        let status = if auth_requests > 0 {
            let failure_rate = (auth_failures as f64) / (auth_requests as f64);
            if failure_rate > 0.5 {
                HealthStatus::Unhealthy
            } else if failure_rate > 0.2 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            }
        } else {
            HealthStatus::Healthy
        };

        let message = match status {
            HealthStatus::Healthy => "Authentication system operating normally".to_string(),
            HealthStatus::Degraded => format!(
                "High failure rate: {:.1}%",
                (auth_failures as f64 / auth_requests as f64) * 100.0
            ),
            HealthStatus::Unhealthy => format!(
                "Critical failure rate: {:.1}%",
                (auth_failures as f64 / auth_requests as f64) * 100.0
            ),
            HealthStatus::Critical => "Authentication system down".to_string(),
        };

        HealthCheckResult {
            component: "authentication".to_string(),
            status,
            message,
            timestamp: current_timestamp(),
            response_time: start_time.elapsed().unwrap_or_default().as_millis() as u64,
        }
    }

    /// Check storage system health
    async fn check_storage_health(&self) -> HealthCheckResult {
        let start_time = SystemTime::now();

        // In production: Check database connectivity, response times, etc.
        // For now: Simple status check

        HealthCheckResult {
            component: "storage".to_string(),
            status: HealthStatus::Healthy,
            message: "Storage system operational".to_string(),
            timestamp: current_timestamp(),
            response_time: start_time.elapsed().unwrap_or_default().as_millis() as u64,
        }
    }

    /// Check token system health
    async fn check_token_health(&self) -> HealthCheckResult {
        let start_time = SystemTime::now();

        let token_validations = self.performance.token_validations.load(Ordering::Relaxed);

        HealthCheckResult {
            component: "tokens".to_string(),
            status: HealthStatus::Healthy,
            message: format!(
                "Token system operational - {} validations",
                token_validations
            ),
            timestamp: current_timestamp(),
            response_time: start_time.elapsed().unwrap_or_default().as_millis() as u64,
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus_metrics(&self) -> String {
        let mut output = String::new();

        let metrics = self.get_performance_metrics();

        for (name, value) in metrics {
            output.push_str(&format!(
                "# HELP auth_{} Authentication framework metric\n",
                name
            ));
            output.push_str(&format!("# TYPE auth_{} counter\n", name));
            output.push_str(&format!("auth_{} {}\n", name, value));
        }

        output
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_monitoring_manager_creation() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);

        let metrics = manager.get_performance_metrics();
        assert_eq!(metrics["auth_requests"], 0);
    }

    #[tokio::test]
    async fn test_auth_request_recording() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);

        manager.record_auth_request().await;
        manager.record_auth_request().await;

        let metrics = manager.get_performance_metrics();
        assert_eq!(metrics["auth_requests"], 2);
    }

    #[tokio::test]
    async fn test_security_event_recording() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);

        let event = SecurityEvent {
            event_type: SecurityEventType::FailedLogin,
            user_id: Some("test_user".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            details: HashMap::new(),
            severity: SecurityEventSeverity::Medium,
            timestamp: current_timestamp(),
        };

        manager.record_security_event(event).await;

        let events = manager.get_security_events(None).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, SecurityEventType::FailedLogin);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);

        let health_results = manager.health_check().await.unwrap();

        assert!(health_results.contains_key("authentication"));
        assert!(health_results.contains_key("storage"));
        assert!(health_results.contains_key("tokens"));
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);

        manager.record_auth_request().await;

        let prometheus_output = manager.export_prometheus_metrics().await;

        assert!(prometheus_output.contains("auth_auth_requests"));
        assert!(prometheus_output.contains("# HELP"));
        assert!(prometheus_output.contains("# TYPE"));
    }
}
