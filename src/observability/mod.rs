//! Enhanced observability with metrics and monitoring (simplified version)
//!
//! This module provides comprehensive observability features including:
//! - Prometheus metrics collection
//! - Real-time performance monitoring
//! - Security event monitoring
//! - Custom metric dashboards

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;

#[cfg(feature = "prometheus")]
use prometheus::{
    Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry,
    register_gauge_with_registry, register_histogram_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry,
};

/// Comprehensive observability manager (simplified).
///
/// # Example
/// ```rust,ignore
/// let mgr = ObservabilityManager::new()?;
/// mgr.record_auth_attempt(true, Duration::from_millis(5), "password").await;
/// ```
pub struct ObservabilityManager {
    /// Prometheus metrics registry
    #[cfg(feature = "prometheus")]
    registry: Registry,

    /// Prometheus metrics
    #[cfg(feature = "prometheus")]
    metrics: PrometheusMetrics,

    /// Real-time performance metrics
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,

    /// Security event monitoring
    security_monitor: Arc<SecurityMonitor>,

    /// Configuration
    config: ObservabilityConfig,
}

/// Prometheus metrics collection
#[cfg(feature = "prometheus")]
#[derive(Clone)]
pub struct PrometheusMetrics {
    // Authentication metrics
    pub auth_requests_total: IntCounter,
    pub auth_success_total: IntCounter,
    pub auth_failures_total: IntCounter,
    pub auth_duration: Histogram,

    // Token metrics
    pub tokens_issued_total: IntCounter,
    pub tokens_validated_total: IntCounter,
    pub tokens_revoked_total: IntCounter,
    pub active_tokens: IntGauge,

    // Session metrics
    pub sessions_created_total: IntCounter,
    pub sessions_destroyed_total: IntCounter,
    pub active_sessions: IntGauge,
    pub session_duration: Histogram,

    // Storage metrics
    pub storage_operations_total: IntCounter,
    pub storage_errors_total: IntCounter,
    pub storage_latency: Histogram,
    pub storage_memory_usage: Gauge,

    // Security metrics
    pub security_events_total: IntCounter,
    pub rate_limit_hits_total: IntCounter,
    pub suspicious_activity_total: IntCounter,

    // Performance metrics
    pub cpu_usage: Gauge,
    pub memory_usage: Gauge,
    pub concurrent_requests: IntGauge,
}

/// Real-time performance metrics
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub requests_per_second: f64,
    pub average_response_time: Duration,
    pub p95_response_time: Duration,
    pub p99_response_time: Duration,
    pub error_rate: f64,
    pub active_connections: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub cache_hit_rate: f64,
    pub storage_operations_per_second: f64,
}

/// Security event monitoring
pub struct SecurityMonitor {
    failed_attempts: Arc<AtomicU64>,
    rate_limit_violations: Arc<AtomicU64>,
    suspicious_patterns: Arc<RwLock<HashMap<String, SuspiciousActivity>>>,
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    threat_levels: Arc<RwLock<HashMap<String, ThreatLevel>>>,
}

/// Suspicious activity tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    pub user_id: String,
    pub ip_address: String,
    pub activity_type: String,
    pub count: u64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub risk_score: f64,
}

/// Security event for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub event_type: SecurityEventType,
    pub timestamp: SystemTime,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub details: HashMap<String, String>,
    pub severity: EventSeverity,
    pub action_taken: Option<String>,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthFailure,
    SuspiciousLogin,
    RateLimitExceeded,
    TokenAbuse,
    PrivilegeEscalation,
    DataExfiltration,
    BruteForceAttempt,
    AccountLockout,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat level assessment
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Observability configuration.
///
/// # Example
/// ```rust
/// use auth_framework::observability::ObservabilityConfig;
/// let config = ObservabilityConfig::default();
/// assert!(config.enable_prometheus);
/// ```
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    pub enable_prometheus: bool,
    pub enable_opentelemetry: bool,
    pub enable_security_monitoring: bool,
    pub metrics_retention_hours: u64,
    pub trace_sampling_ratio: f64,
    pub security_event_max_count: usize,
    pub performance_window_seconds: u64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            enable_opentelemetry: true,
            enable_security_monitoring: true,
            metrics_retention_hours: 24,
            trace_sampling_ratio: 0.1,
            security_event_max_count: 10000,
            performance_window_seconds: 300, // 5 minutes
        }
    }
}

impl ObservabilityManager {
    /// Create new observability manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mgr = ObservabilityManager::new()?;
    /// ```
    pub fn new() -> Result<Self> {
        Self::with_config(ObservabilityConfig::default())
    }

    /// Create with custom configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mgr = ObservabilityManager::with_config(ObservabilityConfig::default())?;
    /// ```
    pub fn with_config(config: ObservabilityConfig) -> Result<Self> {
        #[cfg(feature = "prometheus")]
        let registry = Registry::new();

        #[cfg(feature = "prometheus")]
        let metrics = PrometheusMetrics::new(&registry)?;

        let performance_metrics = Arc::new(RwLock::new(PerformanceMetrics::default()));
        let security_monitor = Arc::new(SecurityMonitor::new());

        let manager = Self {
            #[cfg(feature = "prometheus")]
            registry,
            #[cfg(feature = "prometheus")]
            metrics,
            performance_metrics,
            security_monitor,
            config,
        };

        Ok(manager)
    }

    /// Get observability configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let cfg = mgr.get_config();
    /// ```
    pub fn get_config(&self) -> &ObservabilityConfig {
        &self.config
    }

    /// Get security monitor.
    ///
    /// # Example
    /// ```rust,ignore
    /// let monitor = mgr.get_security_monitor();
    /// ```
    pub fn get_security_monitor(&self) -> &SecurityMonitor {
        &self.security_monitor
    }

    /// Record authentication attempt.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.record_auth_attempt(true, Duration::from_millis(5), "password").await;
    /// ```
    pub async fn record_auth_attempt(&self, success: bool, duration: Duration, _method: &str) {
        #[cfg(feature = "prometheus")]
        {
            self.metrics.auth_requests_total.inc();
            if success {
                self.metrics.auth_success_total.inc();
            } else {
                self.metrics.auth_failures_total.inc();
            }
            self.metrics.auth_duration.observe(duration.as_secs_f64());
        }

        // Update performance metrics
        self.update_performance_metrics(duration, success).await;
    }

    /// Record token operation.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.record_token_operation("issue", "token-1").await;
    /// ```
    pub async fn record_token_operation(&self, operation: &str, _token_id: &str) {
        #[cfg(feature = "prometheus")]
        {
            match operation {
                "issue" => self.metrics.tokens_issued_total.inc(),
                "validate" => self.metrics.tokens_validated_total.inc(),
                "revoke" => self.metrics.tokens_revoked_total.inc(),
                _ => {}
            }
        }
    }

    /// Record session operation.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.record_session_operation("create", Some(Duration::from_secs(3600))).await;
    /// ```
    pub async fn record_session_operation(&self, operation: &str, duration: Option<Duration>) {
        #[cfg(feature = "prometheus")]
        {
            match operation {
                "create" => self.metrics.sessions_created_total.inc(),
                "destroy" => self.metrics.sessions_destroyed_total.inc(),
                _ => {}
            }

            if let Some(dur) = duration {
                self.metrics.session_duration.observe(dur.as_secs_f64());
            }
        }
    }

    /// Record storage operation.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.record_storage_operation("get", Duration::from_micros(200), true).await;
    /// ```
    pub async fn record_storage_operation(
        &self,
        _operation: &str,
        latency: Duration,
        success: bool,
    ) {
        #[cfg(feature = "prometheus")]
        {
            self.metrics.storage_operations_total.inc();
            if !success {
                self.metrics.storage_errors_total.inc();
            }
            self.metrics.storage_latency.observe(latency.as_secs_f64());
        }
    }

    /// Record security event.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.record_security_event(event).await;
    /// ```
    pub async fn record_security_event(&self, event: SecurityEvent) {
        #[cfg(feature = "prometheus")]
        {
            self.metrics.security_events_total.inc();

            match event.event_type {
                SecurityEventType::RateLimitExceeded => self.metrics.rate_limit_hits_total.inc(),
                SecurityEventType::BruteForceAttempt
                | SecurityEventType::SuspiciousLogin
                | SecurityEventType::TokenAbuse => self.metrics.suspicious_activity_total.inc(),
                _ => {}
            }
        }

        // Store security event
        self.security_monitor.record_event(event).await;
    }

    /// Update performance metrics
    async fn update_performance_metrics(&self, response_time: Duration, success: bool) {
        let mut metrics = self.performance_metrics.write().await;

        // Update response time statistics (simplified moving average)
        metrics.average_response_time = Duration::from_millis(
            (metrics.average_response_time.as_millis() as f64 * 0.95
                + response_time.as_millis() as f64 * 0.05) as u64,
        );

        // Update error rate (simplified moving average)
        let error_increment = if success { 0.0 } else { 1.0 };
        metrics.error_rate = metrics.error_rate * 0.95 + error_increment * 0.05;
    }

    /// Get current performance metrics.
    ///
    /// # Example
    /// ```rust,ignore
    /// let perf = mgr.get_performance_metrics().await;
    /// ```
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.read().await.clone()
    }

    /// Get security events.
    ///
    /// # Example
    /// ```rust,ignore
    /// let events = mgr.get_security_events(Some(10)).await;
    /// ```
    pub async fn get_security_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        self.security_monitor.get_events(limit).await
    }

    /// Get threat assessment for user.
    ///
    /// # Example
    /// ```rust,ignore
    /// let level = mgr.get_user_threat_level("user-1").await;
    /// ```
    pub async fn get_user_threat_level(&self, user_id: &str) -> ThreatLevel {
        self.security_monitor.get_user_threat_level(user_id).await
    }

    /// Export Prometheus metrics.
    ///
    /// # Example
    /// ```rust,ignore
    /// let text = mgr.export_prometheus_metrics()?;
    /// ```
    #[cfg(feature = "prometheus")]
    pub fn export_prometheus_metrics(&self) -> Result<String> {
        use prometheus::TextEncoder;

        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families).map_err(|e| {
            AuthError::Storage(crate::errors::StorageError::OperationFailed {
                message: format!("Failed to encode metrics: {}", e),
            })
        })
    }
}

impl Default for ObservabilityManager {
    /// Creates an `ObservabilityManager` with default settings.
    ///
    /// # Panics
    /// Panics if the default observability stack cannot be initialised (e.g.
    /// Prometheus metric registration fails).  Prefer
    /// `ObservabilityManager::new()` which returns `Result` for graceful error
    /// handling in production code.
    fn default() -> Self {
        Self::new().expect(
            "ObservabilityManager::default(): failed to initialise. \
             Use ObservabilityManager::new() for Result-based error handling.",
        )
    }
}

#[cfg(feature = "prometheus")]
impl PrometheusMetrics {
    fn new(registry: &Registry) -> Result<Self> {
        let auth_requests_total = register_int_counter_with_registry!(
            Opts::new(
                "auth_requests_total",
                "Total number of authentication requests"
            ),
            registry
        )?;

        let auth_success_total = register_int_counter_with_registry!(
            Opts::new(
                "auth_success_total",
                "Total number of successful authentications"
            ),
            registry
        )?;

        let auth_failures_total = register_int_counter_with_registry!(
            Opts::new(
                "auth_failures_total",
                "Total number of failed authentications"
            ),
            registry
        )?;

        let auth_duration = register_histogram_with_registry!(
            HistogramOpts::new("auth_duration_seconds", "Authentication request duration"),
            registry
        )?;

        let tokens_issued_total = register_int_counter_with_registry!(
            Opts::new("tokens_issued_total", "Total number of tokens issued"),
            registry
        )?;

        let tokens_validated_total = register_int_counter_with_registry!(
            Opts::new(
                "tokens_validated_total",
                "Total number of token validations"
            ),
            registry
        )?;

        let tokens_revoked_total = register_int_counter_with_registry!(
            Opts::new("tokens_revoked_total", "Total number of tokens revoked"),
            registry
        )?;

        let active_tokens = register_int_gauge_with_registry!(
            Opts::new("active_tokens", "Number of currently active tokens"),
            registry
        )?;

        let sessions_created_total = register_int_counter_with_registry!(
            Opts::new("sessions_created_total", "Total number of sessions created"),
            registry
        )?;

        let sessions_destroyed_total = register_int_counter_with_registry!(
            Opts::new(
                "sessions_destroyed_total",
                "Total number of sessions destroyed"
            ),
            registry
        )?;

        let active_sessions = register_int_gauge_with_registry!(
            Opts::new("active_sessions", "Number of currently active sessions"),
            registry
        )?;

        let session_duration = register_histogram_with_registry!(
            HistogramOpts::new("session_duration_seconds", "Session duration"),
            registry
        )?;

        let storage_operations_total = register_int_counter_with_registry!(
            Opts::new(
                "storage_operations_total",
                "Total number of storage operations"
            ),
            registry
        )?;

        let storage_errors_total = register_int_counter_with_registry!(
            Opts::new("storage_errors_total", "Total number of storage errors"),
            registry
        )?;

        let storage_latency = register_histogram_with_registry!(
            HistogramOpts::new("storage_latency_seconds", "Storage operation latency"),
            registry
        )?;

        let storage_memory_usage = register_gauge_with_registry!(
            Opts::new("storage_memory_usage_bytes", "Storage memory usage"),
            registry
        )?;

        let security_events_total = register_int_counter_with_registry!(
            Opts::new("security_events_total", "Total number of security events"),
            registry
        )?;

        let rate_limit_hits_total = register_int_counter_with_registry!(
            Opts::new(
                "rate_limit_hits_total",
                "Total number of rate limit violations"
            ),
            registry
        )?;

        let suspicious_activity_total = register_int_counter_with_registry!(
            Opts::new(
                "suspicious_activity_total",
                "Total number of suspicious activities"
            ),
            registry
        )?;

        let cpu_usage = register_gauge_with_registry!(
            Opts::new("cpu_usage_percent", "CPU usage percentage"),
            registry
        )?;

        let memory_usage = register_gauge_with_registry!(
            Opts::new("memory_usage_bytes", "Memory usage in bytes"),
            registry
        )?;

        let concurrent_requests = register_int_gauge_with_registry!(
            Opts::new("concurrent_requests", "Number of concurrent requests"),
            registry
        )?;

        Ok(Self {
            auth_requests_total,
            auth_success_total,
            auth_failures_total,
            auth_duration,
            tokens_issued_total,
            tokens_validated_total,
            tokens_revoked_total,
            active_tokens,
            sessions_created_total,
            sessions_destroyed_total,
            active_sessions,
            session_duration,
            storage_operations_total,
            storage_errors_total,
            storage_latency,
            storage_memory_usage,
            security_events_total,
            rate_limit_hits_total,
            suspicious_activity_total,
            cpu_usage,
            memory_usage,
            concurrent_requests,
        })
    }
}

impl SecurityMonitor {
    fn new() -> Self {
        Self {
            failed_attempts: Arc::new(AtomicU64::new(0)),
            rate_limit_violations: Arc::new(AtomicU64::new(0)),
            suspicious_patterns: Arc::new(RwLock::new(HashMap::new())),
            security_events: Arc::new(RwLock::new(Vec::new())),
            threat_levels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failed_attempt(&self) {
        self.failed_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a rate limit violation
    pub fn record_rate_limit_violation(&self) {
        self.rate_limit_violations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get failed attempt count
    pub fn get_failed_attempts(&self) -> u64 {
        self.failed_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get rate limit violation count
    pub fn get_rate_limit_violations(&self) -> u64 {
        self.rate_limit_violations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a suspicious activity pattern
    pub async fn record_suspicious_activity(&self, user_id: String, activity: SuspiciousActivity) {
        let mut patterns = self.suspicious_patterns.write().await;
        patterns.insert(user_id, activity);
    }

    /// Get suspicious activity pattern for a user
    pub async fn get_suspicious_activity(&self, user_id: &str) -> Option<SuspiciousActivity> {
        let patterns = self.suspicious_patterns.read().await;
        patterns.get(user_id).cloned()
    }

    /// Get all suspicious activity patterns
    pub async fn get_all_suspicious_activities(&self) -> Vec<(String, SuspiciousActivity)> {
        let patterns = self.suspicious_patterns.read().await;
        patterns
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Clear suspicious activity pattern for a user
    pub async fn clear_suspicious_activity(&self, user_id: &str) {
        let mut patterns = self.suspicious_patterns.write().await;
        patterns.remove(user_id);
    }

    async fn record_event(&self, event: SecurityEvent) {
        let mut events = self.security_events.write().await;
        events.push(event.clone());

        // Keep only recent events
        if events.len() > 10000 {
            events.drain(0..1000);
        }

        // Update threat assessment
        if let Some(user_id) = &event.user_id {
            self.update_threat_level(user_id, &event).await;
        }
    }

    async fn update_threat_level(&self, user_id: &str, event: &SecurityEvent) {
        let mut threat_levels = self.threat_levels.write().await;

        let current_level = threat_levels.get(user_id).unwrap_or(&ThreatLevel::None);
        let new_level = match (&event.event_type, current_level) {
            (SecurityEventType::BruteForceAttempt, _) => ThreatLevel::High,
            (SecurityEventType::SuspiciousLogin, ThreatLevel::Low) => ThreatLevel::Medium,
            (SecurityEventType::TokenAbuse, _) => ThreatLevel::Medium,
            (SecurityEventType::PrivilegeEscalation, _) => ThreatLevel::Critical,
            (SecurityEventType::AuthFailure, ThreatLevel::None) => ThreatLevel::Low,
            _ => current_level.clone(),
        };

        threat_levels.insert(user_id.to_string(), new_level);
    }

    async fn get_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        let events = self.security_events.read().await;
        let limit = limit.unwrap_or(100);
        events.iter().rev().take(limit).cloned().collect()
    }

    async fn get_user_threat_level(&self, user_id: &str) -> ThreatLevel {
        let threat_levels = self.threat_levels.read().await;
        threat_levels
            .get(user_id)
            .unwrap_or(&ThreatLevel::None)
            .clone()
    }
}

/// Observability middleware for automatic instrumentation
pub struct ObservabilityMiddleware {
    manager: Arc<ObservabilityManager>,
}

impl ObservabilityMiddleware {
    pub fn new(manager: Arc<ObservabilityManager>) -> Self {
        Self { manager }
    }

    /// Instrument authentication operation
    pub async fn instrument_auth<F, T>(
        &self,
        operation: &str,
        user_id: &str,
        future: F,
    ) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let start = std::time::Instant::now();

        let result = future.await;
        let duration = start.elapsed();
        let success = result.is_ok();

        self.manager
            .record_auth_attempt(success, duration, operation)
            .await;

        if !success {
            let event = SecurityEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                event_type: SecurityEventType::AuthFailure,
                timestamp: SystemTime::now(),
                user_id: Some(user_id.to_string()),
                ip_address: None,
                details: HashMap::new(),
                severity: EventSeverity::Medium,
                action_taken: None,
            };
            self.manager.record_security_event(event).await;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_suspicious_activity_recording() {
        let security_monitor = SecurityMonitor::new();

        let activity = SuspiciousActivity {
            user_id: "user123".to_string(),
            ip_address: "192.168.1.100".to_string(),
            activity_type: "brute_force".to_string(),
            count: 5,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 85.0,
        };

        // Record activity
        security_monitor
            .record_suspicious_activity("user123".to_string(), activity.clone())
            .await;

        // Retrieve and verify
        let retrieved = security_monitor.get_suspicious_activity("user123").await;
        assert!(retrieved.is_some());
        let activity = retrieved.unwrap();
        assert_eq!(activity.user_id, "user123");
        assert_eq!(activity.activity_type, "brute_force");
        assert_eq!(activity.count, 5);
    }

    #[tokio::test]
    async fn test_multiple_suspicious_activities() {
        let security_monitor = SecurityMonitor::new();

        let activity1 = SuspiciousActivity {
            user_id: "user1".to_string(),
            ip_address: "192.168.1.1".to_string(),
            activity_type: "brute_force".to_string(),
            count: 3,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 70.0,
        };

        let activity2 = SuspiciousActivity {
            user_id: "user2".to_string(),
            ip_address: "192.168.1.2".to_string(),
            activity_type: "token_abuse".to_string(),
            count: 10,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 95.0,
        };

        // Record both activities
        security_monitor
            .record_suspicious_activity("user1".to_string(), activity1)
            .await;
        security_monitor
            .record_suspicious_activity("user2".to_string(), activity2)
            .await;

        // Get all activities
        let all_activities = security_monitor.get_all_suspicious_activities().await;
        assert_eq!(all_activities.len(), 2);

        // Verify both users are present
        let user_ids: Vec<&str> = all_activities.iter().map(|(id, _)| id.as_str()).collect();
        assert!(user_ids.contains(&"user1"));
        assert!(user_ids.contains(&"user2"));
    }

    #[tokio::test]
    async fn test_clear_suspicious_activity() {
        let security_monitor = SecurityMonitor::new();

        let activity = SuspiciousActivity {
            user_id: "user123".to_string(),
            ip_address: "192.168.1.100".to_string(),
            activity_type: "brute_force".to_string(),
            count: 5,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 85.0,
        };

        // Record activity
        security_monitor
            .record_suspicious_activity("user123".to_string(), activity)
            .await;
        assert!(
            security_monitor
                .get_suspicious_activity("user123")
                .await
                .is_some()
        );

        // Clear it
        security_monitor.clear_suspicious_activity("user123").await;
        assert!(
            security_monitor
                .get_suspicious_activity("user123")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_failed_attempt_tracking() {
        let security_monitor = SecurityMonitor::new();

        assert_eq!(security_monitor.get_failed_attempts(), 0);

        // Record a failed attempt
        security_monitor.record_failed_attempt();
        assert_eq!(security_monitor.get_failed_attempts(), 1);

        // Record multiple failed attempts
        for _ in 0..9 {
            security_monitor.record_failed_attempt();
        }
        assert_eq!(security_monitor.get_failed_attempts(), 10);
    }

    #[tokio::test]
    async fn test_rate_limit_violation_tracking() {
        let security_monitor = SecurityMonitor::new();

        assert_eq!(security_monitor.get_rate_limit_violations(), 0);

        // Record violations
        security_monitor.record_rate_limit_violation();
        assert_eq!(security_monitor.get_rate_limit_violations(), 1);

        for _ in 0..4 {
            security_monitor.record_rate_limit_violation();
        }
        assert_eq!(security_monitor.get_rate_limit_violations(), 5);
    }

    #[tokio::test]
    async fn test_observability_manager_creation() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        let config = manager.get_config();

        assert!(config.enable_security_monitoring);
        assert!(config.enable_prometheus);
        assert_eq!(config.security_event_max_count, 10000);
    }

    #[tokio::test]
    async fn test_security_monitor_via_observability_manager() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        let security_monitor = manager.get_security_monitor();

        // Test metrics collection
        security_monitor.record_failed_attempt();
        security_monitor.record_rate_limit_violation();

        assert_eq!(security_monitor.get_failed_attempts(), 1);
        assert_eq!(security_monitor.get_rate_limit_violations(), 1);
    }

    #[tokio::test]
    async fn test_suspicious_activity_integration_with_manager() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        let security_monitor = manager.get_security_monitor();

        let activity = SuspiciousActivity {
            user_id: "test_user".to_string(),
            ip_address: "10.0.0.1".to_string(),
            activity_type: "suspicious_login".to_string(),
            count: 2,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 60.0,
        };

        security_monitor
            .record_suspicious_activity("test_user".to_string(), activity)
            .await;

        let all_activities = security_monitor.get_all_suspicious_activities().await;
        assert_eq!(all_activities.len(), 1);
        assert_eq!(all_activities[0].0, "test_user");
    }

    #[tokio::test]
    async fn test_security_event_recording_and_retrieval() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");

        let event = SecurityEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::BruteForceAttempt,
            severity: EventSeverity::High,
            user_id: Some("user-1".to_string()),
            ip_address: Some("10.0.0.1".to_string()),
            details: std::collections::HashMap::new(),
            timestamp: SystemTime::now(),
            action_taken: Some("Suspicious login attempt".to_string()),
        };

        manager.record_security_event(event).await;

        let events = manager.get_security_events(Some(10)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].action_taken.as_deref(),
            Some("Suspicious login attempt")
        );
    }

    #[tokio::test]
    async fn test_security_events_limit_none_returns_all() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");

        for i in 0..5 {
            let event = SecurityEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                event_type: SecurityEventType::SuspiciousLogin,
                severity: EventSeverity::Medium,
                user_id: Some(format!("user-{}", i)),
                ip_address: None,
                details: std::collections::HashMap::new(),
                timestamp: SystemTime::now(),
                action_taken: None,
            };
            manager.record_security_event(event).await;
        }

        let events = manager.get_security_events(None).await;
        assert_eq!(events.len(), 5);
    }

    #[tokio::test]
    async fn test_user_threat_level_unknown_user() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        let level = manager.get_user_threat_level("nonexistent").await;
        assert_eq!(level, ThreatLevel::None);
    }

    #[tokio::test]
    async fn test_performance_metrics_initial_state() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        let perf = manager.get_performance_metrics().await;
        assert_eq!(perf.error_rate, 0.0);
    }

    #[tokio::test]
    async fn test_config_custom_values() {
        let config = ObservabilityConfig {
            enable_security_monitoring: false,
            enable_prometheus: false,
            enable_opentelemetry: false,
            metrics_retention_hours: 12,
            trace_sampling_ratio: 0.5,
            security_event_max_count: 500,
            performance_window_seconds: 60,
        };
        let manager = ObservabilityManager::with_config(config).expect("Failed to create manager");
        let cfg = manager.get_config();
        assert!(!cfg.enable_security_monitoring);
        assert!(!cfg.enable_prometheus);
        assert_eq!(cfg.security_event_max_count, 500);
    }

    #[tokio::test]
    async fn test_record_auth_attempt_success_and_failure() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        manager
            .record_auth_attempt(true, Duration::from_millis(10), "password")
            .await;
        manager
            .record_auth_attempt(false, Duration::from_millis(5), "password")
            .await;
        // Should not panic; metrics updated internally
    }

    #[tokio::test]
    async fn test_record_token_operations() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        manager.record_token_operation("issue", "tok-1").await;
        manager.record_token_operation("validate", "tok-1").await;
        manager.record_token_operation("revoke", "tok-1").await;
        // Should not panic
    }

    #[tokio::test]
    async fn test_record_session_operations() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        manager
            .record_session_operation("create", Some(Duration::from_secs(3600)))
            .await;
        manager.record_session_operation("destroy", None).await;
        // Should not panic
    }

    #[tokio::test]
    async fn test_record_storage_operation_success_and_failure() {
        let manager = ObservabilityManager::new().expect("Failed to create manager");
        manager
            .record_storage_operation("get", Duration::from_micros(100), true)
            .await;
        manager
            .record_storage_operation("set", Duration::from_micros(200), false)
            .await;
        // Should not panic
    }

    #[tokio::test]
    async fn test_clear_nonexistent_suspicious_activity() {
        let monitor = SecurityMonitor::new();
        // Should not panic
        monitor.clear_suspicious_activity("nonexistent").await;
        assert!(
            monitor
                .get_suspicious_activity("nonexistent")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_overwrite_suspicious_activity() {
        let monitor = SecurityMonitor::new();

        let activity1 = SuspiciousActivity {
            user_id: "user-1".to_string(),
            ip_address: "1.1.1.1".to_string(),
            activity_type: "brute_force".to_string(),
            count: 3,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 50.0,
        };
        monitor
            .record_suspicious_activity("user-1".to_string(), activity1)
            .await;

        let activity2 = SuspiciousActivity {
            user_id: "user-1".to_string(),
            ip_address: "2.2.2.2".to_string(),
            activity_type: "token_abuse".to_string(),
            count: 10,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            risk_score: 90.0,
        };
        monitor
            .record_suspicious_activity("user-1".to_string(), activity2)
            .await;

        let retrieved = monitor.get_suspicious_activity("user-1").await.unwrap();
        assert_eq!(retrieved.activity_type, "token_abuse");
        assert_eq!(retrieved.count, 10);
    }
}
