//! Analytics and monitoring for RBAC systems.
//!
//! This module provides comprehensive analytics capabilities for monitoring
//! and analyzing RBAC usage patterns, security compliance, and system performance.
//!
//! > **Status:** Analytics are event-backed today. The `compliance`, `reports`,
//! > `metrics`, and `dashboard` modules derive results from stored analytics
//! > events and persisted snapshots, and they expand as additional collectors
//! > feed the pipeline.

use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub mod compliance;
pub mod dashboard;
pub mod metrics;
pub mod reports;

/// Analytics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsConfig {
    /// Enable real-time analytics
    pub real_time_enabled: bool,

    /// Data retention period
    pub data_retention_days: u32,

    /// Metrics collection interval
    pub collection_interval: Duration,

    /// Enable security compliance monitoring
    pub compliance_monitoring: bool,

    /// Enable performance monitoring
    pub performance_monitoring: bool,

    /// Maximum number of events to buffer
    pub max_event_buffer: usize,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            real_time_enabled: true,
            data_retention_days: 90,
            collection_interval: Duration::from_secs(60),
            compliance_monitoring: true,
            performance_monitoring: true,
            max_event_buffer: 10000,
        }
    }
}

/// RBAC analytics event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RbacEventType {
    /// Role assignment/revocation
    RoleAssignment,
    /// Permission check
    PermissionCheck,
    /// Role creation/modification
    RoleManagement,
    /// User authentication
    Authentication,
    /// Authorization decision
    Authorization,
    /// Policy violation
    PolicyViolation,
    /// Privilege escalation attempt
    PrivilegeEscalation,
    /// Access pattern anomaly
    AccessAnomaly,
}

/// Analytics event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    /// Unique event ID
    pub id: String,

    /// Event type
    pub event_type: RbacEventType,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// User ID (if applicable)
    pub user_id: Option<String>,

    /// Role ID (if applicable)
    pub role_id: Option<String>,

    /// Permission/resource (if applicable)
    pub resource: Option<String>,

    /// Action performed
    pub action: Option<String>,

    /// Result of the operation
    pub result: EventResult,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Processing duration (milliseconds)
    pub duration_ms: Option<u64>,

    /// Source IP address
    pub source_ip: Option<String>,

    /// User agent
    pub user_agent: Option<String>,
}

/// Event result types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventResult {
    Success,
    Failure,
    Denied,
    Error,
}

/// Role usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleUsageStats {
    /// Role ID
    pub role_id: String,

    /// Role name
    pub role_name: String,

    /// Number of users assigned to this role
    pub user_count: u32,

    /// Number of permission checks for this role
    pub permission_checks: u64,

    /// Number of successful access attempts
    pub successful_access: u64,

    /// Number of denied access attempts
    pub denied_access: u64,

    /// Last time this role was used
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,

    /// Average response time for permission checks (ms)
    pub avg_response_time_ms: f64,

    /// Most frequently accessed resources
    pub top_resources: Vec<ResourceAccess>,
}

/// Resource access statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess {
    /// Resource identifier
    pub resource: String,

    /// Number of access attempts
    pub access_count: u64,

    /// Success rate (0.0 to 1.0)
    pub success_rate: f64,
}

/// Permission usage analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionUsageStats {
    /// Permission identifier
    pub permission_id: String,

    /// Number of checks for this permission
    pub check_count: u64,

    /// Success rate
    pub success_rate: f64,

    /// Roles that use this permission
    pub used_by_roles: crate::types::Roles,

    /// Most active users for this permission
    pub top_users: Vec<UserActivity>,

    /// Peak usage times
    pub peak_hours: Vec<u8>, // Hours of day (0-23)
}

/// User activity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    /// User ID
    pub user_id: String,

    /// Number of actions
    pub activity_count: u64,

    /// Last activity timestamp
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

/// Security compliance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetrics {
    /// Percentage of users with appropriate role assignments
    pub role_assignment_compliance: f64,

    /// Percentage of permissions properly scoped
    pub permission_scoping_compliance: f64,

    /// Number of orphaned permissions
    pub orphaned_permissions: u32,

    /// Number of over-privileged users
    pub over_privileged_users: u32,

    /// Number of unused roles
    pub unused_roles: u32,

    /// Average time to revoke access (hours)
    pub avg_access_revocation_time_hours: f64,

    /// Policy violations in the last period
    pub policy_violations: u32,

    /// Security incidents related to RBAC
    pub security_incidents: u32,
}

/// Performance metrics for RBAC operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average permission check latency (ms)
    pub avg_permission_check_latency_ms: f64,

    /// 95th percentile permission check latency (ms)
    pub p95_permission_check_latency_ms: f64,

    /// 99th percentile permission check latency (ms)
    pub p99_permission_check_latency_ms: f64,

    /// Total number of permission checks per second
    pub permission_checks_per_second: f64,

    /// Cache hit rate for permission checks
    pub permission_cache_hit_rate: f64,

    /// Error rate for RBAC operations
    pub error_rate: f64,

    /// System resource utilization
    pub cpu_usage_percent: f64,

    /// Memory usage (MB)
    pub memory_usage_mb: u64,
}

/// Time-based analytics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesData {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Metric value
    pub value: f64,

    /// Additional tags/dimensions
    pub tags: HashMap<String, String>,
}

/// Analytics trend information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    /// Metric name
    pub metric_name: String,

    /// Current value
    pub current_value: f64,

    /// Value from previous period
    pub previous_value: f64,

    /// Percentage change
    pub change_percent: f64,

    /// Trend direction
    pub trend: TrendDirection,

    /// Time series data points
    pub data_points: Vec<TimeSeriesData>,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
    Volatile,
}

/// Main analytics manager
pub struct AnalyticsManager {
    config: AnalyticsConfig,
    storage: Arc<dyn AuthStorage>,
    event_buffer: Vec<AnalyticsEvent>,
    last_collection: Instant,
}

impl AnalyticsManager {
    /// Create new analytics manager
    pub fn new(config: AnalyticsConfig, storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            config,
            storage,
            event_buffer: Vec::new(),
            last_collection: Instant::now(),
        }
    }

    /// Record an analytics event
    pub async fn record_event(&mut self, event: AnalyticsEvent) -> Result<(), AnalyticsError> {
        if self.event_buffer.len() >= self.config.max_event_buffer {
            self.flush_events().await?;
        }

        self.event_buffer.push(event);

        if self.config.real_time_enabled {
            // Process event immediately for real-time analytics
            self.process_real_time_event(
                self.event_buffer
                    .last()
                    .expect("buffer non-empty after push"),
            )
            .await?;
        }

        Ok(())
    }

    /// Get role usage statistics
    pub async fn get_role_usage_stats(
        &self,
        _role_id: Option<&str>,
        _time_range: Option<TimeRange>,
    ) -> Result<Vec<RoleUsageStats>, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut stats: HashMap<String, RoleUsageStats> = HashMap::new();
        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<AnalyticsEvent>(&data)
                && let Some(ref role) = event.role_id
            {
                let entry = stats.entry(role.clone()).or_insert_with(|| RoleUsageStats {
                    role_id: role.clone(),
                    role_name: role.clone(),
                    user_count: 1,
                    permission_checks: 0,
                    successful_access: 0,
                    denied_access: 0,
                    last_used: None,
                    avg_response_time_ms: 0.0,
                    top_resources: Vec::new(),
                });
                if event.event_type == RbacEventType::PermissionCheck {
                    entry.permission_checks += 1;
                    if let Some(action) = &event.action {
                        if action == "Granted" {
                            entry.successful_access += 1;
                        } else {
                            entry.denied_access += 1;
                        }
                    }
                    entry.last_used = Some(event.timestamp);
                }
            }
        }
        Ok(stats.into_values().collect())
    }

    /// Get permission usage statistics
    pub async fn get_permission_usage_stats(
        &self,
        _permission_id: Option<&str>,
        _time_range: Option<TimeRange>,
    ) -> Result<Vec<PermissionUsageStats>, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut stats: HashMap<String, PermissionUsageStats> = HashMap::new();
        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<AnalyticsEvent>(&data)
                && let Some(ref perm) = event.resource
            {
                let entry = stats
                    .entry(perm.clone())
                    .or_insert_with(|| PermissionUsageStats {
                        permission_id: perm.clone(),
                        check_count: 0,
                        success_rate: 1.0,
                        used_by_roles: crate::types::Roles::empty(),
                        top_users: Vec::new(),
                        peak_hours: Vec::new(),
                    });
                if event.event_type == RbacEventType::PermissionCheck {
                    entry.check_count += 1;
                }
            }
        }
        Ok(stats.into_values().collect())
    }

    /// Get compliance metrics
    pub async fn get_compliance_metrics(
        &self,
        _time_range: Option<TimeRange>,
    ) -> Result<ComplianceMetrics, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut total_events = 0;
        let mut policy_violations = 0;
        let mut orphaned_permissions = 0;
        let mut security_incidents = 0;
        // Track revocation timing from events that contain revocation metadata
        let mut revocation_durations = Vec::new();
        // Track users with escalation/anomaly events as potentially over-privileged
        let mut escalation_users = std::collections::HashSet::new();

        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<AnalyticsEvent>(&data)
            {
                total_events += 1;
                if let Some(action) = &event.action
                    && (action.contains("Violation") || action.contains("Denied"))
                {
                    policy_violations += 1;
                }
                if event.event_type == RbacEventType::PermissionCheck
                    && event.action.as_deref() == Some("Orphaned")
                {
                    orphaned_permissions += 1;
                }
                if matches!(
                    event.event_type,
                    RbacEventType::PolicyViolation
                        | RbacEventType::PrivilegeEscalation
                        | RbacEventType::AccessAnomaly
                ) || event
                    .action
                    .as_deref()
                    .is_some_and(|action| action.contains("Incident"))
                {
                    security_incidents += 1;
                }
                // Track over-privileged users from escalation events
                if event.event_type == RbacEventType::PrivilegeEscalation
                    && let Some(ref user) = event.user_id
                {
                    escalation_users.insert(user.clone());
                }
                // Track access revocation timing from metadata
                if let Some(ref action) = event.action
                    && (action.contains("Revoked") || action.contains("Revocation"))
                    && let Some(hours_str) = event.metadata.get("revocation_hours")
                    && let Ok(hours) = hours_str.parse::<f64>()
                {
                    revocation_durations.push(hours);
                }
            }
        }

        let compliance_score = if total_events > 0 {
            100.0 - ((policy_violations as f64 / total_events as f64) * 100.0)
        } else {
            100.0
        };

        let avg_access_revocation_time_hours = if !revocation_durations.is_empty() {
            revocation_durations.iter().sum::<f64>() / revocation_durations.len() as f64
        } else {
            0.0 // No revocation data available
        };

        // Count unused roles by comparing defined roles against actual assignments
        let unused_roles = {
            let defined_roles = self
                .storage
                .list_kv_keys("rbac:role:")
                .await
                .unwrap_or_default();
            let assigned: std::collections::HashSet<String> = {
                let user_role_keys = self
                    .storage
                    .list_kv_keys("rbac:user_roles:")
                    .await
                    .unwrap_or_default();
                let mut set = std::collections::HashSet::new();
                for key in &user_role_keys {
                    if let Ok(Some(data)) = self.storage.get_kv(key).await
                        && let Ok(roles) = serde_json::from_slice::<Vec<String>>(&data)
                    {
                        set.extend(roles);
                    }
                }
                set
            };
            defined_roles
                .iter()
                .filter(|k: &&String| {
                    let role_name = k.strip_prefix("rbac:role:").unwrap_or(k);
                    !assigned.contains(role_name)
                })
                .count() as u32
        };

        Ok(ComplianceMetrics {
            role_assignment_compliance: compliance_score,
            permission_scoping_compliance: compliance_score,
            orphaned_permissions,
            over_privileged_users: escalation_users.len() as u32,
            unused_roles,
            avg_access_revocation_time_hours,
            policy_violations,
            security_incidents,
        })
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(
        &self,
        _time_range: Option<TimeRange>,
    ) -> Result<PerformanceMetrics, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut total_events = 0;
        let mut total_duration_ms = 0.0;
        let mut duration_samples = Vec::new();
        let mut errors = 0;
        let mut permission_check_timestamps = Vec::new();

        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<AnalyticsEvent>(&data)
            {
                total_events += 1;
                if let Some(duration_ms) = event.duration_ms {
                    total_duration_ms += duration_ms as f64;
                    duration_samples.push(duration_ms);
                }
                if event.event_type == RbacEventType::PermissionCheck {
                    permission_check_timestamps.push(event.timestamp);
                }
                if matches!(event.result, EventResult::Failure | EventResult::Error) {
                    errors += 1;
                }
            }
        }

        duration_samples.sort_unstable();
        let p95 = if duration_samples.is_empty() {
            0.0
        } else {
            let index = ((duration_samples.len() as f64 * 0.95).floor() as usize)
                .min(duration_samples.len() - 1);
            duration_samples[index] as f64
        };
        let p99 = if duration_samples.is_empty() {
            0.0
        } else {
            let index = ((duration_samples.len() as f64 * 0.99).floor() as usize)
                .min(duration_samples.len() - 1);
            duration_samples[index] as f64
        };
        let avg = if duration_samples.is_empty() {
            0.0
        } else {
            total_duration_ms / duration_samples.len() as f64
        };
        let error_rate = if total_events > 0 {
            errors as f64 / total_events as f64
        } else {
            0.0
        };
        permission_check_timestamps.sort_unstable();
        let permission_checks_per_second = match (
            permission_check_timestamps.first(),
            permission_check_timestamps.last(),
        ) {
            (Some(first), Some(last)) if permission_check_timestamps.len() > 1 => {
                let span_seconds = (*last - *first).num_seconds().max(1) as f64;
                permission_check_timestamps.len() as f64 / span_seconds
            }
            _ => 0.0,
        };

        Ok(PerformanceMetrics {
            avg_permission_check_latency_ms: avg,
            p95_permission_check_latency_ms: p95,
            p99_permission_check_latency_ms: p99,
            permission_checks_per_second,
            // Cache hit rate calculation: count events with metadata key
            // "cache_hit" set to "true" vs total permission check events.
            permission_cache_hit_rate: {
                let cache_hits = self
                    .event_buffer
                    .iter()
                    .filter(|e| e.event_type == RbacEventType::PermissionCheck)
                    .filter(|e| e.metadata.get("cache_hit").is_some_and(|v| v == "true"))
                    .count();
                let cache_total = self
                    .event_buffer
                    .iter()
                    .filter(|e| e.event_type == RbacEventType::PermissionCheck)
                    .count();
                if cache_total > 0 {
                    cache_hits as f64 / cache_total as f64
                } else {
                    0.0
                }
            },
            error_rate,
            // Best-effort process CPU usage via sysinfo crate
            cpu_usage_percent: {
                let mut sys = sysinfo::System::new();
                let pid = sysinfo::get_current_pid().ok();
                if let Some(pid) = pid {
                    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
                    sys.process(pid)
                        .map(|p| p.cpu_usage() as f64)
                        .unwrap_or(0.0)
                } else {
                    0.0
                }
            },
            memory_usage_mb: {
                // Use Rust's allocator stats when available, or a rough
                // approximation via /proc/self/statm on Linux.
                #[cfg(target_os = "linux")]
                {
                    std::fs::read_to_string("/proc/self/statm")
                        .ok()
                        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
                        .map(|pages| pages * 4096 / (1024 * 1024))
                        .unwrap_or(0)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    0
                }
            },
        })
    }

    /// Get trend analysis for a specific metric
    pub async fn get_trend_analysis(
        &self,
        metric_name: &str,
        _time_range: Option<TimeRange>,
    ) -> Result<TrendAnalysis, AnalyticsError> {
        let keys = self
            .storage
            .list_kv_keys("analytics_event_")
            .await
            .unwrap_or_default();
        let mut data_points = Vec::new();

        for key in keys {
            if let Ok(Some(data)) = self.storage.get_kv(&key).await
                && let Ok(event) = serde_json::from_slice::<AnalyticsEvent>(&data)
            {
                data_points.push(TimeSeriesData {
                    timestamp: event.timestamp,
                    value: 1.0,
                    tags: event.metadata.clone(),
                });
            }
        }

        data_points.sort_by_key(|point| point.timestamp);
        let midpoint = data_points.len() / 2;
        let previous_value = midpoint as f64;
        let current_value = (data_points.len() - midpoint) as f64;
        let change_percent = if previous_value == 0.0 {
            if current_value == 0.0 { 0.0 } else { 100.0 }
        } else {
            ((current_value - previous_value) / previous_value) * 100.0
        };
        let direction = if change_percent.abs() < 5.0 {
            TrendDirection::Stable
        } else if change_percent > 0.0 {
            TrendDirection::Increasing
        } else {
            TrendDirection::Decreasing
        };

        Ok(TrendAnalysis {
            metric_name: metric_name.to_string(),
            current_value,
            previous_value,
            change_percent,
            trend: direction,
            data_points,
        })
    }

    /// Generate comprehensive analytics report
    pub async fn generate_report(
        &self,
        report_type: ReportType,
        time_range: TimeRange,
    ) -> Result<AnalyticsReport, AnalyticsError> {
        let role_stats = self
            .get_role_usage_stats(None, Some(time_range.clone()))
            .await?;
        let permission_stats = self
            .get_permission_usage_stats(None, Some(time_range.clone()))
            .await?;
        let compliance_metrics = self
            .get_compliance_metrics(Some(time_range.clone()))
            .await?;
        let performance_metrics = self
            .get_performance_metrics(Some(time_range.clone()))
            .await?;

        Ok(AnalyticsReport {
            report_type,
            time_range,
            generated_at: chrono::Utc::now(),
            role_stats,
            permission_stats,
            compliance_metrics: compliance_metrics.clone(),
            performance_metrics: performance_metrics.clone(),
            summary: self.generate_report_summary(&compliance_metrics, &performance_metrics),
        })
    }

    /// Flush buffered events
    async fn flush_events(&mut self) -> Result<(), AnalyticsError> {
        if self.event_buffer.is_empty() {
            return Ok(());
        }

        // Persist events to storage
        for event in &self.event_buffer {
            if let Ok(json_data) = serde_json::to_vec(event) {
                let key = format!("analytics_event_{}", event.id);
                // We use an arbitrary TTL of 90 days if data retention is enabled
                let ttl =
                    std::time::Duration::from_secs(self.config.data_retention_days as u64 * 86400);
                let _ = self.storage.store_kv(&key, &json_data, Some(ttl)).await;
            }
        }

        // Clear the buffer
        self.event_buffer.clear();
        self.last_collection = Instant::now();

        Ok(())
    }

    /// Process event for real-time analytics by persisting it to storage
    /// immediately so that dashboards and alerts can query the latest data
    /// without waiting for the periodic buffer flush.
    async fn process_real_time_event(&self, event: &AnalyticsEvent) -> Result<(), AnalyticsError> {
        let json_data = serde_json::to_vec(event)?;
        let key = format!("analytics_event_{}", event.id);
        let ttl = std::time::Duration::from_secs(self.config.data_retention_days as u64 * 86400);
        self.storage
            .store_kv(&key, &json_data, Some(ttl))
            .await
            .map_err(|e| AnalyticsError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Generate report summary
    fn generate_report_summary(
        &self,
        compliance: &ComplianceMetrics,
        performance: &PerformanceMetrics,
    ) -> String {
        format!(
            "RBAC Analytics Summary: {}% compliance, {:.1}ms avg latency, {:.1}% error rate",
            compliance.role_assignment_compliance,
            performance.avg_permission_check_latency_ms,
            performance.error_rate * 100.0
        )
    }
}

/// Time range for analytics queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl TimeRange {
    /// Create time range for the last N hours
    pub fn last_hours(hours: u32) -> Self {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::hours(hours as i64);
        Self { start, end }
    }

    /// Create time range for the last N days
    pub fn last_days(days: u32) -> Self {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::days(days as i64);
        Self { start, end }
    }

    /// Create time range for today
    pub fn today() -> Self {
        let now = chrono::Utc::now();
        let start = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("0,0,0 are valid h/m/s values")
            .and_utc();
        let end = now;
        Self { start, end }
    }
}

/// Report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    /// Daily summary report
    Daily,
    /// Weekly summary report
    Weekly,
    /// Monthly summary report
    Monthly,
    /// Security compliance report
    Compliance,
    /// Performance analysis report
    Performance,
    /// Custom report with specific criteria
    Custom(String),
}

/// Comprehensive analytics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsReport {
    pub report_type: ReportType,
    pub time_range: TimeRange,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub role_stats: Vec<RoleUsageStats>,
    pub permission_stats: Vec<PermissionUsageStats>,
    pub compliance_metrics: ComplianceMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub summary: String,
}

/// Analytics-related errors
#[derive(Debug, thiserror::Error)]
pub enum AnalyticsError {
    #[error("Data processing error: {0}")]
    ProcessingError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_config_default() {
        let config = AnalyticsConfig::default();
        assert!(config.real_time_enabled);
        assert_eq!(config.data_retention_days, 90);
        assert!(config.compliance_monitoring);
    }

    #[test]
    fn test_time_range_creation() {
        let range = TimeRange::last_hours(24);
        assert!(range.end > range.start);

        let today = TimeRange::today();
        assert!(today.end > today.start);
    }

    #[tokio::test]
    async fn test_analytics_manager_creation() {
        let config = AnalyticsConfig::default();
        let manager = AnalyticsManager::new(
            config,
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );
        assert_eq!(manager.event_buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_record_event() {
        let config = AnalyticsConfig::default();
        let mut manager = AnalyticsManager::new(
            config,
            std::sync::Arc::new(crate::storage::MemoryStorage::new()),
        );

        let event = AnalyticsEvent {
            id: "test_event_1".to_string(),
            event_type: RbacEventType::PermissionCheck,
            timestamp: chrono::Utc::now(),
            user_id: Some("user123".to_string()),
            role_id: Some("admin".to_string()),
            resource: Some("user_data".to_string()),
            action: Some("read".to_string()),
            result: EventResult::Success,
            metadata: HashMap::new(),
            duration_ms: Some(15),
            source_ip: Some("192.168.1.1".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
        };

        let result = manager.record_event(event).await;
        assert!(result.is_ok());
        assert_eq!(manager.event_buffer.len(), 1);
    }
}
