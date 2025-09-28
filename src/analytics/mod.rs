//! Analytics and monitoring for RBAC systems
//!
//! This module provides comprehensive analytics capabilities for monitoring
//! and analyzing RBAC usage patterns, security compliance, and system performance.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub used_by_roles: Vec<String>,

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
    event_buffer: Vec<AnalyticsEvent>,
    last_collection: Instant,
}

impl AnalyticsManager {
    /// Create new analytics manager
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            config,
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
            self.process_real_time_event(self.event_buffer.last().unwrap())
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
        // Implementation would query stored analytics data
        Ok(vec![])
    }

    /// Get permission usage statistics
    pub async fn get_permission_usage_stats(
        &self,
        _permission_id: Option<&str>,
        _time_range: Option<TimeRange>,
    ) -> Result<Vec<PermissionUsageStats>, AnalyticsError> {
        // Implementation would query stored analytics data
        Ok(vec![])
    }

    /// Get compliance metrics
    pub async fn get_compliance_metrics(
        &self,
        _time_range: Option<TimeRange>,
    ) -> Result<ComplianceMetrics, AnalyticsError> {
        // Implementation would calculate compliance metrics
        Ok(ComplianceMetrics {
            role_assignment_compliance: 95.5,
            permission_scoping_compliance: 88.2,
            orphaned_permissions: 5,
            over_privileged_users: 12,
            unused_roles: 3,
            avg_access_revocation_time_hours: 2.5,
            policy_violations: 8,
            security_incidents: 1,
        })
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(
        &self,
        _time_range: Option<TimeRange>,
    ) -> Result<PerformanceMetrics, AnalyticsError> {
        // Implementation would calculate performance metrics
        Ok(PerformanceMetrics {
            avg_permission_check_latency_ms: 15.5,
            p95_permission_check_latency_ms: 45.2,
            p99_permission_check_latency_ms: 125.8,
            permission_checks_per_second: 1250.0,
            permission_cache_hit_rate: 0.92,
            error_rate: 0.001,
            cpu_usage_percent: 15.5,
            memory_usage_mb: 512,
        })
    }

    /// Get trend analysis for a specific metric
    pub async fn get_trend_analysis(
        &self,
        metric_name: &str,
        _time_range: TimeRange,
    ) -> Result<TrendAnalysis, AnalyticsError> {
        // Implementation would analyze trends
        Ok(TrendAnalysis {
            metric_name: metric_name.to_string(),
            current_value: 100.0,
            previous_value: 95.0,
            change_percent: 5.26,
            trend: TrendDirection::Increasing,
            data_points: vec![],
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

        // Implementation would persist events to storage
        // For now, we'll just clear the buffer
        self.event_buffer.clear();
        self.last_collection = Instant::now();

        Ok(())
    }

    /// Process event for real-time analytics
    async fn process_real_time_event(&self, _event: &AnalyticsEvent) -> Result<(), AnalyticsError> {
        // Implementation would update real-time metrics
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
        let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc();
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
        let manager = AnalyticsManager::new(config);
        assert_eq!(manager.event_buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_record_event() {
        let config = AnalyticsConfig::default();
        let mut manager = AnalyticsManager::new(config);

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
