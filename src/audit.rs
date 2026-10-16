//! Comprehensive audit logging and security event tracking.
//!
//! This module provides detailed audit logging for all authentication,
//! authorization, and security-related events in the system.
impl Default for CorrelationIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}
use crate::errors::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Audit event types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditEventType {
    // Authentication events
    LoginSuccess,
    LoginFailure,
    Logout,
    TokenRefresh,
    TokenExpired,
    TokenRevoked,

    // MFA events
    MfaSetup,
    MfaChallengeCreated,
    MfaVerificationSuccess,
    MfaVerificationFailure,
    MfaMethodEnabled,
    MfaMethodDisabled,

    // Authorization events
    PermissionGranted,
    PermissionDenied,
    RoleAssigned,
    RoleRevoked,
    RoleCreated,
    RoleUpdated,
    RoleDeleted,

    // User management events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserActivated,
    UserDeactivated,
    UserPasswordChanged,
    UserPasswordReset,

    // Security events
    AccountLocked,
    AccountUnlocked,
    SuspiciousActivity,
    BruteForceDetected,
    RateLimitExceeded,
    SecurityPolicyViolation,
    SecurityViolation,

    // Administrative events
    AdminAction,
    ConfigurationChanged,
    SystemStartup,
    SystemShutdown,
    BackupCreated,
    DataExported,
    DataImported,
}

/// Security risk level
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit event outcome
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventOutcome {
    Success,
    Failure,
    Partial,
    Unknown,
}

/// Comprehensive audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// Type of event
    pub event_type: AuditEventType,
    /// When the event occurred
    pub timestamp: SystemTime,
    /// User who initiated the event (if applicable)
    pub user_id: Option<String>,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Event outcome
    pub outcome: EventOutcome,
    /// Risk level assessment
    pub risk_level: RiskLevel,
    /// Human-readable event description
    pub description: String,
    /// Additional event details
    pub details: HashMap<String, String>,
    /// Request metadata
    pub request_metadata: RequestMetadata,
    /// Resource affected (if applicable)
    pub resource: Option<ResourceInfo>,
    /// Actor information
    pub actor: ActorInfo,
    /// Correlation ID for tracking related events
    pub correlation_id: Option<String>,
}

/// Request metadata for audit context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Source IP address
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request ID
    pub request_id: Option<String>,
    /// API endpoint or action
    pub endpoint: Option<String>,
    /// HTTP method (if applicable)
    pub http_method: Option<String>,
    /// Geographic location (if available)
    pub geolocation: Option<GeolocationInfo>,
    /// Device information
    pub device_info: Option<DeviceInfo>,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationInfo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_type: Option<String>,
    pub operating_system: Option<String>,
    pub browser: Option<String>,
    pub is_mobile: bool,
    pub screen_resolution: Option<String>,
}

/// Resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Resource type (user, document, api, etc.)
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// Resource name or title
    pub resource_name: Option<String>,
    /// Additional resource attributes
    pub attributes: HashMap<String, String>,
}

/// Actor information (who performed the action)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    /// Actor type (user, system, api_client, etc.)
    pub actor_type: String,
    /// Actor ID
    pub actor_id: String,
    /// Actor name or identifier
    pub actor_name: Option<String>,
    /// Roles or permissions of the actor
    pub roles: Vec<String>,
}

/// Audit log storage trait
#[async_trait]
pub trait AuditStorage: Send + Sync {
    /// Store an audit event
    async fn store_event(&self, event: &AuditEvent) -> Result<()>;

    /// Query audit events with filters
    async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>>;

    /// Get event by ID
    async fn get_event(&self, event_id: &str) -> Result<Option<AuditEvent>>;

    /// Count events matching criteria
    async fn count_events(&self, query: &AuditQuery) -> Result<u64>;

    /// Delete old events (for retention management)
    async fn delete_old_events(&self, before: SystemTime) -> Result<u64>;

    /// Get audit statistics
    async fn get_statistics(&self, query: &StatsQuery) -> Result<AuditStatistics>;
}

/// Query parameters for audit events
#[derive(Debug, Clone)]
pub struct AuditQuery {
    /// Filter by event types
    pub event_types: Option<Vec<AuditEventType>>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by risk level
    pub risk_level: Option<RiskLevel>,
    /// Filter by outcome
    pub outcome: Option<EventOutcome>,
    /// Time range filter
    pub time_range: Option<TimeRange>,
    /// IP address filter
    pub ip_address: Option<String>,
    /// Resource filter
    pub resource_type: Option<String>,
    /// Actor filter
    pub actor_id: Option<String>,
    /// Correlation ID filter
    pub correlation_id: Option<String>,
    /// Limit number of results
    pub limit: Option<u64>,
    /// Offset for pagination
    pub offset: Option<u64>,
    /// Sort order
    pub sort_order: SortOrder,
}

/// Time range for queries
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub start: SystemTime,
    pub end: SystemTime,
}

/// Sort order for queries
#[derive(Debug, Clone)]
pub enum SortOrder {
    TimestampAsc,
    TimestampDesc,
    RiskLevelDesc,
}

/// Statistics query parameters
#[derive(Debug, Clone)]
pub struct StatsQuery {
    pub time_range: TimeRange,
    pub group_by: Vec<StatsGroupBy>,
}

/// Grouping options for statistics
#[derive(Debug, Clone)]
pub enum StatsGroupBy {
    EventType,
    RiskLevel,
    Outcome,
    Hour,
    Day,
    Week,
    UserId,
    IpAddress,
}

/// Audit statistics result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_events: u64,
    pub event_type_counts: HashMap<String, u64>,
    pub risk_level_counts: HashMap<String, u64>,
    pub outcome_counts: HashMap<String, u64>,
    pub time_series: Vec<TimeSeriesPoint>,
    pub top_users: Vec<UserEventCount>,
    pub top_ips: Vec<IpEventCount>,
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: SystemTime,
    pub count: u64,
}

/// User event count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEventCount {
    pub user_id: String,
    pub event_count: u64,
}

/// IP address event count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEventCount {
    pub ip_address: String,
    pub event_count: u64,
}

/// Main audit logger
pub struct AuditLogger<S: AuditStorage> {
    storage: S,
    correlation_generator: CorrelationIdGenerator,
}

impl<S: AuditStorage> AuditLogger<S> {
    /// Create a new audit logger
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            correlation_generator: CorrelationIdGenerator::new(),
        }
    }

    /// Log an audit event
    pub async fn log_event(&self, mut event: AuditEvent) -> Result<()> {
        // Generate ID if not provided
        if event.id.is_empty() {
            event.id = uuid::Uuid::new_v4().to_string();
        }

        // Set timestamp if not provided
        if event.timestamp == SystemTime::UNIX_EPOCH {
            event.timestamp = SystemTime::now();
        }

        // Store the event
        self.storage.store_event(&event).await?;

        // Check for security alerts
        self.check_security_alerts(&event).await?;

        Ok(())
    }

    /// Log authentication success
    pub async fn log_login_success(
        &self,
        user_id: &str,
        session_id: &str,
        metadata: RequestMetadata,
    ) -> Result<()> {
        let event = AuditEvent {
            id: String::new(),
            event_type: AuditEventType::LoginSuccess,
            timestamp: SystemTime::UNIX_EPOCH,
            user_id: Some(user_id.to_string()),
            session_id: Some(session_id.to_string()),
            outcome: EventOutcome::Success,
            risk_level: RiskLevel::Low,
            description: "User successfully authenticated".to_string(),
            details: HashMap::new(),
            request_metadata: metadata,
            resource: None,
            actor: ActorInfo {
                actor_type: "user".to_string(),
                actor_id: user_id.to_string(),
                actor_name: None,
                roles: vec![],
            },
            correlation_id: Some(self.correlation_generator.generate()),
        };

        self.log_event(event).await
    }

    /// Log authentication failure
    pub async fn log_login_failure(
        &self,
        attempted_user: &str,
        reason: &str,
        metadata: RequestMetadata,
    ) -> Result<()> {
        let mut details = HashMap::new();
        details.insert("failure_reason".to_string(), reason.to_string());
        details.insert("attempted_user".to_string(), attempted_user.to_string());

        let event = AuditEvent {
            id: String::new(),
            event_type: AuditEventType::LoginFailure,
            timestamp: SystemTime::UNIX_EPOCH,
            user_id: None,
            session_id: None,
            outcome: EventOutcome::Failure,
            risk_level: RiskLevel::Medium,
            description: format!("Authentication failed for user: {}", attempted_user),
            details,
            request_metadata: metadata,
            resource: None,
            actor: ActorInfo {
                actor_type: "user".to_string(),
                actor_id: attempted_user.to_string(),
                actor_name: None,
                roles: vec![],
            },
            correlation_id: Some(self.correlation_generator.generate()),
        };

        self.log_event(event).await
    }

    /// Log permission denied event
    pub async fn log_permission_denied(
        &self,
        user_id: &str,
        resource: ResourceInfo,
        permission: &str,
        metadata: RequestMetadata,
    ) -> Result<()> {
        let mut details = HashMap::new();
        details.insert("requested_permission".to_string(), permission.to_string());

        let event = AuditEvent {
            id: String::new(),
            event_type: AuditEventType::PermissionDenied,
            timestamp: SystemTime::UNIX_EPOCH,
            user_id: Some(user_id.to_string()),
            session_id: None,
            outcome: EventOutcome::Failure,
            risk_level: RiskLevel::Medium,
            description: format!(
                "Permission denied: {} on {}",
                permission, resource.resource_type
            ),
            details,
            request_metadata: metadata,
            resource: Some(resource),
            actor: ActorInfo {
                actor_type: "user".to_string(),
                actor_id: user_id.to_string(),
                actor_name: None,
                roles: vec![],
            },
            correlation_id: Some(self.correlation_generator.generate()),
        };

        self.log_event(event).await
    }

    /// Log suspicious activity
    pub async fn log_suspicious_activity(
        &self,
        user_id: Option<&str>,
        activity_type: &str,
        description: &str,
        metadata: RequestMetadata,
    ) -> Result<()> {
        let mut details = HashMap::new();
        details.insert("activity_type".to_string(), activity_type.to_string());

        let event = AuditEvent {
            id: String::new(),
            event_type: AuditEventType::SuspiciousActivity,
            timestamp: SystemTime::UNIX_EPOCH,
            user_id: user_id.map(|s| s.to_string()),
            session_id: None,
            outcome: EventOutcome::Unknown,
            risk_level: RiskLevel::High,
            description: description.to_string(),
            details,
            request_metadata: metadata,
            resource: None,
            actor: ActorInfo {
                actor_type: user_id.map(|_| "user").unwrap_or("system").to_string(),
                actor_id: user_id.unwrap_or("system").to_string(),
                actor_name: None,
                roles: vec![],
            },
            correlation_id: Some(self.correlation_generator.generate()),
        };

        self.log_event(event).await
    }

    /// Check for security alerts based on event patterns
    async fn check_security_alerts(&self, event: &AuditEvent) -> Result<()> {
        match event.event_type {
            AuditEventType::LoginFailure => {
                self.check_brute_force_pattern(event).await?;
            }
            AuditEventType::SuspiciousActivity => {
                // Could trigger immediate alerts
                self.trigger_security_alert(event).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check for brute force attack patterns
    async fn check_brute_force_pattern(&self, event: &AuditEvent) -> Result<()> {
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::LoginFailure]),
            ip_address: event.request_metadata.ip_address.clone(),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(300), // Last 5 minutes
                end: SystemTime::now(),
            }),
            limit: Some(10),
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            sort_order: SortOrder::TimestampDesc,
        };

        let recent_failures = self.storage.query_events(&query).await?;

        if recent_failures.len() >= 5 {
            // Log brute force detection
            let mut details = HashMap::new();
            details.insert(
                "failure_count".to_string(),
                recent_failures.len().to_string(),
            );
            details.insert("time_window".to_string(), "300".to_string());

            let brute_force_event = AuditEvent {
                id: String::new(),
                event_type: AuditEventType::BruteForceDetected,
                timestamp: SystemTime::now(),
                user_id: None,
                session_id: None,
                outcome: EventOutcome::Success,
                risk_level: RiskLevel::Critical,
                description: "Brute force attack detected".to_string(),
                details,
                request_metadata: event.request_metadata.clone(),
                resource: None,
                actor: ActorInfo {
                    actor_type: "system".to_string(),
                    actor_id: "security_monitor".to_string(),
                    actor_name: Some("Security Monitor".to_string()),
                    roles: vec!["system".to_string()],
                },
                correlation_id: Some(self.correlation_generator.generate()),
            };

            self.storage.store_event(&brute_force_event).await?;
        }

        Ok(())
    }

    /// Trigger security alert
    async fn trigger_security_alert(&self, _event: &AuditEvent) -> Result<()> {
        // In a real implementation, this would:
        // - Send notifications to security team
        // - Update security dashboards
        // - Trigger automated responses
        Ok(())
    }

    /// Query audit events
    pub async fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        self.storage.query_events(query).await
    }

    /// Get audit statistics
    pub async fn get_statistics(&self, query: &StatsQuery) -> Result<AuditStatistics> {
        self.storage.get_statistics(query).await
    }

    /// Get failed login count in the last 24 hours
    pub async fn get_failed_login_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::LoginFailure]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Get successful login count in the last 24 hours
    pub async fn get_successful_login_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::LoginSuccess]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Get token issued count in the last 24 hours
    pub async fn get_token_issued_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![
                AuditEventType::TokenRefresh,
                AuditEventType::LoginSuccess,
            ]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Get unique users count in the last 24 hours
    pub async fn get_unique_users_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::LoginSuccess]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };

        let events = self.storage.query_events(&query).await?;
        let unique_users: std::collections::HashSet<_> =
            events.iter().filter_map(|e| e.user_id.as_ref()).collect();
        Ok(unique_users.len() as u64)
    }

    /// Get password reset count in the last 24 hours
    pub async fn get_password_reset_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![AuditEventType::UserPasswordReset]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Get admin action count in the last 24 hours
    pub async fn get_admin_action_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![
                AuditEventType::AdminAction,
                AuditEventType::UserCreated,
                AuditEventType::UserUpdated,
                AuditEventType::UserDeleted,
                AuditEventType::RoleCreated,
                AuditEventType::RoleUpdated,
                AuditEventType::RoleDeleted,
            ]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Get security alert count in the last 24 hours
    pub async fn get_security_alert_count_24h(&self) -> Result<u64> {
        let query = AuditQuery {
            event_types: Some(vec![
                AuditEventType::SuspiciousActivity,
                AuditEventType::BruteForceDetected,
                AuditEventType::SecurityViolation,
            ]),
            time_range: Some(TimeRange {
                start: SystemTime::now() - std::time::Duration::from_secs(24 * 60 * 60),
                end: SystemTime::now(),
            }),
            limit: None,
            offset: None,
            user_id: None,
            risk_level: Some(RiskLevel::High),
            outcome: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            ip_address: None,
            sort_order: SortOrder::TimestampDesc,
        };
        self.storage.count_events(&query).await
    }

    /// Clean up old audit events
    pub async fn cleanup_old_events(&self, retention_days: u32) -> Result<u64> {
        let cutoff_time =
            SystemTime::now() - std::time::Duration::from_secs(retention_days as u64 * 86400);
        self.storage.delete_old_events(cutoff_time).await
    }
}

/// Correlation ID generator for tracking related events
pub struct CorrelationIdGenerator {
    counter: std::sync::atomic::AtomicU64,
}

impl CorrelationIdGenerator {
    pub fn new() -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn generate(&self) -> String {
        let count = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!(
            "corr_{:016x}_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            count
        )
    }
}

/// Helper for creating request metadata
impl RequestMetadata {
    pub fn new() -> Self {
        Self {
            ip_address: None,
            user_agent: None,
            request_id: None,
            endpoint: None,
            http_method: None,
            geolocation: None,
            device_info: None,
        }
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

impl Default for RequestMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_generation() {
        let generator = CorrelationIdGenerator::new();
        let id1 = generator.generate();
        let id2 = generator.generate();

        assert_ne!(id1, id2);
        assert!(id1.starts_with("corr_"));
        assert!(id2.starts_with("corr_"));
    }

    #[test]
    fn test_request_metadata_builder() {
        let metadata = RequestMetadata::new()
            .with_ip("192.168.1.1")
            .with_user_agent("Mozilla/5.0")
            .with_endpoint("/api/auth/login");

        assert_eq!(metadata.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(metadata.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(metadata.endpoint, Some("/api/auth/login".to_string()));
    }
}
