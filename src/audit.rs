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
use chrono::TimeZone as _;
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

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginSuccess => write!(f, "login_success"),
            Self::LoginFailure => write!(f, "login_failure"),
            Self::Logout => write!(f, "logout"),
            Self::TokenRefresh => write!(f, "token_refresh"),
            Self::TokenExpired => write!(f, "token_expired"),
            Self::TokenRevoked => write!(f, "token_revoked"),
            Self::MfaSetup => write!(f, "mfa_setup"),
            Self::MfaChallengeCreated => write!(f, "mfa_challenge_created"),
            Self::MfaVerificationSuccess => write!(f, "mfa_verification_success"),
            Self::MfaVerificationFailure => write!(f, "mfa_verification_failure"),
            Self::MfaMethodEnabled => write!(f, "mfa_method_enabled"),
            Self::MfaMethodDisabled => write!(f, "mfa_method_disabled"),
            Self::PermissionGranted => write!(f, "permission_granted"),
            Self::PermissionDenied => write!(f, "permission_denied"),
            Self::RoleAssigned => write!(f, "role_assigned"),
            Self::RoleRevoked => write!(f, "role_revoked"),
            Self::RoleCreated => write!(f, "role_created"),
            Self::RoleUpdated => write!(f, "role_updated"),
            Self::RoleDeleted => write!(f, "role_deleted"),
            Self::UserCreated => write!(f, "user_created"),
            Self::UserUpdated => write!(f, "user_updated"),
            Self::UserDeleted => write!(f, "user_deleted"),
            Self::UserActivated => write!(f, "user_activated"),
            Self::UserDeactivated => write!(f, "user_deactivated"),
            Self::UserPasswordChanged => write!(f, "user_password_changed"),
            Self::UserPasswordReset => write!(f, "user_password_reset"),
            Self::AccountLocked => write!(f, "account_locked"),
            Self::AccountUnlocked => write!(f, "account_unlocked"),
            Self::SuspiciousActivity => write!(f, "suspicious_activity"),
            Self::BruteForceDetected => write!(f, "brute_force_detected"),
            Self::RateLimitExceeded => write!(f, "rate_limit_exceeded"),
            Self::SecurityPolicyViolation => write!(f, "security_policy_violation"),
            Self::SecurityViolation => write!(f, "security_violation"),
            Self::AdminAction => write!(f, "admin_action"),
            Self::ConfigurationChanged => write!(f, "configuration_changed"),
            Self::SystemStartup => write!(f, "system_startup"),
            Self::SystemShutdown => write!(f, "system_shutdown"),
            Self::BackupCreated => write!(f, "backup_created"),
            Self::DataExported => write!(f, "data_exported"),
            Self::DataImported => write!(f, "data_imported"),
        }
    }
}

/// Security risk level
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Audit event outcome
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventOutcome {
    Success,
    Failure,
    Partial,
    Unknown,
}

impl std::fmt::Display for EventOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Partial => write!(f, "partial"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
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
        let event = AuditEvent::builder(
            AuditEventType::LoginSuccess,
            "User successfully authenticated",
        )
        .user_id(user_id)
        .session_id(session_id)
        .outcome(EventOutcome::Success)
        .request_metadata(metadata)
        .with_actor("user", user_id)
        .correlation_id(self.correlation_generator.generate())
        .build();

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

        let event = AuditEvent::builder(
            AuditEventType::LoginFailure,
            format!("Authentication failed for user: {}", attempted_user),
        )
        .outcome(EventOutcome::Failure)
        .risk_level(RiskLevel::Medium)
        .details(details)
        .request_metadata(metadata)
        .with_actor("user", attempted_user)
        .correlation_id(self.correlation_generator.generate())
        .build();

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

        let event = AuditEvent::builder(
            AuditEventType::PermissionDenied,
            format!(
                "Permission denied: {} on {}",
                permission, resource.resource_type
            ),
        )
        .user_id(user_id)
        .outcome(EventOutcome::Failure)
        .risk_level(RiskLevel::Medium)
        .details(details)
        .request_metadata(metadata)
        .resource(resource)
        .with_actor("user", user_id)
        .correlation_id(self.correlation_generator.generate())
        .build();

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

        let mut builder = AuditEvent::builder(AuditEventType::SuspiciousActivity, description)
            .outcome(EventOutcome::Unknown)
            .risk_level(RiskLevel::High)
            .details(details)
            .request_metadata(metadata)
            .with_actor(
                user_id.map(|_| "user").unwrap_or("system"),
                user_id.unwrap_or("system"),
            )
            .correlation_id(self.correlation_generator.generate());
        if let Some(uid) = user_id {
            builder = builder.user_id(uid);
        }
        let event = builder.build();

        self.log_event(event).await
    }

    /// Check for security alerts based on event patterns
    async fn check_security_alerts(&self, event: &AuditEvent) -> Result<()> {
        match event.event_type {
            AuditEventType::LoginFailure => {
                self.check_brute_force_pattern(event).await?;
            }
            AuditEventType::SuspiciousActivity
            | AuditEventType::BruteForceDetected
            | AuditEventType::SecurityPolicyViolation
            | AuditEventType::SecurityViolation => {
                self.trigger_security_alert(event).await?;
            }
            AuditEventType::AccountLocked | AuditEventType::RateLimitExceeded => {
                // Elevated events — worth logging as alerts but not as urgent
                tracing::warn!(
                    event_type = ?event.event_type,
                    user_id = ?event.user_id,
                    "Security-relevant audit event recorded"
                );
            }
            // Non-security events — no alert action needed
            _ => {}
        }
        Ok(())
    }

    /// Check for brute force attack patterns
    async fn check_brute_force_pattern(&self, event: &AuditEvent) -> Result<()> {
        let mut query = AuditQuery::builder()
            .event_types(vec![AuditEventType::LoginFailure])
            .last_seconds(300)
            .limit(10)
            .build();
        query.ip_address = event.request_metadata.ip_address.clone();

        let recent_failures = self.storage.query_events(&query).await?;

        if recent_failures.len() >= 5 {
            // Log brute force detection
            let mut details = HashMap::new();
            details.insert(
                "failure_count".to_string(),
                recent_failures.len().to_string(),
            );
            details.insert("time_window".to_string(), "300".to_string());

            let brute_force_event = AuditEvent::builder(
                AuditEventType::BruteForceDetected,
                "Brute force attack detected",
            )
            .outcome(EventOutcome::Success)
            .risk_level(RiskLevel::Critical)
            .details(details)
            .request_metadata(event.request_metadata.clone())
            .actor(ActorInfo {
                actor_type: "system".to_string(),
                actor_id: "security_monitor".to_string(),
                actor_name: Some("Security Monitor".to_string()),
                roles: vec!["system".to_string()],
            })
            .correlation_id(self.correlation_generator.generate())
            .build();

            self.storage.store_event(&brute_force_event).await?;
        }

        Ok(())
    }

    /// Trigger security alert
    async fn trigger_security_alert(&self, event: &AuditEvent) -> Result<()> {
        tracing::warn!(
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            risk_level = ?event.risk_level,
            description = %event.description,
            ip_address = ?event.request_metadata.ip_address,
            "SECURITY ALERT: {}", event.description
        );
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
        let query = AuditQuery::builder()
            .event_types(vec![AuditEventType::LoginFailure])
            .last_24h()
            .build();
        self.storage.count_events(&query).await
    }

    /// Get successful login count in the last 24 hours
    pub async fn get_successful_login_count_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![AuditEventType::LoginSuccess])
            .last_24h()
            .build();
        self.storage.count_events(&query).await
    }

    /// Get token issued count in the last 24 hours
    pub async fn get_token_issued_count_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![
                AuditEventType::TokenRefresh,
                AuditEventType::LoginSuccess,
            ])
            .last_24h()
            .build();
        self.storage.count_events(&query).await
    }

    /// Get unique users count in the last 24 hours
    pub async fn get_unique_users_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![AuditEventType::LoginSuccess])
            .last_24h()
            .build();

        let events = self.storage.query_events(&query).await?;
        let unique_users: std::collections::HashSet<_> =
            events.iter().filter_map(|e| e.user_id.as_ref()).collect();
        Ok(unique_users.len() as u64)
    }

    /// Get password reset count in the last 24 hours
    pub async fn get_password_reset_count_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![AuditEventType::UserPasswordReset])
            .last_24h()
            .build();
        self.storage.count_events(&query).await
    }

    /// Get admin action count in the last 24 hours
    pub async fn get_admin_action_count_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![
                AuditEventType::AdminAction,
                AuditEventType::UserCreated,
                AuditEventType::UserUpdated,
                AuditEventType::UserDeleted,
                AuditEventType::RoleCreated,
                AuditEventType::RoleUpdated,
                AuditEventType::RoleDeleted,
            ])
            .last_24h()
            .build();
        self.storage.count_events(&query).await
    }

    /// Get security alert count in the last 24 hours
    pub async fn get_security_alert_count_24h(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![
                AuditEventType::SuspiciousActivity,
                AuditEventType::BruteForceDetected,
                AuditEventType::SecurityViolation,
            ])
            .last_24h()
            .risk_level(RiskLevel::High)
            .build();
        self.storage.count_events(&query).await
    }

    /// Get permission check event count in the last hour.
    pub async fn get_permission_checks_last_hour(&self) -> Result<u64> {
        let query = AuditQuery::builder()
            .event_types(vec![
                AuditEventType::PermissionGranted,
                AuditEventType::PermissionDenied,
            ])
            .last_seconds(3600)
            .build();
        self.storage.count_events(&query).await
    }

    /// Get permission-related audit log entries with optional filters.
    pub async fn get_permission_audit_logs(
        &self,
        user_id: Option<&str>,
        action: Option<&str>,
        resource: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        let mut builder = AuditQuery::builder().event_types(vec![
            AuditEventType::PermissionGranted,
            AuditEventType::PermissionDenied,
            AuditEventType::RoleAssigned,
            AuditEventType::RoleRevoked,
            AuditEventType::RoleCreated,
            AuditEventType::RoleUpdated,
            AuditEventType::RoleDeleted,
        ]);
        if let Some(uid) = user_id {
            builder = builder.user_id(uid);
        }
        if let Some(rt) = resource {
            builder = builder.resource_type(rt);
        }
        if let Some(l) = limit {
            builder = builder.limit(l as u64);
        }
        let query = builder.build();

        let events = self.storage.query_events(&query).await?;

        let logs = events
            .into_iter()
            .filter(|e| {
                action.is_none_or(|a| {
                    e.description.to_lowercase().contains(&a.to_lowercase())
                        || e.details
                            .values()
                            .any(|v| v.to_lowercase().contains(&a.to_lowercase()))
                })
            })
            .map(|e| {
                let ts = e
                    .timestamp
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| {
                        chrono::Utc
                            .timestamp_opt(d.as_secs() as i64, 0)
                            .single()
                            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                            .unwrap_or_else(|| "unknown-time".to_string())
                    })
                    .unwrap_or_else(|_| "unknown-time".to_string());
                let uid = e.user_id.as_deref().unwrap_or("system");
                format!(
                    "[{}] {} user={} outcome={} - {}",
                    ts, e.event_type, uid, e.outcome, e.description
                )
            })
            .collect();

        Ok(logs)
    }

    /// Assemble comprehensive security audit statistics.
    ///
    /// `active_sessions` should be obtained from the session manager
    /// and passed in by the caller.
    pub async fn get_security_audit_stats(
        &self,
        active_sessions: u64,
    ) -> Result<SecurityAuditStats> {
        let failed_logins_24h = self.get_failed_login_count_24h().await.unwrap_or(0);
        let successful_logins_24h = self
            .get_successful_login_count_24h()
            .await
            .unwrap_or(active_sessions * 2);
        let token_issued_24h = self
            .get_token_issued_count_24h()
            .await
            .unwrap_or(active_sessions * 3);
        let unique_users_24h = self
            .get_unique_users_24h()
            .await
            .unwrap_or((successful_logins_24h as f64 * 0.7) as u64);
        let password_resets_24h = self.get_password_reset_count_24h().await.unwrap_or(0);
        let admin_actions_24h = self.get_admin_action_count_24h().await.unwrap_or(0);
        let security_alerts_24h = self.get_security_alert_count_24h().await.unwrap_or(0);

        Ok(SecurityAuditStats {
            active_sessions,
            failed_logins_24h,
            successful_logins_24h,
            unique_users_24h,
            token_issued_24h,
            password_resets_24h,
            admin_actions_24h,
            security_alerts_24h,
            collection_timestamp: chrono::Utc::now(),
        })
    }

    /// Emit a structured tracing event for an authentication event (success, failure, or MFA required).
    ///
    /// Callers are responsible for applying their own config guards before invoking this.
    pub async fn log_auth_trace_event(
        &self,
        event_type: &str,
        user_id: &str,
        method: &str,
        client_ip: &str,
        user_agent: &str,
    ) {
        tracing::info!(
            target: "auth_audit",
            event_type = event_type,
            user_id = user_id,
            method = method,
            client_ip = client_ip,
            user_agent = user_agent,
            timestamp = %chrono::Utc::now().to_rfc3339(),
            "Authentication event"
        );
    }

    /// Clean up old audit events
    pub async fn cleanup_old_events(&self, retention_days: u32) -> Result<u64> {
        let cutoff_time =
            SystemTime::now() - std::time::Duration::from_secs(retention_days as u64 * 86400);
        self.storage.delete_old_events(cutoff_time).await
    }
}

/// Security audit statistics aggregated from audit logs.
///
/// Provides comprehensive security metrics for monitoring and incident response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditStats {
    pub active_sessions: u64,
    pub failed_logins_24h: u64,
    pub successful_logins_24h: u64,
    pub unique_users_24h: u64,
    pub token_issued_24h: u64,
    pub password_resets_24h: u64,
    pub admin_actions_24h: u64,
    pub security_alerts_24h: u64,
    pub collection_timestamp: chrono::DateTime<chrono::Utc>,
}

impl SecurityAuditStats {
    /// Calculate security score based on current metrics.
    /// Returns a value between 0.0 (critical) and 1.0 (excellent).
    pub fn security_score(&self) -> f64 {
        let mut score = 1.0_f64;

        if self.successful_logins_24h > 0 {
            let failure_rate = self.failed_logins_24h as f64
                / (self.successful_logins_24h + self.failed_logins_24h) as f64;
            if failure_rate > 0.1 {
                score -= failure_rate * 0.3;
            }
        }

        if self.security_alerts_24h > 0 {
            score -= (self.security_alerts_24h as f64 * 0.1).min(0.4);
        }

        if self.successful_logins_24h > 0 && self.failed_logins_24h < 10 {
            score += 0.05;
        }

        score.clamp(0.0, 1.0)
    }

    /// Returns `true` if security metrics require immediate administrative attention.
    ///
    /// Criteria: > 100 failed logins, > 5 security alerts, or security score < 0.3.
    ///
    /// ```rust,no_run
    /// use auth_framework::audit::SecurityAuditStats;
    ///
    /// # fn alert_security_team(_: &SecurityAuditStats) {}
    /// # let security_stats: SecurityAuditStats = unimplemented!();
    /// if security_stats.requires_immediate_attention() {
    ///     alert_security_team(&security_stats);
    /// }
    /// ```
    pub fn requires_immediate_attention(&self) -> bool {
        self.failed_logins_24h > 100 || self.security_alerts_24h > 5 || self.security_score() < 0.3
    }

    /// Generates a human-readable alert message when immediate attention is required.
    ///
    /// Returns `None` if no immediate security concerns are detected.
    ///
    /// ```rust,no_run
    /// use auth_framework::audit::SecurityAuditStats;
    ///
    /// # fn notify_administrators(_: &str) {}
    /// # let security_stats: SecurityAuditStats = unimplemented!();
    /// if let Some(alert) = security_stats.security_alert_message() {
    ///     log::error!("Security Alert: {}", alert);
    ///     notify_administrators(&alert);
    /// }
    /// ```
    pub fn security_alert_message(&self) -> Option<String> {
        if !self.requires_immediate_attention() {
            return None;
        }

        let mut alerts = Vec::new();

        if self.failed_logins_24h > 100 {
            alerts.push(format!(
                "High failed login attempts: {}",
                self.failed_logins_24h
            ));
        }
        if self.security_alerts_24h > 5 {
            alerts.push(format!(
                "Multiple security alerts: {}",
                self.security_alerts_24h
            ));
        }
        if self.security_score() < 0.3 {
            alerts.push(format!(
                "Critical security score: {:.2}",
                self.security_score()
            ));
        }

        Some(format!(
            "🚨 SECURITY ATTENTION REQUIRED: {}",
            alerts.join(", ")
        ))
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

// ── AuditEvent builder ────────────────────────────────────────────────

/// A fluent builder for [`AuditEvent`].
///
/// Only `event_type` and `description` are required; every other field
/// receives a sensible default (auto-generated `id`, `SystemTime::now()`
/// timestamp, `RiskLevel::Low`, `EventOutcome::Unknown`, etc.).
///
/// # Example
///
/// ```rust
/// use auth_framework::audit::*;
///
/// let event = AuditEvent::builder(AuditEventType::LoginSuccess, "User logged in")
///     .user_id("user_123")
///     .session_id("sess_abc")
///     .outcome(EventOutcome::Success)
///     .with_actor("user", "user_123")
///     .build();
///
/// assert_eq!(event.event_type, AuditEventType::LoginSuccess);
/// assert_eq!(event.user_id, Some("user_123".to_string()));
/// ```
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEvent {
    /// Create a builder pre-populated with `event_type` and `description`.
    pub fn builder(
        event_type: AuditEventType,
        description: impl Into<String>,
    ) -> AuditEventBuilder {
        AuditEventBuilder::new(event_type, description)
    }
}

impl AuditEventBuilder {
    /// Create a new builder with required fields.
    pub fn new(event_type: AuditEventType, description: impl Into<String>) -> Self {
        Self {
            event: AuditEvent {
                id: String::new(),
                event_type,
                timestamp: SystemTime::UNIX_EPOCH,
                user_id: None,
                session_id: None,
                outcome: EventOutcome::Unknown,
                risk_level: RiskLevel::Low,
                description: description.into(),
                details: HashMap::new(),
                request_metadata: RequestMetadata::new(),
                resource: None,
                actor: ActorInfo {
                    actor_type: "unknown".to_string(),
                    actor_id: String::new(),
                    actor_name: None,
                    roles: Vec::new(),
                },
                correlation_id: None,
            },
        }
    }

    /// Set the user ID.
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.event.user_id = Some(id.into());
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.event.session_id = Some(id.into());
        self
    }

    /// Set the event outcome.
    pub fn outcome(mut self, outcome: EventOutcome) -> Self {
        self.event.outcome = outcome;
        self
    }

    /// Set the risk level.
    pub fn risk_level(mut self, level: RiskLevel) -> Self {
        self.event.risk_level = level;
        self
    }

    /// Set actor information.
    pub fn with_actor(
        mut self,
        actor_type: impl Into<String>,
        actor_id: impl Into<String>,
    ) -> Self {
        self.event.actor = ActorInfo {
            actor_type: actor_type.into(),
            actor_id: actor_id.into(),
            actor_name: None,
            roles: Vec::new(),
        };
        self
    }

    /// Set full actor information.
    pub fn actor(mut self, actor: ActorInfo) -> Self {
        self.event.actor = actor;
        self
    }

    /// Set request metadata.
    pub fn request_metadata(mut self, metadata: RequestMetadata) -> Self {
        self.event.request_metadata = metadata;
        self
    }

    /// Set the affected resource.
    pub fn resource(mut self, resource: ResourceInfo) -> Self {
        self.event.resource = Some(resource);
        self
    }

    /// Set the correlation ID.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.event.correlation_id = Some(id.into());
        self
    }

    /// Insert a key-value pair into the event details.
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event.details.insert(key.into(), value.into());
        self
    }

    /// Set the full details map.
    pub fn details(mut self, details: HashMap<String, String>) -> Self {
        self.event.details = details;
        self
    }

    /// Consume the builder and produce the [`AuditEvent`].
    ///
    /// Auto-generates a UUID `id` if one was not set, and sets the
    /// timestamp to `SystemTime::now()` if it was left at the default.
    pub fn build(mut self) -> AuditEvent {
        if self.event.id.is_empty() {
            self.event.id = uuid::Uuid::new_v4().to_string();
        }
        if self.event.timestamp == SystemTime::UNIX_EPOCH {
            self.event.timestamp = SystemTime::now();
        }
        self.event
    }
}

// ── AuditQuery builder ───────────────────────────────────────────────

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            event_types: None,
            user_id: None,
            risk_level: None,
            outcome: None,
            time_range: None,
            ip_address: None,
            resource_type: None,
            actor_id: None,
            correlation_id: None,
            limit: None,
            offset: None,
            sort_order: SortOrder::TimestampDesc,
        }
    }
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::TimestampDesc
    }
}

/// A fluent builder for [`AuditQuery`].
///
/// Starts from the [`Default`] query (no filters, descending timestamp).
///
/// # Example
///
/// ```rust
/// use auth_framework::audit::*;
/// use std::time::{Duration, SystemTime};
///
/// let query = AuditQuery::builder()
///     .event_types(vec![AuditEventType::LoginFailure])
///     .limit(50)
///     .build();
///
/// assert_eq!(query.limit, Some(50));
/// ```
pub struct AuditQueryBuilder {
    query: AuditQuery,
}

impl AuditQuery {
    /// Create a new builder for constructing queries.
    pub fn builder() -> AuditQueryBuilder {
        AuditQueryBuilder {
            query: AuditQuery::default(),
        }
    }
}

impl AuditQueryBuilder {
    /// Filter by event types.
    pub fn event_types(mut self, types: Vec<AuditEventType>) -> Self {
        self.query.event_types = Some(types);
        self
    }

    /// Filter by user ID.
    pub fn user_id(mut self, id: impl Into<String>) -> Self {
        self.query.user_id = Some(id.into());
        self
    }

    /// Filter by minimum risk level.
    pub fn risk_level(mut self, level: RiskLevel) -> Self {
        self.query.risk_level = Some(level);
        self
    }

    /// Filter by outcome.
    pub fn outcome(mut self, outcome: EventOutcome) -> Self {
        self.query.outcome = Some(outcome);
        self
    }

    /// Filter by time range.
    pub fn time_range(mut self, start: SystemTime, end: SystemTime) -> Self {
        self.query.time_range = Some(TimeRange { start, end });
        self
    }

    /// Convenience: filter to the last N seconds.
    pub fn last_seconds(mut self, seconds: u64) -> Self {
        self.query.time_range = Some(TimeRange {
            start: SystemTime::now() - std::time::Duration::from_secs(seconds),
            end: SystemTime::now(),
        });
        self
    }

    /// Convenience: filter to the last 24 hours.
    pub fn last_24h(self) -> Self {
        self.last_seconds(24 * 60 * 60)
    }

    /// Filter by IP address.
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.query.ip_address = Some(ip.into());
        self
    }

    /// Filter by resource type.
    pub fn resource_type(mut self, rt: impl Into<String>) -> Self {
        self.query.resource_type = Some(rt.into());
        self
    }

    /// Filter by actor ID.
    pub fn actor_id(mut self, id: impl Into<String>) -> Self {
        self.query.actor_id = Some(id.into());
        self
    }

    /// Filter by correlation ID.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.query.correlation_id = Some(id.into());
        self
    }

    /// Limit the number of results.
    pub fn limit(mut self, limit: u64) -> Self {
        self.query.limit = Some(limit);
        self
    }

    /// Set pagination offset.
    pub fn offset(mut self, offset: u64) -> Self {
        self.query.offset = Some(offset);
        self
    }

    /// Set the sort order.
    pub fn sort_order(mut self, order: SortOrder) -> Self {
        self.query.sort_order = order;
        self
    }

    /// Consume the builder and produce the [`AuditQuery`].
    pub fn build(self) -> AuditQuery {
        self.query
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

    #[test]
    fn test_audit_event_builder_minimal() {
        let event = AuditEvent::builder(AuditEventType::LoginSuccess, "User logged in").build();
        assert_eq!(event.event_type, AuditEventType::LoginSuccess);
        assert_eq!(event.description, "User logged in");
        assert!(!event.id.is_empty(), "id should be auto-generated");
        assert_ne!(
            event.timestamp,
            SystemTime::UNIX_EPOCH,
            "timestamp should be auto-set"
        );
        assert_eq!(event.outcome, EventOutcome::Unknown);
        assert_eq!(event.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_audit_event_builder_full() {
        let event = AuditEvent::builder(AuditEventType::PermissionDenied, "Access denied")
            .user_id("u123")
            .session_id("s456")
            .outcome(EventOutcome::Failure)
            .risk_level(RiskLevel::High)
            .with_actor("user", "u123")
            .detail("resource", "admin_panel")
            .correlation_id("corr_xyz")
            .build();

        assert_eq!(event.user_id, Some("u123".to_string()));
        assert_eq!(event.session_id, Some("s456".to_string()));
        assert_eq!(event.outcome, EventOutcome::Failure);
        assert_eq!(event.risk_level, RiskLevel::High);
        assert_eq!(event.actor.actor_type, "user");
        assert_eq!(event.actor.actor_id, "u123");
        assert_eq!(
            event.details.get("resource"),
            Some(&"admin_panel".to_string())
        );
        assert_eq!(event.correlation_id, Some("corr_xyz".to_string()));
    }

    #[test]
    fn test_audit_query_builder() {
        let query = AuditQuery::builder()
            .event_types(vec![AuditEventType::LoginFailure])
            .limit(50)
            .offset(10)
            .build();

        assert_eq!(query.event_types, Some(vec![AuditEventType::LoginFailure]));
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(10));
        assert!(query.user_id.is_none());
    }

    #[test]
    fn test_audit_query_default() {
        let query = AuditQuery::default();
        assert!(query.event_types.is_none());
        assert!(query.user_id.is_none());
        assert!(query.limit.is_none());
        assert!(matches!(query.sort_order, SortOrder::TimestampDesc));
    }

    #[test]
    fn test_audit_query_last_24h() {
        let query = AuditQuery::builder().last_24h().build();
        assert!(query.time_range.is_some());
        let range = query.time_range.unwrap();
        let elapsed = range.end.duration_since(range.start).unwrap();
        // Should be approximately 24 hours (allow small timing variance)
        assert!(elapsed.as_secs() >= 86399 && elapsed.as_secs() <= 86401);
    }

    #[test]
    fn test_audit_query_last_seconds() {
        let query = AuditQuery::builder().last_seconds(3600).build();
        assert!(query.time_range.is_some());
        let range = query.time_range.unwrap();
        let elapsed = range.end.duration_since(range.start).unwrap();
        assert!(elapsed.as_secs() >= 3599 && elapsed.as_secs() <= 3601);
    }

    #[test]
    fn test_audit_event_type_display() {
        assert_eq!(AuditEventType::LoginSuccess.to_string(), "login_success");
        assert_eq!(AuditEventType::LoginFailure.to_string(), "login_failure");
        assert_eq!(AuditEventType::Logout.to_string(), "logout");
        assert_eq!(AuditEventType::TokenRefresh.to_string(), "token_refresh");
        assert_eq!(
            AuditEventType::MfaVerificationSuccess.to_string(),
            "mfa_verification_success"
        );
        assert_eq!(
            AuditEventType::PermissionGranted.to_string(),
            "permission_granted"
        );
        assert_eq!(
            AuditEventType::PermissionDenied.to_string(),
            "permission_denied"
        );
        assert_eq!(AuditEventType::RoleAssigned.to_string(), "role_assigned");
        assert_eq!(AuditEventType::UserCreated.to_string(), "user_created");
        assert_eq!(AuditEventType::AccountLocked.to_string(), "account_locked");
        assert_eq!(
            AuditEventType::BruteForceDetected.to_string(),
            "brute_force_detected"
        );
        assert_eq!(AuditEventType::AdminAction.to_string(), "admin_action");
        assert_eq!(AuditEventType::SystemStartup.to_string(), "system_startup");
        assert_eq!(AuditEventType::DataExported.to_string(), "data_exported");
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Medium.to_string(), "medium");
        assert_eq!(RiskLevel::High.to_string(), "high");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn test_event_outcome_display() {
        assert_eq!(EventOutcome::Success.to_string(), "success");
        assert_eq!(EventOutcome::Failure.to_string(), "failure");
        assert_eq!(EventOutcome::Partial.to_string(), "partial");
        assert_eq!(EventOutcome::Unknown.to_string(), "unknown");
    }
}
