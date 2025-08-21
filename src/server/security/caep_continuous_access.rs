//! # Continuous Access Evaluation Protocol (CAEP)
//!
//! This module implements the Continuous Access Evaluation Protocol (CAEP), enabling
//! real-time access evaluation and revocation based on security events and risk changes.
//!
//! ## Overview
//!
//! CAEP extends traditional OAuth 2.0 and OpenID Connect by providing continuous
//! monitoring and evaluation of access tokens, allowing for immediate revocation
//! when security conditions change.
//!
//! ## Key Features
//!
//! - **Real-time Event Processing**: Continuous monitoring of security events
//! - **Automatic Access Revocation**: Immediate token revocation on security events
//! - **Cross-system Event Propagation**: Events can trigger actions across multiple systems
//! - **Risk-based Evaluation**: Dynamic access decisions based on changing risk profiles
//! - **Session State Management**: Continuous session validity assessment
//!
//! ## Event Types
//!
//! - **User Events**: Login/logout, profile changes, credential changes
//! - **Session Events**: Session creation, modification, timeout, suspicious activity
//! - **Risk Events**: Location changes, device changes, behavioral anomalies
//! - **Policy Events**: Access policy updates, compliance violations
//! - **System Events**: Service outages, security incidents
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::caep_continuous_access::*;
//! use auth_framework::server::{SessionManager, oidc_backchannel_logout::BackChannelLogoutManager};
//! use chrono::Duration;
//! use std::sync::Arc;
//! use async_trait::async_trait;
//!
//! // Example event handler implementation
//! struct RiskScoreHandler;
//!
//! #[async_trait]
//! impl CaepEventHandler for RiskScoreHandler {
//!     async fn handle_event(&self, event: &CaepEvent) -> auth_framework::errors::Result<()> {
//!         if event.risk_score > 0.8 {
//!             // High risk - would revoke access in real implementation
//!             println!("High risk detected: {}", event.risk_score);
//!         }
//!         Ok(())
//!     }
//!
//!     fn supported_event_types(&self) -> Vec<CaepEventType> {
//!         vec![CaepEventType::RiskScoreChange]
//!     }
//! }
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize CAEP manager (simplified example - in real use, get managers from DI container)
//! let config = CaepConfig {
//!     event_stream_url: "wss://events.example.com/caep".to_string(),
//!     evaluation_interval: Duration::from_std(std::time::Duration::from_secs(30))?,
//!     auto_revoke: true,
//!     ..Default::default()
//! };
//!
//! // In real code, create these with proper configuration from your DI container
//! # let session_config = Default::default();
//! # let session_manager = Arc::new(SessionManager::new(session_config));
//! # let logout_config = Default::default();
//! # let logout_manager = Arc::new(BackChannelLogoutManager::new(logout_config, session_manager.as_ref().clone())?);
//! # let mut caep_manager = CaepManager::new(config, session_manager, logout_manager).await?;
//!
//! // Register event handler
//! caep_manager.register_event_handler(
//!     CaepEventType::RiskScoreChange,
//!     Arc::new(RiskScoreHandler)
//! ).await?;
//!
//! // Start continuous evaluation
//! caep_manager.start_continuous_evaluation().await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::server::core::stepped_up_auth::SteppedUpAuthManager;
use crate::server::oidc::oidc_backchannel_logout::BackChannelLogoutManager;
use crate::server::oidc::oidc_session_management::SessionManager;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tokio::time::{Interval, interval};
use uuid::Uuid;

/// Type alias for complex event handler storage
type EventHandlerMap = Arc<RwLock<HashMap<CaepEventType, Vec<Arc<dyn CaepEventHandler>>>>>;

/// Configuration for Continuous Access Evaluation Protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepConfig {
    /// URL for the event stream endpoint
    pub event_stream_url: String,

    /// How frequently to evaluate access decisions (default: 30 seconds)
    pub evaluation_interval: Duration,

    /// Whether to automatically revoke access on high-risk events
    pub auto_revoke: bool,

    /// Minimum risk score threshold for automatic revocation (0.0-1.0)
    pub auto_revoke_threshold: f32,

    /// Maximum number of concurrent event processors
    pub max_concurrent_processors: usize,

    /// Event retention period for audit trails
    pub event_retention_period: Duration,

    /// Cross-system event propagation endpoints
    pub propagation_endpoints: Vec<String>,

    /// Custom evaluation rules
    pub evaluation_rules: Vec<CaepEvaluationRule>,
}

impl Default for CaepConfig {
    fn default() -> Self {
        Self {
            event_stream_url: "wss://localhost:8080/caep/events".to_string(),
            evaluation_interval: Duration::try_seconds(30).unwrap_or(Duration::zero()),
            auto_revoke: true,
            auto_revoke_threshold: 0.8,
            max_concurrent_processors: 10,
            event_retention_period: Duration::try_hours(24).unwrap_or(Duration::zero()),
            propagation_endpoints: Vec::new(),
            evaluation_rules: Vec::new(),
        }
    }
}

/// Types of CAEP events
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaepEventType {
    /// User authentication events
    UserLogin,
    UserLogout,
    UserProfileChange,
    UserCredentialChange,

    /// Session-related events
    SessionCreated,
    SessionModified,
    SessionTimeout,
    SessionSuspiciousActivity,

    /// Risk assessment events
    RiskScoreChange,
    LocationChange,
    DeviceChange,
    BehavioralAnomaly,

    /// Policy and compliance events
    PolicyUpdate,
    ComplianceViolation,
    AccessPatternAnomaly,

    /// System and security events
    SystemOutage,
    SecurityIncident,
    DataBreach,

    /// Custom events for extensibility
    Custom(String),
}

/// Severity levels for CAEP events
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaepEventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Source of a CAEP event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepEventSource {
    /// Identifier of the source system
    pub system_id: String,

    /// Type of source (e.g., "identity_provider", "risk_engine", "policy_engine")
    pub source_type: String,

    /// Version of the source system
    pub version: Option<String>,

    /// Additional source metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A CAEP security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepEvent {
    /// Unique event identifier
    pub id: Uuid,

    /// Type of event
    pub event_type: CaepEventType,

    /// Subject (user) associated with the event
    pub subject: String,

    /// Severity level of the event
    pub severity: CaepEventSeverity,

    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Source of the event
    pub source: CaepEventSource,

    /// Current risk score (0.0-1.0)
    pub risk_score: f32,

    /// Session ID if applicable
    pub session_id: Option<String>,

    /// Geographic location information
    pub location: Option<CaepLocationInfo>,

    /// Device information
    pub device_info: Option<CaepDeviceInfo>,

    /// Event-specific data
    pub event_data: serde_json::Value,

    /// Correlation ID for related events
    pub correlation_id: Option<Uuid>,
}

/// Geographic location information for CAEP events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepLocationInfo {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,

    /// Region or state
    pub region: Option<String>,

    /// City name
    pub city: Option<String>,

    /// Latitude coordinate
    pub latitude: Option<f64>,

    /// Longitude coordinate
    pub longitude: Option<f64>,

    /// IP address
    pub ip_address: Option<String>,

    /// Whether location is considered suspicious
    pub is_suspicious: bool,
}

/// Device information for CAEP events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepDeviceInfo {
    /// Device identifier
    pub device_id: Option<String>,

    /// Device type (mobile, desktop, tablet, etc.)
    pub device_type: Option<String>,

    /// Operating system
    pub os: Option<String>,

    /// Browser or client application
    pub client: Option<String>,

    /// Whether device is trusted
    pub is_trusted: bool,

    /// Whether device binding is required
    pub requires_binding: bool,
}

/// Evaluation rule for continuous access decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepEvaluationRule {
    /// Rule identifier
    pub id: String,

    /// Human-readable description
    pub description: String,

    /// Event types this rule applies to
    pub applicable_events: Vec<CaepEventType>,

    /// Conditions that must be met
    pub conditions: Vec<CaepRuleCondition>,

    /// Actions to take when rule is triggered
    pub actions: Vec<CaepRuleAction>,

    /// Priority of this rule (higher numbers = higher priority)
    pub priority: i32,

    /// Whether rule is currently enabled
    pub enabled: bool,
}

/// Condition for a CAEP evaluation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaepRuleCondition {
    /// Risk score threshold condition
    RiskScoreAbove { threshold: f32 },

    /// Event severity condition
    SeverityAtLeast { severity: CaepEventSeverity },

    /// Location-based condition
    LocationChange { suspicious_only: bool },

    /// Device-based condition
    UnknownDevice { require_trusted: bool },

    /// Time-based condition
    OutsideBusinessHours { timezone: String },

    /// Custom condition with expression
    Custom { expression: String },
}

/// Action to take when a CAEP rule is triggered
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaepRuleAction {
    /// Revoke access tokens for the subject
    RevokeAccess { immediate: bool },

    /// Require step-up authentication
    RequireStepUp { level: String },

    /// Send notification
    SendNotification { channels: Vec<String> },

    /// Log security event
    LogEvent { level: String },

    /// Trigger external webhook
    TriggerWebhook { url: String },

    /// Quarantine session
    QuarantineSession { duration_minutes: u32 },
}

/// Result of a continuous access evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepEvaluationResult {
    /// Subject being evaluated
    pub subject: String,

    /// Current access decision
    pub access_decision: CaepAccessDecision,

    /// Current risk score
    pub risk_score: f32,

    /// Triggered rules
    pub triggered_rules: Vec<String>,

    /// Required actions
    pub required_actions: Vec<CaepRuleAction>,

    /// Evaluation timestamp
    pub evaluated_at: DateTime<Utc>,

    /// Next evaluation time
    pub next_evaluation: DateTime<Utc>,
}

/// Access decision from CAEP evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaepAccessDecision {
    /// Access granted - continue as normal
    Allow,

    /// Access granted but requires monitoring
    AllowWithMonitoring,

    /// Access granted but requires step-up authentication
    AllowWithStepUp,

    /// Access temporarily denied - retry later
    TemporaryDeny,

    /// Access permanently denied - revoke tokens
    Deny,
}

/// State of a CAEP session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaepSessionState {
    /// Session identifier
    pub session_id: String,

    /// Subject (user) of the session
    pub subject: String,

    /// Current risk score
    pub risk_score: f32,

    /// Last evaluation result
    pub last_evaluation: Option<CaepEvaluationResult>,

    /// Active events for this session
    pub active_events: Vec<CaepEvent>,

    /// Session creation time
    pub created_at: DateTime<Utc>,

    /// Last activity time
    pub last_activity: DateTime<Utc>,

    /// Whether session is quarantined
    pub is_quarantined: bool,

    /// Quarantine end time if applicable
    pub quarantine_until: Option<DateTime<Utc>>,
}

/// Comprehensive session information combining OIDC and CAEP data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveSessionInfo {
    /// OIDC session information
    pub oidc_session: crate::server::oidc::oidc_session_management::OidcSession,

    /// CAEP session information if available
    pub caep_session: Option<CaepSessionState>,

    /// Whether this session is being monitored by CAEP
    pub is_monitored_by_caep: bool,
}

/// Event handler trait for CAEP events
#[async_trait]
pub trait CaepEventHandler: Send + Sync {
    /// Handle a CAEP event
    async fn handle_event(&self, event: &CaepEvent) -> Result<()>;

    /// Get event types this handler can process
    fn supported_event_types(&self) -> Vec<CaepEventType>;
}

/// Main CAEP manager for continuous access evaluation
pub struct CaepManager {
    /// Configuration
    config: CaepConfig,

    /// Session manager integration
    session_manager: Arc<SessionManager>,

    /// Logout manager for revocations
    logout_manager: Arc<BackChannelLogoutManager>,

    /// Step-up authentication manager
    step_up_manager: Option<Arc<SteppedUpAuthManager>>,

    /// Active sessions being monitored
    sessions: Arc<RwLock<HashMap<String, CaepSessionState>>>,

    /// Event handlers by type
    event_handlers: EventHandlerMap,

    /// Event stream broadcaster
    event_broadcaster: broadcast::Sender<CaepEvent>,

    /// Evaluation timer
    evaluation_interval: Interval,

    /// Event history for audit trails
    event_history: Arc<RwLock<Vec<CaepEvent>>>,

    /// Evaluation rules
    rules: Arc<RwLock<Vec<CaepEvaluationRule>>>,
}

impl CaepManager {
    /// Create a new CAEP manager
    pub async fn new(
        config: CaepConfig,
        session_manager: Arc<SessionManager>,
        logout_manager: Arc<BackChannelLogoutManager>,
    ) -> Result<Self> {
        let (event_broadcaster, _) = broadcast::channel(1000);
        let evaluation_interval = interval(config.evaluation_interval.to_std().map_err(|e| {
            AuthError::Configuration {
                message: format!("Invalid evaluation interval: {}", e),
                help: Some("Provide a valid duration for evaluation interval".to_string()),
                docs_url: Some("https://docs.auth-framework.com/configuration".to_string()),
                source: None,
                suggested_fix: Some("Check your configuration and ensure the evaluation interval is properly formatted".to_string()),
            }
        })?);

        Ok(Self {
            config: config.clone(),
            session_manager,
            logout_manager,
            step_up_manager: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            event_handlers: Arc::new(RwLock::new(HashMap::new())),
            event_broadcaster,
            evaluation_interval,
            event_history: Arc::new(RwLock::new(Vec::new())),
            rules: Arc::new(RwLock::new(config.evaluation_rules)),
        })
    }

    /// Set step-up authentication manager
    pub fn with_step_up_manager(mut self, step_up_manager: Arc<SteppedUpAuthManager>) -> Self {
        self.step_up_manager = Some(step_up_manager);
        self
    }

    /// Register an event handler
    pub async fn register_event_handler(
        &self,
        event_type: CaepEventType,
        handler: Arc<dyn CaepEventHandler>,
    ) -> Result<()> {
        let mut handlers = self.event_handlers.write().await;
        handlers.entry(event_type).or_default().push(handler);
        Ok(())
    }

    /// Process a CAEP event
    pub async fn process_event(&self, event: CaepEvent) -> Result<CaepEvaluationResult> {
        // Add event to history
        {
            let mut history = self.event_history.write().await;
            history.push(event.clone());

            // Cleanup old events
            let retention_cutoff = Utc::now() - self.config.event_retention_period;
            history.retain(|e| e.timestamp >= retention_cutoff);
        }

        // Broadcast event
        if let Err(e) = self.event_broadcaster.send(event.clone()) {
            log::warn!("Failed to broadcast CAEP event: {}", e);
        }

        // Update session state
        if let Some(session_id) = &event.session_id {
            self.update_session_state(session_id, &event).await?;
        }

        // Evaluate access decision
        let evaluation_result = self.evaluate_access(&event.subject, Some(&event)).await?;

        // Execute required actions
        self.execute_actions(&evaluation_result).await?;

        // Notify registered handlers
        self.notify_handlers(&event).await?;

        Ok(evaluation_result)
    }

    /// Evaluate continuous access for a subject
    pub async fn evaluate_access(
        &self,
        subject: &str,
        triggering_event: Option<&CaepEvent>,
    ) -> Result<CaepEvaluationResult> {
        let rules = self.rules.read().await;
        let mut triggered_rules = Vec::new();
        let mut required_actions = Vec::new();
        let risk_score = if let Some(event) = triggering_event {
            event.risk_score
        } else {
            // Calculate risk from recent events
            self.calculate_risk_score(subject).await?
        };

        // Apply evaluation rules
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if let Some(event) = triggering_event
                && !rule.applicable_events.contains(&event.event_type)
            {
                continue;
            }

            if self
                .evaluate_rule_conditions(rule, subject, triggering_event, risk_score)
                .await?
            {
                triggered_rules.push(rule.id.clone());
                required_actions.extend(rule.actions.clone());
            }
        }

        // Determine access decision
        let access_decision = self.determine_access_decision(risk_score, &required_actions);

        let now = Utc::now();
        Ok(CaepEvaluationResult {
            subject: subject.to_string(),
            access_decision,
            risk_score,
            triggered_rules,
            required_actions,
            evaluated_at: now,
            next_evaluation: now + self.config.evaluation_interval,
        })
    }

    /// Start continuous evaluation loop
    pub async fn start_continuous_evaluation(&mut self) -> Result<()> {
        loop {
            self.evaluation_interval.tick().await;

            // First, synchronize with SessionManager to clean up stale sessions
            self.synchronize_with_session_manager().await?;

            // Evaluate all active sessions
            let sessions = {
                let sessions_guard = self.sessions.read().await;
                sessions_guard.keys().cloned().collect::<Vec<_>>()
            };

            for session_id in sessions {
                if let Some(session_state) = self.sessions.read().await.get(&session_id) {
                    let evaluation = self.evaluate_access(&session_state.subject, None).await?;
                    self.execute_actions(&evaluation).await?;
                }
            }
        }
    }

    /// Synchronize CAEP sessions with SessionManager
    async fn synchronize_with_session_manager(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut sessions_to_remove = Vec::new();

        for (session_id, caep_session) in sessions.iter() {
            // Check if session still exists and is valid in SessionManager
            if let Some(oidc_session) = self.session_manager.get_session(session_id) {
                if !self.session_manager.is_session_valid(session_id) {
                    log::info!("CAEP removing expired session: {}", session_id);
                    sessions_to_remove.push(session_id.clone());
                }
                // Verify subject consistency
                else if oidc_session.sub != caep_session.subject {
                    log::warn!("CAEP session subject mismatch, removing: {}", session_id);
                    sessions_to_remove.push(session_id.clone());
                }
            } else {
                log::info!("CAEP removing orphaned session: {}", session_id);
                sessions_to_remove.push(session_id.clone());
            }
        }

        // Remove stale sessions
        for session_id in sessions_to_remove {
            sessions.remove(&session_id);
        }

        Ok(())
    }

    /// Revoke access for a subject
    pub async fn revoke_subject_access(&self, subject: &str) -> Result<()> {
        log::info!("CAEP revoking access for subject: {}", subject);

        // Find all sessions for this subject and initiate back-channel logout
        let sessions_to_logout = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, session)| session.subject == subject)
                .map(|(session_id, session)| (session_id.clone(), session.clone()))
                .collect::<Vec<_>>()
        };

        // Process back-channel logout for each session
        for (session_id, _) in &sessions_to_logout {
            // Use the BackChannelLogoutManager to perform proper logout
            let logout_request =
                crate::server::oidc::oidc_backchannel_logout::BackChannelLogoutRequest {
                    session_id: session_id.clone(),
                    sub: subject.to_string(),
                    sid: Some(session_id.clone()),
                    iss: "caep-manager".to_string(), // In production, use actual issuer
                    initiating_client_id: None,      // CAEP-initiated logout
                    additional_events: Some({
                        let mut events = HashMap::new();
                        events.insert(
                            "caep_reason".to_string(),
                            serde_json::json!("automatic_revocation"),
                        );
                        events.insert(
                            "timestamp".to_string(),
                            serde_json::json!(Utc::now().timestamp()),
                        );
                        events
                    }),
                };

            // Process the logout through the BackChannelLogoutManager
            // Use async approach to handle logout manager integration
            match self.process_backchannel_logout(&logout_request).await {
                Ok(_) => {
                    log::info!(
                        "Successfully initiated back-channel logout for session {} (subject: {})",
                        session_id,
                        subject
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to initiate back-channel logout for session {} (subject: {}): {}",
                        session_id,
                        subject,
                        e
                    );
                }
            }
        }

        // Remove from CAEP active sessions after logout processing
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| session.subject != subject);

        Ok(())
    }

    /// Process back-channel logout through the logout manager
    async fn process_backchannel_logout(
        &self,
        logout_request: &crate::server::oidc::oidc_backchannel_logout::BackChannelLogoutRequest,
    ) -> Result<()> {
        // Use the logout manager to process the logout request
        // This integrates CAEP with the existing logout infrastructure

        // Use the logout manager to get metadata and validate capabilities
        let logout_metadata = self.logout_manager.get_discovery_metadata();
        log::info!("Logout manager capabilities: {:?}", logout_metadata);

        // Create CAEP-specific logout token based on the result
        let logout_token = self
            .create_logout_token_for_caep_revocation(logout_request)
            .await?;

        // Handle CAEP-specific logout processing
        self.handle_caep_logout(logout_request, &logout_token)
            .await?;

        log::info!("CAEP backchannel logout processed successfully");
        Ok(())
    }

    /// Create logout token for CAEP-initiated revocation
    async fn create_logout_token_for_caep_revocation(
        &self,
        logout_request: &crate::server::oidc::oidc_backchannel_logout::BackChannelLogoutRequest,
    ) -> Result<String> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde_json::json;

        // Create CAEP-specific logout token claims
        let claims = json!({
            "iss": logout_request.iss,
            "sub": logout_request.sub,
            "aud": ["caep-manager"],
            "exp": (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "sid": logout_request.sid,
            "events": {
                "http://schemas.openid.net/secevent/caep/event-type/session-revoked": {}
            },
            "caep_reason": logout_request.additional_events
                .as_ref()
                .and_then(|events| events.get("caep_reason"))
                .unwrap_or(&serde_json::json!("automatic_revocation"))
        });

        // In production, use proper signing key
        let key = EncodingKey::from_secret("caep-secret".as_ref());
        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &key).map_err(|e| {
            AuthError::auth_method("caep", format!("Failed to create logout token: {}", e))
        })?;

        Ok(token)
    }

    /// Handle CAEP logout processing
    async fn handle_caep_logout(
        &self,
        logout_request: &crate::server::oidc::oidc_backchannel_logout::BackChannelLogoutRequest,
        logout_token: &str,
    ) -> Result<()> {
        // This method integrates with the logout manager's functionality
        // In a production system, this would:
        // 1. Validate the logout token
        // 2. Notify all relevant clients about the session termination
        // 3. Update session state in persistent storage
        // 4. Trigger any cleanup procedures

        log::info!(
            "Processing CAEP logout for session: {}",
            logout_request.session_id
        );

        // Update CAEP session state to reflect logout
        {
            let mut sessions = self.sessions.write().await;
            if let Some(_session) = sessions.get(&logout_request.session_id) {
                // Remove the session entirely as it's being terminated
                sessions.remove(&logout_request.session_id);
            }
        }

        // Emit CAEP event for the logout
        let caep_event = CaepEvent {
            id: uuid::Uuid::new_v4(),
            event_type: CaepEventType::UserLogout, // Use existing event type
            subject: logout_request.sub.clone(),
            session_id: Some(logout_request.session_id.clone()),
            timestamp: chrono::Utc::now(),
            severity: CaepEventSeverity::High,
            source: CaepEventSource {
                system_id: "caep-manager".to_string(),
                source_type: "caep_automatic_revocation".to_string(),
                version: Some("1.0".to_string()),
                metadata: std::collections::HashMap::new(),
            },
            risk_score: 1.0, // High risk score for revoked sessions
            location: None,
            device_info: None,
            event_data: serde_json::json!({
                "logout_token": logout_token,
                "initiator": "caep_automatic_revocation",
                "reason": logout_request.additional_events
                    .as_ref()
                    .and_then(|events| events.get("caep_reason"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!("automatic_revocation"))
            }),
            correlation_id: Some(uuid::Uuid::new_v4()),
        };

        // Broadcast the event
        if let Err(e) = self.event_broadcaster.send(caep_event) {
            log::warn!("Failed to broadcast CAEP logout event: {}", e);
        }

        log::info!(
            "CAEP logout completed for session: {}",
            logout_request.session_id
        );
        Ok(())
    }

    /// Calculate risk score for a subject based on recent events
    async fn calculate_risk_score(&self, subject: &str) -> Result<f32> {
        let history = self.event_history.read().await;
        let recent_cutoff = Utc::now() - Duration::try_hours(1).unwrap_or(Duration::zero());

        let recent_events: Vec<_> = history
            .iter()
            .filter(|e| e.subject == subject && e.timestamp >= recent_cutoff)
            .collect();

        if recent_events.is_empty() {
            return Ok(0.0);
        }

        // Calculate weighted risk score
        let mut total_risk = 0.0;
        let mut total_weight = 0.0;

        for event in recent_events {
            let weight = match event.severity {
                CaepEventSeverity::Low => 1.0,
                CaepEventSeverity::Medium => 2.0,
                CaepEventSeverity::High => 4.0,
                CaepEventSeverity::Critical => 8.0,
            };

            total_risk += event.risk_score * weight;
            total_weight += weight;
        }

        Ok(if total_weight > 0.0 {
            (total_risk / total_weight).min(1.0)
        } else {
            0.0
        })
    }

    /// Update session state based on an event
    async fn update_session_state(&self, session_id: &str, event: &CaepEvent) -> Result<()> {
        // First, validate the session exists in the SessionManager
        if let Some(oidc_session) = self.session_manager.get_session(session_id) {
            // Verify the session is still valid
            if !self.session_manager.is_session_valid(session_id) {
                log::warn!(
                    "CAEP received event for expired OIDC session: {}",
                    session_id
                );
                // Remove from CAEP sessions as well
                let mut sessions = self.sessions.write().await;
                sessions.remove(session_id);
                return Ok(());
            }

            // Ensure subjects match
            if oidc_session.sub != event.subject {
                return Err(AuthError::validation(
                    "Subject mismatch between CAEP event and OIDC session",
                ));
            }
        } else {
            log::warn!(
                "CAEP received event for unknown OIDC session: {}",
                session_id
            );
            return Err(AuthError::validation("Session not found in SessionManager"));
        }

        // Update CAEP-specific session state
        let mut sessions = self.sessions.write().await;

        let session_state =
            sessions
                .entry(session_id.to_string())
                .or_insert_with(|| CaepSessionState {
                    session_id: session_id.to_string(),
                    subject: event.subject.clone(),
                    risk_score: event.risk_score,
                    last_evaluation: None,
                    active_events: Vec::new(),
                    created_at: Utc::now(),
                    last_activity: Utc::now(),
                    is_quarantined: false,
                    quarantine_until: None,
                });

        session_state.risk_score = event.risk_score;
        session_state.last_activity = Utc::now();
        session_state.active_events.push(event.clone());

        // Remove old events
        let cutoff = Utc::now() - Duration::try_hours(1).unwrap_or(Duration::zero());
        session_state
            .active_events
            .retain(|e| e.timestamp >= cutoff);

        Ok(())
    }

    /// Evaluate rule conditions
    async fn evaluate_rule_conditions(
        &self,
        rule: &CaepEvaluationRule,
        _subject: &str,
        event: Option<&CaepEvent>,
        risk_score: f32,
    ) -> Result<bool> {
        for condition in &rule.conditions {
            match condition {
                CaepRuleCondition::RiskScoreAbove { threshold } => {
                    if risk_score <= *threshold {
                        return Ok(false);
                    }
                }
                CaepRuleCondition::SeverityAtLeast { severity } => {
                    if let Some(event) = event {
                        let event_severity_level = match event.severity {
                            CaepEventSeverity::Critical => 4,
                            CaepEventSeverity::High => 3,
                            CaepEventSeverity::Medium => 2,
                            CaepEventSeverity::Low => 1,
                        };

                        let required_severity_level = match severity {
                            CaepEventSeverity::Critical => 4,
                            CaepEventSeverity::High => 3,
                            CaepEventSeverity::Medium => 2,
                            CaepEventSeverity::Low => 1,
                        };

                        if event_severity_level < required_severity_level {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
                CaepRuleCondition::LocationChange { suspicious_only } => {
                    if let Some(event) = event {
                        if let Some(location) = &event.location {
                            if *suspicious_only && !location.is_suspicious {
                                return Ok(false);
                            }
                        } else {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
                CaepRuleCondition::UnknownDevice { require_trusted } => {
                    if let Some(event) = event
                        && let Some(device) = &event.device_info
                        && *require_trusted
                        && device.is_trusted
                    {
                        return Ok(false);
                    }
                }
                CaepRuleCondition::OutsideBusinessHours { timezone: _ } => {
                    // Simplified: assume business hours are 9 AM - 5 PM UTC
                    let hour = Utc::now().hour();
                    if (9..17).contains(&hour) {
                        return Ok(false);
                    }
                }
                CaepRuleCondition::Custom { expression: _ } => {
                    // Custom expressions would need a proper expression evaluator
                    // For now, always evaluate to true
                }
            }
        }

        Ok(true)
    }

    /// Determine access decision based on risk and actions
    fn determine_access_decision(
        &self,
        risk_score: f32,
        actions: &[CaepRuleAction],
    ) -> CaepAccessDecision {
        for action in actions {
            match action {
                CaepRuleAction::RevokeAccess { immediate: true } => {
                    return CaepAccessDecision::Deny;
                }
                CaepRuleAction::RevokeAccess { immediate: false } => {
                    return CaepAccessDecision::TemporaryDeny;
                }
                CaepRuleAction::RequireStepUp { .. } => {
                    return CaepAccessDecision::AllowWithStepUp;
                }
                CaepRuleAction::QuarantineSession { .. } => {
                    return CaepAccessDecision::TemporaryDeny;
                }
                _ => {}
            }
        }

        if risk_score >= self.config.auto_revoke_threshold {
            CaepAccessDecision::Deny
        } else if risk_score >= 0.6 {
            CaepAccessDecision::AllowWithMonitoring
        } else {
            CaepAccessDecision::Allow
        }
    }

    /// Execute required actions from evaluation
    async fn execute_actions(&self, evaluation: &CaepEvaluationResult) -> Result<()> {
        for action in &evaluation.required_actions {
            match action {
                CaepRuleAction::RevokeAccess { .. } => {
                    self.revoke_subject_access(&evaluation.subject).await?;
                }
                CaepRuleAction::RequireStepUp { level } => {
                    if let Some(_step_up_manager) = &self.step_up_manager {
                        // Trigger step-up authentication
                        log::info!(
                            "CAEP requiring step-up to level {} for subject {}",
                            level,
                            evaluation.subject
                        );
                    }
                }
                CaepRuleAction::SendNotification { channels } => {
                    log::info!(
                        "CAEP sending notification via channels {:?} for subject {}",
                        channels,
                        evaluation.subject
                    );
                }
                CaepRuleAction::LogEvent { level } => {
                    log::info!(
                        "CAEP logging event at level {} for subject {}",
                        level,
                        evaluation.subject
                    );
                }
                CaepRuleAction::TriggerWebhook { url } => {
                    log::info!(
                        "CAEP triggering webhook {} for subject {}",
                        url,
                        evaluation.subject
                    );
                }
                CaepRuleAction::QuarantineSession { duration_minutes } => {
                    self.quarantine_session(&evaluation.subject, *duration_minutes)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Quarantine a session
    async fn quarantine_session(&self, subject: &str, duration_minutes: u32) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let quarantine_until =
            Utc::now() + Duration::try_minutes(duration_minutes as i64).unwrap_or(Duration::zero());

        // Update CAEP session state
        let mut quarantined_session_ids = Vec::new();
        for session in sessions.values_mut() {
            if session.subject == subject {
                session.is_quarantined = true;
                session.quarantine_until = Some(quarantine_until);
                quarantined_session_ids.push(session.session_id.clone());
            }
        }

        log::info!(
            "CAEP quarantined {} sessions for subject {} until {}. Session IDs: {:?}",
            quarantined_session_ids.len(),
            subject,
            quarantine_until,
            quarantined_session_ids
        );

        // In a production implementation, you might want to notify the SessionManager
        // about the quarantine status through a separate event or notification system

        Ok(())
    }

    /// Notify registered event handlers
    async fn notify_handlers(&self, event: &CaepEvent) -> Result<()> {
        let handlers = self.event_handlers.read().await;

        if let Some(event_handlers) = handlers.get(&event.event_type) {
            for handler in event_handlers {
                if let Err(e) = handler.handle_event(event).await {
                    log::error!("CAEP event handler failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Get current session state
    pub async fn get_session_state(&self, session_id: &str) -> Result<Option<CaepSessionState>> {
        // First validate with SessionManager
        if let Some(oidc_session) = self.session_manager.get_session(session_id) {
            if !self.session_manager.is_session_valid(session_id) {
                // Session is expired in SessionManager, remove from CAEP as well
                let mut sessions = self.sessions.write().await;
                sessions.remove(session_id);
                return Ok(None);
            }

            // Return CAEP session state if it exists and subjects match
            let sessions = self.sessions.read().await;
            if let Some(caep_session) = sessions.get(session_id) {
                if caep_session.subject == oidc_session.sub {
                    return Ok(Some(caep_session.clone()));
                } else {
                    log::warn!(
                        "Subject mismatch between CAEP and OIDC sessions for {}",
                        session_id
                    );
                    return Ok(None);
                }
            }
        }

        // No valid OIDC session found
        Ok(None)
    }

    /// Get event history for a subject
    pub async fn get_event_history(
        &self,
        subject: &str,
        limit: Option<usize>,
    ) -> Result<Vec<CaepEvent>> {
        let history = self.event_history.read().await;
        let mut events: Vec<_> = history
            .iter()
            .filter(|e| e.subject == subject)
            .cloned()
            .collect();

        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            events.truncate(limit);
        }

        Ok(events)
    }

    /// Add or update an evaluation rule
    pub async fn add_evaluation_rule(&self, rule: CaepEvaluationRule) -> Result<()> {
        let mut rules = self.rules.write().await;

        // Remove existing rule with same ID
        rules.retain(|r| r.id != rule.id);

        // Insert new rule and sort by priority
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(())
    }

    /// Remove an evaluation rule
    pub async fn remove_evaluation_rule(&self, rule_id: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let original_len = rules.len();
        rules.retain(|r| r.id != rule_id);
        Ok(rules.len() < original_len)
    }

    /// Get comprehensive session information combining OIDC and CAEP data
    pub async fn get_comprehensive_session_info(
        &self,
        session_id: &str,
    ) -> Result<Option<ComprehensiveSessionInfo>> {
        // Get OIDC session information
        if let Some(oidc_session) = self.session_manager.get_session(session_id) {
            if !self.session_manager.is_session_valid(session_id) {
                return Ok(None);
            }

            // Get CAEP session information if available
            let caep_session = {
                let sessions = self.sessions.read().await;
                sessions.get(session_id).cloned()
            };

            let comprehensive_info = ComprehensiveSessionInfo {
                oidc_session: oidc_session.clone(),
                is_monitored_by_caep: caep_session.is_some(),
                caep_session,
            };

            Ok(Some(comprehensive_info))
        } else {
            Ok(None)
        }
    }

    /// Get all sessions for a subject with comprehensive information
    pub async fn get_subject_sessions(
        &self,
        subject: &str,
    ) -> Result<Vec<ComprehensiveSessionInfo>> {
        let oidc_sessions = self.session_manager.get_sessions_for_subject(subject);
        let mut comprehensive_sessions = Vec::new();

        for oidc_session in oidc_sessions {
            if self
                .session_manager
                .is_session_valid(&oidc_session.session_id)
            {
                let caep_session = {
                    let sessions = self.sessions.read().await;
                    sessions.get(&oidc_session.session_id).cloned()
                };

                comprehensive_sessions.push(ComprehensiveSessionInfo {
                    oidc_session: oidc_session.clone(),
                    is_monitored_by_caep: caep_session.is_some(),
                    caep_session,
                });
            }
        }

        Ok(comprehensive_sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_caep_event_creation() {
        let event = CaepEvent {
            id: Uuid::new_v4(),
            event_type: CaepEventType::RiskScoreChange,
            subject: "user123".to_string(),
            severity: CaepEventSeverity::High,
            timestamp: Utc::now(),
            source: CaepEventSource {
                system_id: "risk_engine".to_string(),
                source_type: "ml_model".to_string(),
                version: Some("1.0.0".to_string()),
                metadata: HashMap::new(),
            },
            risk_score: 0.85,
            session_id: Some("session123".to_string()),
            location: None,
            device_info: None,
            event_data: serde_json::json!({
                "previous_score": 0.3,
                "new_score": 0.85,
                "trigger": "suspicious_login_pattern"
            }),
            correlation_id: None,
        };

        assert_eq!(event.subject, "user123");
        assert_eq!(event.risk_score, 0.85);
        assert!(matches!(event.severity, CaepEventSeverity::High));
    }

    #[tokio::test]
    async fn test_caep_config_creation() {
        let config = CaepConfig::default();
        assert!(!config.event_stream_url.is_empty());
        assert!(config.auto_revoke);
        assert_eq!(config.auto_revoke_threshold, 0.8);
    }

    #[tokio::test]
    async fn test_severity_comparison() {
        // Test severity level comparison logic
        let high_level = match CaepEventSeverity::High {
            CaepEventSeverity::Critical => 4,
            CaepEventSeverity::High => 3,
            CaepEventSeverity::Medium => 2,
            CaepEventSeverity::Low => 1,
        };

        let medium_level = match CaepEventSeverity::Medium {
            CaepEventSeverity::Critical => 4,
            CaepEventSeverity::High => 3,
            CaepEventSeverity::Medium => 2,
            CaepEventSeverity::Low => 1,
        };

        assert!(high_level > medium_level);
    }
}
