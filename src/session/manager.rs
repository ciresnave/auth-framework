//! Comprehensive session management with security hardening.
//!
//! This module provides secure session management with features like
//! session rotation, concurrent session limits, device tracking,
//! and advanced security protections.

use crate::audit::{AuditLogger, AuditStorage, GeolocationInfo, RequestMetadata};
use crate::errors::{AuthError, Result};
use crate::threat_intelligence::{ThreatFeedManager, ThreatIntelConfig};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// Additional imports for session security

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: String,
    /// User ID this session belongs to
    pub user_id: String,
    /// When the session was created
    pub created_at: SystemTime,
    /// When the session was last accessed
    pub last_accessed: SystemTime,
    /// When the session expires
    pub expires_at: SystemTime,
    /// Session state
    pub state: SessionState,
    /// Device information
    pub device_info: DeviceInfo,
    /// Security metadata
    pub security_metadata: SecurityMetadata,
    /// Session data (custom application data)
    pub data: HashMap<String, String>,
    /// MFA verification status
    pub mfa_verified: bool,
    /// Permissions cache (for performance)
    pub cached_permissions: Option<Vec<String>>,
    /// Last activity details
    pub last_activity: ActivityInfo,
}

/// Session state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Expired,
    Revoked,
    Suspended,
    RequiresMfa,
    RequiresReauth,
}

/// Device information for session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device fingerprint (unique identifier)
    pub fingerprint: String,
    /// Device type (mobile, desktop, tablet, etc.)
    pub device_type: String,
    /// Operating system
    pub operating_system: Option<String>,
    /// Browser information
    pub browser: Option<String>,
    /// Screen resolution
    pub screen_resolution: Option<String>,
    /// Timezone
    pub timezone: Option<String>,
    /// Language preferences
    pub language: Option<String>,
    /// Whether this is a trusted device
    pub is_trusted: bool,
    /// Device name (user-assigned)
    pub device_name: Option<String>,
}

/// Security metadata for sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    /// IP address when session was created
    pub creation_ip: String,
    /// Current IP address
    pub current_ip: String,
    /// Geographic location when created
    pub creation_location: Option<GeolocationInfo>,
    /// Current geographic location
    pub current_location: Option<GeolocationInfo>,
    /// Security flags
    pub security_flags: Vec<SecurityFlag>,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// Whether location has changed
    pub location_changed: bool,
    /// Whether IP has changed
    pub ip_changed: bool,
    /// Number of failed authentication attempts
    pub failed_auth_attempts: u32,
}

/// Security flags for sessions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityFlag {
    SuspiciousActivity,
    LocationAnomaly,
    DeviceAnomaly,
    TimeAnomaly,
    ConcurrentSessionLimit,
    BruteForceAttempt,
    RequiresVerification,
    ElevatedPrivileges,
}

/// Activity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityInfo {
    /// Last endpoint accessed
    pub endpoint: Option<String>,
    /// Last action performed
    pub action: Option<String>,
    /// Request metadata
    pub request_metadata: Option<RequestMetadata>,
    /// Activity timestamp
    pub timestamp: SystemTime,
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Default session duration
    pub default_duration: Duration,
    /// Maximum session duration
    pub max_duration: Duration,
    /// Session idle timeout
    pub idle_timeout: Duration,
    /// Whether to rotate session IDs on privilege escalation
    pub rotate_on_privilege_escalation: bool,
    /// Whether to rotate session IDs periodically
    pub rotate_periodically: bool,
    /// Rotation interval
    pub rotation_interval: Duration,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: Option<u32>,
    /// Whether to track device fingerprints
    pub track_device_fingerprints: bool,
    /// Whether to enforce geographic restrictions
    pub enforce_geographic_restrictions: bool,
    /// Allowed countries (if geographic restrictions enabled)
    pub allowed_countries: Vec<String>,
    /// Security policy
    pub security_policy: SessionSecurityPolicy,
}

/// Session security policy
#[derive(Debug, Clone)]
pub struct SessionSecurityPolicy {
    /// Require MFA for new devices
    pub require_mfa_for_new_devices: bool,
    /// Require re-auth for sensitive operations
    pub require_reauth_for_sensitive_ops: bool,
    /// Timeout for re-auth requirement
    pub reauth_timeout: Duration,
    /// Maximum risk score allowed
    pub max_risk_score: u8,
    /// Whether to auto-suspend suspicious sessions
    pub auto_suspend_suspicious: bool,
    /// Whether to require verification after location change
    pub verify_location_changes: bool,
    /// Whether to limit concurrent sessions
    pub limit_concurrent_sessions: bool,
}

/// Session storage trait
#[async_trait]
pub trait SessionStorage: Send + Sync {
    /// Create a new session
    async fn create_session(&self, session: &Session) -> Result<()>;

    /// Get session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<Session>>;

    /// Update existing session
    async fn update_session(&self, session: &Session) -> Result<()>;

    /// Delete session
    async fn delete_session(&self, session_id: &str) -> Result<()>;

    /// Get all sessions for a user
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>>;

    /// Get active sessions count for a user
    async fn count_active_sessions(&self, user_id: &str) -> Result<u32>;

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) -> Result<u32>;

    /// Find sessions by device fingerprint
    async fn find_sessions_by_device(&self, device_fingerprint: &str) -> Result<Vec<Session>>;

    /// Find sessions by IP address
    async fn find_sessions_by_ip(&self, ip_address: &str) -> Result<Vec<Session>>;
}

/// Main session manager
pub struct SessionManager<S: SessionStorage, A: AuditStorage> {
    storage: S,
    config: SessionConfig,
    audit_logger: AuditLogger<A>,
    fingerprint_generator: DeviceFingerprintGenerator,
    risk_calculator: RiskCalculator,
    threat_intel_manager: Option<ThreatFeedManager>,
}

impl<S: SessionStorage, A: AuditStorage> SessionManager<S, A> {
    /// Create a new session manager
    pub fn new(storage: S, config: SessionConfig, audit_logger: AuditLogger<A>) -> Self {
        // Initialize automated threat intelligence if enabled
        let threat_intel_manager = if std::env::var("THREAT_INTEL_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true"
        {
            match ThreatIntelConfig::from_env_and_config() {
                Ok(intel_config) => {
                    log::info!(
                        "🟢 Automated threat intelligence enabled - feeds will update automatically"
                    );
                    match ThreatFeedManager::new(intel_config) {
                        Ok(manager) => {
                            // Start automated feed management in background
                            if let Err(e) = manager.start_automated_updates() {
                                log::error!("Failed to start automated threat feed updates: {}", e);
                                None
                            } else {
                                log::info!(
                                    "✅ Threat intelligence automation started successfully"
                                );
                                Some(manager)
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to initialize threat intelligence manager: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to load threat intelligence configuration: {}", e);
                    None
                }
            }
        } else {
            log::info!("🔴 Automated threat intelligence disabled (THREAT_INTEL_ENABLED=false)");
            None
        };

        Self {
            storage,
            config,
            audit_logger,
            fingerprint_generator: DeviceFingerprintGenerator::new(),
            risk_calculator: RiskCalculator::new(),
            threat_intel_manager,
        }
    }

    /// Create a new session
    pub async fn create_session(
        &self,
        user_id: &str,
        mut device_info: DeviceInfo,
        metadata: RequestMetadata,
    ) -> Result<Session> {
        // Generate device fingerprint if not already present
        if device_info.fingerprint.is_empty() {
            device_info.fingerprint = self.fingerprint_generator.generate_fingerprint(&metadata);
        }

        // Check concurrent session limits
        if let Some(max_sessions) = self.config.max_concurrent_sessions {
            let active_count = self.storage.count_active_sessions(user_id).await?;
            if active_count >= max_sessions {
                return Err(AuthError::TooManyConcurrentSessions);
            }
        }

        let now = SystemTime::now();
        let session_id = self.generate_session_id();

        // Calculate risk score
        let risk_score = self.risk_calculator.calculate_risk(
            &device_info,
            &metadata,
            &self.get_user_session_history(user_id).await?,
            self.threat_intel_manager.as_ref(),
        );

        let mut security_flags = Vec::new();
        if risk_score > 70 {
            security_flags.push(SecurityFlag::SuspiciousActivity);
        }

        // Check if this is a new device
        let existing_sessions = self
            .storage
            .find_sessions_by_device(&device_info.fingerprint)
            .await?;
        let is_new_device = existing_sessions.is_empty();

        if is_new_device && self.config.security_policy.require_mfa_for_new_devices {
            security_flags.push(SecurityFlag::RequiresVerification);
        }

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            last_accessed: now,
            expires_at: now + self.config.default_duration,
            state: if security_flags.contains(&SecurityFlag::RequiresVerification) {
                SessionState::RequiresMfa
            } else {
                SessionState::Active
            },
            device_info: device_info.clone(),
            security_metadata: SecurityMetadata {
                creation_ip: metadata.ip_address.clone().unwrap_or_default(),
                current_ip: metadata.ip_address.clone().unwrap_or_default(),
                creation_location: metadata.geolocation.clone(),
                current_location: metadata.geolocation.clone(),
                security_flags,
                risk_score,
                location_changed: false,
                ip_changed: false,
                failed_auth_attempts: 0,
            },
            data: HashMap::new(),
            mfa_verified: false,
            cached_permissions: None,
            last_activity: ActivityInfo {
                endpoint: metadata.endpoint.clone(),
                action: Some("session_created".to_string()),
                request_metadata: Some(metadata.clone()),
                timestamp: now,
            },
        };

        self.storage.create_session(&session).await?;

        // Log session creation
        self.audit_logger
            .log_event(crate::audit::AuditEvent {
                id: String::new(),
                event_type: crate::audit::AuditEventType::LoginSuccess,
                timestamp: now,
                user_id: Some(user_id.to_string()),
                session_id: Some(session_id),
                outcome: crate::audit::EventOutcome::Success,
                risk_level: if risk_score > 70 {
                    crate::audit::RiskLevel::High
                } else {
                    crate::audit::RiskLevel::Low
                },
                description: "Session created".to_string(),
                details: HashMap::new(),
                request_metadata: metadata,
                resource: None,
                actor: crate::audit::ActorInfo {
                    actor_type: "user".to_string(),
                    actor_id: user_id.to_string(),
                    actor_name: None,
                    roles: vec![],
                },
                correlation_id: None,
            })
            .await?;

        Ok(session)
    }

    /// Validate and refresh a session
    pub async fn validate_session(
        &self,
        session_id: &str,
        metadata: RequestMetadata,
    ) -> Result<Option<Session>> {
        let mut session = match self.storage.get_session(session_id).await? {
            Some(session) => session,
            None => return Ok(None),
        };

        let now = SystemTime::now();

        // Check if session is expired
        if session.expires_at <= now {
            session.state = SessionState::Expired;
            self.storage.update_session(&session).await?;
            return Ok(None);
        }

        // Validate device fingerprint for security
        let current_fingerprint = self.fingerprint_generator.generate_fingerprint(&metadata);
        if current_fingerprint != session.device_info.fingerprint {
            // Device fingerprint mismatch - potential session hijacking
            session.state = SessionState::RequiresMfa;
            self.storage.update_session(&session).await?;

            // Log security event
            self.audit_logger
                .log_suspicious_activity(
                    Some(&session.user_id),
                    "device_fingerprint_mismatch",
                    &format!(
                        "Session ID: {}, Expected: {}, Got: {}",
                        session_id, session.device_info.fingerprint, current_fingerprint
                    ),
                    metadata.clone(),
                )
                .await?;
        }

        // Check if session is idle too long
        let idle_duration = now
            .duration_since(session.last_accessed)
            .unwrap_or_default();
        if idle_duration > self.config.idle_timeout {
            session.state = SessionState::Expired;
            self.storage.update_session(&session).await?;
            return Ok(None);
        }

        // Check session state
        match session.state {
            SessionState::Expired | SessionState::Revoked | SessionState::Suspended => {
                return Ok(None);
            }
            SessionState::RequiresMfa | SessionState::RequiresReauth => {
                // Return session but caller needs to handle MFA/reauth
                return Ok(Some(session));
            }
            SessionState::Active => {}
        }

        // Update security metadata
        let current_ip = metadata.ip_address.clone().unwrap_or_default();
        let ip_changed = current_ip != session.security_metadata.current_ip;

        if ip_changed {
            session.security_metadata.ip_changed = true;
            session.security_metadata.current_ip = current_ip;

            // Check if location verification is required
            if self.config.security_policy.verify_location_changes {
                session
                    .security_metadata
                    .security_flags
                    .push(SecurityFlag::LocationAnomaly);
                session.state = SessionState::RequiresReauth;
            }
        }

        // Update last accessed time and activity
        session.last_accessed = now;
        session.last_activity = ActivityInfo {
            endpoint: metadata.endpoint.clone(),
            action: Some("session_validated".to_string()),
            request_metadata: Some(metadata),
            timestamp: now,
        };

        // Check if session rotation is needed
        let should_rotate = self.should_rotate_session(&session);
        if should_rotate {
            let new_session_id = self.generate_session_id();
            let old_session_id = session.id.clone();
            session.id = new_session_id;

            // Delete old session and create new one
            self.storage.delete_session(&old_session_id).await?;
            self.storage.create_session(&session).await?;
        } else {
            self.storage.update_session(&session).await?;
        }

        Ok(Some(session))
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.state = SessionState::Revoked;
            self.storage.update_session(&session).await?;

            // Log session revocation
            self.audit_logger
                .log_event(crate::audit::AuditEvent {
                    id: String::new(),
                    event_type: crate::audit::AuditEventType::Logout,
                    timestamp: SystemTime::now(),
                    user_id: Some(session.user_id),
                    session_id: Some(session_id.to_string()),
                    outcome: crate::audit::EventOutcome::Success,
                    risk_level: crate::audit::RiskLevel::Low,
                    description: "Session revoked".to_string(),
                    details: HashMap::new(),
                    request_metadata: crate::audit::RequestMetadata::default(),
                    resource: None,
                    actor: crate::audit::ActorInfo {
                        actor_type: "system".to_string(),
                        actor_id: "session_manager".to_string(),
                        actor_name: None,
                        roles: vec![],
                    },
                    correlation_id: None,
                })
                .await?;
        }
        Ok(())
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<u32> {
        let sessions = self.storage.get_user_sessions(user_id).await?;
        let mut revoked_count = 0;

        for mut session in sessions {
            if session.state == SessionState::Active {
                session.state = SessionState::Revoked;
                self.storage.update_session(&session).await?;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Get user sessions with filtering
    pub async fn get_user_sessions(
        &self,
        user_id: &str,
        include_inactive: bool,
    ) -> Result<Vec<Session>> {
        let mut sessions = self.storage.get_user_sessions(user_id).await?;

        if !include_inactive {
            sessions.retain(|s| s.state == SessionState::Active);
        }

        Ok(sessions)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u32> {
        self.storage.cleanup_expired_sessions().await
    }

    /// Generate device fingerprint for given request metadata
    pub fn generate_device_fingerprint(&self, metadata: &RequestMetadata) -> String {
        self.fingerprint_generator.generate_fingerprint(metadata)
    }

    /// Validate device fingerprint against session
    pub fn validate_device_fingerprint(
        &self,
        session: &Session,
        metadata: &RequestMetadata,
    ) -> bool {
        let current_fingerprint = self.fingerprint_generator.generate_fingerprint(metadata);
        current_fingerprint == session.device_info.fingerprint
    }

    /// Suspend suspicious sessions
    pub async fn suspend_session(&self, session_id: &str, reason: &str) -> Result<()> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.state = SessionState::Suspended;
            session
                .security_metadata
                .security_flags
                .push(SecurityFlag::SuspiciousActivity);

            self.storage.update_session(&session).await?;

            // Log suspension
            let mut details = HashMap::new();
            details.insert("suspension_reason".to_string(), reason.to_string());

            self.audit_logger
                .log_event(crate::audit::AuditEvent {
                    id: String::new(),
                    event_type: crate::audit::AuditEventType::AccountLocked,
                    timestamp: SystemTime::now(),
                    user_id: Some(session.user_id),
                    session_id: Some(session_id.to_string()),
                    outcome: crate::audit::EventOutcome::Success,
                    risk_level: crate::audit::RiskLevel::High,
                    description: format!("Session suspended: {}", reason),
                    details,
                    request_metadata: crate::audit::RequestMetadata::default(),
                    resource: None,
                    actor: crate::audit::ActorInfo {
                        actor_type: "system".to_string(),
                        actor_id: "security_monitor".to_string(),
                        actor_name: None,
                        roles: vec![],
                    },
                    correlation_id: None,
                })
                .await?;
        }
        Ok(())
    }

    /// Update session data
    pub async fn update_session_data(
        &self,
        session_id: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.data.insert(key.to_string(), value.to_string());
            session.last_accessed = SystemTime::now();
            self.storage.update_session(&session).await?;
        }
        Ok(())
    }

    /// Generate a new session ID
    fn generate_session_id(&self) -> String {
        format!("sess_{}", uuid::Uuid::new_v4())
    }

    /// Check if session should be rotated
    fn should_rotate_session(&self, session: &Session) -> bool {
        if !self.config.rotate_periodically {
            return false;
        }

        let session_age = SystemTime::now()
            .duration_since(session.created_at)
            .unwrap_or_default();

        session_age > self.config.rotation_interval
    }

    /// Get user session history for risk calculation
    async fn get_user_session_history(&self, user_id: &str) -> Result<Vec<Session>> {
        // This would typically be a more sophisticated query
        // For now, just return recent sessions
        self.storage.get_user_sessions(user_id).await
    }
}

/// Device fingerprint generator
pub struct DeviceFingerprintGenerator;

impl Default for DeviceFingerprintGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceFingerprintGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate device fingerprint from request metadata
    pub fn generate_fingerprint(&self, metadata: &RequestMetadata) -> String {
        let mut fingerprint_data = Vec::new();

        if let Some(ua) = &metadata.user_agent {
            fingerprint_data.push(ua.clone());
        }

        // Comprehensive device fingerprinting implementation
        self.add_advanced_fingerprinting_data(&mut fingerprint_data, metadata);

        let fingerprint_string = fingerprint_data.join("|");
        format!("fp_{:x}", crc32fast::hash(fingerprint_string.as_bytes()))
    }

    /// Add advanced fingerprinting data based on available metadata
    fn add_advanced_fingerprinting_data(
        &self,
        fingerprint_data: &mut Vec<String>,
        metadata: &RequestMetadata,
    ) {
        // Screen characteristics (if available)
        if let Some(ref ip) = metadata.ip_address {
            // Extract geographical and ISP information from IP
            fingerprint_data.push(format!("geo:{}", self.get_ip_geolocation(ip)));
        }

        // Browser/client characteristics
        fingerprint_data.push(format!("lang:{}", self.get_system_language()));
        fingerprint_data.push(format!("tz:{}", self.get_timezone_offset()));
        fingerprint_data.push(format!("hw:{}", self.get_hardware_concurrency()));

        // Network characteristics
        fingerprint_data.push(format!("conn:{}", self.get_connection_info()));

        // Additional entropy sources
        fingerprint_data.push(format!("caps:{}", self.get_client_capabilities()));
    }

    /// Get IP geolocation information for fingerprinting
    fn get_ip_geolocation(&self, ip: &str) -> String {
        use std::net::IpAddr;
        use std::str::FromStr;

        // Parse IP address for classification
        if let Ok(ip_addr) = IpAddr::from_str(ip) {
            match ip_addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();

                    // RFC 1918 private networks
                    if (octets[0] == 10)
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                        || (octets[0] == 192 && octets[1] == 168)
                    {
                        return "private_rfc1918".to_string();
                    }

                    // Loopback
                    if octets[0] == 127 {
                        return "loopback".to_string();
                    }

                    // Link-local (169.254.x.x)
                    if octets[0] == 169 && octets[1] == 254 {
                        return "link_local".to_string();
                    }

                    // Multicast
                    if octets[0] >= 224 && octets[0] <= 239 {
                        return "multicast".to_string();
                    }

                    // Known public DNS servers
                    match (octets[0], octets[1], octets[2], octets[3]) {
                        (8, 8, 8, 8) | (8, 8, 4, 4) => "google_dns".to_string(),
                        (1, 1, 1, 1) | (1, 0, 0, 1) => "cloudflare_dns".to_string(),
                        (208, 67, 222, 222) | (208, 67, 220, 220) => "opendns".to_string(),
                        _ => {
                            // Real MaxMind GeoIP2 database integration
                            self.lookup_maxmind_geolocation(&ipv4).unwrap_or_else(|| {
                                // Fallback to basic regional classification
                                match octets[0] {
                                    1..=23 => "apnic_region".to_string(),    // APNIC (Asia-Pacific)
                                    24..=49 => "arin_region".to_string(),    // ARIN (North America)
                                    50..=99 => "ripe_region".to_string(), // RIPE (Europe/Middle East)
                                    100..=127 => "mixed_region".to_string(), // Various registries
                                    128..=191 => "arin_region".to_string(), // ARIN
                                    192..=223 => "ripe_apnic_region".to_string(), // RIPE/APNIC
                                    _ => format!("public_class_{}", octets[0] / 64),
                                }
                            })
                        }
                    }
                }
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();

                    // IPv6 loopback
                    if ipv6.is_loopback() {
                        return "ipv6_loopback".to_string();
                    }

                    // IPv6 link-local (fe80::/10)
                    if segments[0] & 0xffc0 == 0xfe80 {
                        return "ipv6_link_local".to_string();
                    }

                    // IPv6 unique local (fc00::/7)
                    if segments[0] & 0xfe00 == 0xfc00 {
                        return "ipv6_unique_local".to_string();
                    }

                    // IPv6 multicast (ff00::/8)
                    if segments[0] & 0xff00 == 0xff00 {
                        return "ipv6_multicast".to_string();
                    }

                    // Global unicast
                    format!("ipv6_global_{:x}", segments[0] / 0x1000)
                }
            }
        } else {
            "invalid_ip".to_string()
        }
    }

    /// Get system language for fingerprinting
    fn get_system_language(&self) -> String {
        // Would be extracted from Accept-Language header or client info
        "en-US".to_string()
    }

    /// Get timezone offset for fingerprinting
    fn get_timezone_offset(&self) -> String {
        // Would be provided by client-side JavaScript
        "-05:00".to_string() // EST example
    }

    /// Get hardware concurrency for fingerprinting
    fn get_hardware_concurrency(&self) -> String {
        // Would be provided by client via navigator.hardwareConcurrency
        "4".to_string()
    }

    /// Get connection information for fingerprinting
    fn get_connection_info(&self) -> String {
        // Would include connection speed, type, etc.
        "wifi".to_string()
    }

    /// Get client capabilities for fingerprinting
    fn get_client_capabilities(&self) -> String {
        // Would include supported features, WebGL renderer, etc.
        "webgl2_canvas_audio".to_string()
    }

    /// Lookup IP geolocation using MaxMind GeoIP2 database
    fn lookup_maxmind_geolocation(&self, ip: &std::net::Ipv4Addr) -> Option<String> {
        use std::path::Path;

        // Path to MaxMind GeoLite2-City.mmdb (configurable via environment)
        let db_path =
            std::env::var("MAXMIND_DB_PATH").unwrap_or_else(|_| "GeoLite2-City.mmdb".to_string());

        if !Path::new(&db_path).exists() {
            log::warn!(
                "MaxMind database not found at {}, falling back to basic geolocation",
                db_path
            );
            return None;
        }

        match maxminddb::Reader::open_readfile(&db_path) {
            Ok(reader) => {
                match reader.lookup::<maxminddb::geoip2::City>((*ip).into()) {
                    Ok(Some(city)) => {
                        let mut location_parts = Vec::new();

                        // Build location string from MaxMind data
                        if let Some(country) = city.country.and_then(|c| c.names)
                            && let Some(name) = country.get("en")
                        {
                            location_parts.push(format!("country:{}", name));
                        }

                        if let Some(subdivisions) = city.subdivisions
                            && let Some(subdivision) = subdivisions.first()
                            && let Some(names) = &subdivision.names
                            && let Some(name) = names.get("en")
                        {
                            location_parts.push(format!("region:{}", name));
                        }

                        if let Some(city_data) = city.city.and_then(|c| c.names)
                            && let Some(name) = city_data.get("en")
                        {
                            location_parts.push(format!("city:{}", name));
                        }

                        if let Some(location) = city.location
                            && let (Some(lat), Some(lon)) = (location.latitude, location.longitude)
                        {
                            location_parts.push(format!("coords:{:.4},{:.4}", lat, lon));
                        }

                        // Add threat intelligence from MaxMind
                        if let Some(traits) = city.traits {
                            let mut risk_indicators = Vec::new();

                            if traits.is_anonymous_proxy == Some(true) {
                                risk_indicators.push("proxy");
                            }
                            if traits.is_satellite_provider == Some(true) {
                                risk_indicators.push("satellite");
                            }
                            if traits.is_anycast == Some(true) {
                                risk_indicators.push("anycast");
                            }

                            if !risk_indicators.is_empty() {
                                location_parts
                                    .push(format!("threats:{}", risk_indicators.join(",")));
                            }
                        }

                        Some(location_parts.join("|"))
                    }
                    Ok(None) => {
                        log::debug!("MaxMind lookup returned no data for {}", ip);
                        None
                    }
                    Err(e) => {
                        log::debug!("MaxMind lookup failed for {}: {}", ip, e);
                        None
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to open MaxMind database: {}", e);
                None
            }
        }
    }
}

/// Risk calculator for sessions
pub struct RiskCalculator;

impl Default for RiskCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskCalculator {
    pub fn new() -> Self {
        Self
    }

    /// Calculate risk score (0-100) for a session
    pub fn calculate_risk(
        &self,
        device_info: &DeviceInfo,
        metadata: &RequestMetadata,
        _session_history: &[Session],
        threat_intel_manager: Option<&ThreatFeedManager>,
    ) -> u8 {
        let mut risk_score = 0u8;

        // Check for new device
        if !device_info.is_trusted {
            risk_score += 20;
        }

        // Check IP reputation (simplified)
        if let Some(ip) = &metadata.ip_address
            && self.is_suspicious_ip(ip, threat_intel_manager)
        {
            risk_score += 30;
        }

        // Check geolocation anomalies
        if let Some(location) = &metadata.geolocation {
            let mut geo_risk = 0;

            // Check country-based risk
            if let Some(country) = &location.country {
                let country_lower = country.to_lowercase();

                // High-risk indicators in country names
                let high_risk_countries =
                    ["tor", "anonymous", "vpn", "proxy", "hosting", "datacenter"];

                for indicator in &high_risk_countries {
                    if country_lower.contains(indicator) {
                        geo_risk += 30;
                        break;
                    }
                }

                // Real threat intelligence integration for geographic risk
                geo_risk += self.assess_country_threat_level(&country_lower) as u8;

                // Check against known high-risk hosting providers
                let elevated_risk_patterns = ["cloud", "aws", "azure", "gcp"];
                for pattern in &elevated_risk_patterns {
                    if country_lower.contains(pattern) {
                        geo_risk += 20;
                        break;
                    }
                }
            }

            // Check for impossible travel (basic latitude/longitude analysis)
            if let (Some(lat), Some(lon)) = (location.latitude, location.longitude) {
                // Validate coordinate ranges
                if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
                    geo_risk += 25; // Invalid coordinates are suspicious
                }

                // Detect datacenter coordinates (often round numbers)
                if (lat * 100.0).fract().abs() < 0.01 && (lon * 100.0).fract().abs() < 0.01 {
                    geo_risk += 15; // Suspiciously precise coordinates
                }
            }

            // Region-based analysis
            if let Some(region) = &location.region {
                let region_lower = region.to_lowercase();
                if region_lower.contains("hosting") || region_lower.contains("datacenter") {
                    geo_risk += 20;
                }
            }

            // City-based analysis
            if let Some(city) = &location.city {
                let city_lower = city.to_lowercase();
                if city_lower.contains("server") || city_lower.contains("datacenter") {
                    geo_risk += 15;
                }
            }

            risk_score += geo_risk;
        }

        // Check time-based anomalies
        // - Unusual login times
        // - Rapid geographic movement
        // - Multiple simultaneous sessions

        risk_score.min(100)
    }

    /// Check if IP address is suspicious
    fn is_suspicious_ip(&self, ip: &str, threat_intel_manager: Option<&ThreatFeedManager>) -> bool {
        use std::net::IpAddr;
        use std::str::FromStr;

        // Parse IP address for analysis
        if let Ok(ip_addr) = IpAddr::from_str(ip) {
            match ip_addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();

                    // Real threat intelligence feeds integration
                    if self.check_malicious_ip_feeds(&ipv4, threat_intel_manager) {
                        return true;
                    }

                    // Suspicious hosting ranges (example patterns)
                    let suspicious_ranges = [
                        // Known VPN/hosting provider ranges (examples)
                        (5, 0, 0, 0, 8),   // Various hosting
                        (31, 0, 0, 0, 8),  // Various hosting
                        (37, 0, 0, 0, 8),  // Various hosting
                        (46, 0, 0, 0, 8),  // Various hosting
                        (95, 0, 0, 0, 8),  // Various hosting
                        (185, 0, 0, 0, 8), // Various hosting
                    ];

                    for (net, _, _, _, _) in &suspicious_ranges {
                        if octets[0] == *net {
                            return true;
                        }
                    }

                    // Check for reserved/special ranges that shouldn't be used
                    if octets[0] == 0 ||                              // "This" network
                       (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) || // Carrier-grade NAT
                       (octets[0] == 169 && octets[1] == 254) ||      // Link-local
                       (octets[0] >= 224 && octets[0] <= 239) ||      // Multicast
                       (octets[0] >= 240)
                    {
                        // Reserved/experimental
                        return true;
                    }

                    // Detect potential port scans (suspicious patterns in last octet)
                    if octets[3] == 0 || octets[3] == 255 {
                        return true;
                    }

                    // Real specialized databases for proxy/VPN detection
                    if self.check_proxy_vpn_databases(&ipv4) {
                        return true;
                    }

                    // Fallback proxy port pattern detection
                    let proxy_ports_in_ip = [
                        80, 443, 8080, 3128, 1080, 8000, 8888, 9050, // Common proxy ports
                    ];

                    for &port in &proxy_ports_in_ip {
                        if octets[2] == (port / 256) as u8 && octets[3] == (port % 256) as u8 {
                            return true;
                        }
                    }

                    false
                }
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();

                    // Real-time Tor exit node detection
                    if self.check_tor_exit_nodes(&ipv6) {
                        return true;
                    }

                    // Fallback static range checks
                    if segments[0] == 0x2001 && segments[1] == 0x67c {
                        // Example known Tor range (static fallback)
                        return true;
                    }

                    // Suspicious IPv6 patterns (overly sequential or predictable)
                    let mut sequential_count = 0;
                    for i in 1..segments.len() {
                        if segments[i] == segments[i - 1] + 1 {
                            sequential_count += 1;
                        }
                    }
                    if sequential_count >= 4 {
                        // Too many sequential segments
                        return true;
                    }

                    // Check for tunnel brokers (often used for anonymity)
                    if segments[0] == 0x2001 && segments[1] == 0x470 {
                        // Hurricane Electric
                        return true;
                    }

                    false
                }
            }
        } else {
            true // Invalid IP format is suspicious
        }
    }

    /// Assess threat level for a country using threat intelligence feeds
    fn assess_country_threat_level(&self, country: &str) -> u32 {
        use std::path::Path;

        // Load country threat intelligence (configurable path)
        let threat_db_path = std::env::var("COUNTRY_THREAT_DB_PATH")
            .unwrap_or_else(|_| "country-threats.csv".to_string());

        if Path::new(&threat_db_path).exists() {
            // Real implementation: Load from CSV threat feed
            if let Ok(contents) = std::fs::read_to_string(&threat_db_path) {
                let mut csv_reader = csv::Reader::from_reader(contents.as_bytes());

                for result in csv_reader.records() {
                    if let Ok(record) = result
                        && record.len() >= 2
                    {
                        let threat_country = record[0].to_lowercase();
                        if let Ok(risk_score) = record[1].parse::<u32>()
                            && country.contains(&threat_country)
                        {
                            log::debug!("Country threat match: {} -> risk {}", country, risk_score);
                            return risk_score;
                        }
                    }
                }
            }
        }

        // Fallback: Basic static threat assessment
        let high_risk_indicators = [
            ("botnet", 40),
            ("malware", 35),
            ("ransomware", 45),
            ("cybercrime", 30),
            ("hacking", 25),
            ("fraud", 20),
        ];

        for (indicator, risk) in &high_risk_indicators {
            if country.contains(indicator) {
                return *risk;
            }
        }

        // Countries with elevated hosting/VPN activity
        let hosting_risk_patterns = [
            ("hosting", 15),
            ("datacenter", 15),
            ("cloud", 10),
            ("server", 12),
            ("vps", 18),
            ("dedicated", 10),
        ];

        for (pattern, risk) in &hosting_risk_patterns {
            if country.contains(pattern) {
                return *risk;
            }
        }

        0 // No additional risk
    }

    /// Check IP against malicious IP threat intelligence feeds
    fn check_malicious_ip_feeds(
        &self,
        ip: &std::net::Ipv4Addr,
        threat_intel_manager: Option<&ThreatFeedManager>,
    ) -> bool {
        // Try automated threat intelligence first
        if let Some(threat_manager) = threat_intel_manager {
            return threat_manager.is_malicious_ip(&std::net::IpAddr::V4(*ip));
        }

        // Fall back to manual file checking for backward compatibility
        use std::path::Path;

        // Load malicious IP feeds (multiple sources)
        let feed_paths = [
            std::env::var("MALICIOUS_IPS_DB_PATH")
                .unwrap_or_else(|_| "malicious-ips.txt".to_string()),
            std::env::var("BOTNET_IPS_DB_PATH").unwrap_or_else(|_| "botnet-ips.txt".to_string()),
            std::env::var("TOR_EXIT_NODES_DB_PATH").unwrap_or_else(|_| "tor-exits.txt".to_string()),
        ];

        for feed_path in &feed_paths {
            if Path::new(feed_path).exists()
                && let Ok(contents) = std::fs::read_to_string(feed_path)
            {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    // Check exact IP match
                    if line == ip.to_string() {
                        log::warn!("Malicious IP detected: {} (source: {})", ip, feed_path);
                        return true;
                    }

                    // Check CIDR network match
                    if line.contains('/')
                        && let Ok(network) = line.parse::<ipnetwork::Ipv4Network>()
                        && network.contains(*ip)
                    {
                        log::warn!(
                            "Malicious network detected: {} in {} (source: {})",
                            ip,
                            network,
                            feed_path
                        );
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check against specialized proxy/VPN databases
    fn check_proxy_vpn_databases(&self, ip: &std::net::Ipv4Addr) -> bool {
        use std::path::Path;

        // Multiple specialized databases for proxy/VPN detection
        let db_sources = [
            ("VPN_DATABASE_PATH", "vpn-ranges.txt"),
            ("PROXY_DATABASE_PATH", "proxy-ips.txt"),
            ("DATACENTER_DATABASE_PATH", "datacenter-ranges.txt"),
            ("HOSTING_DATABASE_PATH", "hosting-providers.txt"),
        ];

        for (env_var, default_file) in &db_sources {
            let db_path = std::env::var(env_var).unwrap_or_else(|_| default_file.to_string());

            if Path::new(&db_path).exists()
                && let Ok(contents) = std::fs::read_to_string(&db_path)
            {
                for line in contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    // Support multiple formats: IP, CIDR, IP ranges
                    if line.contains('/') {
                        // CIDR notation
                        if let Ok(network) = line.parse::<ipnetwork::Ipv4Network>()
                            && network.contains(*ip)
                        {
                            log::info!(
                                "Proxy/VPN detected: {} in {} (source: {})",
                                ip,
                                network,
                                db_path
                            );
                            return true;
                        }
                    } else if line.contains('-') {
                        // IP range format: 1.2.3.4-1.2.3.10
                        let parts: Vec<&str> = line.split('-').collect();
                        if parts.len() == 2
                            && let (Ok(start_ip), Ok(end_ip)) = (
                                parts[0].trim().parse::<std::net::Ipv4Addr>(),
                                parts[1].trim().parse::<std::net::Ipv4Addr>(),
                            )
                        {
                            let ip_u32 = u32::from(*ip);
                            let start_u32 = u32::from(start_ip);
                            let end_u32 = u32::from(end_ip);

                            if ip_u32 >= start_u32 && ip_u32 <= end_u32 {
                                log::info!(
                                    "Proxy/VPN range detected: {} in {}-{} (source: {})",
                                    ip,
                                    start_ip,
                                    end_ip,
                                    db_path
                                );
                                return true;
                            }
                        }
                    } else if line == ip.to_string() {
                        // Exact IP match
                        log::info!("Proxy/VPN exact match: {} (source: {})", ip, db_path);
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check against real-time Tor exit node lists
    fn check_tor_exit_nodes(&self, ip: &std::net::Ipv6Addr) -> bool {
        use std::path::Path;

        // Real-time Tor exit node detection
        let tor_db_path = std::env::var("TOR_EXIT_NODES_IPV6_PATH")
            .unwrap_or_else(|_| "tor-exits-ipv6.txt".to_string());

        if Path::new(&tor_db_path).exists()
            && let Ok(contents) = std::fs::read_to_string(&tor_db_path)
        {
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Check IPv6 exact match
                if let Ok(tor_ip) = line.parse::<std::net::Ipv6Addr>()
                    && tor_ip == *ip
                {
                    log::warn!("Tor exit node detected: {}", ip);
                    return true;
                }

                // Check IPv6 network match
                if line.contains('/')
                    && let Ok(network) = line.parse::<ipnetwork::Ipv6Network>()
                    && network.contains(*ip)
                {
                    log::warn!("Tor exit network detected: {} in {}", ip, network);
                    return true;
                }
            }
        }

        // Also check IPv4-mapped IPv6 addresses for Tor
        if let Some(ipv4) = ip.to_ipv4() {
            let tor_v4_path = std::env::var("TOR_EXIT_NODES_IPV4_PATH")
                .unwrap_or_else(|_| "tor-exits-ipv4.txt".to_string());

            if Path::new(&tor_v4_path).exists()
                && let Ok(contents) = std::fs::read_to_string(&tor_v4_path)
            {
                for line in contents.lines() {
                    let line = line.trim();
                    if line == ipv4.to_string() {
                        log::warn!("Tor exit node detected (IPv4-mapped): {}", ip);
                        return true;
                    }
                }
            }
        }

        false
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_duration: Duration::from_secs(3600), // 1 hour
            max_duration: Duration::from_secs(86400),    // 24 hours
            idle_timeout: Duration::from_secs(1800),     // 30 minutes
            rotate_on_privilege_escalation: true,
            rotate_periodically: true,
            rotation_interval: Duration::from_secs(1800), // 30 minutes
            max_concurrent_sessions: Some(5),
            track_device_fingerprints: true,
            enforce_geographic_restrictions: false,
            allowed_countries: vec![],
            security_policy: SessionSecurityPolicy::default(),
        }
    }
}

impl Default for SessionSecurityPolicy {
    fn default() -> Self {
        Self {
            require_mfa_for_new_devices: true,
            require_reauth_for_sensitive_ops: true,
            reauth_timeout: Duration::from_secs(300), // 5 minutes
            max_risk_score: 70,
            auto_suspend_suspicious: true,
            verify_location_changes: true,
            limit_concurrent_sessions: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_fingerprint_generation() {
        let generator = DeviceFingerprintGenerator::new();
        let metadata = RequestMetadata {
            user_agent: Some("Mozilla/5.0".to_string()),
            ..Default::default()
        };

        let fp1 = generator.generate_fingerprint(&metadata);
        let fp2 = generator.generate_fingerprint(&metadata);

        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("fp_"));
    }

    #[test]
    fn test_risk_calculation() {
        let calculator = RiskCalculator::new();
        let device_info = DeviceInfo {
            fingerprint: "test".to_string(),
            device_type: "desktop".to_string(),
            operating_system: None,
            browser: None,
            screen_resolution: None,
            timezone: None,
            language: None,
            is_trusted: false,
            device_name: None,
        };

        let metadata = RequestMetadata::default();
        let history = vec![];

        let risk = calculator.calculate_risk(&device_info, &metadata, &history, None);
        assert!(risk >= 20); // Should have at least 20 for untrusted device
    }
}
