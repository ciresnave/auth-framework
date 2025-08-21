// Secure session management with enhanced security measures
use super::secure_utils::{SecureComparison, SecureRandomGen};
use crate::errors::{AuthError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use zeroize::ZeroizeOnDrop;

/// Secure session with enhanced security properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureSession {
    /// Cryptographically secure session ID
    pub id: String,

    /// User ID associated with this session
    pub user_id: String,

    /// Session creation timestamp
    pub created_at: SystemTime,

    /// Last activity timestamp
    pub last_accessed: SystemTime,

    /// Session expiration time
    pub expires_at: SystemTime,

    /// Session state
    pub state: SessionState,

    /// Device fingerprint for security tracking
    pub device_fingerprint: DeviceFingerprint,

    /// IP address where session was created
    pub creation_ip: String,

    /// Current IP address
    pub current_ip: String,

    /// User agent string
    pub user_agent: String,

    /// MFA verification status
    pub mfa_verified: bool,

    /// Security flags
    pub security_flags: SecurityFlags,

    /// Session metadata
    pub metadata: HashMap<String, String>,

    /// Number of concurrent sessions for this user
    pub concurrent_sessions: u32,

    /// Session risk score (0-100)
    pub risk_score: u8,

    /// Session rotation count
    pub rotation_count: u32,
}

/// Session state with security considerations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Expired,
    Revoked,
    Suspended,
    RequiresMfa,
    RequiresRotation,
    HighRisk,
}

/// Device fingerprint for tracking sessions
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct DeviceFingerprint {
    /// Browser fingerprint hash
    pub browser_hash: String,

    /// Screen resolution
    pub screen_resolution: Option<String>,

    /// Timezone offset
    pub timezone_offset: Option<i32>,

    /// Platform information
    pub platform: Option<String>,

    /// Language preferences
    pub languages: Vec<String>,

    /// Canvas fingerprint
    pub canvas_hash: Option<String>,

    /// WebGL fingerprint
    pub webgl_hash: Option<String>,
}

/// Security flags for session management
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityFlags {
    /// Session created over secure transport (HTTPS)
    pub secure_transport: bool,

    /// Session accessed from suspicious location
    pub suspicious_location: bool,

    /// Multiple failed authentication attempts
    pub multiple_failures: bool,

    /// Session accessed from new device
    pub new_device: bool,

    /// Session accessed outside normal hours
    pub unusual_hours: bool,

    /// High-privilege operations performed
    pub high_privilege_ops: bool,

    /// Session shared across devices (security risk)
    pub cross_device_access: bool,
}

/// Secure session configuration
#[derive(Debug, Clone)]
pub struct SecureSessionConfig {
    /// Maximum session lifetime
    pub max_lifetime: Duration,

    /// Session idle timeout
    pub idle_timeout: Duration,

    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,

    /// Force session rotation interval
    pub rotation_interval: Duration,

    /// Require secure transport (HTTPS)
    pub require_secure_transport: bool,

    /// Enable device fingerprinting
    pub enable_device_fingerprinting: bool,

    /// Maximum allowed risk score
    pub max_risk_score: u8,

    /// Enable IP address validation
    pub validate_ip_address: bool,

    /// Maximum IP address changes per session
    pub max_ip_changes: u32,

    /// Enable geolocation tracking
    pub enable_geolocation: bool,
}

impl Default for SecureSessionConfig {
    fn default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(8 * 3600), // 8 hours
            idle_timeout: Duration::from_secs(30 * 60),  // 30 minutes
            max_concurrent_sessions: 3,
            rotation_interval: Duration::from_secs(3600), // 1 hour
            require_secure_transport: true,
            enable_device_fingerprinting: true,
            max_risk_score: 70,
            validate_ip_address: true,
            max_ip_changes: 3,
            enable_geolocation: false, // Requires external service
        }
    }
}

/// Secure session manager with comprehensive security controls
pub struct SecureSessionManager {
    config: SecureSessionConfig,
    active_sessions: Arc<DashMap<String, SecureSession>>,
    user_sessions: Arc<DashMap<String, Vec<String>>>, // user_id -> session_ids
    ip_changes: Arc<DashMap<String, u32>>,            // session_id -> change_count
}

impl SecureSessionManager {
    /// Create a new secure session manager
    pub fn new(config: SecureSessionConfig) -> Self {
        Self {
            config,
            active_sessions: Arc::new(DashMap::new()),
            user_sessions: Arc::new(DashMap::new()),
            ip_changes: Arc::new(DashMap::new()),
        }
    }

    /// Create a new secure session
    pub fn create_session(
        &self,
        user_id: &str,
        ip_address: &str,
        user_agent: &str,
        device_fingerprint: Option<DeviceFingerprint>,
        secure_transport: bool,
    ) -> Result<SecureSession> {
        // Validate security requirements
        if self.config.require_secure_transport && !secure_transport {
            return Err(AuthError::validation(
                "Session must be created over secure transport (HTTPS)".to_string(),
            ));
        }

        // Check concurrent session limits
        self.enforce_concurrent_session_limit(user_id)?;

        // Generate secure session ID
        let session_id = SecureRandomGen::generate_session_id()?;

        let now = SystemTime::now();
        let expires_at = now + self.config.max_lifetime;

        // Calculate initial risk score
        let risk_score = self.calculate_risk_score(
            ip_address,
            user_agent,
            &device_fingerprint,
            secure_transport,
        );

        // Get concurrent session count
        let concurrent_sessions = self.get_user_session_count(user_id);

        let session = SecureSession {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            last_accessed: now,
            expires_at,
            state: if risk_score > self.config.max_risk_score {
                SessionState::HighRisk
            } else {
                SessionState::Active
            },
            device_fingerprint: device_fingerprint.unwrap_or_else(|| DeviceFingerprint {
                browser_hash: "unknown".to_string(),
                screen_resolution: None,
                timezone_offset: None,
                platform: None,
                languages: vec![],
                canvas_hash: None,
                webgl_hash: None,
            }),
            creation_ip: ip_address.to_string(),
            current_ip: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            mfa_verified: false,
            security_flags: SecurityFlags {
                secure_transport,
                ..SecurityFlags::default()
            },
            metadata: HashMap::new(),
            concurrent_sessions,
            risk_score,
            rotation_count: 0,
        };

        // Store session
        self.store_session(session.clone())?;

        tracing::info!(
            "Created secure session {} for user {} (risk score: {})",
            session_id,
            user_id,
            risk_score
        );

        Ok(session)
    }

    /// Validate and retrieve session
    pub fn get_session(&self, session_id: &str) -> Result<Option<SecureSession>> {
        if let Some(session_ref) = self.active_sessions.get(session_id) {
            let session = session_ref.value().clone();

            // Check if session is expired
            if session.expires_at < SystemTime::now() {
                drop(session_ref);
                self.revoke_session(session_id)?;
                return Ok(None);
            }

            // Check session state
            match session.state {
                SessionState::Active => Ok(Some(session)),
                SessionState::RequiresMfa => Ok(Some(session)),
                SessionState::RequiresRotation => Ok(Some(session)),
                _ => Ok(None), // Expired, revoked, suspended, high risk
            }
        } else {
            Ok(None)
        }
    }

    /// Update session activity and validate security
    pub fn update_session_activity(
        &self,
        session_id: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<()> {
        if let Some(mut session_entry) = self.active_sessions.get_mut(session_id) {
            let session = session_entry.value_mut();
            let now = SystemTime::now();

            // Check idle timeout
            if now
                .duration_since(session.last_accessed)
                .unwrap_or_default()
                > self.config.idle_timeout
            {
                session.state = SessionState::Expired;
                return Err(AuthError::validation(
                    "Session expired due to inactivity".to_string(),
                ));
            }

            // Validate IP address change
            if self.config.validate_ip_address && session.current_ip != ip_address {
                self.handle_ip_change(session, ip_address)?;
            }

            // Validate user agent consistency
            if !SecureComparison::constant_time_eq(&session.user_agent, user_agent) {
                session.security_flags.cross_device_access = true;
                tracing::warn!(
                    "User agent change detected for session {}: {} -> {}",
                    session_id,
                    session.user_agent,
                    user_agent
                );
            }

            // Update activity
            session.last_accessed = now;
            session.current_ip = ip_address.to_string();

            // Check if rotation is needed
            if now.duration_since(session.created_at).unwrap_or_default()
                > self.config.rotation_interval
            {
                session.state = SessionState::RequiresRotation;
            }

            // Recalculate risk score
            let new_risk_score = self.calculate_risk_score_update(session);
            session.risk_score = new_risk_score;

            if new_risk_score > self.config.max_risk_score {
                session.state = SessionState::HighRisk;
                tracing::warn!(
                    "Session {} marked as high risk (score: {})",
                    session_id,
                    new_risk_score
                );
            }

            Ok(())
        } else {
            Err(AuthError::validation("Session not found".to_string()))
        }
    }

    /// Rotate session ID for security
    pub fn rotate_session(&self, session_id: &str) -> Result<String> {
        if let Some((_, mut session)) = self.active_sessions.remove(session_id) {
            // Generate new session ID
            let new_session_id = SecureRandomGen::generate_session_id()?;

            // Update session
            session.id = new_session_id.clone();
            session.rotation_count += 1;
            session.state = SessionState::Active;
            session.last_accessed = SystemTime::now();

            // Store with new ID
            self.active_sessions
                .insert(new_session_id.clone(), session.clone());

            // Update user session tracking with atomic operations
            if let Some(mut user_session_list) = self.user_sessions.get_mut(&session.user_id)
                && let Some(pos) = user_session_list.iter().position(|id| id == session_id)
            {
                user_session_list[pos] = new_session_id.clone();
            }

            tracing::info!(
                "Session rotated: {} -> {} (rotation count: {})",
                session_id,
                new_session_id,
                session.rotation_count
            );

            Ok(new_session_id)
        } else {
            Err(AuthError::validation(
                "Session not found for rotation".to_string(),
            ))
        }
    }

    /// Revoke a session
    pub fn revoke_session(&self, session_id: &str) -> Result<()> {
        if let Some((_, session)) = self.active_sessions.remove(session_id) {
            // Remove from user session tracking using atomic operations
            if let Some(mut user_session_list) = self.user_sessions.get_mut(&session.user_id) {
                user_session_list.retain(|id| id != session_id);
                if user_session_list.is_empty() {
                    drop(user_session_list);
                    self.user_sessions.remove(&session.user_id);
                }
            }

            // Clean up IP change tracking
            self.ip_changes.remove(session_id);

            tracing::info!(
                "Session {} revoked for user {}",
                session_id,
                session.user_id
            );

            Ok(())
        } else {
            Err(AuthError::validation(
                "Session not found for revocation".to_string(),
            ))
        }
    }

    /// Revoke all sessions for a user
    pub fn revoke_user_sessions(&self, user_id: &str) -> Result<u32> {
        if let Some((_, session_ids)) = self.user_sessions.remove(user_id) {
            let count = session_ids.len() as u32;

            for session_id in &session_ids {
                self.active_sessions.remove(session_id);
            }

            // Clean up IP change tracking
            for session_id in &session_ids {
                self.ip_changes.remove(session_id);
            }

            tracing::info!("Revoked {} sessions for user {}", count, user_id);

            Ok(count)
        } else {
            Ok(0)
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&self) -> Result<u32> {
        let now = SystemTime::now();
        let mut expired_sessions = Vec::new();

        // Find expired sessions using DashMap iterator
        for session_ref in self.active_sessions.iter() {
            if session_ref.value().expires_at < now {
                expired_sessions.push(session_ref.key().clone());
            }
        }

        // Remove expired sessions
        let count = expired_sessions.len() as u32;
        for session_id in expired_sessions {
            let _ = self.revoke_session(&session_id);
        }

        if count > 0 {
            tracing::info!("Cleaned up {} expired sessions", count);
        }

        Ok(count)
    }

    /// Store session in memory (in production, use persistent storage)
    fn store_session(&self, session: SecureSession) -> Result<()> {
        self.active_sessions
            .insert(session.id.clone(), session.clone());

        self.user_sessions
            .entry(session.user_id.clone())
            .or_default()
            .push(session.id.clone());

        Ok(())
    }

    /// Enforce concurrent session limits
    fn enforce_concurrent_session_limit(&self, user_id: &str) -> Result<()> {
        let current_count = self.get_user_session_count(user_id);

        if current_count >= self.config.max_concurrent_sessions {
            // Revoke oldest session
            self.revoke_oldest_user_session(user_id)?;
        }

        Ok(())
    }

    /// Get number of active sessions for a user
    fn get_user_session_count(&self, user_id: &str) -> u32 {
        self.user_sessions
            .get(user_id)
            .map(|sessions| sessions.len() as u32)
            .unwrap_or(0)
    }

    /// Revoke the oldest session for a user
    fn revoke_oldest_user_session(&self, user_id: &str) -> Result<()> {
        let oldest_session_id = if let Some(session_ids_ref) = self.user_sessions.get(user_id) {
            let session_ids = session_ids_ref.value();
            session_ids
                .iter()
                .filter_map(|id| self.active_sessions.get(id))
                .min_by_key(|session_ref| session_ref.value().created_at)
                .map(|session_ref| session_ref.key().clone())
        } else {
            None
        };

        if let Some(session_id) = oldest_session_id {
            self.revoke_session(&session_id)?;
            tracing::info!(
                "Revoked oldest session {} for user {} due to concurrent limit",
                session_id,
                user_id
            );
        }

        Ok(())
    }

    /// Handle IP address change
    fn handle_ip_change(&self, session: &mut SecureSession, new_ip: &str) -> Result<()> {
        let mut change_count = self.ip_changes.entry(session.id.clone()).or_insert(0);
        *change_count += 1;

        if *change_count > self.config.max_ip_changes {
            session.state = SessionState::HighRisk;
            session.security_flags.suspicious_location = true;
            return Err(AuthError::validation(
                "Too many IP address changes - session marked as high risk".to_string(),
            ));
        }

        session.security_flags.suspicious_location = true;
        tracing::warn!(
            "IP address change #{} for session {}: {} -> {}",
            *change_count,
            session.id,
            session.current_ip,
            new_ip
        );

        Ok(())
    }

    /// Calculate initial risk score
    fn calculate_risk_score(
        &self,
        ip_address: &str,
        user_agent: &str,
        device_fingerprint: &Option<DeviceFingerprint>,
        secure_transport: bool,
    ) -> u8 {
        let mut score = 0u8;

        // Non-secure transport
        if !secure_transport {
            score += 30;
        }

        // Unknown or suspicious user agent
        if user_agent.is_empty() || user_agent.len() < 10 {
            score += 20;
        }

        // Missing device fingerprint
        if device_fingerprint.is_none() {
            score += 15;
        }

        // Private/local IP addresses (higher risk)
        if self.is_private_ip(ip_address) {
            score += 10;
        }

        score.min(100)
    }

    /// Update risk score based on session activity
    fn calculate_risk_score_update(&self, session: &SecureSession) -> u8 {
        let mut score = session.risk_score;

        // Security flag penalties
        if session.security_flags.suspicious_location {
            score = score.saturating_add(20);
        }
        if session.security_flags.multiple_failures {
            score = score.saturating_add(25);
        }
        if session.security_flags.new_device {
            score = score.saturating_add(15);
        }
        if session.security_flags.unusual_hours {
            score = score.saturating_add(10);
        }
        if session.security_flags.cross_device_access {
            score = score.saturating_add(20);
        }

        // High concurrent sessions
        if session.concurrent_sessions > 5 {
            score = score.saturating_add(15);
        }

        // Multiple rotations (could indicate compromise)
        if session.rotation_count > 3 {
            score = score.saturating_add(10);
        }

        score.min(100)
    }

    /// Check if IP address is private/internal
    fn is_private_ip(&self, ip: &str) -> bool {
        ip.starts_with("192.168.")
            || ip.starts_with("10.")
            || ip.starts_with("172.")
            || ip == "127.0.0.1"
            || ip == "::1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_session_creation() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        let session = manager
            .create_session(
                "user123",
                "192.168.1.100",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        assert_eq!(session.user_id, "user123");
        assert_eq!(session.creation_ip, "192.168.1.100");
        assert!(session.security_flags.secure_transport);
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_session_rotation() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        let session = manager
            .create_session(
                "user123",
                "192.168.1.100",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        let old_id = session.id.clone();
        let new_id = manager.rotate_session(&old_id).unwrap();

        assert_ne!(old_id, new_id);
        assert!(manager.get_session(&old_id).unwrap().is_none());
        assert!(manager.get_session(&new_id).unwrap().is_some());
    }

    #[test]
    fn test_concurrent_session_limit() {
        let config = SecureSessionConfig {
            max_concurrent_sessions: 2,
            ..Default::default()
        };
        let manager = SecureSessionManager::new(config);

        // Create first session
        let session1 = manager
            .create_session(
                "user123",
                "192.168.1.100",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        // Create second session
        let session2 = manager
            .create_session(
                "user123",
                "192.168.1.101",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        // Third session should revoke the first
        let session3 = manager
            .create_session(
                "user123",
                "192.168.1.102",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        // First session should be revoked
        assert!(manager.get_session(&session1.id).unwrap().is_none());
        assert!(manager.get_session(&session2.id).unwrap().is_some());
        assert!(manager.get_session(&session3.id).unwrap().is_some());
    }

    #[test]
    fn test_risk_score_calculation() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        // High risk: non-secure transport, private IP, no device fingerprint
        let risk_score = manager.calculate_risk_score("192.168.1.1", "", &None, false);

        assert!(risk_score > 50, "Risk score should be high: {}", risk_score);
    }

    #[test]
    fn test_session_cleanup() {
        let config = SecureSessionConfig {
            max_lifetime: Duration::from_millis(1), // Very short for testing
            ..Default::default()
        };
        let manager = SecureSessionManager::new(config);

        let session = manager
            .create_session(
                "user123",
                "192.168.1.100",
                "Mozilla/5.0 Test Browser",
                None,
                true,
            )
            .unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let cleaned = manager.cleanup_expired_sessions().unwrap();
        assert_eq!(cleaned, 1);
        assert!(manager.get_session(&session.id).unwrap().is_none());
    }
}
