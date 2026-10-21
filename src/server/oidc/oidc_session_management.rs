//! OpenID Connect Session Management Implementation
//!
//! This module provides comprehensive session management capabilities for OpenID Connect,
//! serving as the foundation for RP-Initiated Logout, Front-Channel Logout,
//! Back-Channel Logout, and other session-related specifications.
//!
//! # Features
//!
//! - Session state monitoring
//! - Session management endpoints
//! - iframe-based session checking
//! - Session change notifications
//! - Multi-tab session coordination

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Session state enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OidcSessionState {
    /// User is authenticated
    Authenticated,
    /// User is not authenticated
    Unauthenticated,
    /// Session state changed
    Changed,
    /// Session state unknown/error
    Unknown,
}

/// OpenID Connect session information
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcSession {
    /// Unique session identifier
    pub session_id: String,
    /// Subject (user) identifier
    pub sub: String,
    /// Client ID for this session
    pub client_id: String,
    /// Session creation timestamp
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Session expiration timestamp
    pub expires_at: u64,
    /// Session state
    pub state: OidcSessionState,
    /// Browser session identifier (session_state parameter)
    pub browser_session_id: String,
    /// Associated logout tokens for backchannel logout
    pub logout_tokens: Vec<String>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

impl std::fmt::Debug for OidcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("OidcSession");
        d.field(
            "session_id",
            &crate::utils::redact::redacted(&self.session_id),
        );
        d.field("sub", &self.sub);
        d.field("client_id", &self.client_id);
        d.field("created_at", &self.created_at);
        d.field("last_activity", &self.last_activity);
        d.field("expires_at", &self.expires_at);
        d.field("state", &self.state);
        d.field(
            "browser_session_id",
            &crate::utils::redact::redacted(&self.browser_session_id),
        );
        d.field("logout_tokens", &self.logout_tokens);
        d.field("metadata", &self.metadata);
        d.finish()
    }
}

/// Session Management configuration
#[derive(Debug, Clone)]
pub struct SessionManagementConfig {
    /// Enable session management features
    pub enabled: bool,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Check session interval in seconds
    pub check_session_interval: u64,
    /// Enable iframe session checking
    pub enable_iframe_checking: bool,
    /// Session management endpoints
    pub check_session_iframe_endpoint: String,
    /// End session endpoint
    pub end_session_endpoint: String,
}

impl Default for SessionManagementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_timeout: 3600,      // 1 hour
            check_session_interval: 30, // 30 seconds
            enable_iframe_checking: true,
            check_session_iframe_endpoint: "/connect/checksession".to_string(),
            end_session_endpoint: "/connect/endsession".to_string(),
        }
    }
}

/// Session Management provider
#[derive(Clone)]
pub struct SessionManager {
    /// Configuration
    config: SessionManagementConfig,
    /// Active sessions storage
    sessions: HashMap<String, OidcSession>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("SessionManager");
        d.field("config", &self.config);
        d.field("sessions", &crate::utils::redact::redacted(&self.sessions));
        d.finish()
    }
}

/// Session check request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCheckRequest {
    /// Client ID
    pub client_id: String,
    /// Session state value
    pub session_state: String,
    /// Origin for CORS
    pub origin: String,
}

/// Session check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCheckResponse {
    /// Session state
    pub state: OidcSessionState,
    /// New session state value if changed
    pub session_state: Option<String>,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(config: SessionManagementConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
        }
    }

    /// Create new session
    pub fn create_session(
        &mut self,
        sub: String,
        client_id: String,
        metadata: HashMap<String, String>,
    ) -> Result<OidcSession> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = OidcSession {
            session_id: Uuid::new_v4().to_string(),
            sub: sub.clone(),
            client_id: client_id.clone(),
            created_at: now,
            last_activity: now,
            expires_at: now + 3600, // Default 1 hour expiration
            state: OidcSessionState::Authenticated,
            browser_session_id: self.generate_browser_session_id(&sub, &client_id)?,
            logout_tokens: Vec::new(),
            metadata,
        };

        self.sessions
            .insert(session.session_id.clone(), session.clone());
        Ok(session)
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Option<&OidcSession> {
        self.sessions.get(session_id)
    }

    /// Update session activity
    pub fn update_session_activity(&mut self, session_id: &str) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            session.last_activity = now;
            Ok(())
        } else {
            Err(AuthError::validation("Session not found"))
        }
    }

    /// Check if session is valid (not expired)
    pub fn is_session_valid(&self, session_id: &str) -> bool {
        if let Some(session) = self.get_session(session_id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            now - session.last_activity < self.config.session_timeout
        } else {
            false
        }
    }

    /// Generate an opaque browser session ID for the OIDC `session_state` parameter.
    ///
    /// Uses SHA-256(sub || client_id || random UUID) so the result is a fixed-length
    /// opaque token that does not leak user identity or client information in the URL.
    fn generate_browser_session_id(&self, sub: &str, client_id: &str) -> Result<String> {
        let nonce = Uuid::new_v4().to_string();
        let mut hasher = Sha256::new();
        hasher.update(sub.as_bytes());
        hasher.update(b":");
        hasher.update(client_id.as_bytes());
        hasher.update(b":");
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    /// Check session state for iframe polling
    pub fn check_session_state(
        &self,
        request: SessionCheckRequest,
    ) -> Result<SessionCheckResponse> {
        // Find session by browser session ID
        let session = self.sessions.values().find(|s| {
            s.browser_session_id == request.session_state && s.client_id == request.client_id
        });

        if let Some(session) = session {
            if self.is_session_valid(&session.session_id) {
                Ok(SessionCheckResponse {
                    state: OidcSessionState::Authenticated,
                    session_state: None, // No change
                })
            } else {
                Ok(SessionCheckResponse {
                    state: OidcSessionState::Unauthenticated,
                    session_state: None,
                })
            }
        } else {
            Ok(SessionCheckResponse {
                state: OidcSessionState::Unauthenticated,
                session_state: None,
            })
        }
    }

    /// End session (logout)
    pub fn end_session(&mut self, session_id: &str) -> Result<OidcSession> {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.state = OidcSessionState::Unauthenticated;
            Ok(session)
        } else {
            Err(AuthError::validation("Session not found"))
        }
    }

    /// Get check session iframe HTML
    pub fn get_check_session_iframe(&self, client_id: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Session Check</title>
    <script>
        (function() {{
            var client_id = "{}";
            var check_interval = {} * 1000; // Convert to milliseconds

            function getCookie(name) {{
                var cookies = document.cookie.split(';');
                for (var i = 0; i < cookies.length; i++) {{
                    var cookie = cookies[i].trim();
                    if (cookie.indexOf(name + '=') === 0) {{
                        return cookie.substring(name.length + 1);
                    }}
                }}
                return null;
            }}

            function checkSession() {{
                var OidcSessionState = getCookie('session_state');
                if (OidcSessionState) {{
                    // Notify parent window of session check
                    window.parent.postMessage({{
                        type: 'session_check',
                        client_id: client_id,
                        session_state: OidcSessionState,
                        state: 'unchanged'
                    }}, '*');
                }} else {{
                    window.parent.postMessage({{
                        type: 'session_check',
                        client_id: client_id,
                        state: 'unauthenticated'
                    }}, '*');
                }}
            }}

            // Initial check
            checkSession();

            // Periodic checking
            setInterval(checkSession, check_interval);

            // Listen for messages from parent
            window.addEventListener('message', function(e) {{
                if (e.data && e.data.type === 'check_session') {{
                    checkSession();
                }}
            }});
        }})();
    </script>
</head>
<body>
    <p>Session monitoring active...</p>
</body>
</html>"#,
            client_id, self.config.check_session_interval
        )
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let initial_count = self.sessions.len();

        self.sessions
            .retain(|_, session| now - session.last_activity < self.config.session_timeout);

        initial_count - self.sessions.len()
    }

    /// Get all sessions for a subject
    pub fn get_sessions_for_subject(&self, sub: &str) -> Vec<&OidcSession> {
        self.sessions
            .values()
            .filter(|session| session.sub == sub)
            .collect()
    }

    /// Add logout token to session (for backchannel logout)
    pub fn add_logout_token(&mut self, session_id: &str, logout_token: String) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.logout_tokens.push(logout_token);
            Ok(())
        } else {
            Err(AuthError::validation("Session not found"))
        }
    }

    /// Get session management discovery metadata
    pub fn get_discovery_metadata(&self) -> HashMap<String, serde_json::Value> {
        let mut metadata = HashMap::new();

        if self.config.enabled {
            metadata.insert(
                "check_session_iframe".to_string(),
                serde_json::Value::String(self.config.check_session_iframe_endpoint.clone()),
            );
            metadata.insert(
                "end_session_endpoint".to_string(),
                serde_json::Value::String(self.config.end_session_endpoint.clone()),
            );
            metadata.insert(
                "frontchannel_logout_supported".to_string(),
                serde_json::Value::Bool(true),
            );
            metadata.insert(
                "frontchannel_logout_session_supported".to_string(),
                serde_json::Value::Bool(true),
            );
            metadata.insert(
                "backchannel_logout_supported".to_string(),
                serde_json::Value::Bool(true),
            );
            metadata.insert(
                "backchannel_logout_session_supported".to_string(),
                serde_json::Value::Bool(true),
            );
        }

        metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let mut manager = SessionManager::new(SessionManagementConfig::default());

        let mut metadata = HashMap::new();
        metadata.insert("ip_address".to_string(), "192.168.1.1".to_string());

        let session = manager
            .create_session("user123".to_string(), "client456".to_string(), metadata)
            .unwrap();

        assert_eq!(session.sub, "user123");
        assert_eq!(session.client_id, "client456");
        assert_eq!(session.state, OidcSessionState::Authenticated);
        assert!(!session.browser_session_id.is_empty());
    }

    #[test]
    fn test_session_validity() {
        let mut manager = SessionManager::new(SessionManagementConfig {
            session_timeout: 1, // 1 second timeout for testing
            ..SessionManagementConfig::default()
        });

        let session = manager
            .create_session(
                "user123".to_string(),
                "client456".to_string(),
                HashMap::new(),
            )
            .unwrap();

        assert!(manager.is_session_valid(&session.session_id));

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_secs(2));

        assert!(!manager.is_session_valid(&session.session_id));
    }

    #[test]
    fn test_check_session_iframe_generation() {
        let manager = SessionManager::new(SessionManagementConfig::default());

        let html = manager.get_check_session_iframe("test_client");

        assert!(html.contains("test_client"));
        assert!(html.contains("session_check"));
        assert!(html.contains("30 * 1000")); // Default interval
    }
}
