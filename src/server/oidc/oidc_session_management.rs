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
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Session state enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub state: SessionState,
    /// Browser session identifier (session_state parameter)
    pub browser_session_id: String,
    /// Associated logout tokens for backchannel logout
    pub logout_tokens: Vec<String>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
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
#[derive(Debug, Clone)]
pub struct SessionManager {
    /// Configuration
    config: SessionManagementConfig,
    /// Active sessions storage
    sessions: HashMap<String, OidcSession>,
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
    pub state: SessionState,
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
            .unwrap()
            .as_secs();

        let session = OidcSession {
            session_id: Uuid::new_v4().to_string(),
            sub: sub.clone(),
            client_id: client_id.clone(),
            created_at: now,
            last_activity: now,
            expires_at: now + 3600, // Default 1 hour expiration
            state: SessionState::Authenticated,
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
                .unwrap()
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
                .unwrap()
                .as_secs();

            now - session.last_activity < self.config.session_timeout
        } else {
            false
        }
    }

    /// Generate browser session ID for session_state parameter
    fn generate_browser_session_id(&self, sub: &str, client_id: &str) -> Result<String> {
        // In a real implementation, this would be a cryptographically secure
        // hash of session data + client salt
        let data = format!("{}:{}:{}", sub, client_id, Uuid::new_v4());

        // Simple base64 encoding for demo - use proper crypto in production
        Ok(STANDARD.encode(data))
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
                    state: SessionState::Authenticated,
                    session_state: None, // No change
                })
            } else {
                Ok(SessionCheckResponse {
                    state: SessionState::Unauthenticated,
                    session_state: None,
                })
            }
        } else {
            Ok(SessionCheckResponse {
                state: SessionState::Unauthenticated,
                session_state: None,
            })
        }
    }

    /// End session (logout)
    pub fn end_session(&mut self, session_id: &str) -> Result<OidcSession> {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.state = SessionState::Unauthenticated;
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
                var sessionState = getCookie('session_state');
                if (sessionState) {{
                    // Notify parent window of session check
                    window.parent.postMessage({{
                        type: 'session_check',
                        client_id: client_id,
                        session_state: sessionState,
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
            .unwrap()
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
        assert_eq!(session.state, SessionState::Authenticated);
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


