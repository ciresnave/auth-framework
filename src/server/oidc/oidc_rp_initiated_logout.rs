//! OpenID Connect RP-Initiated Logout orchestration.
//!
//! This module implements the request validation and session termination flow for
//! RP-Initiated Logout while reusing the existing front-channel and back-channel
//! logout transports for RP notification.

use crate::errors::{AuthError, Result};
use crate::server::oidc::oidc_session_management::{OidcSession, SessionManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// RP-initiated logout request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpInitiatedLogoutRequest {
    /// Client initiating the logout request.
    pub client_id: String,
    /// Subject whose sessions should be terminated.
    pub sub: String,
    /// Optional current session identifier.
    pub session_id: Option<String>,
    /// Optional ID token hint. Presence may be required for redirect validation.
    pub id_token_hint: Option<String>,
    /// Optional post-logout redirect URI requested by the RP.
    pub post_logout_redirect_uri: Option<String>,
    /// Optional opaque state to echo back to the RP.
    pub state: Option<String>,
}

/// Per-client RP-initiated logout registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientLogoutConfig {
    /// OAuth/OIDC client identifier.
    pub client_id: String,
    /// Exact post-logout redirect URIs allowed for this client.
    pub post_logout_redirect_uris: Vec<String>,
    /// Optional front-channel logout endpoint.
    pub frontchannel_logout_uri: Option<String>,
    /// Optional back-channel logout endpoint.
    pub backchannel_logout_uri: Option<String>,
}

/// RP-initiated logout manager configuration.
#[derive(Debug, Clone)]
pub struct RpInitiatedLogoutConfig {
    /// Enable RP-initiated logout handling.
    pub enabled: bool,
    /// Issuer identifier used in logout notification metadata.
    pub issuer: String,
    /// Require an ID token hint when a post-logout redirect URI is supplied.
    pub require_id_token_hint_for_redirect: bool,
    /// Allow loopback HTTP redirects for local development.
    pub allow_localhost_redirects: bool,
    /// End all sessions for the subject rather than only the supplied session ID.
    pub logout_all_user_sessions: bool,
}

impl Default for RpInitiatedLogoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            require_id_token_hint_for_redirect: true,
            allow_localhost_redirects: true,
            logout_all_user_sessions: true,
        }
    }
}

/// Notification target for downstream front-channel or back-channel logout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogoutNotificationTarget {
    /// Client that should receive the logout notification.
    pub client_id: String,
    /// Session identifier associated with that RP session.
    pub sid: Option<String>,
    /// Optional front-channel logout URI.
    pub frontchannel_logout_uri: Option<String>,
    /// Optional back-channel logout URI.
    pub backchannel_logout_uri: Option<String>,
}

/// RP-initiated logout result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpInitiatedLogoutResponse {
    /// Whether request validation and session termination succeeded.
    pub success: bool,
    /// Session IDs terminated by this logout request.
    pub ended_sessions: Vec<String>,
    /// Redirect URI approved for the initiating client.
    pub post_logout_redirect_uri: Option<String>,
    /// Opaque state echoed back to the initiating client.
    pub state: Option<String>,
    /// Logout notifications that should be delivered to other RPs.
    pub logout_notifications: Vec<LogoutNotificationTarget>,
    /// Issuer identifier to include in downstream logout notifications.
    pub iss: String,
}

/// RP-initiated logout manager.
#[derive(Debug, Clone)]
pub struct RpInitiatedLogoutManager {
    config: RpInitiatedLogoutConfig,
    session_manager: SessionManager,
    client_configs: HashMap<String, ClientLogoutConfig>,
}

impl RpInitiatedLogoutManager {
    /// Create a new RP-initiated logout manager.
    pub fn new(config: RpInitiatedLogoutConfig, session_manager: SessionManager) -> Self {
        Self {
            config,
            session_manager,
            client_configs: HashMap::new(),
        }
    }

    /// Register or replace a client logout configuration.
    pub fn register_client_config(&mut self, client_config: ClientLogoutConfig) -> Result<()> {
        self.validate_client_config(&client_config)?;
        self.client_configs
            .insert(client_config.client_id.clone(), client_config);
        Ok(())
    }

    /// Process an RP-initiated logout request.
    pub fn process_logout(
        &mut self,
        request: RpInitiatedLogoutRequest,
    ) -> Result<RpInitiatedLogoutResponse> {
        if !self.config.enabled {
            return Err(AuthError::validation("RP-initiated logout is not enabled"));
        }

        let client_config = self
            .client_configs
            .get(&request.client_id)
            .ok_or_else(|| AuthError::validation("Unknown client for RP-initiated logout"))?;

        if let Some(post_logout_redirect_uri) = &request.post_logout_redirect_uri {
            if self.config.require_id_token_hint_for_redirect && request.id_token_hint.is_none() {
                return Err(AuthError::validation(
                    "id_token_hint required for post_logout_redirect_uri validation",
                ));
            }

            self.validate_post_logout_redirect_uri(client_config, post_logout_redirect_uri)?;
        }

        let sessions_to_end = self.collect_sessions_to_end(&request)?;
        let logout_notifications = self.build_logout_notifications(&request, &sessions_to_end);

        let mut ended_sessions = Vec::with_capacity(sessions_to_end.len());
        for session in sessions_to_end {
            let ended = self.session_manager.end_session(&session.session_id)?;
            ended_sessions.push(ended.session_id);
        }

        Ok(RpInitiatedLogoutResponse {
            success: true,
            ended_sessions,
            post_logout_redirect_uri: request.post_logout_redirect_uri,
            state: request.state,
            logout_notifications,
            iss: self.config.issuer.clone(),
        })
    }

    fn validate_client_config(&self, client_config: &ClientLogoutConfig) -> Result<()> {
        if client_config.client_id.is_empty() {
            return Err(AuthError::validation("Client ID cannot be empty"));
        }

        for uri in &client_config.post_logout_redirect_uris {
            self.validate_logout_uri(uri)?;
        }

        if let Some(uri) = &client_config.frontchannel_logout_uri {
            self.validate_logout_uri(uri)?;
        }

        if let Some(uri) = &client_config.backchannel_logout_uri {
            self.validate_logout_uri(uri)?;
        }

        Ok(())
    }

    fn validate_post_logout_redirect_uri(
        &self,
        client_config: &ClientLogoutConfig,
        uri: &str,
    ) -> Result<()> {
        self.validate_logout_uri(uri)?;

        if !client_config
            .post_logout_redirect_uris
            .iter()
            .any(|registered| registered == uri)
        {
            return Err(AuthError::validation(
                "post_logout_redirect_uri not registered for client",
            ));
        }

        Ok(())
    }

    fn validate_logout_uri(&self, uri: &str) -> Result<()> {
        let parsed = Url::parse(uri)
            .map_err(|e| AuthError::validation(format!("Invalid logout URI: {e}")))?;

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(AuthError::validation(
                "Logout URIs must not include query parameters or fragments",
            ));
        }

        if parsed.username() != "" || parsed.password().is_some() {
            return Err(AuthError::validation(
                "Logout URIs must not embed user credentials",
            ));
        }

        match parsed.scheme() {
            "https" => Ok(()),
            "http" if self.config.allow_localhost_redirects && is_loopback_host(&parsed) => Ok(()),
            _ => Err(AuthError::validation(
                "Logout URIs must use HTTPS or loopback HTTP",
            )),
        }
    }

    fn collect_sessions_to_end(
        &self,
        request: &RpInitiatedLogoutRequest,
    ) -> Result<Vec<OidcSession>> {
        if self.config.logout_all_user_sessions {
            let sessions: Vec<OidcSession> = self
                .session_manager
                .get_sessions_for_subject(&request.sub)
                .into_iter()
                .cloned()
                .collect();

            if sessions.is_empty() {
                return Err(AuthError::validation(
                    "No active sessions found for subject",
                ));
            }

            return Ok(sessions);
        }

        let session_id = request
            .session_id
            .as_deref()
            .ok_or_else(|| AuthError::validation("session_id is required for targeted logout"))?;

        let session = self
            .session_manager
            .get_session(session_id)
            .cloned()
            .ok_or_else(|| AuthError::validation("Session not found"))?;

        if session.sub != request.sub {
            return Err(AuthError::validation(
                "Session subject does not match logout request subject",
            ));
        }

        Ok(vec![session])
    }

    fn build_logout_notifications(
        &self,
        request: &RpInitiatedLogoutRequest,
        sessions_to_end: &[OidcSession],
    ) -> Vec<LogoutNotificationTarget> {
        sessions_to_end
            .iter()
            .filter(|session| session.client_id != request.client_id)
            .filter_map(|session| {
                let config = self.client_configs.get(&session.client_id)?;
                if config.frontchannel_logout_uri.is_none()
                    && config.backchannel_logout_uri.is_none()
                {
                    return None;
                }

                Some(LogoutNotificationTarget {
                    client_id: session.client_id.clone(),
                    sid: Some(session.browser_session_id.clone()),
                    frontchannel_logout_uri: config.frontchannel_logout_uri.clone(),
                    backchannel_logout_uri: config.backchannel_logout_uri.clone(),
                })
            })
            .collect()
    }
}

fn is_loopback_host(parsed: &Url) -> bool {
    matches!(parsed.host_str(), Some("localhost") | Some("127.0.0.1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::oidc::oidc_session_management::SessionManagementConfig;

    fn create_manager() -> (RpInitiatedLogoutManager, String, String) {
        let mut session_manager = SessionManager::new(SessionManagementConfig::default());

        let session_a = session_manager
            .create_session("user-1".to_string(), "client-a".to_string(), HashMap::new())
            .unwrap();
        let session_b = session_manager
            .create_session("user-1".to_string(), "client-b".to_string(), HashMap::new())
            .unwrap();

        let mut manager =
            RpInitiatedLogoutManager::new(RpInitiatedLogoutConfig::default(), session_manager);

        manager
            .register_client_config(ClientLogoutConfig {
                client_id: "client-a".to_string(),
                post_logout_redirect_uris: vec![
                    "https://client-a.example.com/logout-complete".to_string(),
                ],
                frontchannel_logout_uri: Some(
                    "https://client-a.example.com/frontchannel-logout".to_string(),
                ),
                backchannel_logout_uri: None,
            })
            .unwrap();
        manager
            .register_client_config(ClientLogoutConfig {
                client_id: "client-b".to_string(),
                post_logout_redirect_uris: vec![
                    "https://client-b.example.com/logout-complete".to_string(),
                ],
                frontchannel_logout_uri: Some(
                    "https://client-b.example.com/frontchannel-logout".to_string(),
                ),
                backchannel_logout_uri: Some(
                    "https://client-b.example.com/backchannel-logout".to_string(),
                ),
            })
            .unwrap();

        (manager, session_a.session_id, session_b.session_id)
    }

    #[test]
    fn test_process_logout_ends_all_subject_sessions() {
        let (mut manager, session_a, session_b) = create_manager();

        let response = manager
            .process_logout(RpInitiatedLogoutRequest {
                client_id: "client-a".to_string(),
                sub: "user-1".to_string(),
                session_id: Some(session_a.clone()),
                id_token_hint: Some("id-token".to_string()),
                post_logout_redirect_uri: Some(
                    "https://client-a.example.com/logout-complete".to_string(),
                ),
                state: Some("opaque-state".to_string()),
            })
            .unwrap();

        assert!(response.success);
        assert_eq!(response.ended_sessions.len(), 2);
        assert!(response.ended_sessions.contains(&session_a));
        assert!(response.ended_sessions.contains(&session_b));
        assert_eq!(response.logout_notifications.len(), 1);
        assert_eq!(response.logout_notifications[0].client_id, "client-b");
        assert_eq!(
            response.post_logout_redirect_uri.as_deref(),
            Some("https://client-a.example.com/logout-complete")
        );
        assert_eq!(response.state.as_deref(), Some("opaque-state"));
    }

    #[test]
    fn test_process_logout_rejects_unregistered_redirect_uri() {
        let (mut manager, session_a, _) = create_manager();

        let error = manager
            .process_logout(RpInitiatedLogoutRequest {
                client_id: "client-a".to_string(),
                sub: "user-1".to_string(),
                session_id: Some(session_a),
                id_token_hint: Some("id-token".to_string()),
                post_logout_redirect_uri: Some("https://evil.example.com/logout".to_string()),
                state: None,
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("post_logout_redirect_uri not registered for client")
        );
    }

    #[test]
    fn test_process_logout_requires_id_token_hint_for_redirect_validation() {
        let (mut manager, session_a, _) = create_manager();

        let error = manager
            .process_logout(RpInitiatedLogoutRequest {
                client_id: "client-a".to_string(),
                sub: "user-1".to_string(),
                session_id: Some(session_a),
                id_token_hint: None,
                post_logout_redirect_uri: Some(
                    "https://client-a.example.com/logout-complete".to_string(),
                ),
                state: None,
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("id_token_hint required for post_logout_redirect_uri validation")
        );
    }
}
