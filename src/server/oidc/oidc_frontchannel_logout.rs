//! OpenID Connect Front-Channel Logout Implementation
//!
//! This module implements the "OpenID Connect Front-Channel Logout 1.0" specification,
//! which allows OpenID Providers to notify Relying Parties about logout events through
//! front-channel (browser) communication using invisible iframes.
//!
//! # Features
//!
//! - Front-channel logout notification management
//! - Invisible iframe-based RP notification
//! - Session identifier (sid) tracking
//! - Logout token generation and validation
//! - Integration with RP-initiated logout

use crate::errors::{AuthError, Result};
use crate::server::oidc::oidc_session_management::{OidcSession, SessionManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use uuid::Uuid;

/// Front-channel logout request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontChannelLogoutRequest {
    /// Session ID being logged out
    pub session_id: String,
    /// Subject identifier
    pub sub: String,
    /// Session identifier (sid) claim value
    pub sid: Option<String>,
    /// Issuer identifier
    pub iss: String,
    /// Initiating client ID (if logout was client-initiated)
    pub initiating_client_id: Option<String>,
}

/// Front-channel logout response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontChannelLogoutResponse {
    /// Whether logout notifications were sent successfully
    pub success: bool,
    /// Number of RPs notified
    pub notified_rps: usize,
    /// List of RPs that were notified
    pub notified_clients: Vec<String>,
    /// List of RPs that failed to be notified
    pub failed_notifications: Vec<FailedNotification>,
    /// HTML content for front-channel logout page
    pub logout_page_html: String,
}

/// Failed notification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedNotification {
    /// Client ID that failed
    pub client_id: String,
    /// Front-channel logout URI that failed
    pub frontchannel_logout_uri: String,
    /// Error description
    pub error: String,
}

/// Front-channel logout configuration
#[derive(Debug, Clone)]
pub struct FrontChannelLogoutConfig {
    /// Enable front-channel logout
    pub enabled: bool,
    /// Maximum time to wait for iframe loads (milliseconds)
    pub iframe_timeout_ms: u64,
    /// Maximum number of concurrent iframe notifications
    pub max_concurrent_notifications: usize,
    /// Include session_state parameter in logout URIs
    pub include_session_state: bool,
    /// Default iframe dimensions
    pub iframe_width: u32,
    pub iframe_height: u32,
    /// Enable JavaScript console logging for debugging
    pub enable_debug_logging: bool,
}

impl Default for FrontChannelLogoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            iframe_timeout_ms: 5000, // 5 seconds
            max_concurrent_notifications: 10,
            include_session_state: true,
            iframe_width: 0,  // Hidden iframe
            iframe_height: 0, // Hidden iframe
            enable_debug_logging: false,
        }
    }
}

/// RP front-channel logout configuration
#[derive(Debug, Clone)]
pub struct RpFrontChannelConfig {
    /// Client ID
    pub client_id: String,
    /// Front-channel logout URI
    pub frontchannel_logout_uri: String,
    /// Whether RP requires session_state parameter
    pub frontchannel_logout_session_required: bool,
    /// Custom timeout for this RP (if different from global)
    pub custom_timeout_ms: Option<u64>,
}

/// Front-channel logout manager
#[derive(Debug, Clone)]
pub struct FrontChannelLogoutManager {
    /// Configuration
    config: FrontChannelLogoutConfig,
    /// Session manager for session tracking
    session_manager: SessionManager,
    /// Registered RP configurations
    rp_configs: HashMap<String, RpFrontChannelConfig>,
    /// Active logout requests tracking
    active_logouts: HashMap<String, SystemTime>,
}

impl FrontChannelLogoutManager {
    /// Create new front-channel logout manager
    pub fn new(config: FrontChannelLogoutConfig, session_manager: SessionManager) -> Self {
        Self {
            config,
            session_manager,
            rp_configs: HashMap::new(),
            active_logouts: HashMap::new(),
        }
    }

    /// Register RP front-channel logout configuration
    pub fn register_rp_config(&mut self, rp_config: RpFrontChannelConfig) {
        self.rp_configs
            .insert(rp_config.client_id.clone(), rp_config);
    }

    /// Process front-channel logout request
    pub async fn process_frontchannel_logout(
        &mut self,
        request: FrontChannelLogoutRequest,
    ) -> Result<FrontChannelLogoutResponse> {
        if !self.config.enabled {
            return Err(AuthError::validation("Front-channel logout is not enabled"));
        }

        // Find all sessions for the subject
        let user_sessions = self.session_manager.get_sessions_for_subject(&request.sub);

        // Determine which RPs need to be notified
        let mut rps_to_notify = Vec::new();
        let mut notified_clients = Vec::new();
        let mut failed_notifications = Vec::new();

        for session in user_sessions {
            // Skip the session being logged out to avoid self-notification
            if session.session_id == request.session_id {
                continue;
            }

            // Check if this client has front-channel logout configured
            if let Some(rp_config) = self.rp_configs.get(&session.client_id) {
                // Skip the initiating client if this is a client-initiated logout
                if let Some(ref initiating_client) = request.initiating_client_id
                    && &session.client_id == initiating_client
                {
                    continue;
                }

                rps_to_notify.push((session.clone(), rp_config.clone()));
            }
        }

        // Generate front-channel logout URLs for each RP
        let mut iframe_urls = Vec::new();
        for (session, rp_config) in &rps_to_notify {
            match self.build_frontchannel_logout_url(session, rp_config, &request) {
                Ok(url) => {
                    iframe_urls.push((
                        rp_config.client_id.clone(),
                        url,
                        rp_config.custom_timeout_ms,
                    ));
                    notified_clients.push(rp_config.client_id.clone());
                }
                Err(e) => {
                    failed_notifications.push(FailedNotification {
                        client_id: rp_config.client_id.clone(),
                        frontchannel_logout_uri: rp_config.frontchannel_logout_uri.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        // Generate the HTML page with hidden iframes
        let logout_page_html = self.generate_frontchannel_logout_html(&iframe_urls);

        // Track this logout request
        let logout_id = Uuid::new_v4().to_string();
        self.active_logouts.insert(logout_id, SystemTime::now());

        Ok(FrontChannelLogoutResponse {
            success: failed_notifications.is_empty(),
            notified_rps: notified_clients.len(),
            notified_clients,
            failed_notifications,
            logout_page_html,
        })
    }

    /// Build front-channel logout URL for an RP
    fn build_frontchannel_logout_url(
        &self,
        session: &OidcSession,
        rp_config: &RpFrontChannelConfig,
        logout_request: &FrontChannelLogoutRequest,
    ) -> Result<String> {
        let mut url = rp_config.frontchannel_logout_uri.clone();
        let mut params = Vec::new();

        // Add issuer parameter
        params.push(format!("iss={}", urlencoding::encode(&logout_request.iss)));

        // Add session identifier if available and required/configured
        if self.config.include_session_state || rp_config.frontchannel_logout_session_required {
            if let Some(sid) = &logout_request.sid {
                params.push(format!("sid={}", urlencoding::encode(sid)));
            } else {
                // Generate sid from session if not provided
                let sid = format!("sess_{}", &session.session_id[..8]);
                params.push(format!("sid={}", urlencoding::encode(&sid)));
            }
        }

        // Combine URL with parameters
        let separator = if url.contains('?') { "&" } else { "?" };
        if !params.is_empty() {
            url = format!("{}{}{}", url, separator, params.join("&"));
        }

        // Validate the resulting URL
        if !self.is_valid_frontchannel_url(&url) {
            return Err(AuthError::validation("Invalid front-channel logout URL"));
        }

        Ok(url)
    }

    /// Validate front-channel logout URL
    fn is_valid_frontchannel_url(&self, url: &str) -> bool {
        // Basic URL validation
        if url.is_empty() {
            return false;
        }

        // Must be HTTPS in production (allow HTTP for localhost development)
        if !url.starts_with("https://")
            && !url.starts_with("http://localhost")
            && !url.starts_with("http://127.0.0.1")
        {
            return false;
        }

        // Check for prohibited characters that could cause issues
        if url.contains('\n') || url.contains('\r') || url.contains('<') || url.contains('>') {
            return false;
        }

        true
    }

    /// Generate HTML page with hidden iframes for front-channel logout
    fn generate_frontchannel_logout_html(
        &self,
        iframe_urls: &[(String, String, Option<u64>)],
    ) -> String {
        let mut iframes_html = String::new();
        let mut timeout_scripts = String::new();

        for (i, (client_id, url, custom_timeout)) in iframe_urls.iter().enumerate() {
            let timeout = custom_timeout.unwrap_or(self.config.iframe_timeout_ms);

            iframes_html.push_str(&format!(
                r#"        <iframe id="fc_logout_{}" src="{}" width="{}" height="{}" style="display:none; visibility:hidden;"
                onload="handleIframeLoad('{}')"
                onerror="handleIframeError('{}')"></iframe>
"#,
                i, url, self.config.iframe_width, self.config.iframe_height, client_id, client_id
            ));

            // Add timeout for each iframe
            timeout_scripts.push_str(&format!(
                r#"            setTimeout(function() {{
                handleIframeTimeout('{}', {});
            }}, {});
"#,
                client_id, i, timeout
            ));
        }

        let debug_logging = if self.config.enable_debug_logging {
            "const DEBUG_LOGGING = true;"
        } else {
            "const DEBUG_LOGGING = false;"
        };

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Logging Out...</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            text-align: center;
            background-color: #f8f9fa;
        }}
        .logout-container {{
            max-width: 400px;
            margin: 50px auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .status {{ margin-top: 20px; color: #666; }}
        .complete {{ color: #28a745; font-weight: bold; }}
        .error {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="logout-container">
        <h1>🔐 Logging Out</h1>
        <div class="spinner"></div>
        <div id="status" class="status">
            Notifying applications of logout...
        </div>
        <div id="progress" class="status">
            <span id="completed">0</span> of <span id="total">{}</span> notifications sent
        </div>
    </div>

    <!-- Hidden iframes for front-channel logout notifications -->
{}

    <script>
        {}

        let completedNotifications = 0;
        let totalNotifications = {};
        let errors = [];

        function log(message) {{
            if (DEBUG_LOGGING) {{
                console.log('[FrontChannel Logout] ' + message);
            }}
        }}

        function handleIframeLoad(clientId) {{
            completedNotifications++;
            log('Logout notification sent to: ' + clientId);
            updateProgress();
        }}

        function handleIframeError(clientId) {{
            completedNotifications++;
            errors.push(clientId);
            log('Logout notification failed for: ' + clientId);
            updateProgress();
        }}

        function handleIframeTimeout(clientId, iframeIndex) {{
            const iframe = document.getElementById('fc_logout_' + iframeIndex);
            if (iframe && iframe.style.display !== 'none') {{
                completedNotifications++;
                errors.push(clientId + ' (timeout)');
                log('Logout notification timeout for: ' + clientId);
                updateProgress();
            }}
        }}

        function updateProgress() {{
            document.getElementById('completed').textContent = completedNotifications;

            if (completedNotifications >= totalNotifications) {{
                const statusEl = document.getElementById('status');
                if (errors.length === 0) {{
                    statusEl.textContent = 'Logout complete. All applications have been notified.';
                    statusEl.className = 'status complete';
                }} else {{
                    statusEl.textContent = 'Logout complete with some errors.';
                    statusEl.className = 'status error';
                    log('Notifications failed for: ' + errors.join(', '));
                }}

                // Auto-close or redirect after a delay
                setTimeout(function() {{
                    window.close();
                }}, 2000);
            }}
        }}

        // Set up timeouts for all iframes
        log('Starting front-channel logout for ' + totalNotifications + ' applications');
{}

        // Fallback timeout to ensure page doesn't hang
        setTimeout(function() {{
            if (completedNotifications < totalNotifications) {{
                log('Global timeout reached, completing logout process');
                completedNotifications = totalNotifications;
                updateProgress();
            }}
        }}, {});
    </script>
</body>
</html>"#,
            iframe_urls.len(),
            iframes_html,
            debug_logging,
            iframe_urls.len(),
            timeout_scripts,
            self.config.iframe_timeout_ms * 2 // Global timeout is double the iframe timeout
        )
    }

    /// Clean up expired logout tracking
    pub fn cleanup_expired_logouts(&mut self) -> usize {
        let now = SystemTime::now();
        let initial_count = self.active_logouts.len();

        self.active_logouts.retain(|_, timestamp| {
            now.duration_since(*timestamp)
                .map(|d| d.as_secs() < 3600) // Keep for 1 hour
                .unwrap_or(false)
        });

        initial_count - self.active_logouts.len()
    }

    /// Get discovery metadata for front-channel logout
    pub fn get_discovery_metadata(&self) -> HashMap<String, serde_json::Value> {
        let mut metadata = HashMap::new();

        if self.config.enabled {
            metadata.insert(
                "frontchannel_logout_supported".to_string(),
                serde_json::Value::Bool(true),
            );

            metadata.insert(
                "frontchannel_logout_session_supported".to_string(),
                serde_json::Value::Bool(true),
            );
        }

        metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::oidc::oidc_session_management::SessionManagementConfig;

    fn create_test_manager() -> FrontChannelLogoutManager {
        let config = FrontChannelLogoutConfig::default();
        let session_manager = SessionManager::new(SessionManagementConfig::default());
        FrontChannelLogoutManager::new(config, session_manager)
    }

    #[test]
    fn test_frontchannel_url_validation() {
        let manager = create_test_manager();

        // Valid HTTPS URL
        assert!(
            manager.is_valid_frontchannel_url("https://client.example.com/frontchannel_logout")
        );

        // Valid localhost HTTP (for development)
        assert!(manager.is_valid_frontchannel_url("http://localhost:8080/logout"));

        // Invalid - not HTTPS and not localhost
        assert!(!manager.is_valid_frontchannel_url("http://example.com/logout"));

        // Invalid - contains dangerous characters
        assert!(!manager.is_valid_frontchannel_url("https://example.com/logout\n"));
        assert!(!manager.is_valid_frontchannel_url("https://example.com/logout<script>"));

        // Invalid - empty
        assert!(!manager.is_valid_frontchannel_url(""));
    }

    #[tokio::test]
    async fn test_frontchannel_logout_html_generation() {
        let manager = create_test_manager();

        let iframe_urls = vec![
            (
                "client1".to_string(),
                "https://client1.example.com/logout".to_string(),
                None,
            ),
            (
                "client2".to_string(),
                "https://client2.example.com/logout".to_string(),
                Some(3000),
            ),
        ];

        let html = manager.generate_frontchannel_logout_html(&iframe_urls);

        println!("Generated HTML: {}", html);

        assert!(html.contains("https://client1.example.com/logout"));
        assert!(html.contains("https://client2.example.com/logout"));
        assert!(html.contains("fc_logout_0"));
        assert!(html.contains("fc_logout_1"));
        assert!(html.contains("of <span id=\"total\">2</span> notifications"));
        assert!(html.contains("handleIframeLoad"));
        assert!(html.contains("handleIframeError"));
    }

    #[test]
    fn test_frontchannel_logout_url_building() {
        let manager = create_test_manager();

        let session = OidcSession {
            session_id: "session123".to_string(),
            sub: "user123".to_string(),
            client_id: "client456".to_string(),
            created_at: 1000000000,
            last_activity: 1000001000,
            expires_at: 1000002000,
            state: crate::server::oidc::oidc_session_management::SessionState::Authenticated,
            browser_session_id: "browser_session_123".to_string(),
            logout_tokens: vec![],
            metadata: HashMap::new(),
        };

        let rp_config = RpFrontChannelConfig {
            client_id: "client456".to_string(),
            frontchannel_logout_uri: "https://client.example.com/fc_logout".to_string(),
            frontchannel_logout_session_required: true,
            custom_timeout_ms: None,
        };

        let logout_request = FrontChannelLogoutRequest {
            session_id: "other_session".to_string(),
            sub: "user123".to_string(),
            sid: Some("sid123".to_string()),
            iss: "https://op.example.com".to_string(),
            initiating_client_id: None,
        };

        let url = manager
            .build_frontchannel_logout_url(&session, &rp_config, &logout_request)
            .unwrap();

        assert!(url.contains("https://client.example.com/fc_logout"));
        assert!(url.contains("iss=https%3A%2F%2Fop.example.com"));
        assert!(url.contains("sid=sid123"));
    }
}


