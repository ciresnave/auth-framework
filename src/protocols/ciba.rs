//! OpenID Connect Client-Initiated Backchannel Authentication (CIBA).
//!
//! Implements the CIBA flow where a *consumption device* (e.g. a POS terminal
//! or call-center application) authenticates the user on a separate
//! *authentication device* (e.g. the user's phone) without a browser redirect.
//!
//! # Modes
//!
//! - **Poll** — the client repeatedly polls the token endpoint.
//! - **Ping** — the OP sends a notification to the client's callback URI, then the client
//!   fetches the token.
//! - **Push** — the OP pushes the token directly to the client's callback URI.
//!
//! # References
//!
//! - [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
//! - [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449) (optional token binding)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ── Configuration ───────────────────────────────────────────────────

/// CIBA token delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibaMode {
    Poll,
    Ping,
    Push,
}

/// Configuration for a CIBA provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaConfig {
    /// Backchannel authentication endpoint URL.
    pub auth_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// Supported delivery modes.
    pub modes_supported: Vec<CibaMode>,
    /// Default polling interval in seconds.
    #[serde(default = "default_interval")]
    pub default_interval: u64,
    /// Maximum auth request lifetime in seconds.
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
    /// Optional user code support.
    #[serde(default)]
    pub user_code_supported: bool,
}

fn default_interval() -> u64 {
    5
}
fn default_expires_in() -> u64 {
    300
}

// ── Authentication Request ──────────────────────────────────────────

/// Hint identifying the end-user to authenticate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginHint {
    /// Subject identifier.
    LoginHintToken(String),
    /// An id_token_hint.
    IdTokenHint(String),
    /// Login hint (e.g. email or phone).
    LoginHint(String),
}

/// A backchannel authentication request sent by the consumption device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaAuthRequest {
    /// The scopes requested.
    pub scope: String,
    /// Hint identifying the user.
    pub hint: LoginHint,
    /// Human-readable binding message shown on the authentication device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<String>,
    /// User code entered on the consumption device (for user-code mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    /// Requested expiry (seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_expiry: Option<u64>,
    /// ACR values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,
    /// Client notification token (required for ping/push modes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_notification_token: Option<String>,
}

/// Successful response to a backchannel authentication request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaAuthResponse {
    /// Unique identifier for the authentication request.
    pub auth_req_id: String,
    /// Expires-in (seconds).
    pub expires_in: u64,
    /// Minimum polling interval (seconds) — included for poll / ping modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
}

// ── Token Request / Response ────────────────────────────────────────

/// Pending request state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibaRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Token response after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CibaTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Error response per CIBA spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CibaError {
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    AccessDenied,
    InvalidRequest,
    UnauthorizedClient,
    InvalidScope,
    InvalidBindingMessage,
}

// ── Internal state ──────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PendingAuth {
    request: CibaAuthRequest,
    status: CibaRequestStatus,
    created_at: u64,
    expires_at: u64,
    last_polled: Option<u64>,
    mode: CibaMode,
    subject: Option<String>,
    token_response: Option<CibaTokenResponse>,
}

// ── CIBA Provider ───────────────────────────────────────────────────

/// In-memory CIBA provider implementing Auth Request → Token lifecycle.
pub struct CibaProvider {
    config: CibaConfig,
    /// `auth_req_id → PendingAuth`
    pending: Arc<RwLock<HashMap<String, PendingAuth>>>,
    /// Token generator function (auth_req_id, subject, scope) → CibaTokenResponse.
    token_generator: Arc<dyn Fn(&str, &str, &str) -> CibaTokenResponse + Send + Sync>,
}

impl CibaProvider {
    /// Create a provider with the given config and token generator.
    pub fn new(
        config: CibaConfig,
        token_generator: impl Fn(&str, &str, &str) -> CibaTokenResponse + Send + Sync + 'static,
    ) -> Self {
        Self {
            config,
            pending: Arc::new(RwLock::new(HashMap::new())),
            token_generator: Arc::new(token_generator),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    fn generate_auth_req_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    // ── Phase 1: Authentication Request ─────────────────────────

    /// Process a backchannel authentication request.
    pub async fn authenticate(
        &self,
        request: CibaAuthRequest,
        mode: CibaMode,
    ) -> Result<CibaAuthResponse> {
        // Validate mode is supported
        if !self.config.modes_supported.contains(&mode) {
            return Err(AuthError::validation(&format!(
                "CIBA mode {:?} not supported",
                mode
            )));
        }

        // Validate binding message length
        if let Some(ref msg) = request.binding_message {
            if msg.is_empty() || msg.len() > 256 {
                return Err(AuthError::validation(
                    "Binding message must be 1-256 characters",
                ));
            }
        }

        // Ping/push requires client_notification_token
        if matches!(mode, CibaMode::Ping | CibaMode::Push)
            && request.client_notification_token.is_none()
        {
            return Err(AuthError::validation(
                "client_notification_token required for ping/push mode",
            ));
        }

        // Validate scope is non-empty
        if request.scope.is_empty() {
            return Err(AuthError::validation("scope is required"));
        }

        let now = Self::now_secs();
        let expires_in = request
            .requested_expiry
            .unwrap_or(self.config.expires_in)
            .min(self.config.expires_in);

        let auth_req_id = Self::generate_auth_req_id();

        let pending = PendingAuth {
            request,
            status: CibaRequestStatus::Pending,
            created_at: now,
            expires_at: now + expires_in,
            last_polled: None,
            mode,
            subject: None,
            token_response: None,
        };

        self.pending
            .write()
            .await
            .insert(auth_req_id.clone(), pending);

        Ok(CibaAuthResponse {
            auth_req_id,
            expires_in,
            interval: if matches!(mode, CibaMode::Poll | CibaMode::Ping) {
                Some(self.config.default_interval)
            } else {
                None
            },
        })
    }

    // ── Phase 2: User consent (called by authentication device) ─

    /// Approve an authentication request (called when user consents).
    pub async fn approve(&self, auth_req_id: &str, subject: &str) -> Result<()> {
        let mut pending = self.pending.write().await;
        let entry = pending
            .get_mut(auth_req_id)
            .ok_or_else(|| AuthError::validation("Unknown auth_req_id"))?;

        if entry.status != CibaRequestStatus::Pending {
            return Err(AuthError::validation(&format!(
                "Request already {:?}",
                entry.status
            )));
        }

        let now = Self::now_secs();
        if now > entry.expires_at {
            entry.status = CibaRequestStatus::Expired;
            return Err(AuthError::validation("Request has expired"));
        }

        // Generate tokens
        let token_response = (self.token_generator)(auth_req_id, subject, &entry.request.scope);

        entry.status = CibaRequestStatus::Approved;
        entry.subject = Some(subject.to_string());
        entry.token_response = Some(token_response);
        Ok(())
    }

    /// Deny an authentication request.
    pub async fn deny(&self, auth_req_id: &str) -> Result<()> {
        let mut pending = self.pending.write().await;
        let entry = pending
            .get_mut(auth_req_id)
            .ok_or_else(|| AuthError::validation("Unknown auth_req_id"))?;

        if entry.status != CibaRequestStatus::Pending {
            return Err(AuthError::validation(&format!(
                "Request already {:?}",
                entry.status
            )));
        }

        entry.status = CibaRequestStatus::Denied;
        Ok(())
    }

    // ── Phase 3: Token retrieval (poll mode) ────────────────────

    /// Poll for the token (used in poll mode).
    ///
    /// Returns `Ok(CibaTokenResponse)` on success,
    /// `Err` with appropriate CIBA error on pending/denied/expired/slow-down.
    pub async fn poll_token(
        &self,
        auth_req_id: &str,
    ) -> std::result::Result<CibaTokenResponse, CibaError> {
        let mut pending = self.pending.write().await;
        let entry = pending
            .get_mut(auth_req_id)
            .ok_or(CibaError::InvalidRequest)?;

        let now = Self::now_secs();

        // Check expiry
        if now > entry.expires_at {
            entry.status = CibaRequestStatus::Expired;
            return Err(CibaError::ExpiredToken);
        }

        // Slow-down check
        if let Some(last) = entry.last_polled {
            if now - last < self.config.default_interval {
                return Err(CibaError::SlowDown);
            }
        }
        entry.last_polled = Some(now);

        match entry.status {
            CibaRequestStatus::Pending => Err(CibaError::AuthorizationPending),
            CibaRequestStatus::Denied => Err(CibaError::AccessDenied),
            CibaRequestStatus::Expired => Err(CibaError::ExpiredToken),
            CibaRequestStatus::Approved => entry
                .token_response
                .clone()
                .ok_or(CibaError::InvalidRequest),
        }
    }

    /// Get the notification payload for ping/push modes.
    pub async fn get_notification(
        &self,
        auth_req_id: &str,
    ) -> Result<(CibaMode, Option<String>, Option<CibaTokenResponse>)> {
        let pending = self.pending.read().await;
        let entry = pending
            .get(auth_req_id)
            .ok_or_else(|| AuthError::validation("Unknown auth_req_id"))?;

        let client_notification_token = entry.request.client_notification_token.clone();
        let token_response = entry.token_response.clone();
        Ok((entry.mode, client_notification_token, token_response))
    }

    /// Clean up expired requests.
    pub async fn cleanup_expired(&self) {
        let now = Self::now_secs();
        self.pending
            .write()
            .await
            .retain(|_, entry| now <= entry.expires_at);
    }

    /// Get the status of an auth request.
    pub async fn get_status(&self, auth_req_id: &str) -> Option<CibaRequestStatus> {
        let pending = self.pending.read().await;
        pending.get(auth_req_id).map(|e| e.status.clone())
    }

    /// Get the total number of pending requests.
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CibaConfig {
        CibaConfig {
            auth_endpoint: "https://op.example.com/ciba".to_string(),
            token_endpoint: "https://op.example.com/token".to_string(),
            modes_supported: vec![CibaMode::Poll, CibaMode::Ping, CibaMode::Push],
            default_interval: 1,
            expires_in: 120,
            user_code_supported: false,
        }
    }

    fn test_token_gen() -> impl Fn(&str, &str, &str) -> CibaTokenResponse {
        |_req_id, subject, scope| CibaTokenResponse {
            access_token: format!("at_{subject}_{scope}"),
            token_type: "Bearer".to_string(),
            refresh_token: Some(format!("rt_{subject}")),
            expires_in: 3600,
            id_token: Some(format!("idt_{subject}")),
        }
    }

    fn poll_request() -> CibaAuthRequest {
        CibaAuthRequest {
            scope: "openid email".to_string(),
            hint: LoginHint::LoginHint("alice@example.com".to_string()),
            binding_message: Some("Confirm login on terminal 42".to_string()),
            user_code: None,
            requested_expiry: None,
            acr_values: None,
            client_notification_token: None,
        }
    }

    // ── Config serialization ────────────────────────────────────

    #[test]
    fn test_ciba_mode_serde() {
        let json = serde_json::to_string(&CibaMode::Poll).unwrap();
        assert_eq!(json, "\"poll\"");
        let parsed: CibaMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CibaMode::Poll);
    }

    #[test]
    fn test_config_serde() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CibaConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auth_endpoint, config.auth_endpoint);
        assert_eq!(parsed.modes_supported.len(), 3);
    }

    // ── Authentication request ──────────────────────────────────

    #[tokio::test]
    async fn test_auth_request_poll_mode() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let resp = provider
            .authenticate(poll_request(), CibaMode::Poll)
            .await
            .unwrap();
        assert!(!resp.auth_req_id.is_empty());
        assert!(resp.expires_in > 0);
        assert!(resp.interval.is_some());
    }

    #[tokio::test]
    async fn test_auth_request_push_mode_requires_notification_token() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let result = provider.authenticate(poll_request(), CibaMode::Push).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_request_push_mode_with_token() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let mut req = poll_request();
        req.client_notification_token = Some("cnt_abc123".to_string());
        let resp = provider.authenticate(req, CibaMode::Push).await.unwrap();
        assert!(!resp.auth_req_id.is_empty());
        assert!(resp.interval.is_none()); // Push mode has no polling interval
    }

    #[tokio::test]
    async fn test_auth_request_empty_scope_rejected() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let mut req = poll_request();
        req.scope = String::new();
        assert!(provider.authenticate(req, CibaMode::Poll).await.is_err());
    }

    #[tokio::test]
    async fn test_auth_request_invalid_binding_message() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let mut req = poll_request();
        req.binding_message = Some(String::new());
        assert!(provider.authenticate(req, CibaMode::Poll).await.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_mode_rejected() {
        let config = CibaConfig {
            modes_supported: vec![CibaMode::Poll],
            ..test_config()
        };
        let provider = CibaProvider::new(config, test_token_gen());
        let mut req = poll_request();
        req.client_notification_token = Some("token".to_string());
        assert!(provider.authenticate(req, CibaMode::Push).await.is_err());
    }

    // ── Approve / Deny ──────────────────────────────────────────

    #[tokio::test]
    async fn test_approve_and_poll() {
        // Use interval=0 so rapid successive polls don't trigger SlowDown
        let config = CibaConfig {
            default_interval: 0,
            ..test_config()
        };
        let provider = CibaProvider::new(config, test_token_gen());
        let resp = provider
            .authenticate(poll_request(), CibaMode::Poll)
            .await
            .unwrap();

        // Initially pending
        assert_eq!(
            provider.get_status(&resp.auth_req_id).await.unwrap(),
            CibaRequestStatus::Pending
        );

        // Polling before approval → authorization_pending
        let poll_result = provider.poll_token(&resp.auth_req_id).await;
        assert_eq!(poll_result.unwrap_err(), CibaError::AuthorizationPending);

        // Approve
        provider
            .approve(&resp.auth_req_id, "user:alice")
            .await
            .unwrap();
        assert_eq!(
            provider.get_status(&resp.auth_req_id).await.unwrap(),
            CibaRequestStatus::Approved
        );

        // Poll should now succeed (after interval)
        let token = provider.poll_token(&resp.auth_req_id).await.unwrap();
        assert!(token.access_token.contains("alice"));
        assert_eq!(token.token_type, "Bearer");
        assert!(token.id_token.is_some());
    }

    #[tokio::test]
    async fn test_deny_and_poll() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let resp = provider
            .authenticate(poll_request(), CibaMode::Poll)
            .await
            .unwrap();

        provider.deny(&resp.auth_req_id).await.unwrap();

        let poll_result = provider.poll_token(&resp.auth_req_id).await;
        assert_eq!(poll_result.unwrap_err(), CibaError::AccessDenied);
    }

    #[tokio::test]
    async fn test_double_approve_rejected() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let resp = provider
            .authenticate(poll_request(), CibaMode::Poll)
            .await
            .unwrap();
        provider
            .approve(&resp.auth_req_id, "user:alice")
            .await
            .unwrap();
        assert!(
            provider
                .approve(&resp.auth_req_id, "user:bob")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_approve_unknown_id() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        assert!(provider.approve("nonexistent", "user:alice").await.is_err());
    }

    // ── Expiry ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cleanup_expired() {
        let mut config = test_config();
        config.expires_in = 1; // 1 second
        let provider = CibaProvider::new(config, test_token_gen());
        let resp = provider
            .authenticate(poll_request(), CibaMode::Poll)
            .await
            .unwrap();
        assert_eq!(provider.pending_count().await, 1);

        // The request expires_in=1s, but we can't sleep. Instead, manually
        // set the entry to expired by over-riding expires_at.
        {
            let mut pending = provider.pending.write().await;
            let entry = pending.get_mut(&resp.auth_req_id).unwrap();
            entry.expires_at = 0; // Force expired
        }

        provider.cleanup_expired().await;
        assert_eq!(provider.pending_count().await, 0);
    }

    // ── Notification info ───────────────────────────────────────

    #[tokio::test]
    async fn test_get_notification_push() {
        let provider = CibaProvider::new(test_config(), test_token_gen());
        let mut req = poll_request();
        req.client_notification_token = Some("cnt_xyz".to_string());
        let resp = provider.authenticate(req, CibaMode::Push).await.unwrap();

        provider
            .approve(&resp.auth_req_id, "user:alice")
            .await
            .unwrap();

        let (mode, cnt, token) = provider.get_notification(&resp.auth_req_id).await.unwrap();
        assert_eq!(mode, CibaMode::Push);
        assert_eq!(cnt.unwrap(), "cnt_xyz");
        assert!(token.is_some());
    }

    // ── Login hint variants ─────────────────────────────────────

    #[test]
    fn test_login_hint_serde() {
        let hint = LoginHint::IdTokenHint("eyJ...".to_string());
        let json = serde_json::to_string(&hint).unwrap();
        let parsed: LoginHint = serde_json::from_str(&json).unwrap();
        match parsed {
            LoginHint::IdTokenHint(v) => assert_eq!(v, "eyJ..."),
            _ => panic!("Wrong hint variant"),
        }
    }

    // ── CibaError equality ──────────────────────────────────────

    #[test]
    fn test_ciba_error_serde() {
        let err = CibaError::SlowDown;
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(json, "\"slow_down\"");
    }
}
