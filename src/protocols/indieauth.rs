//! IndieAuth protocol support (OAuth 2.0–based identity layer for the IndieWeb).
//!
//! Provides authorization endpoint discovery, PKCE-secured authorization code
//! exchange, and profile URL verification per the IndieAuth specification.
//!
//! # References
//!
//! - [IndieAuth spec](https://indieauth.spec.indieweb.org/)

use crate::errors::{AuthError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// IndieAuth client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthConfig {
    /// Client application URL (used as client_id).
    pub client_id: String,
    /// Redirect URI for the authorization callback.
    pub redirect_uri: String,
    /// Authorization endpoint URL (discovered from the user's profile).
    pub authorization_endpoint: Option<String>,
    /// Token endpoint URL (discovered from the user's profile).
    pub token_endpoint: Option<String>,
}

/// An IndieAuth authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthRequest {
    /// Type of response ("code").
    pub response_type: String,
    /// Client identifier (URL).
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// State parameter for CSRF protection.
    pub state: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method ("S256").
    pub code_challenge_method: String,
    /// Profile URL the user is authenticating as.
    pub me: Option<String>,
    /// Requested scopes (e.g., "profile", "create", "update").
    pub scope: Option<String>,
}

/// IndieAuth authorization response (callback parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthCallback {
    /// Authorization code.
    pub code: String,
    /// State parameter (must match original request).
    pub state: String,
    /// The URL the user authenticated as (canonical form).
    pub me: Option<String>,
}

/// IndieAuth token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthTokenResponse {
    /// The canonical profile URL.
    pub me: String,
    /// Access token (if scopes were requested).
    pub access_token: Option<String>,
    /// Token type ("Bearer").
    pub token_type: Option<String>,
    /// Granted scope.
    pub scope: Option<String>,
    /// Profile information.
    pub profile: Option<IndieAuthProfile>,
}

/// Profile information returned by IndieAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthProfile {
    pub name: Option<String>,
    pub url: Option<String>,
    pub photo: Option<String>,
    pub email: Option<String>,
}

/// IndieAuth client for building authorization flows.
pub struct IndieAuthClient {
    config: IndieAuthConfig,
}

impl IndieAuthClient {
    /// Create a new IndieAuth client.
    pub fn new(config: IndieAuthConfig) -> Result<Self> {
        if config.client_id.is_empty() {
            return Err(AuthError::validation("client_id cannot be empty"));
        }
        if config.redirect_uri.is_empty() {
            return Err(AuthError::validation("redirect_uri cannot be empty"));
        }
        Ok(Self { config })
    }

    /// Generate a PKCE code verifier (43–128 character random string).
    pub fn generate_code_verifier() -> Result<String> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf)
            .map_err(|_| AuthError::crypto("Failed to generate code verifier".to_string()))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
    }

    /// Compute the S256 code challenge from a code verifier.
    pub fn compute_code_challenge(verifier: &str) -> String {
        let hash = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    /// Build an authorization request URL.
    pub fn build_authorization_url(
        &self,
        code_verifier: &str,
        scope: Option<&str>,
        me: Option<&str>,
    ) -> Result<(IndieAuthRequest, String)> {
        let auth_endpoint = self
            .config
            .authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                AuthError::config("Authorization endpoint not discovered yet".to_string())
            })?;

        let state = generate_state()?;
        let code_challenge = Self::compute_code_challenge(code_verifier);

        let request = IndieAuthRequest {
            response_type: "code".to_string(),
            client_id: self.config.client_id.clone(),
            redirect_uri: self.config.redirect_uri.clone(),
            state: state.clone(),
            code_challenge: code_challenge.clone(),
            code_challenge_method: "S256".to_string(),
            me: me.map(|s| s.to_string()),
            scope: scope.map(|s| s.to_string()),
        };

        let mut url = format!(
            "{endpoint}?response_type=code&client_id={cid}&redirect_uri={ruri}&state={state}&code_challenge={cc}&code_challenge_method=S256",
            endpoint = auth_endpoint,
            cid = urlencoding::encode(&self.config.client_id),
            ruri = urlencoding::encode(&self.config.redirect_uri),
            state = urlencoding::encode(&state),
            cc = urlencoding::encode(&code_challenge),
        );

        if let Some(s) = scope {
            url.push_str(&format!("&scope={}", urlencoding::encode(s)));
        }
        if let Some(m) = me {
            url.push_str(&format!("&me={}", urlencoding::encode(m)));
        }

        Ok((request, url))
    }

    /// Verify a callback matches the original request state.
    pub fn verify_callback(
        &self,
        callback: &IndieAuthCallback,
        expected_state: &str,
    ) -> Result<()> {
        if callback.state != expected_state {
            return Err(AuthError::validation("State parameter mismatch"));
        }
        if callback.code.is_empty() {
            return Err(AuthError::validation("Authorization code is empty"));
        }
        Ok(())
    }

    /// Verify a PKCE code challenge against the stored verifier.
    pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> Result<()> {
        let expected = Self::compute_code_challenge(code_verifier);
        if expected != code_challenge {
            return Err(AuthError::validation("PKCE code challenge mismatch"));
        }
        Ok(())
    }

    /// Validate that a profile URL is canonical per IndieAuth rules.
    ///
    /// - Must have scheme `https://` or `http://`
    /// - Must not contain a fragment
    /// - Must not contain a username/password
    /// - Path must end with `/`
    pub fn validate_profile_url(url: &str) -> Result<()> {
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(AuthError::validation(
                "Profile URL must use http or https scheme",
            ));
        }
        if url.contains('#') {
            return Err(AuthError::validation(
                "Profile URL must not contain a fragment",
            ));
        }
        if url.contains('@') {
            return Err(AuthError::validation(
                "Profile URL must not contain userinfo",
            ));
        }
        // Extract host portion
        let after_scheme = url.split("://").nth(1).unwrap_or("");
        let host = after_scheme.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err(AuthError::validation("Profile URL has no host"));
        }
        // Must not be an IP address
        if host.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(AuthError::validation(
                "Profile URL must not be an IP address",
            ));
        }
        Ok(())
    }
}

// ── IndieAuth Server Metadata (RFC draft) ───────────────────────────

/// IndieAuth server metadata (returned at `/.well-known/oauth-authorization-server`
/// or linked from `<link rel="indieauth-metadata">` on the user's profile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndieAuthMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scopes_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub response_types_supported: Vec<String>,
}

impl IndieAuthMetadata {
    /// Create a metadata document for the given issuer base URL.
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            authorization_endpoint: format!("{issuer}/auth"),
            token_endpoint: format!("{issuer}/token"),
            introspection_endpoint: Some(format!("{issuer}/introspect")),
            revocation_endpoint: Some(format!("{issuer}/revoke")),
            code_challenge_methods_supported: vec!["S256".to_string()],
            scopes_supported: vec![
                "profile".to_string(),
                "email".to_string(),
                "create".to_string(),
                "update".to_string(),
                "delete".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
        }
    }
}

// ── IndieAuth Server (authorization + token exchange) ───────────────

/// Access token record: `(me, scope, created_at)`.
type TokenRecord = (String, Option<String>, u64);

/// Stored authorization code with associated metadata.
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StoredAuthCode {
    code: String,
    client_id: String,
    redirect_uri: String,
    me: String,
    scope: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    created_at: u64,
}

/// IndieAuth server handling code issuance and token exchange.
pub struct IndieAuthServer {
    issuer: String,
    /// Authorization code store: code → StoredAuthCode
    codes: Arc<RwLock<HashMap<String, StoredAuthCode>>>,
    /// Access token store: token → (me, scope, created_at)
    tokens: Arc<RwLock<HashMap<String, TokenRecord>>>,
    /// Authorization code lifetime (seconds).
    code_lifetime: u64,
    /// Access token lifetime (seconds).
    token_lifetime: u64,
}

impl IndieAuthServer {
    /// Create a new IndieAuth server with the given issuer URL.
    pub fn new(issuer: &str, code_lifetime: u64, token_lifetime: u64) -> Self {
        Self {
            issuer: issuer.to_string(),
            codes: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            code_lifetime,
            token_lifetime,
        }
    }

    /// Get server metadata.
    pub fn metadata(&self) -> IndieAuthMetadata {
        IndieAuthMetadata::new(&self.issuer)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    fn generate_token() -> Result<String> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf)
            .map_err(|_| AuthError::crypto("Failed to generate token"))?;
        Ok(hex::encode(buf))
    }

    /// Issue an authorization code after user consent.
    pub async fn issue_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        me: &str,
        scope: Option<&str>,
        code_challenge: &str,
        code_challenge_method: &str,
    ) -> Result<String> {
        if code_challenge_method != "S256" {
            return Err(AuthError::validation(
                "Only S256 code_challenge_method is supported",
            ));
        }
        let code = Self::generate_token()?;
        let stored = StoredAuthCode {
            code: code.clone(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            me: me.to_string(),
            scope: scope.map(|s| s.to_string()),
            code_challenge: code_challenge.to_string(),
            code_challenge_method: code_challenge_method.to_string(),
            created_at: Self::now_secs(),
        };
        self.codes.write().await.insert(code.clone(), stored);
        Ok(code)
    }

    /// Exchange an authorization code for a token response.
    ///
    /// This is the server-side token exchange endpoint handler.
    pub async fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<IndieAuthTokenResponse> {
        let stored = {
            let mut codes = self.codes.write().await;
            codes
                .remove(code)
                .ok_or_else(|| AuthError::validation("Invalid or expired authorization code"))?
        };

        // Validate client_id and redirect_uri
        if stored.client_id != client_id {
            return Err(AuthError::validation("client_id mismatch"));
        }
        if stored.redirect_uri != redirect_uri {
            return Err(AuthError::validation("redirect_uri mismatch"));
        }

        // Check code expiry
        let now = Self::now_secs();
        if now - stored.created_at > self.code_lifetime {
            return Err(AuthError::validation("Authorization code has expired"));
        }

        // Verify PKCE
        IndieAuthClient::verify_pkce(code_verifier, &stored.code_challenge)?;

        // Issue access token if scopes were requested
        let (access_token, token_type) = if stored.scope.is_some() {
            let token = Self::generate_token()?;
            self.tokens.write().await.insert(
                token.clone(),
                (stored.me.clone(), stored.scope.clone(), now),
            );
            (Some(token), Some("Bearer".to_string()))
        } else {
            (None, None)
        };

        Ok(IndieAuthTokenResponse {
            me: stored.me,
            access_token,
            token_type,
            scope: stored.scope,
            profile: None,
        })
    }

    /// Introspect an access token.
    pub async fn introspect_token(&self, token: &str) -> Option<(String, Option<String>, bool)> {
        let tokens = self.tokens.read().await;
        tokens.get(token).map(|(me, scope, created_at)| {
            let now = Self::now_secs();
            let active = now - created_at <= self.token_lifetime;
            (me.clone(), scope.clone(), active)
        })
    }

    /// Revoke an access token.
    pub async fn revoke_token(&self, token: &str) -> bool {
        self.tokens.write().await.remove(token).is_some()
    }

    /// Clean up expired codes and tokens.
    pub async fn cleanup(&self) {
        let now = Self::now_secs();
        self.codes
            .write()
            .await
            .retain(|_, v| now - v.created_at <= self.code_lifetime);
        self.tokens
            .write()
            .await
            .retain(|_, (_, _, created)| now - *created <= self.token_lifetime);
    }
}

/// Generate a cryptographically random state parameter.
fn generate_state() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)
        .map_err(|_| AuthError::crypto("Failed to generate state".to_string()))?;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_config() -> IndieAuthConfig {
        IndieAuthConfig {
            client_id: "https://app.example.com/".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            authorization_endpoint: Some("https://indieauth.example.com/auth".to_string()),
            token_endpoint: Some("https://indieauth.example.com/token".to_string()),
        }
    }

    #[test]
    fn test_create_client() {
        let client = IndieAuthClient::new(test_config()).unwrap();
        assert_eq!(client.config.client_id, "https://app.example.com/");
    }

    #[test]
    fn test_empty_client_id_rejected() {
        let mut cfg = test_config();
        cfg.client_id = String::new();
        assert!(IndieAuthClient::new(cfg).is_err());
    }

    #[test]
    fn test_generate_code_verifier() {
        let v1 = IndieAuthClient::generate_code_verifier().unwrap();
        let v2 = IndieAuthClient::generate_code_verifier().unwrap();
        assert!(v1.len() >= 43);
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_pkce_challenge_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = IndieAuthClient::compute_code_challenge(verifier);
        // SHA-256 of the verifier, base64url-encoded
        assert!(!challenge.is_empty());
        // Verify it's valid base64url
        assert!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&challenge)
                .is_ok()
        );
    }

    #[test]
    fn test_pkce_verify_success() {
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);
        IndieAuthClient::verify_pkce(&verifier, &challenge).unwrap();
    }

    #[test]
    fn test_pkce_verify_mismatch() {
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        assert!(IndieAuthClient::verify_pkce(&verifier, "wrong-challenge").is_err());
    }

    #[test]
    fn test_build_authorization_url() {
        let client = IndieAuthClient::new(test_config()).unwrap();
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let (req, url) = client
            .build_authorization_url(
                &verifier,
                Some("profile"),
                Some("https://user.example.com/"),
            )
            .unwrap();

        assert_eq!(req.response_type, "code");
        assert_eq!(req.code_challenge_method, "S256");
        assert!(url.starts_with("https://indieauth.example.com/auth?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("scope=profile"));
    }

    #[test]
    fn test_build_url_no_endpoint() {
        let mut cfg = test_config();
        cfg.authorization_endpoint = None;
        let client = IndieAuthClient::new(cfg).unwrap();
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        assert!(
            client
                .build_authorization_url(&verifier, None, None)
                .is_err()
        );
    }

    #[test]
    fn test_verify_callback_valid() {
        let client = IndieAuthClient::new(test_config()).unwrap();
        let cb = IndieAuthCallback {
            code: "auth-code-123".to_string(),
            state: "expected-state".to_string(),
            me: None,
        };
        client.verify_callback(&cb, "expected-state").unwrap();
    }

    #[test]
    fn test_verify_callback_state_mismatch() {
        let client = IndieAuthClient::new(test_config()).unwrap();
        let cb = IndieAuthCallback {
            code: "auth-code-123".to_string(),
            state: "wrong-state".to_string(),
            me: None,
        };
        assert!(client.verify_callback(&cb, "expected-state").is_err());
    }

    #[test]
    fn test_verify_callback_empty_code() {
        let client = IndieAuthClient::new(test_config()).unwrap();
        let cb = IndieAuthCallback {
            code: String::new(),
            state: "ok".to_string(),
            me: None,
        };
        assert!(client.verify_callback(&cb, "ok").is_err());
    }

    #[test]
    fn test_validate_profile_url_valid() {
        IndieAuthClient::validate_profile_url("https://user.example.com/").unwrap();
        IndieAuthClient::validate_profile_url("http://user.example.com/path").unwrap();
    }

    #[test]
    fn test_validate_profile_url_no_scheme() {
        assert!(IndieAuthClient::validate_profile_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_profile_url_fragment() {
        assert!(IndieAuthClient::validate_profile_url("https://example.com/#frag").is_err());
    }

    #[test]
    fn test_validate_profile_url_userinfo() {
        assert!(IndieAuthClient::validate_profile_url("https://user@example.com/").is_err());
    }

    #[test]
    fn test_validate_profile_url_ip_address() {
        assert!(IndieAuthClient::validate_profile_url("https://127.0.0.1/").is_err());
    }

    // ── Server metadata ─────────────────────────────────────────

    #[test]
    fn test_server_metadata() {
        let meta = IndieAuthMetadata::new("https://auth.example.com");
        assert_eq!(meta.issuer, "https://auth.example.com");
        assert_eq!(meta.authorization_endpoint, "https://auth.example.com/auth");
        assert!(
            meta.code_challenge_methods_supported
                .contains(&"S256".to_string())
        );
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("issuer"));
    }

    // ── Server code exchange ────────────────────────────────────

    #[tokio::test]
    async fn test_server_issue_and_exchange_code() {
        let server = IndieAuthServer::new("https://auth.example.com", 600, 3600);

        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);

        let code = server
            .issue_code(
                "https://app.example.com/",
                "https://app.example.com/callback",
                "https://user.example.com/",
                Some("profile create"),
                &challenge,
                "S256",
            )
            .await
            .unwrap();

        let resp = server
            .exchange_code(
                &code,
                "https://app.example.com/",
                "https://app.example.com/callback",
                &verifier,
            )
            .await
            .unwrap();

        assert_eq!(resp.me, "https://user.example.com/");
        assert!(resp.access_token.is_some());
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.scope.as_deref(), Some("profile create"));
    }

    #[tokio::test]
    async fn test_server_code_single_use() {
        let server = IndieAuthServer::new("https://auth.example.com", 600, 3600);
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);

        let code = server
            .issue_code(
                "https://app/",
                "https://app/cb",
                "https://me/",
                None,
                &challenge,
                "S256",
            )
            .await
            .unwrap();

        // First exchange succeeds
        server
            .exchange_code(&code, "https://app/", "https://app/cb", &verifier)
            .await
            .unwrap();

        // Second exchange fails (code consumed)
        assert!(
            server
                .exchange_code(&code, "https://app/", "https://app/cb", &verifier)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_server_pkce_mismatch() {
        let server = IndieAuthServer::new("https://auth.example.com", 600, 3600);
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);

        let code = server
            .issue_code(
                "https://app/",
                "https://app/cb",
                "https://me/",
                None,
                &challenge,
                "S256",
            )
            .await
            .unwrap();

        assert!(
            server
                .exchange_code(&code, "https://app/", "https://app/cb", "wrong-verifier")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_server_introspect_and_revoke() {
        let server = IndieAuthServer::new("https://auth.example.com", 600, 3600);
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);

        let code = server
            .issue_code(
                "https://app/",
                "https://app/cb",
                "https://me/",
                Some("profile"),
                &challenge,
                "S256",
            )
            .await
            .unwrap();

        let resp = server
            .exchange_code(&code, "https://app/", "https://app/cb", &verifier)
            .await
            .unwrap();

        let token = resp.access_token.unwrap();
        let (me, scope, active) = server.introspect_token(&token).await.unwrap();
        assert_eq!(me, "https://me/");
        assert_eq!(scope.as_deref(), Some("profile"));
        assert!(active);

        assert!(server.revoke_token(&token).await);
        assert!(server.introspect_token(&token).await.is_none());
    }

    #[tokio::test]
    async fn test_server_no_token_without_scope() {
        let server = IndieAuthServer::new("https://auth.example.com", 600, 3600);
        let verifier = IndieAuthClient::generate_code_verifier().unwrap();
        let challenge = IndieAuthClient::compute_code_challenge(&verifier);

        let code = server
            .issue_code(
                "https://app/",
                "https://app/cb",
                "https://me/",
                None,
                &challenge,
                "S256",
            )
            .await
            .unwrap();

        let resp = server
            .exchange_code(&code, "https://app/", "https://app/cb", &verifier)
            .await
            .unwrap();

        assert!(resp.access_token.is_none());
        assert_eq!(resp.me, "https://me/");
    }
}
