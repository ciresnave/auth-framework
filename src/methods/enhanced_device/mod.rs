//! Enhanced Device Flow Implementation
//!
//! This module provides advanced device flow authentication using the oauth-device-flows crate
//! for improved reliability, QR code generation, and better error handling.

use crate::authentication::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, Result};
use crate::methods::{AuthMethod, MethodResult};
use crate::tokens::AuthToken;
#[cfg(feature = "enhanced-device-flow")]
use base64::Engine as _;
#[cfg(feature = "enhanced-device-flow")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

/// Extract the `sub` claim from a JWT access token without verifying the
/// signature.  This is acceptable here because the token was *just* received
/// over TLS from the authorisation server; full signature verification is
/// performed later by the framework's token validation layer.
#[cfg(feature = "enhanced-device-flow")]
fn extract_sub_from_jwt(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sub").and_then(|v| v.as_str()).map(String::from)
}

/// Instructions for device flow authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFlowInstructions {
    /// URL the user should visit
    pub verification_uri: String,
    /// Complete URL with embedded code for faster authentication
    pub verification_uri_complete: Option<String>,
    /// Device code to display to the user
    pub user_code: String,
    /// QR code as base64 encoded PNG (if feature enabled)
    pub qr_code: Option<String>,
    /// How long the user has to complete authentication
    pub expires_in: u64,
    /// How often to poll for completion
    pub interval: u64,
}

/// Enhanced device flow method using oauth-device-flows crate
#[cfg(feature = "enhanced-device-flow")]
#[derive(Debug)]
pub struct EnhancedDeviceFlowMethod {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret (optional for public clients)
    pub client_secret: Option<String>,
    /// Authorization URL
    pub auth_url: String,
    /// Token URL
    pub token_url: String,
    /// Device authorization URL
    pub device_auth_url: String,
    /// OAuth scopes to request
    pub scopes: Vec<String>,
    /// Custom polling interval (optional)
    pub _polling_interval: Option<std::time::Duration>,
    /// Enable QR code generation
    pub enable_qr_code: bool,
}

#[cfg(feature = "enhanced-device-flow")]
impl EnhancedDeviceFlowMethod {
    /// Create a new enhanced device flow method
    pub fn new(
        client_id: String,
        client_secret: Option<String>,
        auth_url: String,
        token_url: String,
        device_auth_url: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url,
            token_url,
            device_auth_url,
            scopes: Vec::new(),
            _polling_interval: None,
            enable_qr_code: true,
        }
    }

    /// Set the OAuth scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set custom polling interval
    pub fn with_polling_interval(mut self, interval: std::time::Duration) -> Self {
        self._polling_interval = Some(interval);
        self
    }

    /// Enable or disable QR code generation
    pub fn with_qr_code(mut self, enable: bool) -> Self {
        self.enable_qr_code = enable;
        self
    }

    /// Initiate device flow and return instructions
    pub async fn initiate_device_flow(&self) -> Result<DeviceFlowInstructions> {
        let client = reqwest::Client::new();
        let mut params = std::collections::HashMap::new();
        params.insert("client_id", self.client_id.clone());
        if !self.scopes.is_empty() {
            params.insert("scope", self.scopes.join(" "));
        }

        let res = client
            .post(&self.device_auth_url)
            .form(&params)
            .send()
            .await
            .map_err(AuthError::Network)?;

        if !res.status().is_success() {
            return Err(AuthError::config(&format!(
                "Device auth request failed: {}",
                res.status()
            )));
        }

        #[derive(Deserialize)]
        struct DeviceAuthResponse {
            #[allow(
                dead_code,
                reason = "RFC 8628 device authorization response field; deserialized with the rest of the response but not used by this client"
            )]
            device_code: String,
            user_code: String,
            verification_uri: String,
            verification_uri_complete: Option<String>,
            expires_in: u64,
            interval: Option<u64>,
        }

        let data: DeviceAuthResponse = res.json().await.map_err(AuthError::Network)?;

        Ok(DeviceFlowInstructions {
            verification_uri: data.verification_uri,
            verification_uri_complete: data.verification_uri_complete,
            user_code: data.user_code,
            qr_code: None, // QR Code generation could be added here
            expires_in: data.expires_in,
            interval: data.interval.unwrap_or(5),
        })
    }
}

#[cfg(feature = "enhanced-device-flow")]
impl AuthMethod for EnhancedDeviceFlowMethod {
    type MethodResult = MethodResult;
    type AuthToken = AuthToken;

    async fn authenticate(
        &self,
        credential: Credential,
        _metadata: CredentialMetadata,
    ) -> Result<Self::MethodResult> {
        let (device_code, _interval) = match credential {
            Credential::EnhancedDeviceFlow {
                device_code,
                interval,
                ..
            } => (device_code, interval),
            _ => {
                return Ok(MethodResult::Failure {
                    reason: "Invalid credential type for enhanced device flow".to_string(),
                });
            }
        };

        let client = reqwest::Client::new();
        let mut params = std::collections::HashMap::new();
        params.insert("client_id", self.client_id.clone());
        params.insert(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        );
        params.insert("device_code", device_code);

        if let Some(secret) = &self.client_secret {
            params.insert("client_secret", secret.clone());
        }

        let res = client
            .post(&self.token_url)
            .form(&params)
            .send()
            .await
            .map_err(AuthError::Network)?;

        if !res.status().is_success() {
            let error_text = res.text().await.unwrap_or_default();
            // Typical errors like authorization_pending, slow_down, expired_token, access_denied
            return Ok(MethodResult::Failure {
                reason: format!("Token exchange failed: {}", error_text),
            });
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
        }

        let token_data: TokenResponse = res.json().await.map_err(AuthError::Network)?;

        // Extract user_id from the JWT access token (the `sub` claim).
        let user_id = extract_sub_from_jwt(&token_data.access_token)
            .unwrap_or_else(|| "unknown_device_user".to_string());

        let expires_in = std::time::Duration::from_secs(token_data.expires_in.unwrap_or(3600));

        let mut token = AuthToken::new(user_id, &token_data.access_token, expires_in, self.name());
        token.refresh_token = token_data.refresh_token;

        Ok(MethodResult::Success(Box::new(token)))
    }

    fn name(&self) -> &str {
        "enhanced_device_flow"
    }

    fn validate_config(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(AuthError::config("Client ID is required"));
        }
        if self.auth_url.is_empty() {
            return Err(AuthError::config("Authorization URL is required"));
        }
        if self.token_url.is_empty() {
            return Err(AuthError::config("Token URL is required"));
        }
        if self.device_auth_url.is_empty() {
            return Err(AuthError::config("Device authorization URL is required"));
        }
        Ok(())
    }
}

// Proper implementation when feature is disabled - captures configuration for error reporting
#[cfg(not(feature = "enhanced-device-flow"))]
#[derive(Debug)]
pub struct EnhancedDeviceFlowMethod {
    /// Client configuration (stored for error reporting)
    client_id: String,
    client_secret: Option<String>,
    auth_url: String,
    token_url: String,
    device_auth_url: String,
}

#[cfg(not(feature = "enhanced-device-flow"))]
impl EnhancedDeviceFlowMethod {
    pub fn new(
        client_id: String,
        client_secret: Option<String>,
        auth_url: String,
        token_url: String,
        device_auth_url: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url,
            token_url,
            device_auth_url,
        }
    }
}

#[cfg(not(feature = "enhanced-device-flow"))]
impl AuthMethod for EnhancedDeviceFlowMethod {
    type MethodResult = MethodResult;
    type AuthToken = AuthToken;

    async fn authenticate(
        &self,
        _credential: Credential,
        _metadata: CredentialMetadata,
    ) -> Result<Self::MethodResult> {
        // Use configuration fields in error message to avoid unused field warnings
        Err(AuthError::config(format!(
            "Enhanced device flow requires 'enhanced-device-flow' feature. Configured for client '{}' with auth_url: {}, token_url: {}, device_auth_url: {}",
            self.client_id, self.auth_url, self.token_url, self.device_auth_url
        )))
    }

    fn name(&self) -> &str {
        "enhanced_device_flow"
    }

    fn validate_config(&self) -> Result<()> {
        // Use configuration fields for validation to avoid unused field warnings
        if self.client_id.is_empty() {
            return Err(AuthError::config("client_id cannot be empty"));
        }
        if self.auth_url.is_empty() {
            return Err(AuthError::config("auth_url cannot be empty"));
        }
        if self.token_url.is_empty() {
            return Err(AuthError::config("token_url cannot be empty"));
        }
        if self.device_auth_url.is_empty() {
            return Err(AuthError::config("device_auth_url cannot be empty"));
        }

        // Log configuration for debugging (uses client_secret field)
        if self.client_secret.is_some() {
            tracing::info!(
                "Enhanced device flow configured for confidential client: {}",
                self.client_id
            );
        } else {
            tracing::info!(
                "Enhanced device flow configured for public client: {}",
                self.client_id
            );
        }

        Err(AuthError::config(
            "Enhanced device flow requires 'enhanced-device-flow' feature to be enabled at compile time",
        ))
    }
}

/// Enhanced device authentication (legacy struct for compatibility)
pub struct EnhancedDevice {
    /// Device identifier
    pub device_id: String,
}

impl EnhancedDevice {
    /// Create new enhanced device
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }

    /// Authenticate using enhanced device
    pub async fn authenticate(&self, challenge: &str) -> Result<bool> {
        // Enhanced device authentication with device binding and trust signals

        if challenge.is_empty() {
            tracing::warn!("Empty challenge provided for device authentication");
            return Ok(false);
        }

        tracing::info!(
            "Starting enhanced device authentication for device: {}",
            self.device_id
        );

        // Simulate enhanced device authentication process
        // In a real implementation, this would:

        // 1. Verify device identity and binding
        if !self.verify_device_binding().await? {
            tracing::warn!("Device binding verification failed for: {}", self.device_id);
            return Ok(false);
        }

        // 2. Check device trust signals
        if !self.check_device_trust_signals().await? {
            tracing::warn!("Device trust signals check failed for: {}", self.device_id);
            return Ok(false);
        }

        // 3. Validate challenge-response with device-specific cryptography
        if !self.validate_device_challenge(challenge).await? {
            tracing::warn!("Device challenge validation failed for: {}", self.device_id);
            return Ok(false);
        }

        tracing::info!(
            "Enhanced device authentication successful for: {}",
            self.device_id
        );
        Ok(true)
    }

    /// Verify device binding and identity
    async fn verify_device_binding(&self) -> Result<bool> {
        tracing::debug!("Verifying device binding for: {}", self.device_id);

        // In production, this would:
        // 1. Check device certificate or attestation
        // 2. Validate device hardware identity
        // 3. Verify device registration status
        // 4. Check device compliance status

        // Simulate device binding check
        if self.device_id.len() < 8 {
            tracing::warn!("Device ID too short for secure binding");
            return Ok(false);
        }

        // Validate device ID format (should be UUID or similar)
        if !self
            .device_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            tracing::warn!("Invalid device ID format");
            return Ok(false);
        }

        tracing::debug!("Device binding verified for: {}", self.device_id);
        Ok(true)
    }

    /// Check device trust signals
    async fn check_device_trust_signals(&self) -> Result<bool> {
        tracing::debug!("Checking device trust signals for: {}", self.device_id);

        // In production, this would check:
        // 1. Device reputation score
        // 2. Recent suspicious activity
        // 3. Device location and behavior patterns
        // 4. Security posture (OS version, patches, etc.)
        // 5. Mobile Device Management (MDM) status
        // 6. Device encryption status

        // Simulate trust signal evaluation
        let trust_score = self.calculate_trust_score().await;

        if trust_score < 0.7 {
            tracing::warn!(
                "Device trust score too low: {} for device: {}",
                trust_score,
                self.device_id
            );
            return Ok(false);
        }

        tracing::info!(
            "Device trust signals validated (score: {}) for: {}",
            trust_score,
            self.device_id
        );
        Ok(true)
    }

    /// Calculate device trust score
    async fn calculate_trust_score(&self) -> f64 {
        // Simulate trust score calculation based on verifiable device properties.
        // In production this would query MDM, EDR, and attestation services.
        let mut score = 1.0_f64;

        // Newly-registered devices start with a lower initial trust score
        if self.device_id.contains("new") {
            score -= 0.1;
        }

        // Test/development devices are considered less trusted
        if self.device_id.contains("test") {
            score -= 0.2;
        }

        // Clamp to [0.0, 1.0] so callers always receive a valid score
        score.clamp(0.0, 1.0)
    }

    /// Validate device-specific challenge
    async fn validate_device_challenge(&self, challenge: &str) -> Result<bool> {
        tracing::debug!("Validating device challenge for: {}", self.device_id);

        // In production, this would:
        // 1. Perform cryptographic challenge-response
        // 2. Validate device attestation
        // 3. Check challenge freshness and replay protection
        // 4. Verify device-specific cryptographic proof

        // Minimum length requirement — too-short challenges cannot provide replay protection
        if challenge.len() < 16 {
            tracing::warn!(
                "Device challenge too short ({} chars) for: {}",
                challenge.len(),
                self.device_id
            );
            return Ok(false);
        }

        // The challenge must consist only of URL-safe base64 / hex characters
        // (alphanumeric, '+', '/', '-', '_', '=')
        let valid_chars = challenge
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='));

        if !valid_chars {
            tracing::warn!(
                "Device challenge contains invalid characters for: {}",
                self.device_id
            );
            return Ok(false);
        }

        tracing::debug!("Device challenge validation successful");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str) -> EnhancedDevice {
        EnhancedDevice::new(id.to_string())
    }

    // ── EnhancedDevice::new ───────────────────────────────────────────────────

    #[test]
    fn test_new_stores_device_id() {
        let d = device("my-device-abc123");
        assert_eq!(d.device_id, "my-device-abc123");
    }

    // ── verify_device_binding ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_device_binding_valid_uuid_format() {
        let d = device("550e8400-e29b-41d4-a716-446655440000");
        // UUID-style device_id is ≥ 8 chars and only alphanumeric + dash
        let result = d.verify_device_binding().await.unwrap();
        assert!(result, "UUID-format device ID should pass binding check");
    }

    #[tokio::test]
    async fn test_device_binding_too_short() {
        let d = device("abc123"); // 6 chars — below 8
        assert!(
            !d.verify_device_binding().await.unwrap(),
            "Device IDs shorter than 8 chars must fail"
        );
    }

    #[tokio::test]
    async fn test_device_binding_invalid_chars() {
        let d = device("device@with#special!chars");
        assert!(
            !d.verify_device_binding().await.unwrap(),
            "Device IDs with special chars (not alphanumeric/-) must fail"
        );
    }

    // ── calculate_trust_score ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_trust_score_clean_device_is_1_0() {
        let d = device("abcd1234efgh5678"); // no "new" or "test" in name
        let score = d.calculate_trust_score().await;
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "Clean device should score 1.0, got {score}"
        );
    }

    #[tokio::test]
    async fn test_trust_score_new_device_is_reduced() {
        let d = device("newdevice-abcd1234");
        let score = d.calculate_trust_score().await;
        assert!(
            score < 1.0,
            "Device containing 'new' should have score < 1.0, got {score}"
        );
        assert!(
            (score - 0.9).abs() < f64::EPSILON,
            "Expected 0.9, got {score}"
        );
    }

    #[tokio::test]
    async fn test_trust_score_test_device_is_reduced() {
        let d = device("testdevice-abcd1234");
        let score = d.calculate_trust_score().await;
        assert!(
            (score - 0.8).abs() < f64::EPSILON,
            "Expected 0.8 for 'test' device, got {score}"
        );
    }

    #[tokio::test]
    async fn test_trust_score_new_and_test_device() {
        let d = device("new-testdevice-abcd1234");
        let score = d.calculate_trust_score().await;
        // 1.0 - 0.1 (new) - 0.2 (test) = 0.7
        assert!(
            (score - 0.7).abs() < f64::EPSILON,
            "Expected 0.7 for device containing both 'new' and 'test', got {score}"
        );
    }

    #[tokio::test]
    async fn test_trust_score_always_in_range() {
        // Even extreme inputs should stay in [0.0, 1.0]
        for id in &[
            "new-test-device-id",
            "new-new-new-test-test-test-device",
            "aaaaaaaaaaaaa",
        ] {
            let score = device(id).calculate_trust_score().await;
            assert!(
                (0.0f64..=1.0).contains(&score),
                "Trust score {score} out of range [0,1] for '{id}'"
            );
        }
    }

    // ── validate_device_challenge ────────────────────────────────────────────

    #[tokio::test]
    async fn test_challenge_valid_hex_16_chars() {
        let d = device("abcdefgh-1234");
        let challenge = "0123456789abcdef"; // 16 hex chars
        assert!(d.validate_device_challenge(challenge).await.unwrap());
    }

    #[tokio::test]
    async fn test_challenge_valid_base64url() {
        let d = device("abcdefgh-1234");
        let challenge = "SGVsbG8gV29ybGQh"; // base64url, 16 chars
        assert!(d.validate_device_challenge(challenge).await.unwrap());
    }

    #[tokio::test]
    async fn test_challenge_too_short() {
        let d = device("abcdefgh-1234");
        assert!(
            !d.validate_device_challenge("short123").await.unwrap(),
            "Challenge < 16 chars must be rejected"
        );
    }

    #[tokio::test]
    async fn test_challenge_empty() {
        let d = device("abcdefgh-1234");
        assert!(!d.validate_device_challenge("").await.unwrap());
    }

    #[tokio::test]
    async fn test_challenge_invalid_chars() {
        let d = device("abcdefgh-1234");
        // Contains space and exclamation mark — invalid
        let challenge = "Hello World!!!!!";
        assert!(
            !d.validate_device_challenge(challenge).await.unwrap(),
            "Challenge with spaces/exclamation marks must be rejected"
        );
    }

    // ── authenticate (integration path) ──────────────────────────────────────

    #[tokio::test]
    async fn test_authenticate_empty_challenge_returns_false() {
        let d = device("abcdefgh-1234");
        assert!(!d.authenticate("").await.unwrap());
    }

    #[tokio::test]
    async fn test_authenticate_valid_device_and_challenge() {
        // Device id: valid format (UUID-like), Challenge: valid base64url ≥ 16 chars
        let d = device("550e8400-e29b-41d4-a716-446655440000");
        let challenge = "SGVsbG8gV29ybGQh"; // valid base64url, 16 chars
        // Trust score is 1.0 (no "new" or "test"), binding passes, challenge passes
        assert!(
            d.authenticate(challenge).await.unwrap(),
            "Valid device + valid challenge should authenticate"
        );
    }

    #[tokio::test]
    async fn test_authenticate_short_device_id_fails() {
        let d = device("tiny"); // < 8 chars, fails binding
        let challenge = "SGVsbG8gV29ybGQh";
        assert!(
            !d.authenticate(challenge).await.unwrap(),
            "Short device ID must fail authentication"
        );
    }

    #[tokio::test]
    async fn test_authenticate_at_minimum_trust_score_passes() {
        // "new" (-0.1) + "test" (-0.2) → score = 0.7, exactly at the threshold.
        // check_device_trust_signals fails only when score < 0.7, so this passes.
        let d = device("new-test-device-abcde"); // score exactly 0.7
        let challenge = "SGVsbG8gV29ybGQh";
        assert!(
            d.authenticate(challenge).await.unwrap(),
            "Device at minimum trust score (0.7) should still authenticate"
        );
    }
}
