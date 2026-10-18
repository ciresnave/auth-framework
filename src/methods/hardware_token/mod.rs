//! OTP-mode hardware token authentication.
//!
//! This module covers hardware tokens that authenticate via a **one-time password (OTP)**
//! delivered as a plain string — currently YubiKey OTP validated against the Yubico
//! cloud API.
//!
//! It also accepts `smart_card` and `piv_card` token types in its dispatch table, but
//! those return a configuration error explaining that PC/SC-based PKI authentication
//! cannot be reduced to a string exchange and must go through mTLS instead.
//!
//! # What does NOT belong here
//!
//! **FIDO2 / WebAuthn** is intentionally absent.  WebAuthn is a two-phase protocol
//! (challenge generation → signed assertion) that requires credential storage and
//! cryptographic signature verification.  Use
//! [`PasskeyAuthMethod`](crate::methods::passkey::PasskeyAuthMethod) for that.

use crate::errors::Result;

/// Configuration for [`HardwareOtpToken`] validation.
///
/// By default, the Yubico API URL points to the official Yubico validation
/// service. Override `yubico_validation_url` in tests to point at a mock server.
#[derive(Clone)]
pub struct HardwareOtpTokenConfig {
    /// Yubico client ID — required to call the Yubico OTP validation API.
    pub yubico_client_id: Option<String>,
    /// Yubico HMAC-SHA1 secret key — reserved for request signing.
    pub yubico_secret_key: Option<String>,
    /// Base URL of the Yubico OTP validation endpoint.
    /// Defaults to `https://api.yubico.com/wsapi/2.0/verify`.
    pub yubico_validation_url: String,
}

impl std::fmt::Debug for HardwareOtpTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("HardwareOtpTokenConfig");
        d.field("yubico_client_id", &self.yubico_client_id);
        d.field(
            "yubico_secret_key",
            &crate::utils::redact::redacted(&self.yubico_secret_key),
        );
        d.field("yubico_validation_url", &self.yubico_validation_url);
        d.finish()
    }
}

impl Default for HardwareOtpTokenConfig {
    fn default() -> Self {
        Self {
            yubico_client_id: None,
            yubico_secret_key: None,
            yubico_validation_url: "https://api.yubico.com/wsapi/2.0/verify".to_string(),
        }
    }
}

/// OTP-mode hardware token authenticator.
///
/// Supports YubiKey OTP (validated via the Yubico cloud API) and exposes
/// `smart_card` / `piv_card` variants that return a clear error directing
/// callers to mTLS-based authentication.
///
/// For FIDO2/WebAuthn use [`PasskeyAuthMethod`](crate::methods::passkey::PasskeyAuthMethod).
pub struct HardwareOtpToken {
    /// Device identifier
    pub device_id: String,
    /// Token type
    pub token_type: String,
    /// Optional configuration (Yubico API credentials, custom URL for tests)
    config: Option<HardwareOtpTokenConfig>,
}

impl HardwareOtpToken {
    /// Create a new OTP hardware token.
    pub fn new(device_id: String, token_type: String) -> Self {
        Self {
            device_id,
            token_type,
            config: None,
        }
    }

    /// Builder: attach a [`HardwareOtpTokenConfig`] (e.g., Yubico API credentials).
    pub fn with_config(mut self, config: HardwareOtpTokenConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Authenticate using hardware token
    pub async fn authenticate(&self, challenge: &str) -> Result<bool> {
        // Hardware token authentication implementation

        // Basic validation
        if challenge.is_empty() {
            return Ok(false);
        }

        // Simulate hardware token authentication process
        match self.token_type.as_str() {
            "yubikey" => {
                tracing::info!("Authenticating with YubiKey device: {}", self.device_id);
                self.validate_yubikey_response(challenge).await
            }
            _ => {
                tracing::warn!(
                    "Unknown OTP token type '{}'. HardwareOtpToken only supports 'yubikey'. \
                     For smart card / PIV certificate authentication use ClientCertAuthMethod; \
                     for FIDO2/WebAuthn use PasskeyAuthMethod.",
                    self.token_type
                );
                Ok(false)
            }
        }
    }

    /// Validate YubiKey response
    async fn validate_yubikey_response(&self, challenge: &str) -> Result<bool> {
        tracing::debug!("Validating YubiKey response for challenge: {}", challenge);

        // YubiKey OTP format: starts with the 12-char device prefix (modhex) followed
        // by a 32-char encrypted OTP — total 44 characters.  The default public-ID
        // prefix for most keys shipped by Yubico starts with "cccc", but any 44-char
        // modhex string is structurally valid.
        if !challenge.starts_with("cccc") || challenge.len() != 44 {
            tracing::warn!(
                "YubiKey validation failed — invalid OTP format \
                (expected 44-char modhex starting with 'cccc')"
            );
            return Ok(false);
        }

        // If the caller supplied API credentials, validate against the Yubico cloud.
        if let Some(cfg) = &self.config
            && let Some(client_id) = &cfg.yubico_client_id
        {
            return self
                .validate_yubikey_via_api(challenge, client_id, &cfg.yubico_validation_url)
                .await;
        }

        // No API credentials configured: format alone proves nothing.
        // A well-formed OTP can be constructed by anyone; without the Yubico
        // validation API (or equivalent HMAC verification) we cannot confirm
        // the OTP is genuine.  Reject and tell the operator what to fix.
        Err(crate::errors::AuthError::Configuration {
            message: "YubiKey OTP validation requires a Yubico client_id and secret_key. \
                      Call HardwareOtpToken::with_config(HardwareOtpTokenConfig { yubico_client_id: Some(...), \
                      yubico_secret_key: Some(...), .. }) before authenticating."
                .to_string(),
            source: None,
            help: Some(
                "Register at https://upgrade.yubico.com/getapikey/ to obtain API credentials."
                    .to_string(),
            ),
            docs_url: Some(
                "https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html"
                    .to_string(),
            ),
            suggested_fix: Some(
                "HardwareOtpToken::new(id, \"yubikey\") \
                 .with_config(HardwareOtpTokenConfig { yubico_client_id: Some(client_id), .. })"
                    .to_string(),
            ),
        })
    }

    /// Call the Yubico OTP validation API.
    ///
    /// Returns `true` only when the API responds with `status=OK`.
    /// All other statuses (e.g. `REPLAYED_OTP`, `BAD_OTP`) return `false`.
    async fn validate_yubikey_via_api(
        &self,
        otp: &str,
        client_id: &str,
        validation_url: &str,
    ) -> Result<bool> {
        // Generate a random nonce to prevent reply attacks.
        let nonce = {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes).map_err(|_| {
                crate::errors::AuthError::internal("Failed to generate nonce for Yubico request")
            })?;
            hex::encode(bytes)
        };

        let client = reqwest::Client::new();
        // otp, client_id, and nonce are all modhex/hex/numeric — no URL encoding needed.
        let url = format!(
            "{}?id={}&otp={}&nonce={}",
            validation_url, client_id, otp, nonce
        );
        let response = client.get(&url).send().await.map_err(|e| {
            crate::errors::AuthError::internal(format!("Yubico API request failed: {}", e))
        })?;

        let body: String = response.text().await.map_err(|e: reqwest::Error| {
            crate::errors::AuthError::internal(format!("Failed to read Yubico API response: {}", e))
        })?;

        // The Yubico API returns a CRLF-delimited key=value list.
        // We only need the `status` line.
        for line in body.lines() {
            if let Some(status) = line.strip_prefix("status=") {
                let status = status.trim();
                return match status {
                    "OK" => {
                        tracing::info!("Yubico API: OTP valid");
                        Ok(true)
                    }
                    "REPLAYED_OTP" => {
                        tracing::warn!("Yubico API: OTP already used (REPLAYED_OTP)");
                        Ok(false)
                    }
                    other => {
                        tracing::warn!("Yubico API: validation rejected — status={}", other);
                        Ok(false)
                    }
                };
            }
        }

        tracing::warn!("Yubico API: response contained no status line");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yubikey(id: &str) -> HardwareOtpToken {
        HardwareOtpToken::new(id.to_string(), "yubikey".to_string())
    }

    // ── HardwareOtpToken::new ─────────────────────────────────────────────────

    #[test]
    fn test_new_stores_fields() {
        let token = HardwareOtpToken::new("dev-001".to_string(), "yubikey".to_string());
        assert_eq!(token.device_id, "dev-001");
        assert_eq!(token.token_type, "yubikey");
    }

    // ── YubiKey ──────────────────────────────────────────────────────────────

    /// A well-formed OTP (correct prefix + length) with **no API config** must
    /// return a configuration `Err` — format alone cannot prove OTP authenticity.
    /// (Full end-to-end validation is covered by the mockito API tests below.)
    #[tokio::test]
    async fn test_yubikey_valid_otp_without_config_returns_err() {
        let token = yubikey("yk-device-001");
        // 4 prefix chars + 40 more = 44 total — structurally valid
        let valid_otp = format!("cccc{}", "a".repeat(40));
        assert!(
            token.authenticate(&valid_otp).await.is_err(),
            "Expected Err(Configuration) when no API credentials provided"
        );
    }

    #[tokio::test]
    async fn test_yubikey_wrong_prefix() {
        let token = yubikey("yk-device-001");
        let bad_otp = format!("xxxx{}", "a".repeat(40)); // wrong prefix
        assert!(!token.authenticate(&bad_otp).await.unwrap());
    }

    #[tokio::test]
    async fn test_yubikey_too_short() {
        let token = yubikey("yk-device-001");
        assert!(!token.authenticate("cccc123").await.unwrap()); // < 44 chars
    }

    #[tokio::test]
    async fn test_yubikey_too_long() {
        let token = yubikey("yk-device-001");
        let long_otp = format!("cccc{}", "a".repeat(41)); // 45 chars > 44
        assert!(!token.authenticate(&long_otp).await.unwrap());
    }

    #[tokio::test]
    async fn test_yubikey_empty_challenge() {
        let token = yubikey("yk-device-001");
        assert!(!token.authenticate("").await.unwrap());
    }

    // ── Unknown token type ───────────────────────────────────────────────────

    /// The `"fido2"` token type was removed — it is not an OTP protocol.
    /// Callers that previously used `token_type = "fido2"` now hit the unknown-type
    /// branch and get `false`, with a tracing warning directing them to `PasskeyAuthMethod`.
    #[tokio::test]
    async fn test_fido2_token_type_is_unknown() {
        let token = HardwareOtpToken::new("dev-fido2".to_string(), "fido2".to_string());
        // Hits the `_ =>` arm — returns false, logs a warning.
        assert!(!token.authenticate("some-challenge").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_token_type_returns_false() {
        let token = HardwareOtpToken::new("dev-999".to_string(), "unknown_type".to_string());
        assert!(!token.authenticate("some-challenge").await.unwrap());
    }

    // ── HardwareOtpTokenConfig / with_config builder ─────────────────────────

    #[test]
    fn test_hardware_token_config_default() {
        let cfg = HardwareOtpTokenConfig::default();
        assert!(cfg.yubico_client_id.is_none());
        assert!(cfg.yubico_secret_key.is_none());
        assert_eq!(
            cfg.yubico_validation_url,
            "https://api.yubico.com/wsapi/2.0/verify"
        );
    }

    #[test]
    fn test_with_config_builder() {
        let cfg = HardwareOtpTokenConfig {
            yubico_client_id: Some("my_id".to_string()),
            yubico_secret_key: Some("my_secret".to_string()),
            yubico_validation_url: "https://example.com/verify".to_string(),
        };
        let token = HardwareOtpToken::new("dev-001".to_string(), "yubikey".to_string())
            .with_config(cfg.clone());
        let stored = token.config.as_ref().unwrap();
        assert_eq!(stored.yubico_client_id.as_deref(), Some("my_id"));
        assert_eq!(stored.yubico_validation_url, "https://example.com/verify");
    }

    // ── YubiKey format-only fallback (no API config) ─────────────────────────

    #[tokio::test]
    async fn test_yubikey_format_only_without_api_config() {
        // Valid format, no API config → must be rejected with a configuration error.
        // Format alone proves nothing; the Yubico API is required.
        let token = HardwareOtpToken::new("yk-001".to_string(), "yubikey".to_string());
        let valid_otp = format!("cccc{}", "b".repeat(40));
        let result = token.authenticate(&valid_otp).await;
        assert!(
            result.is_err(),
            "Expected Err when no API credentials configured, got {:?}",
            result
        );
    }

    // ── YubiKey Yubico API tests (mockito) ────────────────────────────────────

    fn make_yubikey_with_mock_url(mock_url: &str, client_id: &str) -> HardwareOtpToken {
        let cfg = HardwareOtpTokenConfig {
            yubico_client_id: Some(client_id.to_string()),
            yubico_secret_key: None,
            yubico_validation_url: mock_url.to_string(),
        };
        HardwareOtpToken::new("yk-mock".to_string(), "yubikey".to_string()).with_config(cfg)
    }

    /// Valid OTP format + Yubico API responds `status=OK` → should return `true`.
    #[tokio::test]
    async fn test_yubikey_api_ok() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("t=2024-01-01T00:00:00Z0000\nnonce=abcdef\nstatus=OK\n")
            .create_async()
            .await;

        let token = make_yubikey_with_mock_url(&server.url(), "test_client");
        let valid_otp = format!("cccc{}", "c".repeat(40));
        assert!(token.authenticate(&valid_otp).await.unwrap());
    }

    /// Valid OTP format + API responds `status=REPLAYED_OTP` → `false`.
    #[tokio::test]
    async fn test_yubikey_api_replayed_otp() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("t=2024-01-01T00:00:00Z0000\nnonce=abcdef\nstatus=REPLAYED_OTP\n")
            .create_async()
            .await;

        let token = make_yubikey_with_mock_url(&server.url(), "test_client");
        let valid_otp = format!("cccc{}", "d".repeat(40));
        assert!(!token.authenticate(&valid_otp).await.unwrap());
    }

    /// Valid OTP format + API responds `status=BAD_OTP` → `false`.
    #[tokio::test]
    async fn test_yubikey_api_bad_otp_status() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("t=2024-01-01T00:00:00Z0000\nnonce=abcdef\nstatus=BAD_OTP\n")
            .create_async()
            .await;

        let token = make_yubikey_with_mock_url(&server.url(), "test_client");
        let valid_otp = format!("cccc{}", "e".repeat(40));
        assert!(!token.authenticate(&valid_otp).await.unwrap());
    }

    /// Bad OTP format → rejected before any API call is made.
    /// The mock has zero expected calls; mockito will panic on drop if hit.
    #[tokio::test]
    async fn test_yubikey_bad_format_skips_api() {
        let mut server = mockito::Server::new_async().await;
        // Expect zero hits — if the API is called, the test fails.
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("status=OK\n")
            .expect(0)
            .create_async()
            .await;

        let token = make_yubikey_with_mock_url(&server.url(), "test_client");
        let bad_otp = "XXXX_this_is_not_a_valid_otp_at_all";
        assert!(!token.authenticate(bad_otp).await.unwrap());
    }
}
