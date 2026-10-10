//! TOTP (Time-based One-Time Password) manager

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

/// TOTP manager for handling time-based one-time passwords
pub struct TotpManager {
    storage: Arc<dyn AuthStorage>,
}

impl TotpManager {
    /// Create a new TOTP manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// Generate TOTP secret for a user
    pub async fn generate_secret(&self, user_id: &str) -> Result<String> {
        debug!("Generating TOTP secret for user '{}'", user_id);

        // Generate 20 cryptographically-secure random bytes encoded as RFC 4648 Base32,
        // compatible with generate_code_for_window() which base32-decodes the secret.
        let rng = ring::rand::SystemRandom::new();
        let mut raw_bytes = [0u8; 20];
        ring::rand::SecureRandom::fill(&rng, &mut raw_bytes)
            .map_err(|_| AuthError::internal("Failed to generate random bytes for TOTP secret"))?;
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &raw_bytes);

        // Store the secret securely
        let key = format!("user:{}:totp_secret", user_id);
        self.storage.store_kv(&key, secret.as_bytes(), None).await?;

        info!("TOTP secret generated for user '{}'", user_id);
        Ok(secret)
    }

    /// Generate TOTP QR code URL
    pub async fn generate_qr_code(
        &self,
        user_id: &str,
        app_name: &str,
        secret: &str,
    ) -> Result<String> {
        let qr_url =
            format!("otpauth://totp/{app_name}:{user_id}?secret={secret}&issuer={app_name}");

        info!("TOTP QR code generated for user '{}'", user_id);
        Ok(qr_url)
    }

    /// Generate current TOTP code using provided secret
    pub async fn generate_code(&self, secret: &str) -> Result<String> {
        self.generate_code_for_window(secret, None).await
    }

    /// Generate TOTP code for given secret and optional specific time window
    pub async fn generate_code_for_window(
        &self,
        secret: &str,
        time_window: Option<u64>,
    ) -> Result<String> {
        if secret.is_empty() {
            return Err(AuthError::validation("TOTP secret cannot be empty"));
        }

        let window = time_window.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 30
        });

        // Generate TOTP code using ring/sha2 for production cryptographic implementation
        use ring::hmac;

        // Decode base32 secret
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, secret)
            .ok_or_else(|| AuthError::InvalidRequest("Invalid TOTP secret format".to_string()))?;

        // Create HMAC key for TOTP (using SHA1 as per RFC)
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);

        // Convert time window to 8-byte big-endian
        let time_bytes = window.to_be_bytes();

        // Compute HMAC
        let signature = hmac::sign(&key, &time_bytes);
        let hmac_result = signature.as_ref();

        // Dynamic truncation (RFC 4226)
        let offset = (hmac_result[19] & 0xf) as usize;
        let code = ((hmac_result[offset] as u32 & 0x7f) << 24)
            | ((hmac_result[offset + 1] as u32) << 16)
            | ((hmac_result[offset + 2] as u32) << 8)
            | (hmac_result[offset + 3] as u32);

        // Generate 6-digit code
        let totp_code = code % 1_000_000;
        Ok(format!("{:06}", totp_code))
    }

    /// Verify TOTP code for a user
    pub async fn verify_code(&self, user_id: &str, code: &str) -> Result<bool> {
        debug!("Verifying TOTP code for user '{}'", user_id);

        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Get user's TOTP secret
        let user_secret = match self.get_user_secret(user_id).await {
            Ok(secret) => secret,
            Err(_) => {
                warn!("No TOTP secret found for user '{}'", user_id);
                return Ok(false);
            }
        };

        // Generate expected TOTP codes for current and adjacent time windows
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // TOTP uses 30-second time steps
        let time_step = 30;
        let current_window = current_time / time_step;

        // Check current window and ±1 window for clock drift tolerance
        let mut matched_window: Option<u64> = None;
        for window in (current_window.saturating_sub(1))..=(current_window + 1) {
            if let Ok(expected_code) = self
                .generate_code_for_window(&user_secret, Some(window))
                .await
                && bool::from(code.as_bytes().ct_eq(expected_code.as_bytes()))
            {
                matched_window = matched_window.max(Some(window));
            }
        }
        if let Some(window) = matched_window
            && self.claim_step(user_id, window).await?
        {
            info!("TOTP code verification successful for user '{}'", user_id);
            return Ok(true);
        }

        info!("TOTP code verification failed for user '{}'", user_id);
        Ok(false)
    }

    /// Get user's TOTP secret from secure storage.
    ///
    /// Checks both storage locations a secret may have been enrolled under
    /// -- `mfa_secret:{user_id}` (the live `/mfa/setup` API route) and
    /// `user:{user_id}:totp_secret` (the modular `generate_secret` path) --
    /// matching [`Self::verify_login_code`]'s existing dual-key lookup, so
    /// a user enrolled via either route is recognized by this method too.
    ///
    /// Returns an error if the user has no secret enrolled under either
    /// key. There is no fallback secret: a user with nothing enrolled must
    /// fail verification, never receive a silently-derived one.
    async fn get_user_secret(&self, user_id: &str) -> Result<String> {
        let api_key = format!("mfa_secret:{}", user_id);
        if let Some(secret_data) = self.storage.get_kv(&api_key).await? {
            return String::from_utf8(secret_data)
                .map_err(|e| AuthError::internal(format!("Failed to parse TOTP secret: {}", e)));
        }

        let modular_key = format!("user:{}:totp_secret", user_id);
        if let Some(secret_data) = self.storage.get_kv(&modular_key).await? {
            return String::from_utf8(secret_data)
                .map_err(|e| AuthError::internal(format!("Failed to parse TOTP secret: {}", e)));
        }

        Err(AuthError::validation(format!(
            "No TOTP secret enrolled for user '{}'",
            user_id
        )))
    }

    /// Check if user has TOTP secret configured
    pub async fn has_totp_secret(&self, user_id: &str) -> Result<bool> {
        let api_key = format!("mfa_secret:{}", user_id);
        match self.storage.get_kv(&api_key).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                let modular_key = format!("user:{}:totp_secret", user_id);
                match self.storage.get_kv(&modular_key).await {
                    Ok(Some(_)) => Ok(true),
                    Ok(None) => Ok(false),
                    Err(_) => Ok(false),
                }
            }
            Err(_) => Ok(false), // Assume false on error
        }
    }

    /// Verify a TOTP code during the login MFA flow.
    /// Reads from `mfa_secret:{user_id}` (API setup) or `user:{user_id}:totp_secret` (modular setup).
    pub async fn verify_login_code(&self, user_id: &str, code: &str) -> Result<bool> {
        use crate::security::secure_utils::constant_time_compare;

        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Try the API MFA key first, then fall back to the modular TOTP key.
        let secret_b32 = match self
            .storage
            .get_kv(&format!("mfa_secret:{}", user_id))
            .await?
        {
            Some(data) => String::from_utf8_lossy(&data).to_string(),
            None => match self
                .storage
                .get_kv(&format!("user:{}:totp_secret", user_id))
                .await?
            {
                Some(data) => String::from_utf8_lossy(&data).to_string(),
                None => return Ok(false),
            },
        };

        let secret_bytes = match base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            &secret_b32,
        )
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_b32))
        {
            Some(bytes) => bytes,
            None => return Ok(false),
        };

        let now = chrono::Utc::now().timestamp() as u64;
        const STEP: u64 = 30;
        const DIGITS: u32 = 6;
        let mut matched_step: Option<u64> = None;

        for offset in [0u64, STEP, STEP.wrapping_neg()] {
            let timestamp = now.wrapping_add(offset);
            let expected =
                totp_lite::totp_custom::<totp_lite::Sha1>(STEP, DIGITS, &secret_bytes, timestamp);
            if constant_time_compare(expected.as_bytes(), code.as_bytes()) {
                matched_step = matched_step.max(Some(timestamp / STEP));
            }
        }

        match matched_step {
            Some(step) => self.claim_step(user_id, step).await,
            None => Ok(false),
        }
    }

    /// Accept a matched TOTP time step only if it is newer than the last one accepted for
    /// this user, so a code (e.g. one observed over a shoulder or in a log) works once.
    async fn claim_step(&self, user_id: &str, step: u64) -> Result<bool> {
        let key = format!("mfa_totp_last_step:{user_id}");
        let last = match self.storage.get_kv(&key).await? {
            Some(bytes) => std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.parse::<u64>().ok()),
            None => None,
        };
        if last.is_some_and(|last| step <= last) {
            return Ok(false);
        }
        // Claim THIS step atomically: of simultaneous submissions of the same code exactly one
        // wins. A code is valid for at most three steps; remember the claim a little longer.
        if !self
            .storage
            .store_kv_if_absent(
                &format!("mfa_totp_used:{user_id}:{step}"),
                b"1",
                Some(std::time::Duration::from_secs(300)),
            )
            .await?
        {
            return Ok(false);
        }
        self.storage
            .store_kv(
                &key,
                step.to_string().as_bytes(),
                Some(std::time::Duration::from_secs(300)),
            )
            .await?;
        Ok(true)
    }
}
