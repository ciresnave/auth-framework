//! Multi-Factor Authentication API Endpoints
//!
//! Handles TOTP setup, verification, backup codes, and MFA management.
//!
//! ## Storage keys
//! - `mfa_pending_secret:{user_id}` — base32 TOTP secret, TTL 10 min (before verification)
//! - `mfa_pending_backup_codes:{user_id}` — JSON array of hex-encoded SHA-256 hashes, TTL 10 min
//! - `mfa_secret:{user_id}` — active base32 TOTP secret (no TTL)
//! - `mfa_backup_codes:{user_id}` — JSON array of hex-encoded SHA-256 hashes (no TTL)
//! - `mfa_enabled:{user_id}` — b"true" when MFA is active (no TTL)

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{Json, extract::State, http::HeaderMap};
use base32::Alphabet;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Response returned after initiating MFA setup.
///
/// The client must render the `qr_code` (or display `secret`) to the user and
/// prompt for a TOTP code to complete enrollment via the verify endpoint.
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    /// `otpauth://` URI suitable for a QR code.
    pub qr_code: String,
    /// Base32-encoded TOTP shared secret (for manual entry).
    pub secret: String,
    /// One-time recovery codes — store securely; shown only once.
    pub backup_codes: Vec<String>,
}

/// Request payload for the TOTP verification step.
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    /// Six-digit TOTP code from the authenticator app.
    pub totp_code: String,
}

/// Request payload to disable MFA (requires proof of identity).
#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    /// Account password for re-authentication.
    pub password: String,
    /// A valid TOTP code confirming the user still controls the authenticator.
    pub totp_code: String,
}

/// Current MFA enrollment status for the authenticated user.
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    /// `true` when MFA is fully enrolled and enforced.
    pub enabled: bool,
    /// Active MFA methods (e.g. `["totp"]`).
    pub methods: Vec<String>,
    /// Number of unused one-time backup codes remaining.
    pub backup_codes_remaining: u32,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generate a cryptographically-secure TOTP secret and ten single-use backup
/// codes.  Returns `(plaintext_codes, sha256_hex_hashes)`.
fn generate_backup_codes() -> (Vec<String>, Vec<String>) {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Crockford-like, unambiguous
    let mut plaintext = Vec::with_capacity(10);
    let mut hashed = Vec::with_capacity(10);
    let mut buf = [0u8; 8];
    for _ in 0..10 {
        rand::rng().fill_bytes(&mut buf);
        let code: String = buf
            .iter()
            .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
            .collect();
        let hash = hex::encode(Sha256::digest(code.as_bytes()));
        plaintext.push(code);
        hashed.push(hash);
    }
    (plaintext, hashed)
}

/// Hash a backup code for constant-time comparison.
fn hash_backup_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Verify a 6-digit TOTP code against a raw secret with ±1 window tolerance.
/// Always checks all three time windows regardless of whether an earlier window
/// matched, preventing timing side-channels that reveal which window matched.
fn verify_totp_code(provided: &str, secret_bytes: &[u8], now: u64) -> bool {
    use subtle::ConstantTimeEq as _;
    use totp_lite::{Sha1, totp_custom};
    const STEP: u64 = 30;
    const DIGITS: u32 = 6;

    // Allow the previous window, the current window, and the next window to
    // account for clock skew between the server and the user's device.
    // Do NOT return early on a match so all three comparisons always execute.
    let mut matched = false;
    for offset in [0u64, STEP, STEP.wrapping_neg()] {
        let t = now.wrapping_add(offset);
        let expected = totp_custom::<Sha1>(STEP, DIGITS, secret_bytes, t);
        // Constant-time byte-level comparison prevents timing side-channels.
        let eq: bool = expected.as_bytes().ct_eq(provided.as_bytes()).into();
        matched |= eq;
    }
    matched
}

// ---------------------------------------------------------------------------
// Endpoint handlers
// ---------------------------------------------------------------------------

/// `POST /mfa/setup` — initiate MFA enrollment.
///
/// Generates a new TOTP secret and ten backup codes, stores them as *pending*
/// (TTL 10 min), and returns:
/// - `secret` – base32-encoded secret for manual entry into an authenticator
/// - `qr_code` – `otpauth://` URI that can be converted to a QR code
/// - `backup_codes` – **shown once**; user must save these before calling `/mfa/verify`
pub async fn setup_mfa(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<MfaSetupResponse> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Generate a 20-byte (160-bit) random TOTP secret.
                    let mut secret_bytes = [0u8; 20];
                    rand::rng().fill_bytes(&mut secret_bytes);
                    let secret_b32 =
                        base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

                    // Generate backup codes (shown once, hashes stored).
                    let (plaintext_codes, hashed_codes) = generate_backup_codes();

                    // Store both as pending with a 10-minute TTL so they are
                    // discarded if the user never completes verification.
                    let storage = state.auth_framework.storage();
                    let pending_secret_key = format!("mfa_pending_secret:{}", auth_token.user_id);
                    let pending_backup_key =
                        format!("mfa_pending_backup_codes:{}", auth_token.user_id);
                    let ttl = std::time::Duration::from_secs(600);

                    if let Err(e) = storage
                        .store_kv(&pending_secret_key, secret_b32.as_bytes(), Some(ttl))
                        .await
                    {
                        tracing::error!("Failed to store pending MFA secret: {}", e);
                        return ApiResponse::error_typed(
                            "MFA_ERROR",
                            "Failed to initiate MFA setup",
                        );
                    }

                    let hashed_json =
                        serde_json::to_string(&hashed_codes).unwrap_or_else(|_| "[]".to_string());
                    let _ = storage
                        .store_kv(&pending_backup_key, hashed_json.as_bytes(), Some(ttl))
                        .await;

                    // Build the standard otpauth:// URI understood by all
                    // major authenticator apps (Google Authenticator, Authy, …).
                    let issuer = "AuthFramework";
                    let account = urlencoding::encode(&auth_token.user_id);
                    let qr_code = format!(
                        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&digits=6&period=30"
                    );

                    tracing::info!("MFA setup initiated for user: {}", auth_token.user_id);
                    ApiResponse::success(MfaSetupResponse {
                        qr_code,
                        secret: secret_b32,
                        backup_codes: plaintext_codes,
                    })
                }
                Err(_e) => ApiResponse::error_typed("MFA_ERROR", "MFA setup failed"),
            }
        }
        None => ApiResponse::<MfaSetupResponse>::unauthorized_typed(),
    }
}

/// `POST /mfa/verify` — complete MFA enrollment.
///
/// Verifies a TOTP code against the *pending* secret created by `/mfa/setup`.
/// On success the pending secret is promoted to the active secret, backup-code
/// hashes are committed to permanent storage, and the user's MFA-enabled flag
/// is set.
pub async fn verify_mfa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<MfaVerifyRequest>,
) -> ApiResponse<()> {
    if req.totp_code.is_empty() {
        return ApiResponse::validation_error("TOTP code is required");
    }

    if req.totp_code.len() != 6 || !req.totp_code.chars().all(|c| c.is_ascii_digit()) {
        return ApiResponse::validation_error("TOTP code must be 6 digits");
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    let storage = state.auth_framework.storage();
                    let pending_key = format!("mfa_pending_secret:{}", auth_token.user_id);

                    // Retrieve the pending (not-yet-activated) secret.
                    let secret_b32 = match storage.get_kv(&pending_key).await {
                        Ok(Some(data)) => String::from_utf8_lossy(&data).to_string(),
                        _ => {
                            return ApiResponse::error_typed(
                                "MFA_NOT_PENDING",
                                "No pending MFA setup found. Call /mfa/setup first.",
                            );
                        }
                    };

                    let secret_bytes =
                        match base32::decode(Alphabet::Rfc4648 { padding: false }, &secret_b32) {
                            Some(b) => b,
                            None => {
                                return ApiResponse::error_typed(
                                    "MFA_ERROR",
                                    "Invalid stored secret",
                                );
                            }
                        };

                    // Verify the supplied code (±1 window for clock skew).
                    let now = chrono::Utc::now().timestamp() as u64;
                    if !verify_totp_code(&req.totp_code, &secret_bytes, now) {
                        return ApiResponse::error_typed("MFA_INVALID_CODE", "Invalid TOTP code");
                    }

                    // Activate: persist the secret permanently.
                    let active_key = format!("mfa_secret:{}", auth_token.user_id);
                    if let Err(e) = storage
                        .store_kv(&active_key, secret_b32.as_bytes(), None)
                        .await
                    {
                        tracing::error!(
                            "Failed to persist MFA secret for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                        return ApiResponse::error_typed("MFA_ERROR", "Failed to activate MFA");
                    }

                    // Promote backed-up codes.
                    let pending_backup_key =
                        format!("mfa_pending_backup_codes:{}", auth_token.user_id);
                    if let Ok(Some(data)) = storage.get_kv(&pending_backup_key).await {
                        let active_backup_key = format!("mfa_backup_codes:{}", auth_token.user_id);
                        if let Err(e) = storage.store_kv(&active_backup_key, &data, None).await {
                            tracing::warn!(
                                "Failed to promote MFA backup codes for user {}: {}",
                                auth_token.user_id,
                                e
                            );
                        }
                        if let Err(e) = storage.delete_kv(&pending_backup_key).await {
                            tracing::warn!(
                                "Failed to clean up pending MFA backup codes for user {}: {}",
                                auth_token.user_id,
                                e
                            );
                        }
                    }

                    // Clean up pending secret.
                    if let Err(e) = storage.delete_kv(&pending_key).await {
                        tracing::warn!(
                            "Failed to clean up pending MFA secret for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                    }

                    // Set the enabled flag.
                    let flag_key = format!("mfa_enabled:{}", auth_token.user_id);
                    if let Err(e) = storage.store_kv(&flag_key, b"true", None).await {
                        tracing::warn!(
                            "Failed to set MFA enabled flag for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                    }

                    tracing::info!("MFA enabled for user: {}", auth_token.user_id);
                    ApiResponse::<()>::ok_with_message("MFA enabled successfully")
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// `POST /mfa/disable` — remove MFA from the authenticated account.
///
/// Disables MFA for the authenticated user after verifying their password and
/// a valid TOTP code.  All MFA storage keys are deleted.
pub async fn disable_mfa(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<MfaDisableRequest>,
) -> ApiResponse<()> {
    if req.password.is_empty() || req.totp_code.is_empty() {
        return ApiResponse::validation_error("Password and TOTP code are required");
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Verify the user's password before allowing MFA to be
                    // disabled; this protects against token-theft attacks.
                    match state
                        .auth_framework
                        .verify_user_password(&auth_token.user_id, &req.password)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return ApiResponse::error_typed(
                                "MFA_UNAUTHORIZED",
                                "Incorrect password",
                            );
                        }
                        Err(_) => {
                            return ApiResponse::error_typed(
                                "MFA_UNAUTHORIZED",
                                "Password verification failed",
                            );
                        }
                    }

                    let storage = state.auth_framework.storage();
                    let active_key = format!("mfa_secret:{}", auth_token.user_id);

                    // Fetch the active TOTP secret to verify the code.
                    let secret_b32 = match storage.get_kv(&active_key).await {
                        Ok(Some(data)) => String::from_utf8_lossy(&data).to_string(),
                        _ => {
                            return ApiResponse::error_typed(
                                "MFA_NOT_ENABLED",
                                "MFA is not enabled for this account",
                            );
                        }
                    };

                    let secret_bytes =
                        match base32::decode(Alphabet::Rfc4648 { padding: false }, &secret_b32) {
                            Some(b) => b,
                            None => {
                                return ApiResponse::error_typed(
                                    "MFA_ERROR",
                                    "Invalid stored secret",
                                );
                            }
                        };

                    let now = chrono::Utc::now().timestamp() as u64;
                    if !verify_totp_code(&req.totp_code, &secret_bytes, now) {
                        return ApiResponse::error_typed("MFA_INVALID_CODE", "Invalid TOTP code");
                    }

                    // Remove all MFA-related keys.
                    let backup_key = format!("mfa_backup_codes:{}", auth_token.user_id);
                    let flag_key = format!("mfa_enabled:{}", auth_token.user_id);

                    if let Err(e) = storage.delete_kv(&active_key).await {
                        tracing::warn!(
                            "Failed to delete MFA secret for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                    }
                    if let Err(e) = storage.delete_kv(&backup_key).await {
                        tracing::warn!(
                            "Failed to delete MFA backup codes for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                    }
                    if let Err(e) = storage.delete_kv(&flag_key).await {
                        tracing::warn!(
                            "Failed to delete MFA enabled flag for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                    }

                    tracing::info!("MFA disabled for user: {}", auth_token.user_id);
                    ApiResponse::<()>::ok_with_message("MFA disabled successfully")
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// `GET /mfa/status` — query the current MFA enrollment state.
pub async fn get_mfa_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<MfaStatusResponse> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                let storage = state.auth_framework.storage();
                let mfa_enabled = check_mfa_enabled(storage.as_ref(), &auth_token.user_id).await;
                let backup_codes_remaining =
                    count_backup_codes(storage.as_ref(), &auth_token.user_id).await;

                let status = MfaStatusResponse {
                    enabled: mfa_enabled,
                    methods: if mfa_enabled {
                        vec!["totp".to_string()]
                    } else {
                        vec![]
                    },
                    backup_codes_remaining,
                };

                ApiResponse::success(status)
            }
            Err(_e) => ApiResponse::error_typed("MFA_ERROR", "MFA status check failed"),
        },
        None => ApiResponse::<MfaStatusResponse>::unauthorized_typed(),
    }
}

/// `POST /mfa/regenerate-backup-codes` — replace all backup codes.
///
/// Replaces all existing backup codes with a fresh set.  MFA must be enabled.
/// The new plaintext codes are returned **once** and are not stored.
pub async fn regenerate_backup_codes(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<Vec<String>> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    let storage = state.auth_framework.storage();

                    // Only allow regeneration if MFA is active.
                    if !check_mfa_enabled(storage.as_ref(), &auth_token.user_id).await {
                        return ApiResponse::error_typed(
                            "MFA_NOT_ENABLED",
                            "MFA is not enabled for this account",
                        );
                    }

                    let (plaintext, hashed) = generate_backup_codes();
                    let backup_key = format!("mfa_backup_codes:{}", auth_token.user_id);
                    let hashed_json =
                        serde_json::to_string(&hashed).unwrap_or_else(|_| "[]".to_string());

                    if let Err(e) = storage
                        .store_kv(&backup_key, hashed_json.as_bytes(), None)
                        .await
                    {
                        tracing::error!(
                            "Failed to store backup codes for user {}: {}",
                            auth_token.user_id,
                            e
                        );
                        return ApiResponse::error_typed(
                            "MFA_ERROR",
                            "Failed to regenerate backup codes",
                        );
                    }

                    tracing::info!("Backup codes regenerated for user: {}", auth_token.user_id);
                    ApiResponse::success(plaintext)
                }
                Err(_e) => {
                    ApiResponse::error_typed("MFA_ERROR", "MFA backup codes generation failed")
                }
            }
        }
        None => ApiResponse::<Vec<String>>::unauthorized_typed(),
    }
}

/// `POST /mfa/verify-backup-code` — authenticate with a one-time backup code.
///
/// Verifies a backup code for the authenticated user and consumes it (one-time
/// use).  This can be used in lieu of a TOTP code when the user has lost
/// access to their authenticator app.
#[derive(Debug, Deserialize)]
pub struct BackupCodeVerifyRequest {
    /// The plaintext backup code to verify.
    pub backup_code: String,
}

/// Handler for `POST /mfa/verify-backup-code`.
pub async fn verify_backup_code(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<BackupCodeVerifyRequest>,
) -> ApiResponse<()> {
    if req.backup_code.is_empty() {
        return ApiResponse::validation_error("Backup code is required");
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    let storage = state.auth_framework.storage();
                    let backup_key = format!("mfa_backup_codes:{}", auth_token.user_id);

                    // Load stored hashes.
                    let codes: Vec<String> = match storage.get_kv(&backup_key).await {
                        Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
                        _ => {
                            return ApiResponse::error_typed(
                                "MFA_ERROR",
                                "No backup codes found for this account",
                            );
                        }
                    };

                    // Hash the provided code and compare against each stored
                    // hash using constant-time equality to prevent timing attacks.
                    // All stored hashes are always checked (no early break) so
                    // the response time does not reveal which index matched.
                    let provided_hash_hex = hash_backup_code(req.backup_code.trim());
                    let provided_bytes = hex::decode(&provided_hash_hex).unwrap_or_default();

                    let mut found_idx: Option<usize> = None;
                    for (i, stored_hex) in codes.iter().enumerate() {
                        let stored_bytes = hex::decode(stored_hex).unwrap_or_default();
                        if stored_bytes.len() == provided_bytes.len()
                            && bool::from(stored_bytes.ct_eq(&provided_bytes))
                        {
                            // Record the index but continue iterating all codes
                            // so the loop runs in constant time.
                            found_idx = Some(i);
                        }
                    }

                    match found_idx {
                        Some(idx) => {
                            // Consume the code (one-time use).
                            let mut remaining = codes;
                            remaining.remove(idx);
                            let updated = serde_json::to_string(&remaining)
                                .unwrap_or_else(|_| "[]".to_string());
                            let _ = storage
                                .store_kv(&backup_key, updated.as_bytes(), None)
                                .await;

                            tracing::info!(
                                "Backup code used for user: {}. {} codes remaining.",
                                auth_token.user_id,
                                remaining.len()
                            );
                            ApiResponse::<()>::ok_with_message("Backup code verified")
                        }
                        None => ApiResponse::error_typed(
                            "MFA_INVALID_CODE",
                            "Invalid or already-used backup code",
                        ),
                    }
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

// ---------------------------------------------------------------------------
// Shared helper functions used by other API modules
// ---------------------------------------------------------------------------

/// Returns `true` if MFA is currently active for `user_id`.
///
/// Uses the `mfa_enabled:{user_id}` KV key set by [`verify_mfa`].
pub async fn check_user_mfa_status(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
    user_id: &str,
) -> bool {
    check_mfa_enabled(auth_framework.storage().as_ref(), user_id).await
}

/// Low-level helper that works directly with an `AuthStorage` reference.
async fn check_mfa_enabled(storage: &dyn crate::storage::AuthStorage, user_id: &str) -> bool {
    let flag_key = format!("mfa_enabled:{}", user_id);
    matches!(storage.get_kv(&flag_key).await, Ok(Some(_)))
}

/// Returns the number of remaining backup codes for `user_id`.
async fn count_backup_codes(storage: &dyn crate::storage::AuthStorage, user_id: &str) -> u32 {
    let backup_key = format!("mfa_backup_codes:{}", user_id);
    match storage.get_kv(&backup_key).await {
        Ok(Some(data)) => serde_json::from_slice::<Vec<String>>(&data)
            .map(|v| v.len() as u32)
            .unwrap_or(0),
        _ => 0,
    }
}
