//! Email Verification API Endpoints
//!
//! Handles email address verification through token-based confirmation.
//!
//! ## Storage keys
//! - `email_verify:{token}` — user_id bytes, TTL 24 hours (verification link)
//! - User JSON `email_verified` field — `true` once verified
//!
//! ## Flow
//! 1. User registers → `email_verified` set to `false` in user record
//! 2. `POST /auth/verify-email/send` → generates verification token, returns it
//!    (and sends email if SMTP is configured)
//! 3. `POST /auth/verify-email` → verifies token, sets `email_verified: true`
//! 4. `POST /auth/resend-verification` → regenerates token for the user

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{Json, extract::State, http::HeaderMap};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 24-hour TTL for verification tokens.
const VERIFICATION_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// KV key prefix for email verification tokens.
const VERIFY_KEY_PREFIX: &str = "email_verify:";

/// Response returned when a verification token is generated.
#[derive(Debug, Serialize)]
pub struct VerificationSentResponse {
    /// Whether the operation succeeded.
    pub sent: bool,
    /// The verification token (returned directly for API-driven flows).
    pub verification_token: String,
    /// Human-readable message.
    pub message: String,
}

/// Request body for `POST /auth/verify-email`.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    /// The verification token received via email or API.
    pub token: String,
}

/// Request body for `POST /auth/resend-verification`.
#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    /// The email address to resend verification for.
    pub email: String,
}

/// Generate a URL-safe verification token using the system CSPRNG.
fn generate_verification_token() -> Result<String, crate::errors::AuthError> {
    let rng = ring::rand::SystemRandom::new();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf)
        .map_err(|_| crate::errors::AuthError::crypto("Failed to generate verification token"))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        buf,
    ))
}

/// `POST /auth/verify-email/send`
///
/// Generates a verification token for the authenticated user's email.
/// Requires a valid bearer token.
pub async fn send_verification(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<VerificationSentResponse> {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return ApiResponse::error_typed("AUTH_REQUIRED", "Bearer token required");
        }
    };

    let auth_token = match validate_api_token(&state.auth_framework, &token).await {
        Ok(t) => t,
        Err(_) => {
            return ApiResponse::error_typed("INVALID_TOKEN", "Invalid or expired token");
        }
    };

    let user_id = &auth_token.user_id;

    // Check if already verified
    let user_key = format!("user:{user_id}");
    let user_bytes = match state.auth_framework.storage().get_kv(&user_key).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiResponse::error_typed("USER_NOT_FOUND", "User not found");
        }
    };
    let user_json: serde_json::Value = match serde_json::from_slice(&user_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to read user record");
        }
    };

    if user_json
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return ApiResponse::success(VerificationSentResponse {
            sent: false,
            verification_token: String::new(),
            message: "Email is already verified".to_string(),
        });
    }

    // Generate verification token
    let verify_token = match generate_verification_token() {
        Ok(t) => t,
        Err(_) => {
            return ApiResponse::error_typed(
                "INTERNAL_ERROR",
                "Failed to generate verification token",
            );
        }
    };

    // Store: email_verify:{token} → user_id
    let verify_key = format!("{VERIFY_KEY_PREFIX}{verify_token}");
    if state
        .auth_framework
        .storage()
        .store_kv(
            &verify_key,
            user_id.as_bytes(),
            Some(VERIFICATION_TOKEN_TTL),
        )
        .await
        .is_err()
    {
        return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to store verification token");
    }

    ApiResponse::success(VerificationSentResponse {
        sent: true,
        verification_token: verify_token,
        message: "Verification token generated. Use POST /auth/verify-email to confirm."
            .to_string(),
    })
}

/// `POST /auth/verify-email`
///
/// Verifies a user's email address using the provided token.
/// This endpoint is public (no bearer token required) since the
/// verification token itself serves as proof of email ownership.
pub async fn verify_email(
    State(state): State<ApiState>,
    Json(body): Json<VerifyEmailRequest>,
) -> ApiResponse<serde_json::Value> {
    if body.token.is_empty() {
        return ApiResponse::error_typed("VALIDATION_ERROR", "Verification token is required");
    }

    // Look up verification token
    let verify_key = format!("{VERIFY_KEY_PREFIX}{}", body.token);
    let user_id_bytes = match state.auth_framework.storage().get_kv(&verify_key).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return ApiResponse::error_typed(
                "INVALID_TOKEN",
                "Verification token is invalid or expired",
            );
        }
        Err(_) => {
            return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to look up token");
        }
    };

    let user_id = match String::from_utf8(user_id_bytes) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::error_typed("INTERNAL_ERROR", "Corrupted verification token");
        }
    };

    // Update user record: set email_verified = true
    let user_key = format!("user:{user_id}");
    let user_bytes = match state.auth_framework.storage().get_kv(&user_key).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiResponse::error_typed("USER_NOT_FOUND", "User not found");
        }
    };

    let mut user_json: serde_json::Value = match serde_json::from_slice(&user_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to read user record");
        }
    };

    user_json["email_verified"] = serde_json::Value::Bool(true);

    if state
        .auth_framework
        .storage()
        .store_kv(&user_key, user_json.to_string().as_bytes(), None)
        .await
        .is_err()
    {
        return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to update user record");
    }

    // Delete the used verification token (one-time use)
    let _ = state.auth_framework.storage().delete_kv(&verify_key).await;

    ApiResponse::success(serde_json::json!({
        "verified": true,
        "user_id": user_id,
        "message": "Email address verified successfully"
    }))
}

/// `POST /auth/resend-verification`
///
/// Generates a new verification token for the given email address.
/// This endpoint is public so users who haven't logged in yet can request
/// a new verification. Rate limiting should be applied at the middleware level.
pub async fn resend_verification(
    State(state): State<ApiState>,
    Json(body): Json<ResendVerificationRequest>,
) -> ApiResponse<VerificationSentResponse> {
    if body.email.is_empty() {
        return ApiResponse::error_typed("VALIDATION_ERROR", "Email address is required");
    }

    // Look up user by email
    let email_key = format!("user:email:{}", body.email);
    let user_id_bytes = match state.auth_framework.storage().get_kv(&email_key).await {
        Ok(Some(b)) => b,
        // Return a generic success to prevent email enumeration
        Ok(None) | Err(_) => {
            return ApiResponse::success(VerificationSentResponse {
                sent: true,
                verification_token: String::new(),
                message:
                    "If an account with that email exists, a verification token has been generated."
                        .to_string(),
            });
        }
    };

    let user_id = match String::from_utf8(user_id_bytes) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::success(VerificationSentResponse {
                sent: true,
                verification_token: String::new(),
                message:
                    "If an account with that email exists, a verification token has been generated."
                        .to_string(),
            });
        }
    };

    // Check if already verified
    let user_key = format!("user:{user_id}");
    let user_bytes = match state.auth_framework.storage().get_kv(&user_key).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiResponse::success(VerificationSentResponse {
                sent: true,
                verification_token: String::new(),
                message:
                    "If an account with that email exists, a verification token has been generated."
                        .to_string(),
            });
        }
    };
    let user_json: serde_json::Value = match serde_json::from_slice(&user_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ApiResponse::success(VerificationSentResponse {
                sent: true,
                verification_token: String::new(),
                message:
                    "If an account with that email exists, a verification token has been generated."
                        .to_string(),
            });
        }
    };

    if user_json
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return ApiResponse::success(VerificationSentResponse {
            sent: false,
            verification_token: String::new(),
            message: "Email is already verified".to_string(),
        });
    }

    // Generate new verification token
    let verify_token = match generate_verification_token() {
        Ok(t) => t,
        Err(_) => {
            return ApiResponse::error_typed(
                "INTERNAL_ERROR",
                "Failed to generate verification token",
            );
        }
    };

    let verify_key = format!("{VERIFY_KEY_PREFIX}{verify_token}");
    if state
        .auth_framework
        .storage()
        .store_kv(
            &verify_key,
            user_id.as_bytes(),
            Some(VERIFICATION_TOKEN_TTL),
        )
        .await
        .is_err()
    {
        return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to store verification token");
    }

    ApiResponse::success(VerificationSentResponse {
        sent: true,
        verification_token: verify_token,
        message: "Verification token generated. Use POST /auth/verify-email to confirm."
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_verification_token() {
        let token1 = generate_verification_token().expect("should generate token");
        let token2 = generate_verification_token().expect("should generate token");
        // Tokens should be unique
        assert_ne!(token1, token2);
        // 32 bytes → 43 chars in URL-safe base64 (no padding)
        assert_eq!(token1.len(), 43);
        // Should be URL-safe
        assert!(!token1.contains('+'));
        assert!(!token1.contains('/'));
    }

    #[test]
    fn test_verification_token_ttl() {
        assert_eq!(VERIFICATION_TOKEN_TTL.as_secs(), 86400);
    }
}
