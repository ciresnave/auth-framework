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
//! 2. `POST /auth/verify-email/send` → generates a verification token and hands it to the
//!    configured [`EmailVerificationSender`]
//! 3. `POST /auth/verify-email` → verifies token, sets `email_verified: true`
//! 4. `POST /auth/resend-verification` → same as 2 for a not-yet-logged-in user
//!
//! The token proves control of the mailbox, so it is delivered ONLY through the sender
//! (see [`ApiState::with_email_verification_sender`]) and is never part of a response.
//! Without a sender nothing can be delivered and verification cannot complete.

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{Json, extract::State, http::HeaderMap};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Delivers a verification token to the mailbox it proves ownership of.
///
/// The token is a proof of inbox control, so it must travel ONLY through this channel and
/// never appear in an HTTP response. Implementations send `token` to `email`; failures are
/// logged by the caller (without the error text) and never reported to the requester. Errors
/// returned here must not contain the token.
#[async_trait::async_trait]
pub trait EmailVerificationSender: Send + Sync {
    /// Send `token` to `email`, the address registered for `user_id`.
    async fn send_verification_token(
        &self,
        email: &str,
        user_id: &str,
        token: &str,
    ) -> crate::errors::Result<()>;
}

/// 24-hour TTL for verification tokens.
const VERIFICATION_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// KV key prefix for email verification tokens.
const VERIFY_KEY_PREFIX: &str = "email_verify:";

/// Response to a request to send a verification message. It never contains the token.
#[derive(Debug, Serialize)]
pub struct VerificationSentResponse {
    /// Whether a request was accepted (identical for every address on the public path).
    pub sent: bool,
    /// Human-readable message.
    pub message: String,
}

const GENERIC_SENT_MESSAGE: &str = "If an account with that email exists and is not yet verified, a verification message has been sent.";

fn generic_sent() -> ApiResponse<VerificationSentResponse> {
    ApiResponse::success(VerificationSentResponse {
        sent: true,
        message: GENERIC_SENT_MESSAGE.to_string(),
    })
}

/// Mint a token for `user_id`, store it, and deliver it to `email` through the sender.
/// Delivery problems are logged and never reported to the requester.
async fn issue_and_deliver(
    state: &ApiState,
    user_id: &str,
    email: &str,
) -> Result<(), &'static str> {
    let token = generate_verification_token().map_err(|_| "token generation failed")?;
    let verify_key = format!("{VERIFY_KEY_PREFIX}{token}");
    // The token is bound to the address it is mailed to, so a later change of the
    // account's address cannot be verified with a message sent to the old one.
    let binding = serde_json::json!({ "user_id": user_id, "email": email });
    state
        .auth_framework
        .storage()
        .store_kv(
            &verify_key,
            binding.to_string().as_bytes(),
            Some(VERIFICATION_TOKEN_TTL),
        )
        .await
        .map_err(|_| "token storage failed")?;
    match &state.email_verification_sender {
        Some(sender) => {
            // Delivery runs off the request path so that a slow mail gateway cannot be
            // used to tell a pending address from an unknown or verified one by timing.
            let sender = sender.clone();
            let (email, user_id) = (email.to_string(), user_id.to_string());
            tokio::spawn(async move {
                if sender
                    .send_verification_token(&email, &user_id, &token)
                    .await
                    .is_err()
                {
                    // The sender's error text is deliberately not logged: it could echo the token.
                    tracing::error!(user_id, "Verification message could not be delivered");
                }
            });
        }
        None => tracing::warn!(
            user_id,
            "No EmailVerificationSender configured; verification token cannot be delivered"
        ),
    }
    Ok(())
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
/// Sends a verification message to the authenticated user's email address through the
/// configured [`EmailVerificationSender`]. Requires a valid bearer token.
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
            message: "Email is already verified".to_string(),
        });
    }

    let email = match user_json.get("email").and_then(|v| v.as_str()) {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => return ApiResponse::error_typed("INTERNAL_ERROR", "User has no email address"),
    };
    if issue_and_deliver(&state, user_id, &email).await.is_err() {
        return ApiResponse::error_typed("INTERNAL_ERROR", "Failed to create verification token");
    }
    generic_sent()
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
    let binding_bytes = match state.auth_framework.storage().get_kv(&verify_key).await {
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

    // A token names the account AND the address it was mailed to. Anything else (including
    // tokens stored in an older format) is not accepted.
    let binding: serde_json::Value = match serde_json::from_slice(&binding_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ApiResponse::error_typed(
                "INVALID_TOKEN",
                "Verification token is invalid or expired",
            );
        }
    };
    let (Some(user_id), Some(bound_email)) = (
        binding["user_id"].as_str().map(String::from),
        binding["email"].as_str().map(String::from),
    ) else {
        return ApiResponse::error_typed(
            "INVALID_TOKEN",
            "Verification token is invalid or expired",
        );
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

    // The token only proves control of the address it was mailed to.
    if user_json["email"].as_str() != Some(bound_email.as_str()) {
        let _ = state.auth_framework.storage().delete_kv(&verify_key).await;
        return ApiResponse::error_typed(
            "INVALID_TOKEN",
            "Verification token is invalid or expired",
        );
    }

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
/// Sends a new verification message to the given email address. This endpoint is public
/// so users who haven't logged in yet can request a new verification; it returns the same
/// response for every address. Rate limiting should be applied at the middleware level.
pub async fn resend_verification(
    State(state): State<ApiState>,
    Json(body): Json<ResendVerificationRequest>,
) -> ApiResponse<VerificationSentResponse> {
    if body.email.is_empty() {
        return ApiResponse::error_typed("VALIDATION_ERROR", "Email address is required");
    }

    // Every outcome below (unknown address, already verified, mail sent, mail failed)
    // returns the same response, so the endpoint reveals nothing about the account.
    let email_key = format!("user:email:{}", body.email);
    let Ok(Some(id_bytes)) = state.auth_framework.storage().get_kv(&email_key).await else {
        return generic_sent();
    };
    let Ok(user_id) = String::from_utf8(id_bytes) else {
        return generic_sent();
    };
    let Ok(Some(user_bytes)) = state
        .auth_framework
        .storage()
        .get_kv(&format!("user:{user_id}"))
        .await
    else {
        return generic_sent();
    };
    let Ok(user_json) = serde_json::from_slice::<serde_json::Value>(&user_bytes) else {
        return generic_sent();
    };
    if user_json
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return generic_sent();
    }

    // Only the address on the account record receives a token; a stale index entry
    // pointing at a changed address is ignored.
    if user_json.get("email").and_then(|v| v.as_str()) != Some(body.email.as_str()) {
        return generic_sent();
    }
    if issue_and_deliver(&state, &user_id, &body.email)
        .await
        .is_err()
    {
        tracing::error!(user_id, "Could not create a verification token");
    }
    generic_sent()
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
