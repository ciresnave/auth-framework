//! User Management API Endpoints
//!
//! Handles user profile, password changes, and related user operations

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

/// Full user profile returned by the `/users/profile` and `/users/:id` endpoints.
#[derive(Debug, Serialize)]
pub struct UserProfile {
    /// Unique user identifier.
    pub id: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// Role names assigned to this user.
    pub roles: crate::types::Roles,
    /// Effective permissions derived from roles and direct grants.
    pub permissions: crate::types::Permissions,
    /// Whether multi-factor authentication is enrolled.
    pub mfa_enabled: bool,
    /// Whether the user's email address has been verified.
    pub email_verified: bool,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-modification timestamp.
    pub updated_at: String,
}

/// Profile update request. Only the supplied fields are modified.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    /// New email address (must not already be registered to another user).
    #[serde(default)]
    pub email: Option<String>,
}

/// Password change request.
///
/// Both fields are required.  The server will verify `current_password` before
/// applying the change, and will validate `new_password` against the same
/// complexity rules used during registration.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// `GET /users/profile` — fetch the authenticated user's own profile.
pub async fn get_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<UserProfile> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Fetch actual user profile from storage
                    match state
                        .auth_framework
                        .get_user_profile(&auth_token.user_id)
                        .await
                    {
                        Ok(user_profile) => {
                            // Check MFA status from AuthFramework
                            let mfa_enabled =
                                check_user_mfa_status(&state.auth_framework, &auth_token.user_id)
                                    .await;

                            // Extract first_name and last_name from the name field if available
                            let (first_name, last_name) = if let Some(name) = &user_profile.name {
                                let parts: Vec<&str> = name.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    (Some(parts[0].to_string()), Some(parts[1..].join(" ")))
                                } else if parts.len() == 1 {
                                    (Some(parts[0].to_string()), None)
                                } else {
                                    (None, None)
                                }
                            } else {
                                (None, None)
                            };

                            let profile = UserProfile {
                                id: auth_token.user_id.clone(),
                                username: user_profile
                                    .username
                                    .unwrap_or_else(|| format!("user_{}", auth_token.user_id)),
                                email: user_profile.email.unwrap_or_default(),
                                first_name,
                                last_name,
                                roles: auth_token.roles,
                                permissions: auth_token.permissions,
                                mfa_enabled,
                                email_verified: user_profile.email_verified.unwrap_or(false),
                                created_at: user_profile
                                    .additional_data
                                    .get("created_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                updated_at: user_profile
                                    .additional_data
                                    .get("updated_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            };

                            ApiResponse::success(profile)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to fetch user profile for user {}: {}",
                                auth_token.user_id,
                                e
                            );
                            // M-7: Return an error instead of a fabricated profile so callers
                            // cannot mistake placeholder data for real user information.
                            ApiResponse::error_typed(
                                "PROFILE_UNAVAILABLE",
                                "User profile could not be retrieved; please try again",
                            )
                        }
                    }
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// `PUT /users/profile` — update the authenticated user's profile fields.
pub async fn update_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> ApiResponse<UserProfile> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Validate email format before storing to ensure consistency with
                    // the public registration endpoint.
                    if let Some(ref email) = req.email
                        && crate::utils::validation::validate_email(email).is_err()
                    {
                        return ApiResponse::validation_error_typed("Invalid email format");
                    }

                    // Enforce length limits on name fields to prevent storage abuse.
                    if req.first_name.as_deref().is_some_and(|n| n.len() > 100) {
                        return ApiResponse::validation_error_typed(
                            "First name must be 100 characters or fewer",
                        );
                    }
                    if req.last_name.as_deref().is_some_and(|n| n.len() > 100) {
                        return ApiResponse::validation_error_typed(
                            "Last name must be 100 characters or fewer",
                        );
                    }

                    // Persist updated profile to storage
                    let storage = state.auth_framework.storage();
                    let user_key = format!("user:{}", auth_token.user_id);
                    let current_data = storage.get_kv(&user_key).await.ok().flatten();
                    let mut user_json: serde_json::Value = current_data
                        .and_then(|b| serde_json::from_slice(&b).ok())
                        .unwrap_or_else(|| serde_json::json!({}));

                    // Maintain the email reverse-lookup index so duplicate-email
                    // detection at registration keeps working after an email change.
                    if let Some(ref new_email) = req.email {
                        let old_email = user_json["email"].as_str().unwrap_or("").to_string();
                        if old_email != *new_email {
                            // SECURITY: Verify the new email is not already claimed
                            // by another user before updating the index.
                            let new_email_key = format!("user:email:{}", new_email);
                            if let Ok(Some(existing)) = storage.get_kv(&new_email_key).await {
                                let owner = String::from_utf8_lossy(&existing).to_string();
                                if owner != auth_token.user_id {
                                    return ApiResponse::error_typed(
                                        "CONFLICT",
                                        "Email address is already in use",
                                    );
                                }
                            }
                            // Delete the old mapping.
                            if !old_email.is_empty() {
                                let _ = storage
                                    .delete_kv(&format!("user:email:{}", old_email))
                                    .await;
                            }
                            // Write the new email → user_id mapping.
                            let _ = storage
                                .store_kv(&new_email_key, auth_token.user_id.as_bytes(), None)
                                .await;
                        }
                        user_json["email"] = serde_json::json!(new_email);
                    }
                    let name = match (&req.first_name, &req.last_name) {
                        (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                        (Some(f), None) => Some(f.clone()),
                        (None, Some(l)) => Some(l.clone()),
                        (None, None) => None,
                    };
                    if let Some(ref n) = name {
                        user_json["name"] = serde_json::json!(n);
                    }
                    user_json["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());

                    if let Ok(serialized) = serde_json::to_vec(&user_json) {
                        let _ = storage.store_kv(&user_key, &serialized, None).await;
                    }

                    tracing::info!("Profile updated for user: {}", auth_token.user_id);

                    // Read back the stored values to build an accurate response.
                    let (stored_username, stored_email, stored_created_at) = {
                        let fresh = storage.get_kv(&user_key).await.ok().flatten();
                        let j: serde_json::Value = fresh
                            .and_then(|b| serde_json::from_slice(&b).ok())
                            .unwrap_or_default();
                        (
                            j["username"].as_str().map(|s| s.to_string()),
                            j["email"].as_str().unwrap_or("").to_string(),
                            j["created_at"].as_str().unwrap_or("").to_string(),
                        )
                    };

                    // Return updated profile response
                    let updated_profile = UserProfile {
                        id: auth_token.user_id.clone(),
                        username: stored_username
                            .unwrap_or_else(|| format!("user_{}", auth_token.user_id)),
                        email: stored_email,
                        first_name: req.first_name,
                        last_name: req.last_name,
                        roles: auth_token.roles,
                        permissions: auth_token.permissions,
                        mfa_enabled: check_user_mfa_status(
                            &state.auth_framework,
                            &auth_token.user_id,
                        )
                        .await,
                        email_verified: user_json["email_verified"].as_bool().unwrap_or(false),
                        created_at: stored_created_at,
                        updated_at: user_json["updated_at"].as_str().unwrap_or("").to_string(),
                    };

                    ApiResponse::success(updated_profile)
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// `POST /users/change-password` — change the authenticated user's password.
///
/// The current password must be verified before the new one is accepted.
pub async fn change_password(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResponse<()> {
    if req.current_password.is_empty() || req.new_password.is_empty() {
        return ApiResponse::validation_error("Current password and new password are required");
    }

    // Enforce the same password complexity requirements as registration.
    if let Err(e) = crate::utils::validation::validate_password(&req.new_password) {
        return ApiResponse::validation_error_typed(format!("{e}"));
    }

    // Check new password against known data breaches (HIBP k-anonymity API)
    match crate::utils::breach_check::is_password_breached(&req.new_password).await {
        Ok(true) => {
            return ApiResponse::validation_error(
                "This password has appeared in a known data breach. Please choose a different password.",
            );
        }
        Ok(false) => {}
        Err(_) => {} // HIBP API unreachable; fail open
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Verify current password against stored hash
                    match state
                        .auth_framework
                        .verify_user_password(&auth_token.user_id, &req.current_password)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return ApiResponse::validation_error("Current password is incorrect");
                        }
                        Err(_) => {
                            // Return the same generic message regardless of error type
                            // to avoid distinguishing wrong-password from storage errors.
                            return ApiResponse::validation_error("Current password is incorrect");
                        }
                    }

                    // Get the username (update_user_password takes username)
                    let username = match state
                        .auth_framework
                        .get_username_by_id(&auth_token.user_id)
                        .await
                    {
                        Ok(u) => u,
                        Err(e) => return ApiResponse::<()>::from(e),
                    };

                    match state
                        .auth_framework
                        .update_user_password(&username, &req.new_password)
                        .await
                    {
                        Ok(()) => {
                            tracing::info!("Password changed for user: {}", auth_token.user_id);
                            ApiResponse::<()>::ok_with_message("Password changed successfully")
                        }
                        Err(e) => ApiResponse::<()>::from(e),
                    }
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// `GET /users/{user_id}/profile` — fetch another user's profile (admin only).
pub async fn get_user_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResponse<UserProfile> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    if !auth_token.roles.contains("admin") {
                        return ApiResponse::<UserProfile>::forbidden_typed();
                    }

                    match state.auth_framework.get_user_profile(&user_id).await {
                        Ok(user_profile) => {
                            // Load roles from the canonical user record (same
                            // pattern as validate_api_token) rather than hard-coding [].
                            // Load both roles and permissions from the canonical user
                            // record so the admin profile view stays consistent with
                            // what validate_api_token returns for the user's own token.
                            let user_kv_bytes = {
                                let uk = format!("user:{}", user_id);
                                state
                                    .auth_framework
                                    .storage()
                                    .get_kv(&uk)
                                    .await
                                    .ok()
                                    .flatten()
                            };
                            let user_kv_json: serde_json::Value = user_kv_bytes
                                .as_deref()
                                .and_then(|b| serde_json::from_slice(b).ok())
                                .unwrap_or_default();

                            let profile_roles: Vec<String> = user_kv_json["roles"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let profile_permissions: Vec<String> = user_kv_json["permissions"]
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let (first_name, last_name) = if let Some(name) = &user_profile.name {
                                let parts: Vec<&str> = name.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    (Some(parts[0].to_string()), Some(parts[1..].join(" ")))
                                } else if parts.len() == 1 {
                                    (Some(parts[0].to_string()), None)
                                } else {
                                    (None, None)
                                }
                            } else {
                                (None, None)
                            };

                            let profile = UserProfile {
                                id: user_id.clone(),
                                username: user_profile
                                    .username
                                    .unwrap_or_else(|| format!("user_{}", user_id)),
                                email: user_profile.email.unwrap_or_default(),
                                first_name,
                                last_name,
                                roles: profile_roles.into(),
                                permissions: profile_permissions.into(),
                                mfa_enabled: user_profile
                                    .additional_data
                                    .get("mfa_enabled")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                                email_verified: user_kv_json["email_verified"]
                                    .as_bool()
                                    .unwrap_or(false),
                                created_at: user_profile
                                    .additional_data
                                    .get("created_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                updated_at: user_profile
                                    .additional_data
                                    .get("updated_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            };
                            ApiResponse::success(profile)
                        }
                        Err(e) => {
                            let error_response = ApiResponse::<()>::from(e);
                            ApiResponse::<UserProfile> {
                                success: error_response.success,
                                data: None,
                                error: error_response.error,
                                message: error_response.message,
                            }
                        }
                    }
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// `GET /users/sessions` — list the authenticated user's active sessions.
pub async fn get_sessions(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<Vec<SessionInfo>> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                let storage = state.auth_framework.storage();
                match storage.list_user_sessions(&auth_token.user_id).await {
                    Ok(sessions) => {
                        let session_list: Vec<SessionInfo> = sessions
                            .into_iter()
                            .filter(|s| !s.is_expired())
                            .map(|s| SessionInfo {
                                id: s.session_id.clone(),
                                device: s.user_agent.unwrap_or_default(),
                                location: String::new(),
                                ip_address: s.ip_address.unwrap_or_default(),
                                created_at: s.created_at.to_rfc3339(),
                                last_active: s.last_activity.to_rfc3339(),
                                is_current: false,
                            })
                            .collect();
                        ApiResponse::success(session_list)
                    }
                    Err(_e) => {
                        ApiResponse::error_typed("SESSION_ERROR", "Failed to retrieve sessions")
                    }
                }
            }
            Err(_e) => ApiResponse::error_typed("USER_ERROR", "Session operation failed"),
        },
        None => ApiResponse::<Vec<SessionInfo>>::unauthorized_typed(),
    }
}

/// Summary of an active browser/device session.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub id: String,
    /// User-Agent string from the session’s originating request.
    pub device: String,
    /// Approximate geo-location derived from the client IP (may be empty).
    pub location: String,
    /// Client IP address recorded at session creation.
    pub ip_address: String,
    /// ISO-8601 timestamp of session creation.
    pub created_at: String,
    /// ISO-8601 timestamp of the most recent request in this session.
    pub last_active: String,
    /// `true` if this session belongs to the current request.
    pub is_current: bool,
}

/// `DELETE /users/sessions/{session_id}` — revoke a specific session.
///
/// Only the session owner can revoke it; attempting to revoke another user's
/// session returns `FORBIDDEN`.
pub async fn revoke_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResponse<()> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    let storage = state.auth_framework.storage();

                    // SECURITY: Verify that the session belongs to the authenticated user
                    // before deleting it; without this check any authenticated user can
                    // terminate any other user's session by guessing the session_id.
                    match storage.get_session(&session_id).await {
                        Ok(Some(ref session)) if session.user_id == auth_token.user_id => {}
                        Ok(Some(_)) => {
                            return ApiResponse::<()>::error_typed(
                                "FORBIDDEN",
                                "You do not have permission to revoke this session",
                            );
                        }
                        Ok(None) => {
                            return ApiResponse::<()>::error_typed(
                                "NOT_FOUND",
                                "Session not found",
                            );
                        }
                        Err(e) => return ApiResponse::<()>::from(e),
                    }

                    match storage.delete_session(&session_id).await {
                        Ok(()) => {
                            tracing::info!("Revoked session: {}", session_id);
                            ApiResponse::<()>::ok_with_message("Session revoked successfully")
                        }
                        Err(e) => ApiResponse::<()>::from(e),
                    }
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// Helper function for MFA status integration.
///
/// Delegates to the canonical implementation in [`crate::api::mfa`] which
/// checks the `mfa_enabled:{user_id}` KV key written by the MFA verification
/// flow.
async fn check_user_mfa_status(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
    user_id: &str,
) -> bool {
    crate::api::mfa::check_user_mfa_status(auth_framework, user_id).await
}
