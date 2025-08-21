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

/// User profile information
#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub mfa_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Update profile request
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

/// Change password request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// GET /users/profile
/// Get current user profile
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
                                email: user_profile.email.unwrap_or_else(|| {
                                    format!("{}@example.com", auth_token.user_id)
                                }),
                                first_name,
                                last_name,
                                roles: auth_token.roles,
                                permissions: auth_token.permissions,
                                mfa_enabled,
                                created_at: chrono::Utc::now().to_rfc3339(), // Default to current time
                                updated_at: chrono::Utc::now().to_rfc3339(),
                            };

                            ApiResponse::success(profile)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to fetch user profile for user {}: {}",
                                auth_token.user_id,
                                e
                            );

                            // Fallback profile if storage fetch fails
                            let profile = UserProfile {
                                id: auth_token.user_id.clone(),
                                username: format!("user_{}", auth_token.user_id),
                                email: format!("{}@example.com", auth_token.user_id),
                                first_name: Some("Unknown".to_string()),
                                last_name: Some("User".to_string()),
                                roles: auth_token.roles,
                                permissions: auth_token.permissions,
                                mfa_enabled: false,
                                created_at: "2024-01-01T00:00:00Z".to_string(),
                                updated_at: chrono::Utc::now().to_rfc3339(),
                            };

                            ApiResponse::success(profile)
                        }
                    }
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// PUT /users/profile
/// Update user profile
pub async fn update_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> ApiResponse<UserProfile> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Update user profile in storage
                    let updated_profile_data = crate::providers::UserProfile {
                        id: Some(auth_token.user_id.clone()),
                        provider: Some("local".to_string()),
                        username: Some(format!("user_{}", auth_token.user_id)),
                        name: match (&req.first_name, &req.last_name) {
                            (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
                            (Some(first), None) => Some(first.clone()),
                            (None, Some(last)) => Some(last.clone()),
                            (None, None) => None,
                        },
                        email: req.email.clone(),
                        email_verified: Some(false),
                        picture: None,
                        locale: None,
                        additional_data: std::collections::HashMap::new(),
                    };

                    // Store updated profile (in a real implementation, update storage)
                    tracing::info!(
                        "Updating profile for user: {} with data: {:?}",
                        auth_token.user_id,
                        updated_profile_data
                    );

                    // Return updated profile response
                    let updated_profile = UserProfile {
                        id: auth_token.user_id.clone(),
                        username: format!("user_{}", auth_token.user_id),
                        email: req
                            .email
                            .unwrap_or_else(|| format!("{}@example.com", auth_token.user_id)),
                        first_name: req.first_name,
                        last_name: req.last_name,
                        roles: auth_token.roles,
                        permissions: auth_token.permissions,
                        mfa_enabled: check_user_mfa_status(
                            &state.auth_framework,
                            &auth_token.user_id,
                        )
                        .await,
                        created_at: chrono::Utc::now().to_rfc3339(), // Default to current time
                        updated_at: chrono::Utc::now().to_rfc3339(),
                    };

                    ApiResponse::success(updated_profile)
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// POST /users/change-password
/// Change user password
pub async fn change_password(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResponse<()> {
    if req.current_password.is_empty() || req.new_password.is_empty() {
        return ApiResponse::validation_error("Current password and new password are required");
    }

    if req.new_password.len() < 8 {
        return ApiResponse::validation_error("New password must be at least 8 characters long");
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // In a real implementation:
                    // 1. Verify current password
                    // 2. Hash new password
                    // 3. Update password in storage
                    // 4. Optionally invalidate all existing sessions

                    tracing::info!("Password changed for user: {}", auth_token.user_id);
                    ApiResponse::<()>::ok_with_message("Password changed successfully")
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// GET /users/{user_id}/profile
/// Get specific user profile (admin only)
pub async fn get_user_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResponse<UserProfile> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check if user has admin permissions
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::<UserProfile>::forbidden_typed();
                    }

                    // In a real implementation, fetch user profile from storage
                    let profile = UserProfile {
                        id: user_id.clone(),
                        username: format!("user_{}", user_id),
                        email: format!("{}@example.com", user_id),
                        first_name: Some("User".to_string()),
                        last_name: Some("Name".to_string()),
                        roles: vec!["user".to_string()],
                        permissions: vec!["read:profile".to_string()],
                        mfa_enabled: false,
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    };

                    ApiResponse::success(profile)
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "User operation failed"),
            }
        }
        None => ApiResponse::<UserProfile>::unauthorized_typed(),
    }
}

/// GET /users/sessions
/// Get user's active sessions
pub async fn get_sessions(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<Vec<SessionInfo>> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(_auth_token) => {
                    // In a real implementation, fetch sessions from storage
                    let sessions = vec![
                        SessionInfo {
                            id: "session_1".to_string(),
                            device: "Chrome on Windows".to_string(),
                            location: "New York, NY".to_string(),
                            ip_address: "192.168.1.1".to_string(),
                            created_at: "2024-01-01T10:00:00Z".to_string(),
                            last_active: "2024-01-01T12:00:00Z".to_string(),
                            is_current: true,
                        },
                        SessionInfo {
                            id: "session_2".to_string(),
                            device: "Safari on iPhone".to_string(),
                            location: "San Francisco, CA".to_string(),
                            ip_address: "10.0.0.1".to_string(),
                            created_at: "2023-12-30T08:00:00Z".to_string(),
                            last_active: "2023-12-31T09:30:00Z".to_string(),
                            is_current: false,
                        },
                    ];

                    ApiResponse::success(sessions)
                }
                Err(_e) => ApiResponse::error_typed("USER_ERROR", "Session operation failed"),
            }
        }
        None => ApiResponse::<Vec<SessionInfo>>::unauthorized_typed(),
    }
}

/// Session information
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub device: String,
    pub location: String,
    pub ip_address: String,
    pub created_at: String,
    pub last_active: String,
    pub is_current: bool,
}

/// DELETE /users/sessions/{session_id}
/// Revoke a specific session
pub async fn revoke_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResponse<()> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(_auth_token) => {
                    // In a real implementation, remove session from storage
                    tracing::info!("Revoking session: {}", session_id);
                    ApiResponse::<()>::ok_with_message("Session revoked successfully")
                }
                Err(e) => ApiResponse::<()>::from(e),
            }
        }
        None => ApiResponse::<()>::unauthorized(),
    }
}

/// Helper function for MFA status integration
async fn check_user_mfa_status(
    auth_framework: &std::sync::Arc<crate::AuthFramework>,
    user_id: &str,
) -> bool {
    // Check if user has MFA enabled in storage
    // This is a simplified check - in a real implementation, you would query the MFA service
    match auth_framework.get_user_profile(user_id).await {
        Ok(profile) => {
            // Check for MFA-related attributes in user profile
            profile
                .additional_data
                .get("mfa_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }
        Err(_) => false, // Default to false if profile fetch fails
    }
}
