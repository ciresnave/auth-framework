//! Authentication API Endpoints
//!
//! Handles login, logout, token refresh, and related authentication operations

use crate::api::{ApiResponse, ApiState, extract_bearer_token};
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};

/// Login request payload
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub mfa_code: Option<String>,
    #[serde(default)]
    pub remember_me: bool,
}

/// Login response data
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: UserInfo,
}

/// User information in login response
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

/// Token refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Token refresh response
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Logout request
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// POST /auth/login
pub async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> ApiResponse<LoginResponse> {
    // Validate required fields
    if req.username.is_empty() || req.password.is_empty() {
        return ApiResponse::validation_error_typed("Username and password are required");
    }

    // Create credential for authentication
    let credential = crate::authentication::credentials::Credential::Password {
        username: req.username.clone(),
        password: req.password.clone(),
    };

    // Attempt authentication
    match state
        .auth_framework
        .authenticate("password", credential)
        .await
    {
        Ok(auth_result) => match auth_result {
            crate::auth::AuthResult::Success(token) => {
                // Create response with token information
                let user_info = UserInfo {
                    id: token.user_id.clone(),
                    username: req.username,
                    roles: token.roles.clone(),
                    permissions: token.permissions.clone(),
                };

                // Generate actual JWT access token
                let token_lifetime = std::time::Duration::from_secs(3600); // 1 hour
                let access_token = match state.auth_framework.token_manager().create_jwt_token(
                    &token.user_id,
                    token.permissions.clone(),
                    Some(token_lifetime),
                ) {
                    Ok(jwt) => jwt,
                    Err(e) => {
                        tracing::error!("Failed to create JWT token: {}", e);
                        return ApiResponse::error_typed(
                            "TOKEN_CREATION_FAILED",
                            "Failed to create access token",
                        );
                    }
                };

                // Generate refresh token with longer lifetime
                let refresh_token_lifetime = std::time::Duration::from_secs(86400 * 7); // 7 days
                let refresh_token = match state.auth_framework.token_manager().create_jwt_token(
                    &token.user_id,
                    vec!["refresh".to_string()],
                    Some(refresh_token_lifetime),
                ) {
                    Ok(jwt) => jwt,
                    Err(e) => {
                        tracing::error!("Failed to create refresh token: {}", e);
                        return ApiResponse::error_typed(
                            "TOKEN_CREATION_FAILED",
                            "Failed to create refresh token",
                        );
                    }
                };

                let response = LoginResponse {
                    access_token,
                    refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600, // 1 hour
                    user: user_info,
                };

                ApiResponse::success(response)
            }
            crate::auth::AuthResult::MfaRequired(_challenge) => {
                // In real implementation, return MFA challenge info
                ApiResponse::error_typed("MFA_REQUIRED", "Multi-factor authentication required")
            }
            crate::auth::AuthResult::Failure(reason) => {
                ApiResponse::error_typed("AUTHENTICATION_FAILED", reason)
            }
        },
        Err(e) => {
            // Convert auth error to API error
            if matches!(e, crate::errors::AuthError::AuthMethod { .. }) {
                ApiResponse::error_typed("INVALID_CREDENTIALS", "Invalid username or password")
            } else {
                ApiResponse::error_typed("AUTH_ERROR", "Authentication failed")
            }
        }
    }
}

/// POST /auth/refresh
pub async fn refresh_token(
    State(state): State<ApiState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResponse<RefreshResponse> {
    if req.refresh_token.is_empty() {
        return ApiResponse::validation_error_typed("Refresh token is required");
    }

    // Validate the refresh token
    match state
        .auth_framework
        .token_manager()
        .validate_jwt_token(&req.refresh_token)
    {
        Ok(claims) => {
            // Check if this is actually a refresh token
            if !claims.scope.contains("refresh") {
                return ApiResponse::error_typed("INVALID_TOKEN", "Token is not a refresh token");
            }

            // Create new access token
            let token_lifetime = std::time::Duration::from_secs(3600); // 1 hour
            let new_access_token = match state.auth_framework.token_manager().create_jwt_token(
                &claims.sub,
                vec!["read".to_string(), "write".to_string()], // Default permissions
                Some(token_lifetime),
            ) {
                Ok(jwt) => jwt,
                Err(e) => {
                    tracing::error!("Failed to create new access token: {}", e);
                    return ApiResponse::error_typed(
                        "TOKEN_CREATION_FAILED",
                        "Failed to create new access token",
                    );
                }
            };

            let response = RefreshResponse {
                access_token: new_access_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            };

            ApiResponse::success(response)
        }
        Err(e) => {
            tracing::warn!("Invalid refresh token: {}", e);
            ApiResponse::error_typed("INVALID_TOKEN", "Invalid or expired refresh token")
        }
    }
}

/// POST /auth/logout
pub async fn logout(
    State(_state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> ApiResponse<()> {
    // Extract token from Authorization header
    if let Some(token) = extract_bearer_token(&headers) {
        // In a real implementation, invalidate the token
        tracing::info!("Logging out user with token: {}", &token[..10]);
    }

    // If refresh token provided, invalidate it too
    if let Some(ref refresh_token) = req.refresh_token {
        tracing::info!("Invalidating refresh token: {}", &refresh_token[..10]);
    }

    ApiResponse::<()>::ok_with_message("Successfully logged out")
}

/// GET /auth/validate
/// Validate current token and return user information
pub async fn validate_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<UserInfo> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match crate::api::validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Fetch actual user information from storage
                    let username = match state
                        .auth_framework
                        .get_user_profile(&auth_token.user_id)
                        .await
                    {
                        Ok(profile) => profile
                            .username
                            .unwrap_or_else(|| format!("user_{}", auth_token.user_id)),
                        Err(_) => format!("user_{}", auth_token.user_id), // Fallback if profile fetch fails
                    };

                    let user_info = UserInfo {
                        id: auth_token.user_id,
                        username,
                        roles: auth_token.roles,
                        permissions: auth_token.permissions,
                    };
                    ApiResponse::success(user_info)
                }
                Err(_e) => ApiResponse::error_typed("AUTH_ERROR", "Token validation failed"),
            }
        }
        None => ApiResponse::unauthorized_typed(),
    }
}

/// GET /auth/providers
/// List available OAuth providers
pub async fn list_providers(State(_state): State<ApiState>) -> ApiResponse<Vec<ProviderInfo>> {
    let providers = vec![
        ProviderInfo {
            name: "google".to_string(),
            display_name: "Google".to_string(),
            auth_url: "/oauth/google".to_string(),
        },
        ProviderInfo {
            name: "github".to_string(),
            display_name: "GitHub".to_string(),
            auth_url: "/oauth/github".to_string(),
        },
        ProviderInfo {
            name: "microsoft".to_string(),
            display_name: "Microsoft".to_string(),
            auth_url: "/oauth/microsoft".to_string(),
        },
    ];

    ApiResponse::success(providers)
}

/// Provider information
#[derive(Debug, Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub display_name: String,
    pub auth_url: String,
}
