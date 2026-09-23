//! Authentication API Endpoints
//!
//! Handles login, logout, token refresh, and related authentication operations

use crate::api::{ApiResponse, ApiState, extract_bearer_token};
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};

/// Login request payload.
///
/// When `challenge_id` and `mfa_code` are both present the login completes an
/// in-progress MFA challenge instead of performing a fresh password check.
/// The two fields must appear together — providing one without the other is
/// rejected with a validation error.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Identifier of a pending MFA challenge (returned by a prior login attempt).
    #[serde(default)]
    pub challenge_id: Option<String>,
    /// The TOTP or backup code that answers the MFA challenge.
    #[serde(default)]
    pub mfa_code: Option<String>,
    /// When `true`, the session lifetime is extended (e.g. "remember me" cookie).
    #[serde(default)]
    pub remember_me: bool,
}

/// Successful login response.
///
/// Contains access and refresh tokens plus user metadata and adaptive risk
/// information.  Clients should inspect `login_risk_level` and
/// `security_warnings` to decide whether to prompt for additional verification.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: LoginUserInfo,
    /// Risk level of this login attempt: "low", "medium", "high", or "critical".
    /// Clients can use this to prompt the user to enable MFA or perform additional verification.
    pub login_risk_level: String,
    /// Non-blocking security advisories for the authenticated session.
    /// Empty in the common case; populated when adaptive risk policy detects elevated risk.
    pub security_warnings: Vec<String>,
}

/// User information embedded in login and validation responses.
#[derive(Debug, Serialize)]
pub struct LoginUserInfo {
    pub id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

async fn build_login_response(
    state: &ApiState,
    user_id: &str,
    username: String,
    permissions: Vec<String>,
) -> ApiResponse<LoginResponse> {
    let user_key = format!("user:{}", user_id);
    let roles: Vec<String> = match state.auth_framework.storage().get_kv(&user_key).await {
        Ok(Some(bytes)) => {
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            json["roles"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|value| value.as_str())
                        .map(|value| value.to_string())
                        .collect()
                })
                .unwrap_or_default()
        }
        _ => vec![],
    };

    let user_info = LoginUserInfo {
        id: user_id.to_string(),
        username,
        roles: roles.clone(),
        permissions,
    };

    let token_lifetime = state.auth_framework.config().token_lifetime;
    let access_token = match state.auth_framework.token_manager().create_jwt_token(
        user_id,
        roles,
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

    let refresh_token_lifetime = state.auth_framework.config().refresh_token_lifetime;
    let refresh_token = match state.auth_framework.token_manager().create_jwt_token(
        user_id,
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

    ApiResponse::success(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: token_lifetime.as_secs(),
        user: user_info,
        login_risk_level: "low".to_string(), // Caller may override after build
        security_warnings: Vec::new(),       // Caller may override after build
    })
}

/// Token refresh request.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// The refresh token issued during a previous login.
    pub refresh_token: String,
}

/// Token refresh response.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    /// The newly issued access token.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Seconds until the new access token expires.
    pub expires_in: u64,
}

/// Logout request.
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    /// Optional refresh token to revoke alongside the access token.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Compute a login risk level string from request headers.
///
/// This is a lightweight, header-only heuristic used to populate the
/// `login_risk_level` field in the login response and to trigger security
/// warnings when MFA is not enrolled.  It does **not** replace a full
/// risk-engine evaluation — for that, see `AuthorizationContextBuilder`.
pub(crate) fn login_risk_level(headers: &HeaderMap) -> (&'static str, Vec<String>) {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let mut risk_points: u8 = 0;
    let mut warnings: Vec<String> = Vec::new();

    if user_agent.is_empty() {
        risk_points = risk_points.saturating_add(30);
        warnings.push(
            "No browser User-Agent detected; this request may originate from an automated script."
                .to_string(),
        );
    }

    // Detect Tor exit nodes by well-known header patterns.  This is a best-effort
    // check and can be defeated; a proper geo-IP database lookup is more reliable.
    if user_agent.to_lowercase().contains("tor browser") {
        risk_points = risk_points.saturating_add(40);
        warnings.push("Login originated from the Tor Browser.".to_string());
    }

    // Multiple IPs in X-Forwarded-For typically indicate a proxy or VPN hop.
    let hop_count = forwarded_for.split(',').count();
    if hop_count >= 2 {
        risk_points = risk_points.saturating_add(15);
        warnings.push(format!(
            "Request passed through {} proxy hops (X-Forwarded-For).",
            hop_count
        ));
    }

    let level = match risk_points {
        0..=9 => "low",
        10..=29 => "medium",
        30..=59 => "high",
        _ => "critical",
    };
    (level, warnings)
}

/// Increment the per-username failed login counter with a sliding TTL window.
async fn increment_login_failure(state: &ApiState, lockout_key: &str, window_secs: u64) {
    let current: u64 = match state.auth_framework.storage().get_kv(lockout_key).await {
        Ok(Some(bytes)) => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        _ => 0,
    };
    let new_count = current.saturating_add(1);
    let _ = state
        .auth_framework
        .storage()
        .store_kv(
            lockout_key,
            new_count.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(window_secs)),
        )
        .await;
}

/// `POST /auth/login` — authenticate a user with username/password.
///
/// On success returns access + refresh tokens, user metadata, and adaptive
/// risk information.  Returns `ACCOUNT_LOCKED` after 5 consecutive failures
/// within 15 minutes.
pub async fn login(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResponse<LoginResponse> {
    // Validate required fields
    if req.username.is_empty() || req.password.is_empty() {
        return ApiResponse::validation_error_typed("Username and password are required");
    }

    if req.challenge_id.is_some() ^ req.mfa_code.is_some() {
        return ApiResponse::validation_error_typed(
            "challenge_id and mfa_code must be provided together",
        );
    }

    if let (Some(challenge_id), Some(mfa_code)) =
        (req.challenge_id.clone(), req.mfa_code.as_deref())
    {
        return match state
            .auth_framework
            .complete_mfa_by_id(&challenge_id, mfa_code)
            .await
        {
            Ok(token) => {
                let mut response = build_login_response(
                    &state,
                    &token.user_id,
                    req.username,
                    token.permissions.to_vec(),
                )
                .await;
                // MFA completion means the step-up was satisfied — mark as low risk.
                if let Some(data) = response.data.as_mut() {
                    data.login_risk_level = "low".to_string();
                }
                response
            }
            Err(e) => {
                tracing::debug!("MFA completion failed during login: {}", e);
                ApiResponse::error_typed(
                    "MFA_INVALID_CODE",
                    "Invalid or expired MFA challenge or code",
                )
            }
        };
    }

    // Compute adaptive risk from request headers before touching the auth core
    // so the risk assessment can influence the response even on success.
    let (risk_level, mut risk_warnings) = login_risk_level(&headers);

    // SEC-M1/L1: Per-username failed login rate limiting / account lockout.
    // Key: "login_failures:{username}" — stores the current failure count as a
    // decimal string with a 15-minute TTL (auto-resets after 15 min of no attempts).
    let lockout_key = format!("login_failures:{}", req.username);
    const MAX_FAILED_ATTEMPTS: u64 = 5;
    const LOCKOUT_WINDOW_SECS: u64 = 900; // 15 minutes
    if let Ok(Some(count_bytes)) = state.auth_framework.storage().get_kv(&lockout_key).await
        && let Ok(count_str) = std::str::from_utf8(&count_bytes)
        && let Ok(count) = count_str.parse::<u64>()
        && count >= MAX_FAILED_ATTEMPTS
    {
        tracing::warn!(
            username = %req.username,
            failed_attempts = count,
            "Login rejected — account temporarily locked due to repeated failures"
        );
        return ApiResponse::error_typed(
            "ACCOUNT_LOCKED",
            "Too many failed login attempts. Please try again later.",
        );
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
                // Check if the user has MFA enrolled.  If not and the risk level is
                // elevated, add a security advisory recommending MFA enrollment.
                let mfa_enrolled =
                    crate::api::mfa::check_user_mfa_status(&state.auth_framework, &token.user_id)
                        .await;

                if !mfa_enrolled && matches!(risk_level, "high" | "critical") {
                    risk_warnings.push(
                        "Your account does not have multi-factor authentication enabled. \
                         Enable MFA to protect this account from high-risk login contexts."
                            .to_string(),
                    );
                    tracing::warn!(
                        user_id = %token.user_id,
                        risk_level = %risk_level,
                        "High-risk login without MFA enrolled"
                    );
                } else {
                    tracing::info!(
                        user_id = %token.user_id,
                        risk_level = %risk_level,
                        mfa_enrolled = %mfa_enrolled,
                        "Successful login"
                    );
                }

                let mut response = build_login_response(
                    &state,
                    &token.user_id,
                    req.username,
                    token.permissions.to_vec(),
                )
                .await;

                // Reset failed login counter on successful authentication
                let _ = state.auth_framework.storage().delete_kv(&lockout_key).await;

                if let Some(data) = response.data.as_mut() {
                    data.login_risk_level = risk_level.to_string();
                    data.security_warnings = risk_warnings;
                }
                response
            }
            crate::auth::AuthResult::MfaRequired(challenge) => {
                // Return the challenge data so the client knows how to fulfill MFA.
                // The client should prompt for the appropriate second factor and then
                // re-submit the login request with both challenge_id and mfa_code.
                let mfa_type_str = match &challenge.mfa_type {
                    crate::methods::MfaType::Totp => "totp",
                    crate::methods::MfaType::Sms { .. } => "sms",
                    crate::methods::MfaType::Email { .. } => "email",
                    crate::methods::MfaType::Push { .. } => "push",
                    crate::methods::MfaType::SecurityKey => "security_key",
                    crate::methods::MfaType::BackupCode => "backup_code",
                    crate::methods::MfaType::MultiMethod => "totp_or_backup_code",
                };
                ApiResponse::<()>::error_with_details(
                    "MFA_REQUIRED",
                    "Multi-factor authentication required",
                    serde_json::json!({
                        "challenge_id": challenge.id,
                        "mfa_type": mfa_type_str,
                        "expires_at": challenge.expires_at.to_rfc3339(),
                        "message": challenge.message,
                    }),
                )
                .cast()
            }
            crate::auth::AuthResult::Failure(reason) => {
                // Increment failed login counter
                increment_login_failure(&state, &lockout_key, LOCKOUT_WINDOW_SECS).await;
                ApiResponse::error_typed("AUTHENTICATION_FAILED", reason)
            }
        },
        Err(e) => {
            // Increment failed login counter
            increment_login_failure(&state, &lockout_key, LOCKOUT_WINDOW_SECS).await;
            // Always return the same error code/message regardless of *why* auth failed.
            // This prevents timing and enumeration attacks that could distinguish
            // "user not found" from "wrong password".
            tracing::debug!(
                "Authentication error (reported as INVALID_CREDENTIALS): {}",
                e
            );
            ApiResponse::error_typed("INVALID_CREDENTIALS", "Invalid username or password")
        }
    }
}

/// `POST /auth/refresh` — exchange a valid refresh token for a new access token.
pub async fn refresh_token(
    State(state): State<ApiState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResponse<RefreshResponse> {
    if req.refresh_token.is_empty() {
        return ApiResponse::validation_error_typed("Invalid request");
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
                return ApiResponse::error_typed(
                    "INVALID_TOKEN",
                    "Expected a refresh token, but received an access token",
                );
            }

            // SECURITY: Reject revoked refresh tokens (e.g. those already passed to /auth/logout).
            let revocation_key = format!("revoked_token:{}", claims.jti);
            match state.auth_framework.storage().get_kv(&revocation_key).await {
                Ok(Some(_)) => {
                    return ApiResponse::error_typed(
                        "INVALID_TOKEN",
                        "Refresh token has been revoked",
                    );
                }
                Ok(None) => {} // Not revoked — proceed
                Err(e) => {
                    tracing::error!("Refresh token revocation check failed: {}", e);
                    return ApiResponse::error_typed(
                        "INTERNAL_ERROR",
                        "Unable to verify token status",
                    );
                }
            }

            // Create new access token, preserving the user's actual permissions from storage.
            // H-1 fix: do NOT hard-code ["read","write"] — load the real permission set.

            // SECURITY: Reject refresh if the user's account has been deactivated
            // since the refresh token was issued.  Without this check a deactivated
            // user can indefinitely obtain new access tokens.
            {
                let user_key = format!("user:{}", claims.sub);
                if let Ok(Some(user_bytes)) = state.auth_framework.storage().get_kv(&user_key).await
                {
                    let user_json: serde_json::Value =
                        serde_json::from_slice(&user_bytes).unwrap_or_default();
                    let active = user_json["active"].as_bool().unwrap_or(true);
                    if !active {
                        return ApiResponse::error_typed(
                            "ACCOUNT_DEACTIVATED",
                            "Account has been deactivated",
                        );
                    }
                }
            }

            let permissions: Vec<String> = match state
                .auth_framework
                .storage()
                .get_kv(&format!("user_permissions:{}", claims.sub))
                .await
            {
                Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
                _ => vec![],
            };

            let token_lifetime = state.auth_framework.config().token_lifetime;
            let new_access_token = match state.auth_framework.token_manager().create_jwt_token(
                &claims.sub,
                permissions,
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
                expires_in: token_lifetime.as_secs(),
            };

            ApiResponse::success(response)
        }
        Err(e) => {
            tracing::warn!("Invalid refresh token: {}", e);
            ApiResponse::error_typed("INVALID_TOKEN", "Invalid or expired refresh token")
        }
    }
}

/// `POST /auth/logout` — revoke access and (optionally) refresh tokens.
pub async fn logout(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> ApiResponse<()> {
    // Revoke the access token by storing it in the blocklist keyed by JTI
    if let Some(token) = extract_bearer_token(&headers) {
        match state
            .auth_framework
            .token_manager()
            .validate_jwt_token(&token)
        {
            Ok(claims) => {
                let revocation_key = format!("revoked_token:{}", claims.jti);
                // TTL: longer of token's remaining lifetime or 1 hour; cap at 7 days
                let ttl = std::time::Duration::from_secs(7 * 86400);
                if let Err(e) = state
                    .auth_framework
                    .storage()
                    .store_kv(revocation_key.as_str(), b"revoked", Some(ttl))
                    .await
                {
                    tracing::error!("Failed to revoke access token JTI {}: {}", claims.jti, e);
                } else {
                    tracing::info!("Access token revoked (JTI: {})", claims.jti);
                }
            }
            Err(_) => {
                // Token was already invalid; no action needed
                tracing::debug!("Logout called with invalid/expired access token");
            }
        }
    }

    // If refresh token provided, revoke it too
    if let Some(ref refresh_token) = req.refresh_token {
        match state
            .auth_framework
            .token_manager()
            .validate_jwt_token(refresh_token)
        {
            Ok(claims) => {
                let revocation_key = format!("revoked_token:{}", claims.jti);
                let ttl = std::time::Duration::from_secs(7 * 86400);
                if let Err(e) = state
                    .auth_framework
                    .storage()
                    .store_kv(revocation_key.as_str(), b"revoked", Some(ttl))
                    .await
                {
                    tracing::error!("Failed to revoke refresh token JTI {}: {}", claims.jti, e);
                } else {
                    tracing::info!("Refresh token revoked (JTI: {})", claims.jti);
                }
            }
            Err(_) => {
                tracing::debug!("Logout called with invalid/expired refresh token");
            }
        }
    }

    ApiResponse::<()>::ok_with_message("Successfully logged out")
}

/// GET /auth/validate
/// Validate current token and return user information
pub async fn validate_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<LoginUserInfo> {
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

                    let user_info = LoginUserInfo {
                        id: auth_token.user_id,
                        username,
                        roles: auth_token.roles.to_vec(),
                        permissions: auth_token.permissions.to_vec(),
                    };
                    ApiResponse::success(user_info)
                }
                Err(_e) => ApiResponse::error_typed("AUTH_ERROR", "Token validation failed"),
            }
        }
        None => ApiResponse::unauthorized_typed(),
    }
}

/// `GET /auth/providers` — list available OAuth providers and their authorize URLs.
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

/// Summary of an available OAuth login provider.
#[derive(Debug, Serialize)]
pub struct ProviderInfo {
    /// Machine-readable identifier (e.g. `"google"`).
    pub name: String,
    /// Human-readable label.
    pub display_name: String,
    /// Relative URL to initiate the OAuth flow.
    pub auth_url: String,
}

/// User registration request.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Desired username (validated for length, characters, must start with a letter).
    pub username: String,
    /// Email address for the new account.
    pub email: String,
    /// Password (validated against minimum complexity rules).
    pub password: String,
}

/// User registration response.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    /// System-generated unique user identifier.
    pub user_id: String,
    /// The registered username.
    pub username: String,
    /// The registered email.
    pub email: String,
}

/// `POST /auth/register` — create a new user account.
///
/// Validates username format, password complexity, and email uniqueness
/// before persisting the new user.
pub async fn register(
    State(state): State<ApiState>,
    Json(req): Json<RegisterRequest>,
) -> ApiResponse<RegisterResponse> {
    // Validate required fields
    if req.username.is_empty() || req.password.is_empty() || req.email.is_empty() {
        return ApiResponse::validation_error_typed("Username, password, and email are required");
    }

    // Validate username format (length, allowed characters, must start with letter).
    if let Err(e) = crate::utils::validation::validate_username(&req.username) {
        return ApiResponse::validation_error_typed(format!("{e}"));
    }

    // Validate password strength (min 8 characters with complexity)
    if let Err(e) = crate::utils::validation::validate_password(&req.password) {
        return ApiResponse::validation_error_typed(format!("{e}"));
    }

    // Check password against known data breaches (HIBP k-anonymity API)
    match crate::utils::breach_check::is_password_breached(&req.password).await {
        Ok(true) => {
            return ApiResponse::validation_error_typed(
                "This password has appeared in a known data breach. Please choose a different password.",
            );
        }
        Ok(false) => {} // Password not breached, continue
        Err(_) => {}    // HIBP API unreachable; fail open to avoid blocking registration
    }

    // Validate email format
    if let Err(e) = crate::utils::validation::validate_email(&req.email) {
        return ApiResponse::validation_error_typed(format!("{e}"));
    }

    // Check if username already exists
    let username_key = format!("user:credentials:{}", req.username);
    match state.auth_framework.storage().get_kv(&username_key).await {
        Ok(Some(_)) => {
            // Use a generic message for both username and email conflicts to prevent
            // enumeration of existing accounts via the public registration endpoint.
            return ApiResponse::error_typed(
                "CONFLICT",
                "An account with the provided details already exists",
            );
        }
        Err(e) => {
            tracing::error!("Storage error checking username: {}", e);
            return ApiResponse::internal_error_typed();
        }
        Ok(None) => {}
    }

    // Check if email already exists
    let email_key = format!("user:email:{}", req.email);
    match state.auth_framework.storage().get_kv(&email_key).await {
        Ok(Some(_)) => {
            return ApiResponse::error_typed(
                "CONFLICT",
                "An account with the provided details already exists",
            );
        }
        Err(e) => {
            tracing::error!("Storage error checking email: {}", e);
            return ApiResponse::internal_error_typed();
        }
        Ok(None) => {}
    }

    // Hash the password
    let password_hash = match crate::utils::password::hash_password_argon2id(&req.password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Password hashing failed: {:?}", e);
            return ApiResponse::error_typed("REGISTRATION_FAILED", "Failed to process password");
        }
    };

    // Generate user ID
    let user_id = format!("user_{}", uuid::Uuid::new_v4().as_simple());
    let created_at = chrono::Utc::now().to_rfc3339();

    // Build user record
    let user_data = serde_json::json!({
        "user_id": user_id,
        "username": req.username,
        "email": req.email,
        "password_hash": password_hash,
        "created_at": created_at,
    });
    let user_data_bytes = user_data.to_string().into_bytes();

    // Store main user record
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(&username_key, &user_data_bytes, None)
        .await
    {
        tracing::error!("User registration storage failed: {:?}", e);
        return ApiResponse::error_typed("REGISTRATION_FAILED", "Failed to create user account");
    }

    // Store email → user_id mapping for duplicate checking
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(&email_key, user_id.as_bytes(), None)
        .await
    {
        tracing::error!("Email mapping storage failed: {:?}", e);
        // Best-effort rollback
        let _ = state
            .auth_framework
            .storage()
            .delete_kv(&username_key)
            .await;
        return ApiResponse::error_typed("REGISTRATION_FAILED", "Failed to create user account");
    }

    // Store the canonical user record used by admin operations (set_user_active,
    // update_user_password, delete_user, etc.) which all key on user:{user_id}.
    let canonical_user_data = serde_json::json!({
        "user_id": user_id,
        "username": req.username,
        "email": req.email,
        "password_hash": password_hash,
        "roles": ["user"],
        "active": true,
        "created_at": created_at,
    });
    let canonical_key = format!("user:{}", user_id);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &canonical_key,
            canonical_user_data.to_string().as_bytes(),
            None,
        )
        .await
    {
        tracing::error!("Canonical user record storage failed: {:?}", e);
        let _ = state
            .auth_framework
            .storage()
            .delete_kv(&username_key)
            .await;
        let _ = state.auth_framework.storage().delete_kv(&email_key).await;
        return ApiResponse::error_typed("REGISTRATION_FAILED", "Failed to create user account");
    }

    // Store username → user_id mapping (used by get_username_by_id reverse-lookup).
    let username_id_key = format!("user:username:{}", req.username);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(&username_id_key, user_id.as_bytes(), None)
        .await
    {
        tracing::error!("Username-id mapping storage failed: {:?}", e);
        let _ = state
            .auth_framework
            .storage()
            .delete_kv(&username_key)
            .await;
        let _ = state.auth_framework.storage().delete_kv(&email_key).await;
        let _ = state
            .auth_framework
            .storage()
            .delete_kv(&canonical_key)
            .await;
        return ApiResponse::error_typed("REGISTRATION_FAILED", "Failed to create user account");
    }

    // Add user to the global users:index so admin list endpoints include self-registered users.
    let index_key = "users:index";
    let mut ids: Vec<String> = match state.auth_framework.storage().get_kv(index_key).await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => vec![],
    };
    ids.push(user_id.clone());
    if let Ok(idx_json) = serde_json::to_vec(&ids)
        && let Err(e) = state
            .auth_framework
            .storage()
            .store_kv(index_key, &idx_json, None)
            .await
    {
        tracing::warn!("Failed to update user index after registration: {}", e);
    }

    tracing::info!("New user registered: {} ({})", req.username, user_id);

    ApiResponse::success(RegisterResponse {
        user_id,
        username: req.username,
        email: req.email,
    })
}

/// Response returned when an API key is successfully created.
#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    /// The new API key – treat as a secret and display only once.
    pub api_key: String,
    /// Always `"ApiKey"`.
    pub token_type: String,
}

/// POST /api-keys – create an API key (requires authentication)
pub async fn create_api_key(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<CreateApiKeyResponse> {
    // Require a valid Bearer token; reject unauthenticated requests with 401.
    let token = match crate::api::extract_bearer_token(&headers) {
        Some(t) => t,
        None => return ApiResponse::unauthorized_typed(),
    };

    // Validate the token and extract the caller's identity.
    let auth_token = match crate::api::validate_api_token(&state.auth_framework, &token).await {
        Ok(t) => t,
        Err(_) => return ApiResponse::unauthorized_typed(),
    };

    // Create an API key scoped to the authenticated user.
    match state
        .auth_framework
        .create_api_key(&auth_token.user_id, None)
        .await
    {
        Ok(api_key) => ApiResponse::success(CreateApiKeyResponse {
            api_key,
            token_type: "ApiKey".to_string(),
        }),
        Err(e) => {
            tracing::error!(
                "Failed to create API key for user {}: {}",
                auth_token.user_id,
                e
            );
            ApiResponse::internal_error_typed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_login_risk_low_normal_request() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".parse().unwrap(),
        );
        let (level, warnings) = login_risk_level(&headers);
        assert_eq!(level, "low");
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_login_risk_high_no_user_agent() {
        let headers = HeaderMap::new();
        let (level, warnings) = login_risk_level(&headers);
        assert_eq!(level, "high");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_login_risk_tor_browser() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0 (Tor Browser)".parse().unwrap());
        let (level, warnings) = login_risk_level(&headers);
        // Tor alone is 40 points → "high"
        assert!(level == "high" || level == "critical");
        assert!(warnings.iter().any(|w| w.contains("Tor")));
    }

    #[test]
    fn test_login_risk_proxy_hops() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let (level, warnings) = login_risk_level(&headers);
        assert_eq!(level, "medium");
        assert!(warnings.iter().any(|w| w.contains("proxy")));
    }

    #[test]
    fn test_login_request_deserialization() {
        let json = r#"{"username":"alice","password":"secret"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "alice");
        assert_eq!(req.password, "secret");
        assert!(!req.remember_me);
        assert!(req.challenge_id.is_none());
        assert!(req.mfa_code.is_none());
    }

    #[test]
    fn test_login_response_serialization() {
        let resp = LoginResponse {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            user: LoginUserInfo {
                id: "uid".into(),
                username: "alice".into(),
                roles: vec!["user".into()],
                permissions: vec![],
            },
            login_risk_level: "low".into(),
            security_warnings: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["user"]["username"], "alice");
    }

    #[test]
    fn test_register_request_deserialization() {
        let json = r#"{"username":"bob","password":"StrongP@ss1","email":"bob@example.com"}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "bob");
        assert_eq!(req.email, "bob@example.com");
    }

    #[test]
    fn test_refresh_request_deserialization() {
        let json = r#"{"refresh_token":"some_token"}"#;
        let req: RefreshRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.refresh_token, "some_token");
    }
}
