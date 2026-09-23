//! Administrative API Endpoints
//!
//! Handles user management, system configuration, and admin operations.
//!
//! # Security Model
//!
//! **Every handler in this module must independently verify the caller holds the
//! `admin` role** via [`verify_admin_role`].  There is no middleware-level admin
//! guard on these routes — authorization is enforced per-handler so that
//! non-admin error paths can still return proper 401/403 responses.
//!
//! When adding new admin endpoints, always call `verify_admin_role(&auth_token)?`
//! immediately after token validation.

use crate::api::{
    ApiResponse, ApiState, extract_bearer_token, responses::Pagination, validate_api_token,
};
use crate::tokens::AuthToken;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Helper: verify the authenticated token carries the admin role
// ---------------------------------------------------------------------------
/// Checks that `auth_token` carries the `admin` role. Returns `Ok(())` on
/// success or an `ApiResponse::forbidden_typed()` error suitable for early
/// return from any admin handler.
#[allow(clippy::result_large_err)]
fn verify_admin_role<T: Serialize>(auth_token: &AuthToken) -> Result<(), ApiResponse<T>> {
    if auth_token.roles.contains("admin") {
        Ok(())
    } else {
        Err(ApiResponse::<T>::forbidden_typed())
    }
}

// ---------------------------------------------------------------------------
// Helper: load all user IDs from the global index
// ---------------------------------------------------------------------------
async fn load_user_ids(storage: &std::sync::Arc<dyn crate::storage::AuthStorage>) -> Vec<String> {
    match storage.get_kv("users:index").await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// Helper: load a single user record by user_id and convert to UserListItem
// ---------------------------------------------------------------------------
async fn load_user_item(
    storage: &std::sync::Arc<dyn crate::storage::AuthStorage>,
    user_id: &str,
) -> Option<UserListItem> {
    let key = format!("user:{}", user_id);
    let bytes = storage.get_kv(&key).await.ok()??;
    let data: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    let username = data["username"].as_str()?.to_string();
    let email = data["email"].as_str().unwrap_or("").to_string();
    let roles: Vec<String> = data["roles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["user".to_string()]);
    let active = data["active"].as_bool().unwrap_or(true);
    let created_at = data["created_at"].as_str().unwrap_or("").to_string();
    let last_login = data["last_login"].as_str().map(|s| s.to_string());

    Some(UserListItem {
        id: user_id.to_string(),
        username,
        email,
        roles,
        active,
        created_at,
        last_login,
    })
}

/// User list item
#[derive(Debug, Serialize)]
pub struct UserListItem {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub active: bool,
    pub created_at: String,
    pub last_login: Option<String>,
}

/// User list response
#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserListItem>,
    pub pagination: Pagination,
}

/// User list query parameters
#[derive(Debug, Deserialize)]
pub struct UserListQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
}

fn default_page() -> u32 {
    1
}
fn default_limit() -> u32 {
    20
}

/// Create user request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_active() -> bool {
    true
}

/// Update user roles request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRolesRequest {
    pub roles: Vec<String>,
}

/// System stats response
#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub total_users: u64,
    pub active_sessions: u64,
    pub total_tokens: u64,
    pub failed_logins_24h: u64,
    pub system_uptime: String,
    pub memory_usage: String,
    pub cpu_usage: String,
}

/// GET /admin/users
/// List all users (admin only)
pub async fn list_users(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<UserListQuery>,
) -> ApiResponse<UserListResponse> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                if let Err(resp) = verify_admin_role::<UserListResponse>(&auth_token) {
                    return resp;
                }

                let storage = state.auth_framework.storage();
                let all_ids = load_user_ids(&storage).await;

                let mut users: Vec<UserListItem> = Vec::new();
                for id in &all_ids {
                    if let Some(item) = load_user_item(&storage, id).await {
                        if let Some(ref search) = query.search {
                            let s = search.to_lowercase();
                            if !item.username.to_lowercase().contains(&s)
                                && !item.email.to_lowercase().contains(&s)
                            {
                                continue;
                            }
                        }
                        if let Some(ref role) = query.role
                            && !item.roles.contains(role)
                        {
                            continue;
                        }
                        if let Some(filter_active) = query.active
                            && item.active != filter_active
                        {
                            continue;
                        }
                        users.push(item);
                    }
                }

                let total_users = users.len() as u64;
                let page = if query.page == 0 { 1 } else { query.page };
                let limit = if query.limit == 0 {
                    20
                } else {
                    query.limit.min(100)
                };
                let offset = ((page - 1) * limit) as usize;
                let total_pages = ((total_users as f64) / (limit as f64)).ceil() as u32;
                let total_pages = if total_pages == 0 { 1 } else { total_pages };

                let page_users: Vec<UserListItem> = users
                    .into_iter()
                    .skip(offset)
                    .take(limit as usize)
                    .collect();

                let pagination = Pagination {
                    page,
                    limit,
                    total: total_users,
                    pages: total_pages,
                };

                ApiResponse::success(UserListResponse {
                    users: page_users,
                    pagination,
                })
            }
            Err(e) => {
                let error_response = ApiResponse::<()>::from(e);
                ApiResponse::<UserListResponse> {
                    success: error_response.success,
                    data: None,
                    error: error_response.error,
                    message: error_response.message,
                }
            }
        },
        None => ApiResponse::<UserListResponse>::unauthorized_typed(),
    }
}

/// POST /admin/users
/// Create new user (admin only)
pub async fn create_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> ApiResponse<UserListItem> {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() || req.email.is_empty() {
        return ApiResponse::<UserListItem>::validation_error_typed(
            "Username, password, and email are required",
        );
    }

    // Validate username format — same rules as the public registration endpoint.
    if crate::utils::validation::validate_username(&req.username).is_err() {
        return ApiResponse::<UserListItem>::validation_error_typed(
            "Invalid username: must be 3-50 characters, start with a letter, and contain only letters, numbers, underscores, or hyphens",
        );
    }

    // Enforce length limits on optional name fields.
    if req.first_name.as_deref().is_some_and(|n| n.len() > 100) {
        return ApiResponse::<UserListItem>::validation_error_typed(
            "First name must be 100 characters or fewer",
        );
    }
    if req.last_name.as_deref().is_some_and(|n| n.len() > 100) {
        return ApiResponse::<UserListItem>::validation_error_typed(
            "Last name must be 100 characters or fewer",
        );
    }

    // Validate email format for consistency with the public registration endpoint.
    if crate::utils::validation::validate_email(&req.email).is_err() {
        return ApiResponse::<UserListItem>::validation_error_typed("Invalid email format");
    }

    // SECURITY (M-12): Use the same password validation as the public register endpoint
    // so that admin-created accounts cannot bypass complexity requirements.
    if let Err(e) = crate::utils::validation::validate_password(&req.password) {
        // Return a generic message to avoid leaking internal validation rule details.
        tracing::warn!("Admin create_user password validation failed: {e}");
        return ApiResponse::<UserListItem>::validation_error_typed(
            "Password does not meet complexity requirements",
        );
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if let Err(resp) = verify_admin_role(&auth_token) {
                        return resp;
                    }

                    match state
                        .auth_framework
                        .register_user(&req.username, &req.email, &req.password)
                        .await
                    {
                        Ok(user_id) => {
                            if !(req.roles.is_empty()
                                || req.roles.len() == 1 && req.roles[0] == "user")
                                && let Err(e) = state
                                    .auth_framework
                                    .update_user_roles(&user_id, &req.roles)
                                    .await
                            {
                                tracing::warn!(
                                    "Failed to set roles for new user {}: {}",
                                    user_id,
                                    e
                                );
                            }
                            if !req.active
                                && let Err(e) =
                                    state.auth_framework.set_user_active(&user_id, false).await
                            {
                                tracing::warn!("Failed to deactivate new user {}: {}", user_id, e);
                            }
                            let new_user = UserListItem {
                                id: user_id.clone(),
                                username: req.username.clone(),
                                email: req.email.clone(),
                                roles: if req.roles.is_empty() {
                                    vec!["user".to_string()]
                                } else {
                                    req.roles.clone()
                                },
                                active: req.active,
                                created_at: chrono::Utc::now().to_rfc3339(),
                                last_login: None,
                            };
                            tracing::info!("Admin created user: {} ({})", req.username, user_id);
                            ApiResponse::success(new_user)
                        }
                        Err(e) => {
                            let error_response = ApiResponse::<()>::from(e);
                            ApiResponse::<UserListItem> {
                                success: error_response.success,
                                data: None,
                                error: error_response.error,
                                message: error_response.message,
                            }
                        }
                    }
                }
                Err(e) => {
                    // Convert AuthError to typed response
                    let error_response = ApiResponse::<()>::from(e);
                    ApiResponse::<UserListItem> {
                        success: error_response.success,
                        data: None,
                        error: error_response.error,
                        message: error_response.message,
                    }
                }
            }
        }
        None => ApiResponse::<UserListItem>::unauthorized_typed(),
    }
}

/// PUT /admin/users/{user_id}/roles
/// Update user roles (admin only)
pub async fn update_user_roles(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRolesRequest>,
) -> ApiResponse<()> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if let Err(resp) = verify_admin_role(&auth_token) {
                        return resp;
                    }

                    match state
                        .auth_framework
                        .update_user_roles(&user_id, &req.roles)
                        .await
                    {
                        Ok(()) => {
                            tracing::info!(
                                "Admin updated roles for user {}: {:?}",
                                user_id,
                                req.roles
                            );
                            ApiResponse::<()>::ok_with_message("User roles updated successfully")
                        }
                        Err(e) => e.into(),
                    }
                }
                Err(e) => e.into(),
            }
        }
        None => ApiResponse::unauthorized(),
    }
}

/// DELETE /admin/users/{user_id}
/// Delete user (admin only)
pub async fn delete_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResponse<()> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if let Err(resp) = verify_admin_role(&auth_token) {
                        return resp;
                    }

                    // Prevent self-deletion
                    if auth_token.user_id == user_id {
                        return ApiResponse::validation_error("Cannot delete your own account");
                    }

                    match state.auth_framework.get_username_by_id(&user_id).await {
                        Ok(username) => match state.auth_framework.delete_user(&username).await {
                            Ok(()) => {
                                tracing::info!("Admin deleted user: {} ({})", username, user_id);
                                ApiResponse::<()>::ok_with_message("User deleted successfully")
                            }
                            Err(e) => e.into(),
                        },
                        Err(e) => e.into(),
                    }
                }
                Err(e) => e.into(),
            }
        }
        None => ApiResponse::unauthorized(),
    }
}

/// PUT /admin/users/{user_id}/activate
/// Activate/deactivate user (admin only)
#[derive(Debug, Deserialize)]
pub struct ActivateUserRequest {
    pub active: bool,
}

pub async fn activate_user(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<ActivateUserRequest>,
) -> ApiResponse<()> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if !auth_token.roles.contains("admin") {
                        return ApiResponse::forbidden();
                    }

                    match state
                        .auth_framework
                        .set_user_active(&user_id, req.active)
                        .await
                    {
                        Ok(()) => {
                            let action = if req.active {
                                "activated"
                            } else {
                                "deactivated"
                            };
                            tracing::info!("Admin {} user {}", action, user_id);
                            ApiResponse::<()>::ok_with_message(format!(
                                "User {} successfully",
                                action
                            ))
                        }
                        Err(e) => e.into(),
                    }
                }
                Err(e) => e.into(),
            }
        }
        None => ApiResponse::unauthorized(),
    }
}

/// GET /admin/stats
/// Get system statistics (admin only)
pub async fn get_system_stats(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<SystemStats> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if !auth_token.roles.contains("admin") {
                        return ApiResponse::forbidden_typed();
                    }

                    let storage = state.auth_framework.storage();
                    let total_users = load_user_ids(&storage).await.len() as u64;
                    let active_sessions = storage.count_active_sessions().await.unwrap_or(0);

                    // Collect real system metrics via the sysinfo crate.
                    let (system_uptime, memory_usage, cpu_usage) = {
                        use sysinfo::System;
                        let mut sys = System::new();
                        sys.refresh_memory();
                        sys.refresh_cpu_usage();
                        let uptime_secs = System::uptime();
                        let hours = uptime_secs / 3600;
                        let mins = (uptime_secs % 3600) / 60;
                        let secs = uptime_secs % 60;
                        let uptime_str = format!("{hours}h {mins}m {secs}s");
                        let used_mb = sys.used_memory() as f64 / 1_048_576.0;
                        let total_mb = sys.total_memory() as f64 / 1_048_576.0;
                        let mem_str = format!("{used_mb:.1} MB / {total_mb:.1} MB");
                        let cpu_str = format!("{:.1}%", sys.global_cpu_usage());
                        (uptime_str, mem_str, cpu_str)
                    };

                    let stats = SystemStats {
                        total_users,
                        active_sessions,
                        // token count: proxy active sessions — each session
                        // corresponds to at least one issued JWT token.
                        total_tokens: active_sessions,
                        // Persistent audit log not wired; cannot derive 24h
                        // failure count from in-memory state alone.
                        failed_logins_24h: 0,
                        system_uptime,
                        memory_usage,
                        cpu_usage,
                    };

                    ApiResponse::success(stats)
                }
                Err(e) => {
                    let error_response = ApiResponse::<()>::from(e);
                    ApiResponse::<SystemStats> {
                        success: error_response.success,
                        data: None,
                        error: error_response.error,
                        message: error_response.message,
                    }
                }
            }
        }
        None => ApiResponse::unauthorized_typed(),
    }
}

/// GET /admin/audit-logs
/// Get audit logs (admin only)
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub ip_address: String,
    pub user_agent: String,
    pub result: String,
    /// Risk level of the event: "low", "medium", "high", or "critical".
    pub risk_level: String,
    /// Outcome: "success", "failure", "partial", or "unknown".
    pub outcome: String,
    /// Correlation ID linking related events across the same authentication flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogEntry>,
    pub pagination: Pagination,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub start_date: Option<String>,
    #[serde(default)]
    pub end_date: Option<String>,
    /// Filter by risk level: "low", "medium", "high", or "critical".
    #[serde(default)]
    pub risk_level: Option<String>,
    /// Filter by outcome: "success" or "failure".
    #[serde(default)]
    pub outcome: Option<String>,
    /// Filter by correlation ID to trace a single authentication flow.
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Filter by client IP address.
    #[serde(default)]
    pub ip_address: Option<String>,
}

pub async fn get_audit_logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AuditLogQuery>,
) -> ApiResponse<AuditLogResponse> {
    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if !auth_token.roles.contains("admin") {
                        return ApiResponse::forbidden_typed();
                    }

                    let page = if query.page == 0 { 1 } else { query.page };
                    let limit = if query.limit == 0 {
                        20
                    } else {
                        query.limit.min(100)
                    };
                    let offset = ((page - 1) * limit) as usize;
                    let fetch_limit = offset + limit as usize;

                    match state
                        .auth_framework
                        .get_permission_audit_logs(
                            query.user_id.as_deref(),
                            query.action.as_deref(),
                            None,
                            Some(fetch_limit),
                        )
                        .await
                    {
                        Ok(all_logs) => {
                            // Parse and enrich all log entries first so filtering is applied
                            // before pagination.
                            let mut parsed: Vec<AuditLogEntry> = all_logs
                                .into_iter()
                                .enumerate()
                                .map(|(i, log_str)| {
                                    let (ts, rest) = log_str
                                        .strip_prefix('[')
                                        .and_then(|s| s.split_once(']'))
                                        .map(|(t, r)| (t.trim().to_string(), r.trim().to_string()))
                                        .unwrap_or_else(|| {
                                            ("unknown".to_string(), log_str.clone())
                                        });
                                    let uid = rest
                                        .split_whitespace()
                                        .find(|w| w.starts_with("user="))
                                        .and_then(|w| w.strip_prefix("user="))
                                        .unwrap_or("system")
                                        .to_string();
                                    let raw_outcome = rest
                                        .split_whitespace()
                                        .find(|w| w.starts_with("outcome="))
                                        .and_then(|w| w.strip_prefix("outcome="))
                                        .unwrap_or("unknown")
                                        .to_string();
                                    let ip = rest
                                        .split_whitespace()
                                        .find(|w| w.starts_with("ip="))
                                        .and_then(|w| w.strip_prefix("ip="))
                                        .unwrap_or("")
                                        .to_string();
                                    let ua = rest
                                        .split_whitespace()
                                        .find(|w| w.starts_with("ua="))
                                        .and_then(|w| w.strip_prefix("ua="))
                                        .unwrap_or("")
                                        .to_string();
                                    let corr = rest
                                        .split_whitespace()
                                        .find(|w| w.starts_with("correlation_id="))
                                        .and_then(|w| w.strip_prefix("correlation_id="))
                                        .map(str::to_string);
                                    // Derive outcome category and risk level from the raw
                                    // outcome token present in the log line.
                                    let outcome = if raw_outcome.contains("success") {
                                        "success"
                                    } else if raw_outcome.contains("fail")
                                        || raw_outcome.contains("error")
                                    {
                                        "failure"
                                    } else {
                                        "unknown"
                                    };
                                    // Risk level: failures + high index numbers treated as
                                    // higher risk for demonstration; real implementations
                                    // should propagate risk from the authentication path.
                                    let risk_level = if outcome == "failure" {
                                        "medium"
                                    } else {
                                        "low"
                                    };
                                    AuditLogEntry {
                                        id: format!("audit_{}", i),
                                        timestamp: ts,
                                        user_id: uid,
                                        action: rest,
                                        resource: String::new(),
                                        ip_address: ip,
                                        user_agent: ua,
                                        result: raw_outcome,
                                        risk_level: risk_level.to_string(),
                                        outcome: outcome.to_string(),
                                        correlation_id: corr,
                                    }
                                })
                                .collect();

                            // Apply optional client-side filters on the enriched entries.
                            if let Some(ref filter_ip) = query.ip_address {
                                parsed.retain(|e| e.ip_address.contains(filter_ip.as_str()));
                            }
                            if let Some(ref filter_risk) = query.risk_level {
                                parsed.retain(|e| e.risk_level == filter_risk.as_str());
                            }
                            if let Some(ref filter_outcome) = query.outcome {
                                parsed.retain(|e| e.outcome == filter_outcome.as_str());
                            }
                            if let Some(ref filter_corr) = query.correlation_id {
                                parsed.retain(|e| {
                                    e.correlation_id.as_deref() == Some(filter_corr.as_str())
                                });
                            }

                            let total = parsed.len() as u64;
                            let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;
                            let total_pages = if total_pages == 0 { 1 } else { total_pages };

                            let logs: Vec<AuditLogEntry> = parsed
                                .into_iter()
                                .skip(offset)
                                .take(limit as usize)
                                .collect();

                            ApiResponse::success(AuditLogResponse {
                                logs,
                                pagination: Pagination {
                                    page,
                                    limit,
                                    total,
                                    pages: total_pages,
                                },
                            })
                        }
                        Err(e) => {
                            let error_response = ApiResponse::<()>::from(e);
                            ApiResponse::<AuditLogResponse> {
                                success: error_response.success,
                                data: None,
                                error: error_response.error,
                                message: error_response.message,
                            }
                        }
                    }
                }
                Err(e) => {
                    let error_response = ApiResponse::<()>::from(e);
                    ApiResponse::<AuditLogResponse> {
                        success: error_response.success,
                        data: None,
                        error: error_response.error,
                        message: error_response.message,
                    }
                }
            }
        }
        None => ApiResponse::unauthorized_typed(),
    }
}

/// Summary statistics returned by `GET /admin/audit-logs/stats`.
#[derive(Debug, Serialize)]
pub struct AuditLogStats {
    /// Total events recorded in the last 24 hours.
    pub total_events_24h: u64,
    /// Failed login events in the last 24 hours.
    pub failed_logins_24h: u64,
    /// Successful login events in the last 24 hours.
    pub successful_logins_24h: u64,
    /// Events flagged as high-risk or critical in the last 24 hours.
    pub high_risk_events_24h: u64,
    /// Distinct user IDs seen in the last 24 hours.
    pub unique_users_24h: u64,
    /// Security alerts raised in the last 24 hours.
    pub security_alerts_24h: u64,
}

/// GET /admin/audit-logs/stats
///
/// Returns aggregated audit-log statistics for the last 24 hours.
/// Requires an admin bearer token.
pub async fn get_audit_log_stats(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<AuditLogStats> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                if !auth_token.roles.contains("admin") {
                    return ApiResponse::forbidden_typed();
                }

                match state.auth_framework.get_security_audit_stats().await {
                    Ok(sec_stats) => ApiResponse::success(AuditLogStats {
                        total_events_24h: sec_stats.failed_logins_24h
                            + sec_stats.successful_logins_24h
                            + sec_stats.admin_actions_24h,
                        failed_logins_24h: sec_stats.failed_logins_24h,
                        successful_logins_24h: sec_stats.successful_logins_24h,
                        high_risk_events_24h: sec_stats.security_alerts_24h,
                        unique_users_24h: sec_stats.unique_users_24h,
                        security_alerts_24h: sec_stats.security_alerts_24h,
                    }),
                    Err(e) => {
                        let error_response = ApiResponse::<()>::from(e);
                        ApiResponse::<AuditLogStats> {
                            success: error_response.success,
                            data: None,
                            error: error_response.error,
                            message: error_response.message,
                        }
                    }
                }
            }
            Err(e) => {
                let error_response = ApiResponse::<()>::from(e);
                ApiResponse::<AuditLogStats> {
                    success: error_response.success,
                    data: None,
                    error: error_response.error,
                    message: error_response.message,
                }
            }
        },
        None => ApiResponse::unauthorized_typed(),
    }
}

// ─── Admin configuration endpoints ──────────────────────────────────────────

/// Response body for `GET /admin/config`.
///
/// Only runtime-mutable fields are exposed. Security-sensitive settings (JWT
/// secret, signing algorithm, storage backend) are intentionally omitted.
#[derive(Debug, Serialize)]
pub struct AdminConfigView {
    pub token_lifetime_secs: u64,
    pub refresh_token_lifetime_secs: u64,
    pub enable_multi_factor: bool,
    pub rate_limiting_enabled: bool,
    pub rate_limit_max_requests: u32,
    pub rate_limit_window_secs: u64,
    pub rate_limit_burst: u32,
    pub min_password_length: usize,
    pub require_password_complexity: bool,
    pub secure_cookies: bool,
    pub csrf_protection: bool,
    pub session_timeout_secs: u64,
    pub audit_enabled: bool,
    pub audit_log_success: bool,
    pub audit_log_failures: bool,
    pub audit_log_permissions: bool,
    pub audit_log_tokens: bool,
}

impl From<crate::config::RuntimeConfig> for AdminConfigView {
    fn from(c: crate::config::RuntimeConfig) -> Self {
        Self {
            token_lifetime_secs: c.token_lifetime_secs,
            refresh_token_lifetime_secs: c.refresh_token_lifetime_secs,
            enable_multi_factor: c.enable_multi_factor,
            rate_limiting_enabled: c.rate_limiting_enabled,
            rate_limit_max_requests: c.rate_limit_max_requests,
            rate_limit_window_secs: c.rate_limit_window_secs,
            rate_limit_burst: c.rate_limit_burst,
            min_password_length: c.min_password_length,
            require_password_complexity: c.require_password_complexity,
            secure_cookies: c.secure_cookies,
            csrf_protection: c.csrf_protection,
            session_timeout_secs: c.session_timeout_secs,
            audit_enabled: c.audit_enabled,
            audit_log_success: c.audit_log_success,
            audit_log_failures: c.audit_log_failures,
            audit_log_permissions: c.audit_log_permissions,
            audit_log_tokens: c.audit_log_tokens,
        }
    }
}

/// Request body for `PUT /admin/config` — all fields optional.
///
/// Omitted fields retain their current values.  This enables partial updates
/// (patch semantics) without the client needing to re-send unchanged settings.
#[derive(Debug, Deserialize)]
pub struct AdminConfigUpdate {
    #[serde(default)]
    pub token_lifetime_secs: Option<u64>,
    #[serde(default)]
    pub refresh_token_lifetime_secs: Option<u64>,
    #[serde(default)]
    pub enable_multi_factor: Option<bool>,
    #[serde(default)]
    pub rate_limiting_enabled: Option<bool>,
    #[serde(default)]
    pub rate_limit_max_requests: Option<u32>,
    #[serde(default)]
    pub rate_limit_window_secs: Option<u64>,
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
    #[serde(default)]
    pub min_password_length: Option<usize>,
    #[serde(default)]
    pub require_password_complexity: Option<bool>,
    #[serde(default)]
    pub secure_cookies: Option<bool>,
    #[serde(default)]
    pub csrf_protection: Option<bool>,
    #[serde(default)]
    pub session_timeout_secs: Option<u64>,
    #[serde(default)]
    pub audit_enabled: Option<bool>,
    #[serde(default)]
    pub audit_log_success: Option<bool>,
    #[serde(default)]
    pub audit_log_failures: Option<bool>,
    #[serde(default)]
    pub audit_log_permissions: Option<bool>,
    #[serde(default)]
    pub audit_log_tokens: Option<bool>,
}

/// GET /admin/config
///
/// Returns the current runtime-mutable configuration.  Requires admin bearer token.
pub async fn get_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<AdminConfigView> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                if !auth_token.roles.contains("admin") {
                    return ApiResponse::forbidden_typed();
                }
                let cfg = state.auth_framework.runtime_config().await;
                ApiResponse::success(AdminConfigView::from(cfg))
            }
            Err(e) => {
                let error_response = ApiResponse::<()>::from(e);
                ApiResponse::<AdminConfigView> {
                    success: error_response.success,
                    data: None,
                    error: error_response.error,
                    message: error_response.message,
                }
            }
        },
        None => ApiResponse::unauthorized_typed(),
    }
}

/// PUT /admin/config
///
/// Applies a partial update to the runtime-mutable configuration.  Requires admin
/// bearer token.  Returns the updated configuration after applying all changes.
pub async fn update_config(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(update): Json<AdminConfigUpdate>,
) -> ApiResponse<AdminConfigView> {
    match extract_bearer_token(&headers) {
        Some(token) => match validate_api_token(&state.auth_framework, &token).await {
            Ok(auth_token) => {
                if !auth_token.roles.contains("admin") {
                    return ApiResponse::forbidden_typed();
                }

                // Load current config, merge, then validate via update_runtime_config.
                let mut current = state.auth_framework.runtime_config().await;
                if let Some(v) = update.token_lifetime_secs {
                    current.token_lifetime_secs = v;
                }
                if let Some(v) = update.refresh_token_lifetime_secs {
                    current.refresh_token_lifetime_secs = v;
                }
                if let Some(v) = update.enable_multi_factor {
                    current.enable_multi_factor = v;
                }
                if let Some(v) = update.rate_limiting_enabled {
                    current.rate_limiting_enabled = v;
                }
                if let Some(v) = update.rate_limit_max_requests {
                    current.rate_limit_max_requests = v;
                }
                if let Some(v) = update.rate_limit_window_secs {
                    current.rate_limit_window_secs = v;
                }
                if let Some(v) = update.rate_limit_burst {
                    current.rate_limit_burst = v;
                }
                if let Some(v) = update.min_password_length {
                    current.min_password_length = v;
                }
                if let Some(v) = update.require_password_complexity {
                    current.require_password_complexity = v;
                }
                if let Some(v) = update.secure_cookies {
                    current.secure_cookies = v;
                }
                if let Some(v) = update.csrf_protection {
                    current.csrf_protection = v;
                }
                if let Some(v) = update.session_timeout_secs {
                    current.session_timeout_secs = v;
                }
                if let Some(v) = update.audit_enabled {
                    current.audit_enabled = v;
                }
                if let Some(v) = update.audit_log_success {
                    current.audit_log_success = v;
                }
                if let Some(v) = update.audit_log_failures {
                    current.audit_log_failures = v;
                }
                if let Some(v) = update.audit_log_permissions {
                    current.audit_log_permissions = v;
                }
                if let Some(v) = update.audit_log_tokens {
                    current.audit_log_tokens = v;
                }

                match state.auth_framework.update_runtime_config(current).await {
                    Ok(updated) => ApiResponse::success(AdminConfigView::from(updated)),
                    Err(e) => {
                        let error_response = ApiResponse::<()>::from(e);
                        ApiResponse::<AdminConfigView> {
                            success: error_response.success,
                            data: None,
                            error: error_response.error,
                            message: error_response.message,
                        }
                    }
                }
            }
            Err(e) => {
                let error_response = ApiResponse::<()>::from(e);
                ApiResponse::<AdminConfigView> {
                    success: error_response.success,
                    data: None,
                    error: error_response.error,
                    message: error_response.message,
                }
            }
        },
        None => ApiResponse::unauthorized_typed(),
    }
}
