//! Administrative API Endpoints
//!
//! Handles user management, system configuration, and admin operations

use crate::api::{
    ApiResponse, ApiState, extract_bearer_token, responses::Pagination, validate_api_token,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};

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
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::<UserListResponse>::forbidden_typed();
                    }

                    // In a real implementation, fetch users from storage with pagination
                    let total_users = 150u64; // This would come from a count query in real implementation
                    let _offset = (query.page - 1) * query.limit;

                    // Validate pagination parameters
                    let page = if query.page == 0 { 1 } else { query.page };
                    let limit = if query.limit == 0 {
                        20
                    } else {
                        query.limit.min(100)
                    }; // Cap at 100 items per page

                    // Calculate total pages
                    let total_pages = ((total_users as f64) / (limit as f64)).ceil() as u32;
                    let total_pages = if total_pages == 0 { 1 } else { total_pages };

                    let users = vec![
                        UserListItem {
                            id: "user_1".to_string(),
                            username: "admin@example.com".to_string(),
                            email: "admin@example.com".to_string(),
                            roles: vec!["admin".to_string()],
                            active: true,
                            created_at: "2024-01-01T00:00:00Z".to_string(),
                            last_login: Some("2024-08-17T10:30:00Z".to_string()),
                        },
                        UserListItem {
                            id: "user_2".to_string(),
                            username: "user@example.com".to_string(),
                            email: "user@example.com".to_string(),
                            roles: vec!["user".to_string()],
                            active: true,
                            created_at: "2024-01-02T00:00:00Z".to_string(),
                            last_login: Some("2024-08-16T15:45:00Z".to_string()),
                        },
                    ];

                    let pagination = Pagination {
                        page,
                        limit,
                        total: total_users,
                        pages: total_pages,
                    };

                    let response = UserListResponse { users, pagination };

                    ApiResponse::success(response)
                }
                Err(e) => {
                    // Convert AuthError to typed response
                    let error_response = ApiResponse::<()>::from(e);
                    ApiResponse::<UserListResponse> {
                        success: error_response.success,
                        data: None,
                        error: error_response.error,
                        message: error_response.message,
                    }
                }
            }
        }
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

    if req.password.len() < 8 {
        return ApiResponse::<UserListItem>::validation_error_typed(
            "Password must be at least 8 characters long",
        );
    }

    match extract_bearer_token(&headers) {
        Some(token) => {
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Check admin permissions
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden_typed();
                    }

                    // In a real implementation:
                    // 1. Check if username/email already exists
                    // 2. Hash password
                    // 3. Create user in storage
                    // 4. Send welcome email

                    let new_user = UserListItem {
                        id: format!("user_{}", chrono::Utc::now().timestamp()),
                        username: req.username,
                        email: req.email,
                        roles: req.roles,
                        active: req.active,
                        created_at: chrono::Utc::now().to_rfc3339(),
                        last_login: None,
                    };

                    tracing::info!("New user created: {}", new_user.id);
                    ApiResponse::success(new_user)
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
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden();
                    }

                    // In a real implementation:
                    // 1. Validate user exists
                    // 2. Validate roles are valid
                    // 3. Update user roles in storage
                    // 4. Invalidate user's existing sessions if needed

                    tracing::info!("Updated roles for user {}: {:?}", user_id, req.roles);
                    ApiResponse::<()>::ok_with_message("User roles updated successfully")
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
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden();
                    }

                    // Prevent self-deletion
                    if auth_token.user_id == user_id {
                        return ApiResponse::validation_error("Cannot delete your own account");
                    }

                    // In a real implementation:
                    // 1. Validate user exists
                    // 2. Soft delete or hard delete based on policy
                    // 3. Invalidate all user sessions
                    // 4. Archive user data if required

                    tracing::info!("User deleted: {}", user_id);
                    ApiResponse::<()>::ok_with_message("User deleted successfully")
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
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden();
                    }

                    // In a real implementation:
                    // 1. Validate user exists
                    // 2. Update user active status
                    // 3. If deactivating, invalidate all user sessions

                    let action = if req.active {
                        "activated"
                    } else {
                        "deactivated"
                    };
                    tracing::info!("User {} {}", user_id, action);
                    ApiResponse::<()>::ok_with_message(format!("User {} successfully", action))
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
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden_typed();
                    }

                    // In a real implementation, collect actual system statistics
                    let stats = SystemStats {
                        total_users: 1250,
                        active_sessions: 45,
                        total_tokens: 892,
                        failed_logins_24h: 12,
                        system_uptime: "15 days, 4 hours".to_string(),
                        memory_usage: "256 MB / 1 GB".to_string(),
                        cpu_usage: "12%".to_string(),
                    };

                    ApiResponse::success(stats)
                }
                Err(_e) => ApiResponse::error_typed("AUTH_ERROR", "Token validation failed"),
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
                    if !auth_token.roles.contains(&"admin".to_string()) {
                        return ApiResponse::forbidden_typed();
                    }

                    // In a real implementation, fetch audit logs from storage with pagination
                    let total_logs = 1500u64; // This would come from a count query in real implementation
                    let _offset = (query.page - 1) * query.limit;

                    // Validate pagination parameters
                    let page = if query.page == 0 { 1 } else { query.page };
                    let limit = if query.limit == 0 {
                        20
                    } else {
                        query.limit.min(100)
                    }; // Cap at 100 items per page

                    // Calculate total pages
                    let total_pages = ((total_logs as f64) / (limit as f64)).ceil() as u32;
                    let total_pages = if total_pages == 0 { 1 } else { total_pages };

                    let logs = vec![
                        AuditLogEntry {
                            id: "audit_1".to_string(),
                            timestamp: "2024-08-17T10:30:00Z".to_string(),
                            user_id: "user_123".to_string(),
                            action: "login".to_string(),
                            resource: "/auth/login".to_string(),
                            ip_address: "192.168.1.100".to_string(),
                            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
                            result: "success".to_string(),
                        },
                        AuditLogEntry {
                            id: "audit_2".to_string(),
                            timestamp: "2024-08-17T10:25:00Z".to_string(),
                            user_id: "user_456".to_string(),
                            action: "password_change".to_string(),
                            resource: "/users/change-password".to_string(),
                            ip_address: "192.168.1.101".to_string(),
                            user_agent: "Mozilla/5.0 (macOS; Intel Mac OS X 10_15_7)".to_string(),
                            result: "success".to_string(),
                        },
                    ];

                    let pagination = Pagination {
                        page,
                        limit,
                        total: total_logs,
                        pages: total_pages,
                    };

                    let response = AuditLogResponse { logs, pagination };

                    ApiResponse::success(response)
                }
                Err(_e) => ApiResponse::error_typed("AUTH_ERROR", "Token validation failed"),
            }
        }
        None => ApiResponse::unauthorized_typed(),
    }
}
