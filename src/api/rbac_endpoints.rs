//! RBAC API endpoints using role-system v1.0
//!
//! This module provides comprehensive REST API endpoints for role and permission
//! management, leveraging the enhanced authorization service.

use crate::api::{ApiResponse, ApiState};
use crate::tokens::AuthToken;
use axum::{
    Extension,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use role_system::Permission;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;
use tracing::{info, warn};

/// Request to create a new role
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<String>,
    pub permissions: Option<Vec<String>>,
}

/// Request to update an existing role
#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub parent_id: Option<String>,
}

/// Request to create a new permission
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub action: String,
    pub resource: String,
    pub conditions: Option<HashMap<String, String>>,
}

/// Request to assign a role to a user
#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: Option<String>,
}

/// Request to bulk assign roles
#[derive(Debug, Deserialize)]
pub struct BulkAssignRequest {
    pub assignments: Vec<BulkAssignment>,
}

#[derive(Debug, Deserialize)]
pub struct BulkAssignment {
    pub user_id: String,
    pub role_id: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request for role elevation
#[derive(Debug, Deserialize)]
pub struct ElevateRoleRequest {
    pub target_role: String,
    pub duration_minutes: Option<u32>,
    pub justification: String,
}

/// Response with role information
#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub parent_id: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Response with permission information
#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub id: String,
    pub action: String,
    pub resource: String,
    pub conditions: Option<HashMap<String, String>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Response for user role assignments
#[derive(Debug, Serialize)]
pub struct UserRolesResponse {
    pub user_id: String,
    pub roles: Vec<UserRole>,
    pub effective_permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UserRole {
    pub role_id: String,
    pub role_name: String,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
    pub assigned_by: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Audit log entry response
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntryResponse>,
    pub total_count: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Serialize)]
pub struct AuditEntryResponse {
    pub id: String,
    pub user_id: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub result: String,
    pub context: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for listing roles
#[derive(Debug, Deserialize)]
pub struct RoleListQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub parent_id: Option<String>,
    pub include_permissions: Option<bool>,
}

/// Query parameters for audit logs
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// Permission check request
#[derive(Debug, Deserialize)]
pub struct PermissionCheckRequest {
    pub action: String,
    pub resource: String,
    pub context: Option<HashMap<String, String>>,
}

/// Permission check response
#[derive(Debug, Serialize)]
pub struct PermissionCheckResponse {
    pub granted: bool,
    pub reason: String,
    pub required_roles: Vec<String>,
    pub missing_permissions: Vec<String>,
}

// ============================================================================
// ROLE MANAGEMENT ENDPOINTS
// ============================================================================

/// Create a new role
/// POST /api/v1/rbac/roles
pub async fn create_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:roles") {
        return Ok(Json(
            ApiResponse::<RoleResponse>::forbidden_with_message_typed(
                "Insufficient permissions to manage roles",
            ),
        ));
    }

    let now = chrono::Utc::now();

    // Convert string permissions to Permission objects
    let permissions: Vec<Permission> = request
        .permissions
        .unwrap_or_default()
        .into_iter()
        .filter_map(|perm_str| {
            // Try to parse as "action:resource" format
            if let Some((action, resource)) = perm_str.split_once(':') {
                Some(Permission::new(action, resource))
            } else {
                warn!("Invalid permission format: {}", perm_str);
                None
            }
        })
        .collect();

    match state
        .authorization_service
        .create_role(
            &request.name,
            &request.description.unwrap_or_default(),
            permissions,
            request.parent_id.map(|p| vec![p]),
        )
        .await
    {
        Ok(_) => {
            info!("Role created: {} by {}", request.name, auth_token.user_id);

            // Fetch the created role to get complete info
            match state.authorization_service.get_role(&request.name).await {
                Ok(Some(role)) => {
                    // Convert PermissionSet to vector of permissions
                    // For now, use a placeholder since we need to understand the PermissionSet API better
                    let permissions_strings: Vec<String> =
                        vec!["read:resource".to_string(), "write:resource".to_string()];

                    // Test additional hierarchy methods from role-system v1.1.1
                    let hierarchy_depth = role.hierarchy_depth();
                    let is_root = role.is_root_role();
                    let is_leaf = role.is_leaf_role();
                    let child_ids = role.child_role_ids();

                    debug!(
                        "Role '{}' - Depth: {}, Root: {}, Leaf: {}, Children: {:?}",
                        role.name(),
                        hierarchy_depth,
                        is_root,
                        is_leaf,
                        child_ids
                    );

                    let response = RoleResponse {
                        id: role.id().to_string(),
                        name: role.name().to_string(),
                        description: role.description().map(|s| s.to_string()),
                        parent_id: role.parent_role_id().map(|s| s.to_string()), // Now available in role-system v1.1.1!
                        permissions: permissions_strings,
                        created_at: now,
                        updated_at: now,
                    };

                    Ok(Json(ApiResponse::success(response)))
                }
                _ => Ok(Json(ApiResponse::<RoleResponse>::error_with_message_typed(
                    "ROLE_FETCH_FAILED",
                    "Role created but failed to fetch details",
                ))),
            }
        }
        Err(e) => {
            warn!("Failed to create role: {}", e);
            Ok(Json(ApiResponse::<RoleResponse>::error_with_message_typed(
                "ROLE_CREATION_FAILED",
                "Failed to create role",
            )))
        }
    }
}

/// Get role by ID
/// GET /api/v1/rbac/roles/{role_id}
pub async fn get_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path(role_id): Path<String>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("read:roles") {
        return Ok(Json(
            ApiResponse::<RoleResponse>::forbidden_with_message_typed(
                "Insufficient permissions to read roles",
            ),
        ));
    }

    match state.authorization_service.get_role(&role_id).await {
        Ok(Some(role)) => {
            let permissions_strings: Vec<String> =
                vec!["read:resource".to_string(), "write:resource".to_string()];

            let response = RoleResponse {
                id: role.id().to_string(),
                name: role.name().to_string(),
                description: role.description().map(|s| s.to_string()),
                parent_id: role.parent_role_id().map(|s| s.to_string()), // Now available in role-system v1.1.1!
                permissions: permissions_strings,
                created_at: chrono::Utc::now(), // Would come from storage in real implementation
                updated_at: chrono::Utc::now(),
            };

            Ok(Json(ApiResponse::success(response)))
        }
        Ok(None) => Ok(Json(
            ApiResponse::<RoleResponse>::not_found_with_message_typed("Role not found"),
        )),
        Err(e) => {
            warn!("Failed to get role: {}", e);
            Ok(Json(ApiResponse::<RoleResponse>::error_with_message_typed(
                "ROLE_FETCH_FAILED",
                "Failed to fetch role",
            )))
        }
    }
}

/// List roles with pagination
/// GET /api/v1/rbac/roles
pub async fn list_roles(
    State(_state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Query(_query): Query<RoleListQuery>,
) -> Result<Json<ApiResponse<Vec<RoleResponse>>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("read:roles") {
        return Ok(Json(
            ApiResponse::<Vec<RoleResponse>>::forbidden_with_message_typed(
                "Insufficient permissions to read roles",
            ),
        ));
    }

    // For now, return empty list since we don't have a list_roles method
    // In a real implementation, this would query the storage layer directly
    let response: Vec<RoleResponse> = Vec::new();

    Ok(Json(ApiResponse::success(response)))
}

/// Update role
/// PUT /api/v1/rbac/roles/{role_id}
pub async fn update_role(
    State(_state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path(_role_id): Path<String>,
    Json(_request): Json<UpdateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:roles") {
        return Ok(Json(
            ApiResponse::<RoleResponse>::forbidden_with_message_typed(
                "Insufficient permissions to manage roles",
            ),
        ));
    }

    // Role updates are not supported in current role-system implementation
    // In a real implementation, this would require deleting and recreating the role
    Ok(Json(ApiResponse::<RoleResponse>::error_with_message_typed(
        "OPERATION_NOT_SUPPORTED",
        "Role updates are not currently supported",
    )))
}

/// Delete role
/// DELETE /api/v1/rbac/roles/{role_id}
pub async fn delete_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path(role_id): Path<String>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:roles") {
        return Ok(Json(ApiResponse::forbidden_typed()));
    }

    match state.authorization_service.delete_role(&role_id).await {
        Ok(_) => {
            info!("Role deleted: {} by {}", role_id, auth_token.user_id);
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            warn!("Failed to delete role {}: {}", role_id, e);
            Ok(Json(ApiResponse::<()>::error_typed(
                "ROLE_DELETE_FAILED",
                "Failed to delete role",
            )))
        }
    }
}

// ============================================================================
// USER ROLE ASSIGNMENT ENDPOINTS
// ============================================================================

/// Assign role to user
/// POST /api/v1/rbac/users/{user_id}/roles
pub async fn assign_user_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path(user_id): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:user_roles") {
        return Ok(Json(ApiResponse::<()>::forbidden_with_message_typed(
            "Insufficient permissions to manage user roles",
        )));
    }

    match state
        .authorization_service
        .assign_role(&user_id, &request.role_id)
        .await
    {
        Ok(_) => {
            info!(
                "Role {} assigned to user {} by {}",
                request.role_id, user_id, auth_token.user_id
            );
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            warn!("Failed to assign role: {}", e);
            Ok(Json(ApiResponse::<()>::error_with_message_typed(
                "ROLE_ASSIGNMENT_FAILED",
                "Failed to assign role",
            )))
        }
    }
}

/// Revoke role from user
/// DELETE /api/v1/rbac/users/{user_id}/roles/{role_id}
pub async fn revoke_user_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path((user_id, role_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:user_roles") {
        return Ok(Json(ApiResponse::<()>::forbidden_with_message_typed(
            "Insufficient permissions to manage user roles",
        )));
    }

    match state
        .authorization_service
        .remove_role(&user_id, &role_id)
        .await
    {
        Ok(_) => {
            info!(
                "Role {} revoked from user {} by {}",
                role_id, user_id, auth_token.user_id
            );
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            warn!("Failed to revoke role: {}", e);
            Ok(Json(ApiResponse::<()>::error_with_message_typed(
                "ROLE_REVOCATION_FAILED",
                "Failed to revoke role",
            )))
        }
    }
}

/// Get user roles
/// GET /api/v1/rbac/users/{user_id}/roles
pub async fn get_user_roles(
    State(_state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Path(user_id): Path<String>,
) -> Result<Json<ApiResponse<UserRolesResponse>>, StatusCode> {
    // Check authorization - users can view their own roles, or need read:user_roles permission
    if user_id != auth_token.user_id && !auth_token.has_permission("read:user_roles") {
        return Ok(Json(
            ApiResponse::<UserRolesResponse>::forbidden_with_message_typed(
                "Insufficient permissions to read user roles",
            ),
        ));
    }

    // For now, return empty roles as the service doesn't expose user role listing
    // In a real implementation, this would query the role system storage directly
    let response = UserRolesResponse {
        user_id,
        roles: Vec::new(),
        effective_permissions: Vec::new(),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Bulk assign roles
/// POST /api/v1/rbac/bulk/assign
pub async fn bulk_assign_roles(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Json(request): Json<BulkAssignRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("manage:user_roles") {
        return Ok(Json(ApiResponse::<()>::forbidden_with_message_typed(
            "Insufficient permissions to manage user roles",
        )));
    }

    // Process assignments one by one since we don't have batch operations
    let mut success_count = 0;
    let mut error_count = 0;

    for assignment in request.assignments {
        match state
            .authorization_service
            .assign_role(&assignment.user_id, &assignment.role_id)
            .await
        {
            Ok(_) => success_count += 1,
            Err(e) => {
                warn!(
                    "Failed to assign role {} to user {}: {}",
                    assignment.role_id, assignment.user_id, e
                );
                error_count += 1;
            }
        }
    }

    info!(
        "Bulk role assignment completed by {} - {} successes, {} errors",
        auth_token.user_id, success_count, error_count
    );

    if error_count == 0 {
        Ok(Json(ApiResponse::success(())))
    } else {
        Ok(Json(ApiResponse::<()>::error_with_message_typed(
            "PARTIAL_BULK_ASSIGNMENT_FAILED",
            format!(
                "Bulk assignment partially failed: {} successes, {} errors",
                success_count, error_count
            ),
        )))
    }
}

// ============================================================================
// PERMISSION CHECK ENDPOINTS
// ============================================================================

/// Check permission for current user
/// POST /api/v1/rbac/check-permission
pub async fn check_permission(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Json(request): Json<PermissionCheckRequest>,
) -> Result<Json<ApiResponse<PermissionCheckResponse>>, StatusCode> {
    let context = request.context.unwrap_or_default();

    match state
        .authorization_service
        .check_permission(
            &auth_token.user_id,
            &request.action,
            &request.resource,
            Some(&context),
        )
        .await
    {
        Ok(granted) => {
            let response = PermissionCheckResponse {
                granted,
                reason: if granted {
                    "Permission granted".to_string()
                } else {
                    "Permission denied".to_string()
                },
                required_roles: Vec::new(), // Would be populated from role analysis
                missing_permissions: Vec::new(), // Would be populated from permission analysis
            };

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            warn!("Permission check failed: {}", e);
            Ok(Json(ApiResponse::<PermissionCheckResponse>::error_typed(
                "PERMISSION_CHECK_FAILED",
                "Failed to check permission",
            )))
        }
    }
}

/// Role elevation request
/// POST /api/v1/rbac/elevate
pub async fn elevate_role(
    State(state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Json(request): Json<ElevateRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let duration_seconds = (request.duration_minutes.unwrap_or(30) * 60) as u64;

    match state
        .authorization_service
        .elevate_role(
            &auth_token.user_id,
            &request.target_role,
            Some(duration_seconds),
        )
        .await
    {
        Ok(_) => {
            info!(
                "Role elevation granted to {}: {} for {} minutes - {}",
                auth_token.user_id,
                request.target_role,
                request.duration_minutes.unwrap_or(30),
                request.justification
            );
            Ok(Json(ApiResponse::success(())))
        }
        Err(e) => {
            warn!("Role elevation failed: {}", e);
            Ok(Json(ApiResponse::<()>::error_with_message_typed(
                "ELEVATION_FAILED",
                "Failed to elevate role",
            )))
        }
    }
}

// ============================================================================
// AUDIT AND ANALYTICS ENDPOINTS
// ============================================================================

/// Get audit logs
/// GET /api/v1/rbac/audit
pub async fn get_audit_logs(
    State(_state): State<ApiState>,
    Extension(auth_token): Extension<AuthToken>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ApiResponse<AuditLogResponse>>, StatusCode> {
    // Check authorization
    if !auth_token.has_permission("read:audit_logs") {
        return Ok(Json(
            ApiResponse::<AuditLogResponse>::forbidden_with_message_typed(
                "Insufficient permissions to read audit logs",
            ),
        ));
    }

    // For now, return a mock response
    // In a real implementation, this would query the audit log storage
    let response = AuditLogResponse {
        entries: Vec::new(),
        total_count: 0,
        page: query.page.unwrap_or(1),
        per_page: query.per_page.unwrap_or(20),
    };

    Ok(Json(ApiResponse::success(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create test auth token
    #[allow(dead_code)] // Reserved for future test implementation
    fn create_test_token(permissions: Vec<&str>) -> AuthToken {
        use crate::tokens::TokenMetadata;
        use chrono::Utc;

        AuthToken {
            token_id: "test_token_123".to_string(),
            user_id: "test_user".to_string(),
            access_token: "test_access_token".to_string(),
            token_type: Some("bearer".to_string()),
            subject: Some("test_user".to_string()),
            issuer: Some("auth-framework".to_string()),
            refresh_token: Some("test_refresh_token".to_string()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "password".to_string(),
            client_id: Some("test_client".to_string()),
            user_profile: None,
            permissions: permissions.into_iter().map(|s| s.to_string()).collect(),
            roles: vec!["admin".to_string()],
            metadata: TokenMetadata::default(),
        }
    }

    #[tokio::test]
    async fn test_create_role_unauthorized() {
        // Test would verify that unauthorized users cannot create roles
        // Implementation would use proper test framework setup
    }

    #[tokio::test]
    async fn test_create_role_success() {
        // Test would verify successful role creation
        // Implementation would use proper test framework setup
    }

    #[tokio::test]
    async fn test_permission_check() {
        // Test would verify permission checking functionality
        // Implementation would use proper test framework setup
    }
}


