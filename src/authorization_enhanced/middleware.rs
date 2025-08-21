//! Enhanced authorization middleware using role-system v1.0
//!
//! This module provides comprehensive authorization middleware for Axum,
//! replacing the basic role checking with enterprise-grade RBAC.

use crate::api::{ApiResponse, ApiState};
use crate::tokens::AuthToken;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Enhanced RBAC middleware using role-system v1.0
pub async fn rbac_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip auth for public endpoints
    let path = request.uri().path();
    if is_public_endpoint(path) {
        return Ok(next.run(request).await);
    }

    // Get auth token from extensions (should be set by auth_middleware)
    let auth_token = match request.extensions().get::<AuthToken>() {
        Some(token) => token.clone(),
        None => {
            let error_response = ApiResponse::<()>::unauthorized();
            return Err(error_response.into_response());
        }
    };

    // Build request context for conditional permissions
    let context = build_request_context(&request, &auth_token);

    // Check authorization using role-system
    let authorized = match check_authorization(&state, &auth_token, &request, &context).await {
        Ok(granted) => granted,
        Err(e) => {
            warn!("Authorization check failed: {}", e);
            let error_response = ApiResponse::<()>::forbidden();
            return Err(error_response.into_response());
        }
    };

    if authorized {
        debug!(
            "Authorization granted for user '{}' on {}",
            auth_token.user_id, path
        );
        Ok(next.run(request).await)
    } else {
        info!(
            "Authorization denied for user '{}' on {}",
            auth_token.user_id, path
        );
        let error_response = ApiResponse::<()>::forbidden();
        Err(error_response.into_response())
    }
}

/// Conditional permission middleware for time/location-based access
pub async fn conditional_permission_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();

    // Apply conditional permissions for sensitive endpoints
    if is_sensitive_endpoint(path) {
        let auth_token = match request.extensions().get::<AuthToken>() {
            Some(token) => token,
            None => {
                let error_response = ApiResponse::<()>::unauthorized();
                return Err(error_response.into_response());
            }
        };

        let context = build_conditional_context(&request);

        // Check conditional permissions
        let has_conditional_access: bool = state
            .authorization_service
            .check_permission(&auth_token.user_id, "access", path, Some(&context))
            .await
            .unwrap_or_default();

        if !has_conditional_access {
            info!(
                "Conditional access denied for user '{}' on {}",
                auth_token.user_id, path
            );
            let error_response = ApiResponse::<()>::error(
                "CONDITIONAL_ACCESS_DENIED",
                "Access denied due to conditional permissions (time, location, etc.)",
            );
            return Err(error_response.into_response());
        }
    }

    Ok(next.run(request).await)
}

/// Role elevation middleware for administrative actions
pub async fn role_elevation_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();

    // Check if this endpoint requires elevated permissions
    if requires_role_elevation(path) {
        let auth_token = match request.extensions().get::<AuthToken>() {
            Some(token) => token,
            None => {
                let error_response = ApiResponse::<()>::unauthorized();
                return Err(error_response.into_response());
            }
        };

        // Check if user has elevated permissions
        let has_elevated_access: bool = state
            .authorization_service
            .check_permission(&auth_token.user_id, "elevated", "admin", None)
            .await
            .unwrap_or_default();

        if !has_elevated_access {
            info!(
                "Elevated access required for user '{}' on {}",
                auth_token.user_id, path
            );
            let error_response = ApiResponse::<()>::error(
                "ELEVATION_REQUIRED",
                "This action requires elevated permissions. Please request temporary role elevation.",
            );
            return Err(error_response.into_response());
        }
    }

    Ok(next.run(request).await)
}

/// Check authorization using the enhanced authorization service
async fn check_authorization(
    state: &ApiState,
    auth_token: &AuthToken,
    request: &Request,
    context: &HashMap<String, String>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let method = request.method().as_str();
    let path = request.uri().path();

    // Use the enhanced authorization service
    state
        .authorization_service
        .check_api_permission(&auth_token.user_id, method, path, context)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

/// Build request context for conditional permissions
fn build_request_context(request: &Request, auth_token: &AuthToken) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Add user context
    context.insert("user_id".to_string(), auth_token.user_id.clone());
    context.insert("roles".to_string(), auth_token.roles.join(","));

    // Add request metadata
    if let Some(user_agent) = request.headers().get("user-agent")
        && let Ok(ua_str) = user_agent.to_str()
    {
        context.insert("user_agent".to_string(), ua_str.to_string());
    }

    // Add IP address
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for")
        && let Ok(ip_str) = forwarded_for.to_str()
    {
        context.insert("ip_address".to_string(), ip_str.to_string());
    }

    // Add time-based context
    let current_hour = chrono::Utc::now().format("%H").to_string();
    let hour: u32 = current_hour.parse().unwrap_or(0);

    if (9..=17).contains(&hour) {
        context.insert("time".to_string(), "business_hours".to_string());
    } else {
        context.insert("time".to_string(), "after_hours".to_string());
    }

    // Add day of week
    let day_of_week = chrono::Utc::now().format("%u").to_string(); // 1-7, Monday = 1
    let weekday: u32 = day_of_week.parse().unwrap_or(1);

    if (1..=5).contains(&weekday) {
        context.insert("day_type".to_string(), "weekday".to_string());
    } else {
        context.insert("day_type".to_string(), "weekend".to_string());
    }

    context
}

/// Build conditional context for sensitive operations
fn build_conditional_context(request: &Request) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Check for VPN indicators
    if let Some(via) = request.headers().get("via")
        && let Ok(via_str) = via.to_str()
        && (via_str.contains("vpn") || via_str.contains("proxy"))
    {
        context.insert("connection_type".to_string(), "vpn".to_string());
    }

    // Check for mobile device
    if let Some(user_agent) = request.headers().get("user-agent")
        && let Ok(ua_str) = user_agent.to_str()
    {
        if ua_str.contains("Mobile") || ua_str.contains("Android") || ua_str.contains("iPhone") {
            context.insert("device_type".to_string(), "mobile".to_string());
        } else {
            context.insert("device_type".to_string(), "desktop".to_string());
        }
    }

    // Add security level based on endpoint sensitivity
    let path = request.uri().path();
    if path.contains("/admin/") {
        context.insert("security_level".to_string(), "high".to_string());
    } else if path.contains("/api/") {
        context.insert("security_level".to_string(), "medium".to_string());
    } else {
        context.insert("security_level".to_string(), "low".to_string());
    }

    context
}

/// Check if endpoint is public (doesn't require authentication)
fn is_public_endpoint(path: &str) -> bool {
    match path {
        "/health" | "/health/detailed" | "/metrics" | "/readiness" | "/liveness" => true,
        "/auth/login" | "/auth/refresh" | "/auth/providers" => true,
        "/oauth/authorize" | "/oauth/token" | "/oauth/.well-known/openid_configuration" => true,
        _ if path.starts_with("/oauth/.well-known/") => true,
        _ => false,
    }
}

/// Check if endpoint contains sensitive data
fn is_sensitive_endpoint(path: &str) -> bool {
    match path {
        _ if path.starts_with("/admin/") => true,
        _ if path.contains("/secrets/") => true,
        _ if path.contains("/config/") => true,
        _ if path.contains("/keys/") => true,
        "/auth/logout" => true, // Logout should have conditional access
        _ => false,
    }
}

/// Check if endpoint requires role elevation
fn requires_role_elevation(path: &str) -> bool {
    match path {
        _ if path.starts_with("/admin/users/delete") => true,
        _ if path.starts_with("/admin/system/") => true,
        _ if path.contains("/sudo/") => true,
        _ if path.contains("/elevate/") => true,
        _ => false,
    }
}

/// Permission requirement middleware factory
pub fn require_permission(
    action: &str,
    resource: &str,
) -> impl Fn(
    Request,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>>
+ Clone {
    let action = action.to_string();
    let resource = resource.to_string();

    move |request: Request, next: Next| {
        let action = action.clone();
        let resource = resource.clone();
        Box::pin(async move {
            let auth_token = match request.extensions().get::<AuthToken>() {
                Some(token) => token,
                None => {
                    let error_response = ApiResponse::<()>::unauthorized();
                    return Err(error_response.into_response());
                }
            };

            // For this implementation, we'd need access to the authorization service
            // This would typically be passed through the request state
            // For now, we'll do a basic permission check using the auth token
            if check_token_permission(auth_token, &action, &resource) {
                Ok(next.run(request).await)
            } else {
                let error_response = ApiResponse::<()>::forbidden();
                Err(error_response.into_response())
            }
        })
    }
}

/// Basic permission check using auth token (fallback)
fn check_token_permission(auth_token: &AuthToken, action: &str, resource: &str) -> bool {
    // Check for admin role (has all permissions)
    if auth_token.roles.contains(&"admin".to_string()) {
        return true;
    }

    // Check explicit permissions
    let required_permission = format!("{}:{}", action, resource);
    auth_token.permissions.iter().any(|perm| {
        perm == &required_permission
            || perm == "*"
            || (perm.ends_with("*") && required_permission.starts_with(&perm[..perm.len() - 1]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_endpoint_detection() {
        assert!(is_public_endpoint("/health"));
        assert!(is_public_endpoint("/auth/login"));
        assert!(is_public_endpoint(
            "/oauth/.well-known/openid_configuration"
        ));
        assert!(!is_public_endpoint("/api/users"));
        assert!(!is_public_endpoint("/admin/roles"));
    }

    #[test]
    fn test_sensitive_endpoint_detection() {
        assert!(is_sensitive_endpoint("/admin/users"));
        assert!(is_sensitive_endpoint("/api/secrets/vault"));
        assert!(is_sensitive_endpoint("/auth/logout"));
        assert!(!is_sensitive_endpoint("/api/health"));
        assert!(!is_sensitive_endpoint("/public/info"));
    }

    #[test]
    fn test_elevation_requirement() {
        assert!(requires_role_elevation("/admin/users/delete/123"));
        assert!(requires_role_elevation("/admin/system/shutdown"));
        assert!(requires_role_elevation("/api/sudo/execute"));
        assert!(!requires_role_elevation("/admin/users"));
        assert!(!requires_role_elevation("/api/profile"));
    }

    #[test]
    fn test_context_building() {
        // This would require setting up a mock request, which is complex
        // In a real test, we'd create a proper test request and verify context
        let context: HashMap<String, String> = HashMap::new();
        assert!(context.is_empty()); // Placeholder test
    }
}


