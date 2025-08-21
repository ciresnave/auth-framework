//! API Middleware
//!
//! Authentication, authorization, rate limiting, and other middleware

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::time::{Duration, Instant};

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip auth for public endpoints
    let path = request.uri().path();
    if is_public_endpoint(path) {
        return Ok(next.run(request).await);
    }

    // Extract token from headers
    let headers = request.headers();
    match extract_bearer_token(headers) {
        Some(token) => {
            // Validate token
            match validate_api_token(&state.auth_framework, &token).await {
                Ok(auth_token) => {
                    // Add auth token to request extensions for use in handlers
                    request.extensions_mut().insert(auth_token);
                    Ok(next.run(request).await)
                }
                Err(_) => {
                    let error_response = ApiResponse::<()>::unauthorized();
                    Err(error_response.into_response())
                }
            }
        }
        None => {
            let error_response = ApiResponse::<()>::unauthorized();
            Err(error_response.into_response())
        }
    }
}

/// Admin authorization middleware
pub async fn admin_middleware(
    State(_state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Get auth token from extensions (should be set by auth_middleware)
    match request.extensions().get::<crate::tokens::AuthToken>() {
        Some(auth_token) => {
            if auth_token.roles.contains(&"admin".to_string()) {
                Ok(next.run(request).await)
            } else {
                let error_response = ApiResponse::<()>::forbidden();
                Err(error_response.into_response())
            }
        }
        None => {
            // If no auth token, user is not authenticated
            let error_response = ApiResponse::<()>::unauthorized();
            Err(error_response.into_response())
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(request: Request, next: Next) -> Result<Response, Response> {
    // In a real implementation, use a distributed rate limiter like Redis
    // For now, just add rate limit headers

    let mut response = next.run(request).await;

    // Add rate limit headers
    let headers = response.headers_mut();
    headers.insert("X-RateLimit-Limit", "100".parse().unwrap());
    headers.insert("X-RateLimit-Remaining", "95".parse().unwrap());
    headers.insert("X-RateLimit-Reset", "1692278400".parse().unwrap()); // Unix timestamp

    Ok(response)
}

/// CORS middleware
pub async fn cors_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    let mut response = response;
    let headers = response.headers_mut();

    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization".parse().unwrap(),
    );
    headers.insert("Access-Control-Max-Age", "3600".parse().unwrap());

    response
}

/// Logging middleware
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    // Extract user agent and IP for logging
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        "Request started: {} {} from {} ({})",
        method,
        uri,
        forwarded_for,
        user_agent
    );

    let response = next.run(request).await;
    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        "Request completed: {} {} {} in {:?}",
        method,
        uri,
        status,
        duration
    );

    response
}

/// Security headers middleware
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    let mut response = response;
    let headers = response.headers_mut();

    // Security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );

    response
}

/// Request timeout middleware
pub async fn timeout_middleware(request: Request, next: Next) -> Result<Response, Response> {
    // Set a 30-second timeout for all requests
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => {
            let error_response =
                ApiResponse::<()>::error("REQUEST_TIMEOUT", "Request timed out after 30 seconds");
            Err(error_response.into_response())
        }
    }
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

/// Permission check helper
pub fn check_permission(auth_token: &crate::tokens::AuthToken, required_permission: &str) -> bool {
    auth_token.permissions.iter().any(|perm| {
        perm == required_permission
            || perm == "*"
            || (perm.ends_with("*") && required_permission.starts_with(&perm[..perm.len() - 1]))
    })
}

/// Role check helper
pub fn check_role(auth_token: &crate::tokens::AuthToken, required_role: &str) -> bool {
    auth_token.roles.contains(&required_role.to_string())
        || auth_token.roles.contains(&"admin".to_string()) // Admin has all roles
}


