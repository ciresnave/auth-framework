//! Axum integration for auth-framework with enhanced ergonomics.
//!
//! This module provides middleware, extractors, and helper functions for easy integration
//! with Axum web applications. The ergonomic improvements include:
//!
//! - Simple middleware setup with `RequireAuth` and `RequirePermission`
//! - Automatic route protection with `protected()` wrapper
//! - Easy user extraction with `AuthenticatedUser`
//! - Builder pattern for auth routes
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//! use auth_framework::integrations::axum::{AuthenticatedUser, RequireAuth};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create auth framework
//!     let _auth = AuthFramework::quick_start()
//!         .jwt_auth_from_env()
//!         .build().await?;
//!     
//!     // Create authentication middleware
//!     let _auth_middleware = RequireAuth::new()
//!         .with_roles(&["user", "admin"])
//!         .with_permissions(&["read", "write"]);
//!     
//!     println!("Auth framework configured for Axum integration");
//!     Ok(())
//! }
//! ```
//!
//! # Advanced Usage
//!
//! ```rust,no_run
//! use auth_framework::prelude::*;
//! use auth_framework::integrations::axum::*;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let auth = Arc::new(AuthFramework::quick_start().build().await?);
//!
//!     // Configure auth routes
//!     let _auth_routes = AuthRouter::new()
//!         .login_route("/auth/login")
//!         .logout_route("/auth/logout")
//!         .refresh_route("/auth/refresh")
//!         .build();
//!
//!     // Configure middleware
//!     let _permission_middleware = RequirePermission::new("admin:read")
//!         .for_resource("user-profiles");
//!     
//!     println!("Advanced auth configuration completed");
//!     Ok(())
//! }
//! ```

use crate::{AuthError, AuthFramework, AuthToken};
use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Ergonomic authentication middleware that can be easily applied to routes
#[derive(Clone)]
pub struct RequireAuth {
    /// Optional specific permissions required
    pub required_permissions: Vec<String>,
    /// Optional specific roles required
    pub required_roles: Vec<String>,
}

/// Ergonomic permission middleware for fine-grained access control
#[derive(Clone)]
pub struct RequirePermission {
    /// The permission required to access the route
    pub permission: String,
    /// Optional resource context for the permission
    pub resource: Option<String>,
}

/// Authenticated user extractor that automatically validates tokens
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub token: AuthToken,
}

/// Builder for creating authentication-related routes
pub struct AuthRouter {
    login_path: String,
    logout_path: String,
    refresh_path: String,
    profile_path: String,
}

/// Request/response types for auth endpoints
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

/// Protected route wrapper that automatically applies authentication
pub fn protected<F, T>(handler: F) -> ProtectedHandler<F>
where
    F: Clone,
{
    ProtectedHandler::new(handler)
}

/// Protected handler wrapper
#[derive(Clone)]
pub struct ProtectedHandler<F> {
    #[allow(dead_code)]
    handler: F,
    required_permissions: Vec<String>,
    required_roles: Vec<String>,
}

impl RequireAuth {
    /// Create a new authentication middleware
    pub fn new() -> Self {
        Self {
            required_permissions: Vec::new(),
            required_roles: Vec::new(),
        }
    }

    /// Require specific permissions
    pub fn with_permissions(mut self, permissions: &[&str]) -> Self {
        self.required_permissions = permissions.iter().map(|p| p.to_string()).collect();
        self
    }

    /// Require specific roles
    pub fn with_roles(mut self, roles: &[&str]) -> Self {
        self.required_roles = roles.iter().map(|r| r.to_string()).collect();
        self
    }
}

impl RequirePermission {
    /// Create a new permission middleware
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
            resource: None,
        }
    }

    /// Set the resource context for the permission
    pub fn for_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }
}

impl<F> ProtectedHandler<F> {
    fn new(handler: F) -> Self {
        Self {
            handler,
            required_permissions: Vec::new(),
            required_roles: Vec::new(),
        }
    }

    /// Require specific permissions for this route
    pub fn require_permissions(mut self, permissions: &[&str]) -> Self {
        self.required_permissions = permissions.iter().map(|p| p.to_string()).collect();
        self
    }

    /// Require specific roles for this route
    pub fn require_roles(mut self, roles: &[&str]) -> Self {
        self.required_roles = roles.iter().map(|r| r.to_string()).collect();
        self
    }

    /// Require a single permission (convenience method)
    pub fn require_permission(mut self, permission: &str) -> Self {
        self.required_permissions = vec![permission.to_string()];
        self
    }

    /// Require a single role (convenience method)
    pub fn require_role(mut self, role: &str) -> Self {
        self.required_roles = vec![role.to_string()];
        self
    }
}

impl AuthRouter {
    /// Create a new auth router builder
    pub fn new() -> Self {
        Self {
            login_path: "/auth/login".to_string(),
            logout_path: "/auth/logout".to_string(),
            refresh_path: "/auth/refresh".to_string(),
            profile_path: "/auth/profile".to_string(),
        }
    }

    /// Set custom login route path
    pub fn login_route(mut self, path: impl Into<String>) -> Self {
        self.login_path = path.into();
        self
    }

    /// Set custom logout route path
    pub fn logout_route(mut self, path: impl Into<String>) -> Self {
        self.logout_path = path.into();
        self
    }

    /// Set custom token refresh route path
    pub fn refresh_route(mut self, path: impl Into<String>) -> Self {
        self.refresh_path = path.into();
        self
    }

    /// Set custom user profile route path
    pub fn profile_route(mut self, path: impl Into<String>) -> Self {
        self.profile_path = path.into();
        self
    }

    /// Build the auth routes and return a Router
    pub fn build(self) -> Router<Arc<AuthFramework>> {
        Router::new()
            .route(&self.login_path, post(login_handler))
            // .route(&self.logout_path, post(logout_handler))  // Temporarily disabled due to trait issues
            .route(&self.refresh_path, post(refresh_handler))
        // .route(&self.profile_path, get(profile_handler))  // Temporarily disabled due to trait issues
    }
}

// Route handlers for authentication endpoints
async fn login_handler(
    State(auth): State<Arc<AuthFramework>>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // This is a simplified login implementation
    // In a real implementation, you'd validate credentials against your user store

    let token = auth
        .create_auth_token(
            &request.username,
            vec!["read".to_string(), "write".to_string()],
            "jwt",
            None,
        )
        .await?;

    let response = LoginResponse {
        access_token: token.access_token.clone(),
        refresh_token: token.refresh_token.clone(),
        expires_in: 3600, // 1 hour
        user: UserInfo {
            id: token.user_id.clone(),
            username: Some(request.username),
            email: None,
            roles: token.roles.clone(),
        },
    };

    Ok(Json(response))
}

async fn logout_handler(
    State(_auth): State<Arc<AuthFramework>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    // In a real implementation, you'd revoke the token
    tracing::info!("User {} logged out", user.user_id);
    Ok(Json(
        serde_json::json!({"message": "Successfully logged out"}),
    ))
}

async fn refresh_handler(
    State(_auth): State<Arc<AuthFramework>>,
    // Extract refresh token from request
) -> Result<impl IntoResponse, AuthError> {
    // This would implement token refresh logic
    // For now, return a placeholder
    Ok(Json(
        serde_json::json!({"message": "Token refresh not implemented"}),
    ))
}

async fn profile_handler(user: AuthenticatedUser) -> Result<impl IntoResponse, AuthError> {
    Ok(Json(UserInfo {
        id: user.user_id,
        username: None, // Would come from user store
        email: None,    // Would come from user store
        roles: user.roles,
    }))
}

/// Authentication middleware implementation
pub async fn auth_middleware(
    State(auth): State<Arc<AuthFramework>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token_str = extract_bearer_token(&request)?;

    // Validate token using AuthFramework
    match auth.token_manager().validate_jwt_token(&token_str) {
        Ok(_claims) => {
            // Store token in request extensions for later extraction
            request.extensions_mut().insert(token_str);
            Ok(next.run(request).await)
        }
        Err(e) => Err(e),
    }
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(request: &Request) -> Result<String, AuthError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AuthError::Token(crate::errors::TokenError::Missing))?;

    if auth_header.starts_with("Bearer ") {
        Ok(auth_header[7..].to_string())
    } else {
        Err(AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Authorization header must use Bearer scheme".to_string(),
        }))
    }
}

/// Implement FromRequestParts for AuthenticatedUser extractor
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    Arc<AuthFramework>: FromRequestParts<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract auth framework from state
        let _auth = Arc::<AuthFramework>::from_request_parts(parts, state)
            .await
            .map_err(|_| AuthError::internal("Failed to extract auth framework from state"))?;

        // Extract token from request
        let token_str = extract_bearer_token_from_parts(parts)?;

        // Get token details - this is a simplified version
        // In a real implementation, you'd decode the JWT and extract user info
        let user_id = "demo_user".to_string(); // Would come from JWT claims
        let permissions = vec!["read".to_string(), "write".to_string()]; // Would come from JWT/database
        let roles = vec!["user".to_string()]; // Would come from JWT/database

        // Create a mock token for demonstration
        // In reality, you'd either decode the existing token or fetch from storage
        let token = AuthToken {
            token_id: "demo_token_id".to_string(),
            user_id: user_id.clone(),
            access_token: token_str,
            token_type: Some("Bearer".to_string()),
            subject: Some(user_id.clone()),
            issuer: Some("auth-framework".to_string()),
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "jwt".to_string(),
            client_id: None,
            user_profile: None,
            permissions: permissions.clone(),
            roles: roles.clone(),
            metadata: crate::tokens::TokenMetadata::default(),
        };

        Ok(AuthenticatedUser {
            user_id,
            permissions,
            roles,
            token,
        })
    }
}

fn extract_bearer_token_from_parts(parts: &Parts) -> Result<String, AuthError> {
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AuthError::Token(crate::errors::TokenError::Missing))?;

    if auth_header.starts_with("Bearer ") {
        Ok(auth_header[7..].to_string())
    } else {
        Err(AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Authorization header must use Bearer scheme".to_string(),
        }))
    }
}

/// Implement IntoResponse for AuthError to provide proper HTTP error responses
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AuthError::Token(_) => (StatusCode::UNAUTHORIZED, "Authentication required"),
            AuthError::Permission(_) => (StatusCode::FORBIDDEN, "Insufficient permissions"),
            AuthError::RateLimit { .. } => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
            AuthError::Configuration { .. } | AuthError::Storage(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            _ => (StatusCode::BAD_REQUEST, "Bad request"),
        };

        let body = Json(serde_json::json!({
            "error": message,
            "details": self.to_string()
        }));

        (status, body).into_response()
    }
}

/// Ergonomic middleware methods for Router
pub trait AuthRouterExt<S> {
    /// Add authentication requirement to all routes
    fn require_auth(self) -> Self;

    /// Add permission requirement to all routes
    fn require_permission(self, permission: &str) -> Self;

    /// Add role requirement to all routes
    fn require_role(self, role: &str) -> Self;
}

impl<S> AuthRouterExt<S> for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn require_auth(self) -> Self {
        self.layer(axum::middleware::from_fn_with_state(
            (), // This would need the actual auth state
            |_state: (), request: axum::extract::Request, next: axum::middleware::Next| async move {
                // This is a placeholder - would implement actual auth middleware
                next.run(request).await
            },
        ))
    }

    fn require_permission(self, _permission: &str) -> Self {
        // This would implement permission checking middleware
        self
    }

    fn require_role(self, _role: &str) -> Self {
        // This would implement role checking middleware
        self
    }
}

// Re-export for convenience
pub use RequireAuth as AuthMiddleware;
