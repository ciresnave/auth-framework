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
//! ```rust,ignore
//! use auth_framework::prelude::*;
//! use axum::{Router, routing::get};
//!
//! let auth = AuthFramework::quick_start()
//!     .jwt_auth_from_env()
//!     .with_axum()
//!     .build().await?;
//!
//! let app = Router::new()
//!     .route("/public", get(public_handler))
//!     .route("/protected", get(protected(protected_handler)))
//!     .route("/admin", get(protected(admin_handler).require_role("admin")))
//!     .with_state(auth);
//! ```
//!
//! # Advanced Usage
//!
//! ```rust,ignore
//! use auth_framework::prelude::*;
//! use auth_framework::integrations::axum::*;
//!
//! // Custom auth routes
//! let auth_routes = AuthRouter::new()
//!     .login_route("/auth/login")
//!     .logout_route("/auth/logout")
//!     .refresh_route("/auth/refresh")
//!     .build();
//!
//! let app = Router::new()
//!     .merge(auth_routes)
//!     .route("/api/profile", get(profile_handler))
//!     .layer(RequireAuth::new())
//!     .with_state(auth);
//! ```

use crate::{AuthError, AuthFramework, AuthToken};
use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts, Request, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
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
    pub handler: F,
    required_permissions: Vec<String>,
    required_roles: Vec<String>,
}

impl<F: Clone> ProtectedHandler<F> {
    /// Create a new protected handler
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            required_permissions: Vec::new(),
            required_roles: Vec::new(),
        }
    }

    /// Get the underlying handler
    pub fn get_handler(&self) -> F {
        self.handler.clone()
    }

    /// Add required permissions
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.required_permissions = permissions;
        self
    }

    /// Add required roles
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.required_roles = roles;
        self
    }
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

impl Default for RequireAuth {
    fn default() -> Self {
        Self::new()
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
            .route(&self.logout_path, post(logout_handler))
            .route(&self.refresh_path, post(refresh_handler))
            .route(&self.profile_path, get(profile_handler))
    }
}

impl Default for AuthRouter {
    fn default() -> Self {
        Self::new()
    }
}

// Route handlers for authentication endpoints
async fn login_handler(
    State(auth): State<Arc<AuthFramework>>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Authenticate against the user store exactly as the API server's login does; the
    // reason for a failure is not revealed.
    let denied = || {
        AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Invalid credentials".to_string(),
        })
    };
    let token = match auth
        .authenticate(
            "password",
            crate::authentication::credentials::Credential::password(
                &request.username,
                &request.password,
            ),
        )
        .await
    {
        Ok(crate::auth::AuthResult::Success(token)) => *token,
        // This route cannot complete a second factor: no token without it.
        Ok(crate::auth::AuthResult::MfaRequired(_)) => {
            return Err(AuthError::Token(crate::errors::TokenError::Invalid {
                message: "Multi-factor authentication is required".to_string(),
            }));
        }
        Ok(crate::auth::AuthResult::Failure(_)) | Err(_) => return Err(denied()),
    };

    let response = LoginResponse {
        access_token: token.access_token.clone(),
        refresh_token: Some(auth.token_manager().create_refresh_jwt_token(
            &token.user_id,
            Some(auth.config().refresh_token_lifetime),
        )?),
        expires_in: (token.expires_at - token.issued_at).num_seconds().max(0) as u64,
        user: UserInfo {
            id: token.user_id.clone(),
            username: Some(request.username),
            email: None,
            roles: token.roles.to_vec(),
        },
    };

    Ok(Json(response))
}

/// Logout handler for authenticated users
pub async fn logout_handler(
    State(auth): State<Arc<AuthFramework>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    // Revoke the user's current token
    let storage = auth.storage();
    let jti = &user.token.token_id;
    if !jti.is_empty() {
        let key = format!("revoked_token:{}", jti);
        let ttl = std::time::Duration::from_secs(7 * 24 * 60 * 60); // 7 days
        if let Err(e) = storage.store_kv(&key, b"revoked", Some(ttl)).await {
            tracing::warn!("Failed to revoke token {} during logout: {}", jti, e);
        }
    }
    tracing::info!("User {} logged out, token revoked", user.user_id);
    Ok(Json(
        serde_json::json!({"message": "Successfully logged out"}),
    ))
}

async fn refresh_handler(
    State(auth): State<Arc<AuthFramework>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, AuthError> {
    // Extract and validate the existing bearer token
    let token_str = extract_bearer_token(
        &axum::extract::Request::builder()
            .header(
                AUTHORIZATION,
                headers
                    .get(AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or(""),
            )
            .body(axum::body::Body::empty())
            .expect("valid request builder"),
    )?;

    // Only a refresh token can mint a new access token, and it is single-use: redeeming it
    // returns the next refresh token and spends this one.
    let redemption = auth.redeem_refresh_jwt(&token_str).await.map_err(|_| {
        AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Cannot refresh: the refresh token is invalid, expired or already used"
                .to_string(),
        })
    })?;
    let claims = redemption.claims;

    // Permissions come from the account's stored permission set, not from the old token.
    let permissions: Vec<String> = match auth
        .storage()
        .get_kv(&format!("user_permissions:{}", claims.sub))
        .await
    {
        Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
        _ => vec![],
    };
    let new_token_str = auth
        .token_manager()
        .create_jwt_token(&claims.sub, permissions, None)?;

    let expires_in = auth.config().token_lifetime.as_secs();
    Ok(Json(serde_json::json!({
        "access_token": new_token_str,
        "refresh_token": redemption.new_refresh_token,
        "token_type": "Bearer",
        "expires_in": expires_in
    })))
}

/// User profile handler for authenticated users
pub async fn profile_handler(
    State(auth): State<Arc<AuthFramework>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    // Look up full user profile from storage
    let storage = auth.storage();
    let key = format!("user:{}", user.user_id);
    let (username, email) = if let Ok(Some(data)) = storage.get_kv(&key).await {
        if let Ok(profile) = serde_json::from_slice::<serde_json::Value>(&data) {
            (
                profile
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                profile
                    .get("email")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            )
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    Ok(Json(UserInfo {
        id: user.user_id,
        username,
        email,
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
    match auth.validate_access_jwt(&token_str).await {
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

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Ok(token.to_string())
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
    Arc<AuthFramework>: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract auth framework from state via FromRef
        let auth: Arc<AuthFramework> = Arc::from_ref(state);

        // Extract token from request
        let token_str = extract_bearer_token_from_parts(parts)?;

        // Validate JWT and extract real claims
        let claims = auth.validate_access_jwt(&token_str).await?;

        let user_id = claims.sub.clone();
        let permissions = claims.permissions.unwrap_or_default();
        let roles = claims.roles.unwrap_or_default();
        let scopes: Vec<String> = claims
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let issued_at =
            chrono::DateTime::from_timestamp(claims.iat, 0).unwrap_or_else(chrono::Utc::now);
        let expires_at = chrono::DateTime::from_timestamp(claims.exp, 0)
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(1));

        let token = AuthToken {
            token_id: claims.jti.clone(),
            user_id: user_id.clone(),
            access_token: token_str,
            token_type: Some("Bearer".to_string()),
            subject: Some(user_id.clone()),
            issuer: Some(claims.iss.clone()),
            refresh_token: None,
            issued_at,
            expires_at,
            scopes: scopes.into(),
            auth_method: "jwt".to_string(),
            client_id: claims.client_id,
            user_profile: None,
            permissions: permissions.clone().into(),
            roles: roles.clone().into(),
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

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Ok(token.to_string())
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
        self.layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                // Validate that an Authorization: Bearer <token> header is present
                let has_bearer = request
                    .headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .map(|v| v.starts_with("Bearer "))
                    .unwrap_or(false);

                if has_bearer {
                    next.run(request).await
                } else {
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::UNAUTHORIZED)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"error":"Authentication required"}"#,
                        ))
                        .unwrap_or_default()
                }
            },
        ))
    }

    fn require_permission(self, _permission: &str) -> Self {
        self.layer(axum::middleware::from_fn(
            |_request: axum::extract::Request, _next: axum::middleware::Next| async move {
                tracing::error!(
                    "require_permission() was used without an enforcing authorization backend"
                );
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Authorization middleware misconfigured","details":"require_permission() requires an enforcing authorization backend. Use enhanced-rbac middleware for production routes."}"#,
                    ))
                    .unwrap_or_default()
            },
        ))
    }

    fn require_role(self, _role: &str) -> Self {
        self.layer(axum::middleware::from_fn(
            |_request: axum::extract::Request, _next: axum::middleware::Next| async move {
                tracing::error!(
                    "require_role() was used without an enforcing authorization backend"
                );
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Authorization middleware misconfigured","details":"require_role() requires an enforcing authorization backend. Use enhanced-rbac middleware for production routes."}"#,
                    ))
                    .unwrap_or_default()
            },
        ))
    }
}

// Re-export for convenience
pub use RequireAuth as AuthMiddleware;
