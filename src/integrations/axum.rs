/// Advanced middleware hooks (request/response, error mapping) stub
pub trait AdvancedMiddlewareHooks {
    fn on_request<B>(&self, _req: &axum::http::Request<B>) {}
    fn on_response(&self, _res: &Response) {}
    fn on_error(&self, _err: &AuthError) {}
}
// Axum integration for auth-framework.
//
// This module provides middleware and extractors for easy integration
// with Axum web applications.

use crate::AuthError;
use crate::{AuthFramework, AuthToken, Result};
use axum::{
    extract::{FromRequestParts, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

/// Authentication middleware for Axum
pub async fn auth_middleware<B>(
    State(auth): State<Arc<AuthFramework>>,
    mut request: axum::http::Request<B>,
    next: Next,
) -> Result<Response>
where
    axum::body::Body: From<B>,
{
    let token_str = extract_bearer_token(&request)?;
    // Parse and validate JWT token using AuthFramework
    match auth.token_manager().validate_jwt_token(&token_str) {
        Ok(_claims) => {
            // You may want to convert claims to AuthToken if needed
            request.extensions_mut().insert(token_str.clone());
            let req = request.map(axum::body::Body::from);
            Ok(next.run(req).await)
        }
        Err(e) => Err(e),
    }
}

/// Extract bearer token from Authorization header
fn extract_bearer_token<B>(request: &axum::http::Request<B>) -> Result<String> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| AuthError::Token(crate::errors::TokenError::Missing))?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        Ok(token.to_string())
    } else {
        Err(AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Invalid token".to_string(),
        }))
    }
}

/// Axum extractor for authenticated requests
pub struct AuthenticatedUser(pub AuthToken);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection>
    where
        Self: Sized,
    {
        let token = parts
            .extensions
            .get::<AuthToken>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(AuthenticatedUser(token))
    }
}

/// Require specific permissions
pub struct RequirePermission {
    pub permission: String,
    pub resource: String,
}

impl<S> FromRequestParts<S> for RequirePermission
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection>
    where
        Self: Sized,
    {
        let _auth_user = AuthenticatedUser::from_request_parts(parts, _state).await?;
        // Here you would check permissions using AuthFramework
        // For demonstration, assume permission is always granted
        // You can access AuthFramework via state if needed
        Ok(RequirePermission {
            permission: "read".to_string(),
            resource: "default".to_string(),
        })
    }
}
