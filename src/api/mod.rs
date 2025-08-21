//! REST API Server Module
//!
//! This module provides a comprehensive REST API server implementation
//! that exposes all AuthFramework functionality through HTTP endpoints.

pub mod admin;
pub mod auth;
pub mod error_codes;
pub mod health;
pub mod metrics;
pub mod mfa;
pub mod middleware;
pub mod oauth;
pub mod openapi;
pub mod responses;
pub mod server;
pub mod users;
pub mod validation;
pub mod versioning;

#[cfg(feature = "enhanced-rbac")]
#[cfg(feature = "role-system")]
pub mod rbac_endpoints;

pub use responses::{ApiError, ApiResponse, ApiResult};
pub use server::ApiServer;

use crate::AuthFramework;
use crate::errors::AuthError;
use std::sync::Arc;

/// API server state
#[derive(Clone)]
pub struct ApiState {
    pub auth_framework: Arc<AuthFramework>,
    #[cfg(feature = "enhanced-rbac")]
    pub authorization_service: Arc<crate::authorization_enhanced::AuthorizationService>,
}

impl ApiState {
    pub async fn new(auth_framework: Arc<AuthFramework>) -> crate::errors::Result<Self> {
        Ok(Self {
            auth_framework,
            #[cfg(feature = "enhanced-rbac")]
            authorization_service: Arc::new(
                crate::authorization_enhanced::AuthorizationService::new().await?,
            ),
        })
    }

    #[cfg(feature = "enhanced-rbac")]
    pub fn with_authorization_service(
        auth_framework: Arc<AuthFramework>,
        authorization_service: Arc<crate::authorization_enhanced::AuthorizationService>,
    ) -> Self {
        Self {
            auth_framework,
            authorization_service,
        }
    }
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_str| auth_str.strip_prefix("Bearer "))
        .map(|token| token.to_string())
}

/// Validate API token and extract user information
pub async fn validate_api_token(
    auth_framework: &AuthFramework,
    token: &str,
) -> Result<crate::tokens::AuthToken, AuthError> {
    // Use the existing token validation from AuthFramework
    let token_obj = auth_framework.token_manager().validate_jwt_token(token)?;

    // Convert the validated token claims to AuthToken
    Ok(crate::tokens::AuthToken {
        token_id: token_obj.jti.clone(),
        user_id: token_obj.sub.clone(),
        access_token: token.to_string(),
        token_type: Some("Bearer".to_string()),
        subject: Some(token_obj.sub.clone()),
        issuer: Some(token_obj.iss.clone()),
        refresh_token: None,
        issued_at: chrono::DateTime::from_timestamp(token_obj.iat, 0)
            .unwrap_or_else(chrono::Utc::now),
        expires_at: chrono::DateTime::from_timestamp(token_obj.exp, 0)
            .unwrap_or_else(chrono::Utc::now),
        scopes: token_obj
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
        auth_method: "jwt".to_string(),
        client_id: token_obj.client_id,
        user_profile: None,
        permissions: token_obj.permissions.unwrap_or_default(),
        roles: token_obj.roles.unwrap_or_default(),
        metadata: crate::tokens::TokenMetadata {
            session_id: None, // JWT tokens don't have session_id in claims by default
            ..Default::default()
        },
    })
}


