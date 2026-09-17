//! REST API Server Module
//!
//! This module provides a comprehensive REST API server implementation
//! that exposes all AuthFramework functionality through HTTP endpoints.

pub mod admin;
pub mod advanced_protocols;
pub mod auth;
pub mod email_verification;
pub mod error_codes;
pub mod health;
pub mod metrics;
pub mod mfa;
pub mod middleware;
pub mod oauth2;
pub mod oauth_advanced;
pub mod openapi;
pub mod responses;
pub mod saml;
pub mod security;
pub mod security_simple;
pub mod server;
pub mod users;
pub mod validation;
pub mod versioning;
pub mod webauthn;

#[cfg(feature = "enhanced-rbac")]
#[cfg(feature = "role-system")]
pub mod rbac_endpoints;

pub use responses::{ApiError, ApiResponse, ApiResult};
pub use security::SecurityManager;
pub use server::ApiServer;

use crate::AuthFramework;
use crate::distributed::rate_limiting::{DistributedRateLimiter, RateLimitConfig};
use crate::errors::AuthError;
use std::sync::Arc;

/// API server state
#[derive(Clone)]
pub struct ApiState {
    pub auth_framework: Arc<AuthFramework>,
    pub rate_limiter: Arc<DistributedRateLimiter>,
    #[cfg(feature = "enhanced-rbac")]
    pub authorization_service: Arc<crate::authorization_enhanced::AuthorizationService>,
}

impl ApiState {
    /// Create an [`ApiState`] wrapping the given [`AuthFramework`].
    ///
    /// A balanced distributed rate-limiter is initialised automatically.
    ///
    /// # Example
    /// ```rust,ignore
    /// let state = ApiState::new(Arc::new(auth_framework)).await?;
    /// ```
    pub async fn new(auth_framework: Arc<AuthFramework>) -> crate::errors::Result<Self> {
        let rate_limiter =
            Arc::new(DistributedRateLimiter::new(RateLimitConfig::balanced()).await?);
        Ok(Self {
            auth_framework,
            rate_limiter,
            #[cfg(feature = "enhanced-rbac")]
            authorization_service: Arc::new(
                crate::authorization_enhanced::AuthorizationService::new().await?,
            ),
        })
    }

    /// Build an [`ApiState`] with a pre-constructed authorization service.
    ///
    /// # Example
    /// ```rust,ignore
    /// let state = ApiState::with_authorization_service(fw, limiter, authz);
    /// ```
    #[cfg(feature = "enhanced-rbac")]
    pub fn with_authorization_service(
        auth_framework: Arc<AuthFramework>,
        rate_limiter: Arc<DistributedRateLimiter>,
        authorization_service: Arc<crate::authorization_enhanced::AuthorizationService>,
    ) -> Self {
        Self {
            auth_framework,
            rate_limiter,
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
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
}

/// Validate API token and extract user information
pub async fn validate_api_token(
    auth_framework: &AuthFramework,
    token: &str,
) -> Result<crate::tokens::AuthToken, AuthError> {
    // Validate the JWT signature and expiry
    let token_obj = auth_framework.token_manager().validate_jwt_token(token)?;

    // Check whether this token has been explicitly revoked (e.g. via logout)
    let revocation_key = format!("revoked_token:{}", token_obj.jti);
    match auth_framework.storage().get_kv(&revocation_key).await {
        Ok(Some(_)) => {
            return Err(AuthError::Unauthorized(
                "Token has been revoked".to_string(),
            ));
        }
        Ok(None) => {} // Not revoked — proceed
        Err(e) => {
            tracing::error!("Could not check token revocation list: {}", e);
            return Err(AuthError::Unauthorized(
                "Unable to verify token status".to_string(),
            ));
        }
    }

    // Convert the validated token claims to AuthToken.
    // Roles are not embedded in JWT claims (create_jwt_token sets roles: None),
    // so we load them from the user record in KV storage to allow role-based
    // access checks (e.g. admin endpoints) to work correctly.
    let user_id_str = token_obj.sub.clone();
    let roles = {
        let user_key = format!("user:{}", user_id_str);
        match auth_framework.storage().get_kv(&user_key).await {
            Ok(Some(bytes)) => {
                let json: serde_json::Value = match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(user_id = %user_id_str, "Failed to parse user record JSON for role extraction: {}", e);
                        serde_json::Value::default()
                    }
                };
                // Check if account is active
                if json["active"].as_bool() == Some(false) {
                    return Err(AuthError::Unauthorized("Account is disabled".to_string()));
                }
                json["roles"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| token_obj.roles.clone().unwrap_or_default())
            }
            _ => token_obj.roles.clone().unwrap_or_default(),
        }
    };

    Ok(crate::tokens::AuthToken {
        token_id: token_obj.jti.clone(),
        user_id: user_id_str.clone(),
        access_token: token.to_string(),
        token_type: Some("Bearer".to_string()),
        subject: Some(user_id_str.clone()),
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
        permissions: token_obj.permissions.unwrap_or_default().into(),
        roles: roles.into(),
        metadata: crate::tokens::TokenMetadata {
            session_id: None, // JWT tokens don't have session_id in claims by default
            ..Default::default()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer mytoken123".parse().unwrap());
        assert_eq!(
            extract_bearer_token(&headers),
            Some("mytoken123".to_string())
        );
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_not_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());
        // SEC-6: Empty bearer tokens are rejected
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[tokio::test]
    async fn test_validate_api_token_invalid() {
        let config = crate::AuthConfig::new().secret("a]Bc!d@e#f$g%h^i&j*k(l)m_n-o+p=q");
        let fw = AuthFramework::new(config);
        let result = validate_api_token(&fw, "not.a.valid.token").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_api_token_revoked() {
        let config = crate::AuthConfig::new().secret("a]Bc!d@e#f$g%h^i&j*k(l)m_n-o+p=q");
        let mut fw = AuthFramework::new(config);
        fw.initialize().await.unwrap();

        // Create a valid JWT token
        let token = fw
            .token_manager()
            .create_jwt_token("user1", vec!["user".into()], None)
            .unwrap();
        let token_obj = fw.token_manager().validate_jwt_token(&token).unwrap();

        // Revoke it
        let revocation_key = format!("revoked_token:{}", token_obj.jti);
        fw.storage()
            .store_kv(&revocation_key, b"revoked", None)
            .await
            .unwrap();

        // Should fail with "revoked"
        let result = validate_api_token(&fw, &token).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("revoked"));
    }

    #[tokio::test]
    async fn test_validate_api_token_success() {
        let config = crate::AuthConfig::new().secret("a]Bc!d@e#f$g%h^i&j*k(l)m_n-o+p=q");
        let mut fw = AuthFramework::new(config);
        fw.initialize().await.unwrap();

        let token = fw
            .token_manager()
            .create_jwt_token("user_abc", vec!["user".into()], None)
            .unwrap();

        let auth_token = validate_api_token(&fw, &token).await.unwrap();
        assert_eq!(auth_token.user_id, "user_abc");
        assert_eq!(auth_token.auth_method, "jwt");
        assert_eq!(auth_token.token_type.as_deref(), Some("Bearer"));
    }

    #[tokio::test]
    async fn test_validate_api_token_with_roles_from_storage() {
        let config = crate::AuthConfig::new().secret("a]Bc!d@e#f$g%h^i&j*k(l)m_n-o+p=q");
        let mut fw = AuthFramework::new(config);
        fw.initialize().await.unwrap();

        // Store a user profile with an admin role
        let user_json = serde_json::json!({"user_id": "role_user", "roles": ["admin", "editor"]});
        fw.storage()
            .store_kv(
                "user:role_user",
                serde_json::to_vec(&user_json).unwrap().as_slice(),
                None,
            )
            .await
            .unwrap();

        let token = fw
            .token_manager()
            .create_jwt_token("role_user", vec!["user".into()], None)
            .unwrap();

        let auth_token = validate_api_token(&fw, &token).await.unwrap();
        assert!(auth_token.roles.contains(&"admin".to_string()));
        assert!(auth_token.roles.contains(&"editor".to_string()));
    }
}
