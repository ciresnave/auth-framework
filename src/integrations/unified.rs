/*
 * AuthFramework - Unified Web Framework Integration
 *
 * This module provides a unified authentication configuration and validation logic
 * that can be used across multiple web frameworks. While we keep the web-server-abstraction
 * dependency for future integration, this module focuses on providing shared authentication
 * logic that framework-specific integrations can leverage.
 */

use crate::{AuthError, AuthFramework, providers::ProviderProfile};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Configuration for the unified authentication middleware.
///
/// # Example
/// ```rust
/// use auth_framework::integrations::unified::AuthMiddlewareConfig;
/// let config = AuthMiddlewareConfig::default();
/// assert_eq!(config.header_name, "Authorization");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMiddlewareConfig {
    /// Paths to skip authentication (e.g., ["/health", "/api/v1/auth/login"])
    pub skip_paths: Vec<String>,
    /// Required roles for access (empty means any authenticated user)
    pub required_roles: Vec<String>,
    /// Required permissions for access (empty means any authenticated user)  
    pub required_permissions: Vec<String>,
    /// Name of the authentication cookie
    pub cookie_name: String,
    /// Name of the authentication header
    pub header_name: String,
    /// Whether to allow query parameter authentication
    pub allow_query_param: bool,
    /// Name of the query parameter for authentication
    pub query_param_name: String,
}

impl Default for AuthMiddlewareConfig {
    fn default() -> Self {
        Self {
            skip_paths: vec![
                "/health".to_string(),
                "/api/v1/auth/login".to_string(),
                "/api/v1/auth/register".to_string(),
            ],
            required_roles: Vec::new(),
            required_permissions: Vec::new(),
            cookie_name: "auth_token".to_string(),
            header_name: "Authorization".to_string(),
            allow_query_param: false,
            query_param_name: "token".to_string(),
        }
    }
}

/// Unified authentication validator that provides shared logic across web frameworks.
///
/// # Example
/// ```rust,ignore
/// let v = UnifiedAuthValidator::with_defaults(fw.clone());
/// ```
pub struct UnifiedAuthValidator {
    auth_framework: Arc<AuthFramework>,
    config: AuthMiddlewareConfig,
}

impl UnifiedAuthValidator {
    /// Create a new unified authentication validator.
    ///
    /// # Example
    /// ```rust,ignore
    /// let v = UnifiedAuthValidator::new(fw.clone(), AuthMiddlewareConfig::default());
    /// ```
    pub fn new(auth_framework: Arc<AuthFramework>, config: AuthMiddlewareConfig) -> Self {
        Self {
            auth_framework,
            config,
        }
    }

    /// Create a new validator with default configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let v = UnifiedAuthValidator::with_defaults(fw.clone());
    /// ```
    pub fn with_defaults(auth_framework: Arc<AuthFramework>) -> Self {
        Self::new(auth_framework, AuthMiddlewareConfig::default())
    }

    /// Extract authentication token from authorization header.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = v.extract_token_from_header(Some("Bearer abc123"));
    /// ```
    pub fn extract_token_from_header(&self, auth_header: Option<&str>) -> Option<String> {
        if let Some(header_value) = auth_header {
            if let Some(token) = header_value.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
            // Also support just the token without "Bearer " prefix
            if !header_value.contains(' ') {
                return Some(header_value.to_string());
            }
        }
        None
    }

    /// Extract authentication token from cookie value.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = v.extract_token_from_cookie(Some("abc123"));
    /// ```
    pub fn extract_token_from_cookie(&self, cookie_value: Option<&str>) -> Option<String> {
        cookie_value.map(|value| value.to_string())
    }

    /// Extract authentication token from query parameter.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = v.extract_token_from_query(Some("abc123"));
    /// ```
    pub fn extract_token_from_query(&self, query_value: Option<&str>) -> Option<String> {
        if self.config.allow_query_param {
            query_value.map(|value| value.to_string())
        } else {
            None
        }
    }

    /// Check if path should skip authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// assert!(v.should_skip_path("/health"));
    /// ```
    pub fn should_skip_path(&self, path: &str) -> bool {
        self.config.skip_paths.iter().any(|skip_path| {
            // Support both exact matches and prefix matches
            path == skip_path || path.starts_with(&format!("{}/", skip_path))
        })
    }

    /// Validate authentication token and return user profile.
    ///
    /// # Example
    /// ```rust,ignore
    /// let profile = v.validate_token("jwt-token").await?;
    /// ```
    pub async fn validate_token(&self, token: &str) -> Result<ProviderProfile, AuthError> {
        // Validate JWT token string and extract claims
        let jwt_claims = self.auth_framework.validate_access_jwt(token).await?;

        // Get user profile using the user_id from JWT claims
        let user_profile = self
            .auth_framework
            .get_user_profile(&jwt_claims.sub)
            .await?;

        Ok(user_profile)
    }

    /// Validate user access based on configured roles and permissions.
    ///
    /// # Example
    /// ```rust,ignore
    /// v.validate_access("user-1").await?;
    /// ```
    pub async fn validate_access(&self, user_id: &str) -> Result<(), AuthError> {
        // Verify the user profile exists as a basic existence check
        let _user_profile = self.auth_framework.get_user_profile(user_id).await?;

        // Enforce required roles: user must have ALL required roles
        if !self.config.required_roles.is_empty() {
            for role in &self.config.required_roles {
                let has_role = self.auth_framework.user_has_role(user_id, role).await.unwrap_or(false);
                if !has_role {
                    return Err(AuthError::Permission(
                        crate::errors::PermissionError::InsufficientPermissions {
                            required: format!("role:{}", role),
                            actual: "none".to_string(),
                        },
                    ));
                }
            }
        }

        // Enforce required permissions: user must have ALL required permissions
        if !self.config.required_permissions.is_empty() {
            let effective_perms = self
                .auth_framework
                .get_effective_permissions(user_id)
                .await
                .unwrap_or_default();

            for required_perm in &self.config.required_permissions {
                if !effective_perms.contains(required_perm) {
                    return Err(AuthError::Permission(
                        crate::errors::PermissionError::InsufficientPermissions {
                            required: required_perm.clone(),
                            actual: effective_perms.join(", "),
                        },
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Builder for creating unified authentication validator with method chaining.
///
/// # Example
/// ```rust,ignore
/// let v = UnifiedAuthBuilder::new(fw.clone()).skip_paths(vec!["/public".into()]).build();
/// ```
pub struct UnifiedAuthBuilder {
    auth_framework: Arc<AuthFramework>,
    config: AuthMiddlewareConfig,
}

impl UnifiedAuthBuilder {
    /// Create a new builder with the given AuthFramework instance.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = UnifiedAuthBuilder::new(fw.clone());
    /// ```
    pub fn new(auth_framework: Arc<AuthFramework>) -> Self {
        Self {
            auth_framework,
            config: AuthMiddlewareConfig::default(),
        }
    }

    /// Add paths that should skip authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.skip_paths(vec!["/public".into()]);
    /// ```
    pub fn skip_paths(mut self, paths: Vec<String>) -> Self {
        self.config.skip_paths.extend(paths);
        self
    }

    /// Set required roles for access.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.require_roles(vec!["admin".into()]);
    /// ```
    pub fn require_roles(mut self, roles: Vec<String>) -> Self {
        self.config.required_roles = roles;
        self
    }

    /// Set required permissions for access.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.require_permissions(vec!["read:users".into()]);
    /// ```
    pub fn require_permissions(mut self, permissions: Vec<String>) -> Self {
        self.config.required_permissions = permissions;
        self
    }

    /// Set custom cookie name for authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.cookie_name("session".into());
    /// ```
    pub fn cookie_name(mut self, name: String) -> Self {
        self.config.cookie_name = name;
        self
    }

    /// Set custom header name for authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.header_name("X-Auth-Token".into());
    /// ```
    pub fn header_name(mut self, name: String) -> Self {
        self.config.header_name = name;
        self
    }

    /// Enable query parameter authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = builder.allow_query_param("token".into());
    /// ```
    pub fn allow_query_param(mut self, param_name: String) -> Self {
        self.config.allow_query_param = true;
        self.config.query_param_name = param_name;
        self
    }

    /// Build the validator.
    ///
    /// # Example
    /// ```rust,ignore
    /// let v = builder.build();
    /// ```
    pub fn build(self) -> UnifiedAuthValidator {
        UnifiedAuthValidator::new(self.auth_framework, self.config)
    }
}

/// Convenience function to create a unified auth validator with default config.
///
/// # Example
/// ```rust,ignore
/// let v = create_auth_validator(fw.clone());
/// ```
pub fn create_auth_validator(auth_framework: Arc<AuthFramework>) -> UnifiedAuthValidator {
    UnifiedAuthValidator::with_defaults(auth_framework)
}

/// Convenience function to create a builder for more complex configurations.
///
/// # Example
/// ```rust,ignore
/// let builder = auth_validator_builder(fw.clone());
/// ```
pub fn auth_validator_builder(auth_framework: Arc<AuthFramework>) -> UnifiedAuthBuilder {
    UnifiedAuthBuilder::new(auth_framework)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthMiddlewareConfig::default();
        assert_eq!(config.cookie_name, "auth_token");
        assert_eq!(config.header_name, "Authorization");
        assert!(!config.allow_query_param);
        assert!(config.skip_paths.contains(&"/health".to_string()));
    }

    #[test]
    fn test_config_builder() {
        let config = AuthMiddlewareConfig {
            skip_paths: vec!["/api/public".to_string()],
            required_roles: vec!["admin".to_string()],
            cookie_name: "session_token".to_string(),
            ..Default::default()
        };

        assert_eq!(config.cookie_name, "session_token");
        assert!(config.required_roles.contains(&"admin".to_string()));
        assert!(config.skip_paths.contains(&"/api/public".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_from_header() {
        let token = UnifiedAuthValidator::extract_token_from_header("Bearer abc123");
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_token_missing_bearer_prefix() {
        let token = UnifiedAuthValidator::extract_token_from_header("abc123");
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_empty_bearer() {
        let token = UnifiedAuthValidator::extract_token_from_header("Bearer ");
        assert_eq!(token, Some("".to_string()));
    }

    #[test]
    fn test_extract_token_case_sensitive_bearer() {
        // Standard is "Bearer", check "bearer" is rejected
        let token = UnifiedAuthValidator::extract_token_from_header("bearer abc123");
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_from_cookie_present() {
        let cookie_str = "other=val; auth_token=mytoken; foo=bar";
        let token = UnifiedAuthValidator::extract_token_from_cookie(cookie_str, "auth_token");
        assert_eq!(token, Some("mytoken".to_string()));
    }

    #[test]
    fn test_extract_token_from_cookie_missing() {
        let cookie_str = "other=val; foo=bar";
        let token = UnifiedAuthValidator::extract_token_from_cookie(cookie_str, "auth_token");
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_from_cookie_empty_value() {
        let cookie_str = "auth_token=";
        let token = UnifiedAuthValidator::extract_token_from_cookie(cookie_str, "auth_token");
        assert_eq!(token, Some("".to_string()));
    }

    #[test]
    fn test_extract_token_from_query_present() {
        let query = "foo=bar&token=mytoken&baz=1";
        let token = UnifiedAuthValidator::extract_token_from_query(query, "token");
        assert_eq!(token, Some("mytoken".to_string()));
    }

    #[test]
    fn test_extract_token_from_query_missing() {
        let query = "foo=bar";
        let token = UnifiedAuthValidator::extract_token_from_query(query, "token");
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_from_query_empty_value() {
        let query = "token=";
        let token = UnifiedAuthValidator::extract_token_from_query(query, "token");
        assert_eq!(token, Some("".to_string()));
    }

    #[test]
    fn test_should_skip_path_exact_match() {
        let config = AuthMiddlewareConfig {
            skip_paths: vec!["/health".to_string(), "/ready".to_string()],
            ..Default::default()
        };
        let validator = UnifiedAuthValidator {
            auth_framework: Arc::new(AuthFramework::new(
                crate::config::AuthConfig::default().secret("test-secret-for-unified-tests"),
            )),
            config,
        };
        assert!(validator.should_skip_path("/health"));
        assert!(validator.should_skip_path("/ready"));
        assert!(!validator.should_skip_path("/api/users"));
    }

    #[test]
    fn test_should_skip_path_empty_list() {
        let config = AuthMiddlewareConfig {
            skip_paths: vec![],
            ..Default::default()
        };
        let validator = UnifiedAuthValidator {
            auth_framework: Arc::new(AuthFramework::new(
                crate::config::AuthConfig::default().secret("test-secret-for-unified-tests"),
            )),
            config,
        };
        assert!(!validator.should_skip_path("/anything"));
    }

    #[test]
    fn test_builder_chain() {
        let _env = crate::testing::test_infrastructure::TestEnvironmentGuard::new()
            .with_jwt_secret("test-secret-builder");

        let fw = Arc::new(AuthFramework::new(
            crate::config::AuthConfig::default().secret("test-secret-builder"),
        ));

        let validator = UnifiedAuthBuilder::new(fw)
            .skip_paths(vec!["/public".into()])
            .require_roles(vec!["admin".into()])
            .require_permissions(vec!["read:all".into()])
            .cookie_name("my_cookie".into())
            .header_name("X-Token".into())
            .allow_query_param("api_key".into())
            .build();

        assert!(validator.config.skip_paths.contains(&"/public".to_string()));
        assert!(validator.config.required_roles.contains(&"admin".to_string()));
        assert!(validator.config.required_permissions.contains(&"read:all".to_string()));
        assert_eq!(validator.config.cookie_name, "my_cookie");
        assert_eq!(validator.config.header_name, "X-Token");
        assert!(validator.config.allow_query_param);
        assert_eq!(validator.config.query_param_name, "api_key");
    }

    #[test]
    fn test_convenience_functions() {
        let _env = crate::testing::test_infrastructure::TestEnvironmentGuard::new()
            .with_jwt_secret("test-secret-convenience");

        let fw = Arc::new(AuthFramework::new(
            crate::config::AuthConfig::default().secret("test-secret-convenience"),
        ));

        let v = create_auth_validator(fw.clone());
        assert_eq!(v.config.cookie_name, "auth_token");

        let b = auth_validator_builder(fw);
        let v2 = b.build();
        assert_eq!(v2.config.header_name, "Authorization");
    }
}
