//! OAuth 2.1 Framework Module
//!
//! This module implements OAuth 2.1 security enhancements and best practices
//! as a wrapper around the OAuth 2.0 implementation, providing enhanced security
//! and compliance with the latest OAuth 2.1 specification.

use crate::errors::{AuthError, Result};
use crate::server::core::client_registry::ClientConfig;
use crate::server::oauth::oauth2::OAuth2Server;
use crate::storage::core::AuthStorage;
use std::sync::Arc;

/// OAuth 2.1 Security Requirements
#[derive(Debug, Clone)]
pub struct OAuth21SecurityConfig {
    /// Require PKCE for all public clients
    pub require_pkce_for_public_clients: bool,
    /// Disallow the implicit grant type
    pub disallow_implicit_grant: bool,
    /// Require exact redirect URI matching
    pub require_exact_redirect_uri_matching: bool,
    /// Require secure redirect URIs (HTTPS)
    pub require_secure_redirect_uris: bool,
    /// Maximum authorization code lifetime (seconds)
    pub max_auth_code_lifetime: u64,
    /// Maximum access token lifetime (seconds)
    pub max_access_token_lifetime: u64,
    /// Require client authentication for confidential clients
    pub require_client_authentication: bool,
    /// Disallow password grant type
    pub disallow_password_grant: bool,
}

impl Default for OAuth21SecurityConfig {
    fn default() -> Self {
        Self {
            require_pkce_for_public_clients: true,
            disallow_implicit_grant: true,
            require_exact_redirect_uri_matching: true,
            require_secure_redirect_uris: true,
            max_auth_code_lifetime: 600,     // 10 minutes
            max_access_token_lifetime: 3600, // 1 hour
            require_client_authentication: true,
            disallow_password_grant: true,
        }
    }
}

/// OAuth 2.1 Authorization Server
///
/// This server implements OAuth 2.1 security best practices and requirements,
/// providing enhanced security over OAuth 2.0.
#[derive(Clone)]
pub struct OAuth21Server {
    /// Underlying OAuth 2.0 server
    oauth2_server: Arc<OAuth2Server>,
    /// OAuth 2.1 specific security configuration
    security_config: OAuth21SecurityConfig,
}

impl OAuth21Server {
    /// Create a new OAuth 2.1 server
    pub async fn new(
        security_config: Option<OAuth21SecurityConfig>,
        storage: Arc<dyn AuthStorage>,
    ) -> Result<Self> {
        let oauth2_server = Arc::new(OAuth2Server::new(storage).await?);
        let security_config = security_config.unwrap_or_default();

        Ok(Self {
            oauth2_server,
            security_config,
        })
    }

    /// Register a new OAuth 2.1 compliant client
    pub async fn register_client(&self, mut config: ClientConfig) -> Result<ClientConfig> {
        // OAuth 2.1 security validations
        self.validate_oauth21_client_config(&mut config)?;

        // Register with the underlying OAuth 2.0 server
        self.oauth2_server.register_client(config).await
    }

    /// Get a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientConfig>> {
        self.oauth2_server.get_client(client_id).await
    }

    /// Update a client configuration
    pub async fn update_client(&self, client_id: &str, config: ClientConfig) -> Result<()> {
        self.oauth2_server.update_client(client_id, config).await
    }

    /// Delete a client
    pub async fn delete_client(&self, client_id: &str) -> Result<()> {
        self.oauth2_server.delete_client(client_id).await
    }

    /// Get OAuth 2.1 server configuration
    pub async fn get_server_configuration(&self) -> Result<serde_json::Value> {
        let mut config = self.oauth2_server.get_server_configuration().await?;

        // OAuth 2.1 specific modifications
        if let Some(obj) = config.as_object_mut() {
            // Remove implicit grant if disabled
            if self.security_config.disallow_implicit_grant {
                if let Some(grant_types) = obj.get_mut("grant_types_supported")
                    && let Some(grants) = grant_types.as_array_mut()
                {
                    grants.retain(|g| g.as_str() != Some("implicit"));
                }

                if let Some(response_types) = obj.get_mut("response_types_supported")
                    && let Some(types) = response_types.as_array_mut()
                {
                    types.retain(|t| {
                        if let Some(type_str) = t.as_str() {
                            !type_str.contains("token") || type_str.contains("code")
                        } else {
                            true
                        }
                    });
                }
            }

            // Remove password grant if disabled
            if self.security_config.disallow_password_grant
                && let Some(grant_types) = obj.get_mut("grant_types_supported")
                && let Some(grants) = grant_types.as_array_mut()
            {
                grants.retain(|g| g.as_str() != Some("password"));
            }

            // Add OAuth 2.1 specific fields
            obj.insert(
                "oauth21_compliant".to_string(),
                serde_json::Value::Bool(true),
            );
            obj.insert(
                "pkce_required".to_string(),
                serde_json::Value::Bool(self.security_config.require_pkce_for_public_clients),
            );
            obj.insert(
                "implicit_grant_disabled".to_string(),
                serde_json::Value::Bool(self.security_config.disallow_implicit_grant),
            );
            obj.insert(
                "password_grant_disabled".to_string(),
                serde_json::Value::Bool(self.security_config.disallow_password_grant),
            );
        }

        Ok(config)
    }

    /// Validate OAuth 2.1 client configuration
    fn validate_oauth21_client_config(&self, config: &mut ClientConfig) -> Result<()> {
        // OAuth 2.1 requires HTTPS redirect URIs (except localhost for development)
        if self.security_config.require_secure_redirect_uris {
            for uri in &config.redirect_uris {
                if !uri.starts_with("https://")
                    && !uri.starts_with("http://localhost")
                    && !uri.starts_with("http://127.0.0.1")
                {
                    return Err(AuthError::validation(
                        "OAuth 2.1 requires HTTPS redirect URIs (except localhost)",
                    ));
                }
            }
        }

        // Remove insecure grant types for OAuth 2.1 compliance
        if self.security_config.disallow_implicit_grant {
            config.authorized_grant_types.retain(|g| g != "implicit");
            config
                .authorized_response_types
                .retain(|r| !r.contains("token") || r.contains("code"));
        }

        if self.security_config.disallow_password_grant {
            config.authorized_grant_types.retain(|g| g != "password");
        }

        // Ensure at least one valid grant type remains
        if config.authorized_grant_types.is_empty() {
            config
                .authorized_grant_types
                .push("authorization_code".to_string());
        }

        if config.authorized_response_types.is_empty() {
            config.authorized_response_types.push("code".to_string());
        }

        Ok(())
    }

    /// Get security configuration
    pub fn get_security_config(&self) -> &OAuth21SecurityConfig {
        &self.security_config
    }

    /// Update security configuration
    pub fn update_security_config(&mut self, config: OAuth21SecurityConfig) {
        self.security_config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::core::client_registry::{ClientConfig, ClientType};
    use crate::storage::memory::InMemoryStorage;

    #[tokio::test]
    async fn test_oauth21_server_creation() {
        let storage = Arc::new(InMemoryStorage::new());
        let security_config = OAuth21SecurityConfig::default();

        let server = OAuth21Server::new(Some(security_config), storage)
            .await
            .unwrap();

        // Test OAuth 2.1 compliant client registration
        let client_config = ClientConfig {
            client_id: "test_client".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            ..Default::default()
        };

        let registered_client = server.register_client(client_config).await.unwrap();
        assert_eq!(registered_client.client_id, "test_client");

        // Verify implicit grant was removed
        assert!(
            !registered_client
                .authorized_grant_types
                .contains(&"implicit".to_string())
        );
        assert!(
            !registered_client
                .authorized_response_types
                .iter()
                .any(|r| r.contains("token") && !r.contains("code"))
        );
    }

    #[tokio::test]
    async fn test_oauth21_security_validations() {
        let storage = Arc::new(InMemoryStorage::new());
        let security_config = OAuth21SecurityConfig::default();

        let server = OAuth21Server::new(Some(security_config), storage)
            .await
            .unwrap();

        // Test insecure redirect URI rejection
        let client_config = ClientConfig {
            client_id: "test_client".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["http://example.com/callback".to_string()],
            ..Default::default()
        };

        assert!(server.register_client(client_config).await.is_err());

        // Test secure redirect URI acceptance
        let client_config = ClientConfig {
            client_id: "test_client".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            ..Default::default()
        };

        assert!(server.register_client(client_config).await.is_ok());
    }

    #[tokio::test]
    async fn test_oauth21_server_configuration() {
        let storage = Arc::new(InMemoryStorage::new());
        let security_config = OAuth21SecurityConfig::default();

        let server = OAuth21Server::new(Some(security_config), storage)
            .await
            .unwrap();
        let config = server.get_server_configuration().await.unwrap();

        assert_eq!(config["oauth21_compliant"], true);
        assert_eq!(config["pkce_required"], true);
        assert_eq!(config["implicit_grant_disabled"], true);
        assert_eq!(config["password_grant_disabled"], true);

        // Verify implicit grant is not in supported grant types
        let grant_types = config["grant_types_supported"].as_array().unwrap();
        assert!(!grant_types.iter().any(|g| g.as_str() == Some("implicit")));

        // Verify password grant is not in supported grant types
        assert!(!grant_types.iter().any(|g| g.as_str() == Some("password")));
    }
}
