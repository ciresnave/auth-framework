//! OAuth 2.0 Server Module
//!
//! This module provides a clean interface to the OAuth 2.0 server implementation,
//! wrapping the core oauth2_server functionality with proper server integration.

use crate::errors::Result;
use crate::server::core::client_registry::{ClientConfig, ClientRegistry};
use crate::storage::core::AuthStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OAuth 2.0 Server Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ServerConfig {
    /// Server issuer URL
    pub issuer: String,
    /// Supported scopes
    pub supported_scopes: Vec<String>,
    /// Supported response types
    pub supported_response_types: Vec<String>,
    /// Supported grant types
    pub supported_grant_types: Vec<String>,
}

impl Default for OAuth2ServerConfig {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(), // Should be configured in production
            supported_scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "address".to_string(),
                "phone".to_string(),
                "offline_access".to_string(),
            ],
            supported_response_types: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "code id_token".to_string(),
                "token id_token".to_string(),
                "code token id_token".to_string(),
            ],
            supported_grant_types: vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "password".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ],
        }
    }
}

/// OAuth 2.0 Server with integrated client registry
#[derive(Clone)]
pub struct OAuth2Server {
    /// Server configuration
    config: OAuth2ServerConfig,
    /// Client registry for managing OAuth clients
    client_registry: Arc<ClientRegistry>,
}

impl OAuth2Server {
    /// Create a new OAuth 2.0 server
    pub async fn new(storage: Arc<dyn AuthStorage>) -> Result<Self> {
        let client_registry = Arc::new(ClientRegistry::new(storage).await?);
        let config = OAuth2ServerConfig::default();

        Ok(Self {
            config,
            client_registry,
        })
    }

    /// Create a new OAuth 2.0 server with custom configuration
    pub async fn new_with_config(
        storage: Arc<dyn AuthStorage>,
        config: OAuth2ServerConfig,
    ) -> Result<Self> {
        let client_registry = Arc::new(ClientRegistry::new(storage).await?);

        Ok(Self {
            config,
            client_registry,
        })
    }

    /// Register a new OAuth 2.0 client
    pub async fn register_client(&self, config: ClientConfig) -> Result<ClientConfig> {
        self.client_registry.register_client(config).await
    }

    /// Get a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientConfig>> {
        self.client_registry.get_client(client_id).await
    }

    /// Update a client configuration
    pub async fn update_client(&self, client_id: &str, config: ClientConfig) -> Result<()> {
        self.client_registry.update_client(client_id, config).await
    }

    /// Delete a client
    pub async fn delete_client(&self, client_id: &str) -> Result<()> {
        self.client_registry.delete_client(client_id).await
    }

    /// Get server configuration for discovery
    pub async fn get_server_configuration(&self) -> Result<serde_json::Value> {
        // OAuth 2.0 Authorization Server Metadata (RFC 8414)
        // Use configured issuer instead of hardcoded value
        let issuer = &self.config.issuer;
        let config = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/oauth/authorize", issuer),
            "token_endpoint": format!("{}/oauth/token", issuer),
            "scopes_supported": self.config.supported_scopes,
            "response_types_supported": self.config.supported_response_types,
            "grant_types_supported": self.config.supported_grant_types,
            "revocation_endpoint": format!("{}/oauth/revoke", issuer),
            "introspection_endpoint": format!("{}/oauth/introspect", issuer)
        });

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::core::client_registry::{ClientConfig, ClientType};
    use crate::storage::memory::InMemoryStorage;

    #[tokio::test]
    async fn test_oauth2_server_creation() {
        let storage = Arc::new(InMemoryStorage::new());
        let server = OAuth2Server::new(storage).await.unwrap();

        // Test client registration
        let client_config = ClientConfig {
            client_id: "test_client".to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            ..Default::default()
        };

        let registered_client = server.register_client(client_config).await.unwrap();
        assert_eq!(registered_client.client_id, "test_client");

        // Test client retrieval
        let retrieved_client = server.get_client("test_client").await.unwrap().unwrap();
        assert_eq!(retrieved_client.client_id, "test_client");
    }
}
