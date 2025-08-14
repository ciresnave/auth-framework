//! OAuth 2.0 Client Registry Module
//!
//! This module implements a client registry for managing OAuth 2.0 clients
//! including registration, retrieval, and validation.

use crate::errors::{AuthError, Result};
use crate::storage::core::AuthStorage;
use crate::storage::memory::InMemoryStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// OAuth 2.0 Client Types as defined in RFC 6749
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Confidential clients capable of securely storing credentials
    Confidential,
    /// Public clients unable to securely store credentials
    Public,
}

/// OAuth 2.0 Client Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Unique client identifier
    pub client_id: String,
    /// Client secret (only for confidential clients)
    pub client_secret: Option<String>,
    /// Client type
    pub client_type: ClientType,
    /// Authorized redirect URIs
    pub redirect_uris: Vec<String>,
    /// Authorized scopes
    pub authorized_scopes: Vec<String>,
    /// Grant types the client is authorized to use
    pub authorized_grant_types: Vec<String>,
    /// Response types the client is authorized to use
    pub authorized_response_types: Vec<String>,
    /// Client name for display purposes
    pub client_name: Option<String>,
    /// Client description
    pub client_description: Option<String>,
    /// Client metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_id: Uuid::new_v4().to_string(),
            client_secret: None,
            client_type: ClientType::Public,
            redirect_uris: Vec::new(),
            authorized_scopes: vec!["read".to_string()],
            authorized_grant_types: vec!["authorization_code".to_string()],
            authorized_response_types: vec!["code".to_string()],
            client_name: None,
            client_description: None,
            metadata: HashMap::new(),
        }
    }
}

/// Client Registry for managing OAuth 2.0 clients
#[derive(Clone)]
pub struct ClientRegistry {
    storage: Arc<dyn AuthStorage>,
}

impl ClientRegistry {
    /// Create a new client registry
    pub async fn new(storage: Arc<dyn AuthStorage>) -> Result<Self> {
        Ok(Self { storage })
    }

    /// Register a new OAuth 2.0 client
    pub async fn register_client(&self, config: ClientConfig) -> Result<ClientConfig> {
        // Validate the client configuration
        self.validate_client_config(&config)?;

        // Store the client in the storage backend
        let client_key = format!("oauth_client:{}", config.client_id);
        let client_data = serde_json::to_string(&config)
            .map_err(|e| AuthError::internal(format!("Failed to serialize client: {}", e)))?;

        self.storage
            .store_kv(&client_key, client_data.as_bytes(), None)
            .await?;

        Ok(config)
    }

    /// Retrieve a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientConfig>> {
        let client_key = format!("oauth_client:{}", client_id);

        if let Some(client_data) = self.storage.get_kv(&client_key).await? {
            let client_str = std::str::from_utf8(&client_data)
                .map_err(|e| AuthError::internal(format!("Invalid UTF-8 in client data: {}", e)))?;
            let config: ClientConfig = serde_json::from_str(client_str)
                .map_err(|e| AuthError::internal(format!("Failed to deserialize client: {}", e)))?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Update a client configuration
    pub async fn update_client(&self, client_id: &str, config: ClientConfig) -> Result<()> {
        // Ensure the client ID matches
        if config.client_id != client_id {
            return Err(AuthError::validation("Client ID mismatch"));
        }

        // Validate the updated configuration
        self.validate_client_config(&config)?;

        // Store the updated client
        let client_key = format!("oauth_client:{}", client_id);
        let client_data = serde_json::to_string(&config)
            .map_err(|e| AuthError::internal(format!("Failed to serialize client: {}", e)))?;

        self.storage
            .store_kv(&client_key, client_data.as_bytes(), None)
            .await?;

        Ok(())
    }

    /// Delete a client
    pub async fn delete_client(&self, client_id: &str) -> Result<()> {
        let client_key = format!("oauth_client:{}", client_id);
        self.storage.delete_kv(&client_key).await?;
        Ok(())
    }

    /// Validate that a redirect URI is authorized for a client
    pub async fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client.redirect_uris.contains(&redirect_uri.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Validate that a scope is authorized for a client
    pub async fn validate_scope(&self, client_id: &str, scope: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client.authorized_scopes.contains(&scope.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Validate that a grant type is authorized for a client
    pub async fn validate_grant_type(&self, client_id: &str, grant_type: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client
                .authorized_grant_types
                .contains(&grant_type.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Authenticate a confidential client using client credentials
    pub async fn authenticate_client(&self, client_id: &str, client_secret: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            match (&client.client_type, &client.client_secret) {
                (ClientType::Confidential, Some(stored_secret)) => {
                    // Use constant-time comparison to prevent timing attacks
                    Ok(crate::secure_utils::constant_time_compare(
                        client_secret.as_bytes(),
                        stored_secret.as_bytes(),
                    ))
                }
                (ClientType::Public, None) => {
                    // Public clients don't have secrets
                    Ok(true)
                }
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Validate client configuration
    fn validate_client_config(&self, config: &ClientConfig) -> Result<()> {
        // Client ID must not be empty
        if config.client_id.is_empty() {
            return Err(AuthError::validation("Client ID cannot be empty"));
        }

        // Confidential clients must have a secret
        if config.client_type == ClientType::Confidential && config.client_secret.is_none() {
            return Err(AuthError::validation(
                "Confidential clients must have a client secret",
            ));
        }

        // Public clients must not have a secret
        if config.client_type == ClientType::Public && config.client_secret.is_some() {
            return Err(AuthError::validation(
                "Public clients must not have a client secret",
            ));
        }

        // At least one redirect URI must be provided
        if config.redirect_uris.is_empty() {
            return Err(AuthError::validation(
                "At least one redirect URI must be provided",
            ));
        }

        // Validate redirect URIs
        for uri in &config.redirect_uris {
            if uri.is_empty() {
                return Err(AuthError::validation("Redirect URI cannot be empty"));
            }

            // Basic URI validation (in production, use a proper URI parser)
            if !uri.starts_with("https://") && !uri.starts_with("http://localhost") {
                return Err(AuthError::validation(
                    "Redirect URIs must use HTTPS (except localhost)",
                ));
            }
        }

        // At least one scope must be provided
        if config.authorized_scopes.is_empty() {
            return Err(AuthError::validation(
                "At least one authorized scope must be provided",
            ));
        }

        // At least one grant type must be provided
        if config.authorized_grant_types.is_empty() {
            return Err(AuthError::validation(
                "At least one authorized grant type must be provided",
            ));
        }

        // At least one response type must be provided
        if config.authorized_response_types.is_empty() {
            return Err(AuthError::validation(
                "At least one authorized response type must be provided",
            ));
        }

        Ok(())
    }
}

impl Default for ClientRegistry {
    fn default() -> Self {
        // Create default registry with environment-based storage configuration
        let storage =
            if std::env::var("CLIENT_REGISTRY_STORAGE").unwrap_or_default() == "persistent" {
                // In production, this could be database or file-based storage
                Arc::new(InMemoryStorage::new())
            } else {
                // Default to in-memory storage for development/testing
                Arc::new(InMemoryStorage::new())
            };

        Self { storage }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::InMemoryStorage;

    #[tokio::test]
    async fn test_client_registry_operations() {
        let storage = Arc::new(InMemoryStorage::new());
        let registry = ClientRegistry::new(storage).await.unwrap();

        // Create a test client configuration
        let client_config = ClientConfig {
            client_id: "test_client".to_string(),
            client_type: ClientType::Confidential,
            client_secret: Some("test_secret".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            ..Default::default()
        };

        // Register the client
        let registered_client = registry
            .register_client(client_config.clone())
            .await
            .unwrap();
        assert_eq!(registered_client.client_id, "test_client");

        // Retrieve the client
        let retrieved_client = registry.get_client("test_client").await.unwrap().unwrap();
        assert_eq!(retrieved_client.client_id, "test_client");
        assert_eq!(retrieved_client.client_type, ClientType::Confidential);

        // Authenticate the client
        let auth_result = registry
            .authenticate_client("test_client", "test_secret")
            .await
            .unwrap();
        assert!(auth_result);

        let auth_fail = registry
            .authenticate_client("test_client", "wrong_secret")
            .await
            .unwrap();
        assert!(!auth_fail);

        // Validate redirect URI
        let valid_uri = registry
            .validate_redirect_uri("test_client", "https://example.com/callback")
            .await
            .unwrap();
        assert!(valid_uri);

        let invalid_uri = registry
            .validate_redirect_uri("test_client", "https://malicious.com/callback")
            .await
            .unwrap();
        assert!(!invalid_uri);

        // Delete the client
        registry.delete_client("test_client").await.unwrap();
        let deleted_client = registry.get_client("test_client").await.unwrap();
        assert!(deleted_client.is_none());
    }

    #[tokio::test]
    async fn test_client_validation() {
        let storage = Arc::new(InMemoryStorage::new());
        let registry = ClientRegistry::new(storage).await.unwrap();

        // Test empty client ID
        let invalid_config = ClientConfig {
            client_id: "".to_string(),
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());

        // Test confidential client without secret
        let invalid_config = ClientConfig {
            client_type: ClientType::Confidential,
            client_secret: None,
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());

        // Test public client with secret
        let invalid_config = ClientConfig {
            client_type: ClientType::Public,
            client_secret: Some("secret".to_string()),
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());

        // Test empty redirect URIs
        let invalid_config = ClientConfig {
            redirect_uris: vec![],
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());

        // Test insecure redirect URI
        let invalid_config = ClientConfig {
            redirect_uris: vec!["http://example.com/callback".to_string()],
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());
    }
}
