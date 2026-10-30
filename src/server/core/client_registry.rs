//! OAuth 2.0 Client Registry Module
//!
//! This module implements a client registry for managing OAuth 2.0 clients
//! including registration, retrieval, and validation.
//!
//! Clients live in the one registry the HTTP API uses: the KV record `oauth2_client:{client_id}`
//! (issue #90). A confidential client's secret is stored only as a hash
//! (`client_secret_hash`, see [`crate::client_secret`]), so [`ClientRegistry::get_client`] returns
//! a [`ClientConfig`] whose `client_secret` is `None`; authenticate with
//! [`ClientRegistry::authenticate_client`]. Records this registry used to write under
//! `oauth_client:{client_id}` (with the secret in plain text) are still found: the first read
//! moves one to the new key, hashing its secret, and removes the old record.

use crate::errors::{AuthError, Result};
use crate::storage::core::AuthStorage;
use crate::storage::memory::InMemoryStorage;
use serde_json::{Value, json};
use std::sync::Arc;

// Re-export canonical types so existing imports like
// `server::core::client_registry::{ClientType, ClientConfig}` keep working.
pub use crate::client::{ClientConfig, ClientType};

/// Where a client's record is kept.
const RECORD_PREFIX: &str = "oauth2_client:";

/// Where this registry kept client records before they were unified with the HTTP API's.
const LEGACY_RECORD_PREFIX: &str = "oauth_client:";

/// The strings of a JSON array field (anything that is not a string is ignored).
fn strings(record: &Value, field: &str) -> Option<Vec<String>> {
    record.get(field).and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect()
    })
}

/// The stored record of a client: the fields the HTTP API's dynamic registration writes, plus
/// `client_type`, `client_description` and `metadata`. A secret is stored as its hash.
async fn config_to_record(config: &ClientConfig) -> Result<Value> {
    let mut record = json!({
        "client_id": config.client_id,
        "client_type": match config.client_type {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        },
        "client_name": config.client_name,
        "client_description": config.client_description,
        "redirect_uris": config.redirect_uris.iter().collect::<Vec<_>>(),
        "grant_types": config.authorized_grant_types.iter().collect::<Vec<_>>(),
        "response_types": config.authorized_response_types.iter().collect::<Vec<_>>(),
        "scope": config.authorized_scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        "metadata": config.metadata,
    });
    if let Some(secret) = &config.client_secret {
        record["client_secret_hash"] =
            Value::String(crate::client_secret::hash_secret(secret).await?);
    }
    Ok(record)
}

/// The [`ClientConfig`] a stored record describes. Both shapes that have been stored under these
/// keys are read: the HTTP API's (`grant_types`, `scope` as one string) and this registry's
/// earlier one (`authorized_*` arrays). The secret is never part of the result.
fn record_to_config(record: &Value) -> Result<ClientConfig> {
    let client_id = record
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::internal("Stored client has no client_id"))?
        .to_string();
    let client_type = match record.get("client_type").and_then(Value::as_str) {
        Some(kind) if kind.eq_ignore_ascii_case("confidential") => ClientType::Confidential,
        Some(kind) if kind.eq_ignore_ascii_case("public") => ClientType::Public,
        _ if crate::client_secret::is_confidential(record) => ClientType::Confidential,
        _ => ClientType::Public,
    };
    let scopes = strings(record, "authorized_scopes").unwrap_or_else(|| {
        record
            .get("scope")
            .and_then(Value::as_str)
            .map(|scope| scope.split_whitespace().map(String::from).collect())
            .unwrap_or_default()
    });
    Ok(ClientConfig {
        client_id,
        client_secret: None,
        client_type,
        redirect_uris: strings(record, "redirect_uris").unwrap_or_default().into(),
        authorized_scopes: scopes.into(),
        authorized_grant_types: strings(record, "authorized_grant_types")
            .or_else(|| strings(record, "grant_types"))
            .unwrap_or_else(|| vec!["authorization_code".to_string()])
            .into(),
        authorized_response_types: strings(record, "authorized_response_types")
            .or_else(|| strings(record, "response_types"))
            .unwrap_or_else(|| vec!["code".to_string()])
            .into(),
        client_name: record
            .get("client_name")
            .and_then(Value::as_str)
            .map(String::from),
        client_description: record
            .get("client_description")
            .and_then(Value::as_str)
            .map(String::from),
        metadata: record
            .get("metadata")
            .and_then(Value::as_object)
            .map(|fields| fields.clone().into_iter().collect())
            .unwrap_or_default(),
    })
}

fn parse_record(data: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(data)
        .map_err(|e| AuthError::internal(format!("Invalid UTF-8 in client data: {}", e)))?;
    serde_json::from_str(text)
        .map_err(|e| AuthError::internal(format!("Failed to deserialize client: {}", e)))
}

/// Set in a migrated record from the moment it is stored until the old record is gone. A read
/// that finds it removes the old record again, so a failed removal is retried instead of
/// leaving a plain-text secret behind for good.
const CLEANUP_MARKER: &str = "legacy_record_pending_removal";

/// Remove the old record of a client. When it cannot be deleted, its secret is at least
/// overwritten (the record is stored again without it); the delete's error is still returned.
async fn remove_legacy_record(storage: &dyn AuthStorage, legacy_key: &str) -> Result<()> {
    let Err(delete_error) = storage.delete_kv(legacy_key).await else {
        return Ok(());
    };
    if let Ok(Some(data)) = storage.get_kv(legacy_key).await
        && let Ok(mut old) = parse_record(&data)
        && let Some(fields) = old.as_object_mut()
    {
        fields.remove("client_secret");
        if let Err(e) = storage
            .store_kv(legacy_key, old.to_string().as_bytes(), None)
            .await
        {
            tracing::error!("Could not remove the secret from the old client record: {e}");
        }
    }
    Err(delete_error)
}

/// Finish a migration: remove the old record, and when that worked clear the marker. A failure
/// leaves the marker, so the next read tries again.
async fn finish_migration(storage: &dyn AuthStorage, client_id: &str, record: &mut Value) {
    match remove_legacy_record(storage, &format!("{LEGACY_RECORD_PREFIX}{client_id}")).await {
        Ok(()) => {
            if let Some(fields) = record.as_object_mut() {
                fields.remove(CLEANUP_MARKER);
            }
            if let Err(e) = storage
                .store_kv(
                    &format!("{RECORD_PREFIX}{client_id}"),
                    record.to_string().as_bytes(),
                    None,
                )
                .await
            {
                tracing::warn!("Could not clear the migration marker of client {client_id}: {e}");
            }
        }
        Err(e) => tracing::error!(
            "Could not remove the old record of client {client_id}, it will be retried: {e}"
        ),
    }
}

/// Load the stored record of a client from `oauth2_client:{client_id}`.
///
/// A record the registry wrote before the unification (`oauth_client:{client_id}`, secret in
/// plain text) is moved here first: it is stored under the new key with its secret hashed and a
/// marker, and only then is the old record removed, so a failure never loses a client. If the
/// removal fails the marker stays and every later read tries it again (and the old record's
/// secret is overwritten at once where it can be).
pub(crate) async fn load_record(
    storage: &dyn AuthStorage,
    client_id: &str,
) -> Result<Option<Value>> {
    if let Some(data) = storage
        .get_kv(&format!("{RECORD_PREFIX}{client_id}"))
        .await?
    {
        let mut record = parse_record(&data)?;
        if record.get(CLEANUP_MARKER).is_some() {
            finish_migration(storage, client_id, &mut record).await;
        }
        return Ok(Some(record));
    }

    let legacy_key = format!("{LEGACY_RECORD_PREFIX}{client_id}");
    let Some(data) = storage.get_kv(&legacy_key).await? else {
        return Ok(None);
    };
    let legacy = parse_record(&data)?;
    let mut config = record_to_config(&legacy)?;
    config.client_secret = legacy
        .get("client_secret")
        .and_then(Value::as_str)
        .filter(|secret| !secret.is_empty())
        .map(String::from);
    let mut record = config_to_record(&config).await?;
    record[CLEANUP_MARKER] = Value::Bool(true);
    storage
        .store_kv(
            &format!("{RECORD_PREFIX}{client_id}"),
            record.to_string().as_bytes(),
            None,
        )
        .await?;
    finish_migration(storage, client_id, &mut record).await;
    Ok(Some(record))
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

        // Store the client in the storage backend, its secret as a hash
        let record = config_to_record(&config).await?;
        self.storage
            .store_kv(
                &format!("{RECORD_PREFIX}{}", config.client_id),
                record.to_string().as_bytes(),
                None,
            )
            .await?;

        Ok(config)
    }

    /// Retrieve a client by ID. The returned `client_secret` is always `None`: only a hash of
    /// it is stored (use [`authenticate_client`](Self::authenticate_client) to check a secret).
    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientConfig>> {
        match load_record(self.storage.as_ref(), client_id).await? {
            Some(record) => record_to_config(&record).map(Some),
            None => Ok(None),
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
        let record = config_to_record(&config).await?;
        self.storage
            .store_kv(
                &format!("{RECORD_PREFIX}{client_id}"),
                record.to_string().as_bytes(),
                None,
            )
            .await?;

        Ok(())
    }

    /// Delete a client
    pub async fn delete_client(&self, client_id: &str) -> Result<()> {
        self.storage
            .delete_kv(&format!("{RECORD_PREFIX}{client_id}"))
            .await?;
        self.storage
            .delete_kv(&format!("{LEGACY_RECORD_PREFIX}{client_id}"))
            .await?;
        Ok(())
    }

    /// Validate that a redirect URI is authorized for a client
    pub async fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client.redirect_uris.contains(redirect_uri))
        } else {
            Ok(false)
        }
    }

    /// Validate that a scope is authorized for a client
    pub async fn validate_scope(&self, client_id: &str, scope: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client.authorized_scopes.contains(scope))
        } else {
            Ok(false)
        }
    }

    /// Validate that a grant type is authorized for a client
    pub async fn validate_grant_type(&self, client_id: &str, grant_type: &str) -> Result<bool> {
        if let Some(client) = self.get_client(client_id).await? {
            Ok(client.authorized_grant_types.contains(grant_type))
        } else {
            Ok(false)
        }
    }

    /// Authenticate a confidential client using client credentials
    pub async fn authenticate_client(&self, client_id: &str, client_secret: &str) -> Result<bool> {
        let Some(record) = load_record(self.storage.as_ref(), client_id).await? else {
            return Ok(false);
        };
        if crate::client_secret::is_confidential(&record) {
            // The secret is checked against its stored hash.
            Ok(crate::client_secret::authenticate(
                self.storage.as_ref(),
                client_id,
                &record,
                client_secret,
            )
            .await)
        } else {
            // Public clients don't have secrets
            Ok(true)
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
            redirect_uris: vec!["https://example.com/callback".to_string()].into(),
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
            redirect_uris: vec![].into(),
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());

        // Test insecure redirect URI
        let invalid_config = ClientConfig {
            redirect_uris: vec!["http://example.com/callback".to_string()].into(),
            ..Default::default()
        };
        assert!(registry.register_client(invalid_config).await.is_err());
    }

    async fn raw(storage: &Arc<InMemoryStorage>, key: &str) -> Option<String> {
        storage
            .get_kv(key)
            .await
            .unwrap()
            .map(|data| String::from_utf8(data).unwrap())
    }

    #[tokio::test]
    async fn new_clients_are_stored_under_the_unified_key_with_a_hashed_secret() {
        let storage = Arc::new(InMemoryStorage::new());
        let registry = ClientRegistry::new(storage.clone()).await.unwrap();
        registry
            .register_client(ClientConfig {
                client_id: "unified".to_string(),
                client_type: ClientType::Confidential,
                client_secret: Some("plain-secret-value".to_string()),
                redirect_uris: vec!["https://example.com/callback".to_string()].into(),
                ..Default::default()
            })
            .await
            .unwrap();

        let stored = raw(&storage, "oauth2_client:unified").await.unwrap();
        assert!(stored.contains("client_secret_hash"), "{stored}");
        assert!(!stored.contains("plain-secret-value"), "{stored}");
        assert!(raw(&storage, "oauth_client:unified").await.is_none());

        let client = registry.get_client("unified").await.unwrap().unwrap();
        assert_eq!(client.client_type, ClientType::Confidential);
        assert!(
            client.client_secret.is_none(),
            "the secret is not recoverable"
        );
        assert!(
            registry
                .authenticate_client("unified", "plain-secret-value")
                .await
                .unwrap()
        );
        assert!(
            !registry
                .authenticate_client("unified", "wrong")
                .await
                .unwrap()
        );
    }

    /// A record this registry wrote under the old key (the whole `ClientConfig`, secret in plain
    /// text) is still found, and the first read moves it.
    #[tokio::test]
    async fn a_record_under_the_old_key_is_still_readable_and_moves_on_first_read() {
        let storage = Arc::new(InMemoryStorage::new());
        let old = ClientConfig {
            client_id: "legacy".to_string(),
            client_type: ClientType::Confidential,
            client_secret: Some("legacy-plain-secret".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()].into(),
            client_name: Some("Legacy app".to_string()),
            ..Default::default()
        };
        storage
            .store_kv(
                "oauth_client:legacy",
                serde_json::to_string(&old).unwrap().as_bytes(),
                None,
            )
            .await
            .unwrap();
        let registry = ClientRegistry::new(storage.clone()).await.unwrap();

        // Control: the old record really holds the plain secret before anything reads it.
        assert!(
            raw(&storage, "oauth_client:legacy")
                .await
                .unwrap()
                .contains("legacy-plain-secret")
        );

        let client = registry.get_client("legacy").await.unwrap().unwrap();
        assert_eq!(client.client_name.as_deref(), Some("Legacy app"));
        assert_eq!(client.client_type, ClientType::Confidential);
        assert!(
            client
                .redirect_uris
                .contains("https://example.com/callback")
        );

        assert!(
            raw(&storage, "oauth_client:legacy").await.is_none(),
            "old record removed"
        );
        let moved = raw(&storage, "oauth2_client:legacy").await.unwrap();
        assert!(moved.contains("client_secret_hash") && !moved.contains("legacy-plain-secret"));
        assert!(
            registry
                .authenticate_client("legacy", "legacy-plain-secret")
                .await
                .unwrap()
        );
        assert!(
            !registry
                .authenticate_client("legacy", "nope")
                .await
                .unwrap()
        );
    }

    /// A client registered through the HTTP API (its record shape) is visible to the registry.
    #[tokio::test]
    async fn a_record_written_by_the_http_api_is_readable() {
        let storage = Arc::new(InMemoryStorage::new());
        let hash = crate::client_secret::hash_secret("http-secret")
            .await
            .unwrap();
        storage
            .store_kv(
                "oauth2_client:http-app",
                serde_json::json!({
                    "client_id": "http-app",
                    "client_secret_hash": hash,
                    "client_name": "HTTP app",
                    "redirect_uris": ["https://example.com/cb"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "scope": "openid profile",
                })
                .to_string()
                .as_bytes(),
                None,
            )
            .await
            .unwrap();
        let registry = ClientRegistry::new(storage).await.unwrap();
        let client = registry.get_client("http-app").await.unwrap().unwrap();
        assert_eq!(client.client_type, ClientType::Confidential);
        assert!(client.authorized_scopes.contains("profile"));
        assert!(client.authorized_grant_types.contains("refresh_token"));
        assert!(
            registry
                .authenticate_client("http-app", "http-secret")
                .await
                .unwrap()
        );
        assert!(
            registry
                .validate_redirect_uri("http-app", "https://example.com/cb")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn deleting_a_client_removes_both_keys() {
        let storage = Arc::new(InMemoryStorage::new());
        for key in ["oauth2_client:gone", "oauth_client:gone"] {
            storage
                .store_kv(key, br#"{"client_id":"gone"}"#, None)
                .await
                .unwrap();
        }
        let registry = ClientRegistry::new(storage.clone()).await.unwrap();
        registry.delete_client("gone").await.unwrap();
        assert!(raw(&storage, "oauth2_client:gone").await.is_none());
        assert!(raw(&storage, "oauth_client:gone").await.is_none());
    }
}
