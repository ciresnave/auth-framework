//! RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol
//!
//! This module implements the OAuth 2.0 Dynamic Client Registration Protocol
//! as defined in RFC 7591, allowing clients to dynamically register with
//! an authorization server.
//!
//! # Features
//!
//! - **Dynamic Client Registration**: Allow clients to register programmatically
//! - **Client Metadata Management**: Comprehensive client configuration support
//! - **Registration Validation**: Security controls for client registration
//! - **Client Credentials Management**: Automatic client secret generation
//! - **Update and Delete Operations**: Full client lifecycle management
//! - **Security Controls**: Rate limiting and validation for registration requests

use crate::errors::{AuthError, Result, StorageError};
use crate::storage::AuthStorage;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Duration, Utc};
use governor;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use url;
use uuid::Uuid;

/// Client registration request as defined in RFC 7591
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationRequest {
    /// Array of redirect URIs
    pub redirect_uris: Option<Vec<String>>,

    /// Token endpoint authentication method
    pub token_endpoint_auth_method: Option<String>,

    /// Grant types that the client will use
    pub grant_types: Option<Vec<String>>,

    /// Response types that the client will use
    pub response_types: Option<Vec<String>>,

    /// Human-readable name of the client
    pub client_name: Option<String>,

    /// URL of the home page of the client
    pub client_uri: Option<String>,

    /// URL of the logo for the client
    pub logo_uri: Option<String>,

    /// Array of scope values that the client will use
    pub scope: Option<String>,

    /// Array of contact information
    pub contacts: Option<Vec<String>>,

    /// URL of the terms of service
    pub tos_uri: Option<String>,

    /// URL of the privacy policy
    pub policy_uri: Option<String>,

    /// URL for the client's JSON Web Key Set
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set
    pub jwks: Option<Value>,

    /// Software identifier of the client
    pub software_id: Option<String>,

    /// Software version of the client
    pub software_version: Option<String>,

    /// Additional client metadata
    #[serde(flatten)]
    pub additional_metadata: HashMap<String, Value>,
}

/// Client registration response as defined in RFC 7591
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    /// OAuth 2.0 client identifier
    pub client_id: String,

    /// OAuth 2.0 client secret (optional)
    pub client_secret: Option<String>,

    /// Registration access token
    pub registration_access_token: String,

    /// Registration client URI
    pub registration_client_uri: String,

    /// Time at which the client identifier was issued
    pub client_id_issued_at: Option<i64>,

    /// Time at which the client secret will expire
    pub client_secret_expires_at: Option<i64>,

    /// Registered redirect URIs
    pub redirect_uris: Option<Vec<String>>,

    /// Token endpoint authentication method
    pub token_endpoint_auth_method: Option<String>,

    /// Grant types
    pub grant_types: Option<Vec<String>>,

    /// Response types
    pub response_types: Option<Vec<String>>,

    /// Client name
    pub client_name: Option<String>,

    /// Client URI
    pub client_uri: Option<String>,

    /// Logo URI
    pub logo_uri: Option<String>,

    /// Scope
    pub scope: Option<String>,

    /// Contacts
    pub contacts: Option<Vec<String>>,

    /// Terms of service URI
    pub tos_uri: Option<String>,

    /// Policy URI
    pub policy_uri: Option<String>,

    /// JWKS URI
    pub jwks_uri: Option<String>,

    /// JWKS
    pub jwks: Option<Value>,

    /// Software ID
    pub software_id: Option<String>,

    /// Software version
    pub software_version: Option<String>,

    /// Additional metadata
    #[serde(flatten)]
    pub additional_metadata: HashMap<String, Value>,
}

/// Registered client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    /// Client identifier
    pub client_id: String,

    /// Client secret (hashed)
    pub client_secret_hash: Option<String>,

    /// Registration access token (hashed)
    pub registration_access_token_hash: String,

    /// Client metadata
    pub metadata: ClientRegistrationRequest,

    /// Registration timestamp
    pub registered_at: DateTime<Utc>,

    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,

    /// Client secret expiration
    pub client_secret_expires_at: Option<DateTime<Utc>>,

    /// Whether the client is active
    pub is_active: bool,
}

/// Dynamic Client Registration Manager configuration
#[derive(Debug, Clone)]
pub struct ClientRegistrationConfig {
    /// Base URL for registration endpoints
    pub base_url: String,

    /// Whether to require authentication for registration
    pub require_authentication: bool,

    /// Default client secret expiration (seconds)
    pub default_secret_expiration: Option<i64>,

    /// Maximum number of redirect URIs per client
    pub max_redirect_uris: usize,

    /// Allowed grant types
    pub allowed_grant_types: Vec<String>,

    /// Allowed response types
    pub allowed_response_types: Vec<String>,

    /// Allowed authentication methods
    pub allowed_auth_methods: Vec<String>,

    /// Whether to allow public clients
    pub allow_public_clients: bool,

    /// Rate limiting configuration
    pub rate_limit_per_ip: u32,
    pub rate_limit_window: std::time::Duration,
}

impl Default for ClientRegistrationConfig {
    fn default() -> Self {
        Self {
            base_url: "https://auth.example.com".to_string(),
            require_authentication: false,
            default_secret_expiration: Some(86400 * 365), // 1 year
            max_redirect_uris: 10,
            allowed_grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            allowed_response_types: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
            ],
            allowed_auth_methods: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "private_key_jwt".to_string(),
                "none".to_string(),
            ],
            allow_public_clients: true,
            rate_limit_per_ip: 10,
            rate_limit_window: std::time::Duration::from_secs(3600),
        }
    }
}

/// Dynamic Client Registration Manager
pub struct ClientRegistrationManager {
    config: ClientRegistrationConfig,
    storage: Arc<dyn AuthStorage>,
    rate_limiter: Arc<
        governor::RateLimiter<
            governor::state::direct::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl ClientRegistrationManager {
    /// Create a new client registration manager
    pub fn new(config: ClientRegistrationConfig, storage: Arc<dyn AuthStorage>) -> Self {
        let quota =
            governor::Quota::per_hour(std::num::NonZeroU32::new(config.rate_limit_per_ip).unwrap());
        let rate_limiter = Arc::new(governor::RateLimiter::direct(quota));

        Self {
            config,
            storage,
            rate_limiter,
        }
    }

    /// Register a new client
    pub async fn register_client(
        &self,
        request: ClientRegistrationRequest,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<ClientRegistrationResponse> {
        // Rate limiting
        if let Some(_ip) = client_ip
            && self.rate_limiter.check().is_err()
        {
            return Err(AuthError::rate_limit(
                "Client registration rate limit exceeded",
            ));
        }

        // Validate the registration request
        self.validate_registration_request(&request)?;

        // Generate client credentials
        let client_id = self.generate_client_id();
        let (client_secret, client_secret_hash) = if self.requires_client_secret(&request) {
            let secret = self.generate_client_secret();
            let hash = self.hash_secret(&secret)?;
            (Some(secret), Some(hash))
        } else {
            (None, None)
        };

        // Generate registration access token
        let registration_access_token = self.generate_registration_access_token();
        let registration_access_token_hash = self.hash_secret(&registration_access_token)?;

        // Calculate expiration
        let client_secret_expires_at = if client_secret.is_some() {
            self.config
                .default_secret_expiration
                .map(|seconds| Utc::now() + Duration::seconds(seconds))
        } else {
            None
        };

        // Create registered client
        let registered_client = RegisteredClient {
            client_id: client_id.clone(),
            client_secret_hash,
            registration_access_token_hash,
            metadata: request.clone(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            client_secret_expires_at,
            is_active: true,
        };

        // Store the client
        self.store_client(&registered_client).await?;

        // Build response
        let response = ClientRegistrationResponse {
            client_id: client_id.clone(),
            client_secret,
            registration_access_token,
            registration_client_uri: format!("{}/register/{}", self.config.base_url, client_id),
            client_id_issued_at: Some(Utc::now().timestamp()),
            client_secret_expires_at: client_secret_expires_at.map(|dt| dt.timestamp()),
            redirect_uris: request.redirect_uris,
            token_endpoint_auth_method: request.token_endpoint_auth_method,
            grant_types: request.grant_types,
            response_types: request.response_types,
            client_name: request.client_name,
            client_uri: request.client_uri,
            logo_uri: request.logo_uri,
            scope: request.scope,
            contacts: request.contacts,
            tos_uri: request.tos_uri,
            policy_uri: request.policy_uri,
            jwks_uri: request.jwks_uri,
            jwks: request.jwks,
            software_id: request.software_id,
            software_version: request.software_version,
            additional_metadata: request.additional_metadata,
        };

        Ok(response)
    }

    /// Read client configuration
    pub async fn read_client(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<ClientRegistrationResponse> {
        let client = self.get_client(client_id).await?;

        // Verify registration access token
        if !self.verify_registration_token(&client, registration_access_token)? {
            return Err(AuthError::auth_method(
                "client_registration",
                "Invalid registration access token",
            ));
        }

        self.client_to_response(&client)
    }

    /// Update client configuration
    pub async fn update_client(
        &self,
        client_id: &str,
        registration_access_token: &str,
        request: ClientRegistrationRequest,
    ) -> Result<ClientRegistrationResponse> {
        let mut client = self.get_client(client_id).await?;

        // Verify registration access token
        if !self.verify_registration_token(&client, registration_access_token)? {
            return Err(AuthError::auth_method(
                "client_registration",
                "Invalid registration access token",
            ));
        }

        // Validate the update request
        self.validate_registration_request(&request)?;

        // Update client metadata
        client.metadata = request;
        client.updated_at = Utc::now();

        // Store updated client
        self.store_client(&client).await?;

        self.client_to_response(&client)
    }

    /// Delete client
    pub async fn delete_client(
        &self,
        client_id: &str,
        registration_access_token: &str,
    ) -> Result<()> {
        let client = self.get_client(client_id).await?;

        // Verify registration access token
        if !self.verify_registration_token(&client, registration_access_token)? {
            return Err(AuthError::auth_method(
                "client_registration",
                "Invalid registration access token",
            ));
        }

        // Mark client as inactive
        let key = format!("client_registration:{}", client_id);
        self.storage.delete_kv(&key).await?;

        Ok(())
    }

    /// Validate registration request
    fn validate_registration_request(&self, request: &ClientRegistrationRequest) -> Result<()> {
        // Validate redirect URIs
        if let Some(redirect_uris) = &request.redirect_uris {
            if redirect_uris.len() > self.config.max_redirect_uris {
                return Err(AuthError::auth_method(
                    "client_registration",
                    "Too many redirect URIs",
                ));
            }

            for uri in redirect_uris {
                if !self.is_valid_uri(uri) {
                    return Err(AuthError::auth_method(
                        "client_registration",
                        format!("Invalid redirect URI: {}", uri),
                    ));
                }
            }
        }

        // Validate grant types
        if let Some(grant_types) = &request.grant_types {
            for grant_type in grant_types {
                if !self.config.allowed_grant_types.contains(grant_type) {
                    return Err(AuthError::auth_method(
                        "client_registration",
                        format!("Unsupported grant type: {}", grant_type),
                    ));
                }
            }
        }

        // Validate response types
        if let Some(response_types) = &request.response_types {
            for response_type in response_types {
                if !self.config.allowed_response_types.contains(response_type) {
                    return Err(AuthError::auth_method(
                        "client_registration",
                        format!("Unsupported response type: {}", response_type),
                    ));
                }
            }
        }

        // Validate authentication method
        if let Some(auth_method) = &request.token_endpoint_auth_method
            && !self.config.allowed_auth_methods.contains(auth_method)
        {
            return Err(AuthError::auth_method(
                "client_registration",
                format!("Unsupported authentication method: {}", auth_method),
            ));
        }

        Ok(())
    }

    /// Check if client requires a secret
    fn requires_client_secret(&self, request: &ClientRegistrationRequest) -> bool {
        if !self.config.allow_public_clients {
            return true;
        }

        !matches!(request.token_endpoint_auth_method.as_deref(), Some("none"))
    }

    /// Generate client ID
    fn generate_client_id(&self) -> String {
        format!("client_{}", Uuid::new_v4().simple())
    }

    /// Generate client secret
    fn generate_client_secret(&self) -> String {
        use rand::RngCore;
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Generate registration access token
    fn generate_registration_access_token(&self) -> String {
        use rand::RngCore;
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash a secret
    fn hash_secret(&self, secret: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Verify registration access token
    fn verify_registration_token(&self, client: &RegisteredClient, token: &str) -> Result<bool> {
        let token_hash = self.hash_secret(token)?;
        Ok(client.registration_access_token_hash == token_hash)
    }

    /// Validate URI
    fn is_valid_uri(&self, uri: &str) -> bool {
        url::Url::parse(uri).is_ok()
    }

    /// Store client in storage
    async fn store_client(&self, client: &RegisteredClient) -> Result<()> {
        let key = format!("client_registration:{}", client.client_id);
        let value = serde_json::to_string(client)?;
        self.storage.store_kv(&key, value.as_bytes(), None).await?;
        Ok(())
    }

    /// Get client from storage
    async fn get_client(&self, client_id: &str) -> Result<RegisteredClient> {
        let key = format!("client_registration:{}", client_id);
        let value = match self.storage.get_kv(&key).await? {
            Some(value) => value,
            None => {
                return Err(AuthError::auth_method(
                    "client_registration",
                    "Client not found",
                ));
            }
        };
        let value_str = String::from_utf8(value).map_err(|e| {
            AuthError::Storage(StorageError::Serialization {
                message: format!("Invalid UTF-8 data: {}", e),
            })
        })?;
        let client: RegisteredClient = serde_json::from_str(&value_str)?;
        Ok(client)
    }

    /// Convert registered client to response
    fn client_to_response(&self, client: &RegisteredClient) -> Result<ClientRegistrationResponse> {
        Ok(ClientRegistrationResponse {
            client_id: client.client_id.clone(),
            client_secret: None, // Never return the actual secret
            registration_access_token: "***".to_string(), // Never return the actual token
            registration_client_uri: format!(
                "{}/register/{}",
                self.config.base_url, client.client_id
            ),
            client_id_issued_at: Some(client.registered_at.timestamp()),
            client_secret_expires_at: client.client_secret_expires_at.map(|dt| dt.timestamp()),
            redirect_uris: client.metadata.redirect_uris.clone(),
            token_endpoint_auth_method: client.metadata.token_endpoint_auth_method.clone(),
            grant_types: client.metadata.grant_types.clone(),
            response_types: client.metadata.response_types.clone(),
            client_name: client.metadata.client_name.clone(),
            client_uri: client.metadata.client_uri.clone(),
            logo_uri: client.metadata.logo_uri.clone(),
            scope: client.metadata.scope.clone(),
            contacts: client.metadata.contacts.clone(),
            tos_uri: client.metadata.tos_uri.clone(),
            policy_uri: client.metadata.policy_uri.clone(),
            jwks_uri: client.metadata.jwks_uri.clone(),
            jwks: client.metadata.jwks.clone(),
            software_id: client.metadata.software_id.clone(),
            software_version: client.metadata.software_version.clone(),
            additional_metadata: client.metadata.additional_metadata.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn test_client_registration() {
        let storage = Arc::new(MemoryStorage::new());
        let config = ClientRegistrationConfig::default();
        let manager = ClientRegistrationManager::new(config, storage);

        let request = ClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example.com/callback".to_string()]),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
            grant_types: Some(vec!["authorization_code".to_string()]),
            response_types: Some(vec!["code".to_string()]),
            client_name: Some("Test Client".to_string()),
            client_uri: Some("https://client.example.com".to_string()),
            logo_uri: Some("https://client.example.com/logo.png".to_string()),
            scope: Some("read write".to_string()),
            contacts: Some(vec!["admin@client.example.com".to_string()]),
            tos_uri: Some("https://client.example.com/tos".to_string()),
            policy_uri: Some("https://client.example.com/privacy".to_string()),
            jwks_uri: Some("https://client.example.com/jwks".to_string()),
            jwks: None,
            software_id: Some("test-client".to_string()),
            software_version: Some("1.0.0".to_string()),
            additional_metadata: HashMap::new(),
        };

        let response = manager
            .register_client(request.clone(), None)
            .await
            .unwrap();

        assert!(!response.client_id.is_empty());
        assert!(response.client_secret.is_some());
        assert!(!response.registration_access_token.is_empty());
        assert_eq!(response.client_name, Some("Test Client".to_string()));
        assert_eq!(
            response.redirect_uris,
            Some(vec!["https://client.example.com/callback".to_string()])
        );
    }

    #[tokio::test]
    async fn test_public_client_registration() {
        let storage = Arc::new(MemoryStorage::new());
        let config = ClientRegistrationConfig::default();
        let manager = ClientRegistrationManager::new(config, storage);

        let request = ClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example.com/callback".to_string()]),
            token_endpoint_auth_method: Some("none".to_string()),
            grant_types: Some(vec!["authorization_code".to_string()]),
            response_types: Some(vec!["code".to_string()]),
            client_name: Some("Public Client".to_string()),
            client_uri: None,
            logo_uri: None,
            scope: Some("read".to_string()),
            contacts: None,
            tos_uri: None,
            policy_uri: None,
            jwks_uri: None,
            jwks: None,
            software_id: None,
            software_version: None,
            additional_metadata: HashMap::new(),
        };

        let response = manager.register_client(request, None).await.unwrap();

        assert!(!response.client_id.is_empty());
        assert!(response.client_secret.is_none()); // Public client should not have secret
        assert!(!response.registration_access_token.is_empty());
        assert_eq!(response.client_name, Some("Public Client".to_string()));
    }
}
