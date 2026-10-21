//! OAuth 2.0 client types — canonical definitions (RFC 6749 §2.1).
//!
//! [`ClientType`] and [`ClientConfig`] are the single source of truth for client
//! classification used throughout the OAuth 2.0/2.1 stack (domain layer, server
//! layer, and storage layer).  All other modules import these types rather than
//! defining their own copies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// OAuth 2.0 client classification (RFC 6749 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientType {
    /// Confidential clients can securely store their credentials (server-side apps).
    Confidential,
    /// Public clients cannot securely store credentials (SPAs, native apps).
    Public,
}

/// Full configuration record for a registered OAuth 2.0 client.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Unique client identifier
    pub client_id: String,
    /// Client secret — only present for `Confidential` clients
    pub client_secret: Option<String>,
    /// RFC 6749 §2.1 client classification
    pub client_type: ClientType,
    /// Authorised redirect URIs
    pub redirect_uris: crate::types::RedirectUris,
    /// Scopes this client is allowed to request
    pub authorized_scopes: crate::types::Scopes,
    /// Grant types this client is allowed to use
    pub authorized_grant_types: crate::types::GrantTypes,
    /// Response types this client is allowed to use
    pub authorized_response_types: crate::types::ResponseTypes,
    /// Human-readable display name
    pub client_name: Option<String>,
    /// Optional description
    pub client_description: Option<String>,
    /// Arbitrary metadata (e.g. logo_uri, tos_uri, contacts, …)
    pub metadata: HashMap<String, serde_json::Value>,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ClientConfig");
        d.field("client_id", &self.client_id);
        d.field(
            "client_secret",
            &crate::utils::redact::redacted(&self.client_secret),
        );
        d.field("client_type", &self.client_type);
        d.field("redirect_uris", &self.redirect_uris);
        d.field("authorized_scopes", &self.authorized_scopes);
        d.field("authorized_grant_types", &self.authorized_grant_types);
        d.field("authorized_response_types", &self.authorized_response_types);
        d.field("client_name", &self.client_name);
        d.field("client_description", &self.client_description);
        d.field("metadata", &self.metadata);
        d.finish()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client_id: Uuid::new_v4().to_string(),
            client_secret: None,
            client_type: ClientType::Public,
            redirect_uris: crate::types::RedirectUris::empty(),
            authorized_scopes: crate::types::Scopes::from(vec!["read".to_string()]),
            authorized_grant_types: crate::types::GrantTypes::from(vec![
                "authorization_code".to_string(),
            ]),
            authorized_response_types: crate::types::ResponseTypes::from(vec!["code".to_string()]),
            client_name: None,
            client_description: None,
            metadata: HashMap::new(),
        }
    }
}

/// Builder for creating `ClientConfig` instances with fluent API.
///
/// Reduces cognitive load when registering OAuth clients with many optional fields.
/// Required fields are set in `new()`, optional fields via builder methods.
///
/// # Example
///
/// ```rust
/// use auth_framework::client::{ClientConfig, ClientType};
/// use auth_framework::types::{RedirectUris, Scopes, GrantTypes, ResponseTypes};
///
/// let config = ClientConfig::builder("client123", ClientType::Confidential)
///     .client_secret("secret456")
///     .redirect_uris(RedirectUris::new(vec!["https://example.com/callback".to_string()]))
///     .authorized_scopes(Scopes::new(vec!["read".to_string(), "write".to_string()]))
///     .client_name("My App")
///     .build();
/// ```
#[derive(Clone)]
pub struct ClientConfigBuilder {
    client_id: String,
    client_secret: Option<String>,
    client_type: ClientType,
    redirect_uris: crate::types::RedirectUris,
    authorized_scopes: crate::types::Scopes,
    authorized_grant_types: crate::types::GrantTypes,
    authorized_response_types: crate::types::ResponseTypes,
    client_name: Option<String>,
    client_description: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
}

impl std::fmt::Debug for ClientConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ClientConfigBuilder");
        d.field("client_id", &self.client_id);
        d.field(
            "client_secret",
            &crate::utils::redact::redacted(&self.client_secret),
        );
        d.field("client_type", &self.client_type);
        d.field("redirect_uris", &self.redirect_uris);
        d.field("authorized_scopes", &self.authorized_scopes);
        d.field("authorized_grant_types", &self.authorized_grant_types);
        d.field("authorized_response_types", &self.authorized_response_types);
        d.field("client_name", &self.client_name);
        d.field("client_description", &self.client_description);
        d.field("metadata", &self.metadata);
        d.finish()
    }
}

impl ClientConfigBuilder {
    /// Create a new builder with required fields.
    ///
    /// Sets sensible defaults for optional fields:
    /// - `client_secret`: None
    /// - `redirect_uris`: empty
    /// - `authorized_scopes`: ["read"]
    /// - `authorized_grant_types`: ["authorization_code"]
    /// - `authorized_response_types`: ["code"]
    /// - `client_name`, `client_description`: None
    /// - `metadata`: empty
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let builder = ClientConfigBuilder::new("my-app", ClientType::Public);
    /// let config = builder.build();
    /// assert_eq!(config.client_id, "my-app");
    /// ```
    pub fn new(client_id: impl Into<String>, client_type: ClientType) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            client_type,
            redirect_uris: crate::types::RedirectUris::empty(),
            authorized_scopes: crate::types::Scopes::from(vec!["read".to_string()]),
            authorized_grant_types: crate::types::GrantTypes::from(vec![
                "authorization_code".to_string(),
            ]),
            authorized_response_types: crate::types::ResponseTypes::from(vec!["code".to_string()]),
            client_name: None,
            client_description: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the client secret.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Confidential)
    ///     .client_secret("s3cret")
    ///     .build();
    /// assert_eq!(config.client_secret.unwrap(), "s3cret");
    /// ```
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// Set the authorized redirect URIs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    /// use auth_framework::types::RedirectUris;
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .redirect_uris(RedirectUris::new(vec!["https://example.com/cb".into()]))
    ///     .build();
    /// ```
    pub fn redirect_uris(mut self, redirect_uris: crate::types::RedirectUris) -> Self {
        self.redirect_uris = redirect_uris;
        self
    }

    /// Set the authorized scopes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    /// use auth_framework::types::Scopes;
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .authorized_scopes(Scopes::new(vec!["read".into(), "write".into()]))
    ///     .build();
    /// ```
    pub fn authorized_scopes(mut self, authorized_scopes: crate::types::Scopes) -> Self {
        self.authorized_scopes = authorized_scopes;
        self
    }

    /// Set the authorized grant types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    /// use auth_framework::types::GrantTypes;
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Confidential)
    ///     .authorized_grant_types(GrantTypes::new(vec!["client_credentials".into()]))
    ///     .build();
    /// ```
    pub fn authorized_grant_types(
        mut self,
        authorized_grant_types: crate::types::GrantTypes,
    ) -> Self {
        self.authorized_grant_types = authorized_grant_types;
        self
    }

    /// Set the authorized response types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    /// use auth_framework::types::ResponseTypes;
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .authorized_response_types(ResponseTypes::new(vec!["code".into()]))
    ///     .build();
    /// ```
    pub fn authorized_response_types(
        mut self,
        authorized_response_types: crate::types::ResponseTypes,
    ) -> Self {
        self.authorized_response_types = authorized_response_types;
        self
    }

    /// Set the client name.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .client_name("My Application")
    ///     .build();
    /// assert_eq!(config.client_name.unwrap(), "My Application");
    /// ```
    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = Some(client_name.into());
        self
    }

    /// Set the client description.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .client_description("OAuth 2.0 demo app")
    ///     .build();
    /// assert_eq!(config.client_description.unwrap(), "OAuth 2.0 demo app");
    /// ```
    pub fn client_description(mut self, client_description: impl Into<String>) -> Self {
        self.client_description = Some(client_description.into());
        self
    }

    /// Set the metadata.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    /// use std::collections::HashMap;
    ///
    /// let mut meta = HashMap::new();
    /// meta.insert("logo_uri".into(), serde_json::json!("https://example.com/logo.png"));
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .metadata(meta)
    ///     .build();
    /// assert!(config.metadata.contains_key("logo_uri"));
    /// ```
    pub fn metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add a metadata key-value pair.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public)
    ///     .with_metadata("tos_uri", serde_json::json!("https://example.com/tos"))
    ///     .build();
    /// assert!(config.metadata.contains_key("tos_uri"));
    /// ```
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Build the `ClientConfig` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfigBuilder, ClientType};
    ///
    /// let config = ClientConfigBuilder::new("app", ClientType::Public).build();
    /// assert_eq!(config.client_id, "app");
    /// ```
    pub fn build(self) -> ClientConfig {
        ClientConfig {
            client_id: self.client_id,
            client_secret: self.client_secret,
            client_type: self.client_type,
            redirect_uris: self.redirect_uris,
            authorized_scopes: self.authorized_scopes,
            authorized_grant_types: self.authorized_grant_types,
            authorized_response_types: self.authorized_response_types,
            client_name: self.client_name,
            client_description: self.client_description,
            metadata: self.metadata,
        }
    }
}

impl ClientConfig {
    /// Start building a `ClientConfig` with fluent setters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::client::{ClientConfig, ClientType};
    ///
    /// let config = ClientConfig::builder("client123", ClientType::Public)
    ///     .client_name("My SPA")
    ///     .build();
    /// ```
    pub fn builder(client_id: impl Into<String>, client_type: ClientType) -> ClientConfigBuilder {
        ClientConfigBuilder::new(client_id, client_type)
    }
}
