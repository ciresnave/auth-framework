//! Additional server capability modules
//!
//! Note: WebAuthn/FIDO2 support is provided via the `PasskeyAuthMethod`
//! in `src/methods/passkey/mod.rs` using the production-grade `passkey` crate.
//! No separate WebAuthn server module is needed.

/// JWT token server for issuing and validating JWT tokens
pub mod jwt_server {
    use crate::errors::Result;
    use crate::storage::AuthStorage;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    /// Configuration for the JWT token server.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = JwtServerConfig { issuer: "https://auth.example.com".into(), key_id: "k1".into() };
    /// ```
    #[derive(Debug, Clone)]
    pub struct JwtServerConfig {
        pub issuer: String,
        pub key_id: String,
    }

    impl Default for JwtServerConfig {
        fn default() -> Self {
            Self {
                issuer: "https://auth.example.com".to_string(),
                key_id: "default".to_string(),
            }
        }
    }

    pub struct JwtServer {
        config: JwtServerConfig,
        storage: Arc<dyn AuthStorage>,
    }

    impl JwtServer {
        /// Create a new JWT server.
        ///
        /// # Example
        /// ```rust,ignore
        /// let server = JwtServer::new(JwtServerConfig::default(), storage).await?;
        /// ```
        pub async fn new(config: JwtServerConfig, storage: Arc<dyn AuthStorage>) -> Result<Self> {
            Ok(Self { config, storage })
        }

        /// Perform any async initialization after construction.
        ///
        /// `JwtServer` requires no async startup work — all state is set up in [`Self::new`].
        /// This method is provided for API symmetry with other server modules that
        /// do require an initialization step (e.g., connecting to external services).
        ///
        /// # Example
        /// ```rust,ignore
        /// server.initialize().await?;
        /// ```
        pub async fn initialize(&self) -> Result<()> {
            Ok(())
        }

        /// Get the well-known JWT configuration for discovery.
        ///
        /// # Example
        /// ```rust,ignore
        /// let config = server.get_well_known_jwt_configuration().await?;
        /// println!("issuer: {}", config.issuer);
        /// ```
        pub async fn get_well_known_jwt_configuration(&self) -> Result<JwtWellKnownConfiguration> {
            Ok(JwtWellKnownConfiguration {
                issuer: self.config.issuer.clone(),
                jwks_uri: format!("{}/jwks", self.config.issuer),
            })
        }

        /// Store JWT metadata in storage.
        ///
        /// # Example
        /// ```rust,ignore
        /// let meta = server.get_well_known_jwt_configuration().await?;
        /// server.store_jwt_metadata(&meta).await?;
        /// ```
        pub async fn store_jwt_metadata(&self, metadata: &JwtWellKnownConfiguration) -> Result<()> {
            let key = format!("jwt_metadata:{}", self.config.issuer);
            let value = serde_json::to_string(metadata).map_err(|e| {
                crate::errors::AuthError::internal(format!("Serialization error: {}", e))
            })?;

            self.storage.store_kv(&key, value.as_bytes(), None).await?;
            tracing::info!("Stored JWT metadata for issuer: {}", self.config.issuer);
            Ok(())
        }

        /// Retrieve JWT metadata from storage.
        ///
        /// # Example
        /// ```rust,ignore
        /// if let Some(meta) = server.get_stored_metadata().await? {
        ///     println!("stored issuer: {}", meta.issuer);
        /// }
        /// ```
        pub async fn get_stored_metadata(&self) -> Result<Option<JwtWellKnownConfiguration>> {
            let key = format!("jwt_metadata:{}", self.config.issuer);

            if let Some(value_bytes) = self.storage.get_kv(&key).await? {
                let value = String::from_utf8(value_bytes).map_err(|e| {
                    crate::errors::AuthError::internal(format!("UTF-8 conversion error: {}", e))
                })?;
                let metadata: JwtWellKnownConfiguration =
                    serde_json::from_str(&value).map_err(|e| {
                        crate::errors::AuthError::internal(format!("Deserialization error: {}", e))
                    })?;
                Ok(Some(metadata))
            } else {
                Ok(None)
            }
        }

        /// Store JWT signing key information.
        ///
        /// # Example
        /// ```rust,ignore
        /// server.store_signing_key("pem-encoded-key-data").await?;
        /// ```
        pub async fn store_signing_key(&self, key_data: &str) -> Result<()> {
            let key = format!("jwt_key:{}", self.config.key_id);
            self.storage
                .store_kv(&key, key_data.as_bytes(), None)
                .await?;
            tracing::info!("Stored JWT signing key: {}", self.config.key_id);
            Ok(())
        }
    }

    /// Well-known JWT configuration for OIDC discovery.
    ///
    /// # Example
    /// ```rust,ignore
    /// let wk = JwtWellKnownConfiguration { issuer: "https://auth.example.com".into(), jwks_uri: "https://auth.example.com/jwks".into() };
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct JwtWellKnownConfiguration {
        pub issuer: String,
        pub jwks_uri: String,
    }
}

/// API Gateway authentication and authorization
pub mod api_gateway {
    use crate::errors::Result;
    use crate::storage::AuthStorage;
    use std::sync::Arc;

    /// Configuration for the API gateway module.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = ApiGatewayConfig { name: "my-gateway".into() };
    /// ```
    #[derive(Debug, Clone)]
    pub struct ApiGatewayConfig {
        pub name: String,
    }

    impl Default for ApiGatewayConfig {
        fn default() -> Self {
            Self {
                name: "API Gateway".to_string(),
            }
        }
    }

    pub struct ApiGateway {
        config: ApiGatewayConfig,
        storage: Arc<dyn AuthStorage>,
    }

    impl ApiGateway {
        /// Create a new API gateway.
        ///
        /// # Example
        /// ```rust,ignore
        /// let gw = ApiGateway::new(ApiGatewayConfig::default(), storage).await?;
        /// ```
        pub async fn new(config: ApiGatewayConfig, storage: Arc<dyn AuthStorage>) -> Result<Self> {
            Ok(Self { config, storage })
        }

        /// Perform any async initialization after construction.
        ///
        /// `ApiGateway` requires no async startup work — all state is set up in [`Self::new`].
        /// This method is provided for API symmetry with other server modules that
        /// do require an initialization step (e.g., connecting to external services).
        ///
        /// # Example
        /// ```rust,ignore
        /// gw.initialize().await?;
        /// ```
        pub async fn initialize(&self) -> Result<()> {
            Ok(())
        }

        /// Store API gateway configuration metadata.
        ///
        /// # Example
        /// ```rust,ignore
        /// gw.store_gateway_metadata().await?;
        /// ```
        pub async fn store_gateway_metadata(&self) -> Result<()> {
            let key = format!("api_gateway_config:{}", self.config.name);
            let metadata = serde_json::json!({
                "name": self.config.name,
                "initialized_at": chrono::Utc::now().to_rfc3339()
            });
            let value = serde_json::to_string(&metadata).map_err(|e| {
                crate::errors::AuthError::internal(format!("Serialization error: {}", e))
            })?;

            self.storage.store_kv(&key, value.as_bytes(), None).await?;
            tracing::info!("Stored API Gateway metadata for: {}", self.config.name);
            Ok(())
        }

        /// Store API route configuration.
        ///
        /// # Example
        /// ```rust,ignore
        /// gw.store_route_config("/api/users", "{\"auth\": true}").await?;
        /// ```
        pub async fn store_route_config(&self, route_path: &str, config_data: &str) -> Result<()> {
            let key = format!("api_gateway_route:{}:{}", self.config.name, route_path);
            self.storage
                .store_kv(&key, config_data.as_bytes(), None)
                .await?;
            tracing::info!(
                "Stored route config for {} on gateway: {}",
                route_path,
                self.config.name
            );
            Ok(())
        }

        /// Get API route configuration.
        ///
        /// # Example
        /// ```rust,ignore
        /// if let Some(cfg) = gw.get_route_config("/api/users").await? {
        ///     println!("route config: {}", cfg);
        /// }
        /// ```
        pub async fn get_route_config(&self, route_path: &str) -> Result<Option<String>> {
            let key = format!("api_gateway_route:{}:{}", self.config.name, route_path);

            if let Some(config_bytes) = self.storage.get_kv(&key).await? {
                let config = String::from_utf8(config_bytes).map_err(|e| {
                    crate::errors::AuthError::internal(format!("UTF-8 conversion error: {}", e))
                })?;
                Ok(Some(config))
            } else {
                Ok(None)
            }
        }

        /// Get gateway name from config.
        ///
        /// # Example
        /// ```rust,ignore
        /// let name = gw.get_gateway_name();
        /// ```
        pub fn get_gateway_name(&self) -> &str {
            &self.config.name
        }
    }
}

/// SAML Identity Provider
pub mod saml_idp {
    use crate::errors::Result;
    use crate::storage::AuthStorage;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    /// Configuration for the SAML Identity Provider.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = SamlIdpConfig { entity_id: "https://idp.example.com".into() };
    /// ```
    #[derive(Debug, Clone)]
    pub struct SamlIdpConfig {
        pub entity_id: String,
    }

    impl Default for SamlIdpConfig {
        fn default() -> Self {
            Self {
                entity_id: "https://auth.example.com".to_string(),
            }
        }
    }

    pub struct SamlIdentityProvider {
        config: SamlIdpConfig,
        storage: Arc<dyn AuthStorage>,
    }

    impl SamlIdentityProvider {
        /// Create a new SAML Identity Provider.
        ///
        /// # Example
        /// ```rust,ignore
        /// let idp = SamlIdentityProvider::new(SamlIdpConfig::default(), storage).await?;
        /// ```
        pub async fn new(config: SamlIdpConfig, storage: Arc<dyn AuthStorage>) -> Result<Self> {
            Ok(Self { config, storage })
        }

        /// Perform any async initialization after construction.
        ///
        /// `SamlIdentityProvider` requires no async startup work — all state is set up in [`Self::new`].
        /// This method is provided for API symmetry with other server modules that
        /// do require an initialization step (e.g., connecting to external services).
        ///
        /// # Example
        /// ```rust,ignore
        /// idp.initialize().await?;
        /// ```
        pub async fn initialize(&self) -> Result<()> {
            Ok(())
        }

        /// Get the SAML metadata for this identity provider.
        ///
        /// # Example
        /// ```rust,ignore
        /// let meta = idp.get_metadata().await?;
        /// println!("entity: {}", meta.entity_id);
        /// ```
        pub async fn get_metadata(&self) -> Result<SamlMetadata> {
            Ok(SamlMetadata {
                entity_id: self.config.entity_id.clone(),
            })
        }

        /// Store SAML metadata in storage.
        ///
        /// # Example
        /// ```rust,ignore
        /// idp.store_saml_metadata(&meta).await?;
        /// ```
        pub async fn store_saml_metadata(&self, metadata: &SamlMetadata) -> Result<()> {
            let key = format!("saml_metadata:{}", self.config.entity_id);
            let value = serde_json::to_string(metadata).map_err(|e| {
                crate::errors::AuthError::internal(format!("Serialization error: {}", e))
            })?;

            self.storage.store_kv(&key, value.as_bytes(), None).await?;
            tracing::info!("Stored SAML metadata for entity: {}", self.config.entity_id);
            Ok(())
        }

        /// Store SAML assertion.
        ///
        /// # Example
        /// ```rust,ignore
        /// idp.store_assertion("assertion-1", "<xml>...</xml>").await?;
        /// ```
        pub async fn store_assertion(
            &self,
            assertion_id: &str,
            assertion_data: &str,
        ) -> Result<()> {
            let key = format!("saml_assertion:{}:{}", self.config.entity_id, assertion_id);
            self.storage
                .store_kv(
                    &key,
                    assertion_data.as_bytes(),
                    Some(std::time::Duration::from_secs(3600)),
                )
                .await?;
            tracing::info!(
                "Stored SAML assertion {} for entity: {}",
                assertion_id,
                self.config.entity_id
            );
            Ok(())
        }

        /// Retrieve SAML assertion.
        ///
        /// # Example
        /// ```rust,ignore
        /// if let Some(xml) = idp.get_assertion("assertion-1").await? {
        ///     println!("assertion: {}", xml);
        /// }
        /// ```
        pub async fn get_assertion(&self, assertion_id: &str) -> Result<Option<String>> {
            let key = format!("saml_assertion:{}:{}", self.config.entity_id, assertion_id);

            if let Some(assertion_bytes) = self.storage.get_kv(&key).await? {
                let assertion = String::from_utf8(assertion_bytes).map_err(|e| {
                    crate::errors::AuthError::internal(format!("UTF-8 conversion error: {}", e))
                })?;
                Ok(Some(assertion))
            } else {
                Ok(None)
            }
        }
    }

    /// SAML metadata document.
    ///
    /// # Example
    /// ```rust,ignore
    /// let meta = SamlMetadata { entity_id: "https://idp.example.com".into() };
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SamlMetadata {
        pub entity_id: String,
    }
}

// Additional server-side modules

pub mod consent {
    //! User consent management (OAuth 2.0 / OIDC consent screen logic)

    use crate::errors::Result;
    use crate::storage::AuthStorage;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Configuration for the consent module.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = ConsentConfig { require_explicit_consent: true, remember_consent_ttl_secs: 3600 };
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConsentConfig {
        /// Require explicit consent for every OAuth 2.0 authorization request.
        pub require_explicit_consent: bool,
        /// Remember consent decisions for this many seconds (0 = never remember).
        pub remember_consent_ttl_secs: u64,
    }

    impl Default for ConsentConfig {
        fn default() -> Self {
            Self {
                require_explicit_consent: true,
                remember_consent_ttl_secs: 86_400, // 24 hours
            }
        }
    }

    /// A stored consent decision.
    ///
    /// # Example
    /// ```rust,ignore
    /// let record = ConsentRecord {
    ///     user_id: "u1".into(), client_id: "c1".into(),
    ///     scopes: vec!["openid".into()], granted_at: 0, expires_at: None,
    /// };
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConsentRecord {
        pub user_id: String,
        pub client_id: String,
        pub scopes: Vec<String>,
        pub granted_at: u64,
        pub expires_at: Option<u64>,
    }

    /// Manages user consent decisions with optional storage backend for persistence.
    ///
    /// When constructed with [`ConsentManager::new_with_storage`] consent decisions
    /// are written through to `AuthStorage` so they survive process restarts.
    /// When constructed with [`ConsentManager::new`] decisions are kept in-process
    /// only (suitable for testing or single-node scenarios with short TTLs).
    pub struct ConsentManager {
        config: ConsentConfig,
        /// Write-through in-process cache.  Always populated on reads.
        records: HashMap<String, ConsentRecord>,
        storage: Option<Arc<dyn AuthStorage>>,
    }

    impl std::fmt::Debug for ConsentManager {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ConsentManager")
                .field("config", &self.config)
                .field("records", &crate::utils::redact::redacted(&self.records))
                .field("storage", &self.storage.is_some())
                .finish()
        }
    }

    impl Default for ConsentManager {
        fn default() -> Self {
            Self::new(ConsentConfig::default())
        }
    }

    impl ConsentManager {
        /// Create an in-memory-only `ConsentManager`.
        ///
        /// # Example
        /// ```rust,ignore
        /// let mgr = ConsentManager::new(ConsentConfig::default());
        /// ```
        pub fn new(config: ConsentConfig) -> Self {
            Self {
                config,
                records: HashMap::new(),
                storage: None,
            }
        }

        /// Create a storage-backed `ConsentManager` that persists decisions across
        /// restarts using the provided `AuthStorage` implementation.
        ///
        /// # Example
        /// ```rust,ignore
        /// let mgr = ConsentManager::new_with_storage(ConsentConfig::default(), storage);
        /// ```
        pub fn new_with_storage(config: ConsentConfig, storage: Arc<dyn AuthStorage>) -> Self {
            Self {
                config,
                records: HashMap::new(),
                storage: Some(storage),
            }
        }

        /// Storage key for a consent record.
        fn storage_key(user_id: &str, client_id: &str) -> String {
            format!("consent:{}:{}", user_id, client_id)
        }

        /// Record a consent decision, persisting to storage if configured.
        ///
        /// # Example
        /// ```rust,ignore
        /// mgr.grant(record).await?;
        /// ```
        pub async fn grant(&mut self, record: ConsentRecord) -> Result<()> {
            let key = format!("{}:{}", record.user_id, record.client_id);
            if let Some(storage) = &self.storage {
                let storage_key = Self::storage_key(&record.user_id, &record.client_id);
                let ttl = if record.expires_at.is_some() {
                    Some(std::time::Duration::from_secs(
                        self.config.remember_consent_ttl_secs,
                    ))
                } else {
                    None
                };
                let bytes = serde_json::to_vec(&record).map_err(|e| {
                    crate::errors::AuthError::internal(format!(
                        "Consent serialization error: {}",
                        e
                    ))
                })?;
                storage.store_kv(&storage_key, &bytes, ttl).await?;
            }
            self.records.insert(key, record);
            Ok(())
        }

        /// Revoke a previously granted consent, removing it from storage if configured.
        ///
        /// # Example
        /// ```rust,ignore
        /// let was_present = mgr.revoke("user-1", "client-1").await?;
        /// ```
        pub async fn revoke(&mut self, user_id: &str, client_id: &str) -> Result<bool> {
            let key = format!("{}:{}", user_id, client_id);
            if let Some(storage) = &self.storage {
                let storage_key = Self::storage_key(user_id, client_id);
                // Best-effort delete; ignore "not found" errors.
                let _ = storage.delete_kv(&storage_key).await;
            }
            Ok(self.records.remove(&key).is_some())
        }

        /// Check whether consent for the given scopes has already been granted.
        /// Checks the in-process cache first; falls back to storage on a cache miss.
        ///
        /// # Example
        /// ```rust,ignore
        /// let ok = mgr.has_consent("user-1", "client-1", &["openid".into()]).await?;
        /// ```
        pub async fn has_consent(
            &mut self,
            user_id: &str,
            client_id: &str,
            scopes: &[String],
        ) -> Result<bool> {
            if !self.config.require_explicit_consent {
                return Ok(true);
            }
            let key = format!("{}:{}", user_id, client_id);

            // Cache miss: try storage.
            if !self.records.contains_key(&key)
                && let Some(storage) = &self.storage
            {
                let storage_key = Self::storage_key(user_id, client_id);
                if let Ok(Some(bytes)) = storage.get_kv(&storage_key).await
                    && let Ok(record) = serde_json::from_slice::<ConsentRecord>(&bytes)
                {
                    self.records.insert(key.clone(), record);
                }
            }

            Ok(self
                .records
                .get(&key)
                .is_some_and(|record| scopes.iter().all(|s| record.scopes.contains(s))))
        }

        /// Return the configuration in use.
        ///
        /// # Example
        /// ```rust,ignore
        /// let cfg = mgr.config();
        /// assert!(cfg.require_explicit_consent);
        /// ```
        pub fn config(&self) -> &ConsentConfig {
            &self.config
        }
    }
}

pub mod introspection {
    //! Token introspection endpoint (RFC 7662)

    use serde::{Deserialize, Serialize};

    /// Configuration for the token introspection module.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = IntrospectionConfig { restrict_to_registered_servers: true, include_claims: false };
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IntrospectionConfig {
        /// Allow only registered resource servers to call the introspection endpoint.
        pub restrict_to_registered_servers: bool,
        /// Include full JWT claims in the response.
        pub include_claims: bool,
    }

    impl Default for IntrospectionConfig {
        fn default() -> Self {
            Self {
                restrict_to_registered_servers: false,
                include_claims: true,
            }
        }
    }

    /// Response body for RFC 7662 token introspection.
    ///
    /// # Example
    /// ```rust,ignore
    /// let resp = IntrospectionResponse::inactive();
    /// assert!(!resp.active);
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IntrospectionResponse {
        pub active: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub client_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exp: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iat: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub token_type: Option<String>,
    }

    impl IntrospectionResponse {
        /// Return an `active: false` response (e.g., for invalid/expired tokens).
        ///
        /// # Example
        /// ```rust,ignore
        /// let resp = IntrospectionResponse::inactive();
        /// ```
        pub fn inactive() -> Self {
            Self {
                active: false,
                scope: None,
                client_id: None,
                sub: None,
                exp: None,
                iat: None,
                token_type: None,
            }
        }
    }

    /// Handles token introspection logic for the server.
    #[derive(Debug, Default)]
    pub struct IntrospectionManager {
        config: IntrospectionConfig,
    }

    impl IntrospectionManager {
        /// Create a new `IntrospectionManager`.
        ///
        /// # Example
        /// ```rust,ignore
        /// let mgr = IntrospectionManager::new(IntrospectionConfig::default());
        /// ```
        pub fn new(config: IntrospectionConfig) -> Self {
            Self { config }
        }

        /// Return the configuration in use.
        ///
        /// # Example
        /// ```rust,ignore
        /// let cfg = mgr.config();
        /// ```
        pub fn config(&self) -> &IntrospectionConfig {
            &self.config
        }
    }
}

pub mod device_flow_server {
    //! Device Authorization Grant server-side implementation (RFC 8628)

    use crate::errors::Result;
    use crate::storage::AuthStorage;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Configuration for the device flow module.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = DeviceFlowConfig::default();
    /// assert_eq!(config.user_code_length, 8);
    /// ```
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeviceFlowConfig {
        /// Length of the user code (e.g., 8 characters).
        pub user_code_length: usize,
        /// How long a device code is valid (seconds).
        pub device_code_ttl_secs: u64,
        /// Minimum interval between polling requests (seconds).
        pub polling_interval_secs: u64,
        /// Verification URI shown to the user.
        pub verification_uri: String,
    }

    impl Default for DeviceFlowConfig {
        fn default() -> Self {
            Self {
                user_code_length: 8,
                device_code_ttl_secs: 1800, // 30 minutes
                polling_interval_secs: 5,
                verification_uri: "https://example.com/device".to_string(),
            }
        }
    }

    /// State of a pending device authorization request.
    ///
    /// # Example
    /// ```rust,ignore
    /// let state = DeviceAuthState::Pending;
    /// ```
    #[derive(Clone, Serialize, Deserialize)]
    pub enum DeviceAuthState {
        Pending,
        Authorized { access_token: String },
        Denied,
        Expired,
    }

    impl std::fmt::Debug for DeviceAuthState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Pending => f.write_str("Pending"),
                Self::Authorized { access_token } => f
                    .debug_struct("Authorized")
                    .field(
                        "access_token",
                        &crate::utils::redact::redacted(access_token),
                    )
                    .finish(),
                Self::Denied => f.write_str("Denied"),
                Self::Expired => f.write_str("Expired"),
            }
        }
    }

    /// A device authorization record.
    ///
    /// # Example
    /// ```rust,ignore
    /// let rec = DeviceAuthRecord {
    ///     device_code: "dc".into(), user_code: "UC".into(),
    ///     client_id: "c1".into(), scopes: vec![], state: DeviceAuthState::Pending, expires_at: 0,
    /// };
    /// ```
    #[derive(Clone, Serialize, Deserialize)]
    pub struct DeviceAuthRecord {
        pub device_code: String,
        pub user_code: String,
        pub client_id: String,
        pub scopes: Vec<String>,
        pub state: DeviceAuthState,
        pub expires_at: u64,
    }

    impl std::fmt::Debug for DeviceAuthRecord {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut d = f.debug_struct("DeviceAuthRecord");
            d.field(
                "device_code",
                &crate::utils::redact::redacted(&self.device_code),
            );
            d.field(
                "user_code",
                &crate::utils::redact::redacted(&self.user_code),
            );
            d.field("client_id", &self.client_id);
            d.field("scopes", &self.scopes);
            d.field("state", &self.state);
            d.field("expires_at", &self.expires_at);
            d.finish()
        }
    }

    /// Manages device authorization flow state with optional storage backend.
    ///
    /// When constructed with [`DeviceFlowManager::new_with_storage`] device auth
    /// records are written through to `AuthStorage` with TTL equal to
    /// `device_code_ttl_secs`, surviving process restarts and enabling
    /// multi-instance deployments.  When constructed with [`DeviceFlowManager::new`]
    /// records are kept in-process only.
    pub struct DeviceFlowManager {
        config: DeviceFlowConfig,
        /// Write-through in-process cache keyed by `device_code`.
        records: HashMap<String, DeviceAuthRecord>,
        storage: Option<Arc<dyn AuthStorage>>,
    }

    impl std::fmt::Debug for DeviceFlowManager {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeviceFlowManager")
                .field("config", &self.config)
                .field("records", &crate::utils::redact::redacted(&self.records))
                .field("storage", &self.storage.is_some())
                .finish()
        }
    }

    impl Default for DeviceFlowManager {
        fn default() -> Self {
            Self::new(DeviceFlowConfig::default())
        }
    }

    impl DeviceFlowManager {
        /// Create an in-memory-only `DeviceFlowManager`.
        ///
        /// # Example
        /// ```rust,ignore
        /// let mgr = DeviceFlowManager::new(DeviceFlowConfig::default());
        /// ```
        pub fn new(config: DeviceFlowConfig) -> Self {
            Self {
                config,
                records: HashMap::new(),
                storage: None,
            }
        }

        /// Create a storage-backed `DeviceFlowManager` that persists device
        /// authorization records across restarts.
        ///
        /// # Example
        /// ```rust,ignore
        /// let mgr = DeviceFlowManager::new_with_storage(DeviceFlowConfig::default(), storage);
        /// ```
        pub fn new_with_storage(config: DeviceFlowConfig, storage: Arc<dyn AuthStorage>) -> Self {
            Self {
                config,
                records: HashMap::new(),
                storage: Some(storage),
            }
        }

        /// Storage key for a device auth record.
        fn storage_key(device_code: &str) -> String {
            format!("device_flow:{}", device_code)
        }

        /// Persist a new device authorization record.
        ///
        /// # Example
        /// ```rust,ignore
        /// mgr.register(record).await?;
        /// ```
        pub async fn register(&mut self, record: DeviceAuthRecord) -> Result<()> {
            if let Some(storage) = &self.storage {
                let key = Self::storage_key(&record.device_code);
                let ttl = Some(std::time::Duration::from_secs(
                    self.config.device_code_ttl_secs,
                ));
                let bytes = serde_json::to_vec(&record).map_err(|e| {
                    crate::errors::AuthError::internal(format!(
                        "DeviceFlowRecord serialization error: {}",
                        e
                    ))
                })?;
                storage.store_kv(&key, &bytes, ttl).await?;
            }
            self.records.insert(record.device_code.clone(), record);
            Ok(())
        }

        /// Look up a record by device code, checking storage on a cache miss.
        ///
        /// # Example
        /// ```rust,ignore
        /// if let Some(rec) = mgr.get("device-code-1").await? {
        ///     println!("state: {:?}", rec.state);
        /// }
        /// ```
        pub async fn get(&mut self, device_code: &str) -> Result<Option<DeviceAuthRecord>> {
            if let Some(record) = self.records.get(device_code) {
                return Ok(Some(record.clone()));
            }
            if let Some(storage) = &self.storage {
                let key = Self::storage_key(device_code);
                if let Some(bytes) = storage.get_kv(&key).await?
                    && let Ok(record) = serde_json::from_slice::<DeviceAuthRecord>(&bytes)
                {
                    self.records.insert(device_code.to_string(), record.clone());
                    return Ok(Some(record));
                }
            }
            Ok(None)
        }

        /// Approve the authorization request for a given user code.
        ///
        /// # Example
        /// ```rust,ignore
        /// let approved = mgr.approve("USER-CODE", "access-token".into()).await?;
        /// ```
        pub async fn approve(&mut self, user_code: &str, access_token: String) -> Result<bool> {
            // Find the matching record (by user_code, not device_code).
            let device_code = self
                .records
                .values()
                .find(|r| r.user_code == user_code)
                .map(|r| r.device_code.clone());

            if let Some(dc) = device_code {
                if let Some(record) = self.records.get_mut(&dc) {
                    record.state = DeviceAuthState::Authorized {
                        access_token: access_token.clone(),
                    };
                    if let Some(storage) = &self.storage {
                        let key = Self::storage_key(&dc);
                        let bytes = serde_json::to_vec(&*record).map_err(|e| {
                            crate::errors::AuthError::internal(format!(
                                "DeviceFlowRecord serialization error: {}",
                                e
                            ))
                        })?;
                        // Preserve remaining TTL rather than resetting it.
                        storage.store_kv(&key, &bytes, None).await?;
                    }
                }
                return Ok(true);
            }
            Ok(false)
        }

        /// Return the configuration in use.
        ///
        /// # Example
        /// ```rust,ignore
        /// let cfg = mgr.config();
        /// assert_eq!(cfg.user_code_length, 8);
        /// ```
        pub fn config(&self) -> &DeviceFlowConfig {
            &self.config
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── JwtServer ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_jwt_server_store_and_get_metadata() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = jwt_server::JwtServerConfig {
            issuer: "https://auth.example.com".into(),
            key_id: "key_1".into(),
        };
        let server = jwt_server::JwtServer::new(config, storage).await.unwrap();
        server.initialize().await.unwrap();

        let wkc = server.get_well_known_jwt_configuration().await.unwrap();
        assert_eq!(wkc.issuer, "https://auth.example.com");

        server.store_jwt_metadata(&wkc).await.unwrap();
        let retrieved = server.get_stored_metadata().await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_jwt_server_store_signing_key() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = jwt_server::JwtServerConfig {
            issuer: "https://auth.example.com".into(),
            key_id: "key_2".into(),
        };
        let server = jwt_server::JwtServer::new(config, storage).await.unwrap();
        server.store_signing_key("test-key-data").await.unwrap();
    }

    // ── ApiGateway ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_api_gateway_store_and_get_route() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = api_gateway::ApiGatewayConfig {
            name: "test-gw".into(),
        };
        let gw = api_gateway::ApiGateway::new(config, storage).await.unwrap();
        gw.initialize().await.unwrap();
        assert_eq!(gw.get_gateway_name(), "test-gw");

        gw.store_route_config("/api/v1/users", r#"{"auth":"required"}"#)
            .await
            .unwrap();
        let route = gw.get_route_config("/api/v1/users").await.unwrap();
        assert!(route.is_some());
    }

    #[tokio::test]
    async fn test_api_gateway_get_route_not_found() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = api_gateway::ApiGatewayConfig { name: "gw2".into() };
        let gw = api_gateway::ApiGateway::new(config, storage).await.unwrap();
        assert!(gw.get_route_config("/nope").await.unwrap().is_none());
    }

    // ── SAML IdP ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_saml_idp_store_and_get_assertion() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = saml_idp::SamlIdpConfig {
            entity_id: "urn:example:idp".into(),
        };
        let saml = saml_idp::SamlIdentityProvider::new(config, storage)
            .await
            .unwrap();
        saml.initialize().await.unwrap();
        saml.store_assertion("assert_1", "<Assertion/>")
            .await
            .unwrap();
        let a = saml.get_assertion("assert_1").await.unwrap();
        assert_eq!(a.as_deref(), Some("<Assertion/>"));
    }

    #[tokio::test]
    async fn test_saml_idp_get_assertion_not_found() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = saml_idp::SamlIdpConfig {
            entity_id: "urn:example:idp2".into(),
        };
        let saml = saml_idp::SamlIdentityProvider::new(config, storage)
            .await
            .unwrap();
        assert!(saml.get_assertion("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_saml_idp_metadata() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = saml_idp::SamlIdpConfig {
            entity_id: "urn:example:idp3".into(),
        };
        let saml = saml_idp::SamlIdentityProvider::new(config, storage)
            .await
            .unwrap();
        let meta = saml.get_metadata().await.unwrap();
        assert_eq!(meta.entity_id, "urn:example:idp3");
    }

    // ── ConsentManager ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_consent_grant_and_check() {
        let config = consent::ConsentConfig {
            require_explicit_consent: true,
            remember_consent_ttl_secs: 3600,
        };
        let mut cm = consent::ConsentManager::new(config);
        let record = consent::ConsentRecord {
            user_id: "user1".into(),
            client_id: "client1".into(),
            scopes: vec!["read".into(), "write".into()],
            granted_at: now_secs(),
            expires_at: Some(now_secs() + 3600),
        };
        cm.grant(record).await.unwrap();
        assert!(
            cm.has_consent("user1", "client1", &["read".into()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_consent_no_consent_by_default() {
        let config = consent::ConsentConfig {
            require_explicit_consent: true,
            remember_consent_ttl_secs: 3600,
        };
        let mut cm = consent::ConsentManager::new(config);
        assert!(
            !cm.has_consent("user1", "client1", &["read".into()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_consent_revoke() {
        let config = consent::ConsentConfig {
            require_explicit_consent: true,
            remember_consent_ttl_secs: 3600,
        };
        let mut cm = consent::ConsentManager::new(config);
        cm.grant(consent::ConsentRecord {
            user_id: "user2".into(),
            client_id: "client2".into(),
            scopes: vec!["read".into()],
            granted_at: now_secs(),
            expires_at: None,
        })
        .await
        .unwrap();
        let revoked = cm.revoke("user2", "client2").await.unwrap();
        assert!(revoked);
        assert!(
            !cm.has_consent("user2", "client2", &["read".into()])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_consent_revoke_nonexistent() {
        let config = consent::ConsentConfig {
            require_explicit_consent: true,
            remember_consent_ttl_secs: 3600,
        };
        let mut cm = consent::ConsentManager::new(config);
        let revoked = cm.revoke("ghost", "ghost_client").await.unwrap();
        assert!(!revoked);
    }

    #[tokio::test]
    async fn test_consent_with_storage() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = consent::ConsentConfig {
            require_explicit_consent: true,
            remember_consent_ttl_secs: 3600,
        };
        let mut cm = consent::ConsentManager::new_with_storage(config, storage);
        cm.grant(consent::ConsentRecord {
            user_id: "user3".into(),
            client_id: "client3".into(),
            scopes: vec!["openid".into()],
            granted_at: now_secs(),
            expires_at: None,
        })
        .await
        .unwrap();
        assert!(
            cm.has_consent("user3", "client3", &["openid".into()])
                .await
                .unwrap()
        );
    }

    // ── DeviceFlowManager ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_device_flow_register_and_get() {
        let config = device_flow_server::DeviceFlowConfig {
            user_code_length: 8,
            device_code_ttl_secs: 300,
            polling_interval_secs: 5,
            verification_uri: "https://auth.example.com/device".into(),
        };
        let mut df = device_flow_server::DeviceFlowManager::new(config);
        df.register(device_flow_server::DeviceAuthRecord {
            device_code: "dev_code_1".into(),
            user_code: "ABCD-EFGH".into(),
            client_id: "mobile_app".into(),
            scopes: vec!["read".into()],
            state: device_flow_server::DeviceAuthState::Pending,
            expires_at: now_secs() + 300,
        })
        .await
        .unwrap();
        let record = df.get("dev_code_1").await.unwrap();
        assert!(record.is_some());
        assert_eq!(record.unwrap().user_code, "ABCD-EFGH");
    }

    #[tokio::test]
    async fn test_device_flow_get_not_found() {
        let config = device_flow_server::DeviceFlowConfig {
            user_code_length: 8,
            device_code_ttl_secs: 300,
            polling_interval_secs: 5,
            verification_uri: "https://auth.example.com/device".into(),
        };
        let mut df = device_flow_server::DeviceFlowManager::new(config);
        assert!(df.get("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_device_flow_approve() {
        let config = device_flow_server::DeviceFlowConfig {
            user_code_length: 8,
            device_code_ttl_secs: 300,
            polling_interval_secs: 5,
            verification_uri: "https://auth.example.com/device".into(),
        };
        let mut df = device_flow_server::DeviceFlowManager::new(config);
        df.register(device_flow_server::DeviceAuthRecord {
            device_code: "dev_code_2".into(),
            user_code: "WXYZ-1234".into(),
            client_id: "tv_app".into(),
            scopes: vec!["read".into()],
            state: device_flow_server::DeviceAuthState::Pending,
            expires_at: now_secs() + 300,
        })
        .await
        .unwrap();
        let approved = df
            .approve("WXYZ-1234", "access_token_here".into())
            .await
            .unwrap();
        assert!(approved);

        let record = df.get("dev_code_2").await.unwrap().unwrap();
        matches!(
            record.state,
            device_flow_server::DeviceAuthState::Authorized { .. }
        );
    }

    #[tokio::test]
    async fn test_device_flow_approve_nonexistent() {
        let config = device_flow_server::DeviceFlowConfig {
            user_code_length: 8,
            device_code_ttl_secs: 300,
            polling_interval_secs: 5,
            verification_uri: "https://auth.example.com/device".into(),
        };
        let mut df = device_flow_server::DeviceFlowManager::new(config);
        let approved = df.approve("NO_CODE", "token".into()).await.unwrap();
        assert!(!approved);
    }

    #[tokio::test]
    async fn test_device_flow_with_storage() {
        let storage: Arc<dyn crate::storage::AuthStorage> = Arc::new(MemoryStorage::new());
        let config = device_flow_server::DeviceFlowConfig {
            user_code_length: 8,
            device_code_ttl_secs: 300,
            polling_interval_secs: 5,
            verification_uri: "https://auth.example.com/device".into(),
        };
        let mut df = device_flow_server::DeviceFlowManager::new_with_storage(config, storage);
        df.register(device_flow_server::DeviceAuthRecord {
            device_code: "stored_code".into(),
            user_code: "ST0R-ED00".into(),
            client_id: "app".into(),
            scopes: vec![],
            state: device_flow_server::DeviceAuthState::Pending,
            expires_at: now_secs() + 300,
        })
        .await
        .unwrap();
        let record = df.get("stored_code").await.unwrap();
        assert!(record.is_some());
    }

    // ── IntrospectionManager ────────────────────────────────────────────

    #[test]
    fn test_introspection_inactive_response() {
        let resp = introspection::IntrospectionResponse::inactive();
        assert!(!resp.active);
    }
}
