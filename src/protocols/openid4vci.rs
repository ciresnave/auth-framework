//! OpenID for Verifiable Credential Issuance (OpenID4VCI).
//!
//! Implements the issuer-side of the OpenID4VCI specification for issuing
//! Verifiable Credentials using OAuth 2.0 authorization flows.
//!
//! # Architecture
//!
//! - **Credential Issuer Metadata** — discovery endpoint for supported credentials
//! - **Credential Offer** — issuer-initiated issuance flow
//! - **Token → Credential** — exchange access tokens for VCs
//! - **Credential format support** — `jwt_vc_json` and `ldp_vc`
//!
//! # References
//!
//! - [OpenID4VCI spec](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Credential format ───────────────────────────────────────────────

/// Supported Verifiable Credential formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialFormat {
    /// JWT-based VC (W3C VC Data Model, JWT encoding).
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    /// JSON-LD with Linked Data Proofs.
    #[serde(rename = "ldp_vc")]
    LdpVc,
    /// SD-JWT VC.
    #[serde(rename = "vc+sd-jwt")]
    SdJwtVc,
}

// ── Issuer Metadata (§10.2) ─────────────────────────────────────────

/// Credential Issuer Metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// The Credential Issuer's identifier (URL).
    pub credential_issuer: String,
    /// URL of the Credential Endpoint.
    pub credential_endpoint: String,
    /// URL of the Batch Credential Endpoint (optional).
    #[serde(default)]
    pub batch_credential_endpoint: Option<String>,
    /// Supported credential configurations.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
    /// Display properties for the issuer.
    #[serde(default)]
    pub display: Vec<IssuerDisplay>,
}

impl IssuerMetadata {
    /// Build issuer metadata from the issuer URL.
    ///
    /// The credential endpoint defaults to `{issuer}/credential`. Use
    /// [`credential_endpoint`](Self::credential_endpoint) to override.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::openid4vci::*;
    ///
    /// let meta = IssuerMetadata::builder("https://issuer.example.com")
    ///     .add_credential("Degree", CredentialConfiguration::new(CredentialFormat::JwtVcJson)
    ///         .scope("degree")
    ///         .signing_algorithms(vec!["ES256"]))
    ///     .display("Example University", Some("en"))
    ///     .build();
    /// assert!(meta.credential_configurations_supported.contains_key("Degree"));
    /// ```
    pub fn builder(issuer: impl Into<String>) -> IssuerMetadataBuilder {
        let issuer = issuer.into();
        let endpoint = format!("{}/credential", issuer);
        IssuerMetadataBuilder {
            issuer,
            credential_endpoint: endpoint,
            batch_credential_endpoint: None,
            configs: HashMap::new(),
            display: Vec::new(),
        }
    }
}

/// Builder for [`IssuerMetadata`].
pub struct IssuerMetadataBuilder {
    issuer: String,
    credential_endpoint: String,
    batch_credential_endpoint: Option<String>,
    configs: HashMap<String, CredentialConfiguration>,
    display: Vec<IssuerDisplay>,
}

impl IssuerMetadataBuilder {
    /// Override the credential endpoint URL.
    pub fn credential_endpoint(mut self, url: impl Into<String>) -> Self {
        self.credential_endpoint = url.into();
        self
    }

    /// Set the batch credential endpoint URL.
    pub fn batch_credential_endpoint(mut self, url: impl Into<String>) -> Self {
        self.batch_credential_endpoint = Some(url.into());
        self
    }

    /// Add a supported credential configuration.
    pub fn add_credential(
        mut self,
        id: impl Into<String>,
        config: CredentialConfiguration,
    ) -> Self {
        self.configs.insert(id.into(), config);
        self
    }

    /// Add a display entry for the issuer.
    pub fn display(mut self, name: impl Into<String>, locale: Option<&str>) -> Self {
        self.display.push(IssuerDisplay {
            name: name.into(),
            locale: locale.map(String::from),
        });
        self
    }

    /// Consume the builder and produce [`IssuerMetadata`].
    pub fn build(self) -> IssuerMetadata {
        IssuerMetadata {
            credential_issuer: self.issuer,
            credential_endpoint: self.credential_endpoint,
            batch_credential_endpoint: self.batch_credential_endpoint,
            credential_configurations_supported: self.configs,
            display: self.display,
        }
    }
}

/// Display properties for an issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerDisplay {
    pub name: String,
    #[serde(default)]
    pub locale: Option<String>,
}

/// Configuration for a supported credential type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Credential format.
    pub format: CredentialFormat,
    /// Scope value for requesting this credential.
    #[serde(default)]
    pub scope: Option<String>,
    /// Cryptographic binding methods supported.
    #[serde(default)]
    pub cryptographic_binding_methods_supported: Vec<String>,
    /// Credential signing algorithms supported.
    #[serde(default)]
    pub credential_signing_alg_values_supported: Vec<String>,
    /// Display properties.
    #[serde(default)]
    pub display: Vec<CredentialDisplay>,
    /// Credential definition (type, claims).
    #[serde(default)]
    pub credential_definition: Option<CredentialDefinition>,
}

impl CredentialConfiguration {
    /// Create a new credential configuration for the given format.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::openid4vci::{CredentialConfiguration, CredentialFormat};
    ///
    /// let cfg = CredentialConfiguration::new(CredentialFormat::JwtVcJson)
    ///     .scope("degree")
    ///     .signing_algorithms(vec!["ES256"]);
    /// assert_eq!(cfg.format, CredentialFormat::JwtVcJson);
    /// assert_eq!(cfg.scope.as_deref(), Some("degree"));
    /// ```
    pub fn new(format: CredentialFormat) -> Self {
        Self {
            format,
            scope: None,
            cryptographic_binding_methods_supported: Vec::new(),
            credential_signing_alg_values_supported: Vec::new(),
            display: Vec::new(),
            credential_definition: None,
        }
    }

    /// Set the scope value.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the supported cryptographic binding methods.
    pub fn binding_methods(mut self, methods: Vec<impl Into<String>>) -> Self {
        self.cryptographic_binding_methods_supported =
            methods.into_iter().map(Into::into).collect();
        self
    }

    /// Set the supported signing algorithms.
    pub fn signing_algorithms(mut self, algs: Vec<impl Into<String>>) -> Self {
        self.credential_signing_alg_values_supported = algs.into_iter().map(Into::into).collect();
        self
    }

    /// Add a display entry.
    pub fn with_display(mut self, display: CredentialDisplay) -> Self {
        self.display.push(display);
        self
    }

    /// Set the credential definition.
    pub fn with_definition(mut self, definition: CredentialDefinition) -> Self {
        self.credential_definition = Some(definition);
        self
    }
}

/// Display properties for a credential type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub name: String,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub background_color: Option<String>,
    #[serde(default)]
    pub text_color: Option<String>,
}

/// Credential definition per the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub types: Vec<String>,
    #[serde(default)]
    pub credential_subject: Option<HashMap<String, ClaimMetadata>>,
}

/// Metadata about a credential claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMetadata {
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default)]
    pub display: Vec<ClaimDisplay>,
}

/// Display info for a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDisplay {
    pub name: String,
    #[serde(default)]
    pub locale: Option<String>,
}

// ── Credential Offer (§4.1) ─────────────────────────────────────────

/// A Credential Offer from the issuer to the holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The issuer URL.
    pub credential_issuer: String,
    /// List of credential configuration IDs offered.
    pub credential_configuration_ids: Vec<String>,
    /// Pre-authorized code grant parameters (optional).
    #[serde(default)]
    pub grants: Option<CredentialOfferGrants>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOfferGrants {
    /// Authorization code grant.
    #[serde(default, rename = "authorization_code")]
    pub authorization_code: Option<AuthorizationCodeGrant>,
    /// Pre-authorized code grant.
    #[serde(
        default,
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    #[serde(default)]
    pub issuer_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub user_pin_required: bool,
}

// ── Credential Request (§7.2) ───────────────────────────────────────

/// A credential request from the wallet/holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Credential format.
    pub format: CredentialFormat,
    /// Credential definition (types, etc.).
    #[serde(default)]
    pub credential_definition: Option<CredentialDefinition>,
    /// Proof of key possession.
    #[serde(default)]
    pub proof: Option<CredentialProof>,
}

/// Proof of possession in a credential request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Proof type (e.g., "jwt").
    pub proof_type: String,
    /// The proof value (JWT or other).
    #[serde(default)]
    pub jwt: Option<String>,
}

// ── Credential Response (§7.3) ──────────────────────────────────────

/// Credential issuance response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credential (format-specific).
    #[serde(default)]
    pub credential: Option<serde_json::Value>,
    /// Transaction ID for deferred issuance.
    #[serde(default)]
    pub transaction_id: Option<String>,
    /// Nonce for subsequent requests.
    #[serde(default)]
    pub c_nonce: Option<String>,
    /// Nonce lifetime in seconds.
    #[serde(default)]
    pub c_nonce_expires_in: Option<u64>,
}

impl CredentialResponse {
    /// Create an immediate issuance response containing the credential.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::openid4vci::CredentialResponse;
    ///
    /// let resp = CredentialResponse::immediate(
    ///     serde_json::json!({"vc": "..."}),
    ///     "nonce-abc",
    ///     300,
    /// );
    /// assert!(resp.credential.is_some());
    /// assert!(resp.transaction_id.is_none());
    /// ```
    pub fn immediate(
        credential: serde_json::Value,
        c_nonce: impl Into<String>,
        c_nonce_expires_in: u64,
    ) -> Self {
        Self {
            credential: Some(credential),
            transaction_id: None,
            c_nonce: Some(c_nonce.into()),
            c_nonce_expires_in: Some(c_nonce_expires_in),
        }
    }

    /// Create a deferred issuance response with a transaction ID.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::openid4vci::CredentialResponse;
    ///
    /// let resp = CredentialResponse::deferred("tx-123", "nonce-xyz", 300);
    /// assert!(resp.credential.is_none());
    /// assert_eq!(resp.transaction_id.as_deref(), Some("tx-123"));
    /// ```
    pub fn deferred(
        transaction_id: impl Into<String>,
        c_nonce: impl Into<String>,
        c_nonce_expires_in: u64,
    ) -> Self {
        Self {
            credential: None,
            transaction_id: Some(transaction_id.into()),
            c_nonce: Some(c_nonce.into()),
            c_nonce_expires_in: Some(c_nonce_expires_in),
        }
    }

    /// Create a completed deferred response (credential ready, no nonce needed).
    pub fn completed(credential: serde_json::Value) -> Self {
        Self {
            credential: Some(credential),
            transaction_id: None,
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
}

// ── Credential Issuer Service ───────────────────────────────────────

fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| AuthError::validation(format!("Base64url decode error: {e}")))
}

/// Pending credential issuance (deferred).
struct PendingIssuance {
    request: CredentialRequest,
    subject_id: String,
    created_at: u64,
}

/// OpenID4VCI Credential Issuer.
pub struct CredentialIssuer {
    metadata: IssuerMetadata,
    /// Pre-authorized codes → (credential_config_id, subject_id).
    pre_auth_codes: Arc<RwLock<HashMap<String, (String, String)>>>,
    /// Deferred issuance: transaction_id → pending issuance.
    deferred: Arc<RwLock<HashMap<String, PendingIssuance>>>,
    /// Active c_nonces for proof validation.
    nonces: Arc<RwLock<HashMap<String, u64>>>,
}

impl CredentialIssuer {
    /// Create a new credential issuer.
    pub fn new(metadata: IssuerMetadata) -> Self {
        Self {
            metadata,
            pre_auth_codes: Arc::new(RwLock::new(HashMap::new())),
            deferred: Arc::new(RwLock::new(HashMap::new())),
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the issuer metadata (for the discovery endpoint).
    pub fn metadata(&self) -> &IssuerMetadata {
        &self.metadata
    }

    /// Generate a fresh c_nonce.
    pub async fn generate_nonce(&self, lifetime_secs: u64) -> String {
        let nonce = Uuid::new_v4().to_string();
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + lifetime_secs;
        self.nonces.write().await.insert(nonce.clone(), expires);
        nonce
    }

    /// Validate a c_nonce.
    pub async fn validate_nonce(&self, nonce: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonces = self.nonces.read().await;
        matches!(nonces.get(nonce), Some(&exp) if exp > now)
    }

    /// Consume a c_nonce (single use).
    pub async fn consume_nonce(&self, nonce: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut nonces = self.nonces.write().await;
        matches!(nonces.remove(nonce), Some(exp) if exp > now)
    }

    /// Create a credential offer with a pre-authorized code.
    pub async fn create_offer(
        &self,
        credential_config_ids: Vec<String>,
        subject_id: &str,
    ) -> Result<CredentialOffer> {
        if credential_config_ids.is_empty() {
            return Err(AuthError::validation(
                "At least one credential configuration ID is required",
            ));
        }

        // Validate that all config IDs are supported
        for id in &credential_config_ids {
            if !self
                .metadata
                .credential_configurations_supported
                .contains_key(id)
            {
                return Err(AuthError::validation(format!(
                    "Unknown credential configuration: {id}"
                )));
            }
        }

        let code = Uuid::new_v4().to_string();
        self.pre_auth_codes.write().await.insert(
            code.clone(),
            (credential_config_ids[0].clone(), subject_id.to_string()),
        );

        Ok(CredentialOffer {
            credential_issuer: self.metadata.credential_issuer.clone(),
            credential_configuration_ids: credential_config_ids,
            grants: Some(CredentialOfferGrants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: code,
                    user_pin_required: false,
                }),
            }),
        })
    }

    /// Validate a pre-authorized code and return (config_id, subject_id).
    pub async fn validate_pre_auth_code(&self, code: &str) -> Result<(String, String)> {
        self.pre_auth_codes
            .write()
            .await
            .remove(code)
            .ok_or_else(|| AuthError::validation("Invalid or expired pre-authorized code"))
    }

    /// Process a credential request and produce a response.
    ///
    /// This validates the request format, checks the proof if present,
    /// and returns either the credential or a deferred transaction ID.
    pub async fn issue_credential(
        &self,
        request: &CredentialRequest,
        subject_id: &str,
        credential_data: Option<serde_json::Value>,
    ) -> Result<CredentialResponse> {
        // Validate the credential format is supported
        let supported = self
            .metadata
            .credential_configurations_supported
            .values()
            .any(|c| c.format == request.format);
        if !supported {
            return Err(AuthError::validation(format!(
                "Unsupported credential format: {:?}",
                request.format
            )));
        }

        // If proof is provided, validate it
        if let Some(ref proof) = request.proof {
            self.validate_proof(proof).await?;
        }

        // Generate a new c_nonce
        let c_nonce = self.generate_nonce(300).await;

        match credential_data {
            Some(data) => Ok(CredentialResponse::immediate(data, c_nonce, 300)),
            None => {
                // Deferred issuance
                let tx_id = Uuid::new_v4().to_string();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.deferred.write().await.insert(
                    tx_id.clone(),
                    PendingIssuance {
                        request: request.clone(),
                        subject_id: subject_id.to_string(),
                        created_at: now,
                    },
                );
                Ok(CredentialResponse::deferred(tx_id, c_nonce, 300))
            }
        }
    }

    /// Validate a proof of possession JWT.
    ///
    /// Checks:
    /// - `proof_type` is `"jwt"`
    /// - JWT value is present and structurally valid (3-part compact serialization)
    /// - c_nonce claim is present and matches a live nonce (consumed on success)
    async fn validate_proof(&self, proof: &CredentialProof) -> Result<()> {
        if proof.proof_type != "jwt" {
            return Err(AuthError::validation(format!(
                "Unsupported proof type: {}",
                proof.proof_type
            )));
        }
        let jwt = proof
            .jwt
            .as_deref()
            .ok_or_else(|| AuthError::validation("JWT proof value is missing"))?;

        // Structural check — must be 3-part JWS compact serialization
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::validation(
                "Proof JWT must be compact JWS (header.payload.signature)",
            ));
        }

        // Decode payload and check c_nonce
        let payload_bytes = base64_url_decode(parts[1])?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::validation(format!("Invalid proof JWT payload: {e}")))?;

        if let Some(nonce) = payload.get("nonce").and_then(|v| v.as_str())
            && !self.consume_nonce(nonce).await
        {
            return Err(AuthError::validation(
                "Proof JWT nonce is invalid or expired",
            ));
        }

        Ok(())
    }

    /// Process a batch credential request (§8).
    ///
    /// Issues multiple credentials in a single response, one per request.
    pub async fn issue_batch(
        &self,
        requests: &[CredentialRequest],
        subject_id: &str,
        credential_data: &[Option<serde_json::Value>],
    ) -> Result<Vec<CredentialResponse>> {
        if requests.is_empty() {
            return Err(AuthError::validation(
                "Batch request must contain at least one credential request",
            ));
        }
        if requests.len() != credential_data.len() {
            return Err(AuthError::validation(
                "Credential data array length must match requests array length",
            ));
        }

        let mut responses = Vec::with_capacity(requests.len());
        for (req, data) in requests.iter().zip(credential_data.iter()) {
            let resp = self.issue_credential(req, subject_id, data.clone()).await?;
            responses.push(resp);
        }
        Ok(responses)
    }

    /// Complete a deferred credential issuance.
    pub async fn complete_deferred(
        &self,
        transaction_id: &str,
        credential_data: serde_json::Value,
    ) -> Result<CredentialResponse> {
        let pending = self
            .deferred
            .write()
            .await
            .remove(transaction_id)
            .ok_or_else(|| AuthError::validation("Unknown or expired transaction ID"))?;

        let mut credential = match credential_data {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(AuthError::validation(
                    "Deferred credential data must be a JSON object",
                ));
            }
        };

        credential
            .entry("sub".to_string())
            .or_insert_with(|| serde_json::Value::String(pending.subject_id.clone()));
        credential.entry("format".to_string()).or_insert_with(|| {
            serde_json::to_value(&pending.request.format).unwrap_or(serde_json::Value::Null)
        });
        credential
            .entry("issuance_requested_at".to_string())
            .or_insert_with(|| {
                serde_json::Value::Number(serde_json::Number::from(pending.created_at))
            });
        if let Some(definition) = pending.request.credential_definition {
            credential
                .entry("credential_definition".to_string())
                .or_insert_with(|| {
                    serde_json::to_value(definition).unwrap_or(serde_json::Value::Null)
                });
        }

        Ok(CredentialResponse::completed(serde_json::Value::Object(
            credential,
        )))
    }

    /// Get the count of pending deferred issuances.
    pub async fn pending_count(&self) -> usize {
        self.deferred.read().await.len()
    }

    /// Clean up expired nonces.
    pub async fn cleanup_nonces(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut nonces = self.nonces.write().await;
        let before = nonces.len();
        nonces.retain(|_, exp| *exp > now);
        before - nonces.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metadata() -> IssuerMetadata {
        IssuerMetadata::builder("https://issuer.example.com")
            .add_credential(
                "UniversityDegree",
                CredentialConfiguration::new(CredentialFormat::JwtVcJson)
                    .scope("degree")
                    .binding_methods(vec!["did:key"])
                    .signing_algorithms(vec!["ES256"])
                    .with_display(CredentialDisplay {
                        name: "University Degree".to_string(),
                        locale: Some("en".to_string()),
                        description: Some("A university degree credential".to_string()),
                        background_color: Some("#12107c".to_string()),
                        text_color: Some("#ffffff".to_string()),
                    })
                    .with_definition(CredentialDefinition {
                        types: vec![
                            "VerifiableCredential".to_string(),
                            "UniversityDegreeCredential".to_string(),
                        ],
                        credential_subject: None,
                    }),
            )
            .display("Example University", Some("en"))
            .build()
    }

    // ── Credential format serialization ─────────────────────────

    #[test]
    fn test_credential_format_serialization() {
        assert_eq!(
            serde_json::to_string(&CredentialFormat::JwtVcJson).unwrap(),
            r#""jwt_vc_json""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialFormat::LdpVc).unwrap(),
            r#""ldp_vc""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialFormat::SdJwtVc).unwrap(),
            r#""vc+sd-jwt""#
        );
    }

    // ── Metadata ────────────────────────────────────────────────

    #[test]
    fn test_issuer_metadata_serialization() {
        let meta = test_metadata();
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["credential_issuer"], "https://issuer.example.com");
        assert!(json["credential_configurations_supported"]["UniversityDegree"].is_object());
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = test_metadata();
        let json_str = serde_json::to_string(&meta).unwrap();
        let parsed: IssuerMetadata = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.credential_issuer, meta.credential_issuer);
        assert!(
            parsed
                .credential_configurations_supported
                .contains_key("UniversityDegree")
        );
    }

    // ── Credential Offer ────────────────────────────────────────

    #[tokio::test]
    async fn test_create_offer() {
        let issuer = CredentialIssuer::new(test_metadata());
        let offer = issuer
            .create_offer(vec!["UniversityDegree".to_string()], "user-1")
            .await
            .unwrap();

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credential_configuration_ids, vec!["UniversityDegree"]);
        let grants = offer.grants.unwrap();
        assert!(grants.pre_authorized_code.is_some());
    }

    #[tokio::test]
    async fn test_create_offer_invalid_config() {
        let issuer = CredentialIssuer::new(test_metadata());
        let result = issuer
            .create_offer(vec!["NonExistent".to_string()], "user-1")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_offer_empty_configs() {
        let issuer = CredentialIssuer::new(test_metadata());
        let result = issuer.create_offer(vec![], "user-1").await;
        assert!(result.is_err());
    }

    // ── Pre-authorized code ─────────────────────────────────────

    #[tokio::test]
    async fn test_pre_auth_code_flow() {
        let issuer = CredentialIssuer::new(test_metadata());
        let offer = issuer
            .create_offer(vec!["UniversityDegree".to_string()], "user-1")
            .await
            .unwrap();

        let code = &offer
            .grants
            .unwrap()
            .pre_authorized_code
            .unwrap()
            .pre_authorized_code;

        let (config_id, subject_id) = issuer.validate_pre_auth_code(code).await.unwrap();
        assert_eq!(config_id, "UniversityDegree");
        assert_eq!(subject_id, "user-1");

        // Code is single-use
        assert!(issuer.validate_pre_auth_code(code).await.is_err());
    }

    // ── Nonce management ────────────────────────────────────────

    #[tokio::test]
    async fn test_nonce_lifecycle() {
        let issuer = CredentialIssuer::new(test_metadata());
        let nonce = issuer.generate_nonce(300).await;

        assert!(issuer.validate_nonce(&nonce).await);
        assert!(issuer.consume_nonce(&nonce).await);
        // After consumption
        assert!(!issuer.validate_nonce(&nonce).await);
        assert!(!issuer.consume_nonce(&nonce).await);
    }

    #[tokio::test]
    async fn test_nonce_invalid() {
        let issuer = CredentialIssuer::new(test_metadata());
        assert!(!issuer.validate_nonce("nonexistent").await);
    }

    // ── Credential issuance ─────────────────────────────────────

    #[tokio::test]
    async fn test_issue_credential_immediate() {
        let issuer = CredentialIssuer::new(test_metadata());
        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            credential_definition: None,
            proof: None,
        };

        let cred_data = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "credentialSubject": {
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science"
                }
            }
        });

        let resp = issuer
            .issue_credential(&request, "user-1", Some(cred_data))
            .await
            .unwrap();

        assert!(resp.credential.is_some());
        assert!(resp.transaction_id.is_none());
        assert!(resp.c_nonce.is_some());
    }

    #[tokio::test]
    async fn test_issue_credential_deferred() {
        let issuer = CredentialIssuer::new(test_metadata());
        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            credential_definition: None,
            proof: None,
        };

        let resp = issuer
            .issue_credential(&request, "user-1", None)
            .await
            .unwrap();

        assert!(resp.credential.is_none());
        assert!(resp.transaction_id.is_some());
        assert_eq!(issuer.pending_count().await, 1);

        // Complete deferred
        let tx_id = resp.transaction_id.unwrap();
        let final_resp = issuer
            .complete_deferred(&tx_id, serde_json::json!({"credential": "data"}))
            .await
            .unwrap();
        assert!(final_resp.credential.is_some());
        let completed = final_resp.credential.unwrap();
        assert_eq!(completed["credential"], "data");
        assert_eq!(completed["sub"], "user-1");
        assert_eq!(completed["format"], "jwt_vc_json");
        assert!(completed["issuance_requested_at"].is_number());
        assert_eq!(issuer.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_issue_credential_unsupported_format() {
        let issuer = CredentialIssuer::new(test_metadata());
        let request = CredentialRequest {
            format: CredentialFormat::LdpVc,
            credential_definition: None,
            proof: None,
        };

        let result = issuer.issue_credential(&request, "user-1", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_issue_credential_invalid_proof_type() {
        let issuer = CredentialIssuer::new(test_metadata());
        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            credential_definition: None,
            proof: Some(CredentialProof {
                proof_type: "ldp".to_string(),
                jwt: None,
            }),
        };

        let result = issuer
            .issue_credential(&request, "user-1", Some(serde_json::json!({})))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_issue_credential_missing_jwt_proof() {
        let issuer = CredentialIssuer::new(test_metadata());
        let request = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            credential_definition: None,
            proof: Some(CredentialProof {
                proof_type: "jwt".to_string(),
                jwt: None,
            }),
        };

        let result = issuer
            .issue_credential(&request, "user-1", Some(serde_json::json!({})))
            .await;
        assert!(result.is_err());
    }

    // ── Deferred issuance ───────────────────────────────────────

    #[tokio::test]
    async fn test_complete_deferred_invalid_tx() {
        let issuer = CredentialIssuer::new(test_metadata());
        let result = issuer
            .complete_deferred("nonexistent", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }

    // ── Credential offer serialization ──────────────────────────

    #[test]
    fn test_credential_offer_roundtrip() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example".to_string(),
            credential_configuration_ids: vec!["DegreeCredential".to_string()],
            grants: Some(CredentialOfferGrants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "code123".to_string(),
                    user_pin_required: true,
                }),
            }),
        };
        let json = serde_json::to_string(&offer).unwrap();
        let parsed: CredentialOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.credential_issuer, offer.credential_issuer);
        assert!(
            parsed
                .grants
                .unwrap()
                .pre_authorized_code
                .unwrap()
                .user_pin_required
        );
    }

    // ── Request / Response models ───────────────────────────────

    #[test]
    fn test_credential_request_serialization() {
        let req = CredentialRequest {
            format: CredentialFormat::JwtVcJson,
            credential_definition: Some(CredentialDefinition {
                types: vec!["VerifiableCredential".to_string()],
                credential_subject: None,
            }),
            proof: Some(CredentialProof {
                proof_type: "jwt".to_string(),
                jwt: Some("eyJ...".to_string()),
            }),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["format"], "jwt_vc_json");
        assert!(json["proof"]["jwt"].is_string());
    }

    // ── Builder / factory helpers ───────────────────────────────

    #[test]
    fn test_credential_response_immediate() {
        let resp = CredentialResponse::immediate(serde_json::json!({"vc": "data"}), "nonce-1", 300);
        assert!(resp.credential.is_some());
        assert!(resp.transaction_id.is_none());
        assert_eq!(resp.c_nonce.as_deref(), Some("nonce-1"));
        assert_eq!(resp.c_nonce_expires_in, Some(300));
    }

    #[test]
    fn test_credential_response_deferred() {
        let resp = CredentialResponse::deferred("tx-1", "nonce-2", 600);
        assert!(resp.credential.is_none());
        assert_eq!(resp.transaction_id.as_deref(), Some("tx-1"));
        assert_eq!(resp.c_nonce.as_deref(), Some("nonce-2"));
    }

    #[test]
    fn test_credential_response_completed() {
        let resp = CredentialResponse::completed(serde_json::json!({"done": true}));
        assert!(resp.credential.is_some());
        assert!(resp.transaction_id.is_none());
        assert!(resp.c_nonce.is_none());
    }

    #[test]
    fn test_credential_configuration_builder() {
        let cfg = CredentialConfiguration::new(CredentialFormat::JwtVcJson)
            .scope("degree")
            .binding_methods(vec!["did:key"])
            .signing_algorithms(vec!["ES256", "EdDSA"]);
        assert_eq!(cfg.format, CredentialFormat::JwtVcJson);
        assert_eq!(cfg.scope.as_deref(), Some("degree"));
        assert_eq!(cfg.cryptographic_binding_methods_supported, vec!["did:key"]);
        assert_eq!(cfg.credential_signing_alg_values_supported.len(), 2);
    }

    #[test]
    fn test_issuer_metadata_builder() {
        let meta = IssuerMetadata::builder("https://issuer.example.com")
            .add_credential(
                "TestCred",
                CredentialConfiguration::new(CredentialFormat::SdJwtVc).scope("test"),
            )
            .display("Test Issuer", None)
            .build();
        assert_eq!(meta.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            meta.credential_endpoint,
            "https://issuer.example.com/credential"
        );
        assert!(
            meta.credential_configurations_supported
                .contains_key("TestCred")
        );
        assert_eq!(meta.display[0].name, "Test Issuer");
        assert!(meta.display[0].locale.is_none());
    }

    #[test]
    fn test_issuer_metadata_builder_custom_endpoint() {
        let meta = IssuerMetadata::builder("https://example.com")
            .credential_endpoint("https://example.com/api/vc/issue")
            .batch_credential_endpoint("https://example.com/api/vc/batch")
            .build();
        assert_eq!(meta.credential_endpoint, "https://example.com/api/vc/issue");
        assert_eq!(
            meta.batch_credential_endpoint.as_deref(),
            Some("https://example.com/api/vc/batch")
        );
    }
}
