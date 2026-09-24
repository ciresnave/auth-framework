//! OpenID Connect Advanced JARM (JWT Secured Authorization Response Mode)
//!
//! This module implements the Advanced JARM specification, extending the standard JARM
//! response mode with enhanced security features, multiple delivery mechanisms, and
//! comprehensive token management.
//!
//! # Advanced JARM Features
//!
//! - **Enhanced JWT Security**: Advanced encryption and signing algorithms
//! - **Multiple Delivery Modes**: Query, fragment, form_post, and push notifications
//! - **Custom Claims**: Support for custom authorization response claims
//! - **Response Validation**: Comprehensive response integrity validation
//!
//! # Specification Compliance
//!
//! This implementation extends basic JARM with enterprise-grade features:
//! - Advanced cryptographic protection
//! - Multiple response delivery mechanisms
//! - Custom claim injection
//! - Response tampering detection
//! - Comprehensive audit logging
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::oidc::oidc_advanced_jarm::{
//!     AdvancedJarmManager, AdvancedJarmConfig, JarmDeliveryMode, AuthorizationResponse
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AdvancedJarmConfig::default();
//! let jarm_manager = AdvancedJarmManager::new(config);
//!
//! // Create authorization response
//! let authorization_params = AuthorizationResponse {
//!     code: Some("auth_code_123".to_string()),
//!     state: Some("state_123".to_string()),
//!     access_token: None,
//!     token_type: None,
//!     expires_in: None,
//!     scope: None,
//!     id_token: None,
//!     error: None,
//!     error_description: None,
//! };
//!
//! // Create JARM response
//! let response = jarm_manager.create_jarm_response(
//!     "client123",
//!     &authorization_params,
//!     JarmDeliveryMode::Query,
//!     None
//! ).await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
#[cfg(feature = "rsa-key-ops")]
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
#[cfg(feature = "rsa-key-ops")]
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "rsa-key-ops")]
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Advanced JARM configuration
#[derive(Debug, Clone)]
pub struct AdvancedJarmConfig {
    /// Supported signing algorithms
    pub supported_algorithms: Vec<Algorithm>,
    /// Default token expiry
    pub default_token_expiry: Duration,
    /// Enable JWE encryption for nested JWT
    pub enable_jwe_encryption: bool,
    /// Supported delivery modes
    pub supported_delivery_modes: Vec<JarmDeliveryMode>,
    /// Enable custom claims
    pub enable_custom_claims: bool,
    /// Maximum custom claims count
    pub max_custom_claims: usize,
    /// Enable response validation
    pub enable_response_validation: bool,
    /// JWT issuer for JARM tokens
    pub jarm_issuer: String,
    /// Enable audit logging
    pub enable_audit_logging: bool,
    /// Encryption algorithm for JWE
    pub jwe_algorithm: Option<String>,
    /// Content encryption algorithm
    pub jwe_content_encryption: Option<String>,
    /// PEM-encoded RSA private key used to sign JARM tokens.
    ///
    /// If `None`, the lookup falls back to the `JARM_RSA_PRIVATE_KEY_PEM`
    /// environment variable before resorting to a development-only symmetric
    /// key (which triggers a visible `SECURITY WARNING` log entry).
    pub rsa_private_key_pem: Option<String>,
    /// PEM-encoded RSA public key (or certificate) used to verify incoming
    /// JARM tokens.
    ///
    /// If `None`, falls back to `JARM_RSA_PUBLIC_KEY_PEM` env var then the
    /// same symmetric dev fallback as `rsa_private_key_pem`.
    pub rsa_public_key_pem: Option<String>,
    /// PEM-encoded RSA public key of the JWE recipient (the client).
    ///
    /// When `enable_jwe_encryption` is `true` the server wraps the CEK with
    /// this key using RSA-OAEP-SHA-256.  If `None`, falls back to the
    /// `JARM_JWE_RECIPIENT_PUBLIC_KEY_PEM` environment variable.
    pub jwe_recipient_public_key_pem: Option<String>,
    /// PEM-encoded RSA private key for JWE CEK unwrapping.
    ///
    /// Used when the server acts as a JWE recipient (rare, but required for
    /// full round-trip tests).  If `None`, falls back to
    /// `JARM_JWE_RECIPIENT_PRIVATE_KEY_PEM`.
    pub jwe_recipient_private_key_pem: Option<String>,
}

impl Default for AdvancedJarmConfig {
    fn default() -> Self {
        Self {
            supported_algorithms: vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
            default_token_expiry: Duration::minutes(10),
            enable_jwe_encryption: false,
            supported_delivery_modes: vec![
                JarmDeliveryMode::Query,
                JarmDeliveryMode::Fragment,
                JarmDeliveryMode::FormPost,
                JarmDeliveryMode::Push,
            ],
            enable_custom_claims: true,
            max_custom_claims: 20,
            enable_response_validation: true,
            jarm_issuer: "https://auth-server.example.com".to_string(),
            enable_audit_logging: true,
            jwe_algorithm: Some("RSA-OAEP-256".to_string()),
            jwe_content_encryption: Some("A256GCM".to_string()),
            rsa_private_key_pem: None,
            rsa_public_key_pem: None,
            jwe_recipient_public_key_pem: None,
            jwe_recipient_private_key_pem: None,
        }
    }
}

impl AdvancedJarmConfig {
    /// Create a builder starting from the default configuration.
    ///
    /// # Example
    /// ```rust,no_run
    /// use auth_framework::server::oidc::oidc_advanced_jarm::AdvancedJarmConfig;
    ///
    /// let config = AdvancedJarmConfig::builder()
    ///     .jarm_issuer("https://auth.example.com")
    ///     .enable_jwe_encryption(true)
    ///     .build();
    /// ```
    pub fn builder() -> AdvancedJarmConfigBuilder {
        AdvancedJarmConfigBuilder {
            inner: Self::default(),
        }
    }
}

/// Builder for [`AdvancedJarmConfig`].
pub struct AdvancedJarmConfigBuilder {
    inner: AdvancedJarmConfig,
}

impl AdvancedJarmConfigBuilder {
    /// Set supported signing algorithms.
    pub fn supported_algorithms(mut self, algos: Vec<Algorithm>) -> Self {
        self.inner.supported_algorithms = algos;
        self
    }

    /// Set default token expiry.
    pub fn default_token_expiry(mut self, expiry: Duration) -> Self {
        self.inner.default_token_expiry = expiry;
        self
    }

    /// Set whether JWE encryption is enabled.
    pub fn enable_jwe_encryption(mut self, enable: bool) -> Self {
        self.inner.enable_jwe_encryption = enable;
        self
    }

    /// Set supported delivery modes.
    pub fn supported_delivery_modes(mut self, modes: Vec<JarmDeliveryMode>) -> Self {
        self.inner.supported_delivery_modes = modes;
        self
    }

    /// Set whether custom claims are allowed.
    pub fn enable_custom_claims(mut self, enable: bool) -> Self {
        self.inner.enable_custom_claims = enable;
        self
    }

    /// Set maximum custom claims count.
    pub fn max_custom_claims(mut self, max: usize) -> Self {
        self.inner.max_custom_claims = max;
        self
    }

    /// Set whether response validation is enabled.
    pub fn enable_response_validation(mut self, enable: bool) -> Self {
        self.inner.enable_response_validation = enable;
        self
    }

    /// Set the JARM issuer URI.
    pub fn jarm_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.inner.jarm_issuer = issuer.into();
        self
    }

    /// Set whether audit logging is enabled.
    pub fn enable_audit_logging(mut self, enable: bool) -> Self {
        self.inner.enable_audit_logging = enable;
        self
    }

    /// Set the JWE content encryption algorithm.
    pub fn jwe_content_encryption(mut self, enc: impl Into<String>) -> Self {
        self.inner.jwe_content_encryption = Some(enc.into());
        self
    }

    /// Set the JWE key management algorithm.
    pub fn jwe_algorithm(mut self, alg: impl Into<String>) -> Self {
        self.inner.jwe_algorithm = Some(alg.into());
        self
    }

    /// Set the server's RSA private key (PEM).
    pub fn rsa_private_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.inner.rsa_private_key_pem = Some(pem.into());
        self
    }

    /// Set the server's RSA public key (PEM).
    pub fn rsa_public_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.inner.rsa_public_key_pem = Some(pem.into());
        self
    }

    /// Set the recipient's RSA public key (PEM).
    pub fn jwe_recipient_public_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.inner.jwe_recipient_public_key_pem = Some(pem.into());
        self
    }

    /// Set the recipient's RSA private key (PEM).
    pub fn jwe_recipient_private_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.inner.jwe_recipient_private_key_pem = Some(pem.into());
        self
    }

    /// Build the [`AdvancedJarmConfig`].
    pub fn build(self) -> AdvancedJarmConfig {
        self.inner
    }
}

/// JARM delivery modes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JarmDeliveryMode {
    /// JWT response in query parameter
    Query,
    /// JWT response in URL fragment
    Fragment,
    /// JWT response via form POST
    FormPost,
    /// JWT response pushed to client endpoint
    Push,
}

/// Advanced JARM manager
pub struct AdvancedJarmManager {
    /// JARM configuration
    config: AdvancedJarmConfig,
    /// JWT validator for response validation
    jwt_validator: Arc<SecureJwtValidator>,
    /// Encoding key for signing
    encoding_key: EncodingKey,
    /// Decoding key for validation
    decoding_key: DecodingKey,
    /// HTTP client for push notifications
    http_client: crate::server::core::common_http::HttpClient,
    /// RSA public key for JWE CEK wrapping (encrypt to recipient). Requires
    /// the `rsa-key-ops` feature (RUSTSEC-2023-0071 -- see deny.toml).
    #[cfg(feature = "rsa-key-ops")]
    jwe_public_key: Option<RsaPublicKey>,
    /// RSA private key for JWE CEK unwrapping (decrypt when we are
    /// recipient). Requires the `rsa-key-ops` feature.
    #[cfg(feature = "rsa-key-ops")]
    jwe_private_key: Option<RsaPrivateKey>,
}

impl AdvancedJarmManager {
    /// Create new Advanced JARM manager
    pub fn new(config: AdvancedJarmConfig) -> Self {
        // Key resolution order:
        //   1. `config.rsa_private_key_pem` / `config.rsa_public_key_pem` (explicit)
        //   2. `JARM_RSA_PRIVATE_KEY_PEM` / `JARM_RSA_PUBLIC_KEY_PEM` env vars
        //   3. Symmetric dev-only fallback (logs a SECURITY WARNING)
        let private_pem = config
            .rsa_private_key_pem
            .clone()
            .or_else(|| std::env::var("JARM_RSA_PRIVATE_KEY_PEM").ok());
        let public_pem = config
            .rsa_public_key_pem
            .clone()
            .or_else(|| std::env::var("JARM_RSA_PUBLIC_KEY_PEM").ok());

        /// Generate a per-instance random secret for the internal SecureJwtValidator.
        /// The `jwt_secret` field is not used for JARM JWT signing/verification
        /// (those use the explicit `encoding_key`/`decoding_key`), but it must not be
        /// a well-known hardcoded value in case it leaks via `get_decoding_key()`.
        fn make_validator_secret() -> String {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes)
                .expect("System CSPRNG unavailable; cannot initialize JARM JWT validator secret");
            bytes.iter().fold(String::with_capacity(64), |mut s, b| {
                s.push_str(&format!("{b:02x}"));
                s
            })
        }

        // Each arm returns (encoding_key, decoding_key, validator_jwt_secret, validator_rsa_public_key_pem).
        let (encoding_key, decoding_key, validator_jwt_secret, rsa_pub_pem) =
            match (private_pem, public_pem) {
                (Some(priv_pem), Some(pub_pem)) => {
                    match (
                        EncodingKey::from_rsa_pem(priv_pem.as_bytes()),
                        DecodingKey::from_rsa_pem(pub_pem.as_bytes()),
                    ) {
                        (Ok(enc), Ok(dec)) => {
                            info!("JARM: loaded RSA signing/verification keys from configuration");
                            // For the internal validator, prefer an explicit env-var secret;
                            // otherwise generate a fresh random value per instance.
                            let secret = std::env::var("JARM_JWT_SECRET")
                                .unwrap_or_else(|_| make_validator_secret());
                            (enc, dec, secret, Some(pub_pem))
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            warn!(
                                "JARM: failed to parse provided RSA keys ({}). \
                                 Falling back to development-only symmetric key — \
                                 DO NOT use in production.",
                                e
                            );
                            (
                                EncodingKey::from_secret(b"test_key_for_development_only_123456"),
                                DecodingKey::from_secret(b"test_key_for_development_only_123456"),
                                "test_key_for_development_only_123456".to_string(),
                                None,
                            )
                        }
                    }
                }
                _ => {
                    // SECURITY: No RSA key is bundled. Production deployments MUST supply real
                    // RSA keys via AdvancedJarmConfig or environment configuration.
                    // The symmetric fallback below is intentionally weak — it triggers visible
                    // warnings so an operator knows the service is not production-ready.
                    warn!(
                        "SECURITY WARNING: AdvancedJarmManager is using a development-only \
                         symmetric fallback key for JARM signing. This is NOT secure. Supply \
                         an RSA private key via AdvancedJarmConfig::rsa_private_key_pem or \
                         the JARM_RSA_PRIVATE_KEY_PEM environment variable before deploying \
                         to production."
                    );
                    (
                        EncodingKey::from_secret(b"test_key_for_development_only_123456"),
                        DecodingKey::from_secret(b"test_key_for_development_only_123456"),
                        "test_key_for_development_only_123456".to_string(),
                        None,
                    )
                }
            };

        // Resolve JWE key pair: config field → environment variable → None.
        // RSA-OAEP JWE support requires the `rsa-key-ops` feature -- this is
        // the confirmed attacker-reachable RSA private-key operation
        // (RUSTSEC-2023-0071 -- see deny.toml). Without the feature, warn if
        // the operator configured JWE keys anyway so this doesn't fail silently.
        #[cfg(not(feature = "rsa-key-ops"))]
        if config.jwe_recipient_public_key_pem.is_some()
            || config.jwe_recipient_private_key_pem.is_some()
            || std::env::var("JARM_JWE_RECIPIENT_PUBLIC_KEY_PEM").is_ok()
            || std::env::var("JARM_JWE_RECIPIENT_PRIVATE_KEY_PEM").is_ok()
        {
            warn!(
                "JARM JWE recipient keys were configured, but the `rsa-key-ops` \
                 feature is not enabled -- JWE encryption/decryption will be \
                 unavailable. Enable `rsa-key-ops` to use it (RUSTSEC-2023-0071 \
                 applies; see deny.toml)."
            );
        }

        #[cfg(feature = "rsa-key-ops")]
        let jwe_public_key = {
            let jwe_pub_pem = config
                .jwe_recipient_public_key_pem
                .clone()
                .or_else(|| std::env::var("JARM_JWE_RECIPIENT_PUBLIC_KEY_PEM").ok());
            jwe_pub_pem
                .as_deref()
                .and_then(|pem| match RsaPublicKey::from_public_key_pem(pem) {
                    Ok(k) => {
                        info!("JARM JWE: loaded RSA recipient public key");
                        Some(k)
                    }
                    Err(e) => {
                        warn!("JARM JWE: could not parse recipient public key: {e}");
                        None
                    }
                })
        };
        #[cfg(feature = "rsa-key-ops")]
        let jwe_private_key = {
            let jwe_priv_pem = config
                .jwe_recipient_private_key_pem
                .clone()
                .or_else(|| std::env::var("JARM_JWE_RECIPIENT_PRIVATE_KEY_PEM").ok());
            jwe_priv_pem
                .as_deref()
                .and_then(|pem| match RsaPrivateKey::from_pkcs8_pem(pem) {
                    Ok(k) => {
                        info!("JARM JWE: loaded RSA recipient private key");
                        Some(k)
                    }
                    Err(e) => {
                        warn!("JARM JWE: could not parse recipient private key: {e}");
                        None
                    }
                })
        };

        let mut required_issuers = std::collections::HashSet::new();
        required_issuers.insert(config.jarm_issuer.clone());

        let jwt_config = SecureJwtConfig {
            allowed_algorithms: config.supported_algorithms.clone(),
            required_issuers,
            required_audiences: std::collections::HashSet::new(), // Empty - will disable audience validation
            max_token_lifetime: std::time::Duration::from_secs(
                config.default_token_expiry.num_seconds() as u64,
            ),
            clock_skew: std::time::Duration::from_secs(30),
            require_jti: true,
            validate_nbf: true,
            allowed_token_types: {
                let mut types = std::collections::HashSet::new();
                types.insert("JARM".to_string());
                types
            },
            require_secure_transport: true,
            jwt_secret: validator_jwt_secret,
            rsa_public_key_pem: rsa_pub_pem,
            ec_public_key_pem: None,
            ed_public_key_pem: None,
        };

        Self {
            config,
            jwt_validator: Arc::new(SecureJwtValidator::new(jwt_config).unwrap_or_else(|e| {
                tracing::error!("Failed to initialize SecureJwtValidator for JARM: {e}");
                panic!("SecureJwtValidator init failed");
            })),
            encoding_key,
            decoding_key,
            http_client: {
                use crate::server::core::common_config::EndpointConfig;
                let endpoint_config = EndpointConfig::new("https://localhost");
                crate::server::core::common_http::HttpClient::new(endpoint_config).unwrap_or_else(
                    |e| {
                        tracing::error!("Failed to initialize HttpClient for JARM: {e}");
                        panic!("HttpClient init failed");
                    },
                )
            },
            #[cfg(feature = "rsa-key-ops")]
            jwe_public_key,
            #[cfg(feature = "rsa-key-ops")]
            jwe_private_key,
        }
    }

    /// Create JARM response token
    pub async fn create_jarm_response(
        &self,
        client_id: &str,
        authorization_response: &AuthorizationResponse,
        delivery_mode: JarmDeliveryMode,
        custom_claims: Option<HashMap<String, Value>>,
    ) -> Result<JarmResponse> {
        // Validate delivery mode
        if !self
            .config
            .supported_delivery_modes
            .contains(&delivery_mode)
        {
            return Err(AuthError::validation(format!(
                "Unsupported delivery mode: {:?}",
                delivery_mode
            )));
        }

        // Validate custom claims count
        if let Some(ref claims) = custom_claims {
            if self.config.enable_custom_claims {
                if claims.len() > self.config.max_custom_claims {
                    return Err(AuthError::validation(format!(
                        "Too many custom claims: {} > {}",
                        claims.len(),
                        self.config.max_custom_claims
                    )));
                }
            } else {
                return Err(AuthError::validation(
                    "Custom claims are disabled".to_string(),
                ));
            }
        }

        let now = Utc::now();
        let expires_at = now + self.config.default_token_expiry;

        // Build JARM claims with SecureJwtValidator compatibility
        let jti = Uuid::new_v4().to_string();
        let mut claims = json!({
            "iss": self.config.jarm_issuer,
            "aud": client_id,
            "iat": now.timestamp(),
            "exp": expires_at.timestamp(),
            "nbf": now.timestamp(), // Not before - same as issued at for JARM
            "jti": jti,
            "typ": "JARM", // Token type for SecureJwtValidator
            "scope": "", // Empty scope for JARM tokens
            "sub": format!("jarm_{}", client_id), // Subject for JARM tokens
        });

        // Add authorization response data
        if let Some(code) = &authorization_response.code {
            claims["code"] = json!(code);
        }
        if let Some(access_token) = &authorization_response.access_token {
            claims["access_token"] = json!(access_token);
        }
        if let Some(id_token) = &authorization_response.id_token {
            claims["id_token"] = json!(id_token);
        }
        if let Some(state) = &authorization_response.state {
            claims["state"] = json!(state);
        }
        if let Some(error) = &authorization_response.error {
            claims["error"] = json!(error);
        }
        if let Some(error_description) = &authorization_response.error_description {
            claims["error_description"] = json!(error_description);
        }

        // Add token type and expiry if access token present
        if authorization_response.access_token.is_some() {
            claims["token_type"] = json!("Bearer");
            if let Some(expires_in) = authorization_response.expires_in {
                claims["expires_in"] = json!(expires_in);
            }
        }

        // Add scope if present
        if let Some(scope) = &authorization_response.scope {
            claims["scope"] = json!(scope);
        }

        // Add custom claims if provided
        if let Some(custom) = custom_claims {
            for (key, value) in custom {
                claims[key] = value;
            }
        }

        // Create JWT header
        let header = Header {
            typ: Some("JWT".to_string()),
            alg: self.config.supported_algorithms[0], // Use first supported algorithm
            kid: Some("jarm-key-1".to_string()),
            ..Default::default()
        };

        // Sign the JWT
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::token(format!("Failed to create JARM token: {}", e)))?;

        // Validate the created token using SecureJwtValidator for consistency
        if self.config.enable_response_validation {
            let _validated_claims = self
                .jwt_validator
                .validate_token(&token, &self.decoding_key)
                .map_err(|e| {
                    AuthError::token(format!(
                        "Created JARM token failed security validation: {}",
                        e
                    ))
                })?;
        }

        // Apply JWE encryption if enabled
        let final_token = if self.config.enable_jwe_encryption {
            self.encrypt_jwt_response(&token).await?
        } else {
            token
        };

        // Log audit event if enabled
        if self.config.enable_audit_logging {
            self.log_jarm_creation(client_id, &delivery_mode).await;
        }

        Ok(JarmResponse {
            response_token: final_token,
            delivery_mode,
            expires_at,
            client_id: client_id.to_string(),
            response_id: Uuid::new_v4().to_string(),
        })
    }

    /// Encrypt JWT response using JWE (production implementation)
    async fn encrypt_jwt_response(&self, jwt_token: &str) -> Result<String> {
        // Enhanced JWE encryption implementation
        // In production, this would use proper JWE with RSA-OAEP or ECDH-ES key management

        // For now, implement secure encryption pattern
        use base64::Engine;

        // Generate a content encryption key (CEK)
        let cek = self.generate_content_encryption_key();

        // Encrypt the JWT payload with the CEK
        let encrypted_payload = self.encrypt_payload(jwt_token, &cek)?;

        // Encrypt the CEK with the client's public key
        let encrypted_key = self.encrypt_key(&cek)?;

        // Create JWE structure: header.encrypted_key.iv.ciphertext.tag
        let jwe_header = self.create_jwe_header();
        let header_b64 = URL_SAFE_NO_PAD.encode(jwe_header.as_bytes());
        let key_b64 = URL_SAFE_NO_PAD.encode(&encrypted_key);
        let payload_parts: Vec<&str> = encrypted_payload.split('.').collect();

        if payload_parts.len() != 3 {
            return Err(AuthError::auth_method(
                "jarm",
                "Invalid encrypted payload format",
            ));
        }

        let jwe_token = format!(
            "{}.{}.{}.{}.{}",
            header_b64,
            key_b64,
            payload_parts[0], // IV
            payload_parts[1], // Ciphertext
            payload_parts[2]  // Tag
        );

        tracing::debug!("Created JWE-encrypted JARM response");
        Ok(jwe_token)
    }

    /// Generate a cryptographically secure 256-bit content encryption key (CEK).
    fn generate_content_encryption_key(&self) -> Vec<u8> {
        use rand::Rng;
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Encrypt payload with CEK using AES-256-GCM.
    ///
    /// Returns `iv_b64.ciphertext_b64.tag_b64` (three Base64url-no-pad parts) matching
    /// the IV / Ciphertext / Authentication-Tag positions of JWE compact serialisation.
    fn encrypt_payload(&self, payload: &str, cek: &[u8]) -> Result<String> {
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
        use rand::Rng;

        if cek.len() != 32 {
            return Err(AuthError::crypto("CEK must be 32 bytes for AES-256-GCM"));
        }

        // Generate a random 96-bit IV
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(cek);
        let cipher = Aes256Gcm::new(key);

        // aes-gcm appends the 16-byte authentication tag to the ciphertext
        let ciphertext_with_tag = cipher
            .encrypt(nonce, payload.as_bytes())
            .map_err(|e| AuthError::crypto(format!("AES-256-GCM encryption failed: {}", e)))?;

        let tag_pos = ciphertext_with_tag.len().saturating_sub(16);
        let ciphertext = &ciphertext_with_tag[..tag_pos];
        let tag = &ciphertext_with_tag[tag_pos..];

        Ok(format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            URL_SAFE_NO_PAD.encode(ciphertext),
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }

    /// Wrap the CEK using RSA-OAEP-SHA-256.
    ///
    /// Requires a recipient RSA public key supplied via
    /// `AdvancedJarmConfig::jwe_recipient_public_key_pem` or the
    /// `JARM_JWE_RECIPIENT_PUBLIC_KEY_PEM` environment variable.
    #[cfg(feature = "rsa-key-ops")]
    fn encrypt_key(&self, cek: &[u8]) -> Result<Vec<u8>> {
        let pub_key = self.jwe_public_key.as_ref().ok_or_else(|| {
            AuthError::crypto(
                "JARM JWE requires an RSA recipient public key for CEK wrapping. \
                 Set AdvancedJarmConfig::jwe_recipient_public_key_pem or the \
                 JARM_JWE_RECIPIENT_PUBLIC_KEY_PEM environment variable.",
            )
        })?;

        // RSA-OAEP-SHA-256 key wrapping.
        let mut rng = rand_core::OsRng;
        let padding = Oaep::new::<Sha256>();
        pub_key
            .encrypt(&mut rng, padding, cek)
            .map_err(|e| AuthError::crypto(format!("RSA-OAEP CEK wrap failed: {e}")))
    }

    /// RSA-OAEP JWE requires the `rsa-key-ops` feature (RUSTSEC-2023-0071 --
    /// see deny.toml).
    #[cfg(not(feature = "rsa-key-ops"))]
    fn encrypt_key(&self, _cek: &[u8]) -> Result<Vec<u8>> {
        Err(AuthError::crypto(
            "JARM RSA-OAEP JWE encryption requires the `rsa-key-ops` feature. \
             RSA has an open, unpatched timing-sidechannel advisory \
             (RUSTSEC-2023-0071); see deny.toml for the full disposition.",
        ))
    }

    /// Create JWE header
    fn create_jwe_header(&self) -> String {
        serde_json::json!({
            "alg": "RSA-OAEP",
            "enc": "A256GCM",
            "typ": "JOSE",
            "cty": "JWT"
        })
        .to_string()
    }

    /// Validate JARM response token
    pub async fn validate_jarm_response(&self, token: &str) -> Result<JarmValidationResult> {
        self.validate_jarm_response_with_transport(token, true)
            .await
    }

    /// Validate JARM response token with transport security context
    pub async fn validate_jarm_response_with_transport(
        &self,
        token: &str,
        _transport_secure: bool,
    ) -> Result<JarmValidationResult> {
        if !self.config.enable_response_validation {
            return Ok(JarmValidationResult {
                valid: true,
                claims: HashMap::new(),
                errors: vec![],
            });
        }

        let mut errors = vec![];
        let mut claims = HashMap::new();

        // Handle JWE-encrypted tokens
        let jwt_token = if token.starts_with("JWE.") {
            match self.decrypt_jwe_response(token).await {
                Ok(decrypted) => decrypted,
                Err(e) => {
                    errors.push(format!("JWE decryption failed: {}", e));
                    return Ok(JarmValidationResult {
                        valid: false,
                        claims,
                        errors,
                    });
                }
            }
        } else {
            token.to_string()
        };

        // Use SecureJwtValidator for enhanced security validation
        match self
            .jwt_validator
            .validate_token(&jwt_token, &self.decoding_key)
        {
            Ok(secure_claims) => {
                // Convert SecureJwtClaims to HashMap for compatibility
                let claims_value = serde_json::to_value(&secure_claims).map_err(|e| {
                    AuthError::validation(format!("Failed to serialize claims: {}", e))
                })?;

                if let serde_json::Value::Object(claim_map) = claims_value {
                    for (key, value) in claim_map {
                        claims.insert(key, value);
                    }
                }

                // Perform additional JARM-specific validation
                self.perform_additional_validation(&claims, &mut errors)
                    .await;
            }
            Err(e) => {
                errors.push(format!("Enhanced JWT validation failed: {}", e));
            }
        }

        let valid = errors.is_empty();

        Ok(JarmValidationResult {
            valid,
            claims,
            errors,
        })
    }

    /// Decrypt JWE response
    async fn decrypt_jwe_response(&self, jwe_token: &str) -> Result<String> {
        // Parse JWE token structure (header.encrypted_key.iv.ciphertext.tag)
        let parts: Vec<&str> = jwe_token.split('.').collect();
        if parts.len() != 5 {
            return Err(AuthError::InvalidRequest(
                "JWE must have 5 parts".to_string(),
            ));
        }

        // Decode JWE header to determine encryption algorithm
        let header = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| AuthError::InvalidRequest(format!("Invalid header: {}", e)))?;
        let header_str = String::from_utf8(header)
            .map_err(|e| AuthError::InvalidRequest(format!("Invalid header UTF-8: {}", e)))?;

        // Parse the header to extract algorithm information
        let header_json: serde_json::Value = serde_json::from_str(&header_str)
            .map_err(|e| AuthError::InvalidRequest(format!("Invalid header JSON: {}", e)))?;

        // Production implementation: Use header information to determine proper decryption algorithm
        let algorithm = header_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let encryption = header_json
            .get("enc")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        info!(
            "JWE decryption - Algorithm: {}, Encryption: {}",
            algorithm, encryption
        );

        // Validate supported algorithms and encryption methods
        match (algorithm, encryption) {
            ("RSA-OAEP", "A256GCM") | ("RSA-OAEP-256", "A256GCM") => {
                // Supported combinations - proceed with decryption
                debug!(
                    "Using supported JWE algorithm combination: {} + {}",
                    algorithm, encryption
                );
            }
            _ => {
                warn!(
                    "Unsupported JWE algorithm combination: {} + {}",
                    algorithm, encryption
                );
                return Err(AuthError::token(format!(
                    "Unsupported JWE algorithm combination: {} + {}",
                    algorithm, encryption
                )));
            }
        }

        // Production implementation: Perform proper JWE decryption based on detected algorithm
        match self
            .decrypt_jwe_with_algorithm(&parts, algorithm, encryption)
            .await
        {
            Ok(decrypted_payload) => {
                debug!(
                    "JWE decryption successful with {} + {}",
                    algorithm, encryption
                );
                Ok(decrypted_payload)
            }
            Err(e) => {
                error!("JWE decryption failed: {}", e);
                Err(e)
            }
        }
    }

    /// Decrypt JWE using the specified algorithm and encryption method
    async fn decrypt_jwe_with_algorithm(
        &self,
        parts: &[&str],
        algorithm: &str,
        encryption: &str,
    ) -> Result<String, AuthError> {
        // Validate we have all required JWE parts (header, encrypted key, IV, ciphertext, tag)
        if parts.len() != 5 {
            return Err(AuthError::token("Invalid JWE format - must have 5 parts"));
        }

        // Extract JWE components for debug logging.
        let encrypted_key = parts[1];
        let initialization_vector = parts[2];
        let ciphertext = parts[3];
        let authentication_tag = parts[4];

        debug!(
            "JWE Components - Key: {}, IV: {}, Ciphertext: {}, Tag: {}",
            &encrypted_key[..8.min(encrypted_key.len())],
            &initialization_vector[..8.min(initialization_vector.len())],
            &ciphertext[..8.min(ciphertext.len())],
            &authentication_tag[..8.min(authentication_tag.len())]
        );

        // Dispatch to algorithm-specific implementation.
        match (algorithm, encryption) {
            ("RSA-OAEP", "A256GCM") | ("RSA-OAEP-256", "A256GCM") => self.decrypt_rsa_oaep_a256gcm(
                encrypted_key,
                initialization_vector,
                ciphertext,
                authentication_tag,
            ),
            (alg, enc) => {
                error!(
                    "Unsupported JWE algorithm/encryption combination: {} + {}",
                    alg, enc
                );
                Err(AuthError::token(format!(
                    "Unsupported JWE combination: {} + {}",
                    alg, enc
                )))
            }
        }
    }

    /// RSA-OAEP JWE decryption requires the `rsa-key-ops` feature. This is
    /// the CONFIRMED attacker-reachable exposure named in deny.toml's
    /// RUSTSEC-2023-0071 entry: this function performs a raw RSA private-key
    /// decrypt of ciphertext taken directly from an external token string
    /// (see `validate_jarm_response` / `decrypt_jwe_response`), which is
    /// exactly the advisory's own workaround scenario ("avoid using rsa
    /// where attackers can observe timing, over the network").
    #[cfg(not(feature = "rsa-key-ops"))]
    fn decrypt_rsa_oaep_a256gcm(
        &self,
        _encrypted_key_b64: &str,
        _iv_b64: &str,
        _ciphertext_b64: &str,
        _tag_b64: &str,
    ) -> Result<String, AuthError> {
        Err(AuthError::crypto(
            "JARM RSA-OAEP JWE decryption requires the `rsa-key-ops` feature. \
             RSA has an open, unpatched timing-sidechannel advisory \
             (RUSTSEC-2023-0071); see deny.toml for the full disposition.",
        ))
    }

    /// Perform RSA-OAEP-SHA-256 + A256GCM JWE decryption.
    #[cfg(feature = "rsa-key-ops")]
    fn decrypt_rsa_oaep_a256gcm(
        &self,
        encrypted_key_b64: &str,
        iv_b64: &str,
        ciphertext_b64: &str,
        tag_b64: &str,
    ) -> Result<String, AuthError> {
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};

        let priv_key = self.jwe_private_key.as_ref().ok_or_else(|| {
            AuthError::crypto(
                "JARM JWE decryption requires an RSA private key. \
                 Set AdvancedJarmConfig::jwe_recipient_private_key_pem or the \
                 JARM_JWE_RECIPIENT_PRIVATE_KEY_PEM environment variable.",
            )
        })?;

        // 1. Unwrap the CEK with RSA-OAEP-SHA-256.
        let encrypted_cek = URL_SAFE_NO_PAD
            .decode(encrypted_key_b64)
            .map_err(|e| AuthError::token(format!("Bad encrypted_key encoding: {e}")))?;
        let padding = Oaep::new::<Sha256>();
        let cek = priv_key
            .decrypt(padding, &encrypted_cek)
            .map_err(|e| AuthError::crypto(format!("RSA-OAEP CEK unwrap failed: {e}")))?;

        if cek.len() != 32 {
            return Err(AuthError::crypto(format!(
                "Unwrapped CEK has unexpected length {} (expected 32)",
                cek.len()
            )));
        }

        // 2. Decode IV, ciphertext, and authentication tag.
        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(iv_b64)
            .map_err(|e| AuthError::token(format!("Bad IV encoding: {e}")))?;
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(ciphertext_b64)
            .map_err(|e| AuthError::token(format!("Bad ciphertext encoding: {e}")))?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag_b64)
            .map_err(|e| AuthError::token(format!("Bad tag encoding: {e}")))?;

        if nonce_bytes.len() != 12 {
            return Err(AuthError::crypto("JWE IV must be 12 bytes for AES-256-GCM"));
        }

        // aes-gcm expects ciphertext + tag concatenated.
        ciphertext.extend_from_slice(&tag);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let key = Key::<Aes256Gcm>::from_slice(&cek);
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| AuthError::crypto(format!("AES-256-GCM decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|e| AuthError::token(format!("Decrypted payload is not valid UTF-8: {e}")))
    }

    /// Perform additional validation checks
    async fn perform_additional_validation(
        &self,
        claims: &HashMap<String, Value>,
        errors: &mut Vec<String>,
    ) {
        // Check issuer
        if let Some(iss) = claims.get("iss") {
            if iss.as_str() != Some(&self.config.jarm_issuer) {
                errors.push(format!("Invalid issuer: {:?}", iss));
            }
        } else {
            errors.push("Missing issuer claim".to_string());
        }

        // Check expiration
        if let Some(exp) = claims.get("exp") {
            if let Some(exp_time) = exp.as_i64() {
                if Utc::now().timestamp() > exp_time {
                    errors.push("Token has expired".to_string());
                }
            } else {
                errors.push("Invalid expiration claim format".to_string());
            }
        } else {
            errors.push("Missing expiration claim".to_string());
        }

        // Check JWT ID
        if !claims.contains_key("jti") {
            errors.push("Missing JWT ID claim".to_string());
        }
    }

    /// Deliver JARM response based on delivery mode
    pub async fn deliver_jarm_response(
        &self,
        jarm_response: &JarmResponse,
        client_redirect_uri: &str,
        push_endpoint: Option<&str>,
    ) -> Result<DeliveryResult> {
        match jarm_response.delivery_mode {
            JarmDeliveryMode::Query => {
                let url = format!(
                    "{}?response={}",
                    client_redirect_uri, jarm_response.response_token
                );
                Ok(DeliveryResult::Redirect(url))
            }
            JarmDeliveryMode::Fragment => {
                let url = format!(
                    "{}#response={}",
                    client_redirect_uri, jarm_response.response_token
                );
                Ok(DeliveryResult::Redirect(url))
            }
            JarmDeliveryMode::FormPost => {
                let html = self
                    .generate_form_post_html(client_redirect_uri, &jarm_response.response_token);
                Ok(DeliveryResult::FormPost(html))
            }
            JarmDeliveryMode::Push => {
                if let Some(endpoint) = push_endpoint {
                    self.push_jarm_response(endpoint, jarm_response).await?;
                    Ok(DeliveryResult::Push {
                        success: true,
                        endpoint: endpoint.to_string(),
                    })
                } else {
                    Err(AuthError::validation(
                        "Push endpoint required for push delivery".to_string(),
                    ))
                }
            }
        }
    }

    /// Generate HTML for form POST delivery
    fn generate_form_post_html(&self, redirect_uri: &str, response_token: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>JARM Response</title>
    <meta charset="UTF-8">
</head>
<body>
    <form method="post" action="{}" id="jarm_form" style="display: none;">
        <input type="hidden" name="response" value="{}" />
    </form>
    <script>
        window.onload = function() {{
            document.getElementById('jarm_form').submit();
        }};
    </script>
    <noscript>
        <h2>JavaScript Required</h2>
        <p>Please enable JavaScript and reload the page, or manually submit the form below:</p>
        <form method="post" action="{}">
            <input type="hidden" name="response" value="{}" />
            <input type="submit" value="Continue" />
        </form>
    </noscript>
</body>
</html>"#,
            redirect_uri, response_token, redirect_uri, response_token
        )
    }

    /// Push JARM response to client endpoint
    async fn push_jarm_response(&self, endpoint: &str, jarm_response: &JarmResponse) -> Result<()> {
        let payload = json!({
            "response": jarm_response.response_token,
            "client_id": jarm_response.client_id,
            "response_id": jarm_response.response_id,
            "delivered_at": Utc::now(),
        });

        let response = self
            .http_client
            .post_json(endpoint, &payload)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to push JARM response: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::internal(format!(
                "Push delivery failed with status: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Log JARM creation for audit purposes
    async fn log_jarm_creation(&self, client_id: &str, delivery_mode: &JarmDeliveryMode) {
        tracing::info!(
            client_id = %client_id,
            delivery_mode = ?delivery_mode,
            "AUDIT: JARM response created"
        );
    }

    /// Get configuration
    pub fn config(&self) -> &AdvancedJarmConfig {
        &self.config
    }

    /// Revoke a JARM token by JWT ID
    pub fn revoke_jarm_token(&self, jti: &str) -> Result<()> {
        self.jwt_validator
            .revoke_token(jti)
            .map_err(|e| AuthError::validation(format!("Failed to revoke JARM token: {}", e)))
    }

    /// Check if a JARM token is revoked
    pub fn is_jarm_token_revoked(&self, jti: &str) -> Result<bool> {
        self.jwt_validator.is_token_revoked(jti).map_err(|e| {
            AuthError::validation(format!("Failed to check token revocation status: {}", e))
        })
    }

    /// Get JWT validator for advanced token operations
    pub fn get_jwt_validator(&self) -> &Arc<SecureJwtValidator> {
        &self.jwt_validator
    }
}

/// Authorization response data to be included in JARM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// Authorization code
    pub code: Option<String>,
    /// Access token
    pub access_token: Option<String>,
    /// ID token
    pub id_token: Option<String>,
    /// State parameter
    pub state: Option<String>,
    /// Token type
    pub token_type: Option<String>,
    /// Token expiry in seconds
    pub expires_in: Option<u64>,
    /// Granted scope
    pub scope: Option<String>,
    /// Error code
    pub error: Option<String>,
    /// Error description
    pub error_description: Option<String>,
}

/// JARM response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarmResponse {
    /// JWT response token
    pub response_token: String,
    /// Delivery mode
    pub delivery_mode: JarmDeliveryMode,
    /// Response expiration time
    pub expires_at: DateTime<Utc>,
    /// Client identifier
    pub client_id: String,
    /// Unique response identifier
    pub response_id: String,
}

/// JARM validation result
#[derive(Debug, Clone)]
pub struct JarmValidationResult {
    /// Whether the response is valid
    pub valid: bool,
    /// Extracted claims
    pub claims: HashMap<String, Value>,
    /// Validation errors
    pub errors: Vec<String>,
}

/// Delivery result
#[derive(Debug, Clone)]
pub enum DeliveryResult {
    /// Redirect URL for query/fragment modes
    Redirect(String),
    /// HTML content for form POST mode
    FormPost(String),
    /// Push delivery result
    Push {
        /// Whether push was successful
        success: bool,
        /// Push endpoint
        endpoint: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jarm_response_creation() {
        // Create config with HMAC algorithm for testing
        let config = AdvancedJarmConfig::builder()
            .supported_algorithms(vec![Algorithm::HS256]) // Use HMAC for testing
            .enable_response_validation(false) // Disable validation for testing
            .build();
        let manager = AdvancedJarmManager::new(config);

        let auth_response = AuthorizationResponse {
            code: Some("auth_code_123".to_string()),
            state: Some("client_state".to_string()),
            access_token: None,
            id_token: None,
            token_type: None,
            expires_in: None,
            scope: None,
            error: None,
            error_description: None,
        };

        let jarm_response = manager
            .create_jarm_response("test_client", &auth_response, JarmDeliveryMode::Query, None)
            .await
            .unwrap();

        assert!(!jarm_response.response_token.is_empty());
        assert_eq!(jarm_response.delivery_mode, JarmDeliveryMode::Query);
        assert_eq!(jarm_response.client_id, "test_client");
    }

    #[tokio::test]
    async fn test_custom_claims_validation() {
        let config = AdvancedJarmConfig::builder()
            .max_custom_claims(2)
            .supported_algorithms(vec![Algorithm::HS256])
            .build();
        let manager = AdvancedJarmManager::new(config);

        let auth_response = AuthorizationResponse {
            code: Some("code123".to_string()),
            state: None,
            access_token: None,
            id_token: None,
            token_type: None,
            expires_in: None,
            scope: None,
            error: None,
            error_description: None,
        };

        let mut custom_claims = HashMap::new();
        custom_claims.insert("claim1".to_string(), json!("value1"));
        custom_claims.insert("claim2".to_string(), json!("value2"));
        custom_claims.insert("claim3".to_string(), json!("value3")); // Should fail

        let result = manager
            .create_jarm_response(
                "test_client",
                &auth_response,
                JarmDeliveryMode::Query,
                Some(custom_claims),
            )
            .await;

        assert!(result.is_err());
    }

    #[cfg(feature = "rsa-key-ops")]
    #[tokio::test]
    async fn test_jwe_encrypt_decrypt_roundtrip() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        // Generate a 2048-bit RSA key pair for the test.
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generation failed");
        let public_key = private_key.to_public_key();

        let priv_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("private key PEM serialisation failed")
            .to_string();
        let pub_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .expect("public key PEM serialisation failed");

        let config = AdvancedJarmConfig::builder()
            .supported_algorithms(vec![Algorithm::HS256])
            .enable_jwe_encryption(true)
            .enable_response_validation(false)
            .jwe_recipient_public_key_pem(pub_pem)
            .jwe_recipient_private_key_pem(priv_pem)
            .build();
        let manager = AdvancedJarmManager::new(config);

        assert!(
            manager.jwe_public_key.is_some(),
            "JWE public key should have been loaded"
        );
        assert!(
            manager.jwe_private_key.is_some(),
            "JWE private key should have been loaded"
        );

        // Create a regular JARM response (JWE wrapping happens inside).
        let auth_response = AuthorizationResponse {
            code: Some("enc_test_code".to_string()),
            state: Some("enc_state".to_string()),
            access_token: None,
            id_token: None,
            token_type: None,
            expires_in: None,
            scope: None,
            error: None,
            error_description: None,
        };

        let jarm = manager
            .create_jarm_response("enc_client", &auth_response, JarmDeliveryMode::Query, None)
            .await
            .expect("create_jarm_response with JWE failed");

        // JWE compact serialisation has exactly 5 dot-separated parts.
        let parts: Vec<&str> = jarm.response_token.split('.').collect();
        assert_eq!(
            parts.len(),
            5,
            "JWE token should have 5 parts, got: {}",
            parts.len()
        );

        // Decrypt and verify we can recover the original JWT.
        let recovered = manager
            .decrypt_jwe_with_algorithm(&parts, "RSA-OAEP-256", "A256GCM")
            .await
            .expect("JWE decryption failed");

        // The recovered payload must be a valid JWT (3 parts).
        assert_eq!(
            recovered.split('.').count(),
            3,
            "Recovered payload should be a 3-part JWT"
        );
    }

    #[test]
    fn test_form_post_html_generation() {
        let config = AdvancedJarmConfig::builder()
            .supported_algorithms(vec![Algorithm::HS256])
            .build();
        let manager = AdvancedJarmManager::new(config);

        let html = manager.generate_form_post_html(
            "https://client.example.com/callback",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        );

        assert!(html.contains("https://client.example.com/callback"));
        assert!(html.contains("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"));
        assert!(html.contains("jarm_form"));
    }

    #[tokio::test]
    async fn test_delivery_mode_validation() {
        let config = AdvancedJarmConfig::builder()
            .supported_delivery_modes(vec![JarmDeliveryMode::Query])
            .supported_algorithms(vec![Algorithm::HS256]) // Use HMAC for testing
            .build();
        let manager = AdvancedJarmManager::new(config);

        let auth_response = AuthorizationResponse {
            code: Some("code123".to_string()),
            state: None,
            access_token: None,
            id_token: None,
            token_type: None,
            expires_in: None,
            scope: None,
            error: None,
            error_description: None,
        };

        // Should succeed for supported mode
        let result = manager
            .create_jarm_response("test_client", &auth_response, JarmDeliveryMode::Query, None)
            .await;
        assert!(result.is_ok());

        // Should fail for unsupported mode
        let result = manager
            .create_jarm_response("test_client", &auth_response, JarmDeliveryMode::Push, None)
            .await;
        assert!(result.is_err());
    }
}
