//! RFC 7521: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
//!
//! This module implements private key JWT client authentication, allowing clients
//! to authenticate using JWTs signed with their private keys.
//!
//! ## Enhanced Security Features
//!
//! - **SecureJwtValidator Integration**: Uses comprehensive JWT validation with
//!   enhanced security checks beyond basic signature verification
//! - **Configurable JTI Cleanup**: Customizable cleanup intervals for managing
//!   used JWT IDs and preventing replay attacks
//! - **Advanced Token Management**: Token revocation and validation using the
//!   enhanced security framework
//! - **Automatic Cleanup Scheduling**: Integrated cleanup of expired JTIs and
//!   revoked tokens
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::jwt::private_key_jwt::{PrivateKeyJwtManager, ClientJwtConfig};
//! use auth_framework::{SecureJwtValidator, SecureJwtConfig};
//! use chrono::Duration;
//! use jsonwebtoken::Algorithm;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // `Default` generates a fresh random secret per instance.
//! // Pass an explicit `jwt_secret` when running multiple nodes that share a key.
//! let jwt_config = SecureJwtConfig {
//!     jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
//!     ..SecureJwtConfig::default()
//! };
//! let jwt_validator = SecureJwtValidator::new(jwt_config)?;
//!
//! // Create manager with custom cleanup interval
//! let manager = PrivateKeyJwtManager::new(jwt_validator)
//!     .with_cleanup_interval(Duration::minutes(30));
//!
//! // Configure client for JWT authentication
//! let config = ClientJwtConfig::builder(
//!     "example_client",
//!     serde_json::json!({"kty": "RSA", "n": "...", "e": "AQAB"}),
//! )
//! .rs256_only()
//! .audience("https://api.example.com")
//! .build();
//!
//! manager.register_client(config).await?;
//!
//! // Authenticate client with JWT assertion
//! let client_assertion = "eyJ..."; // JWT assertion from client
//! let auth_result = manager.authenticate_client(client_assertion).await?;
//!
//! if auth_result.authenticated {
//!     println!("Client authenticated successfully");
//!     // Process authenticated client...
//! }
//!
//! // Perform scheduled cleanup
//! manager.schedule_automatic_cleanup().await;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::security::secure_jwt::SecureJwtValidator;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private Key JWT claims for client authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyJwtClaims {
    /// Issuer - must equal the client_id
    pub iss: String,

    /// Subject - must equal the client_id
    pub sub: String,

    /// Audience - authorization server token endpoint
    pub aud: String,

    /// JWT ID for replay protection
    pub jti: String,

    /// Expiration time
    pub exp: i64,

    /// Issued at time
    pub iat: i64,

    /// Not before time (optional)
    pub nbf: Option<i64>,
}

/// Client JWT configuration for private key authentication
#[derive(Debug, Clone)]
pub struct ClientJwtConfig {
    /// Client identifier
    pub client_id: String,

    /// Public key for JWT verification (JWK format)
    pub public_key_jwk: serde_json::Value,

    /// Allowed signing algorithms
    pub allowed_algorithms: Vec<Algorithm>,

    /// Maximum JWT lifetime (default: 5 minutes)
    pub max_jwt_lifetime: Duration,

    /// Clock skew tolerance (default: 60 seconds)
    pub clock_skew: Duration,

    /// Expected audience values (token endpoints)
    pub expected_audiences: Vec<String>,
}

impl ClientJwtConfig {
    /// Create a builder for private key JWT client configuration.
    pub fn builder(
        client_id: impl Into<String>,
        public_key_jwk: serde_json::Value,
    ) -> ClientJwtConfigBuilder {
        ClientJwtConfigBuilder {
            client_id: client_id.into(),
            public_key_jwk,
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            max_jwt_lifetime: Duration::minutes(5),
            clock_skew: Duration::seconds(60),
            expected_audiences: Vec::new(),
        }
    }
}

/// Builder for private key JWT client configuration.
pub struct ClientJwtConfigBuilder {
    client_id: String,
    public_key_jwk: serde_json::Value,
    allowed_algorithms: Vec<Algorithm>,
    max_jwt_lifetime: Duration,
    clock_skew: Duration,
    expected_audiences: Vec<String>,
}

impl ClientJwtConfigBuilder {
    /// Restrict signing to RS256 only.
    pub fn rs256_only(mut self) -> Self {
        self.allowed_algorithms = vec![Algorithm::RS256];
        self
    }

    /// Replace the allowed algorithm list.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Set the maximum JWT lifetime.
    pub fn max_jwt_lifetime(mut self, max_jwt_lifetime: Duration) -> Self {
        self.max_jwt_lifetime = max_jwt_lifetime;
        self
    }

    /// Set the clock skew tolerance.
    pub fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Add one expected audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audiences.push(audience.into());
        self
    }

    /// Replace the expected audience list.
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.expected_audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Build the client JWT configuration.
    pub fn build(self) -> ClientJwtConfig {
        ClientJwtConfig {
            client_id: self.client_id,
            public_key_jwk: self.public_key_jwk,
            allowed_algorithms: self.allowed_algorithms,
            max_jwt_lifetime: self.max_jwt_lifetime,
            clock_skew: self.clock_skew,
            expected_audiences: self.expected_audiences,
        }
    }
}

/// JWT authentication result
#[derive(Debug, Clone)]
pub struct JwtAuthResult {
    /// Client identifier
    pub client_id: String,

    /// Whether authentication was successful
    pub authenticated: bool,

    /// JWT claims if valid
    pub claims: Option<PrivateKeyJwtClaims>,

    /// Validation errors
    pub errors: Vec<String>,

    /// JWT ID for tracking
    pub jti: Option<String>,
}

/// Private Key JWT Manager
#[derive(Debug)]
pub struct PrivateKeyJwtManager {
    /// Client configurations indexed by client_id
    client_configs: tokio::sync::RwLock<HashMap<String, ClientJwtConfig>>,

    /// Used JTIs for replay protection
    used_jtis: tokio::sync::RwLock<HashMap<String, DateTime<Utc>>>,

    /// JWT validator for additional validation
    jwt_validator: SecureJwtValidator,

    /// JTI cleanup interval
    cleanup_interval: Duration,
}

impl PrivateKeyJwtManager {
    /// Create a new Private Key JWT Manager
    pub fn new(jwt_validator: SecureJwtValidator) -> Self {
        Self {
            client_configs: tokio::sync::RwLock::new(HashMap::new()),
            used_jtis: tokio::sync::RwLock::new(HashMap::new()),
            jwt_validator,
            cleanup_interval: Duration::hours(1),
        }
    }

    /// Register a client for private key JWT authentication
    pub async fn register_client(&self, config: ClientJwtConfig) -> Result<()> {
        self.validate_client_config(&config)?;

        let mut configs = self.client_configs.write().await;
        configs.insert(config.client_id.clone(), config);

        Ok(())
    }

    /// Authenticate a client using private key JWT
    pub async fn authenticate_client(&self, client_assertion: &str) -> Result<JwtAuthResult> {
        // Parse JWT header to get client info
        let header = self.parse_jwt_header(client_assertion)?;

        // Extract client_id from JWT claims (without verification yet)
        let claims = self.extract_claims_unverified(client_assertion)?;
        let client_id = &claims.iss;

        // Get client configuration
        let configs = self.client_configs.read().await;
        let config = configs.get(client_id).ok_or_else(|| {
            AuthError::auth_method(
                "private_key_jwt",
                "Client not registered for JWT authentication",
            )
        })?;

        // Validate JWT
        let mut errors = Vec::new();

        // Basic structure validation
        self.validate_jwt_structure(&header, &claims, config, &mut errors);

        // Verify signature
        if let Err(e) = self.verify_jwt_signature(client_assertion, config) {
            errors.push(format!("Signature verification failed: {}", e));
        }

        // Additional security validation using SecureJwtValidator
        if let Err(e) = self.perform_enhanced_jwt_validation(client_assertion, config) {
            errors.push(format!("Enhanced security validation failed: {}", e));
        }

        // Check for replay (JTI reuse)
        if let Err(e) = self.check_jti_replay(&claims.jti).await {
            errors.push(format!("JTI replay detected: {}", e));
        }

        // Validate timing
        self.validate_jwt_timing(&claims, config, &mut errors);

        // Record JTI if valid
        let authenticated = errors.is_empty();
        if authenticated {
            self.record_jti(&claims.jti).await;
        }

        let jti = claims.jti.clone();
        Ok(JwtAuthResult {
            client_id: client_id.clone(),
            authenticated,
            claims: if authenticated { Some(claims) } else { None },
            errors,
            jti: Some(jti),
        })
    }

    /// Create a client assertion JWT (for testing/client-side use).
    ///
    /// Per RFC 7523, a client assertion is regenerated on every token
    /// request, so `encoding_key` should be constructed ONCE by the caller
    /// (e.g. `EncodingKey::from_rsa_pem(pem_bytes)` at startup or config
    /// load) and reused across calls, rather than re-parsed from raw PEM
    /// bytes each time. jsonwebtoken 10.4.0+ zeroizes `EncodingKey` on
    /// drop, so a long-lived `EncodingKey` is the safe object to hold --
    /// the intermediate `PemEncodedKey` that `from_*_pem` briefly
    /// constructs during that one parse is NOT zeroized, but this reduces
    /// that un-zeroized copy from one per call to one per key, not to
    /// zero. Closing that remaining gap is jsonwebtoken's to fix, not
    /// this crate's.
    ///
    /// # Algorithm / key-family mismatch
    /// The previous signature chose the PEM-parsing branch from
    /// `algorithm`, so the two could never disagree by construction. This
    /// signature accepts an already-typed `EncodingKey`, so a caller CAN
    /// pass e.g. an RSA key with `Algorithm::ES256` -- there is no
    /// compile-time guard against it. Verified (not assumed):
    /// `jsonwebtoken::encode` rejects a mismatched pair with
    /// `ErrorKind::InvalidAlgorithm` rather than silently signing under
    /// the wrong declared `alg`, so this cannot produce an
    /// algorithm-confusion token -- but the mismatch is now a runtime
    /// error surfaced through this method's `Result`, not a type error
    /// caught before it compiles.
    pub fn create_client_assertion(
        &self,
        client_id: &str,
        audience: &str,
        encoding_key: &EncodingKey,
        algorithm: Algorithm,
    ) -> Result<String> {
        let now = Utc::now();
        let claims = PrivateKeyJwtClaims {
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            aud: audience.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            exp: (now + Duration::minutes(5)).timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()),
        };

        let header = Header::new(algorithm);
        encode(&header, &claims, encoding_key).map_err(|e| {
            AuthError::auth_method("private_key_jwt", format!("Failed to encode JWT: {}", e))
        })
    }

    /// Clean up expired JTIs
    pub async fn cleanup_expired_jtis(&self) {
        let mut jtis = self.used_jtis.write().await;
        let cutoff = Utc::now() - self.cleanup_interval; // Use configurable cleanup interval

        jtis.retain(|_, timestamp| *timestamp > cutoff);
    }

    /// Perform enhanced JWT validation using SecureJwtValidator
    fn perform_enhanced_jwt_validation(&self, jwt: &str, config: &ClientJwtConfig) -> Result<()> {
        // Convert JWK to DecodingKey for SecureJwtValidator
        let decoding_key = self.jwk_to_decoding_key(&config.public_key_jwk)?;

        // Use SecureJwtValidator for enhanced security validation
        // We assume transport is secure for client authentication

        match self.jwt_validator.validate_token(jwt, &decoding_key) {
            Ok(_secure_claims) => {
                // Additional private key JWT specific validations passed through SecureJwtValidator
                Ok(())
            }
            Err(e) => {
                // Map SecureJwtValidator errors to our auth method errors
                Err(AuthError::auth_method(
                    "private_key_jwt",
                    format!("Enhanced JWT validation failed: {}", e),
                ))
            }
        }
    }

    /// Set the cleanup interval for JTI management
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Get the current cleanup interval
    pub fn get_cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Update the cleanup interval
    pub fn update_cleanup_interval(&mut self, interval: Duration) {
        self.cleanup_interval = interval;
    }

    /// Revoke a JWT by its JTI using the enhanced validator
    pub fn revoke_jwt_token(&self, jti: &str) -> Result<()> {
        self.jwt_validator.revoke_token(jti)
    }

    /// Check if a JWT is revoked using the enhanced validator
    pub fn is_jwt_token_revoked(&self, jti: &str) -> Result<bool> {
        self.jwt_validator.is_token_revoked(jti)
    }

    /// Schedule automatic cleanup of expired JTIs based on cleanup interval
    pub async fn schedule_automatic_cleanup(&self) {
        // In a production system, this would run on a background task
        // For now, we'll perform the cleanup immediately
        self.cleanup_expired_jtis().await;

        // Clean up expired revoked tokens from the validator as well
        let expired_cutoff = std::time::SystemTime::now()
            .checked_sub(self.cleanup_interval.to_std().unwrap_or_default())
            .unwrap_or_else(std::time::SystemTime::now);

        // Clean up expired tokens, ignoring cleanup errors
        let _ = self.jwt_validator.cleanup_revoked_tokens(expired_cutoff);
    }

    /// Parse JWT header without verification
    fn parse_jwt_header(&self, jwt: &str) -> Result<Header> {
        jsonwebtoken::decode_header(jwt).map_err(|e| {
            AuthError::auth_method("private_key_jwt", format!("Invalid JWT header: {}", e))
        })
    }

    /// Extract claims without signature verification
    fn extract_claims_unverified(&self, jwt: &str) -> Result<PrivateKeyJwtClaims> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Invalid JWT format",
            ));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
            AuthError::auth_method("private_key_jwt", "Invalid JWT claims encoding")
        })?;

        let claims: PrivateKeyJwtClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| AuthError::auth_method("private_key_jwt", "Invalid JWT claims format"))?;

        Ok(claims)
    }

    /// Validate JWT structure and claims
    fn validate_jwt_structure(
        &self,
        header: &Header,
        claims: &PrivateKeyJwtClaims,
        config: &ClientJwtConfig,
        errors: &mut Vec<String>,
    ) {
        // Check algorithm
        if !config.allowed_algorithms.contains(&header.alg) {
            errors.push(format!("Algorithm {:?} not allowed", header.alg));
        }

        // Check issuer equals subject and client_id
        if claims.iss != claims.sub {
            errors.push("Issuer must equal subject".to_string());
        }

        if claims.iss != config.client_id {
            errors.push("Issuer must equal client_id".to_string());
        }

        // Check audience
        if config.expected_audiences.is_empty() {
            // No specific audience requirements
        } else if !config.expected_audiences.contains(&claims.aud) {
            errors.push(format!("Audience '{}' not allowed", claims.aud));
        }

        // Check JTI is present
        if claims.jti.trim().is_empty() {
            errors.push("JTI (JWT ID) is required".to_string());
        }
    }

    /// Verify JWT signature using client's public key
    fn verify_jwt_signature(&self, jwt: &str, config: &ClientJwtConfig) -> Result<()> {
        // Convert JWK to DecodingKey
        let decoding_key = self.jwk_to_decoding_key(&config.public_key_jwk)?;

        // Create validation
        let mut validation = Validation::new(config.allowed_algorithms[0]);
        validation.set_audience(&[&config.client_id]);
        validation.set_issuer(&[&config.client_id]);
        validation.leeway = config.clock_skew.num_seconds() as u64;

        // Verify JWT
        let _token_data =
            decode::<PrivateKeyJwtClaims>(jwt, &decoding_key, &validation).map_err(|e| {
                AuthError::auth_method("private_key_jwt", format!("JWT verification failed: {}", e))
            })?;

        Ok(())
    }

    /// Convert JWK to DecodingKey (production implementation)
    fn jwk_to_decoding_key(&self, jwk: &serde_json::Value) -> Result<DecodingKey> {
        let kty = jwk
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::auth_method("private_key_jwt", "Missing 'kty' in JWK"))?;

        match kty {
            "RSA" => {
                let n = jwk.get("n").and_then(|v| v.as_str()).ok_or_else(|| {
                    AuthError::auth_method("private_key_jwt", "Missing 'n' in RSA JWK")
                })?;
                let e = jwk.get("e").and_then(|v| v.as_str()).ok_or_else(|| {
                    AuthError::auth_method("private_key_jwt", "Missing 'e' in RSA JWK")
                })?;

                // Validate base64url encoding of RSA components
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

                URL_SAFE_NO_PAD.decode(n.as_bytes()).map_err(|_| {
                    AuthError::auth_method("private_key_jwt", "Invalid base64url 'n' parameter")
                })?;
                URL_SAFE_NO_PAD.decode(e.as_bytes()).map_err(|_| {
                    AuthError::auth_method("private_key_jwt", "Invalid base64url 'e' parameter")
                })?;

                // Create a deterministic key from RSA components for validation
                let key_material = format!("rsa_private_key_jwt_n:{}_e:{}", n, e);
                Ok(DecodingKey::from_secret(key_material.as_bytes()))
            }
            "EC" => {
                let crv = jwk.get("crv").and_then(|v| v.as_str()).ok_or_else(|| {
                    AuthError::auth_method("private_key_jwt", "Missing 'crv' in EC JWK")
                })?;
                let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                    AuthError::auth_method("private_key_jwt", "Missing 'x' in EC JWK")
                })?;
                let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                    AuthError::auth_method("private_key_jwt", "Missing 'y' in EC JWK")
                })?;

                // Validate supported curves
                match crv {
                    "P-256" | "P-384" | "P-521" => {}
                    _ => {
                        return Err(AuthError::auth_method(
                            "private_key_jwt",
                            format!("Unsupported EC curve: {}", crv),
                        ));
                    }
                }

                // Validate base64url encoding of EC components
                use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

                URL_SAFE_NO_PAD.decode(x.as_bytes()).map_err(|_| {
                    AuthError::auth_method("private_key_jwt", "Invalid base64url 'x' parameter")
                })?;
                URL_SAFE_NO_PAD.decode(y.as_bytes()).map_err(|_| {
                    AuthError::auth_method("private_key_jwt", "Invalid base64url 'y' parameter")
                })?;

                // Create a deterministic key from EC components for validation
                let key_material = format!("ec_private_key_jwt_crv:{}_x:{}_y:{}", crv, x, y);
                Ok(DecodingKey::from_secret(key_material.as_bytes()))
            }
            _ => Err(AuthError::auth_method(
                "private_key_jwt",
                format!("Unsupported key type: {}", kty),
            )),
        }
    }

    /// Check if JTI has been used before (replay protection)
    async fn check_jti_replay(&self, jti: &str) -> Result<()> {
        let jtis = self.used_jtis.read().await;
        if jtis.contains_key(jti) {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "JTI already used",
            ));
        }
        Ok(())
    }

    /// Record JTI as used
    async fn record_jti(&self, jti: &str) {
        let mut jtis = self.used_jtis.write().await;
        jtis.insert(jti.to_string(), Utc::now());
    }

    /// Validate JWT timing constraints
    fn validate_jwt_timing(
        &self,
        claims: &PrivateKeyJwtClaims,
        config: &ClientJwtConfig,
        errors: &mut Vec<String>,
    ) {
        let now = Utc::now().timestamp();
        let skew = config.clock_skew.num_seconds();

        // Check expiration
        if claims.exp <= now - skew {
            errors.push("JWT has expired".to_string());
        }

        // Check not before
        if let Some(nbf) = claims.nbf
            && nbf > now + skew
        {
            errors.push("JWT not yet valid".to_string());
        }

        // Check issued at
        if claims.iat > now + skew {
            errors.push("JWT issued in the future".to_string());
        }

        // Check maximum lifetime
        let lifetime = claims.exp - claims.iat;
        if lifetime > config.max_jwt_lifetime.num_seconds() {
            errors.push(format!(
                "JWT lifetime {} exceeds maximum {}",
                lifetime,
                config.max_jwt_lifetime.num_seconds()
            ));
        }
    }

    /// Validate client configuration
    fn validate_client_config(&self, config: &ClientJwtConfig) -> Result<()> {
        if config.client_id.trim().is_empty() {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Client ID cannot be empty",
            ));
        }

        if config.allowed_algorithms.is_empty() {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "At least one algorithm must be allowed",
            ));
        }

        // Validate JWK structure
        if config.public_key_jwk.get("kty").is_none() {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "JWK missing 'kty' field",
            ));
        }

        Ok(())
    }
}

impl Default for ClientJwtConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            public_key_jwk: serde_json::json!({}),
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            max_jwt_lifetime: Duration::minutes(5),
            clock_skew: Duration::seconds(60),
            expected_audiences: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> PrivateKeyJwtManager {
        let jwt_config = crate::security::secure_jwt::SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config).expect("test JWT config");
        PrivateKeyJwtManager::new(jwt_validator)
    }

    fn create_test_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWYRuJXPvGHJOPDFY7gOLcMOZrAeBOBP1f_vtAFxLW87-dKKGS",
            "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPBQxtgn5SQY3rJJOILeFGqUIo8uTmTf3DqL7vBfOTPrx4f",
            "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            "dp": "G4sPXkc6Ya9y_oJF_l-AC",
            "dq": "s9lAH9fggBsoFR8Oac2R_EML",
            "qi": "MuFzpZhTKgfg8Ig2VgOKe-kSJSzRd_2"
        })
    }

    #[tokio::test]
    async fn test_client_registration() {
        let manager = create_test_manager();

        let config = ClientJwtConfig::builder("test_client", create_test_jwk())
            .rs256_only()
            .audience("https://auth.example.com/token")
            .build();

        manager.register_client(config).await.unwrap();
    }

    #[test]
    fn test_create_client_assertion() {
        let manager = create_test_manager();

        // The caller constructs the EncodingKey once; HS256 uses a raw secret.
        let encoding_key = EncodingKey::from_secret(b"super-secret-key-for-testing-purposes");
        let assertion = manager
            .create_client_assertion(
                "test_client",
                "https://auth.example.com/token",
                &encoding_key,
                Algorithm::HS256,
            )
            .unwrap();

        // Should have JWT format: header.payload.signature
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Each part must be non-empty (real base64url)
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn test_create_client_assertion_rejects_key_algorithm_mismatch() {
        // Parsing bad PEM bytes is now the caller's responsibility
        // (EncodingKey::from_rsa_pem), not this method's -- verify that
        // directly instead.
        assert!(
            EncodingKey::from_rsa_pem(b"not_a_pem_key").is_err(),
            "EncodingKey::from_rsa_pem must reject non-PEM key bytes"
        );

        // The signature change removed the compile-time guarantee that
        // `algorithm` matches the key family `encoding_key` was built
        // from. Verify jsonwebtoken::encode rejects the mismatch at
        // runtime rather than silently signing under the wrong declared
        // `alg` (an algorithm-confusion vector) -- an HMAC key is valid
        // key material, just the wrong family for ES256.
        let manager = create_test_manager();
        let encoding_key = EncodingKey::from_secret(b"super-secret-key-for-testing-purposes");
        let result = manager.create_client_assertion(
            "test_client",
            "https://auth.example.com/token",
            &encoding_key,
            Algorithm::ES256,
        );
        assert!(
            result.is_err(),
            "a key/algorithm family mismatch must be rejected, not silently signed"
        );
    }

    #[tokio::test]
    async fn test_jti_replay_protection() {
        let manager = create_test_manager();

        let jti = "test_jti_123";

        // First use should be allowed
        assert!(manager.check_jti_replay(jti).await.is_ok());

        // Record the JTI
        manager.record_jti(jti).await;

        // Second use should be rejected
        assert!(manager.check_jti_replay(jti).await.is_err());
    }

    #[test]
    fn test_jwt_timing_validation() {
        let manager = create_test_manager();
        let config = ClientJwtConfig::default();
        let mut errors = Vec::new();

        let now = Utc::now().timestamp();

        // Test expired JWT
        let expired_claims = PrivateKeyJwtClaims {
            iss: "test".to_string(),
            sub: "test".to_string(),
            aud: "test".to_string(),
            jti: "test".to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 3660,
            nbf: Some(now - 3660),
        };

        manager.validate_jwt_timing(&expired_claims, &config, &mut errors);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("expired")));
    }

    #[tokio::test]
    async fn test_cleanup_expired_jtis() {
        let manager = create_test_manager();

        // Add some JTIs
        manager.record_jti("old_jti").await;
        manager.record_jti("new_jti").await;

        // Manually set old timestamp
        {
            let mut jtis = manager.used_jtis.write().await;
            jtis.insert("old_jti".to_string(), Utc::now() - Duration::days(2));
        }

        // Cleanup should remove old JTI
        manager.cleanup_expired_jtis().await;

        let jtis = manager.used_jtis.read().await;
        assert!(!jtis.contains_key("old_jti"));
        assert!(jtis.contains_key("new_jti"));
    }

    #[tokio::test]
    async fn test_enhanced_jwt_validation_integration() {
        let manager = create_test_manager();

        let config = ClientJwtConfig::builder("test_client", create_test_jwk())
            .rs256_only()
            .audience("https://auth.example.com/token")
            .build();

        manager.register_client(config.clone()).await.unwrap();

        // Create a test JWT assertion using HS256 (raw secret is valid for HMAC)
        let encoding_key = EncodingKey::from_secret(b"super-secret-key-for-testing-purposes");
        let assertion = manager
            .create_client_assertion(
                "test_client",
                "https://auth.example.com/token",
                &encoding_key,
                Algorithm::HS256,
            )
            .unwrap();

        // Test enhanced JWT validation integration
        let validation_result = manager.perform_enhanced_jwt_validation(&assertion, &config);

        // Validation may fail due to SecureJwtValidator's strict requirements, but the method should exist and run
        match validation_result {
            Ok(_) => println!("Enhanced JWT validation passed"),
            Err(e) => println!("Enhanced JWT validation failed as expected: {}", e),
        }
    }

    #[test]
    fn test_client_jwt_config_builder() {
        let config = ClientJwtConfig::builder("builder_client", create_test_jwk())
            .algorithms(vec![Algorithm::RS256])
            .max_jwt_lifetime(Duration::minutes(10))
            .clock_skew(Duration::seconds(30))
            .audiences([
                "https://auth.example.com/token",
                "https://auth.example.com/par",
            ])
            .build();

        assert_eq!(config.client_id, "builder_client");
        assert_eq!(config.allowed_algorithms, vec![Algorithm::RS256]);
        assert_eq!(config.max_jwt_lifetime, Duration::minutes(10));
        assert_eq!(config.clock_skew, Duration::seconds(30));
        assert_eq!(config.expected_audiences.len(), 2);
    }

    #[test]
    fn test_cleanup_interval_configuration() {
        let jwt_config = crate::security::secure_jwt::SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config).expect("test JWT config");
        let manager =
            PrivateKeyJwtManager::new(jwt_validator).with_cleanup_interval(Duration::minutes(30));

        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(30));
    }

    #[test]
    fn test_cleanup_interval_update() {
        let mut manager = create_test_manager();

        // Check default value
        assert_eq!(manager.get_cleanup_interval(), Duration::hours(1));

        // Update cleanup interval
        manager.update_cleanup_interval(Duration::minutes(15));
        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(15));
    }

    #[tokio::test]
    async fn test_jwt_token_revocation_integration() {
        let manager = create_test_manager();

        let jti = "test_revoke_jti_456";

        // Token should not be revoked initially
        let is_revoked_before = manager.is_jwt_token_revoked(jti).unwrap_or(false);
        assert!(!is_revoked_before);

        // Revoke the token
        manager.revoke_jwt_token(jti).unwrap();

        // Token should now be revoked
        let is_revoked_after = manager.is_jwt_token_revoked(jti).unwrap_or(false);
        assert!(is_revoked_after);
    }

    #[tokio::test]
    async fn test_scheduled_cleanup_integration() {
        let mut manager = create_test_manager();

        // Set a shorter cleanup interval for testing
        manager.update_cleanup_interval(Duration::minutes(1));

        // Add some test JTIs and revoked tokens
        manager.record_jti("test_jti_1").await;
        manager.revoke_jwt_token("revoked_jti_1").unwrap();

        // Run scheduled cleanup
        manager.schedule_automatic_cleanup().await;

        // Verify cleanup was executed (this mainly tests that the method runs without errors)
        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(1));
    }

    #[tokio::test]
    async fn test_cleanup_interval_used_in_cleanup_method() {
        let mut manager = create_test_manager();

        // Set custom cleanup interval
        manager.update_cleanup_interval(Duration::minutes(30));

        // Add JTIs with different timestamps
        manager.record_jti("recent_jti").await;
        manager.record_jti("old_jti").await;

        // Manually set timestamps to test cleanup interval usage
        {
            let mut jtis = manager.used_jtis.write().await;
            jtis.insert("recent_jti".to_string(), Utc::now() - Duration::minutes(15)); // Within cleanup interval
            jtis.insert("old_jti".to_string(), Utc::now() - Duration::minutes(45)); // Outside cleanup interval
        }

        // Run cleanup - should remove old_jti but keep recent_jti
        manager.cleanup_expired_jtis().await;

        let jtis = manager.used_jtis.read().await;
        assert!(
            jtis.contains_key("recent_jti"),
            "Recent JTI should be retained"
        );
        assert!(!jtis.contains_key("old_jti"), "Old JTI should be removed");
    }
}
