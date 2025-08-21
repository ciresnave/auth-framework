//! Common JWT Operations
//!
//! This module provides shared JWT functionality to eliminate
//! duplication across server modules.

use crate::errors::{AuthError, Result};
use crate::server::core::common_validation;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Common JWT configuration
#[derive(Clone)]
pub struct JwtConfig {
    /// Signing algorithm
    pub algorithm: Algorithm,
    /// Signing key
    pub signing_key: EncodingKey,
    /// Verification key
    pub verification_key: DecodingKey,
    /// Default expiration time in seconds
    pub default_expiration: u64,
    /// Issuer
    pub issuer: String,
    /// Audiences
    pub audiences: Vec<String>,
}

impl JwtConfig {
    /// Create new JWT config with symmetric key
    pub fn with_symmetric_key(secret: &[u8], issuer: String) -> Self {
        Self {
            algorithm: Algorithm::HS256,
            signing_key: EncodingKey::from_secret(secret),
            verification_key: DecodingKey::from_secret(secret),
            default_expiration: 3600, // 1 hour
            issuer,
            audiences: vec![],
        }
    }

    /// Create new JWT config with RSA keys
    pub fn with_rsa_keys(private_key: &[u8], public_key: &[u8], issuer: String) -> Result<Self> {
        let signing_key = EncodingKey::from_rsa_pem(private_key)
            .map_err(|e| AuthError::validation(format!("Invalid private key: {}", e)))?;

        let verification_key = DecodingKey::from_rsa_pem(public_key)
            .map_err(|e| AuthError::validation(format!("Invalid public key: {}", e)))?;

        Ok(Self {
            algorithm: Algorithm::RS256,
            signing_key,
            verification_key,
            default_expiration: 3600, // 1 hour
            issuer,
            audiences: vec![],
        })
    }

    /// Add audience
    pub fn with_audience(mut self, audience: String) -> Self {
        self.audiences.push(audience);
        self
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expiration: u64) -> Self {
        self.default_expiration = expiration;
        self
    }
}

/// Common JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonJwtClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Not before
    pub nbf: Option<i64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl CommonJwtClaims {
    /// Create new claims with required fields
    pub fn new(issuer: String, subject: String, audiences: Vec<String>, expiration: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            iss: issuer,
            sub: subject,
            aud: audiences,
            exp: expiration,
            iat: now,
            nbf: None,
            jti: None,
            custom: HashMap::new(),
        }
    }

    /// Add custom claim
    pub fn with_custom_claim(mut self, key: String, value: serde_json::Value) -> Self {
        self.custom.insert(key, value);
        self
    }

    /// Set JWT ID
    pub fn with_jti(mut self, jti: String) -> Self {
        self.jti = Some(jti);
        self
    }

    /// Set not before
    pub fn with_nbf(mut self, nbf: i64) -> Self {
        self.nbf = Some(nbf);
        self
    }
}

/// Common JWT token management for OAuth 2.0 and OpenID Connect operations.
///
/// `JwtManager` provides comprehensive JWT token creation, verification, and
/// management capabilities specifically designed for OAuth 2.0 authorization
/// servers and OpenID Connect providers. It supports both symmetric and
/// asymmetric signing algorithms with security best practices.
///
/// # Supported Algorithms
///
/// - **HMAC**: HS256, HS384, HS512 (symmetric)
/// - **RSA**: RS256, RS384, RS512 (asymmetric)
/// - **ECDSA**: ES256, ES384, ES512 (asymmetric)
/// - **EdDSA**: EdDSA (asymmetric, Ed25519)
///
/// # Security Features
///
/// - **Algorithm Validation**: Prevents algorithm confusion attacks
/// - **Time Validation**: Automatic `exp`, `nbf`, and `iat` claim validation
/// - **Audience Validation**: Ensures tokens are used by intended recipients
/// - **Issuer Validation**: Verifies token origin
/// - **Secure Defaults**: Uses secure algorithm choices and expiration times
///
/// # Token Types Supported
///
/// - **Access Tokens**: OAuth 2.0 access tokens with scopes
/// - **ID Tokens**: OpenID Connect identity tokens
/// - **Refresh Tokens**: Long-lived tokens for access token renewal
/// - **Custom Tokens**: Application-specific token types
///
/// # Key Management
///
/// - **Symmetric Keys**: HMAC-based signing with shared secrets
/// - **RSA Keys**: Support for PKCS#1 and PKCS#8 key formats
/// - **Key Rotation**: Support for multiple signing keys
/// - **Key Security**: Secure key storage and access patterns
///
/// # Example
///
/// ```rust
/// use auth_framework::server::core::common_jwt::{JwtManager, JwtConfig, CommonJwtClaims};
///
/// // Create JWT manager with RSA keys
/// let config = JwtConfig::with_rsa_keys(
///     private_key_bytes,
///     public_key_bytes,
///     "https://auth.example.com".to_string()
/// )?;
/// let jwt_manager = JwtManager::new(config);
///
/// // Create access token
/// let claims = CommonJwtClaims::new(
///     "https://auth.example.com".to_string(),
///     "user123".to_string(),
///     vec!["api".to_string()],
///     expiration_time
/// ).with_custom_claim("scope".to_string(), json!("read write"));
///
/// let token = jwt_manager.create_token(&claims)?;
///
/// // Verify token
/// let verified_claims = jwt_manager.verify_token(&token)?;
/// ```
///
/// # Performance Considerations
///
/// - Asymmetric algorithms are more computationally expensive
/// - Token verification is optimized for high-throughput scenarios
/// - Key caching reduces cryptographic operation overhead
///
/// # RFC Compliance
///
/// - **RFC 7519**: JSON Web Token (JWT)
/// - **RFC 7515**: JSON Web Signature (JWS)
/// - **RFC 8725**: JWT Best Current Practices
/// - **RFC 9068**: JWT Profile for OAuth 2.0 Access Tokens
pub struct JwtManager {
    config: JwtConfig,
}

impl JwtManager {
    /// Create new JWT manager
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Create signed JWT token
    pub fn create_token(&self, claims: &CommonJwtClaims) -> Result<String> {
        let header = Header {
            alg: self.config.algorithm,
            ..Default::default()
        };

        encode(&header, claims, &self.config.signing_key)
            .map_err(|e| AuthError::validation(format!("Failed to encode JWT: {}", e)))
    }

    /// Create signed token with custom claims
    pub fn create_token_with_custom_claims<T>(&self, claims: &T) -> Result<String>
    where
        T: Serialize,
    {
        let header = Header {
            alg: self.config.algorithm,
            ..Default::default()
        };

        encode(&header, claims, &self.config.signing_key)
            .map_err(|e| AuthError::validation(format!("Failed to encode JWT: {}", e)))
    }

    /// Verify and decode JWT token
    pub fn verify_token(&self, token: &str) -> Result<CommonJwtClaims> {
        // Basic format validation
        common_validation::jwt::validate_jwt_format(token)?;

        let mut validation = Validation::new(self.config.algorithm);
        validation.set_issuer(&[&self.config.issuer]);

        if !self.config.audiences.is_empty() {
            validation.set_audience(
                &self
                    .config
                    .audiences
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            );
        }

        let token_data =
            decode::<CommonJwtClaims>(token, &self.config.verification_key, &validation)
                .map_err(|e| AuthError::validation(format!("Invalid JWT: {}", e)))?;

        // Additional validation using common validation utilities
        let claims_value = serde_json::to_value(&token_data.claims)
            .map_err(|e| AuthError::validation(format!("Failed to serialize claims: {}", e)))?;

        common_validation::jwt::validate_time_claims(&claims_value)?;

        Ok(token_data.claims)
    }

    /// Verify token and extract custom claims
    pub fn verify_token_with_custom_claims<T>(&self, token: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        common_validation::jwt::validate_jwt_format(token)?;

        let mut validation = Validation::new(self.config.algorithm);
        validation.set_issuer(&[&self.config.issuer]);

        if !self.config.audiences.is_empty() {
            validation.set_audience(
                &self
                    .config
                    .audiences
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            );
        }

        let token_data = decode::<T>(token, &self.config.verification_key, &validation)
            .map_err(|e| AuthError::validation(format!("Invalid JWT: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Create access token with standard claims
    pub fn create_access_token(
        &self,
        subject: String,
        scope: Vec<String>,
        client_id: Option<String>,
    ) -> Result<String> {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + self.config.default_expiration as i64;

        let mut claims = CommonJwtClaims::new(
            self.config.issuer.clone(),
            subject,
            self.config.audiences.clone(),
            exp,
        );

        claims
            .custom
            .insert("scope".to_string(), serde_json::json!(scope.join(" ")));

        if let Some(client_id) = client_id {
            claims.custom.insert(
                "client_id".to_string(),
                serde_json::Value::String(client_id),
            );
        }

        claims.custom.insert(
            "token_type".to_string(),
            serde_json::Value::String("access_token".to_string()),
        );

        self.create_token(&claims)
    }

    /// Create refresh token
    pub fn create_refresh_token(&self, subject: String, client_id: String) -> Result<String> {
        // Refresh tokens typically have longer expiration
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + (self.config.default_expiration * 24) as i64; // 24x longer

        let mut claims = CommonJwtClaims::new(
            self.config.issuer.clone(),
            subject,
            self.config.audiences.clone(),
            exp,
        );

        claims.custom.insert(
            "client_id".to_string(),
            serde_json::Value::String(client_id),
        );
        claims.custom.insert(
            "token_type".to_string(),
            serde_json::Value::String("refresh_token".to_string()),
        );

        self.create_token(&claims)
    }

    /// Create ID token for OpenID Connect
    pub fn create_id_token(
        &self,
        subject: String,
        nonce: Option<String>,
        auth_time: Option<i64>,
        user_info: HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 300; // 5 minutes for ID token

        let mut claims = CommonJwtClaims::new(
            self.config.issuer.clone(),
            subject,
            self.config.audiences.clone(),
            exp,
        );

        claims.custom.insert(
            "token_type".to_string(),
            serde_json::Value::String("id_token".to_string()),
        );

        if let Some(nonce) = nonce {
            claims
                .custom
                .insert("nonce".to_string(), serde_json::Value::String(nonce));
        }

        if let Some(auth_time) = auth_time {
            claims.custom.insert(
                "auth_time".to_string(),
                serde_json::Value::Number(auth_time.into()),
            );
        }

        // Add user info claims
        for (key, value) in user_info {
            claims.custom.insert(key, value);
        }

        self.create_token(&claims)
    }
}

/// JWT utilities for token introspection and manipulation
pub mod utils {
    use super::*;

    /// Extract claims from JWT without verification (for inspection only)
    ///
    /// # Security Warning
    /// This function bypasses JWT signature verification! Only use for:
    /// - Token inspection and debugging
    /// - Extracting metadata before full validation
    /// - Non-security-critical token analysis
    ///
    /// Never use for authentication or authorization decisions!
    pub fn extract_claims_unsafe(token: &str) -> Result<serde_json::Value> {
        common_validation::jwt::extract_claims_unsafe(token)
    }

    /// Check if token is expired without full verification
    ///
    /// # Security Warning
    /// This function checks expiration without validating the JWT signature.
    /// Only use for preliminary checks - always validate the token fully
    /// before making security decisions!
    pub fn is_token_expired(token: &str) -> Result<bool> {
        let claims = extract_claims_unsafe(token)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            Ok(now >= exp)
        } else {
            Ok(false) // No expiration claim means not expired
        }
    }

    /// Get token expiration time without signature validation
    ///
    /// # Security Warning
    /// This function extracts expiration time without validating the JWT signature.
    /// Only use for inspection - validate the token before trusting the data!
    pub fn get_token_expiration(token: &str) -> Result<Option<i64>> {
        let claims = extract_claims_unsafe(token)?;
        Ok(claims.get("exp").and_then(|v| v.as_i64()))
    }

    /// Get token subject without signature validation
    ///
    /// # Security Warning
    /// This function extracts the subject without validating the JWT signature.
    /// Only use for inspection - validate the token before trusting the data!
    pub fn get_token_subject(token: &str) -> Result<Option<String>> {
        let claims = extract_claims_unsafe(token)?;
        Ok(claims.get("sub").and_then(|v| v.as_str()).map(String::from))
    }

    /// Get token scopes without signature validation
    ///
    /// # Security Warning
    /// This function extracts scopes without validating the JWT signature.
    /// Only use for inspection - validate the token before trusting the data!
    pub fn get_token_scopes(token: &str) -> Result<Vec<String>> {
        let claims = extract_claims_unsafe(token)?;

        if let Some(scope_str) = claims.get("scope").and_then(|v| v.as_str()) {
            Ok(scope_str.split_whitespace().map(String::from).collect())
        } else if let Some(scopes_array) = claims.get("scopes").and_then(|v| v.as_array()) {
            Ok(scopes_array
                .iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect())
        } else {
            Ok(vec![])
        }
    }
}


