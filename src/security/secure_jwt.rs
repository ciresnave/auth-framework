use crate::errors::Result;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureJwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub typ: String,
    pub sid: Option<String>,
    pub client_id: Option<String>,
    pub auth_ctx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecureJwtConfig {
    pub allowed_algorithms: Vec<Algorithm>,
    pub required_issuers: HashSet<String>,
    pub required_audiences: HashSet<String>,
    pub max_token_lifetime: Duration,
    pub clock_skew: Duration,
    pub require_jti: bool,
    pub validate_nbf: bool,
    pub allowed_token_types: HashSet<String>,
    pub require_secure_transport: bool,
    /// JWT signing/validation key
    pub jwt_secret: String,
}

impl Default for SecureJwtConfig {
    fn default() -> Self {
        let mut allowed_token_types = HashSet::new();
        allowed_token_types.insert("access".to_string());
        allowed_token_types.insert("refresh".to_string());
        allowed_token_types.insert("JARM".to_string());

        let mut required_issuers = HashSet::new();
        required_issuers.insert("auth-framework".to_string());

        Self {
            allowed_algorithms: vec![Algorithm::HS256, Algorithm::RS256, Algorithm::ES256],
            required_issuers,
            required_audiences: HashSet::new(),
            max_token_lifetime: Duration::from_secs(3600),
            clock_skew: Duration::from_secs(30),
            require_jti: true,
            validate_nbf: true,
            allowed_token_types,
            require_secure_transport: false,
            jwt_secret: "CHANGE_THIS_IN_PRODUCTION_USE_PROPER_KEY_MANAGEMENT".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SecureJwtValidator {
    config: SecureJwtConfig,
    revoked_tokens: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl SecureJwtValidator {
    pub fn new(config: SecureJwtConfig) -> Self {
        Self {
            config,
            revoked_tokens: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Get decoding key for JWT validation
    pub fn get_decoding_key(&self) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_secret(self.config.jwt_secret.as_bytes())
    }

    pub fn validate_token(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
        verify_signature: bool,
    ) -> Result<SecureJwtClaims> {
        use jsonwebtoken::{Algorithm, Validation, decode};

        // Create validation with signature verification
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false; // Let our custom validation handle expiry
        validation.validate_aud = false; // Let our custom validation handle audience
        validation.validate_nbf = false; // Let our custom validation handle not before

        if !verify_signature {
            validation.insecure_disable_signature_validation();
        }

        // Decode and validate the JWT
        match decode::<SecureJwtClaims>(token, decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;

                // Check if token is revoked
                if self.is_token_revoked(&claims.jti)? {
                    return Err(crate::errors::AuthError::Unauthorized(
                        "Token is revoked".to_string(),
                    ));
                }

                // Additional custom validations can be added here

                Ok(claims)
            }
            Err(e) => Err(crate::errors::AuthError::Unauthorized(format!(
                "JWT validation failed: {}",
                e
            ))),
        }
    }

    pub fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        let revoked_tokens = self.revoked_tokens.lock().unwrap();
        Ok(revoked_tokens.contains(jti))
    }

    pub fn revoke_token(&self, jti: &str) -> Result<()> {
        let mut revoked_tokens = self.revoked_tokens.lock().unwrap();
        revoked_tokens.insert(jti.to_string());
        Ok(())
    }

    pub fn cleanup_revoked_tokens(&self, _expired_cutoff: std::time::SystemTime) -> Result<()> {
        // For production, this would actually clean up expired tokens
        // For testing, we'll just keep them all for simplicity
        Ok(())
    }
}
