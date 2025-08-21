//! RFC 9701 - JSON Web Token (JWT) Response for OAuth Token Introspection
//!
//! This module implements JWT-formatted responses for OAuth 2.0 token introspection
//! as defined in RFC 9701.

use crate::errors::{AuthError, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

/// JWT introspection response claims as defined in RFC 9701
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtIntrospectionClaims {
    /// Issuer of the introspection response
    pub iss: String,

    /// Audience(s) for the introspection response
    pub aud: Vec<String>,

    /// Token identifier being introspected
    pub jti: String,

    /// Issued at time
    pub iat: i64,

    /// Expiration time of the introspection response
    pub exp: i64,

    /// Subject of the token being introspected
    pub sub: Option<String>,

    /// Client identifier
    pub client_id: Option<String>,

    /// Whether the token is active
    pub active: bool,

    /// Token type (e.g., "access_token", "refresh_token")
    pub token_type: Option<String>,

    /// Scope values associated with the token
    pub scope: Option<String>,

    /// Username of the resource owner
    pub username: Option<String>,

    /// Expiration time of the token being introspected
    pub token_exp: Option<i64>,

    /// Issued at time of the token being introspected
    pub token_iat: Option<i64>,

    /// Not before time of the token being introspected
    pub token_nbf: Option<i64>,

    /// Audience of the token being introspected
    pub token_aud: Option<Vec<String>>,

    /// Issuer of the token being introspected
    pub token_iss: Option<String>,

    /// Additional claims from the original token
    #[serde(flatten)]
    pub additional_claims: HashMap<String, Value>,
}

/// Basic introspection response (RFC 7662)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicIntrospectionResponse {
    /// Whether the token is active
    pub active: bool,

    /// Scope values associated with the token
    pub scope: Option<String>,

    /// Client identifier
    pub client_id: Option<String>,

    /// Username of the resource owner
    pub username: Option<String>,

    /// Token type
    pub token_type: Option<String>,

    /// Expiration time
    pub exp: Option<i64>,

    /// Issued at time
    pub iat: Option<i64>,

    /// Not before time
    pub nbf: Option<i64>,

    /// Subject
    pub sub: Option<String>,

    /// Audience
    pub aud: Option<Vec<String>>,

    /// Issuer
    pub iss: Option<String>,

    /// Token identifier
    pub jti: Option<String>,

    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, Value>,
}

/// Configuration for JWT introspection responses
#[derive(Debug, Clone)]
pub struct JwtIntrospectionConfig {
    /// Issuer identifier for introspection responses
    pub issuer: String,

    /// Default audience for introspection responses
    pub default_audience: Vec<String>,

    /// Expiration time for introspection responses (seconds)
    pub response_expiration: i64,

    /// Algorithm for signing introspection responses
    pub signing_algorithm: Algorithm,

    /// Whether to include the original token claims
    pub include_token_claims: bool,

    /// Whether to validate the audience in the introspection request
    pub validate_audience: bool,
}

impl Default for JwtIntrospectionConfig {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(),
            default_audience: vec!["https://api.example.com".to_string()],
            response_expiration: 300, // 5 minutes
            signing_algorithm: Algorithm::HS256,
            include_token_claims: true,
            validate_audience: true,
        }
    }
}

/// JWT Token Introspection Manager
pub struct JwtIntrospectionManager {
    config: JwtIntrospectionConfig,
    private_key: EncodingKey,
    public_key: DecodingKey,
}

impl JwtIntrospectionManager {
    /// Create a new JWT introspection manager
    pub fn new(config: JwtIntrospectionConfig) -> Result<Self> {
        // Generate a default key pair for demonstration
        // In production, use proper key management
        let key_bytes = b"introspection_jwt_secret_key_change_in_production";
        let private_key = EncodingKey::from_secret(key_bytes);
        let public_key = DecodingKey::from_secret(key_bytes);

        Ok(Self {
            config,
            private_key,
            public_key,
        })
    }

    /// Create a JWT introspection response from basic introspection data
    pub fn create_jwt_response(
        &self,
        basic_response: BasicIntrospectionResponse,
        audience: Option<Vec<String>>,
        token_jti: Option<String>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.response_expiration);

        let claims = JwtIntrospectionClaims {
            iss: self.config.issuer.clone(),
            aud: audience.unwrap_or_else(|| self.config.default_audience.clone()),
            jti: token_jti.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            sub: basic_response.sub,
            client_id: basic_response.client_id,
            active: basic_response.active,
            token_type: basic_response.token_type,
            scope: basic_response.scope,
            username: basic_response.username,
            token_exp: basic_response.exp,
            token_iat: basic_response.iat,
            token_nbf: basic_response.nbf,
            token_aud: basic_response.aud,
            token_iss: basic_response.iss,
            additional_claims: basic_response.additional_claims,
        };

        let header = Header::new(self.config.signing_algorithm);
        let token = jsonwebtoken::encode(&header, &claims, &self.private_key).map_err(|e| {
            AuthError::crypto(format!(
                "Failed to create JWT introspection response: {}",
                e
            ))
        })?;

        Ok(token)
    }

    /// Verify and parse a JWT introspection response
    pub fn verify_jwt_response(&self, jwt_token: &str) -> Result<JwtIntrospectionClaims> {
        let mut validation = Validation::new(self.config.signing_algorithm);
        validation.set_issuer(&[&self.config.issuer]);

        if self.config.validate_audience {
            validation.set_audience(&self.config.default_audience);
        } else {
            validation.validate_aud = false;
        }

        let token_data = jsonwebtoken::decode::<JwtIntrospectionClaims>(
            jwt_token,
            &self.public_key,
            &validation,
        )
        .map_err(|e| {
            AuthError::crypto(format!(
                "Failed to verify JWT introspection response: {}",
                e
            ))
        })?;

        Ok(token_data.claims)
    }

    /// Create an inactive token response (for expired or invalid tokens)
    pub fn create_inactive_response(
        &self,
        audience: Option<Vec<String>>,
        token_jti: Option<String>,
    ) -> Result<String> {
        let basic_response = BasicIntrospectionResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            additional_claims: HashMap::new(),
        };

        self.create_jwt_response(basic_response, audience, token_jti)
    }

    /// Convert JWT introspection claims back to basic response format
    pub fn jwt_to_basic_response(
        &self,
        claims: &JwtIntrospectionClaims,
    ) -> BasicIntrospectionResponse {
        BasicIntrospectionResponse {
            active: claims.active,
            scope: claims.scope.clone(),
            client_id: claims.client_id.clone(),
            username: claims.username.clone(),
            token_type: claims.token_type.clone(),
            exp: claims.token_exp,
            iat: claims.token_iat,
            nbf: claims.token_nbf,
            sub: claims.sub.clone(),
            aud: claims.token_aud.clone(),
            iss: claims.token_iss.clone(),
            jti: Some(claims.jti.clone()),
            additional_claims: claims.additional_claims.clone(),
        }
    }

    /// Validate introspection request audience
    pub fn validate_request_audience(&self, requested_audience: &[String]) -> bool {
        if !self.config.validate_audience {
            return true;
        }

        // Check if any requested audience is in our allowed audiences
        requested_audience
            .iter()
            .any(|aud| self.config.default_audience.contains(aud))
    }

    /// Get the issuer for introspection responses
    pub fn get_issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Get the default audience
    pub fn get_default_audience(&self) -> &[String] {
        &self.config.default_audience
    }

    /// Create an error response for invalid requests
    pub fn create_error_response(&self, error: &str, error_description: Option<&str>) -> Value {
        let mut response = json!({
            "error": error,
            "active": false
        });

        if let Some(description) = error_description {
            response["error_description"] = json!(description);
        }

        response
    }

    /// Create introspection metadata for discovery
    pub fn create_introspection_metadata(&self) -> Value {
        json!({
            "introspection_endpoint": format!("{}/introspect", self.config.issuer),
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            ],
            "introspection_endpoint_auth_signing_alg_values_supported": [
                "RS256", "RS384", "RS512",
                "ES256", "ES384", "ES512",
                "PS256", "PS384", "PS512"
            ],
            "introspection_signing_alg_values_supported": [
                format!("{:?}", self.config.signing_algorithm)
            ],
            "introspection_response_format": "jwt"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_jwt_introspection_response_creation() {
        let config = JwtIntrospectionConfig::default();
        let manager = JwtIntrospectionManager::new(config).unwrap();

        let basic_response = BasicIntrospectionResponse {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test_client".to_string()),
            username: Some("user123".to_string()),
            token_type: Some("access_token".to_string()),
            exp: Some(Utc::now().timestamp() + 3600),
            iat: Some(Utc::now().timestamp()),
            nbf: None,
            sub: Some("user123".to_string()),
            aud: Some(vec!["https://api.example.com".to_string()]),
            iss: Some("https://auth.example.com".to_string()),
            jti: Some("token123".to_string()),
            additional_claims: HashMap::new(),
        };

        let jwt_response = manager
            .create_jwt_response(
                basic_response,
                Some(vec!["https://api.example.com".to_string()]),
                Some("introspection123".to_string()),
            )
            .unwrap();

        assert!(!jwt_response.is_empty());
        assert!(jwt_response.split('.').count() == 3); // Valid JWT format
    }

    #[test]
    fn test_jwt_introspection_verification() {
        let config = JwtIntrospectionConfig::default();
        let manager = JwtIntrospectionManager::new(config).unwrap();

        let basic_response = BasicIntrospectionResponse {
            active: true,
            scope: Some("read".to_string()),
            client_id: Some("test_client".to_string()),
            username: Some("user123".to_string()),
            token_type: Some("access_token".to_string()),
            exp: Some(Utc::now().timestamp() + 3600),
            iat: Some(Utc::now().timestamp()),
            nbf: None,
            sub: Some("user123".to_string()),
            aud: Some(vec!["https://api.example.com".to_string()]),
            iss: Some("https://auth.example.com".to_string()),
            jti: Some("token123".to_string()),
            additional_claims: HashMap::new(),
        };

        let jwt_response = manager
            .create_jwt_response(basic_response.clone(), None, None)
            .unwrap();

        let verified_claims = manager.verify_jwt_response(&jwt_response).unwrap();

        assert_eq!(verified_claims.active, basic_response.active);
        assert_eq!(verified_claims.scope, basic_response.scope);
        assert_eq!(verified_claims.client_id, basic_response.client_id);
        assert_eq!(verified_claims.username, basic_response.username);
    }

    #[test]
    fn test_inactive_token_response() {
        let config = JwtIntrospectionConfig::default();
        let manager = JwtIntrospectionManager::new(config).unwrap();

        let jwt_response = manager.create_inactive_response(None, None).unwrap();
        let verified_claims = manager.verify_jwt_response(&jwt_response).unwrap();

        assert!(!verified_claims.active);
        assert!(verified_claims.scope.is_none());
        assert!(verified_claims.client_id.is_none());
    }

    #[test]
    fn test_audience_validation() {
        let config = JwtIntrospectionConfig::default();
        let manager = JwtIntrospectionManager::new(config).unwrap();

        let valid_audience = vec!["https://api.example.com".to_string()];
        assert!(manager.validate_request_audience(&valid_audience));

        let invalid_audience = vec!["https://malicious.example.com".to_string()];
        assert!(!manager.validate_request_audience(&invalid_audience));
    }
}


