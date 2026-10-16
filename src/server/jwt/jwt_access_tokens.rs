//! JWT Profile for OAuth 2.0 Access Tokens (RFC 9068)
//!
//! This module implements RFC 9068, which defines how to use JWTs as OAuth 2.0
//! access tokens with standardized claims and validation rules.

use crate::errors::{AuthError, Result};
use crate::tokens::AuthToken;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT Access Token Claims (RFC 9068 compliant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAccessTokenClaims {
    /// Issuer - authorization server identifier
    pub iss: String,

    /// Subject - identifier for the resource owner (user)
    pub sub: String,

    /// Audience - intended recipients of the token
    pub aud: Vec<String>,

    /// Expiration time (seconds since Unix epoch)
    pub exp: i64,

    /// Issued at time (seconds since Unix epoch)
    pub iat: i64,

    /// Not before time (seconds since Unix epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// JWT ID - unique identifier for the token
    pub jti: String,

    /// Client identifier that requested the token
    pub client_id: String,

    /// Space-delimited list of scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Authorization details from RFC 9396
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// Additional claims for specific use cases
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// Authorization Detail structure from RFC 9396
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// Type of authorization detail
    #[serde(rename = "type")]
    pub detail_type: String,

    /// Locations where this authorization applies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,

    /// Actions that are authorized
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,

    /// Data types that can be accessed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,

    /// Identifier for the authorization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    /// Additional detail-specific fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// JWT Access Token Builder for RFC 9068 compliance
#[derive(Clone)]
pub struct JwtAccessTokenBuilder {
    /// JWT signing algorithm
    algorithm: Algorithm,

    /// Encoding key for signing
    encoding_key: EncodingKey,

    /// Issuer identifier
    issuer: String,

    /// Default token lifetime
    default_lifetime: Duration,
}

impl JwtAccessTokenBuilder {
    /// Create a new JWT access token builder
    pub fn new(
        algorithm: Algorithm,
        encoding_key: EncodingKey,
        issuer: String,
        default_lifetime: Duration,
    ) -> Self {
        Self {
            algorithm,
            encoding_key,
            issuer,
            default_lifetime,
        }
    }

    /// Build a JWT access token from auth token
    pub fn build_jwt_access_token(
        &self,
        auth_token: &AuthToken,
        client_id: &str,
        audience: Vec<String>,
        authorization_details: Option<Vec<AuthorizationDetail>>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + self.default_lifetime;

        // Generate unique JWT ID
        let jti = uuid::Uuid::new_v4().to_string();

        // Build scope string from auth token scopes
        let scope = if auth_token.scopes.is_empty() {
            None
        } else {
            Some(auth_token.scopes.join(" "))
        };

        let claims = JwtAccessTokenClaims {
            iss: self.issuer.clone(),
            sub: auth_token.user_id.clone(),
            aud: audience,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()),
            jti,
            client_id: client_id.to_string(),
            scope,
            authorization_details,
            additional_claims: HashMap::new(),
        };

        // Validate claims before signing
        self.validate_claims(&claims)?;

        let header = Header::new(self.algorithm);
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::token(format!("Failed to encode JWT access token: {}", e)))
    }

    /// Validate JWT access token claims for RFC 9068 compliance
    fn validate_claims(&self, claims: &JwtAccessTokenClaims) -> Result<()> {
        // Validate issuer
        if claims.iss.is_empty() {
            return Err(AuthError::token("JWT access token issuer cannot be empty"));
        }

        // Validate subject
        if claims.sub.is_empty() {
            return Err(AuthError::token("JWT access token subject cannot be empty"));
        }

        // Validate audience
        if claims.aud.is_empty() {
            return Err(AuthError::token(
                "JWT access token audience cannot be empty",
            ));
        }

        // Validate client_id
        if claims.client_id.is_empty() {
            return Err(AuthError::token(
                "JWT access token client_id cannot be empty",
            ));
        }

        // Validate expiration is in the future
        let now = Utc::now().timestamp();
        if claims.exp <= now {
            return Err(AuthError::token(
                "JWT access token expiration must be in the future",
            ));
        }

        // Validate issued at is not in the future
        if claims.iat > now + 60 {
            // Allow 60 second clock skew
            return Err(AuthError::token(
                "JWT access token issued at cannot be in the future",
            ));
        }

        // Validate not before if present
        if let Some(nbf) = claims.nbf
            && nbf > claims.exp
        {
            return Err(AuthError::token(
                "JWT access token not before cannot be after expiration",
            ));
        }

        // Validate JWT ID is not empty
        if claims.jti.is_empty() {
            return Err(AuthError::token("JWT access token JTI cannot be empty"));
        }

        // Validate authorization details if present
        if let Some(ref details) = claims.authorization_details {
            self.validate_authorization_details(details)?;
        }

        Ok(())
    }

    /// Validate authorization details structure
    fn validate_authorization_details(&self, details: &[AuthorizationDetail]) -> Result<()> {
        for detail in details {
            if detail.detail_type.is_empty() {
                return Err(AuthError::token(
                    "Authorization detail type cannot be empty",
                ));
            }

            // Additional validation can be added based on specific authorization detail types
        }
        Ok(())
    }
}

/// JWT Access Token Validator for RFC 9068 compliance
#[derive(Clone)]
pub struct JwtAccessTokenValidator {
    /// JWT validation configuration
    validation: Validation,

    /// Decoding key for verification
    decoding_key: DecodingKey,

    /// Expected issuer
    expected_issuer: String,
}

impl JwtAccessTokenValidator {
    /// Create a new JWT access token validator
    pub fn new(algorithm: Algorithm, decoding_key: DecodingKey, expected_issuer: String) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&expected_issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Disable audience validation in jsonwebtoken as we handle it manually
        validation.validate_aud = false;

        Self {
            validation,
            decoding_key,
            expected_issuer,
        }
    }

    /// Validate a JWT access token and extract claims
    pub fn validate_jwt_access_token(&self, token: &str) -> Result<JwtAccessTokenClaims> {
        let token_data = jsonwebtoken::decode::<JwtAccessTokenClaims>(
            token,
            &self.decoding_key,
            &self.validation,
        )
        .map_err(|e| AuthError::token(format!("Invalid JWT access token: {}", e)))?;

        let claims = token_data.claims;

        // Additional RFC 9068 specific validations
        self.validate_rfc9068_compliance(&claims)?;

        Ok(claims)
    }

    /// Validate RFC 9068 specific requirements
    fn validate_rfc9068_compliance(&self, claims: &JwtAccessTokenClaims) -> Result<()> {
        // Verify required claims are present
        if claims.iss != self.expected_issuer {
            return Err(AuthError::token(format!(
                "JWT access token issuer mismatch: expected {}, got {}",
                self.expected_issuer, claims.iss
            )));
        }

        // Verify client_id is present (required by RFC 9068)
        if claims.client_id.is_empty() {
            return Err(AuthError::token(
                "JWT access token missing required client_id claim",
            ));
        }

        // Verify jti is present (required by RFC 9068)
        if claims.jti.is_empty() {
            return Err(AuthError::token(
                "JWT access token missing required jti claim",
            ));
        }

        // Additional security validations
        let now = Utc::now().timestamp();

        // Check token is not expired
        if claims.exp <= now {
            return Err(AuthError::token("JWT access token has expired"));
        }

        // Check token is valid now (nbf check)
        if let Some(nbf) = claims.nbf
            && nbf > now
        {
            return Err(AuthError::token("JWT access token not yet valid"));
        }

        Ok(())
    }

    /// Extract scope list from JWT access token claims
    pub fn extract_scopes(&self, claims: &JwtAccessTokenClaims) -> Vec<String> {
        claims
            .scope
            .as_ref()
            .map(|s| {
                s.split_whitespace()
                    .map(|scope| scope.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if JWT access token has specific scope
    pub fn has_scope(&self, claims: &JwtAccessTokenClaims, required_scope: &str) -> bool {
        self.extract_scopes(claims)
            .contains(&required_scope.to_string())
    }

    /// Validate audience claim against expected audiences
    pub fn validate_audience(
        &self,
        claims: &JwtAccessTokenClaims,
        expected_audiences: &[String],
    ) -> Result<()> {
        for expected in expected_audiences {
            if claims.aud.contains(expected) {
                return Ok(());
            }
        }

        Err(AuthError::token(format!(
            "JWT access token audience validation failed: expected one of {:?}, got {:?}",
            expected_audiences, claims.aud
        )))
    }
}

/// Introspection response for JWT access tokens (RFC 7662 + RFC 9068)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAccessTokenIntrospectionResponse {
    /// Whether the token is active
    pub active: bool,

    /// Space-delimited list of scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Client identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Subject identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Token expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Token issued at time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Token not before time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Intended audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,

    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Authorization details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
}

impl From<JwtAccessTokenClaims> for JwtAccessTokenIntrospectionResponse {
    fn from(claims: JwtAccessTokenClaims) -> Self {
        Self {
            active: true,
            scope: claims.scope,
            client_id: Some(claims.client_id),
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: claims.nbf,
            aud: Some(claims.aud),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
            authorization_details: claims.authorization_details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

    fn create_test_keys() -> (EncodingKey, DecodingKey) {
        let secret = b"test-secret-key-32-bytes-minimum!";
        (
            EncodingKey::from_secret(secret),
            DecodingKey::from_secret(secret),
        )
    }

    fn create_test_auth_token() -> AuthToken {
        AuthToken {
            token_id: "test-token-id".to_string(),
            user_id: "test-user".to_string(),
            access_token: "test-access-token".to_string(),
            token_type: Some("Bearer".to_string()),
            subject: None,
            issuer: None,
            refresh_token: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "test".to_string(),
            client_id: None,
            user_profile: None,
            permissions: vec!["test:read".to_string(), "test:write".to_string()],
            roles: vec!["user".to_string()],
            metadata: Default::default(),
        }
    }

    #[test]
    fn test_jwt_access_token_creation() {
        let (encoding_key, _) = create_test_keys();
        let builder = JwtAccessTokenBuilder::new(
            Algorithm::HS256,
            encoding_key,
            "https://auth.example.com".to_string(),
            Duration::hours(1),
        );

        let auth_token = create_test_auth_token();
        let audience = vec!["https://api.example.com".to_string()];

        let jwt = builder
            .build_jwt_access_token(&auth_token, "test-client-id", audience, None)
            .unwrap();

        assert!(!jwt.is_empty());
        assert!(jwt.split('.').count() == 3); // Header.Payload.Signature
    }

    #[test]
    fn test_jwt_access_token_validation() {
        let (encoding_key, decoding_key) = create_test_keys();
        let issuer = "https://auth.example.com".to_string();

        let builder = JwtAccessTokenBuilder::new(
            Algorithm::HS256,
            encoding_key,
            issuer.clone(),
            Duration::hours(1),
        );

        let validator = JwtAccessTokenValidator::new(Algorithm::HS256, decoding_key, issuer);

        let auth_token = create_test_auth_token();
        let audience = vec!["https://api.example.com".to_string()];

        let jwt = builder
            .build_jwt_access_token(&auth_token, "test-client-id", audience.clone(), None)
            .unwrap();

        let claims = validator.validate_jwt_access_token(&jwt).unwrap();

        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.client_id, "test-client-id");
        assert_eq!(claims.aud, audience);
        assert!(claims.scope.is_some());
        assert_eq!(claims.scope.unwrap(), "read write");
    }

    #[test]
    fn test_scope_validation() {
        let (encoding_key, decoding_key) = create_test_keys();
        let issuer = "https://auth.example.com".to_string();

        let builder = JwtAccessTokenBuilder::new(
            Algorithm::HS256,
            encoding_key,
            issuer.clone(),
            Duration::hours(1),
        );

        let validator = JwtAccessTokenValidator::new(Algorithm::HS256, decoding_key, issuer);

        let auth_token = create_test_auth_token();
        let audience = vec!["https://api.example.com".to_string()];

        let jwt = builder
            .build_jwt_access_token(&auth_token, "test-client-id", audience, None)
            .unwrap();

        let claims = validator.validate_jwt_access_token(&jwt).unwrap();

        assert!(validator.has_scope(&claims, "read"));
        assert!(validator.has_scope(&claims, "write"));
        assert!(!validator.has_scope(&claims, "admin"));
    }

    #[test]
    fn test_authorization_details() {
        let (encoding_key, decoding_key) = create_test_keys();
        let issuer = "https://auth.example.com".to_string();

        let builder = JwtAccessTokenBuilder::new(
            Algorithm::HS256,
            encoding_key,
            issuer.clone(),
            Duration::hours(1),
        );

        let validator = JwtAccessTokenValidator::new(Algorithm::HS256, decoding_key, issuer);

        let auth_token = create_test_auth_token();
        let audience = vec!["https://api.example.com".to_string()];

        let authorization_details = vec![AuthorizationDetail {
            detail_type: "account_information".to_string(),
            locations: Some(vec!["https://api.example.com/accounts".to_string()]),
            actions: Some(vec!["read".to_string()]),
            datatypes: Some(vec!["account_balance".to_string()]),
            identifier: Some("account-123".to_string()),
            additional_fields: HashMap::new(),
        }];

        let jwt = builder
            .build_jwt_access_token(
                &auth_token,
                "test-client-id",
                audience,
                Some(authorization_details.clone()),
            )
            .unwrap();

        let claims = validator.validate_jwt_access_token(&jwt).unwrap();

        assert!(claims.authorization_details.is_some());
        let details = claims.authorization_details.unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].detail_type, "account_information");
    }

    #[test]
    fn test_invalid_claims_validation() {
        let (encoding_key, _) = create_test_keys();
        let builder = JwtAccessTokenBuilder::new(
            Algorithm::HS256,
            encoding_key,
            "https://auth.example.com".to_string(),
            Duration::hours(1),
        );

        // Test empty subject
        let mut claims = JwtAccessTokenClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "".to_string(), // Invalid empty subject
            aud: vec!["https://api.example.com".to_string()],
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            nbf: Some(Utc::now().timestamp()),
            jti: "test-jti".to_string(),
            client_id: "test-client".to_string(),
            scope: None,
            authorization_details: None,
            additional_claims: HashMap::new(),
        };

        assert!(builder.validate_claims(&claims).is_err());

        // Test empty audience
        claims.sub = "test-user".to_string();
        claims.aud = vec![]; // Invalid empty audience

        assert!(builder.validate_claims(&claims).is_err());
    }

    #[test]
    fn test_introspection_response() {
        let claims = JwtAccessTokenClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "test-user".to_string(),
            aud: vec!["https://api.example.com".to_string()],
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            nbf: Some(Utc::now().timestamp()),
            jti: "test-jti".to_string(),
            client_id: "test-client".to_string(),
            scope: Some("read write".to_string()),
            authorization_details: None,
            additional_claims: HashMap::new(),
        };

        let response = JwtAccessTokenIntrospectionResponse::from(claims);

        assert!(response.active);
        assert_eq!(response.client_id.unwrap(), "test-client");
        assert_eq!(response.sub.unwrap(), "test-user");
        assert_eq!(response.scope.unwrap(), "read write");
    }
}
