//! Token management and validation for the authentication framework.

use crate::errors::{AuthError, Result, TokenError};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Represents an authentication token with all associated metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Unique token identifier
    pub token_id: String,
    
    /// User identifier this token belongs to
    pub user_id: String,
    
    /// The actual token string (JWT, opaque token, etc.)
    pub access_token: String,
    
    /// Optional refresh token
    pub refresh_token: Option<String>,
    
    /// Token type (Bearer, etc.)
    pub token_type: String,
    
    /// When the token was issued
    pub issued_at: DateTime<Utc>,
    
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    
    /// Scopes granted to this token
    pub scopes: Vec<String>,
    
    /// Authentication method used to obtain this token
    pub auth_method: String,
    
    /// Client ID that requested this token
    pub client_id: Option<String>,
    
    /// Additional token metadata
    pub metadata: TokenMetadata,
}

/// Additional metadata that can be attached to tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct TokenMetadata {
    /// IP address where the token was issued
    pub issued_ip: Option<String>,
    
    /// User agent of the client
    pub user_agent: Option<String>,
    
    /// Device identifier
    pub device_id: Option<String>,
    
    /// Session identifier
    pub session_id: Option<String>,
    
    /// Whether this token has been revoked
    pub revoked: bool,
    
    /// When the token was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
    
    /// Reason for revocation
    pub revoked_reason: Option<String>,
    
    /// Last time this token was used
    pub last_used: Option<DateTime<Utc>>,
    
    /// Number of times this token has been used
    pub use_count: u64,
    
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

/// Information about a user extracted from a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// User identifier
    pub user_id: String,
    
    /// Username or email
    pub username: Option<String>,
    
    /// User's email address
    pub email: Option<String>,
    
    /// User's display name
    pub name: Option<String>,
    
    /// User's roles
    pub roles: Vec<String>,
    
    /// User's permissions
    pub permissions: Vec<String>,
    
    /// Additional user attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

/// JWT claims structure used internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: String,
    
    /// Issuer
    pub iss: String,
    
    /// Audience
    pub aud: String,
    
    /// Expiration time
    pub exp: i64,
    
    /// Issued at
    pub iat: i64,
    
    /// Not before
    pub nbf: i64,
    
    /// JWT ID
    pub jti: String,
    
    /// Scopes
    pub scope: String,
    
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Token manager for creating, validating, and managing tokens.
pub struct TokenManager {
    /// JWT encoding key
    encoding_key: EncodingKey,
    
    /// JWT decoding key
    decoding_key: DecodingKey,
    
    /// JWT algorithm
    algorithm: Algorithm,
    
    /// Token issuer
    issuer: String,
    
    /// Token audience
    audience: String,
    
    /// Default token lifetime
    default_lifetime: Duration,
}


impl AuthToken {
    /// Create a new authentication token.
    pub fn new(
        user_id: impl Into<String>,
        access_token: impl Into<String>,
        expires_in: std::time::Duration,
        auth_method: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let expires_in_chrono = chrono::Duration::from_std(expires_in).unwrap_or(chrono::Duration::hours(1));
        
        Self {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            access_token: access_token.into(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            issued_at: now,
            expires_at: now + expires_in_chrono,
            scopes: Vec::new(),
            auth_method: auth_method.into(),
            client_id: None,
            metadata: TokenMetadata::default(),
        }
    }

    /// Get the access token string.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Get the user ID.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get the expiration time.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Check if the token has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the token is expiring within the given duration.
    pub fn is_expiring(&self, within: Duration) -> bool {
        Utc::now() + within > self.expires_at
    }

    /// Check if the token has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.metadata.revoked
    }

    /// Check if the token is valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }

    /// Revoke the token.
    pub fn revoke(&mut self, reason: Option<String>) {
        self.metadata.revoked = true;
        self.metadata.revoked_at = Some(Utc::now());
        self.metadata.revoked_reason = reason;
    }

    /// Update the last used time and increment use count.
    pub fn mark_used(&mut self) {
        self.metadata.last_used = Some(Utc::now());
        self.metadata.use_count += 1;
    }

    /// Add a scope to the token.
    pub fn add_scope(&mut self, scope: impl Into<String>) {
        let scope = scope.into();
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
        }
    }

    /// Check if the token has a specific scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }

    /// Set the refresh token.
    pub fn with_refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
        self
    }

    /// Set the client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the token scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Add metadata to the token.
    pub fn with_metadata(mut self, metadata: TokenMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Get time until expiration.
    pub fn time_until_expiry(&self) -> Duration {
        let now = Utc::now();
        if self.expires_at > now {
            (self.expires_at - now).to_std().unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        }
    }
}

impl TokenManager {
    /// Create a new token manager with HMAC key.
    pub fn new_hmac(secret: &[u8], issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
            issuer: issuer.into(),
            audience: audience.into(),
            default_lifetime: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Create a new token manager with RSA keys.
    pub fn new_rsa(
        private_key: &[u8],
        public_key: &[u8],
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key)
            .map_err(|e| AuthError::crypto(format!("Invalid RSA private key: {e}")))?;
        
        let decoding_key = DecodingKey::from_rsa_pem(public_key)
            .map_err(|e| AuthError::crypto(format!("Invalid RSA public key: {e}")))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            algorithm: Algorithm::RS256,
            issuer: issuer.into(),
            audience: audience.into(),
            default_lifetime: Duration::from_secs(3600), // 1 hour
        })
    }

    /// Set the default token lifetime.
    pub fn with_default_lifetime(mut self, lifetime: Duration) -> Self {
        self.default_lifetime = lifetime;
        self
    }

    /// Create a new JWT token.
    pub fn create_jwt_token(
        &self,
        user_id: impl Into<String>,
        scopes: Vec<String>,
        lifetime: Option<Duration>,
    ) -> Result<String> {
        let user_id = user_id.into();
        let lifetime = lifetime.unwrap_or(self.default_lifetime);
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(lifetime).unwrap_or(chrono::Duration::hours(1));

        let claims = JwtClaims {
            sub: user_id,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            scope: scopes.join(" "),
            custom: HashMap::new(),
        };

        let header = Header::new(self.algorithm);
        
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| TokenError::creation_failed(format!("JWT encoding failed: {e}")).into())
    }

    /// Validate and decode a JWT token.
    pub fn validate_jwt_token(&self, token: &str) -> Result<JwtClaims> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Token(TokenError::Expired),
                _ => AuthError::Token(TokenError::Invalid),
            })?;

        Ok(token_data.claims)
    }

    /// Create a complete authentication token with JWT.
    pub fn create_auth_token(
        &self,
        user_id: impl Into<String>,
        scopes: Vec<String>,
        auth_method: impl Into<String>,
        lifetime: Option<std::time::Duration>,
    ) -> Result<AuthToken> {
        let user_id_str = user_id.into();
        let lifetime = lifetime.unwrap_or(self.default_lifetime);
        
        let jwt_token = self.create_jwt_token(&user_id_str, scopes.clone(), Some(lifetime))?;
        
        let token = AuthToken::new(user_id_str, jwt_token, lifetime, auth_method)
            .with_scopes(scopes);

        Ok(token)
    }

    /// Validate an authentication token.
    pub fn validate_auth_token(&self, token: &AuthToken) -> Result<()> {
        // Check if token is expired
        if token.is_expired() {
            return Err(TokenError::Expired.into());
        }

        // Check if token is revoked
        if token.is_revoked() {
            return Err(TokenError::Invalid.into());
        }

        // Validate JWT if it's a JWT token
        if token.auth_method == "jwt" || token.access_token.contains('.') {
            self.validate_jwt_token(&token.access_token)?;
        }

        Ok(())
    }

    /// Refresh a token (create a new one with extended lifetime).
    pub fn refresh_token(&self, token: &AuthToken) -> Result<AuthToken> {
        if token.is_expired() {
            return Err(TokenError::Expired.into());
        }

        if token.is_revoked() {
            return Err(TokenError::Invalid.into());
        }

        // Create a new token with the same properties but new expiry
        self.create_auth_token(
            &token.user_id,
            token.scopes.clone(),
            &token.auth_method,
            Some(self.default_lifetime),
        )
    }

    /// Extract token information from a JWT.
    pub fn extract_token_info(&self, token: &str) -> Result<TokenInfo> {
        let claims = self.validate_jwt_token(token)?;
        
        Ok(TokenInfo {
            user_id: claims.sub,
            username: claims.custom.get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            email: claims.custom.get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            name: claims.custom.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            roles: claims.custom.get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect())
                .unwrap_or_default(),
            permissions: claims.scope.split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            attributes: claims.custom,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_creation() {
        let token = AuthToken::new(
            "user123",
            "token123",
            Duration::from_secs(3600), // 1 hour
            "password"
        );

        assert_eq!(token.user_id(), "user123");
        assert_eq!(token.access_token(), "token123");
        assert!(!token.is_expired());
        assert!(!token.is_revoked());
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_expiry() {
        let token = AuthToken::new(
            "user123",
            "token123",
            Duration::from_millis(1),
            "password"
        );

        // Wait a bit to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_revocation() {
        let mut token = AuthToken::new(
            "user123",
            "token123",
            Duration::from_secs(3600), // 1 hour
            "password"
        );

        assert!(!token.is_revoked());
        
        token.revoke(Some("User logout".to_string()));
        
        assert!(token.is_revoked());
        assert!(!token.is_valid());
        assert_eq!(token.metadata.revoked_reason, Some("User logout".to_string()));
    }

    #[tokio::test]
    async fn test_jwt_token_manager() {
        let secret = b"test-secret-key";
        let manager = TokenManager::new_hmac(secret, "test-issuer", "test-audience");

        let token = manager.create_jwt_token(
            "user123",
            vec!["read".to_string(), "write".to_string()],
            Some(Duration::from_secs(3600)) // 1 hour
        ).unwrap();

        let claims = manager.validate_jwt_token(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.scope, "read write");
    }
}
