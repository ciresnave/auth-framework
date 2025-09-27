//! Token management and validation for the authentication framework.
use crate::errors::{AuthError, Result, TokenError};
use crate::providers::{OAuthProvider, ProfileExtractor, UserProfile};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "postgres-storage")]
use sqlx::FromRow;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Represents an authentication token with all associated metadata.
#[cfg_attr(feature = "postgres-storage", derive(FromRow))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Unique token identifier
    pub token_id: String,

    /// User identifier this token belongs to
    pub user_id: String,

    /// Access token value
    pub access_token: String,

    /// Token type (e.g., "bearer")
    pub token_type: Option<String>,

    /// Subject claim
    pub subject: Option<String>,

    /// Token issuer
    pub issuer: Option<String>,

    /// Optional refresh token
    pub refresh_token: Option<String>,

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

    /// User profile data (optional)
    pub user_profile: Option<UserProfile>,

    /// User's permissions
    pub permissions: Vec<String>,

    /// User's roles
    pub roles: Vec<String>,

    /// Additional token metadata
    pub metadata: TokenMetadata,
}

/// Additional metadata that can be attached to tokens.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[cfg(feature = "postgres-storage")]
use sqlx::{Decode, Postgres, Type, postgres::PgValueRef};

#[cfg(feature = "postgres-storage")]
impl<'r> Decode<'r, Postgres> for TokenMetadata {
    fn decode(value: PgValueRef<'r>) -> std::result::Result<Self, sqlx::error::BoxDynError> {
        let json: serde_json::Value = <serde_json::Value as Decode<Postgres>>::decode(value)?;
        serde_json::from_value(json).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

#[cfg(feature = "postgres-storage")]
impl Type<Postgres> for TokenMetadata {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <serde_json::Value as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <serde_json::Value as Type<Postgres>>::compatible(ty)
    }
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

    /// User permissions
    pub permissions: Option<Vec<String>>,

    /// User roles
    pub roles: Option<Vec<String>>,

    /// Client ID
    pub client_id: Option<String>,

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

    /// Key material for recreating keys during clone
    key_material: KeyMaterial,

    /// JWT algorithm
    algorithm: Algorithm,

    /// Token issuer
    issuer: String,

    /// Token audience
    audience: String,

    /// Default token lifetime
    default_lifetime: Duration,
}

/// Key material for cloning TokenManager
#[derive(Clone)]
enum KeyMaterial {
    /// HMAC secret
    Hmac(Vec<u8>),
    /// RSA private and public keys
    Rsa { private: Vec<u8>, public: Vec<u8> },
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
        let expires_in_chrono =
            chrono::Duration::from_std(expires_in).unwrap_or(chrono::Duration::hours(1));

        Self {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            access_token: access_token.into(),
            refresh_token: None,
            token_type: Some("Bearer".to_string()),
            subject: None,
            issuer: None,
            issued_at: now,
            expires_at: now + expires_in_chrono,
            scopes: Vec::new(),
            auth_method: auth_method.into(),
            client_id: None,
            user_profile: None,
            permissions: Vec::new(),
            roles: Vec::new(),
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

    /// Get the token value
    pub fn token_value(&self) -> &str {
        &self.access_token
    }

    /// Get the token type
    pub fn token_type(&self) -> Option<&str> {
        self.token_type.as_deref()
    }

    /// Get the subject claim
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Get the issuer
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
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

    /// Add a custom claim to the token metadata
    pub fn add_custom_claim(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.custom.insert(key.into(), value);
    }

    /// Get a custom claim from the token metadata
    pub fn get_custom_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.custom.get(key)
    }

    /// Check if the token has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Add a permission to the token
    pub fn add_permission(&mut self, permission: impl Into<String>) {
        let permission = permission.into();
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
    }

    /// Add a role to the token
    pub fn add_role(&mut self, role: impl Into<String>) {
        let role = role.into();
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    /// Check if the token has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Set the permissions
    pub fn with_permissions(mut self, permissions: Vec<String>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set the roles
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }
}

impl Clone for TokenManager {
    fn clone(&self) -> Self {
        match &self.key_material {
            KeyMaterial::Hmac(secret) => Self {
                encoding_key: EncodingKey::from_secret(secret),
                decoding_key: DecodingKey::from_secret(secret),
                key_material: self.key_material.clone(),
                algorithm: self.algorithm,
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                default_lifetime: self.default_lifetime,
            },
            KeyMaterial::Rsa { private, public } => Self {
                encoding_key: EncodingKey::from_rsa_pem(private).expect("Valid RSA private key"),
                decoding_key: DecodingKey::from_rsa_pem(public).expect("Valid RSA public key"),
                key_material: self.key_material.clone(),
                algorithm: self.algorithm,
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                default_lifetime: self.default_lifetime,
            },
        }
    }
}

impl TokenManager {
    /// Create a new token manager with HMAC key.
    pub fn new_hmac(secret: &[u8], issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            key_material: KeyMaterial::Hmac(secret.to_vec()),
            algorithm: Algorithm::HS256,
            issuer: issuer.into(),
            audience: audience.into(),
            default_lifetime: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Create a new token manager with RSA keys.
    ///
    /// ## RSA Key Format Support
    ///
    /// This method supports RSA keys in both standard PEM formats:
    /// - **PKCS#1**: `-----BEGIN RSA PRIVATE KEY-----` (traditional RSA format)
    /// - **PKCS#8**: `-----BEGIN PRIVATE KEY-----` (modern standard format, recommended)
    ///
    /// Both formats are automatically detected and parsed. No format conversion is required.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// use auth_framework::tokens::TokenManager;
    ///
    /// // Both PKCS#1 and PKCS#8 formats work
    /// let private_key = include_bytes!("../../private.pem");  // Either format  
    /// let public_key = include_bytes!("../../public.pem");
    ///
    /// let manager = TokenManager::new_rsa(
    ///     private_key,
    ///     public_key,
    ///     "my-service",
    ///     "my-audience"
    /// )?;
    /// # Ok::<(), auth_framework::errors::AuthError>(())
    /// ```
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
            key_material: KeyMaterial::Rsa {
                private: private_key.to_vec(),
                public: public_key.to_vec(),
            },
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
            permissions: None,
            roles: None,
            client_id: None,
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

        let token_data =
            decode::<JwtClaims>(token, &self.decoding_key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        AuthError::Token(TokenError::Expired)
                    }
                    _ => AuthError::Token(TokenError::Invalid {
                        message: "Invalid token format".to_string(),
                    }),
                }
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

        let token =
            AuthToken::new(user_id_str, jwt_token, lifetime, auth_method).with_scopes(scopes);

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
            return Err(TokenError::Invalid {
                message: "Token has been revoked".to_string(),
            }
            .into());
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
            return Err(TokenError::Invalid {
                message: "Cannot refresh revoked token".to_string(),
            }
            .into());
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
            username: claims
                .custom
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            email: claims
                .custom
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            name: claims
                .custom
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            roles: claims
                .custom
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default(),
            permissions: claims
                .scope
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            attributes: claims.custom,
        })
    }
}

/// Trait for converting tokens to user profiles
#[async_trait::async_trait]
pub trait TokenToProfile {
    /// Convert this token to a user profile using the specified provider
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<UserProfile>;

    /// Convert this token to a user profile with a custom extractor
    async fn to_profile_with_extractor(
        &self,
        provider: &OAuthProvider,
        extractor: &ProfileExtractor,
    ) -> Result<UserProfile>;
}

#[async_trait::async_trait]
impl TokenToProfile for AuthToken {
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<UserProfile> {
        let extractor = ProfileExtractor::new();
        extractor.extract_profile(self, provider).await
    }

    async fn to_profile_with_extractor(
        &self,
        provider: &OAuthProvider,
        extractor: &ProfileExtractor,
    ) -> Result<UserProfile> {
        extractor.extract_profile(self, provider).await
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
            "password",
        );

        assert_eq!(token.user_id(), "user123");
        assert_eq!(token.access_token(), "token123");
        assert!(!token.is_expired());
        assert!(!token.is_revoked());
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_expiry() {
        let token = AuthToken::new("user123", "token123", Duration::from_millis(1), "password");

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
            "password",
        );

        assert!(!token.is_revoked());

        token.revoke(Some("User logout".to_string()));

        assert!(token.is_revoked());
        assert!(!token.is_valid());
        assert!(token.metadata.revoked);
    }
}
