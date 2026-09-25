//! Token management and validation for the authentication framework.
use crate::errors::{AuthError, Result, TokenError};
use crate::providers::{OAuthProvider, ProfileExtractor, ProviderProfile};
#[cfg(feature = "rsa-verify")]
use base64::Engine as _;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
#[cfg(feature = "rsa-verify")]
use rsa::pkcs1::DecodeRsaPublicKey;
#[cfg(feature = "rsa-verify")]
use rsa::pkcs8::DecodePublicKey;
#[cfg(feature = "rsa-verify")]
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
#[cfg(feature = "rsa-verify")]
use sha2::{Digest, Sha256};
#[cfg(feature = "postgres-storage")]
use sqlx::FromRow;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// An issued authentication token with all associated metadata.
///
/// Created by [`TokenManager`] and returned from
/// [`AuthFramework::authenticate`](crate::auth::AuthFramework::authenticate).
/// Contains the encoded `access_token` string, optional `refresh_token`,
/// granted scopes, and contextual [`TokenMetadata`].
#[cfg_attr(feature = "postgres-storage", derive(FromRow))]
#[derive(Clone, Serialize, Deserialize)]
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
    pub scopes: crate::types::Scopes,

    /// Authentication method used to obtain this token
    pub auth_method: String,

    /// Client ID that requested this token
    pub client_id: Option<String>,

    /// User profile data (optional)
    pub user_profile: Option<ProviderProfile>,

    /// User's permissions
    pub permissions: crate::types::Permissions,

    /// User's roles
    pub roles: crate::types::Roles,

    /// Additional token metadata
    pub metadata: TokenMetadata,
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthToken")
            .field("token_id", &self.token_id)
            .field("user_id", &self.user_id)
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field(
                "refresh_token",
                if self.refresh_token.is_some() {
                    &"Some([REDACTED])"
                } else {
                    &"None"
                },
            )
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("auth_method", &self.auth_method)
            .field("client_id", &self.client_id)
            .field("permissions", &self.permissions)
            .field("roles", &self.roles)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Builder for creating `AuthToken` instances with fluent API.
///
/// Reduces cognitive load when constructing tokens with many optional fields.
/// Required fields are set in `new()`, optional fields via builder methods.
///
/// # Example
///
/// ```rust
/// use auth_framework::tokens::{AuthToken, TokenMetadata};
/// use auth_framework::types::{Scopes, Permissions, Roles};
/// use chrono::{Utc, Duration};
///
/// let token = AuthToken::builder("user123", "token456", "access_token_here")
///     .scopes(Scopes::new(vec!["read".to_string(), "write".to_string()]))
///     .permissions(Permissions::new(vec!["admin".to_string()]))
///     .roles(Roles::new(vec!["user".to_string()]))
///     .expires_at(Utc::now() + Duration::hours(1))
///     .client_id("client123")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AuthTokenBuilder {
    token_id: String,
    user_id: String,
    access_token: String,
    token_type: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    refresh_token: Option<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    scopes: crate::types::Scopes,
    auth_method: String,
    client_id: Option<String>,
    user_profile: Option<ProviderProfile>,
    permissions: crate::types::Permissions,
    roles: crate::types::Roles,
    metadata: TokenMetadata,
}

impl AuthTokenBuilder {
    /// Create a new builder with required fields.
    ///
    /// Sets sensible defaults for optional fields:
    /// - `issued_at`: current time
    /// - `expires_at`: 1 hour from now
    /// - `scopes`, `permissions`, `roles`: empty collections
    /// - `auth_method`: "unknown"
    /// - `metadata`: default (empty)
    pub fn new(
        token_id: impl Into<String>,
        user_id: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            token_id: token_id.into(),
            user_id: user_id.into(),
            access_token: access_token.into(),
            token_type: None,
            subject: None,
            issuer: None,
            refresh_token: None,
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            scopes: crate::types::Scopes::empty(),
            auth_method: "unknown".to_string(),
            client_id: None,
            user_profile: None,
            permissions: crate::types::Permissions::empty(),
            roles: crate::types::Roles::empty(),
            metadata: TokenMetadata::default(),
        }
    }

    /// Set the token type (e.g., "bearer").
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .token_type("bearer")
    ///     .build();
    /// assert_eq!(token.token_type.as_deref(), Some("bearer"));
    /// ```
    pub fn token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }

    /// Set the subject claim.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .subject("user@example.com")
    ///     .build();
    /// assert_eq!(token.subject.as_deref(), Some("user@example.com"));
    /// ```
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the token issuer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .issuer("auth.example.com")
    ///     .build();
    /// assert_eq!(token.issuer.as_deref(), Some("auth.example.com"));
    /// ```
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the refresh token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .refresh_token("refresh_token_value")
    ///     .build();
    /// assert!(token.refresh_token.is_some());
    /// ```
    pub fn refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
        self
    }

    /// Set the issued timestamp.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use chrono::Utc;
    ///
    /// let now = Utc::now();
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .issued_at(now)
    ///     .build();
    /// assert_eq!(token.issued_at, now);
    /// ```
    pub fn issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.issued_at = issued_at;
        self
    }

    /// Set the expiration timestamp.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use chrono::{Utc, Duration};
    ///
    /// let expires = Utc::now() + Duration::hours(2);
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .expires_at(expires)
    ///     .build();
    /// ```
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set the granted scopes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Scopes;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .scopes(Scopes::new(vec!["read".into(), "write".into()]))
    ///     .build();
    /// ```
    pub fn scopes(mut self, scopes: crate::types::Scopes) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set the authentication method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .auth_method("password")
    ///     .build();
    /// assert_eq!(token.auth_method, "password");
    /// ```
    pub fn auth_method(mut self, auth_method: impl Into<String>) -> Self {
        self.auth_method = auth_method.into();
        self
    }

    /// Set the client ID.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .client_id("client-app")
    ///     .build();
    /// assert_eq!(token.client_id.as_deref(), Some("client-app"));
    /// ```
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the user profile.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::providers::ProviderProfile;
    ///
    /// let profile = ProviderProfile { /* ... */ };
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .user_profile(profile)
    ///     .build();
    /// ```
    pub fn user_profile(mut self, user_profile: ProviderProfile) -> Self {
        self.user_profile = Some(user_profile);
        self
    }

    /// Set the user permissions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Permissions;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .permissions(Permissions::new(vec!["admin".into()]))
    ///     .build();
    /// ```
    pub fn permissions(mut self, permissions: crate::types::Permissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set the user roles.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Roles;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .roles(Roles::new(vec!["editor".into()]))
    ///     .build();
    /// ```
    pub fn roles(mut self, roles: crate::types::Roles) -> Self {
        self.roles = roles;
        self
    }

    /// Set the token metadata.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::{AuthToken, TokenMetadata};
    ///
    /// let meta = TokenMetadata::builder().issued_ip("10.0.0.1").build();
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .metadata(meta)
    ///     .build();
    /// ```
    pub fn metadata(mut self, metadata: TokenMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Build the `AuthToken` instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert_eq!(token.user_id, "u1");
    /// ```
    pub fn build(self) -> AuthToken {
        AuthToken {
            token_id: self.token_id,
            user_id: self.user_id,
            access_token: self.access_token,
            token_type: self.token_type,
            subject: self.subject,
            issuer: self.issuer,
            refresh_token: self.refresh_token,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            scopes: self.scopes,
            auth_method: self.auth_method,
            client_id: self.client_id,
            user_profile: self.user_profile,
            permissions: self.permissions,
            roles: self.roles,
            metadata: self.metadata,
        }
    }
}

impl AuthToken {
    /// Start building an `AuthToken` with fluent setters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("token123", "user456", "access_token")
    ///     .expires_at(chrono::Utc::now() + chrono::Duration::hours(2))
    ///     .build();
    /// ```
    pub fn builder(
        token_id: impl Into<String>,
        user_id: impl Into<String>,
        access_token: impl Into<String>,
    ) -> AuthTokenBuilder {
        AuthTokenBuilder::new(token_id, user_id, access_token)
    }
}

/// Contextual information attached to a token at issuance time.
///
/// Tracks revocation state, usage counters, and client fingerprints
/// (IP, user-agent, device).  Defaults to an empty / non-revoked state.
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

impl TokenMetadata {
    /// Start building a `TokenMetadata` with fluent setters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    /// let meta = TokenMetadata::builder()
    ///     .issued_ip("10.0.0.1")
    ///     .user_agent("curl/8.0")
    ///     .device_id("device-abc")
    ///     .build();
    /// assert_eq!(meta.issued_ip.as_deref(), Some("10.0.0.1"));
    /// ```
    pub fn builder() -> TokenMetadataBuilder {
        TokenMetadataBuilder::default()
    }
}

/// Fluent builder for [`TokenMetadata`].
#[derive(Debug, Clone, Default)]
pub struct TokenMetadataBuilder {
    inner: TokenMetadata,
}

impl TokenMetadataBuilder {
    /// Set the IP address that issued the token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder().issued_ip("10.0.0.1").build();
    /// assert_eq!(meta.issued_ip.as_deref(), Some("10.0.0.1"));
    /// ```
    pub fn issued_ip(mut self, ip: impl Into<String>) -> Self {
        self.inner.issued_ip = Some(ip.into());
        self
    }

    /// Set the user-agent string of the issuing client.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder().user_agent("curl/8.0").build();
    /// assert_eq!(meta.user_agent.as_deref(), Some("curl/8.0"));
    /// ```
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.inner.user_agent = Some(ua.into());
        self
    }

    /// Set the device identifier.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder().device_id("phone-123").build();
    /// assert_eq!(meta.device_id.as_deref(), Some("phone-123"));
    /// ```
    pub fn device_id(mut self, id: impl Into<String>) -> Self {
        self.inner.device_id = Some(id.into());
        self
    }

    /// Set the associated session identifier.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder().session_id("sess-abc").build();
    /// assert_eq!(meta.session_id.as_deref(), Some("sess-abc"));
    /// ```
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.inner.session_id = Some(id.into());
        self
    }

    /// Insert a custom metadata entry.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder()
    ///     .custom("region", serde_json::json!("us-east-1"))
    ///     .build();
    /// assert_eq!(meta.custom.get("region").unwrap(), "us-east-1");
    /// ```
    pub fn custom(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.inner.custom.insert(key.into(), value);
        self
    }

    /// Consume the builder and return the finished [`TokenMetadata`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::TokenMetadata;
    ///
    /// let meta = TokenMetadata::builder()
    ///     .issued_ip("127.0.0.1")
    ///     .user_agent("test-client")
    ///     .build();
    /// assert!(!meta.revoked);
    /// ```
    pub fn build(self) -> TokenMetadata {
        self.inner
    }
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

/// Lightweight user information extracted from a validated token.
///
/// Returned by [`AuthFramework::get_token_info`](crate::auth::AuthFramework)
/// after token validation succeeds.
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

/// Standard and custom JWT claims used by [`TokenManager`].
///
/// Fields follow the [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
/// registered claim names.  Additional claims can be stored in [`custom`](JwtClaims::custom).
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

/// Central token lifecycle manager: creation, validation, refresh, and
/// revocation.
///
/// Constructed internally by [`AuthFramework`](crate::auth::AuthFramework)
/// — most users interact with token operations through the
/// [`TokenOperations`](crate::auth::TokenOperations) facade instead.
pub struct TokenManager {
    /// JWT encoding key
    encoding_key: EncodingKey,

    /// JWT decoding key (current)
    decoding_key: DecodingKey,

    /// Optional previous decoding key retained during key-rotation grace period.
    ///
    /// Tokens signed with the previous key are still accepted until they expire
    /// naturally.  Once operators are satisfied all pre-rotation tokens have
    /// expired, they can call [`TokenManager::retire_previous_key`] to remove it.
    previous_decoding_key: Option<DecodingKey>,

    /// Key material for recreating keys during clone
    key_material: KeyMaterial,

    /// Key material for the previous key (for clone support after rotation)
    previous_key_material: Option<KeyMaterial>,

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

/// Public key material that can be serialized into a JWKS document.
///
/// Contains the RSA key components needed for JWT verification by external
/// clients. Typically exposed via a `/.well-known/jwks.json` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksPublicKey {
    /// The JWT signing algorithm (e.g., RS256).
    pub algorithm: Algorithm,
    /// Key ID uniquely identifying this key in the JWKS key set.
    pub kid: String,
    /// RSA modulus, base64url-encoded.
    pub n: String,
    /// RSA public exponent, base64url-encoded.
    pub e: String,
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
            scopes: crate::types::Scopes::empty(),
            auth_method: auth_method.into(),
            client_id: None,
            user_profile: None,
            permissions: crate::types::Permissions::empty(),
            roles: crate::types::Roles::empty(),
            metadata: TokenMetadata::default(),
        }
    }

    /// Get the access token string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "my_token").build();
    /// assert_eq!(token.access_token(), "my_token");
    /// ```
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Get the user ID.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "user42", "access").build();
    /// assert_eq!(token.user_id(), "user42");
    /// ```
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get the expiration time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use chrono::Utc;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(token.expires_at() > Utc::now());
    /// ```
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Get the token value.
    ///
    /// Alias for [`access_token()`](Self::access_token).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "tok_value").build();
    /// assert_eq!(token.token_value(), "tok_value");
    /// ```
    pub fn token_value(&self) -> &str {
        &self.access_token
    }

    /// Get the token type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .token_type("Bearer")
    ///     .build();
    /// assert_eq!(token.token_type(), Some("Bearer"));
    /// ```
    pub fn token_type(&self) -> Option<&str> {
        self.token_type.as_deref()
    }

    /// Get the subject claim.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .subject("sub-123")
    ///     .build();
    /// assert_eq!(token.subject(), Some("sub-123"));
    /// ```
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Get the issuer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .issuer("my-service")
    ///     .build();
    /// assert_eq!(token.issuer(), Some("my-service"));
    /// ```
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Check if the token has expired.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(!token.is_expired()); // 1-hour default
    /// ```
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the token is expiring within the given duration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use std::time::Duration;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(token.is_expiring(Duration::from_secs(7200))); // within 2 hours
    /// ```
    pub fn is_expiring(&self, within: Duration) -> bool {
        Utc::now() + within > self.expires_at
    }

    /// Check if the token has been revoked.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(!token.is_revoked());
    /// token.revoke(Some("user request".to_string()));
    /// assert!(token.is_revoked());
    /// ```
    pub fn is_revoked(&self) -> bool {
        self.metadata.revoked
    }

    /// Check if the token is valid (not expired and not revoked).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(token.is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }

    /// Check whether this token carries a refresh token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .refresh_token("rt-abc")
    ///     .build();
    /// assert!(token.has_refresh_token());
    /// ```
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Return the refresh token string, if present.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access")
    ///     .refresh_token("rt-xyz")
    ///     .build();
    /// assert_eq!(token.get_refresh_token(), Some("rt-xyz"));
    /// ```
    pub fn get_refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Revoke the token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.revoke(Some("compromised".to_string()));
    /// assert!(token.is_revoked());
    /// ```
    pub fn revoke(&mut self, reason: Option<String>) {
        self.metadata.revoked = true;
        self.metadata.revoked_at = Some(Utc::now());
        self.metadata.revoked_reason = reason;
    }

    /// Update the last used time and increment use count.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// assert_eq!(token.metadata.use_count, 0);
    /// token.mark_used();
    /// assert_eq!(token.metadata.use_count, 1);
    /// ```
    pub fn mark_used(&mut self) {
        self.metadata.last_used = Some(Utc::now());
        self.metadata.use_count += 1;
    }

    /// Add a scope to the token.
    ///
    /// Duplicates are ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_scope("read");
    /// assert!(token.has_scope("read"));
    /// ```
    pub fn add_scope(&mut self, scope: impl Into<String>) {
        let scope = scope.into();
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
        }
    }

    /// Check if the token has a specific scope.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_scope("write");
    /// assert!(token.has_scope("write"));
    /// assert!(!token.has_scope("admin"));
    /// ```
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// Set the refresh token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_refresh_token("refresh_xyz");
    /// assert!(token.refresh_token.is_some());
    /// ```
    pub fn with_refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
        self
    }

    /// Set the client ID.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_client_id("app-client");
    /// assert_eq!(token.client_id.as_deref(), Some("app-client"));
    /// ```
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the token scopes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Scopes;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_scopes(Scopes::new(vec!["read".into()]));
    /// assert!(token.has_scope("read"));
    /// ```
    pub fn with_scopes(mut self, scopes: impl Into<crate::types::Scopes>) -> Self {
        self.scopes = scopes.into();
        self
    }

    /// Add metadata to the token.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::{AuthToken, TokenMetadata};
    ///
    /// let meta = TokenMetadata::builder().issued_ip("192.168.1.1").build();
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_metadata(meta);
    /// assert_eq!(token.metadata.issued_ip.as_deref(), Some("192.168.1.1"));
    /// ```
    pub fn with_metadata(mut self, metadata: TokenMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Get time until expiration.
    ///
    /// Returns `Duration::ZERO` if the token has already expired.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use std::time::Duration;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(token.time_until_expiry() > Duration::ZERO);
    /// ```
    pub fn time_until_expiry(&self) -> Duration {
        let now = Utc::now();
        if self.expires_at > now {
            (self.expires_at - now).to_std().unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        }
    }

    /// Add a custom claim to the token metadata.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_custom_claim("tenant", serde_json::json!("acme"));
    /// assert_eq!(token.get_custom_claim("tenant").unwrap(), &serde_json::json!("acme"));
    /// ```
    pub fn add_custom_claim(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.custom.insert(key.into(), value);
    }

    /// Get a custom claim from the token metadata.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build();
    /// assert!(token.get_custom_claim("missing").is_none());
    /// ```
    pub fn get_custom_claim(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.custom.get(key)
    }

    /// Check if the token has a specific permission.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_permission("admin");
    /// assert!(token.has_permission("admin"));
    /// ```
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// Add a permission to the token.
    ///
    /// Duplicates are ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_permission("write");
    /// assert!(token.has_permission("write"));
    /// ```
    pub fn add_permission(&mut self, permission: impl Into<String>) {
        let permission = permission.into();
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
    }

    /// Add a role to the token.
    ///
    /// Duplicates are ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_role("editor");
    /// assert!(token.has_role("editor"));
    /// ```
    pub fn add_role(&mut self, role: impl Into<String>) {
        let role = role.into();
        if !self.roles.contains(&role) {
            self.roles.push(role);
        }
    }

    /// Check if the token has a specific role.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    ///
    /// let mut token = AuthToken::builder("t1", "u1", "access").build();
    /// token.add_role("admin");
    /// assert!(token.has_role("admin"));
    /// assert!(!token.has_role("guest"));
    /// ```
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Set the permissions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Permissions;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_permissions(Permissions::new(vec!["read".into()]));
    /// assert!(token.has_permission("read"));
    /// ```
    pub fn with_permissions(mut self, permissions: impl Into<crate::types::Permissions>) -> Self {
        self.permissions = permissions.into();
        self
    }

    /// Set the roles.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::tokens::AuthToken;
    /// use auth_framework::types::Roles;
    ///
    /// let token = AuthToken::builder("t1", "u1", "access").build()
    ///     .with_roles(Roles::new(vec!["viewer".into()]));
    /// assert!(token.has_role("viewer"));
    /// ```
    pub fn with_roles(mut self, roles: impl Into<crate::types::Roles>) -> Self {
        self.roles = roles.into();
        self
    }
}

impl Clone for TokenManager {
    fn clone(&self) -> Self {
        let (previous_decoding_key, previous_key_material) = match &self.previous_key_material {
            Some(KeyMaterial::Hmac(secret)) => (
                Some(DecodingKey::from_secret(secret)),
                Some(KeyMaterial::Hmac(secret.clone())),
            ),
            Some(KeyMaterial::Rsa { public, .. }) => (
                DecodingKey::from_rsa_pem(public).ok(),
                self.previous_key_material.clone(),
            ),
            None => (None, None),
        };
        match &self.key_material {
            KeyMaterial::Hmac(secret) => Self {
                encoding_key: EncodingKey::from_secret(secret),
                decoding_key: DecodingKey::from_secret(secret),
                previous_decoding_key,
                key_material: self.key_material.clone(),
                previous_key_material,
                algorithm: self.algorithm,
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                default_lifetime: self.default_lifetime,
            },
            KeyMaterial::Rsa { private, public } => Self {
                // SAFETY: The PEM was already validated when the TokenManager was first
                // constructed; re-parsing it here during Clone cannot fail unless the
                // bytes were corrupted in memory, which would be a catastrophic bug.
                encoding_key: EncodingKey::from_rsa_pem(private).expect("RSA private key PEM re-parse failed during Clone — this indicates memory corruption"),
                decoding_key: DecodingKey::from_rsa_pem(public).expect("RSA public key PEM re-parse failed during Clone — this indicates memory corruption"),
                previous_decoding_key,
                key_material: self.key_material.clone(),
                previous_key_material,
                algorithm: self.algorithm,
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                default_lifetime: self.default_lifetime,
            },
        }
    }
}

impl TokenManager {
    #[cfg(feature = "rsa-verify")]
    fn jwks_from_public_pem(public_key: &[u8], algorithm: Algorithm) -> Result<JwksPublicKey> {
        let pem = std::str::from_utf8(public_key)
            .map_err(|e| AuthError::crypto(format!("Invalid RSA public key PEM encoding: {e}")))?;

        let public_key = rsa::RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
            .map_err(|e| {
                AuthError::crypto(format!(
                    "Failed to parse RSA public key for JWKS export: {e}"
                ))
            })?;

        let modulus = public_key.n().to_bytes_be();
        let exponent = public_key.e().to_bytes_be();
        let kid_digest = Sha256::digest(&modulus);

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modulus);
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&exponent);
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kid_digest);

        Ok(JwksPublicKey {
            algorithm,
            kid,
            n,
            e,
        })
    }

    /// RSA support is not compiled in without the `rsa-verify` feature (see
    /// RUSTSEC-2023-0071 in deny.toml). `KeyMaterial::Rsa` can still be
    /// constructed, so this returns an actionable error at export time
    /// rather than failing to compile.
    #[cfg(not(feature = "rsa-verify"))]
    fn jwks_from_public_pem(_public_key: &[u8], _algorithm: Algorithm) -> Result<JwksPublicKey> {
        Err(AuthError::crypto(
            "RSA JWKS export requires the `rsa-verify` feature. RSA has an open, \
             unpatched timing-sidechannel advisory (RUSTSEC-2023-0071); see deny.toml \
             for the full disposition. Enable the `rsa-verify` feature to opt in, or \
             use an ECDSA (ES256/ES384) key instead.",
        ))
    }

    /// Export the current and previous RSA verification keys as JWKS-compatible material.
    pub fn export_public_jwks(&self) -> Result<Vec<JwksPublicKey>> {
        let mut keys = Vec::new();

        if let KeyMaterial::Rsa { public, .. } = &self.key_material {
            keys.push(Self::jwks_from_public_pem(public, self.algorithm)?);
        }

        if let Some(KeyMaterial::Rsa { public, .. }) = &self.previous_key_material {
            let previous = Self::jwks_from_public_pem(public, self.algorithm)?;
            if !keys.iter().any(|key| key.kid == previous.kid) {
                keys.push(previous);
            }
        }

        Ok(keys)
    }

    /// Create a new token manager with HMAC key.
    pub fn new_hmac(secret: &[u8], issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            previous_decoding_key: None,
            key_material: KeyMaterial::Hmac(secret.to_vec()),
            previous_key_material: None,
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
    /// ```rust,no_run
    /// use auth_framework::tokens::TokenManager;
    ///
    /// // Both PKCS#1 and PKCS#8 formats work; provide PEM bytes from your key store.
    /// # let private_key: &[u8] = b"";
    /// # let public_key: &[u8] = b"";
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
            previous_decoding_key: None,
            key_material: KeyMaterial::Rsa {
                private: private_key.to_vec(),
                public: public_key.to_vec(),
            },
            previous_key_material: None,
            algorithm: Algorithm::RS256,
            issuer: issuer.into(),
            audience: audience.into(),
            default_lifetime: Duration::from_secs(3600), // 1 hour
        })
    }

    /// Rotate HMAC key, keeping the current key as the previous decoding key
    /// to seamlessly allow verification of tokens signed with the old key.
    pub fn rotate_hmac_key(&mut self, new_secret: &[u8]) {
        // Move current key to previous
        if let KeyMaterial::Hmac(secret) = &self.key_material {
            self.previous_decoding_key = Some(DecodingKey::from_secret(secret));
            self.previous_key_material = Some(KeyMaterial::Hmac(secret.clone()));
        }

        // Set new key
        self.encoding_key = EncodingKey::from_secret(new_secret);
        self.decoding_key = DecodingKey::from_secret(new_secret);
        self.key_material = KeyMaterial::Hmac(new_secret.to_vec());
        self.algorithm = Algorithm::HS256;
    }

    /// Rotate RSA key, keeping the current key as the previous decoding key
    /// to seamlessly allow verification of tokens signed with the old key.
    pub fn rotate_rsa_key(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<()> {
        let new_encoding_key = EncodingKey::from_rsa_pem(private_key)
            .map_err(|e| AuthError::crypto(format!("Invalid RSA private key: {e}")))?;
        let new_decoding_key = DecodingKey::from_rsa_pem(public_key)
            .map_err(|e| AuthError::crypto(format!("Invalid RSA public key: {e}")))?;

        // Move current key to previous
        if let KeyMaterial::Rsa { public, .. } = &self.key_material {
            self.previous_decoding_key = DecodingKey::from_rsa_pem(public).ok();
            self.previous_key_material = Some(self.key_material.clone());
        }

        // Set new key
        self.encoding_key = new_encoding_key;
        self.decoding_key = new_decoding_key;
        self.key_material = KeyMaterial::Rsa {
            private: private_key.to_vec(),
            public: public_key.to_vec(),
        };
        self.algorithm = Algorithm::RS256;

        Ok(())
    }

    /// Retire the previous key (if any), so tokens signed with it are no longer valid.
    pub fn retire_previous_key(&mut self) {
        self.previous_decoding_key = None;
        self.previous_key_material = None;
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

        match decode::<JwtClaims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        Err(AuthError::Token(TokenError::Expired))
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        // If signature is invalid, try the previous key if configured
                        if let Some(prev_key) = &self.previous_decoding_key
                            && let Ok(prev_token_data) =
                                decode::<JwtClaims>(token, prev_key, &validation)
                        {
                            return Ok(prev_token_data.claims);
                        }

                        Err(AuthError::Token(TokenError::Invalid {
                            message: "Invalid token signature".to_string(),
                        }))
                    }
                    _ => Err(AuthError::Token(TokenError::Invalid {
                        message: "Invalid token format".to_string(),
                    })),
                }
            }
        }
    }

    /// Create a complete authentication token with JWT.
    pub fn create_auth_token(
        &self,
        user_id: impl Into<String>,
        scopes: impl Into<crate::types::Scopes>,
        auth_method: impl Into<String>,
        lifetime: Option<std::time::Duration>,
    ) -> Result<AuthToken> {
        let user_id_str = user_id.into();
        let scopes: crate::types::Scopes = scopes.into();
        let lifetime = lifetime.unwrap_or(self.default_lifetime);

        let jwt_token = self.create_jwt_token(&user_id_str, scopes.to_vec(), Some(lifetime))?;

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
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<ProviderProfile>;

    /// Convert this token to a user profile with a custom extractor
    async fn to_profile_with_extractor(
        &self,
        provider: &OAuthProvider,
        extractor: &ProfileExtractor,
    ) -> Result<ProviderProfile>;
}

#[async_trait::async_trait]
impl TokenToProfile for AuthToken {
    async fn to_profile(&self, provider: &OAuthProvider) -> Result<ProviderProfile> {
        let extractor = ProfileExtractor::new();
        extractor.extract_profile(self, provider).await
    }

    async fn to_profile_with_extractor(
        &self,
        provider: &OAuthProvider,
        extractor: &ProfileExtractor,
    ) -> Result<ProviderProfile> {
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
