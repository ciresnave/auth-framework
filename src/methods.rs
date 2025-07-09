//! Authentication method implementations.

use crate::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, Result};
use crate::providers::{OAuthProvider, generate_state, generate_pkce};
use crate::tokens::{AuthToken, TokenManager};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub enum MethodResult {
    /// Authentication was successful
    Success(Box<AuthToken>),
    
    /// Multi-factor authentication is required
    MfaRequired(Box<MfaChallenge>),
    
    /// Authentication failed
    Failure { reason: String },
}

/// Multi-factor authentication challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Unique challenge ID
    pub id: String,
    
    /// Type of MFA required
    pub mfa_type: MfaType,
    
    /// User ID this challenge is for
    pub user_id: String,
    
    /// When the challenge expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
    
    /// Optional message or instructions
    pub message: Option<String>,
    
    /// Additional challenge data
    pub data: HashMap<String, serde_json::Value>,
}

/// Types of multi-factor authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaType {
    /// Time-based one-time password (TOTP)
    Totp,
    
    /// SMS verification code
    Sms { phone_number: String },
    
    /// Email verification code
    Email { email_address: String },
    
    /// Push notification
    Push { device_id: String },
    
    /// Hardware security key
    SecurityKey,
    
    /// Backup codes
    BackupCode,
}

/// Trait for authentication methods.
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Get the name of this authentication method.
    fn name(&self) -> &str;
    
    /// Authenticate using the provided credentials.
    async fn authenticate(
        &self,
        credential: &Credential,
        metadata: &CredentialMetadata,
    ) -> Result<MethodResult>;
    
    /// Validate configuration for this method.
    fn validate_config(&self) -> Result<()>;
    
    /// Check if this method supports refresh tokens.
    fn supports_refresh(&self) -> bool {
        false
    }
    
    /// Refresh a token if supported.
    async fn refresh_token(&self, _refresh_token: &str) -> Result<AuthToken> {
        Err(AuthError::auth_method(
            self.name(),
            "Token refresh not supported by this method".to_string(),
        ))
    }
}

/// Password-based authentication method.
pub struct PasswordMethod {
    name: String,
    password_verifier: Box<dyn PasswordVerifier>,
    token_manager: TokenManager,
    mfa_enabled: bool,
    user_lookup: Box<dyn UserLookup>,
}

/// JWT-based authentication method.
pub struct JwtMethod {
    name: String,
    token_manager: TokenManager,
    issuer: String,
    audience: String,
}

/// API key authentication method.
pub struct ApiKeyMethod {
    name: String,
    key_prefix: Option<String>,
    header_name: String,
    key_validator: Box<dyn ApiKeyValidator>,
    token_manager: TokenManager,
}

/// OAuth 2.0 authentication method.
pub struct OAuth2Method {
    name: String,
    provider: OAuthProvider,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Vec<String>,
    use_pkce: bool,
    token_manager: TokenManager,
}

/// Trait for password verification.
#[async_trait]
pub trait PasswordVerifier: Send + Sync {
    /// Verify a password against a hash.
    async fn verify_password(&self, username: &str, password: &str) -> Result<bool>;
    
    /// Hash a password.
    async fn hash_password(&self, password: &str) -> Result<String>;
}

/// Trait for user lookup operations.
#[async_trait]
pub trait UserLookup: Send + Sync {
    /// Look up a user by username.
    async fn lookup_user(&self, username: &str) -> Result<Option<UserInfo>>;
    
    /// Check if a user requires MFA.
    async fn requires_mfa(&self, user_id: &str) -> Result<bool>;
}

/// Trait for API key validation.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    /// Validate an API key and return associated user info.
    async fn validate_key(&self, api_key: &str) -> Result<Option<UserInfo>>;
    
    /// Create a new API key for a user.
    async fn create_key(&self, user_id: &str, expires_in: Option<Duration>) -> Result<String>;
    
    /// Revoke an API key.
    async fn revoke_key(&self, api_key: &str) -> Result<()>;
}

/// Basic user information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID
    pub id: String,
    
    /// Username
    pub username: String,
    
    /// Email address
    pub email: Option<String>,
    
    /// Display name
    pub name: Option<String>,
    
    /// User roles
    pub roles: Vec<String>,
    
    /// Whether the user is active
    pub active: bool,
    
    /// Additional user attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

impl MfaChallenge {
    /// Create a new MFA challenge.
    pub fn new(
        mfa_type: MfaType,
        user_id: impl Into<String>,
        expires_in: Duration,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            mfa_type,
            user_id: user_id.into(),
            expires_at: chrono::Utc::now() + chrono::Duration::from_std(expires_in).unwrap(),
            message: None,
            data: HashMap::new(),
        }
    }

    /// Get the challenge ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Check if the challenge has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Set a message for the challenge.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

impl PasswordMethod {
    /// Create a new password authentication method.
    pub fn new(
        password_verifier: Box<dyn PasswordVerifier>,
        user_lookup: Box<dyn UserLookup>,
        token_manager: TokenManager,
    ) -> Self {
        Self {
            name: "password".to_string(),
            password_verifier,
            token_manager,
            mfa_enabled: false,
            user_lookup,
        }
    }

    /// Enable or disable MFA for this method.
    pub fn with_mfa(mut self, enabled: bool) -> Self {
        self.mfa_enabled = enabled;
        self
    }
}

#[async_trait]
impl AuthMethod for PasswordMethod {
    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        let (username, password) = match credential {
            Credential::Password { username, password } => (username, password),
            _ => return Err(AuthError::auth_method(
                self.name(),
                "Invalid credential type for password authentication".to_string(),
            )),
        };

        // Verify password
        if !self.password_verifier.verify_password(username, password).await? {
            return Ok(MethodResult::Failure {
                reason: "Invalid username or password".to_string(),
            });
        }

        // Look up user
        let user = self.user_lookup.lookup_user(username).await?
            .ok_or_else(|| AuthError::auth_method(
                self.name(),
                "User not found".to_string(),
            ))?;

        if !user.active {
            return Ok(MethodResult::Failure {
                reason: "User account is disabled".to_string(),
            });
        }

        // Check if MFA is required
        if self.mfa_enabled && self.user_lookup.requires_mfa(&user.id).await? {
            let challenge = MfaChallenge::new(
                MfaType::Totp, // Default to TOTP, could be configurable
                &user.id,
                Duration::from_secs(300), // 5 minutes
            ).with_message("Please enter your MFA code");

            return Ok(MethodResult::MfaRequired(Box::new(challenge)));
        }

        // Create token
        let token = self.token_manager.create_auth_token(
            &user.id,
            vec![], // Scopes would be determined by user roles
            self.name(),
            None,
        )?;

        Ok(MethodResult::Success(Box::new(token)))
    }

    fn validate_config(&self) -> Result<()> {
        // Validation would depend on the specific implementation
        Ok(())
    }
}

impl Default for JwtMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtMethod {
    /// Create a new JWT authentication method.
    pub fn new() -> Self {
        let token_manager = TokenManager::new_hmac(
            b"default-secret", // This should be configurable
            "default-issuer",
            "default-audience",
        );

        Self {
            name: "jwt".to_string(),
            token_manager,
            issuer: "default-issuer".to_string(),
            audience: "default-audience".to_string(),
        }
    }

    /// Set the secret key for JWT signing.
    pub fn secret_key(mut self, secret: impl Into<String>) -> Self {
        let secret = secret.into();
        self.token_manager = TokenManager::new_hmac(
            secret.as_bytes(),
            &self.issuer,
            &self.audience,
        );
        self
    }

    /// Set the issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self.token_manager = TokenManager::new_hmac(
            b"default-secret", // This should use the actual secret
            &self.issuer,
            &self.audience,
        );
        self
    }

    /// Set the audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self.token_manager = TokenManager::new_hmac(
            b"default-secret", // This should use the actual secret
            &self.issuer,
            &self.audience,
        );
        self
    }
}

#[async_trait]
impl AuthMethod for JwtMethod {
    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        let token_str = match credential {
            Credential::Jwt { token } => token,
            Credential::Bearer { token } => token,
            _ => return Err(AuthError::auth_method(
                self.name(),
                "Invalid credential type for JWT authentication".to_string(),
            )),
        };

        // Validate JWT
        let claims = self.token_manager.validate_jwt_token(token_str)?;
        
        // Create auth token from JWT claims
        let remaining_seconds = (claims.exp - chrono::Utc::now().timestamp()).max(0) as u64;
        let token = AuthToken::new(
            claims.sub,
            token_str.clone(),
            std::time::Duration::from_secs(remaining_seconds),
            self.name(),
        ).with_scopes(claims.scope.split_whitespace().map(|s| s.to_string()).collect());

        Ok(MethodResult::Success(Box::new(token)))
    }

    fn validate_config(&self) -> Result<()> {
        // Validate JWT configuration
        Ok(())
    }
}

impl Default for ApiKeyMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyMethod {
    /// Create a new API key authentication method.
    pub fn new() -> Self {
        let token_manager = TokenManager::new_hmac(
            b"default-secret",
            "api-key-issuer",
            "api-key-audience",
        );

        Self {
            name: "api-key".to_string(),
            key_prefix: None,
            header_name: "X-API-Key".to_string(),
            key_validator: Box::new(DefaultApiKeyValidator),
            token_manager,
        }
    }

    /// Set the key prefix.
    pub fn key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }

    /// Set the header name.
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into();
        self
    }

    /// Set the key validator.
    pub fn key_validator(mut self, validator: Box<dyn ApiKeyValidator>) -> Self {
        self.key_validator = validator;
        self
    }
}

#[async_trait]
impl AuthMethod for ApiKeyMethod {
    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        let api_key = match credential {
            Credential::ApiKey { key } => key,
            _ => return Err(AuthError::auth_method(
                self.name(),
                "Invalid credential type for API key authentication".to_string(),
            )),
        };

        // Validate prefix if configured
        if let Some(prefix) = &self.key_prefix {
            if !api_key.starts_with(prefix) {
                return Ok(MethodResult::Failure {
                    reason: "Invalid API key format".to_string(),
                });
            }
        }

        // Validate key
        let user = self.key_validator.validate_key(api_key).await?
            .ok_or_else(|| AuthError::auth_method(
                self.name(),
                "Invalid API key".to_string(),
            ))?;

        // Create token
        let token = self.token_manager.create_auth_token(
            &user.id,
            vec!["api".to_string()], // Default API scope
            self.name(),
            Some(std::time::Duration::from_secs(3600)), // 1 hour default
        )?;

        Ok(MethodResult::Success(Box::new(token)))
    }

    fn validate_config(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for OAuth2Method {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuth2Method {
    /// Create a new OAuth 2.0 authentication method.
    pub fn new() -> Self {
        let token_manager = TokenManager::new_hmac(
            b"oauth-secret",
            "oauth-issuer",
            "oauth-audience",
        );

        Self {
            name: "oauth2".to_string(),
            provider: OAuthProvider::GitHub, // Default provider
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: Vec::new(),
            use_pkce: true,
            token_manager,
        }
    }

    /// Set the OAuth provider.
    pub fn provider(mut self, provider: OAuthProvider) -> Self {
        self.provider = provider;
        self
    }

    /// Set the client ID.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = client_id.into();
        self
    }

    /// Set the client secret.
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = client_secret.into();
        self
    }

    /// Set the redirect URI.
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = redirect_uri.into();
        self
    }

    /// Set the scopes.
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Enable or disable PKCE.
    pub fn use_pkce(mut self, use_pkce: bool) -> Self {
        self.use_pkce = use_pkce;
        self
    }

    /// Generate authorization URL.
    pub fn authorization_url(&self) -> Result<AuthorizationUrlResult> {
        let state = generate_state();
        let pkce = if self.use_pkce {
            Some(generate_pkce())
        } else {
            None
        };

        let url = self.provider.build_authorization_url(
            &self.client_id,
            &self.redirect_uri,
            &state,
            if self.scopes.is_empty() { None } else { Some(&self.scopes) },
            pkce.as_ref().map(|(_, challenge)| challenge.as_str()),
        )?;

        Ok((url, state, pkce))
    }
}

#[async_trait]
impl AuthMethod for OAuth2Method {
    fn name(&self) -> &str {
        &self.name
    }

    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        let (authorization_code, code_verifier) = match credential {
            Credential::OAuth { authorization_code, code_verifier, .. } => {
                (authorization_code, code_verifier.as_deref())
            }
            _ => return Err(AuthError::auth_method(
                self.name(),
                "Invalid credential type for OAuth authentication".to_string(),
            )),
        };

        // Exchange authorization code for tokens
        let token_response = self.provider.exchange_code(
            &self.client_id,
            &self.client_secret,
            authorization_code,
            &self.redirect_uri,
            code_verifier,
        ).await?;

        // Get user info
        let user_info = self.provider.get_user_info(&token_response.access_token).await?;

        // Create auth token
        // Convert to duration with proper type
        let expires_in = token_response.expires_in
            .map(std::time::Duration::from_secs)
            .unwrap_or_else(|| std::time::Duration::from_secs(3600));

        let mut token = self.token_manager.create_auth_token(
            &user_info.id,
            token_response.scope
                .unwrap_or_default()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            self.name(),
            Some(expires_in),
        )?;

        // Set refresh token if available
        if let Some(refresh_token) = token_response.refresh_token {
            token = token.with_refresh_token(refresh_token);
        }

        Ok(MethodResult::Success(Box::new(token)))
    }

    fn validate_config(&self) -> Result<()> {
        if self.client_id.is_empty() {
            return Err(AuthError::config("OAuth client ID is required"));
        }
        if self.client_secret.is_empty() {
            return Err(AuthError::config("OAuth client secret is required"));
        }
        if self.redirect_uri.is_empty() {
            return Err(AuthError::config("OAuth redirect URI is required"));
        }
        Ok(())
    }

    fn supports_refresh(&self) -> bool {
        self.provider.config().supports_refresh
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken> {
        let token_response = self.provider.refresh_token(
            &self.client_id,
            &self.client_secret,
            refresh_token,
        ).await?;

        let expires_in = token_response.expires_in
            .map(Duration::from_secs)
            .unwrap_or_else(|| std::time::Duration::from_secs(3600));

        // We need user info to create the token, but we don't have it from refresh
        // In a real implementation, we'd store user ID with the refresh token
        let token = self.token_manager.create_auth_token(
            "unknown", // This would need to be resolved from the refresh token
            token_response.scope
                .unwrap_or_default()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
            self.name(),
            Some(expires_in),
        )?;

        Ok(token)
    }
}

/// PKCE challenge and verifier pair
type PkceParams = (String, String);

/// OAuth authorization URL result: (url, state, optional_pkce)
type AuthorizationUrlResult = (String, String, Option<PkceParams>);

/// Default API key validator (placeholder implementation).
#[derive(Debug, Clone)]
struct DefaultApiKeyValidator;

#[async_trait]
impl ApiKeyValidator for DefaultApiKeyValidator {
    async fn validate_key(&self, _api_key: &str) -> Result<Option<UserInfo>> {
        // This is a placeholder - real implementation would check against a database
        Ok(None)
    }

    async fn create_key(&self, _user_id: &str, _expires_in: Option<Duration>) -> Result<String> {
        // Generate a new API key
        Ok(format!("api-{}", uuid::Uuid::new_v4()))
    }

    async fn revoke_key(&self, _api_key: &str) -> Result<()> {
        // Mark key as revoked in database
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_challenge() {
        let challenge = MfaChallenge::new(
            MfaType::Totp,
            "user123",
            Duration::from_secs(300),
        );

        assert_eq!(challenge.user_id, "user123");
        assert!(!challenge.is_expired());
        assert_eq!(challenge.id().len(), 36); // UUID length
    }

    #[test]
    fn test_jwt_method_creation() {
        let jwt_method = JwtMethod::new()
            .secret_key("test-secret")
            .issuer("test-issuer")
            .audience("test-audience");

        assert_eq!(jwt_method.name(), "jwt");
        assert_eq!(jwt_method.issuer, "test-issuer");
        assert_eq!(jwt_method.audience, "test-audience");
    }

    #[test]
    fn test_oauth2_method_creation() {
        let oauth_method = OAuth2Method::new()
            .provider(OAuthProvider::GitHub)
            .client_id("test-client")
            .client_secret("test-secret")
            .redirect_uri("https://example.com/callback");

        assert_eq!(oauth_method.name(), "oauth2");
        assert_eq!(oauth_method.client_id, "test-client");
        assert!(oauth_method.use_pkce);
    }
}
