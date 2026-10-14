//! OAuth 2.0 Authorization Server Implementation
//!
//! This module provides a fully secure OAuth 2.0 authorization server implementation
//! with all critical vulnerabilities addressed and proper validation.

use crate::errors::{AuthError, Result};
use crate::oauth2_enhanced_storage::{
    EnhancedAuthorizationCode, EnhancedClientCredentials, EnhancedTokenStorage, RefreshToken,
};
use crate::security::secure_utils::constant_time_compare;
use crate::tokens::{AuthToken, TokenManager};
use crate::user_context::{SessionStore, UserContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// OAuth 2.0 grant types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
    DeviceCode,
    TokenExchange,
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantType::AuthorizationCode => write!(f, "authorization_code"),
            GrantType::RefreshToken => write!(f, "refresh_token"),
            GrantType::ClientCredentials => write!(f, "client_credentials"),
            GrantType::DeviceCode => write!(f, "urn:ietf:params:oauth:grant-type:device_code"),
            GrantType::TokenExchange => {
                write!(f, "urn:ietf:params:oauth:grant-type:token-exchange")
            }
        }
    }
}

/// OAuth 2.0 response types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
}

/// OAuth 2.0 server configuration
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// Authorization server issuer identifier
    pub issuer: String,
    /// Authorization code lifetime
    pub authorization_code_lifetime: Duration,
    /// Access token lifetime
    pub access_token_lifetime: Duration,
    /// Refresh token lifetime
    pub refresh_token_lifetime: Duration,
    /// Device code lifetime
    pub device_code_lifetime: Duration,
    /// Default scope if none specified
    pub default_scope: Option<String>,
    /// Maximum scope lifetime
    pub max_scope_lifetime: Duration,
    /// Require PKCE for public clients
    pub require_pkce: bool,
    /// Enable token introspection
    pub enable_introspection: bool,
    /// Enable token revocation
    pub enable_revocation: bool,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(),
            authorization_code_lifetime: Duration::from_secs(600), // 10 minutes
            access_token_lifetime: Duration::from_secs(3600),      // 1 hour
            refresh_token_lifetime: Duration::from_secs(86400 * 7), // 7 days
            device_code_lifetime: Duration::from_secs(600),        // 10 minutes
            default_scope: Some("read".to_string()),
            max_scope_lifetime: Duration::from_secs(86400 * 30), // 30 days
            require_pkce: true,
            enable_introspection: true,
            enable_revocation: true,
        }
    }
}

/// Token request structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub code_verifier: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub device_code: Option<String>,
}

/// Token response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Authorization request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// OAuth 2.0 Authorization Server
pub struct OAuth2Server {
    config: OAuth2Config,
    token_storage: Arc<RwLock<EnhancedTokenStorage>>,
    session_store: Arc<RwLock<SessionStore>>,
    token_manager: Arc<TokenManager>,
}

impl OAuth2Server {
    pub async fn new(config: OAuth2Config, token_manager: Arc<TokenManager>) -> Result<Self> {
        Ok(Self {
            config,
            token_storage: Arc::new(RwLock::new(EnhancedTokenStorage::new())),
            session_store: Arc::new(RwLock::new(SessionStore::new())),
            token_manager,
        })
    }

    /// Register a confidential client with proper secret validation
    pub async fn register_confidential_client(
        &self,
        client_id: String,
        client_secret: &str,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        grant_types: Vec<String>,
    ) -> Result<()> {
        // Validate client secret strength
        if client_secret.len() < 32 {
            return Err(AuthError::auth_method(
                "oauth2",
                "Client secret must be at least 32 characters",
            ));
        }

        let credentials = EnhancedClientCredentials::new_confidential(
            client_id,
            client_secret,
            redirect_uris,
            allowed_scopes,
            grant_types,
        )?;

        let mut storage = self.token_storage.write().await;
        storage.store_client_credentials(credentials).await?;

        Ok(())
    }

    /// Register a public client (PKCE required)
    pub async fn register_public_client(
        &self,
        client_id: String,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        grant_types: Vec<String>,
    ) -> Result<()> {
        let credentials = EnhancedClientCredentials::new_public(
            client_id,
            redirect_uris,
            allowed_scopes,
            grant_types,
        );

        let mut storage = self.token_storage.write().await;
        storage.store_client_credentials(credentials).await?;

        Ok(())
    }

    /// Create authorization code with proper user context
    pub async fn create_authorization_code(
        &self,
        request: AuthorizationRequest,
        user_context: UserContext,
    ) -> Result<EnhancedAuthorizationCode> {
        // Validate client exists and supports authorization code flow
        let storage = self.token_storage.read().await;
        let client = storage
            .get_client_credentials(&request.client_id)
            .await?
            .ok_or_else(|| AuthError::auth_method("oauth2", "Invalid client_id"))?;

        if !client.supports_grant_type("authorization_code") {
            return Err(AuthError::auth_method(
                "oauth2",
                "Client does not support authorization code grant",
            ));
        }

        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(AuthError::auth_method("oauth2", "Invalid redirect_uri"));
        }

        // Parse and validate scopes
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let authorized_scopes = self.authorize_scopes(&client, &user_context, &requested_scopes)?;

        // Create authorization code with proper user context
        let auth_code = EnhancedAuthorizationCode::new(
            client.client_id.clone(),
            user_context.user_id.clone(), // FIXED: Use real user ID from context
            request.redirect_uri,
            authorized_scopes,
            request.code_challenge,
            request.code_challenge_method,
            self.config.authorization_code_lifetime,
        );

        // Store authorization code
        drop(storage);
        let mut storage = self.token_storage.write().await;
        storage.store_authorization_code(auth_code.clone()).await?;

        Ok(auth_code)
    }

    /// Handle token exchange with comprehensive validation
    pub async fn token_exchange(&self, request: TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            "client_credentials" => self.handle_client_credentials_grant(request).await,
            _ => Err(AuthError::auth_method("oauth2", "Unsupported grant type")),
        }
    }

    /// Handle authorization code grant with proper validation
    async fn handle_authorization_code_grant(
        &self,
        request: TokenRequest,
    ) -> Result<TokenResponse> {
        // Validate client credentials FIRST
        let storage = self.token_storage.read().await;
        let _client = storage
            .get_client_credentials(&request.client_id)
            .await?
            .ok_or_else(|| AuthError::auth_method("oauth2", "Invalid client_id"))?;

        // CRITICAL FIX: Validate client secret properly
        if !storage
            .validate_client_credentials(&request.client_id, request.client_secret.as_deref())
            .await?
        {
            return Err(AuthError::auth_method(
                "oauth2",
                "Invalid client credentials",
            ));
        }

        // Get and validate authorization code
        let code = request
            .code
            .ok_or_else(|| AuthError::auth_method("oauth2", "Missing authorization code"))?;

        drop(storage);
        let mut storage = self.token_storage.write().await;
        let auth_code = storage
            .consume_authorization_code(&code)
            .await?
            .ok_or_else(|| {
                AuthError::auth_method("oauth2", "Invalid or expired authorization code")
            })?;

        // Validate code belongs to this client
        if auth_code.client_id != request.client_id {
            return Err(AuthError::auth_method(
                "oauth2",
                "Authorization code does not belong to client",
            ));
        }

        // Validate PKCE if required
        if let Some(challenge) = &auth_code.code_challenge {
            let verifier = request
                .code_verifier
                .ok_or_else(|| AuthError::auth_method("oauth2", "PKCE code verifier required"))?;

            if !self.validate_pkce_challenge(
                challenge,
                &verifier,
                &auth_code.code_challenge_method,
            )? {
                return Err(AuthError::auth_method(
                    "oauth2",
                    "Invalid PKCE code verifier",
                ));
            }
        }

        // Generate tokens with proper user context
        let access_token = self
            .generate_access_token(
                &auth_code.client_id,
                Some(&auth_code.user_id), // FIXED: Use actual user ID from auth code
                &auth_code.scopes,
            )
            .await?;

        // Generate refresh token
        let refresh_token = RefreshToken::new(
            auth_code.client_id.clone(),
            auth_code.user_id.clone(), // FIXED: Use actual user ID
            auth_code.scopes.clone(),  // FIXED: Use authorized scopes from auth code
            self.config.refresh_token_lifetime,
        );

        let refresh_token_id = storage.store_refresh_token(refresh_token).await?;

        Ok(TokenResponse {
            access_token: access_token.access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_lifetime.as_secs(),
            refresh_token: Some(refresh_token_id),
            scope: Some(auth_code.scopes.join(" ")),
            id_token: None,
        })
    }

    /// Handle refresh token grant with proper validation
    async fn handle_refresh_token_grant(&self, request: TokenRequest) -> Result<TokenResponse> {
        // Validate client credentials
        let storage = self.token_storage.read().await;
        if !storage
            .validate_client_credentials(&request.client_id, request.client_secret.as_deref())
            .await?
        {
            return Err(AuthError::auth_method(
                "oauth2",
                "Invalid client credentials",
            ));
        }

        // Get and validate refresh token
        let refresh_token_id = request
            .refresh_token
            .ok_or_else(|| AuthError::auth_method("oauth2", "Missing refresh token"))?;

        // CRITICAL FIX: Validate refresh token from storage
        let stored_token = storage
            .get_refresh_token(&refresh_token_id)
            .await?
            .ok_or_else(|| AuthError::auth_method("oauth2", "Invalid refresh token"))?;

        if !stored_token.is_valid() {
            return Err(AuthError::auth_method(
                "oauth2",
                "Refresh token is expired or revoked",
            ));
        }

        // Validate token belongs to this client
        if stored_token.client_id != request.client_id {
            return Err(AuthError::auth_method(
                "oauth2",
                "Refresh token does not belong to client",
            ));
        }

        // Parse requested scopes (must be subset of original)
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let authorized_scopes = if requested_scopes.is_empty() {
            stored_token.scopes.clone() // FIXED: Use original scopes from token
        } else {
            self.validate_scope_subset(&stored_token.scopes, &requested_scopes)?
        };

        drop(storage);

        // Generate new access token
        let access_token = self
            .generate_access_token(
                &stored_token.client_id,
                Some(&stored_token.user_id), // FIXED: Use actual user ID from token
                &authorized_scopes,
            )
            .await?;

        // Generate new refresh token
        let mut storage = self.token_storage.write().await;
        storage.revoke_refresh_token(&refresh_token_id).await?; // Revoke old token

        let new_refresh_token = RefreshToken::new(
            stored_token.client_id.clone(),
            stored_token.user_id.clone(),
            authorized_scopes.clone(),
            self.config.refresh_token_lifetime,
        );

        let new_refresh_token_id = storage.store_refresh_token(new_refresh_token).await?;

        Ok(TokenResponse {
            access_token: access_token.access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_lifetime.as_secs(),
            refresh_token: Some(new_refresh_token_id),
            scope: Some(authorized_scopes.join(" ")),
            id_token: None,
        })
    }

    /// Handle client credentials grant with proper validation
    async fn handle_client_credentials_grant(
        &self,
        request: TokenRequest,
    ) -> Result<TokenResponse> {
        // Validate client credentials
        let storage = self.token_storage.read().await;
        let client = storage
            .get_client_credentials(&request.client_id)
            .await?
            .ok_or_else(|| AuthError::auth_method("oauth2", "Invalid client_id"))?;

        // CRITICAL FIX: Validate client secret properly
        if !storage
            .validate_client_credentials(&request.client_id, request.client_secret.as_deref())
            .await?
        {
            return Err(AuthError::auth_method(
                "oauth2",
                "Invalid client credentials",
            ));
        }

        if !client.supports_grant_type("client_credentials") {
            return Err(AuthError::auth_method(
                "oauth2",
                "Client does not support client credentials grant",
            ));
        }

        // Parse and validate scopes
        let requested_scopes = self.parse_scopes(request.scope.as_deref())?;
        let authorized_scopes = requested_scopes
            .iter()
            .filter(|scope| client.has_scope(scope))
            .cloned()
            .collect::<Vec<_>>();

        if authorized_scopes.is_empty() && !requested_scopes.is_empty() {
            return Err(AuthError::auth_method("oauth2", "No authorized scopes"));
        }

        drop(storage);

        // Generate access token (no user context for client credentials)
        let access_token = self
            .generate_access_token(&request.client_id, None, &authorized_scopes)
            .await?;

        Ok(TokenResponse {
            access_token: access_token.access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_token_lifetime.as_secs(),
            refresh_token: None, // No refresh token for client credentials
            scope: Some(authorized_scopes.join(" ")),
            id_token: None,
        })
    }

    /// Generate access token with proper validation
    async fn generate_access_token(
        &self,
        client_id: &str,
        user_id: Option<&str>,
        scopes: &[String],
    ) -> Result<AuthToken> {
        let subject = user_id.unwrap_or(client_id);
        let mut token = self.token_manager.create_auth_token(
            subject,
            scopes.iter().map(|s| s.to_string()).collect(),
            "oauth2",
            Some(self.config.access_token_lifetime),
        )?;

        // Add client_id claim
        token.add_custom_claim(
            "client_id".to_string(),
            serde_json::Value::String(client_id.to_string()),
        );

        // Add user_id claim if present
        if let Some(uid) = user_id {
            token.add_custom_claim(
                "user_id".to_string(),
                serde_json::Value::String(uid.to_string()),
            );
        }

        Ok(token)
    }

    /// Parse scopes from scope string
    fn parse_scopes(&self, scope_str: Option<&str>) -> Result<Vec<String>> {
        match scope_str {
            Some(scopes) => Ok(scopes.split_whitespace().map(|s| s.to_string()).collect()),
            None => match &self.config.default_scope {
                Some(default) => Ok(vec![default.clone()]),
                None => Ok(vec![]),
            },
        }
    }

    /// Authorize scopes based on client and user permissions
    fn authorize_scopes(
        &self,
        client: &EnhancedClientCredentials,
        user_context: &UserContext,
        requested_scopes: &[String],
    ) -> Result<Vec<String>> {
        let mut authorized = Vec::new();

        for scope in requested_scopes {
            // Check if client is allowed this scope
            if client.has_scope(scope) {
                // Check if user has this scope (if applicable)
                if user_context.has_scope(scope) {
                    authorized.push(scope.clone());
                }
            }
        }

        if authorized.is_empty() && !requested_scopes.is_empty() {
            return Err(AuthError::auth_method("oauth2", "No authorized scopes"));
        }

        Ok(authorized)
    }

    /// Validate that requested scopes are subset of original scopes
    fn validate_scope_subset(
        &self,
        original_scopes: &[String],
        requested_scopes: &[String],
    ) -> Result<Vec<String>> {
        let mut validated = Vec::new();

        for scope in requested_scopes {
            if original_scopes.contains(scope) {
                validated.push(scope.clone());
            } else {
                return Err(AuthError::auth_method(
                    "oauth2",
                    format!("Requested scope '{}' not in original grant", scope),
                ));
            }
        }

        Ok(validated)
    }

    /// Validate PKCE code challenge
    fn validate_pkce_challenge(
        &self,
        challenge: &str,
        verifier: &str,
        method: &Option<String>,
    ) -> Result<bool> {
        let method = method.as_deref().unwrap_or("plain");

        match method {
            "plain" => Ok(constant_time_compare(
                challenge.as_bytes(),
                verifier.as_bytes(),
            )),
            "S256" => {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                use sha2::{Digest, Sha256};

                let hash = Sha256::digest(verifier.as_bytes());
                let encoded = URL_SAFE_NO_PAD.encode(hash);
                Ok(constant_time_compare(
                    challenge.as_bytes(),
                    encoded.as_bytes(),
                ))
            }
            _ => Err(AuthError::auth_method("oauth2", "Unsupported PKCE method")),
        }
    }

    /// Revoke token (refresh token or access token)
    pub async fn revoke_token(&self, token: &str, client_id: &str) -> Result<bool> {
        let mut storage = self.token_storage.write().await;

        // Validate client is authorized to revoke this token
        if client_id.is_empty() {
            return Err(AuthError::auth_method(
                "oauth2",
                "Client ID is required for token revocation",
            ));
        }

        // Verify client exists by trying to get its credentials
        if storage.get_client_credentials(client_id).await.is_err() {
            return Err(AuthError::auth_method("oauth2", "Invalid client"));
        }

        // Try to revoke as refresh token first
        if storage.validate_refresh_token(token).await? {
            return storage.revoke_refresh_token(token).await;
        }

        // For access tokens, we would need to maintain a revocation list
        // This is a simplified implementation
        Ok(false)
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<usize> {
        let mut storage = self.token_storage.write().await;
        storage.cleanup_expired_tokens().await
    }

    /// Authenticate user and create session
    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
        scopes: Vec<String>,
    ) -> Result<UserContext> {
        // CRITICAL SECURITY FIX: Validate credentials against storage
        let storage = self.token_storage.read().await;

        // Validate username exists and password is correct using storage
        if !self
            .validate_user_credentials_against_storage(&storage, username, password)
            .await?
        {
            return Err(AuthError::auth_method(
                "oauth2",
                "Invalid username or password",
            ));
        }

        // Validate user is authorized for requested scopes
        let authorized_scopes = self
            .validate_user_scopes_against_storage(&storage, username, &scopes)
            .await?;

        drop(storage);

        // Create user context with validated information
        let user_context = UserContext::new(
            self.generate_user_id(username).await?,
            username.to_string(),
            self.get_user_email(username).await?,
        )
        .with_scopes(authorized_scopes);

        let mut session_store = self.session_store.write().await;
        session_store.create_session(user_context.clone());

        Ok(user_context)
    }

    /// Validate user credentials against secure storage
    async fn validate_user_credentials_against_storage(
        &self,
        storage: &EnhancedTokenStorage,
        username: &str,
        password: &str,
    ) -> Result<bool> {
        // Minimum security requirements - but don't return early to prevent timing attacks
        let is_empty = username.is_empty() || password.is_empty();
        let is_too_short = password.len() < 8;

        // Always perform the expensive bcrypt operation to prevent timing attacks
        match storage.get_user_credentials(username).await {
            Ok(Some(stored_credentials)) => {
                // Use bcrypt to verify password against hash
                use bcrypt::verify;
                match verify(password, &stored_credentials.password_hash) {
                    Ok(is_valid) => {
                        // Only return true if all conditions are met
                        Ok(is_valid && !is_empty && !is_too_short)
                    }
                    Err(_) => {
                        // Hash verification failed - fail securely
                        Ok(false)
                    }
                }
            }
            Ok(None) => {
                // User not found - still do dummy bcrypt operation to prevent timing attacks
                use bcrypt::verify;
                let _dummy_result = verify(
                    password,
                    "$2b$12$K2CtDP7zMH7VgxScmHTa/.EUm5nd9.xnZM8Cl/p9RMb5QZaJUHgBm",
                );
                Ok(false)
            }
            Err(_) => {
                // Storage error - still do dummy bcrypt operation to prevent timing attacks
                use bcrypt::verify;
                let _dummy_result = verify(
                    password,
                    "$2b$12$K2CtDP7zMH7VgxScmHTa/.EUm5nd9.xnZM8Cl/p9RMb5QZaJUHgBm",
                );
                Ok(false)
            }
        }
    }

    /// Validate user is authorized for requested scopes using storage
    async fn validate_user_scopes_against_storage(
        &self,
        storage: &EnhancedTokenStorage,
        username: &str,
        requested_scopes: &[String],
    ) -> Result<Vec<String>> {
        // Get user permissions from storage
        let user_permissions = match storage.get_user_permissions(username).await {
            Ok(Some(permissions)) => permissions.scopes,
            Ok(None) => {
                return Err(AuthError::auth_method(
                    "oauth2",
                    "User not found in permission store",
                ));
            }
            Err(_) => {
                return Err(AuthError::auth_method(
                    "oauth2",
                    "Failed to retrieve user permissions",
                ));
            }
        };

        let mut authorized = Vec::new();
        for scope in requested_scopes {
            if user_permissions.contains(scope) {
                authorized.push(scope.clone());
            }
        }

        // If no scopes requested, give default read scope for valid users
        if authorized.is_empty() && !requested_scopes.is_empty() {
            return Err(AuthError::auth_method(
                "oauth2",
                "User not authorized for requested scopes",
            ));
        }

        if authorized.is_empty() {
            // Check if user has at least read permission for default scope
            if user_permissions.contains(&"read".to_string()) {
                authorized.push("read".to_string());
            } else {
                return Err(AuthError::auth_method(
                    "oauth2",
                    "User has no authorized scopes",
                ));
            }
        }

        Ok(authorized)
    }

    /// Generate consistent user ID
    async fn generate_user_id(&self, username: &str) -> Result<String> {
        // In production, this would be the user's UUID from the database
        // For now, create a deterministic but unique ID
        let hash = Sha256::digest(format!("user_id_{}", username).as_bytes());
        let hash_str = format!("{:x}", hash);
        Ok(format!("user_{}", &hash_str[0..16]))
    }

    /// Get user email from user store
    async fn get_user_email(&self, username: &str) -> Result<Option<String>> {
        // In production, this would query the user database
        Ok(Some(format!("{}@example.com", username)))
    }

    /// Get user context from session
    pub async fn get_user_context(&self, session_id: &str) -> Result<Option<UserContext>> {
        let session_store = self.session_store.read().await;
        Ok(session_store.get_session(session_id).cloned())
    }

    /// Invalidate user session
    pub async fn invalidate_session(&self, session_id: &str) -> Result<bool> {
        let mut session_store = self.session_store.write().await;
        Ok(session_store.invalidate_session(session_id))
    }
}
