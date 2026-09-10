//! Enhanced OAuth2 token and code storage with proper validation

use crate::client::ClientType;
use crate::errors::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use uuid::Uuid;

/// Stored refresh token with validation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token_id: String,
    pub client_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub is_revoked: bool,
}

impl RefreshToken {
    pub fn new(
        client_id: String,
        user_id: String,
        scopes: Vec<String>,
        lifetime: std::time::Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            token_id: Uuid::new_v4().to_string(),
            client_id,
            user_id,
            scopes,
            issued_at: now,
            expires_at: now + lifetime,
            is_revoked: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.is_revoked && !self.is_expired()
    }

    pub fn revoke(&mut self) {
        self.is_revoked = true;
    }
}

/// Enhanced authorization code with user context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub is_used: bool,
}

impl EnhancedAuthorizationCode {
    pub fn new(
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scopes: Vec<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        lifetime: std::time::Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            code: Uuid::new_v4().to_string(),
            client_id,
            user_id,
            redirect_uri,
            scopes,
            code_challenge,
            code_challenge_method,
            issued_at: now,
            expires_at: now + lifetime,
            is_used: false,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn is_valid(&self) -> bool {
        !self.is_used && !self.is_expired()
    }

    pub fn mark_used(&mut self) {
        self.is_used = true;
    }
}

/// Enhanced client credentials with proper secret validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedClientCredentials {
    pub client_id: String,
    pub client_secret_hash: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub grant_types: Vec<String>,
    pub created_at: SystemTime,
    pub is_active: bool,
}

impl EnhancedClientCredentials {
    pub fn new_confidential(
        client_id: String,
        client_secret: &str,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        grant_types: Vec<String>,
    ) -> Result<Self> {
        use crate::security::secure_utils::hash_password_bcrypt;

        Ok(Self {
            client_id,
            client_secret_hash: hash_password_bcrypt(client_secret)?,
            client_type: ClientType::Confidential,
            redirect_uris,
            allowed_scopes,
            grant_types,
            created_at: SystemTime::now(),
            is_active: true,
        })
    }

    pub fn new_public(
        client_id: String,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        grant_types: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_secret_hash: String::new(), // Public clients don't have secrets
            client_type: ClientType::Public,
            redirect_uris,
            allowed_scopes,
            grant_types,
            created_at: SystemTime::now(),
            is_active: true,
        }
    }

    pub fn validate_secret(&self, provided_secret: &str) -> Result<bool> {
        match self.client_type {
            ClientType::Public => Ok(true), // Public clients don't need secret validation
            ClientType::Confidential => {
                use crate::security::secure_utils::verify_password_bcrypt;
                verify_password_bcrypt(provided_secret, &self.client_secret_hash)
            }
        }
    }

    pub fn requires_secret(&self) -> bool {
        matches!(self.client_type, ClientType::Confidential)
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.allowed_scopes.contains(&scope.to_string())
    }

    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.grant_types.contains(&grant_type.to_string())
    }
}

/// Enhanced token storage with proper validation
#[derive(Debug, Clone)]
pub struct EnhancedTokenStorage {
    refresh_tokens: HashMap<String, RefreshToken>,
    authorization_codes: HashMap<String, EnhancedAuthorizationCode>,
    client_credentials: HashMap<String, EnhancedClientCredentials>,
    users: HashMap<String, UserCredentials>,
}

impl EnhancedTokenStorage {
    pub fn new() -> Self {
        Self {
            refresh_tokens: HashMap::new(),
            authorization_codes: HashMap::new(),
            client_credentials: HashMap::new(),
            users: HashMap::new(),
        }
    }

    // Refresh token operations
    pub async fn store_refresh_token(&mut self, token: RefreshToken) -> Result<String> {
        let token_id = token.token_id.clone();
        self.refresh_tokens.insert(token_id.clone(), token);
        Ok(token_id)
    }

    pub async fn get_refresh_token(&self, token_id: &str) -> Result<Option<RefreshToken>> {
        Ok(self.refresh_tokens.get(token_id).cloned())
    }

    pub async fn validate_refresh_token(&self, token_id: &str) -> Result<bool> {
        match self.refresh_tokens.get(token_id) {
            Some(token) => Ok(token.is_valid()),
            None => Ok(false),
        }
    }

    pub async fn revoke_refresh_token(&mut self, token_id: &str) -> Result<bool> {
        match self.refresh_tokens.get_mut(token_id) {
            Some(token) => {
                token.revoke();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    // Authorization code operations
    pub async fn store_authorization_code(
        &mut self,
        code: EnhancedAuthorizationCode,
    ) -> Result<String> {
        let code_value = code.code.clone();
        self.authorization_codes.insert(code_value.clone(), code);
        Ok(code_value)
    }

    pub async fn get_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<EnhancedAuthorizationCode>> {
        Ok(self.authorization_codes.get(code).cloned())
    }

    pub async fn consume_authorization_code(
        &mut self,
        code: &str,
    ) -> Result<Option<EnhancedAuthorizationCode>> {
        match self.authorization_codes.get_mut(code) {
            Some(auth_code) if auth_code.is_valid() => {
                auth_code.mark_used();
                Ok(Some(auth_code.clone()))
            }
            _ => Ok(None),
        }
    }

    // Client credentials operations
    pub async fn store_client_credentials(
        &mut self,
        credentials: EnhancedClientCredentials,
    ) -> Result<()> {
        let client_id = credentials.client_id.clone();
        self.client_credentials.insert(client_id, credentials);
        Ok(())
    }

    pub async fn get_client_credentials(
        &self,
        client_id: &str,
    ) -> Result<Option<EnhancedClientCredentials>> {
        Ok(self.client_credentials.get(client_id).cloned())
    }

    pub async fn validate_client_credentials(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<bool> {
        match self.client_credentials.get(client_id) {
            Some(credentials) if credentials.is_active => {
                if credentials.requires_secret() {
                    match client_secret {
                        Some(secret) => credentials.validate_secret(secret),
                        None => Ok(false), // Secret required but not provided
                    }
                } else {
                    Ok(true) // Public client, no secret required
                }
            }
            _ => Ok(false), // Client not found or inactive
        }
    }

    // Cleanup operations
    pub async fn cleanup_expired_tokens(&mut self) -> Result<usize> {
        let initial_count = self.refresh_tokens.len() + self.authorization_codes.len();

        // Remove expired refresh tokens
        self.refresh_tokens.retain(|_, token| token.is_valid());

        // Remove expired authorization codes
        self.authorization_codes.retain(|_, code| code.is_valid());

        let final_count = self.refresh_tokens.len() + self.authorization_codes.len();
        Ok(initial_count - final_count)
    }

    // User credential management methods

    /// Store user credentials
    pub async fn store_user_credentials(&mut self, creds: UserCredentials) -> Result<()> {
        self.users.insert(creds.username.clone(), creds);
        Ok(())
    }

    /// Get user credentials for authentication
    pub async fn get_user_credentials(&self, username: &str) -> Result<Option<UserCredentials>> {
        Ok(self.users.get(username).cloned())
    }

    /// Get user permissions/scopes
    pub async fn get_user_permissions(&self, username: &str) -> Result<Option<UserPermissions>> {
        // Get credentials which include permissions
        if let Some(credentials) = self.get_user_credentials(username).await? {
            Ok(Some(UserPermissions {
                username: credentials.username,
                scopes: credentials.scopes,
                is_active: credentials.is_active,
            }))
        } else {
            Ok(None)
        }
    }
}

/// User credentials stored in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCredentials {
    pub username: String,
    pub password_hash: String, // In production: bcrypt/argon2 hash
    pub scopes: Vec<String>,
    pub is_active: bool,
    /// The user's email address. Optional for backwards compatibility with stored
    /// credentials that pre-date this field; `None` means the email is not on record.
    #[serde(default)]
    pub email: Option<String>,
}

/// User permissions/scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissions {
    pub username: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
}

impl Default for EnhancedTokenStorage {
    fn default() -> Self {
        Self::new()
    }
}
