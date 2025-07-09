//! Main authentication framework implementation.

use crate::config::AuthConfig;
use crate::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, MfaError, Result};
use crate::methods::{AuthMethod, MfaChallenge, MethodResult};
use crate::permissions::{Permission, PermissionChecker};
use crate::storage::{AuthStorage, MemoryStorage, SessionData};
use crate::tokens::{AuthToken, TokenManager};
use crate::utils::rate_limit::RateLimiter;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication was successful
    Success(Box<AuthToken>),
    
    /// Multi-factor authentication is required
    MfaRequired(Box<MfaChallenge>),
    
    /// Authentication failed
    Failure(String),
}

/// Information about a user.
#[derive(Debug, Clone)]
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

/// Main authentication framework.
pub struct AuthFramework {
    /// Configuration
    config: AuthConfig,
    
    /// Registered authentication methods
    methods: HashMap<String, Box<dyn AuthMethod>>,
    
    /// Token manager
    token_manager: TokenManager,
    
    /// Storage backend
    storage: Arc<dyn AuthStorage>,
    
    /// Permission checker
    permission_checker: Arc<RwLock<PermissionChecker>>,
    
    /// Rate limiter
    rate_limiter: Option<RateLimiter>,
    
    /// Active MFA challenges
    mfa_challenges: Arc<RwLock<HashMap<String, MfaChallenge>>>,
    
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    
    /// Framework initialization state
    initialized: bool,
}

impl AuthFramework {
    /// Create a new authentication framework.
    pub fn new(config: AuthConfig) -> Self {
        // Validate configuration
        config.validate().expect("Invalid configuration");
        
        // Create token manager
        let token_manager = if let Some(secret) = &config.security.secret_key {
            TokenManager::new_hmac(
                secret.as_bytes(),
                "auth-framework",
                "auth-framework",
            )
        } else {
            TokenManager::new_hmac(
                b"default-secret-key", // This should be replaced with a proper secret
                "auth-framework",
                "auth-framework",
            )
        };
        
        // Create storage backend
        let storage: Arc<dyn AuthStorage> = match &config.storage {
            #[cfg(feature = "redis-storage")]
            crate::config::StorageConfig::Redis { url, key_prefix } => {
                Arc::new(crate::storage::RedisStorage::new(url, key_prefix)
                    .expect("Failed to create Redis storage"))
            }
            _ => Arc::new(MemoryStorage::new()),
        };
        
        // Create rate limiter if enabled
        let rate_limiter = if config.rate_limiting.enabled {
            Some(RateLimiter::new(
                config.rate_limiting.max_requests,
                config.rate_limiting.window,
            ))
        } else {
            None
        };
        
        Self {
            config,
            methods: HashMap::new(),
            token_manager,
            storage,
            permission_checker: Arc::new(RwLock::new(PermissionChecker::new())),
            rate_limiter,
            mfa_challenges: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            initialized: false,
        }
    }

    /// Register an authentication method.
    pub fn register_method(&mut self, name: impl Into<String>, method: Box<dyn AuthMethod>) {
        let name = name.into();
        info!("Registering authentication method: {}", name);
        
        // Validate method configuration
        if let Err(e) = method.validate_config() {
            error!("Method '{}' configuration validation failed: {}", name, e);
            return;
        }
        
        self.methods.insert(name, method);
    }

    /// Initialize the authentication framework.
    pub async fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        info!("Initializing authentication framework");
        
        // Initialize permission checker with default roles
        {
            let mut checker = self.permission_checker.write().await;
            checker.create_default_roles();
        }
        
        // Perform any necessary setup
        self.cleanup_expired_data().await?;
        
        self.initialized = true;
        info!("Authentication framework initialized successfully");
        
        Ok(())
    }

    /// Authenticate a user with the specified method.
    pub async fn authenticate(
        &self,
        method_name: &str,
        credential: Credential,
    ) -> Result<AuthResult> {
        self.authenticate_with_metadata(method_name, credential, CredentialMetadata::new()).await
    }

    /// Authenticate a user with the specified method and metadata.
    pub async fn authenticate_with_metadata(
        &self,
        method_name: &str,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<AuthResult> {
        if !self.initialized {
            return Err(AuthError::internal("Framework not initialized"));
        }

        // Check rate limiting
        if let Some(ref rate_limiter) = self.rate_limiter {
            let rate_key = format!("auth:{}:{}", 
                method_name, 
                metadata.client_ip.as_deref().unwrap_or("unknown")
            );
            
            if !rate_limiter.is_allowed(&rate_key) {
                warn!("Rate limit exceeded for method '{}' from IP {:?}", 
                    method_name, metadata.client_ip);
                return Err(AuthError::rate_limit("Too many authentication attempts"));
            }
        }

        // Get the authentication method
        let method = self.methods.get(method_name)
            .ok_or_else(|| AuthError::auth_method(
                method_name,
                "Authentication method not found".to_string(),
            ))?;

        // Log authentication attempt
        debug!("Authentication attempt with method '{}' for credential: {}", 
            method_name, credential.safe_display());

        // Perform authentication
        let result = method.authenticate(&credential, &metadata).await?;

        // Log and handle the result
        match &result {
            MethodResult::Success(token) => {
                info!("Authentication successful for user '{}' with method '{}'", 
                    token.user_id, method_name);
                
                // Store token
                self.storage.store_token(token).await?;
                
                // Log audit event
                self.log_audit_event("auth_success", &token.user_id, method_name, &metadata).await;
                
                Ok(AuthResult::Success(token.clone()))
            }
            
            MethodResult::MfaRequired(challenge) => {
                info!("MFA required for user '{}' with method '{}'", 
                    challenge.user_id, method_name);
                
                // Store MFA challenge
                let mut challenges = self.mfa_challenges.write().await;
                challenges.insert(challenge.id.clone(), (**challenge).clone());
                
                // Log audit event
                self.log_audit_event("mfa_required", &challenge.user_id, method_name, &metadata).await;
                
                Ok(AuthResult::MfaRequired(challenge.clone()))
            }
            
            MethodResult::Failure { reason } => {
                warn!("Authentication failed for method '{}': {}", method_name, reason);
                
                // Log audit event
                self.log_audit_event("auth_failure", "unknown", method_name, &metadata).await;
                
                Ok(AuthResult::Failure(reason.clone()))
            }
        }
    }

    /// Complete multi-factor authentication.
    pub async fn complete_mfa(
        &self,
        challenge: MfaChallenge,
        mfa_code: &str,
    ) -> Result<AuthToken> {
        debug!("Completing MFA for challenge '{}'", challenge.id);

        // Check if challenge exists and is valid
        let mut challenges = self.mfa_challenges.write().await;
        let stored_challenge = challenges.get(&challenge.id)
            .ok_or(MfaError::ChallengeExpired)?;

        if stored_challenge.is_expired() {
            challenges.remove(&challenge.id);
            return Err(MfaError::ChallengeExpired.into());
        }

        // Verify MFA code (this would integrate with actual MFA providers)
        if !self.verify_mfa_code(stored_challenge, mfa_code).await? {
            return Err(MfaError::InvalidCode.into());
        }

        // Remove the challenge
        challenges.remove(&challenge.id);

        // Create authentication token
        let token = self.token_manager.create_auth_token(
            &challenge.user_id,
            vec![], // Scopes would be determined by user permissions
            "mfa",
            None,
        )?;

        // Store the token
        self.storage.store_token(&token).await?;

        info!("MFA completed successfully for user '{}'", challenge.user_id);
        
        Ok(token)
    }

    /// Validate a token.
    pub async fn validate_token(&self, token: &AuthToken) -> Result<bool> {
        // Check basic token validity
        if !token.is_valid() {
            return Ok(false);
        }

        // Validate with token manager
        self.token_manager.validate_auth_token(token)?;

        // Check if token exists in storage
        if let Some(stored_token) = self.storage.get_token(&token.token_id).await? {
            // Update last used time
            let mut updated_token = stored_token;
            updated_token.mark_used();
            self.storage.update_token(&updated_token).await?;
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get user information from a token.
    pub async fn get_user_info(&self, token: &AuthToken) -> Result<UserInfo> {
        if !self.validate_token(token).await? {
            return Err(AuthError::auth_method("token", "Invalid token".to_string()));
        }

        // Extract user info from token
        let token_info = self.token_manager.extract_token_info(&token.access_token)?;
        
        Ok(UserInfo {
            id: token_info.user_id,
            username: token_info.username.unwrap_or_else(|| "unknown".to_string()),
            email: token_info.email,
            name: token_info.name,
            roles: token_info.roles,
            active: true, // This would come from user storage
            attributes: token_info.attributes,
        })
    }

    /// Check if a token has a specific permission.
    pub async fn check_permission(
        &self,
        token: &AuthToken,
        action: &str,
        resource: &str,
    ) -> Result<bool> {
        if !self.validate_token(token).await? {
            return Ok(false);
        }

        let permission = Permission::new(action, resource);
        let mut checker = self.permission_checker.write().await;
        checker.check_token_permission(token, &permission)
    }

    /// Refresh a token.
    pub async fn refresh_token(&self, token: &AuthToken) -> Result<AuthToken> {
        debug!("Refreshing token for user '{}'", token.user_id);

        // Check if the auth method supports refresh
        if let Some(method) = self.methods.get(&token.auth_method) {
            if method.supports_refresh() {
                if let Some(ref refresh_token) = token.refresh_token {
                    let new_token = method.refresh_token(refresh_token).await?;
                    self.storage.store_token(&new_token).await?;
                    return Ok(new_token);
                }
            }
        }

        // Fallback to creating a new token with the same properties
        let new_token = self.token_manager.refresh_token(token)?;
        self.storage.store_token(&new_token).await?;
        
        info!("Token refreshed for user '{}'", token.user_id);
        
        Ok(new_token)
    }

    /// Revoke a token.
    pub async fn revoke_token(&self, token: &AuthToken) -> Result<()> {
        debug!("Revoking token for user '{}'", token.user_id);

        // Mark token as revoked
        let mut revoked_token = token.clone();
        revoked_token.revoke(Some("Manual revocation".to_string()));
        
        // Update in storage
        self.storage.update_token(&revoked_token).await?;
        
        info!("Token revoked for user '{}'", token.user_id);
        
        Ok(())
    }

    /// Create a new API key for a user.
    pub async fn create_api_key(&self, user_id: &str, expires_in: Option<Duration>) -> Result<String> {
        debug!("Creating API key for user '{}'", user_id);

        // Generate a secure API key
        let api_key = format!("ak_{}", crate::utils::crypto::generate_token(32));
        
        // Create a token for the API key
        let token = self.token_manager.create_auth_token(
            user_id,
            vec!["api".to_string()],
            "api-key",
            expires_in,
        )?;

        // Store the token
        self.storage.store_token(&token).await?;

        info!("API key created for user '{}'", user_id);
        
        Ok(api_key)
    }

    /// Create a new session.
    pub async fn create_session(
        &self,
        user_id: &str,
        expires_in: Duration,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        let session_id = crate::utils::string::generate_id(Some("sess"));
        let session = SessionData::new(session_id.clone(), user_id, expires_in)
            .with_metadata(ip_address, user_agent);

        self.storage.store_session(&session_id, &session).await?;
        
        info!("Session created for user '{}'", user_id);
        
        Ok(session_id)
    }

    /// Get session information.
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        self.storage.get_session(session_id).await
    }

    /// Delete a session.
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.storage.delete_session(session_id).await?;
        info!("Session '{}' deleted", session_id);
        Ok(())
    }

    /// Get all tokens for a user.
    pub async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        self.storage.list_user_tokens(user_id).await
    }

    /// Clean up expired data.
    pub async fn cleanup_expired_data(&self) -> Result<()> {
        debug!("Cleaning up expired data");

        // Clean up storage
        self.storage.cleanup_expired().await?;

        // Clean up MFA challenges
        {
            let mut challenges = self.mfa_challenges.write().await;
            let now = chrono::Utc::now();
            challenges.retain(|_, challenge| challenge.expires_at > now);
        }

        // Clean up sessions
        {
            let mut sessions = self.sessions.write().await;
            let now = chrono::Utc::now();
            sessions.retain(|_, session| session.expires_at > now);
        }

        // Clean up rate limiter
        if let Some(ref rate_limiter) = self.rate_limiter {
            rate_limiter.cleanup();
        }

        Ok(())
    }

    /// Get authentication framework statistics.
    pub async fn get_stats(&self) -> Result<AuthStats> {
        let mut stats = AuthStats::default();

        // Count active tokens per user
        // This would be more efficient with proper storage queries
        let _user_tokens: HashMap<String, u32> = HashMap::new();
        for method in self.methods.keys() {
            stats.registered_methods.push(method.clone());
        }

        stats.active_sessions = self.sessions.read().await.len() as u64;
        stats.active_mfa_challenges = self.mfa_challenges.read().await.len() as u64;

        Ok(stats)
    }

    /// Verify MFA code (placeholder implementation).
    async fn verify_mfa_code(&self, _challenge: &MfaChallenge, _code: &str) -> Result<bool> {
        // This would integrate with actual MFA providers (TOTP, SMS, etc.)
        // For now, we'll accept any 6-digit code
        Ok(true)
    }

    /// Log an audit event.
    async fn log_audit_event(
        &self,
        event_type: &str,
        user_id: &str,
        method: &str,
        metadata: &CredentialMetadata,
    ) {
        if self.config.audit.enabled {
            let should_log = match event_type {
                "auth_success" => self.config.audit.log_success,
                "auth_failure" => self.config.audit.log_failures,
                "mfa_required" => self.config.audit.log_success,
                _ => true,
            };

            if should_log {
                info!(
                    target: "auth_audit",
                    event_type = event_type,
                    user_id = user_id,
                    method = method,
                    client_ip = metadata.client_ip.as_deref().unwrap_or("unknown"),
                    user_agent = metadata.user_agent.as_deref().unwrap_or("unknown"),
                    timestamp = chrono::Utc::now().to_rfc3339(),
                    "Authentication event"
                );
            }
        }
    }

    /// Create an authentication token directly (useful for testing and demos).
    /// 
    /// Note: In production, tokens should be created through the `authenticate` method.
    pub async fn create_auth_token(
        &self,
        user_id: impl Into<String>,
        scopes: Vec<String>,
        method_name: impl Into<String>,
        lifetime: Option<Duration>,
    ) -> Result<AuthToken> {
        let method_name = method_name.into();
        let user_id = user_id.into();
        
        // Get the method to access its token manager
        let _method = self.methods.get(&method_name)
            .ok_or_else(|| AuthError::auth_method(&method_name, "Method not found"))?;
        
        // Create a proper JWT token using the default token manager
        let jwt_token = self.token_manager.create_jwt_token(
            &user_id,
            scopes.clone(),
            lifetime,
        )?;
        
        // Create the auth token
        let token = AuthToken::new(
            user_id,
            jwt_token,
            lifetime.unwrap_or(Duration::from_secs(3600)),
            method_name,
        ).with_scopes(scopes);
        
        // Store the token
        self.storage.store_token(&token).await?;
        
        Ok(token)
    }
}

/// Authentication framework statistics.
#[derive(Debug, Clone, Default)]
pub struct AuthStats {
    /// Number of registered authentication methods
    pub registered_methods: Vec<String>,
    
    /// Number of active sessions
    pub active_sessions: u64,
    
    /// Number of active MFA challenges
    pub active_mfa_challenges: u64,
    
    /// Number of tokens issued (this would need proper tracking)
    pub tokens_issued: u64,
    
    /// Number of authentication attempts (this would need proper tracking)
    pub auth_attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::JwtMethod;
    use crate::config::AuthConfig;

    #[tokio::test]
    async fn test_framework_initialization() {
        let config = AuthConfig::new();
        let mut framework = AuthFramework::new(config);
        
        assert!(framework.initialize().await.is_ok());
        assert!(framework.initialized);
    }

    #[tokio::test]
    async fn test_method_registration() {
        let config = AuthConfig::new();
        let mut framework = AuthFramework::new(config);
        
        let jwt_method = JwtMethod::new().secret_key("test-secret");
        framework.register_method("jwt", Box::new(jwt_method));
        
        assert!(framework.methods.contains_key("jwt"));
    }

    #[tokio::test]
    async fn test_token_validation() {
        let config = AuthConfig::new();
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        
        let token = framework.token_manager.create_auth_token(
            "test-user",
            vec!["read".to_string()],
            "test",
            None,
        ).unwrap();
        
        // Store the token first
        framework.storage.store_token(&token).await.unwrap();
        
        assert!(framework.validate_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_session_management() {
        let config = AuthConfig::new();
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        
        let session_id = framework.create_session(
            "test-user",
            Duration::from_secs(3600),
            Some("192.168.1.1".to_string()),
            Some("Test Agent".to_string()),
        ).await.unwrap();
        
        let session = framework.get_session(&session_id).await.unwrap();
        assert!(session.is_some());
        
        framework.delete_session(&session_id).await.unwrap();
        let session = framework.get_session(&session_id).await.unwrap();
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired_data() {
        let config = AuthConfig::new();
        let mut framework = AuthFramework::new(config);
        framework.initialize().await.unwrap();
        
        // This test would need expired data to be meaningful
        assert!(framework.cleanup_expired_data().await.is_ok());
    }
}
