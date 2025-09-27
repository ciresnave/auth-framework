//! Modular authentication framework with component-based architecture.
//!
//! This module provides a modular approach to authentication and authorization,
//! allowing fine-grained control over individual components while maintaining
//! the same high-level API as the main `AuthFramework`.
//!
//! # Architecture
//!
//! The modular framework separates concerns into distinct managers:
//! - **MFA Manager**: Multi-factor authentication coordination
//! - **Session Manager**: Session lifecycle and security
//! - **User Manager**: User account and profile management
//! - **Token Manager**: JWT token creation and validation
//! - **Permission Checker**: Authorization and access control
//!
//! # Benefits of Modular Design
//!
//! - **Composability**: Use only the components you need
//! - **Testability**: Test individual components in isolation
//! - **Extensibility**: Replace or extend specific managers
//! - **Memory Efficiency**: Reduced memory footprint for specialized use cases
//! - **Performance**: Optimized component interactions
//!
//! # Component Independence
//!
//! Each manager can operate independently while sharing common storage
//! and configuration. This allows for:
//! - Microservice deployment patterns
//! - Custom authentication flows
//! - Progressive feature adoption
//! - A/B testing of authentication methods
//!
//! # Example
//!
//! ```rust
//! use auth_framework::auth_modular::AuthFramework;
//! use auth_framework::config::AuthConfig;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create modular framework with JWT secret
//! let mut config = AuthConfig::default();
//! config.security.secret_key = Some("a_very_strong_secret_of_32_plus_chars_123".to_string());
//! let auth = AuthFramework::new(config);
//!
//! // Access individual managers
//! let mfa_manager = auth.mfa_manager();
//! let session_manager = auth.session_manager();
//! let user_manager = auth.user_manager();
//! # Ok(())
//! # }
//! ```
//!
//! # Migration from Monolithic Framework
//!
//! The modular framework maintains API compatibility with the main framework,
//! making migration straightforward while providing additional flexibility.

pub mod mfa;
pub mod session_manager;
pub mod user_manager;

use crate::authentication::credentials::{Credential, CredentialMetadata};
use crate::config::AuthConfig;
use crate::errors::{AuthError, MfaError, Result};
use crate::methods::{AuthMethod, AuthMethodEnum, MethodResult, MfaChallenge};
use crate::permissions::{Permission, PermissionChecker};
use crate::storage::{AuthStorage, MemoryStorage};
use crate::tokens::{AuthToken, TokenManager};
use crate::utils::rate_limit::RateLimiter;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub use mfa::MfaManager;
pub use session_manager::SessionManager;
pub use user_manager::{UserInfo, UserManager};

/// Result of an authentication attempt
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication was successful
    Success(Box<AuthToken>),

    /// Multi-factor authentication is required
    MfaRequired(Box<MfaChallenge>),

    /// Authentication failed
    Failure(String),
}

/// Main authentication framework - now focused and modular
pub struct AuthFramework {
    /// Configuration
    config: AuthConfig,

    /// Registered authentication methods
    methods: HashMap<String, AuthMethodEnum>,

    /// Token manager
    token_manager: TokenManager,

    /// Storage backend
    storage: Arc<dyn AuthStorage>,

    /// Permission checker
    permission_checker: Arc<RwLock<PermissionChecker>>,

    /// Rate limiter
    rate_limiter: Option<RateLimiter>,

    /// MFA manager
    mfa_manager: MfaManager,

    /// Session manager
    session_manager: SessionManager,

    /// User manager
    user_manager: UserManager,

    /// Framework initialization state
    initialized: bool,
}

impl AuthFramework {
    /// Create a new authentication framework
    pub fn new(config: AuthConfig) -> Self {
        // Validate configuration
        if let Err(e) = config.validate() {
            panic!("Invalid configuration: {}", e);
        }

        // Create token manager
        let token_manager = if let Some(secret) = &config.security.secret_key {
            if secret.len() < 32 {
                eprintln!(
                    "WARNING: JWT secret is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(secret.as_bytes(), "auth-framework", "auth-framework")
        } else if let Some(secret) = &config.secret {
            if secret.len() < 32 {
                eprintln!(
                    "WARNING: JWT secret is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(secret.as_bytes(), "auth-framework", "auth-framework")
        } else if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            if jwt_secret.len() < 32 {
                eprintln!(
                    "WARNING: JWT_SECRET is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(jwt_secret.as_bytes(), "auth-framework", "auth-framework")
        } else {
            panic!(
                "JWT secret not set! Please set JWT_SECRET env variable or provide in config.\n\
                   For security reasons, no default secret is provided.\n\
                   Generate a secure secret with: openssl rand -base64 32"
            );
        };

        // Create storage backend
        let storage: Arc<dyn AuthStorage> = match &config.storage {
            #[cfg(feature = "redis-storage")]
            crate::config::StorageConfig::Redis { url, key_prefix } => Arc::new(
                crate::storage::RedisStorage::new(url, key_prefix).unwrap_or_else(|e| {
                    panic!("Failed to create Redis storage: {}", e);
                }),
            ),
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

        // Create specialized managers
        let mfa_manager = MfaManager::new(storage.clone());
        let session_manager = SessionManager::new(storage.clone());
        let user_manager = UserManager::new(storage.clone());

        Self {
            config,
            methods: HashMap::new(),
            token_manager,
            storage,
            permission_checker: Arc::new(RwLock::new(PermissionChecker::new())),
            rate_limiter,
            mfa_manager,
            session_manager,
            user_manager,
            initialized: false,
        }
    }

    /// Replace the storage backend with a custom implementation.
    ///
    /// This will swap the internal storage Arc and recreate dependent managers so
    /// they use the provided storage instance.
    pub fn replace_storage(&mut self, storage: Arc<dyn AuthStorage>) {
        // Replace storage
        self.storage = storage.clone();

        // Recreate managers that depend on storage
        self.mfa_manager = MfaManager::new(self.storage.clone());
        self.session_manager = SessionManager::new(self.storage.clone());
        self.user_manager = UserManager::new(self.storage.clone());
    }

    /// Convenience constructor that creates a framework with a custom storage instance.
    pub fn new_with_storage(config: AuthConfig, storage: Arc<dyn AuthStorage>) -> Self {
        let mut framework = Self::new(config);
        framework.replace_storage(storage);
        framework
    }

    /// Create a new framework with SMSKit configuration
    #[cfg(feature = "smskit")]
    pub fn new_with_smskit_config(
        config: AuthConfig,
        smskit_config: crate::auth_modular::mfa::SmsKitConfig,
    ) -> Result<Self> {
        // First create the framework normally
        let mut framework = Self::new(config);

        // Then replace the MFA manager with one configured for SMSKit
        framework.mfa_manager = crate::auth_modular::mfa::MfaManager::new_with_smskit_config(
            framework.storage.clone(),
            smskit_config,
        )?;

        Ok(framework)
    }

    /// Register an authentication method
    pub fn register_method(&mut self, name: impl Into<String>, method: AuthMethodEnum) {
        let name = name.into();
        info!("Registering authentication method: {}", name);

        // Validate method configuration
        if let Err(e) = method.validate_config() {
            error!("Method '{}' configuration validation failed: {}", name, e);
            return;
        }

        self.methods.insert(name, method);
    }

    /// Initialize the authentication framework
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

        // Perform any necessary cleanup
        self.cleanup_expired_data().await?;

        self.initialized = true;
        info!("Authentication framework initialized successfully");

        Ok(())
    }

    /// Authenticate a user with the specified method
    pub async fn authenticate(
        &self,
        method_name: &str,
        credential: Credential,
    ) -> Result<AuthResult> {
        self.authenticate_with_metadata(method_name, credential, CredentialMetadata::new())
            .await
    }

    /// Authenticate a user with the specified method and metadata
    pub async fn authenticate_with_metadata(
        &self,
        method_name: &str,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<AuthResult> {
        use std::time::Instant;
        use tokio::time::{Duration as TokioDuration, sleep};

        let start_time = Instant::now();

        if !self.initialized {
            return Err(AuthError::internal("Framework not initialized"));
        }

        // Perform the authentication logic
        let result = self
            .authenticate_internal(method_name, credential, metadata)
            .await;

        // Ensure minimum response time to prevent timing attacks
        let min_duration = TokioDuration::from_millis(100);
        let elapsed = start_time.elapsed();
        if elapsed < min_duration {
            sleep(min_duration - elapsed).await;
        }

        result
    }

    /// Internal authentication logic without timing protection
    async fn authenticate_internal(
        &self,
        method_name: &str,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<AuthResult> {
        // Check rate limiting
        if let Some(ref rate_limiter) = self.rate_limiter {
            let rate_key = format!(
                "auth:{}:{}",
                method_name,
                metadata.client_ip.as_deref().unwrap_or("unknown")
            );

            if !rate_limiter.is_allowed(&rate_key) {
                warn!(
                    "Rate limit exceeded for method '{}' from IP {:?}",
                    method_name, metadata.client_ip
                );
                return Err(AuthError::rate_limit("Too many authentication attempts"));
            }
        }

        // Get the authentication method
        let method = self.methods.get(method_name).ok_or_else(|| {
            AuthError::auth_method(method_name, "Authentication method not found".to_string())
        })?;

        // Log authentication attempt
        debug!(
            "Authentication attempt with method '{}' for credential: {}",
            method_name,
            credential.safe_display()
        );

        // Perform authentication
        let result = method.authenticate(credential, metadata.clone()).await?;

        // Handle the result
        match &result {
            MethodResult::Success(token) => {
                info!(
                    "Authentication successful for user '{}' with method '{}'",
                    token.user_id, method_name
                );

                // Store token
                self.storage.store_token(token).await?;

                // Log audit event
                self.log_audit_event("auth_success", &token.user_id, method_name, &metadata)
                    .await;

                Ok(AuthResult::Success(token.clone()))
            }

            MethodResult::MfaRequired(challenge) => {
                info!(
                    "MFA required for user '{}' with method '{}'",
                    challenge.user_id, method_name
                );

                // Store MFA challenge
                self.mfa_manager
                    .store_challenge((**challenge).clone())
                    .await?;

                // Log audit event
                self.log_audit_event("mfa_required", &challenge.user_id, method_name, &metadata)
                    .await;

                Ok(AuthResult::MfaRequired(challenge.clone()))
            }

            MethodResult::Failure { reason } => {
                warn!(
                    "Authentication failed for method '{}': {}",
                    method_name, reason
                );

                // Log audit event
                self.log_audit_event("auth_failure", "unknown", method_name, &metadata)
                    .await;

                Ok(AuthResult::Failure(reason.clone()))
            }
        }
    }

    /// Complete multi-factor authentication
    pub async fn complete_mfa(&self, challenge: MfaChallenge, mfa_code: &str) -> Result<AuthToken> {
        debug!("Completing MFA for challenge '{}'", challenge.id);

        // Check if challenge exists and is valid
        let stored_challenge = self
            .mfa_manager
            .get_challenge(&challenge.id)
            .await?
            .ok_or(MfaError::ChallengeExpired)?;

        if stored_challenge.is_expired() {
            self.mfa_manager.remove_challenge(&challenge.id).await?;
            return Err(MfaError::ChallengeExpired.into());
        }

        // Verify MFA code based on challenge type
        let is_valid = match &stored_challenge.mfa_type {
            crate::methods::MfaType::Totp => {
                self.mfa_manager
                    .totp
                    .verify_code(&stored_challenge.user_id, mfa_code)
                    .await?
            }
            crate::methods::MfaType::Sms { .. } => {
                self.mfa_manager
                    .sms
                    .verify_code(&challenge.id, mfa_code)
                    .await?
            }
            crate::methods::MfaType::Email { .. } => {
                self.mfa_manager
                    .email
                    .verify_code(&challenge.id, mfa_code)
                    .await?
            }
            crate::methods::MfaType::BackupCode => {
                self.mfa_manager
                    .backup_codes
                    .verify_code(&stored_challenge.user_id, mfa_code)
                    .await?
            }
            _ => false,
        };

        if !is_valid {
            return Err(MfaError::InvalidCode.into());
        }

        // Remove the challenge
        self.mfa_manager.remove_challenge(&challenge.id).await?;

        // Create authentication token
        let token = self.token_manager.create_auth_token(
            &challenge.user_id,
            vec![], // Scopes would be determined by user permissions
            "mfa",
            None,
        )?;

        // Store the token
        self.storage.store_token(&token).await?;

        info!(
            "MFA completed successfully for user '{}'",
            challenge.user_id
        );

        Ok(token)
    }

    /// Validate a token
    pub async fn validate_token(&self, token: &AuthToken) -> Result<bool> {
        if !self.initialized {
            return Err(AuthError::internal("Framework not initialized"));
        }

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

    /// Get user information from a token
    pub async fn get_user_info(&self, token: &AuthToken) -> Result<UserInfo> {
        if !self.validate_token(token).await? {
            return Err(AuthError::auth_method("token", "Invalid token".to_string()));
        }

        self.user_manager.get_user_info(&token.user_id).await
    }

    /// Check if a token has a specific permission
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

    /// Get the token manager
    pub fn token_manager(&self) -> &TokenManager {
        &self.token_manager
    }

    /// Get the MFA manager
    pub fn mfa_manager(&self) -> &MfaManager {
        &self.mfa_manager
    }

    /// Get the session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get the user manager
    pub fn user_manager(&self) -> &UserManager {
        &self.user_manager
    }

    /// Initiate SMS challenge (uses SMSKit)
    pub async fn initiate_sms_challenge(&self, user_id: &str) -> Result<String> {
        self.mfa_manager.sms.initiate_challenge(user_id).await
    }

    /// Send SMS code (uses SMSKit)
    pub async fn send_sms_code(&self, challenge_id: &str, phone_number: &str) -> Result<()> {
        self.mfa_manager
            .sms
            .send_code(challenge_id, phone_number)
            .await
    }

    /// Generate SMS code (uses SMSKit)
    pub async fn generate_sms_code(&self, challenge_id: &str) -> Result<String> {
        self.mfa_manager.sms.generate_code(challenge_id).await
    }

    /// Verify SMS code (uses SMSKit)
    pub async fn verify_sms_code(&self, challenge_id: &str, code: &str) -> Result<bool> {
        self.mfa_manager.sms.verify_code(challenge_id, code).await
    }

    /// Clean up expired data
    pub async fn cleanup_expired_data(&self) -> Result<()> {
        debug!("Cleaning up expired data");

        // Clean up storage
        self.storage.cleanup_expired().await?;

        // Clean up MFA challenges
        self.mfa_manager.cleanup_expired_challenges().await?;

        // Clean up sessions
        self.session_manager.cleanup_expired_sessions().await?;

        // Clean up rate limiter
        if let Some(ref rate_limiter) = self.rate_limiter {
            rate_limiter.cleanup();
        }

        Ok(())
    }

    /// Get authentication framework statistics
    pub async fn get_stats(&self) -> Result<AuthStats> {
        let mut stats = AuthStats::default();

        for method in self.methods.keys() {
            stats.registered_methods.push(method.clone());
        }

        stats.active_mfa_challenges = self.mfa_manager.get_active_challenge_count().await as u64;

        Ok(stats)
    }

    /// Log an audit event
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
}

/// Authentication framework statistics
#[derive(Debug, Clone, Default)]
pub struct AuthStats {
    /// Number of registered authentication methods
    pub registered_methods: Vec<String>,

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
    use crate::config::{AuthConfig, SecurityConfig};
    use std::time::Duration;

    #[tokio::test]
    async fn test_modular_framework_initialization() {
        let config = AuthConfig::new().security(SecurityConfig {
            min_password_length: 8,
            require_password_complexity: false,
            password_hash_algorithm: crate::config::PasswordHashAlgorithm::Bcrypt,
            jwt_algorithm: crate::config::JwtAlgorithm::HS256,
            secret_key: Some("test_secret_key_32_bytes_long!!!!".to_string()),
            secure_cookies: false,
            cookie_same_site: crate::config::CookieSameSite::Lax,
            csrf_protection: false,
            session_timeout: Duration::from_secs(3600),
        });
        let mut framework = AuthFramework::new(config);

        assert!(framework.initialize().await.is_ok());
        assert!(framework.initialized);
    }

    #[tokio::test]
    async fn test_mfa_manager_access() {
        let config = AuthConfig::new().security(SecurityConfig {
            min_password_length: 8,
            require_password_complexity: false,
            password_hash_algorithm: crate::config::PasswordHashAlgorithm::Bcrypt,
            jwt_algorithm: crate::config::JwtAlgorithm::HS256,
            secret_key: Some("test_secret_key_32_bytes_long!!!!".to_string()),
            secure_cookies: false,
            cookie_same_site: crate::config::CookieSameSite::Lax,
            csrf_protection: false,
            session_timeout: Duration::from_secs(3600),
        });
        let framework = AuthFramework::new(config);

        // Test that we can access specialized managers
        let _mfa_manager = framework.mfa_manager();
        let _session_manager = framework.session_manager();
        let _user_manager = framework.user_manager();
    }
}
