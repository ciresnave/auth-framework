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
//! ```rust,no_run
//! use auth_framework::auth_modular::AuthFramework;
//! use auth_framework::config::AuthConfig;
//!
//! // Create modular framework
//! let config = AuthConfig::default();
//! let auth = AuthFramework::new(config).expect("valid modular auth framework config");
//!
//! // Access individual managers
//! let mfa_manager = auth.mfa_manager();
//! let session_manager = auth.session_manager();
//! let user_manager = auth.user_manager();
//! ```
//!
//! # Migration from Monolithic Framework
//!
//! The modular framework maintains API compatibility with the main framework,
//! making migration straightforward while providing additional flexibility.
//!
//! # When To Use This Module
//!
//! Prefer [`crate::AuthFramework`] for most applications.
//! Reach for [`crate::ModularAuthFramework`] only when you need direct access
//! to manager-level composition such as `session_manager()` or `user_manager()`.

pub mod authorization_manager;
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

pub use authorization_manager::AuthorizationManager;
pub use mfa::MfaManager;
pub use session_manager::SessionManager;
pub use user_manager::{UserInfo, UserManager};

/// Result of an authentication attempt — alias for the canonical [`crate::auth::AuthResult`].
pub use crate::auth::AuthResult;

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
    /// Create a new authentication framework.
    ///
    /// Returns a descriptive error if the configuration is invalid rather than
    /// panicking, so callers can decide how to handle startup failures.
    ///
    /// Equivalent to [`AuthFramework::try_new`].
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::{AuthFramework, config::AuthConfig};
    ///
    /// let fw = AuthFramework::new(AuthConfig::default())?;
    /// ```
    pub fn new(config: AuthConfig) -> crate::errors::Result<Self> {
        Self::try_new(config)
    }

    /// Create a new authentication framework, returning an error instead of panicking.
    ///
    /// This is the preferred constructor for library callers and server startup code where
    /// configuration errors should be handled gracefully rather than aborting the process.
    ///
    /// # Example
    /// ```rust,ignore
    /// let fw = AuthFramework::try_new(AuthConfig::default())?;
    /// ```
    pub fn try_new(config: AuthConfig) -> crate::errors::Result<Self> {
        // Validate configuration
        config.validate().map_err(|e| {
            crate::errors::AuthError::configuration(format!("Invalid configuration: {e}"))
        })?;

        // Create token manager
        let token_manager = if let Some(secret) = &config.security.secret_key {
            if secret.len() < 32 {
                tracing::warn!(
                    "JWT secret is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(secret.as_bytes(), "auth-framework", "auth-framework")
        } else if let Some(secret) = &config.secret {
            if secret.len() < 32 {
                tracing::warn!(
                    "JWT secret is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(secret.as_bytes(), "auth-framework", "auth-framework")
        } else if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            if jwt_secret.len() < 32 {
                tracing::warn!(
                    "JWT_SECRET is shorter than 32 characters. Consider using a longer secret for better security."
                );
            }
            TokenManager::new_hmac(jwt_secret.as_bytes(), "auth-framework", "auth-framework")
        } else {
            return Err(crate::errors::AuthError::configuration(
                "JWT secret not set! Please set JWT_SECRET env variable or provide in config.\n\
                   For security reasons, no default secret is provided.\n\
                   Generate a secure secret with: openssl rand -base64 32",
            ));
        };

        // Create storage backend
        let storage: Arc<dyn AuthStorage> = match &config.storage {
            #[cfg(feature = "redis-storage")]
            crate::config::StorageConfig::Redis { url, key_prefix } => Arc::new(
                crate::storage::RedisStorage::new(url, key_prefix).map_err(|e| {
                    crate::errors::AuthError::configuration(format!(
                        "Failed to create Redis storage: {e}"
                    ))
                })?,
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

        Ok(Self {
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
        })
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
    ///
    /// # Example
    /// ```rust,ignore
    /// let fw = AuthFramework::new_with_storage(config, Arc::new(MyStorage::new()))?;
    /// ```
    pub fn new_with_storage(
        config: AuthConfig,
        storage: Arc<dyn AuthStorage>,
    ) -> crate::errors::Result<Self> {
        let mut framework = Self::new(config)?;
        framework.replace_storage(storage);
        Ok(framework)
    }

    /// Create a new framework with SMSKit configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let fw = AuthFramework::new_with_smskit_config(config, smskit_cfg)?;
    /// ```
    #[cfg(feature = "smskit")]
    pub fn new_with_smskit_config(
        config: AuthConfig,
        smskit_config: crate::auth_modular::mfa::SmsKitConfig,
    ) -> Result<Self> {
        // First create the framework normally
        let mut framework = Self::new(config)?;

        // Then replace the MFA manager with one configured for SMSKit
        framework.mfa_manager = crate::auth_modular::mfa::MfaManager::new_with_smskit_config(
            framework.storage.clone(),
            smskit_config,
        )?;

        Ok(framework)
    }

    /// Register an authentication method.
    ///
    /// # Example
    /// ```rust,ignore
    /// fw.register_method("password", AuthMethodEnum::Password(PasswordAuth::default()));
    /// ```
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

    /// Initialize the authentication framework.
    ///
    /// Sets up default roles and marks the framework as ready. Must be called
    /// before `authenticate` or `validate_token`.
    ///
    /// # Example
    /// ```rust,ignore
    /// fw.initialize().await?;
    /// ```
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

    /// Authenticate a user with the specified method.
    ///
    /// Delegates to [`authenticate_with_metadata`](Self::authenticate_with_metadata)
    /// with empty metadata.
    ///
    /// # Example
    /// ```rust,ignore
    /// let result = fw.authenticate("jwt", Credential::jwt(token)).await?;
    /// match result {
    ///     AuthResult::Success(token) => println!("authenticated"),
    ///     AuthResult::MfaRequired(challenge) => println!("MFA needed"),
    ///     AuthResult::Failure(msg) => eprintln!("failed: {msg}"),
    /// }
    /// ```
    pub async fn authenticate(
        &self,
        method_name: &str,
        credential: Credential,
    ) -> Result<AuthResult> {
        self.authenticate_with_metadata(method_name, credential, CredentialMetadata::new())
            .await
    }

    /// Authenticate a user with the specified method and additional metadata.
    ///
    /// Metadata can carry client IP, user-agent, and other contextual information
    /// for adaptive risk scoring and audit logging.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut meta = CredentialMetadata::new();
    /// meta.client_ip = Some("203.0.113.1".to_string());
    /// let result = fw.authenticate_with_metadata("jwt", credential, meta).await?;
    /// ```
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

        if method_name == "jwt" {
            return match credential {
                Credential::Jwt { token } | Credential::Bearer { token } => {
                    self.authenticate_jwt_builtin(&token, &metadata, "jwt")
                        .await
                }
                _ => Ok(AuthResult::Failure(
                    "JWT authentication expects Credential::jwt or Credential::bearer".to_string(),
                )),
            };
        }

        if matches!(method_name, "api_key" | "api-key") {
            return match credential {
                Credential::ApiKey { key } => {
                    self.authenticate_api_key_builtin(&key, &metadata, "api_key")
                        .await
                }
                _ => Ok(AuthResult::Failure(
                    "API key authentication expects Credential::api_key".to_string(),
                )),
            };
        }

        if method_name == "oauth2" {
            return self
                .authenticate_oauth2_builtin(credential, &metadata)
                .await;
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

    async fn authenticate_jwt_builtin(
        &self,
        token: &str,
        metadata: &CredentialMetadata,
        auth_method: &str,
    ) -> Result<AuthResult> {
        if token.is_empty() {
            return Ok(AuthResult::Failure("JWT token cannot be empty".to_string()));
        }

        match self.token_manager.validate_jwt_token(token) {
            Ok(claims) => {
                let token =
                    Self::build_validated_jwt_auth_token(token, claims, metadata, auth_method);
                Ok(AuthResult::Success(Box::new(token)))
            }
            Err(error) => {
                if let Some(reason) = Self::credential_failure_reason(&error) {
                    Ok(AuthResult::Failure(reason))
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn authenticate_api_key_builtin(
        &self,
        api_key: &str,
        metadata: &CredentialMetadata,
        auth_method: &str,
    ) -> Result<AuthResult> {
        if api_key.is_empty() {
            return Ok(AuthResult::Failure("API key cannot be empty".to_string()));
        }

        match self.user_manager.validate_api_key(api_key).await {
            Ok(user) => {
                let scopes: Vec<String> = if user.roles.is_empty() {
                    vec!["api_user".to_string()]
                } else {
                    user.roles.to_vec()
                };
                let mut token = self
                    .token_manager
                    .create_auth_token(&user.id, scopes.clone(), auth_method, None)?
                    .with_roles(user.roles)
                    .with_scopes(scopes);
                token.metadata.issued_ip = metadata.client_ip.clone();
                token.metadata.user_agent = metadata.user_agent.clone();
                Ok(AuthResult::Success(Box::new(token)))
            }
            Err(error) => {
                if let Some(reason) = Self::credential_failure_reason(&error) {
                    Ok(AuthResult::Failure(reason))
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn authenticate_oauth2_builtin(
        &self,
        credential: Credential,
        metadata: &CredentialMetadata,
    ) -> Result<AuthResult> {
        match credential {
            Credential::OAuth {
                authorization_code, ..
            } => {
                if authorization_code.is_empty() {
                    return Ok(AuthResult::Failure(
                        "OAuth authorization code cannot be empty".to_string(),
                    ));
                }
                Ok(AuthResult::Failure(
                    "OAuth 2.0 authorization codes must be exchanged through an OAuth provider or server endpoint before authentication completes"
                        .to_string(),
                ))
            }
            Credential::OAuthRefresh { refresh_token } => {
                if refresh_token.is_empty() {
                    return Ok(AuthResult::Failure(
                        "OAuth refresh token cannot be empty".to_string(),
                    ));
                }
                Ok(AuthResult::Failure(
                    "OAuth 2.0 refresh tokens must be exchanged through an OAuth provider or server endpoint before authentication completes"
                        .to_string(),
                ))
            }
            Credential::Jwt { token }
            | Credential::Bearer { token }
            | Credential::OpenIdConnect { id_token: token, .. } => {
                self.authenticate_jwt_builtin(&token, metadata, "oauth2").await
            }
            _ => Ok(AuthResult::Failure(
                "OAuth2 authentication expects Credential::oauth_code, Credential::oauth_refresh, Credential::jwt, Credential::bearer, or Credential::openid_connect"
                    .to_string(),
            )),
        }
    }

    fn build_validated_jwt_auth_token(
        raw_token: &str,
        claims: crate::tokens::JwtClaims,
        metadata: &CredentialMetadata,
        auth_method: &str,
    ) -> AuthToken {
        let crate::tokens::JwtClaims {
            sub,
            iss,
            exp,
            iat,
            jti,
            scope,
            permissions,
            roles,
            client_id,
            ..
        } = claims;

        let now = chrono::Utc::now();
        let issued_at = chrono::DateTime::<chrono::Utc>::from_timestamp(iat, 0).unwrap_or(now);
        let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(exp, 0)
            .unwrap_or(now + chrono::Duration::hours(1));
        let lifetime = (expires_at - now)
            .to_std()
            .unwrap_or_else(|_| std::time::Duration::from_secs(1));
        let scopes = if scope.trim().is_empty() {
            Vec::new()
        } else {
            scope.split_whitespace().map(str::to_string).collect()
        };

        let mut token = AuthToken::new(sub.clone(), raw_token.to_string(), lifetime, auth_method)
            .with_scopes(scopes)
            .with_permissions(permissions.unwrap_or_default())
            .with_roles(roles.unwrap_or_default());
        token.token_id = jti;
        token.subject = Some(sub);
        token.issuer = Some(iss);
        token.issued_at = issued_at;
        token.expires_at = expires_at;
        token.metadata.issued_ip = metadata.client_ip.clone();
        token.metadata.user_agent = metadata.user_agent.clone();
        if let Some(client_id) = client_id {
            token.client_id = Some(client_id);
        }
        token
    }

    fn credential_failure_reason(error: &AuthError) -> Option<String> {
        match error {
            AuthError::Token(_) | AuthError::Jwt(_) => Some(error.to_string()),
            AuthError::Validation { message } => Some(message.clone()),
            AuthError::UserNotFound => Some("User not found".to_string()),
            _ => None,
        }
    }

    /// Complete multi-factor authentication.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = fw.complete_mfa(challenge, "123456").await?;
    /// ```
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

        // Look up user roles from storage
        let user_key = format!("user:{}", challenge.user_id);
        let scopes = if let Ok(Some(data)) = self.storage.get_kv(&user_key).await {
            serde_json::from_slice::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| {
                    v.get("roles").and_then(|r| {
                        r.as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        })
                    })
                })
                .unwrap_or_else(|| vec!["user".to_string()])
        } else {
            vec!["user".to_string()]
        };

        // Create authentication token
        let token =
            self.token_manager
                .create_auth_token(&challenge.user_id, scopes, "mfa", None)?;

        // Store the token
        self.storage.store_token(&token).await?;

        info!(
            "MFA completed successfully for user '{}'",
            challenge.user_id
        );

        Ok(token)
    }

    /// Validate a token.
    ///
    /// # Example
    /// ```rust,ignore
    /// let valid = fw.validate_token(&token).await?;
    /// ```
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

    /// Get user information from a token.
    ///
    /// # Example
    /// ```rust,ignore
    /// let info = fw.get_user_info(&token).await?;
    /// println!("username: {}", info.username);
    /// ```
    pub async fn get_user_info(&self, token: &AuthToken) -> Result<UserInfo> {
        if !self.validate_token(token).await? {
            return Err(AuthError::auth_method("token", "Invalid token".to_string()));
        }

        self.user_manager.get_user_info(&token.user_id).await
    }

    /// Check if a token has a specific permission.
    ///
    /// # Example
    /// ```rust,ignore
    /// let allowed = fw.check_permission(&token, "read", "users").await?;
    /// ```
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

    /// Get the token manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let tm = fw.token_manager();
    /// ```
    pub fn token_manager(&self) -> &TokenManager {
        &self.token_manager
    }

    /// Get the MFA manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mfa = fw.mfa_manager();
    /// ```
    pub fn mfa_manager(&self) -> &MfaManager {
        &self.mfa_manager
    }

    /// Get the session manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let sm = fw.session_manager();
    /// ```
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get the user manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// let um = fw.user_manager();
    /// ```
    pub fn user_manager(&self) -> &UserManager {
        &self.user_manager
    }

    /// Initiate SMS challenge (uses SMSKit).
    ///
    /// # Example
    /// ```rust,ignore
    /// let challenge_id = fw.initiate_sms_challenge("user-1").await?;
    /// ```
    pub async fn initiate_sms_challenge(&self, user_id: &str) -> Result<String> {
        self.mfa_manager.sms.initiate_challenge(user_id).await
    }

    /// Send SMS code (uses SMSKit).
    ///
    /// # Example
    /// ```rust,ignore
    /// fw.send_sms_code(&challenge_id, "+1234567890").await?;
    /// ```
    pub async fn send_sms_code(&self, challenge_id: &str, phone_number: &str) -> Result<()> {
        self.mfa_manager
            .sms
            .send_code(challenge_id, phone_number)
            .await
    }

    /// Generate SMS code (uses SMSKit).
    ///
    /// # Example
    /// ```rust,ignore
    /// let code = fw.generate_sms_code(&challenge_id).await?;
    /// ```
    pub async fn generate_sms_code(&self, challenge_id: &str) -> Result<String> {
        self.mfa_manager.sms.generate_code(challenge_id).await
    }

    /// Verify SMS code (uses SMSKit).
    ///
    /// # Example
    /// ```rust,ignore
    /// let ok = fw.verify_sms_code(&challenge_id, "123456").await?;
    /// ```
    pub async fn verify_sms_code(&self, challenge_id: &str, code: &str) -> Result<bool> {
        self.mfa_manager.sms.verify_code(challenge_id, code).await
    }

    /// Clean up expired data (sessions, MFA challenges, rate limiter entries).
    ///
    /// # Example
    /// ```rust,ignore
    /// fw.cleanup_expired_data().await?;
    /// ```
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
            let _ = rate_limiter.cleanup().ok();
        }

        Ok(())
    }

    /// Get authentication framework statistics.
    ///
    /// # Example
    /// ```rust,ignore
    /// let stats = fw.get_stats().await?;
    /// println!("methods: {:?}", stats.registered_methods);
    /// ```
    pub async fn get_stats(&self) -> Result<AuthStats> {
        let mut stats = AuthStats::default();

        for method in self.methods.keys() {
            stats.registered_methods.push(method.clone());
        }

        stats.active_mfa_challenges = self.mfa_manager.get_active_challenge_count().await as u64;

        // Count tokens from storage as a proxy for tokens_issued
        stats.tokens_issued = self.storage.count_active_sessions().await.unwrap_or(0) as u64;

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
    use crate::authentication::credentials::Credential;
    use crate::config::{AuthConfig, SecurityConfig};
    use std::time::Duration;

    async fn initialized_framework(config: AuthConfig) -> AuthFramework {
        let mut framework = AuthFramework::new(config).expect("test config should be valid");
        framework
            .initialize()
            .await
            .expect("framework initialization should succeed");
        framework
    }

    fn test_config() -> AuthConfig {
        AuthConfig::new().secret("test_secret_key_32_bytes_long!!!!")
    }

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
            previous_secret_key: None,
        });
        let mut framework = AuthFramework::new(config).expect("test config should be valid");

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
            previous_secret_key: None,
        });
        let framework = AuthFramework::new(config).expect("test config should be valid");

        // Test that we can access specialized managers
        let _mfa_manager = framework.mfa_manager();
        let _session_manager = framework.session_manager();
        let _user_manager = framework.user_manager();
    }

    #[tokio::test]
    async fn test_authenticate_with_metadata_enforces_minimum_duration() {
        let framework = initialized_framework(test_config()).await;
        let start = std::time::Instant::now();

        let result = framework
            .authenticate_with_metadata(
                "oauth2",
                Credential::oauth_refresh(""),
                CredentialMetadata::new(),
            )
            .await
            .expect("empty refresh token should return failure, not error");

        assert!(
            start.elapsed() >= std::time::Duration::from_millis(90),
            "timing floor should add a noticeable delay"
        );
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[tokio::test]
    async fn test_authenticate_oauth2_refresh_empty_returns_failure() {
        let framework = initialized_framework(test_config()).await;

        let result = framework
            .authenticate("oauth2", Credential::oauth_refresh(""))
            .await
            .expect("empty refresh token should return failure, not error");

        match result {
            AuthResult::Failure(reason) => {
                assert!(reason.contains("refresh token cannot be empty"));
            }
            _ => panic!("expected failure result for empty OAuth refresh token"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_oauth2_openid_connect_routes_to_jwt_validation() {
        let framework = initialized_framework(test_config()).await;
        let jwt = framework
            .token_manager()
            .create_jwt_token("oidc-user", vec!["openid".to_string()], None)
            .expect("jwt creation should succeed");

        let result = framework
            .authenticate("oauth2", Credential::openid_connect(jwt))
            .await
            .expect("valid OIDC credential should authenticate");

        match result {
            AuthResult::Success(token) => {
                assert_eq!(token.user_id, "oidc-user");
                assert_eq!(token.auth_method, "oauth2");
            }
            _ => panic!("expected success result for OpenID Connect credential"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_oauth2_unsupported_credential_returns_failure() {
        let framework = initialized_framework(test_config()).await;

        let result = framework
            .authenticate("oauth2", Credential::password("alice", "secret"))
            .await
            .expect("unsupported credential should return failure, not error");

        match result {
            AuthResult::Failure(reason) => {
                assert!(reason.contains("OAuth2 authentication expects"));
            }
            _ => panic!("expected failure result for unsupported OAuth2 credential"),
        }
    }

    #[tokio::test]
    async fn test_rate_limiting_without_client_ip_uses_shared_unknown_bucket() {
        let config = AuthConfig::new()
            .secret("test_secret_key_32_bytes_long!!!!")
            .rate_limiting(crate::config::RateLimitConfig {
                enabled: true,
                max_requests: 1,
                window: Duration::from_secs(60),
                burst: 0,
            });
        let framework = initialized_framework(config).await;

        let first = framework
            .authenticate_with_metadata(
                "oauth2",
                Credential::oauth_code("first-code"),
                CredentialMetadata::new(),
            )
            .await
            .expect("first request should pass rate limiting");
        assert!(matches!(first, AuthResult::Failure(_)));

        let second = framework
            .authenticate_with_metadata(
                "oauth2",
                Credential::oauth_code("second-code"),
                CredentialMetadata::new(),
            )
            .await;
        assert!(second.is_err(), "second request should be rate limited");
        assert!(
            second
                .unwrap_err()
                .to_string()
                .contains("Too many authentication attempts")
        );
    }

    #[tokio::test]
    async fn test_complete_mfa_missing_challenge_returns_expired_error() {
        let framework = initialized_framework(test_config()).await;
        let challenge = MfaChallenge::new(
            crate::methods::MfaType::BackupCode,
            "user-123",
            Duration::from_secs(60),
        );

        let result = framework.complete_mfa(challenge, "123456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_complete_mfa_expired_challenge_is_removed() {
        let framework = initialized_framework(test_config()).await;
        let mut challenge = MfaChallenge::new(
            crate::methods::MfaType::BackupCode,
            "user-123",
            Duration::from_secs(60),
        );
        challenge.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        framework
            .mfa_manager
            .store_challenge(challenge.clone())
            .await
            .expect("storing challenge should succeed");

        let result = framework.complete_mfa(challenge.clone(), "123456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
        assert!(
            framework
                .mfa_manager
                .get_challenge(&challenge.id)
                .await
                .expect("challenge lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_validate_token_returns_false_for_expired_token() {
        let framework = initialized_framework(test_config()).await;
        let mut token = framework
            .token_manager()
            .create_auth_token("user-123", vec!["read".to_string()], "jwt", None)
            .expect("token creation should succeed");
        token.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);

        let valid = framework
            .validate_token(&token)
            .await
            .expect("expired token should return false, not error");
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_validate_token_returns_false_when_not_in_storage() {
        let framework = initialized_framework(test_config()).await;
        let token = framework
            .token_manager()
            .create_auth_token("user-123", vec!["read".to_string()], "jwt", None)
            .expect("token creation should succeed");

        let valid = framework
            .validate_token(&token)
            .await
            .expect("missing stored token should return false, not error");
        assert!(!valid);
    }
}
