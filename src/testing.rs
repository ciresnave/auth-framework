//! Testing utilities for auth-framework.
//!
//! This module provides mock implementations and helper functions
//! to make testing applications that use auth-framework easier.

use crate::{
    auth::AuthFramework,
    config::AuthConfig,
    credentials::{Credential, CredentialMetadata},
    errors::{AuthError, Result, StorageError},
    methods::{AuthMethod, MethodResult, MfaChallenge, MfaType},
    providers::{UserProfile, OAuthTokenResponse, DeviceAuthorizationResponse},
    storage::{AuthStorage, SessionData},
    tokens::AuthToken,
    permissions::Permission,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use uuid::Uuid;

/// Mock authentication method for testing.
#[derive(Debug, Clone)]
pub struct MockAuthMethod {
    /// Whether authentication should succeed
    pub should_succeed: bool,
    /// Simulated user profiles to return
    pub user_profiles: HashMap<String, UserProfile>,
    /// Simulated delay for authentication
    pub delay: Option<Duration>,
}

impl MockAuthMethod {
    /// Create a new mock authentication method that always succeeds
    pub fn new_success() -> Self {
        Self {
            should_succeed: true,
            user_profiles: HashMap::new(),
            delay: None,
        }
    }
    
    /// Create a new mock authentication method that always fails
    pub fn new_failure() -> Self {
        Self {
            should_succeed: false,
            user_profiles: HashMap::new(),
            delay: None,
        }
    }
    
    /// Add a user profile for a specific user ID
    pub fn with_user(mut self, user_id: impl Into<String>, profile: UserProfile) -> Self {
        self.user_profiles.insert(user_id.into(), profile);
        self
    }
    
    /// Set a delay for authentication (useful for testing timeouts)
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

#[async_trait]
impl AuthMethod for MockAuthMethod {
    fn name(&self) -> &str {
        "mock"
    }
    
    fn validate_config(&self) -> Result<()> {
        Ok(())
    }
    
    async fn authenticate(
        &self,
        credential: &Credential,
        _metadata: &CredentialMetadata,
    ) -> Result<MethodResult> {
        // Simulate delay if configured
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        
        if !self.should_succeed {
            return Ok(MethodResult::Failure { reason: "Mock authentication failed".to_string() });
        }
        
        // Extract user ID based on credential type
        let user_id = match credential {
            Credential::Password { username, .. } => username.clone(),
            Credential::ApiKey { key } => format!("api_user_{}", &key[..8.min(key.len())]),
            Credential::OAuth { .. } => "oauth_user".to_string(),
            Credential::DeviceCode { .. } => "device_user".to_string(),
            _ => "test_user".to_string(),
        };
        
        // Create a mock token
        let token = AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            access_token: format!("mock_token_{}", Uuid::new_v4()),
            refresh_token: Some(format!("refresh_{}", Uuid::new_v4())),
            token_type: "Bearer".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
        };
        
        Ok(MethodResult::Success(Box::new(token)))
    }
    
    async fn refresh_token(&self, _refresh_token: &str) -> Result<AuthToken> {
        if !self.should_succeed {
            return Err(AuthError::auth_method("mock", "Refresh failed"));
        }
        
        Ok(AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: "refreshed_user".to_string(),
            access_token: "mock_refreshed_token".to_string(),
            refresh_token: Some("mock_new_refresh_token".to_string()),
            token_type: "Bearer".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
        })
    }
}

/// Mock storage implementation for testing.
#[derive(Debug, Clone)]
pub struct MockStorage {
    tokens: Arc<Mutex<HashMap<String, AuthToken>>>,
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
    kv_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    should_fail: bool,
}

impl MockStorage {
    /// Create a new mock storage
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            kv_store: Arc::new(Mutex::new(HashMap::new())),
            should_fail: false,
        }
    }
    
    /// Create a mock storage that fails operations
    pub fn new_failing() -> Self {
        let mut storage = Self::new();
        storage.should_fail = true;
        storage
    }
    
    /// Preset a token in storage
    pub fn with_token(&self, token: AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut tokens = self.tokens.lock().unwrap();
        tokens.insert(token.access_token.clone(), token);
        Ok(())
    }
    
    /// Clear all storage
    pub fn clear(&self) {
        self.tokens.lock().unwrap().clear();
        self.sessions.lock().unwrap().clear();
        self.kv_store.lock().unwrap().clear();
    }
}

impl Default for MockStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthStorage for MockStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut tokens = self.tokens.lock().unwrap();
        tokens.insert(token.access_token.clone(), token.clone());
        Ok(())
    }
    
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.values().find(|t| t.token_id == token_id).cloned())
    }
    
    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.get(access_token).cloned())
    }
    
    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut tokens = self.tokens.lock().unwrap();
        tokens.insert(token.access_token.clone(), token.clone());
        Ok(())
    }
    
    async fn delete_token(&self, token_id: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut tokens = self.tokens.lock().unwrap();
        tokens.retain(|_, token| token.token_id != token_id);
        Ok(())
    }
    
    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let tokens = self.tokens.lock().unwrap();
        Ok(tokens.values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect())
    }
    
    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.to_string(), data.clone());
        Ok(())
    }
    
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.get(session_id).cloned())
    }
    
    async fn delete_session(&self, session_id: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
        Ok(())
    }
    
    async fn store_kv(&self, key: &str, value: &[u8], _ttl: Option<Duration>) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut kv_store = self.kv_store.lock().unwrap();
        kv_store.insert(key.to_string(), value.to_vec());
        Ok(())
    }
    
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let kv_store = self.kv_store.lock().unwrap();
        Ok(kv_store.get(key).cloned())
    }
    
    async fn delete_kv(&self, key: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let mut kv_store = self.kv_store.lock().unwrap();
        kv_store.remove(key);
        Ok(())
    }
    
    async fn cleanup_expired(&self) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }
        
        let now = chrono::Utc::now();
        let mut tokens = self.tokens.lock().unwrap();
        
        tokens.retain(|_, token| token.expires_at > now);
        
        Ok(())
    }
}

/// Test helper functions
pub mod helpers {
    use super::*;
    use std::sync::Arc;
    
    /// Create a test auth framework with mock storage
    pub fn create_test_auth_framework() -> AuthFramework {
        let config = AuthConfig::new()
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));
        
        AuthFramework::new(config)
    }
    
    /// Create a test user profile
    pub fn create_test_user_profile(user_id: &str) -> UserProfile {
        UserProfile::new(user_id, "test")
            .with_name(format!("Test User {}", user_id))
            .with_email(format!("{}@test.com", user_id))
            .with_email_verified(true)
    }
    
    /// Create a test auth token
    pub fn create_test_token(user_id: &str) -> AuthToken {
        let now = chrono::Utc::now();
        AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            access_token: format!("test_token_{}", Uuid::new_v4()),
            refresh_token: Some(format!("refresh_token_{}", Uuid::new_v4())),
            token_type: "Bearer".to_string(),
            expires_at: now + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: now,
            auth_method: "test".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
        }
    }
    
    /// Create test credentials
    pub fn create_test_credentials() -> Vec<Credential> {
        vec![
            Credential::password("testuser", "testpass"),
            Credential::api_key("test_api_key"),
            Credential::oauth_code("test_auth_code"),
            Credential::device_code("test_device_code", "test_client_id"),
            Credential::jwt("test.jwt.token"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mock_auth_method_success() {
        let method = MockAuthMethod::new_success();
        let credential = Credential::password("testuser", "testpass");
        let metadata = CredentialMetadata::default();
        
        let result = method.authenticate(&credential, &metadata).await.unwrap();
        match result {
            MethodResult::Success(token) => {
                assert_eq!(token.user_id, "testuser");
            }
            _ => panic!("Expected success"),
        }
    }
    
    #[tokio::test]
    async fn test_mock_auth_method_failure() {
        let method = MockAuthMethod::new_failure();
        let credential = Credential::password("testuser", "testpass");
        let metadata = CredentialMetadata::default();
        
        let result = method.authenticate(&credential, &metadata).await.unwrap();
        match result {
            MethodResult::Failure { .. } => {
                // Expected
            }
            _ => panic!("Expected failure"),
        }
    }
    
    #[tokio::test]
    async fn test_mock_storage() {
        let storage = MockStorage::new();
        let token = helpers::create_test_token("testuser");
        
        // Store token
        storage.store_token(&token).await.unwrap();
        
        // Retrieve token
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().token_id, token.token_id);
    }
    
    #[tokio::test]
    async fn test_failing_mock_storage() {
        let storage = MockStorage::new_failing();
        let token = helpers::create_test_token("testuser");
        
        // Store should fail
        let result = storage.store_token(&token).await;
        assert!(result.is_err());
    }
}
