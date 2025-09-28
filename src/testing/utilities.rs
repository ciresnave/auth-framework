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
        MockAuthMethod {
            should_succeed: true,
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
use crate::authentication::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, Result};
use crate::methods::{AuthMethod, MethodResult};
use crate::providers::UserProfile;
use crate::storage::AuthStorage;
use crate::storage::core::SessionData;
use crate::tokens::AuthToken;
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
// Ensure all top-level impls are closed before the test module
#[cfg(test)]
// use crate::security::SecurityConfig;
#[tokio::test]
async fn test_mock_storage() {
    use crate::testing::test_infrastructure::TestEnvironmentGuard;
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let storage = MockStorage::new();
    let token = helpers::create_test_token("testuser");
    storage.store_token(&token).await.unwrap();
    let retrieved = storage.get_token(&token.token_id).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().token_id, token.token_id);
}

#[tokio::test]
async fn test_failing_mock_storage() {
    use crate::testing::test_infrastructure::TestEnvironmentGuard;
    let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");

    let storage = MockStorage::new_failing();
    let token = helpers::create_test_token("testuser");
    let result = storage.store_token(&token).await;
    assert!(result.is_err());
}

#[test]
fn test_secret_loading_from_env() {
    use crate::auth::AuthFramework;
    use crate::config::AuthConfig;
    use crate::testing::test_infrastructure::TestEnvironmentGuard;

    let _env = TestEnvironmentGuard::new().with_jwt_secret("env_secret_value");

    let config = AuthConfig::default().secret("config_secret_value");
    let framework = AuthFramework::new(config.clone());
    let token = framework
        .token_manager()
        .create_jwt_token("user", vec!["read".to_string()], None);
    assert!(token.is_ok());
}

#[test]
fn test_secret_loading_from_config() {
    use crate::auth::AuthFramework;
    use crate::config::AuthConfig;
    use crate::testing::test_infrastructure::TestEnvironmentGuard;

    // Ensure JWT_SECRET is not set in environment for this test
    let _env = TestEnvironmentGuard::new();

    let config = AuthConfig::default().secret("config_secret_value");
    let framework = AuthFramework::new(config.clone());
    let token = framework
        .token_manager()
        .create_jwt_token("user", vec!["read".to_string()], None);
    assert!(token.is_ok());
}

#[test]
fn test_secret_missing_returns_error() {
    use crate::auth::AuthFramework;
    use crate::config::AuthConfig;

    // Ensure JWT_SECRET is not set for this test
    unsafe {
        std::env::remove_var("JWT_SECRET");
    }

    // In production mode, should return error instead of panic
    unsafe {
        std::env::set_var("ENVIRONMENT", "production");

        let config = AuthConfig::default();
        match AuthFramework::new_validated(config) {
            Err(e) => {
                // Should fail with proper error message about JWT secret
                assert!(e.to_string().contains("JWT secret"));
            }
            Ok(_) => panic!("Expected error when JWT_SECRET is missing in production"),
        }

        // Clean up
        std::env::remove_var("ENVIRONMENT");
    }
}

impl AuthMethod for MockAuthMethod {
    type MethodResult = MethodResult;
    type AuthToken = AuthToken;

    fn name(&self) -> &str {
        "mock"
    }

    fn validate_config(&self) -> Result<()> {
        Ok(())
    }

    async fn authenticate(
        &self,
        credential: Credential,
        _metadata: CredentialMetadata,
    ) -> Result<Self::MethodResult> {
        // Simulate delay if configured
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }

        if !self.should_succeed {
            return Ok(MethodResult::Failure {
                reason: "Mock authentication failed".to_string(),
            });
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
            token_type: Some("Bearer".to_string()),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            subject: Some(user_id.clone()),
            issuer: Some("mock".to_string()),
            user_profile: None,
            client_id: Some("test_client".to_string()),
            permissions: vec!["read:all".to_string(), "write:all".to_string()],
            roles: vec!["mock_user".to_string()],
            metadata: crate::tokens::TokenMetadata::default(),
        };

        Ok(MethodResult::Success(Box::new(token)))
    }

    async fn refresh_token(&self, _refresh_token: String) -> Result<Self::AuthToken> {
        if !self.should_succeed {
            return Err(AuthError::auth_method("mock", "Refresh failed"));
        }

        Ok(AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: "refreshed_user".to_string(),
            access_token: "mock_refreshed_token".to_string(),
            refresh_token: Some("mock_new_refresh_token".to_string()),
            token_type: Some("Bearer".to_string()),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
            subject: Some("refreshed_user".to_string()),
            issuer: Some("mock".to_string()),
            user_profile: None,
            permissions: vec!["read:all".to_string(), "write:all".to_string()],
            roles: vec!["refreshed_user".to_string()],
        })
    }
}

/// Mock storage implementation for testing with DashMap for deadlock-free operations.
#[derive(Debug, Clone)]
pub struct MockStorage {
    tokens: Arc<DashMap<String, AuthToken>>,
    sessions: Arc<DashMap<String, SessionData>>,
    kv_store: Arc<DashMap<String, Vec<u8>>>,
    should_fail: bool,
}

impl MockStorage {
    /// Create a new mock storage with DashMap for deadlock-free operations
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            kv_store: Arc::new(DashMap::new()),
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

        // Use DashMap deadlock-free insertion
        self.tokens.insert(token.access_token.clone(), token);
        Ok(())
    }

    /// Clear all storage using DashMap atomic operations
    pub fn clear(&self) {
        self.tokens.clear();
        self.sessions.clear();
        self.kv_store.clear();
    }
}

impl Default for MockStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuthStorage for MockStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free insertion
        self.tokens
            .insert(token.access_token.clone(), token.clone());
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free iteration with immediate value extraction
        for entry in self.tokens.iter() {
            if entry.value().token_id == token_id {
                return Ok(Some(entry.value().clone()));
            }
        }
        Ok(None)
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free get with immediate value extraction
        Ok(self
            .tokens
            .get(access_token)
            .map(|entry| entry.value().clone()))
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free update
        self.tokens
            .insert(token.access_token.clone(), token.clone());
        Ok(())
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free removal with retain-like operation
        self.tokens.retain(|_, token| token.token_id != token_id);
        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap with manual iteration to avoid API issues
        let mut tokens = Vec::new();
        for entry in self.tokens.iter() {
            if entry.value().user_id == user_id {
                tokens.push(entry.value().clone());
            }
        }
        Ok(tokens)
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free insertion
        self.sessions.insert(session_id.to_string(), data.clone());
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free get with immediate value extraction
        Ok(self
            .sessions
            .get(session_id)
            .map(|entry| entry.value().clone()))
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free removal
        self.sessions.remove(session_id);
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap with manual iteration to avoid API issues
        let mut sessions = Vec::new();
        for entry in self.sessions.iter() {
            if entry.value().user_id == user_id && !entry.value().is_expired() {
                sessions.push(entry.value().clone());
            }
        }
        Ok(sessions)
    }

    async fn store_kv(&self, key: &str, value: &[u8], _ttl: Option<Duration>) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free insertion
        self.kv_store.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free get with immediate value extraction
        Ok(self.kv_store.get(key).map(|entry| entry.value().clone()))
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free removal
        self.kv_store.remove(key);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        let now = chrono::Utc::now();

        // Use DashMap deadlock-free retain operation
        self.tokens.retain(|_, token| token.expires_at > now);

        Ok(())
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Count non-expired sessions using DashMap with manual iteration
        let mut count = 0u64;
        for entry in self.sessions.iter() {
            if !entry.value().is_expired() {
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Test helper functions
pub mod helpers {
    use super::*;
    // use std::sync::Arc;  // Temporarily unused

    /// Create a test user profile
    pub fn create_test_user_profile(user_id: &str) -> UserProfile {
        UserProfile::new()
            .with_id(user_id)
            .with_provider("test")
            .with_name(Some(format!("Test User {}", user_id)))
            .with_email(Some(format!("{}@test.com", user_id)))
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
            token_type: Some("Bearer".to_string()),
            expires_at: now + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()],
            issued_at: now,
            auth_method: "test".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
            subject: Some(user_id.to_string()),
            issuer: Some("test".to_string()),
            user_profile: None,
            permissions: vec!["read:all".to_string(), "write:all".to_string()],
            roles: vec!["test_user".to_string()],
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
