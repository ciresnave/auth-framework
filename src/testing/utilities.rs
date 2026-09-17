/// Mock authentication method for testing.
///
/// # Example
/// ```rust,ignore
/// let mock = MockAuthMethod::new_success();
/// assert!(mock.should_succeed);
/// ```
#[derive(Debug, Clone)]
pub struct MockAuthMethod {
    /// Whether authentication should succeed
    pub should_succeed: bool,
    /// Simulated user profiles to return
    pub user_profiles: HashMap<String, ProviderProfile>,
    /// Simulated delay for authentication
    pub delay: Option<Duration>,
}

impl MockAuthMethod {
    /// Create a new mock authentication method that always succeeds.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mock = MockAuthMethod::new_success();
    /// assert!(mock.should_succeed);
    /// ```
    pub fn new_success() -> Self {
        MockAuthMethod {
            should_succeed: true,
            user_profiles: HashMap::new(),
            delay: None,
        }
    }

    /// Add a user profile for a specific user ID.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mock = MockAuthMethod::new_success()
    ///     .with_user("user-1", ProviderProfile::new().with_id("user-1"));
    /// ```
    pub fn with_user(mut self, user_id: impl Into<String>, profile: ProviderProfile) -> Self {
        self.user_profiles.insert(user_id.into(), profile);
        self
    }

    /// Set a delay for authentication (useful for testing timeouts).
    ///
    /// # Example
    /// ```rust,ignore
    /// let mock = MockAuthMethod::new_success()
    ///     .with_delay(Duration::from_millis(100));
    /// ```
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}
use crate::authentication::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, Result};
use crate::methods::{AuthMethod, MethodResult};
use crate::providers::ProviderProfile;
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
    use crate::testing::test_infrastructure::TestEnvironmentGuard;

    // Guard clears JWT_SECRET and sets RUST_TEST=1 for proper isolation.
    // force_production_mode() on the config drives production validation without
    // touching the global ENVIRONMENT variable, eliminating the parallel-test race.
    let _env = TestEnvironmentGuard::new();

    let config = AuthConfig::default().force_production_mode();
    match AuthFramework::new_validated(config) {
        Err(e) => {
            // Should fail with proper error message about JWT secret
            assert!(
                e.to_string().contains("JWT secret"),
                "Expected JWT secret error, got: {e}"
            );
        }
        Ok(_) => panic!("Expected error when JWT_SECRET is missing in production"),
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
            scopes: vec!["read".to_string(), "write".to_string()].into(),
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            subject: Some(user_id.clone()),
            issuer: Some("mock".to_string()),
            user_profile: None,
            client_id: Some("test_client".to_string()),
            permissions: vec!["read:all".to_string(), "write:all".to_string()].into(),
            roles: vec!["mock_user".to_string()].into(),
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
            scopes: vec!["read".to_string(), "write".to_string()].into(),
            issued_at: chrono::Utc::now(),
            auth_method: "mock".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
            subject: Some("refreshed_user".to_string()),
            issuer: Some("mock".to_string()),
            user_profile: None,
            permissions: vec!["read:all".to_string(), "write:all".to_string()].into(),
            roles: vec!["refreshed_user".to_string()].into(),
        })
    }
}

/// Mock storage implementation for testing with DashMap for deadlock-free operations.
///
/// # Example
/// ```rust,ignore
/// let storage = MockStorage::new();
/// storage.store_token(&token).await.unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct MockStorage {
    tokens: Arc<DashMap<String, AuthToken>>,
    sessions: Arc<DashMap<String, SessionData>>,
    kv_store: Arc<DashMap<String, Vec<u8>>>,
    should_fail: bool,
}

impl MockStorage {
    /// Create a new mock storage with DashMap for deadlock-free operations.
    ///
    /// # Example
    /// ```rust,ignore
    /// let storage = MockStorage::new();
    /// ```
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            kv_store: Arc::new(DashMap::new()),
            should_fail: false,
        }
    }

    /// Create a mock storage that fails operations.
    ///
    /// # Example
    /// ```rust,ignore
    /// let storage = MockStorage::new_failing();
    /// assert!(storage.store_token(&token).await.is_err());
    /// ```
    pub fn new_failing() -> Self {
        let mut storage = Self::new();
        storage.should_fail = true;
        storage
    }

    /// Preset a token in storage.
    ///
    /// # Example
    /// ```rust,ignore
    /// let storage = MockStorage::new();
    /// storage.with_token(token).unwrap();
    /// ```
    pub fn with_token(&self, token: AuthToken) -> Result<()> {
        if self.should_fail {
            return Err(AuthError::internal("Mock storage configured to fail"));
        }

        // Use DashMap deadlock-free insertion
        self.tokens.insert(token.access_token.clone(), token);
        Ok(())
    }

    /// Clear all storage using DashMap atomic operations.
    ///
    /// # Example
    /// ```rust,ignore
    /// let storage = MockStorage::new();
    /// storage.clear();
    /// ```
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

    /// Create a test user profile.
    ///
    /// # Example
    /// ```rust,ignore
    /// let profile = helpers::create_test_user_profile("user-1");
    /// ```
    pub fn create_test_user_profile(user_id: &str) -> ProviderProfile {
        ProviderProfile::new()
            .with_id(user_id)
            .with_provider("test")
            .with_name(Some(format!("Test User {}", user_id)))
            .with_email(Some(format!("{}@test.com", user_id)))
            .with_email_verified(true)
    }

    /// Create a test auth token.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = helpers::create_test_token("user-1");
    /// assert_eq!(token.user_id, "user-1");
    /// ```
    pub fn create_test_token(user_id: &str) -> AuthToken {
        let now = chrono::Utc::now();
        AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            access_token: format!("test_token_{}", Uuid::new_v4()),
            refresh_token: Some(format!("refresh_token_{}", Uuid::new_v4())),
            token_type: Some("Bearer".to_string()),
            expires_at: now + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()].into(),
            issued_at: now,
            auth_method: "test".to_string(),
            client_id: Some("test_client".to_string()),
            metadata: crate::tokens::TokenMetadata::default(),
            subject: Some(user_id.to_string()),
            issuer: Some("test".to_string()),
            user_profile: None,
            permissions: vec!["read:all".to_string(), "write:all".to_string()].into(),
            roles: vec!["test_user".to_string()].into(),
        }
    }

    /// Create test credentials.
    ///
    /// # Example
    /// ```rust,ignore
    /// let creds = helpers::create_test_credentials();
    /// assert_eq!(creds.len(), 5);
    /// ```
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

// ── Edge-case tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod edge_tests {
    use super::*;
    use crate::testing::test_infrastructure::TestEnvironmentGuard;

    // --- MockAuthMethod authenticate edge cases ---

    #[tokio::test]
    async fn test_mock_auth_failure_mode() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod {
            should_succeed: false,
            user_profiles: HashMap::new(),
            delay: None,
        };
        let cred = Credential::password("user", "pass");
        let meta = CredentialMetadata::default();
        let result = mock.authenticate(cred, meta).await.unwrap();
        match result {
            MethodResult::Failure { reason } => {
                assert!(reason.contains("failed"), "Expected failure: {reason}");
            }
            _ => panic!("Expected Failure variant"),
        }
    }

    #[tokio::test]
    async fn test_mock_auth_api_key_empty() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod::new_success();
        let cred = Credential::api_key("");
        let meta = CredentialMetadata::default();
        // Should not panic with empty API key — &key[..0] is valid
        let result = mock.authenticate(cred, meta).await.unwrap();
        match result {
            MethodResult::Success(token) => {
                assert!(token.user_id.starts_with("api_user_"));
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_mock_auth_api_key_short() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod::new_success();
        let cred = Credential::api_key("abc");
        let meta = CredentialMetadata::default();
        let result = mock.authenticate(cred, meta).await.unwrap();
        match result {
            MethodResult::Success(token) => {
                assert_eq!(token.user_id, "api_user_abc");
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_mock_auth_catch_all_credential() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod::new_success();
        let cred = Credential::jwt("some.jwt.token");
        let meta = CredentialMetadata::default();
        let result = mock.authenticate(cred, meta).await.unwrap();
        match result {
            MethodResult::Success(token) => {
                assert_eq!(token.user_id, "test_user");
            }
            _ => panic!("Expected success"),
        }
    }

    // --- MockAuthMethod refresh edge cases ---

    #[tokio::test]
    async fn test_mock_refresh_success() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod::new_success();
        let token = mock.refresh_token("old_refresh".to_string()).await.unwrap();
        assert_eq!(token.user_id, "refreshed_user");
        assert!(token.refresh_token.is_some());
    }

    #[tokio::test]
    async fn test_mock_refresh_failure() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let mock = MockAuthMethod {
            should_succeed: false,
            user_profiles: HashMap::new(),
            delay: None,
        };
        let result = mock.refresh_token("old_refresh".to_string()).await;
        assert!(result.is_err());
    }

    // --- MockStorage token operations ---

    #[tokio::test]
    async fn test_storage_get_token_by_access_token() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let token = helpers::create_test_token("user1");
        let access = token.access_token.clone();
        storage.store_token(&token).await.unwrap();
        let found = storage.get_token_by_access_token(&access).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, "user1");
    }

    #[tokio::test]
    async fn test_storage_get_token_by_access_token_not_found() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let found = storage
            .get_token_by_access_token("nonexistent")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_storage_update_token() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let mut token = helpers::create_test_token("user1");
        storage.store_token(&token).await.unwrap();
        token.user_id = "updated_user".to_string();
        storage.update_token(&token).await.unwrap();
        let found = storage
            .get_token_by_access_token(&token.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, "updated_user");
    }

    #[tokio::test]
    async fn test_storage_delete_token() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let token = helpers::create_test_token("user1");
        let tid = token.token_id.clone();
        storage.store_token(&token).await.unwrap();
        storage.delete_token(&tid).await.unwrap();
        let found = storage.get_token(&tid).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_storage_list_user_tokens_filters_by_user() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let t1 = helpers::create_test_token("alice");
        let t2 = helpers::create_test_token("alice");
        let t3 = helpers::create_test_token("bob");
        storage.store_token(&t1).await.unwrap();
        storage.store_token(&t2).await.unwrap();
        storage.store_token(&t3).await.unwrap();
        let alice_tokens = storage.list_user_tokens("alice").await.unwrap();
        assert_eq!(alice_tokens.len(), 2);
        let bob_tokens = storage.list_user_tokens("bob").await.unwrap();
        assert_eq!(bob_tokens.len(), 1);
    }

    // --- MockStorage session operations ---

    #[tokio::test]
    async fn test_storage_session_crud() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let session = SessionData {
            session_id: "sess1".to_string(),
            user_id: "user1".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            last_activity: chrono::Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: None,
            data: Default::default(),
        };
        storage.store_session("sess1", &session).await.unwrap();
        let found = storage.get_session("sess1").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, "user1");

        storage.delete_session("sess1").await.unwrap();
        let gone = storage.get_session("sess1").await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_storage_list_user_sessions_filters_expired() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let active = SessionData {
            session_id: "active".to_string(),
            user_id: "user1".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            last_activity: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        };
        let expired = SessionData {
            session_id: "expired".to_string(),
            user_id: "user1".to_string(),
            created_at: chrono::Utc::now() - chrono::Duration::seconds(7200),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(3600),
            last_activity: chrono::Utc::now() - chrono::Duration::seconds(7200),
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        };
        storage.store_session("active", &active).await.unwrap();
        storage.store_session("expired", &expired).await.unwrap();
        let sessions = storage.list_user_sessions("user1").await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "active");
    }

    // --- MockStorage KV operations ---

    #[tokio::test]
    async fn test_storage_kv_crud() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        storage.store_kv("key1", b"value1", None).await.unwrap();
        let val = storage.get_kv("key1").await.unwrap();
        assert_eq!(val.unwrap(), b"value1");

        storage.delete_kv("key1").await.unwrap();
        let gone = storage.get_kv("key1").await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_storage_kv_not_found() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let val = storage.get_kv("nonexistent").await.unwrap();
        assert!(val.is_none());
    }

    // --- MockStorage cleanup ---

    #[tokio::test]
    async fn test_storage_cleanup_expired_tokens() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let mut expired_token = helpers::create_test_token("user1");
        expired_token.expires_at = chrono::Utc::now() - chrono::Duration::seconds(10);
        let valid_token = helpers::create_test_token("user2");
        storage.store_token(&expired_token).await.unwrap();
        storage.store_token(&valid_token).await.unwrap();
        storage.cleanup_expired().await.unwrap();
        // Expired token should be gone
        let found_expired = storage
            .get_token_by_access_token(&expired_token.access_token)
            .await
            .unwrap();
        assert!(found_expired.is_none());
        // Valid token should remain
        let found_valid = storage
            .get_token_by_access_token(&valid_token.access_token)
            .await
            .unwrap();
        assert!(found_valid.is_some());
    }

    // --- helpers::create_test_credentials ---

    #[test]
    fn test_create_test_credentials_all_variants() {
        let creds = helpers::create_test_credentials();
        assert_eq!(creds.len(), 5);
        assert!(matches!(&creds[0], Credential::Password { .. }));
        assert!(matches!(&creds[1], Credential::ApiKey { .. }));
        assert!(matches!(&creds[2], Credential::OAuth { .. }));
        assert!(matches!(&creds[3], Credential::DeviceCode { .. }));
        assert!(matches!(&creds[4], Credential::Jwt { .. }));
    }

    // --- MockStorage count_active_sessions ---

    #[tokio::test]
    async fn test_storage_count_active_sessions() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
        let storage = MockStorage::new();
        let active = SessionData {
            session_id: "active1".to_string(),
            user_id: "user1".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(3600),
            last_activity: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        };
        let expired = SessionData {
            session_id: "expired1".to_string(),
            user_id: "user2".to_string(),
            created_at: chrono::Utc::now() - chrono::Duration::seconds(7200),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(3600),
            last_activity: chrono::Utc::now() - chrono::Duration::seconds(7200),
            ip_address: None,
            user_agent: None,
            data: Default::default(),
        };
        storage.store_session("active1", &active).await.unwrap();
        storage.store_session("expired1", &expired).await.unwrap();
        let count = storage.count_active_sessions().await.unwrap();
        assert_eq!(count, 1);
    }
}
