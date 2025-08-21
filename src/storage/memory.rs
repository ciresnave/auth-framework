//! In-memory storage backend for auth-framework with DashMap for deadlock-free operations.
//!
//! This module provides a fast in-memory storage implementation
//! suitable for development, testing, and single-instance deployments.
//!
//! Uses DashMap to provide:
//! - Lock-free concurrent access
//! - Deadlock-free operations
//! - Better performance under high concurrency

use crate::{
    errors::Result,
    storage::{AuthStorage, SessionData},
    tokens::AuthToken,
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::time;

/// In-memory storage backend with automatic cleanup
#[derive(Clone)]
pub struct InMemoryStorage {
    tokens: Arc<RwLock<HashMap<String, TimestampedToken>>>,
    access_tokens: Arc<RwLock<HashMap<String, String>>>, // access_token -> token_id
    user_tokens: Arc<RwLock<HashMap<String, Vec<String>>>>, // user_id -> token_ids
    sessions: Arc<RwLock<HashMap<String, TimestampedSession>>>,
    kv_store: Arc<RwLock<HashMap<String, TimestampedValue>>>,
    cleanup_interval: Duration,
    default_ttl: Duration,
}

#[derive(Clone)]
struct TimestampedToken {
    token: AuthToken,
    expires_at: Instant,
}

#[derive(Clone)]
struct TimestampedSession {
    session: SessionData,
    expires_at: Instant,
}

#[derive(Clone)]
struct TimestampedValue {
    value: Vec<u8>,
    expires_at: Instant,
}

impl InMemoryStorage {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        let storage = Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            user_tokens: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            kv_store: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            default_ttl: Duration::from_secs(3600),     // 1 hour
        };

        // Start background cleanup task
        storage.start_cleanup_task();
        storage
    }

    /// Create in-memory storage with custom configuration
    pub fn with_config(cleanup_interval: Duration, default_ttl: Duration) -> Self {
        let mut storage = Self::new();
        storage.cleanup_interval = cleanup_interval;
        storage.default_ttl = default_ttl;
        storage
    }

    fn start_cleanup_task(&self) {
        let tokens = self.tokens.clone();
        let access_tokens = self.access_tokens.clone();
        let user_tokens = self.user_tokens.clone();
        let sessions = self.sessions.clone();
        let kv_store = self.kv_store.clone();
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut cleanup_timer = time::interval(interval);

            loop {
                cleanup_timer.tick().await;
                Self::cleanup_expired_data(
                    &tokens,
                    &access_tokens,
                    &user_tokens,
                    &sessions,
                    &kv_store,
                );
            }
        });
    }

    fn cleanup_expired_data(
        tokens: &Arc<RwLock<HashMap<String, TimestampedToken>>>,
        access_tokens: &Arc<RwLock<HashMap<String, String>>>,
        user_tokens: &Arc<RwLock<HashMap<String, Vec<String>>>>,
        sessions: &Arc<RwLock<HashMap<String, TimestampedSession>>>,
        kv_store: &Arc<RwLock<HashMap<String, TimestampedValue>>>,
    ) {
        let now = Instant::now();

        // Clean up expired tokens
        {
            let mut tokens_guard = tokens.write().unwrap();
            let mut access_tokens_guard = access_tokens.write().unwrap();
            let mut user_tokens_guard = user_tokens.write().unwrap();

            let expired_tokens: Vec<String> = tokens_guard
                .iter()
                .filter(|(_, timestamped)| timestamped.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect();

            for token_id in expired_tokens {
                if let Some(timestamped) = tokens_guard.remove(&token_id) {
                    // Remove access token lookup
                    access_tokens_guard.remove(&timestamped.token.access_token);

                    // Remove from user tokens
                    if let Some(user_token_list) =
                        user_tokens_guard.get_mut(&timestamped.token.user_id)
                    {
                        user_token_list.retain(|id| id != &token_id);
                        if user_token_list.is_empty() {
                            user_tokens_guard.remove(&timestamped.token.user_id);
                        }
                    }
                }
            }
        }

        // Clean up expired sessions
        {
            let mut sessions_guard = sessions.write().unwrap();
            sessions_guard.retain(|_, timestamped| timestamped.expires_at > now);
        }

        // Clean up expired KV pairs
        {
            let mut kv_guard = kv_store.write().unwrap();
            kv_guard.retain(|_, timestamped| timestamped.expires_at > now);
        }
    }

    fn calculate_expiry(&self, token: &AuthToken) -> Instant {
        let now = chrono::Utc::now();
        if token.expires_at > now {
            let duration = (token.expires_at - now).num_seconds() as u64;
            Instant::now() + Duration::from_secs(duration)
        } else {
            Instant::now() + self.default_ttl
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthStorage for InMemoryStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let expires_at = self.calculate_expiry(token);
        let timestamped_token = TimestampedToken {
            token: token.clone(),
            expires_at,
        };

        {
            let mut tokens = self.tokens.write().unwrap();
            tokens.insert(token.token_id.clone(), timestamped_token);
        }

        {
            let mut access_tokens = self.access_tokens.write().unwrap();
            access_tokens.insert(token.access_token.clone(), token.token_id.clone());
        }

        {
            let mut user_tokens = self.user_tokens.write().unwrap();
            user_tokens
                .entry(token.user_id.clone())
                .or_default()
                .push(token.token_id.clone());
        }

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let tokens = self.tokens.read().unwrap();
        if let Some(timestamped) = tokens.get(token_id) {
            if timestamped.expires_at > Instant::now() {
                Ok(Some(timestamped.token.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let token_id_opt = {
            let access_tokens = self.access_tokens.read().unwrap();
            access_tokens.get(access_token).cloned()
        };
        if let Some(token_id) = token_id_opt {
            self.get_token(&token_id).await
        } else {
            Ok(None)
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // For in-memory storage, update is the same as store
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        let removed_token = {
            let mut tokens = self.tokens.write().unwrap();
            tokens.remove(token_id)
        };

        if let Some(timestamped) = removed_token {
            // Remove access token lookup
            {
                let mut access_tokens = self.access_tokens.write().unwrap();
                access_tokens.remove(&timestamped.token.access_token);
            }

            // Remove from user tokens
            {
                let mut user_tokens = self.user_tokens.write().unwrap();
                if let Some(user_token_list) = user_tokens.get_mut(&timestamped.token.user_id) {
                    user_token_list.retain(|id| id != token_id);
                    if user_token_list.is_empty() {
                        user_tokens.remove(&timestamped.token.user_id);
                    }
                }
            }
        }

        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let user_tokens = self.user_tokens.read().unwrap();
        let tokens = self.tokens.read().unwrap();
        let now = Instant::now();

        match user_tokens.get(user_id) {
            Some(token_ids) => {
                let mut result = Vec::new();
                for token_id in token_ids {
                    if let Some(timestamped) = tokens.get(token_id)
                        && timestamped.expires_at > now
                    {
                        result.push(timestamped.token.clone());
                    }
                }
                Ok(result)
            }
            None => Ok(Vec::new()),
        }
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let expires_at = Instant::now() + self.default_ttl;
        let timestamped_session = TimestampedSession {
            session: data.clone(),
            expires_at,
        };

        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session_id.to_string(), timestamped_session);
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let sessions = self.sessions.read().unwrap();
        if let Some(timestamped) = sessions.get(session_id) {
            if timestamped.expires_at > Instant::now() {
                Ok(Some(timestamped.session.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let sessions = self.sessions.read().unwrap();
        let now = Instant::now();

        let user_sessions: Vec<SessionData> = sessions
            .values()
            .filter_map(|timestamped| {
                if timestamped.session.user_id == user_id && timestamped.expires_at > now {
                    Some(timestamped.session.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(user_sessions)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let expires_at = Instant::now() + ttl.unwrap_or(self.default_ttl);
        let timestamped_value = TimestampedValue {
            value: value.to_vec(),
            expires_at,
        };

        let mut kv_store = self.kv_store.write().unwrap();
        kv_store.insert(key.to_string(), timestamped_value);
        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let kv_store = self.kv_store.read().unwrap();
        if let Some(timestamped) = kv_store.get(key) {
            if timestamped.expires_at > Instant::now() {
                Ok(Some(timestamped.value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        let mut kv_store = self.kv_store.write().unwrap();
        kv_store.remove(key);
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        Self::cleanup_expired_data(
            &self.tokens,
            &self.access_tokens,
            &self.user_tokens,
            &self.sessions,
            &self.kv_store,
        );
        Ok(())
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let sessions = self.sessions.read().unwrap();
        let now = Instant::now();

        let active_count = sessions
            .values()
            .filter(|timestamped| timestamped.expires_at > now)
            .count() as u64;

        Ok(active_count)
    }
}

/// Configuration for in-memory storage
pub struct InMemoryConfig {
    pub cleanup_interval: Duration,
    pub default_ttl: Duration,
}

impl Default for InMemoryConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            default_ttl: Duration::from_secs(3600),     // 1 hour
        }
    }
}

impl InMemoryConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    pub fn build(self) -> InMemoryStorage {
        InMemoryStorage::with_config(self.cleanup_interval, self.default_ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::helpers::create_test_token;

    #[tokio::test]
    async fn test_in_memory_token_operations() {
        let storage = InMemoryStorage::new();
        let token = create_test_token("test_user");

        // Store token
        storage.store_token(&token).await.unwrap();

        // Retrieve by ID
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().token_id, token.token_id);

        // Retrieve by access token
        let retrieved = storage
            .get_token_by_access_token(&token.access_token)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().access_token, token.access_token);

        // List user tokens
        let user_tokens = storage.list_user_tokens(&token.user_id).await.unwrap();
        assert_eq!(user_tokens.len(), 1);

        // Delete token
        storage.delete_token(&token.token_id).await.unwrap();
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_expiration() {
        let storage = InMemoryStorage::with_config(
            Duration::from_millis(100), // Fast cleanup
            Duration::from_millis(200), // Short TTL
        );

        let key = "test_key";
        let value = b"test_value";

        // Store with short TTL
        storage
            .store_kv(key, value, Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Should be available immediately
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_session_operations() {
        let storage = InMemoryStorage::new();

        let session_id = "test_session";
        let session_data = SessionData {
            session_id: session_id.to_string(),
            user_id: "test_user".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            last_activity: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            data: [("key".to_string(), serde_json::json!("value"))]
                .into_iter()
                .collect(),
        };

        // Store session
        storage
            .store_session(session_id, &session_data)
            .await
            .unwrap();

        // Retrieve session
        let retrieved = storage.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, session_data.user_id);

        // Delete session
        storage.delete_session(session_id).await.unwrap();
        let retrieved = storage.get_session(session_id).await.unwrap();
        assert!(retrieved.is_none());
    }
}


