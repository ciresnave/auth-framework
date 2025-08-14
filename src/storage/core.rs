//! Storage backends for authentication data.

use crate::errors::Result;
use crate::tokens::AuthToken;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[cfg(feature = "redis-storage")]
use crate::errors::StorageError;

/// Trait for authentication data storage.
#[async_trait]
pub trait AuthStorage: Send + Sync {
    /// Bulk store tokens.
    async fn store_tokens_bulk(&self, tokens: &[AuthToken]) -> Result<()> {
        for token in tokens {
            self.store_token(token).await?;
        }
        Ok(())
    }

    /// Bulk delete tokens by ID.
    async fn delete_tokens_bulk(&self, token_ids: &[String]) -> Result<()> {
        for token_id in token_ids {
            self.delete_token(token_id).await?;
        }
        Ok(())
    }

    /// Bulk store sessions.
    async fn store_sessions_bulk(&self, sessions: &[(String, SessionData)]) -> Result<()> {
        for (session_id, data) in sessions {
            self.store_session(session_id, data).await?;
        }
        Ok(())
    }

    /// Bulk delete sessions by ID.
    async fn delete_sessions_bulk(&self, session_ids: &[String]) -> Result<()> {
        for session_id in session_ids {
            self.delete_session(session_id).await?;
        }
        Ok(())
    }
    /// Store a token.
    async fn store_token(&self, token: &AuthToken) -> Result<()>;

    /// Retrieve a token by ID.
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>>;

    /// Retrieve a token by access token string.
    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>>;

    /// Update a token.
    async fn update_token(&self, token: &AuthToken) -> Result<()>;

    /// Delete a token.
    async fn delete_token(&self, token_id: &str) -> Result<()>;

    /// List all tokens for a user.
    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>>;

    /// Store session data.
    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()>;

    /// Retrieve session data.
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>>;

    /// Delete session data.
    async fn delete_session(&self, session_id: &str) -> Result<()>;

    /// List all sessions for a user.
    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>>;

    /// Store arbitrary key-value data with expiration.
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()>;

    /// Retrieve arbitrary key-value data.
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete arbitrary key-value data.
    async fn delete_kv(&self, key: &str) -> Result<()>;

    /// Clean up expired data.
    async fn cleanup_expired(&self) -> Result<()>;
}

/// Session data stored in the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session ID
    pub session_id: String,

    /// User ID associated with this session
    pub user_id: String,

    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the session expires
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Last activity timestamp
    pub last_activity: chrono::DateTime<chrono::Utc>,

    /// IP address of the session
    pub ip_address: Option<String>,

    /// User agent
    pub user_agent: Option<String>,

    /// Custom session data
    pub data: HashMap<String, serde_json::Value>,
}

/// In-memory storage implementation (for development/testing).
/// SECURITY UPDATE: Now uses DashMap for deadlock-free concurrent operations
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    // Primary storage using DashMap for deadlock-free operations
    inner: crate::storage::dashmap_memory::DashMapMemoryStorage,
    // RBAC storage still uses RwLock for compatibility (lower concurrency requirements)
    roles: Arc<RwLock<HashMap<String, crate::authorization::Role>>>,
    user_roles: Arc<RwLock<Vec<crate::authorization::UserRole>>>,
}

/// Redis storage implementation.
#[cfg(feature = "redis-storage")]
#[derive(Debug, Clone)]
pub struct RedisStorage {
    client: redis::Client,
    key_prefix: String,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// Create a new in-memory storage.
    pub fn new() -> Self {
        Self {
            inner: crate::storage::dashmap_memory::DashMapMemoryStorage::new(),
            roles: Arc::new(RwLock::new(HashMap::new())),
            user_roles: Arc::new(RwLock::new(Vec::new())),
        }
    }
}
// In-memory AuthorizationStorage implementation for RBAC examples
#[async_trait::async_trait]
impl crate::authorization::AuthorizationStorage for MemoryStorage {
    async fn store_role(&self, role: &crate::authorization::Role) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().unwrap();
        roles.insert(role.id.clone(), role.clone());
        Ok(())
    }

    async fn get_role(
        &self,
        role_id: &str,
    ) -> crate::errors::Result<Option<crate::authorization::Role>> {
        let roles = self.roles.read().unwrap();
        Ok(roles.get(role_id).cloned())
    }

    async fn update_role(&self, role: &crate::authorization::Role) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().unwrap();
        roles.insert(role.id.clone(), role.clone());
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().unwrap();
        roles.remove(role_id);
        Ok(())
    }

    async fn list_roles(&self) -> crate::errors::Result<Vec<crate::authorization::Role>> {
        let roles = self.roles.read().unwrap();
        Ok(roles.values().cloned().collect())
    }

    async fn assign_role(
        &self,
        user_role: &crate::authorization::UserRole,
    ) -> crate::errors::Result<()> {
        let mut user_roles = self.user_roles.write().unwrap();
        user_roles.push(user_role.clone());
        Ok(())
    }

    async fn remove_role(&self, user_id: &str, role_id: &str) -> crate::errors::Result<()> {
        let mut user_roles = self.user_roles.write().unwrap();
        user_roles.retain(|ur| ur.user_id != user_id || ur.role_id != role_id);
        Ok(())
    }

    async fn get_user_roles(
        &self,
        user_id: &str,
    ) -> crate::errors::Result<Vec<crate::authorization::UserRole>> {
        let user_roles = self.user_roles.read().unwrap();
        Ok(user_roles
            .iter()
            .filter(|ur| ur.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn get_role_users(
        &self,
        role_id: &str,
    ) -> crate::errors::Result<Vec<crate::authorization::UserRole>> {
        let user_roles = self.user_roles.read().unwrap();
        Ok(user_roles
            .iter()
            .filter(|ur| ur.role_id == role_id)
            .cloned()
            .collect())
    }
}

#[async_trait]
impl AuthStorage for MemoryStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.store_token(token).await
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.get_token(token_id).await
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.get_token_by_access_token(access_token).await
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.update_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.delete_token(token_id).await
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.list_user_tokens(user_id).await
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.store_session(session_id, data).await
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.get_session(session_id).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.delete_session(session_id).await
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.list_user_sessions(user_id).await
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.store_kv(key, value, ttl).await
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.get_kv(key).await
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.delete_kv(key).await
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.cleanup_expired().await
    }
}

#[cfg(feature = "redis-storage")]
impl RedisStorage {
    /// Create a new Redis storage.
    pub fn new(redis_url: &str, key_prefix: impl Into<String>) -> Result<Self> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            StorageError::connection_failed(format!("Redis connection failed: {e}"))
        })?;

        Ok(Self {
            client,
            key_prefix: key_prefix.into(),
        })
    }

    /// Get a Redis connection.
    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| {
                StorageError::connection_failed(format!("Failed to get Redis connection: {e}"))
                    .into()
            })
    }

    /// Generate a key with the configured prefix.
    fn key(&self, suffix: &str) -> String {
        format!("{}{}", self.key_prefix, suffix)
    }
}

#[cfg(feature = "redis-storage")]
#[async_trait]
impl AuthStorage for RedisStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let token_json = serde_json::to_string(token)
            .map_err(|e| StorageError::serialization(format!("Token serialization failed: {e}")))?;

        let token_key = self.key(&format!("token:{}", token.token_id));
        let access_token_key = self.key(&format!("access_token:{}", token.access_token));
        let user_tokens_key = self.key(&format!("user_tokens:{}", token.user_id));

        // Calculate TTL
        let ttl = token.time_until_expiry().as_secs().max(1);

        // Store token data
        let _: () = redis::cmd("SETEX")
            .arg(&token_key)
            .arg(ttl)
            .arg(&token_json)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to store token: {e}")))?;

        // Store access token mapping
        let _: () = redis::cmd("SETEX")
            .arg(&access_token_key)
            .arg(ttl)
            .arg(&token.token_id)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                StorageError::operation_failed(format!("Failed to store access token mapping: {e}"))
            })?;

        // Add to user tokens set
        let _: () = redis::cmd("SADD")
            .arg(&user_tokens_key)
            .arg(&token.token_id)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                StorageError::operation_failed(format!("Failed to add token to user set: {e}"))
            })?;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let token_key = self.key(&format!("token:{token_id}"));

        let token_json: Option<String> = redis::cmd("GET")
            .arg(&token_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to get token: {e}")))?;

        if let Some(json) = token_json {
            let token: AuthToken = serde_json::from_str(&json).map_err(|e| {
                StorageError::serialization(format!("Token deserialization failed: {e}"))
            })?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let access_token_key = self.key(&format!("access_token:{access_token}"));

        let token_id: Option<String> = redis::cmd("GET")
            .arg(&access_token_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                StorageError::operation_failed(format!("Failed to get access token mapping: {e}"))
            })?;

        if let Some(token_id) = token_id {
            self.get_token(&token_id).await
        } else {
            Ok(None)
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // Same as store_token for Redis
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;

        // Get token first to get access token and user ID
        if let Some(token) = self.get_token(token_id).await? {
            let token_key = self.key(&format!("token:{token_id}"));
            let access_token_key = self.key(&format!("access_token:{}", token.access_token));
            let user_tokens_key = self.key(&format!("user_tokens:{}", token.user_id));

            // Delete token data
            let _: () = redis::cmd("DEL")
                .arg(&token_key)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    StorageError::operation_failed(format!("Failed to delete token: {e}"))
                })?;

            // Delete access token mapping
            let _: () = redis::cmd("DEL")
                .arg(&access_token_key)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    StorageError::operation_failed(format!(
                        "Failed to delete access token mapping: {e}"
                    ))
                })?;

            // Remove from user tokens set
            let _: () = redis::cmd("SREM")
                .arg(&user_tokens_key)
                .arg(token_id)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    StorageError::operation_failed(format!(
                        "Failed to remove token from user set: {e}"
                    ))
                })?;
        }

        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let user_tokens_key = self.key(&format!("user_tokens:{user_id}"));

        let token_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_tokens_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                StorageError::operation_failed(format!("Failed to get user tokens: {e}"))
            })?;

        let mut tokens = Vec::new();
        for token_id in token_ids {
            if let Some(token) = self.get_token(&token_id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let session_key = self.key(&format!("session:{session_id}"));

        let session_json = serde_json::to_string(data).map_err(|e| {
            StorageError::serialization(format!("Session serialization failed: {e}"))
        })?;

        let ttl = (data.expires_at - chrono::Utc::now()).num_seconds().max(1);

        let _: () = redis::cmd("SETEX")
            .arg(&session_key)
            .arg(ttl)
            .arg(&session_json)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to store session: {e}")))?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let mut conn = self.get_connection().await?;
        let session_key = self.key(&format!("session:{session_id}"));

        let session_json: Option<String> = redis::cmd("GET")
            .arg(&session_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to get session: {e}")))?;

        if let Some(json) = session_json {
            let session: SessionData = serde_json::from_str(&json).map_err(|e| {
                StorageError::serialization(format!("Session deserialization failed: {e}"))
            })?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let session_key = self.key(&format!("session:{session_id}"));

        let _: () = redis::cmd("DEL")
            .arg(&session_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                StorageError::operation_failed(format!("Failed to delete session: {e}"))
            })?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let mut conn = self.get_connection().await?;
        let pattern = self.key("session:*");

        // Use SCAN to find all session keys
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to scan sessions: {e}")))?;

        let mut user_sessions = Vec::new();

        // Check each session to see if it belongs to the user
        for key in keys {
            if let Ok(session_json) = redis::cmd("GET")
                .arg(&key)
                .query_async::<Option<String>>(&mut conn)
                .await
                && let Some(session_json) = session_json
                && let Ok(session) = serde_json::from_str::<SessionData>(&session_json)
                && session.user_id == user_id
                && !session.is_expired()
            {
                user_sessions.push(session);
            }
        }

        Ok(user_sessions)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let storage_key = self.key(&format!("kv:{key}"));

        if let Some(ttl) = ttl {
            let _: () = redis::cmd("SETEX")
                .arg(&storage_key)
                .arg(ttl.as_secs())
                .arg(value)
                .query_async(&mut conn)
                .await
                .map_err(|e| {
                    StorageError::operation_failed(format!("Failed to store KV with TTL: {e}"))
                })?;
        } else {
            let _: () = redis::cmd("SET")
                .arg(&storage_key)
                .arg(value)
                .query_async(&mut conn)
                .await
                .map_err(|e| StorageError::operation_failed(format!("Failed to store KV: {e}")))?;
        }

        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;
        let storage_key = self.key(&format!("kv:{key}"));

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&storage_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to get KV: {e}")))?;

        Ok(value)
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let storage_key = self.key(&format!("kv:{key}"));

        let _: () = redis::cmd("DEL")
            .arg(&storage_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to delete KV: {e}")))?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Redis handles expiration automatically, so this is a no-op
        Ok(())
    }
}

impl SessionData {
    /// Create a new session.
    pub fn new(
        session_id: impl Into<String>,
        user_id: impl Into<String>,
        expires_in: Duration,
    ) -> Self {
        let now = chrono::Utc::now();

        Self {
            session_id: session_id.into(),
            user_id: user_id.into(),
            created_at: now,
            expires_at: now + chrono::Duration::from_std(expires_in).unwrap(),
            last_activity: now,
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
        }
    }

    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Update the last activity timestamp.
    pub fn update_activity(&mut self) {
        self.last_activity = chrono::Utc::now();
    }

    /// Set session metadata.
    pub fn with_metadata(mut self, ip_address: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    /// Add custom data to the session.
    pub fn set_data(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    /// Get custom data from the session.
    pub fn get_data(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::AuthToken;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();

        // Create a test token
        let token = AuthToken::new("user123", "token123", Duration::from_secs(3600), "test");

        // Store token
        storage.store_token(&token).await.unwrap();

        // Retrieve token
        let retrieved = storage.get_token(&token.token_id).await.unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user123");

        // Retrieve by access token
        let retrieved = storage
            .get_token_by_access_token(&token.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.token_id, token.token_id);

        // List user tokens
        let user_tokens = storage.list_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);

        // Delete token
        storage.delete_token(&token.token_id).await.unwrap();
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_session_storage() {
        let storage = MemoryStorage::new();

        let session = SessionData::new("session123", "user123", Duration::from_secs(3600))
            .with_metadata(
                Some("192.168.1.1".to_string()),
                Some("Test Agent".to_string()),
            );

        // Store session
        storage
            .store_session(&session.session_id, &session)
            .await
            .unwrap();

        // Retrieve session
        let retrieved = storage
            .get_session(&session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.user_id, "user123");
        assert_eq!(retrieved.ip_address, Some("192.168.1.1".to_string()));

        // Delete session
        storage.delete_session(&session.session_id).await.unwrap();
        let retrieved = storage.get_session(&session.session_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_kv_storage() {
        let storage = MemoryStorage::new();

        let key = "test_key";
        let value = b"test_value";

        // Store KV
        storage
            .store_kv(key, value, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        // Retrieve KV
        let retrieved = storage.get_kv(key).await.unwrap().unwrap();
        assert_eq!(retrieved, value);

        // Delete KV
        storage.delete_kv(key).await.unwrap();
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_none());
    }
}
