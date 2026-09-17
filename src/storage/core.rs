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

/// Trait for authentication data storage backends.
///
/// All persistence in `AuthFramework` goes through this trait — tokens,
/// sessions, and arbitrary key-value data.  Implement it to plug in a
/// custom database while keeping the rest of the framework unchanged.
///
/// # Provided Implementations
///
/// | Backend | Type | Feature flag |
/// |---------|------|-------------|
/// | In-memory (DashMap) | [`MemoryStorage`] | *(always available)* |
/// | PostgreSQL | [`PostgresStorage`](crate::storage::postgres::PostgresStorage) | `postgres-storage` |
/// | MySQL | [`MySqlStorage`](crate::storage::mysql::MySqlStorage) | `mysql-storage` |
/// | Redis | [`RedisStorage`] | `redis-storage` |
/// | SQLite | [`SqliteStorage`](crate::storage::sqlite::SqliteStorage) | `sqlite-storage` |
/// | Encrypted wrapper | [`EncryptedStorage`](crate::storage::encryption::EncryptedStorage) | *(always available)* |
///
/// # Implementing This Trait
///
/// Custom storage backends must:
///
/// 1. **Be thread-safe** — the trait requires `Send + Sync`.
/// 2. **Handle concurrent access** — multiple tasks will read/write
///    simultaneously. Use connection pooling or interior mutability.
/// 3. **Honour TTL** — [`store_kv`](Self::store_kv) accepts an optional TTL.
///    Expired entries must not be returned by [`get_kv`](Self::get_kv).
/// 4. **Override `list_kv_keys`** — the default returns an empty `Vec`.
///    Analytics, compliance, and RBAC queries depend on real data.
/// 5. **Implement `cleanup_expired`** — periodically called to prune stale
///    tokens and sessions.
///
/// # Example (skeleton)
///
/// ```rust,no_run
/// use auth_framework::storage::{AuthStorage, SessionData};
/// use auth_framework::tokens::AuthToken;
/// use auth_framework::errors::Result;
/// use async_trait::async_trait;
/// use std::time::Duration;
///
/// struct MyStorage { /* ... */ }
///
/// #[async_trait]
/// impl AuthStorage for MyStorage {
///     async fn store_token(&self, token: &AuthToken) -> Result<()> { todo!() }
///     async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> { todo!() }
///     async fn get_token_by_access_token(&self, _: &str) -> Result<Option<AuthToken>> { todo!() }
///     async fn update_token(&self, token: &AuthToken) -> Result<()> { todo!() }
///     async fn delete_token(&self, token_id: &str) -> Result<()> { todo!() }
///     async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> { todo!() }
///     async fn store_session(&self, id: &str, data: &SessionData) -> Result<()> { todo!() }
///     async fn get_session(&self, id: &str) -> Result<Option<SessionData>> { todo!() }
///     async fn delete_session(&self, id: &str) -> Result<()> { todo!() }
///     async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> { todo!() }
///     async fn count_active_sessions(&self) -> Result<u64> { todo!() }
///     async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> { todo!() }
///     async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> { todo!() }
///     async fn delete_kv(&self, key: &str) -> Result<()> { todo!() }
///     async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> { todo!() }
///     async fn cleanup_expired(&self) -> Result<()> { todo!() }
/// }
/// ```
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

    /// Count currently active sessions (non-expired)
    async fn count_active_sessions(&self) -> Result<u64>;

    /// Store arbitrary key-value data with expiration.
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()>;

    /// Retrieve arbitrary key-value data.
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete arbitrary key-value data.
    async fn delete_kv(&self, key: &str) -> Result<()>;

    /// List keys with a specific prefix.
    ///
    /// **Important:** All storage backends must override this method to return
    /// real key data. The default returns an empty `Vec` for backward compatibility
    /// but will cause analytics, compliance, and RBAC queries to operate on empty data.
    async fn list_kv_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        tracing::warn!(
            "list_kv_keys called on a storage backend that does not override it — returning empty"
        );
        Ok(Vec::new())
    }

    /// Clean up expired data.
    async fn cleanup_expired(&self) -> Result<()>;
}

/// Session data stored in the backend.
///
/// All fields are public for serialization flexibility. When constructing
/// a new session prefer [`SessionData::new`] which initialises timestamps
/// consistently.
///
/// # Chainable construction
///
/// ```rust,ignore
/// let session = SessionData::new("sess-1", "user-1", Duration::from_secs(3600))
///     .ip_address("127.0.0.1")
///     .user_agent("Mozilla/5.0")
///     .with_data("role", json!("admin"));
/// ```
///
/// The older [`SessionData::with_metadata`] helper sets both IP and
/// user-agent in a single call and remains available.
///
/// # Invariants (not enforced at the type level)
///
/// * `created_at <= last_activity`
/// * `created_at < expires_at`
/// * `last_activity` is updated on every authenticated access.
/// * `data` may contain arbitrary application-specific key/value pairs
///   — the framework never reads them.
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

/// In-memory storage implementation (for development/testing only).
///
/// # ⚠️ Production Unsuitability
///
/// This implementation is NOT recommended for production use:
/// - **Data Loss**: All stored tokens and sessions are lost on process restart
/// - **Memory Growth**: No automatic cleanup; memory usage grows unbounded
/// - **TTL Ignored**: Expiration times are not enforced; expired tokens may be returned
/// - **Single Instance**: Cannot be used in multi-instance deployments
/// - **No Persistence**: No option to back up or export data
///
/// Use `PostgresStorage`, `MySqlStorage`, `RedisStorage`, or `SqliteStorage` for production.
///
/// SECURITY UPDATE: Now uses DashMap for deadlock-free concurrent operations
#[derive(Debug, Clone)]
pub struct MemoryStorage {
    // Primary storage using DashMap for deadlock-free operations
    inner: crate::storage::dashmap_memory::DashMapMemoryStorage,
    // RBAC storage still uses RwLock for compatibility (lower concurrency requirements)
    roles: Arc<RwLock<HashMap<String, crate::authorization::AbacRole>>>,
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
    async fn store_role(&self, role: &crate::authorization::AbacRole) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        roles.insert(role.id.clone(), role.clone());
        Ok(())
    }

    async fn get_role(
        &self,
        role_id: &str,
    ) -> crate::errors::Result<Option<crate::authorization::AbacRole>> {
        let roles = self.roles.read().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        Ok(roles.get(role_id).cloned())
    }

    async fn update_role(
        &self,
        role: &crate::authorization::AbacRole,
    ) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        roles.insert(role.id.clone(), role.clone());
        Ok(())
    }

    async fn delete_role(&self, role_id: &str) -> crate::errors::Result<()> {
        let mut roles = self.roles.write().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        roles.remove(role_id);
        Ok(())
    }

    async fn list_roles(&self) -> crate::errors::Result<Vec<crate::authorization::AbacRole>> {
        let roles = self.roles.read().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        Ok(roles.values().cloned().collect())
    }

    async fn assign_role(
        &self,
        user_role: &crate::authorization::UserRole,
    ) -> crate::errors::Result<()> {
        let mut user_roles = self.user_roles.write().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        user_roles.push(user_role.clone());
        Ok(())
    }

    async fn remove_role(&self, user_id: &str, role_id: &str) -> crate::errors::Result<()> {
        let mut user_roles = self.user_roles.write().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
        user_roles.retain(|ur| ur.user_id != user_id || ur.role_id != role_id);
        Ok(())
    }

    async fn get_user_roles(
        &self,
        user_id: &str,
    ) -> crate::errors::Result<Vec<crate::authorization::UserRole>> {
        let user_roles = self.user_roles.read().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
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
        let user_roles = self.user_roles.read().map_err(|_| {
            crate::errors::AuthError::internal(
                "Lock poisoned — a prior thread panicked while holding this lock",
            )
        })?;
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

    async fn count_active_sessions(&self) -> Result<u64> {
        // Delegate to DashMap implementation for deadlock-free operations
        self.inner.count_active_sessions().await
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

    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self.inner.list_kv_keys_by_prefix(prefix))
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
            .get_multiplexed_async_connection()
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

    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let mut conn = self.get_connection().await?;
        let pattern = self.key(&format!("kv:{prefix}*"));
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to list KV keys: {e}")))?;

        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&self.key_prefix).map(str::to_string))
            .filter_map(|key| key.strip_prefix("kv:").map(str::to_string))
            .collect())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Redis handles expiration automatically, so this is a no-op
        Ok(())
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let mut conn = self.get_connection().await?;
        let pattern = self.key("session:*");

        // Use KEYS to find all session keys (consider SCAN for production with many keys)
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(&pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| StorageError::operation_failed(format!("Failed to scan sessions: {e}")))?;

        // Count only non-expired sessions by checking TTL
        let mut active_count = 0u64;
        for key in keys {
            let ttl: i64 = redis::cmd("TTL")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .map_err(|e| StorageError::operation_failed(format!("Failed to check TTL: {e}")))?;

            // TTL > 0 means key has expiration and is still active
            // TTL = -1 means key has no expiration (active)
            // TTL = -2 means key doesn't exist (expired)
            if ttl > 0 || ttl == -1 {
                active_count += 1;
            }
        }

        Ok(active_count)
    }
}

impl SessionData {
    /// Create a new session with consistent timestamps.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier (typically a UUID)
    /// * `user_id` - Associated user ID
    /// * `expires_in` - Session lifetime from now
    ///
    /// Use [`with_metadata`](SessionData::with_metadata) to attach IP and
    /// user-agent information after construction.
    ///
    /// # Panics
    /// If `expires_in` conversion to `chrono::Duration` fails catastrophically.
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
            expires_at: now
                + chrono::Duration::from_std(expires_in).unwrap_or(chrono::Duration::hours(1)),
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

    /// Return the remaining lifetime of this session.
    ///
    /// Returns [`Duration::ZERO`](std::time::Duration::ZERO) when the session
    /// has already expired.
    pub fn time_until_expiry(&self) -> std::time::Duration {
        let remaining = self.expires_at - chrono::Utc::now();
        remaining.to_std().unwrap_or(std::time::Duration::ZERO)
    }

    /// Check if the session is still active (not expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }

    /// Update the last activity timestamp.
    pub fn update_activity(&mut self) {
        self.last_activity = chrono::Utc::now();
    }

    /// Set session metadata (IP address and user-agent) in one call.
    pub fn with_metadata(mut self, ip_address: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    /// Set the client IP address.
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the client user-agent string.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Add a custom data entry (chainable).
    pub fn with_data(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.data.insert(key.into(), value);
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

/// Implementation of AuditStorage for MemoryStorage
#[async_trait]
impl crate::audit::AuditStorage for MemoryStorage {
    async fn store_event(&self, event: &crate::audit::AuditEvent) -> Result<()> {
        // Store audit event as JSON in KV storage
        let json_data = serde_json::to_vec(event).map_err(|e| {
            crate::errors::AuthError::internal(format!("Failed to serialize audit event: {}", e))
        })?;

        let key = format!("audit_event_{}", event.id);
        self.store_kv(&key, &json_data, None).await
    }

    async fn query_events(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<Vec<crate::audit::AuditEvent>> {
        // Simple implementation - in production, this would be more efficient
        let all_keys = self.list_kv_keys("audit_event_").await?;
        let mut events = Vec::new();

        for key in all_keys {
            if let Some(data) = self.get_kv(&key).await?
                && let Ok(event) = serde_json::from_slice::<crate::audit::AuditEvent>(&data)
            {
                // Apply filters
                let mut include = true;

                if let Some(ref time_range) = query.time_range
                    && (event.timestamp < time_range.start || event.timestamp > time_range.end)
                {
                    include = false;
                }

                if let Some(ref event_types) = query.event_types
                    && !event_types.contains(&event.event_type)
                {
                    include = false;
                }

                if let Some(ref user_id) = query.user_id
                    && event.user_id.as_ref() != Some(user_id)
                {
                    include = false;
                }

                if include {
                    events.push(event);
                }
            }
        }

        // Sort and limit
        events.sort_by(|a, b| match query.sort_order {
            crate::audit::SortOrder::TimestampAsc => a.timestamp.cmp(&b.timestamp),
            crate::audit::SortOrder::TimestampDesc => b.timestamp.cmp(&a.timestamp),
            crate::audit::SortOrder::RiskLevelDesc => b.risk_level.cmp(&a.risk_level),
        });

        if let Some(limit) = query.limit {
            events.truncate(limit as usize);
        }
        Ok(events)
    }

    async fn get_event(&self, event_id: &str) -> Result<Option<crate::audit::AuditEvent>> {
        let key = format!("audit_event_{}", event_id);
        if let Some(data) = self.get_kv(&key).await? {
            let event = serde_json::from_slice(&data).map_err(|e| {
                crate::errors::AuthError::internal(format!(
                    "Failed to deserialize audit event: {}",
                    e
                ))
            })?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    async fn count_events(&self, query: &crate::audit::AuditQuery) -> Result<u64> {
        let events = self.query_events(query).await?;
        Ok(events.len() as u64)
    }

    async fn delete_old_events(&self, before: std::time::SystemTime) -> Result<u64> {
        let all_keys = self.list_kv_keys("audit_event_").await?;
        let mut deleted_count = 0;

        for key in all_keys {
            if let Some(data) = self.get_kv(&key).await?
                && let Ok(event) = serde_json::from_slice::<crate::audit::AuditEvent>(&data)
                && event.timestamp < before
            {
                self.delete_kv(&key).await?;
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    async fn get_statistics(
        &self,
        query: &crate::audit::StatsQuery,
    ) -> Result<crate::audit::AuditStatistics> {
        use std::collections::HashMap;

        // Pull all events matching the time range in the query.
        let audit_query = crate::audit::AuditQuery::builder()
            .time_range(query.time_range.start, query.time_range.end)
            .sort_order(crate::audit::SortOrder::TimestampAsc)
            .build();
        let events = self.query_events(&audit_query).await?;
        let total_events = events.len() as u64;

        let mut event_type_counts: HashMap<String, u64> = HashMap::new();
        let mut risk_level_counts: HashMap<String, u64> = HashMap::new();
        let mut outcome_counts: HashMap<String, u64> = HashMap::new();

        for event in &events {
            *event_type_counts
                .entry(format!("{:?}", event.event_type))
                .or_insert(0) += 1;
            *risk_level_counts
                .entry(format!("{:?}", event.risk_level))
                .or_insert(0) += 1;
            *outcome_counts
                .entry(format!("{:?}", event.outcome))
                .or_insert(0) += 1;
        }

        Ok(crate::audit::AuditStatistics {
            total_events,
            event_type_counts,
            risk_level_counts,
            outcome_counts,
            time_series: Vec::new(),
            top_users: Vec::new(),
            top_ips: Vec::new(),
        })
    }
}

impl MemoryStorage {
    /// Helper method to list KV keys with a prefix
    async fn list_kv_keys(&self, _prefix: &str) -> Result<Vec<String>> {
        Ok(self.inner.list_kv_keys_by_prefix(_prefix))
    }
}

/// Implementation of AuditStorage for `Arc<MemoryStorage>`
#[async_trait]
impl crate::audit::AuditStorage for Arc<MemoryStorage> {
    async fn store_event(&self, event: &crate::audit::AuditEvent) -> Result<()> {
        self.as_ref().store_event(event).await
    }

    async fn query_events(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<Vec<crate::audit::AuditEvent>> {
        self.as_ref().query_events(query).await
    }

    async fn get_event(&self, event_id: &str) -> Result<Option<crate::audit::AuditEvent>> {
        self.as_ref().get_event(event_id).await
    }

    async fn count_events(&self, query: &crate::audit::AuditQuery) -> Result<u64> {
        self.as_ref().count_events(query).await
    }

    async fn delete_old_events(&self, before: std::time::SystemTime) -> Result<u64> {
        self.as_ref().delete_old_events(before).await
    }

    async fn get_statistics(
        &self,
        query: &crate::audit::StatsQuery,
    ) -> Result<crate::audit::AuditStatistics> {
        self.as_ref().get_statistics(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::AuthToken;

    // ── Token CRUD ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryStorage::new();

        let token = AuthToken::new("user123", "token123", Duration::from_secs(3600), "test");

        storage.store_token(&token).await.unwrap();

        let retrieved = storage.get_token(&token.token_id).await.unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user123");

        let retrieved = storage
            .get_token_by_access_token(&token.access_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.token_id, token.token_id);

        let user_tokens = storage.list_user_tokens("user123").await.unwrap();
        assert_eq!(user_tokens.len(), 1);

        storage.delete_token(&token.token_id).await.unwrap();
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_token_update() {
        let storage = MemoryStorage::new();
        let mut token = AuthToken::new("user1", "access_original", Duration::from_secs(3600), "pw");
        storage.store_token(&token).await.unwrap();

        token.auth_method = "mfa".to_string();
        storage.update_token(&token).await.unwrap();

        let retrieved = storage.get_token(&token.token_id).await.unwrap().unwrap();
        assert_eq!(retrieved.auth_method, "mfa");
    }

    #[tokio::test]
    async fn test_token_get_nonexistent() {
        let storage = MemoryStorage::new();
        let result = storage.get_token("nonexistent").await.unwrap();
        assert!(result.is_none());

        let result = storage
            .get_token_by_access_token("nonexistent")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_user_tokens_multiple() {
        let storage = MemoryStorage::new();
        let t1 = AuthToken::new("user_a", "at1", Duration::from_secs(3600), "pw");
        let t2 = AuthToken::new("user_a", "at2", Duration::from_secs(3600), "pw");
        let t3 = AuthToken::new("user_b", "at3", Duration::from_secs(3600), "pw");

        storage.store_token(&t1).await.unwrap();
        storage.store_token(&t2).await.unwrap();
        storage.store_token(&t3).await.unwrap();

        let user_a_tokens = storage.list_user_tokens("user_a").await.unwrap();
        assert_eq!(user_a_tokens.len(), 2);

        let user_b_tokens = storage.list_user_tokens("user_b").await.unwrap();
        assert_eq!(user_b_tokens.len(), 1);

        let empty = storage.list_user_tokens("nobody").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn test_store_tokens_bulk() {
        let storage = MemoryStorage::new();
        let tokens = vec![
            AuthToken::new("u1", "a1", Duration::from_secs(3600), "pw"),
            AuthToken::new("u2", "a2", Duration::from_secs(3600), "pw"),
            AuthToken::new("u3", "a3", Duration::from_secs(3600), "pw"),
        ];
        let ids: Vec<String> = tokens.iter().map(|t| t.token_id.clone()).collect();

        storage.store_tokens_bulk(&tokens).await.unwrap();

        for id in &ids {
            assert!(storage.get_token(id).await.unwrap().is_some());
        }

        storage.delete_tokens_bulk(&ids).await.unwrap();

        for id in &ids {
            assert!(storage.get_token(id).await.unwrap().is_none());
        }
    }

    // ── Session CRUD ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_session_storage() {
        let storage = MemoryStorage::new();

        let session = SessionData::new("session123", "user123", Duration::from_secs(3600))
            .with_metadata(
                Some("192.168.1.1".to_string()),
                Some("Test Agent".to_string()),
            );

        storage
            .store_session(&session.session_id, &session)
            .await
            .unwrap();

        let retrieved = storage
            .get_session(&session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.user_id, "user123");
        assert_eq!(retrieved.ip_address, Some("192.168.1.1".to_string()));

        storage.delete_session(&session.session_id).await.unwrap();
        let retrieved = storage.get_session(&session.session_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_session_get_nonexistent() {
        let storage = MemoryStorage::new();
        let result = storage.get_session("no_such_session").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_user_sessions() {
        let storage = MemoryStorage::new();

        let s1 = SessionData::new("s1", "alice", Duration::from_secs(3600));
        let s2 = SessionData::new("s2", "alice", Duration::from_secs(3600));
        let s3 = SessionData::new("s3", "bob", Duration::from_secs(3600));

        storage.store_session("s1", &s1).await.unwrap();
        storage.store_session("s2", &s2).await.unwrap();
        storage.store_session("s3", &s3).await.unwrap();

        let alice_sessions = storage.list_user_sessions("alice").await.unwrap();
        assert_eq!(alice_sessions.len(), 2);

        let bob_sessions = storage.list_user_sessions("bob").await.unwrap();
        assert_eq!(bob_sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_count_active_sessions() {
        let storage = MemoryStorage::new();

        let s1 = SessionData::new("cs1", "u1", Duration::from_secs(3600));
        let s2 = SessionData::new("cs2", "u2", Duration::from_secs(3600));
        storage.store_session("cs1", &s1).await.unwrap();
        storage.store_session("cs2", &s2).await.unwrap();

        let count = storage.count_active_sessions().await.unwrap();
        assert!(count >= 2);
    }

    #[tokio::test]
    async fn test_store_sessions_bulk() {
        let storage = MemoryStorage::new();
        let sessions = vec![
            (
                "bs1".to_string(),
                SessionData::new("bs1", "u1", Duration::from_secs(3600)),
            ),
            (
                "bs2".to_string(),
                SessionData::new("bs2", "u2", Duration::from_secs(3600)),
            ),
        ];

        storage.store_sessions_bulk(&sessions).await.unwrap();
        assert!(storage.get_session("bs1").await.unwrap().is_some());
        assert!(storage.get_session("bs2").await.unwrap().is_some());

        let ids = vec!["bs1".to_string(), "bs2".to_string()];
        storage.delete_sessions_bulk(&ids).await.unwrap();
        assert!(storage.get_session("bs1").await.unwrap().is_none());
        assert!(storage.get_session("bs2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_session_custom_data() {
        let storage = MemoryStorage::new();
        let mut session = SessionData::new("sd1", "u1", Duration::from_secs(3600));
        session.set_data("theme", serde_json::json!("dark"));
        session.set_data("lang", serde_json::json!("en"));

        storage.store_session("sd1", &session).await.unwrap();

        let retrieved = storage.get_session("sd1").await.unwrap().unwrap();
        assert_eq!(
            retrieved.get_data("theme"),
            Some(&serde_json::json!("dark"))
        );
        assert_eq!(retrieved.get_data("lang"), Some(&serde_json::json!("en")));
        assert_eq!(retrieved.get_data("missing"), None);
    }

    // ── KV Storage ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_kv_storage() {
        let storage = MemoryStorage::new();

        let key = "test_key";
        let value = b"test_value";

        storage
            .store_kv(key, value, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let retrieved = storage.get_kv(key).await.unwrap().unwrap();
        assert_eq!(retrieved, value);

        storage.delete_kv(key).await.unwrap();
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_kv_no_ttl() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("persistent", b"forever", None)
            .await
            .unwrap();

        let retrieved = storage.get_kv("persistent").await.unwrap().unwrap();
        assert_eq!(retrieved, b"forever");
    }

    #[tokio::test]
    async fn test_kv_overwrite() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("k1", b"v1", Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        storage
            .store_kv("k1", b"v2", Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let retrieved = storage.get_kv("k1").await.unwrap().unwrap();
        assert_eq!(retrieved, b"v2");
    }

    #[tokio::test]
    async fn test_kv_get_nonexistent() {
        let storage = MemoryStorage::new();
        let result = storage.get_kv("no_such_key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_kv_list_keys_prefix() {
        let storage = MemoryStorage::new();
        storage
            .store_kv("user:1:name", b"alice", None)
            .await
            .unwrap();
        storage
            .store_kv("user:1:email", b"alice@x.com", None)
            .await
            .unwrap();
        storage.store_kv("user:2:name", b"bob", None).await.unwrap();
        storage
            .store_kv("session:abc", b"data", None)
            .await
            .unwrap();

        let user1_keys = storage.list_kv_keys("user:1:").await.unwrap();
        assert_eq!(user1_keys.len(), 2);

        let all_user_keys = storage.list_kv_keys("user:").await.unwrap();
        assert_eq!(all_user_keys.len(), 3);

        let session_keys = storage.list_kv_keys("session:").await.unwrap();
        assert_eq!(session_keys.len(), 1);

        let empty = storage.list_kv_keys("nonexistent:").await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn test_kv_binary_data() {
        let storage = MemoryStorage::new();
        let binary = vec![0u8, 1, 2, 255, 254, 253, 0, 128];
        storage.store_kv("binary_key", &binary, None).await.unwrap();

        let retrieved = storage.get_kv("binary_key").await.unwrap().unwrap();
        assert_eq!(retrieved, binary);
    }

    // ── Cleanup ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cleanup_expired() {
        let storage = MemoryStorage::new();

        // Store a KV entry with a very short TTL (already expired by the time
        // cleanup runs because DashMap wraps its own expiry clock).
        // Note: MemoryStorage cleanup uses TimestampedToken's own expires_at
        // (derived from default_ttl), NOT AuthToken.expires_at. We test KV
        // cleanup because it respects TTLs directly.
        storage
            .store_kv("expire_me", b"val", Some(Duration::from_secs(0)))
            .await
            .unwrap();
        storage
            .store_kv("keep_me", b"val", Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        // Give a tiny window for the zero-TTL entry to register as expired
        tokio::time::sleep(Duration::from_millis(10)).await;

        storage.cleanup_expired().await.unwrap();

        // Zero-TTL entry should be cleaned up, valid entry remains
        assert!(storage.get_kv("expire_me").await.unwrap().is_none());
        assert!(storage.get_kv("keep_me").await.unwrap().is_some());
    }

    // ── Session expiration ──────────────────────────────────────────

    #[tokio::test]
    async fn test_session_is_expired() {
        let mut session = SessionData::new("exp1", "u1", Duration::from_secs(3600));
        assert!(!session.is_expired());

        session.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert!(session.is_expired());
    }

    #[tokio::test]
    async fn test_session_update_activity() {
        let mut session = SessionData::new("act1", "u1", Duration::from_secs(3600));
        let first_activity = session.last_activity;
        // Small delay to ensure timestamp changes
        session.update_activity();
        assert!(session.last_activity >= first_activity);
    }

    // ── Token upsert semantics ──────────────────────────────────────

    #[tokio::test]
    async fn test_token_store_twice_overwrites_primary() {
        let storage = MemoryStorage::new();
        let token = AuthToken::new("u1", "at1", Duration::from_secs(3600), "pw");
        let token_id = token.token_id.clone();

        storage.store_token(&token).await.unwrap();
        storage.store_token(&token).await.unwrap();

        // Primary DashMap uses insert() so only one entry with this token_id exists.
        let got = storage.get_token(&token_id).await.unwrap();
        assert!(got.is_some());
    }

    // ── Delete idempotency ──────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_nonexistent_token() {
        let storage = MemoryStorage::new();
        // Deleting a key that doesn't exist should not error
        let result = storage.delete_token("nope").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_session() {
        let storage = MemoryStorage::new();
        let result = storage.delete_session("nope").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_kv() {
        let storage = MemoryStorage::new();
        let result = storage.delete_kv("nope").await;
        assert!(result.is_ok());
    }
}
