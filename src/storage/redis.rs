//! Redis storage backend for auth-framework.
//!
//! This module provides a production-ready Redis storage implementation
//! with connection pooling, serialization, and error handling.

use crate::errors::StorageError;
use crate::{
    errors::{AuthError, Result},
    storage::{AuthStorage, SessionData},
    tokens::AuthToken,
};
use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, Client};
use serde_json;
use std::time::Duration;

/// Redis storage backend for authentication data
#[derive(Clone)]
pub struct RedisStorage {
    client: Client,
    key_prefix: String,
    default_ttl: Duration,
}

impl RedisStorage {
    /// Create a new Redis storage backend
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = Client::open(redis_url)
            .map_err(|e| AuthError::Storage(StorageError::connection_failed(e.to_string())))?;
        Ok(Self {
            client,
            key_prefix: "auth:".to_string(),
            default_ttl: Duration::from_secs(3600), // 1 hour
        })
    }

    /// Create Redis storage with custom configuration
    pub async fn with_config(
        redis_url: &str,
        key_prefix: impl Into<String>,
        default_ttl: Duration,
    ) -> Result<Self> {
        let mut storage = Self::new(redis_url).await?;
        storage.key_prefix = key_prefix.into();
        storage.default_ttl = default_ttl;
        Ok(storage)
    }

    fn token_key(&self, token_id: &str) -> String {
        format!("{}token:{}", self.key_prefix, token_id)
    }

    fn access_token_key(&self, access_token: &str) -> String {
        format!("{}access:{}", self.key_prefix, access_token)
    }

    fn user_tokens_key(&self, user_id: &str) -> String {
        format!("{}user:{}:tokens", self.key_prefix, user_id)
    }

    fn session_key(&self, session_id: &str) -> String {
        format!("{}session:{}", self.key_prefix, session_id)
    }

    fn kv_key(&self, key: &str) -> String {
        format!("{}kv:{}", self.key_prefix, key)
    }

    /// Verify connectivity to the Redis server by sending a PING command.
    ///
    /// Returns `Ok(())` on success or an `AuthError::Storage` on failure.
    pub async fn health_check(&self) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| AuthError::Storage(StorageError::connection_failed(e.to_string())))?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err(AuthError::Storage(StorageError::connection_failed(
                format!("unexpected PING response: {pong}"),
            )))
        }
    }

    async fn get_connection(&self) -> Result<MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Storage(StorageError::connection_failed(e.to_string())))
    }
}

#[async_trait]
impl AuthStorage for RedisStorage {
    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // For Redis, update is just an overwrite
        self.store_token(token).await
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let session_key = self.session_key(session_id);
        let session_data = serde_json::to_string(data)
            .map_err(|e| AuthError::Storage(StorageError::serialization(e.to_string())))?;
        let ttl = if data.expires_at > chrono::Utc::now() {
            (data.expires_at - chrono::Utc::now()).num_seconds() as u64
        } else {
            self.default_ttl.as_secs()
        };
        let _: () = conn
            .set_ex(&session_key, &session_data, ttl)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let mut conn = self.get_connection().await?;
        let session_key = self.session_key(session_id);
        let session_data: Option<String> = conn
            .get(&session_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        match session_data {
            Some(data) => {
                let session: SessionData = serde_json::from_str(&data)
                    .map_err(|e| AuthError::Storage(StorageError::serialization(e.to_string())))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let session_key = self.session_key(session_id);
        let _: usize = conn
            .del(&session_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let mut conn = self.get_connection().await?;
        let pattern = format!("{}session:*", self.key_prefix);

        // Use cursor-based SCAN instead of KEYS to avoid blocking Redis (SEC-M3).
        let mut cursor: u64 = 0;
        let mut user_sessions = Vec::new();
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

            for key in keys {
                if let Ok(session_json) = conn.get::<_, String>(&key).await
                    && let Ok(session) = serde_json::from_str::<SessionData>(&session_json)
                    && session.user_id == user_id
                    && !session.is_expired()
                {
                    user_sessions.push(session);
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(user_sessions)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let kv_key = self.kv_key(key);
        // SEC-L5: When no TTL is specified, store without expiration so that
        // configuration data and permanent records don't silently vanish.
        if let Some(duration) = ttl {
            let _: () = conn
                .set_ex(&kv_key, value, duration.as_secs())
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        } else {
            let _: () = conn
                .set(&kv_key, value)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        }
        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.get_connection().await?;
        let kv_key = self.kv_key(key);
        let value: Option<Vec<u8>> = conn
            .get(&kv_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        Ok(value)
    }

    async fn get_kv_ttl(&self, key: &str) -> Result<Option<Duration>> {
        let mut conn = self.get_connection().await?;
        let kv_key = self.kv_key(key);
        // PTTL: -2 = no such key, -1 = no expiry, otherwise milliseconds left.
        let millis: i64 = conn
            .pttl(&kv_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        Ok(u64::try_from(millis)
            .ok()
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis))
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let kv_key = self.kv_key(key);
        let _: usize = conn
            .del(&kv_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Redis handles expiration automatically via TTL
        Ok(())
    }
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let mut conn = self.get_connection().await?;

        // Reject already-expired tokens rather than re-activating them with a
        // fresh TTL (SEC-H1).
        let now = chrono::Utc::now();
        if token.expires_at <= now {
            return Err(AuthError::Storage(StorageError::operation_failed(
                "Cannot store an already-expired token".to_string(),
            )));
        }
        let ttl = (token.expires_at - now).num_seconds() as u64;

        // Serialize token
        let token_data = serde_json::to_string(token)
            .map_err(|e| AuthError::Storage(StorageError::serialization(e.to_string())))?;

        // Store token by ID
        let token_key = self.token_key(&token.token_id);
        let _: () = conn
            .set_ex(&token_key, &token_data, ttl)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        // Store access token lookup
        let access_key = self.access_token_key(&token.access_token);
        let _: () = conn
            .set_ex(&access_key, &token.token_id, ttl)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        // Add to user's token set
        let user_tokens_key = self.user_tokens_key(&token.user_id);
        let _: () = conn
            .sadd(&user_tokens_key, &token.token_id)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        // Set expiration on user tokens set
        let _: bool = conn
            .expire(&user_tokens_key, ttl as i64)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let token_key = self.token_key(token_id);

        let token_data: Option<String> = conn
            .get(&token_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        match token_data {
            Some(data) => {
                let token: AuthToken = serde_json::from_str(&data)
                    .map_err(|e| AuthError::Storage(StorageError::serialization(e.to_string())))?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let access_key = self.access_token_key(access_token);

        let token_id: Option<String> = conn
            .get(&access_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        match token_id {
            Some(id) => self.get_token(&id).await,
            None => Ok(None),
        }
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;

        // Get token to find access token and user ID
        if let Some(token) = self.get_token(token_id).await? {
            let token_key = self.token_key(token_id);
            let access_key = self.access_token_key(&token.access_token);
            let user_tokens_key = self.user_tokens_key(&token.user_id);

            // Delete token
            let _: usize = conn
                .del(&token_key)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

            // Delete access token lookup
            let _: usize = conn
                .del(&access_key)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

            // Remove from user's token set
            let _: usize = conn
                .srem(&user_tokens_key, token_id)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;
        }
        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let mut conn = self.get_connection().await?;
        let user_tokens_key = self.user_tokens_key(user_id);

        let token_ids: Vec<String> = conn
            .smembers(&user_tokens_key)
            .await
            .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

        let mut tokens = Vec::new();
        for token_id in token_ids {
            if let Some(token) = self.get_token(&token_id).await? {
                tokens.push(token);
            }
        }

        Ok(tokens)
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let mut conn = self.get_connection().await?;
        let pattern = format!("{}session:*", self.key_prefix);

        // Use SCAN instead of KEYS to avoid blocking the Redis server
        let mut active_count = 0u64;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(|e| AuthError::Storage(StorageError::operation_failed(e.to_string())))?;

            for key in keys {
                let ttl: i64 = conn.ttl(&key).await.map_err(|e| {
                    AuthError::Storage(StorageError::operation_failed(e.to_string()))
                })?;

                // TTL > 0 means key has expiration and is still active
                // TTL = -1 means key has no expiration (active)
                // TTL = -2 means key doesn't exist (expired)
                if ttl > 0 || ttl == -1 {
                    active_count += 1;
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(active_count)
    }
}
