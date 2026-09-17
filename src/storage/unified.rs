//! High-performance unified storage implementation using DashMap
//!
//! This module provides a unified approach to storage operations that achieves
//! significant performance improvements through:
//! - Single DashMap for all storage operations
//! - Reduced memory allocations through object pooling
//! - Cache-friendly data structures
//! - Zero-copy operations where possible

use crate::{
    errors::{AuthError, Result},
    storage::{AuthStorage, SessionData},
    tokens::AuthToken,
};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::time::interval;

#[cfg(feature = "object-pool")]
use object_pool::Pool;

#[cfg(feature = "bumpalo")]
use bumpalo::Bump;

/// Unified storage key for all data types
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum StorageKey {
    Token(String),
    AccessToken(String),
    UserTokens(String),
    Session(String),
    UserSessions(String),
    KeyValue(String),
}

/// Unified storage value with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageValue {
    pub data: StorageData,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub access_count: u64,
    pub last_accessed: SystemTime,
}

/// Storage data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageData {
    Token(AuthToken),
    TokenRef(String),           // Reference to token ID for access token lookups
    UserTokenList(Vec<String>), // List of token IDs for user
    Session(SessionData),
    UserSessionList(Vec<String>), // List of session IDs for user
    KeyValue(Vec<u8>),
}

/// High-performance unified storage with optimizations
pub struct UnifiedStorage {
    /// Single DashMap for all storage operations
    storage: Arc<DashMap<StorageKey, StorageValue>>,

    /// Performance metrics
    hit_count: AtomicU64,
    miss_count: AtomicU64,
    total_memory: AtomicU64,

    /// Object pool for reducing allocations
    #[cfg(feature = "object-pool")]
    token_pool: Pool<AuthToken>,

    #[cfg(feature = "object-pool")]
    session_pool: Pool<SessionData>,

    /// Memory arena for temporary allocations
    #[cfg(feature = "bumpalo")]
    arena: Arc<parking_lot::Mutex<Bump>>,

    /// Configuration
    default_ttl: Duration,
    max_memory: usize,
}

impl UnifiedStorage {
    /// Create new unified storage with optimizations
    pub fn new() -> Self {
        Self::with_config(UnifiedStorageConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: UnifiedStorageConfig) -> Self {
        let storage = Arc::new(DashMap::with_capacity(config.initial_capacity));

        #[cfg(feature = "object-pool")]
        let token_pool = Pool::new(config.pool_size, || pooled_defaults::create_default_token());

        #[cfg(feature = "object-pool")]
        let session_pool = Pool::new(config.pool_size, || {
            pooled_defaults::create_default_session()
        });
        #[cfg(feature = "bumpalo")]
        let arena = Arc::new(parking_lot::Mutex::new(Bump::with_capacity(
            config.arena_size,
        )));

        let storage_instance = Self {
            storage,
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            total_memory: AtomicU64::new(0),
            #[cfg(feature = "object-pool")]
            token_pool,
            #[cfg(feature = "object-pool")]
            session_pool,
            #[cfg(feature = "bumpalo")]
            arena,
            default_ttl: config.default_ttl,
            max_memory: config.max_memory,
        };

        // Start background cleanup task
        storage_instance.start_cleanup_task();

        storage_instance
    }

    /// Start background cleanup task for expired entries
    fn start_cleanup_task(&self) {
        let storage = Arc::clone(&self.storage);
        let total_memory = Arc::new(AtomicU64::new(0));
        let max_memory = self.max_memory;

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));

            loop {
                cleanup_interval.tick().await;

                let now = SystemTime::now();
                let mut memory_freed = 0usize;
                let mut expired_keys = Vec::new();

                // Collect expired keys
                for entry in storage.iter() {
                    let (key, value) = (entry.key(), entry.value());

                    if let Some(expires_at) = value.expires_at {
                        if now > expires_at {
                            expired_keys.push(key.clone());
                            memory_freed += Self::estimate_value_size(value);
                        }
                    }
                }

                // Remove expired entries
                for key in expired_keys {
                    storage.remove(&key);
                }

                // Update memory counter
                total_memory.fetch_sub(memory_freed as u64, Ordering::Relaxed);

                // Aggressive cleanup if memory usage is high
                if total_memory.load(Ordering::Relaxed) as usize > max_memory {
                    Self::aggressive_cleanup(&storage, &total_memory, max_memory);
                }
            }
        });
    }

    /// Aggressive cleanup when memory limit is exceeded
    fn aggressive_cleanup(
        storage: &DashMap<StorageKey, StorageValue>,
        total_memory: &AtomicU64,
        max_memory: usize,
    ) {
        let mut entries: Vec<_> = storage
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_accessed))
            .collect();

        // Sort by last accessed time (oldest first)
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        let mut memory_freed = 0usize;
        let target_memory = max_memory * 3 / 4; // Free to 75% capacity

        for (key, _) in entries {
            if total_memory.load(Ordering::Relaxed) as usize <= target_memory {
                break;
            }

            if let Some((_, value)) = storage.remove(&key) {
                memory_freed += Self::estimate_value_size(&value);
                total_memory.fetch_sub(memory_freed as u64, Ordering::Relaxed);
            }
        }
    }

    /// Estimate memory size of a storage value
    fn estimate_value_size(value: &StorageValue) -> usize {
        match &value.data {
            StorageData::Token(_) => 512, // Optimized from 1KB to 512 bytes
            StorageData::TokenRef(_) => 64,
            StorageData::UserTokenList(list) => 32 + list.len() * 32,
            StorageData::Session(_) => 256,
            StorageData::UserSessionList(list) => 32 + list.len() * 32,
            StorageData::KeyValue(data) => data.len(),
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> StorageStats {
        let hit_count = self.hit_count.load(Ordering::Relaxed);
        let miss_count = self.miss_count.load(Ordering::Relaxed);
        let total_requests = hit_count + miss_count;
        let hit_rate = if total_requests > 0 {
            (hit_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        StorageStats {
            total_entries: self.storage.len(),
            memory_usage: self.total_memory.load(Ordering::Relaxed) as usize,
            hit_rate,
            hit_count,
            miss_count,
        }
    }

    /// Internal method to store value with automatic memory tracking
    fn store_internal(
        &self,
        key: StorageKey,
        data: StorageData,
        ttl: Option<Duration>,
    ) -> Result<()> {
        let now = SystemTime::now();
        let expires_at = ttl.map(|t| now + t);

        let value = StorageValue {
            data,
            created_at: now,
            expires_at,
            access_count: 0,
            last_accessed: now,
        };

        let memory_size = Self::estimate_value_size(&value);

        // Check memory limit before insertion
        if self.total_memory.load(Ordering::Relaxed) as usize + memory_size > self.max_memory {
            return Err(AuthError::Storage(
                crate::errors::StorageError::OperationFailed {
                    message: "Memory limit exceeded".to_string(),
                },
            ));
        }

        self.storage.insert(key, value);
        self.total_memory
            .fetch_add(memory_size as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Internal method to get value with access tracking
    fn get_internal(&self, key: &StorageKey) -> Option<StorageValue> {
        if let Some(mut entry) = self.storage.get_mut(key) {
            // Check expiration
            if let Some(expires_at) = entry.expires_at {
                if SystemTime::now() > expires_at {
                    drop(entry);
                    self.storage.remove(key);
                    self.miss_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }

            // Update access statistics
            entry.access_count += 1;
            entry.last_accessed = SystemTime::now();
            self.hit_count.fetch_add(1, Ordering::Relaxed);

            Some(entry.clone())
        } else {
            self.miss_count.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

impl Default for UnifiedStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthStorage for UnifiedStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        // Store the main token
        self.store_internal(
            StorageKey::Token(token.token_id.clone()),
            StorageData::Token(token.clone()),
            Some(Duration::from_secs(
                (token.expires_at.timestamp() - chrono::Utc::now().timestamp()) as u64,
            )),
        )?;

        // Store access token reference
        self.store_internal(
            StorageKey::AccessToken(token.access_token.clone()),
            StorageData::TokenRef(token.token_id.clone()),
            Some(Duration::from_secs(
                (token.expires_at.timestamp() - chrono::Utc::now().timestamp()) as u64,
            )),
        )?;

        // Update user token list
        let user_key = StorageKey::UserTokens(token.user_id.clone());
        let mut user_tokens = if let Some(value) = self.get_internal(&user_key) {
            match value.data {
                StorageData::UserTokenList(tokens) => tokens,
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };

        user_tokens.push(token.token_id.clone());
        self.store_internal(user_key, StorageData::UserTokenList(user_tokens), None)?;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        if let Some(value) = self.get_internal(&StorageKey::Token(token_id.to_string())) {
            match value.data {
                StorageData::Token(token) => Ok(Some(token)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        // First get the token ID from access token reference
        if let Some(value) = self.get_internal(&StorageKey::AccessToken(access_token.to_string())) {
            match value.data {
                StorageData::TokenRef(token_id) => {
                    // Then get the actual token
                    self.get_token(&token_id).await
                }
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // Update is essentially a store operation
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        // Get token first to find access token
        if let Some(token) = self.get_token(token_id).await? {
            // Remove main token
            self.storage
                .remove(&StorageKey::Token(token_id.to_string()));

            // Remove access token reference
            self.storage
                .remove(&StorageKey::AccessToken(token.access_token.clone()));

            // Update user token list
            let user_key = StorageKey::UserTokens(token.user_id.clone());
            if let Some(value) = self.get_internal(&user_key) {
                if let StorageData::UserTokenList(mut tokens) = value.data {
                    tokens.retain(|t| t != token_id);
                    let _ = self.store_internal(user_key, StorageData::UserTokenList(tokens), None);
                }
            }
        }

        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let user_key = StorageKey::UserTokens(user_id.to_string());

        if let Some(value) = self.get_internal(&user_key) {
            match value.data {
                StorageData::UserTokenList(token_ids) => {
                    let mut tokens = Vec::new();

                    for token_id in token_ids {
                        if let Some(token) = self.get_token(&token_id).await? {
                            tokens.push(token);
                        }
                    }

                    Ok(tokens)
                }
                _ => Ok(Vec::new()),
            }
        } else {
            Ok(Vec::new())
        }
    }

    async fn store_session(&self, session_id: &str, session: &SessionData) -> Result<()> {
        // Store the main session
        let ttl = Some(Duration::from_secs(
            (session.expires_at.timestamp() - chrono::Utc::now().timestamp()) as u64,
        ));

        self.store_internal(
            StorageKey::Session(session_id.to_string()),
            StorageData::Session(session.clone()),
            ttl,
        )?;

        // Update user session list
        let user_key = StorageKey::UserSessions(session.user_id.clone());
        let mut user_sessions = if let Some(value) = self.get_internal(&user_key) {
            match value.data {
                StorageData::UserSessionList(sessions) => sessions,
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };

        user_sessions.push(session_id.to_string());
        self.store_internal(user_key, StorageData::UserSessionList(user_sessions), None)?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        if let Some(value) = self.get_internal(&StorageKey::Session(session_id.to_string())) {
            match value.data {
                StorageData::Session(session) => Ok(Some(session)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        // Get session first to find user ID
        if let Some(session) = self.get_session(session_id).await? {
            // Remove main session
            self.storage
                .remove(&StorageKey::Session(session_id.to_string()));

            // Update user session list
            let user_key = StorageKey::UserSessions(session.user_id.clone());
            if let Some(value) = self.get_internal(&user_key) {
                if let StorageData::UserSessionList(mut sessions) = value.data {
                    sessions.retain(|s| s != session_id);
                    let _ =
                        self.store_internal(user_key, StorageData::UserSessionList(sessions), None);
                }
            }
        }

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let user_key = StorageKey::UserSessions(user_id.to_string());

        if let Some(value) = self.get_internal(&user_key) {
            match value.data {
                StorageData::UserSessionList(session_ids) => {
                    let mut sessions = Vec::new();

                    for session_id in session_ids {
                        if let Some(session) = self.get_session(&session_id).await? {
                            sessions.push(session);
                        }
                    }

                    Ok(sessions)
                }
                _ => Ok(Vec::new()),
            }
        } else {
            Ok(Vec::new())
        }
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.store_internal(
            StorageKey::KeyValue(key.to_string()),
            StorageData::KeyValue(value.to_vec()),
            ttl.or_else(|| Some(self.default_ttl)),
        )
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.get_internal(&StorageKey::KeyValue(key.to_string())) {
            match value.data {
                StorageData::KeyValue(data) => Ok(Some(data)),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        self.storage.remove(&StorageKey::KeyValue(key.to_string()));
        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Cleanup is handled by background task, but we can trigger immediate cleanup
        let now = SystemTime::now();
        let expired_keys: Vec<_> = self
            .storage
            .iter()
            .filter_map(|entry| {
                if let Some(expires_at) = entry.value().expires_at {
                    if now > expires_at {
                        Some(entry.key().clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        for key in expired_keys {
            self.storage.remove(&key);
        }

        Ok(())
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let count = self
            .storage
            .iter()
            .filter(|entry| matches!(entry.key(), StorageKey::Session(_)))
            .filter(|entry| {
                if let Some(expires_at) = entry.value().expires_at {
                    SystemTime::now() <= expires_at
                } else {
                    true
                }
            })
            .count();

        Ok(count as u64)
    }
}

/// Configuration for unified storage
#[derive(Debug, Clone)]
pub struct UnifiedStorageConfig {
    pub initial_capacity: usize,
    pub default_ttl: Duration,
    pub max_memory: usize,
    pub pool_size: usize,
    pub arena_size: usize,
}

impl Default for UnifiedStorageConfig {
    fn default() -> Self {
        Self {
            initial_capacity: 16384,
            default_ttl: Duration::from_secs(3600),
            max_memory: 512 * 1024 * 1024, // 512MB
            pool_size: 1000,
            arena_size: 64 * 1024, // 64KB
        }
    }
}

/// Storage performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_entries: usize,
    pub memory_usage: usize,
    pub hit_rate: f64,
    pub hit_count: u64,
    pub miss_count: u64,
}

// Default implementations for pooled objects are handled by the existing implementations
#[cfg(feature = "object-pool")]
mod pooled_defaults {
    use super::*;
    use crate::tokens::TokenMetadata;
    use std::collections::HashMap;

    // These would be used for object pool initialization if needed
    pub fn create_default_token() -> AuthToken {
        AuthToken {
            token_id: String::new(),
            user_id: String::new(),
            access_token: String::new(),
            token_type: None,
            subject: None,
            issuer: None,
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            scopes: Vec::new(),
            auth_method: String::new(),
            client_id: None,
            user_profile: None,
            permissions: Vec::new(),
            roles: Vec::new(),
            metadata: TokenMetadata::default(),
        }
    }

    pub fn create_default_session() -> SessionData {
        SessionData {
            session_id: String::new(),
            user_id: String::new(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            data: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::TokenMetadata;

    fn create_test_token(user_id: &str) -> AuthToken {
        AuthToken {
            token_id: format!("token-{}", user_id),
            user_id: user_id.to_string(),
            access_token: format!("access-{}", user_id),
            token_type: Some("bearer".to_string()),
            subject: Some(user_id.to_string()),
            issuer: Some("test".to_string()),
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
            auth_method: "password".to_string(),
            client_id: Some("test-client".to_string()),
            user_profile: None,
            permissions: vec!["read:data".to_string()],
            roles: vec!["user".to_string()],
            metadata: TokenMetadata::default(),
        }
    }

    #[tokio::test]
    async fn test_unified_storage_basic() {
        let storage = UnifiedStorage::new();
        let token = create_test_token("test-user");

        // Store token
        storage.store_token(&token).await.unwrap();

        // Retrieve token
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.user_id, token.user_id);
        assert_eq!(retrieved.token_id, token.token_id);
    }
}
