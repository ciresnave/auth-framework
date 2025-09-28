# Custom Storage Backend Implementation Guide

This guide shows you how to create a custom storage backend for AuthFramework, using SurrealDB as an example. This follows the Dependency Inversion Principle (DIP) by depending on the `AuthStorage` abstraction.

## Overview

AuthFramework uses the `AuthStorage` trait to abstract storage operations. Any storage backend that implements this trait can be used with the framework, providing maximum flexibility while maintaining type safety.

## Step 1: Understand the AuthStorage Trait

The core trait you must implement:

```rust
#[async_trait]
pub trait AuthStorage: Send + Sync {
    // Token operations
    async fn store_token(&self, token: &AuthToken) -> Result<()>;
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>>;
    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>>;
    async fn update_token(&self, token: &AuthToken) -> Result<()>;
    async fn delete_token(&self, token_id: &str) -> Result<()>;
    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>>;

    // Session operations
    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()>;
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>>;
    async fn delete_session(&self, session_id: &str) -> Result<()>;
    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>>;
    async fn count_active_sessions(&self) -> Result<u64>;

    // Key-value operations
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()>;
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_kv(&self, key: &str) -> Result<()>;
    
    // Cleanup operations
    async fn cleanup_expired(&self) -> Result<()>;

    // Bulk operations (optional with default implementations)
    async fn store_tokens_bulk(&self, tokens: &[AuthToken]) -> Result<()> {
        for token in tokens {
            self.store_token(token).await?;
        }
        Ok(())
    }

    async fn delete_tokens_bulk(&self, token_ids: &[String]) -> Result<()> {
        for token_id in token_ids {
            self.delete_token(token_id).await?;
        }
        Ok(())
    }

    async fn store_sessions_bulk(&self, sessions: &[(String, SessionData)]) -> Result<()> {
        for (session_id, data) in sessions {
            self.store_session(session_id, data).await?;
        }
        Ok(())
    }

    async fn delete_sessions_bulk(&self, session_ids: &[String]) -> Result<()> {
        for session_id in session_ids {
            self.delete_session(session_id).await?;
        }
        Ok(())
    }
}
```

## Step 2: Create Your Storage Implementation

Here's a complete SurrealDB implementation example:

```rust
use auth_framework::{
    errors::{AuthError, Result},
    storage::{AuthStorage, SessionData},
    tokens::AuthToken,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use surrealdb::{Surreal, engine::remote::ws::{Client, Ws}};

/// SurrealDB storage backend for AuthFramework
#[derive(Clone)]
pub struct SurrealStorage {
    db: Surreal<Client>,
    namespace: String,
    database: String,
}

/// Configuration for SurrealDB storage
#[derive(Debug, Clone)]
pub struct SurrealConfig {
    pub url: String,
    pub namespace: String,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for SurrealConfig {
    fn default() -> Self {
        Self {
            url: "ws://localhost:8000".to_string(),
            namespace: "authframework".to_string(),
            database: "auth".to_string(),
            username: None,
            password: None,
        }
    }
}

// Internal data structures for SurrealDB
#[derive(Debug, Serialize, Deserialize)]
struct TokenRecord {
    id: String,
    user_id: String,
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_at: i64,
    created_at: i64,
    scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionRecord {
    id: String,
    user_id: String,
    data: serde_json::Value,
    created_at: i64,
    last_accessed: i64,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KvRecord {
    id: String,
    value: Vec<u8>,
    expires_at: Option<i64>,
    created_at: i64,
}

impl SurrealStorage {
    /// Create a new SurrealDB storage instance
    pub async fn new(config: SurrealConfig) -> Result<Self> {
        // Connect to SurrealDB
        let db = Surreal::new::<Ws>(&config.url)
            .await
            .map_err(|e| AuthError::internal(format!("SurrealDB connection failed: {}", e)))?;

        // Authenticate if credentials provided
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            db.signin(surrealdb::opt::auth::Root {
                username,
                password,
            })
            .await
            .map_err(|e| AuthError::internal(format!("SurrealDB auth failed: {}", e)))?;
        }

        // Use namespace and database
        db.use_ns(&config.namespace)
            .use_db(&config.database)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to use namespace/database: {}", e)))?;

        let storage = Self {
            db,
            namespace: config.namespace,
            database: config.database,
        };

        // Initialize schema
        storage.initialize_schema().await?;

        Ok(storage)
    }

    /// Convenience constructor with default configuration
    pub async fn connect(url: &str) -> Result<Self> {
        let config = SurrealConfig {
            url: url.to_string(),
            ..Default::default()
        };
        Self::new(config).await
    }

    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<()> {
        // Define tables and indexes
        let schema_queries = vec![
            // Tokens table
            "DEFINE TABLE tokens SCHEMAFULL;",
            "DEFINE FIELD user_id ON TABLE tokens TYPE string;",
            "DEFINE FIELD access_token ON TABLE tokens TYPE string;",
            "DEFINE FIELD refresh_token ON TABLE tokens TYPE option<string>;",
            "DEFINE FIELD token_type ON TABLE tokens TYPE string;",
            "DEFINE FIELD expires_at ON TABLE tokens TYPE int;",
            "DEFINE FIELD created_at ON TABLE tokens TYPE int;",
            "DEFINE FIELD scopes ON TABLE tokens TYPE array<string>;",
            "DEFINE INDEX idx_tokens_access_token ON TABLE tokens COLUMNS access_token UNIQUE;",
            "DEFINE INDEX idx_tokens_user_id ON TABLE tokens COLUMNS user_id;",
            "DEFINE INDEX idx_tokens_expires_at ON TABLE tokens COLUMNS expires_at;",

            // Sessions table
            "DEFINE TABLE sessions SCHEMAFULL;",
            "DEFINE FIELD user_id ON TABLE sessions TYPE string;",
            "DEFINE FIELD data ON TABLE sessions TYPE object;",
            "DEFINE FIELD created_at ON TABLE sessions TYPE int;",
            "DEFINE FIELD last_accessed ON TABLE sessions TYPE int;",
            "DEFINE FIELD expires_at ON TABLE sessions TYPE option<int>;",
            "DEFINE INDEX idx_sessions_user_id ON TABLE sessions COLUMNS user_id;",
            "DEFINE INDEX idx_sessions_expires_at ON TABLE sessions COLUMNS expires_at;",

            // Key-value table
            "DEFINE TABLE kv SCHEMAFULL;",
            "DEFINE FIELD value ON TABLE kv TYPE bytes;",
            "DEFINE FIELD expires_at ON TABLE kv TYPE option<int>;",
            "DEFINE FIELD created_at ON TABLE kv TYPE int;",
            "DEFINE INDEX idx_kv_expires_at ON TABLE kv COLUMNS expires_at;",
        ];

        for query in schema_queries {
            self.db
                .query(query)
                .await
                .map_err(|e| AuthError::internal(format!("Schema creation failed: {}", e)))?;
        }

        Ok(())
    }

    /// Convert AuthToken to TokenRecord
    fn token_to_record(token: &AuthToken) -> TokenRecord {
        TokenRecord {
            id: format!("tokens:{}", token.token_id),
            user_id: token.user_id.clone(),
            access_token: token.access_token.clone(),
            refresh_token: token.refresh_token.clone(),
            token_type: token.token_type.clone(),
            expires_at: token.expires_at.timestamp(),
            created_at: token.created_at.timestamp(),
            scopes: token.scopes.clone(),
        }
    }

    /// Convert TokenRecord to AuthToken
    fn record_to_token(record: TokenRecord) -> Result<AuthToken> {
        use chrono::{DateTime, Utc};

        Ok(AuthToken {
            token_id: record.id.strip_prefix("tokens:").unwrap_or(&record.id).to_string(),
            user_id: record.user_id,
            access_token: record.access_token,
            refresh_token: record.refresh_token,
            token_type: record.token_type,
            expires_at: DateTime::from_timestamp(record.expires_at, 0)
                .ok_or_else(|| AuthError::internal("Invalid expires_at timestamp".to_string()))?,
            created_at: DateTime::from_timestamp(record.created_at, 0)
                .ok_or_else(|| AuthError::internal("Invalid created_at timestamp".to_string()))?,
            scopes: record.scopes,
        })
    }

    /// Get current timestamp
    fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

#[async_trait]
impl AuthStorage for SurrealStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let record = Self::token_to_record(token);
        
        self.db
            .create(("tokens", &token.token_id))
            .content(record)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to store token: {}", e)))?;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        let record: Option<TokenRecord> = self.db
            .select(("tokens", token_id))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to get token: {}", e)))?;

        match record {
            Some(record) => {
                // Check if token is expired
                let now = Self::current_timestamp();
                if record.expires_at <= now {
                    // Token is expired, delete it and return None
                    let _ = self.delete_token(token_id).await;
                    return Ok(None);
                }
                Ok(Some(Self::record_to_token(record)?))
            }
            None => Ok(None),
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        let mut response = self.db
            .query("SELECT * FROM tokens WHERE access_token = $access_token LIMIT 1")
            .bind(("access_token", access_token))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to query token: {}", e)))?;

        let records: Vec<TokenRecord> = response
            .take(0)
            .map_err(|e| AuthError::internal(format!("Failed to parse query result: {}", e)))?;

        match records.into_iter().next() {
            Some(record) => {
                // Check if token is expired
                let now = Self::current_timestamp();
                if record.expires_at <= now {
                    // Token is expired, delete it and return None
                    let token_id = record.id.strip_prefix("tokens:").unwrap_or(&record.id);
                    let _ = self.delete_token(token_id).await;
                    return Ok(None);
                }
                Ok(Some(Self::record_to_token(record)?))
            }
            None => Ok(None),
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        let record = Self::token_to_record(token);
        
        self.db
            .update(("tokens", &token.token_id))
            .content(record)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to update token: {}", e)))?;

        Ok(())
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        self.db
            .delete(("tokens", token_id))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to delete token: {}", e)))?;

        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        let mut response = self.db
            .query("SELECT * FROM tokens WHERE user_id = $user_id AND expires_at > $now")
            .bind(("user_id", user_id))
            .bind(("now", Self::current_timestamp()))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to list user tokens: {}", e)))?;

        let records: Vec<TokenRecord> = response
            .take(0)
            .map_err(|e| AuthError::internal(format!("Failed to parse query result: {}", e)))?;

        records
            .into_iter()
            .map(Self::record_to_token)
            .collect()
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let record = SessionRecord {
            id: format!("sessions:{}", session_id),
            user_id: data.user_id.clone(),
            data: data.data.clone(),
            created_at: data.created_at.timestamp(),
            last_accessed: data.last_accessed.timestamp(),
            expires_at: None, // SurrealDB doesn't have built-in TTL, manage manually
        };

        self.db
            .create(("sessions", session_id))
            .content(record)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to store session: {}", e)))?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        let record: Option<SessionRecord> = self.db
            .select(("sessions", session_id))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to get session: {}", e)))?;

        match record {
            Some(record) => {
                use chrono::{DateTime, Utc};
                
                Ok(Some(SessionData {
                    user_id: record.user_id,
                    data: record.data,
                    created_at: DateTime::from_timestamp(record.created_at, 0)
                        .ok_or_else(|| AuthError::internal("Invalid created_at timestamp".to_string()))?,
                    last_accessed: DateTime::from_timestamp(record.last_accessed, 0)
                        .ok_or_else(|| AuthError::internal("Invalid last_accessed timestamp".to_string()))?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.db
            .delete(("sessions", session_id))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to delete session: {}", e)))?;

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let mut response = self.db
            .query("SELECT * FROM sessions WHERE user_id = $user_id")
            .bind(("user_id", user_id))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to list user sessions: {}", e)))?;

        let records: Vec<SessionRecord> = response
            .take(0)
            .map_err(|e| AuthError::internal(format!("Failed to parse query result: {}", e)))?;

        let mut sessions = Vec::new();
        for record in records {
            use chrono::{DateTime, Utc};
            
            sessions.push(SessionData {
                user_id: record.user_id,
                data: record.data,
                created_at: DateTime::from_timestamp(record.created_at, 0)
                    .ok_or_else(|| AuthError::internal("Invalid created_at timestamp".to_string()))?,
                last_accessed: DateTime::from_timestamp(record.last_accessed, 0)
                    .ok_or_else(|| AuthError::internal("Invalid last_accessed timestamp".to_string()))?,
            });
        }

        Ok(sessions)
    }

    async fn count_active_sessions(&self) -> Result<u64> {
        let mut response = self.db
            .query("SELECT count() FROM sessions WHERE expires_at IS NONE OR expires_at > $now")
            .bind(("now", Self::current_timestamp()))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to count active sessions: {}", e)))?;

        let count: Option<u64> = response
            .take(0)
            .map_err(|e| AuthError::internal(format!("Failed to parse count result: {}", e)))?;

        Ok(count.unwrap_or(0))
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let expires_at = ttl.map(|duration| {
            Self::current_timestamp() + duration.as_secs() as i64
        });

        let record = KvRecord {
            id: format!("kv:{}", key),
            value: value.to_vec(),
            expires_at,
            created_at: Self::current_timestamp(),
        };

        self.db
            .create(("kv", key))
            .content(record)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to store key-value: {}", e)))?;

        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let record: Option<KvRecord> = self.db
            .select(("kv", key))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to get key-value: {}", e)))?;

        match record {
            Some(record) => {
                // Check if expired
                if let Some(expires_at) = record.expires_at {
                    let now = Self::current_timestamp();
                    if expires_at <= now {
                        // Expired, delete and return None
                        let _ = self.delete_kv(key).await;
                        return Ok(None);
                    }
                }
                Ok(Some(record.value))
            }
            None => Ok(None),
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        self.db
            .delete(("kv", key))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to delete key-value: {}", e)))?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        let now = Self::current_timestamp();

        // Clean up expired tokens
        let _ = self.db
            .query("DELETE FROM tokens WHERE expires_at <= $now")
            .bind(("now", now))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to cleanup expired tokens: {}", e)))?;

        // Clean up expired key-value pairs
        let _ = self.db
            .query("DELETE FROM kv WHERE expires_at IS NOT NONE AND expires_at <= $now")
            .bind(("now", now))
            .await
            .map_err(|e| AuthError::internal(format!("Failed to cleanup expired kv: {}", e)))?;

        Ok(())
    }
}
```

## Step 3: Add Feature Gating (Recommended)

Add to your `Cargo.toml`:

```toml
[features]
default = []
surrealdb-storage = ["surrealdb", "serde_json"]

[dependencies]
surrealdb = { version = "1.0", optional = true }
serde_json = { version = "1.0", optional = true }
auth-framework = "0.4.2"
async-trait = "0.1"
serde = { version = "1.0", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1.0", features = ["full"] }
```

Gate your implementation:

```rust
#[cfg(feature = "surrealdb-storage")]
pub mod surrealdb;

#[cfg(feature = "surrealdb-storage")]
pub use surrealdb::SurrealStorage;
```

## Step 4: Error Handling Best Practices

Implement proper error conversion:

```rust
impl From<surrealdb::Error> for auth_framework::errors::AuthError {
    fn from(err: surrealdb::Error) -> Self {
        auth_framework::errors::AuthError::internal(format!(
            "SurrealDB error: {}", err
        ))
    }
}
```

## Step 5: Testing Your Implementation

Create comprehensive tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use auth_framework::testing::helpers;
    use std::sync::Arc;

    async fn setup_test_storage() -> Arc<SurrealStorage> {
        let config = SurrealConfig {
            url: "memory".to_string(), // Use in-memory for tests
            ..Default::default()
        };
        Arc::new(SurrealStorage::new(config).await.expect("Failed to create test storage"))
    }

    #[tokio::test]
    async fn test_token_operations() {
        let storage = setup_test_storage().await;
        
        // Create a test token
        let token = helpers::create_test_token("user123", "test-token");
        
        // Store token
        storage.store_token(&token).await.unwrap();
        
        // Retrieve token
        let retrieved = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
        
        // Delete token
        storage.delete_token(&token.token_id).await.unwrap();
        
        // Verify deletion
        let deleted = storage.get_token(&token.token_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_session_operations() {
        let storage = setup_test_storage().await;
        
        let session_data = helpers::create_test_session_data("user123");
        let session_id = "test-session-id";
        
        // Store session
        storage.store_session(session_id, &session_data).await.unwrap();
        
        // Retrieve session
        let retrieved = storage.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
        
        // Delete session
        storage.delete_session(session_id).await.unwrap();
        
        // Verify deletion
        let deleted = storage.get_session(session_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_kv_operations() {
        let storage = setup_test_storage().await;
        
        let key = "test-key";
        let value = b"test-value";
        
        // Store key-value
        storage.store_kv(key, value, None).await.unwrap();
        
        // Retrieve value
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), value);
        
        // Delete key
        storage.delete_kv(key).await.unwrap();
        
        // Verify deletion
        let deleted = storage.get_kv(key).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let storage = setup_test_storage().await;
        
        let key = "ttl-key";
        let value = b"ttl-value";
        let short_ttl = Duration::from_millis(100);
        
        // Store with short TTL
        storage.store_kv(key, value, Some(short_ttl)).await.unwrap();
        
        // Should be available immediately
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_some());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired now
        let expired = storage.get_kv(key).await.unwrap();
        assert!(expired.is_none());
    }
}
```

## Step 6: Integration with AuthFramework

Your storage is now ready to use with AuthFramework:

```rust
use auth_framework::{AuthFramework, AuthConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create your custom storage
    let storage = Arc::new(SurrealStorage::connect("ws://localhost:8000").await?);
    
    // Create AuthFramework with your custom storage
    let mut config = AuthConfig::default();
    config.security.secret_key = Some("your-jwt-secret-key-32-chars-min".to_string());
    
    let auth = AuthFramework::builder()
        .customize(|c| {
            c.secret = config.security.secret_key;
            c
        })
        .with_storage()
        .custom(storage)
        .done()
        .build()
        .await?;
    
    // Use the auth framework normally
    // All storage operations will use your SurrealDB backend
    
    Ok(())
}
```

## Best Practices Summary

1. **Follow SOLID Principles**: Your storage implements the `AuthStorage` interface (DIP)
2. **Proper Error Handling**: Convert database errors to `AuthError` types
3. **Feature Gating**: Make your storage optional via Cargo features
4. **Comprehensive Testing**: Test all storage operations thoroughly
5. **Documentation**: Document configuration options and usage
6. **Security**: Handle sensitive data appropriately (tokens, sessions)
7. **Performance**: Use appropriate indexes and queries
8. **Connection Management**: Handle connection pooling and retries

## Next Steps

- Add connection pooling for better performance
- Implement proper logging and metrics
- Add backup and recovery procedures
- Consider implementing read replicas for scaling
- Add migration scripts for schema changes

This implementation provides a solid foundation for integrating any database with AuthFramework while maintaining the framework's security and performance standards.