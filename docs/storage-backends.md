# Storage Backends Guide

This guide covers the various storage backends available in auth-framework and how to configure them for different use cases.

## Overview

Auth-framework supports multiple storage backends to meet different application requirements:

- **In-Memory**: Fast, lightweight, perfect for development and testing
- **Redis**: High-performance, distributed caching with persistence options
- **PostgreSQL**: Robust, ACID-compliant relational database for production

## In-Memory Storage

The in-memory storage backend stores all data in RAM and is ideal for development, testing, and single-instance applications where persistence across restarts is not required.

### Features

- Ultra-fast read/write operations
- Automatic cleanup of expired data
- Configurable TTL and cleanup intervals
- Thread-safe with async support
- Zero external dependencies

### Setup

```rust
use auth_framework::storage::{InMemoryStorage, InMemoryConfig};
use std::time::Duration;

// Basic setup
let storage = InMemoryStorage::new();

// Custom configuration
let storage = InMemoryStorage::with_config(
    Duration::from_secs(300), // cleanup every 5 minutes
    Duration::from_secs(3600), // default TTL of 1 hour
);

// Using builder pattern
let storage = InMemoryConfig::new()
    .with_cleanup_interval(Duration::from_secs(60))
    .with_default_ttl(Duration::from_secs(1800))
    .build();
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `cleanup_interval` | 5 minutes | How often to remove expired data |
| `default_ttl` | 1 hour | Default expiration time for stored data |

### Use Cases

- **Development**: Quick setup without external dependencies
- **Testing**: Isolated test environments with fast cleanup
- **Single-instance apps**: Applications that don't need persistence
- **Caching layer**: Temporary storage with automatic expiration

### Performance

In-memory storage provides the highest performance:

- **Token verification**: ~1,000,000 ops/sec
- **Storage operations**: ~1,000,000 ops/sec
- **Memory usage**: ~1KB per token
- **Latency**: < 0.001ms average

### Example

```rust
use auth_framework::{AuthFramework, InMemoryStorage, config::AuthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = InMemoryStorage::new();
    let config = AuthConfig::default();
    let auth = AuthFramework::new(storage, config).await?;

    // Register and authenticate
    auth.register_user("user123", "password").await?;
    let token = auth.authenticate("user123", "password").await?;

    // Token is stored in memory and will be automatically cleaned up
    println!("Token: {}", token.access_token);

    Ok(())
}
```

## Redis Storage

Redis provides high-performance, distributed storage with optional persistence and is excellent for production applications requiring scalability.

### Features

- High-performance distributed storage
- Connection pooling for scalability
- Automatic failover and cluster support
- Configurable persistence options
- Built-in expiration handling
- Cross-application data sharing

### Setup

First, add the Redis feature to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["redis"] }
```

```rust
use auth_framework::storage::{RedisStorage, RedisConfig};

// Basic setup
let storage = RedisStorage::new("redis://localhost:6379").await?;

// With authentication
let storage = RedisStorage::new("redis://username:password@localhost:6379/0").await?;

// Custom configuration
let config = RedisConfig::new()
    .with_url("redis://localhost:6379")
    .with_pool_size(10)
    .with_timeout(Duration::from_secs(5))
    .with_key_prefix("auth:")
    .with_default_ttl(Duration::from_secs(3600));

let storage = RedisStorage::with_config(config).await?;
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `url` | `redis://localhost:6379` | Redis connection URL |
| `pool_size` | 10 | Maximum connections in pool |
| `timeout` | 5 seconds | Connection timeout |
| `key_prefix` | `auth:` | Prefix for all keys |
| `default_ttl` | 1 hour | Default expiration time |
| `cluster_mode` | false | Enable Redis cluster support |

### Redis Cluster Setup

```rust
use auth_framework::storage::RedisConfig;

let config = RedisConfig::new()
    .with_cluster_urls(vec![
        "redis://node1:6379",
        "redis://node2:6379",
        "redis://node3:6379",
    ])
    .with_cluster_mode(true)
    .with_pool_size(20);

let storage = RedisStorage::with_config(config).await?;
```

### Data Structure

Redis storage uses the following key patterns:

```
auth:token:{token_id} -> AuthToken (JSON)
auth:access:{access_token} -> token_id (String)
auth:user:{user_id}:tokens -> [token_ids] (List)
auth:session:{session_id} -> SessionData (JSON)
auth:kv:{key} -> value (Bytes)
```

### Performance

Redis storage provides excellent performance for distributed applications:

- **Token verification**: ~50,000 ops/sec
- **Storage operations**: ~50,000 ops/sec
- **Network latency**: 1-5ms typical
- **Memory usage**: ~2KB per token (including overhead)

### High Availability Setup

```rust
use auth_framework::storage::{RedisConfig, RedisFailoverConfig};

let failover_config = RedisFailoverConfig {
    master_name: "mymaster".to_string(),
    sentinels: vec![
        "redis://sentinel1:26379",
        "redis://sentinel2:26379",
        "redis://sentinel3:26379",
    ],
    sentinel_password: Some("sentinel_password".to_string()),
};

let config = RedisConfig::new()
    .with_failover(failover_config)
    .with_retry_attempts(3)
    .with_retry_delay(Duration::from_millis(100));

let storage = RedisStorage::with_config(config).await?;
```

### Example with Connection Pooling

```rust
use auth_framework::{AuthFramework, storage::RedisStorage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Redis storage with connection pooling
    let storage = RedisStorage::new("redis://localhost:6379").await?;
    let config = AuthConfig::default();
    let auth = Arc::new(AuthFramework::new(storage, config).await?);

    // Simulate concurrent operations
    let mut handles = vec![];

    for i in 0..100 {
        let auth_clone = auth.clone();
        let handle = tokio::spawn(async move {
            let user_id = format!("user{}", i);
            auth_clone.register_user(&user_id, "password").await.unwrap();
            let token = auth_clone.authenticate(&user_id, "password").await.unwrap();
            println!("User {} authenticated: {}", user_id, token.access_token);
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
```

## PostgreSQL Storage

PostgreSQL provides robust, ACID-compliant storage with advanced features and is the recommended choice for production applications requiring data integrity.

### Features

- ACID transactions ensuring data consistency
- Advanced indexing for fast queries
- Full-text search capabilities
- JSON support for flexible data storage
- Backup and replication support
- Complex queries and analytics

### Setup

Add the PostgreSQL feature to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["postgres"] }
```

```rust
use auth_framework::storage::{PostgresStorage, PostgresConfig};

// Basic setup
let storage = PostgresStorage::new("postgresql://user:password@localhost/auth_db").await?;

// Custom configuration
let config = PostgresConfig::new()
    .with_url("postgresql://user:password@localhost/auth_db")
    .with_pool_size(20)
    .with_timeout(Duration::from_secs(30))
    .with_table_prefix("auth_")
    .with_enable_ssl(true);

let storage = PostgresStorage::with_config(config).await?;
```

### Database Schema

The PostgreSQL storage backend automatically creates the following tables:

```sql
-- Tokens table
CREATE TABLE auth_tokens (
    token_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    access_token VARCHAR(1024) NOT NULL UNIQUE,
    refresh_token VARCHAR(1024),
    token_type VARCHAR(50) NOT NULL DEFAULT 'Bearer',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    permissions JSONB DEFAULT '[]',
    roles JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}'
);

-- Sessions table
CREATE TABLE auth_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Key-value store
CREATE TABLE auth_kv_store (
    key VARCHAR(255) PRIMARY KEY,
    value BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Audit log
CREATE TABLE auth_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    outcome BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Indexes for performance
CREATE INDEX idx_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX idx_tokens_access_token ON auth_tokens(access_token);
CREATE INDEX idx_tokens_expires_at ON auth_tokens(expires_at);
CREATE INDEX idx_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON auth_sessions(expires_at);
CREATE INDEX idx_kv_expires_at ON auth_kv_store(expires_at);
CREATE INDEX idx_audit_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_audit_created_at ON auth_audit_log(created_at);
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `url` | Required | PostgreSQL connection URL |
| `pool_size` | 10 | Maximum connections in pool |
| `timeout` | 30 seconds | Query timeout |
| `table_prefix` | `auth_` | Prefix for table names |
| `enable_ssl` | false | Enable SSL connections |
| `migration_mode` | `auto` | How to handle schema migrations |

### Advanced Configuration

```rust
use auth_framework::storage::{PostgresConfig, PostgresSSLConfig, PostgresMigrationMode};

let ssl_config = PostgresSSLConfig {
    require_ssl: true,
    ca_cert_path: Some("/path/to/ca-cert.pem".to_string()),
    client_cert_path: Some("/path/to/client-cert.pem".to_string()),
    client_key_path: Some("/path/to/client-key.pem".to_string()),
};

let config = PostgresConfig::new()
    .with_url("postgresql://user:password@localhost/auth_db")
    .with_pool_size(50)
    .with_ssl_config(ssl_config)
    .with_migration_mode(PostgresMigrationMode::Strict)
    .with_enable_audit_log(true)
    .with_cleanup_interval(Duration::from_secs(3600)); // Clean expired tokens hourly

let storage = PostgresStorage::with_config(config).await?;
```

### Performance Optimization

```rust
use auth_framework::storage::PostgresOptimization;

let storage = PostgresStorage::new(database_url).await?
    .with_optimization(PostgresOptimization {
        enable_prepared_statements: true,
        connection_pool_size: 50,
        statement_cache_size: 100,
        enable_query_optimization: true,
        batch_size: 1000,
    });
```

### Backup and Maintenance

```rust
use auth_framework::storage::PostgresStorage;

// Create backup
let storage = PostgresStorage::new(database_url).await?;
storage.create_backup("/path/to/backup.sql").await?;

// Clean up expired data
storage.cleanup_expired_tokens().await?;
storage.cleanup_expired_sessions().await?;

// Get storage statistics
let stats = storage.get_statistics().await?;
println!("Total tokens: {}", stats.total_tokens);
println!("Active sessions: {}", stats.active_sessions);
println!("Database size: {} MB", stats.database_size_mb);
```

### Performance

PostgreSQL storage provides robust performance for production applications:

- **Token verification**: ~10,000 ops/sec
- **Storage operations**: ~5,000 ops/sec
- **Query latency**: 1-10ms typical
- **Concurrent connections**: 100+ supported

## Storage Backend Comparison

| Feature | In-Memory | Redis | PostgreSQL |
|---------|-----------|-------|------------|
| **Performance** | Excellent | Very Good | Good |
| **Scalability** | Single instance | Highly scalable | Very scalable |
| **Persistence** | None | Optional | Full |
| **ACID compliance** | N/A | Limited | Full |
| **Setup complexity** | Minimal | Low | Moderate |
| **Memory usage** | High | Moderate | Low |
| **Best for** | Dev/Testing | High-traffic apps | Enterprise apps |

## Choosing the Right Backend

### Use In-Memory When:
- Developing or testing applications
- Building single-instance applications
- Performance is critical and persistence isn't needed
- You want zero external dependencies

### Use Redis When:
- Building distributed applications
- You need high performance with some persistence
- Implementing caching strategies
- Scaling horizontally across multiple instances

### Use PostgreSQL When:
- Building production applications
- Data integrity is critical
- You need complex queries and analytics
- Compliance requires audit trails
- Long-term data retention is important

## Migration Between Backends

```rust
use auth_framework::storage::{StorageMigration, MigrationOptions};

// Migrate from in-memory to PostgreSQL
let source = InMemoryStorage::new();
let target = PostgresStorage::new(database_url).await?;

let migration = StorageMigration::new(source, target)
    .with_batch_size(1000)
    .with_verify_data(true)
    .with_preserve_ttl(true);

migration.migrate_all().await?;

// Migrate specific data types
migration.migrate_tokens().await?;
migration.migrate_sessions().await?;
migration.migrate_kv_data().await?;
```

## Testing with Different Backends

```rust
#[cfg(test)]
mod tests {
    use super::*;

    async fn test_with_storage<S: AuthStorage + Clone>(storage: S) {
        let config = AuthConfig::default();
        let auth = AuthFramework::new(storage, config).await.unwrap();

        // Test operations
        auth.register_user("test", "password").await.unwrap();
        let token = auth.authenticate("test", "password").await.unwrap();
        assert!(!token.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();
        test_with_storage(storage).await;
    }

    #[tokio::test]
    async fn test_redis_storage() {
        let storage = RedisStorage::new("redis://localhost:6379").await.unwrap();
        test_with_storage(storage).await;
    }

    #[tokio::test]
    async fn test_postgres_storage() {
        let storage = PostgresStorage::new("postgresql://localhost/test_db").await.unwrap();
        test_with_storage(storage).await;
    }
}
```

This guide covers the essential aspects of choosing and configuring storage backends for auth-framework. Each backend has its strengths and is optimized for different use cases.
