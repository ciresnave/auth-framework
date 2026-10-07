# Storage Backends Guide

This guide covers the various storage backends available in auth-framework and
how to configure them for different use cases.

## Quick Decision Guide

Choose the right backend for your deployment scenario:

| Scenario                                     | Recommended backend |           Feature flag           |
| -------------------------------------------- | ------------------: | :------------------------------: |
| Local development or automated tests         |           In-memory |   *(none — always available)*    |
| Single-node production deployment            |          PostgreSQL | `postgres-storage` (**default**) |
| Multi-node or horizontally scaled deployment |  PostgreSQL + Redis |         `tiered-storage`         |
| Session caching / distributed rate limiting  |               Redis |         `redis-storage`          |
| High-throughput, single-process              |      UnifiedStorage |   `performance-optimization`     |

**Default build:** The `postgres-storage` feature is enabled by default. New
projects connect to PostgreSQL without any feature selection. If you do not have
a PostgreSQL instance, the in-memory backend is still available for local
development and tests, but it should not be treated as a production fallback.

### Which backends are default vs. optional?

| Backend           |       Default        | Rationale                                              |
| ----------------- | :------------------: | ------------------------------------------------------ |
| In-memory         |     ✅ (no flag)      | Zero-dependency dev/test backend; always present       |
| **PostgreSQL**    | ✅ `postgres-storage` | Production-grade ACID store; most users need it        |
| Redis             |  ⬜ `redis-storage`   | Requires a Redis cluster; opt-in for performance/scale |
| Tiered (Redis+PG) |  ⬜ `tiered-storage`  | Optimization feature; higher operational complexity    |
| UnifiedStorage    |  ⬜ `performance-optimization` | In-process DashMap; single-process only       |

To opt out of PostgreSQL (e.g. for a read-only CLI tool), use
`default-features = false`:

```toml
[dependencies]
auth-framework = { version = "0.5", default-features = false, features = ["redis-storage"] }
```

---

## Overview

Auth-framework supports multiple storage backends:

- **In-Memory** (`MemoryStorage`): Fast, lightweight, perfect for development
- **Redis** (`RedisStorage`): High-performance distributed caching
- **PostgreSQL** (`PostgresStorage`): Robust ACID-compliant storage
- **UnifiedStorage**: DashMap-based high-performance in-process storage
- **EncryptedStorage**: Transparent encryption wrapper for any backend

All backends implement the `AuthStorage` trait:

```rust
#[async_trait]
pub trait AuthStorage: Send + Sync {
    async fn store_token(&self, token: &AuthToken) -> Result<()>;
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>>;
    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>>;
    async fn update_token(&self, token: &AuthToken) -> Result<()>;
    async fn delete_token(&self, token_id: &str) -> Result<()>;
    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>>;

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()>;
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>>;
    async fn delete_session(&self, session_id: &str) -> Result<()>;
    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>>;
    async fn count_active_sessions(&self) -> Result<u64>;

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()>;
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_kv(&self, key: &str) -> Result<()>;
    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>>;

    async fn cleanup_expired(&self) -> Result<()>;
}
```

---

## In-Memory Storage

The in-memory storage backend stores all data in RAM and is ideal for
development, testing, and single-instance applications.

### Setup

```rust
use auth_framework::storage::MemoryStorage;

// Basic — uses default cleanup interval and TTL
let storage = MemoryStorage::new();
```

### Builder Pattern

```rust
use auth_framework::storage::InMemoryConfig;
use std::time::Duration;

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

### Using with AuthFramework

`AuthFramework::new(config)` uses in-memory storage by default — no extra
setup required:

```rust
use auth_framework::{AuthFramework, config::AuthConfig};

let config = AuthConfig::new();
let mut auth = AuthFramework::new(config);
auth.initialize().await?;
```

### Use Cases

- **Development**: Quick setup without external dependencies
- **Testing**: Isolated test environments with fast cleanup
- **Single-instance apps**: Applications that don't need persistence
- **Caching layer**: Temporary storage with automatic expiration

---

## Redis Storage

Redis provides high-performance, distributed storage with optional persistence.
Requires the `redis-storage` feature.

### Setup

Add the feature to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = { version = "0.5", features = ["redis-storage"] }
```

```rust
use auth_framework::storage::RedisStorage;
use std::time::Duration;

// Basic setup
let storage = RedisStorage::new("redis://localhost:6379").await?;

// With custom configuration
let storage = RedisStorage::with_config(
    "redis://localhost:6379",
    "auth:",                      // key prefix
    Duration::from_secs(3600),    // default TTL
).await?;
```

### Using with AuthFramework

```rust
use auth_framework::{AuthFramework, config::AuthConfig};
use auth_framework::storage::RedisStorage;
use std::sync::Arc;

let storage = RedisStorage::new("redis://localhost:6379").await?;
let config = AuthConfig::new();
let mut auth = AuthFramework::new_with_storage(config, Arc::new(storage));
auth.initialize().await?;
```

### Data Structure

Redis storage uses the following key patterns:

```text
{prefix}token:{token_id}         -> AuthToken (JSON)
{prefix}access:{access_token}    -> token_id (String)
{prefix}user:{user_id}:tokens    -> [token_ids] (List)
{prefix}session:{session_id}     -> SessionData (JSON)
{prefix}kv:{key}                 -> value (Bytes)
```

### Use Cases

- Distributed applications across multiple nodes
- High-throughput with persistence needs
- Session caching and rate limiting
- Horizontal scaling scenarios

---

## PostgreSQL Storage

PostgreSQL provides robust, ACID-compliant storage and is the recommended
choice for production. Requires the `postgres-storage` feature (enabled by
default).

### Setup

```toml
[dependencies]
auth-framework = { version = "0.5" }  # postgres-storage is on by default
```

```rust
use auth_framework::storage::PostgresStorage;
use sqlx::PgPool;

let pool = PgPool::connect("postgres://user:pass@localhost/auth_db").await?;
let storage = PostgresStorage::new(pool);
storage.migrate().await?;  // Creates tables if they don't exist
```

### Using with AuthFramework

```rust
use auth_framework::{AuthFramework, config::AuthConfig};
use auth_framework::storage::PostgresStorage;
use sqlx::PgPool;
use std::sync::Arc;

let pool = PgPool::connect("postgres://user:pass@localhost/auth_db").await?;
let storage = PostgresStorage::new(pool);
storage.migrate().await?;

let config = AuthConfig::new();
let mut auth = AuthFramework::new_with_storage(config, Arc::new(storage));
auth.initialize().await?;
```

### Database Schema

The `migrate()` method automatically creates these tables:

```sql
CREATE TABLE IF NOT EXISTS auth_tokens (
    token_id    VARCHAR(255) PRIMARY KEY,
    user_id     VARCHAR(255) NOT NULL,
    token_data  JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id  VARCHAR(255) PRIMARY KEY,
    user_id     VARCHAR(255) NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS kv_store (
    key         VARCHAR(512) PRIMARY KEY,
    value       BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ
);
```

### Use Cases

- Production applications requiring data integrity
- Compliance and audit trail requirements
- Long-term data retention
- Complex queries and analytics

---

## UnifiedStorage (Performance Optimization)

`UnifiedStorage` is a high-performance in-process storage backend built on
`DashMap` with background cleanup, object pooling, and memory arena support.
Requires the `performance-optimization` feature.

### Setup

```toml
[dependencies]
auth-framework = { version = "0.5", features = ["performance-optimization"] }
```

```rust
use auth_framework::storage::{UnifiedStorage, UnifiedStorageConfig};
use std::time::Duration;

// Default configuration
let storage = UnifiedStorage::new();

// Custom configuration
let config = UnifiedStorageConfig {
    initial_capacity: 10_000,
    default_ttl: Duration::from_secs(3600),
    max_memory: 512 * 1024 * 1024, // 512 MB
    ..Default::default()
};
let storage = UnifiedStorage::with_config(config);
```

### Performance Metrics

`UnifiedStorage` tracks hit/miss ratios and memory usage internally:

```rust
let stats = storage.get_stats();
println!("Hits: {}, Misses: {}", stats.hits, stats.misses);
```

### Use Cases

- Single-process, high-throughput workloads
- Benchmarking and performance testing
- Embedded applications without external dependencies
- When sub-millisecond latency is critical

---

## Encrypted Storage

`EncryptedStorage` wraps any other storage backend and transparently encrypts
data at rest. Always available — no feature flag required.

```rust
use auth_framework::storage::{EncryptedStorage, MemoryStorage};

let inner = MemoryStorage::new();
let storage = EncryptedStorage::new(inner, encryption_key);
```

---

## Storage Backend Comparison

| Feature              | In-Memory      | Redis           | PostgreSQL    | UnifiedStorage  |
| -------------------- | -------------- | --------------- | ------------- | --------------- |
| **Performance**      | Excellent      | Very Good       | Good          | Excellent       |
| **Scalability**      | Single process | Highly scalable | Very scalable | Single process  |
| **Persistence**      | None           | Optional        | Full          | None            |
| **ACID compliance**  | N/A            | Limited         | Full          | N/A             |
| **Setup complexity** | Minimal        | Low             | Moderate      | Minimal         |
| **Best for**         | Dev/Testing    | Distributed     | Production    | High-throughput |

## Choosing the Right Backend

### Use In-Memory When

- Developing or testing applications
- Building single-instance applications
- Performance is critical and persistence isn't needed
- You want zero external dependencies

### Use Redis When

- Building distributed applications
- You need high performance with some persistence
- Implementing caching strategies
- Scaling horizontally across multiple instances

### Use PostgreSQL When

- Building production applications
- Data integrity is critical
- Compliance requires audit trails
- Long-term data retention is important

### Use UnifiedStorage When

- Running a single-process server
- Sub-millisecond latency is required
- External dependencies are not an option
- Persistence is not needed

## Testing with Different Backends

```rust
#[cfg(test)]
mod tests {
    use auth_framework::{AuthFramework, config::AuthConfig};
    use auth_framework::storage::MemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_with_memory_storage() {
        let config = AuthConfig::new();
        let mut auth = AuthFramework::new(config);
        auth.initialize().await.unwrap();

        let user_id = auth
            .register_user("alice", "alice@test.com", "P@ssw0rd!")
            .await
            .unwrap();
        assert!(!user_id.is_empty());
    }
}
```
