# API Reference Guide

This comprehensive API reference covers the public interfaces, traits, and
structures in auth-framework.

## Core Framework

### AuthFramework

The main entry point for the authentication framework.

```rust
pub struct AuthFramework {
    // private fields — storage is managed internally
}
```

#### Constructors

##### `AuthFramework::new`

```rust
pub fn new(config: AuthConfig) -> Self
```

Creates a new framework instance with in-memory storage. Configuration
validation and component initialization is deferred to `initialize()`.

```rust
use auth_framework::{AuthFramework, config::AuthConfig};

let config = AuthConfig::new();
let mut auth = AuthFramework::new(config);
```

##### `AuthFramework::new_validated`

```rust
pub fn new_validated(config: AuthConfig) -> Result<Self>
```

Like `new`, but validates the configuration eagerly and returns an error
on invalid settings.

##### `AuthFramework::new_with_storage`

```rust
pub fn new_with_storage(config: AuthConfig, storage: Arc<dyn AuthStorage>) -> Self
```

Creates a framework with an externally provided storage backend
(e.g. Redis, PostgreSQL).

##### `AuthFramework::quick_start`

```rust
pub fn quick_start() -> QuickStartBuilder
```

One-liner initialization with sensible defaults:

```rust
let auth = AuthFramework::quick_start()
    .jwt_auth("your-32-character-secret-key-here!!")
    .build()
    .await?;
```

#### Framework Initialization

```rust
pub async fn initialize(&mut self) -> Result<()>
```

Initializes the authentication framework. Must be called before using the
framework.

```rust
auth.initialize().await?;
```

> **Initialization Guard:** All storage, token, session, user-management,
> and authorization methods require the framework to be initialized. Calling
> them before `initialize()` (or without using the builder path) returns
> `Err(AuthError::Configuration("Framework not initialized. …"))` with
> guidance on how to fix it. Config/validation helpers such as
> `runtime_config()`, `validate_username()`, and monitoring exports are NOT
> guarded and work immediately.

---

### Core Methods

#### Authentication

```rust
pub async fn authenticate(
    &self,
    method_name: &str,
    credential: Credential,
) -> Result<AuthResult>
```

Authenticates a credential using the specified method.

**Returns:** `Result<AuthResult>` where `AuthResult` can be:

- `Success(AuthToken)` — Authentication successful
- `MfaRequired(MfaChallenge)` — Multi-factor authentication required
- `Failure(String)` — Authentication failed

```rust
use auth_framework::authentication::credentials::Credential;

let credential = Credential::jwt(token_string);
match auth.authenticate("jwt", credential).await? {
    AuthResult::Success(token) => println!("Authenticated: {}", token.user_id),
    AuthResult::MfaRequired(challenge) => println!("MFA needed: {:?}", challenge),
    AuthResult::Failure(reason) => eprintln!("Failed: {reason}"),
}
```

#### Token Validation

```rust
pub async fn validate_token(&self, token: &AuthToken) -> Result<bool>
```

Validates an authentication token against storage and expiration.

```rust
if auth.validate_token(&token).await? {
    println!("Token is valid");
}
```

#### Token Creation

```rust
pub async fn create_auth_token(
    &self,
    user_id: impl Into<String>,
    scopes: impl Into<Scopes>,
    method_name: impl Into<String>,
    lifetime: Option<Duration>,
) -> Result<AuthToken>
```

Creates an authentication token for a user.

```rust
use std::time::Duration;

let token = auth
    .create_auth_token("user123", vec!["read".to_string()], "jwt", None)
    .await?;
println!("Token: {}", token.token_id);
```

#### Token Refresh

```rust
pub async fn refresh_token(&self, token: &AuthToken) -> Result<AuthToken>
```

Generates a new access token from an existing valid token.

```rust
let new_token = auth.refresh_token(&old_token).await?;
```

#### User Registration

```rust
pub async fn register_user(
    &self,
    username: &str,
    email: &str,
    password: &str,
) -> Result<String>
```

Registers a new user and returns their generated user ID.

```rust
let user_id = auth.register_user("alice", "alice@example.com", "S3cur3P@ss!").await?;
```

---

### Authorization Methods

#### Permission Management

```rust
pub async fn grant_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<()>
pub async fn revoke_permission(&self, user_id: &str, action: &str, resource: &str) -> Result<()>
pub async fn check_permission(&self, token: &AuthToken, action: &str, resource: &str) -> Result<bool>
pub async fn get_effective_permissions(&self, user_id: &str) -> Result<Vec<String>>
```

```rust
// Grant and check permissions
auth.grant_permission("alice", "read", "documents").await?;
let allowed = auth.check_permission(&token, "read", "documents").await?;
let all_perms = auth.get_effective_permissions("alice").await?;
```

#### Role Management

```rust
pub async fn assign_role(&self, user_id: &str, role_name: &str) -> Result<()>
pub async fn remove_role(&self, user_id: &str, role_name: &str) -> Result<()>
pub async fn user_has_role(&self, user_id: &str, role_name: &str) -> Result<bool>
pub async fn list_user_roles(&self, user_id: &str) -> Result<Vec<String>>
```

```rust
auth.assign_role("alice", "moderator").await?;
let is_mod = auth.user_has_role("alice", "moderator").await?;
let roles = auth.list_user_roles("alice").await?;
```

---

### Façade Operations

`AuthFramework` exposes grouped operations via accessor methods:

```rust
auth.users()         // UserOperations — register, profile, list, validate, update, delete
auth.sessions()      // SessionOperations — create, list, filter, revoke
auth.tokens()        // TokenOperations — create, create_token, validate, revoke
auth.authorization() // AuthorizationOperations — roles, permissions, ABAC
auth.mfa()           // MfaOperations — TOTP, backup codes, QR URLs
auth.monitoring()    // MonitoringOperations — metrics, health, Prometheus
auth.maintenance()   // MaintenanceOperations — cleanup, stats
auth.audit()         // AuditOperations — query audit logs
auth.admin()         // AdminOperations — ABAC, delegation, role hierarchy, bulk attributes
```

> **Prefer query builders over positional parameters.** Methods like
> `users().list(limit, offset, active_only)` are deprecated in favour of
> `users().list_with_query(UserListQuery::new().limit(50).active_only())`.
> The query-builder variants avoid boolean-position footguns and are
> forwards-compatible with new filter fields.

#### Request Structs

##### SessionCreateRequest

```rust
let session_id = auth.sessions()
    .create_session(
        SessionCreateRequest::new("user123", Duration::from_secs(3600))
            .ip_address("203.0.113.1")
            .user_agent("Mozilla/5.0")
    )
    .await?;
```

##### SessionFilter

```rust
use auth_framework::auth_operations::SessionFilter;

// List only active (non-expired) sessions for a user
let active = auth.sessions()
    .list_for_user_filtered("user123", SessionFilter::ActiveOnly)
    .await?;

// List all sessions including expired ones
let all = auth.sessions()
    .list_for_user_filtered("user123", SessionFilter::IncludeInactive)
    .await?;
```

##### AuditLogQuery

```rust
let logs = auth.audit()
    .query(
        AuditLogQuery::new()
            .user("alice")
            .action("login")
            .limit(50)
    )
    .await?;
```

##### DelegationRequest

```rust
auth.admin()
    .delegate(
        DelegationRequest::new("alice", "bob", "read", "documents")
            .duration(Duration::from_secs(86400))
    )
    .await?;
```

##### Bulk User Attributes

```rust
// Set multiple ABAC attributes in one call
auth.admin()
    .set_user_attributes("user123", &[
        ("department", "engineering"),
        ("clearance", "top-secret"),
        ("location", "us-west"),
    ])
    .await?;
```

##### TokenCreateRequest

```rust
use auth_framework::auth_operations::TokenCreateRequest;

let token = auth.tokens().create_token(
    TokenCreateRequest::new("user123", "jwt")
        .scope("read")
        .scope("write")
        .lifetime(Duration::from_secs(7200))
).await?;
```

#### Validation Helpers

`UserOperations` exposes synchronous validation methods that return
`Result<()>` — `Ok(())` when valid, `Err(AuthError::Validation { .. })` with
a human-readable reason when invalid:

```rust
// Check username against format rules
auth.users().check_username("alice")?;

// Check email format
auth.users().check_email("alice@example.com")?;

// Check password against strength policy
auth.users().check_password_strength("C0mpl3x!Pa$$word")?;
```

---

## Storage Traits and Types

### AuthStorage Trait

The core storage abstraction. All backends implement this trait.

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
    async fn list_kv_keys(&self, prefix: &str) -> Result<Vec<String>>;

    // Bulk operations (default implementations provided)
    async fn store_tokens_bulk(&self, tokens: &[AuthToken]) -> Result<()>;
    async fn delete_tokens_bulk(&self, token_ids: &[String]) -> Result<()>;
    async fn store_sessions_bulk(&self, sessions: &[(String, SessionData)]) -> Result<()>;
    async fn delete_sessions_bulk(&self, session_ids: &[String]) -> Result<()>;

    // Maintenance
    async fn cleanup_expired(&self) -> Result<()>;
}
```

### Storage Implementations

| Backend          | Feature Flag                 | Constructor                          |
| ---------------- | ---------------------------- | ------------------------------------ |
| In-Memory        | *(always available)*         | `MemoryStorage::new()`               |
| PostgreSQL       | `postgres-storage` (default) | `PostgresStorage::new(pool: PgPool)` |
| Redis            | `redis-storage`              | `RedisStorage::new(url).await?`      |
| UnifiedStorage   | `performance-optimization`   | `UnifiedStorage::new()`              |
| EncryptedStorage | *(always available)*         | `EncryptedStorage::new(inner, key)`  |

#### InMemoryStorage

```rust
use auth_framework::storage::MemoryStorage;

let storage = MemoryStorage::new();
```

#### InMemoryConfig Builder

```rust
use auth_framework::storage::InMemoryConfig;
use std::time::Duration;

let storage = InMemoryConfig::new()
    .with_cleanup_interval(Duration::from_secs(60))
    .with_default_ttl(Duration::from_secs(1800))
    .build();
```

#### PostgresStorage

Requires the `postgres-storage` feature (enabled by default).

```rust
use auth_framework::storage::PostgresStorage;
use sqlx::PgPool;

let pool = PgPool::connect("postgres://user:pass@localhost/auth_db").await?;
let storage = PostgresStorage::new(pool);
storage.migrate().await?; // Creates tables if they don't exist
```

#### RedisStorage

Requires the `redis-storage` feature.

```rust
use auth_framework::storage::RedisStorage;
use std::time::Duration;

// Basic
let storage = RedisStorage::new("redis://localhost:6379").await?;

// With configuration
let storage = RedisStorage::with_config(
    "redis://localhost:6379",
    "auth:",                      // key prefix
    Duration::from_secs(3600),    // default TTL
).await?;
```

#### UnifiedStorage

High-performance DashMap-based storage with background cleanup. Requires the
`performance-optimization` feature.

```rust
use auth_framework::storage::{UnifiedStorage, UnifiedStorageConfig};

let storage = UnifiedStorage::new();

// Or with custom configuration
let config = UnifiedStorageConfig {
    initial_capacity: 10_000,
    default_ttl: Duration::from_secs(3600),
    max_memory: 512 * 1024 * 1024, // 512 MB
    ..Default::default()
};
let storage = UnifiedStorage::with_config(config);
```

---

## Core Types

### AuthToken

Represents an authentication token with metadata.

```rust
pub struct AuthToken {
    pub token_id: String,
    pub user_id: String,
    pub access_token: String,
    pub token_type: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub refresh_token: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub scopes: Scopes,
    pub auth_method: String,
    pub client_id: Option<String>,
    pub user_profile: Option<ProviderProfile>,
    pub permissions: Permissions,
    pub roles: Roles,
    pub metadata: TokenMetadata,
}
```

#### Key Methods

| Method                | Returns        | Description                          |
| --------------------- | -------------- | ------------------------------------ |
| `access_token()`      | `&str`         | The bearer token value               |
| `user_id()`           | `&str`         | Owning user ID                       |
| `is_expired()`        | `bool`         | Whether `expires_at` is in the past  |
| `is_valid()`          | `bool`         | Not expired and not revoked          |
| `time_until_expiry()` | `Duration`     | Time remaining (or `Duration::ZERO`) |
| `has_refresh_token()` | `bool`         | Whether a refresh token is present   |
| `get_refresh_token()` | `Option<&str>` | The refresh token, if any            |
| `is_revoked()`        | `bool`         | Whether the token has been revoked   |
| `add_scope(scope)`    | `&mut self`    | Add a scope to the token             |
| `has_scope(scope)`    | `bool`         | Check for a specific scope           |

> **Note:** `Debug` output redacts `access_token` and `refresh_token` for
> security.

### TokenMetadata

```rust
pub struct TokenMetadata {
    pub issued_ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
    pub last_used: Option<DateTime<Utc>>,
    pub use_count: u64,
    pub custom: HashMap<String, serde_json::Value>,
}
```

### JwtClaims

JWT token claims structure used for token verification.

```rust
pub struct JwtClaims {
    pub sub: String,                              // Subject (user ID)
    pub iss: String,                              // Issuer
    pub aud: String,                              // Audience
    pub exp: i64,                                 // Expiration timestamp
    pub iat: i64,                                 // Issued at timestamp
    pub nbf: i64,                                 // Not before timestamp
    pub jti: String,                              // JWT ID
    pub scope: String,                            // Space-separated scopes
    pub permissions: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub custom: HashMap<String, serde_json::Value>,
}
```

### SessionData

```rust
pub struct SessionData {
    pub user_id: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}
```

#### Key Methods

| Method                | Returns          | Description                             |
| --------------------- | ---------------- | --------------------------------------- |
| `new(user_id, ttl)`   | `SessionData`    | Create a new session with TTL           |
| `is_expired()`        | `bool`           | Whether `last_accessed + TTL` is past   |
| `is_active()`         | `bool`           | Inverse of `is_expired()`               |
| `time_until_expiry()` | `Duration`       | Time remaining (or `Duration::ZERO`)    |
| `update_activity()`   | `&mut self`      | Touch `last_accessed`                   |
| `with_metadata(k, v)` | `Self`           | Add a metadata key-value pair (builder) |
| `set_data(k, v)`      |                  | Set a data field                        |
| `get_data(k)`         | `Option<&Value>` | Retrieve a data field                   |

---

## Configuration

### AuthConfig

Main framework configuration. Supports both direct construction and builder
pattern.

#### Builder Pattern (Recommended)

```rust
use auth_framework::config::AuthConfig;
use std::time::Duration;

let config = AuthConfig::builder()
    .jwt_secret("your-secret-key".to_string())
    .token_expiry(Duration::from_secs(86400))
    .refresh_token_expiry(Duration::from_secs(2_592_000))
    .max_login_attempts(5)
    .lockout_duration(Duration::from_secs(900))
    .build();
```

#### Quick Default

```rust
let config = AuthConfig::new(); // Generates random JWT secret
```

#### From Environment Variables

Reads `JWT_SECRET`, `DATABASE_URL`, `REDIS_URL`, `AUTH_ISSUER`, and
`AUTH_AUDIENCE` from the process environment. Missing variables fall back to
defaults.

```rust
let config = AuthConfig::from_env();
```

#### Display

All config types implement `Display` for logging/debugging:

```rust
let config = AuthConfig::new();
println!("{config}");
// AuthConfig { tokens: 3600s/604800s refresh, storage: memory, mfa: off, rbac: off,
//   rate_limit: 100 req/60s (burst 10), security: Security { pw≥8, ... }, cors: cors(off),
//   audit: audit(tracing) }
```

### RSA Key Support

Both PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`) formats
are auto-detected:

```rust
use auth_framework::tokens::TokenManager;

let token_manager = TokenManager::new_rsa(
    &private_key_bytes,
    &public_key_bytes,
    "issuer",
    "audience",
)?;
```

---

## Web Framework Integrations

### Axum Integration (Feature: `api-server` or `axum-integration`)

The default API server uses Axum. See `src/api/` for the full router.

```rust
use auth_framework::api::ApiServer;
use std::sync::Arc;

let auth = Arc::new(auth_framework);
let server = ApiServer::new(auth.clone());
server.start().await?;
// Server provides routes: /auth/login, /auth/register, /auth/refresh, etc.
```

### Actix-web Integration (Feature: `actix-integration`)

```rust
use auth_framework::integrations::actix_web::configure_actix_app;

HttpServer::new(move || {
    App::new()
        .configure(|cfg| configure_actix_app(cfg, auth.clone()))
})
```

### Warp Integration (Feature: `warp-integration`)

```rust
use auth_framework::integrations::warp::*;

let auth_filter = with_auth(auth.clone());
let protected = warp::path("profile")
    .and(auth_filter)
    .map(|user| format!("User: {}", user.user_id));
```

---

## Error Handling

### AuthError

The primary error type. Uses `thiserror` for ergonomic error handling.

Key variants:

| Variant                              | Description                         |
| ------------------------------------ | ----------------------------------- |
| `Configuration { message, .. }`      | Invalid configuration               |
| `AuthMethod { method, message, .. }` | Authentication method failure       |
| `Token(TokenError)`                  | Token verification/creation failure |
| `Permission(PermissionError)`        | Authorization failure               |
| `Storage(StorageError)`              | Storage backend error               |
| `RateLimit { message }`              | Rate limit exceeded                 |
| `Mfa(MfaError)`                      | MFA challenge/verification failure  |
| `UserNotFound`                       | User lookup failed                  |
| `Validation { message }`             | Input validation error              |
| `Internal { message }`               | Unexpected internal error           |

#### Error Classification Helpers

Every `AuthError` exposes framework-agnostic helpers for programmatic handling:

```rust
use auth_framework::AuthError;

let err = AuthError::rate_limit("slow down");

// HTTP status code (works without any web framework feature)
assert_eq!(err.http_status_code(), 429);

// Stable machine-readable code for API responses and metrics
assert_eq!(err.error_code(), "rate_limit");

// Retry guidance
assert!(err.is_retryable());

// Quick category checks
assert!(err.is_client_error());   // 4xx
assert!(!err.is_server_error());  // 5xx
```

| Method               | Returns        | Description                                                   |
| -------------------- | -------------- | ------------------------------------------------------------- |
| `http_status_code()` | `u16`          | HTTP status (400, 401, 403, 404, 408, 429, 500, 502, 503)     |
| `error_code()`       | `&'static str` | Stable identifier (`"rate_limit"`, `"invalid_token"`, …)      |
| `is_retryable()`     | `bool`         | `true` for rate-limit, timeout, network, storage connectivity |
| `is_client_error()`  | `bool`         | `true` when `http_status_code()` is 4xx                       |
| `is_server_error()`  | `bool`         | `true` when `http_status_code()` is 5xx                       |

### Result Type

```rust
pub type Result<T> = std::result::Result<T, AuthError>;
```

---

## Testing Utilities

```rust
use auth_framework::testing::{MockAuthMethod, TestEnvironment};

// Create a mock auth method that always succeeds
let mock = MockAuthMethod::new_success();

// Set up test environment variables (restored on drop)
let _env = TestEnvironment::new()
    .with_jwt_secret("test-secret")
    .with_database_url("postgres://localhost/test");
```

---

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `postgres-storage` | PostgreSQL storage backend | **Yes** |
| `enhanced-rbac` | Enterprise RBAC + API server | **Yes** |
| `redis-storage` | Redis storage backend | No |
| `actix-integration` | Actix-web framework integration | No |
| `warp-integration` | Warp framework integration | No |
| `axum-integration` | Axum framework integration | No |
| `passkeys` | WebAuthn/FIDO2 passkey support | No |
| `saml` | SAML 2.0 support | No |
| `otp-auth` | OTP authentication | No |
| `ldap-auth` | LDAP authentication | No |
| `hsm` | Hardware Security Module support | No |
| `performance-optimization` | UnifiedStorage, object pools | No |
| `tiered-storage` | Redis + PostgreSQL tiered storage | No |
| `enhanced-observability` | Built-in metrics/security monitoring (no OpenTelemetry export) | No |
| `config-hot-reload` | File-system config watching | No |

```toml
[dependencies]
auth-framework = { version = "0.5", features = ["redis-storage", "actix-integration"] }
```

This API reference covers the primary public interfaces in auth-framework. For
protocol-specific configuration, see [PROTOCOL_CONFIGURATION.md](PROTOCOL_CONFIGURATION.md).
For deployment guidance, see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).
