# API Reference Guide

This comprehensive API reference covers all public interfaces, traits, and structures in auth-framework.

## Core Framework

### AuthFramework

The main entry point for the authentication framework.

```rust
pub struct AuthFramework {
    // Storage is handled internally as MemoryStorage
    // private fields...
}
```

#### Constructor

```rust
impl AuthFramework {
    pub fn new(config: AuthConfig) -> Self
}
```

**Parameters:**

- `config`: Authentication configuration

**Returns:** `AuthFramework` instance

**Example:**

```rust
let config = AuthConfig::new();
let mut auth = AuthFramework::new(config);
```

#### Core Methods

##### Method Registration

```rust
pub fn register_method(&mut self, name: impl Into<String>, method: AuthMethodEnum)
```

Registers an authentication method with the framework.

**Parameters:**

- `name`: Unique name for the authentication method
- `method`: Authentication method wrapped in `AuthMethodEnum`

**Example:**

```rust
use auth_framework::methods::{JwtMethod, AuthMethodEnum};

let jwt_method = JwtMethod::new().secret_key("key").issuer("issuer");
auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
```

##### Framework Initialization

```rust
pub async fn initialize(&mut self) -> Result<()>
```

Initializes the authentication framework. Must be called before using the framework.

**Example:**

```rust
auth.initialize().await?;
```

##### Authentication

```rust
pub async fn authenticate(
    &self,
    method_name: impl Into<String>,
    credential: Credential,
) -> Result<AuthResult>
```

Authenticates a credential using the specified method.

**Parameters:**

- `method_name`: Name of the registered authentication method
- `credential`: Credential to authenticate

**Returns:** `Result<AuthResult, AuthError>` where `AuthResult` can be:

- `Success(AuthToken)` - Authentication successful
- `MfaRequired(MfaChallenge)` - Multi-factor authentication required
- `Failure(String)` - Authentication failed

**Example:**

```rust
use auth_framework::credentials::Credential;

let credential = Credential::password("user123", "password");
match auth.authenticate("jwt", credential).await? {
    AuthResult::Success(token) => println!("Login successful"),
    AuthResult::MfaRequired(challenge) => println!("MFA required"),
    AuthResult::Failure(reason) => println!("Login failed: {}", reason),
}
```

##### Token Validation

```rust
pub async fn validate_token(&self, token: &AuthToken) -> Result<bool>
```

Validates an authentication token.

**Parameters:**

- `token`: The authentication token to validate

**Returns:** `Result<bool, AuthError>`

**Example:**

```rust
if auth.validate_token(&token).await? {
    println!("Token is valid");
}
```

##### Token Creation (Testing)

```rust
pub async fn create_auth_token(
    &self,
    user_id: impl Into<String>,
    scopes: Vec<String>,
    method_name: impl Into<String>,
    lifetime: Option<Duration>,
) -> Result<AuthToken>
```

Creates an authentication token directly (primarily for testing).

**Parameters:**

- `user_id`: User identifier
- `scopes`: List of permissions/scopes
- `method_name`: Name of the authentication method
- `lifetime`: Optional token lifetime

**Returns:** `Result<AuthToken, AuthError>`

**Example:**

```rust
let claims = auth.verify_token(&token.access_token).await?;
println!("User ID from token: {}", claims.sub);
```

##### Token Refresh

```rust
pub async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken>
```

Generates a new access token using a refresh token.

**Parameters:**

- `refresh_token`: Valid refresh token

**Returns:** `Result<AuthToken, AuthError>`

**Example:**

```rust
let new_token = auth.refresh_token(&old_token.refresh_token.unwrap()).await?;
```

##### Permission Management

```rust
pub async fn assign_permission(
    &self,
    user_id: &str,
    permission: &str
) -> Result<()>

pub async fn revoke_permission(
    &self,
    user_id: &str,
    permission: &str
) -> Result<()>

pub async fn has_permission(
    &self,
    user_id: &str,
    permission: &str
) -> Result<bool>

pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<String>>
```

**Example:**

```rust
// Assign permission
auth.assign_permission("john_doe", "admin").await?;

// Check permission
let has_admin = auth.has_permission("john_doe", "admin").await?;

// Get all permissions
let permissions = auth.get_user_permissions("john_doe").await?;
```

##### Role Management

```rust
pub async fn assign_role(&self, user_id: &str, role: &str) -> Result<()>
pub async fn revoke_role(&self, user_id: &str, role: &str) -> Result<()>
pub async fn has_role(&self, user_id: &str, role: &str) -> Result<bool>
pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>>
```

**Example:**

```rust
// Assign role
auth.assign_role("john_doe", "moderator").await?;

// Check role
let is_moderator = auth.has_role("john_doe", "moderator").await?;
```

## Storage Traits and Types

### AuthStorage Trait

The core storage abstraction that all storage backends must implement.

```rust
#[async_trait]
pub trait AuthStorage: Send + Sync + Clone {
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

    // Key-value operations
    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()>;
    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_kv(&self, key: &str) -> Result<()>;

    // Maintenance
    async fn cleanup_expired(&self) -> Result<()>;
}
```

### Storage Implementations

#### InMemoryStorage

Fast in-memory storage for development and testing.

```rust
pub struct InMemoryStorage {
    // private fields...
}

impl InMemoryStorage {
    pub fn new() -> Self
    pub fn with_config(cleanup_interval: Duration, default_ttl: Duration) -> Self
}
```

**Configuration:**

```rust
pub struct InMemoryConfig {
    pub cleanup_interval: Duration,
    pub default_ttl: Duration,
}

impl InMemoryConfig {
    pub fn new() -> Self
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self
    pub fn build(self) -> InMemoryStorage
}
```

**Example:**

```rust
// Basic usage
let storage = InMemoryStorage::new();

// Custom configuration
let storage = InMemoryConfig::new()
    .with_cleanup_interval(Duration::from_secs(60))
    .with_default_ttl(Duration::from_secs(1800))
    .build();
```

#### RedisStorage (Feature: "redis")

High-performance Redis-backed storage.

```rust
#[cfg(feature = "redis")]
pub struct RedisStorage {
    // private fields...
}

#[cfg(feature = "redis")]
impl RedisStorage {
    pub async fn new(url: &str) -> Result<Self>
    pub async fn with_config(config: RedisConfig) -> Result<Self>
}
```

**Configuration:**

```rust
#[cfg(feature = "redis")]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub timeout: Duration,
    pub key_prefix: String,
    pub default_ttl: Duration,
}
```

**Example:**

```rust
// Basic usage
let storage = RedisStorage::new("redis://localhost:6379").await?;

// Custom configuration
let config = RedisConfig {
    url: "redis://localhost:6379".to_string(),
    pool_size: 20,
    timeout: Duration::from_secs(5),
    key_prefix: "auth:".to_string(),
    default_ttl: Duration::from_secs(3600),
};
let storage = RedisStorage::with_config(config).await?;
```

#### PostgresStorage (Feature: "postgres")

Robust PostgreSQL storage for production.

```rust
#[cfg(feature = "postgres")]
pub struct PostgresStorage {
    // private fields...
}

#[cfg(feature = "postgres")]
impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self>
    pub async fn with_config(config: PostgresConfig) -> Result<Self>
}
```

## Core Types

### AuthToken

Represents an authentication token with metadata.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token_id: String,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub metadata: serde_json::Value,
}
```

### TokenClaims

JWT token claims structure.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,        // Subject (user ID)
    pub exp: i64,          // Expiration timestamp
    pub iat: i64,          // Issued at timestamp
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub metadata: serde_json::Value,
}
```

### UserCredentials

User credential information.

```rust
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub user_id: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
}
```

### SessionData

Session storage structure.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}
```

## Configuration

### AuthConfig

Main framework configuration.

```rust
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_algorithm: Algorithm,
    pub token_expiry: Duration,
    pub refresh_token_expiry: Duration,
    pub session_ttl: Duration,
    pub password_hash_cost: u32,
    pub max_login_attempts: u32,
    pub lockout_duration: Duration,
    // ... additional fields
}
```

#### Builder Pattern

```rust
impl AuthConfig {
    pub fn builder() -> AuthConfigBuilder
    pub fn default() -> Self
}

pub struct AuthConfigBuilder {
    // private fields...
}

impl AuthConfigBuilder {
    pub fn jwt_secret(mut self, secret: String) -> Self
    pub fn jwt_algorithm(mut self, algorithm: Algorithm) -> Self
    pub fn token_expiry(mut self, expiry: Duration) -> Self
    pub fn refresh_token_expiry(mut self, expiry: Duration) -> Self
    pub fn session_ttl(mut self, ttl: Duration) -> Self
    pub fn password_hash_cost(mut self, cost: u32) -> Self
    pub fn max_login_attempts(mut self, attempts: u32) -> Self
    pub fn lockout_duration(mut self, duration: Duration) -> Self
    pub fn build(self) -> AuthConfig
}
```

**Example:**

```rust
let config = AuthConfig::builder()
    .jwt_secret("your-secret-key".to_string())
    .token_expiry(Duration::hours(24))
    .refresh_token_expiry(Duration::days(30))
    .session_ttl(Duration::hours(2))
    .password_hash_cost(12)
    .max_login_attempts(5)
    .lockout_duration(Duration::minutes(15))
    .build();
```

### RSA Key Format Support

When using RSA keys for JWT signing and token management, the framework supports both standard PEM formats:

#### Supported Formats

- **PKCS#1 Format**: `-----BEGIN RSA PRIVATE KEY-----` (traditional RSA format)
- **PKCS#8 Format**: `-----BEGIN PRIVATE KEY-----` (modern standard format, recommended)

#### TokenManager with RSA Keys

```rust
use auth_framework::tokens::TokenManager;

// Both PKCS#1 and PKCS#8 formats are automatically detected
let private_key = std::fs::read("private.pem")?;
let public_key = std::fs::read("public.pem")?;

let token_manager = TokenManager::new_rsa(
    &private_key,
    &public_key,
    "issuer",
    "audience"
)?;
```

#### Key Generation Examples

```bash
# PKCS#1 format (traditional)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# PKCS#8 format (recommended)
openssl genpkey -algorithm RSA -out private_pkcs8.pem -pkcs8
openssl pkey -in private_pkcs8.pem -pubout -out public_spki.pem
```

**Note**: No format conversion is required - both formats are automatically detected and parsed.

## Web Framework Integrations

### Actix-web Integration (Feature: "actix-web")

```rust
#[cfg(feature = "actix-web")]
pub mod actix_web {
    use actix_web::{FromRequest, HttpRequest, Result as ActixResult};

    // Middleware
    pub struct AuthMiddleware {
        // private fields...
    }

    impl AuthMiddleware {
        pub fn new() -> Self
        pub fn with_config(config: AuthConfig) -> Self
    }

    // Extractors
    pub struct AuthenticatedUser {
        pub user_id: String,
        pub permissions: Vec<String>,
        pub roles: Vec<String>,
        pub token_claims: TokenClaims,
    }

    impl FromRequest for AuthenticatedUser {
        type Error = actix_web::Error;
        type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future
    }

    // Permission guards
    pub struct RequirePermission<const PERMISSION: &'static str>;

    impl<const PERMISSION: &'static str> FromRequest for RequirePermission<PERMISSION> {
        type Error = actix_web::Error;
        type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

        fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future
    }

    // Role guards
    pub struct RequireRole<const ROLE: &'static str>;
}
```

**Usage Example:**

```rust
use actix_web::{web, App, HttpServer, Result};
use auth_framework::integrations::actix_web::{
    AuthMiddleware, AuthenticatedUser, RequirePermission
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(AuthMiddleware::new())
            .route("/profile", web::get().to(get_profile))
            .route("/admin", web::get().to(admin_only))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn get_profile(user: AuthenticatedUser) -> Result<String> {
    Ok(format!("User: {}", user.user_id))
}

async fn admin_only(
    _user: AuthenticatedUser,
    _admin: RequirePermission<"admin">
) -> Result<String> {
    Ok("Admin panel".to_string())
}
```

### Warp Integration (Feature: "warp")

```rust
#[cfg(feature = "warp")]
pub mod warp {
    use warp::{Filter, Rejection};

    pub fn with_auth<S: AuthStorage>(
        auth: AuthFramework<S>
    ) -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone

    pub fn require_permission(
        permission: &'static str
    ) -> impl Filter<Extract = (), Error = Rejection> + Clone

    pub fn require_role(
        role: &'static str
    ) -> impl Filter<Extract = (), Error = Rejection> + Clone

    // Types
    pub struct AuthenticatedUser {
        pub user_id: String,
        pub permissions: Vec<String>,
        pub roles: Vec<String>,
        pub token_claims: TokenClaims,
    }

    // Custom rejection types
    #[derive(Debug)]
    pub struct AuthenticationError;
    impl warp::reject::Reject for AuthenticationError {}

    #[derive(Debug)]
    pub struct PermissionError;
    impl warp::reject::Reject for PermissionError {}
}
```

**Usage Example:**

```rust
use warp::Filter;
use auth_framework::integrations::warp::{with_auth, require_permission};

#[tokio::main]
async fn main() {
    let auth = /* initialize auth framework */;
    let auth_filter = with_auth(auth);

    let profile = warp::path("profile")
        .and(warp::get())
        .and(auth_filter.clone())
        .map(|user: AuthenticatedUser| {
            format!("User: {}", user.user_id)
        });

    let admin = warp::path("admin")
        .and(warp::get())
        .and(auth_filter)
        .and(require_permission("admin"))
        .map(|user: AuthenticatedUser| {
            "Admin panel"
        });

    let routes = profile.or(admin);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
```

### Rocket Integration (Feature: "rocket")

```rust
#[cfg(feature = "rocket")]
pub mod rocket {
    use rocket::{Request, request::{self, FromRequest}};

    // Request guards
    pub struct AuthenticatedUser {
        pub user_id: String,
        pub permissions: Vec<String>,
        pub roles: Vec<String>,
        pub token_claims: TokenClaims,
    }

    #[rocket::async_trait]
    impl<'r> FromRequest<'r> for AuthenticatedUser {
        type Error = ();

        async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error>
    }

    pub struct RequirePermission<const PERMISSION: &'static str>;

    #[rocket::async_trait]
    impl<'r, const PERMISSION: &'static str> FromRequest<'r> for RequirePermission<PERMISSION> {
        type Error = ();

        async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error>
    }

    pub struct RequireRole<const ROLE: &'static str>;

    // Fairings
    pub struct AuthFairing {
        // private fields...
    }

    impl AuthFairing {
        pub fn new() -> Self
        pub fn with_config(config: AuthConfig) -> Self
    }
}
```

**Usage Example:**

```rust
use rocket::{get, launch, routes, State};
use auth_framework::integrations::rocket::{AuthenticatedUser, RequirePermission};

#[get("/profile")]
fn get_profile(user: AuthenticatedUser) -> String {
    format!("User: {}", user.user_id)
}

#[get("/admin")]
fn admin_only(_user: AuthenticatedUser, _admin: RequirePermission<"admin">) -> &'static str {
    "Admin panel"
}

#[launch]
async fn rocket() -> _ {
    rocket::build()
        .manage(/* auth framework instance */)
        .mount("/", routes![get_profile, admin_only])
}
```

## Error Handling

### AuthError

The main error type for all authentication operations.

```rust
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token invalid")]
    TokenInvalid,

    #[error("User not found")]
    UserNotFound,

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}
```

### Result Type

Convenience type alias for operations that may fail.

```rust
pub type Result<T> = std::result::Result<T, AuthError>;
```

## Advanced Features

### Multi-Factor Authentication

```rust
use auth_framework::methods::MfaAuth;

pub struct MfaAuth<S: AuthStorage> {
    // private fields...
}

impl<S: AuthStorage> MfaAuth<S> {
    pub fn new(storage: S) -> Self

    // TOTP methods
    pub async fn enable_totp(&self, user_id: &str) -> Result<String>
    pub async fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool>
    pub async fn disable_totp(&self, user_id: &str) -> Result<()>

    // SMS methods
    pub async fn send_sms_code(&self, user_id: &str, phone: &str) -> Result<()>
    pub async fn verify_sms_code(&self, user_id: &str, code: &str) -> Result<bool>

    // Backup codes
    pub async fn generate_backup_codes(&self, user_id: &str) -> Result<Vec<String>>
    pub async fn use_backup_code(&self, user_id: &str, code: &str) -> Result<bool>
}
```

### API Key Management

```rust
use auth_framework::methods::ApiKeyAuth;

pub struct ApiKeyAuth<S: AuthStorage> {
    // private fields...
}

pub struct ApiKey {
    pub key: String,
    pub user_id: String,
    pub name: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

impl<S: AuthStorage> ApiKeyAuth<S> {
    pub fn new(storage: S) -> Self

    pub async fn create_api_key(
        &self,
        user_id: &str,
        name: &str,
        expires_at: Option<DateTime<Utc>>
    ) -> Result<ApiKey>

    pub async fn verify_api_key(&self, key: &str) -> Result<Option<ApiKey>>
    pub async fn revoke_api_key(&self, key: &str) -> Result<()>
    pub async fn list_user_api_keys(&self, user_id: &str) -> Result<Vec<ApiKey>>
}
```

### OAuth2 Device Flow

```rust
use auth_framework::methods::enhanced_device::{EnhancedDeviceFlow, DeviceFlowConfig};

pub struct DeviceFlowConfig {
    pub client_id: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub device_code_expiry: Duration,
    pub poll_interval: Duration,
    pub scope: Option<String>,
}

pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

impl<S: AuthStorage> EnhancedDeviceFlow<S> {
    pub fn new(storage: S, config: DeviceFlowConfig) -> Self

    pub async fn start_authorization(&self) -> Result<DeviceAuthorizationResponse>

    pub async fn poll_for_token(&self, device_code: &str) -> Result<DeviceTokenResponse>

    pub async fn complete_authorization(
        &self,
        device_code: &str,
        user_id: &str,
        permissions: Vec<String>
    ) -> Result<()>
}
```

## Testing Utilities

```rust
#[cfg(feature = "testing")]
pub mod testing {
    use crate::*;

    pub struct TestAuthFramework {
        // private fields...
    }

    impl TestAuthFramework {
        pub async fn new() -> Self
        pub async fn with_config(config: AuthConfig) -> Self

        // Helper methods for testing
        pub async fn create_test_user(&self, user_id: &str) -> Result<UserCredentials>
        pub async fn create_test_token(&self, user_id: &str) -> Result<AuthToken>
        pub fn create_expired_token(&self, user_id: &str) -> AuthToken
    }

    pub mod helpers {
        use super::*;

        pub fn create_test_user(user_id: &str) -> UserCredentials
        pub fn create_test_token(user_id: &str) -> AuthToken
        pub fn create_test_claims(user_id: &str) -> TokenClaims
        pub fn create_test_config() -> AuthConfig
    }
}
```

## Feature Flags

The following Cargo features are available:

| Feature | Description | Default |
|---------|-------------|---------|
| `actix-web` | Actix-web framework integration | No |
| `warp` | Warp framework integration | No |
| `rocket` | Rocket framework integration | No |
| `redis` | Redis storage backend | No |
| `postgres` | PostgreSQL storage backend | No |
| `testing` | Testing utilities | No |
| `full` | Enable all features | No |

**Example Cargo.toml:**

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["actix-web", "redis", "testing"] }
```

This API reference provides comprehensive coverage of all public interfaces in auth-framework. For implementation examples, see the examples directory and integration guides.
