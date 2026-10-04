# AuthFramework Quick Start Guide

Get a complete authentication and authorization system running in your Rust application in minutes.

---

## Prerequisites

- **Rust 1.89+** (edition 2024)
- **Tokio** async runtime
- A running **PostgreSQL** instance (recommended) or use in-memory storage for development

## Step 1: Add the Dependency

```toml
# Cargo.toml
[dependencies]
auth-framework = "0.5"
tokio = { version = "1", features = ["full"] }
serde_json = "1"
```

The default feature set includes PostgreSQL storage, Axum API server, OpenID Connect, and enterprise RBAC. See [FEATURE_FLAGS.md](../FEATURE_FLAGS.md) for customization.

## Step 2: Initialize the Framework

### Option A: Quick Start (Fastest)

```rust
use auth_framework::AuthFramework;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One-liner initialization with in-memory storage
    let auth = AuthFramework::quick_start()
        .jwt_auth("your-32-character-secret-key-here!!")
        .build()
        .await?;

    println!("AuthFramework is ready!");
    Ok(())
}
```

### Option B: Environment Variable Configuration

```rust
use auth_framework::AuthFramework;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Reads JWT_SECRET from environment
    let auth = AuthFramework::quick_start()
        .jwt_auth_from_env()
        .build()
        .await?;

    Ok(())
}
```

Set the environment variable before running:

```bash
export JWT_SECRET="your-32-character-secret-key-here!!"
```

### Option B½: Config from Environment

If you prefer the config-level API over the quick-start builder, `AuthConfig::from_env()`
reads `JWT_SECRET`, `DATABASE_URL`, `REDIS_URL`, `AUTH_ISSUER`, and `AUTH_AUDIENCE` from the
environment and builds an `AuthConfig` with sensible defaults:

```rust
use auth_framework::{AuthFramework, config::AuthConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::from_env();
    let auth = AuthFramework::new(config);
    auth.initialize().await?;
    Ok(())
}
```

### Option C: Full Builder (Production)

```rust
use auth_framework::{AuthFramework, config::SecurityConfig};
use auth_framework::builders::{SecurityPreset, PerformancePreset, UseCasePreset};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = AuthFramework::builder()
        .security_preset(SecurityPreset::HighSecurity)
        .performance_preset(PerformancePreset::LowLatency)
        .use_case_preset(UseCasePreset::WebApp)
        .build()
        .await?;

    Ok(())
}
```

### Option D: Manual Configuration

```rust
use auth_framework::{AuthFramework, config::AuthConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::builder()
        .secret("your-32-character-secret-key-here!!".to_string())
        .issuer("my-application".to_string())
        .audience("my-api".to_string())
        .token_lifetime(Duration::from_secs(3600))      // 1 hour
        .refresh_token_lifetime(Duration::from_secs(604800)) // 7 days
        .security(SecurityConfig::secure()) // Production hardened
        .build();

    let auth = AuthFramework::new(config);
    auth.initialize().await?;

    Ok(())
}
```

> **Important**: Always call `initialize().await?` when using `AuthFramework::new()`. The `quick_start()` and `builder()` paths handle this automatically. Calling any storage, user, token, session, or authorization method before initializing returns a clear `AuthError::Configuration` telling you what to do.

## Step 3: Register Users

```rust
// Validate inputs before registration (returns Err with reason on failure)
auth.users().check_username("alice")?;
auth.users().check_email("alice@example.com")?;
auth.users().check_password_strength("StrongP@ssw0rd!")?;

// Register a new user
let user_id = auth.users().register(
    "alice",
    "alice@example.com",
    "StrongP@ssw0rd!",
).await?;

println!("Registered user: {}", user_id);

// Retrieve user profile
let profile = auth.users().profile(&user_id).await?;
println!("User: {} ({})", profile.username, profile.email);
```

## Step 4: Issue and Manage Tokens

```rust
use auth_framework::auth_operations::TokenCreateRequest;

// Preferred: use the TokenCreateRequest builder
let token = auth.tokens().create_token(
    TokenCreateRequest::new(&user_id, "jwt")
        .scope("read")
        .scope("write")
).await?;

// Alternative: positional parameters (less readable for optional args)
// let token = auth.tokens().create(&user_id, ["read", "write"], "jwt", None).await?;

println!("Access Token: {}", token.access_token);
println!("Refresh Token: {:?}", token.refresh_token);

// Validate a token
let is_valid = auth.tokens().validate(&token).await?;
assert!(is_valid);

// Refresh an expired token
let refreshed = auth.tokens().refresh(&token).await?;
println!("New access token: {}", refreshed.access_token);

// Revoke a token (logout)
auth.tokens().revoke(&refreshed).await?;
```

## Step 5: Manage Sessions

```rust
use auth_framework::auth_operations::SessionCreateRequest;
use std::time::Duration;

// Create a session
let session_id = auth.sessions().create_session(
    SessionCreateRequest::new(&user_id, Duration::from_secs(3600))
        .ip_address("192.168.1.1")
        .user_agent("Mozilla/5.0...")
).await?;

println!("Session ID: {}", session_id);

// Retrieve session
let active = auth.sessions().get(&session_id).await?;

// List only active sessions for a user
use auth_framework::auth_operations::SessionFilter;
let active_sessions = auth.sessions()
    .list_for_user_filtered(&user_id, SessionFilter::ActiveOnly)
    .await?;
println!("Active sessions: {}", active_sessions.len());

// Delete session (logout)
auth.sessions().delete(&session_id).await?;
```

## Step 6: Authorization (Roles & Permissions)

```rust
use auth_framework::permissions::{Permission, Role};

let mut admin = Role::new("admin");
admin.add_permission(Permission::new("documents", "delete"));
auth.authorization().create_role(admin).await?;

// Assign a role to a user
auth.authorization().assign_role(&user_id, "admin").await?;

// Check if user has a role
let is_admin = auth.authorization().has_role(&user_id, "admin").await?;
assert!(is_admin);

// Check a permission using a token
let can_delete = auth.authorization().check(
    &token,
    "delete",
    "documents",
).await?;
assert!(can_delete);
```

## Step 7: Multi-Factor Authentication (Optional)

```rust
// Generate a TOTP secret for a user
let secret = auth.mfa().generate_totp_secret(&user_id).await?;
let provisioning_uri = auth.mfa()
    .generate_totp_qr_url(&user_id, "AuthFramework Demo", &secret)
    .await?;
println!("Scan this QR code: {}", provisioning_uri);
println!("Or enter this secret: {}", secret);

// Verify TOTP code to complete setup
let is_valid = auth.mfa().verify_totp(&user_id, "123456").await?;
println!("TOTP valid: {}", is_valid);

// Generate backup codes
let backup_codes = auth.mfa().generate_backup_codes(&user_id, 10).await?;
println!("Save these backup codes: {:?}", backup_codes);
```

## Step 8: Monitoring & Health

```rust
// Health check
let health = auth.monitoring().health_check().await?;
println!("Subsystems checked: {}", health.len());

// Get metrics (Prometheus format)
let metrics = auth.monitoring().prometheus_metrics().await;
println!("{}", metrics);
```

---

## Web Framework Integration

### Axum (Recommended)

```rust
use auth_framework::AuthFramework;
use axum::{Router, routing::get, extract::State, Json};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = AuthFramework::quick_start()
        .jwt_auth_from_env()
        .build()
        .await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/protected", get(protected))
        .with_state(Arc::new(auth));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health(State(auth): State<Arc<AuthFramework>>) -> &'static str {
    "OK"
}

async fn protected(State(auth): State<Arc<AuthFramework>>) -> Result<String, String> {
    // Token validation happens via middleware or manual extraction
    Ok("You are authenticated!".to_string())
}
```

### Actix-web

Enable the `actix-integration` feature:

```toml
auth-framework = { version = "0.5", features = ["actix-integration"] }
```

See [Web Framework Integration Guide](web-frameworks.md) for full Actix-web, Warp, and Axum patterns.

### Warp

Enable the `warp-integration` feature:

```toml
auth-framework = { version = "0.5", features = ["warp-integration"] }
```

---

## Docker Deployment

```bash
docker run -p 8080:8080 \
  -e JWT_SECRET="your-32-character-secret-key-here!!" \
  -e DATABASE_URL="postgresql://user:pass@host/dbname" \
  ghcr.io/ciresnave/auth-framework:latest
```

See [Docker Deployment Guide](DOCKER_DEPLOYMENT.md) and [Deployment Guide](DEPLOYMENT_GUIDE.md) for production configuration.

---

## Storage Backend Selection

| Backend    | Feature Flag                 | Best For                      |
| ---------- | ---------------------------- | ----------------------------- |
| In-Memory  | *(always available)*         | Development, testing          |
| PostgreSQL | `postgres-storage` (default) | Production (recommended)      |
| SQLite     | `sqlite-storage`             | Single-server, embedded       |
| Redis      | `redis-storage`              | Caching layer, sessions       |
| Tiered     | `tiered-storage`             | PostgreSQL + Redis combined   |

See [Storage Backends Guide](storage-backends.md) for configuration details.

---

## What's Next?

- [Security Configuration Guide](guides/security-configuration.md) — Hardening for production
- [Protocol Configuration Guide](PROTOCOL_CONFIGURATION.md) — Enable OAuth 2.0 server, OIDC, SAML, WebAuthn, and more
- [Web Framework Integration](web-frameworks.md) — Actix-web, Axum, Warp patterns
- [Feature Flags Reference](../FEATURE_FLAGS.md) — All available features
- [HSM Integration](guides/hsm-integration.md) — Hardware security module support
- [Administrator Setup](guides/administrator-setup.md) — Production deployment
