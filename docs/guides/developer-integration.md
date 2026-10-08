# Developer Integration Guide

This guide covers how to integrate AuthFramework as a Rust library into your application.
If you are looking to deploy the standalone server binary, see [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) instead.

---

## Prerequisites

- Rust 1.89+ with Cargo
- An async runtime — the examples use [Tokio](https://tokio.rs)
- A database — PostgreSQL is the recommended default storage backend

---

## Step 1 — Add the dependency

```toml
[dependencies]
auth-framework = "0.5.0-rc24"
tokio = { version = "1", features = ["full"] }
```

The default feature set includes PostgreSQL storage, Axum integration, OIDC support, and
enhanced RBAC. No feature flags are required for the common path.

To opt out of specific subsystems:

```toml
# Axum-only, no OIDC
auth-framework = { version = "0.5.0-rc24", default-features = false, features = ["enhanced-rbac", "postgres-storage", "axum-integration"] }
```

See [Cargo.toml](../../Cargo.toml) for the full feature flag reference.

---

## Step 2 — Configure and initialize

```rust
use auth_framework::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3_600))
        .refresh_token_lifetime(Duration::from_secs(7 * 86_400))
        // In production, load from env: std::env::var("JWT_SECRET")?
        .secret("replace-with-a-32-char-random-secret!!".to_string());

    let mut auth = AuthFramework::new(config);
    auth.initialize().await?;

    // auth is now ready to use
    Ok(())
}
```

`AuthFramework::new()` is synchronous. Call `.initialize().await` before serving requests
so that background cleanup tasks are scheduled.

---

## Step 3 — User management

All user operations are available through `auth.users()`:

```rust
// Register a new user — returns the generated user ID
let user_id = auth.users().register("alice", "alice@example.com", "s3cr3t!").await?;

// Check existence
let exists = auth.users().exists_by_username("alice").await?;

// Get full profile
let profile = auth.users().profile(&user_id).await?;

// Update password
auth.users().update_password("alice", "n3wP@ss!").await?;

// Assign roles
auth.users().update_roles(&user_id, &["editor".to_string()]).await?;

// Enable / disable
auth.users().set_status(&user_id, UserStatus::Inactive).await?;

// Delete
auth.users().delete("alice").await?;
```

---

## Step 4 — Token lifecycle

Token operations live under `auth.tokens()`:

```rust
use std::time::Duration;

// Issue a token
let token = auth.tokens()
    .create(&user_id, vec!["read".into(), "write".into()], "jwt", None)
    .await?;

// Validate
let valid: bool = auth.tokens().validate(&token).await?;

// Refresh
let refreshed = auth.tokens().refresh(&token).await?;

// Revoke
auth.tokens().revoke(&token).await?;

// API keys
let api_key = auth.tokens().create_api_key(&user_id, Some(Duration::from_secs(30 * 86_400))).await?;
let info    = auth.tokens().validate_api_key(&api_key).await?;
auth.tokens().revoke_api_key(&api_key).await?;
```

---

## Step 5 — Authorization

Permission checks and role management live under `auth.authorization()`:

```rust
// Check whether a token grants access
let allowed = auth.authorization().check(&token, "write", "documents").await?;

// Grant / revoke direct permissions
auth.authorization().grant(&user_id, "read", "reports").await?;
auth.authorization().revoke(&user_id, "read", "reports").await?;

// Role management
use auth_framework::permissions::Role;
auth.authorization().create_role(Role::new("editor")).await?;
auth.authorization().assign_role(&user_id, "editor").await?;
auth.authorization().remove_role(&user_id, "editor").await?;
```

---

## Step 6 — Session management

Session operations live under `auth.sessions()`:

```rust
use std::time::Duration;

let session_id = auth.sessions()
    .create(&user_id, Duration::from_secs(86_400), Some("192.168.1.1".into()), None)
    .await?;

let session = auth.sessions().get(&session_id).await?;

auth.sessions().delete(&session_id).await?;

// Periodic cleanup of expired sessions
auth.sessions().cleanup_expired().await?;
```

---

## Step 7 — Axum integration

AuthFramework ships a first-class Axum integration in the `axum-integration` feature
(on by default). The `AuthenticatedUser` extractor validates the `Authorization: Bearer`
header on every request automatically.

```rust
use auth_framework::prelude::*;
use auth_framework::integrations::axum::AuthenticatedUser;
use axum::{Router, routing::get, Json, extract::State, http::StatusCode};
use std::sync::Arc;

type AppState = Arc<AuthFramework>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new()
        .secret(std::env::var("JWT_SECRET")?);
    let mut auth = AuthFramework::new(config);
    auth.initialize().await?;

    let state: AppState = Arc::new(auth);

    let app = Router::new()
        .route("/profile", get(profile_handler))
        .route("/admin",   get(admin_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Any authenticated user can reach this handler.
async fn profile_handler(
    user: AuthenticatedUser,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.user_id,
        "roles": user.roles,
    }))
}

/// Only users whose token grants the "admin" role.
async fn admin_handler(
    State(auth): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !user.roles.contains(&"admin".to_string()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let health = auth.monitoring().health_check().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "healthy": health.is_healthy })))
}
```

---

## Step 8 — Multi-factor authentication

MFA operations live under `auth.mfa()`:

```rust
// Generate a TOTP secret and QR URL (show the QR code to the user)
let secret = auth.mfa().generate_totp_secret(&user_id).await?;
let qr_url = auth.mfa().generate_totp_qr_url(&user_id, "MyApp", &secret).await?;

// After the user scans and enters the confirmation code:
let ok = auth.mfa().verify_totp(&user_id, &code).await?;

// Backup codes
let codes = auth.mfa().generate_backup_codes(&user_id, 10).await?;
```

---

## Step 9 — Health and monitoring

```rust
let health   = auth.monitoring().health_check().await?;
let perf     = auth.monitoring().performance_metrics().await?;
let security = auth.monitoring().security_metrics().await?;

// Prometheus-format scrape endpoint
let prometheus_text = auth.monitoring().prometheus_metrics().await?;
```

---

## Further reading

- [Security Configuration Guide](security-configuration.md)
- [Custom Storage Implementation](custom-storage-implementation.md)
- [Feature Flags Reference (Cargo.toml)](../../Cargo.toml) — see the `[features]` section
- [Project Roadmap](../ROADMAP.md)
- [Administrator Setup Guide](administrator-setup.md)
