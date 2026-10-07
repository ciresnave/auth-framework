# Deployment Guide

This guide covers deploying AuthFramework in production environments.

## Prerequisites

- **Rust** ≥ 1.88 (if building from source)
- A supported storage backend (PostgreSQL recommended for production)
- TLS certificates for all endpoints

## Quick Start

### 1. Add the dependency

```toml
[dependencies]
auth-framework = "0.5"
```

The default feature set includes `enhanced-rbac` and `postgres-storage`, which covers the most common deployment scenario.

### 2. Minimal server configuration

```rust
use std::sync::Arc;

use auth_framework::{
    AuthFramework,
    api::server::{ApiServer, ApiServerConfig},
    config::{AuthConfig, CorsConfig, StorageConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_config = AuthConfig::new()
        .secret(std::env::var("JWT_SECRET")?)
        .storage(StorageConfig::Postgres {
            connection_string: std::env::var("DATABASE_URL")?,
            table_prefix: "auth_".to_string(),
        });

    let mut auth = AuthFramework::new(auth_config);
    auth.initialize().await?;

    // API server
    let config = ApiServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8443,
        cors: CorsConfig::for_origins(["https://app.example.com"]),
        ..Default::default()
    };

    let server = ApiServer::with_config(Arc::new(auth), config);
    server.start().await?;
    Ok(())
}
```

## Storage Backends

### PostgreSQL (recommended)

```bash
export DATABASE_URL="postgres://user:password@localhost:5432/authdb"
```

Feature: `postgres-storage` (default)

### Redis

Used as a caching/session layer alongside a primary database.

```bash
export REDIS_URL="redis://localhost:6379"
```

Feature: `redis-storage`

### In-Memory

Suitable only for development and testing. Data is lost on restart.

```rust
use auth_framework::storage::MemoryStorage;
let storage = MemoryStorage::new();
```

## Security Configuration

### JWT Secrets

> **Critical**: `SecureJwtConfig::default()` generates a random secret per instance.
> For multi-node deployments, **all nodes must share the same `jwt_secret`**.

```bash
# Generate a strong secret (≥64 bytes recommended)
openssl rand -base64 64
```

Set via environment variable:

```bash
export JWT_SECRET="<your-generated-secret>"
```

### TLS

AuthFramework enforces secure defaults — TLS is required for all production endpoints. Configure your reverse proxy (nginx, Caddy, etc.) or use Rust TLS directly:

```bash
export TLS_CERT_PATH="/etc/certs/server.pem"
export TLS_KEY_PATH="/etc/certs/server-key.pem"
```

### CORS

CORS is disabled by default. When enabling it, always specify `cors.allowed_origins` explicitly:

```rust
let config = ApiServerConfig {
    cors: auth_framework::config::CorsConfig::for_origins([
        "https://app.example.com",
        "https://admin.example.com",
    ]),
    ..Default::default()
};
```

**Never** use `*` for origins in production.

## Admin GUI

The web-based admin GUI is available with the `web-gui` feature.

```toml
auth-framework = { version = "0.5", features = ["web-gui"] }
```

Login credentials are configured via environment variables:

```bash
export ADMIN_GUI_USERNAME="admin"
export ADMIN_GUI_PASSWORD="<strong-password>"
```

> **Important**: If `ADMIN_GUI_PASSWORD` is not set, the login endpoint returns 403 (disabled).

## MFA (Multi-Factor Authentication)

MFA is enabled by default. TOTP secrets are stored in the KV backend with the following key patterns:

| Key Pattern                          | Purpose                      | TTL       |
| ------------------------------------ | ---------------------------- | --------- |
| `mfa_secret:{user_id}`               | TOTP shared secret           | Permanent |
| `mfa_enabled:{user_id}`              | MFA status flag              | Permanent |
| `mfa_backup_codes:{user_id}`         | SHA-256 hashed backup codes  | Permanent |
| `mfa_pending_secret:{user_id}`       | Setup-phase temporary secret | 10 min    |
| `mfa_pending_backup_codes:{user_id}` | Setup-phase backup codes     | 10 min    |

## Token Management

### Token Revocation

Revoked tokens are stored in KV:

```text
revoked_token:{jti} → "revoked"   (TTL: 7 days)
```

The `validate_api_token` function checks this key after JWT signature verification.

### User Data Keys

| Key Pattern            | Purpose                   |
| ---------------------- | ------------------------- |
| `user:{user_id}`       | User profile (JSON)       |
| `users:index`          | All user IDs (JSON array) |
| `user:username:{name}` | Username → user ID lookup |
| `user:email:{email}`   | Email → user ID lookup    |

## Feature Flags

### Default Features

The default build includes:

- `enhanced-rbac` — role-based access control
- `postgres-storage` — PostgreSQL backend

### Optional Features

| Feature         | Description                 |
| --------------- | --------------------------- |
| `redis-storage` | Redis caching/sessions      |
| `web-gui`       | Admin web interface         |
| `ldap-auth`     | LDAP/AD integration         |
| `passkeys`      | Passkey/WebAuthn support    |
| `acme`          | ACME certificate management |

### Minimal Build

For resource-constrained environments, disable default features and opt in:

```toml
auth-framework = { version = "0.5", default-features = false, features = ["enhanced-rbac"] }
```

## Multi-Node Deployment

For horizontal scaling:

1. **Shared storage** — All nodes must connect to the same database
2. **Shared JWT secret** — Set `JWT_SECRET` identically on all nodes
3. **Session affinity** — Not required (sessions are stored in the database)
4. **Health checks** — Use the `/health` endpoint

```text
             ┌──────────────┐
             │ Load Balancer │
             └──────┬───────┘
            ┌───────┼───────┐
            ▼       ▼       ▼
        ┌──────┐ ┌──────┐ ┌──────┐
        │Node 1│ │Node 2│ │Node 3│
        └──┬───┘ └──┬───┘ └──┬───┘
           │        │        │
           └────────┼────────┘
                    ▼
            ┌──────────────┐
            │  PostgreSQL  │
            └──────────────┘
```

## Environment Variables Summary

| Variable             | Required         | Description                                   |
| -------------------- | ---------------- | --------------------------------------------- |
| `DATABASE_URL`       | Yes (postgres)   | PostgreSQL connection string                  |
| `REDIS_URL`          | Yes (redis)      | Redis connection string                       |
| `JWT_SECRET`         | Yes (production) | Shared JWT signing secret                     |
| `TLS_CERT_PATH`      | Recommended      | TLS certificate path                          |
| `TLS_KEY_PATH`       | Recommended      | TLS private key path                          |
| `ADMIN_GUI_USERNAME` | Optional         | Admin GUI username                            |
| `ADMIN_GUI_PASSWORD` | Optional         | Admin GUI password (required to enable login) |
| `RUST_LOG`           | Optional         | Log level (e.g., `info`, `debug`)             |

## Monitoring

### Logs

Use `RUST_LOG` to control log verbosity:

```bash
export RUST_LOG="auth_framework=info,tower_http=debug"
```

### Health Check

```bash
curl https://localhost:8443/health
```

## Troubleshooting

### "JWT secret too short"

The JWT secret must meet minimum length requirements. Generate a proper secret:

```bash
openssl rand -base64 64
```

### "Production memory storage" warning

You are using in-memory storage in a production build. Switch to PostgreSQL.

### Connection refused on startup

Ensure the database is running and `DATABASE_URL` is correct. Test connectivity:

```bash
psql "$DATABASE_URL" -c "SELECT 1"
```
