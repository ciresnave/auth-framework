# Feature Flags Guide

AuthFramework uses Cargo feature flags to control optional functionality. This document explains each feature, its purpose, and when to use it.

## Default Features

The following features are enabled by default when you add `auth-framework` to your `Cargo.toml`:

| Feature            | Purpose                                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------------------- |
| `enhanced-rbac`    | Enterprise role-based access control with the `role-system` crate, plus the `api-server` (Axum HTTP) layer |
| `postgres-storage` | PostgreSQL storage backend via `sqlx` and `tokio-postgres`                                                 |

This default set gives you a fully functional auth server with persistent storage and comprehensive authorization out of the box.

## Feature Tiers

### Core (Always Compiled)

These capabilities are always available regardless of feature flags:

- Token management (JWT creation, validation, rotation)
- In-memory storage (`MemoryStorage` / `DashMapStorage`)
- Password hashing (bcrypt, argon2)
- Rate limiting (governor)
- Session management
- MFA support (TOTP, backup codes)
- Error types and storage traits
- Security utilities (secure JWT validation, PBKDF2)

### Storage Backends

| Feature            | Dependencies                | Description                                 |
| ------------------ | --------------------------- | ------------------------------------------- |
| `postgres-storage` | `sqlx`, `tokio-postgres`    | PostgreSQL storage (default)                |
| `sqlite-storage`   | `sqlx`                      | SQLite storage for development/embedded use |
| `mysql-storage`    | `sqlx`                      | MySQL/MariaDB storage                       |
| `redis-storage`    | `redis`                     | Redis storage for caching and sessions      |
| `tiered-storage`   | `postgres-storage`, `redis` | Combined PostgreSQL + Redis tiered storage  |

### Authentication Methods

| Feature                | Dependencies                                                            | Description                          |
| ---------------------- | ----------------------------------------------------------------------- | ------------------------------------ |
| `ldap-auth`            | `ldap3`                                                                 | LDAP/Active Directory authentication |
| `otp-auth`             | `otpauth`                                                               | One-time password authentication     |
| `passkeys`             | `coset`, `passkey`, `passkey-client`                                    | WebAuthn/FIDO2 passkey support       |
| `saml`                 | `bergshamra`, `p256`, `p384`, `quick-xml`                               | SAML 2.0 SP and IdP support          |
| `enhanced-device-flow` | `oauth-device-flows`                                                    | OAuth 2.0 Device Authorization Grant |
| `smskit`               | `sms-core`, `sms-twilio`, `sms-plivo`, `sms-web-generic`               | SMS-based MFA via SMSKit             |
| `openid-connect`       | `openidconnect`                                                         | OpenID Connect client support        |

### Web Framework Integrations

| Feature             | Dependencies                                                | Description                       |
| ------------------- | ----------------------------------------------------------- | --------------------------------- |
| `api-server`        | `axum`, `tower`, `tower-http`                               | Built-in Axum HTTP API server     |
| `axum-integration`  | `axum`, `tower`, `tower-http`, `serde_urlencoded`           | Axum middleware and extractors    |
| `actix-integration` | `actix-web`, `futures-util`                                 | Actix-web middleware              |
| `warp-integration`  | `warp`                                                      | Warp filter integration           |
| `web-gui`           | `askama`, `axum`, `tower`, `tower-http`, `serde_urlencoded` | Admin web GUI (HTML dashboard)    |
| `smskit-web-axum`   | `axum-integration`, `sms-web-axum`, `smskit`                | SMSKit webhook endpoints for Axum |

### Tooling & Administration

| Feature        | Dependencies                                                                          | Description                                     |
| -------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `cli`          | `clap`, `colored`, `console`, `dialoguer`, `indicatif`, `rpassword`, `tokio-postgres` | Command-line interface for user/role management |
| `tui`          | `ratatui`, `crossterm`, `tui-input`, `colored`, `console`, `indicatif`                | Terminal UI dashboard                           |
| `admin-binary` | `cli`, `tui`, `web-gui`                                                               | Full admin binary with CLI, TUI, and web GUI    |

### Advanced / Enterprise

| Feature                     | Dependencies                                                                                                          | Description                                                   |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `enhanced-rbac`             | `api-server`, `role-system`                                                                                           | Enterprise RBAC with role hierarchy and permission management |
| `enhanced-crypto`           | `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`                                                                   | Additional cryptographic algorithms                           |
| `fips-compliance`           | `aws-lc-rs`                                                                                                           | FIPS 140-2 compliant cryptography via AWS-LC                  |
| `distributed-rate-limiting` | `redis`                                                                                                               | Distributed rate limiting across multiple nodes               |
| `enhanced-observability`    | `opentelemetry`, `opentelemetry-otlp`, `opentelemetry-prometheus`, `tracing-opentelemetry`, `tokio-stream`, `futures` | OpenTelemetry metrics and traces                              |
| `performance-optimization`  | `bumpalo`, `metrics`, `metrics-prometheus`, `object-pool`, `prometheus`                                               | Arena allocation, metrics collection, object pooling          |
| `event-sourcing`            | `futures`, `notify`, `tokio-stream`                                                                                   | Event sourcing and change data capture                        |
| `config-hot-reload`         | `notify`                                                                                                              | File-system-based configuration hot reloading                 |
| `unicode-support`           | `unicode-normalization`                                                                                               | Unicode normalization for usernames and identifiers           |

### Testing & Development

| Feature        | Dependencies     | Description                                  |
| -------------- | ---------------- | -------------------------------------------- |
| `testing`      | (none)           | Enables test utilities and `TestEnvironment` |
| `docker-tests` | `testcontainers` | Integration tests using Docker containers    |

## Common Deployment Profiles

### Minimal (embedded / library use)

```toml
[dependencies]
auth-framework = { version = "0.5", default-features = false }
```

Gives you the core library with in-memory storage, JWT tokens, password hashing,
rate limiting, and the non-optional protocol/runtime components. Optional SQL
backends, admin surfaces, and web framework integrations stay disabled.

### Default (recommended for most deployments)

```toml
[dependencies]
auth-framework = "0.5"
```

Adds PostgreSQL storage and enterprise RBAC with a built-in API server.

### SQLite Development Server

```toml
[dependencies]
auth-framework = { version = "0.5", default-features = false, features = ["sqlite-storage", "api-server"] }
```

### Full-Featured Production

```toml
[dependencies]
auth-framework = { version = "0.5", features = [
    "redis-storage",
    "ldap-auth",
    "saml",
    "passkeys",
    "enhanced-observability",
    "config-hot-reload",
] }
```

### FIPS-Compliant Deployment

```toml
[dependencies]
auth-framework = { version = "0.5", features = ["fips-compliance", "enhanced-crypto"] }
```

## Notes

- The `role-system` dependency is pulled in automatically by `enhanced-rbac`
- Storage features are mutually compatible — you can enable multiple backends
- `admin-binary` is a convenience feature that bundles `cli`, `tui`, and `web-gui`
- All web framework integrations (`axum-integration`, `actix-integration`, `warp-integration`) are independent and can be enabled alongside each other
