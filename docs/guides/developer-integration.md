# Developer Integration Guide

## Introduction

This guide provides developers with step-by-step instructions for integrating AuthFramework into their applications. AuthFramework is designed to be the premier authentication and authorization solution, offering high performance, comprehensive security, and seamless integration with popular Rust web frameworks.

## Prerequisites

Before integrating AuthFramework, ensure you have:

- **Rust 1.70+** - Latest stable Rust toolchain
- **Cargo** - Rust package manager
- **Web Framework** - Axum, Actix-web, Warp, or Rocket
- **Storage Backend** - PostgreSQL, Redis, or in-memory for development
- **TLS Certificate** - For production HTTPS deployment

## Quick Start

### 1. Add AuthFramework to Your Project

Add AuthFramework to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = { version = "0.4.0", features = ["axum", "postgresql"] }
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
```

Available features:

- **Web Frameworks**: `axum`, `actix-web`, `warp`, `rocket`
- **Storage Backends**: `postgresql`, `redis`, `memory`
- **Authentication Methods**: `jwt`, `oauth2`, `saml`
- **Security Features**: `rate-limiting`, `session-management`, `mfa`

### 2. Basic Configuration

Create a configuration file `auth-config.toml`:

```toml
[server]
host = "127.0.0.1"
port = 8080

[security]
jwt_secret = "${JWT_SECRET}"
jwt_expiry = "1h"
require_https = true

[storage]
type = "postgresql"
url = "${DATABASE_URL}"

[logging]
level = "info"
format = "json"
```

### 3. Initialize AuthFramework

```rust
use auth_framework::{AuthFramework, AuthConfig};
use axum::{Router, routing::get};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = AuthConfig::load()?;

    // Initialize AuthFramework
    let auth = AuthFramework::new(config).await?;

    // Create your application routes
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/protected", get(protected_handler))
        .with_state(auth);

    // Start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

### 4. Add Authentication to Routes

#### Protecting Routes with Authentication

```rust
use auth_framework::extractors::AuthUser;
use axum::{Json, response::Json as ResponseJson};
use serde_json::json;

async fn protected_handler(
    user: AuthUser,
) -> ResponseJson<serde_json::Value> {
    Json(json!({
        "message": "Access granted",
        "user_id": user.id(),
        "username": user.username(),
        "roles": user.roles()
    }))
}
```

#### Login Endpoint

```rust
use auth_framework::{AuthFramework, LoginRequest, AuthError};
use axum::{State, Json, http::StatusCode};

async fn login_handler(
    State(auth): State<AuthFramework>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let result = auth
        .authenticate_user(&request.username, &request.password)
        .await?;

    Ok(Json(LoginResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        expires_in: result.expires_in,
        user: result.user,
    }))
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(serde::Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    user: UserInfo,
}
```

## Advanced Integration

### Multi-Factor Authentication (MFA)

Enable MFA for enhanced security:

```rust
use auth_framework::mfa::{MfaManager, TotpConfig};

// Initialize MFA
let mfa_config = TotpConfig::new("YourApp", "user@example.com");
let mfa = auth.mfa_manager();

// Setup TOTP for user
async fn setup_mfa(
    State(auth): State<AuthFramework>,
    user: AuthUser,
) -> Result<Json<MfaSetupResponse>, AuthError> {
    let mfa = auth.mfa_manager();
    let setup = mfa.setup_totp(&user.id()).await?;

    Ok(Json(MfaSetupResponse {
        qr_code: setup.qr_code_url,
        secret: setup.secret,
        backup_codes: setup.backup_codes,
    }))
}

// Verify MFA during login
async fn verify_mfa(
    State(auth): State<AuthFramework>,
    Json(request): Json<MfaVerifyRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let mfa = auth.mfa_manager();
    let verification = mfa
        .verify_totp(&request.user_id, &request.code)
        .await?;

    if verification.is_valid() {
        let tokens = auth.create_tokens(&request.user_id).await?;
        Ok(Json(LoginResponse::from(tokens)))
    } else {
        Err(AuthError::InvalidMfaCode)
    }
}
```

### Session Management

Implement session-based authentication:

```rust
use auth_framework::session::{SessionManager, SessionConfig};

// Configure sessions
let session_config = SessionConfig::new()
    .with_timeout(Duration::from_hours(24))
    .with_secure_cookies(true)
    .with_same_site_strict();

// Create session middleware
let session_layer = auth.session_layer(session_config);

let app = Router::new()
    .route("/login", post(login_handler))
    .route("/logout", post(logout_handler))
    .route("/profile", get(profile_handler))
    .layer(session_layer);

async fn profile_handler(
    session: Session,
) -> Result<Json<UserProfile>, AuthError> {
    let user_id = session
        .get::<String>("user_id")
        .ok_or(AuthError::NotAuthenticated)?;

    let user = auth.get_user(&user_id).await?;
    Ok(Json(UserProfile::from(user)))
}
```

### Role-Based Authorization

Implement role-based access control:

```rust
use auth_framework::authorization::{Role, Permission, AuthorizeRole};

// Define roles and permissions
#[derive(AuthorizeRole)]
enum UserRole {
    #[role(permissions = ["read", "write"])]
    Admin,
    #[role(permissions = ["read"])]
    User,
    #[role(permissions = [])]
    Guest,
}

// Protect routes with role requirements
async fn admin_handler(
    user: AuthUser,
) -> Result<Json<AdminData>, AuthError> {
    // AuthUser automatically validates required role
    user.require_role(&UserRole::Admin)?;

    let admin_data = get_admin_data().await?;
    Ok(Json(admin_data))
}

// Alternative: Use role extractor
use auth_framework::extractors::RequireRole;

async fn admin_handler_v2(
    _user: RequireRole<UserRole::Admin>,
) -> Json<AdminData> {
    // Route automatically rejects non-admin users
    Json(get_admin_data().await.unwrap())
}
```

### OAuth 2.0 Integration

Integrate with OAuth 2.0 providers:

```rust
use auth_framework::oauth2::{OAuthProvider, OAuthConfig};

// Configure OAuth providers
let oauth_config = OAuthConfig::new()
    .add_provider("google", OAuthProvider::Google {
        client_id: env::var("GOOGLE_CLIENT_ID")?,
        client_secret: env::var("GOOGLE_CLIENT_SECRET")?,
        redirect_uri: "https://yourapp.com/auth/callback",
    })
    .add_provider("github", OAuthProvider::GitHub {
        client_id: env::var("GITHUB_CLIENT_ID")?,
        client_secret: env::var("GITHUB_CLIENT_SECRET")?,
        redirect_uri: "https://yourapp.com/auth/callback",
    });

// OAuth login endpoint
async fn oauth_login(
    State(auth): State<AuthFramework>,
    Path(provider): Path<String>,
) -> Result<Redirect, AuthError> {
    let oauth = auth.oauth_manager();
    let auth_url = oauth.authorization_url(&provider).await?;

    Ok(Redirect::to(&auth_url))
}

// OAuth callback endpoint
async fn oauth_callback(
    State(auth): State<AuthFramework>,
    Path(provider): Path<String>,
    Query(params): Query<OAuthCallback>,
) -> Result<Json<LoginResponse>, AuthError> {
    let oauth = auth.oauth_manager();
    let user_info = oauth
        .exchange_code(&provider, &params.code)
        .await?;

    // Create or update user
    let user = auth
        .get_or_create_oauth_user(&user_info)
        .await?;

    // Generate tokens
    let tokens = auth.create_tokens(&user.id).await?;

    Ok(Json(LoginResponse::from(tokens)))
}
```

## Error Handling

AuthFramework provides comprehensive error handling:

```rust
use auth_framework::{AuthError, AuthErrorKind};
use axum::{response::IntoResponse, http::StatusCode, Json};

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self.kind() {
            AuthErrorKind::NotAuthenticated => {
                (StatusCode::UNAUTHORIZED, "Authentication required")
            },
            AuthErrorKind::AccessDenied => {
                (StatusCode::FORBIDDEN, "Access denied")
            },
            AuthErrorKind::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials")
            },
            AuthErrorKind::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
            },
            AuthErrorKind::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            },
        };

        let body = Json(json!({
            "error": message,
            "code": status.as_u16()
        }));

        (status, body).into_response()
    }
}
```

## Testing

AuthFramework provides testing utilities:

```rust
#[cfg(test)]
mod tests {
    use auth_framework::testing::{TestAuth, MockUser};
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_protected_route() {
        let auth = TestAuth::new().await;
        let user = MockUser::new("test@example.com");

        let app = create_app(auth.clone());
        let server = TestServer::new(app).unwrap();

        // Test without authentication
        let response = server.get("/protected").await;
        assert_eq!(response.status_code(), 401);

        // Test with authentication
        let token = auth.create_test_token(&user).await;
        let response = server
            .get("/protected")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);
    }
}
```

## Performance Optimization

### Connection Pooling

Configure database connection pooling:

```rust
use auth_framework::storage::{PostgreSqlConfig, PoolConfig};

let storage_config = PostgreSqlConfig::new(&database_url)
    .with_pool_config(PoolConfig {
        max_connections: 20,
        min_connections: 5,
        connection_timeout: Duration::from_secs(30),
        idle_timeout: Some(Duration::from_secs(600)),
    });
```

### Caching

Enable Redis caching for improved performance:

```rust
use auth_framework::cache::{RedisCache, CacheConfig};

let cache_config = CacheConfig::new()
    .with_default_ttl(Duration::from_secs(300))
    .with_max_memory_mb(256);

let cache = RedisCache::new(&redis_url, cache_config).await?;
let auth = AuthFramework::new(config)
    .with_cache(cache)
    .build()
    .await?;
```

### Rate Limiting

Configure rate limiting:

```rust
use auth_framework::rate_limit::{RateLimitConfig, RateLimitLayer};

let rate_limit_config = RateLimitConfig::new()
    .with_requests_per_minute(60)
    .with_burst_limit(10);

let rate_limit_layer = RateLimitLayer::new(rate_limit_config);

let app = Router::new()
    .route("/login", post(login_handler))
    .layer(rate_limit_layer);
```

## Security Best Practices

### HTTPS Configuration

Always use HTTPS in production:

```rust
use auth_framework::tls::{TlsConfig, TlsAcceptor};

let tls_config = TlsConfig::new()
    .with_cert_file("cert.pem")
    .with_key_file("key.pem")
    .with_protocols(&["TLSv1.2", "TLSv1.3"]);

let tls_acceptor = TlsAcceptor::new(tls_config)?;

// Use with axum-server
use axum_server::tls_rustls::RustlsConfig;
let rustls_config = RustlsConfig::from_pem_file("cert.pem", "key.pem").await?;

axum_server::bind_rustls("0.0.0.0:443".parse()?, rustls_config)
    .serve(app.into_make_service())
    .await?;
```

### Environment Variables

Use environment variables for sensitive configuration:

```bash
# .env file
JWT_SECRET=your-super-secret-jwt-key-here
DATABASE_URL=postgresql://user:pass@localhost/authdb
REDIS_URL=redis://localhost:6379
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Logging and Monitoring

Configure comprehensive logging:

```rust
use auth_framework::logging::{LoggingConfig, SecurityLogger};

let logging_config = LoggingConfig::new()
    .with_level("info")
    .with_format("json")
    .with_security_events(true);

let logger = SecurityLogger::new(logging_config);

// Log security events
logger.log_login_attempt(&user_id, &source_ip, true).await;
logger.log_rate_limit_exceeded(&source_ip).await;
logger.log_suspicious_activity(&user_id, &details).await;
```

## Next Steps

1. **Read the [Administrator Setup Guide](administrator-setup.md)** for production deployment
2. **Review the [Security Configuration Guide](security-configuration.md)** for security hardening
3. **Check the [API Reference](../api/complete-reference.md)** for detailed API documentation
4. **Explore [Integration Patterns](../api/integration-patterns.md)** for advanced use cases

## Support

- **Documentation**: [docs.authframework.dev](https://docs.authframework.dev)
- **GitHub**: [github.com/authframework/auth-framework](https://github.com/authframework/auth-framework)
- **Community**: [Discord](https://discord.gg/authframework)
- **Issues**: [GitHub Issues](https://github.com/authframework/auth-framework/issues)

---

*AuthFramework v0.4.0 - THE premier authentication and authorization solution*
