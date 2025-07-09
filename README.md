# Auth Framework

A comprehensive authentication and authorization framework for Rust applications.

## Features

- **Multiple Authentication Methods**: OAuth, JWT, API keys, password-based authentication
- **Token Management**: Issuance, validation, refresh, and revocation
- **Permission System**: Role-based access control with fine-grained permissions
- **Multi-Factor Authentication**: Support for TOTP, SMS, email, and hardware keys
- **Session Management**: Secure session handling with expiration
- **Rate Limiting**: Built-in protection against brute force attacks
- **Audit Logging**: Comprehensive logging of authentication events
- **Storage Backends**: In-memory, Redis, PostgreSQL, MySQL support
- **Middleware**: Easy integration with web frameworks
- **Distributed**: Cross-node authentication validation

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use auth_framework::{AuthFramework, AuthConfig};
use auth_framework::methods::JwtMethod;
use auth_framework::storage::MemoryStorage;
use std::time::Duration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the auth framework
    let config = AuthConfig::new()
        .token_lifetime(Duration::from_secs(3600))
        .refresh_token_lifetime(Duration::from_secs(86400 * 7));
    
    // Create storage
    let storage = Arc::new(MemoryStorage::new());
    
    // Create the auth framework
    let mut auth = AuthFramework::new(config, storage);
    
    // Register a JWT authentication method
    let jwt_method = JwtMethod::new()
        .secret_key("your-secret-key")
        .issuer("your-service");
    
    auth.register_method("jwt", Box::new(jwt_method));
    
    // Initialize the framework
    auth.initialize().await?;
    
    // Create a JWT token for testing
    let token = auth.create_auth_token(
        "user123",
        vec!["read".to_string(), "write".to_string()],
        "jwt",
        None,
    ).await?;
    
    // Validate the token
    if auth.validate_token(&token).await? {
        println!("Token is valid!");
        
        // Check permissions
        if auth.check_permission(&token, "read", "documents").await? {
            println!("User has permission to read documents");
        }
    }
    
    Ok(())
}
```

### OAuth Authentication

```rust
use auth_framework::methods::OAuth2Method;
use auth_framework::providers::OAuthProvider;

// Set up OAuth with GitHub
let oauth_method = OAuth2Method::new()
    .provider(OAuthProvider::GitHub)
    .client_id("your-github-client-id")
    .client_secret("your-github-client-secret")
    .redirect_uri("https://your-app.com/auth/callback");

auth.register_method("github", Box::new(oauth_method));

// Generate authorization URL
let (auth_url, state, pkce) = oauth_method.authorization_url()?;
println!("Visit: {}", auth_url);

// After user authorizes, exchange code for token
let credential = auth_framework::credentials::Credential::oauth_code("authorization-code-from-callback");
let result = auth.authenticate("github", credential).await?;

match result {
    auth_framework::AuthResult::Success(token) => {
        println!("GitHub authentication successful!");
        let user_info = auth.get_user_info(&token).await?;
        println!("Welcome, {}!", user_info.name.unwrap_or("User".to_string()));
    }
    _ => println!("Authentication failed"),
}
```

### API Key Authentication

```rust
use auth_framework::methods::ApiKeyMethod;

// Set up API key authentication
let api_key_method = ApiKeyMethod::new()
    .key_prefix("ak_")
    .header_name("X-API-Key");

auth.register_method("api-key", Box::new(api_key_method));

// Create an API key for a user
let api_key = auth.create_api_key("user123", Some(Duration::from_secs(86400 * 30))).await?;
println!("New API key: {}", api_key);

// Authenticate with API key
let credential = auth_framework::credentials::Credential::api_key(&api_key);
let result = auth.authenticate("api-key", credential).await?;
```

### Multi-Factor Authentication

```rust
// Enable MFA in configuration
let config = AuthConfig::new()
    .enable_multi_factor(true);

// Authentication with MFA
let credential = auth_framework::credentials::Credential::password("username", "password");
let result = auth.authenticate("password", credential).await?;

match result {
    auth_framework::AuthResult::MfaRequired(challenge) => {
        println!("MFA required. Challenge ID: {}", challenge.id());
        
        // User provides MFA code
        let mfa_code = "123456";
        let token = auth.complete_mfa(challenge, mfa_code).await?;
        println!("MFA successful!");
    }
    auth_framework::AuthResult::Success(token) => {
        println!("Direct authentication successful!");
    }
    auth_framework::AuthResult::Failure(reason) => {
        println!("Authentication failed: {}", reason);
    }
}
```

### Permission Management

```rust
use auth_framework::permissions::{Permission, Role, PermissionChecker};

// Permission checking is built into the AuthFramework
// Create a test token first
let token = auth.create_auth_token(
    "user123",
    vec!["read".to_string(), "write".to_string()],
    "jwt",
    None,
).await?;

// Check permissions
let can_read = auth.check_permission(&token, "read", "documents").await?;
let can_write = auth.check_permission(&token, "write", "documents").await?;
let can_delete = auth.check_permission(&token, "delete", "documents").await?;

println!("Can read: {}, Can write: {}, Can delete: {}", can_read, can_write, can_delete);
```

### Storage Configuration

#### Redis Storage

```rust
use auth_framework::config::{AuthConfig, StorageConfig};

let config = AuthConfig::new()
    .storage(StorageConfig::Redis {
        url: "redis://localhost:6379".to_string(),
        key_prefix: "auth:".to_string(),
    });
```

#### Custom Storage

```rust
use auth_framework::storage::AuthStorage;
use auth_framework::tokens::AuthToken;

#[derive(Clone)]
struct MyCustomStorage;

#[async_trait::async_trait]
impl AuthStorage for MyCustomStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        // Your custom storage implementation
        Ok(())
    }
    
    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        // Your implementation
        Ok(None)
    }
    
    async fn delete_token(&self, token_id: &str) -> Result<()> {
        // Your implementation
        Ok(())
    }
    
    // Implement other required methods...
}

// Use your custom storage
let storage = Arc::new(MyCustomStorage);
let auth = AuthFramework::new(config, storage);
```

### Rate Limiting

```rust
use auth_framework::config::RateLimitConfig;

let config = AuthConfig::new()
    .rate_limiting(RateLimitConfig::new(
        100, // max requests
        Duration::from_secs(60), // per minute
    ));
```

### Middleware Integration

#### Axum Integration

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

async fn auth_middleware(
    State(auth): State<Arc<AuthFramework>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    
    if let Some(token_str) = auth_header {
        // In a real implementation, you'd need to parse the token string back to AuthToken
        // This is simplified for demonstration
        if token_str.starts_with("valid_") {
            return Ok(next.run(request).await);
        }
    }
    
    Err(StatusCode::UNAUTHORIZED)
}
```

#### Actix Web Integration

```rust
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;

async fn auth_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, Error> {
    let auth = req.app_data::<web::Data<AuthFramework>>().unwrap();
    
    if let Ok(Some(token)) = auth.storage.get_token_by_access_token(credentials.token()).await {
        if auth.validate_token(&token).await.unwrap_or(false) {
            req.extensions_mut().insert(token);
            return Ok(req);
        }
    }
    
    Err(AuthError::auth_method("bearer", "Invalid token").into())
}
```

## Configuration

### Full Configuration Example

```rust
use auth_framework::config::*;

let config = AuthConfig::new()
    .token_lifetime(Duration::from_secs(3600))
    .refresh_token_lifetime(Duration::from_secs(86400 * 7))
    .enable_multi_factor(true)
    .storage(StorageConfig::Redis {
        url: "redis://localhost:6379".to_string(),
        key_prefix: "auth:".to_string(),
    })
    .rate_limiting(RateLimitConfig::new(100, Duration::from_secs(60)))
    .security(SecurityConfig::secure())
    .audit(AuditConfig {
        enabled: true,
        log_success: true,
        log_failures: true,
        log_permissions: true,
        log_tokens: false,
        storage: AuditStorage::Tracing,
    });
```

## Security Considerations

1. **Secret Management**: Never hardcode secrets. Use environment variables or secure vaults.
2. **Token Storage**: Use secure storage backends in production (Redis, PostgreSQL).
3. **HTTPS**: Always use HTTPS in production to protect tokens in transit.
4. **Rate Limiting**: Enable rate limiting to prevent brute force attacks.
5. **Token Expiration**: Set appropriate token lifetimes based on your security requirements.
6. **Audit Logging**: Enable comprehensive audit logging for security monitoring.

## Examples

See the `examples/` directory for complete examples:

- `basic.rs` - Basic authentication setup (working)
- `oauth.rs` - OAuth integration (working)

Additional examples (currently being updated):

- `api_keys.rs` - API key management
- `mfa.rs` - Multi-factor authentication
- `permissions.rs` - Advanced permission management
- `middleware.rs` - Web framework integration
- `benchmarks.rs` - Performance benchmarks
- `security_audit.rs` - Security features demonstration

**Note**: Some examples are currently being updated to match the latest API.
The `basic.rs` and `oauth.rs` examples are fully functional.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our development process, coding standards, and how to submit pull requests.

## Security

Security is our top priority. Please review our [Security Policy](SECURITY.md) for:

- Reporting security vulnerabilities
- Security best practices
- Supported versions
- Compliance information

For security issues, please email [security@example.com](mailto:security@example.com) instead of using the issue tracker.

## License

This project is licensed under the MIT OR Apache-2.0 license.
