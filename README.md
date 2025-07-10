# Auth Framework

A comprehensive authentication and authorization framework for Rust applications.

## 🆕 What's New in v0.2.0

Based on community feedback, v0.2.0 introduces significant improvements:

- **🔧 Device Flow Support** - Dedicated device flow authentication for CLI apps and IoT devices
- **📚 Enhanced Documentation** - Comprehensive examples and clear API guidance  
- **🎯 Improved API Clarity** - Better relationship between credentials and authentication methods
- **⚙️ Streamlined Provider Config** - Predefined settings for popular OAuth providers (GitHub, Google, etc.)
- **👤 Standardized User Profiles** - Unified `UserProfile` type across all providers
- **🧪 Testing Utilities** - Mock implementations and helpers for easier testing
- **🚨 Better Error Handling** - Specific error types for device flow, OAuth, and authentication scenarios
- **💻 CLI Integration** - Helper utilities for command-line applications
- **📋 Token Persistence** - Built-in mechanisms for secure token storage and retrieval

**Breaking Changes**: This version includes API improvements that may require minor updates to existing code.

## Features

- **Multiple Authentication Methods**: OAuth, JWT, API keys, password-based authentication
- **Enhanced Device Flow**: Optional integration with [`oauth-device-flows`](https://crates.io/crates/oauth-device-flows) for robust CLI and IoT authentication
- **Token Management**: Issuance, validation, refresh, and revocation
- **Permission System**: Role-based access control with fine-grained permissions
- **Multi-Factor Authentication**: Support for TOTP, SMS, email, and hardware keys
- **Session Management**: Secure session handling with expiration
- **Rate Limiting**: Built-in protection against brute force attacks
- **Audit Logging**: Comprehensive logging of authentication events
- **Storage Backends**: In-memory, Redis, PostgreSQL, MySQL support
- **Middleware**: Easy integration with web frameworks
- **Distributed**: Cross-node authentication validation

### 🆕 Enhanced Device Flow (Optional)

For advanced device flow authentication, enable the `enhanced-device-flow` feature to leverage the specialized [`oauth-device-flows`](https://crates.io/crates/oauth-device-flows) crate:

```toml
[dependencies]
auth-framework = { version = "0.2.0", features = ["enhanced-device-flow"] }
```

This provides:
- ✅ **QR code generation** for mobile authentication
- ✅ **Robust polling** with exponential backoff
- ✅ **Automatic token refresh** and lifecycle management
- ✅ **Multiple OAuth providers** (GitHub, Google, Microsoft, GitLab)
- ✅ **Minimal dependencies** suitable for embedded use

See [`OAUTH_DEVICE_FLOWS_INTEGRATION.md`](OAUTH_DEVICE_FLOWS_INTEGRATION.md) for detailed integration guide.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = "0.2.0"
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

### Device Flow Authentication

Device flow is perfect for CLI applications, IoT devices, or any scenario where the user authenticates on a different device than where the application is running.

```rust
use auth_framework::{
    AuthFramework, AuthConfig, Credential,
    methods::OAuth2Method,
    providers::{OAuthProvider, DeviceAuthorizationResponse},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up auth framework
    let config = AuthConfig::new();
    let mut auth = AuthFramework::new(config);
    
    // Configure OAuth for device flow
    let oauth_method = OAuth2Method::new()
        .provider(OAuthProvider::GitHub)
        .client_id("your-client-id")
        .client_secret("your-client-secret");
    
    auth.register_method("github", Box::new(oauth_method));
    auth.initialize().await?;
    
    // Step 1: Request device authorization
    // (In a real implementation, this would make an HTTP request)
    let device_auth = DeviceAuthorizationResponse {
        device_code: "device_code_from_provider".to_string(),
        user_code: "USER-CODE".to_string(),
        verification_uri: "https://github.com/login/device".to_string(),
        verification_uri_complete: None,
        interval: 5,
        expires_in: 900,
    };
    
    // Step 2: Show instructions to user
    println!("Visit: {}", device_auth.verification_uri);
    println!("Enter code: {}", device_auth.user_code);
    
    // Step 3: Poll for authorization (simplified)
    let credential = Credential::Custom {
        method: "device_code".to_string(),
        data: {
            let mut data = std::collections::HashMap::new();
            data.insert("device_code".to_string(), device_auth.device_code);
            data.insert("client_id".to_string(), "your-client-id".to_string());
            data
        }
    };
    
    // Poll until user completes authorization
    loop {
        match auth.authenticate("github", credential.clone()).await? {
            auth_framework::AuthResult::Success(token) => {
                println!("Success! Access token: {}", token.access_token);
                break;
            }
            auth_framework::AuthResult::Failure(reason) => {
                if reason.contains("authorization_pending") {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                } else {
                    eprintln!("Authentication failed: {}", reason);
                    break;
                }
            }
            _ => {
                eprintln!("Unexpected result");
                break;
            }
        }
    }
    
    Ok(())
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

- `basic.rs` - Basic authentication setup (✅ working)
- `oauth.rs` - OAuth integration (✅ working)
- `device_flow.rs` - Device flow authentication for CLI apps (✅ working)

Additional examples (currently being updated):

- `api_keys.rs` - API key management
- `mfa.rs` - Multi-factor authentication
- `permissions.rs` - Advanced permission management
- `middleware.rs` - Web framework integration
- `benchmarks.rs` - Performance benchmarks
- `security_audit.rs` - Security features demonstration

**Note**: The basic, OAuth, and device flow examples are fully functional and demonstrate core features.
Additional examples are being updated to match the latest API.

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

### Testing Your Authentication Code

The framework provides comprehensive testing utilities to make testing your authentication logic easy:

```toml
[dev-dependencies]
auth-framework = { version = "0.2.0", features = ["testing"] }
```

```rust
use auth_framework::{
    testing::{MockAuthMethod, MockStorage, helpers},
    AuthFramework, AuthConfig, Credential,
};

#[tokio::test]
async fn test_user_authentication() {
    // Create a test auth framework
    let mut auth = helpers::create_test_auth_framework();
    
    // Set up a mock authentication method
    let mock_method = MockAuthMethod::new_success()
        .with_user("testuser".to_string(), helpers::create_test_user_profile("testuser"));
    
    auth.register_method("mock", Box::new(mock_method));
    auth.initialize().await.unwrap();
    
    // Test authentication
    let credential = Credential::password("testuser", "password");
    let result = auth.authenticate("mock", credential).await.unwrap();
    
    match result {
        auth_framework::AuthResult::Success(token) => {
            assert_eq!(token.user_id, "testuser");
            assert!(token.scopes.contains(&"read".to_string()));
        }
        _ => panic!("Expected successful authentication"),
    }
}

#[tokio::test]
async fn test_authentication_failure() {
    let mut auth = helpers::create_test_auth_framework();
    
    // Mock method that always fails
    let mock_method = MockAuthMethod::new_failure();
    auth.register_method("mock", Box::new(mock_method));
    auth.initialize().await.unwrap();
    
    let credential = Credential::password("testuser", "wrong_password");
    let result = auth.authenticate("mock", credential).await.unwrap();
    
    match result {
        auth_framework::AuthResult::Failure(_) => {
            // Expected
        }
        _ => panic!("Expected authentication failure"),
    }
}

#[tokio::test]
async fn test_token_storage() {
    let storage = MockStorage::new();
    let token = helpers::create_test_token("testuser");
    
    // Store and retrieve token
    storage.store_token(&token).await.unwrap();
    let retrieved = storage.get_token(&token.id).await.unwrap();
    
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().user_id, "testuser");
}
```

**Testing Features:**

- `MockAuthMethod` - Configurable mock authentication
- `MockStorage` - In-memory storage for testing
- `helpers::create_test_*` - Helper functions for test data
- Configurable delays and failures for testing edge cases
- Comprehensive test coverage examples

## Error Handling

The framework provides specific error types for better error handling:

```rust
use auth_framework::{AuthError, DeviceFlowError, OAuthProviderError};

async fn handle_auth_errors() {
    // Device flow specific errors
    match some_device_flow_operation().await {
        Err(AuthError::DeviceFlow(DeviceFlowError::AuthorizationPending)) => {
            println!("User hasn't completed authorization yet");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::SlowDown)) => {
            println!("Polling too frequently, slowing down");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::ExpiredToken)) => {
            println!("Device code expired, need to restart flow");
        }
        Err(AuthError::DeviceFlow(DeviceFlowError::AccessDenied)) => {
            println!("User denied authorization");
        }
        _ => {}
    }
    
    // OAuth provider specific errors
    match some_oauth_operation().await {
        Err(AuthError::OAuthProvider(OAuthProviderError::InvalidAuthorizationCode)) => {
            println!("Authorization code is invalid or expired");
        }
        Err(AuthError::OAuthProvider(OAuthProviderError::InsufficientScope { required, granted })) => {
            println!("Insufficient permissions: need '{}', got '{}'", required, granted);
        }
        Err(AuthError::OAuthProvider(OAuthProviderError::RateLimited { message })) => {
            println!("Rate limited by provider: {}", message);
        }
        _ => {}
    }
    
    // General auth errors
    match some_auth_operation().await {
        Err(AuthError::InvalidCredential { credential_type, message }) => {
            println!("Invalid {}: {}", credential_type, message);
        }
        Err(AuthError::Timeout { timeout_seconds }) => {
            println!("Operation timed out after {} seconds", timeout_seconds);
        }
        Err(AuthError::ProviderNotConfigured { provider }) => {
            println!("Provider '{}' is not configured", provider);
        }
        _ => {}
    }
}
```

## Provider Configuration

Simplified provider setup with sensible defaults:

```rust
use auth_framework::{AuthFramework, providers::{OAuthProvider, UserProfile}};

// GitHub with default scopes and settings
let github_method = OAuth2Method::new()
    .provider(OAuthProvider::GitHub) // Automatically includes user:email scope
    .client_id("your-github-client-id")
    .client_secret("your-github-client-secret");

// Google with default profile scopes
let google_method = OAuth2Method::new()
    .provider(OAuthProvider::Google) // Includes profile, email scopes
    .client_id("your-google-client-id")
    .client_secret("your-google-client-secret");

// Custom provider with full configuration
let custom_method = OAuth2Method::new()
    .provider(OAuthProvider::Custom {
        name: "My Provider".to_string(),
        config: OAuthProviderConfig {
            authorization_url: "https://auth.example.com/authorize".to_string(),
            token_url: "https://auth.example.com/token".to_string(),
            device_authorization_url: Some("https://auth.example.com/device".to_string()),
            userinfo_url: Some("https://auth.example.com/userinfo".to_string()),
            revocation_url: Some("https://auth.example.com/revoke".to_string()),
            default_scopes: vec!["read".to_string(), "profile".to_string()],
            supports_pkce: true,
            supports_refresh: true,
            supports_device_flow: true,
            additional_params: HashMap::new(),
        },
    })
    .client_id("your-client-id")
    .client_secret("your-client-secret");
```

## User Profile Standardization

The framework provides a standardized `UserProfile` type that works across all providers:

```rust
use auth_framework::providers::UserProfile;

// Creating user profiles
let profile = UserProfile::new("user123", "github")
    .with_name("John Doe")
    .with_email("john@example.com")
    .with_email_verified(true)
    .with_picture("https://github.com/avatar.jpg")
    .with_locale("en-US")
    .with_additional_data("github_login".to_string(), serde_json::Value::String("johndoe".to_string()));

// Converting to your application's user type
#[derive(serde::Deserialize)]
struct AppUser {
    id: String,
    name: String,
    email: String,
    avatar_url: Option<String>,
}

impl From<UserProfile> for AppUser {
    fn from(profile: UserProfile) -> Self {
        Self {
            id: profile.id,
            name: profile.name.unwrap_or_default(),
            email: profile.email.unwrap_or_default(),
            avatar_url: profile.picture,
        }
    }
}

// Usage
let app_user: AppUser = user_profile.into();
```

## Credential Types Guide

Understanding the relationship between credentials and authentication methods:

```rust
use auth_framework::Credential;

// Password credentials -> PasswordMethod
let password_cred = Credential::password("username", "password");

// OAuth authorization code -> OAuth2Method
let oauth_cred = Credential::oauth_code("authorization_code_from_callback");

// OAuth refresh token -> OAuth2Method (for token refresh)
let refresh_cred = Credential::oauth_refresh("refresh_token_string");

// API key -> ApiKeyMethod
let api_key_cred = Credential::api_key("your_api_key_here");

// JWT token -> JwtMethod
let jwt_cred = Credential::jwt("jwt.token.string");

// Device code (for device flow) -> OAuth2Method with device flow
let device_cred = Credential::Custom {
    method: "device_code".to_string(),
    data: {
        let mut data = HashMap::new();
        data.insert("device_code".to_string(), "device_code_string".to_string());
        data.insert("client_id".to_string(), "your_client_id".to_string());
        data
    }
};

// Multi-factor authentication
let mfa_cred = Credential::Mfa {
    primary_credential: Box::new(password_cred),
    mfa_code: "123456".to_string(),
    challenge_id: "mfa_challenge_id".to_string(),
};

// Custom credentials for custom auth methods
let custom_cred = Credential::Custom {
    method: "custom_auth".to_string(),
    data: {
        let mut data = HashMap::new();
        data.insert("token".to_string(), "custom_token".to_string());
        data.insert("signature".to_string(), "signature_string".to_string());
        data
    }
};
```

## CLI Integration

Helper utilities for integrating with CLI frameworks:

```toml
[dependencies]
auth-framework = "0.2.0"
clap = "4.0"
tokio = { version = "1.0", features = ["full"] }
```

```rust
use auth_framework::{AuthFramework, AuthConfig, Credential};
use clap::{Arg, Command};

fn create_auth_command() -> Command {
    Command::new("myapp")
        .subcommand(
            Command::new("auth")
                .about("Authenticate with OAuth provider")
                .arg(
                    Arg::new("provider")
                        .short('p')
                        .long("provider")
                        .value_name("PROVIDER")
                        .help("OAuth provider (github, google, microsoft)")
                        .default_value("github")
                )
                .arg(
                    Arg::new("client-id")
                        .long("client-id")
                        .value_name("CLIENT_ID")
                        .help("OAuth client ID")
                        .env("OAUTH_CLIENT_ID")
                        .required(true)
                )
                .arg(
                    Arg::new("device-flow")
                        .long("device-flow")
                        .help("Use device flow authentication")
                        .action(clap::ArgAction::SetTrue)
                )
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = create_auth_command().get_matches();
    
    if let Some(auth_matches) = matches.subcommand_matches("auth") {
        let provider = auth_matches.get_one::<String>("provider").unwrap();
        let client_id = auth_matches.get_one::<String>("client-id").unwrap();
        let use_device_flow = auth_matches.get_flag("device-flow");
        
        if use_device_flow {
            perform_device_flow_auth(provider, client_id).await?;
        } else {
            perform_web_flow_auth(provider, client_id).await?;
        }
    }
    
    Ok(())
}

async fn perform_device_flow_auth(provider: &str, client_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Starting device flow authentication with {}...", provider);
    
    // Set up auth framework
    let config = AuthConfig::new();
    let mut auth = AuthFramework::new(config);
    
    // Configure OAuth method based on provider
    let oauth_method = match provider {
        "github" => OAuth2Method::new()
            .provider(OAuthProvider::GitHub)
            .client_id(client_id)
            .client_secret(&std::env::var("GITHUB_CLIENT_SECRET")?),
        "google" => OAuth2Method::new()
            .provider(OAuthProvider::Google)
            .client_id(client_id)
            .client_secret(&std::env::var("GOOGLE_CLIENT_SECRET")?),
        _ => return Err("Unsupported provider".into()),
    };
    
    auth.register_method("oauth", Box::new(oauth_method));
    auth.initialize().await?;
    
    // Implement device flow logic here...
    println!("✅ Authentication successful!");
    
    Ok(())
}

async fn perform_web_flow_auth(provider: &str, client_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Starting web flow authentication with {}...", provider);
    
    // Generate authorization URL and open browser
    // Implementation details...
    
    Ok(())
}
```
