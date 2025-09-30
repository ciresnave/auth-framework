# Third-Party Storage Backend Usage Guide

This guide shows you how to use third-party storage backends with AuthFramework, including the integration patterns and best practices.

## Overview

AuthFramework's builder pattern makes it easy to integrate any storage backend that implements the `AuthStorage` trait. This guide covers the two primary integration methods: the builder API and convenience constructors.

## Integration Methods

### Method 1: Builder Pattern with Custom Storage (Recommended)

The builder pattern provides the most flexibility and follows AuthFramework's fluent API design:

```rust
use auth_framework::{AuthFramework, AuthConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Create your storage backend
    let storage = Arc::new(YourCustomStorage::connect("connection-string").await?);

    // Step 2: Configure AuthFramework
    let mut config = AuthConfig::default();
    config.security.secret_key = Some("your-jwt-secret-32-chars-or-more".to_string());

    // Step 3: Build with custom storage
    let auth = AuthFramework::builder()
        .customize(|c| {
            c.secret = config.security.secret_key;
            c
        })
        .with_storage()
        .custom(storage)  // Pass your storage here
        .done()
        .build()
        .await?;

    // Step 4: Use normally - all operations will use your storage
    println!("AuthFramework initialized with custom storage!");

    Ok(())
}
```

### Method 2: Convenience Constructor

For simpler use cases, use the convenience constructor:

```rust
use auth_framework::{AuthFramework, AuthConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(YourCustomStorage::connect("connection-string").await?);
    let mut config = AuthConfig::default();
    config.security.secret_key = Some("your-jwt-secret-32-chars-or-more".to_string());

    // This returns an initialized AuthFramework instance
    let auth = AuthFramework::new_initialized_with_storage(config, storage).await?;

    println!("AuthFramework ready to use!");

    Ok(())
}
```

## Real-World Examples

### Example 1: SurrealDB Integration

```rust
use auth_framework::{AuthFramework, AuthConfig, errors::Result as AuthResult};
use std::sync::Arc;
use std::time::Duration;

// Assuming you have a SurrealDB storage implementation
use your_surreal_crate::SurrealStorage;

#[derive(Clone)]
pub struct AuthService {
    auth: Arc<AuthFramework>,
}

impl AuthService {
    pub async fn new() -> AuthResult<Self> {
        // Configure SurrealDB connection
        let storage_config = your_surreal_crate::SurrealConfig {
            url: std::env::var("SURREAL_URL")
                .unwrap_or_else(|_| "ws://localhost:8000".to_string()),
            namespace: "production".to_string(),
            database: "authframework".to_string(),
            username: std::env::var("SURREAL_USER").ok(),
            password: std::env::var("SURREAL_PASS").ok(),
        };

        // Create storage backend
        let storage = Arc::new(
            SurrealStorage::new(storage_config)
                .await
                .map_err(|e| auth_framework::errors::AuthError::config(
                    format!("Failed to initialize SurrealDB: {}", e)
                ))?
        );

        // Configure authentication
        let mut config = AuthConfig::default();
        config.security.secret_key = Some(std::env::var("JWT_SECRET").map_err(|_| {
            auth_framework::errors::AuthError::config(
                "JWT_SECRET environment variable is required"
            )
        })?);

        // Build the authentication framework
        let auth = Arc::new(
            AuthFramework::builder()
                .customize(|c| {
                    c.secret = config.security.secret_key.clone();
                    c
                })
                .with_storage()
                .custom(storage)
                .done()
                .build()
                .await?
        );

        Ok(Self { auth })
    }

    pub async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
    ) -> AuthResult<String> {
        // Use the auth framework normally
        let credential = auth_framework::authentication::credentials::Credential::Password {
            username: email.to_string(),
            password: password.to_string(),
        };

        // This will use your SurrealDB backend for all storage operations
        match self.auth.authenticate("password", credential).await? {
            auth_framework::authentication::AuthResult::Success(token) => {
                Ok(token.access_token)
            }
            auth_framework::authentication::AuthResult::Failed(reason) => {
                Err(auth_framework::errors::AuthError::authentication_failed(reason))
            }
            _ => Err(auth_framework::errors::AuthError::authentication_failed(
                "Authentication method not configured".to_string()
            ))
        }
    }
}
```

### Example 2: Web Application Integration

```rust
use auth_framework::{AuthFramework, AuthConfig};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use std::time::Duration;

// Your custom storage backend
use your_storage_crate::CustomStorage;

#[derive(Clone)]
struct AppState {
    auth: Arc<AuthFramework>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize custom storage with connection pooling
    let storage = Arc::new(
        CustomStorage::builder()
            .connection_string(&std::env::var("DATABASE_URL")?)
            .pool_size(20)
            .timeout(Duration::from_secs(30))
            .enable_ssl(true)
            .build()
            .await?
    );

    // Configure AuthFramework
    let mut config = AuthConfig::default();
    config.security.secret_key = Some(std::env::var("JWT_SECRET")?);

    // Build with advanced configuration
    let auth = Arc::new(
        AuthFramework::builder()
            .customize(|c| {
                c.secret = config.security.secret_key.clone();
                c
            })
            .with_storage()
            .custom(storage)
            .done()
            .build()
            .await?
    );

    let state = AppState { auth };

    // Create Axum router
    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/profile", get(profile_handler))
        .with_state(state);

    // Start server
    println!("Server starting on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let credential = auth_framework::authentication::credentials::Credential::Password {
        username: payload.email,
        password: payload.password,
    };

    match state.auth.authenticate("password", credential).await {
        Ok(auth_framework::authentication::AuthResult::Success(token)) => {
            Ok(Json(LoginResponse {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                expires_in: 3600,
            }))
        }
        Ok(_) => Err(StatusCode::UNAUTHORIZED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn profile_handler(
    State(state): State<AppState>,
    // Add auth middleware extraction here
) -> Result<Json<UserProfile>, StatusCode> {
    // Profile handler implementation
    Ok(Json(UserProfile {
        id: "user123".to_string(),
        email: "user@example.com".to_string(),
    }))
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(serde::Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(serde::Serialize)]
struct UserProfile {
    id: String,
    email: String,
}
```

### Example 3: Microservice Architecture

```rust
use auth_framework::{AuthFramework, AuthConfig};
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

// Your distributed storage backend
use your_distributed_storage::DistributedStorage;

pub struct AuthService {
    auth: Arc<AuthFramework>,
}

impl AuthService {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create distributed storage with service discovery
        let storage_config = your_distributed_storage::Config {
            consul_url: std::env::var("CONSUL_URL")?,
            service_name: "auth-storage".to_string(),
            datacenter: "dc1".to_string(),
            replication_factor: 3,
        };

        let storage = Arc::new(
            DistributedStorage::with_service_discovery(storage_config).await?
        );

        // Configure for microservice use
        let mut config = AuthConfig::default();
        config.security.secret_key = Some(std::env::var("JWT_SECRET")?);

        let auth = Arc::new(
            AuthFramework::builder()
                .customize(|c| {
                    c.secret = config.security.secret_key.clone();
                    c
                })
                .with_storage()
                .custom(storage)
                .done()
                .build()
                .await?
        );

        Ok(Self { auth })
    }

    pub async fn validate_service_token(&self, token: &str) -> Result<bool, Status> {
        match self.auth.validate_token(token).await {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(e) => {
                tracing::error!("Token validation error: {}", e);
                Err(Status::internal("Validation failed"))
            }
        }
    }
}
```

## Configuration Best Practices

### Environment-Based Configuration

```rust
use auth_framework::AuthConfig;
use std::env;
use std::time::Duration;

pub fn create_auth_config() -> Result<AuthConfig, Box<dyn std::error::Error>> {
    let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    let mut base_config = AuthConfig::default();
    base_config.security.secret_key = Some(env::var("JWT_SECRET")?);

    let config = match environment.as_str() {
        "production" => {
            // Production configuration
            base_config
        }
        "staging" => {
            // Staging configuration
            base_config
        }
        _ => {
            // Development defaults
            base_config
        }
    };

    Ok(config)
}
```

### Storage-Specific Configuration

```rust
use your_storage_crate::{StorageConfig, ConnectionPool};

pub async fn create_storage_backend() -> Result<Arc<dyn auth_framework::storage::AuthStorage>, Box<dyn std::error::Error>> {
    let storage_type = std::env::var("STORAGE_TYPE").unwrap_or_else(|_| "memory".to_string());

    match storage_type.as_str() {
        "postgresql" => {
            let config = StorageConfig::postgresql()
                .connection_string(&std::env::var("DATABASE_URL")?)
                .pool_config(ConnectionPool::new()
                    .max_connections(50)
                    .min_connections(5)
                    .connection_timeout(Duration::from_secs(30))
                )
                .enable_ssl(true)
                .ssl_ca_cert_path(&std::env::var("SSL_CA_CERT")?);

            Ok(Arc::new(YourPostgresStorage::new(config).await?))
        }
        "redis" => {
            let config = StorageConfig::redis()
                .cluster_urls(vec![
                    std::env::var("REDIS_URL_1")?,
                    std::env::var("REDIS_URL_2")?,
                    std::env::var("REDIS_URL_3")?,
                ])
                .enable_cluster_mode(true)
                .connection_pool_size(20);

            Ok(Arc::new(YourRedisStorage::new(config).await?))
        }
        "surrealdb" => {
            let config = StorageConfig::surrealdb()
                .url(&std::env::var("SURREAL_URL")?)
                .namespace(&std::env::var("SURREAL_NAMESPACE")?)
                .database(&std::env::var("SURREAL_DATABASE")?)
                .credentials(
                    &std::env::var("SURREAL_USER")?,
                    &std::env::var("SURREAL_PASS")?
                );

            Ok(Arc::new(YourSurrealStorage::new(config).await?))
        }
        _ => {
            // Fallback to memory storage for development
            Ok(Arc::new(auth_framework::storage::MemoryStorage::new()))
        }
    }
}
```

## Error Handling Patterns

### Robust Error Handling

```rust
use auth_framework::errors::{AuthError, Result as AuthResult};

pub async fn initialize_auth_service() -> AuthResult<Arc<AuthFramework>> {
    let storage = create_custom_storage().await.map_err(|e| {
        AuthError::config_with_help(
            format!("Failed to initialize storage: {}", e),
            "Check your storage configuration and connection parameters",
            Some("Ensure your database is running and accessible".to_string())
        )
    })?;

    let config = create_auth_config().map_err(|e| {
        AuthError::config_with_help(
            format!("Invalid configuration: {}", e),
            "Check all required environment variables are set",
            Some("Run 'env | grep JWT_SECRET' to verify JWT secret is set".to_string())
        )
    })?;

    AuthFramework::builder()
        .customize(|c| {
            c.secret = config.security.secret_key.clone();
            c
        })
        .with_storage()
        .custom(storage)
        .done()
        .build()
        .await
        .map(Arc::new)
}

async fn create_custom_storage() -> Result<Arc<dyn auth_framework::storage::AuthStorage>, Box<dyn std::error::Error>> {
    // Your storage creation logic with proper error handling
    Ok(Arc::new(YourStorage::new().await?))
}
```

### Graceful Degradation

```rust
use auth_framework::storage::MemoryStorage;

pub async fn create_resilient_storage() -> Arc<dyn auth_framework::storage::AuthStorage> {
    // Try primary storage first
    if let Ok(storage) = YourPrimaryStorage::connect(&primary_url).await {
        tracing::info!("Connected to primary storage");
        return Arc::new(storage);
    }

    // Fall back to secondary storage
    if let Ok(storage) = YourSecondaryStorage::connect(&secondary_url).await {
        tracing::warn!("Primary storage unavailable, using secondary");
        return Arc::new(storage);
    }

    // Last resort: memory storage with warning
    tracing::error!("All persistent storage backends unavailable, using memory storage");
    Arc::new(MemoryStorage::new())
}
```

## Testing Your Integration

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use auth_framework::testing::helpers;

    async fn setup_test_auth() -> AuthFramework {
        let storage = Arc::new(YourStorage::new_for_testing().await.unwrap());
        let mut config = AuthConfig::default();
        config.security.secret_key = Some("test-secret-32-characters-long!".to_string());

        AuthFramework::builder()
            .customize(|c| {
                c.secret = config.security.secret_key.clone();
                c
            })
            .with_storage()
            .custom(storage)
            .done()
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_full_auth_flow() {
        let auth = setup_test_auth().await;

        // Register authentication method
        let jwt_method = auth_framework::methods::JwtMethod::new()
            .secret_key("test-secret-32-characters-long!");

        auth.register_method("jwt",
            auth_framework::methods::AuthMethodEnum::Jwt(jwt_method)
        );

        // Test token creation and validation
        let token = auth.create_auth_token(
            "test-user",
            vec!["read".to_string(), "write".to_string()],
            "jwt",
            None
        ).await.unwrap();

        assert!(!token.access_token.is_empty());

        // Test token validation
        let is_valid = auth.validate_token(&token.access_token).await.unwrap();
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_storage_persistence() {
        let auth = setup_test_auth().await;

        // Create and store a token
        let token = helpers::create_test_token("user123", "test-token-id");
        auth.storage.store_token(&token).await.unwrap();

        // Verify it can be retrieved
        let retrieved = auth.storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
    }
}
```

## Production Deployment

### Docker Configuration

```dockerfile
FROM rust:1.70 as builder

WORKDIR /app
COPY . .
RUN cargo build --release --features "your-storage-backend"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/your-app /usr/local/bin/your-app
COPY --from=builder /app/config /config

EXPOSE 8080
CMD ["your-app"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: your-registry/auth-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: STORAGE_TYPE
          value: "postgresql"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Migration and Maintenance

### Storage Migration

```rust
use auth_framework::storage::StorageMigration;

pub async fn migrate_storage() -> Result<(), Box<dyn std::error::Error>> {
    let old_storage = Arc::new(OldStorage::connect(&old_config).await?);
    let new_storage = Arc::new(NewStorage::connect(&new_config).await?);

    let migration = StorageMigration::new(old_storage, new_storage)
        .with_batch_size(1000)
        .with_verify_data(true)
        .with_preserve_ttl(true);

    println!("Starting storage migration...");

    let result = migration.migrate_all().await?;

    println!("Migration completed: {} tokens, {} sessions migrated",
             result.tokens_migrated, result.sessions_migrated);

    Ok(())
}
```

## Troubleshooting

### Common Issues and Solutions

1. **Connection Failures**

   ```rust
   // Implement connection retry logic
   async fn connect_with_retry<T>(connect_fn: impl Fn() -> Future<Output = Result<T, E>>) -> Result<T, E> {
       let mut attempts = 0;
       loop {
           match connect_fn().await {
               Ok(connection) => return Ok(connection),
               Err(e) if attempts < 3 => {
                   attempts += 1;
                   tokio::time::sleep(Duration::from_secs(2_u64.pow(attempts))).await;
               }
               Err(e) => return Err(e),
           }
       }
   }
   ```

2. **Performance Issues**

   ```rust
   // Enable connection pooling and optimize queries
   let storage_config = YourStorageConfig::new()
       .pool_size(50)
       .enable_connection_pooling(true)
       .query_timeout(Duration::from_secs(30))
       .enable_prepared_statements(true);
   ```

3. **Memory Usage**

   ```rust
   // Implement proper cleanup and monitoring
   let cleanup_interval = Duration::from_secs(3600);
   tokio::spawn(async move {
       let mut interval = tokio::time::interval(cleanup_interval);
       loop {
           interval.tick().await;
           if let Err(e) = storage.cleanup_expired().await {
               tracing::error!("Cleanup failed: {}", e);
           }
       }
   });
   ```

## Summary

This guide covers the complete integration of third-party storage backends with AuthFramework. The builder pattern provides flexibility while maintaining type safety and following Rust best practices. The key points to remember:

- Use `Arc<dyn AuthStorage>` for your storage instances
- Prefer the builder pattern for complex configurations
- Implement proper error handling and fallback strategies
- Test thoroughly in both unit and integration scenarios
- Plan for production deployment and monitoring

With these patterns, you can integrate any storage backend while maintaining AuthFramework's security, performance, and reliability standards.
