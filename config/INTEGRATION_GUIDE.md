# Configuration Integration Guide

# How to integrate auth-framework configuration into parent applications

This guide demonstrates how parent applications can seamlessly integrate
auth-framework configuration while maintaining modularity and flexibility.

## Basic Integration Patterns

### 1. Include Pattern

The simplest way to integrate auth-framework into your application configuration:

```toml
# your-app.toml
[app]
name = "MyApplication"
version = "1.0.0"

# Include auth-framework configuration
include = ["auth-framework.toml"]

# Override specific auth settings
[auth.jwt]
secret_key = "your-production-secret"
issuer = "myapp.com"
```

### 2. Nested Configuration Pattern

Organize auth-framework as a subsection of your application config:

```toml
# your-app.toml
[app]
name = "MyApplication"

[auth]
# Include entire auth-framework config as a subsection
include = ["config/auth-framework.toml"]

# Application-specific auth overrides
[auth.session]
name = "MYAPP_SESSION"
domain = "myapp.com"
```

### 3. Environment-Specific Integration

Use different auth configurations for different environments:

```toml
# your-app.toml
[app]
name = "MyApplication"
environment = "${APP_ENV:development}"

# Conditional includes based on environment
include = [
    "auth-framework.toml",
    "auth-${APP_ENV}.toml"  # auth-development.toml, auth-production.toml, etc.
]
```

## Programmatic Integration Examples

### Using ConfigManager in Rust Applications

```rust
use auth_framework::config::{ConfigManager, AuthFrameworkConfigManager};
use config::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Method 1: Load auth-framework config independently
    let auth_config = AuthFrameworkConfigManager::from_files(&[
        "config/auth-framework.toml"
    ])?;

    // Method 2: Merge into your application config
    let mut app_config = Config::builder()
        .add_source(config::File::with_name("your-app"))
        .build()?;

    // Merge auth-framework config under "auth" key
    let auth_manager = AuthFrameworkConfigManager::new();
    let auth_config = auth_manager.merge_configs(&[
        "config/auth-framework.toml"
    ])?;

    app_config.merge(auth_config.nested("auth"))?;

    Ok(())
}
```

### Using Builder Pattern for Custom Configuration

```rust
use auth_framework::config::AuthFrameworkConfigManager;

fn configure_auth() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthFrameworkConfigManager::builder()
        .with_file("config/auth-framework.toml")
        .with_env_prefix("MYAPP_AUTH")  // Environment variables with MYAPP_AUTH_ prefix
        .with_cli_args()               // Command line argument parsing
        .with_overrides([
            ("jwt.secret_key", "production-secret"),
            ("session.domain", "myapp.com"),
        ])
        .build()?;

    Ok(())
}
```

## Configuration Layering and Precedence

The config crate supports layered configuration with the following precedence (highest to lowest):

1. **Command Line Arguments** - `--jwt-secret-key=value`
2. **Environment Variables** - `AUTH_JWT_SECRET_KEY=value`
3. **Configuration Files** - Values from TOML/YAML/JSON files
4. **Default Values** - Built-in defaults

### Environment Variable Mapping

Auth-framework uses the following environment variable patterns:

```bash
# JWT Configuration
AUTH_JWT_SECRET_KEY=your-secret
AUTH_JWT_ALGORITHM=HS256
AUTH_JWT_EXPIRY=1h

# Session Configuration
AUTH_SESSION_NAME=AUTH_SESSION
AUTH_SESSION_DOMAIN=localhost
AUTH_SESSION_SECURE=true

# OAuth2 Configuration
AUTH_OAUTH2_GOOGLE_CLIENT_ID=your-client-id
AUTH_OAUTH2_GOOGLE_CLIENT_SECRET=your-secret

# Threat Intelligence
AUTH_THREAT_INTEL_ENABLED=true
AUTH_THREAT_INTEL_FEEDS_0_URL=https://example.com/feed1
AUTH_THREAT_INTEL_FEEDS_0_API_KEY=key1
```

## Docker Integration

### Using Environment Variables in Docker

```dockerfile
# Dockerfile
FROM rust:1.75-alpine
COPY . /app
WORKDIR /app

# Set default environment variables
ENV AUTH_JWT_SECRET_KEY=change-me-in-production
ENV AUTH_SESSION_SECURE=true
ENV AUTH_THREAT_INTEL_ENABLED=true

CMD ["./your-app"]
```

### Using Docker Compose with Config Files

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    volumes:
      - ./config:/app/config:ro  # Mount config directory
    environment:
      - AUTH_JWT_SECRET_KEY=${JWT_SECRET}
      - AUTH_SESSION_DOMAIN=myapp.com
      - APP_ENV=production
    env_file:
      - .env
```

## Kubernetes ConfigMaps Integration

```yaml
# kubernetes-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
data:
  auth-framework.toml: |
    [jwt]
    algorithm = "RS256"
    expiry = "1h"

    [session]
    name = "AUTH_SESSION"
    secure = true

    include = [
      "methods/oauth2.toml",
      "methods/mfa.toml"
    ]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        volumeMounts:
        - name: auth-config
          mountPath: /app/config
        env:
        - name: AUTH_JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
      volumes:
      - name: auth-config
        configMap:
          name: auth-config
```

## Configuration Validation Examples

### Validating Parent App Integration

```rust
use auth_framework::config::{ConfigManager, AuthFrameworkConfigManager};
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    app: AppSettings,
    auth: auth_framework::config::AuthConfig,
    database: DatabaseConfig,
}

fn validate_integration() -> Result<(), Box<dyn std::error::Error>> {
    let config_manager = AuthFrameworkConfigManager::new();

    // Load and validate auth configuration
    let auth_config = config_manager.from_files(&[
        "config/your-app.toml"
    ])?;

    // Validate that required auth settings are present
    config_manager.validate(&auth_config)?;

    // Deserialize into your app's config structure
    let app_config: AppConfig = auth_config.try_deserialize()?;

    println!("Auth configuration successfully integrated!");
    Ok(())
}
```

## Best Practices for Integration

### 1. **Modular Configuration Structure**

```
your-app/
├── config/
│   ├── your-app.toml              # Main app config
│   ├── auth-framework.toml        # Auth framework config
│   ├── environments/
│   │   ├── development.toml       # Dev-specific overrides
│   │   ├── staging.toml          # Staging overrides
│   │   └── production.toml       # Production overrides
│   └── methods/                  # Auth method configs
│       ├── oauth2.toml
│       ├── jwt.toml
│       └── mfa.toml
```

### 2. **Security Considerations**

- Never commit sensitive values to configuration files
- Use environment variables or secret management for production secrets
- Validate configuration at application startup
- Use different configurations for different environments

### 3. **Configuration Documentation**

- Document all configuration options and their defaults
- Provide examples for common use cases
- Include migration guides when updating configuration schemas

### 4. **Testing Configuration**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_integration() {
        let config = AuthFrameworkConfigManager::from_files(&[
            "tests/fixtures/test-config.toml"
        ]).expect("Should load test config");

        // Validate that integration works correctly
        assert!(config.jwt.is_some());
        assert!(config.oauth2.is_some());
    }
}
```

This integration approach ensures that auth-framework remains flexible and easy to adopt while providing powerful configuration management capabilities.
