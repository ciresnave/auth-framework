# Configuration Examples and Usage

# Practical examples for using auth-framework configuration

## Quick Start Examples

### Minimal Configuration

```toml
# minimal-auth.toml
[jwt]
secret_key = "${JWT_SECRET_KEY:development-secret}"
algorithm = "HS256"
expiry = "1h"

[session]
name = "AUTH_SESSION"
secure = false  # Set to true in production
```

### Development Configuration

```toml
# development.toml
[jwt]
secret_key = "dev-secret-key-not-for-production"
algorithm = "HS256"
expiry = "24h"  # Longer expiry for development

[session]
name = "DEV_SESSION"
secure = false
same_site = "lax"
max_age = "24h"

[oauth2.google]
client_id = "dev-client-id"
client_secret = "dev-client-secret"
redirect_uri = "http://localhost:8080/auth/callback"

# Enable logging for development
[logging]
level = "debug"
log_auth_attempts = true

# Disable threat intelligence in development
[threat_intel]
enabled = false
```

### Production Configuration

```toml
# production.toml
[jwt]
secret_key = "${JWT_SECRET_KEY}"  # Must be provided via environment
algorithm = "RS256"
expiry = "15m"
refresh_expiry = "30d"

[session]
name = "AUTH_SESSION"
secure = true
same_site = "strict"
domain = "myapp.com"
max_age = "4h"

[oauth2.google]
client_id = "${GOOGLE_CLIENT_ID}"
client_secret = "${GOOGLE_CLIENT_SECRET}"
redirect_uri = "https://myapp.com/auth/callback"

# Enable all security features in production
[threat_intel]
enabled = true
auto_update_feeds = true
cache_duration = "1h"

[security]
require_https = true
enable_csrf_protection = true
rate_limiting = true

# Production logging
[logging]
level = "info"
log_auth_attempts = true
log_to_file = true
```

## CLI Configuration Examples

### Using clap integration for command-line overrides

```rust
use clap::{Arg, Command};
use auth_framework::config::AuthFrameworkConfigManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("myapp")
        .arg(Arg::new("config")
             .long("config")
             .value_name("FILE")
             .help("Configuration file path"))
        .arg(Arg::new("jwt-secret")
             .long("jwt-secret")
             .value_name("SECRET")
             .help("JWT secret key"))
        .arg(Arg::new("port")
             .short('p')
             .long("port")
             .value_name("PORT")
             .help("Server port"))
        .get_matches();

    let config_manager = AuthFrameworkConfigManager::builder()
        .with_file(matches.get_one::<String>("config").unwrap_or(&"config.toml"))
        .with_env_prefix("MYAPP")
        .build()?;

    // CLI overrides
    if let Some(jwt_secret) = matches.get_one::<String>("jwt-secret") {
        config_manager.set("jwt.secret_key", jwt_secret)?;
    }

    if let Some(port) = matches.get_one::<String>("port") {
        config_manager.set("server.port", port.parse::<u16>()?)?;
    }

    Ok(())
}
```

## Environment Variable Examples

### Setting up environment variables for different deployment scenarios

#### Docker Environment Variables

```bash
# .env file for Docker
AUTH_JWT_SECRET_KEY=your-production-jwt-secret
AUTH_JWT_ALGORITHM=RS256
AUTH_SESSION_SECURE=true
AUTH_SESSION_DOMAIN=myapp.com
AUTH_OAUTH2_GOOGLE_CLIENT_ID=your-google-client-id
AUTH_OAUTH2_GOOGLE_CLIENT_SECRET=your-google-client-secret
AUTH_THREAT_INTEL_ENABLED=true
```

#### Kubernetes Environment Variables

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-env-config
data:
  AUTH_JWT_ALGORITHM: "RS256"
  AUTH_SESSION_SECURE: "true"
  AUTH_THREAT_INTEL_ENABLED: "true"
  AUTH_THREAT_INTEL_AUTO_UPDATE_FEEDS: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
data:
  AUTH_JWT_SECRET_KEY: <base64-encoded-secret>
  AUTH_OAUTH2_GOOGLE_CLIENT_SECRET: <base64-encoded-secret>
```

#### Systemd Service Environment Variables

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Application with Auth Framework
After=network.target

[Service]
Type=simple
User=myapp
Environment=AUTH_JWT_SECRET_KEY=production-secret
Environment=AUTH_SESSION_SECURE=true
Environment=AUTH_SESSION_DOMAIN=myapp.com
EnvironmentFile=/etc/myapp/auth.env
ExecStart=/usr/local/bin/myapp
Restart=always

[Install]
WantedBy=multi-user.target
```

## Advanced Configuration Patterns

### Multi-Tenant Configuration

```toml
# multi-tenant.toml
[tenants.default]
jwt_secret = "${DEFAULT_JWT_SECRET}"
session_name = "DEFAULT_SESSION"
oauth2_providers = ["google", "github"]

[tenants.enterprise]
jwt_secret = "${ENTERPRISE_JWT_SECRET}"
session_name = "ENTERPRISE_SESSION"
oauth2_providers = ["azure_ad", "okta"]
mfa_required = true

[tenants.saas]
jwt_secret = "${SAAS_JWT_SECRET}"
session_name = "SAAS_SESSION"
oauth2_providers = ["google", "github", "gitlab"]
rate_limit_multiplier = 2.0
```

### Feature Flag Configuration

```toml
# feature-flags.toml
[features]
mfa_enabled = true
webauthn_enabled = false
api_key_auth_enabled = true
threat_intel_enabled = true
session_replay_protection = true

# Feature-specific configuration
[mfa]
enabled = "${FEATURE_MFA_ENABLED:true}"
required_for_admin = true
backup_codes = true

[webauthn]
enabled = "${FEATURE_WEBAUTHN_ENABLED:false}"
require_user_verification = true

[api_keys]
enabled = "${FEATURE_API_KEY_AUTH_ENABLED:true}"
max_keys_per_user = 5
```

### Load Balancer and High Availability Configuration

```toml
# ha-cluster.toml
[cluster]
node_id = "${NODE_ID:node-1}"
discovery_method = "consul"  # consul, etcd, redis
shared_secret = "${CLUSTER_SHARED_SECRET}"

[session]
# Use Redis for shared session storage in cluster
storage = "redis"
redis_url = "${REDIS_URL:redis://localhost:6379}"
redis_key_prefix = "auth:sessions:"

[jwt]
# Use shared secret for JWT validation across nodes
secret_key = "${CLUSTER_JWT_SECRET}"
algorithm = "HS256"

[threat_intel]
# Share threat intelligence cache across cluster
cache_backend = "redis"
cache_key_prefix = "auth:threat:"
```

## Configuration Testing Examples

### Unit Tests for Configuration

```rust
#[cfg(test)]
mod config_tests {
    use super::*;
    use auth_framework::config::AuthFrameworkConfigManager;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_minimal_config_loads() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"
[jwt]
secret_key = "test-secret"
algorithm = "HS256"
        "#).unwrap();

        let config = AuthFrameworkConfigManager::from_files(&[
            temp_file.path().to_str().unwrap()
        ]).expect("Should load minimal config");

        assert_eq!(config.jwt.secret_key, "test-secret");
        assert_eq!(config.jwt.algorithm, "HS256");
    }

    #[test]
    fn test_environment_variable_override() {
        std::env::set_var("AUTH_JWT_SECRET_KEY", "env-secret");

        let config = AuthFrameworkConfigManager::builder()
            .with_env_prefix("AUTH")
            .build()
            .unwrap();

        assert_eq!(config.jwt.secret_key, "env-secret");
        std::env::remove_var("AUTH_JWT_SECRET_KEY");
    }

    #[test]
    fn test_invalid_config_fails() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"
[jwt]
algorithm = "INVALID_ALGORITHM"
        "#).unwrap();

        let result = AuthFrameworkConfigManager::from_files(&[
            temp_file.path().to_str().unwrap()
        ]);

        assert!(result.is_err());
    }
}
```

### Integration Tests with Different Configurations

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_oauth2_flow_with_config() {
        let config = AuthFrameworkConfigManager::from_files(&[
            "tests/fixtures/oauth2-test-config.toml"
        ]).unwrap();

        let auth_service = AuthService::new(config);

        // Test OAuth2 flow
        let auth_url = auth_service.get_oauth2_auth_url("google").unwrap();
        assert!(auth_url.contains("client_id="));
    }

    #[tokio::test]
    async fn test_jwt_validation_with_config() {
        let config = AuthFrameworkConfigManager::from_files(&[
            "tests/fixtures/jwt-test-config.toml"
        ]).unwrap();

        let jwt_service = JwtService::new(config.jwt);

        let token = jwt_service.create_token("test-user").unwrap();
        let claims = jwt_service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "test-user");
    }
}
```

## Configuration Migration Examples

### Migrating from v1.0 to v2.0 Configuration Format

```rust
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Deserialize)]
struct V1Config {
    jwt_secret: String,
    jwt_expiry: String,
    session_name: String,
    oauth_google_client_id: Option<String>,
}

#[derive(Serialize)]
struct V2Config {
    jwt: JwtConfig,
    session: SessionConfig,
    oauth2: Option<OAuth2Config>,
}

fn migrate_config_v1_to_v2(v1_path: &str, v2_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let v1_content = fs::read_to_string(v1_path)?;
    let v1_config: V1Config = toml::from_str(&v1_content)?;

    let v2_config = V2Config {
        jwt: JwtConfig {
            secret_key: v1_config.jwt_secret,
            expiry: v1_config.jwt_expiry,
            algorithm: "HS256".to_string(), // Default for v2
        },
        session: SessionConfig {
            name: v1_config.session_name,
            secure: true, // Default for v2
            ..Default::default()
        },
        oauth2: v1_config.oauth_google_client_id.map(|client_id| OAuth2Config {
            google: Some(GoogleConfig {
                client_id,
                ..Default::default()
            }),
            ..Default::default()
        }),
    };

    let v2_content = toml::to_string_pretty(&v2_config)?;
    fs::write(v2_path, v2_content)?;

    println!("Successfully migrated configuration from v1.0 to v2.0");
    Ok(())
}
```

These examples demonstrate the flexibility and power of the config crate integration, allowing auth-framework to adapt to various deployment scenarios while maintaining security and best practices.
