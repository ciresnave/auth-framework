# Package: config

> `src/config/` — centralised configuration for the framework

> [← 01-errors](01-errors.md) · [index](23-cross-package.md) · [03-tokens →](03-tokens.md)

```mermaid
classDiagram
    class AuthConfig {
        +Duration token_lifetime
        +Duration refresh_token_lifetime
        +bool enable_multi_factor
        +String issuer
        +String audience
        +Option~String~ secret
        +StorageConfig storage
        +RateLimitConfig rate_limiting
        +SecurityConfig security
        +AuditConfig audit
        +bool force_production_mode
    }
    class StorageConfig {
        <<enumeration>>
        Memory
        Redis
        Postgres
        Custom
    }
    class JwtAlgorithm {
        <<enumeration>>
        HS256
        HS384
        HS512
        RS256
        RS384
        RS512
        ES256
        ES384
    }
    class PasswordHashAlgorithm {
        <<enumeration>>
        Argon2
        Bcrypt
        Scrypt
    }
    class SecurityConfig {
        +usize min_password_length
        +bool require_password_complexity
        +PasswordHashAlgorithm password_hash_algorithm
        +JwtAlgorithm jwt_algorithm
        +Option~String~ secret_key
        +bool secure_cookies
        +bool csrf_protection
        +Duration session_timeout
    }
    class RateLimitConfig {
        +bool enabled
        +u32 max_requests
        +Duration window
        +u32 burst
    }
    class AuditConfig {
        +bool enabled
        +bool log_success
        +bool log_failures
        +bool log_permissions
        +bool log_tokens
        +AuditStorage storage
    }
    class ConfigManager {
        +Vec~String~ sources
        +String env_prefix
        +load() Result~AuthFrameworkSettings~
        +reload() Result
        +get(key) Result~T~
    }
    class AuthFrameworkSettings {
        +AuthConfig auth
        +Option~SessionSettings~ session
        +HashMap~String, Value~ custom
    }
    class SessionSettings {
        +Option~u32~ max_concurrent_sessions
        +Option~u64~ cleanup_interval
        +Option~bool~ enable_device_tracking
    }

    AuthConfig *-- SecurityConfig
    AuthConfig *-- RateLimitConfig
    AuthConfig *-- AuditConfig
    AuthConfig *-- StorageConfig
    SecurityConfig ..> JwtAlgorithm
    SecurityConfig ..> PasswordHashAlgorithm
    AuthFrameworkSettings *-- AuthConfig
    AuthFrameworkSettings *-- SessionSettings
    ConfigManager ..> AuthFrameworkSettings : produces
```

---

**Related:** [01-errors](01-errors.md) · [03-tokens](03-tokens.md) · [22-core](22-core.md)
