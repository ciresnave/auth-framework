//! Comprehensive error types for the AuthFramework.
//!
//! This module defines all error types used throughout the authentication framework,
//! providing detailed error information for debugging, logging, and user feedback.
//! All errors implement standard Rust error traits and provide contextual information
//! to help diagnose issues.
//!
//! # Error Categories
//!
//! - **Authentication Errors**: Credential validation and method failures
//! - **Authorization Errors**: Permission and access control failures
//! - **Token Errors**: JWT creation, validation, and lifecycle issues
//! - **Configuration Errors**: Setup and configuration problems
//! - **Storage Errors**: Database and persistence layer issues
//! - **Network Errors**: External service communication failures
//! - **Cryptographic Errors**: Security operation failures
//!
//! # Error Handling Patterns
//!
//! The framework uses structured error handling with:
//! - Contextual error messages with relevant details
//! - Error chaining to preserve root cause information
//! - Categorized errors for appropriate response handling
//! - Security-safe error messages that don't leak sensitive data
//!
//! # Example Error Handling
//!
//! ```rust
//! use auth_framework::{AuthFramework, AuthError};
//!
//! match auth_framework.authenticate("password", credential, metadata).await {
//!     Ok(result) => handle_success(result),
//!     Err(AuthError::InvalidCredential { credential_type, message }) => {
//!         log::warn!("Invalid {} credential: {}", credential_type, message);
//!         respond_with_auth_failure()
//!     },
//!     Err(AuthError::RateLimited { retry_after, .. }) => {
//!         respond_with_rate_limit(retry_after)
//!     },
//!     Err(e) => {
//!         log::error!("Authentication system error: {}", e);
//!         respond_with_system_error()
//!     }
//! }
//! ```
//!
//! # Security Considerations
//!
//! Error messages are designed to:
//! - Provide useful debugging information for developers
//! - Avoid exposing sensitive information to potential attackers
//! - Enable proper security monitoring and alerting
//! - Support compliance requirements for audit logging

use thiserror::Error;

/// Type alias for Results in the authentication framework.
///
/// This alias simplifies error handling throughout the framework by defaulting
/// to `AuthError` as the error type while allowing flexibility for other error
/// types when needed.
pub type Result<T, E = AuthError> = std::result::Result<T, E>;

/// Comprehensive error type covering all authentication and authorization failures.
///
/// `AuthError` provides detailed error information for all aspects of the authentication
/// framework, from configuration issues to runtime failures. Each error variant includes
/// contextual information to aid in debugging and provide appropriate user feedback.
///
/// This enhanced error type provides:
/// - **Actionable error messages** with specific suggestions for fixes
/// - **Documentation links** to relevant guides and troubleshooting
/// - **Contextual help** that guides users to solutions
/// - **Security-aware messaging** that doesn't leak sensitive information
///
/// # Error Categories
///
/// ## Configuration Errors
/// Errors that occur during framework setup and configuration validation.
///
/// ## Authentication Errors
/// Errors related to credential validation and authentication method execution.
///
/// ## Authorization Errors
/// Errors related to permission checking and access control.
///
/// ## Token Errors
/// JWT token creation, validation, expiration, and lifecycle issues.
///
/// ## Storage Errors
/// Database connectivity, query failures, and data persistence issues.
///
/// ## Network Errors
/// External service communication, timeouts, and connectivity problems.
///
/// ## Cryptographic Errors
/// Encryption, decryption, signing, and other security operation failures.
///
/// # Enhanced Error Handling
///
/// ```rust
/// use auth_framework::AuthError;
///
/// // Enhanced error handling with contextual help
/// match auth_result {
///     Err(AuthError::Configuration { message, help, docs_url, .. }) => {
///         eprintln!("❌ Configuration Error: {}", message);
///         if let Some(help) = help {
///             eprintln!("💡 Help: {}", help);
///         }
///         if let Some(docs) = docs_url {
///             eprintln!("📖 See: {}", docs);
///         }
///     },
///     Err(AuthError::InvalidCredential { credential_type, message, suggested_fix, .. }) => {
///         eprintln!("🔐 Invalid {}: {}", credential_type, message);
///         if let Some(fix) = suggested_fix {
///             eprintln!("🔧 Suggested fix: {}", fix);
///         }
///     },
///     // ... handle other error types
/// }
/// ```
///
/// # Security Notes
///
/// Error messages are carefully crafted to:
/// - Provide sufficient detail for debugging and monitoring
/// - Avoid exposing sensitive information that could aid attackers
/// - Enable security teams to identify potential threats
/// - Support compliance and audit requirements
/// - Guide users to secure solutions and best practices
#[derive(Error, Debug)]
pub enum AuthError {
    /// Configuration validation and setup errors.
    ///
    /// These errors occur when the authentication framework is misconfigured
    /// or when configuration validation fails during startup.
    #[error("Configuration error: {message}")]
    Configuration {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// Helpful guidance for fixing the issue
        help: Option<String>,
        /// Link to relevant documentation
        docs_url: Option<String>,
        /// Specific fix suggestion with commands or code
        suggested_fix: Option<String>,
    },

    /// Authentication method execution errors.
    ///
    /// These errors occur when a specific authentication method fails to
    /// execute properly, such as OAuth provider communication failures.
    #[error("Authentication method '{method}' error: {message}")]
    AuthMethod {
        method: String,
        message: String,
        /// Helpful guidance for fixing the issue
        help: Option<String>,
        /// Link to relevant documentation
        docs_url: Option<String>,
        /// Specific fix suggestion
        suggested_fix: Option<String>,
    },

    /// Token-related errors
    #[error("Token error: {0}")]
    Token(#[from] TokenError),

    /// Permission-related errors
    #[error("Permission error: {0}")]
    Permission(#[from] PermissionError),

    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Network/HTTP errors
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// JSON parsing errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// JWT errors
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// YAML parsing errors
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// TOML parsing errors
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Prometheus metrics errors
    #[cfg(feature = "prometheus")]
    #[error("Metrics error: {0}")]
    Metrics(#[from] prometheus::Error),

    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// CLI interaction errors
    #[error("CLI error: {0}")]
    Cli(String),

    /// System time errors
    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    /// Session-related errors
    #[error("Too many concurrent sessions for user")]
    TooManyConcurrentSessions,

    /// MFA-related errors
    #[error("MFA error: {0}")]
    Mfa(#[from] MfaError),

    /// Device flow errors
    #[error("Device flow error: {0}")]
    DeviceFlow(#[from] DeviceFlowError),

    /// OAuth provider errors
    #[error("OAuth provider error: {0}")]
    OAuthProvider(#[from] OAuthProviderError),

    /// Password verification errors
    #[error("Password verification failed: {0}")]
    PasswordVerification(String),

    /// Password hashing errors
    #[error("Password hashing failed: {0}")]
    PasswordHashing(String),

    /// User not found error
    #[error("User not found")]
    UserNotFound,

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Hardware token errors
    #[error("Hardware token error: {0}")]
    HardwareToken(String),

    /// Backup code verification errors
    #[error("Backup code verification failed: {0}")]
    BackupCodeVerification(String),

    /// Backup code hashing errors
    #[error("Backup code hashing failed: {0}")]
    BackupCodeHashing(String),

    /// Invalid secret error
    #[error("Invalid secret format")]
    InvalidSecret,

    /// User profile errors
    #[error("User profile error: {message}")]
    UserProfile { message: String },

    /// Credential validation errors
    #[error("Invalid credential: {credential_type} - {message}")]
    InvalidCredential {
        credential_type: String,
        message: String,
    },

    /// Authentication timeout
    #[error("Authentication timeout after {timeout_seconds} seconds")]
    Timeout { timeout_seconds: u64 },

    /// Provider configuration missing
    #[error("Provider '{provider}' is not configured or supported")]
    ProviderNotConfigured { provider: String },

    /// Cryptography errors
    #[error("Cryptography error: {message}")]
    Crypto { message: String },

    /// Validation errors
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Generic internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// Invalid request error
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Step-up authentication required
    #[error(
        "Step-up authentication required: current level '{current_level}', required level '{required_level}'"
    )]
    StepUpRequired {
        current_level: String,
        required_level: String,
        step_up_url: String,
    },

    /// Session error
    #[error("Session error: {0}")]
    SessionError(String),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Token generation error
    #[error("Token generation error: {0}")]
    TokenGeneration(String),

    /// Invalid token error
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Unsupported provider error
    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),

    /// Network error with custom message
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Parse error with custom message
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Configuration error with custom message
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Token-specific errors
#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token has expired")]
    Expired,

    #[error("Token is invalid")]
    Invalid { message: String },

    #[error("Token not found")]
    NotFound,

    #[error("Token is missing")]
    Missing,

    #[error("Token creation failed: {message}")]
    CreationFailed { message: String },

    #[error("Token refresh failed: {message}")]
    RefreshFailed { message: String },

    #[error("Token revocation failed: {message}")]
    RevocationFailed { message: String },
}

/// Permission-specific errors
#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("Access denied: missing permission '{permission}' for resource '{resource}'")]
    AccessDenied {
        permission: String,
        resource: String,
    },

    #[error("Role '{role}' not found")]
    RoleNotFound { role: String },

    #[error("Permission '{permission}' not found")]
    PermissionNotFound { permission: String },

    #[error("Invalid permission format: {message}")]
    InvalidFormat { message: String },

    #[error("Permission denied: {message}")]
    Denied {
        action: String,
        resource: String,
        message: String,
    },
}

/// Storage-specific errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Operation failed: {message}")]
    OperationFailed { message: String },

    #[error("Serialization error: {message}")]
    Serialization { message: String },

    #[error("Storage backend not available")]
    BackendUnavailable,
}

/// MFA-specific errors
#[derive(Error, Debug)]
pub enum MfaError {
    #[error("MFA challenge expired")]
    ChallengeExpired,

    #[error("Invalid MFA code")]
    InvalidCode,

    #[error("MFA method not supported: {method}")]
    MethodNotSupported { method: String },

    #[error("MFA setup required")]
    SetupRequired,

    #[error("MFA verification failed: {message}")]
    VerificationFailed { message: String },
}

/// Device flow specific errors
#[derive(Error, Debug)]
pub enum DeviceFlowError {
    #[error("Authorization pending - user has not yet completed authorization")]
    AuthorizationPending,

    #[error("Slow down - polling too frequently")]
    SlowDown,

    #[error("Device code expired")]
    ExpiredToken,

    #[error("Access denied by user")]
    AccessDenied,

    #[error("Invalid device code")]
    InvalidDeviceCode,

    #[error("Unsupported grant type")]
    UnsupportedGrantType,
}

/// OAuth provider specific errors
#[derive(Error, Debug)]
pub enum OAuthProviderError {
    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,

    #[error("Invalid redirect URI")]
    InvalidRedirectUri,

    #[error("Invalid client credentials")]
    InvalidClientCredentials,

    #[error("Insufficient scope: required '{required}', granted '{granted}'")]
    InsufficientScope { required: String, granted: String },

    #[error("Provider '{provider}' does not support '{feature}'")]
    UnsupportedFeature { provider: String, feature: String },

    #[error("Rate limited by provider: {message}")]
    RateLimited { message: String },
}

impl AuthError {
    /// Create a new configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            source: None,
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }

    /// Create a configuration error with helpful context
    pub fn config_with_help(
        message: impl Into<String>,
        help: impl Into<String>,
        suggested_fix: Option<String>,
    ) -> Self {
        Self::Configuration {
            message: message.into(),
            source: None,
            help: Some(help.into()),
            docs_url: Some(
                "https://docs.rs/auth-framework/latest/auth_framework/config/".to_string(),
            ),
            suggested_fix,
        }
    }

    /// Create a JWT secret validation error with helpful guidance
    pub fn jwt_secret_too_short(current_length: usize) -> Self {
        Self::Configuration {
            message: format!(
                "JWT secret too short (got {} characters, need 32+ for security)",
                current_length
            ),
            source: None,
            help: Some("Use a cryptographically secure random string of at least 32 characters".to_string()),
            docs_url: Some("https://docs.rs/auth-framework/latest/auth_framework/config/struct.SecurityConfig.html".to_string()),
            suggested_fix: Some("Generate a secure secret: `openssl rand -hex 32`".to_string()),
        }
    }

    /// Create a production environment error with guidance
    pub fn production_memory_storage() -> Self {
        Self::Configuration {
            message: "Memory storage is not suitable for production environments".to_string(),
            source: None,
            help: Some("Use a persistent storage backend like PostgreSQL or Redis".to_string()),
            docs_url: Some("https://docs.rs/auth-framework/latest/auth_framework/storage/".to_string()),
            suggested_fix: Some("Configure PostgreSQL: .with_postgres(\"postgresql://...\") or Redis: .with_redis(\"redis://...\")".to_string()),
        }
    }

    /// Create a new auth method error
    pub fn auth_method(method: impl Into<String>, message: impl Into<String>) -> Self {
        Self::AuthMethod {
            method: method.into(),
            message: message.into(),
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }

    /// Create an auth method error with helpful context
    pub fn auth_method_with_help(
        method: impl Into<String>,
        message: impl Into<String>,
        help: impl Into<String>,
        suggested_fix: Option<String>,
    ) -> Self {
        Self::AuthMethod {
            method: method.into(),
            message: message.into(),
            help: Some(help.into()),
            docs_url: Some(
                "https://docs.rs/auth-framework/latest/auth_framework/methods/".to_string(),
            ),
            suggested_fix,
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create a new crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a new validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create a new internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Create an authorization error
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Permission(PermissionError::Denied {
            action: "authorize".to_string(),
            resource: "resource".to_string(),
            message: message.into(),
        })
    }

    /// Create an access denied error
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::Permission(PermissionError::Denied {
            action: "access".to_string(),
            resource: "resource".to_string(),
            message: message.into(),
        })
    }

    /// Create a token error
    pub fn token(message: impl Into<String>) -> Self {
        Self::Token(TokenError::Invalid {
            message: message.into(),
        })
    }

    /// Create a device flow error
    pub fn device_flow(error: DeviceFlowError) -> Self {
        Self::DeviceFlow(error)
    }

    /// Create an OAuth provider error
    pub fn oauth_provider(error: OAuthProviderError) -> Self {
        Self::OAuthProvider(error)
    }

    /// Create a user profile error
    pub fn user_profile(message: impl Into<String>) -> Self {
        Self::UserProfile {
            message: message.into(),
        }
    }

    /// Create an invalid credential error
    pub fn invalid_credential(
        credential_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidCredential {
            credential_type: credential_type.into(),
            message: message.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(timeout_seconds: u64) -> Self {
        Self::Timeout { timeout_seconds }
    }

    /// Create a provider not configured error
    pub fn provider_not_configured(provider: impl Into<String>) -> Self {
        Self::ProviderNotConfigured {
            provider: provider.into(),
        }
    }

    /// Create a rate limited error
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create a configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            source: None,
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }
}

impl TokenError {
    /// Create a new token creation failed error
    pub fn creation_failed(message: impl Into<String>) -> Self {
        Self::CreationFailed {
            message: message.into(),
        }
    }

    /// Create a new token refresh failed error
    pub fn refresh_failed(message: impl Into<String>) -> Self {
        Self::RefreshFailed {
            message: message.into(),
        }
    }

    /// Create a new token revocation failed error
    pub fn revocation_failed(message: impl Into<String>) -> Self {
        Self::RevocationFailed {
            message: message.into(),
        }
    }
}

impl PermissionError {
    /// Create a new access denied error
    pub fn access_denied(permission: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::AccessDenied {
            permission: permission.into(),
            resource: resource.into(),
        }
    }

    /// Create a new role not found error
    pub fn role_not_found(role: impl Into<String>) -> Self {
        Self::RoleNotFound { role: role.into() }
    }

    /// Create a new permission not found error
    pub fn permission_not_found(permission: impl Into<String>) -> Self {
        Self::PermissionNotFound {
            permission: permission.into(),
        }
    }

    /// Create a new invalid format error
    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: message.into(),
        }
    }
}

impl StorageError {
    /// Create a new connection failed error
    pub fn connection_failed(message: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            message: message.into(),
        }
    }

    /// Create a new operation failed error
    pub fn operation_failed(message: impl Into<String>) -> Self {
        Self::OperationFailed {
            message: message.into(),
        }
    }

    /// Create a new serialization error
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }
}

impl MfaError {
    /// Create a new method not supported error
    pub fn method_not_supported(method: impl Into<String>) -> Self {
        Self::MethodNotSupported {
            method: method.into(),
        }
    }

    /// Create a new verification failed error
    pub fn verification_failed(message: impl Into<String>) -> Self {
        Self::VerificationFailed {
            message: message.into(),
        }
    }
}

// Actix-web ResponseError implementation
#[cfg(feature = "actix-integration")]
impl actix_web::ResponseError for AuthError {
    fn error_response(&self) -> actix_web::HttpResponse {
        match self {
            AuthError::Token(_) => {
                actix_web::HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": self.to_string()
                }))
            }
            AuthError::Permission(_) => {
                actix_web::HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "insufficient_permissions",
                    "error_description": self.to_string()
                }))
            }
            AuthError::RateLimit { .. } => {
                actix_web::HttpResponse::TooManyRequests().json(serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "error_description": self.to_string()
                }))
            }
            AuthError::Configuration { .. } | AuthError::Storage(_) => {
                actix_web::HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "An internal error occurred"
                }))
            }
            _ => actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                "error": "bad_request",
                "error_description": self.to_string()
            })),
        }
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            AuthError::Token(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            AuthError::Permission(_) => actix_web::http::StatusCode::FORBIDDEN,
            AuthError::RateLimit { .. } => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            AuthError::Configuration { .. } | AuthError::Storage(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }
}

// Additional From implementations for admin tools
impl From<Box<dyn std::error::Error + Send + Sync>> for AuthError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        AuthError::Cli(format!("Admin tool error: {}", error))
    }
}

impl From<Box<dyn std::error::Error>> for AuthError {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        AuthError::Cli(format!("Admin tool error: {}", error))
    }
}
