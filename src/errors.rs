//! Error types for the authentication framework.

use thiserror::Error;

/// Result type alias for the authentication framework.
pub type Result<T, E = AuthError> = std::result::Result<T, E>;

/// Main error type for the authentication framework.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Configuration errors
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// Authentication method errors
    #[error("Authentication method '{method}' error: {message}")]
    AuthMethod { method: String, message: String },

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
    Toml(#[from] toml::ser::Error),

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
        }
    }

    /// Create a new auth method error
    pub fn auth_method(method: impl Into<String>, message: impl Into<String>) -> Self {
        Self::AuthMethod {
            method: method.into(),
            message: message.into(),
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
