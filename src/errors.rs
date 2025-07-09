//! Error types for the authentication framework.

use thiserror::Error;

/// Result type alias for the authentication framework.
pub type Result<T> = std::result::Result<T, AuthError>;

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

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    /// MFA-related errors
    #[error("MFA error: {0}")]
    Mfa(#[from] MfaError),

    /// Cryptography errors
    #[error("Cryptography error: {message}")]
    Crypto { message: String },

    /// Validation errors
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// Generic internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

/// Token-specific errors
#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token has expired")]
    Expired,

    #[error("Token is invalid")]
    Invalid,

    #[error("Token not found")]
    NotFound,

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
    AccessDenied { permission: String, resource: String },

    #[error("Role '{role}' not found")]
    RoleNotFound { role: String },

    #[error("Permission '{permission}' not found")]
    PermissionNotFound { permission: String },

    #[error("Invalid permission format: {message}")]
    InvalidFormat { message: String },
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
        Self::RoleNotFound {
            role: role.into(),
        }
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
