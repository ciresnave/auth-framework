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
//! ```rust,no_run
//! use auth_framework::{AuthFramework, AuthError};
//! use auth_framework::authentication::credentials::Credential;
//! use auth_framework::authentication::CredentialMetadata;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let auth_framework: AuthFramework = unimplemented!();
//! # let credential: Credential = unimplemented!();
//! # fn handle_success<T>(_: T) {}
//! # fn respond_with_auth_failure() {}
//! # fn respond_with_rate_limit(_: Option<u64>) {}
//! # fn respond_with_system_error() {}
//! match auth_framework.authenticate("password", credential).await {
//!     Ok(result) => handle_success(result),
//!     Err(AuthError::InvalidCredential { credential_type, message, .. }) => {
//!         log::warn!("Invalid {} credential: {}", credential_type, message);
//!         respond_with_auth_failure()
//!     },
//!     Err(AuthError::RateLimit { message, .. }) => {
//!         respond_with_rate_limit(None)
//!     },
//!     Err(e) => {
//!         log::error!("Authentication system error: {}", e);
//!         respond_with_system_error()
//!     }
//! }
//! # Ok(())
//! # }
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
/// ```rust,no_run
/// use auth_framework::AuthError;
///
/// # let auth_result: auth_framework::errors::Result<()> = Ok(());
/// // Enhanced error handling with contextual help
/// match auth_result {
///     Err(AuthError::Configuration { message, help, docs_url, .. }) => {
///         eprintln!("Configuration Error: {}", message);
///         if let Some(help) = help {
///             eprintln!("Help: {}", help);
///         }
///         if let Some(docs) = docs_url {
///             eprintln!("See: {}", docs);
///         }
///     },
///     Err(AuthError::InvalidCredential { credential_type, message, .. }) => {
///         eprintln!("Invalid {}: {}", credential_type, message);
///     },
///     // ... handle other error types
///     _ => {}
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
    Toml(#[from] toml::ser::Error),

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
    #[error(
        "Too many concurrent sessions for user (limit reached). \
             Revoke an existing session before creating a new one."
    )]
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

    /// The stored password hash does not match the supplied credential.
    ///
    /// This typically means the user entered the wrong password. Do **not**
    /// reveal which field (username vs. password) was incorrect to the caller.
    #[error("Password verification failed: {0}")]
    PasswordVerification(String),

    /// The password hashing algorithm (argon2/bcrypt) encountered an error.
    #[error("Password hashing failed: {0}")]
    PasswordHashing(String),

    /// No user record exists for the given identifier.
    #[error("User not found. The requested user ID does not exist in the store.")]
    UserNotFound,

    /// A request parameter failed validation (e.g. empty username, invalid email format).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// A hardware security key (FIDO2 / WebAuthn) operation failed.
    #[error("Hardware token error: {0}")]
    HardwareToken(String),

    /// A one-time backup code was rejected (already used, incorrect, or expired).
    #[error("Backup code verification failed: {0}")]
    BackupCodeVerification(String),

    /// Failed to hash a backup code for secure storage.
    #[error("Backup code hashing failed: {0}")]
    BackupCodeHashing(String),

    /// The TOTP or MFA secret is in an invalid format (e.g. not valid Base32).
    #[error("Invalid secret format")]
    InvalidSecret,

    /// An error occurred while reading or updating a user profile.
    #[error("User profile error: {message}")]
    UserProfile { message: String },

    /// Credential validation errors
    #[error("Invalid credential: {credential_type} - {message}")]
    InvalidCredential {
        credential_type: String,
        message: String,
    },

    /// An authentication operation did not complete within the allowed window.
    #[error("Authentication timeout after {timeout_seconds} seconds")]
    Timeout { timeout_seconds: u64 },

    /// Provider configuration missing
    #[error(
        "Provider '{provider}' is not configured or supported. \
             Add it via AuthConfig::method_config() or check available providers."
    )]
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

    /// A session-layer error (e.g. session not found, session expired, store failure).
    #[error("Session error: {0}")]
    SessionError(String),

    /// The caller lacks valid credentials or the credentials have been revoked.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Token creation failed at the signing or encoding stage.
    ///
    /// Consider using [`AuthError::token`] for richer [`TokenError`] variants.
    #[error("Token generation error: {0}")]
    TokenGeneration(String),

    /// Invalid token error.
    ///
    /// **Prefer** [`AuthError::token`] which routes through the structured
    /// [`TokenError`] hierarchy for consistent token error handling.
    #[deprecated(
        since = "0.5.0",
        note = "Use `AuthError::token(msg)` instead — it routes through the structured TokenError hierarchy"
    )]
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// The named authentication provider is not compiled in or not recognized.
    #[error("Unsupported provider: {0}")]
    UnsupportedProvider(String),

    /// Network error with custom message.
    ///
    /// **Prefer** [`AuthError::Internal`] with a descriptive message, or let
    /// [`reqwest::Error`] convert automatically via the [`From`] impl on
    /// [`AuthError::Network`].
    #[deprecated(
        since = "0.5.0",
        note = "Use `AuthError::internal(msg)` or let `reqwest::Error` convert via `AuthError::Network` instead"
    )]
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Parse error with custom message.
    ///
    /// **Prefer** [`AuthError::Internal`] with a descriptive message, or let
    /// [`serde_json::Error`] convert automatically via the [`From`] impl on
    /// [`AuthError::Json`].
    #[deprecated(
        since = "0.5.0",
        note = "Use `AuthError::internal(msg)` or let serde errors convert via `AuthError::Json` instead"
    )]
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Configuration error with custom message.
    ///
    /// **Prefer** [`AuthError::config`] or [`AuthError::config_with_help`] which
    /// carry richer context (help text, docs URL, suggested fix).
    #[deprecated(
        since = "0.5.0",
        note = "Use `AuthError::config(msg)` instead — it provides richer context fields"
    )]
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Token-specific errors.
///
/// Covers the lifecycle of authentication tokens: creation, validation,
/// refresh, and revocation.
#[derive(Error, Debug)]
pub enum TokenError {
    /// The token's `exp` claim is in the past.
    #[error("Token has expired")]
    Expired,

    /// The token failed signature verification or structural validation.
    #[error("Token is invalid: {message}")]
    Invalid { message: String },

    /// No token matching the given identifier exists in the store.
    #[error("Token not found")]
    NotFound,

    /// The request did not include a required token (e.g. missing `Authorization` header).
    #[error("Token is missing")]
    Missing,

    /// A new token could not be issued (e.g. signing key unavailable).
    #[error("Token creation failed: {message}")]
    CreationFailed { message: String },

    /// An existing token could not be refreshed (e.g. refresh token revoked).
    #[error("Token refresh failed: {message}")]
    RefreshFailed { message: String },

    /// Token revocation did not complete (e.g. storage write failure).
    #[error("Token revocation failed: {message}")]
    RevocationFailed { message: String },
}

/// Permission and access-control errors.
///
/// Returned when an authenticated principal lacks the required permissions
/// or roles to perform an operation.
#[derive(Error, Debug)]
pub enum PermissionError {
    /// The principal does not hold the required permission for the target resource.
    #[error("Access denied: missing permission '{permission}' for resource '{resource}'")]
    AccessDenied {
        permission: String,
        resource: String,
    },

    /// The specified role does not exist in the role store.
    #[error("Role '{role}' not found")]
    RoleNotFound { role: String },

    /// The specified permission identifier does not exist.
    #[error("Permission '{permission}' not found")]
    PermissionNotFound { permission: String },

    /// A permission string could not be parsed (e.g. missing `resource:action` separator).
    #[error("Invalid permission format: {message}")]
    InvalidFormat { message: String },

    /// General permission denial with a descriptive message.
    #[error("Permission denied: {message}")]
    Denied {
        action: String,
        resource: String,
        message: String,
    },
}

/// Storage backend errors.
///
/// Covers connectivity, query execution, and serialization issues for
/// all storage backends (Memory, PostgreSQL, MySQL, Redis, SQLite).
#[derive(Error, Debug)]
pub enum StorageError {
    /// Could not establish a connection to the storage backend.
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    /// A read or write operation against the store failed.
    #[error("Operation failed: {message}")]
    OperationFailed { message: String },

    /// Data could not be serialized to or deserialized from the storage format.
    #[error("Serialization error: {message}")]
    Serialization { message: String },

    /// The configured storage backend is unreachable or not initialized.
    #[error("Storage backend not available")]
    BackendUnavailable,
}

/// Multi-factor authentication errors.
#[derive(Error, Debug)]
pub enum MfaError {
    /// The MFA challenge window has elapsed; the user must request a new challenge.
    #[error("MFA challenge expired")]
    ChallengeExpired,

    /// The TOTP or one-time code provided by the user is incorrect.
    #[error("Invalid MFA code")]
    InvalidCode,

    /// The requested MFA method (e.g. SMS, hardware key) is not enabled.
    #[error("MFA method not supported: {method}")]
    MethodNotSupported { method: String },

    /// MFA has not been configured for this account yet.
    #[error("MFA setup required")]
    SetupRequired,

    /// MFA verification failed for a reason described in `message`.
    #[error("MFA verification failed: {message}")]
    VerificationFailed { message: String },
}

/// Device Authorization Grant (RFC 8628) errors.
///
/// These map 1-to-1 to the error codes defined in RFC 8628 §3.5.
#[derive(Error, Debug)]
pub enum DeviceFlowError {
    /// The user has not yet completed authorization on the verification URI.
    #[error("Authorization pending - user has not yet completed authorization")]
    AuthorizationPending,

    /// The client is polling faster than the allowed `interval`.
    #[error("Slow down - polling too frequently")]
    SlowDown,

    /// The device code has exceeded its `expires_in` window.
    #[error("Device code expired")]
    ExpiredToken,

    /// The end user denied the authorization request.
    #[error("Access denied by user")]
    AccessDenied,

    /// The device code presented by the client is not recognized.
    #[error("Invalid device code")]
    InvalidDeviceCode,

    /// The grant type is not supported by this server.
    #[error("Unsupported grant type")]
    UnsupportedGrantType,
}

/// OAuth 2.0 provider interaction errors.
///
/// Covers issues encountered when communicating with upstream OAuth providers
/// or when validating OAuth protocol messages.
#[derive(Error, Debug)]
pub enum OAuthProviderError {
    /// The authorization code is expired, already consumed, or invalid.
    #[error("Invalid authorization code")]
    InvalidAuthorizationCode,

    /// The `redirect_uri` does not match the registered value for the client.
    #[error("Invalid redirect URI")]
    InvalidRedirectUri,

    /// The client ID or client secret is incorrect.
    #[error("Invalid client credentials")]
    InvalidClientCredentials,

    /// The granted scopes do not satisfy the required scopes for the operation.
    #[error("Insufficient scope: required '{required}', granted '{granted}'")]
    InsufficientScope { required: String, granted: String },

    /// The provider does not implement the requested feature.
    #[error("Provider '{provider}' does not support '{feature}'")]
    UnsupportedFeature { provider: String, feature: String },

    /// The upstream provider returned a rate-limit response.
    #[error("Rate limited by provider: {message}")]
    RateLimited { message: String },
}

impl AuthError {
    /// Create a new configuration error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::config("Missing database URL");
    /// assert!(err.to_string().contains("Missing database URL"));
    /// ```
    pub fn config(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            source: None,
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }

    /// Create a configuration error with helpful context.
    ///
    /// Includes a human-readable `help` string and an optional `suggested_fix`
    /// that can be displayed by CLI tools or IDE integrations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::config_with_help(
    ///     "JWT secret not set",
    ///     "Set the JWT_SECRET environment variable",
    ///     Some("export JWT_SECRET=$(openssl rand -hex 32)".into()),
    /// );
    /// assert!(err.to_string().contains("JWT secret not set"));
    /// ```
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

    /// Create a JWT secret validation error with helpful guidance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::jwt_secret_too_short(16);
    /// assert!(err.to_string().contains("16 characters"));
    /// ```
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

    /// Create a production environment error with guidance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::production_memory_storage();
    /// assert!(err.to_string().contains("Memory storage"));
    /// ```
    pub fn production_memory_storage() -> Self {
        Self::Configuration {
            message: "Memory storage is not suitable for production environments".to_string(),
            source: None,
            help: Some("Use a persistent storage backend like PostgreSQL or Redis".to_string()),
            docs_url: Some("https://docs.rs/auth-framework/latest/auth_framework/storage/".to_string()),
            suggested_fix: Some("Configure PostgreSQL: .with_postgres(\"postgresql://...\") or Redis: .with_redis(\"redis://...\")".to_string()),
        }
    }

    /// Create a new auth method error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::auth_method("oauth2", "token endpoint unreachable");
    /// assert!(err.to_string().contains("oauth2"));
    /// ```
    pub fn auth_method(method: impl Into<String>, message: impl Into<String>) -> Self {
        Self::AuthMethod {
            method: method.into(),
            message: message.into(),
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }

    /// Create an auth method error with helpful context.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::auth_method_with_help(
    ///     "saml",
    ///     "certificate expired",
    ///     "Renew the SAML signing certificate",
    ///     Some("openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem".into()),
    /// );
    /// assert!(err.to_string().contains("saml"));
    /// ```
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

    /// Create a new rate limit error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::rate_limit("too many login attempts");
    /// assert!(err.to_string().contains("too many login attempts"));
    /// ```
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create a new crypto error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::crypto("HMAC key too short");
    /// assert!(err.to_string().contains("HMAC key too short"));
    /// ```
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }

    /// Create a new validation error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::validation("email format invalid");
    /// assert!(err.to_string().contains("email format invalid"));
    /// ```
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Create a new internal error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::internal("unexpected state");
    /// assert!(err.to_string().contains("unexpected state"));
    /// ```
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Create an authorization error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::authorization("insufficient privileges");
    /// assert!(err.to_string().contains("insufficient privileges"));
    /// ```
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Permission(PermissionError::Denied {
            action: "authorize".to_string(),
            resource: "resource".to_string(),
            message: message.into(),
        })
    }

    /// Create an access denied error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::access_denied("admin role required");
    /// assert!(err.to_string().contains("admin role required"));
    /// ```
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::Permission(PermissionError::Denied {
            action: "access".to_string(),
            resource: "resource".to_string(),
            message: message.into(),
        })
    }

    /// Create a token error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::token("signature mismatch");
    /// assert!(err.to_string().contains("signature mismatch"));
    /// ```
    pub fn token(message: impl Into<String>) -> Self {
        Self::Token(TokenError::Invalid {
            message: message.into(),
        })
    }

    /// Create a device flow error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::{AuthError, DeviceFlowError};
    ///
    /// let err = AuthError::device_flow(DeviceFlowError::ExpiredToken);
    /// assert!(err.to_string().contains("expired"));
    /// ```
    pub fn device_flow(error: DeviceFlowError) -> Self {
        Self::DeviceFlow(error)
    }

    /// Create an OAuth provider error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::{AuthError, OAuthProviderError};
    ///
    /// let err = AuthError::oauth_provider(OAuthProviderError::InvalidRedirectUri);
    /// assert!(err.to_string().contains("redirect"));
    /// ```
    pub fn oauth_provider(error: OAuthProviderError) -> Self {
        Self::OAuthProvider(error)
    }

    /// Create a user profile error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::user_profile("email already in use");
    /// assert!(err.to_string().contains("email already in use"));
    /// ```
    pub fn user_profile(message: impl Into<String>) -> Self {
        Self::UserProfile {
            message: message.into(),
        }
    }

    /// Create an invalid credential error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::invalid_credential("password", "too short");
    /// assert!(err.to_string().contains("password"));
    /// ```
    pub fn invalid_credential(
        credential_type: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidCredential {
            credential_type: credential_type.into(),
            message: message.into(),
        }
    }

    /// Create a timeout error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::timeout(30);
    /// assert!(err.to_string().contains("30"));
    /// ```
    pub fn timeout(timeout_seconds: u64) -> Self {
        Self::Timeout { timeout_seconds }
    }

    /// Create a provider not configured error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::provider_not_configured("github");
    /// assert!(err.to_string().contains("github"));
    /// ```
    pub fn provider_not_configured(provider: impl Into<String>) -> Self {
        Self::ProviderNotConfigured {
            provider: provider.into(),
        }
    }

    /// Create a rate limited error (alias for [`rate_limit`](Self::rate_limit)).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::rate_limited("5 requests per second exceeded");
    /// assert!(err.to_string().contains("5 requests"));
    /// ```
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create a configuration error (alias for [`config`](Self::config)).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// let err = AuthError::configuration("invalid issuer URL");
    /// assert!(err.to_string().contains("invalid issuer URL"));
    /// ```
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
            source: None,
            help: None,
            docs_url: None,
            suggested_fix: None,
        }
    }

    // -----------------------------------------------------------------------
    // Classification helpers — framework-agnostic error introspection
    // -----------------------------------------------------------------------

    /// Return the HTTP status code that best represents this error.
    ///
    /// This is framework-agnostic and works without enabling any web framework
    /// feature flag. Web framework integrations (actix-web, axum, …) use this
    /// internally but you can also call it directly when building custom
    /// response types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// assert_eq!(AuthError::rate_limit("slow down").http_status_code(), 429);
    /// assert_eq!(AuthError::internal("oops").http_status_code(), 500);
    /// assert_eq!(AuthError::token("bad jwt").http_status_code(), 401);
    /// ```
    pub fn http_status_code(&self) -> u16 {
        match self {
            // 400 Bad Request
            Self::InvalidInput(_)
            | Self::Validation { .. }
            | Self::InvalidCredential { .. }
            | Self::HardwareToken(_)
            | Self::InvalidRequest(_)
            | Self::InvalidSecret => 400,

            // 401 Unauthorized
            Self::Token(_)
            | Self::AuthMethod { .. }
            | Self::Jwt(_)
            | Self::Unauthorized(_)
            | Self::PasswordVerification(_) => 401,

            // 403 Forbidden
            Self::Permission(_) | Self::StepUpRequired { .. } => 403,

            // 404 Not Found
            Self::UserNotFound | Self::ProviderNotConfigured { .. } => 404,

            // 408 Request Timeout
            Self::Timeout { .. } => 408,

            // 429 Too Many Requests
            Self::RateLimit { .. } | Self::TooManyConcurrentSessions => 429,

            // 502 Bad Gateway (upstream provider errors)
            Self::OAuthProvider(_) | Self::Network(_) => 502,

            // 503 Service Unavailable (storage / infra)
            Self::Storage(_) => 503,

            // 500 Internal Server Error (everything else)
            Self::Configuration { .. }
            | Self::Crypto { .. }
            | Self::Internal { .. }
            | Self::Json(_)
            | Self::Yaml(_)
            | Self::Toml(_)
            | Self::Io(_)
            | Self::Mfa(_)
            | Self::DeviceFlow(_)
            | Self::TokenGeneration(_)
            | Self::SessionError(_)
            | Self::UserProfile { .. }
            | Self::Cli(_)
            | Self::SystemTime(_)
            | Self::PasswordHashing(_)
            | Self::BackupCodeVerification(_)
            | Self::BackupCodeHashing(_)
            | Self::UnsupportedProvider(_) => 500,

            #[cfg(feature = "prometheus")]
            Self::Metrics(_) => 500,

            // Deprecated variants
            #[allow(deprecated)]
            Self::InvalidToken(_)
            | Self::NetworkError(_)
            | Self::ParseError(_)
            | Self::ConfigurationError(_) => 500,
        }
    }

    /// Whether this error is transient and the operation may succeed on retry.
    ///
    /// Returns `true` for rate-limit, timeout, network, and storage
    /// connectivity errors. Returns `false` for authentication failures,
    /// validation errors, and other permanent conditions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// assert!(AuthError::rate_limit("too fast").is_retryable());
    /// assert!(AuthError::timeout(30).is_retryable());
    /// assert!(!AuthError::token("invalid").is_retryable());
    /// assert!(!AuthError::validation("bad input").is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimit { .. }
                | Self::Timeout { .. }
                | Self::TooManyConcurrentSessions
                | Self::Network(_)
                | Self::Storage(StorageError::ConnectionFailed { .. })
        )
    }

    /// A short, stable, machine-readable code for this error category.
    ///
    /// Useful for API responses, metrics labels, and log filtering.
    /// These codes are stable across patch releases.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// assert_eq!(AuthError::rate_limit("nope").error_code(), "rate_limit");
    /// assert_eq!(AuthError::token("bad").error_code(), "invalid_token");
    /// assert_eq!(AuthError::config("bad").error_code(), "configuration");
    /// ```
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "configuration",
            Self::AuthMethod { .. } => "auth_method",
            Self::Token(_) => "invalid_token",
            Self::Permission(_) => "insufficient_permissions",
            Self::Storage(_) => "storage",
            Self::Network(_) => "network",
            Self::Json(_) | Self::Yaml(_) | Self::Toml(_) => "serialization",
            Self::Jwt(_) => "jwt",
            Self::Io(_) => "io",
            Self::RateLimit { .. } => "rate_limit",
            Self::TooManyConcurrentSessions => "concurrent_sessions",
            Self::Mfa(_) => "mfa",
            Self::DeviceFlow(_) => "device_flow",
            Self::OAuthProvider(_) => "oauth_provider",
            Self::PasswordVerification(_) => "password_verification",
            Self::UserNotFound => "user_not_found",
            Self::InvalidInput(_) => "invalid_input",
            Self::HardwareToken(_) => "hardware_token",
            Self::InvalidCredential { .. } => "invalid_credential",
            Self::Timeout { .. } => "timeout",
            Self::Crypto { .. } => "crypto",
            Self::Validation { .. } => "validation",
            Self::Internal { .. } => "internal",
            Self::StepUpRequired { .. } => "step_up_required",
            Self::SessionError(_) => "session",
            Self::Unauthorized(_) => "unauthorized",
            Self::TokenGeneration(_) => "token_generation",
            Self::UserProfile { .. } => "user_profile",
            Self::ProviderNotConfigured { .. } => "provider_not_configured",
            Self::Cli(_) => "cli",
            Self::SystemTime(_) => "internal",
            Self::PasswordHashing(_) => "password_hashing",
            Self::BackupCodeVerification(_) => "backup_code",
            Self::BackupCodeHashing(_) => "backup_code",
            Self::InvalidSecret => "invalid_secret",
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnsupportedProvider(_) => "unsupported_provider",
            #[cfg(feature = "prometheus")]
            Self::Metrics(_) => "metrics",
            #[allow(deprecated)]
            Self::InvalidToken(_) => "invalid_token",
            #[allow(deprecated)]
            Self::NetworkError(_) => "network",
            #[allow(deprecated)]
            Self::ParseError(_) => "parse",
            #[allow(deprecated)]
            Self::ConfigurationError(_) => "configuration",
        }
    }

    /// Whether this is a client-side error (4xx status code).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// assert!(AuthError::validation("bad").is_client_error());
    /// assert!(!AuthError::internal("oops").is_client_error());
    /// ```
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.http_status_code())
    }

    /// Whether this is a server-side error (5xx status code).
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::AuthError;
    ///
    /// assert!(AuthError::internal("oops").is_server_error());
    /// assert!(!AuthError::validation("bad").is_server_error());
    /// ```
    pub fn is_server_error(&self) -> bool {
        self.http_status_code() >= 500
    }
}

impl TokenError {
    /// Create a new token creation failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::TokenError;
    ///
    /// let err = TokenError::creation_failed("signing key unavailable");
    /// assert!(err.to_string().contains("signing key unavailable"));
    /// ```
    pub fn creation_failed(message: impl Into<String>) -> Self {
        Self::CreationFailed {
            message: message.into(),
        }
    }

    /// Create a new token refresh failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::TokenError;
    ///
    /// let err = TokenError::refresh_failed("refresh token revoked");
    /// assert!(err.to_string().contains("refresh token revoked"));
    /// ```
    pub fn refresh_failed(message: impl Into<String>) -> Self {
        Self::RefreshFailed {
            message: message.into(),
        }
    }

    /// Create a new token revocation failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::TokenError;
    ///
    /// let err = TokenError::revocation_failed("storage write failed");
    /// assert!(err.to_string().contains("storage write failed"));
    /// ```
    pub fn revocation_failed(message: impl Into<String>) -> Self {
        Self::RevocationFailed {
            message: message.into(),
        }
    }
}

impl PermissionError {
    /// Create a new access denied error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::PermissionError;
    ///
    /// let err = PermissionError::access_denied("write", "documents");
    /// assert!(err.to_string().contains("write"));
    /// ```
    pub fn access_denied(permission: impl Into<String>, resource: impl Into<String>) -> Self {
        Self::AccessDenied {
            permission: permission.into(),
            resource: resource.into(),
        }
    }

    /// Create a new role not found error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::PermissionError;
    ///
    /// let err = PermissionError::role_not_found("superadmin");
    /// assert!(err.to_string().contains("superadmin"));
    /// ```
    pub fn role_not_found(role: impl Into<String>) -> Self {
        Self::RoleNotFound { role: role.into() }
    }

    /// Create a new permission not found error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::PermissionError;
    ///
    /// let err = PermissionError::permission_not_found("delete_user");
    /// assert!(err.to_string().contains("delete_user"));
    /// ```
    pub fn permission_not_found(permission: impl Into<String>) -> Self {
        Self::PermissionNotFound {
            permission: permission.into(),
        }
    }

    /// Create a new invalid format error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::PermissionError;
    ///
    /// let err = PermissionError::invalid_format("missing resource:action separator");
    /// assert!(err.to_string().contains("separator"));
    /// ```
    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: message.into(),
        }
    }
}

impl StorageError {
    /// Create a new connection failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::StorageError;
    ///
    /// let err = StorageError::connection_failed("connection refused");
    /// assert!(err.to_string().contains("connection refused"));
    /// ```
    pub fn connection_failed(message: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            message: message.into(),
        }
    }

    /// Create a new operation failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::StorageError;
    ///
    /// let err = StorageError::operation_failed("table not found");
    /// assert!(err.to_string().contains("table not found"));
    /// ```
    pub fn operation_failed(message: impl Into<String>) -> Self {
        Self::OperationFailed {
            message: message.into(),
        }
    }

    /// Create a new serialization error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::StorageError;
    ///
    /// let err = StorageError::serialization("invalid JSON");
    /// assert!(err.to_string().contains("invalid JSON"));
    /// ```
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization {
            message: message.into(),
        }
    }
}

impl MfaError {
    /// Create a new method not supported error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::MfaError;
    ///
    /// let err = MfaError::method_not_supported("biometric");
    /// assert!(err.to_string().contains("biometric"));
    /// ```
    pub fn method_not_supported(method: impl Into<String>) -> Self {
        Self::MethodNotSupported {
            method: method.into(),
        }
    }

    /// Create a new verification failed error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_framework::errors::MfaError;
    ///
    /// let err = MfaError::verification_failed("code expired");
    /// assert!(err.to_string().contains("code expired"));
    /// ```
    pub fn verification_failed(message: impl Into<String>) -> Self {
        Self::VerificationFailed {
            message: message.into(),
        }
    }
}

// Actix-web ResponseError implementation
#[cfg(feature = "actix-web")]
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
            AuthError::Configuration { .. }
            | AuthError::Storage(_)
            | AuthError::Internal { .. } => {
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
            AuthError::Internal { .. }
            | AuthError::Configuration { .. }
            | AuthError::Storage(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_auth_error_creation() {
        let token_error = AuthError::token("Invalid JWT signature");
        assert!(matches!(token_error, AuthError::Token(_)));
        assert!(token_error.to_string().contains("Invalid JWT signature"));

        let permission_error = AuthError::access_denied("Access denied");
        assert!(matches!(permission_error, AuthError::Permission(_)));
        assert!(permission_error.to_string().contains("Access denied"));

        let config_error = AuthError::config("Database connection failed");
        assert!(matches!(config_error, AuthError::Configuration { .. }));
        assert!(
            config_error
                .to_string()
                .contains("Database connection failed")
        );
    }

    #[test]
    fn test_auth_error_categorization() {
        // Test various error types maintain their category
        let errors = vec![
            (AuthError::token("test"), "Token"),
            (AuthError::access_denied("test"), "Permission"),
            (AuthError::config("test"), "Configuration"),
            (AuthError::crypto("test"), "Crypto"),
            (AuthError::validation("test"), "Validation"),
        ];

        for (error, expected_category) in errors {
            let error_string = format!("{:?}", error);
            assert!(
                error_string.contains(expected_category),
                "Error {:?} should contain category {}",
                error,
                expected_category
            );
        }
    }

    #[test]
    fn test_rate_limit_error() {
        let rate_limit_error = AuthError::rate_limit("Too many requests");

        match rate_limit_error {
            AuthError::RateLimit { message } => {
                assert_eq!(message, "Too many requests");
            }
            _ => panic!("Expected RateLimit error"),
        }
    }

    #[test]
    fn test_validation_error() {
        let validation_error = AuthError::validation("username must not be empty");

        match validation_error {
            AuthError::Validation { message } => {
                assert_eq!(message, "username must not be empty");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_configuration_error() {
        let config_error = AuthError::config("jwt_secret is required");

        match config_error {
            AuthError::Configuration { message, .. } => {
                assert_eq!(message, "jwt_secret is required");
            }
            _ => panic!("Expected Configuration error"),
        }
    }

    #[test]
    fn test_error_chain() {
        let root_cause = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let auth_error = AuthError::internal(format!("Config file error: {}", root_cause));

        // Test that error information is preserved
        assert!(auth_error.to_string().contains("File not found"));
        assert!(auth_error.to_string().contains("Config file error"));
    }

    #[test]
    fn test_error_source() {
        let token_error = AuthError::token("JWT parsing failed");

        // AuthError implements Error trait
        // Token error wraps TokenError, so it should have a source
        assert!(token_error.source().is_some());

        // Test error display
        let error_msg = format!("{}", token_error);
        assert!(error_msg.contains("JWT parsing failed"));
    }

    #[test]
    fn test_from_conversions() {
        // Test conversion from std::io::Error
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let auth_error: AuthError = io_error.into();
        assert!(matches!(auth_error, AuthError::Io(_)));

        // Test conversion from serde_json::Error
        let json_str = r#"{"invalid": json"#;
        let json_error: serde_json::Error =
            serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let auth_error: AuthError = json_error.into();
        assert!(matches!(auth_error, AuthError::Json(_)));
    }

    #[test]
    fn test_error_equality() {
        let error1 = AuthError::token("Same message");
        let error2 = AuthError::token("Same message");
        let error3 = AuthError::token("Different message");

        // Test Debug representation for consistency
        assert_eq!(format!("{:?}", error1), format!("{:?}", error2));
        assert_ne!(format!("{:?}", error1), format!("{:?}", error3));
    }

    #[test]
    fn test_actix_web_integration() {
        #[cfg(feature = "actix-web")]
        {
            use actix_web::ResponseError;

            // Test status codes
            assert_eq!(
                AuthError::token("test").status_code(),
                actix_web::http::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                AuthError::access_denied("test").status_code(),
                actix_web::http::StatusCode::FORBIDDEN
            );
            assert_eq!(
                AuthError::rate_limit("test").status_code(),
                actix_web::http::StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                AuthError::internal("test").status_code(),
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            );
        }
    }

    #[test]
    fn test_error_message_safety() {
        // Ensure error messages don't leak sensitive information
        let sensitive_data = "password123";
        let safe_error = AuthError::token("Invalid credentials");

        // Error message should not contain sensitive data
        assert!(!safe_error.to_string().contains(sensitive_data));

        // Test that we can create errors without exposing internals
        let config_error = AuthError::config("connection failed");
        assert!(!config_error.to_string().contains("password"));
        assert!(!config_error.to_string().contains("secret"));
    }

    #[test]
    fn test_cli_error_conversion() {
        let boxed_error: Box<dyn std::error::Error + Send + Sync> = "CLI operation failed".into();
        let auth_error: AuthError = boxed_error.into();

        assert!(matches!(auth_error, AuthError::Cli(_)));
        assert!(auth_error.to_string().contains("CLI operation failed"));
    }

    #[test]
    fn test_error_variants_coverage() {
        // Ensure all error variants can be created and have proper messages
        let test_errors = vec![
            AuthError::token("token error"),
            AuthError::access_denied("permission error"),
            AuthError::internal("internal error"),
            AuthError::crypto("crypto error"),
            AuthError::Cli("cli error".to_string()),
            AuthError::validation("validation error"),
            AuthError::config("config error"),
            AuthError::rate_limit("rate limit error"),
        ];

        for error in test_errors {
            // All errors should have non-empty messages
            assert!(
                !error.to_string().is_empty(),
                "Error should have message: {:?}",
                error
            );

            // All errors should implement Debug
            let debug_repr = format!("{:?}", error);
            assert!(
                !debug_repr.is_empty(),
                "Error should have debug representation: {:?}",
                error
            );
        }
    }

    #[test]
    fn test_oauth_specific_errors() {
        // Test OAuth-specific error creation using auth_method
        let invalid_client = AuthError::auth_method("oauth", "Client authentication failed");
        assert!(
            invalid_client
                .to_string()
                .contains("Client authentication failed")
        );

        let invalid_grant = AuthError::auth_method("oauth", "Authorization code expired");
        assert!(
            invalid_grant
                .to_string()
                .contains("Authorization code expired")
        );
    }

    #[test]
    fn test_error_context_preservation() {
        // Test that errors maintain context through transformations
        let original_msg = "Original error message";
        let context_msg = "Additional context";

        let base_error = AuthError::internal(original_msg);
        let contextual_error = AuthError::internal(format!("{}: {}", context_msg, base_error));

        assert!(contextual_error.to_string().contains(original_msg));
        assert!(contextual_error.to_string().contains(context_msg));
    }

    #[test]
    fn test_error_serialization() {
        // Test that errors can be converted to JSON for API responses
        let error = AuthError::validation("email invalid format");

        // Should be able to include in structured responses
        let error_response = serde_json::json!({
            "error": "validation_failed",
            "message": error.to_string(),
            "field": "email"
        });

        assert!(
            error_response["message"]
                .as_str()
                .unwrap()
                .contains("invalid format")
        );
    }

    #[test]
    fn test_concurrent_error_creation() {
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let error = AuthError::token(format!("Concurrent error {}", i));
                    assert!(
                        error
                            .to_string()
                            .contains(&format!("Concurrent error {}", i))
                    );
                    error
                })
            })
            .collect();

        // Wait for all threads and verify errors
        for handle in handles {
            let error = handle.join().unwrap();
            assert!(!error.to_string().is_empty());
        }
    }
}
