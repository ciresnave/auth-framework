//! # Auth Framework
//!
//! A comprehensive authentication and authorization framework for Rust applications.
//! 
//! This crate provides a unified interface for various authentication methods,
//! token management, permission checking, and secure credential handling with
//! a focus on distributed systems.
//!
//! ## Features
//!
//! - Multiple authentication methods (OAuth, API keys, JWT, etc.)
//! - Token issuance, validation, and refresh
//! - Role-based access control integration
//! - Permission checking and enforcement
//! - Secure credential storage
//! - Authentication middleware for web frameworks
//! - Distributed authentication with cross-node validation
//! - Single sign-on capabilities
//! - Multi-factor authentication support
//! - Audit logging of authentication events
//! - Rate limiting and brute force protection
//! - Session management
//! - Password hashing and validation
//! - Customizable authentication flows
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use auth_framework::{AuthFramework, AuthConfig};
//! use auth_framework::methods::JwtMethod;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure the auth framework
//! let config = AuthConfig::new()
//!     .token_lifetime(Duration::from_secs(3600))
//!     .refresh_token_lifetime(Duration::from_secs(86400 * 7));
//! 
//! // Create the auth framework
//! let mut auth = AuthFramework::new(config);
//! 
//! // Register a JWT authentication method
//! let jwt_method = JwtMethod::new()
//!     .secret_key("your-secret-key")
//!     .issuer("your-service");
//! 
//! auth.register_method("jwt", Box::new(jwt_method));
//! 
//! // Initialize the framework
//! auth.initialize().await?;
//! 
//! // Create a token
//! let token = auth.create_auth_token(
//!     "user123",
//!     vec!["read".to_string(), "write".to_string()],
//!     "jwt",
//!     None,
//! ).await?;
//! 
//! // Validate the token
//! if auth.validate_token(&token).await? {
//!     println!("Token is valid!");
//!     
//!     // Check permissions
//!     if auth.check_permission(&token, "read", "documents").await? {
//!         println!("User has permission to read documents");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! - Always use HTTPS in production
//! - Use strong, unique secrets for token signing
//! - Enable rate limiting to prevent brute force attacks
//! - Regularly rotate secrets and keys
//! - Monitor authentication events for suspicious activity
//! - Follow the principle of least privilege for permissions
//!
//! See the [Security Policy](https://github.com/yourusername/auth-framework/blob/main/SECURITY.md) 
//! for comprehensive security guidelines.

pub mod auth;
pub mod config;
pub mod credentials;
pub mod errors;
pub mod methods;
pub mod permissions;
pub mod providers;
pub mod storage;
pub mod tokens;
pub mod utils;

// Re-export main types for convenience
pub use auth::{AuthFramework, AuthResult};
pub use config::AuthConfig;
pub use credentials::Credential;
pub use errors::{AuthError, Result};
pub use tokens::{AuthToken, TokenInfo};

// Re-export method types
pub use methods::{
    ApiKeyMethod, JwtMethod, OAuth2Method, PasswordMethod,
    AuthMethod, MethodResult,
};

// Re-export provider types
pub use providers::OAuthProvider;

// Re-export permission types
pub use permissions::{Permission, Role, PermissionChecker};
