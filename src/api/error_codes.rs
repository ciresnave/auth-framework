//! Standard API Error Codes
//!
//! Consistent error codes for API responses

/// Standard error codes used across the API
pub struct ErrorCodes;

impl ErrorCodes {
    // Authentication errors
    pub const INVALID_CREDENTIALS: &'static str = "INVALID_CREDENTIALS";
    pub const TOKEN_EXPIRED: &'static str = "TOKEN_EXPIRED";
    pub const TOKEN_INVALID: &'static str = "TOKEN_INVALID";
    pub const MFA_REQUIRED: &'static str = "MFA_REQUIRED";
    pub const MFA_INVALID: &'static str = "MFA_INVALID";

    // Authorization errors
    pub const INSUFFICIENT_PERMISSIONS: &'static str = "INSUFFICIENT_PERMISSIONS";
    pub const FORBIDDEN: &'static str = "FORBIDDEN";
    pub const UNAUTHORIZED: &'static str = "UNAUTHORIZED";

    // Validation errors
    pub const VALIDATION_ERROR: &'static str = "VALIDATION_ERROR";
    pub const INVALID_REQUEST: &'static str = "INVALID_REQUEST";
    pub const MISSING_PARAMETER: &'static str = "MISSING_PARAMETER";

    // Resource errors
    pub const NOT_FOUND: &'static str = "NOT_FOUND";
    pub const ALREADY_EXISTS: &'static str = "ALREADY_EXISTS";
    pub const CONFLICT: &'static str = "CONFLICT";

    // Rate limiting
    pub const RATE_LIMITED: &'static str = "RATE_LIMITED";
    pub const TOO_MANY_REQUESTS: &'static str = "TOO_MANY_REQUESTS";

    // Server errors
    pub const INTERNAL_ERROR: &'static str = "INTERNAL_ERROR";
    pub const SERVICE_UNAVAILABLE: &'static str = "SERVICE_UNAVAILABLE";
    pub const MAINTENANCE_MODE: &'static str = "MAINTENANCE_MODE";

    // OAuth specific
    pub const INVALID_GRANT: &'static str = "INVALID_GRANT";
    pub const UNSUPPORTED_GRANT_TYPE: &'static str = "UNSUPPORTED_GRANT_TYPE";
    pub const INVALID_CLIENT: &'static str = "INVALID_CLIENT";
    pub const INVALID_SCOPE: &'static str = "INVALID_SCOPE";
}

/// Error code utility functions
impl ErrorCodes {
    /// Check if an error code is retryable
    pub fn is_retryable(code: &str) -> bool {
        matches!(
            code,
            Self::INTERNAL_ERROR
                | Self::SERVICE_UNAVAILABLE
                | Self::RATE_LIMITED
                | Self::TOO_MANY_REQUESTS
        )
    }

    /// Get human-readable description for error code
    pub fn description(code: &str) -> &'static str {
        match code {
            Self::INVALID_CREDENTIALS => "The provided credentials are invalid",
            Self::TOKEN_EXPIRED => "The authentication token has expired",
            Self::TOKEN_INVALID => "The authentication token is invalid",
            Self::MFA_REQUIRED => "Multi-factor authentication is required",
            Self::MFA_INVALID => "The MFA code is invalid",
            Self::INSUFFICIENT_PERMISSIONS => "Insufficient permissions for this operation",
            Self::FORBIDDEN => "Access to this resource is forbidden",
            Self::UNAUTHORIZED => "Authentication is required",
            Self::VALIDATION_ERROR => "Request validation failed",
            Self::INVALID_REQUEST => "The request is malformed or invalid",
            Self::MISSING_PARAMETER => "A required parameter is missing",
            Self::NOT_FOUND => "The requested resource was not found",
            Self::ALREADY_EXISTS => "The resource already exists",
            Self::CONFLICT => "The request conflicts with the current state",
            Self::RATE_LIMITED => "Request rate limit exceeded",
            Self::TOO_MANY_REQUESTS => "Too many requests in a short time",
            Self::INTERNAL_ERROR => "An internal server error occurred",
            Self::SERVICE_UNAVAILABLE => "The service is temporarily unavailable",
            Self::MAINTENANCE_MODE => "The service is in maintenance mode",
            Self::INVALID_GRANT => "The authorization grant is invalid",
            Self::UNSUPPORTED_GRANT_TYPE => "The grant type is not supported",
            Self::INVALID_CLIENT => "The client credentials are invalid",
            Self::INVALID_SCOPE => "The requested scope is invalid",
            _ => "Unknown error",
        }
    }
}
