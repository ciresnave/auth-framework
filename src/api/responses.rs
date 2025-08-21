//! API Response Types
//!
//! Common response types for the REST API

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Standard API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// API error details
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Pagination information
#[derive(Debug, Serialize)]
pub struct Pagination {
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub pages: u32,
}

/// API result type
pub type ApiResult<T> = Result<ApiResponse<T>, ApiResponse<()>>;

impl<T> ApiResponse<T> {
    /// Create successful response with data
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    /// Convert this ApiResponse to another type (for error responses)
    pub fn cast<U>(self) -> ApiResponse<U> {
        ApiResponse {
            success: self.success,
            data: None,
            error: self.error,
            message: self.message,
        }
    }

    /// Create a forbidden response for any type
    pub fn forbidden_typed() -> ApiResponse<T> {
        ApiResponse::<()>::forbidden().cast()
    }

    /// Create an unauthorized response for any type
    pub fn unauthorized_typed() -> ApiResponse<T> {
        ApiResponse::<()>::unauthorized().cast()
    }

    /// Create an error response for any type
    pub fn error_typed(code: &str, message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::error(code, message).cast()
    }

    /// Create a validation error response for any type
    pub fn validation_error_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::validation_error(message).cast()
    }

    /// Create a not found response for any type
    pub fn not_found_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::not_found(message).cast()
    }

    /// Create a forbidden response with message for any type
    pub fn forbidden_with_message_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::forbidden_with_message(message).cast()
    }

    /// Create an error response with message for any type
    pub fn error_with_message_typed(code: &str, message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::error_with_message(code, message).cast()
    }

    /// Create a not found response with message for any type
    pub fn not_found_with_message_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::not_found_with_message(message).cast()
    }

    /// Create an internal error response for any type
    pub fn internal_error_typed() -> ApiResponse<T> {
        ApiResponse::<()>::internal_error().cast()
    }

    /// Create successful response with message
    pub fn success_with_message(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: Some(message.into()),
        }
    }

    /// Create simple success response
    pub fn ok() -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            error: None,
            message: None,
        }
    }

    /// Create success response with message only
    pub fn ok_with_message(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            error: None,
            message: Some(message.into()),
        }
    }
}

impl ApiResponse<()> {
    /// Create error response
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.into(),
                message: message.into(),
                details: None,
            }),
            message: None,
        }
    }

    /// Create error response with details
    pub fn error_with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code: code.into(),
                message: message.into(),
                details: Some(details),
            }),
            message: None,
        }
    }

    /// Create validation error
    pub fn validation_error(message: impl Into<String>) -> Self {
        Self::error("VALIDATION_ERROR", message)
    }

    /// Create unauthorized error
    pub fn unauthorized() -> Self {
        Self::error("UNAUTHORIZED", "Authentication required")
    }

    /// Create forbidden error
    pub fn forbidden() -> Self {
        Self::error("FORBIDDEN", "Insufficient permissions")
    }

    /// Create forbidden error with custom message
    pub fn forbidden_with_message(message: impl Into<String>) -> Self {
        Self::error("FORBIDDEN", message)
    }

    /// Create not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::error("NOT_FOUND", format!("{} not found", resource.into()))
    }

    /// Create not found error with custom message
    pub fn not_found_with_message(message: impl Into<String>) -> Self {
        Self::error("NOT_FOUND", message)
    }

    /// Create error response with custom message
    pub fn error_with_message(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::error(code, message)
    }

    /// Create internal server error
    pub fn internal_error() -> Self {
        Self::error("SERVER_ERROR", "Internal server error")
    }
}

impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let status = if self.success {
            StatusCode::OK
        } else {
            match self.error.as_ref().map(|e| e.code.as_str()) {
                Some("UNAUTHORIZED") => StatusCode::UNAUTHORIZED,
                Some("FORBIDDEN") => StatusCode::FORBIDDEN,
                Some("NOT_FOUND") => StatusCode::NOT_FOUND,
                Some("VALIDATION_ERROR") => StatusCode::BAD_REQUEST,
                Some("RATE_LIMITED") => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        };

        (status, Json(self)).into_response()
    }
}

/// Convert AuthError to API response
impl From<crate::errors::AuthError> for ApiResponse<()> {
    fn from(error: crate::errors::AuthError) -> Self {
        match &error {
            crate::errors::AuthError::Token(_) => Self::error("INVALID_TOKEN", error.to_string()),
            crate::errors::AuthError::Validation { .. } => {
                Self::validation_error(error.to_string())
            }
            crate::errors::AuthError::AuthMethod { .. } => {
                Self::error("INVALID_CREDENTIALS", error.to_string())
            }
            crate::errors::AuthError::UserNotFound => Self::not_found(error.to_string()),
            crate::errors::AuthError::Permission(_) => Self::forbidden(),
            crate::errors::AuthError::RateLimit { .. } => {
                Self::error("RATE_LIMITED", error.to_string())
            }
            _ => Self::internal_error(),
        }
    }
}


