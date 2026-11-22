// SPDX-License-Identifier: MIT OR Apache-2.0
//! API Response Types
//!
//! Common response types for the REST API

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Standard API response wrapper.
///
/// Encapsulates success/error status, optional data payload,
/// optional error details, and an optional human-readable message.
///
/// # Example
/// ```rust
/// use auth_framework::api::responses::ApiResponse;
///
/// let resp = ApiResponse::success("hello");
/// assert!(resp.success);
/// assert_eq!(resp.data, Some("hello"));
/// ```
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

/// API error details attached to a failed [`ApiResponse`].
///
/// Contains a machine-readable `code`, human-readable `message`,
/// and optional structured `details`.
///
/// # Example
/// ```rust
/// use auth_framework::api::responses::ApiResponse;
///
/// let resp = ApiResponse::<()>::error("BAD_INPUT", "missing field");
/// let err = resp.error.unwrap();
/// assert_eq!(err.code, "BAD_INPUT");
/// ```
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Pagination metadata for list endpoints.
///
/// # Example
/// ```rust
/// use auth_framework::api::responses::Pagination;
///
/// let page = Pagination { page: 1, limit: 25, total: 100, pages: 4 };
/// assert_eq!(page.pages, 4);
/// ```
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
    /// Create a successful response carrying `data`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::success(42u32);
    /// assert!(resp.success);
    /// assert_eq!(resp.data, Some(42));
    /// ```
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    /// Convert this response to another data type, discarding the payload.
    ///
    /// Useful for propagating error responses where the data type differs.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let err = ApiResponse::<()>::error("FAIL", "oops");
    /// let typed: ApiResponse<String> = err.cast();
    /// assert!(!typed.success);
    /// ```
    pub fn cast<U>(self) -> ApiResponse<U> {
        ApiResponse {
            success: self.success,
            data: None,
            error: self.error,
            message: self.message,
        }
    }

    /// Create a forbidden (403) response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<String> = ApiResponse::forbidden_typed();
    /// assert!(!resp.success);
    /// ```
    pub fn forbidden_typed() -> ApiResponse<T> {
        ApiResponse::<()>::forbidden().cast()
    }

    /// Create an unauthorized (401) response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<Vec<u8>> = ApiResponse::unauthorized_typed();
    /// assert!(!resp.success);
    /// ```
    pub fn unauthorized_typed() -> ApiResponse<T> {
        ApiResponse::<()>::unauthorized().cast()
    }

    /// Create an error response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<i32> = ApiResponse::error_typed("FAIL", "bad input");
    /// assert!(!resp.success);
    /// ```
    pub fn error_typed(code: &str, message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::error(code, message).cast()
    }

    /// Create a validation error (400) response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<()> = ApiResponse::validation_error_typed("bad field");
    /// assert!(!resp.success);
    /// ```
    pub fn validation_error_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::validation_error(message).cast()
    }

    /// Create a not-found (404) response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<String> = ApiResponse::not_found_typed("user");
    /// assert!(!resp.success);
    /// ```
    pub fn not_found_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::not_found(message).cast()
    }

    /// Create a forbidden (403) response with a custom message for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<()> = ApiResponse::forbidden_with_message_typed("admin only");
    /// assert!(!resp.success);
    /// ```
    pub fn forbidden_with_message_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::forbidden_with_message(message).cast()
    }

    /// Create an error response with a custom code and message for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<()> = ApiResponse::error_with_message_typed("QUOTA", "exceeded");
    /// assert_eq!(resp.error.unwrap().code, "QUOTA");
    /// ```
    pub fn error_with_message_typed(code: &str, message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::error_with_message(code, message).cast()
    }

    /// Create a not-found (404) response with a custom message for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<()> = ApiResponse::not_found_with_message_typed("gone");
    /// assert!(!resp.success);
    /// ```
    pub fn not_found_with_message_typed(message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse::<()>::not_found_with_message(message).cast()
    }

    /// Create an internal server error (500) response for any data type `T`.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp: ApiResponse<()> = ApiResponse::internal_error_typed();
    /// assert!(!resp.success);
    /// ```
    pub fn internal_error_typed() -> ApiResponse<T> {
        ApiResponse::<()>::internal_error().cast()
    }

    /// Create a successful response with data and a human-readable message.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::success_with_message("done", "operation complete");
    /// assert!(resp.success);
    /// assert_eq!(resp.message, Some("operation complete".into()));
    /// ```
    pub fn success_with_message(data: T, message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: Some(message.into()),
        }
    }

    /// Create a simple success response with no data.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::ok();
    /// assert!(resp.success);
    /// assert!(resp.data.is_none());
    /// ```
    pub fn ok() -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            error: None,
            message: None,
        }
    }

    /// Create a success response with a message but no data.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::ok_with_message("saved");
    /// assert!(resp.success);
    /// assert_eq!(resp.message, Some("saved".into()));
    /// ```
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
    /// Create an error response with a code and message.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::error("BAD_REQUEST", "missing param");
    /// assert!(!resp.success);
    /// assert_eq!(resp.error.as_ref().unwrap().code, "BAD_REQUEST");
    /// ```
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

    /// Create an error response with structured details.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let details = serde_json::json!({"fields": ["name"]});
    /// let resp = ApiResponse::<()>::error_with_details("VALIDATION", "invalid", details);
    /// assert!(resp.error.as_ref().unwrap().details.is_some());
    /// ```
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

    /// Create a validation error (400) response.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::validation_error("email is invalid");
    /// assert_eq!(resp.error.as_ref().unwrap().code, "VALIDATION_ERROR");
    /// ```
    pub fn validation_error(message: impl Into<String>) -> Self {
        Self::error("VALIDATION_ERROR", message)
    }

    /// Create an unauthorized (401) error response.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::unauthorized();
    /// assert_eq!(resp.error.as_ref().unwrap().code, "UNAUTHORIZED");
    /// ```
    pub fn unauthorized() -> Self {
        Self::error("UNAUTHORIZED", "Authentication required")
    }

    /// Create a forbidden (403) error response.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::forbidden();
    /// assert_eq!(resp.error.as_ref().unwrap().code, "FORBIDDEN");
    /// ```
    pub fn forbidden() -> Self {
        Self::error("FORBIDDEN", "Insufficient permissions")
    }

    /// Create a forbidden (403) error with a custom message.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::forbidden_with_message("admin area");
    /// assert_eq!(resp.error.as_ref().unwrap().message, "admin area");
    /// ```
    pub fn forbidden_with_message(message: impl Into<String>) -> Self {
        Self::error("FORBIDDEN", message)
    }

    /// Create a not-found (404) error naming the missing resource.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::not_found("User");
    /// assert!(resp.error.as_ref().unwrap().message.contains("not found"));
    /// ```
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::error("NOT_FOUND", format!("{} not found", resource.into()))
    }

    /// Create a not-found (404) error with a custom message.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::not_found_with_message("deleted");
    /// assert_eq!(resp.error.as_ref().unwrap().code, "NOT_FOUND");
    /// ```
    pub fn not_found_with_message(message: impl Into<String>) -> Self {
        Self::error("NOT_FOUND", message)
    }

    /// Create an error response with a custom code and message (alias for [`error`](Self::error)).
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::error_with_message("LIMIT", "rate exceeded");
    /// assert_eq!(resp.error.as_ref().unwrap().code, "LIMIT");
    /// ```
    pub fn error_with_message(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::error(code, message)
    }

    /// Create an internal server error (500) response.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::api::responses::ApiResponse;
    ///
    /// let resp = ApiResponse::<()>::internal_error();
    /// assert_eq!(resp.error.as_ref().unwrap().code, "SERVER_ERROR");
    /// ```
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
                // Authentication failures should be 401, not 500
                Some(
                    "AUTHENTICATION_FAILED"
                    | "INVALID_CREDENTIALS"
                    | "AUTH_ERROR"
                    | "MFA_REQUIRED"
                    | "TOKEN_EXPIRED"
                    | "INVALID_TOKEN",
                ) => StatusCode::UNAUTHORIZED,
                // Client-side errors (bad input / missing resource)
                Some("CONFLICT" | "DUPLICATE_USER") => StatusCode::CONFLICT,
                Some("NOT_IMPLEMENTED") => StatusCode::NOT_IMPLEMENTED,
                // RFC 6749 OAuth error codes (lowercase) and internal codes (uppercase)
                Some(
                    "UNSUPPORTED_GRANT_TYPE"
                    | "UNSUPPORTED_RESPONSE_TYPE"
                    | "unsupported_grant_type"
                    | "unsupported_response_type"
                    | "invalid_grant"
                    | "invalid_request"
                    | "invalid_scope",
                ) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        };

        (status, Json(self)).into_response()
    }
}

/// Convert an [`AuthError`](crate::errors::AuthError) into an appropriate API error response.
///
/// Maps error variants to HTTP-semantic error codes:
/// - `Token` → `INVALID_TOKEN`
/// - `Validation` → `VALIDATION_ERROR`
/// - `AuthMethod` → `INVALID_CREDENTIALS`
/// - `UserNotFound` → `NOT_FOUND`
/// - `Permission` → `FORBIDDEN`
/// - `RateLimit` → `RATE_LIMITED`
/// - everything else → `SERVER_ERROR`
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
