"""
Exception classes for the AuthFramework SDK.
"""

from __future__ import annotations

from typing import Any


class AuthFrameworkError(Exception):
    """Base exception for AuthFramework SDK errors."""

    def __init__(
        self,
        message: str,
        code: str = "UNKNOWN_ERROR",
        details: Any | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details
        self.status_code = status_code


class ValidationError(AuthFrameworkError):
    """Raised when request validation fails."""

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message, "VALIDATION_ERROR", details, 400)


class AuthenticationError(AuthFrameworkError):
    """Raised when authentication fails."""

    def __init__(
        self, message: str = "Authentication failed", details: Any | None = None
    ) -> None:
        super().__init__(message, "AUTHENTICATION_ERROR", details, 401)


class AuthorizationError(AuthFrameworkError):
    """Raised when authorization fails."""

    def __init__(
        self, message: str = "Insufficient permissions", details: Any | None = None
    ) -> None:
        super().__init__(message, "AUTHORIZATION_ERROR", details, 403)


class NotFoundError(AuthFrameworkError):
    """Raised when a resource is not found."""

    def __init__(
        self, message: str = "Resource not found", details: Any | None = None
    ) -> None:
        super().__init__(message, "NOT_FOUND_ERROR", details, 404)


class ConflictError(AuthFrameworkError):
    """Raised when a resource conflict occurs."""

    def __init__(
        self, message: str = "Resource conflict", details: Any | None = None
    ) -> None:
        super().__init__(message, "CONFLICT_ERROR", details, 409)


class RateLimitError(AuthFrameworkError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
        details: Any | None = None,
    ) -> None:
        super().__init__(message, "RATE_LIMIT_ERROR", details, 429)
        self.retry_after = retry_after


class ServerError(AuthFrameworkError):
    """Raised when a server error occurs."""

    def __init__(
        self,
        message: str = "Internal server error",
        details: Any | None = None,
        status_code: int = 500,
    ) -> None:
        super().__init__(message, "SERVER_ERROR", details, status_code)


class NetworkError(AuthFrameworkError):
    """Raised when a network error occurs."""

    def __init__(
        self, message: str = "Network error", details: Any | None = None
    ) -> None:
        super().__init__(message, "NETWORK_ERROR", details)


class TimeoutError(AuthFrameworkError):  # noqa: A001
    """Raised when a request times out."""

    def __init__(
        self, message: str = "Request timeout", details: Any | None = None
    ) -> None:
        super().__init__(message, "TIMEOUT_ERROR", details)


def create_error_from_response(
    status_code: int,
    error_response: dict[str, Any | None] | None = None,
    default_message: str | None = None,
) -> AuthFrameworkError:
    """Create an appropriate error instance based on HTTP status code and error response."""
    message = (error_response or {}).get(
        "message", default_message or "An error occurred"
    )
    code = (error_response or {}).get("code", "UNKNOWN_ERROR")
    details = (error_response or {}).get("details")

    # Ensure message and code are strings
    message_str = str(message) if message is not None else "An error occurred"
    code_str = str(code) if code is not None else "UNKNOWN_ERROR"

    if status_code == 400:
        return ValidationError(message_str, details)
    elif status_code == 401:
        return AuthenticationError(message_str, details)
    elif status_code == 403:
        return AuthorizationError(message_str, details)
    elif status_code == 404:
        return NotFoundError(message_str, details)
    elif status_code == 409:
        return ConflictError(message_str, details)
    elif status_code == 429:
        retry_after = (error_response or {}).get("retry_after")
        return RateLimitError(message_str, retry_after, details)
    elif status_code >= 500:
        return ServerError(message_str, details, status_code)
    else:
        return AuthFrameworkError(message_str, code_str, details, status_code)


def is_retryable_error(error: Exception) -> bool:
    """Check if an error is retryable (network errors and 5xx server errors)."""
    if isinstance(error, (NetworkError, TimeoutError)):
        return True

    if isinstance(error, AuthFrameworkError) and error.status_code:
        return error.status_code >= 500

    return False
