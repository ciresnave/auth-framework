"""
AuthFramework Python SDK

Official Python client library for the AuthFramework REST API.
Provides type-safe access to authentication, user management,
MFA, OAuth 2.0, and administrative features.
"""

from .client import AuthFrameworkClient
from .exceptions import *
from .models import *

__version__ = "0.6.0rc4"
__author__ = "AuthFramework Team"
__email__ = "support@authframework.dev"

__all__ = [
    "AuthFrameworkClient",
    # Exceptions
    "AuthFrameworkError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
    "TimeoutError",
    # Models
    "UserInfo",
    "UserProfile",
    "LoginResponse",
    "TokenResponse",
    "MFASetupResponse",
    "SystemStats",
    "HealthStatus",
    "DetailedHealthStatus",
]
