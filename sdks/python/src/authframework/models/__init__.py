"""AuthFramework models package.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from typing import Any
from pydantic import BaseModel

# Import from domain-specific model files
from .health_models import (
    HealthStatus,
    ServiceHealth, 
    DetailedHealthStatus,
    HealthMetrics,
    ReadinessCheck,
    LivenessCheck,
)
from .token_models import (
    TokenValidationResponse,
    CreateTokenRequest,
    CreateTokenResponse,
    TokenInfo,
    RefreshTokenRequest,
    TokenResponse,
)
from .rate_limit_models import RateLimitConfig, RateLimitStats
from .admin_models import (
    Permission,
    Role,
    CreatePermissionRequest,
    CreateRoleRequest,
    SystemStats,
)
from .user_models import (
    UserInfo,
    UserProfile,
    UpdateProfileRequest,
    ChangePasswordRequest,
    CreateUserRequest,
    LoginResponse,
)
from .oauth_models import (
    OAuthTokenRequest,
    OAuthTokenResponse,
    RevokeTokenRequest,
    IntrospectTokenRequest,
    TokenIntrospectionResponse,
    OAuthAuthorizeParams,
)
from .mfa_models import (
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    DisableMFARequest,
)


# Base models that don't fit into domain-specific categories
class RequestOptions(BaseModel):
    """Request options model."""

    timeout: float | None = None
    retries: int | None = None
    headers: dict[str, str] | None = None

    class Config:
        """Pydantic configuration."""

        extra = "allow"


class ListOptions(BaseModel):
    """List options model."""

    page: int | None = 1
    limit: int | None = 20
    search: str | None = None
    sort: str | None = None
    order: str | None = None


class UserListOptions(ListOptions):
    """User list options model."""

    role: str | None = None


# Re-export all models for backward compatibility
__all__ = [
    # Health models
    "HealthStatus",
    "ServiceHealth", 
    "DetailedHealthStatus",
    "HealthMetrics",
    "ReadinessCheck",
    "LivenessCheck",
    # Token models
    "TokenValidationResponse",
    "CreateTokenRequest",
    "CreateTokenResponse", 
    "TokenInfo",
    "RefreshTokenRequest",
    "TokenResponse",
    # Rate limit models
    "RateLimitConfig",
    "RateLimitStats",
    # Admin models
    "Permission",
    "Role",
    "CreatePermissionRequest",
    "CreateRoleRequest", 
    "SystemStats",
    # User models
    "UserInfo",
    "UserProfile",
    "UpdateProfileRequest",
    "ChangePasswordRequest",
    "CreateUserRequest",
    "LoginResponse",
    # OAuth models
    "OAuthTokenRequest",
    "OAuthTokenResponse",
    "RevokeTokenRequest",
    "IntrospectTokenRequest",
    "TokenIntrospectionResponse",
    "OAuthAuthorizeParams",
    # MFA models
    "MFASetupResponse",
    "MFAVerifyRequest",
    "MFAVerifyResponse",
    "DisableMFARequest",
    # Base models
    "RequestOptions",
    "ListOptions",
    "UserListOptions",
]