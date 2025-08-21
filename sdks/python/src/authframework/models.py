"""Pydantic models for AuthFramework API responses and requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ApiResponse(BaseModel):
    """Base API response model."""

    success: bool
    timestamp: datetime


class ApiError(BaseModel):
    """API error response model."""

    success: bool = False
    error: dict[str, Any]
    timestamp: datetime


class Pagination(BaseModel):
    """Pagination information."""

    page: int
    limit: int
    total: int
    has_next: bool
    has_prev: bool


class PaginatedResponse(ApiResponse):
    """Paginated API response."""

    pagination: Pagination


# Authentication Models
class LoginRequest(BaseModel):
    """Login request model."""

    username: str
    password: str
    remember_me: bool | None = False


class UserInfo(BaseModel):
    """User information model."""

    id: str
    username: str
    email: str
    roles: list[str]
    mfa_enabled: bool
    created_at: datetime
    last_login: datetime | None = None


class LoginResponse(BaseModel):
    """Login response model."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserInfo


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""

    refresh_token: str


class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str
    token_type: str
    expires_in: int


# User Models
class UserProfile(BaseModel):
    """User profile model."""

    id: str
    user_id: str  # Alias for id for backwards compatibility
    username: str
    email: str
    display_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    timezone: str | None = None
    locale: str | None = None
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime


class UpdateProfileRequest(BaseModel):
    """Update profile request model."""

    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    timezone: str | None = None
    locale: str | None = None


class ChangePasswordRequest(BaseModel):
    """Change password request model."""

    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    """Create user request model."""

    username: str
    email: str
    password: str
    roles: list[str] | None = None
    first_name: str | None = None
    last_name: str | None = None


# MFA Models
class MFASetupResponse(BaseModel):
    """MFA setup response model."""

    secret: str
    qr_code: str
    backup_codes: list[str]
    setup_uri: str


class MFAVerifyRequest(BaseModel):
    """MFA verification request model."""

    code: str


class MFAVerifyResponse(BaseModel):
    """MFA verification response model."""

    verified: bool
    backup_codes: list[str] | None = None


class DisableMFARequest(BaseModel):
    """Disable MFA request model."""

    password: str
    code: str


# OAuth Models
class OAuthTokenRequest(BaseModel):
    """OAuth token request model."""

    grant_type: str
    code: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    refresh_token: str | None = None
    scope: str | None = None
    code_verifier: str | None = None


class OAuthTokenResponse(BaseModel):
    """OAuth token response model."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None


class RevokeTokenRequest(BaseModel):
    """Revoke token request model."""

    token: str
    token_type_hint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class IntrospectTokenRequest(BaseModel):
    """Introspect token request model."""

    token: str
    token_type_hint: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class TokenIntrospectionResponse(BaseModel):
    """Token introspection response model."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    sub: str | None = None
    aud: str | None = None
    iss: str | None = None


# Health Models
class HealthStatus(BaseModel):
    """Health status model."""

    status: str
    version: str
    timestamp: datetime


class ServiceHealth(BaseModel):
    """Service health model."""

    status: str
    response_time: float
    last_check: datetime


class DetailedHealthStatus(BaseModel):
    """Detailed health status model."""

    status: str
    services: dict[str, ServiceHealth]
    uptime: int
    version: str
    timestamp: datetime


# Admin Models
class SystemStats(BaseModel):
    """System statistics model."""

    total_users: int
    active_sessions: int
    users: dict[str, int]
    sessions: dict[str, int]
    oauth: dict[str, int]
    system: dict[str, int | float]
    timestamp: datetime


# OAuth Authorization Parameters
class OAuthAuthorizeParams(BaseModel):
    """OAuth authorization parameters model."""

    response_type: str
    client_id: str
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None


# Request Options
class RequestOptions(BaseModel):
    """Request options model."""

    timeout: float | None = None
    retries: int | None = None
    headers: dict[str, str] | None = None

    class Config:
        """Pydantic configuration."""

        extra = "allow"


# List Options
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
