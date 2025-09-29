"""User management models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from pydantic import BaseModel


class UserInfo(BaseModel):
    """User information model."""

    id: str
    username: str
    email: str
    roles: list[str]
    mfa_enabled: bool
    created_at: datetime
    last_login: datetime | None = None


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


class LoginResponse(BaseModel):
    """Login response model."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserInfo