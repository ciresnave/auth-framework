"""Token management models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from pydantic import BaseModel


class TokenValidationResponse(BaseModel):
    """Token validation response model."""

    valid: bool
    expired: bool
    token_type: str | None = None
    expires_at: datetime | None = None
    user_id: str | None = None
    scopes: list[str] | None = None


class CreateTokenRequest(BaseModel):
    """Create token request model."""

    user_id: str
    scopes: list[str] | None = None
    expires_in: int | None = None
    token_type: str | None = "access"


class CreateTokenResponse(BaseModel):
    """Create token response model."""

    token: str
    token_type: str
    expires_in: int
    expires_at: datetime


class TokenInfo(BaseModel):
    """Token information model."""

    id: str
    user_id: str
    token_type: str
    scopes: list[str]
    expires_at: datetime
    created_at: datetime
    last_used: datetime | None = None


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""

    refresh_token: str


class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str
    token_type: str
    expires_in: int