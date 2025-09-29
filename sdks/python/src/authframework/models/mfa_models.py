"""MFA (Multi-Factor Authentication) models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from pydantic import BaseModel


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