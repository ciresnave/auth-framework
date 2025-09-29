"""OAuth models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from pydantic import BaseModel


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


class OAuthAuthorizeParams(BaseModel):
    """OAuth authorization parameters model."""

    response_type: str
    client_id: str
    redirect_uri: str | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None