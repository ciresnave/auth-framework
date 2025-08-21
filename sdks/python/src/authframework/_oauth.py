"""OAuth service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class OAuthService:
    """Service for OAuth operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize OAuth service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
    ) -> dict[str, Any]:
        """Initialize OAuth authorization flow.

        Args:
            client_id: OAuth client ID
            redirect_uri: Redirect URI after authorization
            scope: Requested scopes
            state: Optional state parameter
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE challenge method

        Returns:
            Authorization response with redirect URL.

        """
        params: dict[str, Any] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "response_type": "code",
        }

        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method

        config = RequestConfig(params=params)
        return await self._client.make_request("GET", "/oauth/authorize", config=config)

    async def token(
        self,
        grant_type: str,
        client_id: str,
        client_secret: str | None = None,
        code: str | None = None,
        redirect_uri: str | None = None,
        refresh_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        scope: str | None = None,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code or credentials for tokens.

        Args:
            grant_type: OAuth grant type
            client_id: OAuth client ID
            client_secret: OAuth client secret
            code: Authorization code
            redirect_uri: Redirect URI
            refresh_token: Refresh token for refresh grant
            username: Username for password grant
            password: Password for password grant
            scope: Requested scope
            code_verifier: PKCE code verifier

        Returns:
            Token response with access and refresh tokens.

        """
        data: dict[str, Any] = {
            "grant_type": grant_type,
            "client_id": client_id,
        }

        if client_secret:
            data["client_secret"] = client_secret
        if code:
            data["code"] = code
        if redirect_uri:
            data["redirect_uri"] = redirect_uri
        if refresh_token:
            data["refresh_token"] = refresh_token
        if username:
            data["username"] = username
        if password:
            data["password"] = password
        if scope:
            data["scope"] = scope
        if code_verifier:
            data["code_verifier"] = code_verifier

        config = RequestConfig(form_data=data)
        response = await self._client.make_request(
            "POST", "/oauth/token", config=config
        )

        # Store access token if received
        if "access_token" in response:
            self._client.set_access_token(response["access_token"])

        return response

    async def revoke(
        self,
        token: str,
        client_id: str,
        client_secret: str | None = None,
        token_type_hint: str | None = None,
    ) -> dict[str, Any]:
        """Revoke an OAuth token.

        Args:
            token: Token to revoke
            client_id: OAuth client ID
            client_secret: OAuth client secret
            token_type_hint: Hint about token type

        Returns:
            Revocation confirmation.

        """
        data: dict[str, Any] = {
            "token": token,
            "client_id": client_id,
        }

        if client_secret:
            data["client_secret"] = client_secret
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        config = RequestConfig(form_data=data)
        response = await self._client.make_request(
            "POST", "/oauth/revoke", config=config
        )

        # Clear token if it was the current one
        if token == self._client.get_access_token():
            self._client.clear_access_token()

        return response

    async def introspect(
        self,
        token: str,
        client_id: str,
        client_secret: str | None = None,
        token_type_hint: str | None = None,
    ) -> dict[str, Any]:
        """Introspect an OAuth token.

        Args:
            token: Token to introspect
            client_id: OAuth client ID
            client_secret: OAuth client secret
            token_type_hint: Hint about token type

        Returns:
            Token introspection response.

        """
        data: dict[str, Any] = {
            "token": token,
            "client_id": client_id,
        }

        if client_secret:
            data["client_secret"] = client_secret
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        config = RequestConfig(form_data=data)
        return await self._client.make_request(
            "POST", "/oauth/introspect", config=config
        )

    async def get_userinfo(self) -> dict[str, Any]:
        """Get user information using current token.

        Returns:
            User information from the token.

        """
        return await self._client.make_request("GET", "/oauth/userinfo")
