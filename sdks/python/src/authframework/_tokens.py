"""Token management service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class TokenService:
    """Service for token management operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize token service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def validate(self, token: str | None = None) -> dict[str, Any]:
        """Validate a token.

        Args:
            token: Token to validate. If None, uses the stored access token.

        Returns:
            Token validation result with user information.

        """
        config = RequestConfig()
        
        # If a specific token is provided, we need to temporarily set it
        original_token = None
        if token is not None:
            original_token = self._client.get_access_token()
            self._client.set_access_token(token)
        
        try:
            return await self._client.make_request("GET", "/auth/validate", config=config)
        finally:
            # Restore original token if we temporarily changed it
            if token is not None and original_token is not None:
                self._client.set_access_token(original_token)
            elif token is not None:
                self._client.clear_access_token()

    async def refresh(self, refresh_token: str) -> dict[str, Any]:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New token response with access_token and refresh_token.

        """
        data: dict[str, Any] = {"refresh_token": refresh_token}
        config = RequestConfig(json_data=data)
        response = await self._client.make_request("POST", "/auth/refresh", config=config)

        # Update stored access token if available
        if "access_token" in response:
            self._client.set_access_token(response["access_token"])

        return response

    async def create(
        self,
        user_id: str,
        permissions: list[str],
        expires_in: int = 3600,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Create a new token for a user.

        Note: This endpoint needs to be implemented in the Rust API.
        Currently this will fail until the corresponding API endpoint is added.

        Args:
            user_id: User ID to create token for
            permissions: List of permissions to grant
            expires_in: Token lifetime in seconds (default: 1 hour)
            **kwargs: Additional token parameters

        Returns:
            New token information.

        """
        data: dict[str, Any] = {
            "user_id": user_id,
            "permissions": permissions,
            "expires_in": expires_in,
            **kwargs,
        }
        config = RequestConfig(json_data=data)
        return await self._client.make_request("POST", "/api/tokens", config=config)

    async def revoke(self, token: str) -> dict[str, Any]:
        """Revoke a token.

        Note: This endpoint needs to be implemented in the Rust API.
        Currently this will fail until the corresponding API endpoint is added.

        Args:
            token: Token to revoke

        Returns:
            Revocation confirmation.

        """
        config = RequestConfig()
        return await self._client.make_request("DELETE", f"/api/tokens/{token}", config=config)

    async def list_user_tokens(self, user_id: str) -> dict[str, Any]:
        """List all tokens for a user (admin only).

        Note: This endpoint needs to be implemented in the Rust API.
        Currently this will fail until the corresponding API endpoint is added.

        Args:
            user_id: User ID to list tokens for

        Returns:
            List of user tokens.

        """
        config = RequestConfig()
        return await self._client.make_request("GET", f"/admin/users/{user_id}/tokens", config=config)