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
        
        # If a specific token is provided, pass it directly in headers to avoid race conditions
        if token is not None:
            # Create a custom request with the specific token in headers
            from urllib.parse import urljoin
            import httpx
            
            url = urljoin(self._client.base_url, "/auth/validate")
            headers = {
                "Authorization": f"Bearer {token}",
                "User-Agent": "AuthFramework-Python-SDK/1.0.0"
            }
            
            try:
                async with httpx.AsyncClient(timeout=self._client.timeout) as client:
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code < 400:
                        return response.json()
                    
                    # Handle error response
                    error_info = self._client._parse_error_response(response)
                    self._client._raise_api_error(response.status_code, error_info)
            except httpx.TimeoutException as e:
                from .exceptions import AuthTimeoutError
                raise AuthTimeoutError("Request timeout") from e
            except httpx.NetworkError as e:
                from .exceptions import NetworkError
                raise NetworkError("Network error") from e
        
        # Use the stored token through normal client flow
        return await self._client.make_request("GET", "/auth/validate", config=config)

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