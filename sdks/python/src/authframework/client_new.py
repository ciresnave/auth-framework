"""Simplified AuthFramework client using service composition.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any, Self

from ._admin import AdminService
from ._auth import AuthService
from ._base import BaseClient
from ._mfa import MFAService
from ._oauth import OAuthService
from ._user import UserService


class AuthFrameworkClient:
    """Simplified AuthFramework client using service composition."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        retries: int = 3,
        api_key: str | None = None,
    ) -> None:
        """Initialize AuthFramework client.

        Args:
            base_url: Base URL of the AuthFramework server
            timeout: Request timeout in seconds
            retries: Number of retry attempts for failed requests
            api_key: Optional API key for authentication

        """
        self._client = BaseClient(
            base_url=base_url,
            timeout=timeout,
            retries=retries,
            api_key=api_key,
        )

        # Initialize service clients
        self.auth = AuthService(self._client)
        self.user = UserService(self._client)
        self.mfa = MFAService(self._client)
        self.oauth = OAuthService(self._client)
        self.admin = AdminService(self._client)

    async def __aenter__(self) -> Self:
        """Async context manager entry.

        Returns:
            The client instance.

        """
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred

        """
        await self._client.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self) -> None:
        """Close the client and clean up resources."""
        await self._client.close()

    def set_access_token(self, token: str) -> None:
        """Set access token for authenticated requests.

        Args:
            token: Access token to set

        """
        self._client.set_access_token(token)

    def clear_access_token(self) -> None:
        """Clear the stored access token."""
        self._client.clear_access_token()

    def get_access_token(self) -> str | None:
        """Get the current access token.

        Returns:
            Current access token or None if not set.

        """
        return self._client.get_access_token()

    async def health_check(self) -> dict[str, Any]:
        """Check server health status.

        Returns:
            Server health information.

        """
        return await self._client.make_request("GET", "/health")

    async def get_server_info(self) -> dict[str, Any]:
        """Get server information and capabilities.

        Returns:
            Server information and supported features.

        """
        return await self._client.make_request("GET", "/info")
