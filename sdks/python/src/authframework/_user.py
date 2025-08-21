"""User management service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class UserService:
    """Service for user management operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize user service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def get_profile(self) -> dict[str, Any]:
        """Get current user's profile.

        Returns:
            User profile data.

        """
        return await self._client.make_request("GET", "/user/profile")

    async def update_profile(self, profile_data: dict[str, Any]) -> dict[str, Any]:
        """Update current user's profile.

        Args:
            profile_data: Updated profile information

        Returns:
            Updated profile data.

        """
        config = RequestConfig(json_data=profile_data)
        return await self._client.make_request("PUT", "/user/profile", config=config)

    async def get_users(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
    ) -> dict[str, Any]:
        """Get list of users.

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip
            search: Search query

        Returns:
            List of users and pagination info.

        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search

        config = RequestConfig(params=params)
        return await self._client.make_request("GET", "/users", config=config)

    async def get_user(self, user_id: str) -> dict[str, Any]:
        """Get specific user by ID.

        Args:
            user_id: User ID

        Returns:
            User data.

        """
        return await self._client.make_request("GET", f"/users/{user_id}")

    async def create_user(self, user_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new user (admin only).

        Args:
            user_data: User creation data

        Returns:
            Created user data.

        """
        config = RequestConfig(json_data=user_data)
        return await self._client.make_request("POST", "/users", config=config)

    async def update_user(
        self,
        user_id: str,
        user_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update user information (admin only).

        Args:
            user_id: User ID
            user_data: Updated user data

        Returns:
            Updated user data.

        """
        config = RequestConfig(json_data=user_data)
        return await self._client.make_request(
            "PUT",
            f"/users/{user_id}",
            config=config,
        )

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        """Delete a user (admin only).

        Args:
            user_id: User ID

        Returns:
            Deletion confirmation.

        """
        return await self._client.make_request("DELETE", f"/users/{user_id}")

    async def deactivate_user(self, user_id: str) -> dict[str, Any]:
        """Deactivate a user account.

        Args:
            user_id: User ID

        Returns:
            Deactivation confirmation.

        """
        return await self._client.make_request("POST", f"/users/{user_id}/deactivate")

    async def activate_user(self, user_id: str) -> dict[str, Any]:
        """Activate a user account.

        Args:
            user_id: User ID

        Returns:
            Activation confirmation.

        """
        return await self._client.make_request("POST", f"/users/{user_id}/activate")
