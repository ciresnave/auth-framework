"""Admin service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class AdminService:
    """Service for administrative operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize admin service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def get_system_stats(self) -> dict[str, Any]:
        """Get system statistics.

        Returns:
            System statistics and metrics.

        """
        return await self._client.make_request("GET", "/admin/stats")

    async def get_user_sessions(self, user_id: str) -> dict[str, Any]:
        """Get active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active sessions.

        """
        return await self._client.make_request(
            "GET", f"/admin/users/{user_id}/sessions"
        )

    async def revoke_user_sessions(
        self,
        user_id: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Revoke user sessions.

        Args:
            user_id: User ID
            session_id: Specific session ID to revoke (all if None)

        Returns:
            Revocation confirmation.

        """
        endpoint = f"/admin/users/{user_id}/sessions"
        if session_id:
            endpoint += f"/{session_id}"

        return await self._client.make_request("DELETE", endpoint)

    async def get_audit_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        user_id: str | None = None,
        action: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> dict[str, Any]:
        """Get audit logs.

        Args:
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            user_id: Filter by user ID
            action: Filter by action type
            start_date: Filter by start date (ISO 8601)
            end_date: Filter by end date (ISO 8601)

        Returns:
            Audit logs and pagination info.

        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if user_id:
            params["user_id"] = user_id
        if action:
            params["action"] = action
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        config = RequestConfig(params=params)
        return await self._client.make_request(
            "GET", "/admin/audit-logs", config=config
        )

    async def create_role(self, role_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new role.

        Args:
            role_data: Role creation data

        Returns:
            Created role data.

        """
        config = RequestConfig(json_data=role_data)
        return await self._client.make_request("POST", "/admin/roles", config=config)

    async def get_roles(self) -> dict[str, Any]:
        """Get all roles.

        Returns:
            List of all roles.

        """
        return await self._client.make_request("GET", "/admin/roles")

    async def update_role(
        self,
        role_id: str,
        role_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a role.

        Args:
            role_id: Role ID
            role_data: Updated role data

        Returns:
            Updated role data.

        """
        config = RequestConfig(json_data=role_data)
        return await self._client.make_request(
            "PUT", f"/admin/roles/{role_id}", config=config
        )

    async def delete_role(self, role_id: str) -> dict[str, Any]:
        """Delete a role.

        Args:
            role_id: Role ID

        Returns:
            Deletion confirmation.

        """
        return await self._client.make_request("DELETE", f"/admin/roles/{role_id}")

    async def assign_role(self, user_id: str, role_id: str) -> dict[str, Any]:
        """Assign role to user.

        Args:
            user_id: User ID
            role_id: Role ID

        Returns:
            Assignment confirmation.

        """
        data = {"role_id": role_id}
        config = RequestConfig(json_data=data)
        return await self._client.make_request(
            "POST", f"/admin/users/{user_id}/roles", config=config
        )

    async def revoke_role(self, user_id: str, role_id: str) -> dict[str, Any]:
        """Revoke role from user.

        Args:
            user_id: User ID
            role_id: Role ID

        Returns:
            Revocation confirmation.

        """
        return await self._client.make_request(
            "DELETE", f"/admin/users/{user_id}/roles/{role_id}"
        )

    async def get_permissions(self) -> dict[str, Any]:
        """Get all permissions.

        Returns:
            List of all permissions.

        """
        return await self._client.make_request("GET", "/admin/permissions")

    async def create_permission(
        self, permission_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a new permission.

        Args:
            permission_data: Permission creation data

        Returns:
            Created permission data.

        """
        config = RequestConfig(json_data=permission_data)
        return await self._client.make_request(
            "POST", "/admin/permissions", config=config
        )
