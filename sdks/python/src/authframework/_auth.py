"""Authentication service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class AuthService:
    """Service for authentication operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize authentication service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def login(
        self,
        username: str,
        password: str,
        remember_me: bool = False,
    ) -> dict[str, Any]:
        """Authenticate a user with username and password.

        Args:
            username: User's username or email
            password: User's password
            remember_me: Whether to extend session lifetime

        Returns:
            Authentication response with tokens and user info.

        """
        data = {
            "username": username,
            "password": password,
            "remember_me": remember_me,
        }

        config = RequestConfig(json_data=data)
        response = await self._client.make_request("POST", "/auth/login", config=config)

        # Store access token for future requests
        if "access_token" in response:
            self._client.set_access_token(response["access_token"])

        return response

    async def logout(self) -> dict[str, Any]:
        """Log out the current user and invalidate tokens.

        Returns:
            Logout confirmation response.

        """
        response = await self._client.make_request("POST", "/auth/logout")
        self._client.clear_access_token()
        return response

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh access token using refresh token.

        Args:
            refresh_token: The refresh token

        Returns:
            Response with new access token.

        """
        data = {"refresh_token": refresh_token}
        config = RequestConfig(json_data=data)
        response = await self._client.make_request(
            "POST", "/auth/refresh", config=config
        )

        # Update stored access token
        if "access_token" in response:
            self._client.set_access_token(response["access_token"])

        return response

    async def register(
        self,
        username: str,
        email: str,
        password: str,
        user_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register a new user account.

        Args:
            username: Desired username
            email: User's email address
            password: User's password
            user_data: Additional user data

        Returns:
            Registration response.

        """
        data = {
            "username": username,
            "email": email,
            "password": password,
        }

        if user_data:
            data.update(user_data)

        config = RequestConfig(json_data=data)
        return await self._client.make_request("POST", "/auth/register", config=config)

    async def verify_email(self, token: str) -> dict[str, Any]:
        """Verify user's email address.

        Args:
            token: Email verification token

        Returns:
            Verification response.

        """
        data = {"token": token}
        config = RequestConfig(json_data=data)
        return await self._client.make_request(
            "POST", "/auth/verify-email", config=config
        )

    async def reset_password_request(self, email: str) -> dict[str, Any]:
        """Request password reset email.

        Args:
            email: User's email address

        Returns:
            Password reset request response.

        """
        data = {"email": email}
        config = RequestConfig(json_data=data)
        return await self._client.make_request(
            "POST", "/auth/reset-password", config=config
        )

    async def reset_password_confirm(
        self,
        token: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Confirm password reset with new password.

        Args:
            token: Password reset token
            new_password: New password

        Returns:
            Password reset confirmation response.

        """
        data = {
            "token": token,
            "new_password": new_password,
        }
        config = RequestConfig(json_data=data)
        return await self._client.make_request(
            "POST", "/auth/reset-password/confirm", config=config
        )

    async def change_password(
        self,
        current_password: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Change user's password.

        Args:
            current_password: Current password
            new_password: New password

        Returns:
            Password change response.

        """
        data = {
            "current_password": current_password,
            "new_password": new_password,
        }
        config = RequestConfig(json_data=data)
        return await self._client.make_request(
            "POST", "/auth/change-password", config=config
        )

    async def validate_token(self, token: str | None = None) -> dict[str, Any]:
        """Validate an access token.

        Args:
            token: Token to validate (uses current token if None)

        Returns:
            Token validation response.

        """
        if token:
            # Temporarily use provided token
            original_token = self._client.get_access_token()
            self._client.set_access_token(token)
            try:
                response = await self._client.make_request("GET", "/auth/validate")
                return response
            finally:
                # Restore original token
                if original_token:
                    self._client.set_access_token(original_token)
                else:
                    self._client.clear_access_token()

        return await self._client.make_request("GET", "/auth/validate")
