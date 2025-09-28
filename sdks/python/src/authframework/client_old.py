"""AuthFramework Python client.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""


from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlencode

import httpx

from .exceptions import (
    AuthFrameworkError,
    NetworkError,
    TimeoutError as AuthTimeoutError,
    create_error_from_response,
    is_retryable_error,
)
from .models import (
    DetailedHealthStatus,
    HealthStatus,
    LoginResponse,
    MFASetupResponse,
    MFAVerifyResponse,
    OAuthTokenResponse,
    SystemStats,
    TokenResponse,
    UserInfo,
    UserProfile,
)


class AuthFrameworkClient:
    """Main AuthFramework API client."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        retries: int = 3,
        api_key: str | None = None,
    ) -> None:
        """Initialize the AuthFramework client.

        Args:
            base_url: The base URL of the AuthFramework API
            timeout: Request timeout in seconds
            retries: Number of retry attempts for failed requests
            api_key: Optional API key for authentication

        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.api_key = api_key
        self._access_token: str | None = None

        # Create HTTP client
        headers = {"User-Agent": "AuthFramework-Python-SDK/1.0.0"}
        if api_key:
            headers["X-API-Key"] = api_key

        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
        )

    async def __aenter__(self) -> "AuthFrameworkClient":
        """Async context manager entry.

        Returns:
            The client instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit.

        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
        """
        await self._client.aclose()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    def set_access_token(self, token: str) -> None:
        """Set the access token for authenticated requests."""
        self._access_token = token

    def clear_access_token(self) -> None:
        """Clear the access token."""
        self._access_token = None

    def get_access_token(self) -> str | None:
        """Get the current access token."""
        return self._access_token

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict[str, Any | None] | None = None,
        form_data: dict[str, str | None] | None = None,
        params: dict[str, Any | None] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with retry logic."""
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        request_timeout = timeout or self.timeout
        request_retries = retries if retries is not None else self.retries

        headers: dict[str, str] = {}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        for attempt in range(request_retries + 1):
            try:
                if form_data:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    response = await self._client.request(
                        method,
                        url,
                        data=form_data,
                        params=params,
                        headers=headers,
                        timeout=request_timeout,
                    )
                else:
                    response = await self._client.request(
                        method,
                        url,
                        json=json_data,
                        params=params,
                        headers=headers,
                        timeout=request_timeout,
                    )

                if response.status_code < 400:
                    return response.json()

                # Handle error response
                try:
                    error_data = response.json()
                    error_info = error_data.get("error", {})
                except Exception:
                    error_info = {"message": response.text, "code": "UNKNOWN_ERROR"}

                raise create_error_from_response(response.status_code, error_info)

            except httpx.TimeoutException as e:
                if attempt == request_retries:
                    timeout_msg = "Request timeout"
                    raise AuthTimeoutError(timeout_msg) from e
            except httpx.NetworkError as e:
                if attempt == request_retries:
                    network_msg = "Network error"
                    raise NetworkError(network_msg) from e
            except AuthFrameworkError:
                # Don't retry AuthFramework errors
                raise
            except Exception as e:
                if attempt == request_retries or not is_retryable_error(e):
                    failed_msg = "Request failed"
                    raise AuthFrameworkError(failed_msg) from e

            # Exponential backoff
            if attempt < request_retries:
                await asyncio.sleep(min(2**attempt, 10))

        retries_msg = "Max retries exceeded"
        raise AuthFrameworkError(retries_msg)

    # Authentication methods
    async def login(
        self,
        username: str,
        password: str,
        remember_me: bool = False,
    ) -> LoginResponse:
        """Authenticate user and return tokens.

        Returns:
            LoginResponse containing access tokens and user info.

        """
        data = {"username": username, "password": password, "remember_me": remember_me}
        response = await self._make_request("POST", "/auth/login", json_data=data)

        login_response = LoginResponse(**response["data"])
        self.set_access_token(login_response.access_token)
        return login_response

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """Refresh access token.

        Returns:
            TokenResponse containing new access token.

        """
        data = {"refresh_token": refresh_token}
        response = await self._make_request("POST", "/auth/refresh", json_data=data)

        token_response = TokenResponse(**response["data"])
        self.set_access_token(token_response.access_token)
        return token_response

    async def logout(self) -> None:
        """Logout and invalidate session."""
        await self._make_request("POST", "/auth/logout")
        self.clear_access_token()

    async def validate_token(self) -> UserInfo:
        """Validate current token and get user info."""
        response = await self._make_request("POST", "/auth/validate")
        return UserInfo(**response["data"])

    # User management methods
    async def get_profile(self) -> UserProfile:
        """Get current user's profile."""
        response = await self._make_request("GET", "/users/profile")
        return UserProfile(**response["data"])

    async def update_profile(self, **kwargs: Any) -> UserProfile:
        """Update current user's profile."""
        response = await self._make_request("PATCH", "/users/profile", json_data=kwargs)
        return UserProfile(**response["data"])

    async def change_password(self, current_password: str, new_password: str) -> None:
        """Change current user's password."""
        data = {"current_password": current_password, "new_password": new_password}
        await self._make_request("POST", "/users/password", json_data=data)

    # MFA methods
    async def setup_mfa(self) -> MFASetupResponse:
        """Set up MFA for current user.

        Returns:
            MFASetupResponse containing setup information.

        """
        response = await self._make_request("POST", "/mfa/setup")
        return MFASetupResponse(**response["data"])

    async def verify_mfa(self, code: str) -> MFAVerifyResponse:
        """Verify MFA code."""
        data = {"code": code}
        response = await self._make_request("POST", "/mfa/verify", json_data=data)
        return MFAVerifyResponse(**response["data"])

    async def disable_mfa(self, password: str, code: str) -> None:
        """Disable MFA for current user."""
        data = {"password": password, "code": code}
        await self._make_request("POST", "/mfa/disable", json_data=data)

    # Health methods
    async def get_health(self) -> HealthStatus:
        """Get basic health status."""
        response = await self._make_request("GET", "/health")
        return HealthStatus(**response["data"])

    async def get_detailed_health(self) -> DetailedHealthStatus:
        """Get detailed health status."""
        response = await self._make_request("GET", "/health/detailed")
        return DetailedHealthStatus(**response["data"])

    # OAuth methods
    def get_oauth_authorize_url(self, **params: Any) -> str:
        """Generate OAuth authorization URL."""
        query_string = urlencode({k: v for k, v in params.items() if v is not None})
        return f"{self.base_url}/oauth/authorize?{query_string}"

    async def get_oauth_token(self, **kwargs: Any) -> OAuthTokenResponse:
        """Get OAuth token."""
        form_data: dict[str, str | None] = {
            k: str(v) if v is not None else None for k, v in kwargs.items()
        }
        response = await self._make_request("POST", "/oauth/token", form_data=form_data)
        return OAuthTokenResponse(**response)

    # Admin methods (require admin permissions)
    async def list_users(self, **params: Any) -> dict[str, Any]:
        """List users (admin only)."""
        return await self._make_request("GET", "/admin/users", params=params)

    async def create_user(self, **kwargs: Any) -> UserInfo:
        """Create a new user (admin only)."""
        response = await self._make_request("POST", "/admin/users", json_data=kwargs)
        return UserInfo(**response["data"])

    async def get_user(self, user_id: str) -> UserInfo:
        """Get user details (admin only)."""
        response = await self._make_request("GET", f"/admin/users/{user_id}")
        return UserInfo(**response["data"])

    async def delete_user(self, user_id: str) -> None:
        """Delete user (admin only)."""
        await self._make_request("DELETE", f"/admin/users/{user_id}")

    async def get_system_stats(self) -> SystemStats:
        """Get system statistics (admin only)."""
        response = await self._make_request("GET", "/admin/stats")
        return SystemStats(**response["data"])
