"""Base HTTP client for AuthFramework API operations.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

import asyncio
from typing import Any, NamedTuple
from urllib.parse import urljoin

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

import httpx

from .exceptions import (
    AuthFrameworkError,
    NetworkError,
    TimeoutError as AuthTimeoutError,
    create_error_from_response,
    is_retryable_error,
)


# HTTP Error Status Constants
HTTP_SUCCESS_THRESHOLD = 400


class RequestConfig(NamedTuple):
    """Configuration for HTTP requests."""

    json_data: dict[str, Any] | None = None
    form_data: dict[str, str | None] | None = None
    params: dict[str, Any] | None = None
    timeout: float | None = None
    retries: int | None = None


class BaseClient:
    """Base HTTP client for making API requests."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        retries: int = 3,
        api_key: str | None = None,
    ) -> None:
        """Initialize base HTTP client.

        Args:
            base_url: The base URL of the API
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

    async def __aenter__(self) -> Self:
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
        """Get the current access token.

        Returns:
            Current access token or None if not set.

        """
        return self._access_token

    async def make_request(
        self,
        method: str,
        endpoint: str,
        *,
        config: RequestConfig | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            config: Request configuration

        Returns:
            Parsed JSON response data.

        Raises:
            AuthFrameworkError: For authentication/authorization errors
            NetworkError: For network-related errors
            AuthTimeoutError: For timeout errors

        """
        if config is None:
            config = RequestConfig()

        url = urljoin(self.base_url, endpoint.lstrip("/"))
        request_timeout = config.timeout or self.timeout
        request_retries = config.retries if config.retries is not None else self.retries

        headers: dict[str, str] = {}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        for attempt in range(request_retries + 1):
            response = await self._attempt_request(
                method,
                url,
                headers,
                config,
                request_timeout,
            )
            if response:
                return response

            # Exponential backoff for retries
            if attempt < request_retries:
                await asyncio.sleep(min(2**attempt, 10))

        retries_msg = "Max retries exceeded"
        raise AuthFrameworkError(retries_msg)

    async def _attempt_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        config: RequestConfig,
        request_timeout: float,
    ) -> dict[str, Any] | None:
        """Attempt a single HTTP request.

        Returns:
            Response data if successful, None if retryable error.

        Raises:
            Various errors for non-retryable failures.

        """
        try:
            response = await self._execute_request(
                method,
                url,
                headers,
                config,
                request_timeout,
            )

            if response.status_code < HTTP_SUCCESS_THRESHOLD:
                return response.json()

            # Handle error response
            error_info = self._parse_error_response(response)
            self._raise_api_error(response.status_code, error_info)

        except httpx.TimeoutException as e:
            timeout_msg = "Request timeout"
            raise AuthTimeoutError(timeout_msg) from e
        except httpx.NetworkError as e:
            network_msg = "Network error"
            raise NetworkError(network_msg) from e
        except AuthFrameworkError:
            # Don't retry AuthFramework errors
            raise
        except Exception as e:
            if not is_retryable_error(e):
                failed_msg = "Request failed"
                raise AuthFrameworkError(failed_msg) from e
            return None

        return None

    async def _execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        config: RequestConfig,
        timeout: float,
    ) -> httpx.Response:
        """Execute the actual HTTP request.

        Returns:
            The HTTP response.

        """
        if config.form_data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            return await self._client.request(
                method,
                url,
                data=config.form_data,
                params=config.params,
                headers=headers,
                timeout=timeout,
            )

        return await self._client.request(
            method,
            url,
            json=config.json_data,
            params=config.params,
            headers=headers,
            timeout=timeout,
        )

    @staticmethod
    def _parse_error_response(response: httpx.Response) -> dict[str, Any]:
        """Parse error response from the API.

        Returns:
            Parsed error data.

        """
        try:
            error_data = response.json()
            return error_data.get("error", {})
        except (ValueError, KeyError):
            return {"message": response.text, "code": "UNKNOWN_ERROR"}

    @staticmethod
    def _raise_api_error(status_code: int, error_info: dict[str, Any]) -> None:
        """Raise appropriate error for API response.

        Args:
            status_code: HTTP status code
            error_info: Error information from response

        """
        raise create_error_from_response(status_code, error_info)
