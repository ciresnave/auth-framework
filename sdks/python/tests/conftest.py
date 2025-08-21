"""Test configuration and common utilities.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import respx
from authframework import AuthFrameworkClient

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator


@pytest.fixture
def base_url() -> str:
    """Return base URL for test server.

    Returns:
        str: The base URL for testing.

    """
    return "https://api.authframework.test"


@pytest.fixture
def api_key() -> str:
    """Return test API key.

    Returns:
        str: The API key for testing.

    """
    return "test-api-key-12345"


@pytest.fixture
async def client(
    base_url: str,
    api_key: str,
) -> AsyncGenerator[AuthFrameworkClient, None]:
    """Create test client.

    Yields:
        AuthFrameworkClient: Configured test client.

    """
    async with AuthFrameworkClient(
        base_url=base_url,
        api_key=api_key,
        timeout=5.0,
        retries=1,
    ) as client:
        yield client


@pytest.fixture
def mock_responses() -> Generator[Any, None, None]:
    """Mock HTTP responses.

    Yields:
        The mock router for HTTP requests.

    """
    with respx.mock:
        yield respx


@pytest.fixture
def sample_user_data() -> dict[str, Any]:
    """Sample user data for testing.

    Returns:
        dict[str, Any]: Sample user data.

    """
    return {
        "id": "user123",
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def sample_login_response() -> dict[str, Any]:
    """Sample login response.

    Returns:
        dict[str, Any]: Sample login response data.

    """
    return {
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {
            "id": "user123",
            "username": "testuser",
            "email": "test@example.com",
        },
    }


@pytest.fixture
def sample_error_response() -> dict[str, Any]:
    """Sample error response.

    Returns:
        dict[str, Any]: Sample error response data.

    """
    return {
        "error": {
            "code": "INVALID_CREDENTIALS",
            "message": "Invalid username or password",
            "details": {"field": "password"},
        },
    }
