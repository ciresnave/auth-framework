"""Simple conftest for integration tests."""

import pytest
from authframework import AuthFrameworkClient


@pytest.fixture
async def integration_client():
    """Create a client for integration tests."""
    # Use a test server URL - this will be replaced with real server management later
    async with AuthFrameworkClient(
        base_url="http://localhost:8088",
        timeout=10.0,
        retries=2,
    ) as client:
        yield client