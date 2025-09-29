"""Health and monitoring service for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseClient, RequestConfig


class HealthService:
    """Service for health checks and monitoring operations."""

    def __init__(self, client: BaseClient) -> None:
        """Initialize health service.

        Args:
            client: The base HTTP client

        """
        self._client = client

    async def check(self) -> dict[str, Any]:
        """Basic health check.

        Returns:
            Basic health status information.

        """
        config = RequestConfig()
        return await self._client.make_request("GET", "/health", config=config)

    async def detailed_check(self) -> dict[str, Any]:
        """Detailed health check with service metrics.

        Returns:
            Detailed health status with service-level information.

        """
        config = RequestConfig()
        return await self._client.make_request("GET", "/health/detailed", config=config)

    async def get_metrics(self) -> str:
        """Get Prometheus metrics.

        Returns:
            Prometheus-formatted metrics as raw text.

        """
        config = RequestConfig()
        response = await self._client.make_request("GET", "/metrics", config=config)
        
        # The metrics endpoint returns raw text, but our base client expects JSON
        # We'll need to handle this specially
        return response if isinstance(response, str) else str(response)

    async def readiness_check(self) -> dict[str, Any]:
        """Kubernetes readiness probe.

        Returns:
            Readiness probe status wrapped in a consistent format.

        """
        config = RequestConfig()
        response = await self._client._make_text_request("GET", "/readiness", config=config)
        return {
            "success": True,
            "data": {
                "status": response.strip().lower(),
                "message": response.strip()
            }
        }

    async def liveness_check(self) -> dict[str, Any]:
        """Kubernetes liveness probe.

        Returns:
            Liveness probe status wrapped in a consistent format.

        """
        config = RequestConfig()
        response = await self._client._make_text_request("GET", "/liveness", config=config)
        return {
            "success": True,
            "data": {
                "status": response.strip().lower(), 
                "message": response.strip()
            }
        }