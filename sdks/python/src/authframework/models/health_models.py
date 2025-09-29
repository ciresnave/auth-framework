"""Health and monitoring models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from pydantic import BaseModel


class HealthStatus(BaseModel):
    """Health status model."""

    status: str
    version: str
    timestamp: datetime


class ServiceHealth(BaseModel):
    """Service health model."""

    status: str
    response_time: float
    last_check: datetime


class DetailedHealthStatus(BaseModel):
    """Detailed health status model."""

    status: str
    services: dict[str, ServiceHealth]
    uptime: int
    version: str
    timestamp: datetime


class HealthMetrics(BaseModel):
    """Health metrics model."""

    uptime_seconds: int
    memory_usage_bytes: int
    cpu_usage_percent: float
    active_connections: int
    request_count: int
    error_count: int
    timestamp: datetime


class ReadinessCheck(BaseModel):
    """Readiness check result model."""

    ready: bool
    dependencies: dict[str, bool]
    timestamp: datetime


class LivenessCheck(BaseModel):
    """Liveness check result model."""

    alive: bool
    timestamp: datetime