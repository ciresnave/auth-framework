"""Rate limiting models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from typing import Any
from pydantic import BaseModel


class RateLimitConfig(BaseModel):
    """Rate limiting configuration model."""

    enabled: bool
    requests_per_minute: int
    requests_per_hour: int
    burst_size: int
    whitelist: list[str] | None = None
    blacklist: list[str] | None = None


class RateLimitStats(BaseModel):
    """Rate limiting statistics model."""

    total_requests: int
    blocked_requests: int
    current_minute_requests: int
    current_hour_requests: int
    top_ips: list[dict[str, Any]]
    timestamp: datetime