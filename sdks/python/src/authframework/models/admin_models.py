"""Admin and permission models for AuthFramework.

Copyright (c) 2025 AuthFramework. All rights reserved.
"""

from datetime import datetime
from typing import Any
from pydantic import BaseModel


class Permission(BaseModel):
    """Permission model."""

    id: str
    name: str
    description: str | None = None
    resource: str
    action: str
    created_at: datetime


class Role(BaseModel):
    """Role model."""

    id: str
    name: str
    description: str | None = None
    permissions: list[Permission]
    created_at: datetime
    updated_at: datetime


class CreatePermissionRequest(BaseModel):
    """Create permission request model."""

    name: str
    description: str | None = None
    resource: str
    action: str


class CreateRoleRequest(BaseModel):
    """Create role request model."""

    name: str
    description: str | None = None
    permission_ids: list[str] | None = None


class SystemStats(BaseModel):
    """System statistics model."""

    total_users: int
    active_sessions: int
    users: dict[str, int]
    sessions: dict[str, int]
    oauth: dict[str, int]
    system: dict[str, int | float] 
    timestamp: datetime