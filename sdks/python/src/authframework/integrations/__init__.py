"""Framework integrations for AuthFramework Python SDK."""

from .fastapi import *
from .flask import *

__all__ = [
    # FastAPI
    "AuthFrameworkFastAPI",
    "require_auth",
    "require_role",
    "require_permission",
    "AuthUser",
    # Flask
    "AuthFrameworkFlask",
    "auth_required",
    "role_required",
    "permission_required",
    "get_current_user",
]