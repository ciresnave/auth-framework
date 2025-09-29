"""FastAPI integration for AuthFramework."""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..client import AuthFrameworkClient
from ..exceptions import AuthFrameworkError
from ..models import UserInfo, TokenValidationResponse


class AuthUser:
    """Authenticated user information for FastAPI."""

    def __init__(self, user_info: UserInfo, token: str):
        self.user_info = user_info
        self.token = token
        self.id = user_info.id
        self.username = user_info.username
        self.email = user_info.email
        self.roles = user_info.roles
        self.mfa_enabled = user_info.mfa_enabled

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(role in self.roles for role in roles)


class AuthFrameworkFastAPI:
    """FastAPI integration for AuthFramework authentication."""

    def __init__(self, client: AuthFrameworkClient):
        self.client = client
        self.security = HTTPBearer()

    async def _validate_token(self, credentials: HTTPAuthorizationCredentials) -> AuthUser:
        """Validate token and return user information."""
        try:
            # Validate token using the tokens service
            validation_result = await self.client.tokens.validate(credentials.credentials)
            
            # Parse ApiResponse structure: {"success": true, "data": {...}}
            if not validation_result.get("success", False):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token"
                )

            # Extract user data from the nested data field
            user_data = validation_result.get("data")
            if not user_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token validation response missing user data"
                )

            # Get user information from the nested data
            user_id = user_data.get("id")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token does not contain user information"
                )

            # Create user info object from the API response data
            user_info = UserInfo(
                id=user_id,
                username=user_data.get("username", ""),
                email=user_data.get("email", ""),  # May not be present in auth response
                roles=user_data.get("roles", []),
                mfa_enabled=user_data.get("mfa_enabled", False),  # May not be present
                created_at=user_data.get("created_at"),  # May not be present
                last_login=user_data.get("last_login")  # May not be present
            )

            return AuthUser(user_info, credentials.credentials)

        except AuthFrameworkError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {e}"
            ) from e

    def get_current_user(self) -> Callable:
        """Get the current authenticated user as a FastAPI dependency."""
        async def _get_current_user(
            credentials: HTTPAuthorizationCredentials = Depends(self.security)
        ) -> AuthUser:
            return await self._validate_token(credentials)
        return _get_current_user

    def require_auth(self) -> Callable:
        """Require authentication decorator/dependency."""
        return self.get_current_user()

    def require_role(self, required_role: str) -> Callable:
        """Require a specific role decorator/dependency."""
        async def _require_role(
            user: AuthUser = Depends(self.get_current_user())
        ) -> AuthUser:
            if not user.has_role(required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{required_role}' required"
                )
            return user
        return _require_role

    def require_any_role(self, required_roles: list[str]) -> Callable:
        """Require any of the specified roles decorator/dependency."""
        async def _require_any_role(
            user: AuthUser = Depends(self.get_current_user())
        ) -> AuthUser:
            if not user.has_any_role(required_roles):
                roles_str = "', '".join(required_roles)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"One of the following roles required: '{roles_str}'"
                )
            return user
        return _require_any_role

    def require_permission(self, resource: str, action: str) -> Callable:
        """Require a specific permission decorator/dependency."""
        async def _require_permission(
            user: AuthUser = Depends(self.get_current_user())
        ) -> AuthUser:
            # Placeholder: granular permission checks are not yet supported
            raise NotImplementedError(
                f"Permission checks for '{action}' on '{resource}' are not yet implemented."
            )
        return _require_permission


# Convenience functions for backward compatibility
def require_auth(auth_framework: AuthFrameworkFastAPI) -> Callable:
    """Convenience function for requiring authentication."""
    return auth_framework.require_auth()


def require_role(auth_framework: AuthFrameworkFastAPI, role: str) -> Callable:
    """Convenience function for requiring a specific role."""
    return auth_framework.require_role(role)


def require_permission(
    auth_framework: AuthFrameworkFastAPI, resource: str, action: str
) -> Callable:
    """Convenience function for requiring a specific permission."""
    return auth_framework.require_permission(resource, action)