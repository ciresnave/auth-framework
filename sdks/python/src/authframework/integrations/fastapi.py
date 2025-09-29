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
            
            if not validation_result.get("valid", False):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token"
                )

            # Get user information
            user_id = validation_result.get("user_id")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token does not contain user information"
                )

            # This would typically come from the validation response
            # For now, we'll create a basic user info object
            user_info = UserInfo(
                id=user_id,
                username=validation_result.get("username", ""),
                email=validation_result.get("email", ""),
                roles=validation_result.get("scopes", []),
                mfa_enabled=validation_result.get("mfa_enabled", False),
                created_at=validation_result.get("created_at"),
                last_login=validation_result.get("last_login")
            )

            return AuthUser(user_info, credentials.credentials)

        except AuthFrameworkError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {e}"
            )

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
            # Note: This would need to be implemented in the Rust API
            # For now, we'll check if the user has an 'admin' role as a placeholder
            if not user.has_role("admin"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{action}' on '{resource}' required"
                )
            return user
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