"""Flask integration for AuthFramework."""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional

try:
    from flask import g, request, jsonify, current_app
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from ..client import AuthFrameworkClient
from ..exceptions import AuthFrameworkError
from ..models import UserInfo


class FlaskAuthUser:
    """Authenticated user information for Flask."""

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


class AuthFrameworkFlask:
    """Flask integration for AuthFramework authentication."""

    def __init__(self, client: AuthFrameworkClient):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is not installed. Install it with: pip install flask")
        
        self.client = client

    def _get_token_from_request(self) -> Optional[str]:
        """Extract token from request headers."""
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        return None

    async def _validate_token(self, token: str) -> FlaskAuthUser:
        """Validate token and return user information."""
        try:
            # Validate token using the tokens service
            validation_result = await self.client.tokens.validate(token)
            
            if not validation_result.get("valid", False):
                raise AuthFrameworkError("Invalid or expired token")

            # Get user information
            user_id = validation_result.get("user_id")
            if not user_id:
                raise AuthFrameworkError("Token does not contain user information")

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

            return FlaskAuthUser(user_info, token)

        except AuthFrameworkError:
            raise

    def _handle_auth_error(self, message: str, status_code: int = 401):
        """Handle authentication errors."""
        return jsonify({"error": message}), status_code


def get_current_user() -> Optional[FlaskAuthUser]:
    """Get the current authenticated user from Flask's g object."""
    return getattr(g, 'current_user', None)


def auth_required(auth_framework: AuthFrameworkFlask):
    """Decorator to require authentication."""
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        async def decorated_function(*args: Any, **kwargs: Any) -> Any:
            token = auth_framework._get_token_from_request()
            if not token:
                return auth_framework._handle_auth_error("Authorization header missing")

            try:
                user = await auth_framework._validate_token(token)
                g.current_user = user
                return await f(*args, **kwargs)
            except AuthFrameworkError as e:
                return auth_framework._handle_auth_error(f"Authentication failed: {e}")

        return decorated_function
    return decorator


def role_required(auth_framework: AuthFrameworkFlask, required_role: str):
    """Decorator to require a specific role."""
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @auth_required(auth_framework)
        async def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user or not user.has_role(required_role):
                return auth_framework._handle_auth_error(
                    f"Role '{required_role}' required", 403
                )
            return await f(*args, **kwargs)

        return decorated_function
    return decorator


def any_role_required(auth_framework: AuthFrameworkFlask, required_roles: list[str]):
    """Decorator to require any of the specified roles."""
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @auth_required(auth_framework)
        async def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user or not user.has_any_role(required_roles):
                roles_str = "', '".join(required_roles)
                return auth_framework._handle_auth_error(
                    f"One of the following roles required: '{roles_str}'", 403
                )
            return await f(*args, **kwargs)

        return decorated_function
    return decorator


def permission_required(
    auth_framework: AuthFrameworkFlask, resource: str, action: str
):
    """Decorator to require a specific permission."""
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        @auth_required(auth_framework)
        async def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user = get_current_user()
            if not user:
                return auth_framework._handle_auth_error("Authentication required")

            # Note: This would need to be implemented in the Rust API
            # For now, we'll check if the user has an 'admin' role as a placeholder
            if not user.has_role("admin"):
                return auth_framework._handle_auth_error(
                    f"Permission '{action}' on '{resource}' required", 403
                )
            return await f(*args, **kwargs)

        return decorated_function
    return decorator