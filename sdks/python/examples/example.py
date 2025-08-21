"""Example usage of the AuthFramework Python SDK."""
# Copyright (c) 2025 AuthFramework Team. All rights reserved.

import asyncio
import logging

from authframework import AuthFrameworkClient
from authframework.exceptions import AuthenticationError, AuthFrameworkError


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main() -> None:
    """Execute main example function."""
    # Initialize client
    client = AuthFrameworkClient("http://localhost:8080")

    try:
        # Example 1: Login and get profile
        logger.info("=== Login Example ===")

        login_response = await client.auth.login("user@example.com", "password")
        logger.info(
            "Login successful! Token expires in %s seconds",
            login_response.get("expires_in", "unknown"),
        )

        # Get user profile
        profile = await client.user.get_profile()
        logger.info(
            "Welcome, %s! (ID: %s)",
            profile.get("display_name", "User"),
            profile.get("user_id", "unknown"),
        )

        # Example 2: Update profile
        logger.info("=== Profile Update Example ===")

        await client.user.update_profile(
            profile_data={
                "display_name": "Updated Name",
                "preferences": {"theme": "dark", "notifications": True},
            },
        )
        logger.info("Profile updated successfully!")

        # Example 3: MFA setup (if not already enabled)
        logger.info("=== MFA Setup Example ===")

        if not profile["mfa_enabled"]:
            mfa_setup = await client.mfa.enable_totp()
            logger.info("MFA Secret: %s", mfa_setup["secret"])
            logger.info("QR Code URL: %s", mfa_setup["qr_code"])
            logger.info("Scan the QR code with your authenticator app")

            # In a real app, you'd prompt the user for the code
            # For demonstration, we'll simulate MFA verification
            logger.info("MFA enabled successfully!")
        else:
            logger.info("MFA is already enabled for this user")

        # Example 4: OAuth authorization URL
        logger.info("=== OAuth Example ===")

        auth_url = await client.oauth.authorize(
            client_id="example-app",
            redirect_uri="https://example.com/callback",
            scope="read write",
            state="random-state-123",
        )
        logger.info("OAuth Authorization URL: %s", auth_url)

        # Example 5: Health check
        logger.info("=== Health Check Example ===")

        health = await client.health_check()
        logger.info("Service status: %s", health["status"])
        logger.info("Service version: %s", health["version"])

        # Example 6: Admin functions (if user has admin role)
        logger.info("=== Admin Functions Example ===")

        try:
            stats = await client.admin.get_system_stats()
            logger.info("Total users: %s", stats["total_users"])
            logger.info("Active sessions: %s", stats["active_sessions"])

            # List users
            users = await client.user.get_users(limit=5)
            logger.info("Found %s users", len(users.get("users", [])))

        except AuthenticationError:
            logger.info("User doesn't have admin permissions")

        # Example 7: Logout
        logger.info("=== Logout Example ===")

        await client.auth.logout()
        logger.info("Logged out successfully!")

    except AuthenticationError as e:
        logger.exception("Authentication failed: %s", e.message)
    except AuthFrameworkError as e:
        logger.exception("API error: %s (Status: %s)", e.message, e.status_code)
    except Exception:
        logger.exception("Unexpected error occurred")
    finally:
        # Always close the client
        await client.close()


async def context_manager_example() -> None:
    """Use context manager example (recommended approach)."""
    logger.info("=== Context Manager Example ===")

    try:
        async with AuthFrameworkClient("http://localhost:8080") as client:
            # Login
            await client.auth.login("user@example.com", "password")

            # Get profile
            profile = await client.user.get_profile()
            logger.info("User: %s", profile["display_name"])

            # Client is automatically closed when exiting the context

    except AuthFrameworkError:
        logger.exception("API error occurred")


async def concurrent_requests_example() -> None:
    """Demonstrate making concurrent requests."""
    logger.info("=== Concurrent Requests Example ===")

    async with AuthFrameworkClient("http://localhost:8080") as client:
        # Login first
        await client.auth.login("admin@example.com", "admin_password")

        # Make multiple concurrent requests
        tasks = [
            client.health_check(),
            client.user.get_profile(),
            client.admin.get_system_stats(),
        ]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error("Task %s failed: %s", i, result)
                else:
                    logger.info("Task %s completed successfully", i)

        except Exception:
            logger.exception("Concurrent requests failed")


if __name__ == "__main__":
    # Run the main example
    asyncio.run(main())

    # Run context manager example
    asyncio.run(context_manager_example())

    # Run concurrent requests example
    asyncio.run(concurrent_requests_example())
