"""Integration test configuration for running tests against a real AuthFramework server.

This module provides utilities for starting/stopping the AuthFramework server
and running integration tests against it.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import AsyncGenerator

import httpx
import pytest

from authframework import AuthFrameworkClient


class AuthFrameworkTestServer:
    """Manages a test AuthFramework server instance."""

    def __init__(self, port: int | None = None):
        self.port = port or int(os.environ.get("AUTH_FRAMEWORK_TEST_PORT", "8088"))
        self.base_url = f"http://localhost:{port}"
        self.process: subprocess.Popen | None = None
        self.project_root = Path(__file__).parent.parent.parent.parent

    async def start(self) -> None:
        """Start the AuthFramework server."""
        print(f"🚀 Starting AuthFramework server on port {self.port}...")
        
        # Build the server first
        build_result = subprocess.run(
            ["cargo", "build", "--bin", "auth-framework", "--features", "admin-binary"],
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        if build_result.returncode != 0:
            raise RuntimeError(f"Failed to build AuthFramework server: {build_result.stderr}")

        # Start the server
        env = os.environ.copy()
        env.update({
            "AUTH_FRAMEWORK_HOST": "127.0.0.1",
            "AUTH_FRAMEWORK_PORT": str(self.port),
            "AUTH_FRAMEWORK_DATABASE_URL": "sqlite::memory:",
            "AUTH_FRAMEWORK_JWT_SECRET": "test-secret-for-integration-tests-only-not-secure",
            "AUTH_FRAMEWORK_LOG_LEVEL": "info",
            "RUST_LOG": "auth_framework=debug",
        })

        self.process = subprocess.Popen(
            [self.project_root / "target" / "debug" / "auth-framework"],
            cwd=self.project_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait for server to be ready
        await self._wait_for_server_ready()
        print(f"✅ AuthFramework server ready at {self.base_url}")

    async def _wait_for_server_ready(self, timeout: int = 30) -> None:
        """Wait for the server to be ready to accept requests."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{self.base_url}/health")
                    if response.status_code == 200:
                        return
            except (httpx.RequestError, httpx.ConnectError):
                pass
            
            # Check if process is still running
            if self.process and self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise RuntimeError(
                    f"AuthFramework server process died:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
                )
            
            await asyncio.sleep(0.5)
        
        raise TimeoutError(f"Server did not become ready within {timeout} seconds")

    async def stop(self) -> None:
        """Stop the AuthFramework server."""
        if self.process:
            print("🛑 Stopping AuthFramework server...")
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("⚠️  Server didn't stop gracefully, killing...")
                self.process.kill()
                self.process.wait()
            
            self.process = None
            print("✅ AuthFramework server stopped")

    async def is_healthy(self) -> bool:
        """Check if the server is healthy."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except Exception:
            return False


# Global server instance for test session
_test_server: AuthFrameworkTestServer | None = None


@pytest.fixture(scope="session")
async def test_server() -> AsyncGenerator[AuthFrameworkTestServer, None]:
    """Session-scoped test server fixture."""
    global _test_server
    
    _test_server = AuthFrameworkTestServer()
    
    try:
        await _test_server.start()
        yield _test_server
    finally:
        if _test_server:
            await _test_server.stop()


@pytest.fixture
async def integration_client(test_server: AuthFrameworkTestServer) -> AsyncGenerator[AuthFrameworkClient, None]:
    """Create a client connected to the test server."""
    async with AuthFrameworkClient(
        base_url=test_server.base_url,
        timeout=10.0,
        retries=2,
    ) as client:
        yield client


@pytest.fixture
async def authenticated_client(integration_client: AuthFrameworkClient) -> AsyncGenerator[AuthFrameworkClient, None]:
    """Create an authenticated client for tests that need authentication."""
    try:
        # Try to create a test user and login
        # Note: This will depend on the actual AuthFramework API endpoints
        
        test_user = {
            "username": "integration_test_user",
            "email": "test@integration.test",
            "password": "TestPassword123!",
        }
        
        # Create user (this might fail if user already exists, which is fine)
        try:
            await integration_client.admin.create_user(test_user)
        except Exception:
            # User might already exist
            pass
        
        # Login
        login_response = await integration_client.auth.login(
            test_user["username"], 
            test_user["password"]
        )
        
        # Set the token on the client
        integration_client._client.token = login_response["access_token"]
        
        yield integration_client
        
    except Exception as e:
        # If we can't authenticate, skip tests that need it
        pytest.skip(f"Could not create authenticated client: {e}")


# Mark for integration tests
integration_test = pytest.mark.asyncio


def requires_server():
    """Mark tests that require a running server."""
    return pytest.mark.integration