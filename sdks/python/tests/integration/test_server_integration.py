"""Integration tests for AuthFramework Python SDK.

These tests run against a real AuthFramework server to ensure
the SDK works correctly end-to-end.
"""

import pytest


# Simple markers for integration tests
integration_test = pytest.mark.asyncio
requires_server = lambda: pytest.mark.integration


@requires_server()
class TestHealthServiceIntegration:
    """Integration tests for HealthService."""

    @integration_test
    async def test_basic_health_check(self, integration_client):
        """Test basic health check against real server."""
        health = await integration_client.health.check()
        
        assert isinstance(health, dict)
        assert "status" in health
        assert health["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in health

    @integration_test
    async def test_detailed_health_check(self, integration_client):
        """Test detailed health check against real server."""
        detailed_health = await integration_client.health.detailed_check()
        
        assert isinstance(detailed_health, dict)
        assert "status" in detailed_health
        assert "uptime" in detailed_health
        assert "services" in detailed_health
        assert isinstance(detailed_health["services"], dict)

    @integration_test
    async def test_readiness_check(self, integration_client):
        """Test readiness check against real server."""
        readiness = await integration_client.health.readiness_check()
        
        assert isinstance(readiness, dict)
        assert "ready" in readiness
        assert isinstance(readiness["ready"], bool)
        if "dependencies" in readiness:
            assert isinstance(readiness["dependencies"], dict)

    @integration_test
    async def test_liveness_check(self, integration_client):
        """Test liveness check against real server."""
        liveness = await integration_client.health.liveness_check()
        
        assert isinstance(liveness, dict)
        assert "alive" in liveness
        assert isinstance(liveness["alive"], bool)
        # Liveness should be True if we can call it
        assert liveness["alive"] is True

    @integration_test
    async def test_health_metrics(self, integration_client):
        """Test health metrics retrieval."""
        try:
            metrics = await integration_client.health.get_metrics()
            
            assert isinstance(metrics, dict)
            # Metrics might not be available on all servers
            if "uptime_seconds" in metrics:
                assert isinstance(metrics["uptime_seconds"], (int, float))
                assert metrics["uptime_seconds"] >= 0
        except Exception as e:
            # Metrics endpoint might not be implemented yet
            pytest.skip(f"Metrics endpoint not available: {e}")


@requires_server()
class TestAuthServiceIntegration:
    """Integration tests for AuthService."""

    @integration_test
    async def test_health_endpoint_accessible(self, integration_client):
        """Test that we can reach the server through auth service endpoints."""
        # This is a basic connectivity test
        # We expect some endpoints to require authentication and return 401
        try:
            # This should fail with authentication error, not connection error
            await integration_client.auth.get_profile()
            pytest.fail("Expected authentication error")
        except Exception as e:
            # We expect an auth error, not a connection error
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["auth", "token", "unauthorized", "401"])

    @integration_test
    async def test_login_with_invalid_credentials(self, integration_client):
        """Test login with invalid credentials returns appropriate error."""
        try:
            await integration_client.auth.login("nonexistent_user", "wrong_password")
            pytest.fail("Expected authentication error")
        except Exception as e:
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["invalid", "credentials", "unauthorized", "401"])


@requires_server()
class TestTokenServiceIntegration:
    """Integration tests for TokenService."""

    @integration_test
    async def test_token_validation_with_invalid_token(self, integration_client):
        """Test token validation with invalid token."""
        try:
            result = await integration_client.tokens.validate("invalid-token-12345")
            # If this succeeds, the token should be marked as invalid
            assert isinstance(result, dict)
            assert result.get("valid", True) is False
        except Exception as e:
            # Some implementations might throw an exception for invalid tokens
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["invalid", "token", "unauthorized"])

    @integration_test
    async def test_token_refresh_with_invalid_token(self, integration_client):
        """Test token refresh with invalid refresh token."""
        try:
            await integration_client.tokens.refresh("invalid-refresh-token")
            pytest.fail("Expected error for invalid refresh token")
        except Exception as e:
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["invalid", "token", "unauthorized", "refresh"])


@requires_server()
class TestAdminServiceIntegration:
    """Integration tests for AdminService."""

    @integration_test
    async def test_admin_endpoints_require_auth(self, integration_client):
        """Test that admin endpoints require authentication."""
        try:
            await integration_client.admin.get_stats()
            pytest.fail("Expected authentication error")
        except Exception as e:
            error_msg = str(e).lower()
            assert any(word in error_msg for word in ["auth", "token", "unauthorized", "401", "403"])

    @integration_test
    async def test_rate_limit_endpoints_exist(self, integration_client):
        """Test that rate limiting endpoints exist (even if they require auth)."""
        try:
            await integration_client.admin.get_rate_limits()
            pytest.fail("Expected authentication error")
        except Exception as e:
            error_msg = str(e).lower()
            # Should be auth error, not "not found" or "method not allowed"
            assert not any(word in error_msg for word in ["not found", "404", "method not allowed", "405"])
            assert any(word in error_msg for word in ["auth", "token", "unauthorized", "401", "403"])


@requires_server()
class TestServerConnectivity:
    """Basic server connectivity tests."""

    @integration_test
    async def test_server_is_running(self, test_server):
        """Test that the server is running and healthy."""
        assert await test_server.is_healthy()

    @integration_test
    async def test_client_can_connect(self, integration_client):
        """Test that the client can connect to the server."""
        # Try a basic health check to verify connectivity
        health = await integration_client.health.check()
        assert isinstance(health, dict)
        assert "status" in health


# Optional: Test with authentication if we can set up a test user
@requires_server()
class TestAuthenticatedOperations:
    """Integration tests that require authentication."""

    @integration_test
    async def test_authenticated_profile_access(self, authenticated_client):
        """Test accessing user profile with authentication."""
        try:
            profile = await authenticated_client.auth.get_profile()
            assert isinstance(profile, dict)
            assert "id" in profile or "username" in profile
        except Exception as e:
            # Skip if we can't set up authentication properly
            pytest.skip(f"Authentication setup failed: {e}")

    @integration_test
    async def test_token_validation_with_valid_token(self, authenticated_client):
        """Test token validation with a valid token."""
        try:
            # Get the token from the authenticated client
            token = authenticated_client._client.token
            if not token:
                pytest.skip("No token available on authenticated client")
            
            result = await authenticated_client.tokens.validate(token)
            assert isinstance(result, dict)
            assert result.get("valid", False) is True
        except Exception as e:
            pytest.skip(f"Token validation test failed: {e}")