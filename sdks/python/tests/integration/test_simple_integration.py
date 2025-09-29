"""Simple integration test to verify concept."""

import pytest
from authframework import AuthFrameworkClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_basic_connectivity():
    """Test basic SDK functionality - this will fail gracefully if no server."""
    client = AuthFrameworkClient(base_url="http://localhost:8088")
    
    try:
        async with client:
            # Try a health check - this should work if server is running
            health = await client.health.check()
            assert isinstance(health, dict)
            print(f"✅ Server is running! Health status: {health.get('status')}")
            
    except Exception as e:
        # Expected if no server running
        error_msg = str(e).lower()
        error_type = type(e).__name__.lower()
        if any(word in error_msg for word in ["connection", "refused", "timeout", "network"]) or \
           any(word in error_type for word in ["connection", "network", "timeout"]):
            pytest.skip(f"No AuthFramework server running on localhost:8088: {e}")
        else:  
            # Re-raise unexpected errors
            raise


@pytest.mark.integration 
@pytest.mark.asyncio
async def test_health_service_endpoints():
    """Test all health service endpoints if server is available."""
    client = AuthFrameworkClient(base_url="http://localhost:8088")
    
    try:
        async with client:
            # Basic health
            health = await client.health.check()
            assert health["success"] is True
            assert "status" in health["data"]
            assert health["data"]["status"] == "healthy"
            
            # Detailed health 
            detailed = await client.health.detailed_check()
            assert detailed["success"] is True
            assert "status" in detailed["data"]
            assert detailed["data"]["status"] == "healthy"
            
            # Readiness
            readiness = await client.health.readiness_check() 
            assert readiness["success"] is True
            
            # Liveness
            liveness = await client.health.liveness_check()
            assert liveness["success"] is True
            
            print("✅ All health endpoints working!")
            
    except Exception as e:
        error_msg = str(e).lower()
        error_type = type(e).__name__.lower()
        if any(word in error_msg for word in ["connection", "refused", "timeout", "network"]) or \
           any(word in error_type for word in ["connection", "network", "timeout"]):
            pytest.skip(f"No AuthFramework server running: {e}")
        else:
            raise


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auth_endpoints_require_authentication():
    """Test that auth endpoints properly require authentication."""
    client = AuthFrameworkClient(base_url="http://localhost:8088")
    
    try:
        async with client:
            # This should fail with auth error, not connection error
            try:
                await client.auth.get_profile()
                pytest.fail("Expected authentication error")
            except Exception as auth_error:
                auth_msg = str(auth_error).lower()
                # Should be auth-related error, not connection error
                assert any(word in auth_msg for word in [
                    "auth", "token", "unauthorized", "401", "forbidden"
                ])
                print("✅ Auth endpoints properly require authentication!")
                
    except Exception as e:
        error_msg = str(e).lower()
        error_type = type(e).__name__.lower()
        if any(word in error_msg for word in ["connection", "refused", "timeout", "network"]) or \
           any(word in error_type for word in ["connection", "network", "timeout"]):
            pytest.skip(f"No AuthFramework server running: {e}")
        else:
            raise