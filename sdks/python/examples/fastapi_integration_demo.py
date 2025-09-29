"""
FastAPI integration example for AuthFramework.

This example shows how to use the AuthFramework decorators with FastAPI.
"""

try:
    from fastapi import FastAPI, Depends
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from authframework import AuthFrameworkClient
from authframework.integrations.fastapi import AuthFrameworkFastAPI, AuthUser

if not FASTAPI_AVAILABLE:
    print("FastAPI is not installed. Install it with: pip install fastapi uvicorn")
    exit(1)

# Initialize the AuthFramework client
client = AuthFrameworkClient(
    base_url="http://localhost:8080",
    api_key="fastapi-demo-api-key"
)

# Initialize the FastAPI integration
auth = AuthFrameworkFastAPI(client)

# Create FastAPI app
app = FastAPI(
    title="AuthFramework FastAPI Demo",
    description="Demonstrating AuthFramework integration with FastAPI",
    version="1.0.0"
)


@app.get("/")
async def root():
    """Public endpoint - no authentication required."""
    return {"message": "Welcome to AuthFramework FastAPI Demo!"}


@app.get("/protected")
async def protected_endpoint(user: AuthUser = Depends(auth.require_auth())):
    """Protected endpoint - authentication required."""
    return {
        "message": "You are authenticated!",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles
        }
    }


@app.get("/admin-only")
async def admin_only_endpoint(user: AuthUser = Depends(auth.require_role("admin"))):
    """Admin-only endpoint - requires admin role."""
    return {
        "message": "Welcome, admin!",
        "user": {
            "id": user.id,
            "username": user.username,
            "admin_privileges": True
        }
    }


@app.get("/user-or-moderator")
async def user_or_moderator_endpoint(
    user: AuthUser = Depends(auth.require_any_role(["user", "moderator"]))
):
    """Endpoint requiring either user or moderator role."""
    return {
        "message": f"Welcome, {user.username}!",
        "user": {
            "id": user.id,
            "username": user.username,
            "roles": user.roles,
            "has_required_role": True
        }
    }


@app.get("/manage-users")
async def manage_users_endpoint(
    user: AuthUser = Depends(auth.require_permission("users", "manage"))
):
    """Endpoint requiring specific permission."""
    return {
        "message": "You can manage users!",
        "user": {
            "id": user.id,
            "username": user.username,
            "permissions": ["users:manage"]
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint using AuthFramework's health service."""
    try:
        health_status = await client.health.check()
        return health_status
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check endpoint."""
    try:
        detailed_health = await client.health.detailed_check()
        return detailed_health
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.on_event("startup")
async def startup_event():
    """Initialize the AuthFramework client on startup."""
    print("🚀 Starting FastAPI with AuthFramework integration...")
    print("📋 Available endpoints:")
    print("   GET  /                     - Public endpoint")
    print("   GET  /protected            - Requires authentication")
    print("   GET  /admin-only           - Requires admin role")  
    print("   GET  /user-or-moderator    - Requires user or moderator role")
    print("   GET  /manage-users         - Requires users:manage permission")
    print("   GET  /health               - Health check")
    print("   GET  /health/detailed      - Detailed health check")
    print()
    print("🔐 To test authentication:")
    print("   Add header: Authorization: Bearer <your-token>")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown."""
    await client.close()


if __name__ == "__main__":
    import uvicorn
    
    print("=== AuthFramework FastAPI Integration Demo ===")
    print()
    print("This demo shows how to use AuthFramework with FastAPI:")
    print("• Authentication decorators")
    print("• Role-based access control")
    print("• Permission-based access control")
    print("• Health monitoring integration")
    print()
    print("Starting server on http://localhost:8000")
    print("API docs available at http://localhost:8000/docs")
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)