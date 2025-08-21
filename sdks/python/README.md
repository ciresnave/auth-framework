# AuthFramework Python SDK

The official Python client library for AuthFramework authentication and authorization services.

## Features

- **Async/await support** with httpx for high-performance HTTP requests
- **Type safety** with Pydantic models and comprehensive type hints
- **Automatic token management** with refresh handling
- **Error handling** with custom exceptions and retry logic
- **Context manager support** for proper resource cleanup
- **Full API coverage** for all AuthFramework endpoints

## Installation

```bash
pip install authframework
```

Or from source:

```bash
cd sdks/python
pip install -e .
```

## Quick Start

### Basic Usage

```python
import asyncio
from authframework import AuthFrameworkClient

async def main():
    # Create client instance
    client = AuthFrameworkClient('http://localhost:8080')

    try:
        # Login
        login_response = await client.login('user@example.com', 'password')
        print(f"Logged in as: {login_response.user.username}")

        # Get user profile
        profile = await client.get_profile()
        print(f"User ID: {profile.user_id}")

        # Update profile
        await client.update_profile(display_name="New Name")

    finally:
        await client.close()

# Run the async function
asyncio.run(main())
```

### Using Context Manager (Recommended)

```python
import asyncio
from authframework import AuthFrameworkClient

async def main():
    async with AuthFrameworkClient('http://localhost:8080') as client:
        # Login
        await client.login('user@example.com', 'password')

        # All API calls are automatically authenticated
        profile = await client.get_profile()
        print(f"Welcome, {profile.display_name}!")

asyncio.run(main())
```

## Authentication

### Basic Login

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    # Login with username/password
    response = await client.login('user@example.com', 'password')

    # Access tokens are automatically managed
    print(f"Access token expires in: {response.expires_in} seconds")
```

### API Key Authentication

```python
# For server-to-server authentication
client = AuthFrameworkClient(
    'http://localhost:8080',
    api_key='your-api-key'
)
```

### Token Refresh

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    await client.login('user@example.com', 'password')

    # Tokens are automatically refreshed when needed
    # You can also manually refresh:
    new_tokens = await client.refresh_token()
```

## User Management

### Profile Management

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    await client.login('user@example.com', 'password')

    # Get current user profile
    profile = await client.get_profile()
    print(f"Email: {profile.email}")
    print(f"Display Name: {profile.display_name}")
    print(f"MFA Enabled: {profile.mfa_enabled}")

    # Update profile
    await client.update_profile(
        display_name="New Display Name",
        preferences={"theme": "dark", "language": "en"}
    )

    # Change password
    await client.change_password(
        current_password="old_password",
        new_password="new_password"
    )
```

## Multi-Factor Authentication (MFA)

### Setup MFA

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    await client.login('user@example.com', 'password')

    # Setup MFA
    mfa_setup = await client.setup_mfa()
    print(f"QR Code URL: {mfa_setup.qr_code}")
    print(f"Secret Key: {mfa_setup.secret}")
    print(f"Backup Codes: {mfa_setup.backup_codes}")

    # Verify MFA setup with code from authenticator app
    await client.verify_mfa("123456")
```

### Disable MFA

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    await client.login('user@example.com', 'password')

    # Disable MFA (requires password and current MFA code)
    await client.disable_mfa(
        password="current_password",
        code="123456"
    )
```

## OAuth 2.0 Integration

### Authorization Code Flow

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    # Generate authorization URL
    auth_url = client.get_oauth_authorize_url(
        response_type="code",
        client_id="your-app-id",
        redirect_uri="https://yourapp.com/callback",
        scope="read write",
        state="random-state-value"
    )

    print(f"Redirect user to: {auth_url}")

    # After user authorizes and you receive the code:
    token_response = await client.get_oauth_token(
        grant_type="authorization_code",
        code="authorization-code",
        client_id="your-app-id",
        client_secret="your-app-secret",
        redirect_uri="https://yourapp.com/callback"
    )

    print(f"Access Token: {token_response.access_token}")
```

### Client Credentials Flow

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    # Server-to-server authentication
    token_response = await client.get_oauth_token(
        grant_type="client_credentials",
        client_id="your-service-id",
        client_secret="your-service-secret",
        scope="admin"
    )

    # Use the access token for API calls
    client._access_token = token_response.access_token
```

## Administrative Functions

### User Management (Admin Only)

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    # Login as admin
    await client.login('admin@example.com', 'admin_password')

    # List users with pagination
    users = await client.list_users(page=1, limit=10, search="john")

    # Create new user
    new_user = await client.create_user(
        username="newuser@example.com",
        password="secure_password",
        email="newuser@example.com",
        display_name="New User",
        roles=["user"]
    )

    # Get user details
    user = await client.get_user(new_user.user_id)

    # Delete user
    await client.delete_user(user.user_id)

    # Get system statistics
    stats = await client.get_system_stats()
    print(f"Total Users: {stats.total_users}")
    print(f"Active Sessions: {stats.active_sessions}")
```

## Health Monitoring

### Basic Health Check

```python
async with AuthFrameworkClient('http://localhost:8080') as client:
    # Basic health status
    health = await client.get_health()
    print(f"Status: {health.status}")
    print(f"Version: {health.version}")

    # Detailed health information
    detailed_health = await client.get_detailed_health()
    print(f"Database: {detailed_health.database}")
    print(f"Redis: {detailed_health.redis}")
    print(f"Uptime: {detailed_health.uptime}")
```

## Error Handling

### Exception Types

```python
from authframework.exceptions import (
    AuthFrameworkError,     # Base exception
    AuthenticationError,    # 401 errors
    AuthorizationError,     # 403 errors
    ValidationError,        # 400 errors
    NotFoundError,         # 404 errors
    RateLimitError,        # 429 errors
    ServerError,           # 5xx errors
    NetworkError,          # Network issues
    TimeoutError           # Request timeouts
)

async with AuthFrameworkClient('http://localhost:8080') as client:
    try:
        await client.login('invalid@email.com', 'wrong_password')
    except AuthenticationError as e:
        print(f"Login failed: {e.message}")
    except ValidationError as e:
        print(f"Invalid input: {e.message}")
        print(f"Details: {e.details}")
    except RateLimitError as e:
        print(f"Rate limited. Retry after: {e.retry_after} seconds")
    except AuthFrameworkError as e:
        print(f"API error: {e.message} (Status: {e.status_code})")
```

### Retry Logic

```python
# Client automatically retries on transient errors
client = AuthFrameworkClient(
    'http://localhost:8080',
    retries=3,  # Number of retry attempts
    timeout=30.0  # Request timeout in seconds
)
```

## Configuration

### Client Options

```python
client = AuthFrameworkClient(
    base_url='http://localhost:8080',
    timeout=30.0,           # Request timeout in seconds
    retries=3,              # Number of retry attempts
    api_key='optional-key'  # For API key authentication
)
```

### Environment Variables

```bash
# You can set default values via environment variables
export AUTHFRAMEWORK_BASE_URL=http://localhost:8080
export AUTHFRAMEWORK_TIMEOUT=30
export AUTHFRAMEWORK_RETRIES=3
export AUTHFRAMEWORK_API_KEY=your-api-key
```

```python
import os
from authframework import AuthFrameworkClient

# Use environment variables as defaults
client = AuthFrameworkClient(
    base_url=os.getenv('AUTHFRAMEWORK_BASE_URL', 'http://localhost:8080'),
    timeout=float(os.getenv('AUTHFRAMEWORK_TIMEOUT', '30.0')),
    retries=int(os.getenv('AUTHFRAMEWORK_RETRIES', '3')),
    api_key=os.getenv('AUTHFRAMEWORK_API_KEY')
)
```

## Type Safety

The SDK is fully typed with Pydantic models:

```python
from authframework.models import UserInfo, LoginResponse

async with AuthFrameworkClient('http://localhost:8080') as client:
    # Return types are properly typed
    response: LoginResponse = await client.login('user@example.com', 'password')
    profile: UserInfo = await client.get_profile()

    # Access typed fields with IDE support
    print(f"User ID: {profile.user_id}")
    print(f"Email: {profile.email}")
    print(f"Created: {profile.created_at}")
```

## Advanced Usage

### Custom HTTP Client Configuration

```python
import httpx
from authframework import AuthFrameworkClient

# Create custom HTTP client
http_client = httpx.AsyncClient(
    limits=httpx.Limits(max_connections=100),
    verify=False,  # Disable SSL verification (not recommended for production)
    proxies={'http://': 'http://proxy:8080'}
)

client = AuthFrameworkClient('http://localhost:8080')
client._client = http_client
```

### Concurrent Requests

```python
import asyncio
from authframework import AuthFrameworkClient

async def process_users():
    async with AuthFrameworkClient('http://localhost:8080') as client:
        await client.login('admin@example.com', 'password')

        # Make concurrent requests
        tasks = [
            client.get_user(f"user_{i}")
            for i in range(10)
        ]

        users = await asyncio.gather(*tasks, return_exceptions=True)

        for user in users:
            if isinstance(user, Exception):
                print(f"Error: {user}")
            else:
                print(f"User: {user.username}")
```

## Testing

### Mock Client for Testing

```python
from unittest.mock import AsyncMock
from authframework import AuthFrameworkClient

# Mock the client for testing
async def test_user_login():
    client = AuthFrameworkClient('http://localhost:8080')
    client.login = AsyncMock(return_value=MockLoginResponse())

    # Test your code that uses the client
    result = await client.login('test@example.com', 'password')
    assert result.access_token == 'mock_token'
```

## Development

### Running Tests

```bash
cd sdks/python
pytest tests/
```

### Building

```bash
cd sdks/python
python -m build
```

### Installing in Development Mode

```bash
cd sdks/python
pip install -e .[dev]
```

## API Reference

### Models

All request and response models are available in `authframework.models`:

- `LoginRequest`, `LoginResponse`
- `UserInfo`, `UserProfile`
- `MFASetupResponse`, `MFAVerifyResponse`
- `OAuthTokenResponse`
- `HealthStatus`, `DetailedHealthStatus`
- `SystemStats`

### Exceptions

All custom exceptions are available in `authframework.exceptions`:

- `AuthFrameworkError` - Base exception class
- `AuthenticationError` - Authentication failures (401)
- `AuthorizationError` - Authorization failures (403)
- `ValidationError` - Validation errors (400)
- `NotFoundError` - Resource not found (404)
- `RateLimitError` - Rate limiting (429)
- `ServerError` - Server errors (5xx)
- `NetworkError` - Network connectivity issues
- `TimeoutError` - Request timeouts

## Support

- **Documentation**: [AuthFramework Docs](https://authframework.dev/docs)
- **API Reference**: [API Documentation](https://authframework.dev/api)
- **Issues**: [GitHub Issues](https://github.com/authframework/authframework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/authframework/authframework/discussions)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
