# AuthFramework REST API Documentation

This directory contains comprehensive documentation for the AuthFramework REST API.

## Quick Links

- 🔗 **[OpenAPI Specification](./openapi.yaml)** - Complete API specification in OpenAPI 3.1 format
- 📚 **[Complete API Reference](./complete-reference.md)** - Detailed endpoint documentation
- 🔌 **[Integration Patterns](./integration-patterns.md)** - Common integration scenarios
- 🚀 **[Performance Optimization](./performance-optimization.md)** - Performance tuning guide
- 📈 **[Migration & Upgrade](./migration-upgrade.md)** - Version migration guide

## Getting Started

### 1. Running the API Server

Enable the API server feature and run the example:

```bash
# Run the example API server
cargo run --example complete_rest_api_server --features api-server

# Or run with custom configuration
RUST_LOG=info AUTH_API_HOST=0.0.0.0 AUTH_API_PORT=3000 \
    cargo run --example complete_rest_api_server --features api-server
```

### 2. Basic Usage Examples

#### Health Check

```bash
curl http://localhost:8080/health
```

#### User Authentication

```bash
# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password"}'

# Response:
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "username": "user@example.com",
      "email": "user@example.com",
      "roles": ["user"],
      "mfa_enabled": false
    }
  },
  "timestamp": "2024-01-20T15:30:45Z"
}
```

#### Authenticated Requests

```bash
# Get user profile
curl -H "Authorization: Bearer <your-access-token>" \
  http://localhost:8080/users/profile

# Update profile
curl -X PATCH http://localhost:8080/users/profile \
  -H "Authorization: Bearer <your-access-token>" \
  -H "Content-Type: application/json" \
  -d '{"first_name":"John","last_name":"Doe"}'
```

## API Overview

### Authentication & Authorization

The AuthFramework REST API provides comprehensive authentication and authorization features:

- **JWT-based Authentication**: Secure token-based authentication with access and refresh tokens
- **Role-based Access Control**: Fine-grained permissions based on user roles
- **Multi-factor Authentication**: TOTP-based MFA with backup codes
- **OAuth 2.0 Server**: Full OAuth 2.0 authorization server implementation
- **Session Management**: Secure session handling with token invalidation

### Core Features

#### 🔐 Authentication Endpoints

- `POST /auth/login` - User authentication
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - Session termination
- `POST /auth/validate` - Token validation

#### 👤 User Management

- `GET /users/profile` - Get user profile
- `PATCH /users/profile` - Update profile
- `POST /users/password` - Change password

#### 🔒 Multi-Factor Authentication

- `POST /mfa/setup` - Initialize MFA
- `POST /mfa/verify` - Verify MFA codes
- `POST /mfa/disable` - Disable MFA

#### 🌐 OAuth 2.0 Server

- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/revoke` - Token revocation
- `POST /oauth/introspect` - Token introspection

#### 👨‍💼 Administrative

- `GET /admin/users` - List users (paginated)
- `POST /admin/users` - Create user
- `GET /admin/users/{id}` - Get user details
- `DELETE /admin/users/{id}` - Delete user
- `GET /admin/stats` - System statistics

#### 📊 Health & Monitoring

- `GET /health` - Basic health check
- `GET /health/detailed` - Detailed health status
- `GET /metrics` - Prometheus metrics

### Response Format

All API endpoints return standardized JSON responses:

```json
{
  "success": true,
  "data": {
    // Response payload varies by endpoint
  },
  "timestamp": "2024-01-20T15:30:45Z"
}
```

Error responses follow the same format:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      // Optional additional error context
    }
  },
  "timestamp": "2024-01-20T15:30:45Z"
}
```

### Security Features

#### Rate Limiting

- **Authentication endpoints**: 5 requests/minute per IP
- **Standard endpoints**: 100 requests/minute per user
- **Admin endpoints**: 50 requests/minute per admin

#### CORS Support

Configurable Cross-Origin Resource Sharing support for web applications.

#### Security Headers

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (HTTPS only)

#### Request Validation

- JSON schema validation for request bodies
- Parameter type validation
- Authorization header validation

## Client SDKs

### JavaScript/TypeScript SDK

```typescript
import { AuthFrameworkClient } from '@authframework/js-sdk';

const client = new AuthFrameworkClient({
  baseUrl: 'http://localhost:8080',
  apiKey: 'your-api-key' // Optional for public endpoints
});

// Login
const { data } = await client.auth.login({
  username: 'user@example.com',
  password: 'password'
});

// Use access token for subsequent requests
client.setAccessToken(data.access_token);

// Get user profile
const profile = await client.users.getProfile();
```

### Python SDK

```python
from authframework import AuthFrameworkClient

client = AuthFrameworkClient(
    base_url='http://localhost:8080',
    api_key='your-api-key'  # Optional for public endpoints
)

# Login
response = client.auth.login(
    username='user@example.com',
    password='password'
)

# Use access token for subsequent requests
client.set_access_token(response.data.access_token)

# Get user profile
profile = client.users.get_profile()
```

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_CREDENTIALS` | Username or password is incorrect |
| `TOKEN_EXPIRED` | Access token has expired |
| `TOKEN_INVALID` | Access token is malformed or invalid |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions |
| `RATE_LIMIT_EXCEEDED` | Too many requests in time window |
| `MFA_REQUIRED` | Multi-factor authentication required |
| `MFA_INVALID_CODE` | Invalid MFA verification code |
| `USER_NOT_FOUND` | Requested user does not exist |
| `EMAIL_ALREADY_EXISTS` | Email address already registered |
| `VALIDATION_ERROR` | Request validation failed |
| `INTERNAL_ERROR` | Internal server error |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_API_HOST` | API server host | `127.0.0.1` |
| `AUTH_API_PORT` | API server port | `8080` |
| `AUTH_API_CORS_ENABLED` | Enable CORS | `true` |
| `AUTH_API_MAX_BODY_SIZE` | Max request body size | `1048576` (1MB) |
| `AUTH_JWT_SECRET` | JWT signing secret | *(required)* |
| `AUTH_TOKEN_EXPIRY` | Access token lifetime | `3600` (1 hour) |
| `AUTH_REFRESH_TOKEN_EXPIRY` | Refresh token lifetime | `604800` (7 days) |

### Programmatic Configuration

```rust
use auth_framework::api::{ApiServer, ApiServerConfig};

let config = ApiServerConfig {
    host: "0.0.0.0".to_string(),
    port: 3000,
    enable_cors: true,
    max_body_size: 2 * 1024 * 1024, // 2MB
    enable_tracing: true,
};

let server = ApiServer::with_config(auth_framework, config);
```

## Production Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --features api-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/complete_rest_api_server /usr/local/bin/
EXPOSE 8080
CMD ["complete_rest_api_server"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authframework-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authframework-api
  template:
    metadata:
      labels:
        app: authframework-api
    spec:
      containers:
      - name: api
        image: authframework/api:latest
        ports:
        - containerPort: 8080
        env:
        - name: AUTH_API_HOST
          value: "0.0.0.0"
        - name: AUTH_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: authframework-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/detailed
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Monitoring & Observability

### Prometheus Metrics

The `/metrics` endpoint exposes Prometheus-compatible metrics:

- `authframework_requests_total` - Total API requests
- `authframework_request_duration_seconds` - Request duration histogram
- `authframework_active_sessions` - Number of active user sessions
- `authframework_failed_logins_total` - Failed login attempts
- `authframework_mfa_verifications_total` - MFA verification attempts

### Health Checks

- **Basic**: `GET /health` - Returns service status
- **Detailed**: `GET /health/detailed` - Includes dependency health
- **Kubernetes**: Configured for liveness and readiness probes

### Logging

Structured logging with configurable levels:

```bash
# Enable debug logging
RUST_LOG=debug cargo run --example complete_rest_api_server --features api-server

# JSON formatted logs
RUST_LOG=info RUST_LOG_FORMAT=json cargo run --example complete_rest_api_server --features api-server
```

## Testing

### Unit Tests

```bash
# Run API tests
cargo test --features api-server api::

# Run with coverage
cargo tarpaulin --features api-server
```

### Integration Tests

```bash
# Start test server
cargo run --example complete_rest_api_server --features api-server &

# Run integration tests
cargo test --test api_integration --features api-server
```

### Load Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/health

# Using wrk
wrk -t12 -c400 -d30s http://localhost:8080/health
```

## Support & Contributing

- 📝 **Documentation**: [Full API Reference](./complete-reference.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/cires/AuthFramework/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/cires/AuthFramework/discussions)
- 🤝 **Contributing**: [Contributing Guide](../../CONTRIBUTING.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## API Endpoints

### Authentication Endpoints

#### POST /auth/login

Authenticate user with credentials.

**Request:**

```json
{
  "username": "user@example.com",
  "password": "secure_password",
  "mfa_code": "123456",
  "remember_me": false
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user_123",
      "username": "user@example.com",
      "roles": ["user"],
      "permissions": ["read:profile", "write:profile"]
    }
  }
}
```

#### POST /auth/refresh

Refresh access token using refresh token.

**Request:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

#### POST /auth/logout

Invalidate current session and tokens.

**Request:**

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**

```json
{
  "success": true,
  "message": "Successfully logged out"
}
```

### User Management

#### GET /users/profile

Get current user profile.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "username": "user@example.com",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["user"],
    "permissions": ["read:profile", "write:profile"],
    "mfa_enabled": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

#### PUT /users/profile

Update user profile.

**Request:**

```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john.doe@example.com"
}
```

#### POST /users/change-password

Change user password.

**Request:**

```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

### Multi-Factor Authentication

#### POST /mfa/setup

Set up TOTP multi-factor authentication.

**Response:**

```json
{
  "success": true,
  "data": {
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "secret": "JBSWY3DPEHPK3PXP",
    "backup_codes": [
      "12345678",
      "87654321",
      "11223344"
    ]
  }
}
```

#### POST /mfa/verify

Verify TOTP code to enable MFA.

**Request:**

```json
{
  "totp_code": "123456"
}
```

#### POST /mfa/disable

Disable multi-factor authentication.

**Request:**

```json
{
  "password": "user_password",
  "totp_code": "123456"
}
```

### OAuth 2.0 Endpoints

#### GET /oauth/authorize

OAuth 2.0 authorization endpoint.

**Query Parameters:**

- `response_type`: "code" for authorization code flow
- `client_id`: OAuth client identifier
- `redirect_uri`: Callback URL
- `scope`: Requested permissions
- `state`: CSRF protection parameter

#### POST /oauth/token

OAuth 2.0 token endpoint.

**Request:**

```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_from_authorize",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "redirect_uri": "https://yourapp.com/callback"
}
```

### Administrative Endpoints

#### GET /admin/users

List all users (admin only).

**Query Parameters:**

- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20)
- `search`: Search term
- `role`: Filter by role

**Response:**

```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_123",
        "username": "user@example.com",
        "roles": ["user"],
        "created_at": "2024-01-01T00:00:00Z",
        "last_login": "2024-01-02T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 150,
      "pages": 8
    }
  }
}
```

#### POST /admin/users

Create new user (admin only).

**Request:**

```json
{
  "username": "newuser@example.com",
  "password": "secure_password",
  "email": "newuser@example.com",
  "first_name": "New",
  "last_name": "User",
  "roles": ["user"]
}
```

#### PUT /admin/users/{user_id}/roles

Update user roles (admin only).

**Request:**

```json
{
  "roles": ["user", "moderator"]
}
```

### Health and Monitoring

#### GET /health

Health check endpoint.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "storage": "healthy"
  }
}
```

#### GET /metrics

Prometheus metrics endpoint.

**Response:** Prometheus format metrics

## Error Responses

All error responses follow this format:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid username or password",
    "details": {
      "field": "password",
      "reason": "incorrect"
    }
  },
  "request_id": "req_123456789"
}
```

### Common Error Codes

- `INVALID_CREDENTIALS`: Authentication failed
- `UNAUTHORIZED`: Missing or invalid token
- `FORBIDDEN`: Insufficient permissions
- `NOT_FOUND`: Resource not found
- `VALIDATION_ERROR`: Request validation failed
- `RATE_LIMITED`: Too many requests
- `SERVER_ERROR`: Internal server error

## Rate Limiting

API endpoints are rate limited:

- Authentication: 10 requests per minute
- General API: 100 requests per minute
- Admin endpoints: 50 requests per minute

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## SDKs and Libraries

### JavaScript/Node.js

```javascript
import { AuthFrameworkClient } from '@auth-framework/client';

const client = new AuthFrameworkClient({
  baseUrl: 'https://api.yourdomain.com',
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret'
});

// Login
const tokens = await client.auth.login({
  username: 'user@example.com',
  password: 'password'
});

// Get profile
const profile = await client.users.getProfile(tokens.access_token);
```

### Python

```python
from auth_framework import AuthFrameworkClient

client = AuthFrameworkClient(
    base_url='https://api.yourdomain.com',
    client_id='your_client_id',
    client_secret='your_client_secret'
)

# Login
tokens = client.auth.login(
    username='user@example.com',
    password='password'
)

# Get profile
profile = client.users.get_profile(tokens['access_token'])
```

### Rust

```rust
use auth_framework_client::AuthFrameworkClient;

let client = AuthFrameworkClient::new(
    "https://api.yourdomain.com",
    "your_client_id",
    "your_client_secret"
);

// Login
let tokens = client.auth().login(
    "user@example.com",
    "password",
    None
).await?;

// Get profile
let profile = client.users().get_profile(&tokens.access_token).await?;
```

## Integration Examples

### Single Sign-On (SSO)

```html
<!-- Authorization request -->
<a href="https://api.yourdomain.com/oauth/authorize?response_type=code&client_id=your_client_id&redirect_uri=https://yourapp.com/callback&scope=openid%20profile&state=csrf_token">
  Login with AuthFramework
</a>
```

### API Authentication

```bash
# Get token
curl -X POST https://api.yourdomain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password"}'

# Use token
curl -X GET https://api.yourdomain.com/users/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Webhooks

AuthFramework can send webhooks for various events:

### User Events

- `user.created`: New user registered
- `user.updated`: User profile updated
- `user.deleted`: User account deleted
- `user.login`: User logged in
- `user.logout`: User logged out

### Security Events

- `security.suspicious_login`: Suspicious login attempt
- `security.password_changed`: Password changed
- `security.mfa_enabled`: MFA enabled
- `security.mfa_disabled`: MFA disabled

### Webhook Payload

```json
{
  "event": "user.login",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "user_id": "user_123",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "location": "New York, NY"
  },
  "signature": "sha256=..."
}
```

## Testing

### Postman Collection

Import the provided Postman collection for testing:

- [AuthFramework API Collection](./postman/AuthFramework.postman_collection.json)

### OpenAPI Specification

Full OpenAPI 3.0 specification available:

- [OpenAPI Spec](./openapi/authframework-api.yaml)

## Support

- **Documentation**: <https://docs.authframework.com>
- **GitHub**: <https://github.com/auth-framework/auth-framework>
- **Discord**: <https://discord.gg/authframework>
- **Email**: <support@authframework.com>
