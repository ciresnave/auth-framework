# Complete API Reference

## Introduction

This comprehensive API reference documents all public APIs available in AuthFramework v0.4.0. Each endpoint includes detailed descriptions, request/response examples, error handling, and usage patterns to help developers integrate AuthFramework effectively.

## Base URL and Versioning

**Base URL**: `https://auth.yourdomain.com/api/v1`

**API Versioning**: AuthFramework uses semantic versioning for API compatibility:

- **Major version changes** (v1 → v2): Breaking changes
- **Minor version changes** (v1.1 → v1.2): Backward-compatible additions
- **Patch version changes** (v1.1.1 → v1.1.2): Bug fixes and security updates

## Authentication

All API endpoints (except public endpoints) require authentication via Bearer token:

```http
Authorization: Bearer <access_token>
```

### Obtaining Access Tokens

Use the `/auth/login` endpoint to obtain access tokens:

```bash
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "secure_password"
  }'
```

## Core Authentication API

### POST /auth/login

Authenticates a user with username/email and password.

**Request:**

```json
{
  "username": "user@example.com",
  "password": "secure_password",
  "remember_me": false
}
```

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "def502008a4c2b...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "user@example.com",
    "email": "user@example.com",
    "roles": ["user"],
    "permissions": ["profile:read", "profile:write"],
    "last_login": "2025-08-17T10:30:00Z",
    "mfa_enabled": true
  }
}
```

**Error Responses:**

```json
// 401 Unauthorized - Invalid credentials
{
  "error": "invalid_credentials",
  "message": "Invalid username or password",
  "code": 401
}

// 423 Locked - Account locked
{
  "error": "account_locked",
  "message": "Account locked due to multiple failed attempts",
  "code": 423,
  "retry_after": 900
}

// 403 Forbidden - MFA required
{
  "error": "mfa_required",
  "message": "Multi-factor authentication required",
  "code": 403,
  "mfa_token": "temp_mfa_token_here"
}
```

### POST /auth/refresh

Refreshes an access token using a refresh token.

**Request:**

```json
{
  "refresh_token": "def502008a4c2b..."
}
```

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "abc123007b5d3c...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

### POST /auth/logout

Logs out a user and invalidates tokens.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "all_devices": false
}
```

**Response (200 OK):**

```json
{
  "message": "Successfully logged out"
}
```

### POST /auth/verify

Verifies the validity of an access token.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "valid": true,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "user@example.com",
    "roles": ["user"],
    "permissions": ["profile:read", "profile:write"]
  },
  "expires_at": "2025-08-17T11:00:00Z"
}
```

## Multi-Factor Authentication API

### POST /auth/mfa/setup

Initiates MFA setup for the authenticated user.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "method": "totp",
  "label": "MyApp - user@example.com"
}
```

**Response (200 OK):**

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp",
  "backup_codes": [
    "12345678",
    "87654321",
    "11223344"
  ],
  "setup_token": "mfa_setup_token_here"
}
```

### POST /auth/mfa/verify-setup

Completes MFA setup by verifying the TOTP code.

**Request:**

```json
{
  "setup_token": "mfa_setup_token_here",
  "code": "123456"
}
```

**Response (200 OK):**

```json
{
  "message": "MFA setup completed successfully",
  "enabled": true
}
```

### POST /auth/mfa/verify

Verifies MFA code during login.

**Request:**

```json
{
  "mfa_token": "temp_mfa_token_here",
  "code": "123456"
}
```

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "def502008a4c2b...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "username": "user@example.com",
    "roles": ["user"]
  }
}
```

### POST /auth/mfa/disable

Disables MFA for the authenticated user.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "password": "current_password"
}
```

**Response (200 OK):**

```json
{
  "message": "MFA disabled successfully"
}
```

## User Management API

### GET /users/profile

Retrieves the authenticated user's profile.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user@example.com",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["user"],
  "permissions": ["profile:read", "profile:write"],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2025-08-17T10:30:00Z",
  "last_login": "2025-08-17T10:30:00Z",
  "email_verified": true,
  "mfa_enabled": true,
  "preferences": {
    "language": "en",
    "timezone": "UTC",
    "notifications": {
      "email": true,
      "sms": false
    }
  }
}
```

### PUT /users/profile

Updates the authenticated user's profile.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "preferences": {
    "language": "es",
    "timezone": "America/New_York",
    "notifications": {
      "email": true,
      "sms": true
    }
  }
}
```

**Response (200 OK):**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user@example.com",
  "email": "user@example.com",
  "first_name": "Jane",
  "last_name": "Smith",
  "updated_at": "2025-08-17T11:00:00Z",
  "preferences": {
    "language": "es",
    "timezone": "America/New_York",
    "notifications": {
      "email": true,
      "sms": true
    }
  }
}
```

### POST /users/change-password

Changes the authenticated user's password.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password",
  "confirm_password": "new_secure_password"
}
```

**Response (200 OK):**

```json
{
  "message": "Password changed successfully"
}
```

### POST /users/change-email

Initiates email change process for the authenticated user.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Request:**

```json
{
  "new_email": "newemail@example.com",
  "password": "current_password"
}
```

**Response (200 OK):**

```json
{
  "message": "Email change verification sent",
  "verification_required": true
}
```

## Admin User Management API

### GET /admin/users

Lists all users (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Query Parameters:**

- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50, max: 100)
- `search` (optional): Search by username/email
- `role` (optional): Filter by role
- `status` (optional): Filter by status (active, inactive, locked)

**Response (200 OK):**

```json
{
  "users": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "username": "user1@example.com",
      "email": "user1@example.com",
      "roles": ["user"],
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z",
      "last_login": "2025-08-17T10:30:00Z",
      "mfa_enabled": true
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 150,
    "pages": 3
  }
}
```

### POST /admin/users

Creates a new user (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Request:**

```json
{
  "username": "newuser@example.com",
  "email": "newuser@example.com",
  "password": "temporary_password",
  "first_name": "New",
  "last_name": "User",
  "roles": ["user"],
  "send_welcome_email": true
}
```

**Response (201 Created):**

```json
{
  "id": "456e7890-e89b-12d3-a456-426614174000",
  "username": "newuser@example.com",
  "email": "newuser@example.com",
  "first_name": "New",
  "last_name": "User",
  "roles": ["user"],
  "status": "active",
  "created_at": "2025-08-17T11:00:00Z",
  "email_verified": false,
  "mfa_enabled": false
}
```

### GET /admin/users/{user_id}

Retrieves a specific user (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user@example.com",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "roles": ["user"],
  "permissions": ["profile:read", "profile:write"],
  "status": "active",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2025-08-17T10:30:00Z",
  "last_login": "2025-08-17T10:30:00Z",
  "email_verified": true,
  "mfa_enabled": true,
  "login_attempts": 0,
  "locked_until": null
}
```

### PUT /admin/users/{user_id}

Updates a specific user (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Request:**

```json
{
  "first_name": "Updated",
  "last_name": "Name",
  "roles": ["user", "moderator"],
  "status": "active"
}
```

**Response (200 OK):**

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "user@example.com",
  "email": "user@example.com",
  "first_name": "Updated",
  "last_name": "Name",
  "roles": ["user", "moderator"],
  "status": "active",
  "updated_at": "2025-08-17T11:00:00Z"
}
```

### DELETE /admin/users/{user_id}

Deletes a specific user (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**

```json
{
  "message": "User deleted successfully",
  "deleted_at": "2025-08-17T11:00:00Z"
}
```

## Session Management API

### GET /sessions

Lists active sessions for the authenticated user.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "sessions": [
    {
      "id": "session_123",
      "device": "Chrome on Windows",
      "ip_address": "192.168.1.100",
      "location": "New York, US",
      "created_at": "2025-08-17T10:30:00Z",
      "last_activity": "2025-08-17T11:00:00Z",
      "current": true
    },
    {
      "id": "session_456",
      "device": "Safari on iPhone",
      "ip_address": "192.168.1.101",
      "location": "New York, US",
      "created_at": "2025-08-16T15:20:00Z",
      "last_activity": "2025-08-17T09:15:00Z",
      "current": false
    }
  ]
}
```

### DELETE /sessions/{session_id}

Revokes a specific session.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "message": "Session revoked successfully"
}
```

### DELETE /sessions

Revokes all sessions except the current one.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "message": "All other sessions revoked successfully",
  "revoked_count": 3
}
```

## OAuth 2.0 API

### GET /oauth/authorize

Initiates OAuth 2.0 authorization flow.

**Query Parameters:**

- `response_type`: Must be "code"
- `client_id`: OAuth client identifier
- `redirect_uri`: Callback URL
- `scope`: Requested permissions (space-separated)
- `state`: CSRF protection token

**Example:**

```
GET /oauth/authorize?response_type=code&client_id=your_client_id&redirect_uri=https://yourapp.com/callback&scope=read%20write&state=random_state_value
```

**Response (302 Redirect):**
User is redirected to login page or directly to callback with authorization code.

### POST /oauth/token

Exchanges authorization code for access token.

**Request:**

```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code_here",
  "redirect_uri": "https://yourapp.com/callback",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

**Response (200 OK):**

```json
{
  "access_token": "oauth_access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "oauth_refresh_token",
  "scope": "read write"
}
```

### POST /oauth/revoke

Revokes an OAuth access or refresh token.

**Request:**

```json
{
  "token": "token_to_revoke",
  "token_type_hint": "access_token"
}
```

**Response (200 OK):**

```json
{
  "message": "Token revoked successfully"
}
```

## Password Reset API

### POST /auth/forgot-password

Initiates password reset process.

**Request:**

```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**

```json
{
  "message": "Password reset email sent if account exists"
}
```

### POST /auth/reset-password

Completes password reset with token.

**Request:**

```json
{
  "token": "password_reset_token",
  "new_password": "new_secure_password",
  "confirm_password": "new_secure_password"
}
```

**Response (200 OK):**

```json
{
  "message": "Password reset successfully"
}
```

### POST /auth/verify-reset-token

Verifies password reset token validity.

**Request:**

```json
{
  "token": "password_reset_token"
}
```

**Response (200 OK):**

```json
{
  "valid": true,
  "expires_at": "2025-08-17T12:00:00Z"
}
```

## Email Verification API

### POST /auth/verify-email

Verifies email address with token.

**Request:**

```json
{
  "token": "email_verification_token"
}
```

**Response (200 OK):**

```json
{
  "message": "Email verified successfully"
}
```

### POST /auth/resend-verification

Resends email verification.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "message": "Verification email sent"
}
```

## Role and Permission Management API

### GET /admin/roles

Lists all roles (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**

```json
{
  "roles": [
    {
      "id": "role_admin",
      "name": "admin",
      "description": "Full system access",
      "permissions": ["*"],
      "user_count": 5,
      "created_at": "2024-01-01T00:00:00Z"
    },
    {
      "id": "role_user",
      "name": "user",
      "description": "Standard user access",
      "permissions": ["profile:read", "profile:write"],
      "user_count": 150,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /admin/roles

Creates a new role (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Request:**

```json
{
  "name": "moderator",
  "description": "Content moderation access",
  "permissions": [
    "content:read",
    "content:moderate",
    "users:read"
  ]
}
```

**Response (201 Created):**

```json
{
  "id": "role_moderator",
  "name": "moderator",
  "description": "Content moderation access",
  "permissions": [
    "content:read",
    "content:moderate",
    "users:read"
  ],
  "user_count": 0,
  "created_at": "2025-08-17T11:00:00Z"
}
```

### GET /admin/permissions

Lists all available permissions (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**

```json
{
  "permissions": [
    {
      "name": "users:read",
      "description": "Read user information",
      "category": "users"
    },
    {
      "name": "users:write",
      "description": "Create and update users",
      "category": "users"
    },
    {
      "name": "profile:read",
      "description": "Read own profile",
      "category": "profile"
    }
  ],
  "categories": ["users", "profile", "content", "system"]
}
```

## Rate Limiting and Quota API

### GET /users/quota

Retrieves current user's rate limiting status.

**Request Headers:**

```http
Authorization: Bearer <access_token>
```

**Response (200 OK):**

```json
{
  "limits": {
    "api_requests": {
      "limit": 1000,
      "used": 150,
      "remaining": 850,
      "reset_at": "2025-08-17T12:00:00Z"
    },
    "login_attempts": {
      "limit": 10,
      "used": 2,
      "remaining": 8,
      "reset_at": "2025-08-17T11:15:00Z"
    }
  }
}
```

## System Information API

### GET /system/health

System health check endpoint.

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "0.4.0",
  "uptime": 86400,
  "services": {
    "database": "healthy",
    "cache": "healthy",
    "external_auth": "healthy"
  },
  "timestamp": "2025-08-17T11:00:00Z"
}
```

### GET /system/info

System information (public endpoint).

**Response (200 OK):**

```json
{
  "name": "AuthFramework",
  "version": "0.4.0",
  "api_version": "v1",
  "features": [
    "multi_factor_auth",
    "oauth2",
    "role_based_access",
    "session_management"
  ],
  "supported_auth_methods": [
    "password",
    "oauth2",
    "saml"
  ]
}
```

## Webhooks API

### GET /admin/webhooks

Lists configured webhooks (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Response (200 OK):**

```json
{
  "webhooks": [
    {
      "id": "webhook_123",
      "url": "https://yourapp.com/auth-webhook",
      "events": ["user.created", "user.login"],
      "active": true,
      "secret": "webhook_secret_hash",
      "created_at": "2025-01-01T00:00:00Z",
      "last_delivery": "2025-08-17T10:30:00Z"
    }
  ]
}
```

### POST /admin/webhooks

Creates a new webhook (admin only).

**Request Headers:**

```http
Authorization: Bearer <admin_access_token>
```

**Request:**

```json
{
  "url": "https://yourapp.com/new-webhook",
  "events": ["user.created", "user.updated", "user.deleted"],
  "secret": "your_webhook_secret",
  "active": true
}
```

**Response (201 Created):**

```json
{
  "id": "webhook_456",
  "url": "https://yourapp.com/new-webhook",
  "events": ["user.created", "user.updated", "user.deleted"],
  "active": true,
  "secret": "hashed_secret",
  "created_at": "2025-08-17T11:00:00Z"
}
```

## Error Handling

### Standard Error Response Format

All API errors follow a consistent format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "code": 400,
  "details": {
    "field": "Additional error details if applicable"
  },
  "request_id": "req_123456789"
}
```

### Common Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `invalid_request` | Malformed request or missing required fields |
| 401 | `unauthorized` | Authentication required or invalid token |
| 403 | `forbidden` | Insufficient permissions for the requested action |
| 404 | `not_found` | Requested resource does not exist |
| 409 | `conflict` | Resource conflict (e.g., duplicate email) |
| 422 | `validation_error` | Request validation failed |
| 429 | `rate_limited` | Rate limit exceeded |
| 500 | `internal_error` | Server error |
| 503 | `service_unavailable` | Service temporarily unavailable |

### Rate Limiting Headers

When rate limits are applied, responses include these headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1692270000
Retry-After: 60
```

## Request/Response Examples

### User Registration Flow

```bash
# 1. Register new user
curl -X POST https://auth.yourdomain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser@example.com",
    "email": "newuser@example.com",
    "password": "SecurePassword123!",
    "first_name": "New",
    "last_name": "User"
  }'

# 2. Verify email (user clicks link in email)
curl -X POST https://auth.yourdomain.com/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "email_verification_token_from_email"
  }'

# 3. Login
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser@example.com",
    "password": "SecurePassword123!"
  }'
```

### OAuth 2.0 Flow

```bash
# 1. Redirect user to authorization endpoint
# User visits: https://auth.yourdomain.com/api/v1/oauth/authorize?response_type=code&client_id=your_client&redirect_uri=https://yourapp.com/callback&state=random_state

# 2. Exchange authorization code for token
curl -X POST https://auth.yourdomain.com/api/v1/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "received_auth_code",
    "redirect_uri": "https://yourapp.com/callback",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret"
  }'

# 3. Use access token for API calls
curl -X GET https://auth.yourdomain.com/api/v1/users/profile \
  -H "Authorization: Bearer oauth_access_token"
```

### MFA Setup Flow

```bash
# 1. Setup MFA
curl -X POST https://auth.yourdomain.com/api/v1/auth/mfa/setup \
  -H "Authorization: Bearer access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp",
    "label": "MyApp - user@example.com"
  }'

# 2. User scans QR code and enters verification code
curl -X POST https://auth.yourdomain.com/api/v1/auth/mfa/verify-setup \
  -H "Content-Type: application/json" \
  -d '{
    "setup_token": "mfa_setup_token",
    "code": "123456"
  }'

# 3. Future logins require MFA
curl -X POST https://auth.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "password"
  }'
# Returns mfa_required error with mfa_token

curl -X POST https://auth.yourdomain.com/api/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_token": "temp_mfa_token",
    "code": "654321"
  }'
```

## SDK and Integration Examples

### JavaScript/Node.js Example

```javascript
const AuthFramework = require('@authframework/client');

const auth = new AuthFramework({
  baseUrl: 'https://auth.yourdomain.com/api/v1',
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret'
});

// Login
try {
  const result = await auth.login('user@example.com', 'password');
  console.log('Login successful:', result.user);

  // Store tokens
  localStorage.setItem('access_token', result.access_token);
  localStorage.setItem('refresh_token', result.refresh_token);
} catch (error) {
  console.error('Login failed:', error.message);
}

// Make authenticated request
try {
  const profile = await auth.getProfile();
  console.log('User profile:', profile);
} catch (error) {
  if (error.code === 401) {
    // Token expired, try refresh
    await auth.refreshToken();
    const profile = await auth.getProfile();
  }
}
```

### Python Example

```python
import requests
from authframework import AuthClient

# Initialize client
auth = AuthClient(
    base_url='https://auth.yourdomain.com/api/v1',
    client_id='your_client_id',
    client_secret='your_client_secret'
)

# Login
try:
    result = auth.login('user@example.com', 'password')
    print(f"Login successful: {result['user']}")

    # Store tokens
    access_token = result['access_token']
    refresh_token = result['refresh_token']

except AuthError as e:
    print(f"Login failed: {e.message}")

# Make authenticated request
try:
    profile = auth.get_profile()
    print(f"User profile: {profile}")
except AuthError as e:
    if e.code == 401:
        # Refresh token and retry
        auth.refresh_token()
        profile = auth.get_profile()
```

### cURL Examples Collection

```bash
# Complete authentication flow
#!/bin/bash

BASE_URL="https://auth.yourdomain.com/api/v1"
EMAIL="user@example.com"
PASSWORD="secure_password"

# Login
echo "=== Login ==="
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

echo $LOGIN_RESPONSE | jq .

# Extract tokens
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.refresh_token')

# Get profile
echo -e "\n=== Get Profile ==="
curl -s -X GET "$BASE_URL/users/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# Refresh token
echo -e "\n=== Refresh Token ==="
curl -s -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}" | jq .

# Logout
echo -e "\n=== Logout ==="
curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"all_devices\":false}" | jq .
```

## Best Practices

### Security Best Practices

1. **Always use HTTPS** in production
2. **Store tokens securely** (never in localStorage for sensitive apps)
3. **Implement token refresh** before expiration
4. **Validate SSL certificates** in API clients
5. **Use rate limiting** on client side
6. **Implement proper error handling** for security scenarios

### Performance Best Practices

1. **Cache user profile data** to reduce API calls
2. **Use connection pooling** for high-traffic applications
3. **Implement exponential backoff** for retries
4. **Monitor API response times** and adjust timeouts
5. **Use appropriate page sizes** for list endpoints

### Integration Best Practices

1. **Handle all error scenarios** gracefully
2. **Implement proper logging** for debugging
3. **Use webhooks** for real-time updates
4. **Test with rate limiting** enabled
5. **Validate all user inputs** before API calls

## Support and Resources

- **API Documentation**: [api.authframework.dev](https://api.authframework.dev)
- **SDK Downloads**: [github.com/authframework/sdks](https://github.com/authframework/sdks)
- **Postman Collection**: [Download collection](https://api.authframework.dev/postman)
- **OpenAPI Spec**: [Download specification](https://api.authframework.dev/openapi.json)
- **API Support**: [api-support@authframework.dev](mailto:api-support@authframework.dev)

---

*AuthFramework v0.4.0 - THE premier authentication and authorization solution*
