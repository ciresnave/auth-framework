# Complete API Reference

This reference documents the currently mounted `ApiServer` routes and the payloads they actually accept and return.

## Conventions

### Base paths

- JSON API routes live under `/api/v1`
- OpenAPI JSON is served from `/api/openapi.json`
- Swagger UI is served from `/docs`

### Standard wrapper

Most JSON endpoints use the shared `ApiResponse<T>` envelope:

```json
{
  "success": true,
  "data": {},
  "message": "optional message"
}
```

Errors use this shape:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable message",
    "details": {}
  }
}
```

Protocol-native exceptions include:

- `GET /api/v1/.well-known/openid-configuration`
- `GET /api/v1/.well-known/jwks.json`
- `POST /api/v1/oauth/introspect`
- `GET /api/v1/metrics`
- `GET /api/v1/readiness`
- `GET /api/v1/liveness`
- `GET /api/v1/saml/metadata` when the `saml` feature is enabled

## Authentication

### POST /auth/register

Create a new user account.

Request:

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "SecurePassword123!"
}
```

Success response:

```json
{
  "success": true,
  "data": {
    "user_id": "user_123456",
    "username": "newuser",
    "email": "newuser@example.com"
  }
}
```

### POST /auth/login

Authenticate with username and password. The same endpoint also completes a pending MFA challenge when `challenge_id` and `mfa_code` are both present.

Request:

```json
{
  "username": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": false
}
```

Success response:

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user_123",
      "username": "user@example.com",
      "roles": ["user"],
      "permissions": ["profile:read", "profile:write"]
    },
    "login_risk_level": "low",
    "security_warnings": []
  }
}
```

If MFA is required, the endpoint returns an error response with challenge metadata in `error.details`:

```json
{
  "success": false,
  "error": {
    "code": "MFA_REQUIRED",
    "message": "Multi-factor authentication required",
    "details": {
      "challenge_id": "mfa_challenge_123",
      "mfa_type": "totp_or_backup_code",
      "expires_at": "2026-01-20T15:45:00Z",
      "message": "Enter your authenticator code"
    }
  }
}
```

To complete that flow, call the same endpoint again:

```json
{
  "username": "user@example.com",
  "password": "SecurePassword123!",
  "challenge_id": "mfa_challenge_123",
  "mfa_code": "123456",
  "remember_me": false
}
```

### POST /auth/refresh

Exchange a valid refresh token for a new access token.

Request:

```json
{
  "refresh_token": "eyJhbGciOi..."
}
```

Success response:

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOi...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

### POST /auth/logout

Revoke the current access token and optionally a refresh token.

Headers:

```http
Authorization: Bearer <access_token>
```

Request:

```json
{
  "refresh_token": "eyJhbGciOi..."
}
```

Success response:

```json
{
  "success": true,
  "message": "Successfully logged out"
}
```

### GET /auth/validate

Validate the current bearer token and return the resolved user identity.

Headers:

```http
Authorization: Bearer <access_token>
```

Success response:

```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "username": "user@example.com",
    "roles": ["user"],
    "permissions": ["profile:read", "profile:write"]
  }
}
```

### GET /auth/providers

Return the built-in external login providers.

### POST /api-keys

Create an API key for the authenticated user.

Success response:

```json
{
  "success": true,
  "data": {
    "api_key": "af_live_...",
    "token_type": "ApiKey"
  }
}
```

## Email Verification

### POST /auth/verify-email/send

Generate a verification token for the authenticated user's email address.

Success response:

```json
{
  "success": true,
  "data": {
    "sent": true,
    "verification_token": "url_safe_token",
    "message": "Verification token generated. Use POST /auth/verify-email to confirm."
  }
}
```

### POST /auth/verify-email

Confirm an email address using the verification token.

Request:

```json
{
  "token": "url_safe_token"
}
```

Success response:

```json
{
  "success": true,
  "data": {
    "verified": true,
    "user_id": "user_123",
    "message": "Email address verified successfully"
  }
}
```

### POST /auth/resend-verification

Generate a fresh verification token for an email address. Unknown emails deliberately return a generic success payload.

## User Management

### GET /users/me

Return the OIDC-style userinfo payload for the current bearer token. This is an alias of `/oauth/userinfo`, not the same shape as `/users/profile`.

### GET /users/profile

Return the authenticated user's full profile.

Success response:

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
    "permissions": ["profile:read", "profile:write"],
    "mfa_enabled": true,
    "email_verified": true,
    "created_at": "2026-01-20T15:30:45Z",
    "updated_at": "2026-01-20T15:45:10Z"
  }
}
```

### PUT /users/profile

Update the authenticated user's `first_name`, `last_name`, and/or `email`.

Request:

```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "email": "jane.smith@example.com"
}
```

### POST /users/change-password

Change the authenticated user's password.

Request:

```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewSecurePassword123!"
}
```

### GET /users/sessions

List the authenticated user's active sessions.

Success response:

```json
{
  "success": true,
  "data": [
    {
      "id": "session_123",
      "device": "Mozilla/5.0 (...)",
      "location": "",
      "ip_address": "203.0.113.10",
      "created_at": "2026-01-20T15:30:45Z",
      "last_active": "2026-01-20T15:45:10Z",
      "is_current": false
    }
  ]
}
```

### DELETE /users/sessions/{session_id}

Revoke a specific session owned by the authenticated user.

### GET /users/{user_id}/profile

Admin-only profile lookup for another user.

## Multi-Factor Authentication

### POST /mfa/setup

Generate a pending TOTP secret plus backup codes for the authenticated user.

Success response:

```json
{
  "success": true,
  "data": {
    "qr_code": "otpauth://totp/AuthFramework:user_123?secret=JBSWY3DPEHPK3PXP&issuer=AuthFramework&digits=6&period=30",
    "secret": "JBSWY3DPEHPK3PXP",
    "backup_codes": ["ABCD2345", "EFGH6789"]
  }
}
```

### POST /mfa/verify

Complete MFA enrollment for the authenticated user.

Request:

```json
{
  "totp_code": "123456"
}
```

### POST /mfa/disable

Disable MFA after verifying both password and TOTP code.

Request:

```json
{
  "password": "CurrentPassword123!",
  "totp_code": "123456"
}
```

### GET /mfa/status

Return whether MFA is enabled plus the number of remaining backup codes.

### POST /mfa/regenerate-backup-codes

Replace all backup codes for the authenticated user and return the new plaintext codes once.

### POST /mfa/verify-backup-code

Consume a one-time backup code.

Request:

```json
{
  "backup_code": "ABCD2345"
}
```

## Admin Endpoints

All `/admin/*` routes require a bearer token with the `admin` role.

### Users

- `GET /admin/users`
  - Query params: `page`, `limit`, `search`, `role`, `active`
  - Response data: `{ "users": [...], "pagination": {...} }`
- `POST /admin/users`
  - Request body: `username`, `password`, `email`, optional `first_name`, `last_name`, `roles`, `active`
  - Response data: `UserListItem`
- `PUT /admin/users/{user_id}/roles`
  - Request body: `{ "roles": ["admin", "user"] }`
- `DELETE /admin/users/{user_id}`
- `PUT /admin/users/{user_id}/activate`
  - Request body: `{ "active": true }`

### System and audit

- `GET /admin/stats`
- `GET /admin/audit-logs`
  - Query params: `page`, `limit`, `user_id`, `action`, `start_date`, `end_date`, `risk_level`, `outcome`, `correlation_id`, `ip_address`
- `GET /admin/audit-logs/stats`
- `GET /admin/config`
- `PUT /admin/config`
  - Partial update body. Omitted fields keep their current values.

## Health and Observability

- `GET /health` returns the lightweight wrapped health payload.
- `GET /health/detailed` returns per-service timings and system usage.
- `GET /metrics` returns Prometheus text exposition.
- `GET /readiness` returns plain text `Ready` or `Not Ready`.
- `GET /liveness` returns plain text `Alive`.

## WebAuthn

### POST /webauthn/registration/init

Request:

```json
{
  "username": "user@example.com",
  "display_name": "Jane Doe",
  "authenticator_attachment": "platform",
  "user_verification": "preferred"
}
```

Success response:

```json
{
  "success": true,
  "message": "WebAuthn registration challenge generated",
  "data": {
    "challenge": "base64url-challenge",
    "rp": {
      "id": "localhost",
      "name": "AuthFramework"
    },
    "user": {
      "id": "dXNlckBleGFtcGxlLmNvbQ",
      "name": "user@example.com",
      "display_name": "Jane Doe"
    },
    "pubkey_cred_params": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "excludeCredentials": null,
    "authenticatorSelection": {
      "authenticator_attachment": "platform",
      "require_resident_key": false,
      "user_verification": "preferred"
    },
    "attestation": "none",
    "session_id": "webauthn_550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### POST /webauthn/registration/complete

Request fields:

- `session_id`
- `credential_id`
- `credential_public_key`
- `attestation_object`
- `client_data_json`
- `authenticator_data`
- `signature`

### POST /webauthn/authentication/init

Request:

```json
{
  "username": "user@example.com",
  "user_verification": "preferred"
}
```

### POST /webauthn/authentication/complete

Success response:

```json
{
  "success": true,
  "message": "WebAuthn authentication successful",
  "data": {
    "access_token": "eyJhbGciOi...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user_id": "user@example.com",
    "authentication_method": "webauthn"
  }
}
```

### Credential management

- `GET /webauthn/credentials/{username}`
- `DELETE /webauthn/credentials/{username}/{credential_id}`

## OAuth 2.0 and OpenID Connect

The current API mounts these routes:

- `GET /oauth/authorize`
- `POST /oauth/token`
- `POST /oauth/revoke`
- `POST /oauth/introspect`
- `POST /oauth/par`
- `POST /oauth/device`
- `POST /oauth/ciba`
- `GET /oauth/userinfo`
- `GET /oauth/end_session`
- `POST /oauth/register`
- `GET /oauth/clients/{client_id}`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

Important notes:

- `/oauth/introspect` expects client authentication via HTTP Basic auth or `client_id` plus `client_secret` in the form body.
- `/oauth/register` creates a client. The current REST API does not expose `PUT /oauth/register/{client_id}`.
- `/oauth/clients/{client_id}` returns the stored `ClientInfo` object.
- `/oauth/end_session` implements RP-initiated logout using query parameters such as `id_token_hint`, `post_logout_redirect_uri`, and `state`.

## SAML

The following routes are only present when the crate is built with the `saml` feature:

- `GET /saml/metadata`
- `POST /saml/sso`
- `POST /saml/acs`
- `POST /saml/slo`
- `GET /saml/slo/response`
- `POST /saml/assertion`
- `GET /saml/idps`

Current behavior:

- `GET /saml/metadata` returns raw XML metadata generated from storage key `saml_sp:config`.
- `POST /saml/sso` returns a wrapped payload containing `redirect_url`, `saml_request`, and optional `relay_state`.
- `POST /saml/acs` expects a form body with `SAMLResponse` and optional `RelayState` and returns wrapped token data.
- `POST /saml/slo` returns a wrapped payload with `redirect_url` and `status`.
- `POST /saml/assertion` returns a wrapped XML string for IdP-style assertion generation.

## Feature-Gated Surfaces

- SAML routes require the `saml` cargo feature.
- Admin GUI documentation is outside this file and depends on the `web-gui` feature.
