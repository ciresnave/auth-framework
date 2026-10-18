# AuthFramework REST API

This directory documents the REST API surface mounted by `ApiServer`.

## Quick Links

- [Complete API Reference](./complete-reference.md)
- [Integration Patterns](./integration-patterns.md)
- [Performance Optimization](./performance-optimization.md)
- [Migration & Upgrade](./migration-upgrade.md)
- Server-served OpenAPI JSON: `/api/openapi.json`
- Server-served Swagger UI: `/docs`

## Runtime Layout

- Base API prefix: `/api/v1`
- Most JSON endpoints return the standard `ApiResponse<T>` envelope:

```json
{
  "success": true,
  "data": {},
  "message": "optional human-readable message"
}
```

- Failed wrapped responses use `error.code`, `error.message`, and optional `error.details`.
- Protocol-native exceptions exist for a few RFC endpoints:
  - `GET /api/v1/.well-known/openid-configuration`
  - `GET /api/v1/.well-known/jwks.json`
  - `POST /api/v1/oauth/introspect`
  - `GET /api/v1/saml/metadata` when the `saml` feature is enabled
  - `GET /api/v1/metrics`, `GET /api/v1/readiness`, and `GET /api/v1/liveness`

## Running the API Server

```bash
cargo run --bin auth-framework --features api-server,postgres-storage
```

With the example server running locally, the main entry points are:

- `http://localhost:8080/api/v1/health`
- `http://localhost:8080/api/openapi.json`
- `http://localhost:8080/docs`

## Quick Examples

### Health Check

```bash
curl http://localhost:8080/api/v1/health
```

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2026-01-20T15:30:45Z",
    "services": {
      "auth_framework": "healthy",
      "storage": "healthy",
      "token_manager": "healthy",
      "memory": "healthy"
    },
    "version": "0.6.0-rc96",
    "uptime": "0h 12m 03s"
  }
}
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "password": "SecurePassword123!",
    "remember_me": false
  }'
```

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

### Get the Authenticated User Profile

```bash
curl -H "Authorization: Bearer <access_token>" \
  http://localhost:8080/api/v1/users/profile
```

## Route Summary

### Public and authenticated auth routes

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/validate`
- `GET /auth/providers`
- `POST /api-keys`

### Email verification

- `POST /auth/verify-email/send`
- `POST /auth/verify-email`
- `POST /auth/resend-verification`

### User management

- `GET /users/me`
- `GET /users/profile`
- `PUT /users/profile`
- `POST /users/change-password`
- `GET /users/sessions`
- `DELETE /users/sessions/{session_id}`
- `GET /users/{user_id}/profile`

### MFA

- `POST /mfa/setup`
- `POST /mfa/verify`
- `POST /mfa/disable`
- `GET /mfa/status`
- `POST /mfa/regenerate-backup-codes`
- `POST /mfa/verify-backup-code`

### OAuth 2.0 / OpenID Connect

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

### Admin

- `GET /admin/users`
- `POST /admin/users`
- `PUT /admin/users/{user_id}/roles`
- `DELETE /admin/users/{user_id}`
- `PUT /admin/users/{user_id}/activate`
- `GET /admin/stats`
- `GET /admin/audit-logs`
- `GET /admin/audit-logs/stats`
- `GET /admin/config`
- `PUT /admin/config`

### Health and observability

- `GET /health`
- `GET /health/detailed`
- `GET /metrics`
- `GET /readiness`
- `GET /liveness`

### WebAuthn

- `POST /webauthn/registration/init`
- `POST /webauthn/registration/complete`
- `POST /webauthn/authentication/init`
- `POST /webauthn/authentication/complete`
- `GET /webauthn/credentials/{username}`
- `DELETE /webauthn/credentials/{username}/{credential_id}`

### SAML

The `/saml/*` routes are only mounted when the crate is built with the `saml` feature.

- `GET /saml/metadata`
- `POST /saml/sso`
- `POST /saml/acs`
- `POST /saml/slo`
- `GET /saml/slo/response`
- `POST /saml/assertion`
- `GET /saml/idps`

## Important Notes

- `GET /users/me` is an alias for the OIDC-style `/oauth/userinfo` response. It does not return the full `/users/profile` payload.
- `POST /mfa/verify` completes MFA enrollment for the authenticated user. Login-time MFA completion stays on `POST /auth/login` via the `challenge_id` and `mfa_code` fields.
- `POST /oauth/introspect` requires client authentication with HTTP Basic auth or `client_id` plus `client_secret` in the form body. Bearer-token auth is rejected.
- SAML metadata and ACS behavior depend on storage-backed configuration keys such as `saml_sp:config` and `saml_idp:{entity_id}`.
