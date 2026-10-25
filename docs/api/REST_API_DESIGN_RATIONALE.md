# AuthFramework REST API Design Rationale

> Historical design note: this document captures rationale, gaps, and proposed API evolution ideas at the time it was written. It is not a route-by-route description of the currently mounted REST router. For the current implementation, use `docs/api/README.md`, `docs/api/complete-reference.md`, and the live `/api/openapi.json` output.

## Document Purpose

This document explains the **why** behind every design decision in the AuthFramework REST API. It serves as:

1. **Architectural Decision Record (ADR)** - documenting why things are structured as they are
2. **SDK Development Guide** - helping implementers understand intent, not just mechanics
3. **API Evolution Guide** - providing context for future changes
4. **Audit Tool** - helping identify gaps, inconsistencies, or areas for improvement

## Core Design Principles

### 1. **REST + JSON First**

**Why**: Universal compatibility across all languages and platforms.

- JSON is the lingua franca of web APIs
- REST principles provide predictable, intuitive resource manipulation
- HTTP verbs map naturally to CRUD operations
- Stateless design enables horizontal scaling

**Tradeoffs Considered**:

- ❌ GraphQL: Adds complexity, harder to cache, not needed for our use case
- ❌ gRPC: Excellent for service-to-service, poor for web/browser clients
- ✅ REST + JSON: Maximum compatibility, established patterns, excellent tooling

### 2. **Standard HTTP Status Codes**

**Why**: Developers already know what they mean.

We use standard HTTP semantics:

- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `204 No Content` - Success with no response body
- `400 Bad Request` - Client error (validation, malformed request)
- `401 Unauthorized` - Authentication required or failed
- `403 Forbidden` - Authenticated but not authorized
- `404 Not Found` - Resource doesn't exist
- `409 Conflict` - Resource conflict (duplicate, constraint violation)
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

**Anti-pattern Avoided**: Never return `200 OK` with an error in the body. HTTP status codes exist for a reason.

### 3. **Consistent Response Envelope**

**Why**: Predictable parsing across all endpoints.

Every response (except raw metrics/health) uses:

```json
{
  "success": true,
  "data": { /* actual payload */ },
  "timestamp": "2025-09-30T12:00:00Z"
}
```

Or for errors:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "The provided credentials are invalid",
    "details": null
  },
  "timestamp": "2025-09-30T12:00:00Z"
}
```

**Why this structure**:

- `success` boolean: Allows explicit success checking in loosely-typed languages
- `data` object: Actual payload, consistent location
- `error` object: Structured error information
- `timestamp`: Helps with debugging, logging, audit trails

**Tradeoffs**:

- ❌ "Naked" responses: Simpler but inconsistent, harder to parse generically
- ❌ Error-specific structures: More flexible but unpredictable
- ✅ Envelope pattern: Slight verbosity for massive consistency win

### 4. **Bearer Token Authentication**

**Why**: Industry standard, stateless, secure.

```text
Authorization: Bearer <jwt-token>
```

**Why Bearer tokens**:

- RFC 6750 standard
- Stateless - no server-side session storage
- JWT carries claims (user_id, roles, permissions)
- Works across microservices without shared state
- Can be validated independently

**Alternatives Rejected**:

- ❌ API Keys in URL: Security risk (logs, browser history)
- ❌ Basic Auth: Credentials in every request, no expiry
- ❌ Custom header: Non-standard, reinventing the wheel
- ❌ Cookies only: Poor for mobile/native apps, CSRF concerns

**Note**: We also support API keys via `X-API-Key` header for service accounts where appropriate.

## API Structure & Organization

### Path Hierarchy Design

```text
/
├── health/              # Monitoring (always public, unauthenticated)
├── metrics/             # Observability (public, Prometheus format)
├── auth/                # Authentication operations
├── oauth/               # OAuth 2.0 & OIDC operations
├── users/               # User account management (authenticated)
├── mfa/                 # Multi-factor authentication (authenticated)
├── admin/               # Administrative operations (admin role required)
└── api/v1/rbac/         # RBAC operations (versioned, authenticated)
```

### Why This Hierarchy?

#### 1. **Top-level Health & Metrics**

**Path**: `/health`, `/metrics`
**Why**:

- Need to be accessible without authentication (load balancers, monitoring)
- Should never change location (stability for infrastructure)
- Universally expected at root level

**Security Note**: `/health/detailed` requires authentication to prevent information disclosure.

#### 2. **Auth at Root**

**Path**: `/auth/*`
**Why**:

- Authentication is fundamental, not a "feature"
- Login is the entry point - should be obvious
- Commonly expected location (convention)

**Endpoints**:

- `POST /auth/login` - Get tokens
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Invalidate tokens
- `GET /auth/validate` - Check token validity
- `GET /auth/providers` - List available auth providers

**Design Note**: We use `/auth/login` not `/login` to keep auth operations grouped.

#### 3. **OAuth Separate from Auth**

**Path**: `/oauth/*`
**Why**:

- OAuth is a protocol, not just "authentication"
- Distinct use case (delegated authorization)
- Different clients (third-party apps vs first-party users)
- Follows OAuth 2.0 spec conventions

**Endpoints**:

- `GET /oauth/authorize` - Authorization endpoint (OAuth 2.0 spec)
- `POST /oauth/token` - Token endpoint (OAuth 2.0 spec)
- `POST /oauth/revoke` - Token revocation (RFC 7009)
- `POST /oauth/introspect` - Token introspection (RFC 7662)
- `GET /oauth/clients/{client_id}` - Client information

**Standard Compliance**: Paths match OAuth 2.0 specification recommendations.

#### 4. **User Operations**

**Path**: `/users/*`
**Why**:

- Resource-oriented (users are resources)
- Operations on the authenticated user's own account
- Distinct from admin user management

**Endpoints**:

- `GET /users/profile` - Get own profile
- `PUT /users/profile` - Update own profile
- `POST /users/change-password` - Change own password
- `GET /users/sessions` - List own sessions
- `DELETE /users/sessions/{session_id}` - Revoke own session
- `GET /users/{user_id}/profile` - Get another user's public profile

**Design Choice**: Why not `/me`?

- `/me` is a nice shorthand but `/users/profile` is more explicit
- Consistency: all user operations under `/users`
- RESTful: `/users` represents the users collection

#### 5. **MFA Operations**

**Path**: `/mfa/*`
**Why**:

- MFA is a distinct feature, not just "auth"
- Multiple operations (setup, verify, disable, backup codes)
- Should be grouped together for discoverability

**Endpoints**:

- `POST /mfa/setup` - Initialize MFA
- `POST /mfa/verify` - Verify MFA code
- `POST /mfa/disable` - Disable MFA
- `GET /mfa/status` - Check MFA status
- `POST /mfa/regenerate-backup-codes` - New backup codes
- `POST /mfa/verify-backup-code` - Use backup code

**Design Note**: Could have been `/users/mfa/*` but MFA deserves top-level visibility.

#### 6. **Admin Operations**

**Path**: `/admin/*`
**Why**:

- Clear separation of admin vs user operations
- Easier to apply admin-only middleware
- Security: explicit admin intent
- Discoverability: all admin operations in one place

**Endpoints**:

- `GET /admin/users` - List all users
- `POST /admin/users` - Create user (admin)
- `PUT /admin/users/{user_id}/roles` - Assign roles
- `DELETE /admin/users/{user_id}` - Delete user
- `PUT /admin/users/{user_id}/activate` - Activate/deactivate
- `GET /admin/stats` - System statistics
- `GET /admin/audit-logs` - Audit log access

**Security Model**: All `/admin/*` endpoints require `admin` role or specific permissions.

#### 7. **RBAC Operations (Versioned API)**

**Path**: `/api/v1/rbac/*`
**Why versioned**:

- RBAC is complex and likely to evolve
- Version prefix allows breaking changes without disrupting old clients
- Clear contract: `/api/v1/` = versioned, stable API

**Why `/api/v1/` prefix**:

- Distinguishes versioned from unversioned endpoints
- Common pattern (GitHub, Stripe, many others)
- Future-proof: `/api/v2/` when needed

**Endpoints**:

- `POST /api/v1/rbac/roles` - Create role
- `GET /api/v1/rbac/roles` - List roles
- `GET /api/v1/rbac/roles/{role_id}` - Get role
- `PUT /api/v1/rbac/roles/{role_id}` - Update role
- `DELETE /api/v1/rbac/roles/{role_id}` - Delete role
- `POST /api/v1/rbac/users/{user_id}/roles` - Assign role
- `DELETE /api/v1/rbac/users/{user_id}/roles/{role_id}` - Revoke role
- `GET /api/v1/rbac/users/{user_id}/roles` - Get user roles
- `POST /api/v1/rbac/bulk/assign` - Bulk role assignment
- `POST /api/v1/rbac/check-permission` - Check permission
- `POST /api/v1/rbac/elevate` - Elevate privileges
- `GET /api/v1/rbac/audit` - RBAC audit log

**Design Question**: Why not `/admin/rbac/*`?

- RBAC is not admin-only - users check their own permissions
- RBAC might need different versioning than admin operations
- Separation of concerns: RBAC is authorization, admin is management

## HTTP Verb Usage

### POST vs PUT vs PATCH

**POST** - Create new resources or perform actions

- `POST /auth/login` - Action: authenticate
- `POST /api/v1/rbac/roles` - Create new role
- `POST /mfa/verify` - Action: verify code

**PUT** - Replace entire resource

- `PUT /users/profile` - Replace entire profile
- `PUT /api/v1/rbac/roles/{role_id}` - Replace role

**PATCH** - Partial update (future consideration)

- Not currently used, but reserved for partial updates
- Example: `PATCH /users/profile` could update only changed fields

**DELETE** - Remove resource

- `DELETE /users/sessions/{session_id}` - Remove session
- `DELETE /api/v1/rbac/roles/{role_id}` - Remove role

**GET** - Retrieve resource(s)

- `GET /users/profile` - Retrieve profile
- `GET /api/v1/rbac/roles` - List roles

### Why Actions Use POST

Some endpoints are actions, not resource manipulations:

- `POST /auth/login` - Not creating a "login", performing authentication
- `POST /auth/logout` - Action: invalidate token
- `POST /mfa/verify` - Action: verify code
- `POST /api/v1/rbac/check-permission` - Action: check permission

**Alternative considered**: Custom HTTP verbs (WEBDAV)

- ❌ Non-standard, poor tooling support
- ✅ POST for actions is widely accepted

## Authentication & Authorization Model

### Three-Layer Security

1. **Public Endpoints** (no authentication)
   - `/health`
   - `/metrics`
   - `/auth/login`
   - `/oauth/authorize`
   - `/oauth/token`

2. **Authenticated Endpoints** (valid token required)
   - `/users/*`
   - `/mfa/*`
   - `/api/v1/rbac/check-permission`

3. **Authorized Endpoints** (specific roles/permissions required)
   - `/admin/*` - requires `admin` role
   - `/api/v1/rbac/roles` (POST) - requires `rbac:roles:create`
   - `/admin/audit-logs` - requires `audit:read`

### Permission Checking Strategy

**Where to check**:

1. **Middleware**: Token validation (all authenticated endpoints)
2. **Endpoint**: Role/permission checking (specific endpoints)

**Why not all in middleware**:

- Different endpoints need different permissions
- Some endpoints have complex authorization (context-dependent)
- Better error messages at endpoint level

### Token Types

1. **Access Token** (short-lived, 15-60 minutes)
   - Used for API requests
   - Contains user_id, roles, permissions
   - Cannot be revoked (short lifetime mitigates risk)

2. **Refresh Token** (long-lived, days/weeks)
   - Used to obtain new access tokens
   - Can be revoked
   - Stored securely, not sent on every request

**Why two tokens**:

- Security: Minimize access token exposure
- Performance: Stateless access token validation
- Flexibility: Can revoke refresh tokens without affecting active sessions

## Request/Response Patterns

### Pagination

For list endpoints:

```text
GET /api/v1/rbac/roles?page=2&per_page=50
```

**Response includes**:

```json
{
  "success": true,
  "data": {
    "items": [...],
    "total_count": 150,
    "page": 2,
    "per_page": 50,
    "total_pages": 3
  }
}
```

**Why page-based not cursor-based**:

- Simpler for most use cases
- Allows jumping to specific pages
- Total count is useful for UI

**Future consideration**: Cursor-based pagination for very large datasets.

### Filtering & Sorting

```text
GET /admin/users?role=admin&sort=created_at&order=desc
```

**Why query parameters**:

- RESTful convention
- Easy to construct in any HTTP client
- Clear separation from resource path

### Timestamps

**Format**: ISO 8601 with timezone (RFC 3339)

```text
"2025-09-30T12:00:00Z"
```

**Why**:

- Unambiguous
- Sortable as strings
- Parseable by all date libraries

### IDs

**Format**: UUID v4 or sequential strings

```text
"123e4567-e89b-12d3-a456-426614174000"
```

**Why UUIDs**:

- Globally unique without coordination
- No enumeration attacks
- Can be generated client-side

**Tradeoff**: Larger than integers, but security and distribution benefits win.

## Error Handling

### Error Code Structure

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "The provided credentials are invalid",
    "details": {
      "field": "password",
      "reason": "incorrect"
    }
  },
  "timestamp": "2025-09-30T12:00:00Z"
}
```

### Error Code Categories

**Authentication Errors** (`AUTH_*`)

- `AUTH_REQUIRED` - Authentication required
- `INVALID_CREDENTIALS` - Bad username/password
- `INVALID_TOKEN` - Token validation failed
- `TOKEN_EXPIRED` - Token has expired
- `MFA_REQUIRED` - MFA verification needed

**Authorization Errors** (`AUTHZ_*`)

- `INSUFFICIENT_PERMISSIONS` - Missing required permission
- `ROLE_REQUIRED` - Missing required role
- `FORBIDDEN` - Operation not allowed

**Validation Errors** (`VALIDATION_*`)

- `INVALID_INPUT` - Request validation failed
- `MISSING_REQUIRED_FIELD` - Required field not provided
- `INVALID_FORMAT` - Field format incorrect

**Resource Errors** (`RESOURCE_*`)

- `NOT_FOUND` - Resource doesn't exist
- `ALREADY_EXISTS` - Duplicate resource
- `CONFLICT` - Resource state conflict

**Rate Limiting** (`RATE_*`)

- `RATE_LIMIT_EXCEEDED` - Too many requests

**System Errors** (`SYSTEM_*`)

- `INTERNAL_ERROR` - Server error
- `SERVICE_UNAVAILABLE` - Service temporarily unavailable
- `DATABASE_ERROR` - Database operation failed

**Why structured codes**:

- Machine-readable for client logic
- Categorized for easier handling
- Human-readable messages for debugging

### Details Field

Optional `details` object provides additional context:

```json
"details": {
  "field": "email",
  "reason": "invalid_format",
  "expected": "user@example.com"
}
```

**When to include details**:

- Validation errors (which field failed)
- Complex errors (multiple issues)
- Debug information (development mode)

**When to omit details**:

- Security-sensitive errors (don't leak info)
- Simple errors (message is enough)

## Rate Limiting

### Strategy

**Per-endpoint rate limits**:

- `/auth/login`: 5 requests/minute per IP
- Standard endpoints: 100 requests/minute per user
- Admin endpoints: 50 requests/minute per user

### Headers

```text
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1633024800
```

**Why per-endpoint**:

- Authentication endpoints need stricter limits (brute force)
- Read operations can be more permissive than writes
- Admin operations need moderate protection

**Why these numbers**:

- Login: 5/min prevents brute force while allowing retries
- Standard: 100/min = ~1.6/sec, enough for interactive use
- Admin: 50/min = safety margin for powerful operations

## Security Considerations

### CORS Policy

**Default**: Disabled in production
**Development**: Can be enabled via configuration

**Why disabled by default**:

- Most secure option
- Authentication APIs typically aren't accessed cross-origin
- Enables only when explicitly needed

### CSRF Protection

**Not required for Bearer token authentication**:

- Tokens in Authorization header
- Browser doesn't automatically send tokens
- Not vulnerable to CSRF

**Would be required for**:

- Cookie-based authentication
- Form submissions

### HTTPS Enforcement

**Should always be enforced in production**:

- Bearer tokens in clear text over HTTP = security disaster
- Many endpoints contain sensitive data

**Configuration**: Server should reject HTTP in production.

### Sensitive Data Handling

**Never return in responses**:

- Password hashes
- Raw secrets
- Internal system details
- Full stack traces (production)

**Audit logging**:

- All authentication attempts
- Permission checks
- Admin operations
- Sensitive data access

## API Versioning Strategy

### Current Approach

**Two-tier system**:

1. **Unversioned endpoints** - Stable, won't break
   - `/auth/*`, `/oauth/*`, `/users/*`, etc.
   - Follow semantic versioning of library
   - Breaking changes require major version bump

2. **Versioned endpoints** - Complex features
   - `/api/v1/rbac/*`
   - Can evolve independently
   - `/api/v2/rbac/*` can coexist

### Why This Hybrid Approach?

**Unversioned for stable features**:

- Authentication patterns are well-established
- OAuth 2.0 is a stable spec
- Basic user operations rarely need breaking changes

**Versioned for complex features**:

- RBAC is complex and evolving
- Permission model might need significant changes
- Allows innovation without breaking existing integrations

### Version Deprecation Policy

When introducing breaking changes:

1. Release new version (`/api/v2/*`)
2. Maintain old version for minimum 6 months
3. Add deprecation warnings to old version
4. Communicate migration path
5. Remove old version in major library version

## OpenAPI Specification

### Why OpenAPI 3.1?

**Benefits**:

- Machine-readable API definition
- Generates client SDKs automatically
- Interactive documentation (Swagger UI)
- Validation tooling
- Industry standard

**Our Usage**:

- `openapi.yaml` is source of truth
- Used to generate documentation
- Used to validate requests/responses
- Used for SDK generation

### Structure

Our OpenAPI spec includes:

- Complete endpoint definitions
- Request/response schemas
- Authentication schemes
- Error responses
- Examples

**Maintained**: Updated with every API change (enforced in PR reviews).

## Identified Gaps & Improvements Needed

### 🔴 Critical Issues

1. **RBAC Endpoints Not Registered**
   - **Problem**: RBAC endpoints exist but aren't in the router
   - **Impact**: Unusable in current state
   - **Fix Required**: Add RBAC routes to `server.rs`

2. **Missing OIDC Endpoints**
   - **Problem**: OIDC provider exists but no REST endpoints
   - **Missing**: `/.well-known/openid-configuration`, `/userinfo`, `/jwks`
   - **Impact**: OIDC clients can't discover or use OIDC features

3. **No Token Exchange Endpoint**
   - **Problem**: Token exchange exists but no REST API
   - **Missing**: `POST /oauth/token-exchange` (RFC 8693)
   - **Impact**: Can't use token exchange from REST API

### 🟡 Medium Priority

1. **Inconsistent Documentation**
   - **Problem**: OpenAPI spec mentions endpoints not in code
   - **Impact**: Confusing for users, SDK generation fails
   - **Fix**: Audit OpenAPI against actual routes

2. **No Batch Operations**
   - **Problem**: Some operations need to happen in bulk
   - **Missing**: Batch user creation, batch permission checks
   - **Impact**: Performance issues for bulk operations

3. **Limited Filtering Options**
   - **Problem**: List endpoints have basic pagination only
   - **Missing**: Filtering by multiple fields, search
   - **Impact**: Clients must filter client-side

### 🟢 Nice to Have

1. **No WebSocket Support**
   - **Opportunity**: Real-time permission updates
   - **Use case**: Live session invalidation, role changes

2. **No GraphQL Alternative**
   - **Opportunity**: Complex queries with single request
   - **Use case**: Dashboard with user + roles + permissions

## Future API Evolution

### Planned Additions (v0.5.0)

1. **WebAuthn/Passkey Endpoints**
   - `POST /auth/webauthn/register`
   - `POST /auth/webauthn/authenticate`

2. **OIDC Discovery**
   - `GET /.well-known/openid-configuration`
   - `GET /.well-known/jwks.json`

3. **Token Exchange**
   - `POST /oauth/token-exchange`

4. **Enhanced Admin APIs**
   - Batch operations
   - Advanced filtering
   - Export/import capabilities

### Under Consideration

1. **API Keys Management**
   - `POST /api-keys` - Create API key
   - `GET /api-keys` - List keys
   - `DELETE /api-keys/{key_id}` - Revoke key

2. **Session Management API**
   - `GET /sessions` - List all sessions
   - `DELETE /sessions/{session_id}` - Kill session
   - `POST /sessions/{session_id}/extend` - Extend session

## SDK Implications

### What SDKs Should Provide

Based on this API design, language SDKs should:

1. **Type-Safe Models**
   - Every request/response as a typed struct
   - Generated from OpenAPI spec

2. **Automatic Token Management**
   - Store access + refresh tokens
   - Auto-refresh when access token expires
   - Handle token errors gracefully

3. **Retry Logic**
   - Retry on 429 (rate limit)
   - Exponential backoff
   - Configurable retry strategies

4. **Error Handling**
   - Translate error codes to exceptions/results
   - Provide error code enums
   - Include details when available

5. **Pagination Helpers**
   - Iterator pattern for list endpoints
   - Automatic page fetching
   - Lazy loading

6. **Builder Patterns**
   - Fluent APIs for constructing requests
   - Sensible defaults
   - Type-safe option passing

### Rust SDK Specifics

The Rust SDK should be:

- **Zero-cost**: No runtime overhead vs manual reqwest calls
- **Type-safe**: Leverage Rust's type system fully
- **Async**: Tokio-based, `async fn` everywhere
- **Ergonomic**: Builder patterns, Result types
- **Well-documented**: Docs.rs compatible, examples

Example desired API:

```rust
let client = AuthFrameworkClient::builder()
    .base_url("https://auth.example.com")
    .build()?;

// Automatic token management
let tokens = client.login("user@example.com", "password").await?;

// Type-safe permission checking
let allowed = client
    .check_permission("read", "documents/123")
    .await?;

// Iterator for pagination
let users = client.admin().list_users()
    .page_size(50)
    .all() // Returns async iterator
    .await?;
```

## Conclusion

This API design prioritizes:

1. **Compatibility**: Works everywhere, standard patterns
2. **Security**: Defense in depth, secure by default
3. **Consistency**: Predictable structure, clear conventions
4. **Evolvability**: Versioning strategy for long-term maintenance
5. **Developer Experience**: Intuitive paths, good errors, complete docs

Every decision is deliberate, balancing:

- Simplicity vs Flexibility
- Security vs Usability  
- Standards vs Innovation
- Present needs vs Future growth

This document should be updated whenever API design decisions are made, ensuring we never lose the reasoning behind our choices.

---

**Document Status**: Living document, updated with each API change  
**Last Updated**: 2025-09-30  
**Next Review**: When adding v0.5.0 features
