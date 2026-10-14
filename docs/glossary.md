# Glossary

Terms used across these docs, defined once. Standards are named by their RFC or specification;
crate-specific terms point at the type or module.

## Protocols and tokens

| Term | Meaning |
|---|---|
| **Access token** | A credential a client presents to a resource server. Opaque or a JWT; short-lived. A bearer credential: anyone holding it can use it. |
| **Refresh token** | A longer-lived credential exchanged for new access tokens. Single use where rotation is enabled. |
| **ID token** | An OpenID Connect JWT that tells a client who authenticated and how. Not an access credential. |
| **Authorization code** | A one-time code returned to the client after user consent and exchanged at the token endpoint. |
| **PKCE** | Proof Key for Code Exchange (RFC 7636): binds the authorization code to a secret only the starting client holds. |
| **PAR** | Pushed Authorization Requests (RFC 9126): the client posts the authorization request directly to the server and receives a `request_uri`. |
| **JAR / JARM** | JWT-secured Authorization Request (RFC 9101) and JWT-secured Authorization Response Mode: the request or response parameters travel in a signed JWT. |
| **RAR** | Rich Authorization Requests (RFC 9396): structured `authorization_details` instead of coarse scopes. |
| **DPoP** | Demonstrating Proof of Possession (RFC 9449): a per-request signed proof that ties a token to a client key. |
| **mTLS client authentication** | Mutual-TLS client authentication and certificate-bound tokens (RFC 8705). |
| **Token exchange** | RFC 8693: trade one token for another with a different audience, scope or subject. |
| **Introspection / revocation** | RFC 7662 and RFC 7009: ask whether a token is active; invalidate a token. |
| **Device authorization grant** | RFC 8628: sign-in on an input-constrained device by approving on another device. |
| **JWT / JWKS** | JSON Web Token (RFC 7519) and the JSON Web Key Set a server publishes so others can verify its signatures. |
| **OIDC** | OpenID Connect: an identity layer on OAuth 2.0. |
| **SAML assertion** | A signed XML statement from an identity provider (IdP) about a user, consumed by a service provider (SP). |

## Authentication and authorization

| Term | Meaning |
|---|---|
| **MFA** | Multi-factor authentication: more than one independent proof, e.g. a password plus a TOTP code or a passkey. |
| **TOTP** | Time-based one-time password (RFC 6238). |
| **WebAuthn / passkey** | Public-key credentials bound to an origin, held by an authenticator; a passkey is a discoverable, usually synced, WebAuthn credential. |
| **RBAC** | Role-based access control: permissions are granted to roles and roles to users. |
| **ABAC** | Attribute-based access control: decisions are computed from attributes of the subject, resource and context. |
| **Step-up authentication** | Requiring a stronger or fresher authentication for a sensitive action. |

## This crate

| Term | Meaning |
|---|---|
| **`AuthFramework`** | The top-level type that wires configuration, storage and the authentication methods together. |
| **`AuthStorage`** | The storage trait every backend implements (memory, Redis, PostgreSQL, MySQL, SQLite, unified). Values only; see key names below. |
| **KV row** | A key/value record written through `AuthStorage::store_kv`, such as an API-key row. |
| **Key name** | The key a row is stored under. Encryption at rest protects values, not key names, so a credential is never used as a key name. |
| **Digest name** | The one-way name of a row: a domain-separated SHA-256 of the credential (`api_key_h:`, `access_token_h:`, `session_h:`). |
| **Legacy name** | The pre-0.6.0-rc57 key name that held the raw credential. Rows under it are read, moved to their digest name and then removed. |
| **Revoke marker** | A short-lived record a revoke leaves on release lines without create-if-absent, so an in-flight migration cannot undo the revoke. |
| **Encryption at rest** | Sealing stored values with a data key before they reach the backend; designed in [ADR-011](architecture/ADR-011-token-session-encryption-at-rest.md). |
| **Release line** | A maintained version series: `main` (0.6.x) and `release/0.5.x`, `release/0.4.x`. Fixes are backported by hand and carry their own version. |
