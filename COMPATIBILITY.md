# Compatibility and Support

This document describes the supported Rust versions, feature stability tiers, storage backend
support matrix, web framework integration matrix, and the project's versioning and migration
policies.

---

## Rust Version Support

| Property                              | Value    |
| ------------------------------------- | -------- |
| Minimum Supported Rust Version (MSRV) | **1.95** |
| Rust Edition                          | 2024     |
| Recommended toolchain                 | `stable` |

The MSRV is enforced by the `rust-version` field in `Cargo.toml`. A Rust version bump is
treated as a **minor** breaking change and will be announced in the changelog with at least one
release cycle of advance notice.

Pre-release exception: the MSRV may be raised in a pre-release (`-rc`) version, with a
**Breaking** entry in that release's changelog; in a stable release it needs the announced
advance notice of one release cycle described above.

---

## Versioning Policy

AuthFramework follows [Semantic Versioning 2.0](https://semver.org/):

| Change type                                                      | Version bump                        |
| ---------------------------------------------------------------- | ----------------------------------- |
| Backwards-compatible additions, new features, new optional flags | Minor (`0.x.0`)                     |
| Bug fixes with no public API change                              | Patch (`0.0.x`)                     |
| Breaking public API change, MSRV bump, removed item              | Major or explicit pre-release label |

During the `0.x` series:

- **Release candidates** (`0.5.0-rc*`) are production-grade candidates. The public API is
  stabilising but may change between RCs.
- The first stable `0.5.0` release will freeze the public API for the `0.5.x` line.
- Breaking changes in the `0.x` series will still be announced via deprecation warnings in at
  least one prior minor release where possible.

---

## Feature Stability Tiers

### Stable (included in all `0.5.x` releases)

These capabilities are covered by the SemVer guarantee and are part of the batteries-included
default build:

| Feature / Capability                     | Default build | Feature flag                   |
| ---------------------------------------- | :-----------: | ------------------------------ |
| Core authentication (`AuthFramework`)    |       ✅       | *(always on)*                  |
| Password authentication (Argon2, bcrypt) |       ✅       | *(always on)*                  |
| JWT issuance and validation              |       ✅       | *(always on)*                  |
| Session management                       |       ✅       | *(always on)*                  |
| API key management                       |       ✅       | *(always on)*                  |
| MFA / TOTP                               |       ✅       | *(always on)*                  |
| Role-based access control (RBAC)         |       ✅       | `enhanced-rbac`                |
| Axum REST API server                     |       ✅       | `api-server` / `enhanced-rbac` |
| Axum middleware and extractors           |       ✅       | `axum-integration`             |
| PostgreSQL storage backend               |       ✅       | `postgres-storage`             |
| OpenID Connect provider                  |       ✅       | `openid-connect`               |
| OAuth 2.0 / OAuth 2.1 server             |       ✅       | *(always on)*                  |
| Audit logging                            |       ✅       | *(always on)*                  |
| Threat intelligence and geo-IP           |       ✅       | *(always on)*                  |
| Admin web UI                             |   ⬜ opt-in    | `web-gui`                      |
| Admin CLI and TUI                        |   ⬜ opt-in    | `cli` / `tui` / `admin-binary` |

### Experimental (available, API may change)

These features are functional but their public API may change in minor releases. File an issue
before building stable integrations on top of them.

| Feature / Capability                     | Feature flag                          |
| ---------------------------------------- | ------------------------------------- |
| SAML service-provider support            | `saml`                                |
| WebAuthn / Passkeys                      | `passkeys`                            |
| LDAP authentication                      | `ldap-auth`                           |
| SMS / OTP delivery (SMSKit)              | `smskit` / `smskit-web-axum`          |
| Built-in metrics and security monitoring | `enhanced-observability`              |
| Performance memory pools                 | `performance-optimization`            |
| ChaCha20-Poly1305 / Ed25519 crypto       | `enhanced-crypto`                     |
| FIPS 140-3 algorithms via AWS-LC         | `fips-compliance`                     |
| OAuth 2.0 enhanced device flow           | `enhanced-device-flow`                |
| Event sourcing                           | `event-sourcing`                      |
| Configuration hot-reload                 | `config-hot-reload`                   |
| Distributed rate limiting (Redis)        | `distributed-rate-limiting`           |
| Unicode username normalization           | `unicode-support`                     |
| Redis storage backend                    | `redis-storage`                       |
| Tiered storage (Redis + Postgres)        | `tiered-storage`                      |
| HSM / PKCS#11 integration (cryptoki)     | *(always compiled, API experimental)* |
| Kerberos authentication                  | *(always compiled, fully implemented)* |
| OpenID for Verifiable Presentations      | *(always compiled, ~85% — DID resolution + JWS verification)* |
| GNAP (Grant Negotiation & Authorization) | *(always compiled, substantially complete)* |
| UMA 2.0 (User-Managed Access)           | *(always compiled, API experimental)* |
| ACME (RFC 8555)                          | *(always compiled, client-side — account, order, challenge)* |
| SPIFFE/SVID                              | *(always compiled, ID validation + JWT-SVID + trust bundles)* |
| CAEP (Continuous Access Evaluation)      | *(always compiled, SSE transmitter/receiver + event types)* |
| OpenID4VCI (Credential Issuance)         | *(always compiled, issuer-side — offers, issuance, deferred)* |

#### Protocol Implementation Details

| Protocol          | LOC    | Tests | Completeness | Key Capabilities                                                                                                                                                                                                      |
| ----------------- | ------ | ----- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kerberos**      | ~1,780 | 25    | Full         | ASN.1 DER parser, AES-CTS-HMAC-SHA1-96 (etypes 17/18), n-fold key derivation (RFC 3961), SPNEGO/GSS-API, MIT keytab v2, AP-REQ validation with replay detection and clock skew                                        |
| **GNAP**          | ~1,800 | 38    | Substantial  | Full transaction lifecycle, JWK thumbprint (RFC 7638), ES256/RS256 client key binding with cryptographic proof, interaction hash (draft §4.2.3), continuation token rotation, token introspection/revocation/rotation |
| **ACME**          | ~550   | 19    | Substantial  | ES256 JWS signing (RFC 8555 §6.2), account registration, order lifecycle, HTTP-01/DNS-01 challenge key authorization, CSR finalization, certificate download, JWK thumbprint (RFC 7638), anti-replay nonce management |
| **SPIFFE**        | ~500   | 28    | Substantial  | SPIFFE ID parsing/validation per spec, JWT-SVID validation (expiration, audience, algorithm), X.509-SVID fingerprinting, trust bundle management, workload authorization policies with wildcard matching              |
| **CAEP**          | ~480   | 17    | Substantial  | SSE Framework stream management (create/pause/delete), 5 CAEP event types, SET claims encoding (RFC 8417), push+poll delivery, event receiver with deduplication, authorization policy callbacks                      |
| **OpenID4VCI**    | ~450   | 17    | Substantial  | Credential Issuer Metadata, credential offers with pre-authorized codes, nonce lifecycle, jwt_vc_json/ldp_vc/sd-jwt formats, immediate + deferred issuance, proof-of-possession validation                            |
| **OpenID4VP**     | ~600   | 27    | Substantial  | DID resolution (did:key Ed25519/P-256, did:web), JWS verification (EdDSA, ES256), W3C VP data model validation, presentation request generation                                                                       |
| **UMA 2.0**       | ~300   | 11    | Core         | Resource registration (§3.1), permission tickets (§3.2), RPT issuance with claims-based policy evaluation (§3.3), resource set CRUD, ticket expiration                                                                |
| **PASETO**        | ~280   | 13    | Core         | v4.local symmetric encryption/decryption, claim validation (exp, nbf, iss, aud), key generation, token builder API                                                                                                    |
| **SD-JWT**        | ~380   | 12    | Core         | Selective Disclosure JWT (IETF draft), issuer/verifier roles, SHA-256 disclosure digests, selective presentation, forged disclosure rejection, key-binding JWT parsing                                                |
| **FIDO1/U2F**     | ~270   | 12    | Core         | Registration request/response parsing (reserved byte, public key, key handle extraction), authentication with user presence and counter validation                                                                    |
| **Macaroons**     | ~250   | 10    | Core         | HMAC-SHA256 chained caveat construction, independent caveat verification via replayed chain, token attenuation                                                                                                        |
| **TACACS+**       | ~300   | 10    | Core         | RFC 8907 packet header (12-byte wire format roundtrip), AuthenStart/Reply bodies, XOR-based body obfuscation with SHA-256 pseudo-pad                                                                                  |
| **SIWE**          | ~350   | 14    | Core         | ERC-4361 message construction/parsing, domain and nonce validation, expiration checking, EIP-55 Ethereum address format verification                                                                                  |
| **IndieAuth**     | ~350   | 14    | Core         | PKCE S256 (code verifier/challenge generation and verification), authorization URL building, callback verification, profile URL validation                                                                            |
| **OAuth 1.0a**    | ~340   | 12    | Core         | RFC 5849 request signing (HMAC-SHA1, HMAC-SHA256, Plaintext), RFC 3986 percent encoding, signature base string, Authorization header generation                                                                       |
| **SAML 2.0**      | ~800   | 10    | Core         | Assertion/NameID/Subject/Conditions/AuthnStatement/AuthzDecision builder, XML generation with injection escaping, attribute statements                                                                                |
| **SCIM 2.0**      | ~400   | 8     | Core         | User/Group resource types, SCIM schema, list response, patch operations, attribute filtering                                                                                                                          |
| **CAS**           | ~300   | 8     | Core         | Service ticket validation, proxy granting, CAS 2.0/3.0 protocol support                                                                                                                                               |
| **RADIUS**        | ~350   | 10    | Core         | Packet construction/parsing, authenticator hashing, attribute TLV encoding, Access-Request/Accept/Reject/Challenge                                                                                                    |
| **WS-Trust**      | ~700   | 8     | Core         | Security Token Service (STS), RST/RSTR lifecycle, WS-Security UsernameToken, SOAP envelope construction, token issuance/validation/renewal/cancellation                                                               |
| **WS-Security**   | ~350   | 6     | Core         | UsernameToken header with PasswordText/PasswordDigest, nonce/timestamp, BinarySecurityToken, XML header generation                                                                                                    |
| **WS-Federation** | ~300   | 6     | Core         | Sign-in/sign-out URL construction, security token request/response parsing, metadata generation                                                                                                                       |
| **HOTP**          | ~200   | 6     | Core         | RFC 4226 HMAC-based OTP generation and verification, counter management, configurable digit length                                                                                                                    |

### Deprecated

| Capability                                       | Replacement                                               | Removal target |
| ------------------------------------------------ | --------------------------------------------------------- | -------------- |
| `AppConfigBuilder` (legacy)                      | `LayeredConfigBuilder`                                    | `0.6.0`        |
| `ModularAuthFramework` (legacy alias)            | `AuthFramework`                                           | `0.6.0`        |
| Direct monolithic `AuthFramework` method surface | Grouped accessors (`auth.users()`, `auth.tokens()`, etc.) | `0.7.0`        |

Deprecated items emit a `#[deprecated]` warning at compile time and will be removed in the
target release. Migration guidance is published in the [changelog](CHANGELOG.md).

---

## Storage Backend Support Matrix

| Backend               | Feature flag       | Default | Status       | Notes                                                   |
| --------------------- | ------------------ | :-----: | ------------ | ------------------------------------------------------- |
| **In-memory**         | *(none)*           |    ✅    | Stable       | Suitable for development and testing only               |
| **PostgreSQL**        | `postgres-storage` |    ✅    | Stable       | Recommended for production                              |
| **Redis**             | `redis-storage`    |    ⬜    | Stable       | For distributed session storage and caching             |
| **Tiered (Redis+PG)** | `tiered-storage`   |    ⬜    | Experimental | Hot-path Redis cache with Postgres persistence          |
| **SQLite**            | Experimental       |    \u26a0\ufe0f    | Preview      | Available via `sqlite-storage` feature for lightweight/embedded deployments |
| **SurrealDB**         | *(planned)*        |    ⬜    | Roadmap      | Planned as an optional community-maintained integration |

**MySQL / MariaDB** (`mysql-storage`) was removed in 0.6.0 -- see
`CHANGELOG.md` for the migration note.

**Choosing a storage backend for production:**

- Use `postgres-storage` (the default) for any multi-user or multi-node deployment.
- Add `redis-storage` (or `distributed-rate-limiting`) when you need distributed session
  consistency, token revocation propagation, or cross-node rate limiting.
- Use `tiered-storage` to combine Redis read performance with Postgres durability.
- The in-memory backend is available without any feature flag; it is appropriate only for local
  development and automated tests.

---

## Web Framework Integration Support Matrix

| Framework            | Feature flag                   | Default | Status | Notes                                             |
| -------------------- | ------------------------------ | :-----: | ------ | ------------------------------------------------- |
| **Axum**             | `axum-integration`             |    ✅    | Stable | Primary recommended framework                     |
| **Axum REST server** | `api-server` / `enhanced-rbac` |    ✅    | Stable | Built-in HTTP server for auth endpoints           |
| **Actix Web**        | `actix-integration`            |    ⬜    | Stable | Fully functional; not the primary documented path |
| **Warp**             | `warp-integration`             |    ⬜    | Stable | Fully functional; not the primary documented path |

All three integrations are maintained and tested on every release path. Axum is the primary
documented path; Actix Web and Warp are maintained alternatives.

---

## Platform Support

| Platform              | Tier | Notes                                                                |
| --------------------- | ---- | -------------------------------------------------------------------- |
| Linux x86-64          | 1    | Primary development and CI target                                    |
| Linux aarch64         | 1    | Tested; primary target for ARM servers                               |
| macOS (Apple Silicon) | 1    | Tested in CI                                                         |
| macOS (Intel)         | 2    | Compiled and spot-tested                                             |
| Windows x86-64        | 2    | Compiled and tested; some optional dependencies may need extra setup |
| musl libc (Linux)     | 2    | Supported for Alpine-based containers                                |
| Tier 3 (other)        | 3    | Builds attempted where dependencies allow; not actively tested       |

**Tier definitions:**

- **Tier 1**: Actively tested in CI on every PR; breakage blocks release.
- **Tier 2**: Compiled and spot-tested; breakage is treated as a high-priority bug.
- **Tier 3**: Best-effort; bugs accepted but may not be fixed immediately.

---

## Dependency Policy

- `tokio` (async runtime) and `axum` (default web layer) are pinned to the latest stable minor
  version and updated regularly.
- Cryptographic dependencies (`ring`, `rsa`, `argon2`, `jsonwebtoken`) are updated on every
  security advisory; the project monitors RustSec advisories continuously.
- The `sqlx` version is aligned with the minimum version that resolves known security advisories.
- Optional and community-maintained integrations (SMSKit, SurrealDB) may track their own
  dependency schedules.

---

## Migration Guide Summary

### `0.4.x` → `0.5.x`

- The default feature set changed: `enhanced-rbac`, `postgres-storage`, `openid-connect`, and
  `axum-integration` are now included by default. If you previously specified these explicitly,
  you can drop them.
- `AppConfigBuilder` is deprecated in favour of `LayeredConfigBuilder`.
- Grouped accessor methods (`auth.users()`, `auth.tokens()`, `auth.authorization()`, etc.) are
  now the preferred API surface; the flat `AuthFramework` methods remain available but are
  soft-deprecated.
- SAML tests require the `saml` feature flag and a working IdP; the feature is no longer
  compiled by default.

Full migration notes are in [CHANGELOG.md](CHANGELOG.md).

---

## Support Lifetime

| Track              | Supported fixes           |
| ------------------ | ------------------------- |
| Current stable     | Security fixes, bug fixes |
| Previous minor     | Security fixes only       |
| Release candidates | No patch backports        |
| Older versions     | No support                |

If you discover a security issue, please follow the process described in [SECURITY.md](SECURITY.md).
