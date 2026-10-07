# Supported Protocols and Standards

AuthFramework implements 35+ authentication and authorization protocols.
Most are compiled unconditionally; a few require opt-in feature flags for
platform-specific dependencies.

## Production-Grade Protocols

| Protocol                            | Standard                                  | Module                             | Feature Flag           |
| ----------------------------------- | ----------------------------------------- | ---------------------------------- | ---------------------- |
| OAuth 2.0 / 2.1                     | RFC 6749, RFC 9068                        | core                               | — (always)             |
| PKCE                                | RFC 7636                                  | core                               | —                      |
| DPoP                                | RFC 9449                                  | core                               | —                      |
| Pushed Authorization Requests (PAR) | RFC 9126                                  | core                               | —                      |
| Rich Authorization Requests (RAR)   | RFC 9396                                  | core                               | —                      |
| Token Exchange                      | RFC 8693                                  | core                               | —                      |
| Token Introspection                 | RFC 7662                                  | core                               | —                      |
| Device Authorization Flow           | RFC 8628                                  | `src/methods/enhanced_device/`     | `enhanced-device-flow` |
| OpenID Connect 1.0                  | OpenID Core, RFC 8414                     | `src/server/oidc/`                 | —                      |
| JSON Web Tokens (JWT)               | RFC 7519                                  | `src/security/`                    | —                      |
| PASETO v4                           | PASETO Spec                               | `src/protocols/paseto.rs`          | —                      |
| SD-JWT                              | IETF Draft                                | `src/protocols/sd_jwt.rs`          | —                      |
| WebAuthn / FIDO2                    | W3C WebAuthn L2, FIDO2                    | `src/api/webauthn.rs`              | —                      |
| TOTP                                | RFC 6238                                  | `src/api/mfa.rs`                   | —                      |
| HOTP                                | RFC 4226                                  | `src/protocols/hotp.rs`            | `otp-auth`             |
| SAML 2.0 Assertions                 | OASIS SAML 2.0 Core                       | `src/protocols/saml_assertions.rs` | `saml`                 |
| LDAP / Active Directory             | RFC 4511                                  | `src/protocols/`                   | `ldap-auth`            |
| Kerberos 5 / SPNEGO                 | RFC 4120, RFC 4178                        | `src/protocols/kerberos.rs`        | —                      |
| RADIUS                              | RFC 2865, RFC 2866                        | `src/protocols/radius.rs`          | —                      |
| SCIM 2.0                            | RFC 7643, RFC 7644                        | `src/protocols/scim.rs`            | —                      |
| OAuth 1.0a                          | RFC 5849                                  | `src/protocols/oauth1.rs`          | —                      |
| CAS                                 | Apereo CAS Protocol                       | `src/protocols/cas.rs`             | —                      |
| WS-Federation                       | WS-Federation 1.2                         | `src/protocols/ws_federation.rs`   | —                      |
| WS-Security                         | OASIS WS-Security                         | `src/protocols/ws_security.rs`     | —                      |
| WS-Trust                            | OASIS WS-Trust 1.4                        | `src/protocols/ws_trust.rs`        | —                      |
| GNAP                                | IETF Draft                                | `src/protocols/gnap.rs`            | —                      |
| UMA 2.0                             | Kantara UMA 2.0                           | `src/protocols/uma.rs`             | —                      |
| FAPI                                | OpenID FAPI 2.0                           | core                               | —                      |
| SIWE (Sign-In with Ethereum)        | ERC-4361                                  | `src/protocols/siwe.rs`            | —                      |
| API Key Authentication              | —                                         | core                               | —                      |
| OpenID4VP                           | OpenID for Verifiable Presentations       | `src/protocols/openid4vp.rs`       | —                      |
| OpenID4VCI                          | OpenID for Verifiable Credential Issuance | `src/protocols/openid4vci.rs`      | —                      |
| FIDO U2F (FIDO1)                    | FIDO Alliance                             | `src/protocols/fido1.rs`           | `passkeys`             |
| Macaroons                           | Google Research                           | `src/protocols/macaroons.rs`       | —                      |
| CAEP                                | OpenID Continuous Access Evaluation       | `src/protocols/caep.rs`            | —                      |
| SPIFFE / SVID                       | CNCF SPIFFE 1.2                           | `src/protocols/spiffe.rs`          | —                      |
| TACACS+                             | RFC 8907                                  | `src/protocols/tacacs.rs`          | —                      |
| IndieAuth                           | IndieWeb                                  | `src/protocols/indieauth.rs`       | —                      |
| ACME                                | RFC 8555                                  | `src/protocols/acme.rs`            | —                      |
| mTLS / X.509 Client Certs           | RFC 5280, RFC 8705                        | `src/methods/client_cert/`         | —                      |
| OPA / Rego                          | Open Policy Agent                         | `src/protocols/opa.rs`             | —                      |
| Google Zanzibar ReBAC               | Zanzibar (Google)                         | `src/protocols/zanzibar.rs`        | —                      |
| OIDC CIBA                           | OpenID CIBA Core                          | `src/protocols/ciba.rs`            | —                      |

## Protocol Details

### OpenID for Verifiable Presentations (OpenID4VP)

Full implementation of the OpenID4VP specification including authorization
request/response handling, DIF Presentation Exchange v2 types
(`PresentationDefinition`, `InputDescriptor`, `PresentationSubmission`),
and submission validation.

### OpenID for Verifiable Credential Issuance (OpenID4VCI)

Complete credential issuance flow: issuer metadata, credential offers,
token-based issuance, JWT proof validation with c_nonce, and batch
credential issuance endpoint.

### FIDO U2F (FIDO1)

Full FIDO U2F protocol with real ECDSA P-256 signature verification using
`ring`. Supports registration and authentication ceremonies per the FIDO
Alliance specifications.

### Macaroons

Bearer credential tokens with first-party caveats, third-party caveats
(with encrypted caveat keys), and discharge macaroon verification.
Supports delegation and attenuation chains.

### CAEP (Continuous Access Evaluation Protocol)

SSE (Security Signals Events) transmitter with support for all five CAEP
event types: session revoked, token claims change, credential change,
assurance level change, and compliance status change. Multi-stream
dispatch with configurable stream endpoints.

### SPIFFE / SVID

Comprehensive SPIFFE identity framework: SPIFFE ID parsing and validation,
JWT-SVID verification, X.509-SVID extraction, trust bundle management,
Workload API client (SVID lifecycle, rotation detection, expiry cleanup),
SPIRE-style workload attestation (registration entries, selector matching),
and federated trust bundle management (cross-domain trust exchange).

### TACACS+

Full Terminal Access Controller Access-Control System Plus per RFC 8907:
header serialization/parsing with body encryption/decryption,
authentication start/reply/continue, authorization request/reply, and
accounting request/reply message types.

### IndieAuth

Complete IndieAuth implementation: client-side discovery and identity
verification, and server-side authorization code issuance with PKCE
(S256), code exchange, access token management, introspection, revocation,
metadata endpoint, and expired code/token cleanup.

### ACME (RFC 8555)

Full ACME client: directory discovery, account registration, order
creation, HTTP-01/DNS-01 challenge computation, JWS signing (ES256),
certificate finalization and download, certificate revocation, and
certificate lifecycle tracking (renewal scheduling, expiry monitoring).

### mTLS / X.509 Client Certificates

Application-layer client certificate authentication with DER parsing
(x509-parser), subject/issuer DN allowlists, SAN extraction, trusted CA
policy checks, certificate pinning (SHA-256 fingerprint store),
CRL-based revocation checking, and RFC 8705 certificate-bound access
token support (`x5t#S256` thumbprint binding and verification).

### UMA 2.0

User-Managed Access 2.0: resource set registration, permission ticket
flow, RPT (Requesting Party Token) issuance with claims-based policy
evaluation, UMA discovery metadata (`.well-known/uma2-configuration`),
Protection API Token (PAT) management with issuance/validation/revocation,
and RPT introspection (RFC 7662).

### OPA / Rego Integration

Open Policy Agent integration with HTTP-based policy evaluation (query,
evaluate, health check, policy/data management, response caching) and a
local policy evaluator for embedded use supporting Equals, NotEquals,
Contains, In, and Exists operators with deny-overrides-allow semantics.

### Google Zanzibar ReBAC

Relationship-Based Access Control inspired by Google Zanzibar: relation
tuples with namespace/object/relation/subject addressing, namespace
configuration with union and tuple-to-userset relation rewrites, graph
traversal authorization checks with cycle protection, expand (list all
subjects), and reverse lookup (list all objects a subject can access).

### OIDC CIBA (Client-Initiated Backchannel Authentication)

OpenID Connect CIBA Core implementation: poll, ping, and push modes,
authentication requests with login hint variants (email, phone, subject),
binding message validation, consent approval/denial workflow, slow-down
detection for polling, notification info for ping/push modes, and expired
request cleanup.

## Feature Flags Reference

- **`openid-connect`** — OpenID Connect provider (discovery, ID tokens, UserInfo)
- **`enhanced-device-flow`** — OAuth 2.0 Device Authorization Grant
- **`ldap-auth`** — LDAP / Active Directory authentication backend
- **`otp-auth`** — HOTP (RFC 4226) counter-based one-time passwords
- **`passkeys`** — FIDO U2F / passkey support (includes FIDO1 module)
- **`saml`** — SAML 2.0 assertion parsing and validation. **Linux/macOS only for now** (not Windows) -- see [#106](https://github.com/ciresnave/auth-framework/issues/106); we are actively looking for a way around this.
