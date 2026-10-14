# Changelog

All notable changes to the AuthFramework project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **Breaking:** the `sms-aws-sns` optional dependency (and the `sms-aws-sns` feature it implied) is
  removed from the `smskit` feature, and `actix-web` is built with `default-features = false`
  (`macros` only). The crate never sent through `sms-aws-sns` on this line (the AWS SNS provider
  only logs), so runtime behaviour is unchanged; the dependency pulled a legacy `rustls` 0.21 /
  `rustls-webpki` 0.101 / `h2` 0.3 stack that carries open advisories (RUSTSEC-2026-0098/0099/
  0104/0258, -0346/0349). Applications that enable actix-web's `http2` feature (or compression or
  cookies) must enable them on their own `actix-web` dependency. The security audit for this line
  now reports only RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2025-0111 (`tokio-tar`), neither with a
  patched release.

### Changed

- CI only for the workflow: `ci-cd.yml` runs on pushes and pull requests for `release/**`
  branches, so this line gets the same checks as main. The workflow no longer fails the Slack
  step when no webhook is configured.
- Dependencies: `cargo fmt` applied to the tree; `Cargo.lock` raised for RUSTSEC-2025-0055,
  -2026-0007, -2026-0009, -2026-0037, -2026-0178, -2026-0179, -2026-0180, -2026-0185,
  -2026-0204, -2026-0258 (h2 0.4.x), -2026-0338..-0342; `quick-xml` 0.38 -> 0.41
  (RUSTSEC-2026-0194/0195); `maxminddb` 0.26 -> 0.27 (RUSTSEC-2025-0132). **Behaviour change:**
  with `maxminddb` 0.27 the session location string no longer carries the `proxy` and
  `satellite` threat flags (the model only exposes `is_anycast`); coordinates, country, region
  and city are unchanged. No public signature changes.

### Security

- **Storage key names no longer hold credentials.** API-key rows, the Redis access-token mapping and
  Redis session records are named by a domain-separated SHA-256 digest of the credential
  (`api_key_h:`, `access_token_h:`/`access_h:`, `session_h:`) instead of the credential itself.
  Storage encryption protects values only, so a raw credential in a key name was readable by
  anyone able to read the store. Rows written under the previous names keep working: each is moved
  to its new name the first time it is read, and revoke/delete remove both names. **Upgrade note:**
  upgrade every node that shares a Redis or database together (or drain old nodes first): a node
  still on the previous release neither sees rows written by an upgraded node nor keeps rows an
  upgraded node has moved. Backups taken before the upgrade still hold the previous key names; API
  keys readable from such a backup should be rotated.
- `private_key_jwt` client authentication (`PrivateKeyJwtManager`) now verifies the assertion's
  signature against the registered public key (RSA of at least 2048 bits, EC P-256 / P-384, or
  Ed25519), with the algorithm taken from the assertion header and required to be on the client's
  allow-list and to fit the key. Before, the "verification key" was an HMAC secret derived from the
  public JWK's own members (`rsa_private_key_jwt_n:{n}_e:{e}`), so anyone who could read a client's
  public key could forge an assertion for it (when the validator accepted HS256 and the client was
  registered with HS256). `register_client` now refuses symmetric (`HS*`) algorithms, a JWK carrying
  private or symmetric key parameters, and a key that no allowed algorithm can verify. `iss`, `sub`,
  `aud`, `exp`, `nbf`, lifetime and `jti` are checked on the verified claims; a `jti` is claimed
  atomically, per client (at most 5,000 unexpired per client, 100,000 in all), and a revoked `jti` is
  refused; `aud` may be a string or an array. An unknown client and an assertion that does not verify
  get the same answer (`authenticated == false`, one generic message), and
  `FapiManager::authenticate_client_jwt` no longer returns the detailed reasons to its caller (they
  are logged). `create_client_assertion` now really signs (it used to produce a placeholder
  signature). No public signature changed: `PrivateKeyJwtClaims::iat` stays an `i64` (an assertion
  without `iat`, which RFC 7523 allows, reads as `0` and its lifetime is bounded through `exp`), and
  `ClientJwtConfig` is unchanged. New: `ClientJwtConfig::builder` and `PrivateKeyJwtManager::require_audiences`.
  **Behaviour you may notice:** a client registered without `expected_audiences` is still accepted
  (any `aud` value; a warning is logged) so that a patch release does not refuse existing
  registrations; call `PrivateKeyJwtManager::require_audiences(true)` to make registration refuse
  it. Without an audience an assertion is not bound to this server, so a genuine assertion captured
  elsewhere could be presented here. Replay and revocation records are in memory per manager.

## [0.4.7] - 2026-10-12

### Security

- `POST /auth/refresh` no longer decides that a token is a refresh token by looking for the text
  `refresh` in its scope string. A token qualifies only if it was minted as a refresh token
  (`TokenManager::create_refresh_jwt_token`, which `POST /auth/login` now uses; it carries a
  `token_use: "refresh"` claim, read with the new `JwtClaims::is_refresh_token`). An access token
  whose scope merely contains the word (for example a permission or role name such as
  `token_refresh_manager`) was accepted and exchanged for a new access token; it is now refused.
  Behaviour change: refresh tokens issued by an earlier release carry no such claim and are no
  longer accepted, so those sessions must log in again. Affects 0.4.2 to 0.4.6.
- The client address that authorization policies see (`ContextBuilder`, the `rbac_middleware`
  request context) is now the connection's peer address (axum `ConnectInfo<SocketAddr>`). Before,
  it was taken from `X-Forwarded-For` / `X-Real-IP`, which any client can set, so an ABAC policy
  keyed on the client address (`ip_address`, corporate network membership) could be satisfied by
  a forged header. Behind a reverse proxy, declare it with the new
  `ContextBuilder::with_trusted_proxies`: only then is `X-Forwarded-For` believed (rightmost entry
  that is not itself a trusted proxy; a trusted proxy that sends none, or one that cannot be
  read, is reported as the client). `rbac_middleware` has no proxy list on this line and always
  reports the connection's peer (behind a proxy that is the proxy's address, so key policies on
  it accordingly, or build the context with `ContextBuilder`). Serve the router with
  `into_make_service_with_connect_info::<SocketAddr>()`; without a peer address there is no
  client address (`ip_address` is `None` and the connection type is `Unknown`). The connection
  type is likewise decided from the peer address: a client-supplied `Via` header can only raise
  the assessed risk (VPN / proxy). Behaviour change: a request without a `Via` header used to be
  assessed `Unknown`; it is now `Direct`, or `Corporate` when the peer is inside a configured
  corporate network, and the Tor user-agent check no longer depends on `Via`. No public
  signature changed. Affects 0.4.2 to 0.4.6, library users of
  `authorization_enhanced` only (the shipped API server does not mount these middlewares).

## [0.4.6] - 2026-10-10

### Security

- Mutual-TLS client-certificate validation (`MutualTlsManager`) now uses one validator built on `rustls-webpki`
  (ring backend; no new C dependency) for `authenticate_client` and `validate_client_certificate`: the certification
  path is verified (signatures, validity, basicConstraints / pathLen, name constraints, `clientAuth` extended key
  usage) and the certificate is matched to the registered client. Previously the certificate's issuer name was
  compared with a trusted CA's subject name and the signature was not verified, so a certificate that merely named
  a trusted CA as its issuer was accepted. A PKI client must be registered with an exact `client_certificate` pin or
  an `expected_subject_dn` (an RFC 4514 string, compared as structure, values case-sensitive); `register_client`
  rejects a PKI client without one, an empty or unparsable DN, and a CA list that holds anything but usable CA
  certificates. This is a behaviour change for callers that registered unbound PKI clients. New
  `authenticate_client_with_chain` / `validate_client_certificate_with_chain` accept the client's intermediate
  certificates. FAPI: certificates passed as text are decoded as PEM or base64 DER, the `x5t#S256` thumbprint is
  computed over the DER, and the client id is read from the parsed subject CN or SAN. Certificate revocation
  (CRL / OCSP) is not checked by this crate. Upgrade from every earlier 0.4.x release.

## [0.4.5] - 2026-10-04

### Security

- Fixed GHSA-jfmh-j245-wpjg: MFA verification no longer derives a
  fallback secret. As part of this fix, `AuthFramework::generate_totp_secret`
  now actually persists the secret it generates (previously it stored
  nothing), so calling it for a user who already has one enrolled now
  overwrites the existing secret -- this is a real behavior change for
  that method, though no legitimate enrollment previously worked through
  this path at all.

## [0.4.3] - 2026-09-17

### Security

- Fixed GHSA-cc4x-p872-64jg: `MfaManager::complete_cross_method_step` could mark a
  step-up MFA method as completed without a valid code. All users of 0.4.0-0.4.2
  should upgrade.

## [0.4.2] - 2025-08-24

### 🛠️ Fixed

- **Comprehensive Test Suite Improvements**: Resolved 13 failing tests, bringing total to **393 passing tests** with 0 failures
- **Enhanced Error Handling**: Fixed error display formatting, HTTP status code mappings, and error source expectations
- **Security Utilities Rebuild**: Completely reconstructed `secure_utils.rs` with comprehensive validation and security functions
- **Email Validation Enhancement**: Improved email validation with robust edge case handling including:
  - Rejection of consecutive dots in domain names
  - Validation of domain start/end characters
  - Comprehensive format validation
- **Password Strength Algorithm**: Enhanced password strength scoring with improved criteria and point allocation
- **String Utilities Improvements**: Fixed string masking logic and edge case handling for utility functions
- **File Integrity**: Resolved file corruption issues and improved overall code quality

### 🔧 Improved

- **Error Display Consistency**: Standardized error message formatting across all error types
- **Actix-Web Integration**: Simplified and improved HTTP middleware integration
- **Validation Functions**: Enhanced input sanitization and validation capabilities
- **Code Quality**: Improved maintainability and reliability through comprehensive testing

### 📊 Testing

- **Test Coverage**: Achieved 393 passing tests with 100% pass rate
- **Quality Assurance**: Comprehensive test suite covering all core functionality
- **Security Testing**: Enhanced security validation and edge case testing

## [0.3.0] - 2024-08-14

### 🚀 Added

- **Complete Configuration Management System** using the `config` crate
  - Multi-format support (TOML, YAML, JSON, RON, INI)
  - Environment variable mapping with customizable prefixes
  - Include directive system for modular configuration
  - CLI argument integration with clap
  - Parent application integration capabilities
- **Advanced Threat Intelligence Integration**
  - Real-time threat feed updates with automated scheduling
  - MaxMind GeoIP2 database integration for IP geolocation
  - CIDR network parsing and threat classification
  - Configurable threat severity levels and response actions
- **Enhanced SMS Kit Integration** (Next-Generation SMS)
  - Multi-provider support (Twilio, Plivo, AWS SNS, generic web APIs)
  - SMS web integration with Axum framework
  - Advanced delivery tracking and retry mechanisms
  - Comprehensive SMS testing and validation tools
- **Production-Ready Admin Binary**
  - Command Line Interface (CLI) with comprehensive user management
  - Terminal User Interface (TUI) with real-time monitoring
  - Web-based GUI with modern responsive design
  - Integrated health checks, metrics, and security monitoring
- **Enhanced Device Flow Support**
  - Convenient constructor methods for OAuth device flows
  - Support for GitHub, Google, Microsoft, and custom providers
  - Simplified device code completion workflows
  - Enhanced error handling and user experience
- **Token-to-Profile Conversion Utilities**
  - Automatic conversion from OAuth tokens to standardized user profiles
  - Support for multiple OAuth providers with consistent interface
  - Extensible profile mapping for custom user data

### 🛡️ Security Enhancements

- **RUSTSEC-2023-0071 Vulnerability Documentation**
  - Comprehensive analysis of Marvin Attack on RSA
  - PostgreSQL migration recommendation for complete vulnerability elimination
  - Detailed risk assessment showing extremely low practical risk
  - Alternative mitigation strategies for MySQL users
- **Enhanced Cryptographic Support**
  - AES-GCM encryption enabled by default
  - Optional ChaCha20-Poly1305 support
  - X25519 and Ed25519 curve support
  - AWS-LC-RS for FIPS compliance (optional)
- **Advanced Security Features**
  - Comprehensive audit trails with correlation IDs
  - Enhanced rate limiting with penalty systems
  - Secure session management with risk scoring
  - Multi-factor authentication improvements

### 🏗️ Infrastructure Improvements

- **Database Optimization**
  - PostgreSQL set as recommended default storage backend
  - Enhanced connection pooling and management
  - Improved migration and schema management
  - Better error handling and recovery mechanisms
- **Performance Enhancements**
  - Optimized dependency tree for faster compilation
  - Reduced memory footprint in core components
  - Improved async task management
  - Better resource cleanup and lifecycle management

### 📚 Documentation & Testing

- **Comprehensive Documentation Updates**
  - Updated README with PostgreSQL recommendations
  - Enhanced security guides and best practices
  - Complete configuration examples and guides
  - Production deployment patterns and examples
- **Testing Infrastructure**
  - 266+ comprehensive unit tests with high coverage
  - Security-focused test scenarios
  - Performance benchmarking tests
  - Integration tests for all major features

### 🔧 Developer Experience

- **Enhanced Error Handling**
  - Specific error types for different failure modes
  - Detailed error messages with recovery suggestions
  - Consistent error propagation patterns
  - Better debugging and troubleshooting support
- **Improved Configuration**
  - Sensible defaults for production deployment
  - Environment-specific configuration templates
  - Validation and sanity checking for all configuration options
  - Clear migration guides for configuration updates

### ⚠️ Security Notices

- **RUSTSEC-2023-0071**: Theoretical RSA timing vulnerability in MySQL storage
  - **Status**: Documented with extremely low practical risk
  - **Recommendation**: Use PostgreSQL for optimal security
  - **Impact**: No immediate action required for most deployments
- **Dependencies**: All dependencies updated to latest secure versions
- **Default Configuration**: Changed to PostgreSQL storage for enhanced security

### 🔄 Breaking Changes

- **Default Storage Backend**: Changed from Redis to PostgreSQL for optimal security
- **Configuration Format**: Enhanced configuration structure may require updates
- **SMS Implementation**: Legacy SMS manager deprecated in favor of SMS Kit
- **Feature Flags**: Some feature flags restructured for better organization

### 📊 Statistics

- **Lines of Code**: 50,000+ lines of production-ready Rust code
- **Test Coverage**: 95%+ with comprehensive security testing
- **Dependencies**: 180+ carefully selected and maintained dependencies
- **Features**: 25+ optional feature flags for modular deployment
- **Documentation**: 1,000+ lines of comprehensive guides and examples

### 🚀 Migration Guide

For users upgrading from previous versions:

1. **Configuration**: Update configuration files to use new format
2. **Storage**: Consider migrating to PostgreSQL for optimal security
3. **SMS**: Migrate from legacy SMS manager to SMS Kit integration
4. **Features**: Review and update feature flags in Cargo.toml
5. **Documentation**: Review updated security and configuration guides

See [`MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md) for detailed upgrade instructions.

---

## [0.2.x] - Previous Versions

### Legacy Features

- Basic authentication and authorization framework
- Initial OAuth 2.0 and OpenID Connect support
- Fundamental security features and session management
- Core storage backends (Memory, Redis)
- Basic configuration system
- Essential documentation and examples

---

## Future Roadmap

### Planned for 0.4.0

- **Advanced FAPI Support**: Financial-grade API security enhancements
- **Enhanced WebAuthn**: Biometric authentication and passkey support
- **Distributed Architecture**: Multi-node deployment and coordination
- **Advanced Monitoring**: Prometheus metrics and distributed tracing
- **Enterprise SSO**: Enhanced SAML, WS-Federation, and enterprise integrations

### Long-term Vision

- Full OAuth 2.1 compliance with latest security standards
- Advanced threat detection and response capabilities
- Machine learning-based fraud detection
- Zero-trust architecture components
- Cloud-native deployment optimization

---

**Note**: This project follows semantic versioning. Breaking changes are clearly documented and migration guides are provided for major version updates.
