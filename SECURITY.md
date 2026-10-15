# Security Policy

## 🚨 Security Notice: RUSTSEC-2023-0071 (partly resolved)

**RUSTSEC-2023-0071** (Marvin Attack on RSA, a timing side-channel in RSA
PKCS#1 v1.5 decryption, no patched release) previously reached this framework
through jsonwebtoken's RS*/PS* support, the JARM RSA-OAEP JWE path, the
optional `openidconnect` dependency, and MySQL storage (`sqlx-mysql`).
The JWT and JARM paths now use `aws-lc-rs` (not subject to this advisory),
`openidconnect` is removed, and **MySQL storage (`mysql-storage`) has been
removed from this crate** -- use `postgres-storage`, `sqlite-storage` or
`redis-storage`. See `CHANGELOG.md` for the migration note.

The `rsa` crate is still built by the `saml` feature on this release line (not
on by default). `cargo audit` therefore keeps reporting it only for builds that
enable `saml`.

## Supported Versions

Currently supported versions of the Auth Framework with security updates:

| Version    | Supported          |
| ---------- | ------------------ |
| 0.5.x (rc) | :white_check_mark: |
| 0.4.x      | :x:                |
| < 0.4      | :x:                |

## Security Considerations

The Auth Framework is designed with security as a primary concern. However, security is a shared responsibility between the library maintainers and the users implementing it.

### Library Security Features

This library provides:

- **Secure Token Management**: JWT tokens with proper signing and validation
- **Password Hashing**: Argon2 and bcrypt implementations
- **Rate Limiting**: Protection against brute force attacks
- **Session Management**: Secure session handling with expiration
- **Constant-Time Operations**: Protection against timing attacks
- **Input Validation**: Comprehensive input sanitization
- **Audit Logging**: Security event tracking

### User Responsibilities

When using this library, ensure:

- **Secret Management**: Never hardcode secrets in your application
- **HTTPS**: Always use HTTPS in production
- **Key Rotation**: Regularly rotate signing keys and secrets
- **Dependency Updates**: Keep all dependencies updated
- **Configuration Review**: Regularly review security configurations
- **Monitoring**: Monitor for suspicious authentication patterns

## Reporting Security Vulnerabilities

We take security vulnerabilities seriously. If you discover a security issue:

### DO NOT create a public GitHub issue

Instead, please:

1. **Email**: Send details to [ciresnave@gmail.com](mailto:ciresnave@gmail.com)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Encrypt**: Use PGP if possible (key available on request)

### Response Process

1. **Acknowledgment**: We will acknowledge receipt within 48 hours
2. **Assessment**: We will assess the vulnerability within 5 business days
3. **Fix**: We will work on a fix and coordinate disclosure
4. **Release**: Security fixes will be released as soon as possible
5. **Credit**: We will credit the reporter unless they prefer to remain anonymous

## Security Best Practices

### For Library Users

#### Configuration

```rust
// Use strong secrets
let config = AuthConfig::new()
    .security(SecurityConfig::secure()) // Use secure defaults
    .rate_limiting(RateLimitConfig::new(100, Duration::from_secs(60)));
```

#### Secret Management

```rust
// Good: Use environment variables
let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

// Bad: Hardcoded secret
let secret = "hardcoded-secret"; // DON'T DO THIS
```

#### Storage

```rust
// Use secure storage in production
let storage = RedisStorage::new("rediss://user:pass@redis.example.com:6380")?;

// Not recommended for production
let storage = MemoryStorage::new(); // Only for development/testing
```

### For Library Contributors

#### Code Review Checklist

- [ ] No hardcoded secrets or passwords
- [ ] Proper input validation
- [ ] Constant-time operations for sensitive comparisons
- [ ] No sensitive data in logs
- [ ] Proper error handling without information leakage
- [ ] Secure defaults in configurations
- [ ] Updated dependencies

#### Security Testing

- [ ] Test with invalid/malformed inputs
- [ ] Test rate limiting functionality
- [ ] Test token expiration and revocation
- [ ] Test permission boundaries
- [ ] Test against common attack vectors

## Threat Model

### Assets

- User credentials and authentication data
- Session tokens and API keys
- User personal information
- System configuration and secrets

### Threats

- **Credential Stuffing**: Automated attempts using stolen credentials
- **Brute Force**: Systematic password guessing attempts
- **Session Hijacking**: Stealing or intercepting session tokens
- **Privilege Escalation**: Gaining unauthorized access levels
- **Timing Attacks**: Exploiting time differences in operations
- **Injection Attacks**: Malicious input exploitation

### Mitigations

- Rate limiting and account lockout
- Strong password requirements
- Secure session management
- Proper authorization checks
- Constant-time operations
- Input validation and sanitization

## Compliance

This library aims to help users meet common security standards:

- **OWASP Top 10**: Address common web application vulnerabilities
- **NIST Cybersecurity Framework**: Implement security controls
- **PCI DSS**: Payment card industry security standards
- **GDPR**: Data protection compliance features

## Dependencies

We regularly audit and update dependencies. Security-sensitive dependencies include:

- `ring`: Cryptographic operations (HMAC, random generation, key agreement)
- `jsonwebtoken`: JWT implementation
- `argon2`: Password hashing
- `sha2`: SHA-256/SHA-512 digests
- `hmac`: HMAC constructions (backchannel logout, RADIUS)
- `md-5`: MD5 for RADIUS RFC 2865 protocol compliance only
- `aes-gcm`: AES-GCM authenticated encryption
- `redis`: Storage backend
- `tokio`: Async runtime

## Known Cryptographic Limitations

### SHA-1 Usage in WS-Security / SAML

The framework includes a SAML integration layer (`src/api/saml.rs`) that implements portions of the **WS-Security** and **SAML 2.0** specifications. These legacy SOAP/XML-based protocols mandate SHA-1 as a required digest algorithm in their standards-defined signature and reference validation flows.

**Status**: SHA-1 is used exclusively for WS-Security XML digital signature canonicalization, where it is required by the protocol specification itself. It is **not** used for:

- Password storage (Argon2 / bcrypt)
- JWT signing (HMAC-SHA256 or RS256)
- Any application-controlled cryptographic operation

**Risk assessment**: Low. The SHA-1 usage is confined to the SAML/WS-Security XML layer where:

1. The attacker would need to forge a signed SAML assertion
2. SHA-1 collision attacks require impractical computation on XML structures
3. Modern IdPs increasingly support SHA-256 variants; configure your IdP to prefer `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` where possible

**Mitigation path**: When your SAML Identity Provider supports SHA-256 digests (`http://www.w3.org/2001/04/xmlenc#sha256`), configure it to use them. A future release will add configurable algorithm preference to the SAML handler.

## Known Implementation Limitations

The following protocol implementations have known limitations that users should be aware of:

### Protocol Stubs

Several protocol modules provide partial or stub implementations that are not yet suitable for production use without additional cryptographic verification:

- **Kerberos/SPNEGO**: AP-REQ validation performs basic ASN.1 tag checking only. Full Kerberos ticket validation requires integration with a KDC. The module returns an error indicating this limitation.
- **SAML Assertions**: XML signature verification uses SHA-1 per protocol specification. No full XML canonicalization (C14N) or signature chain validation is implemented.
- **WS-Federation JWT**: JWT payload extraction is implemented but signature verification is not performed. Use a dedicated JWT validator for production token verification.
- **WS-Trust**: Issued tokens are stored in-memory only. They are lost on restart and not shared across instances. Production deployments should integrate with the StorageBackend KV layer.
- **GNAP**: Implements grant negotiation flow with transaction state management but lacks DPoP proof validation and full key binding.
- **OpenID4VP**: Parses and structurally validates Verifiable Presentations but does not perform cryptographic signature verification on credentials.
- **UMA 2.0**: Implements resource registration, permission tickets, and basic policy evaluation. Does not include a full claims-gathering interaction flow.

### MD5 in RADIUS

The RADIUS client (`src/protocols/radius.rs`) uses MD5 as required by RFC 2865. MD5 is known to be cryptographically weak, but its use is mandated by the RADIUS protocol specification. Mitigate by:

1. Using RADIUS over IPsec or a secure tunnel
2. Migrating to RADIUS/TLS (RFC 6614) when infrastructure supports it
3. Using strong shared secrets (32+ random bytes)

## Changelog

Security-related changes will be clearly marked in the changelog with the `[SECURITY]` tag.

## Contact

For security questions or concerns:

- **Email**: [ciresnave@gmail.com](mailto:ciresnave@gmail.com)
- **PGP Key**: Available on request

## Acknowledgments

We thank the security researchers and community members who help keep this project secure.

---

*This security policy is subject to updates. Please check regularly for the latest version.*
