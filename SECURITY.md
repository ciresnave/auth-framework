# Security Policy

## 🚨 Important Security Notice: RUSTSEC-2023-0071

### Current Vulnerability Status

**RUSTSEC-2023-0071** (Marvin Attack on RSA) affects this framework when using MySQL storage through the SQLx dependency chain. This is a **timing side-channel vulnerability** in RSA PKCS#1 v1.5 decryption operations.

**Key Details:**

- **CVE**: CVE-2023-49092
- **Severity**: Medium (CVSS 5.9)
- **Risk Assessment**: **EXTREMELY LOW** in typical production environments
- **Affected Features**: MySQL storage (`mysql-storage` feature)

### Risk Analysis

The vulnerability poses **minimal practical risk** because:

1. **Network Access Required**: Attacker needs ability to trigger RSA operations remotely
2. **Complex Attack**: Requires sophisticated timing analysis over many operations
3. **Limited Exposure**: RSA operations in SQLx are primarily for TLS connection setup
4. **Infrastructure Protection**: Production environments typically have network isolation

### 🔒 **RECOMMENDED SOLUTION**: Use PostgreSQL

**We strongly recommend using PostgreSQL instead of MySQL** to completely eliminate this vulnerability:

```toml
[features]
default = ["postgres-storage"]  # Instead of mysql-storage
```

**Benefits of PostgreSQL Migration:**

- ✅ **Complete RSA elimination** - No RSA dependencies in the chain
- ✅ **Better performance** - Native Rust PostgreSQL drivers
- ✅ **Enhanced features** - Superior JSON support, full-text search
- ✅ **Minimal migration effort** - SQLx provides database-agnostic interface

### Alternative Mitigation Strategies

If PostgreSQL migration is not immediately feasible:

1. **Network Isolation**: Ensure database connections are not exposed to untrusted networks
2. **VPN/Private Networks**: Use secure, isolated network channels for database communication
3. **Connection Pooling**: Use connection pooling to reduce RSA handshake frequency
4. **Monitoring**: Monitor for unusual timing patterns in database operations

### Current Status

- **Production Safe**: Framework is secure for production use with proper network isolation
- **No Immediate Action Required**: Vulnerability is not practically exploitable in typical deployments
- **Long-term Recommendation**: Migrate to PostgreSQL for optimal security posture

For detailed technical analysis, see [`RUSTSEC-2023-0071_COMPREHENSIVE_ANALYSIS.md`](RUSTSEC-2023-0071_COMPREHENSIVE_ANALYSIS.md).

## Supported Versions

Currently supported versions of the Auth Framework with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

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

1. **Email**: Send details to [security@example.com](mailto:security@example.com)
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

- `ring`: Cryptographic operations
- `jsonwebtoken`: JWT implementation
- `argon2`: Password hashing
- `redis`: Storage backend
- `tokio`: Async runtime

## Changelog

Security-related changes will be clearly marked in the changelog with the `[SECURITY]` tag.

## Contact

For security questions or concerns:

- **Email**: [security@example.com](mailto:security@example.com)
- **PGP Key**: Available on request

## Acknowledgments

We thank the security researchers and community members who help keep this project secure.

---

*This security policy is subject to updates. Please check regularly for the latest version.*
