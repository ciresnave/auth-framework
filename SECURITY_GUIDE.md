# Security Guide

## JWT Secret Configuration 🔐

### ⚠️ **Critical Security Requirement**

The AuthFramework requires a cryptographically secure JWT secret to function. **No default secret is provided** to prevent accidental security vulnerabilities.

### 🚨 **Why No Default Secret?**

Using default secrets would create severe security risks:

- **Predictable tokens**: Anyone could forge JWTs for your application
- **Cross-application attacks**: Multiple apps with the same secret can impersonate each other
- **Silent failures**: Developers might deploy vulnerable applications unknowingly
- **Production disasters**: Apps could go live without proper security

### ✅ **Proper Secret Configuration**

#### Option 1: Environment Variable (Recommended)

```bash
export JWT_SECRET="your-super-secure-32-char-plus-secret-here"
```

#### Option 2: Configuration File

```rust
let config = AuthConfig::new()
    .secret("your-super-secure-32-char-plus-secret-here");
```

#### Option 3: TOML Configuration

```toml
[security]
secret_key = "your-super-secure-32-char-plus-secret-here"
```

### 🔑 **Generating Secure Secrets**

**Use at least 32 characters for optimal security.**

#### Using OpenSSL

```bash
openssl rand -base64 32
```

#### Using Node.js

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

#### Using Python

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 🛡️ **Security Best Practices**

1. **Never hardcode secrets** in source code
2. **Use environment variables** for production
3. **Rotate secrets periodically** (invalidates existing tokens)
4. **Use different secrets** for different environments
5. **Store secrets securely** (vault, environment, etc.)

### 🔒 **Multi-Environment Setup**

```bash
# Development
export JWT_SECRET="dev-secret-32-chars-minimum-length"

# Staging
export JWT_SECRET="staging-secret-32-chars-minimum-length"

# Production
export JWT_SECRET="production-secret-32-chars-minimum-length"
```

### ⚡ **Framework Behavior**

- **Panics immediately** if no secret is configured
- **Warns** if secret is shorter than 32 characters
- **Checks both** config and environment variables
- **Provides helpful error messages** with generation commands

### 🚫 **What NOT to Do**

```rust
// ❌ NEVER do this
let config = AuthConfig::new()
    .secret("weak"); // Too short and predictable

// ❌ NEVER commit secrets to version control
let config = AuthConfig::new()
    .secret("my-production-secret-key");

// ❌ NEVER use the same secret across environments
```

### ✅ **What TO Do**

```rust
// ✅ Good - Uses environment variable
let config = AuthConfig::new(); // Will read JWT_SECRET automatically

// ✅ Good - Loads from secure configuration
let secret = std::env::var("JWT_SECRET")
    .expect("JWT_SECRET must be set");
let config = AuthConfig::new().secret(secret);

// ✅ Good - Different secrets per environment
let config = match env::var("ENVIRONMENT").as_deref() {
    Ok("production") => AuthConfig::production(),
    Ok("staging") => AuthConfig::staging(),
    _ => AuthConfig::development(),
};
```

### 📋 **Checklist**

- [ ] Generated a cryptographically secure secret (32+ characters)
- [ ] Configured secret via environment variable or secure config
- [ ] Different secrets for different environments
- [ ] Secrets not committed to version control
- [ ] Secret rotation strategy in place
- [ ] Monitoring for security warnings

Remember: **Security is not optional** - the framework forces secure configuration by design! 🛡️
