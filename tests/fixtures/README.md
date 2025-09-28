# Test Fixtures

This directory contains test-only cryptographic keys and certificates used for documentation examples and testing purposes.

## Files

- `test_private_key.pem` - RSA 2048-bit private key for testing (PKCS#1 format)
- `test_public_key.pem` - Corresponding RSA public key for testing

## ⚠️ Security Notice

**These keys are for testing and documentation purposes only!**

- Do NOT use these keys in production
- These keys are publicly visible in the repository
- They provide no security whatsoever
- They are safe to commit to version control because they're test-only

## Usage

These keys are used in:

- Documentation examples in `src/tokens/mod.rs`
- Unit tests requiring RSA key examples
- Integration tests demonstrating JWT functionality

## Key Generation

Generated using OpenSSL:

```bash
openssl genrsa -out test_private_key.pem 2048
openssl rsa -in test_private_key.pem -pubout -out test_public_key.pem
```