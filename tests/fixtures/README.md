# Test Fixtures

Files here are read by tests. Nothing in this directory is a secret.

## Files

- `passkey_wire_format.json` - a passkey credential and assertion recorded once, read by `tests/passkey_authentication.rs` and `tests/passkey_wire_format.rs`
- `test_public_key.pem` - an RSA public key. No code or test references it, and its private key was removed (it was unused; see the changelog).

## Keys

Do not commit private keys here. A test that needs one generates it at run time (for example with `rcgen`).
