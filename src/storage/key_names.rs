//! One-way key names for credentials.
//!
//! Storage encryption protects values only; a key *name* is stored and
//! indexed in the clear by every backend. A bearer credential (an API key, an
//! access token, a session id) is therefore never used verbatim as part of a
//! key name. Backends name such rows by a domain-separated SHA-256 digest of
//! the credential instead, and read the legacy (raw) name only to migrate it.
//!
//! An unkeyed digest is sound for credentials the framework generates itself:
//! API keys carry about 190 bits of randomness (32 characters over 62),
//! session ids about 95 bits (16 characters over 62, `generate_id`) or 122 bits
//! (UUID v4). A caller-supplied access token is only as unguessable as the
//! caller made it; the keyed blind index of ADR-011 is the complete answer for
//! tokens.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const DOMAIN_PREFIX: &[u8] = b"auth-framework/key-name/v1\0";

/// Lower-case hex SHA-256 over a fixed prefix, the `domain` and the secret.
///
/// `domain` separates the roles (`"api_key"`, `"access_token"`, `"session"`),
/// so the same string used in two roles yields two unrelated names. Domain and
/// secret are length-delimited, so no pair of inputs can collide by moving a
/// boundary.
pub(crate) fn digest(domain: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PREFIX);
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((secret.len() as u64).to_be_bytes());
    hasher.update(secret.as_bytes());
    let out = hasher.finalize();
    let mut hex = String::with_capacity(out.len() * 2);
    for byte in out {
        // writing to a String cannot fail
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Drop the legacy-named keys whose digest-named twin is also in `keys`, so a
/// record present under both names (an interrupted write) is seen once.
///
/// `legacy_prefix` and `new_prefix` are the full key prefixes (including any
/// namespace) up to the credential / digest; `domain` is the one passed to
/// [`digest`] for that credential.
#[cfg(feature = "redis-storage")] // only the Redis backend lists keys by prefix
pub(crate) fn without_shadowed_legacy(
    keys: Vec<String>,
    legacy_prefix: &str,
    new_prefix: &str,
    domain: &str,
) -> Vec<String> {
    let present: std::collections::HashSet<&str> = keys.iter().map(String::as_str).collect();
    let shadowed: Vec<bool> = keys
        .iter()
        .map(|k| match k.strip_prefix(legacy_prefix) {
            Some(raw) => present.contains(format!("{new_prefix}{}", digest(domain, raw)).as_str()),
            None => false,
        })
        .collect();
    keys.into_iter()
        .zip(shadowed)
        .filter_map(|(k, drop)| (!drop).then_some(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_is_stable_hex_and_does_not_contain_the_secret() {
        let d = digest("api_key", "ak_secret");
        assert_eq!(d.len(), 64);
        assert!(
            d.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert!(!d.contains("ak_secret"));
        assert_eq!(d, digest("api_key", "ak_secret"), "deterministic");
    }

    #[test]
    fn digest_separates_domains_and_secrets() {
        assert_ne!(digest("api_key", "x"), digest("session", "x"));
        assert_ne!(digest("api_key", "x"), digest("api_key", "y"));
        // boundary shifts must not collide
        assert_ne!(digest("ab", "c"), digest("a", "bc"));
    }

    /// Pins the algorithm: a change here silently orphans every stored name.
    /// The literal was computed independently (Python `hashlib`).
    #[test]
    fn digest_known_answer() {
        assert_eq!(
            digest("api_key", "abc"),
            "3e6ddb238ad77685dcec66b10ce8dc809d7640df8a5aa6fcf043be3f4327f36c"
        );
    }
}
