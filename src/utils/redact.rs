//! Helpers for `Debug` impls that must not print secret values.
//!
//! A field that holds a secret is shown as `<redacted>`; an optional one keeps its shape
//! (`None` stays `None`, `Some(..)` becomes `Some(<redacted>)`), so a log line still says whether
//! the secret is configured.

use std::fmt;

/// What a secret field prints as.
pub(crate) enum Redacted {
    Absent,
    Present,
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Redacted::Absent => f.write_str("None"),
            Redacted::Present => f.write_str("<redacted>"),
        }
    }
}

/// Anything a secret can be stored in.
pub(crate) trait Secret {
    fn redacted(&self) -> Redacted;
}

impl Secret for String {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl Secret for Vec<String> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl Secret for Vec<u8> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T> Secret for Option<T> {
    fn redacted(&self) -> Redacted {
        if self.is_some() {
            Redacted::Present
        } else {
            Redacted::Absent
        }
    }
}

/// Maps, sets, JSON values and shared wrappers: the whole container is hidden, keys included (a map
/// keyed by a token or session id would print it).
impl Secret for serde_json::Value {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K, V, S> Secret for std::collections::HashMap<K, V, S> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K, V> Secret for std::collections::BTreeMap<K, V> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T, S> Secret for std::collections::HashSet<T, S> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K: Eq + std::hash::Hash, V> Secret for dashmap::DashMap<K, V> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::Arc<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for tokio::sync::RwLock<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for tokio::sync::Mutex<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::Mutex<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::RwLock<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

/// The value to hand to `DebugStruct::field` in place of a secret.
pub(crate) fn redacted<T: Secret>(value: &T) -> Redacted {
    value.redacted()
}

/// A short reference to a high-entropy identifier (a session id, a token) that is safe to put in a log
/// line: it lets two lines about the same value be matched, and it cannot be turned back into the
/// value. Low-entropy secrets (one-time codes, passwords) must not be fingerprinted -- a 32-bit prefix
/// of their hash can be brute-forced -- and are logged as `"<redacted>"` instead.
pub(crate) struct Fingerprint(String);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `sha256:` and the first four bytes of the SHA-256 of `value`, in hex.
pub(crate) fn fingerprint(value: &str) -> Fingerprint {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::from("sha256:");
    for byte in &digest[..4] {
        out.push_str(&format!("{byte:02x}"));
    }
    Fingerprint(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc") starts ba7816bf (FIPS 180-2 test vector).
    #[test]
    fn fingerprint_is_a_prefix_of_the_sha256_digest() {
        assert_eq!(fingerprint("abc").to_string(), "sha256:ba7816bf");
        assert_eq!(format!("{:?}", fingerprint("abc")), "sha256:ba7816bf");
    }

    #[test]
    fn fingerprint_does_not_contain_the_value() {
        let secret = "SECRET-MARKER-7f3a9c";
        assert!(!fingerprint(secret).to_string().contains(secret));
        assert_ne!(
            fingerprint(secret).to_string(),
            fingerprint("other").to_string()
        );
    }
}
