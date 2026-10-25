//! Macaroons authorization credential support.
//!
//! Implements Macaroons — a flexible authorization credential mechanism using
//! chained HMAC-based caveats for decentralized attenuation.
//!
//! # References
//!
//! - [Macaroons: Cookies with Contextual Caveats](https://research.google/pubs/pub41892/)

use crate::errors::{AuthError, Result};
use crate::security::secure_utils::SecureComparison;
use ring::hmac;
use serde::{Deserialize, Serialize};

/// A Macaroon authorization token with chained HMAC caveats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macaroon {
    /// Location hint (not cryptographically bound).
    pub location: String,
    /// Opaque identifier for this macaroon.
    pub identifier: String,
    /// First-party caveats.
    pub caveats: Vec<Caveat>,
    /// HMAC signature (hex-encoded).
    pub signature: String,
}

/// A first-party caveat restricting the macaroon's authority.
///
/// Unknown fields are rejected on deserialization, so a credential that carries
/// anything other than a plain predicate is refused instead of being read as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caveat {
    /// Caveat identifier (e.g. "account = 3735928559").
    pub cid: String,
}

impl Caveat {
    /// Create a new first-party caveat.
    pub fn first_party(predicate: &str) -> Self {
        Self {
            cid: predicate.to_string(),
        }
    }
}

/// Macaroon minting and verification.
pub struct MacaroonManager {
    root_key: Vec<u8>,
}

impl MacaroonManager {
    /// Create a manager from a root key.
    ///
    /// The root key should be at least 32 bytes of cryptographically random data.
    pub fn new(root_key: &[u8]) -> Result<Self> {
        if root_key.len() < 16 {
            return Err(AuthError::validation("Root key must be at least 16 bytes"));
        }
        Ok(Self {
            root_key: root_key.to_vec(),
        })
    }

    /// Mint a new macaroon with the given identifier.
    pub fn create(&self, location: &str, identifier: &str) -> Macaroon {
        let sig = hmac_hex(&self.root_key, identifier.as_bytes());
        Macaroon {
            location: location.to_string(),
            identifier: identifier.to_string(),
            caveats: Vec::new(),
            signature: sig,
        }
    }

    /// Add a first-party caveat, updating the signature chain.
    pub fn add_first_party_caveat(&self, macaroon: &mut Macaroon, predicate: &str) {
        let sig_bytes = hex::decode(&macaroon.signature).unwrap_or_default();
        let new_sig = hmac_hex(&sig_bytes, predicate.as_bytes());
        macaroon.caveats.push(Caveat::first_party(predicate));
        macaroon.signature = new_sig;
    }

    /// Verify a macaroon by replaying the HMAC chain and checking caveats.
    ///
    /// `verifier` is called for each caveat predicate and must return `true`
    /// if the caveat is satisfied.
    pub fn verify<F>(&self, macaroon: &Macaroon, verifier: F) -> Result<()>
    where
        F: Fn(&str) -> bool,
    {
        let mut sig = hmac_hex(&self.root_key, macaroon.identifier.as_bytes());

        for caveat in &macaroon.caveats {
            let sig_bytes = hex::decode(&sig).unwrap_or_default();
            sig = hmac_hex(&sig_bytes, caveat.cid.as_bytes());
            if !verifier(&caveat.cid) {
                return Err(AuthError::validation(format!(
                    "Caveat not satisfied: {}",
                    caveat.cid
                )));
            }
        }

        if !SecureComparison::constant_time_eq(&sig, &macaroon.signature) {
            return Err(AuthError::validation("Macaroon signature mismatch"));
        }
        Ok(())
    }

    /// Attenuate (create a restricted copy of) a macaroon with additional caveats.
    pub fn attenuate(&self, macaroon: &Macaroon, predicates: &[&str]) -> Macaroon {
        let mut attenuated = macaroon.clone();
        for p in predicates {
            self.add_first_party_caveat(&mut attenuated, p);
        }
        attenuated
    }
}

/// Compute HMAC-SHA256 and return the result as a hex string.
fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, data);
    hex::encode(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0xABu8; 32]
    }

    #[test]
    fn test_create_macaroon() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let m = mgr.create("https://example.com", "user-token-1");
        assert_eq!(m.identifier, "user-token-1");
        assert_eq!(m.location, "https://example.com");
        assert!(m.caveats.is_empty());
        assert!(!m.signature.is_empty());
    }

    #[test]
    fn test_short_key_rejected() {
        assert!(MacaroonManager::new(&[1; 8]).is_err());
    }

    #[test]
    fn test_verify_no_caveats() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let m = mgr.create("https://example.com", "token-1");
        mgr.verify(&m, |_| true).unwrap();
    }

    #[test]
    fn test_verify_with_caveats() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        mgr.add_first_party_caveat(&mut m, "account = 12345");
        mgr.add_first_party_caveat(&mut m, "time < 2099-01-01");

        mgr.verify(&m, |caveat| {
            caveat == "account = 12345" || caveat.starts_with("time < ")
        })
        .unwrap();
    }

    #[test]
    fn test_verify_fails_unsatisfied_caveat() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        mgr.add_first_party_caveat(&mut m, "admin = true");

        assert!(mgr.verify(&m, |_| false).is_err());
    }

    #[test]
    fn test_verify_fails_tampered_signature() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        m.signature =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(mgr.verify(&m, |_| true).is_err());
    }

    #[test]
    fn test_different_keys_fail() {
        let mgr1 = MacaroonManager::new(&[0xAA; 32]).unwrap();
        let mgr2 = MacaroonManager::new(&[0xBB; 32]).unwrap();
        let m = mgr1.create("https://example.com", "token-1");
        assert!(mgr2.verify(&m, |_| true).is_err());
    }

    #[test]
    fn test_attenuate() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let m = mgr.create("https://example.com", "token-1");
        let attenuated = mgr.attenuate(&m, &["op = read", "ip = 10.0.0.1"]);
        assert_eq!(attenuated.caveats.len(), 2);
        mgr.verify(&attenuated, |c| c == "op = read" || c == "ip = 10.0.0.1")
            .unwrap();
    }

    #[test]
    fn test_signature_deterministic() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let m1 = mgr.create("loc", "id-1");
        let m2 = mgr.create("loc", "id-1");
        assert_eq!(m1.signature, m2.signature);
    }

    #[test]
    fn test_credential_carrying_a_third_party_caveat_is_refused() {
        // Shape of a credential minted by releases that had third-party caveats.
        let json = r#"{"location":"l","identifier":"token-1","caveats":[{"cid":"tp","vid":"00","cl":"https://auth.third-party.com"}],"signature":"00"}"#;
        assert!(serde_json::from_str::<Macaroon>(json).is_err());
    }

    #[test]
    fn test_tampered_caveat_list_is_rejected() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        mgr.add_first_party_caveat(&mut m, "op = read");
        m.caveats[0] = Caveat::first_party("op = write");
        assert!(mgr.verify(&m, |_| true).is_err());
    }
}
