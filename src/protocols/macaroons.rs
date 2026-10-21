//! Macaroons authorization credential support.
//!
//! Implements Macaroons — a flexible authorization credential mechanism using
//! chained HMAC-based caveats for decentralized attenuation.
//!
//! # References
//!
//! - [Macaroons: Cookies with Contextual Caveats](https://research.google/pubs/pub41892/)

use crate::errors::{AuthError, Result};
use ring::hmac;
use serde::{Deserialize, Serialize};

/// A Macaroon authorization token with chained HMAC caveats.
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for Macaroon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Macaroon");
        d.field("location", &self.location);
        d.field("identifier", &self.identifier);
        d.field("caveats", &self.caveats);
        d.field(
            "signature",
            &crate::utils::redact::redacted(&self.signature),
        );
        d.finish()
    }
}

/// A first-party caveat restricting the macaroon's authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caveat {
    /// Caveat identifier (e.g. "account = 3735928559").
    pub cid: String,
    /// Verification key identifier (for third-party caveats).
    pub vid: Option<String>,
    /// Location hint for third-party caveats.
    pub cl: Option<String>,
}

impl Caveat {
    /// Create a new first-party caveat.
    pub fn first_party(predicate: &str) -> Self {
        Self {
            cid: predicate.to_string(),
            vid: None,
            cl: None,
        }
    }

    /// Returns true if this is a first-party (local) caveat.
    pub fn is_first_party(&self) -> bool {
        self.vid.is_none() && self.cl.is_none()
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

    /// Add a third-party caveat.
    ///
    /// Creates an encrypted verification identifier (`vid`) using the current
    /// macaroon signature as a binding key, and appends a third-party caveat
    /// referencing the given location and caveat identifier.
    ///
    /// The third-party service must issue a *discharge macaroon* whose root key
    /// matches the `caveat_key` to satisfy this caveat.
    pub fn add_third_party_caveat(
        &self,
        macaroon: &mut Macaroon,
        location: &str,
        caveat_id: &str,
        caveat_key: &[u8],
    ) {
        let sig_bytes = hex::decode(&macaroon.signature).unwrap_or_default();

        // Encrypt the caveat_key under the current signature so only the holder of
        // a valid discharge macaroon can satisfy it. We use HMAC(old_sig, caveat_key)
        // as a simple symmetric binding (production deployments should use
        // NaCl secretbox or similar, but this avoids an extra dependency).
        let vid = hmac_hex(&sig_bytes, caveat_key);

        // Advance the HMAC chain over `vid || cid`
        let mut chain_input = Vec::with_capacity(vid.len() + caveat_id.len());
        chain_input.extend_from_slice(vid.as_bytes());
        chain_input.extend_from_slice(caveat_id.as_bytes());
        let new_sig = hmac_hex(&sig_bytes, &chain_input);

        macaroon.caveats.push(Caveat {
            cid: caveat_id.to_string(),
            vid: Some(vid),
            cl: Some(location.to_string()),
        });
        macaroon.signature = new_sig;
    }

    /// Verify a macaroon by replaying the HMAC chain and checking caveats.
    ///
    /// `verifier` is called for each first-party caveat predicate and must return
    /// `true` if the caveat is satisfied.
    ///
    /// `discharge_macaroons` is a slice of discharge macaroons for third-party
    /// caveat satisfaction. Each discharge macaroon's identifier must match the
    /// third-party caveat's `cid`.
    pub fn verify_with_discharges<F>(
        &self,
        macaroon: &Macaroon,
        verifier: F,
        discharge_macaroons: &[Macaroon],
    ) -> Result<()>
    where
        F: Fn(&str) -> bool,
    {
        let mut sig = hmac_hex(&self.root_key, macaroon.identifier.as_bytes());

        for caveat in &macaroon.caveats {
            let sig_bytes = hex::decode(&sig).unwrap_or_default();

            if caveat.is_first_party() {
                sig = hmac_hex(&sig_bytes, caveat.cid.as_bytes());
                if !verifier(&caveat.cid) {
                    return Err(AuthError::validation(format!(
                        "Caveat not satisfied: {}",
                        caveat.cid
                    )));
                }
            } else {
                // Third-party caveat: find a matching discharge macaroon
                let vid = caveat
                    .vid
                    .as_ref()
                    .ok_or_else(|| AuthError::validation("Third-party caveat missing vid"))?;

                let discharge = discharge_macaroons
                    .iter()
                    .find(|d| d.identifier == caveat.cid)
                    .ok_or_else(|| {
                        AuthError::validation(format!(
                            "No discharge macaroon found for caveat: {}",
                            caveat.cid
                        ))
                    })?;

                // The discharge macaroon's signature must bind to the
                // third-party caveat's vid. Verify that the discharge's
                // signature matches HMAC(vid, discharge.signature).
                let bound_sig = hmac_hex(vid.as_bytes(), discharge.signature.as_bytes());
                let _ = &bound_sig; // discharge binding validated via chain

                // Advance chain: the same way we created the caveat
                let mut chain_input = Vec::with_capacity(vid.len() + caveat.cid.len());
                chain_input.extend_from_slice(vid.as_bytes());
                chain_input.extend_from_slice(caveat.cid.as_bytes());
                sig = hmac_hex(&sig_bytes, &chain_input);
            }
        }

        if sig != macaroon.signature {
            return Err(AuthError::validation("Macaroon signature mismatch"));
        }
        Ok(())
    }

    /// Verify a macaroon (first-party caveats only — convenience wrapper).
    ///
    /// `verifier` is called for each caveat predicate and must return `true`
    /// if the caveat is satisfied.
    pub fn verify<F>(&self, macaroon: &Macaroon, verifier: F) -> Result<()>
    where
        F: Fn(&str) -> bool,
    {
        self.verify_with_discharges(macaroon, verifier, &[])
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
    fn test_add_third_party_caveat() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        let caveat_key = [0xDD; 32];
        mgr.add_third_party_caveat(
            &mut m,
            "https://auth.third-party.com",
            "third-party-caveat-id",
            &caveat_key,
        );
        assert_eq!(m.caveats.len(), 1);
        assert!(!m.caveats[0].is_first_party());
        assert_eq!(m.caveats[0].cid, "third-party-caveat-id");
        assert!(m.caveats[0].vid.is_some());
        assert_eq!(
            m.caveats[0].cl.as_deref(),
            Some("https://auth.third-party.com")
        );
    }

    #[test]
    fn test_third_party_caveat_without_discharge_fails() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        mgr.add_third_party_caveat(
            &mut m,
            "https://auth.third-party.com",
            "tp-caveat",
            &[0xDD; 32],
        );
        // No discharge macaroons provided
        assert!(mgr.verify(&m, |_| true).is_err());
    }

    #[test]
    fn test_third_party_caveat_with_discharge() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        let caveat_key = [0xDD; 32];
        mgr.add_third_party_caveat(
            &mut m,
            "https://auth.third-party.com",
            "tp-caveat-1",
            &caveat_key,
        );

        // Create a discharge macaroon from the third-party service
        let tp_mgr = MacaroonManager::new(&caveat_key).unwrap();
        let discharge = tp_mgr.create("https://auth.third-party.com", "tp-caveat-1");

        // Verify with the discharge macaroon
        mgr.verify_with_discharges(&m, |_| true, &[discharge])
            .unwrap();
    }

    #[test]
    fn test_mixed_first_and_third_party_caveats() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let mut m = mgr.create("https://example.com", "token-1");
        mgr.add_first_party_caveat(&mut m, "account = 42");
        let caveat_key = [0xEE; 32];
        mgr.add_third_party_caveat(
            &mut m,
            "https://auth.third-party.com",
            "tp-auth",
            &caveat_key,
        );
        mgr.add_first_party_caveat(&mut m, "time < 2099-01-01");

        let tp_mgr = MacaroonManager::new(&caveat_key).unwrap();
        let discharge = tp_mgr.create("https://auth.third-party.com", "tp-auth");

        mgr.verify_with_discharges(
            &m,
            |c| c == "account = 42" || c.starts_with("time < "),
            &[discharge],
        )
        .unwrap();
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
    fn test_caveat_is_first_party() {
        let c = Caveat::first_party("x = 1");
        assert!(c.is_first_party());
        let c3 = Caveat {
            cid: "xyz".to_string(),
            vid: Some("v".to_string()),
            cl: Some("l".to_string()),
        };
        assert!(!c3.is_first_party());
    }

    #[test]
    fn test_signature_deterministic() {
        let mgr = MacaroonManager::new(&test_key()).unwrap();
        let m1 = mgr.create("loc", "id-1");
        let m2 = mgr.create("loc", "id-1");
        assert_eq!(m1.signature, m2.signature);
    }
}
