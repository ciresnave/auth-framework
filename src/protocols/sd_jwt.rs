//! SD-JWT (Selective Disclosure JWT) implementation.
//!
//! Implements the IETF SD-JWT specification (draft-ietf-oauth-selective-disclosure-jwt)
//! for creating JWTs whose claims can be selectively disclosed by the holder.
//!
//! # Architecture
//!
//! - **Issuer**: Creates an SD-JWT with selectively disclosable claims hashed into
//!   the `_sd` array. Each claim becomes a separate disclosure.
//! - **Holder**: Receives the full SD-JWT and can present a subset of disclosures
//!   to a verifier, revealing only the claims they choose.
//! - **Verifier**: Validates the JWT signature and reconstructs disclosed claims
//!   by matching disclosure hashes against the `_sd` array.
//!
//! # Example
//!
//! ```rust,no_run
//! use auth_framework::protocols::sd_jwt::{SdJwtIssuer, SdJwtConfig};
//!
//! let config = SdJwtConfig::default();
//! let issuer = SdJwtIssuer::new(config);
//!
//! let mut claims = serde_json::Map::new();
//! claims.insert("sub".into(), serde_json::json!("user-42"));
//! claims.insert("email".into(), serde_json::json!("user@example.com"));
//!
//! // "email" is selectively disclosable; "sub" stays in the clear
//! let sd_jwt = issuer.issue(
//!     &claims,
//!     &["email"],
//!     "signing-secret-key",
//! ).unwrap();
//! ```

use crate::errors::{AuthError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Hash algorithm used for disclosure digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SdHashAlgorithm {
    /// SHA-256 (default, recommended).
    #[serde(rename = "sha-256")]
    #[default]
    Sha256,
}

impl SdHashAlgorithm {
    /// Return the `_sd_alg` string value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
        }
    }

    /// Compute the digest of `input` using this algorithm.
    fn digest(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(input).to_vec(),
        }
    }
}

/// Configuration for SD-JWT operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtConfig {
    /// Hash algorithm for disclosure digests.
    pub hash_algorithm: SdHashAlgorithm,
    /// JWT signing algorithm.
    pub signing_algorithm: jsonwebtoken::Algorithm,
    /// Issuer claim value.
    pub issuer: String,
    /// Token lifetime in seconds.
    pub lifetime_secs: u64,
    /// Salt length in bytes (minimum 16 recommended by spec).
    pub salt_length: usize,
}

impl Default for SdJwtConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: SdHashAlgorithm::default(),
            signing_algorithm: jsonwebtoken::Algorithm::HS256,
            issuer: "auth-framework".to_string(),
            lifetime_secs: 3600,
            salt_length: 16,
        }
    }
}

/// A single disclosure: the base64url-encoded `[salt, claim_name, claim_value]` array.
#[derive(Debug, Clone)]
pub struct Disclosure {
    /// The base64url-encoded disclosure string.
    pub encoded: String,
    /// The claim name this disclosure reveals.
    pub claim_name: String,
    /// The claim value.
    pub claim_value: serde_json::Value,
    /// The hash digest of the encoded disclosure (for inclusion in `_sd`).
    pub digest: String,
}

/// The issued SD-JWT: a compact JWT, the tilde-separated disclosures, and
/// an optional key-binding JWT.
#[derive(Debug, Clone)]
pub struct SdJwt {
    /// The signed JWT containing `_sd` digests.
    pub jwt: String,
    /// All disclosures produced by the issuer.
    pub disclosures: Vec<Disclosure>,
    /// Optional holder key-binding JWT.
    pub key_binding_jwt: Option<String>,
}

impl SdJwt {
    /// Serialize to the SD-JWT compact format: `<JWT>~<Disclosure1>~...~<DisclosureN>~[KB-JWT]`.
    pub fn serialize(&self) -> String {
        let mut out = self.jwt.clone();
        for d in &self.disclosures {
            out.push('~');
            out.push_str(&d.encoded);
        }
        out.push('~');
        if let Some(ref kb) = self.key_binding_jwt {
            out.push_str(kb);
        }
        out
    }

    /// Create a presentation with only the selected claim names disclosed.
    pub fn present(&self, claims_to_disclose: &[&str]) -> String {
        let mut out = self.jwt.clone();
        for d in &self.disclosures {
            if claims_to_disclose.contains(&d.claim_name.as_str()) {
                out.push('~');
                out.push_str(&d.encoded);
            }
        }
        out.push('~');
        if let Some(ref kb) = self.key_binding_jwt {
            out.push_str(kb);
        }
        out
    }
}

/// SD-JWT issuer: creates SD-JWTs with selectively disclosable claims.
pub struct SdJwtIssuer {
    config: SdJwtConfig,
}

impl SdJwtIssuer {
    /// Create a new issuer with the given configuration.
    pub fn new(config: SdJwtConfig) -> Self {
        Self { config }
    }

    /// Generate a cryptographically random salt.
    fn generate_salt(&self) -> Result<String> {
        let mut salt = vec![0u8; self.config.salt_length];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
            .map_err(|_| AuthError::crypto("Failed to generate random salt"))?;
        Ok(URL_SAFE_NO_PAD.encode(&salt))
    }

    /// Build a disclosure for a single claim and return its digest.
    fn create_disclosure(
        &self,
        claim_name: &str,
        claim_value: &serde_json::Value,
    ) -> Result<Disclosure> {
        let salt = self.generate_salt()?;
        let array = serde_json::json!([salt, claim_name, claim_value]);
        let encoded = URL_SAFE_NO_PAD.encode(array.to_string().as_bytes());
        let hash = self.config.hash_algorithm.digest(encoded.as_bytes());
        let digest = URL_SAFE_NO_PAD.encode(&hash);

        Ok(Disclosure {
            encoded,
            claim_name: claim_name.to_string(),
            claim_value: claim_value.clone(),
            digest,
        })
    }

    /// Issue an SD-JWT.
    ///
    /// * `claims` — all claims to include in the token.
    /// * `sd_claims` — names of claims that should be selectively disclosable.
    ///   Claims not listed here are included in the JWT payload in the clear.
    /// * `signing_key` — the symmetric key (for HMAC algorithms) or PEM-encoded
    ///   private key (for RSA/EC algorithms).
    pub fn issue(
        &self,
        claims: &serde_json::Map<String, serde_json::Value>,
        sd_claims: &[&str],
        signing_key: &str,
    ) -> Result<SdJwt> {
        if claims.is_empty() {
            return Err(AuthError::validation("Claims map cannot be empty"));
        }

        let mut payload = serde_json::Map::new();
        let mut disclosures = Vec::new();
        let mut sd_digests: Vec<serde_json::Value> = Vec::new();

        // Separate plaintext claims from selectively-disclosable claims.
        for (name, value) in claims {
            if sd_claims.contains(&name.as_str()) {
                let disclosure = self.create_disclosure(name, value)?;
                sd_digests.push(serde_json::Value::String(disclosure.digest.clone()));
                disclosures.push(disclosure);
            } else {
                payload.insert(name.clone(), value.clone());
            }
        }

        // Add standard JWT claims.
        let now = chrono::Utc::now().timestamp() as u64;
        payload.insert("iss".to_string(), serde_json::json!(self.config.issuer));
        payload.insert("iat".to_string(), serde_json::json!(now));
        payload.insert(
            "exp".to_string(),
            serde_json::json!(now + self.config.lifetime_secs),
        );

        // Add the `_sd` array and `_sd_alg`.
        if !sd_digests.is_empty() {
            payload.insert("_sd".to_string(), serde_json::Value::Array(sd_digests));
            payload.insert(
                "_sd_alg".to_string(),
                serde_json::json!(self.config.hash_algorithm.as_str()),
            );
        }

        // Sign the JWT.
        let header = jsonwebtoken::Header::new(self.config.signing_algorithm);
        let key = jsonwebtoken::EncodingKey::from_secret(signing_key.as_bytes());
        let jwt = jsonwebtoken::encode(&header, &payload, &key)
            .map_err(|e| AuthError::crypto(format!("SD-JWT signing failed: {e}")))?;

        Ok(SdJwt {
            jwt,
            disclosures,
            key_binding_jwt: None,
        })
    }
}

/// SD-JWT verifier: validates SD-JWTs and reconstructs disclosed claims.
pub struct SdJwtVerifier {
    config: SdJwtConfig,
}

impl SdJwtVerifier {
    /// Create a new verifier.
    pub fn new(config: SdJwtConfig) -> Self {
        Self { config }
    }

    /// Parse a serialized SD-JWT string into its components.
    pub fn parse(input: &str) -> Result<(String, Vec<String>, Option<String>)> {
        let parts: Vec<&str> = input.split('~').collect();
        if parts.len() < 2 {
            return Err(AuthError::validation(
                "Invalid SD-JWT format: must contain at least JWT~",
            ));
        }

        let jwt = parts[0].to_string();
        let last = *parts
            .last()
            .ok_or_else(|| AuthError::validation("Invalid SD-JWT format: no parts"))?;

        // If the last part is empty, there is no key-binding JWT.
        // If the last part looks like a JWT (has dots), treat it as KB-JWT.
        let (disclosure_parts, kb_jwt) = if last.is_empty() {
            (&parts[1..parts.len() - 1], None)
        } else if last.chars().filter(|&c| c == '.').count() == 2 {
            (&parts[1..parts.len() - 1], Some(last.to_string()))
        } else {
            (&parts[1..], None)
        };

        let disclosures = disclosure_parts
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Ok((jwt, disclosures, kb_jwt))
    }

    /// Verify an SD-JWT and return the disclosed claims.
    ///
    /// * `sd_jwt_str` — the compact SD-JWT string.
    /// * `verification_key` — the symmetric key or public key for signature verification.
    pub fn verify(&self, sd_jwt_str: &str, verification_key: &str) -> Result<VerifiedSdJwt> {
        let (jwt, disclosure_strings, kb_jwt) = Self::parse(sd_jwt_str)?;

        // Verify JWT signature and decode payload.
        let key = jsonwebtoken::DecodingKey::from_secret(verification_key.as_bytes());
        let mut validation = jsonwebtoken::Validation::new(self.config.signing_algorithm);
        validation.set_required_spec_claims::<&str>(&[]);
        validation.validate_exp = true;
        validation.set_issuer(&[&self.config.issuer]);

        let token_data = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
            &jwt,
            &key,
            &validation,
        )
        .map_err(|e| AuthError::token(format!("SD-JWT signature verification failed: {e}")))?;

        let mut payload = token_data.claims;

        // Extract `_sd` digests and `_sd_alg`.
        let sd_digests: Vec<String> = payload
            .remove("_sd")
            .map(|v| {
                v.as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let _sd_alg = payload.remove("_sd_alg");

        // Process disclosures: decode, hash, and match against `_sd`.
        let mut disclosed_claims = HashMap::new();
        for disclosure_str in &disclosure_strings {
            let decoded_bytes = URL_SAFE_NO_PAD
                .decode(disclosure_str.as_bytes())
                .map_err(|e| AuthError::validation(format!("Invalid disclosure encoding: {e}")))?;

            let disclosure_array: serde_json::Value = serde_json::from_slice(&decoded_bytes)
                .map_err(|e| AuthError::validation(format!("Invalid disclosure JSON: {e}")))?;

            let arr = disclosure_array
                .as_array()
                .ok_or_else(|| AuthError::validation("Disclosure must be a JSON array"))?;

            if arr.len() != 3 {
                return Err(AuthError::validation(
                    "Disclosure array must have exactly 3 elements [salt, name, value]",
                ));
            }

            let claim_name = arr[1]
                .as_str()
                .ok_or_else(|| AuthError::validation("Disclosure claim name must be a string"))?;
            let claim_value = &arr[2];

            // Verify the disclosure hash is in the `_sd` array.
            let hash = self.config.hash_algorithm.digest(disclosure_str.as_bytes());
            let digest = URL_SAFE_NO_PAD.encode(&hash);

            if !sd_digests.contains(&digest) {
                return Err(AuthError::validation(format!(
                    "Disclosure for '{}' does not match any _sd digest",
                    claim_name,
                )));
            }

            disclosed_claims.insert(claim_name.to_string(), claim_value.clone());
        }

        Ok(VerifiedSdJwt {
            plaintext_claims: payload,
            disclosed_claims,
            key_binding_jwt: kb_jwt,
        })
    }
}

/// Result of verifying an SD-JWT.
#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    /// Claims that were in the JWT payload in the clear.
    pub plaintext_claims: serde_json::Map<String, serde_json::Value>,
    /// Claims reconstructed from the presented disclosures.
    pub disclosed_claims: HashMap<String, serde_json::Value>,
    /// The optional key-binding JWT, if present.
    pub key_binding_jwt: Option<String>,
}

impl VerifiedSdJwt {
    /// Get a claim by name, checking disclosed claims first, then plaintext.
    pub fn get_claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.disclosed_claims
            .get(name)
            .or_else(|| self.plaintext_claims.get(name))
    }

    /// Merge all claims into a single map.
    pub fn all_claims(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut merged = self.plaintext_claims.clone();
        for (k, v) in &self.disclosed_claims {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "test-signing-key-at-least-256-bits-long!!";

    fn test_config() -> SdJwtConfig {
        SdJwtConfig {
            lifetime_secs: 3600,
            ..SdJwtConfig::default()
        }
    }

    fn sample_claims() -> serde_json::Map<String, serde_json::Value> {
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user-42"));
        claims.insert("email".into(), serde_json::json!("user@example.com"));
        claims.insert("name".into(), serde_json::json!("Alice"));
        claims.insert(
            "address".into(),
            serde_json::json!({"street": "123 Main St", "city": "Springfield"}),
        );
        claims
    }

    #[test]
    fn test_issue_and_serialize() {
        let issuer = SdJwtIssuer::new(test_config());
        let claims = sample_claims();
        let sd_jwt = issuer
            .issue(&claims, &["email", "address"], TEST_KEY)
            .unwrap();

        assert!(!sd_jwt.jwt.is_empty());
        assert_eq!(sd_jwt.disclosures.len(), 2);

        let serialized = sd_jwt.serialize();
        // JWT + 2 disclosures + trailing tilde
        assert_eq!(serialized.matches('~').count(), 3);
    }

    #[test]
    fn test_issue_no_sd_claims() {
        let issuer = SdJwtIssuer::new(test_config());
        let claims = sample_claims();
        let sd_jwt = issuer.issue(&claims, &[], TEST_KEY).unwrap();

        assert!(sd_jwt.disclosures.is_empty());
        let serialized = sd_jwt.serialize();
        assert!(serialized.ends_with('~'));
    }

    #[test]
    fn test_full_disclosure_roundtrip() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);
        let claims = sample_claims();

        let sd_jwt = issuer.issue(&claims, &["email", "name"], TEST_KEY).unwrap();
        let serialized = sd_jwt.serialize();

        let verified = verifier.verify(&serialized, TEST_KEY).unwrap();

        assert_eq!(verified.get_claim("sub").unwrap(), "user-42");
        assert_eq!(verified.get_claim("email").unwrap(), "user@example.com");
        assert_eq!(verified.get_claim("name").unwrap(), "Alice");
    }

    #[test]
    fn test_selective_disclosure() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);
        let claims = sample_claims();

        let sd_jwt = issuer
            .issue(&claims, &["email", "name", "address"], TEST_KEY)
            .unwrap();

        // Present only "email", omitting "name" and "address"
        let presentation = sd_jwt.present(&["email"]);

        let verified = verifier.verify(&presentation, TEST_KEY).unwrap();

        // "sub" is plaintext — always visible
        assert_eq!(verified.get_claim("sub").unwrap(), "user-42");
        // "email" was disclosed
        assert_eq!(verified.get_claim("email").unwrap(), "user@example.com");
        // "name" and "address" were NOT disclosed
        assert!(verified.get_claim("name").is_none());
        assert!(verified.get_claim("address").is_none());
    }

    #[test]
    fn test_all_claims_merged() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);
        let claims = sample_claims();

        let sd_jwt = issuer.issue(&claims, &["email"], TEST_KEY).unwrap();
        let serialized = sd_jwt.serialize();

        let verified = verifier.verify(&serialized, TEST_KEY).unwrap();
        let merged = verified.all_claims();

        assert!(merged.contains_key("sub"));
        assert!(merged.contains_key("email"));
        assert!(merged.contains_key("iss"));
        assert!(merged.contains_key("iat"));
        assert!(merged.contains_key("exp"));
    }

    #[test]
    fn test_reject_empty_claims() {
        let issuer = SdJwtIssuer::new(test_config());
        let claims = serde_json::Map::new();
        assert!(issuer.issue(&claims, &[], TEST_KEY).is_err());
    }

    #[test]
    fn test_reject_wrong_key() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);
        let claims = sample_claims();

        let sd_jwt = issuer.issue(&claims, &["email"], TEST_KEY).unwrap();
        let serialized = sd_jwt.serialize();

        assert!(
            verifier
                .verify(&serialized, "wrong-key-wrong-key-wrong-key!!!")
                .is_err()
        );
    }

    #[test]
    fn test_reject_forged_disclosure() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);
        let claims = sample_claims();

        let sd_jwt = issuer.issue(&claims, &["email"], TEST_KEY).unwrap();

        // Forge a disclosure that isn't in the _sd array
        let forged = serde_json::json!(["fakesalt", "role", "admin"]);
        let forged_encoded = URL_SAFE_NO_PAD.encode(forged.to_string().as_bytes());
        let forged_sd_jwt = format!("{}~{}~", sd_jwt.jwt, forged_encoded);

        assert!(verifier.verify(&forged_sd_jwt, TEST_KEY).is_err());
    }

    #[test]
    fn test_parse_components() {
        let input = "eyJ0eXAi.payload.sig~disc1~disc2~";
        let (jwt, disclosures, kb) = SdJwtVerifier::parse(input).unwrap();
        assert_eq!(jwt, "eyJ0eXAi.payload.sig");
        assert_eq!(disclosures.len(), 2);
        assert!(kb.is_none());
    }

    #[test]
    fn test_parse_with_kb_jwt() {
        let input = "eyJ0eXAi.payload.sig~disc1~header.payload.signature";
        let (jwt, disclosures, kb) = SdJwtVerifier::parse(input).unwrap();
        assert_eq!(jwt, "eyJ0eXAi.payload.sig");
        assert_eq!(disclosures.len(), 1);
        assert_eq!(kb.unwrap(), "header.payload.signature");
    }

    #[test]
    fn test_disclosure_uniqueness() {
        let issuer = SdJwtIssuer::new(test_config());
        let claims = sample_claims();

        let sd_jwt1 = issuer.issue(&claims, &["email"], TEST_KEY).unwrap();
        let sd_jwt2 = issuer.issue(&claims, &["email"], TEST_KEY).unwrap();

        // Different salts produce different disclosures
        assert_ne!(
            sd_jwt1.disclosures[0].encoded,
            sd_jwt2.disclosures[0].encoded
        );
        assert_ne!(sd_jwt1.disclosures[0].digest, sd_jwt2.disclosures[0].digest);
    }

    #[test]
    fn test_complex_claim_value() {
        let config = test_config();
        let issuer = SdJwtIssuer::new(config.clone());
        let verifier = SdJwtVerifier::new(config);

        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!("user-1"));
        claims.insert(
            "address".into(),
            serde_json::json!({
                "street": "123 Main St",
                "city": "Springfield",
                "zip": "62701"
            }),
        );

        let sd_jwt = issuer.issue(&claims, &["address"], TEST_KEY).unwrap();
        let serialized = sd_jwt.serialize();
        let verified = verifier.verify(&serialized, TEST_KEY).unwrap();

        let addr = verified.get_claim("address").unwrap();
        assert_eq!(addr["city"], "Springfield");
        assert_eq!(addr["zip"], "62701");
    }
}
