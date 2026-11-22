// SPDX-License-Identifier: MIT OR Apache-2.0
//! FIDO U2F (Universal 2nd Factor) protocol support.
//!
//! Provides U2F registration and authentication challenge/response data
//! structures and verification logic following the FIDO U2F specification.

use crate::errors::{AuthError, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// U2F application identity (facet).
const U2F_VERSION: &str = "U2F_V2";

/// U2F registration request sent to the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fRegistrationRequest {
    pub app_id: String,
    pub challenge: String,
}

/// U2F registration response from the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fRegistrationResponse {
    pub registration_data: Vec<u8>,
    pub client_data: Vec<u8>,
}

/// Parsed U2F registration result containing the key handle and public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fRegistration {
    pub key_handle: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_cert: Vec<u8>,
}

/// U2F authentication (sign) request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fSignRequest {
    pub app_id: String,
    pub challenge: String,
    pub key_handle: Vec<u8>,
}

/// U2F authentication (sign) response from the authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fSignResponse {
    pub signature_data: Vec<u8>,
    pub client_data: Vec<u8>,
    pub key_handle: Vec<u8>,
}

/// Parsed client data from U2F operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct U2fClientData {
    pub typ: String,
    pub challenge: String,
    pub origin: String,
}

/// Manager for U2F registration and authentication flows.
pub struct U2fManager {
    app_id: String,
    registrations: HashMap<String, Vec<U2fRegistration>>,
}

impl U2fManager {
    /// Create a new U2F manager for the given application ID.
    ///
    /// The `app_id` should be the application's origin (e.g., `https://example.com`).
    pub fn new(app_id: &str) -> Result<Self> {
        if app_id.is_empty() {
            return Err(AuthError::validation("App ID cannot be empty"));
        }
        Ok(Self {
            app_id: app_id.to_string(),
            registrations: HashMap::new(),
        })
    }

    /// Generate a registration challenge for a new U2F device.
    pub fn generate_registration_challenge(&self) -> Result<U2fRegistrationRequest> {
        let challenge = generate_challenge()?;
        Ok(U2fRegistrationRequest {
            app_id: self.app_id.clone(),
            challenge,
        })
    }

    /// Verify a U2F registration response and store the credential.
    ///
    /// Per the U2F spec, the registration response contains:
    /// - 1 byte: reserved (0x05)
    /// - 65 bytes: user public key (uncompressed P-256)
    /// - 1 byte: key handle length
    /// - N bytes: key handle
    /// - remaining: attestation certificate + signature
    ///
    /// # Example
    /// ```rust,ignore
    /// let request = authenticator.generate_registration_challenge()?;
    /// // … user interacts with the U2F device …
    /// let registration = authenticator.verify_registration("user1", &request, &response)?;
    /// ```
    pub fn verify_registration(
        &mut self,
        user_id: &str,
        request: &U2fRegistrationRequest,
        response: &U2fRegistrationResponse,
    ) -> Result<U2fRegistration> {
        // Validate client data
        let client_data: U2fClientData = serde_json::from_slice(&response.client_data)
            .map_err(|e| AuthError::validation(format!("Invalid client data: {e}")))?;

        if client_data.typ != "navigator.id.finishEnrollment" {
            return Err(AuthError::validation(
                "Invalid client data type for registration",
            ));
        }
        if client_data.challenge != request.challenge {
            return Err(AuthError::validation("Challenge mismatch"));
        }

        // Parse registration data
        let data = &response.registration_data;
        if data.len() < 67 {
            return Err(AuthError::validation("Registration data too short"));
        }
        if data[0] != 0x05 {
            return Err(AuthError::validation(
                "Invalid reserved byte (expected 0x05)",
            ));
        }

        let public_key = data[1..66].to_vec();
        let key_handle_len = data[66] as usize;

        if data.len() < 67 + key_handle_len {
            return Err(AuthError::validation("Registration data truncated"));
        }

        let key_handle = data[67..67 + key_handle_len].to_vec();
        let attestation_cert = data[67 + key_handle_len..].to_vec();

        let registration = U2fRegistration {
            key_handle,
            public_key,
            attestation_cert,
        };

        self.registrations
            .entry(user_id.to_string())
            .or_default()
            .push(registration.clone());

        Ok(registration)
    }

    /// Generate an authentication challenge for a registered user.
    pub fn generate_sign_challenge(&self, user_id: &str) -> Result<Vec<U2fSignRequest>> {
        let regs = self
            .registrations
            .get(user_id)
            .ok_or_else(|| AuthError::validation("No registrations found for user"))?;

        let challenge = generate_challenge()?;

        Ok(regs
            .iter()
            .map(|reg| U2fSignRequest {
                app_id: self.app_id.clone(),
                challenge: challenge.clone(),
                key_handle: reg.key_handle.clone(),
            })
            .collect())
    }

    /// Verify a U2F authentication response.
    ///
    /// The signature data contains:
    /// - 1 byte: user presence
    /// - 4 bytes: counter (big-endian)
    /// - remaining: ECDSA signature
    pub fn verify_authentication(
        &self,
        user_id: &str,
        request: &U2fSignRequest,
        response: &U2fSignResponse,
    ) -> Result<u32> {
        // Validate client data
        let client_data: U2fClientData = serde_json::from_slice(&response.client_data)
            .map_err(|e| AuthError::validation(format!("Invalid client data: {e}")))?;

        if client_data.typ != "navigator.id.getAssertion" {
            return Err(AuthError::validation(
                "Invalid client data type for authentication",
            ));
        }
        if client_data.challenge != request.challenge {
            return Err(AuthError::validation("Challenge mismatch"));
        }

        // Find matching registration
        let regs = self
            .registrations
            .get(user_id)
            .ok_or_else(|| AuthError::validation("No registrations found"))?;

        let _reg = regs
            .iter()
            .find(|r| r.key_handle == response.key_handle)
            .ok_or_else(|| AuthError::validation("Unknown key handle"))?;

        // Parse signature data
        if response.signature_data.len() < 5 {
            return Err(AuthError::validation("Signature data too short"));
        }

        let user_presence = response.signature_data[0];
        if user_presence & 0x01 == 0 {
            return Err(AuthError::validation("User presence not asserted"));
        }

        let counter = u32::from_be_bytes([
            response.signature_data[1],
            response.signature_data[2],
            response.signature_data[3],
            response.signature_data[4],
        ]);

        // Verify ECDSA P-256 signature over the signed data.
        // Per the U2F spec, the signed data is:
        //   application_parameter (32) | user_presence (1) | counter (4) | client_data_hash (32)
        let app_param = self.app_param();
        let client_data_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&response.client_data);
            hasher.finalize().into()
        };

        let mut signed_data = Vec::with_capacity(69);
        signed_data.extend_from_slice(&app_param);
        signed_data.push(user_presence);
        signed_data.extend_from_slice(&response.signature_data[1..5]);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = &response.signature_data[5..];
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &_reg.public_key,
        );
        public_key
            .verify(&signed_data, signature)
            .map_err(|_| AuthError::crypto("ECDSA P-256 signature verification failed"))?;

        Ok(counter)
    }

    /// Get all registrations for a user.
    pub fn get_registrations(&self, user_id: &str) -> Option<&Vec<U2fRegistration>> {
        self.registrations.get(user_id)
    }

    /// Remove a specific key handle registration.
    pub fn remove_registration(&mut self, user_id: &str, key_handle: &[u8]) -> bool {
        if let Some(regs) = self.registrations.get_mut(user_id) {
            let before = regs.len();
            regs.retain(|r| r.key_handle != key_handle);
            regs.len() < before
        } else {
            false
        }
    }

    /// Compute the application parameter (SHA-256 of app_id).
    pub fn app_param(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.app_id.as_bytes());
        hasher.finalize().into()
    }

    /// Get the U2F version string.
    pub fn version(&self) -> &'static str {
        U2F_VERSION
    }
}

/// Generate a cryptographically random challenge (32 bytes, base64url-encoded).
fn generate_challenge() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf)
        .map_err(|_| AuthError::crypto("Failed to generate challenge".to_string()))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u2f_manager_creation() {
        let mgr = U2fManager::new("https://example.com").unwrap();
        assert_eq!(mgr.app_id, "https://example.com");
        assert_eq!(mgr.version(), "U2F_V2");
    }

    #[test]
    fn test_empty_app_id_rejected() {
        assert!(U2fManager::new("").is_err());
    }

    #[test]
    fn test_registration_challenge_generation() {
        let mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();
        assert_eq!(req.app_id, "https://example.com");
        assert!(!req.challenge.is_empty());
    }

    #[test]
    fn test_challenge_uniqueness() {
        let mgr = U2fManager::new("https://example.com").unwrap();
        let c1 = mgr.generate_registration_challenge().unwrap();
        let c2 = mgr.generate_registration_challenge().unwrap();
        assert_ne!(c1.challenge, c2.challenge);
    }

    #[test]
    fn test_verify_registration_invalid_reserved_byte() {
        let mut mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();
        let client_data = serde_json::json!({
            "typ": "navigator.id.finishEnrollment",
            "challenge": req.challenge,
            "origin": "https://example.com"
        });
        let response = U2fRegistrationResponse {
            registration_data: vec![0x04; 100], // wrong reserved byte
            client_data: serde_json::to_vec(&client_data).unwrap(),
        };
        assert!(mgr.verify_registration("user1", &req, &response).is_err());
    }

    #[test]
    fn test_verify_registration_valid() {
        let mut mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();

        // Build minimal valid registration data
        let mut reg_data = vec![0x05]; // reserved
        reg_data.extend_from_slice(&[0xAA; 65]); // public key (65 bytes)
        reg_data.push(4); // key handle length
        reg_data.extend_from_slice(&[0xBB; 4]); // key handle
        reg_data.extend_from_slice(&[0xCC; 10]); // attestation cert stub

        let client_data = serde_json::json!({
            "typ": "navigator.id.finishEnrollment",
            "challenge": req.challenge,
            "origin": "https://example.com"
        });

        let response = U2fRegistrationResponse {
            registration_data: reg_data,
            client_data: serde_json::to_vec(&client_data).unwrap(),
        };

        let reg = mgr.verify_registration("user1", &req, &response).unwrap();
        assert_eq!(reg.key_handle, vec![0xBB; 4]);
        assert_eq!(reg.public_key.len(), 65);
        assert!(mgr.get_registrations("user1").is_some());
    }

    #[test]
    fn test_sign_challenge_no_registrations() {
        let mgr = U2fManager::new("https://example.com").unwrap();
        assert!(mgr.generate_sign_challenge("unknown").is_err());
    }

    #[test]
    fn test_verify_auth_user_presence() {
        let mut mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();

        // Register first
        let mut reg_data = vec![0x05];
        reg_data.extend_from_slice(&[0xAA; 65]);
        reg_data.push(4);
        reg_data.extend_from_slice(&[0xBB; 4]);
        reg_data.extend_from_slice(&[0xCC; 10]);

        let client_data = serde_json::json!({
            "typ": "navigator.id.finishEnrollment",
            "challenge": req.challenge,
            "origin": "https://example.com"
        });
        let reg_response = U2fRegistrationResponse {
            registration_data: reg_data,
            client_data: serde_json::to_vec(&client_data).unwrap(),
        };
        mgr.verify_registration("user1", &req, &reg_response)
            .unwrap();

        // Now test authentication
        let sign_reqs = mgr.generate_sign_challenge("user1").unwrap();
        let sign_req = &sign_reqs[0];

        // No user presence (byte 0 = 0x00)
        let mut sig_data = vec![0x00]; // no user presence
        sig_data.extend_from_slice(&[0, 0, 0, 1]); // counter=1
        sig_data.extend_from_slice(&[0xFF; 10]); // signature stub

        let auth_client_data = serde_json::json!({
            "typ": "navigator.id.getAssertion",
            "challenge": sign_req.challenge,
            "origin": "https://example.com"
        });
        let sign_response = U2fSignResponse {
            signature_data: sig_data,
            client_data: serde_json::to_vec(&auth_client_data).unwrap(),
            key_handle: vec![0xBB; 4],
        };

        assert!(
            mgr.verify_authentication("user1", sign_req, &sign_response)
                .is_err()
        );
    }

    #[test]
    fn test_verify_auth_success() {
        use ring::rand::SystemRandom;
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec(); // 65 bytes

        let mut mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();

        let mut reg_data = vec![0x05];
        reg_data.extend_from_slice(&public_key_bytes);
        reg_data.push(4);
        reg_data.extend_from_slice(&[0xBB; 4]);
        reg_data.extend_from_slice(&[0xCC; 10]);

        let client_data = serde_json::json!({
            "typ": "navigator.id.finishEnrollment",
            "challenge": req.challenge,
            "origin": "https://example.com"
        });
        let reg_resp = U2fRegistrationResponse {
            registration_data: reg_data,
            client_data: serde_json::to_vec(&client_data).unwrap(),
        };
        mgr.verify_registration("user1", &req, &reg_resp).unwrap();

        let sign_reqs = mgr.generate_sign_challenge("user1").unwrap();
        let sign_req = &sign_reqs[0];

        // Build the signed data the same way verify_authentication does
        let app_param = mgr.app_param();
        let auth_client = serde_json::json!({
            "typ": "navigator.id.getAssertion",
            "challenge": sign_req.challenge,
            "origin": "https://example.com"
        });
        let auth_client_bytes = serde_json::to_vec(&auth_client).unwrap();
        let client_data_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&auth_client_bytes);
            hasher.finalize().into()
        };

        let user_presence: u8 = 0x01;
        let counter_bytes: [u8; 4] = 5u32.to_be_bytes();

        let mut signed_data = Vec::with_capacity(69);
        signed_data.extend_from_slice(&app_param);
        signed_data.push(user_presence);
        signed_data.extend_from_slice(&counter_bytes);
        signed_data.extend_from_slice(&client_data_hash);

        let signature = key_pair.sign(&rng, &signed_data).unwrap();

        let mut sig_data = vec![user_presence];
        sig_data.extend_from_slice(&counter_bytes);
        sig_data.extend_from_slice(signature.as_ref());

        let sign_resp = U2fSignResponse {
            signature_data: sig_data,
            client_data: auth_client_bytes,
            key_handle: vec![0xBB; 4],
        };

        let counter = mgr
            .verify_authentication("user1", sign_req, &sign_resp)
            .unwrap();
        assert_eq!(counter, 5);
    }

    #[test]
    fn test_remove_registration() {
        let mut mgr = U2fManager::new("https://example.com").unwrap();
        let req = mgr.generate_registration_challenge().unwrap();

        let mut reg_data = vec![0x05];
        reg_data.extend_from_slice(&[0xAA; 65]);
        reg_data.push(4);
        reg_data.extend_from_slice(&[0xBB; 4]);
        reg_data.extend_from_slice(&[0xCC; 10]);

        let client_data = serde_json::json!({
            "typ": "navigator.id.finishEnrollment",
            "challenge": req.challenge,
            "origin": "https://example.com"
        });
        let resp = U2fRegistrationResponse {
            registration_data: reg_data,
            client_data: serde_json::to_vec(&client_data).unwrap(),
        };
        mgr.verify_registration("user1", &req, &resp).unwrap();

        assert!(mgr.remove_registration("user1", &[0xBB; 4]));
        assert_eq!(mgr.get_registrations("user1").unwrap().len(), 0);
    }

    #[test]
    fn test_app_param() {
        let mgr = U2fManager::new("https://example.com").unwrap();
        let param = mgr.app_param();
        assert_eq!(param.len(), 32);
        // Same app_id should yield same param
        let param2 = mgr.app_param();
        assert_eq!(param, param2);
    }
}
