//! Enhanced cryptography module providing modern algorithm alternatives.
//!
//! When the `enhanced-crypto` feature is enabled, this module exposes:
//!
//! - **ChaCha20-Poly1305** AEAD encryption (alternative to AES-256-GCM)
//! - **Ed25519** digital signatures (alternative to ECDSA/RSA)
//! - **X25519** Diffie-Hellman key agreement
//!
//! These algorithms offer excellent performance on platforms without
//! hardware AES acceleration and provide strong security margins.

use crate::errors::{AuthError, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

// ─── ChaCha20-Poly1305 AEAD ──────────────────────────────────────────

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

/// Encrypted data container (compatible with [`crate::storage::encryption::EncryptedData`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedEncryptedData {
    /// Base64-encoded ciphertext (includes 16-byte Poly1305 tag appended by the AEAD)
    pub data: String,
    /// Base64-encoded 12-byte nonce
    pub nonce: String,
    /// Algorithm identifier
    pub algorithm: String,
}

/// AEAD encryption manager backed by ChaCha20-Poly1305.
///
/// Drop-in alternative to [`crate::storage::encryption::StorageEncryption`]
/// for platforms that benefit from a non-AES cipher (no AES-NI required).
pub struct ChaChaEncryption {
    cipher: ChaCha20Poly1305,
}

impl ChaChaEncryption {
    /// Create from a 32-byte key.
    pub fn from_key(key_bytes: &[u8; 32]) -> Self {
        let key = chacha20poly1305::Key::from_slice(key_bytes);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    /// Create from a base64-encoded 32-byte key.
    pub fn from_base64_key(b64_key: &str) -> Result<Self> {
        let key_bytes = BASE64
            .decode(b64_key)
            .map_err(|_| AuthError::config("Invalid base64 in ChaCha20 encryption key"))?;
        if key_bytes.len() != 32 {
            return Err(AuthError::config(
                "ChaCha20-Poly1305 key must be 32 bytes (256 bits)",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        let result = Self::from_key(&arr);
        zeroize::Zeroize::zeroize(&mut arr);
        Ok(result)
    }

    /// Generate a new random 256-bit key (base64-encoded).
    pub fn generate_key() -> String {
        use rand::Rng;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        BASE64.encode(key)
    }

    /// Encrypt plaintext, returning an [`EnhancedEncryptedData`] envelope.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EnhancedEncryptedData> {
        use chacha20poly1305::Nonce;
        use rand::Rng;

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AuthError::internal(format!("ChaCha20-Poly1305 encrypt failed: {}", e)))?;

        Ok(EnhancedEncryptedData {
            data: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(nonce_bytes),
            algorithm: "ChaCha20-Poly1305".to_string(),
        })
    }

    /// Decrypt an [`EnhancedEncryptedData`] envelope.
    pub fn decrypt(&self, encrypted: &EnhancedEncryptedData) -> Result<Vec<u8>> {
        use chacha20poly1305::Nonce;

        if encrypted.algorithm != "ChaCha20-Poly1305" {
            return Err(AuthError::internal(format!(
                "Unsupported algorithm: {}",
                encrypted.algorithm
            )));
        }

        let ciphertext = BASE64
            .decode(&encrypted.data)
            .map_err(|_| AuthError::internal("Invalid base64 in encrypted data"))?;

        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|_| AuthError::internal("Invalid base64 in nonce"))?;

        if nonce_bytes.len() != 12 {
            return Err(AuthError::internal("Nonce must be 12 bytes"));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| AuthError::internal(format!("ChaCha20-Poly1305 decrypt failed: {}", e)))
    }
}

// ─── Ed25519 Signatures ──────────────────────────────────────────────

use ed25519_dalek::{Signer, Verifier};

/// Ed25519 signing key pair for token and message signing.
pub struct Ed25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Restore from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Export the 32-byte seed (private key material).
    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Export the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    /// Verify a signature against the embedded public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|e| AuthError::crypto(format!("Invalid Ed25519 signature: {}", e)))?;
        self.signing_key
            .verifying_key()
            .verify(message, &sig)
            .map_err(|_| AuthError::crypto("Ed25519 signature verification failed"))
    }
}

/// Verify an Ed25519 signature using a raw 32-byte public key.
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| AuthError::crypto(format!("Invalid Ed25519 public key: {}", e)))?;
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| AuthError::crypto(format!("Invalid Ed25519 signature: {}", e)))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| AuthError::crypto("Ed25519 signature verification failed"))
}

// ─── X25519 Key Agreement ────────────────────────────────────────────

/// X25519 ephemeral key pair for Diffie-Hellman key agreement.
///
/// Useful for establishing shared secrets in token encryption,
/// client-server key exchange, or forward-secret session keys.
pub struct X25519KeyPair {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        use rand_core::OsRng;
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Restore from a 32-byte private key.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the 32-byte public key for sharing with the peer.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform Diffie-Hellman with the peer's public key.
    ///
    /// Returns the 32-byte shared secret. Both sides derive the same value.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

// ─── Algorithm selection helper ──────────────────────────────────────

/// Available AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AeadAlgorithm {
    /// AES-256-GCM (hardware-accelerated on modern x86/ARM)
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305 (fast in software, constant-time by design)
    ChaCha20Poly1305,
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_round_trip() {
        let key = [42u8; 32];
        let enc = ChaChaEncryption::from_key(&key);
        let plaintext = b"Hello, AuthFramework!";

        let encrypted = enc.encrypt(plaintext).unwrap();
        assert_eq!(encrypted.algorithm, "ChaCha20-Poly1305");

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha_wrong_key_fails() {
        let enc1 = ChaChaEncryption::from_key(&[1u8; 32]);
        let enc2 = ChaChaEncryption::from_key(&[2u8; 32]);

        let encrypted = enc1.encrypt(b"secret").unwrap();
        assert!(enc2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_chacha_from_base64_key() {
        let b64 = ChaChaEncryption::generate_key();
        let enc = ChaChaEncryption::from_base64_key(&b64).unwrap();

        let encrypted = enc.encrypt(b"test data").unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn test_chacha_rejects_wrong_algorithm() {
        let enc = ChaChaEncryption::from_key(&[0u8; 32]);
        let mut data = enc.encrypt(b"x").unwrap();
        data.algorithm = "AES-256-GCM".to_string();
        assert!(enc.decrypt(&data).is_err());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = Ed25519KeyPair::generate();
        let message = b"Authenticate this message";

        let sig = kp.sign(message);
        assert_eq!(sig.len(), 64);

        kp.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_wrong_message_fails() {
        let kp = Ed25519KeyPair::generate();
        let sig = kp.sign(b"original");
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_ed25519_from_seed_deterministic() {
        let seed = [7u8; 32];
        let kp1 = Ed25519KeyPair::from_seed(&seed);
        let kp2 = Ed25519KeyPair::from_seed(&seed);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());

        let sig = kp1.sign(b"hello");
        kp2.verify(b"hello", &sig).unwrap();
    }

    #[test]
    fn test_ed25519_standalone_verify() {
        let kp = Ed25519KeyPair::generate();
        let pub_key = kp.public_key_bytes();
        let sig = kp.sign(b"data");
        ed25519_verify(&pub_key, b"data", &sig).unwrap();
    }

    #[test]
    fn test_x25519_key_agreement() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key_bytes());
        let bob_shared = bob.diffie_hellman(&alice.public_key_bytes());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_from_secret_bytes() {
        let kp1 = X25519KeyPair::generate();
        let secret = kp1.public_key_bytes(); // using public as seed for a different kp
        let kp_a = X25519KeyPair::from_secret_bytes(secret);
        let kp_b = X25519KeyPair::generate();

        let shared_a = kp_a.diffie_hellman(&kp_b.public_key_bytes());
        let shared_b = kp_b.diffie_hellman(&kp_a.public_key_bytes());
        assert_eq!(shared_a, shared_b);
    }
}
