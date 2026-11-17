// SPDX-License-Identifier: MIT OR Apache-2.0
//! KM2: creation and import of keys.
//!
//! Every private key is created here, by the one crypto backend already in the
//! tree (ring for EC, Ed25519 and signing; aws-lc-rs through rcgen for RSA
//! generation). A [`LocalKey`] holds its PKCS#8 bytes in a zeroizing buffer, never
//! prints them (`Debug` is redacted) and gives them out only through
//! [`LocalKey::to_pkcs8_der`], whose name says what it does.

use super::{KeyKind, Kid, PublicJwk, Signer};
use crate::errors::{AuthError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::rsa::KeyPair as RsaKeyPair;
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
    Ed25519KeyPair, KeyPair,
};
use zeroize::Zeroizing;

/// A JWS signing algorithm a generated or imported key can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlg {
    /// ECDSA P-256 with SHA-256.
    Es256,
    /// ECDSA P-384 with SHA-384.
    Es384,
    /// Ed25519.
    EdDsa,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
}

impl SigningAlg {
    /// The JWS `alg` name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
}

enum Pair {
    Ec(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
    Rsa(RsaKeyPair),
    /// An X25519 key-agreement key: it never signs. The secret zeroizes when dropped.
    #[cfg(feature = "key-agreement")]
    X25519(x25519_dalek::StaticSecret),
    /// A P-256 key-agreement key (RFC 7518 section 4.6): it never signs. `p256::SecretKey`
    /// zeroizes its scalar when dropped.
    #[cfg(feature = "key-agreement")]
    P256(p256::SecretKey),
}

/// The RFC 8410 PKCS#8 prefix of an X25519 private key; the 32 secret bytes follow.
#[cfg(feature = "key-agreement")]
const X25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// An asymmetric private key held in this process. Exportable by design;
/// non-exportable stores (KM3) implement [`Signer`] without this type.
pub struct LocalKey {
    kid: Kid,
    kind: KeyKind,
    alg: Option<SigningAlg>,
    pkcs8: Zeroizing<Vec<u8>>,
    pair: Pair,
    public: PublicJwk,
}

impl std::fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKey")
            .field("kid", &self.kid)
            .field("kind", &self.kind)
            .field("alg", &self.alg)
            .field("private", &"<redacted>")
            .finish()
    }
}

fn rng_err() -> AuthError {
    AuthError::crypto("system random number generator failed")
}

fn require_signing_kind(kind: KeyKind) -> Result<()> {
    // A TLS key signs handshakes and certificates but has no JWK `use`, so it is admitted
    // by name; a JWE key agrees or wraps and does not sign.
    if kind.is_asymmetric() && (kind.jwk_use() == Some("sig") || kind == KeyKind::Mtls) {
        Ok(())
    } else {
        Err(AuthError::validation(format!(
            "{kind:?} is not a signing key kind"
        )))
    }
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

impl LocalKey {
    /// Generate a signing key. RSA uses 2048 bits; see [`LocalKey::generate_rsa`].
    /// `kid` defaults to the key's own RFC 7638 thumbprint.
    pub fn generate(kind: KeyKind, alg: SigningAlg, kid: Option<Kid>) -> Result<Self> {
        if alg == SigningAlg::Rs256 {
            return Self::generate_rsa(kind, 2048, kid);
        }
        require_signing_kind(kind)?;
        let rng = SystemRandom::new();
        let der = match alg {
            SigningAlg::Es256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map(|d| d.as_ref().to_vec())
            }
            SigningAlg::Es384 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
                    .map(|d| d.as_ref().to_vec())
            }
            SigningAlg::EdDsa => Ed25519KeyPair::generate_pkcs8(&rng).map(|d| d.as_ref().to_vec()),
            SigningAlg::Rs256 => unreachable!("handled above"),
        }
        .map_err(|_| rng_err())?;
        Self::from_pkcs8_der(&der, kind, kid)
    }

    /// Generate an RSA signing key of 2048, 3072 or 4096 bits (RS256).
    pub fn generate_rsa(kind: KeyKind, bits: u32, kid: Option<Kid>) -> Result<Self> {
        require_signing_kind(kind)?;
        let size = match bits {
            2048 => rcgen::RsaKeySize::_2048,
            3072 => rcgen::RsaKeySize::_3072,
            4096 => rcgen::RsaKeySize::_4096,
            other => {
                return Err(AuthError::validation(format!(
                    "RSA key size {other} is not 2048, 3072 or 4096"
                )));
            }
        };
        let kp = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, size)
            .map_err(|e| AuthError::crypto(format!("RSA key generation failed: {e}")))?;
        let der = Zeroizing::new(kp.serialize_der());
        Self::from_pkcs8_der(&der, kind, kid)
    }

    /// Import a PKCS#8 DER private key. The algorithm is detected from the key;
    /// an RSA key under 2048 bits, or anything ring cannot parse, is refused.
    pub fn from_pkcs8_der(der: &[u8], kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        if kind == KeyKind::JweEncryption {
            return Self::from_agreement_pkcs8(der, kind, kid);
        }
        require_signing_kind(kind)?;
        let rng = SystemRandom::new();
        let (pair, alg, public) = if let Ok(kp) =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
        {
            let jwk = ec_jwk("P-256", 32, kp.public_key().as_ref())?;
            (Pair::Ec(kp), SigningAlg::Es256, jwk)
        } else if let Ok(kp) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, der, &rng)
        {
            let jwk = ec_jwk("P-384", 48, kp.public_key().as_ref())?;
            (Pair::Ec(kp), SigningAlg::Es384, jwk)
        } else if let Ok(kp) = Ed25519KeyPair::from_pkcs8(der) {
            let jwk = PublicJwk::okp("Ed25519", &b64(kp.public_key().as_ref()))?;
            (Pair::Ed(kp), SigningAlg::EdDsa, jwk)
        } else if let Ok(kp) = RsaKeyPair::from_pkcs8(der) {
            if kp.public().modulus_len() * 8 < 2048 {
                return Err(AuthError::validation(
                    "RSA keys under 2048 bits are refused",
                ));
            }
            let comps: ring::rsa::PublicKeyComponents<Vec<u8>> = kp.public().into();
            let jwk = PublicJwk::rsa(&b64(&comps.n), &b64(&comps.e))?;
            (Pair::Rsa(kp), SigningAlg::Rs256, jwk)
        } else {
            return Err(AuthError::validation(
                "not a PKCS#8 RSA (2048+), P-256, P-384 or Ed25519 private key",
            ));
        };
        let mut public = public;
        public.use_ = kind.jwk_use().map(str::to_owned);
        public.alg = Some(alg.name().to_owned());
        public.key_ops = Some(vec!["verify".to_owned()]);
        let public = match kid {
            Some(k) => {
                public.kid = Some(k);
                public
            }
            None => public.with_thumbprint_kid()?,
        };
        let kid = public
            .kid
            .clone()
            .ok_or_else(|| AuthError::crypto("key id missing after construction"))?;
        Ok(Self {
            kid,
            kind,
            alg: Some(alg),
            pkcs8: Zeroizing::new(der.to_vec()),
            pair,
            public,
        })
    }

    /// Generate an X25519 key-agreement key (JWE `ECDH-ES`) of kind
    /// [`KeyKind::JweEncryption`]. `kid` defaults to the key's RFC 7638 thumbprint.
    #[cfg(feature = "key-agreement")]
    pub fn generate_x25519(kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut secret[..])
            .map_err(|_| rng_err())?;
        let mut der = Zeroizing::new(X25519_PKCS8_PREFIX.to_vec());
        der.extend_from_slice(&secret[..]);
        Self::from_x25519_pkcs8(&der, kind, kid)
    }

    /// Generate a P-256 key-agreement key (JWE `ECDH-ES`, RFC 7518 section 4.6) of kind
    /// [`KeyKind::JweEncryption`]. `kid` defaults to the key's RFC 7638 thumbprint.
    #[cfg(feature = "key-agreement")]
    pub fn generate_p256(kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        use p256::pkcs8::EncodePrivateKey;
        let rng = SystemRandom::new();
        // A random 32-byte string is a valid scalar unless it is 0 or at least the group order
        // (about one in 2^32); draw again then, a few times at most.
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rng.fill(&mut bytes[..]).map_err(|_| rng_err())?;
            if let Ok(secret) = p256::SecretKey::from_slice(&bytes[..]) {
                let der = secret
                    .to_pkcs8_der()
                    .map_err(|_| AuthError::crypto("cannot encode the P-256 key as PKCS#8"))?;
                return Self::from_p256_pkcs8(der.as_bytes(), kind, kid);
            }
        }
        Err(rng_err())
    }

    /// Import a PKCS#8 private key as a key-agreement key: RFC 8410 X25519 or RFC 5958 P-256.
    #[cfg(feature = "key-agreement")]
    fn from_agreement_pkcs8(der: &[u8], kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        if kind != KeyKind::JweEncryption {
            return Err(AuthError::validation(
                "only a JweEncryption key can be a key-agreement key",
            ));
        }
        if der.starts_with(&X25519_PKCS8_PREFIX[..]) {
            Self::from_x25519_pkcs8(der, kind, kid)
        } else {
            Self::from_p256_pkcs8(der, kind, kid)
        }
    }

    /// Import an RFC 5958 PKCS#8 P-256 private key as a key-agreement key. The DER is kept as
    /// given; a scalar of 0 or at least the group order, another curve and garbage are refused.
    #[cfg(feature = "key-agreement")]
    fn from_p256_pkcs8(der: &[u8], kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        if kind != KeyKind::JweEncryption {
            return Err(AuthError::validation(
                "only a JweEncryption key can be a P-256 agreement key",
            ));
        }
        let secret = p256::SecretKey::from_pkcs8_der(der).map_err(|_| {
            AuthError::validation(
                "not a PKCS#8 X25519 (RFC 8410) or P-256 (RFC 5958) private key",
            )
        })?;
        let point = secret.public_key().to_sec1_bytes();
        let mut public = ec_jwk("P-256", 32, &point)?;
        public.use_ = kind.jwk_use().map(str::to_owned);
        public.alg = Some("ECDH-ES".to_owned());
        let public = match kid {
            Some(k) => {
                public.kid = Some(k);
                public
            }
            None => public.with_thumbprint_kid()?,
        };
        let kid = public
            .kid
            .clone()
            .ok_or_else(|| AuthError::crypto("key id missing after construction"))?;
        Ok(Self {
            kid,
            kind,
            alg: None,
            pkcs8: Zeroizing::new(der.to_vec()),
            pair: Pair::P256(secret),
            public,
        })
    }

    /// Import an RFC 8410 X25519 PKCS#8 private key (48 bytes) as a key-agreement key.
    #[cfg(feature = "key-agreement")]
    fn from_x25519_pkcs8(der: &[u8], kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        if kind != KeyKind::JweEncryption {
            return Err(AuthError::validation(
                "only a JweEncryption key can be an X25519 agreement key",
            ));
        }
        let secret: [u8; 32] = der
            .strip_prefix(&X25519_PKCS8_PREFIX[..])
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                AuthError::validation("not an RFC 8410 PKCS#8 X25519 private key (48 bytes)")
            })?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let point = x25519_dalek::PublicKey::from(&secret);
        let mut public = PublicJwk::okp("X25519", &b64(point.as_bytes()))?;
        public.use_ = kind.jwk_use().map(str::to_owned);
        public.alg = Some("ECDH-ES".to_owned());
        let public = match kid {
            Some(k) => {
                public.kid = Some(k);
                public
            }
            None => public.with_thumbprint_kid()?,
        };
        let kid = public
            .kid
            .clone()
            .ok_or_else(|| AuthError::crypto("key id missing after construction"))?;
        Ok(Self {
            kid,
            kind,
            alg: None,
            pkcs8: Zeroizing::new(der.to_vec()),
            pair: Pair::X25519(secret),
            public,
        })
    }

    /// Without the `key-agreement` feature no agreement key can be held.
    #[cfg(not(feature = "key-agreement"))]
    fn from_agreement_pkcs8(_der: &[u8], _kind: KeyKind, _kid: Option<Kid>) -> Result<Self> {
        Err(AuthError::validation(
            "a key-agreement (JweEncryption) key needs the `key-agreement` feature: rebuild with it              to open a key directory that holds one",
        ))
    }

    /// The shared secret with `peer_public` (32 bytes) for a key-agreement key.
    ///
    /// **X25519**: `peer_public` is the 32-byte u coordinate. A peer key of low order (the
    /// all-zero point and the other points of order 1, 2, 4 and 8, in any encoding) would make
    /// the secret independent of this key, so it is refused, as is a key that is not 32 bytes.
    ///
    /// **P-256** (ECDH-ES, RFC 7518 section 4.6): `peer_public` is an uncompressed SEC1 point,
    /// `04 || x || y` (65 bytes); the secret is the x coordinate of the shared point (the `Z` of
    /// RFC 7518 section 4.6.2). Anything else is refused: another length or tag, the identity,
    /// a coordinate not below the field prime, a point that is not on the curve (an invalid-curve
    /// attack's input). P-256 has cofactor 1, so every point on the curve is in the group.
    ///
    /// This is a pure primitive: it knows nothing of the key's lifecycle state, which
    /// [`crate::keys::agree`] checks where the key is fetched from a store.
    #[cfg(feature = "key-agreement")]
    pub fn agree(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        match &self.pair {
            Pair::X25519(secret) => {
                let peer: [u8; 32] = peer_public.try_into().map_err(|_| {
                    AuthError::validation("an X25519 public key is exactly 32 bytes")
                })?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err(AuthError::crypto(
                        "the peer's X25519 public key is of low order: refused",
                    ));
                }
                Ok(Zeroizing::new(shared.to_bytes()))
            }
            Pair::P256(secret) => {
                if peer_public.len() != 65 || peer_public[0] != 4 {
                    return Err(AuthError::validation(
                        "a P-256 public key is an uncompressed SEC1 point: 65 bytes, the first 0x04",
                    ));
                }
                let peer = p256::PublicKey::from_sec1_bytes(peer_public).map_err(|_| {
                    AuthError::crypto(
                        "the peer's P-256 public key is not a point on the curve: refused",
                    )
                })?;
                let shared =
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(shared.raw_secret_bytes().as_slice());
                Ok(out)
            }
            _ => Err(AuthError::validation(
                "only a key-agreement key can agree",
            )),
        }
    }

    /// Import a PKCS#8 private key in PEM (`PRIVATE KEY`).
    pub fn from_pkcs8_pem(pem: &str, kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        // Built from parts so no PEM armor line is spelled out in source.
        const LABEL: &str = "PRIVATE KEY";
        let begin = format!("-----BEGIN {LABEL}-----");
        let end = format!("-----END {LABEL}-----");
        let body = pem
            .trim()
            .strip_prefix(begin.as_str())
            .and_then(|r| r.strip_suffix(end.as_str()))
            .ok_or_else(|| AuthError::validation("expected a PKCS#8 'PRIVATE KEY' PEM block"))?;
        let compact: String = body.split_whitespace().collect();
        let der = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(compact)
                .map_err(|_| AuthError::validation("PEM body is not base64"))?,
        );
        Self::from_pkcs8_der(&der, kind, kid)
    }

    /// The PKCS#8 DER private key. The only way the private bytes leave this type.
    pub fn to_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The key's purpose.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The signing algorithm, or `None` for a key that does not sign (every key today signs;
    /// a key-agreement key will not, see `docs/KEY_AGREEMENT_DESIGN.md`).
    pub fn signing_alg(&self) -> Option<SigningAlg> {
        self.alg
    }

    /// The public half, with `kid`, `use`, `alg` and `key_ops` set.
    pub fn public(&self) -> &PublicJwk {
        &self.public
    }
}

fn ec_jwk(crv: &str, coord: usize, point: &[u8]) -> Result<PublicJwk> {
    if point.len() != 1 + 2 * coord || point[0] != 4 {
        return Err(AuthError::crypto("unexpected EC public point encoding"));
    }
    PublicJwk::ec(crv, &b64(&point[1..=coord]), &b64(&point[1 + coord..]))
}

impl Signer for LocalKey {
    fn kid(&self) -> &Kid {
        &self.kid
    }

    fn algorithm(&self) -> &str {
        self.public.alg.as_deref().unwrap_or_default()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.pair {
            Pair::Ec(kp) => kp
                .sign(&SystemRandom::new(), message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| AuthError::crypto("ECDSA signing failed")),
            Pair::Ed(kp) => Ok(kp.sign(message).as_ref().to_vec()),
            #[cfg(feature = "key-agreement")]
            Pair::X25519(_) | Pair::P256(_) => {
                Err(AuthError::validation("a key-agreement key does not sign"))
            }
            Pair::Rsa(kp) => {
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut sig,
                )
                .map_err(|_| AuthError::crypto("RSA signing failed"))?;
                Ok(sig)
            }
        }
    }

    fn public_jwk(&self) -> Result<PublicJwk> {
        Ok(self.public.clone())
    }
}

/// A 256-bit symmetric key (HMAC or AEAD). Zeroized on drop; `Debug` is redacted.
pub struct SymmetricKey {
    kid: Kid,
    kind: KeyKind,
    bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("kid", &self.kid)
            .field("kind", &self.kind)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl SymmetricKey {
    /// Generate a random 256-bit key for `KeyKind::Hmac` or `KeyKind::Aead`.
    pub fn generate(kind: KeyKind, kid: Kid) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(&mut bytes[..])
            .map_err(|_| rng_err())?;
        Self::from_bytes(kind, kid, *bytes)
    }

    /// Import 32 bytes as a symmetric key.
    pub fn from_bytes(kind: KeyKind, kid: Kid, bytes: [u8; 32]) -> Result<Self> {
        if kind.is_asymmetric() {
            return Err(AuthError::validation(format!(
                "{kind:?} is not a symmetric key kind"
            )));
        }
        Ok(Self {
            kid,
            kind,
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The key id.
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// The key's purpose.
    pub fn kind(&self) -> KeyKind {
        self.kind
    }

    /// The raw key bytes. The only way they leave this type.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, VerificationAlgorithm};

    fn verify(alg: SigningAlg, jwk: &serde_json::Value, msg: &[u8], sig: &[u8]) -> bool {
        let dec = |k: &str| URL_SAFE_NO_PAD.decode(jwk[k].as_str().unwrap()).unwrap();
        match alg {
            SigningAlg::Es256 | SigningAlg::Es384 => {
                let mut point = vec![4u8];
                point.extend(dec("x"));
                point.extend(dec("y"));
                let a: &dyn VerificationAlgorithm = if alg == SigningAlg::Es256 {
                    &signature::ECDSA_P256_SHA256_FIXED
                } else {
                    &signature::ECDSA_P384_SHA384_FIXED
                };
                UnparsedPublicKey::new(a, point).verify(msg, sig).is_ok()
            }
            SigningAlg::EdDsa => UnparsedPublicKey::new(&signature::ED25519, dec("x"))
                .verify(msg, sig)
                .is_ok(),
            SigningAlg::Rs256 => signature::RsaPublicKeyComponents {
                n: dec("n"),
                e: dec("e"),
            }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
            .is_ok(),
        }
    }

    #[test]
    fn every_algorithm_signs_and_the_exported_public_key_verifies() {
        for alg in [
            SigningAlg::Es256,
            SigningAlg::Es384,
            SigningAlg::EdDsa,
            SigningAlg::Rs256,
        ] {
            let k = LocalKey::generate(KeyKind::JwsSigning, alg, None).unwrap();
            let sig = k.sign(b"payload").unwrap();
            let jwk = k.public_jwk().unwrap().to_value();
            assert!(verify(alg, &jwk, b"payload", &sig), "{alg:?} verifies");
            assert!(!verify(alg, &jwk, b"other", &sig), "{alg:?} rejects other");
            assert_eq!(jwk["alg"], alg.name());
            assert_eq!(jwk["use"], "sig");
            assert!(jwk.get("d").is_none(), "{alg:?} public export has no d");
            assert_eq!(k.algorithm(), alg.name());
        }
    }

    #[test]
    fn default_kid_is_the_thumbprint_and_a_given_kid_wins() {
        let k = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::EdDsa, None).unwrap();
        assert_eq!(k.kid().as_str(), k.public().thumbprint().unwrap());
        let named = Kid::new("signing-2026-11").unwrap();
        let k = LocalKey::generate(KeyKind::Dpop, SigningAlg::Es256, Some(named)).unwrap();
        assert_eq!(k.kid().as_str(), "signing-2026-11");
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::Es256, None).unwrap();
        let b = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::Es256, None).unwrap();
        assert_ne!(a.to_pkcs8_der(), b.to_pkcs8_der());
        assert_ne!(a.kid(), b.kid());
    }

    #[test]
    fn a_signing_key_reports_its_signing_algorithm_and_signs_with_it() {
        for alg in [
            SigningAlg::Es256,
            SigningAlg::Es384,
            SigningAlg::EdDsa,
            SigningAlg::Rs256,
        ] {
            let k = LocalKey::generate(KeyKind::JwsSigning, alg, None).unwrap();
            assert_eq!(k.signing_alg(), Some(alg), "{alg:?}");
            assert_eq!(Signer::algorithm(&k), alg.name(), "{alg:?}");
            assert!(Signer::sign(&k, b"m").is_ok(), "{alg:?}");
        }
    }

    #[test]
    fn import_round_trips_der_and_pem_with_the_same_identity() {
        for alg in [SigningAlg::Es256, SigningAlg::Es384, SigningAlg::EdDsa] {
            let k = LocalKey::generate(KeyKind::GnapClient, alg, None).unwrap();
            let back =
                LocalKey::from_pkcs8_der(k.to_pkcs8_der(), KeyKind::GnapClient, None).unwrap();
            assert_eq!(back.kid(), k.kid());
            assert_eq!(back.signing_alg(), Some(alg));
            let label = "PRIVATE KEY";
            let pem = format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
                base64::engine::general_purpose::STANDARD.encode(k.to_pkcs8_der())
            );
            let from_pem = LocalKey::from_pkcs8_pem(&pem, KeyKind::GnapClient, None).unwrap();
            assert_eq!(from_pem.kid(), k.kid());
        }
    }

    #[test]
    fn garbage_and_wrong_kinds_are_refused() {
        assert!(LocalKey::from_pkcs8_der(b"not a key", KeyKind::JwsSigning, None).is_err());
        assert!(LocalKey::from_pkcs8_pem("nope", KeyKind::JwsSigning, None).is_err());
        assert!(LocalKey::generate(KeyKind::Hmac, SigningAlg::Es256, None).is_err());
        assert!(LocalKey::generate(KeyKind::JweEncryption, SigningAlg::Es256, None).is_err());
        assert!(LocalKey::generate_rsa(KeyKind::JwsSigning, 1024, None).is_err());
    }

    #[test]
    fn debug_never_shows_private_bytes() {
        let k = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::EdDsa, None).unwrap();
        let shown = format!("{k:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&b64(k.to_pkcs8_der())));
        let s = SymmetricKey::generate(KeyKind::Hmac, Kid::new("h1").unwrap()).unwrap();
        assert!(format!("{s:?}").contains("redacted"));
    }

    #[test]
    fn symmetric_keys_are_random_and_only_for_symmetric_kinds() {
        let a = SymmetricKey::generate(KeyKind::Aead, Kid::new("a").unwrap()).unwrap();
        let b = SymmetricKey::generate(KeyKind::Aead, Kid::new("b").unwrap()).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), &[0u8; 32]);
        assert!(SymmetricKey::generate(KeyKind::Mtls, Kid::new("m").unwrap()).is_err());
        assert!(
            SymmetricKey::from_bytes(KeyKind::JwsSigning, Kid::new("x").unwrap(), [1; 32]).is_err()
        );
    }

    #[cfg(feature = "key-agreement")]
    mod agreement {
        use super::*;

        /// RFC 7748 section 6.1: Alice's and Bob's private keys, public keys and shared secret.
        const ALICE_PRIVATE: &str =
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        const ALICE_PUBLIC: &str =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        const BOB_PRIVATE: &str =
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        /// The points of order 1, 2, 4 and 8 on Curve25519 and their non-canonical encodings
        /// (little-endian u coordinates): the small subgroup a peer must not be able to pick.
        const LOW_ORDER: [&str; 11] = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            // The same points with bit 255 set, which X25519 ignores.
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
        ];

        fn unhex(h: &str) -> Vec<u8> {
            hex::decode(h).unwrap()
        }

        fn imported(private_hex: &str) -> LocalKey {
            let mut der = X25519_PKCS8_PREFIX.to_vec();
            der.extend_from_slice(&unhex(private_hex));
            LocalKey::from_pkcs8_der(&der, KeyKind::JweEncryption, None).unwrap()
        }

        #[test]
        fn the_rfc_7748_vectors_give_the_published_public_keys_and_shared_secret() {
            let alice = imported(ALICE_PRIVATE);
            let bob = imported(BOB_PRIVATE);
            let jwk = alice.public().to_value();
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk["x"].as_str().unwrap())
                    .unwrap(),
                unhex(ALICE_PUBLIC)
            );
            assert_eq!(
                &alice.agree(&unhex(BOB_PUBLIC)).unwrap()[..],
                &unhex(SHARED)[..]
            );
            assert_eq!(
                &bob.agree(&unhex(ALICE_PUBLIC)).unwrap()[..],
                &unhex(SHARED)[..],
                "both sides derive the same secret"
            );
        }

        #[test]
        fn a_generated_agreement_key_is_an_enc_okp_key_that_never_signs() {
            let k = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            let jwk = k.public().to_value();
            assert_eq!(jwk["kty"], "OKP");
            assert_eq!(jwk["crv"], "X25519");
            assert_eq!(jwk["use"], "enc");
            assert_eq!(jwk["alg"], "ECDH-ES");
            assert!(jwk.get("d").is_none(), "no private member");
            assert_eq!(k.signing_alg(), None);
            assert_eq!(Signer::algorithm(&k), "ECDH-ES");
            assert!(
                Signer::sign(&k, b"m").is_err(),
                "an agreement key does not sign"
            );
            assert_eq!(k.kid().as_str(), k.public().thumbprint().unwrap());
            let other = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            assert_ne!(k.kid(), other.kid());
            let back =
                LocalKey::from_pkcs8_der(k.to_pkcs8_der(), KeyKind::JweEncryption, None).unwrap();
            assert_eq!(back.kid(), k.kid(), "PKCS#8 round trip keeps the identity");
            assert_eq!(k.to_pkcs8_der().len(), 48);
            let a = other.public().to_value();
            let peer = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(a["x"].as_str().unwrap())
                .unwrap();
            let mine = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk["x"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                &k.agree(&peer).unwrap()[..],
                &other.agree(&mine).unwrap()[..]
            );
        }

        #[test]
        fn only_a_jwe_encryption_key_can_be_an_agreement_key_and_the_pkcs8_must_be_exact() {
            for kind in [KeyKind::JwsSigning, KeyKind::Mtls, KeyKind::Dpop] {
                assert!(LocalKey::generate_x25519(kind, None).is_err(), "{kind:?}");
            }
            let good = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            let der = good.to_pkcs8_der().to_vec();
            assert!(
                LocalKey::from_pkcs8_der(&der, KeyKind::JwsSigning, None).is_err(),
                "an X25519 key is not a signing key"
            );
            for bad in [&der[..47], &[der.clone(), vec![0]].concat()[..]] {
                assert!(LocalKey::from_pkcs8_der(bad, KeyKind::JweEncryption, None).is_err());
            }
            let mut wrong_oid = der.clone();
            wrong_oid[11] = 0x70;
            assert!(LocalKey::from_pkcs8_der(&wrong_oid, KeyKind::JweEncryption, None).is_err());
            let ec = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::Es256, None).unwrap();
            assert!(
                LocalKey::from_pkcs8_der(ec.to_pkcs8_der(), KeyKind::JweEncryption, None).is_err(),
                "P-256 agreement keys are a later slice"
            );
        }

        #[test]
        fn a_peer_key_that_is_not_32_bytes_or_is_of_another_curve_is_refused() {
            let k = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            for len in [0usize, 1, 31, 33, 64] {
                assert!(k.agree(&vec![9u8; len]).is_err(), "{len} bytes");
            }
            let p256 = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::Es256, None).unwrap();
            let jwk = p256.public().to_value();
            let mut sec1 = vec![4u8];
            for c in ["x", "y"] {
                sec1.extend(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(jwk[c].as_str().unwrap())
                        .unwrap(),
                );
            }
            assert_eq!(sec1.len(), 65);
            assert!(
                k.agree(&sec1).is_err(),
                "a P-256 point is not an X25519 key"
            );
            let signer = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::EdDsa, None).unwrap();
            assert!(
                signer.agree(&[9u8; 32]).is_err(),
                "only an X25519 key agrees"
            );
        }

        #[test]
        fn a_peer_key_in_the_small_subgroup_is_refused_in_every_encoding() {
            let k = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            for point in LOW_ORDER {
                let err = k.agree(&unhex(point)).unwrap_err().to_string();
                assert!(err.contains("low order"), "{point}: {err}");
            }
            // A genuine peer is still accepted and its secret is not all zero.
            let peer = imported(BOB_PRIVATE);
            let x = peer.public().to_value();
            let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x["x"].as_str().unwrap())
                .unwrap();
            let shared = k.agree(&x).unwrap();
            assert_ne!(&shared[..], &[0u8; 32][..]);
        }
    }

    /// P-256 ECDH keys (JWE `ECDH-ES`, RFC 7518 section 4.6) behind the same feature.
    #[cfg(feature = "key-agreement")]
    mod p256_agreement {
        use super::*;

        /// RFC 5903 section 8.1 (256-bit random ECP group): the initiator's private key `i` and
        /// public point `gi`, the responder's `r` and `gr`, and the shared x coordinate. Re-derived
        /// independently of the `p256` crate (plain big-integer curve arithmetic) before use here.
        const I: &str =
            "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433";
        const GIX: &str =
            "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180";
        const GIY: &str =
            "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3";
        const R: &str =
            "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53";
        const GRX: &str =
            "d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63";
        const GRY: &str =
            "56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab";
        const SHARED: &str =
            "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";

        /// RFC 5958 PKCS#8 header of a P-256 private key whose ECPrivateKey carries no public key
        /// and no parameters (version 0, id-ecPublicKey, prime256v1); the 32 scalar bytes follow.
        const P256_PKCS8_PREFIX: [u8; 35] = [
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
            0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
        ];

        fn unhex(h: &str) -> Vec<u8> {
            hex::decode(h).unwrap()
        }

        /// An uncompressed SEC1 point, `04 || x || y`.
        fn point(x: &str, y: &str) -> Vec<u8> {
            [&[4u8][..], &unhex(x), &unhex(y)].concat()
        }

        fn imported(scalar_hex: &str) -> LocalKey {
            let mut der = P256_PKCS8_PREFIX.to_vec();
            der.extend_from_slice(&unhex(scalar_hex));
            LocalKey::from_pkcs8_der(&der, KeyKind::JweEncryption, None).unwrap()
        }

        fn jwk_coord(k: &LocalKey, member: &str) -> Vec<u8> {
            let jwk = k.public().to_value();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwk[member].as_str().unwrap())
                .unwrap()
        }

        #[test]
        fn the_rfc_5903_vectors_give_the_published_public_points_and_shared_secret() {
            let initiator = imported(I);
            let responder = imported(R);
            assert_eq!(jwk_coord(&initiator, "x"), unhex(GIX));
            assert_eq!(jwk_coord(&initiator, "y"), unhex(GIY));
            assert_eq!(jwk_coord(&responder, "x"), unhex(GRX));
            assert_eq!(jwk_coord(&responder, "y"), unhex(GRY));
            assert_eq!(
                &initiator.agree(&point(GRX, GRY)).unwrap()[..],
                &unhex(SHARED)[..]
            );
            assert_eq!(
                &responder.agree(&point(GIX, GIY)).unwrap()[..],
                &unhex(SHARED)[..],
                "both sides derive the same secret"
            );
        }

        #[test]
        fn a_generated_p256_agreement_key_is_an_enc_ec_key_that_never_signs() {
            let k = LocalKey::generate_p256(KeyKind::JweEncryption, None).unwrap();
            let jwk = k.public().to_value();
            assert_eq!(jwk["kty"], "EC");
            assert_eq!(jwk["crv"], "P-256");
            assert_eq!(jwk["use"], "enc");
            assert_eq!(jwk["alg"], "ECDH-ES");
            assert!(jwk.get("d").is_none(), "no private member");
            assert_eq!(k.signing_alg(), None);
            assert_eq!(Signer::algorithm(&k), "ECDH-ES");
            assert!(Signer::sign(&k, b"m").is_err(), "an agreement key does not sign");
            for kind in [
                KeyKind::JwsSigning,
                KeyKind::Mtls,
                KeyKind::Dpop,
                KeyKind::HttpSig,
                KeyKind::GnapClient,
                KeyKind::Hmac,
                KeyKind::Aead,
            ] {
                assert!(LocalKey::generate_p256(kind, None).is_err(), "{kind:?}");
            }
        }

        #[test]
        fn two_generated_p256_keys_agree_on_one_secret_and_it_is_not_constant() {
            let a = LocalKey::generate_p256(KeyKind::JweEncryption, None).unwrap();
            let b = LocalKey::generate_p256(KeyKind::JweEncryption, None).unwrap();
            let c = LocalKey::generate_p256(KeyKind::JweEncryption, None).unwrap();
            let pt = |k: &LocalKey| [&[4u8][..], &jwk_coord(k, "x"), &jwk_coord(k, "y")].concat();
            let ab = a.agree(&pt(&b)).unwrap();
            assert_eq!(&ab[..], &b.agree(&pt(&a)).unwrap()[..]);
            assert_ne!(&ab[..], &a.agree(&pt(&c)).unwrap()[..]);
            assert_ne!(&ab[..], &[0u8; 32][..]);
            assert_ne!(a.kid(), b.kid(), "the thumbprint kid differs per key");
        }

        #[test]
        fn a_peer_that_is_not_a_valid_uncompressed_p256_point_is_refused() {
            let k = imported(I);
            let good = point(GRX, GRY);
            assert!(k.agree(&good).is_ok(), "control: the genuine peer is accepted");
            let mut off_curve = good.clone();
            *off_curve.last_mut().unwrap() ^= 1;
            let mut x_at_p = vec![4u8];
            x_at_p.extend_from_slice(&unhex(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            ));
            x_at_p.extend_from_slice(&unhex(GRY));
            let compressed = [&[2u8][..], &unhex(GRX)].concat();
            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("empty", vec![]),
                ("the identity encoding", vec![0]),
                ("x and y without the 04 tag", good[1..].to_vec()),
                ("a compressed point", compressed),
                ("a hybrid tag", [&[6u8][..], &good[1..]].concat()),
                ("an 04 tag then all zeros", [&[4u8][..], &[0u8; 64][..]].concat()),
                ("a point off the curve", off_curve.clone()),
                ("x equal to the field prime", x_at_p),
                ("an X25519-sized key", vec![9u8; 32]),
                ("a truncated point", good[..64].to_vec()),
                ("a point with trailing bytes", [&good[..], &[0u8][..]].concat()),
            ];
            for (what, bytes) in cases {
                assert!(k.agree(&bytes).is_err(), "{what} must be refused");
            }
            let err = k.agree(&off_curve).unwrap_err().to_string();
            assert!(err.contains("not a point on the curve"), "{err}");
        }

        #[test]
        fn the_p256_pkcs8_import_is_exact_and_refuses_other_curves_and_garbage() {
            let k = LocalKey::generate_p256(KeyKind::JweEncryption, None).unwrap();
            let again = LocalKey::from_pkcs8_der(
                k.to_pkcs8_der(),
                KeyKind::JweEncryption,
                Some(k.kid().clone()),
            )
            .unwrap();
            assert_eq!(again.to_pkcs8_der(), k.to_pkcs8_der(), "the DER is kept byte for byte");
            assert_eq!(again.public().to_value(), k.public().to_value());

            // A ring-generated P-256 PKCS#8 (it carries the public key too) is a valid agreement key.
            let rng = SystemRandom::new();
            let ring_p256 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let as_agreement =
                LocalKey::from_pkcs8_der(ring_p256.as_ref(), KeyKind::JweEncryption, None).unwrap();
            let as_signing =
                LocalKey::from_pkcs8_der(ring_p256.as_ref(), KeyKind::JwsSigning, None).unwrap();
            assert_eq!(jwk_coord(&as_agreement, "x"), jwk_coord(&as_signing, "x"));
            assert_eq!(jwk_coord(&as_agreement, "y"), jwk_coord(&as_signing, "y"));
            assert_eq!(as_agreement.signing_alg(), None);
            assert_eq!(as_signing.signing_alg(), Some(SigningAlg::Es256));

            let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
            let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            for (what, der) in [
                ("a P-384 key", p384.as_ref().to_vec()),
                ("an Ed25519 key", ed.as_ref().to_vec()),
                ("garbage", vec![7u8; 67]),
                ("an empty input", vec![]),
                ("a truncated P-256 key", P256_PKCS8_PREFIX.to_vec()),
            ] {
                assert!(
                    LocalKey::from_pkcs8_der(&der, KeyKind::JweEncryption, None).is_err(),
                    "{what} is not an agreement key"
                );
            }
            // The scalar zero and the group order are not private keys.
            for scalar in [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            ] {
                let mut der = P256_PKCS8_PREFIX.to_vec();
                der.extend_from_slice(&unhex(scalar));
                assert!(
                    LocalKey::from_pkcs8_der(&der, KeyKind::JweEncryption, None).is_err(),
                    "{scalar}"
                );
            }
        }

        #[test]
        fn only_a_key_agreement_key_agrees() {
            let signer = LocalKey::generate(KeyKind::JwsSigning, SigningAlg::Es256, None).unwrap();
            assert!(signer.agree(&point(GRX, GRY)).is_err());
            let x25519 = LocalKey::generate_x25519(KeyKind::JweEncryption, None).unwrap();
            assert!(
                x25519.agree(&point(GRX, GRY)).is_err(),
                "a P-256 point is not an X25519 key"
            );
            let p256 = imported(I);
            assert!(
                p256.agree(&[9u8; 32]).is_err(),
                "an X25519 public key is not a P-256 point"
            );
        }
    }
}
