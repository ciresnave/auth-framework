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
}

/// An asymmetric private key held in this process. Exportable by design;
/// non-exportable stores (KM3) implement [`Signer`] without this type.
pub struct LocalKey {
    kid: Kid,
    kind: KeyKind,
    alg: SigningAlg,
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
    if kind.is_asymmetric() && kind.jwk_use() == Some("sig") {
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
            alg,
            pkcs8: Zeroizing::new(der.to_vec()),
            pair,
            public,
        })
    }

    /// Import a PKCS#8 private key in PEM (`PRIVATE KEY`).
    pub fn from_pkcs8_pem(pem: &str, kind: KeyKind, kid: Option<Kid>) -> Result<Self> {
        const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
        const END: &str = "-----END PRIVATE KEY-----";
        let body = pem
            .trim()
            .strip_prefix(BEGIN)
            .and_then(|r| r.strip_suffix(END))
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

    /// The signing algorithm.
    pub fn signing_alg(&self) -> SigningAlg {
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
        self.alg.name()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.pair {
            Pair::Ec(kp) => kp
                .sign(&SystemRandom::new(), message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| AuthError::crypto("ECDSA signing failed")),
            Pair::Ed(kp) => Ok(kp.sign(message).as_ref().to_vec()),
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
    fn import_round_trips_der_and_pem_with_the_same_identity() {
        for alg in [SigningAlg::Es256, SigningAlg::Es384, SigningAlg::EdDsa] {
            let k = LocalKey::generate(KeyKind::GnapClient, alg, None).unwrap();
            let back =
                LocalKey::from_pkcs8_der(k.to_pkcs8_der(), KeyKind::GnapClient, None).unwrap();
            assert_eq!(back.kid(), k.kid());
            assert_eq!(back.signing_alg(), alg);
            let pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
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
}
