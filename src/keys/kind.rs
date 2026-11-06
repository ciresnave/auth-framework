use crate::errors::{AuthError, Result};

/// What a key is for. One variant per role a client or server needs a key in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// JWS/JWT signing key (published through a JWKS).
    JwsSigning,
    /// JWE key-agreement or key-wrapping key.
    JweEncryption,
    /// GNAP client key (JWK, `cert` or `cert#S256` form).
    GnapClient,
    /// DPoP proof key (RFC 9449).
    Dpop,
    /// HTTP message signature key (RFC 9421).
    HttpSig,
    /// TLS / mTLS key pair.
    Mtls,
    /// Symmetric HMAC key.
    Hmac,
    /// Symmetric AEAD key.
    Aead,
}

impl KeyKind {
    /// True when the key has a public half that can be exported.
    pub fn is_asymmetric(self) -> bool {
        !matches!(self, KeyKind::Hmac | KeyKind::Aead)
    }

    /// The JWK `use` value for kinds that publish one (`sig` or `enc`).
    pub fn jwk_use(self) -> Option<&'static str> {
        match self {
            KeyKind::JwsSigning | KeyKind::GnapClient | KeyKind::Dpop | KeyKind::HttpSig => {
                Some("sig")
            }
            KeyKind::JweEncryption => Some("enc"),
            KeyKind::Mtls | KeyKind::Hmac | KeyKind::Aead => None,
        }
    }
}

/// A key identifier. Never empty, never padded with whitespace, so it can be
/// used as a JWS `kid`, a storage key and a log field unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct Kid(String);

impl Kid {
    /// Validate and wrap an identifier (1..=128 visible ASCII characters).
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(AuthError::validation(
                "key id must be 1 to 128 visible ASCII characters",
            ));
        }
        Ok(Self(id))
    }

    /// The identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Kid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signs on behalf of a key without returning its private bytes, so a
/// non-exportable key (OS keystore, TPM, KMS) can stand behind the same
/// interface as an in-memory one. Callers take a `Signer`, not PEM.
pub trait Signer: Send + Sync {
    /// The key's identifier.
    fn kid(&self) -> &Kid;
    /// The JWS algorithm name this key signs with (for example `ES256`).
    fn algorithm(&self) -> &str;
    /// Sign `message`; the output is the JWS/raw signature for [`Self::algorithm`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// The public half as a JWK.
    fn public_jwk(&self) -> Result<crate::keys::PublicJwk>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid_rejects_empty_whitespace_and_long() {
        assert!(Kid::new("").is_err());
        assert!(Kid::new("a b").is_err());
        assert!(Kid::new(" a").is_err());
        assert!(Kid::new("a".repeat(129)).is_err());
        assert!(Kid::new("a".repeat(128)).is_ok());
        assert_eq!(Kid::new("k-1").unwrap().as_str(), "k-1");
    }

    #[test]
    fn symmetric_kinds_have_no_public_half_or_jwk_use() {
        for k in [KeyKind::Hmac, KeyKind::Aead] {
            assert!(!k.is_asymmetric());
            assert_eq!(k.jwk_use(), None);
        }
        assert_eq!(KeyKind::JweEncryption.jwk_use(), Some("enc"));
        assert_eq!(KeyKind::Dpop.jwk_use(), Some("sig"));
        assert!(KeyKind::Mtls.is_asymmetric());
    }
}
