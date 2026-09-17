//! Client certificate authentication (application-layer mTLS identity extraction).
//!
//! # Where this fits in the stack
//!
//! ```text
//! TLS layer   ─── mTLS handshake ──► proves client holds the private key
//! This module ─── cert inspection ──► extracts identity, applies policy
//! ```
//!
//! The TLS handshake cryptographically proves that the client possesses the
//! private key corresponding to the certificate it presented.  Once TLS is
//! established, the server-side application receives the **verified** certificate
//! as DER bytes.  This module's job is the *second* part: inspecting the certificate
//! to answer "who is this client?" and "are they permitted?".
//!
//! # What this module covers
//!
//! Any PKI-based client authentication that delivers an X.509 certificate to
//! the application layer:
//! - Software client certificates (p12/pfx, PEM bundles)
//! - Smart card client certificates (SC/PKCS#11, hardware-bound private key)
//! - US government PIV (NIST SP 800-73) certificates
//! - CAC (Common Access Card) certificates
//!
//! From this module's perspective a smart card certificate is just an X.509 DER
//! byte string.  The PC/SC protocol that extracts it from the physical card is
//! handled at the transport layer (PKCS#11 middleware, OS TLS stack, etc.).
//!
//! # What this module does NOT do
//!
//! - **Cryptographic signature verification of the cert chain**: that belongs in the
//!   TLS library (rustls, native-tls).  `ClientCertConfig::trusted_ca_ders` is a
//!   *defence-in-depth* post-TLS policy check (issuer DN matching), not a replacement
//!   for TLS-level chain verification.
//! - **OCSP / CRL revocation checking**: a future extension.  Rely on the TLS layer's
//!   revocation configuration for now.
//! - **PC/SC card reader access**: use a PKCS#11 middleware library at the transport
//!   layer (e.g. OpenSC).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{
    authentication::credentials::Credential,
    errors::{AuthError, Result},
};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for [`ClientCertAuthMethod`].
#[derive(Debug, Clone)]
pub struct ClientCertConfig {
    /// DER-encoded trusted CA certificates.
    ///
    /// When non-empty, the presented certificate's issuer DN is matched against
    /// the subjects of these CAs.  This provides a meaningful policy guard when
    /// the list is kept to a small, curated set of CAs you actually trust.
    ///
    /// **Security note**: this is an *issuer DN equality check*, not a full
    /// cryptographic path validation.  For cryptographic assurance configure your
    /// TLS library's trusted CA store, then use this list as a second policy filter.
    pub trusted_ca_ders: Vec<Vec<u8>>,

    /// Subject DN substrings that are allowed.  An empty list accepts any subject
    /// (given other checks pass).  Matching is case-sensitive substring search on
    /// the full Distinguished Name string (e.g. `"CN=alice"` or just `"alice"`).
    pub subject_allowlist: Vec<String>,

    /// Issuer DN substrings that are allowed.  An empty list accepts any issuer.
    pub issuer_allowlist: Vec<String>,

    /// When `true`, the certificate must contain a Subject Alternative Name (SAN)
    /// extension.  PIV and modern TLS certificates always carry one; older
    /// enterprise CAs sometimes do not.
    pub require_san: bool,

    /// Lifetime of the session issued after successful authentication (seconds).
    pub token_lifetime_secs: u64,
}

impl Default for ClientCertConfig {
    fn default() -> Self {
        Self {
            trusted_ca_ders: Vec::new(),
            subject_allowlist: Vec::new(),
            issuer_allowlist: Vec::new(),
            require_san: false,
            token_lifetime_secs: 3600,
        }
    }
}

impl ClientCertConfig {
    /// Create a permissive configuration with a 1-hour session lifetime.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: add a trusted CA (DER-encoded).
    pub fn trust_ca(mut self, ca_der: Vec<u8>) -> Self {
        self.trusted_ca_ders.push(ca_der);
        self
    }

    /// Builder: allow only subjects whose DN contains `pattern`.
    pub fn allow_subject(mut self, pattern: impl Into<String>) -> Self {
        self.subject_allowlist.push(pattern.into());
        self
    }

    /// Builder: allow only issuers whose DN contains `pattern`.
    pub fn allow_issuer(mut self, pattern: impl Into<String>) -> Self {
        self.issuer_allowlist.push(pattern.into());
        self
    }

    /// Builder: require a SAN extension.
    pub fn with_require_san(mut self) -> Self {
        self.require_san = true;
        self
    }
}

// ─── Identity type ────────────────────────────────────────────────────────────

/// Identity extracted from a successfully validated client certificate.
#[derive(Debug, Clone)]
pub struct CertIdentity {
    /// Full Distinguished Name of the subject (e.g. `"CN=alice, O=Example Corp"`).
    pub subject_dn: String,
    /// Common Name (CN) extracted from the subject, if present.
    pub common_name: Option<String>,
    /// Subject Alternative Names collected from the SAN extension, if present.
    /// Each entry is prefixed with its type: `"dns:host.example.com"`,
    /// `"email:user@example.com"`, `"ip:192.0.2.1"`.
    pub sans: Vec<String>,
    /// Full Distinguished Name of the issuer.
    pub issuer_dn: String,
}

// ─── Method ───────────────────────────────────────────────────────────────────

/// Application-layer client certificate authenticator.
///
/// Validates an X.509 client certificate presented after an mTLS handshake and
/// extracts a [`CertIdentity`] that higher-level code can use to create a session.
///
/// ## Minimal usage
///
/// ```rust,no_run
/// use auth_framework::methods::client_cert::{ClientCertAuthMethod, ClientCertConfig};
/// use auth_framework::authentication::credentials::Credential;
///
/// # let cert_der: Vec<u8> = unimplemented!();
/// let method = ClientCertAuthMethod::new(ClientCertConfig::new());
///
/// // `cert_der` comes from your HTTP framework's peer certificate extraction.
/// let identity = method.authenticate(&Credential::client_cert_from_tls(cert_der))?;
/// # Ok::<_, auth_framework::errors::AuthError>(())
/// ```
pub struct ClientCertAuthMethod {
    config: ClientCertConfig,
}

impl ClientCertAuthMethod {
    /// Create a new authenticator with the given configuration.
    pub fn new(config: ClientCertConfig) -> Self {
        Self { config }
    }

    /// Validate `credential` and return the caller's certificate identity.
    ///
    /// Accepts `Credential::Certificate { certificate, .. }`.  The `private_key`
    /// field is **ignored** — key possession was already proved by the TLS
    /// handshake.  Use [`Credential::client_cert_from_tls`] to construct the
    /// credential without supplying a private key.
    pub fn authenticate(&self, credential: &Credential) -> Result<CertIdentity> {
        let cert_der = match credential {
            Credential::Certificate {
                certificate,
                private_key,
                ..
            } => {
                if !private_key.is_empty() {
                    tracing::warn!(
                        "ClientCertAuthMethod received a non-empty private_key — \
                         it will be ignored.  For mTLS flows use \
                         `Credential::client_cert_from_tls(der_bytes)`."
                    );
                }
                certificate.as_slice()
            }
            other => {
                return Err(AuthError::InvalidCredential {
                    credential_type: other.credential_type().to_string(),
                    message: "ClientCertAuthMethod requires a Credential::Certificate. \
                              Use Credential::client_cert_from_tls(der_bytes) for mTLS flows."
                        .to_string(),
                });
            }
        };

        self.validate_der(cert_der)
    }

    // ── Validation pipeline ───────────────────────────────────────────────────

    fn validate_der(&self, cert_der: &[u8]) -> Result<CertIdentity> {
        use x509_parser::prelude::*;

        if cert_der.is_empty() {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: "Certificate DER bytes are empty".to_string(),
            });
        }

        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|_| AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: "Failed to parse X.509 DER certificate — verify that the bytes \
                          are DER-encoded (not PEM) and are not truncated."
                    .to_string(),
            })?;

        self.check_validity(&cert)?;
        self.check_subject_allowlist(&cert)?;
        self.check_issuer_allowlist(&cert)?;
        self.check_san_required(&cert)?;
        self.check_trust_chain(cert_der)?;
        self.extract_identity(&cert)
    }

    fn check_validity(&self, cert: &x509_parser::certificate::X509Certificate<'_>) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        if now < not_before {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: format!(
                    "Certificate is not yet valid (valid from Unix timestamp {})",
                    not_before
                ),
            });
        }
        if now > not_after {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: "Certificate has expired".to_string(),
            });
        }
        Ok(())
    }

    fn check_subject_allowlist(
        &self,
        cert: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Result<()> {
        if self.config.subject_allowlist.is_empty() {
            return Ok(());
        }
        let subject = cert.subject().to_string();
        if !self
            .config
            .subject_allowlist
            .iter()
            .any(|p| subject.contains(p.as_str()))
        {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: format!("Subject DN '{}' is not in the subject allowlist", subject),
            });
        }
        Ok(())
    }

    fn check_issuer_allowlist(
        &self,
        cert: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Result<()> {
        if self.config.issuer_allowlist.is_empty() {
            return Ok(());
        }
        let issuer = cert.issuer().to_string();
        if !self
            .config
            .issuer_allowlist
            .iter()
            .any(|p| issuer.contains(p.as_str()))
        {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: format!("Issuer DN '{}' is not in the issuer allowlist", issuer),
            });
        }
        Ok(())
    }

    fn check_san_required(
        &self,
        cert: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Result<()> {
        if !self.config.require_san {
            return Ok(());
        }
        // SAN extension OID: 2.5.29.17
        let has_san = cert
            .extensions()
            .iter()
            .any(|ext| ext.oid.to_id_string() == "2.5.29.17");
        if !has_san {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: "Certificate does not contain a Subject Alternative Name (SAN) \
                          extension, but require_san is enabled in the configuration."
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Issuer DN matching against trusted CAs.
    ///
    /// Finds a CA in `trusted_ca_ders` whose subject DN equals the end-entity
    /// certificate's issuer DN.  This is effective as a policy filter when the CA
    /// list is carefully maintained; it is NOT a cryptographic signature check.
    fn check_trust_chain(&self, cert_der: &[u8]) -> Result<()> {
        if self.config.trusted_ca_ders.is_empty() {
            return Ok(());
        }

        use x509_parser::prelude::*;

        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|_| AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: "Failed to re-parse certificate for chain check".to_string(),
            })?;
        let issuer_dn = cert.issuer().to_string();

        let found = self.config.trusted_ca_ders.iter().any(|ca_der| {
            if let Ok((_, ca_cert)) = X509Certificate::from_der(ca_der) {
                ca_cert.subject().to_string() == issuer_dn
            } else {
                false
            }
        });

        if !found {
            return Err(AuthError::InvalidCredential {
                credential_type: "certificate".to_string(),
                message: format!(
                    "No trusted CA found for issuer '{}'. \
                     Add the issuing CA's DER bytes to ClientCertConfig::trusted_ca_ders.",
                    issuer_dn
                ),
            });
        }
        Ok(())
    }

    fn extract_identity(
        &self,
        cert: &x509_parser::certificate::X509Certificate<'_>,
    ) -> Result<CertIdentity> {
        let subject_dn = cert.subject().to_string();
        let issuer_dn = cert.issuer().to_string();

        // First CN attribute in the subject RDN sequence.
        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(str::to_string);

        // Collect DNS, email, and IP SANs from the SAN extension (OID 2.5.29.17).
        let mut sans: Vec<String> = Vec::new();
        for ext in cert.extensions() {
            if ext.oid.to_id_string() == "2.5.29.17"
                && let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                    ext.parsed_extension()
            {
                for gn in &san.general_names {
                    let entry = match gn {
                        x509_parser::extensions::GeneralName::DNSName(s) => {
                            format!("dns:{s}")
                        }
                        x509_parser::extensions::GeneralName::RFC822Name(s) => {
                            format!("email:{s}")
                        }
                        x509_parser::extensions::GeneralName::IPAddress(ip) => {
                            format!("ip:{}", fmt_ip(ip))
                        }
                        _ => continue,
                    };
                    sans.push(entry);
                }
            }
        }

        Ok(CertIdentity {
            subject_dn,
            common_name,
            sans,
            issuer_dn,
        })
    }
}

/// Format raw IP bytes as dotted-decimal (IPv4) or colon-hex (IPv6).
fn fmt_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let parts: Vec<String> = bytes
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            parts.join(":")
        }
        _ => format!("{:?}", bytes),
    }
}

// ── Certificate Pinning ───────────────────────────────────────────────────────

/// Certificate fingerprint for pinning.
///
/// Stores the SHA-256 hash of a DER-encoded certificate for pin comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertPin {
    /// SHA-256 fingerprint as a lowercase hex string.
    pub sha256_hex: String,
}

impl CertPin {
    /// Compute a pin from DER-encoded certificate bytes.
    pub fn from_der(cert_der: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(cert_der);
        Self {
            sha256_hex: hex::encode(digest),
        }
    }

    /// Create a pin from a known hex fingerprint.
    pub fn from_hex(hex_fingerprint: impl Into<String>) -> Self {
        Self {
            sha256_hex: hex_fingerprint.into().to_lowercase(),
        }
    }
}

/// A certificate pin store for enforcing certificate pinning.
///
/// When pinning is enabled, only certificates whose SHA-256 fingerprint
/// appears in this store are accepted.
#[derive(Debug, Clone, Default)]
pub struct CertPinStore {
    pins: Arc<std::sync::RwLock<HashSet<String>>>,
}

impl CertPinStore {
    /// Create a new empty pin store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pin by SHA-256 hex fingerprint.
    pub fn add(&self, pin: &CertPin) {
        self.pins.write().unwrap().insert(pin.sha256_hex.clone());
    }

    /// Remove a pin.
    pub fn remove(&self, pin: &CertPin) -> bool {
        self.pins.write().unwrap().remove(&pin.sha256_hex)
    }

    /// Check if a certificate (DER) matches any pinned fingerprint.
    pub fn is_pinned(&self, cert_der: &[u8]) -> bool {
        let pin = CertPin::from_der(cert_der);
        self.pins.read().unwrap().contains(&pin.sha256_hex)
    }

    /// Number of stored pins.
    pub fn count(&self) -> usize {
        self.pins.read().unwrap().len()
    }
}

// ── Revocation Checking ───────────────────────────────────────────────────────

/// Revocation check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is known to be good (not revoked).
    Good,
    /// Certificate has been revoked.
    Revoked {
        /// RFC 5280 CRLReason (optional).
        reason: Option<String>,
    },
    /// Revocation status is unknown (e.g., responder unavailable).
    Unknown,
}

/// An in-memory CRL (Certificate Revocation List) store.
///
/// For production deployments, the TLS layer should handle CRL/OCSP. This
/// provides an application-layer defence-in-depth check against known-revoked
/// serial numbers.
#[derive(Debug, Clone, Default)]
pub struct CrlStore {
    /// Revoked certificate serial numbers (hex-encoded), keyed by issuer DN.
    revoked: Arc<std::sync::RwLock<std::collections::HashMap<String, HashSet<String>>>>,
}

impl CrlStore {
    /// Create a new empty CRL store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a certificate serial number as revoked for a given issuer DN.
    pub fn add_revoked(&self, issuer_dn: &str, serial_hex: &str) {
        self.revoked
            .write()
            .unwrap()
            .entry(issuer_dn.to_string())
            .or_default()
            .insert(serial_hex.to_lowercase());
    }

    /// Check if a certificate (by issuer DN and serial hex) is revoked.
    pub fn check(&self, issuer_dn: &str, serial_hex: &str) -> RevocationStatus {
        let store = self.revoked.read().unwrap();
        if let Some(serials) = store.get(issuer_dn) {
            if serials.contains(&serial_hex.to_lowercase()) {
                return RevocationStatus::Revoked { reason: None };
            }
        }
        RevocationStatus::Good
    }

    /// Check a DER-encoded certificate against the CRL store.
    pub fn check_der(&self, cert_der: &[u8]) -> RevocationStatus {
        use x509_parser::prelude::*;
        let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
            return RevocationStatus::Unknown;
        };
        let issuer = cert.issuer().to_string();
        let serial = cert.raw_serial_as_string().to_lowercase();
        self.check(&issuer, &serial)
    }

    /// Total count of revoked serial numbers across all issuers.
    pub fn revoked_count(&self) -> usize {
        self.revoked.read().unwrap().values().map(|s| s.len()).sum()
    }

    /// Remove all entries for an issuer.
    pub fn clear_issuer(&self, issuer_dn: &str) {
        self.revoked.write().unwrap().remove(issuer_dn);
    }
}

// ── Certificate-Bound Access Tokens (RFC 8705) ───────────────────────────────

/// Computes a certificate thumbprint for use in RFC 8705 certificate-bound
/// access tokens (mTLS client certificate binding).
///
/// Returns the base64url-encoded SHA-256 hash of the DER-encoded certificate,
/// suitable for the `x5t#S256` confirmation claim in JWT access tokens.
pub fn cert_thumbprint_s256(cert_der: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert_der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify that a presented certificate matches the `x5t#S256` thumbprint
/// bound to an access token (RFC 8705 §3).
pub fn verify_cert_binding(cert_der: &[u8], expected_thumbprint: &str) -> Result<()> {
    let actual = cert_thumbprint_s256(cert_der);
    if actual == expected_thumbprint {
        Ok(())
    } else {
        Err(AuthError::InvalidCredential {
            credential_type: "certificate".to_string(),
            message: format!(
                "Certificate thumbprint mismatch: token bound to '{}', presented cert has '{}'",
                expected_thumbprint, actual
            ),
        })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Configuration ─────────────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        let cfg = ClientCertConfig::default();
        assert!(cfg.trusted_ca_ders.is_empty());
        assert!(cfg.subject_allowlist.is_empty());
        assert!(cfg.issuer_allowlist.is_empty());
        assert!(!cfg.require_san);
        assert_eq!(cfg.token_lifetime_secs, 3600);
    }

    #[test]
    fn test_config_builder_chain() {
        let cfg = ClientCertConfig::new()
            .allow_subject("alice")
            .allow_issuer("MyCA")
            .with_require_san();
        assert_eq!(cfg.subject_allowlist, ["alice"]);
        assert_eq!(cfg.issuer_allowlist, ["MyCA"]);
        assert!(cfg.require_san);
    }

    // ── Error paths (no real cert required) ───────────────────────────────────

    #[test]
    fn test_wrong_credential_type_rejected() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let cred = Credential::Password {
            username: "u".into(),
            password: "p".into(),
        };
        let err = method.authenticate(&cred).unwrap_err();
        assert!(
            format!("{err}").contains("Certificate"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_empty_der_rejected() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let cred = Credential::Certificate {
            certificate: vec![],
            private_key: vec![],
            passphrase: None,
        };
        let err = method.authenticate(&cred).unwrap_err();
        assert!(format!("{err}").contains("empty"), "unexpected: {err}");
    }

    #[test]
    fn test_garbage_der_rejected() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let cred = Credential::Certificate {
            certificate: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            private_key: vec![],
            passphrase: None,
        };
        assert!(method.authenticate(&cred).is_err());
    }

    // ── Certificate DER builder for tests ─────────────────────────────────────
    //
    // Constructs a minimal self-signed Ed25519 X.509v3 certificate in DER.
    // Validity dates are hardcoded as UTCTime raw bytes (ISO 8601 compact form).
    //
    // To regenerate equivalent certs with openssl:
    //   openssl req -x509 -newkey ed25519 -keyout /tmp/k.pem -out /tmp/c.pem \
    //     -days 730 -nodes -subj "/CN=<cn>"
    //   openssl x509 -in /tmp/c.pem -outform DER | xxd -i
    fn build_cert_der(
        cn: &str,
        not_before_utc: &[u8; 13], // raw UTCTime bytes e.g. b"250101000000Z"
        not_after_utc: &[u8; 13],
    ) -> Vec<u8> {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = kp.public_key().as_ref(); // 32 bytes

        // Short-form TLV (content < 128 bytes)
        let tlv = |tag: u8, content: &[u8]| -> Vec<u8> {
            assert!(
                content.len() < 128,
                "content too large for short-form TLV: {} bytes",
                content.len()
            );
            let mut v = vec![tag, content.len() as u8];
            v.extend_from_slice(content);
            v
        };

        // TLV with definite long form when content >= 128 bytes
        let long_tlv = |tag: u8, content: &[u8]| -> Vec<u8> {
            let len = content.len();
            let mut v = vec![tag];
            if len < 128 {
                v.push(len as u8);
            } else {
                // Two-byte length (content < 65536)
                v.push(0x81);
                v.push(len as u8);
            }
            v.extend_from_slice(content);
            v
        };

        // OID 1.3.101.112 (id-EdDSA / Ed25519)
        let alg_id = tlv(0x30, &[0x06, 0x03, 0x2B, 0x65, 0x70]);

        // Name: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String cn } } }
        let cn_bytes = cn.as_bytes();
        let utf8_cn = tlv(0x0C, cn_bytes);
        let oid_cn = [0x06u8, 0x03, 0x55, 0x04, 0x03];
        let seq_atv = [oid_cn.as_slice(), utf8_cn.as_slice()].concat();
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &seq_atv)));

        // Validity: SEQUENCE { UTCTime nb, UTCTime na }
        let nb_der = tlv(0x17, not_before_utc);
        let na_der = tlv(0x17, not_after_utc);
        let validity = tlv(0x30, &[nb_der.as_slice(), na_der.as_slice()].concat());

        // SubjectPublicKeyInfo: SEQUENCE { alg_id, BIT STRING { 0x00 || pub_key } }
        let mut bit_content = vec![0x00u8];
        bit_content.extend_from_slice(pub_key);
        let bit_str = tlv(0x03, &bit_content);
        let spki = tlv(0x30, &[alg_id.as_slice(), bit_str.as_slice()].concat());

        // TBSCertificate
        let version = [0xA0u8, 0x03, 0x02, 0x01, 0x02]; // [0] EXPLICIT INTEGER 2 (v3)
        let serial = tlv(0x02, &[0x01]);
        let tbs_body: Vec<u8> = [
            version.as_slice(),
            serial.as_slice(),
            alg_id.as_slice(), // signatureAlgorithm
            name.as_slice(),   // issuer
            validity.as_slice(),
            name.as_slice(), // subject (same as issuer: self-signed)
            spki.as_slice(),
        ]
        .concat();
        let tbs = long_tlv(0x30, &tbs_body);

        // Self-sign the TBSCertificate bytes
        let sig = kp.sign(&tbs);
        let mut sig_content = vec![0x00u8]; // BIT STRING: 0 unused bits
        sig_content.extend_from_slice(sig.as_ref()); // 64 bytes
        let sig_bit_str = tlv(0x03, &sig_content);

        // Certificate: SEQUENCE { tbs, signatureAlgorithm, signatureValue }
        let cert_body: Vec<u8> =
            [tbs.as_slice(), alg_id.as_slice(), sig_bit_str.as_slice()].concat();
        long_tlv(0x30, &cert_body)
    }

    // Validity windows (UTCTime raw bytes):
    //   Valid now (2025-01-01 → 2027-01-01)
    fn valid_cert(cn: &str) -> Vec<u8> {
        build_cert_der(cn, b"250101000000Z", b"270101000000Z")
    }
    //   Expired (2020-01-01 → 2021-01-01)
    fn expired_cert(cn: &str) -> Vec<u8> {
        build_cert_der(cn, b"200101000000Z", b"210101000000Z")
    }
    //   Future (2028-01-01 → 2030-01-01)
    fn future_cert(cn: &str) -> Vec<u8> {
        build_cert_der(cn, b"280101000000Z", b"300101000000Z")
    }

    fn cert_cred(der: Vec<u8>) -> Credential {
        Credential::Certificate {
            certificate: der,
            private_key: vec![],
            passphrase: None,
        }
    }

    // ── Certificate-based tests ────────────────────────────────────────────────

    #[test]
    fn test_valid_cert_accepted() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let id = method
            .authenticate(&cert_cred(valid_cert("alice")))
            .expect("valid cert should be accepted");
        assert!(
            id.subject_dn.contains("alice"),
            "subject should contain CN: {}",
            id.subject_dn
        );
        assert_eq!(id.common_name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_expired_cert_rejected() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let err = method
            .authenticate(&cert_cred(expired_cert("bob")))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expired"), "expected 'expired' in: {msg}");
    }

    #[test]
    fn test_future_cert_rejected() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let err = method
            .authenticate(&cert_cred(future_cert("carol")))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("valid"), "expected 'valid' in: {msg}");
    }

    #[test]
    fn test_subject_allowlist_permits_matching_cn() {
        let cfg = ClientCertConfig::new().allow_subject("alice");
        assert!(
            ClientCertAuthMethod::new(cfg)
                .authenticate(&cert_cred(valid_cert("alice")))
                .is_ok()
        );
    }

    #[test]
    fn test_subject_allowlist_blocks_non_matching_cn() {
        let cfg = ClientCertConfig::new().allow_subject("alice");
        let err = ClientCertAuthMethod::new(cfg)
            .authenticate(&cert_cred(valid_cert("mallory")))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("allowlist"), "expected 'allowlist' in: {msg}");
    }

    #[test]
    fn test_issuer_allowlist_permits_self_signed_when_matches() {
        // Self-signed: issuer DN == subject DN == "CN=alice"
        let cfg = ClientCertConfig::new().allow_issuer("alice");
        assert!(
            ClientCertAuthMethod::new(cfg)
                .authenticate(&cert_cred(valid_cert("alice")))
                .is_ok()
        );
    }

    #[test]
    fn test_issuer_allowlist_blocks_unmatched_issuer() {
        let cfg = ClientCertConfig::new().allow_issuer("TrustedCorp");
        let err = ClientCertAuthMethod::new(cfg)
            .authenticate(&cert_cred(valid_cert("alice")))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("allowlist"), "expected 'allowlist' in: {msg}");
    }

    #[test]
    fn test_require_san_rejects_cert_without_san() {
        // Our test cert builder produces no SAN extension.
        let cfg = ClientCertConfig::new().with_require_san();
        let err = ClientCertAuthMethod::new(cfg)
            .authenticate(&cert_cred(valid_cert("alice")))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Subject Alternative Name") || msg.contains("SAN"),
            "expected SAN mention in: {msg}"
        );
    }

    #[test]
    fn test_trusted_ca_accepts_when_issuer_dn_matches() {
        // A self-signed cert is its own issuer; adding it to trusted_ca_ders
        // means its own subject DN matches the issuer DN look-up.
        let der = valid_cert("alice");
        let cfg = ClientCertConfig::new().trust_ca(der.clone());
        assert!(
            ClientCertAuthMethod::new(cfg)
                .authenticate(&cert_cred(der))
                .is_ok()
        );
    }

    #[test]
    fn test_trusted_ca_rejects_when_no_ca_matches() {
        let untrusted_cert = valid_cert("alice");
        // Different self-signed cert = different subject DN
        let different_ca = valid_cert("OtherCA");
        let cfg = ClientCertConfig::new().trust_ca(different_ca);
        let err = ClientCertAuthMethod::new(cfg)
            .authenticate(&cert_cred(untrusted_cert))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("trusted CA") || msg.contains("issuer"),
            "expected CA/issuer mention in: {msg}"
        );
    }

    #[test]
    fn test_client_cert_from_tls_constructor() {
        let der = valid_cert("sys");
        let cred = Credential::client_cert_from_tls(der.clone());
        match &cred {
            Credential::Certificate {
                certificate,
                private_key,
                passphrase,
            } => {
                assert_eq!(certificate, &der);
                assert!(private_key.is_empty(), "private_key should be empty");
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected Credential::Certificate"),
        }

        // Also verify it authenticates successfully
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        assert!(method.authenticate(&cred).is_ok());
    }

    #[test]
    fn test_issuer_dn_populated_in_identity() {
        let method = ClientCertAuthMethod::new(ClientCertConfig::new());
        let id = method
            .authenticate(&cert_cred(valid_cert("charlie")))
            .unwrap();
        // Self-signed: issuer == subject
        assert_eq!(id.issuer_dn, id.subject_dn);
    }

    // ── Certificate Pinning ─────────────────────────────────────

    #[test]
    fn test_cert_pin_from_der() {
        let der = valid_cert("pin-test");
        let pin = CertPin::from_der(&der);
        assert_eq!(pin.sha256_hex.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_cert_pin_deterministic() {
        let der = vec![0x30, 0x82, 0x01, 0x00];
        let p1 = CertPin::from_der(&der);
        let p2 = CertPin::from_der(&der);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_cert_pin_from_hex() {
        let pin = CertPin::from_hex("AABB");
        assert_eq!(pin.sha256_hex, "aabb"); // lowercase
    }

    #[test]
    fn test_cert_pin_store_add_and_check() {
        let store = CertPinStore::new();
        let der = valid_cert("pinned");
        let pin = CertPin::from_der(&der);
        store.add(&pin);
        assert_eq!(store.count(), 1);
        assert!(store.is_pinned(&der));
        assert!(!store.is_pinned(&valid_cert("not-pinned")));
    }

    #[test]
    fn test_cert_pin_store_remove() {
        let store = CertPinStore::new();
        let der = valid_cert("removable");
        let pin = CertPin::from_der(&der);
        store.add(&pin);
        assert!(store.remove(&pin));
        assert!(!store.is_pinned(&der));
        assert_eq!(store.count(), 0);
    }

    // ── CRL Store ───────────────────────────────────────────────

    #[test]
    fn test_crl_store_add_and_check() {
        let store = CrlStore::new();
        store.add_revoked("CN=TestCA", "0a1b2c");
        assert_eq!(
            store.check("CN=TestCA", "0a1b2c"),
            RevocationStatus::Revoked { reason: None }
        );
        assert_eq!(store.check("CN=TestCA", "ffffff"), RevocationStatus::Good);
        assert_eq!(store.check("CN=OtherCA", "0a1b2c"), RevocationStatus::Good);
    }

    #[test]
    fn test_crl_store_case_insensitive_serial() {
        let store = CrlStore::new();
        store.add_revoked("CN=CA", "aAbBcC");
        assert_eq!(
            store.check("CN=CA", "AABBCC"),
            RevocationStatus::Revoked { reason: None }
        );
    }

    #[test]
    fn test_crl_store_check_der() {
        let store = CrlStore::new();
        let der = valid_cert("crl-test");
        // Without any revocations → Good
        assert_eq!(store.check_der(&der), RevocationStatus::Good);
    }

    #[test]
    fn test_crl_store_revoked_count() {
        let store = CrlStore::new();
        store.add_revoked("CN=CA1", "01");
        store.add_revoked("CN=CA1", "02");
        store.add_revoked("CN=CA2", "01");
        assert_eq!(store.revoked_count(), 3);
    }

    #[test]
    fn test_crl_store_clear_issuer() {
        let store = CrlStore::new();
        store.add_revoked("CN=CA", "01");
        store.add_revoked("CN=CA", "02");
        store.clear_issuer("CN=CA");
        assert_eq!(store.revoked_count(), 0);
    }

    // ── RFC 8705 Certificate-Bound Tokens ───────────────────────

    #[test]
    fn test_cert_thumbprint_s256() {
        let der = valid_cert("rfc8705");
        let thumbprint = cert_thumbprint_s256(&der);
        // base64url-encoded SHA-256 = 43 chars
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn test_cert_thumbprint_deterministic() {
        let der = vec![0x30, 0x82, 0x00, 0x01];
        let t1 = cert_thumbprint_s256(&der);
        let t2 = cert_thumbprint_s256(&der);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_verify_cert_binding_success() {
        let der = valid_cert("bound");
        let thumbprint = cert_thumbprint_s256(&der);
        assert!(verify_cert_binding(&der, &thumbprint).is_ok());
    }

    #[test]
    fn test_verify_cert_binding_mismatch() {
        let der = valid_cert("bound");
        let err = verify_cert_binding(&der, "wrong-thumbprint").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("mismatch"), "expected 'mismatch' in: {msg}");
    }
}
