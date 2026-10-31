//! Enhanced X.509 Certificate Signing Module
//!
//! This module provides comprehensive X.509 certificate signing capabilities
//! for enterprise authentication scenarios including:
//!
//! # Features
//!
//! - **Certificate Authority (CA) Operations**: Root and intermediate CA management
//! - **Certificate Signing Requests (CSR)**: Generate and sign CSRs
//! - **Certificate Lifecycle**: Create, renew, revoke, and validate certificates
//! - **Multiple Key Types**: RSA, ECDSA, and Ed25519 support
//! - **Certificate Profiles**: Different certificate types for various use cases
//! - **CRL and OCSP**: Certificate revocation mechanisms
//! - **Enterprise Integration**: LDAP, Active Directory, and PKI integration
//!
//! # Use Cases
//!
//! - Client certificate authentication (OAuth 2.0 mTLS)
//! - Code signing certificates
//! - TLS/SSL server certificates
//! - Email signing and encryption certificates
//! - Document signing certificates
//! - IoT device certificates
//!
//! # Honesty rules
//!
//! Nothing here claims cryptography it does not perform. A CA certificate is only
//! accepted if it parses and is a usable CA; its metadata is read from the certificate
//! itself; a CA can sign only if its private key was loaded (and matches the certificate);
//! issued certificates carry the requester's public key and are signed by the CA; the
//! revocation list is a signed DER CRL; and chain validation is done by `rustls-webpki`
//! against the configured CAs. Where an operation cannot be done it returns an error, and a
//! setting that is accepted is honoured or rejected rather than ignored, with the few
//! exceptions listed under "Settings that are only labels or recorded".
//!
//! # Who authorises what
//!
//! The manager enforces *form*, not *entitlement*. A request is a bare public key plus
//! requested names, so there is no proof that the requester holds the key and no check that the
//! requester may have the names: **the caller must authenticate the requester and authorise the
//! subject, the SANs, the profile and the key before calling `sign_certificate_request`.** What
//! the manager does enforce is a policy on what can be asked for: text fields of bounded length
//! without control or formatting (for example bidirectional) characters, a two-letter country
//! code, DNS names that are real multi-label host names (no `localhost`, no bare labels),
//! wildcard / IP address / URI / e-mail names only when the profile's [`SanPolicy`] allows
//! them, URIs only with the schemes `http`, `https`, `urn` and `spiffe`, and subject keys that
//! are well-formed RSA of 2048 to 16384 bits (odd modulus, odd public exponent of at least
//! 65537), ECDSA P-256 / P-384 (a valid point on the curve) or Ed25519 (32 bytes), and at least
//! as strong as the profile's `preferred_key_type`. Not checked: that the CN matches a SAN, and
//! whether a wildcard sits under a public suffix (`*.co.uk`): leave `wildcard_dns` off unless
//! the requester is trusted with it.
//!
//! # State
//!
//! **The certificate store and the revocation list live in memory.** Without
//! [`X509Config::state_path`] a restart forgets every issued certificate and every revocation
//! (`initialize` logs a warning); the stores are also unbounded, so a long-running issuer
//! should rotate them. With `state_path` set the state is loaded at `initialize` and rewritten
//! (to a temporary file that is synced and renamed over the old one, and the directory synced
//! where the platform allows) after every issuance, revocation and CRL; if that fails the
//! operation fails (a revocation that cannot be saved still stays in force in memory). A state
//! file that exists but cannot be read or parsed stops `initialize`, so an unreadable file is
//! never mistaken for an empty one. **A file that has been deleted or replaced by an older copy
//! cannot be detected**: protect it like the CA key's directory, and back it up. The file is
//! written by one manager at a time: **two managers or processes sharing one `state_path`
//! overwrite each other's updates**; give each issuer its own file. Writing the whole file on
//! every change is fine for hundreds of certificates, not for millions.
//! [`load_state`](X509CertificateManager::load_state) merges (it never removes a revocation or
//! lowers a CRL number). Without a state file, [`save_state`](X509CertificateManager::save_state)
//! exports the state and
//! [`revoke_certificate_pem`](X509CertificateManager::revoke_certificate_pem) revokes from the
//! certificate itself.
//!
//! # Settings that are only labels or recorded
//!
//! `CertificateProfile::name` and `CertificateRequest::requested_at` are labels / recorded in
//! the stored certificate's metadata (`request_id` is recorded after a length and character
//! check); `CertificateProfile::cert_type` decides whether a profile is a CA profile (refused
//! for issuance) and which extended key usage it must list. When `X509_HSM_CONFIG`,
//! `X509_AZURE_VAULT_URL` or `X509_AWS_SECRET_ID` select an external root CA, `root_ca_path`,
//! `root_ca_cert_path` and `root_ca_key_path` are not used (a warning is logged), the CA
//! signs nothing (its key stays with the source), and the HSM configuration's `label` field is
//! the PKCS#11 object label only.

use crate::errors::{AuthError, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

/// Enhanced X.509 Certificate Manager
#[derive(Debug, Clone)]
pub struct X509CertificateManager {
    /// Configuration
    config: X509Config,

    /// Certificate store
    certificate_store: Arc<RwLock<HashMap<String, StoredCertificate>>>,

    /// Certificate revocation list
    revocation_list: Arc<RwLock<HashMap<String, RevocationEntry>>>,

    /// CA certificates
    ca_certificates: Arc<RwLock<HashMap<String, CACertificate>>>,

    /// Last CRL number issued per CA
    crl_numbers: Arc<RwLock<HashMap<String, u64>>>,

    /// Serialises writes of the state file
    persist_lock: Arc<tokio::sync::Mutex<()>>,
}

/// X.509 Configuration
#[derive(Debug, Clone)]
pub struct X509Config {
    /// Validity period (days) for a profile that does not set its own (`validity_days == 0`)
    pub default_validity_days: i64,

    /// Root CA certificate path
    pub root_ca_cert_path: String,

    /// Root CA certificate path (alias)
    pub root_ca_path: String,

    /// Root CA private key path
    pub root_ca_key_path: String,

    /// Intermediate CA certificate path
    pub intermediate_ca_cert_path: Option<String>,

    /// Intermediate CA certificate path (alias)
    pub intermediate_ca_path: Option<String>,

    /// Intermediate CA private key path
    pub intermediate_ca_key_path: Option<String>,

    /// Certificate profiles
    pub certificate_profiles: HashMap<String, CertificateProfile>,

    /// OCSP is not implemented: `initialize` fails if this is `true`
    pub enable_ocsp: bool,

    /// OCSP responder URL (not implemented; must stay `None` while `enable_ocsp` is `false`)
    pub ocsp_responder_url: Option<String>,

    /// Enable CRL (Certificate Revocation List); `generate_crl` fails when `false`
    pub enable_crl: bool,

    /// CRL distribution point URL, placed in every issued certificate when set
    /// (`http://` or `https://`)
    pub crl_distribution_url: Option<String>,

    /// File that keeps the certificate store, the revocation list and the CRL numbers across
    /// restarts. Unset means the state is volatile (see the module documentation).
    pub state_path: Option<String>,

    /// Development only: allow `initialize` to create a root CA (certificate and key, written
    /// to the configured paths) when the root certificate file does not exist. Off by default,
    /// so a missing root file is an error and never silently becomes a new trust anchor.
    pub generate_development_root_ca: bool,
}

/// ECDSA Curve types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EcdsaCurve {
    /// P-256 (secp256r1)
    P256,
    /// P-384 (secp384r1)
    P384,
    /// P-521 (secp521r1)
    P521,
}

/// Certificate Profile for different use cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProfile {
    /// Profile name
    pub name: String,

    /// Certificate type
    pub cert_type: CertificateType,

    /// Key usage flags
    pub key_usage: Vec<KeyUsage>,

    /// Extended key usage
    pub extended_key_usage: Vec<ExtendedKeyUsage>,

    /// Subject alternative names added to every certificate of this profile (in addition to
    /// the requested ones; each is checked by the same policy)
    pub subject_alt_names: Vec<SubjectAltName>,

    /// Which kinds of requested subject alternative names this profile accepts
    #[serde(default)]
    pub san_policy: SanPolicy,

    /// Validity period (days); `0` means `X509Config::default_validity_days`, negative is refused
    pub validity_days: i64,

    /// Minimum key strength: a subject key is accepted if it is on the allow-list (RSA of at
    /// least 2048 bits, ECDSA P-256 / P-384 / P-521, Ed25519) and at least as strong as this
    pub preferred_key_type: KeyType,

    /// Additional extensions (not supported: a profile with any is refused at issuance)
    pub extensions: HashMap<String, Value>,
}

/// Which kinds of requested subject alternative names a profile accepts. Plain DNS names are
/// always allowed (they must be real multi-label host names); everything else is opt-in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanPolicy {
    /// Allow a wildcard DNS name (`*.example.com`, left-most label only)
    pub wildcard_dns: bool,
    /// Allow IP address names (never unspecified, loopback or multicast addresses)
    pub ip_address: bool,
    /// Allow URI names
    pub uri: bool,
    /// Allow e-mail names, and the request's subject e-mail address
    pub email: bool,
}

/// The purpose a certificate chain is validated for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificatePurpose {
    /// TLS server authentication
    ServerAuth,
    /// TLS client authentication
    ClientAuth,
    /// Code signing
    CodeSigning,
    /// E-mail protection
    EmailProtection,
    /// Time stamping
    TimeStamping,
    /// OCSP response signing
    OcspSigning,
}

/// Certificate Types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateType {
    /// Root Certificate Authority
    RootCA,
    /// Intermediate Certificate Authority
    IntermediateCA,
    /// End entity certificate (leaf)
    EndEntity,
    /// Code signing certificate
    CodeSigning,
    /// Email certificate
    Email,
    /// TLS server certificate
    TlsServer,
    /// TLS client certificate
    TlsClient,
    /// Document signing certificate
    DocumentSigning,
}

/// Key Usage flags
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Digital signature
    DigitalSignature,
    /// Non-repudiation
    NonRepudiation,
    /// Key encipherment
    KeyEncipherment,
    /// Data encipherment
    DataEncipherment,
    /// Key agreement
    KeyAgreement,
    /// Key certificate signing
    KeyCertSign,
    /// CRL signing
    CrlSign,
    /// Encipher only
    EncipherOnly,
    /// Decipher only
    DecipherOnly,
}

/// Extended Key Usage
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExtendedKeyUsage {
    /// Server authentication
    ServerAuth,
    /// Client authentication
    ClientAuth,
    /// Code signing
    CodeSigning,
    /// Email protection
    EmailProtection,
    /// Time stamping
    TimeStamping,
    /// OCSP signing
    OcspSigning,
}

/// Subject Alternative Name types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SubjectAltName {
    /// DNS name
    DnsName(String),
    /// Email address
    Email(String),
    /// URI
    Uri(String),
    /// IP address
    IpAddress(String),
}

/// Key Types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA key
    Rsa(u32), // Key size in bits
    /// ECDSA key
    Ecdsa(EcdsaCurve),
    /// Ed25519 key
    Ed25519,
}

/// Stored Certificate
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// Certificate ID
    pub cert_id: String,

    /// Certificate data (PEM format)
    pub certificate_pem: String,

    /// Private key (PEM format, optional)
    pub private_key_pem: Option<String>,

    /// Certificate subject
    pub subject: String,

    /// Certificate issuer
    pub issuer: String,

    /// Serial number
    pub serial_number: String,

    /// Not before date
    pub not_before: DateTime<Utc>,

    /// Not after date
    pub not_after: DateTime<Utc>,

    /// Certificate profile used
    pub profile: String,

    /// Certificate status
    pub status: CertificateStatus,

    /// Fingerprint (SHA-256)
    pub fingerprint: String,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Metadata
    pub metadata: HashMap<String, Value>,
}

impl std::fmt::Debug for StoredCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("StoredCertificate");
        d.field("cert_id", &self.cert_id);
        d.field("certificate_pem", &self.certificate_pem);
        d.field(
            "private_key_pem",
            &crate::utils::redact::redacted(&self.private_key_pem),
        );
        d.field("subject", &self.subject);
        d.field("issuer", &self.issuer);
        d.field("serial_number", &self.serial_number);
        d.field("not_before", &self.not_before);
        d.field("not_after", &self.not_after);
        d.field("profile", &self.profile);
        d.field("status", &self.status);
        d.field("fingerprint", &self.fingerprint);
        d.field("created_at", &self.created_at);
        d.field("metadata", &self.metadata);
        d.finish()
    }
}

/// Certificate Status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// Certificate is valid
    Valid,
    /// Certificate is expired
    Expired,
    /// Certificate is revoked
    Revoked,
    /// Certificate is suspended
    Suspended,
}

/// CA Certificate
///
/// Does not derive `Debug`: `private_key` holds the CA's raw signing key,
/// and a derived `Debug` would print it verbatim on any accidental
/// `{:?}`. The manual impl below redacts it.
#[derive(Clone)]
pub struct CACertificate {
    /// CA ID
    pub ca_id: String,

    /// CA certificate
    pub certificate: StoredCertificate,

    /// Certificate subject
    pub subject: String,

    /// CA private key
    pub private_key: Zeroizing<Vec<u8>>,

    /// CA type
    pub ca_type: CAType,

    /// Issued certificates count
    pub issued_count: u64,
}

impl fmt::Debug for CACertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CACertificate")
            .field("ca_id", &self.ca_id)
            .field("certificate", &self.certificate)
            .field("subject", &self.subject)
            .field("private_key", &"[redacted]")
            .field("ca_type", &self.ca_type)
            .field("issued_count", &self.issued_count)
            .finish()
    }
}

/// CA Types
#[derive(Debug, Clone, PartialEq)]
pub enum CAType {
    /// Root CA
    Root,
    /// Intermediate CA
    Intermediate,
}

/// Certificate Revocation Entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Certificate serial number
    pub serial_number: String,

    /// Revocation date
    pub revocation_date: DateTime<Utc>,

    /// Revocation reason
    pub reason: RevocationReason,

    /// Additional information
    pub additional_info: Option<String>,
}

/// Revocation Reasons (RFC 5280)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Unspecified
    Unspecified,
    /// Key compromise
    KeyCompromise,
    /// CA compromise
    CaCompromise,
    /// Affiliation changed
    AffiliationChanged,
    /// Superseded
    Superseded,
    /// Cessation of operation
    CessationOfOperation,
    /// Certificate hold
    CertificateHold,
    /// Remove from CRL
    RemoveFromCrl,
    /// Privilege withdrawn
    PrivilegeWithdrawn,
    /// AA compromise
    AaCompromise,
}

/// Certificate Signing Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// Request ID
    pub request_id: String,

    /// Certificate subject information
    pub subject: CertificateSubject,

    /// Certificate profile to use
    pub profile: String,

    /// Public key (PEM format)
    pub public_key_pem: String,

    /// Subject alternative names
    pub subject_alt_names: Vec<SubjectAltName>,

    /// Request timestamp
    pub requested_at: DateTime<Utc>,

    /// Requester information
    pub requester: String,

    /// Additional attributes
    pub attributes: HashMap<String, Value>,
}

/// Certificate Subject Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSubject {
    /// Common name
    pub common_name: String,

    /// Organization
    pub organization: Option<String>,

    /// Organizational unit
    pub organizational_unit: Option<String>,

    /// Country
    pub country: Option<String>,

    /// State/Province
    pub state: Option<String>,

    /// City/Locality
    pub locality: Option<String>,

    /// Email address
    pub email: Option<String>,
}

impl X509CertificateManager {
    /// Create new X.509 certificate manager
    pub fn new(config: X509Config) -> Self {
        Self {
            config,
            certificate_store: Arc::new(RwLock::new(HashMap::new())),
            revocation_list: Arc::new(RwLock::new(HashMap::new())),
            ca_certificates: Arc::new(RwLock::new(HashMap::new())),
            crl_numbers: Arc::new(RwLock::new(HashMap::new())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Initialize certificate manager with CA certificates
    ///
    /// Fails if OCSP is enabled (not implemented), if a configured CA cannot be used, or if
    /// `state_path` names a file that cannot be read back. Call it once, before issuing.
    pub async fn initialize(&self) -> Result<()> {
        if self.config.enable_ocsp || self.config.ocsp_responder_url.is_some() {
            return Err(AuthError::config(
                "OCSP is not implemented: set enable_ocsp = false and leave ocsp_responder_url unset"
                    .to_string(),
            ));
        }
        if let Some(url) = &self.config.crl_distribution_url {
            check_distribution_url(url)?;
        }
        if self.config.intermediate_ca_key_path.is_some()
            && self.config.intermediate_ca_cert_path.is_none()
            && self.config.intermediate_ca_path.is_none()
        {
            return Err(AuthError::config(
                "intermediate_ca_key_path is set but no intermediate CA certificate path is"
                    .to_string(),
            ));
        }
        for (name, profile) in &self.config.certificate_profiles {
            validate_profile(name, profile)?;
        }

        // Load root CA certificate
        self.load_root_ca().await?;

        // Load intermediate CA certificate if configured
        if self.config.intermediate_ca_cert_path.is_some()
            || self.config.intermediate_ca_path.is_some()
        {
            self.load_intermediate_ca().await?;
        }

        match &self.config.state_path {
            Some(path) => {
                // `Path::exists` would turn a permission error into "no file", and an
                // unreadable state file into an empty one.
                match std::fs::exists(path) {
                    Ok(true) => self.load_state(path).await?,
                    Ok(false) => {}
                    Err(e) => {
                        return Err(AuthError::config(format!(
                            "Cannot tell whether state file {} exists: {}",
                            path, e
                        )));
                    }
                }
            }
            None => tracing::warn!(
                "X509CertificateManager has no state_path: issued certificates and revocations are \
                 kept in memory only and are lost on restart"
            ),
        }
        // Whatever the revocation list holds applies to the CAs just (re)loaded from files,
        // with or without a state file.
        self.refresh_after_revocation().await;

        Ok(())
    }

    /// Mark the loaded CA certificates that the revocation list revokes.
    async fn refresh_ca_revocations(&self) {
        let cas: Vec<(String, Vec<u8>)> = self
            .ca_certificates
            .read()
            .await
            .values()
            .filter_map(|ca| {
                pem_certificates(&ca.certificate.certificate_pem)
                    .ok()
                    .map(|mut ders| (ca.ca_id.clone(), ders.remove(0)))
            })
            .collect();
        for (ca_id, der) in cas {
            if self.is_revoked(&der).await
                && let Some(ca) = self.ca_certificates.write().await.get_mut(&ca_id)
            {
                ca.certificate.status = CertificateStatus::Revoked;
            }
        }
    }

    /// Make the stores agree with the revocation list: stored certificates and held CAs that
    /// it revokes are marked revoked.
    async fn refresh_after_revocation(&self) {
        let revoked: std::collections::HashSet<(String, String)> = self
            .revocation_list
            .read()
            .await
            .keys()
            .filter_map(|key| key.split_once('\u{0}'))
            .map(|(ca_id, serial)| (ca_id.to_string(), serial.to_string()))
            .collect();
        for cert in self.certificate_store.write().await.values_mut() {
            if let Some(ca_id) = cert.metadata.get("ca_id").and_then(|v| v.as_str())
                && revoked.contains(&(ca_id.to_string(), cert.serial_number.clone()))
            {
                cert.status = CertificateStatus::Revoked;
            }
        }
        self.refresh_ca_revocations().await;
    }

    /// Write the certificate store, the revocation list and the CRL numbers to `path`: to a
    /// temporary file that is synced and then renamed over `path` (and the directory synced on
    /// Unix). Only one write runs at a time; two managers sharing a path overwrite each other.
    pub async fn save_state(&self, path: &str) -> Result<()> {
        let _one_writer = self.persist_lock.lock().await;
        let state = PersistedState {
            version: 1,
            certificates: self.certificate_store.read().await.clone(),
            revocations: self.revocation_list.read().await.clone(),
            crl_numbers: self.crl_numbers.read().await.clone(),
        };
        let json = serde_json::to_vec_pretty(&state)
            .map_err(|e| AuthError::internal(format!("Failed to encode state: {e}")))?;
        let target = path.to_string();
        tokio::task::spawn_blocking(move || write_state_file(&target, &json))
            .await
            .map_err(|e| AuthError::internal(format!("State writer failed: {e}")))?
    }

    /// Merge the state saved in `path` into the current one: certificates and revocations are
    /// added, a certificate revoked in either is revoked, and a CRL number is the larger of the
    /// two. It can add but never remove a revocation or lower a number, so loading an old copy
    /// cannot un-revoke. A file that cannot be read or parsed is an error and changes nothing.
    pub async fn load_state(&self, path: &str) -> Result<()> {
        let bytes = std::fs::read(path)
            .map_err(|e| AuthError::config(format!("Failed to read state {}: {}", path, e)))?;
        let state: PersistedState = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::config(format!("State file {} is corrupt: {}", path, e)))?;
        if state.version != 1 {
            return Err(AuthError::config(format!(
                "State file {} has unsupported version {}",
                path, state.version
            )));
        }
        {
            let mut store = self.certificate_store.write().await;
            for (id, loaded) in state.certificates {
                match store.get_mut(&id) {
                    Some(existing) => {
                        if loaded.status == CertificateStatus::Revoked {
                            existing.status = CertificateStatus::Revoked;
                        }
                    }
                    None => {
                        store.insert(id, loaded);
                    }
                }
            }
        }
        {
            let mut revocations = self.revocation_list.write().await;
            for (key, entry) in state.revocations {
                revocations.entry(key).or_insert(entry);
            }
        }
        {
            let mut numbers = self.crl_numbers.write().await;
            for (ca_id, number) in state.crl_numbers {
                let slot = numbers.entry(ca_id).or_insert(0);
                *slot = (*slot).max(number);
            }
        }
        self.refresh_after_revocation().await;
        Ok(())
    }

    /// Write the state to `state_path` if one is configured.
    async fn persist(&self) -> Result<()> {
        match &self.config.state_path {
            Some(path) => self.save_state(path).await,
            None => Ok(()),
        }
    }

    /// Load root CA certificate
    async fn load_root_ca(&self) -> Result<()> {
        // Production implementation: Load from secure certificate store or HSM
        // Check for HSM configuration first
        #[cfg(feature = "hsm")]
        if let Ok(hsm_config) = std::env::var("X509_HSM_CONFIG") {
            tracing::info!("Loading CA certificate from HSM: {}", hsm_config);
            // In production, integrate with PKCS#11 or Azure Key Vault
            return self.load_ca_from_hsm(&hsm_config).await;
        }
        #[cfg(not(feature = "hsm"))]
        if std::env::var("X509_HSM_CONFIG").is_ok() {
            tracing::warn!(
                "X509_HSM_CONFIG is set but the 'hsm' feature is not enabled — ignoring"
            );
        }

        // Check for Azure Key Vault configuration
        if let Ok(vault_url) = std::env::var("X509_AZURE_VAULT_URL")
            && let Ok(cert_name) = std::env::var("X509_AZURE_CERT_NAME")
        {
            tracing::warn!(
                "X509_AZURE_VAULT_URL selects the root CA: root_ca_path / root_ca_cert_path / root_ca_key_path are not used"
            );
            tracing::info!("Loading CA certificate from Azure Key Vault: {}", vault_url);
            return self.load_ca_from_azure_vault(&vault_url, &cert_name).await;
        }

        // Check for AWS Secrets Manager configuration
        if let Ok(secret_id) = std::env::var("X509_AWS_SECRET_ID") {
            tracing::warn!(
                "X509_AWS_SECRET_ID selects the root CA: root_ca_path / root_ca_cert_path / root_ca_key_path are not used"
            );
            tracing::info!(
                "Loading CA certificate from AWS Secrets Manager: {}",
                secret_id
            );
            return self.load_ca_from_aws_secrets(&secret_id).await;
        }

        // Fallback to file system loading with proper security validation
        let ca_cert_path = self.root_ca_certificate_path()?;

        tracing::warn!(
            "Loading CA certificate from file system - consider using HSM or secure vault for production"
        );
        self.load_ca_from_file(&ca_cert_path).await
    }

    /// Load CA certificate from HSM (Hardware Security Module) via PKCS#11.
    ///
    /// `hsm_config` must be a JSON object with the following fields:
    /// - `library` (required): absolute path to the PKCS#11 shared library (`.so` / `.dll`)
    /// - `slot` (optional, default `0`): slot index returned by `get_slots_with_initialized_token`
    /// - `pin` (optional): User PIN for login (omit for login-less tokens)
    /// - `label` (optional, default `"ca-cert"`): CKA_LABEL of the certificate object
    ///
    /// # Example config
    /// ```text
    /// {"library":"/usr/lib/softhsm/libsofthsm2.so","slot":0,"pin":"1234","label":"root-ca"}
    /// ```
    #[cfg(feature = "hsm")]
    async fn load_ca_from_hsm(&self, hsm_config: &str) -> Result<()> {
        let config: serde_json::Value = serde_json::from_str(hsm_config)
            .map_err(|e| AuthError::config(format!("Invalid HSM JSON config: {}", e)))?;

        let library = config["library"]
            .as_str()
            .ok_or_else(|| AuthError::config("HSM config missing 'library' path".to_string()))?;

        // Extract optional parameters
        let slot_id = config["slot"].as_u64().unwrap_or(0);
        let pin = config["pin"].as_str().map(|s| s.to_string());
        let _label = config["label"].as_str().unwrap_or("root-ca").to_string();

        // Note: Real PKCS#11 operations are synchronous and may block.
        // We use spawn_blocking to prevent blocking the async runtime.
        let library_path = library.to_string();

        let handle = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            // First, initialize the PKCS#11 context
            let pkcs11 = cryptoki::context::Pkcs11::new(&library_path)
                .map_err(|e| AuthError::config(format!("Failed to load PKCS#11 library: {}", e)))?;

            pkcs11
                .initialize(cryptoki::context::CInitializeArgs::new(
                    cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
                ))
                .map_err(|e| {
                    AuthError::config(format!("Failed to initialize PKCS#11 context: {}", e))
                })?;

            // Get slots
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| AuthError::config(format!("Failed to get PKCS#11 slots: {}", e)))?;

            if slot_id as usize >= slots.len() {
                return Err(AuthError::config(format!(
                    "HSM slot {} not found or has no token",
                    slot_id
                )));
            }
            let slot = slots[slot_id as usize];

            // Open a session
            let session = pkcs11
                .open_ro_session(slot)
                .map_err(|e| AuthError::config(format!("Failed to open PKCS#11 session: {}", e)))?;

            // Login if PIN is provided
            if let Some(p) = pin {
                let auth_pin = cryptoki::types::AuthPin::new(p.into());
                session
                    .login(cryptoki::session::UserType::User, Some(&auth_pin))
                    .map_err(|e| AuthError::config(format!("HSM login failed: {}", e)))?;
            }

            // Find the certificate object by label
            let search_template: Vec<cryptoki::object::Attribute> = vec![
                cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::CERTIFICATE),
                cryptoki::object::Attribute::Label(_label.clone().into_bytes()),
            ];

            let objects = session.find_objects(&search_template).map_err(|e| {
                AuthError::config(format!("Failed to search PKCS#11 objects: {}", e))
            })?;

            if objects.is_empty() {
                return Err(AuthError::config(format!(
                    "Certificate with label '{}' not found in HSM",
                    _label
                )));
            }

            // Read the certificate value (usually CKA_VALUE for X.509 certs)
            let cert_obj = objects[0];
            let attrs = session
                .get_attributes(cert_obj, &[cryptoki::object::AttributeType::Value])
                .map_err(|e| {
                    AuthError::config(format!("Failed to get certificate value from HSM: {}", e))
                })?;

            if attrs.is_empty() {
                return Err(AuthError::config(
                    "Certificate object has no value attribute".to_string(),
                ));
            }

            let value = match &attrs[0] {
                cryptoki::object::Attribute::Value(v) => v.clone(),
                _ => {
                    return Err(AuthError::config(
                        "Invalid value attribute type".to_string(),
                    ));
                }
            };

            Ok(value)
        });

        let cert_der = handle
            .await
            .map_err(|_| AuthError::config("HSM task panicked".to_string()))??;

        // Convert the DER certificate bytes to PEM format and store via the
        // shared helper that all external CA integrations use.
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            BASE64_STANDARD.encode(&cert_der)
        );

        self.store_ca_certificate_from_pem(&cert_pem, &format!("hsm:slot{}", slot_id))
            .await
    }

    async fn load_ca_from_azure_vault(&self, vault_url: &str, cert_name: &str) -> Result<()> {
        let tenant_id = std::env::var("X509_AZURE_TENANT_ID").map_err(|_| {
            AuthError::config(
                "X509_AZURE_TENANT_ID environment variable required for Azure Key Vault authentication"
                    .to_string(),
            )
        })?;
        let client_id = std::env::var("X509_AZURE_CLIENT_ID").map_err(|_| {
            AuthError::config(
                "X509_AZURE_CLIENT_ID environment variable required for Azure Key Vault authentication"
                    .to_string(),
            )
        })?;
        let client_secret = std::env::var("X509_AZURE_CLIENT_SECRET").map_err(|_| {
            AuthError::config(
                "X509_AZURE_CLIENT_SECRET environment variable required for Azure Key Vault authentication"
                    .to_string(),
            )
        })?;

        let http = reqwest::Client::new();

        // Step 1: Client-credentials flow → access token.
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );
        let token_resp = http
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("scope", "https://vault.azure.net/.default"),
            ])
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("Azure AD token request failed: {}", e)))?;

        if !token_resp.status().is_success() {
            let status = token_resp.status();
            let body = token_resp.text().await.unwrap_or_default();
            return Err(AuthError::config(format!(
                "Azure AD token request returned {}: {}",
                status, body
            )));
        }

        let token_json: serde_json::Value = token_resp.json().await.map_err(|e| {
            AuthError::internal(format!("Failed to parse Azure AD token response: {}", e))
        })?;
        let access_token = token_json["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Azure AD response missing 'access_token'"))?
            .to_string();

        // Step 2: Fetch the secret from Key Vault (returns PEM / PKCS#12 bundle).
        let vault_base = vault_url.trim_end_matches('/');
        let secret_url = format!("{}/secrets/{}?api-version=7.4", vault_base, cert_name);
        let cert_resp = http
            .get(&secret_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("Azure Key Vault request failed: {}", e)))?;

        if !cert_resp.status().is_success() {
            let status = cert_resp.status();
            let body = cert_resp.text().await.unwrap_or_default();
            return Err(AuthError::config(format!(
                "Azure Key Vault secret fetch returned {}: {}",
                status, body
            )));
        }

        let cert_json: serde_json::Value = cert_resp.json().await.map_err(|e| {
            AuthError::internal(format!("Failed to parse Azure Key Vault response: {}", e))
        })?;

        let raw_value = cert_json["value"]
            .as_str()
            .ok_or_else(|| AuthError::internal("Azure Key Vault response missing 'value' field"))?
            .to_string();

        let content_type = cert_json["contentType"]
            .as_str()
            .unwrap_or("application/x-pem-file");

        let cert_pem = if content_type == "application/x-pem-file"
            || raw_value.contains("-----BEGIN")
        {
            // PEM bundle — extract only the leaf/CA certificate block.
            x509_extract_certificate_pem(&raw_value)
        } else {
            return Err(AuthError::config(format!(
                "Azure Key Vault certificate '{}' uses content-type '{}'. \
                 Store the certificate as a PEM secret (application/x-pem-file) for automatic import.",
                cert_name, content_type
            )));
        };

        tracing::info!(
            "Successfully loaded CA certificate from Azure Key Vault: {}/{}",
            vault_base,
            cert_name
        );
        self.store_ca_certificate_from_pem(
            &cert_pem,
            &format!("azure_kv:{}/{}", vault_base, cert_name),
        )
        .await
    }

    /// Load CA certificate from AWS Secrets Manager using AWS SigV4 request signing.
    ///
    /// Required environment variables (standard AWS credential chain):
    /// - `AWS_ACCESS_KEY_ID`
    /// - `AWS_SECRET_ACCESS_KEY`
    /// - `AWS_REGION` or `AWS_DEFAULT_REGION`
    /// - `AWS_SESSION_TOKEN` (optional, for temporary credentials)
    ///
    /// The secret value must be a PEM-encoded certificate (or a PEM bundle; the
    /// first `CERTIFICATE` block is extracted automatically).
    async fn load_ca_from_aws_secrets(&self, secret_id: &str) -> Result<()> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            AuthError::config(
                "AWS_ACCESS_KEY_ID environment variable required for Secrets Manager".to_string(),
            )
        })?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            AuthError::config(
                "AWS_SECRET_ACCESS_KEY environment variable required for Secrets Manager"
                    .to_string(),
            )
        })?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| {
                AuthError::config(
                    "AWS_REGION (or AWS_DEFAULT_REGION) environment variable required for Secrets Manager"
                        .to_string(),
                )
            })?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        let service = "secretsmanager";
        let host = format!("{}.{}.amazonaws.com", service, region);
        let payload =
            serde_json::to_vec(&serde_json::json!({ "SecretId": secret_id })).map_err(|e| {
                AuthError::internal(format!(
                    "Failed to serialise Secrets Manager GetSecretValue request: {}",
                    e
                ))
            })?;

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let authorization = AwsSigV4Request::new(&access_key, &secret_key)
            .session_token(session_token.as_deref())
            .region(&region)
            .service(service)
            .method("POST")
            .host(&host)
            .payload(&payload)
            .amz_date(&amz_date)
            .date_stamp(&date_stamp)
            .amz_target("secretsmanager.GetSecretValue")
            .sign();

        let url = format!("https://{}/", host);
        let http = reqwest::Client::new();
        let mut req_builder = http
            .post(&url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "secretsmanager.GetSecretValue")
            .header("X-Amz-Date", &amz_date)
            .header("Authorization", &authorization)
            .body(payload);

        if let Some(ref token) = session_token {
            req_builder = req_builder.header("X-Amz-Security-Token", token.as_str());
        }

        let resp = req_builder.send().await.map_err(|e| {
            AuthError::internal(format!("AWS Secrets Manager request failed: {}", e))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::config(format!(
                "AWS Secrets Manager GetSecretValue returned {}: {}",
                status, body
            )));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| {
            AuthError::internal(format!("Failed to parse Secrets Manager response: {}", e))
        })?;

        let raw_value = if let Some(s) = json["SecretString"].as_str() {
            s.to_string()
        } else if let Some(b64) = json["SecretBinary"].as_str() {
            let bytes = BASE64_STANDARD.decode(b64).map_err(|e| {
                AuthError::internal(format!("Failed to decode SecretBinary: {}", e))
            })?;
            String::from_utf8(bytes).map_err(|e| {
                AuthError::internal(format!("SecretBinary is not valid UTF-8: {}", e))
            })?
        } else {
            return Err(AuthError::config(format!(
                "AWS Secrets Manager secret '{}' contains neither SecretString nor SecretBinary",
                secret_id
            )));
        };

        let cert_pem = if raw_value.contains("-----BEGIN CERTIFICATE-----") {
            x509_extract_certificate_pem(&raw_value)
        } else {
            raw_value
        };

        tracing::info!(
            "Successfully loaded CA certificate from AWS Secrets Manager: {}",
            secret_id
        );
        self.store_ca_certificate_from_pem(&cert_pem, &format!("aws_secrets:{}", secret_id))
            .await
    }

    /// Path of the root CA certificate. `root_ca_path` and `root_ca_cert_path` name the same
    /// setting; if both are set they must agree.
    fn root_ca_certificate_path(&self) -> Result<String> {
        let (a, b) = (&self.config.root_ca_path, &self.config.root_ca_cert_path);
        match (a.is_empty(), b.is_empty()) {
            (true, true) => Ok("ca/root-ca.pem".to_string()),
            (false, true) => Ok(a.clone()),
            (true, false) => Ok(b.clone()),
            (false, false) if a == b => Ok(a.clone()),
            (false, false) => Err(AuthError::config(format!(
                "root_ca_path ({a}) and root_ca_cert_path ({b}) are the same setting and must agree"
            ))),
        }
    }

    /// Read a CA certificate from PEM: the first certificate in the text must parse, be a
    /// usable CA, and be valid now. Returns its normalised PEM, DER and the facts read from it.
    fn parse_ca_pem(&self, pem: &str) -> Result<(String, Vec<u8>, CertificateFacts)> {
        let der = pem_certificates(pem)?.remove(0);
        ensure_ca_certificate(&der)?;
        let facts = certificate_facts(&der)?;
        Ok((der_to_pem(&der), der, facts))
    }

    /// Load the CA signing key at `key_path`, if there is one. A key that exists must be
    /// usable and must belong to the certificate; a missing key leaves the CA verify-only.
    fn load_signing_key(key_path: &str, cert_der: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if key_path.is_empty() || !std::path::Path::new(key_path).exists() {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let bytes = Zeroizing::new(std::fs::read(key_path).map_err(|e| {
            AuthError::config(format!("Failed to read CA key {}: {}", key_path, e))
        })?);
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| AuthError::config(format!("CA key {} is not PEM text", key_path)))?;
        let key = rcgen::KeyPair::from_pem(text).map_err(|e| {
            AuthError::config(format!(
                "CA key {} is not a usable private key: {}",
                key_path, e
            ))
        })?;
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| AuthError::config(format!("Invalid CA certificate: {e}")))?;
        if cert.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err(AuthError::config(format!(
                "CA key {} does not belong to the CA certificate",
                key_path
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(key_path)
                && meta.permissions().mode() & 0o077 != 0
            {
                tracing::warn!("CA key {} is readable by group or others", key_path);
            }
        }
        Ok(bytes)
    }

    /// Create a development root CA: the certificate at `cert_path` and its key at
    /// `key_path`. The key is written once, never over an existing file, owner-only on Unix,
    /// and is loaded back from there like any configured key, so a restart keeps the same
    /// root. With no `key_path` there is nowhere to keep the key, and nothing is generated.
    async fn generate_development_root_ca(&self, cert_path: &str, key_path: &str) -> Result<()> {
        if !self.config.generate_development_root_ca {
            return Err(AuthError::config(format!(
                "Root CA certificate not found at {cert_path}; set generate_development_root_ca                  to create a development root there (never for production)"
            )));
        }
        if key_path.is_empty() {
            return Err(AuthError::config(format!(
                "Root CA certificate not found at {cert_path} and no root_ca_key_path is configured; \
                 refusing to generate a CA whose key cannot be kept"
            )));
        }
        if std::path::Path::new(key_path).exists() {
            return Err(AuthError::config(format!(
                "Root CA certificate not found at {cert_path} but a key exists at {key_path}; \
                 refusing to overwrite it"
            )));
        }
        tracing::warn!(
            "Root CA certificate not found at {}, generating a development root CA (key at {})",
            cert_path,
            key_path
        );
        let (cert_pem, key_pem) = self.generate_self_signed_root_ca().await?;
        write_new_file(key_path, key_pem.as_bytes(), true)?;
        if let Err(e) = write_new_file(cert_path, cert_pem.as_bytes(), false) {
            let _ = std::fs::remove_file(key_path);
            return Err(e);
        }
        Ok(())
    }

    /// Build a CA entry from a parsed certificate.
    fn ca_entry(
        ca_id: &str,
        ca_type: CAType,
        pem: String,
        facts: CertificateFacts,
        private_key: Zeroizing<Vec<u8>>,
        source: &str,
    ) -> CACertificate {
        let profile = match ca_type {
            CAType::Root => "root_ca",
            CAType::Intermediate => "intermediate_ca",
        };
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), Value::String(source.to_string()));
        let certificate = StoredCertificate {
            cert_id: ca_id.to_string(),
            certificate_pem: pem,
            private_key_pem: None, // never kept on the certificate record
            subject: facts.subject.clone(),
            issuer: facts.issuer,
            serial_number: facts.serial,
            not_before: facts.not_before,
            not_after: facts.not_after,
            profile: profile.to_string(),
            status: CertificateStatus::Valid,
            fingerprint: facts.fingerprint,
            created_at: Utc::now(),
            metadata,
        };
        CACertificate {
            ca_id: ca_id.to_string(),
            certificate,
            subject: facts.subject,
            private_key,
            ca_type,
            issued_count: 0,
        }
    }

    /// Load CA certificate from file system (with security validation)
    async fn load_ca_from_file(&self, ca_cert_path: &str) -> Result<()> {
        let key_path = self.config.root_ca_key_path.clone();
        if !std::path::Path::new(ca_cert_path).exists() {
            self.generate_development_root_ca(ca_cert_path, &key_path)
                .await?;
        }

        let cert_content = tokio::fs::read_to_string(ca_cert_path)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to read CA certificate: {}", e)))?;
        let (pem, der, facts) = self.parse_ca_pem(&cert_content).map_err(|e| {
            AuthError::config(format!(
                "CA certificate {} is not usable: {}",
                ca_cert_path, e
            ))
        })?;
        let private_key = Self::load_signing_key(&key_path, &der)?;

        let ca = Self::ca_entry(
            "root_ca",
            CAType::Root,
            pem,
            facts,
            private_key,
            &format!("file:{}", ca_cert_path),
        );
        self.ca_certificates
            .write()
            .await
            .insert("root_ca".to_string(), ca);
        Ok(())
    }

    /// Load intermediate CA certificate
    async fn load_intermediate_ca(&self) -> Result<()> {
        let path = match (
            &self.config.intermediate_ca_cert_path,
            &self.config.intermediate_ca_path,
        ) {
            (Some(a), Some(b)) if a != b => {
                return Err(AuthError::config(format!(
                    "intermediate_ca_cert_path ({a}) and intermediate_ca_path ({b}) are the same \
                     setting and must agree"
                )));
            }
            (Some(path), _) | (None, Some(path)) => path.clone(),
            (None, None) => return Ok(()),
        };

        let cert_content = tokio::fs::read_to_string(&path).await.map_err(|e| {
            AuthError::config(format!("Failed to read intermediate CA {}: {}", path, e))
        })?;
        let (pem, der, facts) = self.parse_ca_pem(&cert_content).map_err(|e| {
            AuthError::config(format!("Intermediate CA {} is not usable: {}", path, e))
        })?;

        // It must be issued under a CA we hold. (The signature itself is checked whenever a
        // path through this intermediate is validated, which is also done on every issuance.)
        let issuer_known = self
            .ca_certificates
            .read()
            .await
            .values()
            .any(|ca| ca.subject == facts.issuer);
        if !issuer_known {
            return Err(AuthError::config(format!(
                "Intermediate CA {} was issued by '{}', which is not a loaded CA",
                path, facts.issuer
            )));
        }

        let key_path = self
            .config
            .intermediate_ca_key_path
            .clone()
            .unwrap_or_default();
        let private_key = Self::load_signing_key(&key_path, &der)?;
        let ca = Self::ca_entry(
            "intermediate_ca",
            CAType::Intermediate,
            pem,
            facts,
            private_key,
            &format!("file:{}", path),
        );
        self.ca_certificates
            .write()
            .await
            .insert("intermediate_ca".to_string(), ca);

        tracing::info!("Loaded intermediate CA certificate");
        Ok(())
    }

    /// Sign certificate request
    ///
    /// The certificate carries the public key in `request.public_key_pem` and is signed by the
    /// private key of CA `ca_id`, which must have been loaded (a CA without its key is
    /// verify-only and this returns an error) and must not be revoked. The request is a bare
    /// public key, not a CSR, so there is no proof that the requester holds the matching
    /// private key, and the names are only checked for form: **the caller must authenticate
    /// and authorise the requester, the names, the profile and the key.** Requests are refused
    /// (never partly honoured) when they ask for something the profile or the name and key
    /// policy does not allow, when they carry `attributes` (not supported), or when the profile
    /// uses `extensions` (not supported). CA profiles are not issuable here. The serial number
    /// is random (126 bits) and the issued certificate is verified to chain to the configured
    /// CAs before it is returned.
    pub async fn sign_certificate_request(
        &self,
        request: &CertificateRequest,
        ca_id: &str,
    ) -> Result<StoredCertificate> {
        // Get CA certificate
        let ca = {
            let cas = self.ca_certificates.read().await;
            cas.get(ca_id)
                .ok_or_else(|| AuthError::InvalidRequest(format!("CA not found: {}", ca_id)))?
                .clone()
        };
        let ca_revoked = match pem_certificates(&ca.certificate.certificate_pem) {
            Ok(mut ders) => self.is_revoked(&ders.remove(0)).await,
            Err(_) => true,
        };
        if ca.certificate.status == CertificateStatus::Revoked || ca_revoked {
            return Err(AuthError::InvalidRequest(format!(
                "CA '{}' has been revoked and cannot issue certificates",
                ca_id
            )));
        }
        if ca.private_key.is_empty() {
            return Err(AuthError::config(format!(
                "CA '{}' has no signing key loaded; it can validate certificates but not issue them",
                ca_id
            )));
        }

        // Get certificate profile
        let profile = self
            .config
            .certificate_profiles
            .get(&request.profile)
            .ok_or_else(|| {
                AuthError::InvalidRequest(format!(
                    "Certificate profile not found: {}",
                    request.profile
                ))
            })?;
        if matches!(
            profile.cert_type,
            CertificateType::RootCA | CertificateType::IntermediateCA
        ) {
            return Err(AuthError::InvalidRequest(format!(
                "Profile '{}' is a CA profile; CA certificates are not issued through certificate requests",
                request.profile
            )));
        }
        validate_profile(&request.profile, profile)?;
        validate_request(request, profile)?;
        let validity_days = match profile.validity_days {
            days if days > 0 => days,
            0 => self.config.default_validity_days,
            days => {
                return Err(AuthError::config(format!(
                    "Profile '{}' has a negative validity ({days} days)",
                    request.profile
                )));
            }
        };
        if validity_days <= 0 {
            return Err(AuthError::config(
                "Neither the profile nor default_validity_days gives a positive validity"
                    .to_string(),
            ));
        }

        let serial = self.new_serial(ca_id).await?;
        let certificate_pem =
            self.generate_certificate_pem(request, profile, &ca, &serial, validity_days)?;

        // Never hand out a certificate that does not chain to the CAs we trust.
        let der = pem_certificates(&certificate_pem)?.remove(0);
        if let Err(reason) = self.verify_path(&der, &[], profile_purpose(profile)).await {
            return Err(AuthError::internal(format!(
                "Issued certificate does not validate against the configured CAs: {reason}"
            )));
        }
        let facts = certificate_facts(&der)?;

        let mut metadata = HashMap::new();
        metadata.insert("ca_id".to_string(), Value::String(ca_id.to_string()));
        metadata.insert(
            "request_id".to_string(),
            Value::String(request.request_id.clone()),
        );
        metadata.insert(
            "requester".to_string(),
            Value::String(request.requester.clone()),
        );
        metadata.insert(
            "requested_at".to_string(),
            Value::String(request.requested_at.to_rfc3339()),
        );
        let certificate = StoredCertificate {
            cert_id: Uuid::new_v4().to_string(),
            certificate_pem,
            private_key_pem: None, // Certificate doesn't include private key
            subject: facts.subject,
            issuer: facts.issuer,
            serial_number: facts.serial,
            not_before: facts.not_before,
            not_after: facts.not_after,
            profile: request.profile.clone(),
            status: CertificateStatus::Valid,
            fingerprint: facts.fingerprint,
            created_at: Utc::now(),
            metadata,
        };

        // Store certificate; if it cannot be recorded durably it is not handed out.
        self.certificate_store
            .write()
            .await
            .insert(certificate.cert_id.clone(), certificate.clone());
        if let Err(e) = self.persist().await {
            self.certificate_store
                .write()
                .await
                .remove(&certificate.cert_id);
            return Err(e);
        }

        // Update CA issued count
        self.increment_ca_issued_count(ca_id).await?;

        Ok(certificate)
    }

    /// A fresh random serial number for `ca_id`: 16 bytes from the system RNG with the top bit
    /// clear and the next bit set (so it is positive and 126 bits wide), not already used by
    /// that CA.
    async fn new_serial(&self, ca_id: &str) -> Result<Vec<u8>> {
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        for _ in 0..8 {
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes)
                .map_err(|_| AuthError::internal("System random number generator failed"))?;
            bytes[0] = (bytes[0] & 0x7f) | 0x40;
            let decimal = x509_parser::num_bigint::BigUint::from_bytes_be(&bytes).to_string();
            let in_use = self.certificate_store.read().await.values().any(|cert| {
                cert.serial_number == decimal
                    && cert.metadata.get("ca_id").and_then(|v| v.as_str()) == Some(ca_id)
            });
            if !in_use {
                return Ok(bytes.to_vec());
            }
        }
        Err(AuthError::internal(
            "Could not find an unused serial number",
        ))
    }

    /// Generate the certificate with rcgen: the requester's public key, signed by `ca`.
    fn generate_certificate_pem(
        &self,
        request: &CertificateRequest,
        profile: &CertificateProfile,
        ca: &CACertificate,
        serial: &[u8],
        validity_days: i64,
    ) -> Result<String> {
        use rcgen::{
            CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, SanType,
            SerialNumber,
        };

        let invalid = |what: &str, e: &dyn fmt::Display| {
            AuthError::InvalidRequest(format!("Invalid {what}: {e}"))
        };

        let subject_key = rcgen::SubjectPublicKeyInfo::from_pem(&request.public_key_pem)
            .map_err(|e| invalid("public_key_pem (expected a PEM SubjectPublicKeyInfo)", &e))?;

        let ca_key_pem = std::str::from_utf8(&ca.private_key)
            .map_err(|_| AuthError::internal("CA signing key is not PEM text"))?;
        let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)
            .map_err(|e| AuthError::internal(format!("CA signing key unusable: {e}")))?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.certificate.certificate_pem, ca_key)
            .map_err(|e| AuthError::internal(format!("CA certificate unusable as issuer: {e}")))?;

        let mut params = CertificateParams::default();

        // Set distinguished name
        params
            .distinguished_name
            .push(DnType::CommonName, &request.subject.common_name);
        if let Some(ref org) = request.subject.organization {
            params
                .distinguished_name
                .push(DnType::OrganizationName, org);
        }
        if let Some(ref ou) = request.subject.organizational_unit {
            params
                .distinguished_name
                .push(DnType::OrganizationalUnitName, ou);
        }
        if let Some(ref country) = request.subject.country {
            params.distinguished_name.push(DnType::CountryName, country);
        }
        if let Some(ref state) = request.subject.state {
            params
                .distinguished_name
                .push(DnType::StateOrProvinceName, state);
        }
        if let Some(ref locality) = request.subject.locality {
            params
                .distinguished_name
                .push(DnType::LocalityName, locality);
        }

        params.serial_number = Some(SerialNumber::from(serial.to_vec()));

        // Validity: backdated a little for clock skew, never beyond the CA's own.
        let now = Utc::now();
        let not_before = (now - Duration::minutes(5)).max(ca.certificate.not_before);
        let not_after = chrono::TimeDelta::try_days(validity_days)
            .and_then(|span| now.checked_add_signed(span))
            .ok_or_else(|| {
                AuthError::InvalidRequest(format!(
                    "Validity of {validity_days} days is out of range"
                ))
            })?
            .min(ca.certificate.not_after);
        let to_time = |instant: DateTime<Utc>| {
            time::OffsetDateTime::from_unix_timestamp(instant.timestamp())
                .map_err(|e| AuthError::internal(format!("Invalid time: {e}")))
        };
        params.not_before = to_time(not_before)?;
        params.not_after = to_time(not_after)?;
        if params.not_after <= params.not_before {
            return Err(AuthError::InvalidRequest(
                "The CA certificate expires before any certificate could be issued".to_string(),
            ));
        }

        // Set key usages
        params.key_usages = profile
            .key_usage
            .iter()
            .map(|ku| match ku {
                KeyUsage::DigitalSignature => KeyUsagePurpose::DigitalSignature,
                KeyUsage::NonRepudiation => KeyUsagePurpose::ContentCommitment,
                KeyUsage::KeyEncipherment => KeyUsagePurpose::KeyEncipherment,
                KeyUsage::DataEncipherment => KeyUsagePurpose::DataEncipherment,
                KeyUsage::KeyAgreement => KeyUsagePurpose::KeyAgreement,
                KeyUsage::KeyCertSign => KeyUsagePurpose::KeyCertSign,
                KeyUsage::CrlSign => KeyUsagePurpose::CrlSign,
                KeyUsage::EncipherOnly => KeyUsagePurpose::EncipherOnly,
                KeyUsage::DecipherOnly => KeyUsagePurpose::DecipherOnly,
            })
            .collect();

        // Set extended key usages
        params.extended_key_usages = profile
            .extended_key_usage
            .iter()
            .map(|eku| match eku {
                ExtendedKeyUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsage::ClientAuth => ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsage::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
                ExtendedKeyUsage::EmailProtection => ExtendedKeyUsagePurpose::EmailProtection,
                ExtendedKeyUsage::TimeStamping => ExtendedKeyUsagePurpose::TimeStamping,
                ExtendedKeyUsage::OcspSigning => ExtendedKeyUsagePurpose::OcspSigning,
            })
            .collect();

        // Subject alternative names (already checked by the policy): the profile's own, the
        // requested ones, and the subject e-mail address.
        let mut sans = Vec::new();
        for san in profile
            .subject_alt_names
            .iter()
            .chain(request.subject_alt_names.iter())
        {
            sans.push(match san {
                SubjectAltName::DnsName(name) => SanType::DnsName(
                    name.clone()
                        .try_into()
                        .map_err(|e| invalid("DNS subject alternative name", &e))?,
                ),
                SubjectAltName::Email(email) => SanType::Rfc822Name(
                    email
                        .clone()
                        .try_into()
                        .map_err(|e| invalid("email subject alternative name", &e))?,
                ),
                SubjectAltName::IpAddress(ip) => SanType::IpAddress(
                    ip.parse()
                        .map_err(|e| invalid("IP subject alternative name", &e))?,
                ),
                SubjectAltName::Uri(uri) => SanType::URI(
                    uri.clone()
                        .try_into()
                        .map_err(|e| invalid("URI subject alternative name", &e))?,
                ),
            });
        }
        if let Some(email) = &request.subject.email {
            sans.push(SanType::Rfc822Name(
                email
                    .clone()
                    .try_into()
                    .map_err(|e| invalid("subject email address", &e))?,
            ));
        }
        params.subject_alt_names = sans;

        // End entity: basicConstraints cA=FALSE, subject and authority key identifiers, and the
        // CRL distribution point when one is configured.
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        if let Some(url) = &self.config.crl_distribution_url {
            params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
                uris: vec![url.clone()],
            }];
        }

        let cert = params
            .signed_by(&subject_key, &issuer)
            .map_err(|e| AuthError::internal(format!("Certificate signing failed: {}", e)))?;
        Ok(cert.pem())
    }

    /// Increment CA issued certificate count
    async fn increment_ca_issued_count(&self, ca_id: &str) -> Result<()> {
        let mut cas = self.ca_certificates.write().await;
        let ca = cas
            .get_mut(ca_id)
            .ok_or_else(|| AuthError::InvalidRequest(format!("CA not found: {}", ca_id)))?;

        ca.issued_count += 1;

        Ok(())
    }

    /// Key under which a revocation is kept: serial numbers are only unique per issuer.
    fn revocation_key(ca_id: &str, serial_number: &str) -> String {
        format!("{}\u{0}{}", ca_id, serial_number)
    }

    /// `RemoveFromCrl` (reason 8) only means "un-revoke" in a delta CRL; it is not a reason
    /// to revoke.
    fn check_revocation_reason(reason: &RevocationReason) -> Result<()> {
        if *reason == RevocationReason::RemoveFromCrl {
            return Err(AuthError::InvalidRequest(
                "RemoveFromCrl is not a reason to revoke a certificate".to_string(),
            ));
        }
        Ok(())
    }

    /// The CA that issued the one stored certificate with this serial number. A serial number
    /// is unique only within one issuer, so a serial held by certificates of two CAs (or by
    /// none) is an error; use the `*_issued_by` methods to name the issuer.
    async fn sole_issuer_of_serial(&self, serial_number: &str) -> Result<String> {
        let store = self.certificate_store.read().await;
        let mut issuers: Vec<String> = store
            .values()
            .filter(|cert| cert.serial_number == serial_number)
            .filter_map(|cert| {
                cert.metadata
                    .get("ca_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect();
        issuers.sort();
        issuers.dedup();
        let mut issuers = issuers.into_iter();
        match (issuers.next(), issuers.next()) {
            (Some(only), None) => Ok(only),
            (None, _) => Err(AuthError::InvalidRequest(
                "Certificate not found".to_string(),
            )),
            (Some(_), Some(_)) => Err(AuthError::InvalidRequest(
                "Serial number is held by certificates of more than one CA; name the issuing CA"
                    .to_string(),
            )),
        }
    }

    /// Revoke certificate
    ///
    /// Fails if no stored certificate has this serial number, or if certificates of more than
    /// one CA do (use [`revoke_certificate_issued_by`](Self::revoke_certificate_issued_by)).
    pub async fn revoke_certificate(
        &self,
        serial_number: &str,
        reason: RevocationReason,
        additional_info: Option<String>,
    ) -> Result<()> {
        let ca_id = self.sole_issuer_of_serial(serial_number).await?;
        self.revoke_certificate_issued_by(&ca_id, serial_number, reason, additional_info)
            .await
    }

    /// Revoke the certificate with `serial_number` issued by CA `ca_id`. The revocation is
    /// written to `state_path` (when set) before this returns; if that fails, the revocation
    /// stays in force in memory and the error is returned.
    pub async fn revoke_certificate_issued_by(
        &self,
        ca_id: &str,
        serial_number: &str,
        reason: RevocationReason,
        additional_info: Option<String>,
    ) -> Result<()> {
        Self::check_revocation_reason(&reason)?;

        // The serial may be that of a CA certificate this manager holds, issued by `ca_id`:
        // that is a CA revocation, and takes the CA out of service.
        let held_ca = {
            let cas = self.ca_certificates.read().await;
            let issuer_subject = cas.get(ca_id).map(|ca| ca.subject.clone());
            cas.values()
                .find(|ca| {
                    ca.certificate.serial_number == serial_number
                        && issuer_subject.as_deref() == Some(ca.certificate.issuer.as_str())
                })
                .map(|ca| ca.ca_id.clone())
        };
        if let Some(held_ca) = held_ca {
            return self
                .revoke_ca_certificate(&held_ca, reason, additional_info)
                .await;
        }

        // Update certificate status
        {
            let mut store = self.certificate_store.write().await;
            let cert = store
                .values_mut()
                .find(|cert| {
                    cert.serial_number == serial_number
                        && cert.metadata.get("ca_id").and_then(|v| v.as_str()) == Some(ca_id)
                })
                .ok_or_else(|| AuthError::InvalidRequest("Certificate not found".to_string()))?;
            cert.status = CertificateStatus::Revoked;
        }

        // Add to revocation list
        let revocation_entry = RevocationEntry {
            serial_number: serial_number.to_string(),
            revocation_date: Utc::now(),
            reason,
            additional_info,
        };

        self.revocation_list
            .write()
            .await
            .insert(Self::revocation_key(ca_id, serial_number), revocation_entry);

        self.refresh_after_revocation().await;
        self.persist().await
    }

    /// Revoke a certificate given as PEM, without it having to be in the store (for example
    /// after a restart of a manager with no `state_path`). It must have been signed by one of
    /// this manager's CAs. A stored copy, if any, is marked revoked.
    pub async fn revoke_certificate_pem(
        &self,
        cert_pem: &str,
        reason: RevocationReason,
        additional_info: Option<String>,
    ) -> Result<()> {
        Self::check_revocation_reason(&reason)?;
        let der = pem_certificates(cert_pem)?.remove(0);
        let facts = certificate_facts(&der)?;
        let (_, cert) = parse_x509_certificate(&der)
            .map_err(|e| AuthError::InvalidRequest(format!("Not a valid certificate: {e}")))?;

        let candidates: Vec<(String, String)> = self
            .ca_certificates
            .read()
            .await
            .values()
            .filter(|ca| ca.subject == facts.issuer)
            .map(|ca| (ca.ca_id.clone(), ca.certificate.certificate_pem.clone()))
            .collect();
        let mut issuing_ca = None;
        for (ca_id, ca_pem) in candidates {
            let Ok(mut ca_ders) = pem_certificates(&ca_pem) else {
                continue;
            };
            let ca_der = ca_ders.remove(0);
            if let Ok((_, ca_cert)) = parse_x509_certificate(&ca_der)
                && cert.verify_signature(Some(ca_cert.public_key())).is_ok()
            {
                issuing_ca = Some(ca_id);
                break;
            }
        }
        let ca_id = issuing_ca.ok_or_else(|| {
            AuthError::InvalidRequest(
                "Certificate was not issued by a CA of this manager".to_string(),
            )
        })?;

        for stored in self.certificate_store.write().await.values_mut() {
            if stored.serial_number == facts.serial
                && stored.metadata.get("ca_id").and_then(|v| v.as_str()) == Some(ca_id.as_str())
            {
                stored.status = CertificateStatus::Revoked;
            }
        }
        self.revocation_list.write().await.insert(
            Self::revocation_key(&ca_id, &facts.serial),
            RevocationEntry {
                serial_number: facts.serial,
                revocation_date: Utc::now(),
                reason,
                additional_info,
            },
        );
        // The certificate may be one of this manager's own CAs: take it out of service.
        self.refresh_after_revocation().await;
        self.persist().await
    }

    /// Revoke a CA certificate held by this manager. It is recorded against the CA(s) that
    /// issued it (for a root, itself), marked revoked, never used as a trust anchor or
    /// intermediate again, and can no longer issue.
    pub async fn revoke_ca_certificate(
        &self,
        ca_id: &str,
        reason: RevocationReason,
        additional_info: Option<String>,
    ) -> Result<()> {
        Self::check_revocation_reason(&reason)?;
        let (serial, issuer) = {
            let cas = self.ca_certificates.read().await;
            let ca = cas
                .get(ca_id)
                .ok_or_else(|| AuthError::InvalidRequest(format!("CA not found: {}", ca_id)))?;
            (
                ca.certificate.serial_number.clone(),
                ca.certificate.issuer.clone(),
            )
        };
        let issuers: Vec<String> = self
            .ca_certificates
            .read()
            .await
            .values()
            .filter(|ca| ca.subject == issuer)
            .map(|ca| ca.ca_id.clone())
            .collect();
        if issuers.is_empty() {
            return Err(AuthError::InvalidRequest(format!(
                "The issuer of CA '{}' is not a loaded CA, so there is no list to record the revocation in",
                ca_id
            )));
        }
        {
            let mut revoked = self.revocation_list.write().await;
            for issuer_id in &issuers {
                revoked.insert(
                    Self::revocation_key(issuer_id, &serial),
                    RevocationEntry {
                        serial_number: serial.clone(),
                        revocation_date: Utc::now(),
                        reason: reason.clone(),
                        additional_info: additional_info.clone(),
                    },
                );
            }
        }
        if let Some(ca) = self.ca_certificates.write().await.get_mut(ca_id) {
            ca.certificate.status = CertificateStatus::Revoked;
        }
        self.persist().await
    }

    /// Check certificate status (see [`revoke_certificate`](Self::revoke_certificate) for how
    /// the serial number is resolved).
    pub async fn check_certificate_status(&self, serial_number: &str) -> Result<CertificateStatus> {
        let ca_id = self.sole_issuer_of_serial(serial_number).await?;
        self.check_certificate_status_issued_by(&ca_id, serial_number)
            .await
    }

    /// Check the status of the certificate with `serial_number` issued by CA `ca_id`.
    pub async fn check_certificate_status_issued_by(
        &self,
        ca_id: &str,
        serial_number: &str,
    ) -> Result<CertificateStatus> {
        // Check revocation list first
        if self
            .revocation_list
            .read()
            .await
            .contains_key(&Self::revocation_key(ca_id, serial_number))
        {
            return Ok(CertificateStatus::Revoked);
        }

        // Check certificate store
        let store = self.certificate_store.read().await;
        for cert in store.values() {
            if cert.serial_number == serial_number
                && cert.metadata.get("ca_id").and_then(|v| v.as_str()) == Some(ca_id)
            {
                // Check expiration
                if Utc::now() > cert.not_after {
                    return Ok(CertificateStatus::Expired);
                }
                return Ok(cert.status.clone());
            }
        }

        Err(AuthError::InvalidRequest(
            "Certificate not found".to_string(),
        ))
    }

    /// Get certificate by ID
    pub async fn get_certificate(&self, cert_id: &str) -> Result<Option<StoredCertificate>> {
        let store = self.certificate_store.read().await;
        Ok(store.get(cert_id).cloned())
    }

    /// List certificates
    pub async fn list_certificates(
        &self,
        filter: Option<CertificateFilter>,
    ) -> Result<Vec<StoredCertificate>> {
        let store = self.certificate_store.read().await;
        let mut certificates: Vec<StoredCertificate> = store.values().cloned().collect();

        // Apply filter if provided
        if let Some(f) = filter {
            certificates.retain(|cert| f.matches(cert));
        }

        Ok(certificates)
    }

    /// Generate a Certificate Revocation List (CRL) for CA `ca_id`: a DER CRL signed by the
    /// CA's key, as PEM, listing the certificates that CA issued and that were revoked. Fails
    /// if CRLs are disabled in the configuration or the CA has no signing key loaded. The CRL
    /// number increases with every CRL, across restarts when `state_path` is set.
    pub async fn generate_crl(&self, ca_id: &str) -> Result<String> {
        if !self.config.enable_crl {
            return Err(AuthError::config(
                "CRL generation is disabled (enable_crl = false)".to_string(),
            ));
        }
        let ca = {
            let cas = self.ca_certificates.read().await;
            cas.get(ca_id)
                .ok_or_else(|| AuthError::InvalidRequest(format!("CA not found: {}", ca_id)))?
                .clone()
        };
        if ca.private_key.is_empty() {
            return Err(AuthError::config(format!(
                "CA '{}' has no signing key loaded; it cannot sign a CRL",
                ca_id
            )));
        }

        // The revocation snapshot and the CRL number are taken together: a CRL with a higher
        // number never lacks a revocation that a lower-numbered one had. (Strictly increasing
        // per CA, and never below the clock, so a restart without saved state moves forward.)
        let now = Utc::now();
        let revocations = self.revocation_list.read().await;
        let crl_number = {
            let mut numbers = self.crl_numbers.write().await;
            let last = numbers.get(ca_id).copied().unwrap_or(0);
            let next = last.saturating_add(1).max(now.timestamp().max(0) as u64);
            numbers.insert(ca_id.to_string(), next);
            next
        };
        let prefix = Self::revocation_key(ca_id, "");
        let mut revoked_certs = Vec::new();
        for (key, entry) in revocations.iter() {
            if !key.starts_with(&prefix) {
                continue;
            }
            let serial =
                x509_parser::num_bigint::BigUint::parse_bytes(entry.serial_number.as_bytes(), 10)
                    .ok_or_else(|| {
                    AuthError::internal(format!(
                        "Serial number {} is not numeric",
                        entry.serial_number
                    ))
                })?;
            revoked_certs.push(rcgen::RevokedCertParams {
                serial_number: rcgen::SerialNumber::from(serial.to_bytes_be()),
                revocation_time: time::OffsetDateTime::from_unix_timestamp(
                    entry.revocation_date.timestamp(),
                )
                .map_err(|e| AuthError::internal(format!("Invalid revocation time: {e}")))?,
                reason_code: match entry.reason {
                    // reasonCode 0 is the default and is left out (RFC 5280, 5.3.1)
                    RevocationReason::Unspecified => None,
                    RevocationReason::KeyCompromise => Some(rcgen::RevocationReason::KeyCompromise),
                    RevocationReason::CaCompromise => Some(rcgen::RevocationReason::CaCompromise),
                    RevocationReason::AffiliationChanged => {
                        Some(rcgen::RevocationReason::AffiliationChanged)
                    }
                    RevocationReason::Superseded => Some(rcgen::RevocationReason::Superseded),
                    RevocationReason::CessationOfOperation => {
                        Some(rcgen::RevocationReason::CessationOfOperation)
                    }
                    RevocationReason::CertificateHold => {
                        Some(rcgen::RevocationReason::CertificateHold)
                    }
                    RevocationReason::PrivilegeWithdrawn => {
                        Some(rcgen::RevocationReason::PrivilegeWithdrawn)
                    }
                    RevocationReason::AaCompromise => Some(rcgen::RevocationReason::AaCompromise),
                    RevocationReason::RemoveFromCrl => {
                        return Err(AuthError::internal(
                            "A revocation with reason RemoveFromCrl cannot be listed",
                        ));
                    }
                },
                invalidity_date: None,
            });
        }
        let revoked_count = revoked_certs.len();
        drop(revocations);

        let ca_key_pem = std::str::from_utf8(&ca.private_key)
            .map_err(|_| AuthError::internal("CA signing key is not PEM text"))?;
        let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)
            .map_err(|e| AuthError::internal(format!("CA signing key unusable: {e}")))?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.certificate.certificate_pem, ca_key)
            .map_err(|e| AuthError::internal(format!("CA certificate unusable as issuer: {e}")))?;

        let this_update =
            time::OffsetDateTime::from_unix_timestamp((now - Duration::minutes(5)).timestamp())
                .map_err(|e| AuthError::internal(format!("Invalid time: {e}")))?;
        let params = rcgen::CertificateRevocationListParams {
            this_update,
            next_update: this_update + time::Duration::days(7), // CRL valid for 7 days
            crl_number: rcgen::SerialNumber::from(crl_number.to_be_bytes().to_vec()),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = params
            .signed_by(&issuer)
            .map_err(|e| AuthError::internal(format!("CRL signing failed: {e}")))?;
        let crl_pem = crl
            .pem()
            .map_err(|e| AuthError::internal(format!("CRL encoding failed: {e}")))?;
        self.persist().await?;

        tracing::info!(
            "Generated CRL for CA {} with {} revoked certificates",
            ca_id,
            revoked_count
        );
        Ok(crl_pem)
    }

    /// Build and verify the certification path of `leaf_der` against the configured CAs:
    /// the root CAs are the trust anchors; the loaded intermediate CAs and `extra` (certificates
    /// the caller presented with it) are candidate intermediates. Revoked CAs are not used.
    /// Signatures, validity of every certificate, basicConstraints / pathLen, name constraints
    /// and the extended key usage for `purpose` are checked by `rustls-webpki`.
    async fn verify_path(
        &self,
        leaf_der: &[u8],
        extra: &[Vec<u8>],
        purpose: CertificatePurpose,
    ) -> std::result::Result<(), String> {
        let (anchors, mut intermediates) = {
            let cas = self.ca_certificates.read().await;
            let mut anchors = Vec::new();
            let mut intermediates = Vec::new();
            for ca in cas.values() {
                if ca.certificate.status == CertificateStatus::Revoked {
                    continue;
                }
                let Ok(mut der) = pem_certificates(&ca.certificate.certificate_pem) else {
                    continue;
                };
                match ca.ca_type {
                    CAType::Root => anchors.push(der.remove(0)),
                    CAType::Intermediate => intermediates.push(der.remove(0)),
                }
            }
            (anchors, intermediates)
        };
        intermediates.extend(extra.iter().cloned());

        crate::server::security::mtls::verify_chain_for_usage(
            leaf_der,
            &intermediates,
            &anchors,
            purpose_usage(purpose),
        )
    }

    /// Whether this manager has revoked the certificate: a revocation recorded by any CA we
    /// hold whose subject is the certificate's issuer, for the certificate's serial number.
    async fn is_revoked(&self, cert_der: &[u8]) -> bool {
        let Ok(facts) = certificate_facts(cert_der) else {
            return true; // cannot be read: do not vouch for it
        };
        let issuer_ids: Vec<String> = self
            .ca_certificates
            .read()
            .await
            .values()
            .filter(|ca| ca.subject == facts.issuer)
            .map(|ca| ca.ca_id.clone())
            .collect();
        let revoked = self.revocation_list.read().await;
        issuer_ids
            .iter()
            .any(|ca_id| revoked.contains_key(&Self::revocation_key(ca_id, &facts.serial)))
    }

    /// Validate certificate chain for `purpose`
    ///
    /// `cert_pem` is the certificate to validate, optionally followed by intermediate
    /// certificates. Returns `Ok(true)` only if it chains, with valid signatures, validity
    /// periods and constraints, to a root CA this manager holds, it may be used for `purpose`
    /// (a certificate with an extended key usage must list the purpose; one without is valid
    /// for any), and neither it nor an intermediate on the path has been revoked here. A
    /// certificate that merely names a trusted CA as its subject or issuer is not valid. A
    /// configured root CA validates as itself, unless it has been revoked.
    pub async fn validate_certificate_chain(
        &self,
        cert_pem: &str,
        purpose: CertificatePurpose,
    ) -> Result<bool> {
        let mut presented = pem_certificates(cert_pem)?;
        let leaf = presented.remove(0);
        certificate_facts(&leaf)?; // must parse

        // A configured root CA, presented as itself, that is still valid and not revoked.
        let is_trusted_root = {
            let cas = self.ca_certificates.read().await;
            cas.values().any(|ca| {
                ca.ca_type == CAType::Root
                    && ca.certificate.status != CertificateStatus::Revoked
                    && pem_certificates(&ca.certificate.certificate_pem)
                        .is_ok_and(|ders| ders[0] == leaf)
            })
        };
        if is_trusted_root {
            return Ok(
                ensure_ca_certificate(&leaf).is_ok() && certificate_allows_purpose(&leaf, purpose)
            );
        }

        if let Err(reason) = self.verify_path(&leaf, &presented, purpose).await {
            tracing::warn!("Certificate chain validation failed: {}", reason);
            return Ok(false);
        }

        if self.is_revoked(&leaf).await {
            tracing::warn!("Certificate has been revoked");
            return Ok(false);
        }
        // The intermediates the path may have used: ours and the ones presented.
        let mut intermediates: Vec<Vec<u8>> = {
            let cas = self.ca_certificates.read().await;
            cas.values()
                .filter(|ca| ca.ca_type == CAType::Intermediate)
                .filter_map(|ca| pem_certificates(&ca.certificate.certificate_pem).ok())
                .map(|mut ders| ders.remove(0))
                .collect()
        };
        intermediates.extend(presented);
        for intermediate in &intermediates {
            if self.is_revoked(intermediate).await {
                tracing::warn!("An intermediate CA has been revoked");
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Generate a self-signed root CA certificate for development/testing
    ///
    /// Returns a tuple of (certificate_pem, private_key_pem).
    async fn generate_self_signed_root_ca(&self) -> Result<(String, String)> {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose, SerialNumber,
        };

        let mut params = CertificateParams::default();

        // Set distinguished name for root CA
        params
            .distinguished_name
            .push(DnType::CommonName, "AuthFramework Dev Root CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Auth Framework");
        params.distinguished_name.push(DnType::CountryName, "US");

        // Root CAs have long validity
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

        // Serial number 1 for root CA
        params.serial_number = Some(SerialNumber::from(1u64.to_be_bytes().to_vec()));

        // Root CA flags
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Generate ECDSA P-256 key pair
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AuthError::internal(format!("CA key pair generation failed: {}", e)))?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AuthError::internal(format!("CA self-sign failed: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        tracing::info!("Generated self-signed root CA certificate for development use");

        Ok((cert_pem, key_pem))
    }

    /// Store a CA certificate from PEM data into the internal CA certificate store.
    ///
    /// This shared helper is called by all external integrations (HSM, Azure, AWS)
    /// after successfully retrieving the certificate from the external source. The
    /// certificate must parse and be a usable, currently valid CA, and everything recorded
    /// about it is read from the certificate. The private key stays with the external
    /// source, so a CA stored this way validates but does not sign.
    async fn store_ca_certificate_from_pem(&self, cert_pem: &str, source: &str) -> Result<()> {
        let (pem, _der, facts) = self.parse_ca_pem(cert_pem).map_err(|e| {
            AuthError::config(format!(
                "CA certificate from {} is not usable: {}",
                source, e
            ))
        })?;
        let ca = Self::ca_entry(
            "root_ca",
            CAType::Root,
            pem,
            facts,
            Zeroizing::new(Vec::new()),
            source,
        );
        self.ca_certificates
            .write()
            .await
            .insert("root_ca".to_string(), ca);
        Ok(())
    }
}

/// Certificate Filter for listing operations
#[derive(Debug, Clone)]
pub struct CertificateFilter {
    /// Filter by certificate status
    pub status: Option<CertificateStatus>,

    /// Filter by profile
    pub profile: Option<String>,

    /// Filter by expiration date range
    pub expires_before: Option<DateTime<Utc>>,

    /// Filter by expiration date range
    pub expires_after: Option<DateTime<Utc>>,

    /// Filter by subject
    pub subject_contains: Option<String>,
}

impl CertificateFilter {
    /// Check if certificate matches filter
    pub fn matches(&self, cert: &StoredCertificate) -> bool {
        if let Some(ref status) = self.status
            && &cert.status != status
        {
            return false;
        }

        if let Some(ref profile) = self.profile
            && &cert.profile != profile
        {
            return false;
        }

        if let Some(expires_before) = self.expires_before
            && cert.not_after > expires_before
        {
            return false;
        }

        if let Some(expires_after) = self.expires_after
            && cert.not_after < expires_after
        {
            return false;
        }

        if let Some(ref subject_contains) = self.subject_contains
            && !cert.subject.contains(subject_contains)
        {
            return false;
        }

        true
    }
}

// Default implementations

impl Default for X509Config {
    fn default() -> Self {
        let mut certificate_profiles = HashMap::new();

        // Add default profiles
        certificate_profiles.insert(
            "tls_server".to_string(),
            CertificateProfile {
                name: "TLS Server".to_string(),
                cert_type: CertificateType::TlsServer,
                key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
                extended_key_usage: vec![ExtendedKeyUsage::ServerAuth],
                subject_alt_names: vec![],
                san_policy: SanPolicy::default(),
                validity_days: 365,
                preferred_key_type: KeyType::Rsa(2048),
                extensions: HashMap::new(),
            },
        );

        certificate_profiles.insert(
            "tls_client".to_string(),
            CertificateProfile {
                name: "TLS Client".to_string(),
                cert_type: CertificateType::TlsClient,
                key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyAgreement],
                extended_key_usage: vec![ExtendedKeyUsage::ClientAuth],
                subject_alt_names: vec![],
                san_policy: SanPolicy::default(),
                validity_days: 365,
                preferred_key_type: KeyType::Rsa(2048),
                extensions: HashMap::new(),
            },
        );

        Self {
            default_validity_days: 365,
            root_ca_cert_path: "ca/root-ca.crt".to_string(),
            root_ca_path: "ca/root-ca.crt".to_string(),
            root_ca_key_path: "ca/root-ca.key".to_string(),
            intermediate_ca_cert_path: None,
            intermediate_ca_path: None,
            intermediate_ca_key_path: None,
            certificate_profiles,
            enable_ocsp: false,
            ocsp_responder_url: None,
            enable_crl: true,
            crl_distribution_url: None,
            state_path: None,
            generate_development_root_ca: false,
        }
    }
}

// ─── Certificate reading and file helpers ─────────────────────────────────────

/// What the manager records about a certificate, read from the certificate itself.
struct CertificateFacts {
    subject: String,
    issuer: String,
    /// Decimal serial number.
    serial: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    /// SHA-256 of the DER, uppercase hex with colons.
    fingerprint: String,
}

/// DER of every `CERTIFICATE` block in `pem` (other blocks are skipped); at least one.
fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    for item in x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()) {
        let item =
            item.map_err(|e| AuthError::InvalidRequest(format!("Invalid PEM data: {}", e)))?;
        if item.label == "CERTIFICATE" {
            certificates.push(item.contents);
        }
    }
    if certificates.is_empty() {
        return Err(AuthError::InvalidRequest(
            "No PEM CERTIFICATE block found".to_string(),
        ));
    }
    Ok(certificates)
}

/// PEM for one DER certificate.
fn der_to_pem(der: &[u8]) -> String {
    let body = BASE64_STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Read the facts of a certificate. Fails unless `der` is exactly one parsable certificate.
fn certificate_facts(der: &[u8]) -> Result<CertificateFacts> {
    use sha2::{Digest, Sha256};

    let (rest, cert) = parse_x509_certificate(der)
        .map_err(|e| AuthError::InvalidRequest(format!("Not a valid X.509 certificate: {}", e)))?;
    if !rest.is_empty() {
        return Err(AuthError::InvalidRequest(
            "Trailing data after the certificate".to_string(),
        ));
    }
    let instant = |timestamp: i64| {
        DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| AuthError::InvalidRequest("Certificate time out of range".to_string()))
    };
    let fingerprint = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":");
    Ok(CertificateFacts {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.serial.to_string(),
        not_before: instant(cert.validity().not_before.timestamp())?,
        not_after: instant(cert.validity().not_after.timestamp())?,
        fingerprint,
    })
}

/// A CA certificate must be a CA (basicConstraints), allow certificate signing if it states
/// key usage, be valid now, and be usable by the verifier as an anchor.
fn ensure_ca_certificate(der: &[u8]) -> Result<()> {
    let (rest, cert) = parse_x509_certificate(der)
        .map_err(|e| AuthError::InvalidRequest(format!("Not a valid X.509 certificate: {}", e)))?;
    if !rest.is_empty() {
        return Err(AuthError::InvalidRequest(
            "Trailing data after the certificate".to_string(),
        ));
    }
    let is_ca = matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca);
    if !is_ca {
        return Err(AuthError::InvalidRequest(
            "Certificate is not a CA certificate".to_string(),
        ));
    }
    match cert.key_usage() {
        Ok(None) => {}
        Ok(Some(key_usage)) if key_usage.value.key_cert_sign() => {}
        Ok(Some(_)) => {
            return Err(AuthError::InvalidRequest(
                "CA certificate does not allow certificate signing".to_string(),
            ));
        }
        Err(_) => {
            return Err(AuthError::InvalidRequest(
                "CA certificate has a malformed keyUsage extension".to_string(),
            ));
        }
    }
    let now = Utc::now().timestamp();
    if now < cert.validity().not_before.timestamp() {
        return Err(AuthError::InvalidRequest(
            "CA certificate is not yet valid".to_string(),
        ));
    }
    if now > cert.validity().not_after.timestamp() {
        return Err(AuthError::InvalidRequest(
            "CA certificate has expired".to_string(),
        ));
    }
    webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(der)).map_err(
        |e| {
            AuthError::InvalidRequest(format!(
                "CA certificate is not usable as a trust anchor: {e}"
            ))
        },
    )?;
    Ok(())
}

/// The persisted part of the manager's state.
#[derive(Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    certificates: HashMap<String, StoredCertificate>,
    revocations: HashMap<String, RevocationEntry>,
    crl_numbers: HashMap<String, u64>,
}

// id-kp-codeSigning, id-kp-emailProtection, id-kp-timeStamping, id-kp-OCSPSigning
const EKU_CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const EKU_EMAIL_PROTECTION: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
const EKU_TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
const EKU_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

/// The path requirement for a purpose: when the certificate carries an extended key usage it
/// must list the purpose; one without the extension is valid for any purpose.
fn purpose_usage(purpose: CertificatePurpose) -> webpki::KeyUsage {
    match purpose {
        CertificatePurpose::ServerAuth => webpki::KeyUsage::server_auth(),
        CertificatePurpose::ClientAuth => webpki::KeyUsage::client_auth(),
        CertificatePurpose::CodeSigning => webpki::KeyUsage::required_if_present(EKU_CODE_SIGNING),
        CertificatePurpose::EmailProtection => {
            webpki::KeyUsage::required_if_present(EKU_EMAIL_PROTECTION)
        }
        CertificatePurpose::TimeStamping => {
            webpki::KeyUsage::required_if_present(EKU_TIME_STAMPING)
        }
        CertificatePurpose::OcspSigning => webpki::KeyUsage::required_if_present(EKU_OCSP_SIGNING),
    }
}

/// The purpose certificates of a profile are verified for after issuance: the first extended
/// key usage the profile lists, client authentication if it lists none.
fn profile_purpose(profile: &CertificateProfile) -> CertificatePurpose {
    match profile.extended_key_usage.first() {
        Some(ExtendedKeyUsage::ServerAuth) => CertificatePurpose::ServerAuth,
        Some(ExtendedKeyUsage::CodeSigning) => CertificatePurpose::CodeSigning,
        Some(ExtendedKeyUsage::EmailProtection) => CertificatePurpose::EmailProtection,
        Some(ExtendedKeyUsage::TimeStamping) => CertificatePurpose::TimeStamping,
        Some(ExtendedKeyUsage::OcspSigning) => CertificatePurpose::OcspSigning,
        Some(ExtendedKeyUsage::ClientAuth) | None => CertificatePurpose::ClientAuth,
    }
}

/// A CRL distribution point must be an absolute `http://` or `https://` URL.
fn check_distribution_url(url: &str) -> Result<()> {
    let ok = (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 2048
        && url.chars().all(|c| c.is_ascii_graphic());
    if ok {
        Ok(())
    } else {
        Err(AuthError::config(format!(
            "crl_distribution_url must be an http:// or https:// URL without spaces or control characters: {url:?}"
        )))
    }
}

fn policy_error(message: String) -> AuthError {
    AuthError::InvalidRequest(message)
}

/// A subject text field: not empty, at most `max` characters, no control characters.
fn check_text(field: &str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(policy_error(format!("{field} cannot be empty")));
    }
    if value.chars().count() > max {
        return Err(policy_error(format!(
            "{field} is longer than {max} characters"
        )));
    }
    if value.chars().any(|c| c.is_control() || is_format_char(c)) {
        return Err(policy_error(format!(
            "{field} contains control or formatting characters"
        )));
    }
    Ok(())
}

/// Invisible formatting characters that can disguise a name: zero-width characters,
/// bidirectional controls and embeddings, word joiners, the byte-order mark.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// A DNS name: real multi-label host name, optionally with a left-most wildcard label.
fn check_dns_name(name: &str, allow_wildcard: bool) -> Result<()> {
    let (wildcard, host) = match name.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, name),
    };
    if wildcard && !allow_wildcard {
        return Err(policy_error(format!(
            "wildcard name {name:?} is not allowed by the profile"
        )));
    }
    if name.len() > 253 {
        return Err(policy_error(
            "DNS name is longer than 253 characters".to_string(),
        ));
    }
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if labels.len() < 2 || !labels.iter().all(label_ok) {
        return Err(policy_error(format!(
            "{name:?} is not a valid multi-label DNS name"
        )));
    }
    let last = labels[labels.len() - 1];
    if last.chars().all(|c| c.is_ascii_digit()) {
        return Err(policy_error(format!("{name:?} looks like an IP address")));
    }
    if last.eq_ignore_ascii_case("localhost") {
        return Err(policy_error(format!("{name:?} is a localhost name")));
    }
    Ok(())
}

fn check_ip_name(ip: &str) -> Result<()> {
    let parsed: std::net::IpAddr = ip
        .parse()
        .map_err(|_| policy_error(format!("{ip:?} is not an IP address")))?;
    // An IPv4-mapped IPv6 address (::ffff:127.0.0.1) is judged as the IPv4 address it wraps.
    let address = parsed.to_canonical();
    let broadcast = matches!(address, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() || broadcast {
        return Err(policy_error(format!(
            "{ip:?} is an unspecified, loopback, multicast or broadcast address"
        )));
    }
    Ok(())
}

fn check_uri_name(uri: &str) -> Result<()> {
    let scheme_end = uri.find(':').unwrap_or(0);
    let scheme_ok = scheme_end > 0
        && uri[..scheme_end].starts_with(|c: char| c.is_ascii_alphabetic())
        && uri[..scheme_end]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    let scheme = uri[..scheme_end].to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "urn" | "spiffe") {
        return Err(policy_error(format!(
            "URI scheme {scheme:?} is not allowed (http, https, urn, spiffe)"
        )));
    }
    if uri.len() > 2048
        || !scheme_ok
        || uri.len() == scheme_end + 1
        || !uri.chars().all(|c| c.is_ascii_graphic())
    {
        return Err(policy_error(format!("{uri:?} is not an acceptable URI")));
    }
    Ok(())
}

fn check_email_name(email: &str) -> Result<()> {
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| policy_error(format!("{email:?} is not an e-mail address")))?;
    if email.len() > 254
        || local.is_empty()
        || local.len() > 64
        || domain.contains('@')
        || !email.chars().all(|c| c.is_ascii_graphic())
    {
        return Err(policy_error(format!(
            "{email:?} is not an acceptable e-mail address"
        )));
    }
    check_dns_name(domain, false)
}

/// Check one subject alternative name against the profile's policy.
fn check_san(san: &SubjectAltName, policy: &SanPolicy) -> Result<()> {
    match san {
        SubjectAltName::DnsName(name) => check_dns_name(name, policy.wildcard_dns),
        SubjectAltName::IpAddress(ip) if policy.ip_address => check_ip_name(ip),
        SubjectAltName::Uri(uri) if policy.uri => check_uri_name(uri),
        SubjectAltName::Email(email) if policy.email => check_email_name(email),
        other => Err(policy_error(format!(
            "{other:?} subject alternative names are not allowed by the profile"
        ))),
    }
}

/// Security strength in bits of an RSA modulus of `bits` bits (NIST SP 800-57).
fn rsa_strength(bits: usize) -> u32 {
    match bits {
        0..=2047 => 0,
        2048..=3071 => 112,
        3072..=7679 => 128,
        _ => 192,
    }
}

/// The strength a profile's `preferred_key_type` asks for as a minimum.
fn required_strength(minimum: &KeyType) -> u32 {
    match minimum {
        KeyType::Rsa(bits) => rsa_strength(*bits as usize).max(112),
        KeyType::Ecdsa(EcdsaCurve::P256) | KeyType::Ed25519 => 128,
        KeyType::Ecdsa(EcdsaCurve::P384) => 192,
        KeyType::Ecdsa(EcdsaCurve::P521) => 256,
    }
}

/// A subject key must be well-formed, on the allow-list (RSA of 2048 to 16384 bits, ECDSA
/// P-256 / P-384, Ed25519) and at least as strong as the profile's minimum.
fn check_subject_key(public_key_pem: &str, minimum: &KeyType) -> Result<()> {
    use x509_parser::prelude::FromDer;
    use x509_parser::public_key::PublicKey;

    let (_, pem) = x509_parser::pem::parse_x509_pem(public_key_pem.as_bytes())
        .map_err(|e| policy_error(format!("public_key_pem is not PEM: {e}")))?;
    if pem.label != "PUBLIC KEY" {
        return Err(policy_error(
            "public_key_pem must be a PEM PUBLIC KEY (SubjectPublicKeyInfo)".to_string(),
        ));
    }
    let (rest, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(&pem.contents)
        .map_err(|e| policy_error(format!("public_key_pem is not a SubjectPublicKeyInfo: {e}")))?;
    if !rest.is_empty() {
        return Err(policy_error(
            "Trailing data after the public key".to_string(),
        ));
    }
    let key_bytes: &[u8] = spki.subject_public_key.data.as_ref();
    let strength = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = rsa.key_size();
            if bits < 2048 {
                return Err(policy_error(format!(
                    "RSA key of {bits} bits is below the 2048-bit minimum"
                )));
            }
            if bits > 16384 {
                return Err(policy_error(format!(
                    "RSA key of {bits} bits is above the 16384-bit maximum"
                )));
            }
            if rsa.modulus.last().is_none_or(|b| b % 2 == 0) {
                return Err(policy_error("RSA modulus is even".to_string()));
            }
            let exponent = rsa
                .exponent
                .iter()
                .skip_while(|b| **b == 0)
                .collect::<Vec<_>>();
            let exponent_value = exponent
                .iter()
                .try_fold(0u64, |acc, b| acc.checked_mul(256).map(|v| v | **b as u64));
            match exponent_value {
                Some(e) if exponent.len() <= 8 && e >= 65_537 && e % 2 == 1 => {}
                _ => {
                    return Err(policy_error(
                        "RSA public exponent must be odd and at least 65537".to_string(),
                    ));
                }
            }
            rsa_strength(bits)
        }
        Ok(PublicKey::EC(_)) => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_string());
            let (algorithm, point_len, strength) = match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => (&ring::agreement::ECDH_P256, 65, 128),
                Some("1.3.132.0.34") => (&ring::agreement::ECDH_P384, 97, 192),
                other => {
                    return Err(policy_error(format!(
                        "EC curve {other:?} is not allowed (P-256, P-384)"
                    )));
                }
            };
            if key_bytes.len() != point_len || key_bytes[0] != 0x04 {
                return Err(policy_error(
                    "EC public key must be an uncompressed point of the curve's size".to_string(),
                ));
            }
            // ring validates the peer's point (it must lie on the curve) when it is used.
            let rng = ring::rand::SystemRandom::new();
            let ephemeral = ring::agreement::EphemeralPrivateKey::generate(algorithm, &rng)
                .map_err(|_| AuthError::internal("System random number generator failed"))?;
            ring::agreement::agree_ephemeral(
                ephemeral,
                &ring::agreement::UnparsedPublicKey::new(algorithm, key_bytes),
                |_| (),
            )
            .map_err(|_| policy_error("EC public key is not a point on the curve".to_string()))?;
            strength
        }
        _ if spki.algorithm.algorithm.to_string() == "1.3.101.112" => {
            // Ed25519 (RFC 8410): 32-byte key, no algorithm parameters.
            if key_bytes.len() != 32 || spki.algorithm.parameters.is_some() {
                return Err(policy_error(
                    "Ed25519 public key must be 32 bytes without parameters".to_string(),
                ));
            }
            128
        }
        _ => {
            return Err(policy_error(
                "Only RSA, ECDSA (P-256, P-384) and Ed25519 subject keys are accepted".to_string(),
            ));
        }
    };
    if strength < required_strength(minimum) {
        return Err(policy_error(format!(
            "Subject key is weaker than the profile's minimum ({minimum:?})"
        )));
    }
    Ok(())
}

/// A profile that contradicts itself is refused rather than half-honoured: an end-entity
/// profile may not ask for certificate or CRL signing, and the profile's type must be backed by
/// the extended key usage it implies.
fn validate_profile(name: &str, profile: &CertificateProfile) -> Result<()> {
    let bad = |why: &str| AuthError::config(format!("Certificate profile '{name}': {why}"));
    let ca_profile = matches!(
        profile.cert_type,
        CertificateType::RootCA | CertificateType::IntermediateCA
    );
    if !ca_profile
        && profile
            .key_usage
            .iter()
            .any(|ku| matches!(ku, KeyUsage::KeyCertSign | KeyUsage::CrlSign))
    {
        return Err(bad(
            "an end-entity profile cannot ask for keyCertSign or cRLSign (the certificate would be cA=FALSE)",
        ));
    }
    let required = match profile.cert_type {
        CertificateType::TlsServer => Some(ExtendedKeyUsage::ServerAuth),
        CertificateType::TlsClient => Some(ExtendedKeyUsage::ClientAuth),
        CertificateType::CodeSigning => Some(ExtendedKeyUsage::CodeSigning),
        CertificateType::Email => Some(ExtendedKeyUsage::EmailProtection),
        _ => None,
    };
    if let Some(required) = required
        && !profile.extended_key_usage.contains(&required)
    {
        return Err(bad(&format!(
            "its type needs {required:?} in extended_key_usage"
        )));
    }
    if profile.validity_days < 0 {
        return Err(bad("validity_days cannot be negative"));
    }
    Ok(())
}

/// Whether a certificate may be used for `purpose` by its own extended key usage (none at
/// all: any purpose).
fn certificate_allows_purpose(der: &[u8], purpose: CertificatePurpose) -> bool {
    let Ok((_, cert)) = parse_x509_certificate(der) else {
        return false;
    };
    match cert.extended_key_usage() {
        Ok(None) => true,
        Ok(Some(eku)) => {
            let eku = &eku.value;
            eku.any
                || match purpose {
                    CertificatePurpose::ServerAuth => eku.server_auth,
                    CertificatePurpose::ClientAuth => eku.client_auth,
                    CertificatePurpose::CodeSigning => eku.code_signing,
                    CertificatePurpose::EmailProtection => eku.email_protection,
                    CertificatePurpose::TimeStamping => eku.time_stamping,
                    CertificatePurpose::OcspSigning => eku.ocsp_signing,
                }
        }
        Err(_) => false,
    }
}

/// Write `contents` to `path` through a synced temporary file and a rename, then sync the
/// directory (Unix). Runs on a blocking thread.
fn write_state_file(path: &str, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let fail = |what: &str, e: std::io::Error| {
        AuthError::internal(format!("Failed to {what} state file {path}: {e}"))
    };
    let target = std::path::Path::new(path);
    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| fail("create the directory of", e))?;
    }
    let temporary = format!("{path}.tmp");
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(fail("write", e));
    }
    #[cfg(unix)]
    if let Some(parent) = target.parent() {
        let dir = if parent.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            parent
        };
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| fail("sync the directory of", e))?;
    }
    Ok(())
}

/// Everything about a request that does not need the CA: unsupported inputs are refused,
/// names and key are checked against the profile. Nothing is issued or numbered before this.
fn validate_request(request: &CertificateRequest, profile: &CertificateProfile) -> Result<()> {
    if !request.attributes.is_empty() {
        return Err(policy_error(
            "request attributes are not supported and would be ignored".to_string(),
        ));
    }
    if !profile.extensions.is_empty() {
        return Err(policy_error(format!(
            "profile '{}' uses extensions, which are not supported",
            profile.name
        )));
    }

    check_text("request id", &request.request_id, 128)?;
    let subject = &request.subject;
    check_text("common name", &subject.common_name, 64)?;
    for (field, value, max) in [
        ("organization", &subject.organization, 64),
        ("organizational unit", &subject.organizational_unit, 64),
        ("state", &subject.state, 128),
        ("locality", &subject.locality, 128),
    ] {
        if let Some(value) = value {
            check_text(field, value, max)?;
        }
    }
    if let Some(country) = &subject.country
        && !(country.len() == 2 && country.chars().all(|c| c.is_ascii_uppercase()))
    {
        return Err(policy_error(
            "country must be a two-letter upper-case code".to_string(),
        ));
    }

    let names = profile.subject_alt_names.len() + request.subject_alt_names.len();
    if names > 25 {
        return Err(policy_error(
            "at most 25 subject alternative names are accepted".to_string(),
        ));
    }
    for san in profile
        .subject_alt_names
        .iter()
        .chain(request.subject_alt_names.iter())
    {
        check_san(san, &profile.san_policy)?;
    }
    if let Some(email) = &subject.email {
        check_san(&SubjectAltName::Email(email.clone()), &profile.san_policy)?;
    }

    check_subject_key(&request.public_key_pem, &profile.preferred_key_type)
}

/// Create a file that must not already exist and write `contents` to it; with `private` it is
/// readable by its owner only (on Unix; on other platforms the directory's ACL applies).
fn write_new_file(path: &str, contents: &[u8], private: bool) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            AuthError::internal(format!("Failed to create {}: {}", parent.display(), e))
        })?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| AuthError::internal(format!("Failed to create {}: {}", path, e)))?;
    file.write_all(contents)
        .map_err(|e| AuthError::internal(format!("Failed to write {}: {}", path, e)))
}

// ─── Module-level helpers ─────────────────────────────────────────────────────

/// Extract the first `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`
/// block from a PEM bundle.  Private key blocks and extra certificate entries are
/// discarded.  If no proper PEM block is found the input is returned unchanged.
fn x509_extract_certificate_pem(pem: &str) -> String {
    let mut in_cert = false;
    let mut lines: Vec<&str> = Vec::new();
    let mut collected = false;

    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            if collected {
                break; // Only keep the first certificate.
            }
            in_cert = true;
            collected = true;
            lines.push(line);
        } else if line.starts_with("-----END CERTIFICATE-----") {
            lines.push(line);
            in_cert = false;
        } else if in_cert {
            lines.push(line);
        }
    }

    if collected {
        lines.join("\n") + "\n"
    } else {
        pem.to_string()
    }
}

/// Parameters for building an AWS SigV4 `Authorization` header.
///
/// Use [`AwsSigV4Request::new`] to create an instance with the required
/// credentials, then set the remaining fields with chainable helpers:
///
/// ```rust,ignore
/// let auth = AwsSigV4Request::new("AKIA…", "secret")
///     .region("us-east-1")
///     .service("secretsmanager")
///     .method("POST")
///     .host("secretsmanager.us-east-1.amazonaws.com")
///     .payload(b"{\"SecretId\":\"my-secret\"}")
///     .amz_date("20230101T000000Z")
///     .date_stamp("20230101")
///     .amz_target("secretsmanager.GetSecretValue")
///     .sign();
/// ```
struct AwsSigV4Request<'a> {
    access_key: &'a str,
    secret_key: &'a str,
    session_token: Option<&'a str>,
    region: &'a str,
    service: &'a str,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    query: &'a str,
    payload: &'a [u8],
    amz_date: &'a str,
    date_stamp: &'a str,
    amz_target: &'a str,
}

impl<'a> AwsSigV4Request<'a> {
    /// Create a new request with the required AWS credentials.
    fn new(access_key: &'a str, secret_key: &'a str) -> Self {
        Self {
            access_key,
            secret_key,
            session_token: None,
            region: "us-east-1",
            service: "",
            method: "POST",
            host: "",
            path: "/",
            query: "",
            payload: b"",
            amz_date: "",
            date_stamp: "",
            amz_target: "",
        }
    }

    fn session_token(mut self, token: Option<&'a str>) -> Self {
        self.session_token = token;
        self
    }

    fn region(mut self, region: &'a str) -> Self {
        self.region = region;
        self
    }

    fn service(mut self, service: &'a str) -> Self {
        self.service = service;
        self
    }

    fn method(mut self, method: &'a str) -> Self {
        self.method = method;
        self
    }

    fn host(mut self, host: &'a str) -> Self {
        self.host = host;
        self
    }

    fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = payload;
        self
    }

    fn amz_date(mut self, amz_date: &'a str) -> Self {
        self.amz_date = amz_date;
        self
    }

    fn date_stamp(mut self, date_stamp: &'a str) -> Self {
        self.date_stamp = date_stamp;
        self
    }

    fn amz_target(mut self, amz_target: &'a str) -> Self {
        self.amz_target = amz_target;
        self
    }

    /// Compute the AWS SigV4 `Authorization` header value.
    ///
    /// Implements [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
    fn sign(&self) -> String {
        use hmac::{KeyInit, Mac, SimpleHmac};
        use sha2::{Digest, Sha256};

        fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut mac =
                <SimpleHmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }

        fn sha256hex(data: &[u8]) -> String {
            let mut h = Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        }

        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/x-amz-json-1.1".into()),
            ("host".into(), self.host.into()),
            ("x-amz-date".into(), self.amz_date.into()),
            ("x-amz-target".into(), self.amz_target.into()),
        ];
        if let Some(tok) = self.session_token {
            headers.push(("x-amz-security-token".into(), tok.into()));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
            .collect();
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            method = self.method,
            path = self.path,
            query = self.query,
            canonical_headers = canonical_headers,
            signed_headers = signed_headers,
            payload_hash = sha256hex(self.payload),
        );

        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            self.date_stamp, self.region, self.service
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}",
            amz_date = self.amz_date,
            credential_scope = credential_scope,
            canonical_hash = sha256hex(canonical_request.as_bytes()),
        );

        let signing_key = hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(
                    &hmac_sha256(
                        format!("AWS4{}", self.secret_key).as_bytes(),
                        self.date_stamp.as_bytes(),
                    ),
                    self.region.as_bytes(),
                ),
                self.service.as_bytes(),
            ),
            b"aws4_request",
        );

        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            access_key = self.access_key,
            credential_scope = credential_scope,
            signed_headers = signed_headers,
            signature = signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_x509_manager_creation() {
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);

        // Test basic functionality
        assert!(!manager.config.certificate_profiles.is_empty());
        assert_eq!(manager.config.default_validity_days, 365);
    }

    #[tokio::test]
    async fn test_certificate_profile() {
        let config = X509Config::default();

        // Check default profiles
        assert!(config.certificate_profiles.contains_key("tls_server"));
        assert!(config.certificate_profiles.contains_key("tls_client"));

        let tls_server_profile = &config.certificate_profiles["tls_server"];
        assert_eq!(tls_server_profile.cert_type, CertificateType::TlsServer);
        assert!(
            tls_server_profile
                .extended_key_usage
                .contains(&ExtendedKeyUsage::ServerAuth)
        );
    }

    #[tokio::test]
    async fn test_certificate_filter() {
        let filter = CertificateFilter {
            status: Some(CertificateStatus::Valid),
            profile: None,
            expires_before: None,
            expires_after: None,
            subject_contains: Some("example.com".to_string()),
        };

        let cert = StoredCertificate {
            cert_id: "test".to_string(),
            certificate_pem: "".to_string(),
            private_key_pem: None,
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "123".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + Duration::days(365),
            profile: "tls_server".to_string(),
            status: CertificateStatus::Valid,
            fingerprint: "test_fp".to_string(),
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        assert!(filter.matches(&cert));
    }

    // ─── HSM / Azure / AWS integration unit tests ─────────────────────────────

    #[test]
    fn test_x509_extract_certificate_pem_single_cert() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBxx==\n-----END CERTIFICATE-----\n";
        let extracted = x509_extract_certificate_pem(pem);
        assert!(extracted.contains("-----BEGIN CERTIFICATE-----"));
        assert!(extracted.contains("-----END CERTIFICATE-----"));
        assert!(extracted.contains("MIIBxx=="));
    }

    #[test]
    fn test_x509_extract_certificate_pem_strips_key() {
        // A PEM bundle with a private key + certificate — only the cert should come out.
        let bundle = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK==\n-----END RSA PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\nMIICert==\n-----END CERTIFICATE-----\n",
        );
        let extracted = x509_extract_certificate_pem(bundle);
        assert!(
            !extracted.contains("PRIVATE KEY"),
            "Private key must be stripped"
        );
        assert!(extracted.contains("-----BEGIN CERTIFICATE-----"));
        assert!(extracted.contains("MIICert=="));
    }

    #[test]
    fn test_x509_extract_certificate_pem_keeps_first_only() {
        let bundle = concat!(
            "-----BEGIN CERTIFICATE-----\nMIIFirst==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIISecond==\n-----END CERTIFICATE-----\n",
        );
        let extracted = x509_extract_certificate_pem(bundle);
        assert!(
            extracted.contains("MIIFirst=="),
            "First cert should be kept"
        );
        assert!(
            !extracted.contains("MIISecond=="),
            "Second cert must be discarded"
        );
    }

    #[test]
    fn test_aws_sigv4_authorization_format() {
        // Verify the output is structured like a valid AWS SigV4 Authorization header.
        let auth = AwsSigV4Request::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .region("us-east-1")
        .service("secretsmanager")
        .method("POST")
        .host("secretsmanager.us-east-1.amazonaws.com")
        .payload(b"{\"SecretId\":\"my-secret\"}")
        .amz_date("20230101T000000Z")
        .date_stamp("20230101")
        .amz_target("secretsmanager.GetSecretValue")
        .sign();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
        // Signature must be a 64-character hex string.
        let sig_part = auth.split("Signature=").nth(1).unwrap_or("");
        assert_eq!(sig_part.len(), 64, "SigV4 signature must be 64 hex chars");
    }

    #[tokio::test]
    async fn test_azure_vault_missing_tenant_id() {
        // Clear any accidentally-set env vars to ensure the credential-absent error path.
        // Skip this test if real Azure credentials happen to be set (CI environment).
        if std::env::var("X509_AZURE_TENANT_ID").is_ok() {
            return;
        }
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);
        let result = manager
            .load_ca_from_azure_vault("https://test.vault.azure.net", "my-ca")
            .await;
        assert!(result.is_err(), "Should fail when tenant_id is not set");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("X509_AZURE_TENANT_ID"),
            "Error should name the missing variable: {msg}"
        );
    }

    #[tokio::test]
    async fn test_aws_secrets_missing_access_key() {
        // Skip if real AWS credentials are set.
        if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
            return;
        }
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);
        let result = manager.load_ca_from_aws_secrets("my-ca-cert").await;
        assert!(
            result.is_err(),
            "Should fail when AWS_ACCESS_KEY_ID is not set"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("AWS_ACCESS_KEY_ID"),
            "Error should name the missing variable: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "hsm")]
    async fn test_hsm_invalid_json_config() {
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);
        // Pass nonsense — must get a clear JSON-parse error, not a panic.
        let result = manager.load_ca_from_hsm("not-valid-json").await;
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("JSON") || msg.contains("json") || msg.contains("X509_HSM_CONFIG"),
            "Error should mention JSON parsing: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "hsm")]
    async fn test_hsm_missing_library_field() {
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);
        // Valid JSON but missing the required 'library' field.
        let result = manager
            .load_ca_from_hsm(r#"{"slot": 0, "pin": "1234", "label": "ca-cert"}"#)
            .await;
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("library"),
            "Error should mention the missing 'library' field: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "hsm")]
    async fn test_hsm_nonexistent_library_path() {
        let config = X509Config::default();
        let manager = X509CertificateManager::new(config);
        let result = manager
            .load_ca_from_hsm(
                r#"{"library": "/nonexistent/pkcs11/libpkcs11.so", "slot": 0, "pin": "", "label": "ca-cert"}"#,
            )
            .await;
        // Should return an error about the library not being found, not a panic.
        assert!(
            result.is_err(),
            "Expected error loading non-existent PKCS#11 library"
        );
    }

    // ─── Real-certificate tests ────────────────────────────────────────────────

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };
    use std::path::{Path, PathBuf};
    use x509_parser::prelude::FromDer;

    /// A CA held by the test: its certificate and key.
    struct TestCa {
        cert_pem: String,
        key_pem: String,
    }

    fn ca_params(cn: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, cn);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
    }

    fn new_key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
    }

    impl TestCa {
        fn root(cn: &str) -> Self {
            Self::root_with(ca_params(cn))
        }

        fn root_with(params: CertificateParams) -> Self {
            let key = new_key();
            let cert = params.self_signed(&key).unwrap();
            TestCa {
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
            }
        }

        fn issuer(&self) -> Issuer<'static, KeyPair> {
            Issuer::from_ca_cert_pem(&self.cert_pem, KeyPair::from_pem(&self.key_pem).unwrap())
                .unwrap()
        }

        fn intermediate(&self, cn: &str) -> Self {
            let key = new_key();
            let cert = ca_params(cn).signed_by(&key, &self.issuer()).unwrap();
            TestCa {
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
            }
        }

        /// A leaf signed by this CA; `adjust` can change its parameters.
        fn leaf(&self, cn: &str, adjust: impl FnOnce(&mut CertificateParams)) -> String {
            let key = new_key();
            let mut params = CertificateParams::new(vec![format!("{cn}.example")]).unwrap();
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CommonName, cn);
            adjust(&mut params);
            params.signed_by(&key, &self.issuer()).unwrap().pem()
        }

        fn write(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
            let cert = dir.join(format!("{name}.crt"));
            let key = dir.join(format!("{name}.key"));
            std::fs::write(&cert, &self.cert_pem).unwrap();
            std::fs::write(&key, &self.key_pem).unwrap();
            (cert, key)
        }
    }

    fn config_for(cert: &Path, key: &Path) -> X509Config {
        X509Config {
            root_ca_path: cert.to_string_lossy().to_string(),
            root_ca_cert_path: cert.to_string_lossy().to_string(),
            root_ca_key_path: key.to_string_lossy().to_string(),
            ..X509Config::default()
        }
    }

    /// An initialised manager whose root is `root` (with its key unless `with_key` is false).
    async fn manager_with(dir: &Path, root: &TestCa, with_key: bool) -> X509CertificateManager {
        let (cert, key) = root.write(dir, "root");
        if !with_key {
            std::fs::remove_file(&key).unwrap();
        }
        let manager = X509CertificateManager::new(config_for(&cert, &key));
        manager.initialize().await.unwrap();
        manager
    }

    fn request(cn: &str, key: &KeyPair, profile: &str) -> CertificateRequest {
        CertificateRequest {
            request_id: format!("req-{cn}"),
            subject: CertificateSubject {
                common_name: cn.to_string(),
                organization: None,
                organizational_unit: None,
                country: None,
                state: None,
                locality: None,
                email: None,
            },
            subject_alt_names: vec![SubjectAltName::DnsName(format!("{cn}.example"))],
            public_key_pem: key.public_key_pem(),
            profile: profile.to_string(),
            requested_at: Utc::now(),
            requester: "tester".to_string(),
            attributes: HashMap::new(),
        }
    }

    fn der_of(pem: &str) -> Vec<u8> {
        pem_certificates(pem).unwrap().remove(0)
    }

    async fn ca_subject(manager: &X509CertificateManager, ca_id: &str) -> String {
        manager.ca_certificates.read().await[ca_id].subject.clone()
    }

    #[tokio::test]
    async fn root_ca_metadata_is_read_from_the_certificate() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Real Root");
        let manager = manager_with(dir.path(), &root, true).await;

        let cas = manager.ca_certificates.read().await;
        let ca = &cas["root_ca"];
        let der = der_of(&root.cert_pem);
        let (_, parsed) = parse_x509_certificate(&der).unwrap();
        assert_eq!(ca.subject, parsed.subject().to_string());
        assert!(ca.subject.contains("Real Root"), "{}", ca.subject);
        assert_eq!(ca.certificate.issuer, parsed.issuer().to_string());
        assert_eq!(ca.certificate.serial_number, parsed.serial.to_string());
        assert_eq!(
            ca.certificate.not_after.timestamp(),
            parsed.validity().not_after.timestamp()
        );
        let expected = Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(ca.certificate.fingerprint, expected);
        assert!(!ca.private_key.is_empty(), "the CA key is loaded");
    }

    #[tokio::test]
    async fn unusable_root_ca_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("root.key");

        // Not a certificate.
        let cert_path = dir.path().join("garbage.crt");
        std::fs::write(&cert_path, "this is not a certificate").unwrap();
        let manager = X509CertificateManager::new(config_for(&cert_path, &key_path));
        assert!(manager.initialize().await.is_err());
        assert!(manager.ca_certificates.read().await.is_empty());

        // A certificate that is not a CA.
        let root = TestCa::root("Issuer");
        let leaf_path = dir.path().join("leaf.crt");
        std::fs::write(&leaf_path, root.leaf("not-a-ca", |_| {})).unwrap();
        let manager = X509CertificateManager::new(config_for(&leaf_path, &key_path));
        assert!(manager.initialize().await.is_err());

        // An expired CA.
        let mut params = ca_params("Old Root");
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let expired = TestCa::root_with(params);
        let (cert, key) = expired.write(dir.path(), "expired");
        let manager = X509CertificateManager::new(config_for(&cert, &key));
        assert!(manager.initialize().await.is_err());
    }

    #[tokio::test]
    async fn a_key_that_does_not_belong_to_the_ca_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let (cert, key) = root.write(dir.path(), "root");
        std::fs::write(&key, new_key().serialize_pem()).unwrap();
        let manager = X509CertificateManager::new(config_for(&cert, &key));
        assert!(manager.initialize().await.is_err());
        std::fs::write(&key, "not a key").unwrap();
        assert!(manager.initialize().await.is_err());
    }

    #[tokio::test]
    async fn a_missing_root_is_not_generated_without_a_place_for_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("root.crt");
        let mut config = config_for(&cert, &dir.path().join("root.key"));
        config.root_ca_key_path = String::new();
        config.generate_development_root_ca = true;
        let manager = X509CertificateManager::new(config);
        assert!(manager.initialize().await.is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn a_development_root_keeps_its_key_only_at_the_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("pki").join("root.crt");
        let key = dir.path().join("keys").join("root.key");

        // Without the explicit opt-in a missing root is an error, and nothing is created.
        let off = X509CertificateManager::new(config_for(&cert, &key));
        assert!(off.initialize().await.is_err());
        assert!(!cert.exists() && !key.exists());

        let mut config = config_for(&cert, &key);
        config.generate_development_root_ca = true;
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();

        assert!(cert.exists() && key.exists());
        // Nothing else was written, in particular no "ca.key" beside the certificate.
        let beside_cert: Vec<_> = std::fs::read_dir(cert.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(beside_cert.len(), 1, "{beside_cert:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // It can sign, and a restart loads the same root rather than a new one.
        let leaf_key = new_key();
        manager
            .sign_certificate_request(&request("dev", &leaf_key, "tls_client"), "root_ca")
            .await
            .unwrap();
        let fingerprint = manager.ca_certificates.read().await["root_ca"]
            .certificate
            .fingerprint
            .clone();
        let restarted = X509CertificateManager::new(config_for(&cert, &key));
        restarted.initialize().await.unwrap(); // the files exist now: no opt-in needed
        assert_eq!(
            restarted.ca_certificates.read().await["root_ca"]
                .certificate
                .fingerprint,
            fingerprint
        );

        // An existing key is never overwritten by generating a root.
        std::fs::remove_file(&cert).unwrap();
        let before = std::fs::read(&key).unwrap();
        let again = X509CertificateManager::new(config_for(&cert, &key));
        assert!(again.initialize().await.is_err());
        assert_eq!(std::fs::read(&key).unwrap(), before);
    }

    #[tokio::test]
    async fn a_ca_certificate_that_may_not_sign_certificates_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut params = ca_params("No Signing");
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let ca = TestCa::root_with(params);
        let (cert, key) = ca.write(dir.path(), "root");
        let manager = X509CertificateManager::new(config_for(&cert, &key));
        assert!(manager.initialize().await.is_err());
    }

    #[tokio::test]
    async fn the_two_root_path_settings_must_agree() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let (cert, key) = root.write(dir.path(), "root");

        let mut config = config_for(&cert, &key);
        // A different, perfectly good CA file: only the disagreement is wrong.
        let other = TestCa::root("Other Root");
        let (other_cert, _) = other.write(dir.path(), "other");
        config.root_ca_path = other_cert.to_string_lossy().to_string();
        config.root_ca_key_path = String::new();
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        // Either name alone is enough.
        let mut config = config_for(&cert, &key);
        config.root_ca_path = String::new();
        X509CertificateManager::new(config)
            .initialize()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_intermediate_is_loaded_under_either_path_setting() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let (root_cert, root_key) = root.write(dir.path(), "root");
        let (inter_cert, _) = intermediate.write(dir.path(), "inter");

        for as_cert_path in [true, false] {
            let mut config = config_for(&root_cert, &root_key);
            let path = Some(inter_cert.to_string_lossy().to_string());
            if as_cert_path {
                config.intermediate_ca_cert_path = path;
            } else {
                config.intermediate_ca_path = path;
            }
            let manager = X509CertificateManager::new(config);
            manager.initialize().await.unwrap();
            let subject = ca_subject(&manager, "intermediate_ca").await;
            assert!(subject.contains("Issuing CA"), "{subject}");
            let cas = manager.ca_certificates.read().await;
            assert!(cas["intermediate_ca"].certificate.issuer.contains("Root"));
            assert_eq!(cas["intermediate_ca"].ca_type, CAType::Intermediate);
        }
    }

    #[tokio::test]
    async fn an_intermediate_from_an_unknown_ca_or_a_missing_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let stranger = TestCa::root("Stranger").intermediate("Foreign CA");
        let (root_cert, root_key) = root.write(dir.path(), "root");
        let (foreign, _) = stranger.write(dir.path(), "foreign");

        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path = Some(foreign.to_string_lossy().to_string());
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path =
            Some(dir.path().join("absent.crt").to_string_lossy().to_string());
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_issued_certificate_carries_the_requesters_key_and_is_signed_by_the_ca() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Signing Root");
        let manager = manager_with(dir.path(), &root, true).await;

        for profile in ["tls_server", "tls_client"] {
            let purpose = if profile == "tls_server" {
                CertificatePurpose::ServerAuth
            } else {
                CertificatePurpose::ClientAuth
            };
            let requester_key = new_key();
            let stored = manager
                .sign_certificate_request(&request("svc", &requester_key, profile), "root_ca")
                .await
                .unwrap();
            let der = der_of(&stored.certificate_pem);
            let (_, cert) = parse_x509_certificate(&der).unwrap();

            // The subject key is the requester's, not a throwaway.
            assert_eq!(
                cert.public_key().subject_public_key.data.as_ref(),
                requester_key.public_key_raw()
            );
            // Signed by the CA, not self-signed.
            assert_ne!(cert.subject().to_string(), cert.issuer().to_string());
            assert_eq!(
                cert.issuer().to_string(),
                ca_subject(&manager, "root_ca").await
            );
            assert!(!cert.is_ca());
            // The record describes the certificate.
            assert_eq!(stored.subject, cert.subject().to_string());
            assert_eq!(stored.issuer, cert.issuer().to_string());
            assert_eq!(stored.serial_number, cert.serial.to_string());
            assert_eq!(
                stored.not_after.timestamp(),
                cert.validity().not_after.timestamp()
            );
            let digest = Sha256::digest(&der)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            assert_eq!(
                stored.fingerprint, digest,
                "fingerprint is of the certificate"
            );
            // And it validates against the CA.
            assert!(
                manager
                    .validate_certificate_chain(&stored.certificate_pem, purpose)
                    .await
                    .unwrap(),
                "{profile}"
            );
            assert!(
                manager
                    .get_certificate(&stored.cert_id)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn an_issued_certificate_is_not_valid_beyond_its_ca() {
        let dir = tempfile::tempdir().unwrap();
        let mut params = ca_params("Short Root");
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3);
        let root = TestCa::root_with(params);
        let manager = manager_with(dir.path(), &root, true).await;
        let stored = manager
            .sign_certificate_request(&request("svc", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        // The profile asks for 365 days; the CA has 3.
        let ca_not_after = manager.ca_certificates.read().await["root_ca"]
            .certificate
            .not_after;
        assert!(stored.not_after <= ca_not_after);
    }

    #[tokio::test]
    async fn a_ca_without_its_key_validates_but_does_not_issue() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Verify Only");
        let manager = manager_with(dir.path(), &root, false).await;

        let err = manager
            .sign_certificate_request(&request("svc", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no signing key"), "{err}");
        assert!(manager.generate_crl("root_ca").await.is_err());

        let leaf = root.leaf("known", |_| {});
        assert!(
            manager
                .validate_certificate_chain(&leaf, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn bad_requests_are_refused_instead_of_being_partly_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let mut config = config_for(&dir.path().join("root.crt"), &dir.path().join("root.key"));
        root.write(dir.path(), "root");
        config.certificate_profiles.insert(
            "ca".to_string(),
            CertificateProfile {
                name: "CA".to_string(),
                cert_type: CertificateType::IntermediateCA,
                key_usage: vec![KeyUsage::KeyCertSign],
                extended_key_usage: vec![],
                subject_alt_names: vec![],
                san_policy: SanPolicy::default(),
                validity_days: 30,
                preferred_key_type: KeyType::Ed25519,
                extensions: HashMap::new(),
            },
        );
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        let key = new_key();

        // A CA profile is not issuable through a request.
        assert!(
            manager
                .sign_certificate_request(&request("sub-ca", &key, "ca"), "root_ca")
                .await
                .is_err()
        );
        // Unknown profile / CA, garbage key, blank name, unusable names.
        assert!(
            manager
                .sign_certificate_request(&request("x", &key, "nope"), "root_ca")
                .await
                .is_err()
        );
        assert!(
            manager
                .sign_certificate_request(&request("x", &key, "tls_client"), "nope")
                .await
                .is_err()
        );
        let mut bad_key = request("x", &key, "tls_client");
        bad_key.public_key_pem = "not a key".to_string();
        assert!(
            manager
                .sign_certificate_request(&bad_key, "root_ca")
                .await
                .is_err()
        );
        let mut blank = request("  ", &key, "tls_client");
        blank.subject.common_name = "  ".to_string();
        assert!(
            manager
                .sign_certificate_request(&blank, "root_ca")
                .await
                .is_err()
        );
        let mut bad_san = request("x", &key, "tls_client");
        bad_san.subject_alt_names = vec![SubjectAltName::DnsName("münchen.example".to_string())];
        assert!(
            manager
                .sign_certificate_request(&bad_san, "root_ca")
                .await
                .is_err()
        );
        let mut bad_ip = request("x", &key, "tls_client");
        bad_ip.subject_alt_names = vec![SubjectAltName::IpAddress("999.1.1.1".to_string())];
        assert!(
            manager
                .sign_certificate_request(&bad_ip, "root_ca")
                .await
                .is_err()
        );
        assert!(manager.list_certificates(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn certificates_that_only_look_like_ours_do_not_validate() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Trusted Root");
        let manager = manager_with(dir.path(), &root, true).await;
        let root_der = der_of(&root.cert_pem);
        let (_, root_cert) = parse_x509_certificate(&root_der).unwrap();

        // Genuine.
        assert!(
            manager
                .validate_certificate_chain(
                    &root.leaf("ok", |_| {}),
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );
        // The configured root, as itself.
        assert!(
            manager
                .validate_certificate_chain(&root.cert_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );

        // Self-signed with the root's exact subject, but the attacker's key.
        let mut forged_params = ca_params("Trusted Root");
        forged_params.distinguished_name = DistinguishedName::new();
        forged_params
            .distinguished_name
            .push(DnType::CommonName, "Trusted Root");
        forged_params
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        let forged = TestCa::root_with(forged_params);
        let forged_der = der_of(&forged.cert_pem);
        let (_, forged_cert) = parse_x509_certificate(&forged_der).unwrap();
        assert_eq!(
            forged_cert.subject().to_string(),
            root_cert.subject().to_string()
        );
        assert!(
            !manager
                .validate_certificate_chain(&forged.cert_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );

        // A leaf issued by that forged CA, claiming the root's issuer name.
        assert!(
            !manager
                .validate_certificate_chain(
                    &forged.leaf("evil", |_| {}),
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );

        // An unrelated CA's certificate.
        let other = TestCa::root("Other CA");
        assert!(
            !manager
                .validate_certificate_chain(
                    &other.leaf("victim", |_| {}),
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );

        // Genuinely issued but expired.
        let expired = root.leaf("old", |p| {
            p.not_before = rcgen::date_time_ymd(2000, 1, 1);
            p.not_after = rcgen::date_time_ymd(2001, 1, 1);
        });
        assert!(
            !manager
                .validate_certificate_chain(&expired, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );

        // Not a certificate at all.
        assert!(
            manager
                .validate_certificate_chain("garbage", CertificatePurpose::ClientAuth)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_chain_through_an_intermediate_validates_when_the_intermediate_is_known() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let manager = manager_with(dir.path(), &root, true).await; // root only
        let leaf = intermediate.leaf("deep", |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });

        // The intermediate is unknown here: the path cannot be built.
        assert!(
            !manager
                .validate_certificate_chain(&leaf, CertificatePurpose::ServerAuth)
                .await
                .unwrap()
        );
        // Presented with the leaf, it is used as a candidate intermediate.
        let bundle = format!("{leaf}{}", intermediate.cert_pem);
        assert!(
            manager
                .validate_certificate_chain(&bundle, CertificatePurpose::ServerAuth)
                .await
                .unwrap()
        );
        // The same bundle under a different root does not validate.
        let other_dir = tempfile::tempdir().unwrap();
        let other = manager_with(other_dir.path(), &TestCa::root("Elsewhere"), true).await;
        assert!(
            !other
                .validate_certificate_chain(&bundle, CertificatePurpose::ServerAuth)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn serial_numbers_and_revocations_are_scoped_to_the_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let (root_cert, root_key) = root.write(dir.path(), "root");
        let (inter_cert, inter_key) = intermediate.write(dir.path(), "inter");
        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path = Some(inter_cert.to_string_lossy().to_string());
        config.intermediate_ca_key_path = Some(inter_key.to_string_lossy().to_string());
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();

        let from_root = manager
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        let from_inter = manager
            .sign_certificate_request(&request("b", &new_key(), "tls_client"), "intermediate_ca")
            .await
            .unwrap();
        assert_ne!(from_root.serial_number, from_inter.serial_number);
        // Force the situation that scoping exists for: another issuer holding the same serial.
        {
            let mut twin = from_inter.clone();
            twin.cert_id = "twin".to_string();
            twin.serial_number = from_root.serial_number.clone();
            manager
                .certificate_store
                .write()
                .await
                .insert("twin".to_string(), twin);
        }
        assert!(from_inter.issuer.contains("Issuing CA"));
        assert!(
            manager
                .validate_certificate_chain(
                    &from_inter.certificate_pem,
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );

        // The bare serial is ambiguous: refused, nothing revoked.
        let serial = from_root.serial_number.clone();
        assert!(
            manager
                .revoke_certificate(&serial, RevocationReason::KeyCompromise, None)
                .await
                .is_err()
        );
        assert!(manager.check_certificate_status(&serial).await.is_err());
        assert!(
            manager
                .validate_certificate_chain(
                    &from_root.certificate_pem,
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );

        // Naming the issuer revokes only that issuer's certificate.
        manager
            .revoke_certificate_issued_by("root_ca", &serial, RevocationReason::KeyCompromise, None)
            .await
            .unwrap();
        assert_eq!(
            manager
                .check_certificate_status_issued_by("root_ca", &serial)
                .await
                .unwrap(),
            CertificateStatus::Revoked
        );
        assert_eq!(
            manager
                .check_certificate_status_issued_by("intermediate_ca", &serial)
                .await
                .unwrap(),
            CertificateStatus::Valid
        );
        assert!(
            !manager
                .validate_certificate_chain(
                    &from_root.certificate_pem,
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );
        assert!(
            manager
                .validate_certificate_chain(
                    &from_inter.certificate_pem,
                    CertificatePurpose::ClientAuth
                )
                .await
                .unwrap()
        );

        // An unknown serial cannot be pre-revoked.
        assert!(
            manager
                .revoke_certificate_issued_by(
                    "root_ca",
                    "424242",
                    RevocationReason::Unspecified,
                    None
                )
                .await
                .is_err()
        );

        // A serial held by one certificate only resolves without naming the issuer.
        let third = manager
            .sign_certificate_request(&request("c", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        manager
            .revoke_certificate(
                &third.serial_number,
                RevocationReason::Superseded,
                Some("test".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            manager
                .check_certificate_status(&third.serial_number)
                .await
                .unwrap(),
            CertificateStatus::Revoked
        );
    }

    #[tokio::test]
    async fn a_revoked_intermediate_invalidates_what_it_issued() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let (root_cert, root_key) = root.write(dir.path(), "root");
        let (inter_cert, inter_key) = intermediate.write(dir.path(), "inter");
        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path = Some(inter_cert.to_string_lossy().to_string());
        config.intermediate_ca_key_path = Some(inter_key.to_string_lossy().to_string());
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        let issued = manager
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "intermediate_ca")
            .await
            .unwrap();
        assert!(
            manager
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );

        // The root's CA revokes the intermediate through the public API.
        manager
            .revoke_ca_certificate("intermediate_ca", RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        assert!(
            manager
                .sign_certificate_request(
                    &request("b", &new_key(), "tls_client"),
                    "intermediate_ca"
                )
                .await
                .is_err(),
            "a revoked CA cannot issue"
        );
        assert!(
            !manager
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn the_crl_is_a_signed_der_crl_for_this_cas_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("CRL Root");
        let manager = manager_with(dir.path(), &root, true).await;
        let mut serials = Vec::new();
        for name in ["a", "b", "c"] {
            let stored = manager
                .sign_certificate_request(&request(name, &new_key(), "tls_client"), "root_ca")
                .await
                .unwrap();
            serials.push(stored.serial_number);
        }
        manager
            .revoke_certificate_issued_by(
                "root_ca",
                &serials[0],
                RevocationReason::KeyCompromise,
                None,
            )
            .await
            .unwrap();
        manager
            .revoke_certificate_issued_by(
                "root_ca",
                &serials[2],
                RevocationReason::Superseded,
                None,
            )
            .await
            .unwrap();
        // A revocation recorded for another CA is not on this CA's list.
        manager.revocation_list.write().await.insert(
            X509CertificateManager::revocation_key("someone_else", "1"),
            RevocationEntry {
                serial_number: "1".to_string(),
                revocation_date: Utc::now(),
                reason: RevocationReason::Unspecified,
                additional_info: None,
            },
        );

        let crl_pem = manager.generate_crl("root_ca").await.unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(crl_pem.as_bytes()).unwrap();
        assert_eq!(pem.label, "X509 CRL");
        let (rest, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&pem.contents)
                .unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            crl.issuer().to_string(),
            ca_subject(&manager, "root_ca").await
        );
        let mut listed: Vec<String> = crl
            .iter_revoked_certificates()
            .map(|r| r.user_certificate.to_string())
            .collect();
        listed.sort();
        let mut expected = vec![serials[0].clone(), serials[2].clone()];
        expected.sort();
        assert_eq!(listed, expected);
        assert!(crl.next_update().is_some());

        // The signature verifies under the CA's key, and not under another.
        let ca_der = der_of(&root.cert_pem);
        let (_, ca_cert) = parse_x509_certificate(&ca_der).unwrap();
        crl.verify_signature(ca_cert.public_key())
            .expect("signed by the CA");
        let other = TestCa::root("Other");
        let other_der = der_of(&other.cert_pem);
        let (_, other_cert) = parse_x509_certificate(&other_der).unwrap();
        assert!(crl.verify_signature(other_cert.public_key()).is_err());
    }

    #[tokio::test]
    async fn an_imported_ca_certificate_is_parsed_or_refused() {
        let manager = X509CertificateManager::new(X509Config::default());
        assert!(
            manager
                .store_ca_certificate_from_pem(
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                    "test"
                )
                .await
                .is_err()
        );
        assert!(manager.ca_certificates.read().await.is_empty());

        let root = TestCa::root("Imported Root");
        manager
            .store_ca_certificate_from_pem(&root.cert_pem, "test")
            .await
            .unwrap();
        let cas = manager.ca_certificates.read().await;
        assert!(cas["root_ca"].subject.contains("Imported Root"));
        assert!(
            cas["root_ca"].private_key.is_empty(),
            "key stays with the source"
        );
        drop(cas);
        // It validates what it issued but cannot issue.
        assert!(
            manager
                .validate_certificate_chain(&root.leaf("x", |_| {}), CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            manager
                .sign_certificate_request(&request("svc", &new_key(), "tls_client"), "root_ca")
                .await
                .is_err()
        );
    }

    // ─── Review round: policy, persistence, serials, CA revocation, purposes ───

    fn open_profile(name: &str) -> CertificateProfile {
        CertificateProfile {
            name: name.to_string(),
            cert_type: CertificateType::TlsClient,
            key_usage: vec![KeyUsage::DigitalSignature],
            extended_key_usage: vec![ExtendedKeyUsage::ClientAuth],
            subject_alt_names: vec![],
            san_policy: SanPolicy {
                wildcard_dns: true,
                ip_address: true,
                uri: true,
                email: true,
            },
            validity_days: 30,
            preferred_key_type: KeyType::Ecdsa(EcdsaCurve::P256),
            extensions: HashMap::new(),
        }
    }

    /// A manager with the default profiles plus `extra`, over a fresh root.
    async fn manager_with_profiles(
        dir: &Path,
        extra: Vec<(&str, CertificateProfile)>,
    ) -> (X509CertificateManager, TestCa) {
        let root = TestCa::root("Policy Root");
        let (cert, key) = root.write(dir, "root");
        let mut config = config_for(&cert, &key);
        for (name, profile) in extra {
            config
                .certificate_profiles
                .insert(name.to_string(), profile);
        }
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        (manager, root)
    }

    async fn assert_refused(
        manager: &X509CertificateManager,
        request: &CertificateRequest,
        why: &str,
    ) {
        let before = manager.list_certificates(None).await.unwrap().len();
        assert!(
            manager
                .sign_certificate_request(request, "root_ca")
                .await
                .is_err(),
            "{why}"
        );
        assert_eq!(
            manager.list_certificates(None).await.unwrap().len(),
            before,
            "{why}: nothing may be stored"
        );
    }

    #[tokio::test]
    async fn hostile_names_and_unsupported_inputs_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut with_extensions = open_profile("ext");
        with_extensions
            .extensions
            .insert("anything".to_string(), Value::Bool(true));
        let (manager, _) = manager_with_profiles(
            dir.path(),
            vec![("open", open_profile("open")), ("ext", with_extensions)],
        )
        .await;
        let key = new_key();
        let base = |profile: &str| request("host", &key, profile);

        // Subject text.
        for (why, cn) in [
            ("newline in CN", "evil\nCN=admin".to_string()),
            ("NUL in CN", "evil\0".to_string()),
            ("tab in CN", "a\tb".to_string()),
            ("65-character CN", "a".repeat(65)),
            ("45,000-character CN", "a".repeat(45_000)),
        ] {
            let mut r = base("tls_client");
            r.subject.common_name = cn;
            assert_refused(&manager, &r, why).await;
        }
        for country in ["ZZZZZZ", "us", "U", ""] {
            let mut r = base("tls_client");
            r.subject.country = Some(country.to_string());
            assert_refused(&manager, &r, &format!("country {country:?}")).await;
        }
        let mut r = base("tls_client");
        r.subject.organization = Some("o\r\nx".to_string());
        assert_refused(&manager, &r, "control character in organization").await;

        // Names the profile does not allow.
        for (why, san) in [
            (
                "wildcard",
                SubjectAltName::DnsName("*.example.com".to_string()),
            ),
            (
                "localhost",
                SubjectAltName::DnsName("localhost".to_string()),
            ),
            (
                "sub.localhost",
                SubjectAltName::DnsName("a.localhost".to_string()),
            ),
            (
                "bare label",
                SubjectAltName::DnsName("intranet".to_string()),
            ),
            (
                "numeric TLD",
                SubjectAltName::DnsName("1.2.3.4".to_string()),
            ),
            ("empty name", SubjectAltName::DnsName(String::new())),
            (
                "underscore",
                SubjectAltName::DnsName("a_b.example".to_string()),
            ),
            (
                "45,000-char name",
                SubjectAltName::DnsName(format!("{}.example", "a".repeat(45_000))),
            ),
            (
                "long label",
                SubjectAltName::DnsName(format!("{}.example", "a".repeat(64))),
            ),
            (
                "IP without policy",
                SubjectAltName::IpAddress("192.0.2.1".to_string()),
            ),
            (
                "URI without policy",
                SubjectAltName::Uri("https://svc.example/id".to_string()),
            ),
            (
                "e-mail without policy",
                SubjectAltName::Email("a@example.com".to_string()),
            ),
        ] {
            let mut r = base("tls_client");
            r.subject_alt_names = vec![san];
            assert_refused(&manager, &r, why).await;
        }
        // Names that are refused even where the profile allows the kind.
        for (why, san) in [
            (
                "loopback IP",
                SubjectAltName::IpAddress("127.0.0.1".to_string()),
            ),
            (
                "unspecified IP",
                SubjectAltName::IpAddress("0.0.0.0".to_string()),
            ),
            (
                "multicast IP",
                SubjectAltName::IpAddress("224.0.0.1".to_string()),
            ),
            (
                "garbage IP",
                SubjectAltName::IpAddress("999.1.1.1".to_string()),
            ),
            (
                "URI with space",
                SubjectAltName::Uri("https://a b".to_string()),
            ),
            (
                "URI without scheme",
                SubjectAltName::Uri("no-scheme".to_string()),
            ),
            (
                "e-mail without @",
                SubjectAltName::Email("nobody".to_string()),
            ),
            (
                "e-mail with two @",
                SubjectAltName::Email("a@b@example.com".to_string()),
            ),
            (
                "e-mail to localhost",
                SubjectAltName::Email("a@localhost".to_string()),
            ),
            (
                "non-ASCII DNS",
                SubjectAltName::DnsName("münchen.example".to_string()),
            ),
        ] {
            let mut r = base("open");
            r.subject_alt_names = vec![san];
            assert_refused(&manager, &r, why).await;
        }
        let mut r = base("open");
        r.subject_alt_names = (0..26)
            .map(|i| SubjectAltName::DnsName(format!("h{i}.example.com")))
            .collect();
        assert_refused(&manager, &r, "26 names").await;

        // Inputs that would be accepted and ignored.
        let mut r = base("tls_client");
        r.attributes
            .insert("anything".to_string(), Value::Bool(true));
        assert_refused(&manager, &r, "request attributes").await;
        assert_refused(&manager, &base("ext"), "profile extensions").await;

        // Subject keys: weak, wrong strength class, not a public key.
        let mut r = base("tls_client");
        r.public_key_pem = rsa_spki_pem(1024);
        assert_refused(&manager, &r, "RSA-1024").await;
        r.public_key_pem = rsa_spki_pem(512);
        assert_refused(&manager, &r, "RSA-512").await;
        let mut r = base("tls_client");
        r.public_key_pem =
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_string();
        assert_refused(&manager, &r, "not a public key").await;

        // Accepted where allowed, with the names carried into the certificate.
        let mut ok = base("open");
        ok.subject_alt_names = vec![
            SubjectAltName::DnsName("*.example.com".to_string()),
            SubjectAltName::IpAddress("192.0.2.10".to_string()),
            SubjectAltName::Uri("https://svc.example/id".to_string()),
            SubjectAltName::Email("ops@example.com".to_string()),
        ];
        ok.subject.email = Some("owner@example.com".to_string());
        ok.subject.country = Some("US".to_string());
        let stored = manager
            .sign_certificate_request(&ok, "root_ca")
            .await
            .unwrap();
        let der = der_of(&stored.certificate_pem);
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names.len(),
            5,
            "{:?}",
            san.value.general_names
        );
    }

    /// A SubjectPublicKeyInfo PEM for an RSA key of `bits` bits (the modulus is not a real
    /// product of primes: only its size is looked at).
    fn rsa_spki_pem(bits: usize) -> String {
        fn der(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match content.len() {
                n if n < 128 => out.push(n as u8),
                n if n < 256 => out.extend([0x81, n as u8]),
                n => out.extend([0x82, (n >> 8) as u8, n as u8]),
            }
            out.extend(content);
            out
        }
        let mut modulus = vec![0u8];
        modulus.extend(vec![0xC5u8; bits / 8]);
        let rsa_key = der(
            0x30,
            &[der(0x02, &modulus), der(0x02, &[0x01, 0x00, 0x01])].concat(),
        );
        let mut bit_string = vec![0u8];
        bit_string.extend(rsa_key);
        let algorithm = der(
            0x30,
            &[
                der(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                ),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let spki = der(0x30, &[algorithm, der(0x03, &bit_string)].concat());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64_STANDARD.encode(spki)
        )
    }

    #[tokio::test]
    async fn the_profile_decides_the_minimum_key_strength() {
        let dir = tempfile::tempdir().unwrap();
        let mut strong = open_profile("strong");
        strong.preferred_key_type = KeyType::Ecdsa(EcdsaCurve::P384);
        let (manager, _) = manager_with_profiles(dir.path(), vec![("strong", strong)]).await;
        // P-256 is weaker than the profile's P-384 minimum; P-384 is enough.
        assert_refused(
            &manager,
            &request("a", &new_key(), "strong"),
            "P-256 under a P-384 minimum",
        )
        .await;
        let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        manager
            .sign_certificate_request(&request("a", &p384, "strong"), "root_ca")
            .await
            .unwrap();
        // Ed25519 meets the default profiles' RSA-2048 minimum.
        let ed = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        manager
            .sign_certificate_request(&request("b", &ed, "tls_client"), "root_ca")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn profile_settings_are_honoured_or_refused_never_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixed = open_profile("fixed");
        fixed.subject_alt_names = vec![SubjectAltName::DnsName("fixed.example.com".to_string())];
        let mut default_days = open_profile("default-days");
        default_days.validity_days = 0;
        let mut huge = open_profile("huge");
        huge.validity_days = i64::MAX;
        let root = TestCa::root("Profiles");
        let (cert, key) = root.write(dir.path(), "root");
        let mut config = config_for(&cert, &key);
        config.default_validity_days = 7;
        for (name, p) in [
            ("fixed", fixed),
            ("default-days", default_days),
            ("huge", huge),
        ] {
            config.certificate_profiles.insert(name.to_string(), p);
        }
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        let key = new_key();

        // The profile's own names are in the certificate.
        let stored = manager
            .sign_certificate_request(&request("one", &key, "fixed"), "root_ca")
            .await
            .unwrap();
        let der = der_of(&stored.certificate_pem);
        let (_, parsed) = parse_x509_certificate(&der).unwrap();
        let names = format!(
            "{:?}",
            parsed
                .subject_alternative_name()
                .unwrap()
                .unwrap()
                .value
                .general_names
        );
        assert!(
            names.contains("fixed.example.com") && names.contains("one.example"),
            "{names}"
        );

        // default_validity_days applies when the profile has none.
        let stored = manager
            .sign_certificate_request(&request("two", &key, "default-days"), "root_ca")
            .await
            .unwrap();
        let days = (stored.not_after - Utc::now()).num_days();
        assert!((6..=7).contains(&days), "{days}");
        // Not-before is backdated for clock skew.
        assert!(stored.not_before <= Utc::now() - Duration::minutes(4));

        // Nonsense validity is an error, not a panic.
        assert_refused(&manager, &request("three", &key, "huge"), "i64::MAX days").await;
    }

    #[tokio::test]
    async fn unsupported_settings_stop_initialize() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Settings");
        let (cert, key) = root.write(dir.path(), "root");

        let mut config = config_for(&cert, &key);
        config.enable_ocsp = true;
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );
        let mut config = config_for(&cert, &key);
        config.ocsp_responder_url = Some("https://ocsp.example.com".to_string());
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );
        for bad in [
            "ldap://x",
            "https://a b",
            "https://x\ny",
            "javascript:alert(1)",
        ] {
            let mut config = config_for(&cert, &key);
            config.crl_distribution_url = Some(bad.to_string());
            assert!(
                X509CertificateManager::new(config)
                    .initialize()
                    .await
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn the_crl_distribution_point_and_ca_false_reach_issued_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("DP Root");
        let (cert, key) = root.write(dir.path(), "root");
        let mut config = config_for(&cert, &key);
        config.crl_distribution_url = Some("https://crl.example.com/root.crl".to_string());
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        let stored = manager
            .sign_certificate_request(&request("svc", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        let der = der_of(&stored.certificate_pem);
        let (_, parsed) = parse_x509_certificate(&der).unwrap();
        let has = |oid: &x509_parser::der_parser::oid::Oid| {
            parsed.extensions().iter().any(|e| &e.oid == oid)
        };
        assert!(has(
            &x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS
        ));
        assert!(has(
            &x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
        ));
        assert!(has(
            &x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
        ));
        let basic = parsed
            .basic_constraints()
            .unwrap()
            .expect("basicConstraints present");
        assert!(!basic.value.ca);

        // With CRLs disabled there is no CRL.
        let mut config = config_for(&cert, &key);
        config.enable_crl = false;
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        assert!(manager.generate_crl("root_ca").await.is_err());
    }

    #[tokio::test]
    async fn serial_numbers_are_random_wide_and_never_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) = manager_with_profiles(dir.path(), vec![]).await;
        let mut tasks = Vec::new();
        for i in 0..40 {
            let manager = manager.clone();
            tasks.push(tokio::spawn(async move {
                manager
                    .sign_certificate_request(
                        &request(&format!("c{i}"), &new_key(), "tls_client"),
                        "root_ca",
                    )
                    .await
                    .unwrap()
                    .serial_number
            }));
        }
        let mut serials = Vec::new();
        for task in tasks {
            serials.push(task.await.unwrap());
        }
        // A second initialize (as after a restart in one process) must not reuse numbers.
        manager.initialize().await.unwrap();
        for i in 0..10 {
            serials.push(
                manager
                    .sign_certificate_request(
                        &request(&format!("d{i}"), &new_key(), "tls_client"),
                        "root_ca",
                    )
                    .await
                    .unwrap()
                    .serial_number,
            );
        }
        let unique: std::collections::HashSet<_> = serials.iter().collect();
        assert_eq!(unique.len(), serials.len(), "duplicate serial numbers");
        let floor = x509_parser::num_bigint::BigUint::from(1u8) << 120usize;
        for serial in &serials {
            let n = x509_parser::num_bigint::BigUint::parse_bytes(serial.as_bytes(), 10).unwrap();
            assert!(n > floor, "serial {serial} is not 120+ bits wide");
        }
    }

    #[tokio::test]
    async fn revocations_survive_a_restart_when_a_state_file_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("State Root");
        let (cert, key) = root.write(dir.path(), "root");
        let state = dir.path().join("state").join("x509.json");
        let config = {
            let mut c = config_for(&cert, &key);
            c.state_path = Some(state.to_string_lossy().to_string());
            c
        };
        let first = X509CertificateManager::new(config.clone());
        first.initialize().await.unwrap();
        let issued = first
            .sign_certificate_request(&request("svc", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        let other = first
            .sign_certificate_request(&request("keep", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        first
            .revoke_certificate(&issued.serial_number, RevocationReason::KeyCompromise, None)
            .await
            .unwrap();
        let crl_one = first.generate_crl("root_ca").await.unwrap();

        // "Restart": a new manager over the same files.
        let second = X509CertificateManager::new(config.clone());
        second.initialize().await.unwrap();
        assert_eq!(
            second
                .check_certificate_status(&issued.serial_number)
                .await
                .unwrap(),
            CertificateStatus::Revoked,
            "a restart must not un-revoke"
        );
        assert!(
            !second
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            second
                .validate_certificate_chain(&other.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        // An old certificate can still be revoked after the restart.
        second
            .revoke_certificate(&other.serial_number, RevocationReason::Superseded, None)
            .await
            .unwrap();
        // CRL numbers keep increasing.
        let number = |pem: &str| {
            use x509_parser::prelude::FromDer;
            let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            let (_, crl) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(&p.contents)
                    .unwrap();
            crl.crl_number().unwrap().clone()
        };
        let crl_two = second.generate_crl("root_ca").await.unwrap();
        let crl_three = second.generate_crl("root_ca").await.unwrap();
        assert!(number(&crl_two) > number(&crl_one));
        assert!(number(&crl_three) > number(&crl_two));

        // A damaged state file stops initialize instead of starting empty.
        std::fs::write(&state, "{ not json").unwrap();
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_state_file_that_cannot_be_written_fails_the_operation() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Unwritable");
        let (cert, key) = root.write(dir.path(), "root");
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap(); // a directory where the file should go
        let mut config = config_for(&cert, &key);
        config.state_path = Some(blocked.to_string_lossy().to_string());
        let manager = X509CertificateManager::new(config);
        // initialize sees the directory as "a state file" and refuses to read it.
        assert!(manager.initialize().await.is_err());

        // A manager whose state path only became unwritable after it started.
        let state = dir.path().join("later.json");
        let mut config = config_for(&cert, &key);
        config.state_path = Some(state.to_string_lossy().to_string());
        let manager = X509CertificateManager::new(config);
        manager.initialize().await.unwrap();
        let issued = manager
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        std::fs::remove_file(&state).ok();
        std::fs::create_dir(&state).unwrap();
        // Issuing now fails and records nothing...
        let before = manager.list_certificates(None).await.unwrap().len();
        assert!(
            manager
                .sign_certificate_request(&request("b", &new_key(), "tls_client"), "root_ca")
                .await
                .is_err()
        );
        assert_eq!(manager.list_certificates(None).await.unwrap().len(), before);
        // ...and a revocation that cannot be saved still takes effect, and says so.
        assert!(
            manager
                .revoke_certificate(&issued.serial_number, RevocationReason::KeyCompromise, None)
                .await
                .is_err()
        );
        assert!(
            !manager
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn without_a_state_file_a_certificate_can_still_be_revoked_from_its_pem() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Volatile");
        let (cert, key) = root.write(dir.path(), "root");
        let first = X509CertificateManager::new(config_for(&cert, &key));
        first.initialize().await.unwrap();
        let issued = first
            .sign_certificate_request(&request("old", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();

        // Restart without state: the store is empty and the serial is unknown...
        let second = X509CertificateManager::new(config_for(&cert, &key));
        second.initialize().await.unwrap();
        assert!(
            second
                .revoke_certificate(&issued.serial_number, RevocationReason::KeyCompromise, None)
                .await
                .is_err()
        );
        // ...but the certificate itself is enough.
        second
            .revoke_certificate_pem(
                &issued.certificate_pem,
                RevocationReason::KeyCompromise,
                None,
            )
            .await
            .unwrap();
        assert!(
            !second
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        // A certificate that carries OUR issuer name but was signed by someone else is refused.
        let mut forged_ca = ca_params("Volatile");
        forged_ca.distinguished_name = DistinguishedName::new();
        forged_ca
            .distinguished_name
            .push(DnType::CommonName, "Volatile");
        forged_ca
            .distinguished_name
            .push(DnType::OrganizationName, "Test Org");
        let impostor = TestCa::root_with(forged_ca).leaf("victim", |_| {});
        assert!(
            second
                .revoke_certificate_pem(&impostor, RevocationReason::KeyCompromise, None)
                .await
                .is_err(),
            "revoking needs a certificate our CA really signed"
        );
        // A certificate some other CA signed is refused.
        let stranger = TestCa::root("Stranger").leaf("x", |_| {});
        assert!(
            second
                .revoke_certificate_pem(&stranger, RevocationReason::KeyCompromise, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_revoked_ca_stays_revoked_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let (root_cert, root_key) = root.write(dir.path(), "root");
        let (inter_cert, inter_key) = intermediate.write(dir.path(), "inter");
        let state = dir.path().join("state.json");
        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path = Some(inter_cert.to_string_lossy().to_string());
        config.intermediate_ca_key_path = Some(inter_key.to_string_lossy().to_string());
        config.state_path = Some(state.to_string_lossy().to_string());
        let first = X509CertificateManager::new(config.clone());
        first.initialize().await.unwrap();
        let issued = first
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "intermediate_ca")
            .await
            .unwrap();
        first
            .revoke_ca_certificate("intermediate_ca", RevocationReason::CaCompromise, None)
            .await
            .unwrap();

        let second = X509CertificateManager::new(config);
        second.initialize().await.unwrap();
        assert_eq!(
            second.ca_certificates.read().await["intermediate_ca"]
                .certificate
                .status,
            CertificateStatus::Revoked
        );
        assert!(
            second
                .sign_certificate_request(
                    &request("b", &new_key(), "tls_client"),
                    "intermediate_ca"
                )
                .await
                .is_err()
        );
        assert!(
            !second
                .validate_certificate_chain(&issued.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        // The root is untouched and still issues.
        second
            .sign_certificate_request(&request("c", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();

        // Revoking the root ends the whole tree.
        second
            .revoke_ca_certificate("root_ca", RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        assert!(
            second
                .sign_certificate_request(&request("d", &new_key(), "tls_client"), "root_ca")
                .await
                .is_err()
        );
        assert!(
            !second
                .validate_certificate_chain(&root.leaf("e", |_| {}), CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            !second
                .validate_certificate_chain(&root.cert_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            second
                .revoke_ca_certificate("nobody", RevocationReason::Unspecified, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_purpose_is_the_callers_not_the_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Purposes");
        let manager = manager_with(dir.path(), &root, true).await;
        let server_only = root.leaf("srv", |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });
        let signing_only = root.leaf("sign", |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        });
        let unrestricted = root.leaf("any", |_| {});
        let valid = |pem: &str, purpose| {
            let manager = manager.clone();
            let pem = pem.to_string();
            async move {
                manager
                    .validate_certificate_chain(&pem, purpose)
                    .await
                    .unwrap()
            }
        };
        use CertificatePurpose::*;
        assert!(valid(&server_only, ServerAuth).await);
        assert!(!valid(&server_only, ClientAuth).await);
        assert!(!valid(&server_only, CodeSigning).await);
        assert!(valid(&signing_only, CodeSigning).await);
        assert!(!valid(&signing_only, ServerAuth).await);
        assert!(!valid(&signing_only, ClientAuth).await);
        // No extended key usage at all: valid for any purpose.
        for purpose in [
            ServerAuth,
            ClientAuth,
            CodeSigning,
            EmailProtection,
            TimeStamping,
            OcspSigning,
        ] {
            assert!(valid(&unrestricted, purpose).await, "{purpose:?}");
        }
    }

    #[tokio::test]
    async fn crl_numbers_increase_and_reason_codes_are_right() {
        use x509_parser::prelude::FromDer;
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) = manager_with_profiles(dir.path(), vec![]).await;
        let mut issued = Vec::new();
        for name in ["a", "b"] {
            issued.push(
                manager
                    .sign_certificate_request(&request(name, &new_key(), "tls_client"), "root_ca")
                    .await
                    .unwrap(),
            );
        }
        // "Remove from CRL" is not a reason to revoke.
        assert!(
            manager
                .revoke_certificate(
                    &issued[0].serial_number,
                    RevocationReason::RemoveFromCrl,
                    None
                )
                .await
                .is_err()
        );
        manager
            .revoke_certificate(
                &issued[0].serial_number,
                RevocationReason::Unspecified,
                None,
            )
            .await
            .unwrap();
        manager
            .revoke_certificate(
                &issued[1].serial_number,
                RevocationReason::KeyCompromise,
                None,
            )
            .await
            .unwrap();

        let parse = |pem: &str| {
            let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            p.contents
        };
        let first = parse(&manager.generate_crl("root_ca").await.unwrap());
        let second = parse(&manager.generate_crl("root_ca").await.unwrap());
        let (_, first) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&first).unwrap();
        let (_, second) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&second).unwrap();
        assert!(second.crl_number().unwrap() > first.crl_number().unwrap());
        assert!(
            first.last_update().timestamp() <= Utc::now().timestamp() - 240,
            "backdated"
        );
        for entry in first.iter_revoked_certificates() {
            let code = entry.reason_code().map(|(_, c)| c.0);
            if entry.user_certificate.to_string() == issued[0].serial_number {
                assert_eq!(code, None, "reasonCode 0 is omitted");
            } else {
                assert_eq!(code, Some(1), "keyCompromise");
            }
        }
    }

    // ─── Review round 3 ────────────────────────────────────────────────────────

    /// A manager with a root and an intermediate (both with keys) and no state file.
    async fn two_level_manager(
        dir: &Path,
        state: Option<&Path>,
    ) -> (X509CertificateManager, TestCa, TestCa, X509Config) {
        let root = TestCa::root("Root");
        let intermediate = root.intermediate("Issuing CA");
        let (root_cert, root_key) = root.write(dir, "root");
        let (inter_cert, inter_key) = intermediate.write(dir, "inter");
        let mut config = config_for(&root_cert, &root_key);
        config.intermediate_ca_cert_path = Some(inter_cert.to_string_lossy().to_string());
        config.intermediate_ca_key_path = Some(inter_key.to_string_lossy().to_string());
        config.state_path = state.map(|p| p.to_string_lossy().to_string());
        let manager = X509CertificateManager::new(config.clone());
        manager.initialize().await.unwrap();
        (manager, root, intermediate, config)
    }

    async fn can_issue(manager: &X509CertificateManager, ca_id: &str, name: &str) -> bool {
        manager
            .sign_certificate_request(&request(name, &new_key(), "tls_client"), ca_id)
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn revoking_a_held_ca_by_pem_or_serial_takes_it_out_of_service() {
        let dir = tempfile::tempdir().unwrap();

        // Intermediate, by its certificate.
        let (manager, root, intermediate, _) = two_level_manager(dir.path(), None).await;
        let leaf = manager
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "intermediate_ca")
            .await
            .unwrap();
        assert!(
            manager
                .validate_certificate_chain(&leaf.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        manager
            .revoke_certificate_pem(&intermediate.cert_pem, RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        assert!(
            !can_issue(&manager, "intermediate_ca", "b").await,
            "revoked intermediate issued"
        );
        assert!(
            !manager
                .validate_certificate_chain(&leaf.certificate_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            can_issue(&manager, "root_ca", "c").await,
            "the root is unaffected"
        );

        // Root, by its certificate: it signs nothing and trusts nothing any more.
        manager
            .revoke_certificate_pem(&root.cert_pem, RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        assert!(
            !can_issue(&manager, "root_ca", "d").await,
            "revoked root issued"
        );
        assert!(
            !manager
                .validate_certificate_chain(&root.cert_pem, CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );
        assert!(
            !manager
                .validate_certificate_chain(&root.leaf("e", |_| {}), CertificatePurpose::ClientAuth)
                .await
                .unwrap()
        );

        // Intermediate, by serial number through the issuer-scoped call.
        let dir2 = tempfile::tempdir().unwrap();
        let (manager, _, _, _) = two_level_manager(dir2.path(), None).await;
        let serial = manager.ca_certificates.read().await["intermediate_ca"]
            .certificate
            .serial_number
            .clone();
        manager
            .revoke_certificate_issued_by("root_ca", &serial, RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        assert!(!can_issue(&manager, "intermediate_ca", "f").await);
        assert_eq!(
            manager.ca_certificates.read().await["intermediate_ca"]
                .certificate
                .status,
            CertificateStatus::Revoked
        );
    }

    #[tokio::test]
    async fn initialize_again_does_not_bring_a_revoked_ca_back() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _, _, _) = two_level_manager(dir.path(), None).await;
        manager
            .revoke_ca_certificate("intermediate_ca", RevocationReason::CaCompromise, None)
            .await
            .unwrap();
        manager.initialize().await.unwrap(); // no state file
        assert!(!can_issue(&manager, "intermediate_ca", "x").await);
        assert_eq!(
            manager.ca_certificates.read().await["intermediate_ca"]
                .certificate
                .status,
            CertificateStatus::Revoked
        );
    }

    #[tokio::test]
    async fn loading_an_older_state_cannot_roll_back_a_revocation_or_a_crl_number() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let (manager, _, _, _) = two_level_manager(dir.path(), Some(&state)).await;
        let a = manager
            .sign_certificate_request(&request("a", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        let b = manager
            .sign_certificate_request(&request("b", &new_key(), "tls_client"), "root_ca")
            .await
            .unwrap();
        // A copy of the state before the revocation and before the second CRL.
        manager.generate_crl("root_ca").await.unwrap();
        let old_copy = dir.path().join("old.json");
        std::fs::copy(&state, &old_copy).unwrap();
        manager
            .revoke_certificate(&a.serial_number, RevocationReason::KeyCompromise, None)
            .await
            .unwrap();
        manager.generate_crl("root_ca").await.unwrap();
        let number = manager.crl_numbers.read().await["root_ca"];

        manager
            .load_state(old_copy.to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(
            manager
                .check_certificate_status(&a.serial_number)
                .await
                .unwrap(),
            CertificateStatus::Revoked,
            "an old copy must not un-revoke"
        );
        assert_eq!(manager.crl_numbers.read().await["root_ca"], number);
        assert_eq!(
            manager
                .check_certificate_status(&b.serial_number)
                .await
                .unwrap(),
            CertificateStatus::Valid
        );

        // And the other direction: a newer file adds what this manager lacks.
        let fresh = X509CertificateManager::new(manager.config.clone());
        fresh.initialize().await.unwrap(); // loads the state file
        fresh.load_state(old_copy.to_str().unwrap()).await.unwrap();
        assert_eq!(
            fresh
                .check_certificate_status(&a.serial_number)
                .await
                .unwrap(),
            CertificateStatus::Revoked
        );
    }

    #[tokio::test]
    async fn saving_state_leaves_no_temporary_file_and_survives_concurrent_writers() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let (manager, _, _, _) = two_level_manager(dir.path(), Some(&state)).await;
        let mut tasks = Vec::new();
        for i in 0..12 {
            let manager = manager.clone();
            tasks.push(tokio::spawn(async move {
                manager
                    .sign_certificate_request(
                        &request(&format!("c{i}"), &new_key(), "tls_client"),
                        "root_ca",
                    )
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let text = std::fs::read_to_string(&state).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("complete JSON");
        assert_eq!(parsed["certificates"].as_object().unwrap().len(), 12);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[tokio::test]
    async fn ip_names_that_wrap_or_hide_special_addresses_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) =
            manager_with_profiles(dir.path(), vec![("open", open_profile("open"))]).await;
        for ip in [
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "ff02::1",
        ] {
            let mut r = request("host", &new_key(), "open");
            r.subject_alt_names = vec![SubjectAltName::IpAddress(ip.to_string())];
            assert_refused(&manager, &r, ip).await;
        }
        let mut ok = request("host", &new_key(), "open");
        ok.subject_alt_names = vec![
            SubjectAltName::IpAddress("192.0.2.7".to_string()),
            SubjectAltName::IpAddress("2001:db8::7".to_string()),
        ];
        manager
            .sign_certificate_request(&ok, "root_ca")
            .await
            .unwrap();
    }

    /// SubjectPublicKeyInfo PEM from raw parts.
    fn spki_pem(algorithm_oid: &[u8], parameters: Option<&[u8]>, key: &[u8]) -> String {
        fn der(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match content.len() {
                n if n < 128 => out.push(n as u8),
                n if n < 256 => out.extend([0x81, n as u8]),
                n if n < 65536 => out.extend([0x82, (n >> 8) as u8, n as u8]),
                n => out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
            }
            out.extend(content);
            out
        }
        let mut algorithm = der(0x06, algorithm_oid);
        if let Some(parameters) = parameters {
            algorithm.extend(parameters);
        }
        let mut bits = vec![0u8];
        bits.extend(key);
        let spki = der(0x30, &[der(0x30, &algorithm), der(0x03, &bits)].concat());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64_STANDARD.encode(spki)
        )
    }

    fn rsa_pem_parts(modulus: &[u8], exponent: &[u8]) -> String {
        fn int(bytes: &[u8]) -> Vec<u8> {
            // Minimal DER: a leading zero only when the top bit would make it negative.
            let mut content = Vec::new();
            if bytes.first().is_some_and(|b| *b >= 0x80) {
                content.push(0);
            }
            content.extend(bytes);
            let mut out = vec![0x02];
            let n = content.len();
            match n {
                n if n < 128 => out.push(n as u8),
                n if n < 256 => out.extend([0x81, n as u8]),
                n => out.extend([0x82, (n >> 8) as u8, n as u8]),
            }
            out.extend(content);
            out
        }
        let body = [int(modulus), int(exponent)].concat();
        let mut key = vec![0x30];
        match body.len() {
            n if n < 128 => key.push(n as u8),
            n if n < 256 => key.extend([0x81, n as u8]),
            n => key.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        key.extend(body);
        spki_pem(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            Some(&[0x05, 0x00]),
            &key,
        )
    }

    #[tokio::test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "the cases are built up in groups, with setup between"
    )]
    async fn malformed_or_unusable_subject_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) = manager_with_profiles(dir.path(), vec![]).await;
        let odd_modulus = |bytes: usize| {
            let mut m = vec![0xC5u8; bytes];
            *m.last_mut().unwrap() |= 1;
            m
        };
        let mut cases: Vec<(&str, String)> = Vec::new();

        // RSA: exponent and modulus.
        cases.push(("exponent 1", rsa_pem_parts(&odd_modulus(256), &[1])));
        cases.push(("exponent 3", rsa_pem_parts(&odd_modulus(256), &[3])));
        cases.push((
            "even exponent",
            rsa_pem_parts(&odd_modulus(256), &[1, 0, 2]),
        ));
        cases.push(("zero exponent", rsa_pem_parts(&odd_modulus(256), &[0])));
        let mut even = odd_modulus(256);
        *even.last_mut().unwrap() &= !1;
        cases.push(("even modulus", rsa_pem_parts(&even, &[1, 0, 1])));
        cases.push((
            "32768-bit modulus",
            rsa_pem_parts(&odd_modulus(4096), &[1, 0, 1]),
        ));
        cases.push((
            "1024-bit modulus",
            rsa_pem_parts(&odd_modulus(128), &[1, 0, 1]),
        ));

        // Ed25519: wrong length, parameters present.
        let ed_oid = [0x2b, 0x65, 0x70];
        cases.push(("1-byte Ed25519", spki_pem(&ed_oid, None, &[7])));
        cases.push(("33-byte Ed25519", spki_pem(&ed_oid, None, &[7u8; 33])));
        cases.push((
            "Ed25519 with parameters",
            spki_pem(&ed_oid, Some(&[0x05, 0x00]), &[7u8; 32]),
        ));

        // EC: a real key with its point damaged, a compressed prefix, a wrong size.
        let real = new_key();
        let raw = real.public_key_raw().to_vec();
        let p256_oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let p256_params = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut off_curve = raw.clone();
        *off_curve.last_mut().unwrap() ^= 0x01;
        cases.push((
            "point not on the curve",
            spki_pem(&p256_oid, Some(&p256_params), &off_curve),
        ));
        let mut compressed = raw.clone();
        compressed[0] = 0x02;
        cases.push((
            "compressed prefix",
            spki_pem(&p256_oid, Some(&p256_params), &compressed),
        ));
        cases.push((
            "short point",
            spki_pem(&p256_oid, Some(&p256_params), &raw[..40]),
        ));
        let all_zero = {
            let mut z = vec![0u8; 65];
            z[0] = 4;
            z
        };
        cases.push((
            "zero point",
            spki_pem(&p256_oid, Some(&p256_params), &all_zero),
        ));

        for (why, pem) in cases {
            let mut r = request("k", &real, "tls_client");
            r.public_key_pem = pem;
            assert_refused(&manager, &r, why).await;
        }
        // Positive controls: the same hand-built shapes, well-formed, are accepted (so the
        // refusals above are about the damage and not about the builder).
        let mut sound_rsa = request("k", &real, "tls_client");
        sound_rsa.public_key_pem = rsa_pem_parts(&odd_modulus(256), &[1, 0, 1]);
        manager
            .sign_certificate_request(&sound_rsa, "root_ca")
            .await
            .expect("a sound hand-built RSA key is accepted");
        let mut sound_ed = request("k", &real, "tls_client");
        sound_ed.public_key_pem = spki_pem(&ed_oid, None, &[7u8; 32]);
        manager
            .sign_certificate_request(&sound_ed, "root_ca")
            .await
            .expect("a sound hand-built Ed25519 key is accepted");
        // The undamaged key is fine.
        manager
            .sign_certificate_request(&request("k", &real, "tls_client"), "root_ca")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn uris_formatting_characters_and_request_ids_are_policed() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _) =
            manager_with_profiles(dir.path(), vec![("open", open_profile("open"))]).await;
        for uri in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://host.example/x",
            "data:text/plain,hi",
            "ldap://host.example",
        ] {
            let mut r = request("u", &new_key(), "open");
            r.subject_alt_names = vec![SubjectAltName::Uri(uri.to_string())];
            assert_refused(&manager, &r, uri).await;
        }
        for uri in [
            "https://svc.example/id",
            "HTTP://svc.example/id",
            "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66",
            "spiffe://example.org/ns/a",
        ] {
            let mut r = request("u", &new_key(), "open");
            r.subject_alt_names = vec![SubjectAltName::Uri(uri.to_string())];
            manager
                .sign_certificate_request(&r, "root_ca")
                .await
                .unwrap_or_else(|e| panic!("{uri}: {e}"));
        }
        for (why, text) in [
            ("right-to-left override", "bank\u{202e}moc.evil"),
            ("zero-width space", "pay\u{200b}pal"),
            ("byte-order mark", "\u{feff}admin"),
            ("isolate", "a\u{2066}b"),
        ] {
            let mut r = request("f", &new_key(), "tls_client");
            r.subject.common_name = text.to_string();
            assert_refused(&manager, &r, why).await;
        }
        let mut r = request("id", &new_key(), "tls_client");
        r.request_id = "x".repeat(129);
        assert_refused(&manager, &r, "long request id").await;
        r.request_id = "bad\nid".to_string();
        assert_refused(&manager, &r, "control character in request id").await;
    }

    #[tokio::test]
    async fn a_root_is_valid_as_itself_only_for_the_purposes_it_allows() {
        let dir = tempfile::tempdir().unwrap();
        let unrestricted = TestCa::root("Any Purpose Root");
        let manager = manager_with(dir.path(), &unrestricted, true).await;
        for purpose in [
            CertificatePurpose::ServerAuth,
            CertificatePurpose::CodeSigning,
        ] {
            assert!(
                manager
                    .validate_certificate_chain(&unrestricted.cert_pem, purpose)
                    .await
                    .unwrap(),
                "{purpose:?}"
            );
        }

        let dir2 = tempfile::tempdir().unwrap();
        let mut params = ca_params("Signing Only Root");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let restricted = TestCa::root_with(params);
        let manager = manager_with(dir2.path(), &restricted, true).await;
        assert!(
            manager
                .validate_certificate_chain(&restricted.cert_pem, CertificatePurpose::CodeSigning)
                .await
                .unwrap()
        );
        assert!(
            !manager
                .validate_certificate_chain(&restricted.cert_pem, CertificatePurpose::ServerAuth)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn contradictory_profiles_and_orphan_key_paths_stop_initialize() {
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Config");
        let (cert, key) = root.write(dir.path(), "root");

        // A TLS server profile without serverAuth.
        let mut config = config_for(&cert, &key);
        let mut profile = open_profile("bad");
        profile.cert_type = CertificateType::TlsServer; // but lists clientAuth only
        config
            .certificate_profiles
            .insert("bad".to_string(), profile);
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        // An end-entity profile asking for keyCertSign (it would still be cA=FALSE).
        let mut config = config_for(&cert, &key);
        let mut profile = open_profile("signer");
        profile.key_usage = vec![KeyUsage::DigitalSignature, KeyUsage::KeyCertSign];
        config
            .certificate_profiles
            .insert("signer".to_string(), profile);
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        // A negative validity.
        let mut config = config_for(&cert, &key);
        let mut profile = open_profile("negative");
        profile.validity_days = -1;
        config
            .certificate_profiles
            .insert("negative".to_string(), profile);
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        // An intermediate key path with no intermediate certificate.
        let mut config = config_for(&cert, &key);
        config.intermediate_ca_key_path = Some("ca/inter.key".to_string());
        assert!(
            X509CertificateManager::new(config)
                .initialize()
                .await
                .is_err()
        );

        // The consistent configuration is fine.
        X509CertificateManager::new(config_for(&cert, &key))
            .initialize()
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_state_location_stops_initialize_instead_of_starting_empty() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = TestCa::root("Perm");
        let (cert, key) = root.write(dir.path(), "root");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("state.json"), "{}").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = std::fs::metadata(locked.join("state.json")).is_ok(); // running as root
        let mut config = config_for(&cert, &key);
        config.state_path = Some(locked.join("state.json").to_string_lossy().to_string());
        let outcome = X509CertificateManager::new(config).initialize().await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !readable_anyway {
            assert!(
                outcome.is_err(),
                "a permission error must not read as \"no state yet\""
            );
        }
    }
}
