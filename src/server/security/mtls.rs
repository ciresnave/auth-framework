//! OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (RFC 8705)
//!
//! This module implements RFC 8705, which defines:
//! 1. Mutual TLS client authentication methods
//! 2. Certificate-bound access tokens for enhanced security
//! 3. X.509 certificate validation and processing

use crate::errors::{AuthError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

/// Mutual TLS authentication methods
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutualTlsMethod {
    /// PKI Mutual TLS - certificate validation against CA
    PkiMutualTls,

    /// Self-signed certificate authentication
    SelfSignedTlsClientAuth,
}

/// X.509 Certificate information for OAuth 2.0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509CertificateInfo {
    /// Certificate fingerprint (SHA-256)
    pub thumbprint: String,

    /// Certificate subject Distinguished Name
    pub subject_dn: String,

    /// Certificate issuer Distinguished Name
    pub issuer_dn: String,

    /// Certificate serial number
    pub serial_number: String,

    /// Certificate validity period
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,

    /// Subject Alternative Names
    pub san_dns: Vec<String>,
    pub san_uri: Vec<String>,
    pub san_email: Vec<String>,
}

/// Certificate-bound access token confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfirmation {
    /// Certificate thumbprint (x5t#S256)
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

/// Mutual TLS client configuration
#[derive(Debug, Clone)]
pub struct MutualTlsClientConfig {
    /// Client identifier
    pub client_id: String,

    /// Authentication method
    pub auth_method: MutualTlsMethod,

    /// For PKI method: DER trust anchors for this client. When empty, the manager's CA store
    /// (see [`MutualTlsManager::add_ca_certificate`]) is used; at least one must exist.
    pub ca_certificates: Vec<Vec<u8>>,

    /// Registered certificate (DER). Self-signed method: its public key must match. PKI method:
    /// an exact pin; the presented certificate must be byte-identical (takes precedence over
    /// `expected_subject_dn`).
    pub client_certificate: Option<Vec<u8>>,

    /// Exact subject distinguished name the certificate must carry (compared case- and
    /// whitespace-insensitively after rendering as `CN=a, O=b`, as in
    /// [`X509CertificateInfo::subject_dn`]). A PKI client needs this or `client_certificate`.
    pub expected_subject_dn: Option<String>,

    /// Whether to bind access tokens to certificates
    pub certificate_bound_access_tokens: bool,
}

/// Mutual TLS authentication result
#[derive(Debug, Clone)]
pub struct MutualTlsAuthResult {
    /// Client identifier
    pub client_id: String,

    /// Certificate information
    pub certificate_info: X509CertificateInfo,

    /// Whether the certificate is valid
    pub is_valid: bool,

    /// Validation errors (if any)
    pub validation_errors: Vec<String>,
}

/// Mutual TLS manager for OAuth 2.0
#[derive(Debug)]
pub struct MutualTlsManager {
    /// Registered clients with mTLS configuration
    clients: tokio::sync::RwLock<HashMap<String, MutualTlsClientConfig>>,

    /// Trusted CA certificates for PKI validation
    ca_store: Vec<Vec<u8>>,
}

impl MutualTlsManager {
    /// Create a new Mutual TLS manager
    pub fn new() -> Self {
        Self {
            clients: tokio::sync::RwLock::new(HashMap::new()),
            ca_store: Vec::new(),
        }
    }

    /// Add a trusted CA certificate (DER).
    ///
    /// Trust anchors are used as given: an anchor's own `pathLen` is not enforced by the
    /// verifier, so constrain intermediates (not the anchor) with `pathLen`.
    ///
    /// The certificate must parse as a single X.509 certificate and assert
    /// `basicConstraints: cA = TRUE`. It becomes a trust anchor for every PKI client
    /// that does not carry its own `ca_certificates`.
    pub fn add_ca_certificate(&mut self, ca_cert: Vec<u8>) -> Result<()> {
        ensure_ca_certificate(&ca_cert)?;
        self.ca_store.push(ca_cert);
        Ok(())
    }

    /// Register a client for Mutual TLS authentication.
    ///
    /// A `PkiMutualTls` client must be bound to its certificate: set `client_certificate`
    /// (exact certificate pin) or `expected_subject_dn` (exact subject DN), otherwise any
    /// certificate issued by a trusted CA would authenticate as this client.
    pub async fn register_client(&self, config: MutualTlsClientConfig) -> Result<()> {
        self.validate_client_config(&config)?;

        let mut clients = self.clients.write().await;
        clients.insert(config.client_id.clone(), config);

        Ok(())
    }

    /// Authenticate a client using Mutual TLS.
    ///
    /// # Security: where the certificate bytes come from
    ///
    /// This validates a certificate; it cannot tell whether the peer holds its private key.
    /// Pass only the certificate that your TLS acceptor verified the client's possession of
    /// (the handshake's peer certificate), or one forwarded by a terminating proxy that strips
    /// any client-supplied copy of the header it uses. Never pass a certificate read from a
    /// request header or body that the client controls: a public certificate is not a secret.
    ///
    /// Equivalent to [`authenticate_client_with_chain`](Self::authenticate_client_with_chain)
    /// with no intermediate certificates.
    pub async fn authenticate_client(
        &self,
        client_id: &str,
        client_certificate: &[u8],
    ) -> Result<MutualTlsAuthResult> {
        self.authenticate_client_with_chain(client_id, client_certificate, &[])
            .await
    }

    /// Authenticate a client using Mutual TLS, with the intermediate certificates the
    /// client presented in the TLS handshake (DER, any order).
    ///
    /// For `PkiMutualTls` the chain is built and verified by `rustls-webpki` (signatures,
    /// validity of every certificate, basicConstraints and pathLen, name constraints,
    /// `clientAuth` extended key usage), the trust anchors are the client's own
    /// `ca_certificates` when set and the manager's CA store otherwise (never empty), and the
    /// certificate must be bound to the client (see [`register_client`](Self::register_client)).
    pub async fn authenticate_client_with_chain(
        &self,
        client_id: &str,
        client_certificate: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<MutualTlsAuthResult> {
        let clients = self.clients.read().await;
        let client_config = clients
            .get(client_id)
            .ok_or_else(|| AuthError::auth_method("mtls", "Client not registered for mTLS"))?;

        // Parse the client certificate (exactly one certificate, no trailing data)
        let cert = parse_single_certificate(client_certificate)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid client certificate format"))?;

        // Extract certificate information
        let cert_info = self.extract_certificate_info(&cert, client_certificate)?;

        // Validate based on authentication method
        let (is_valid, validation_errors) = match client_config.auth_method {
            MutualTlsMethod::PkiMutualTls => self.validate_pki_certificate(
                &cert,
                client_certificate,
                intermediates,
                client_config,
            ),
            MutualTlsMethod::SelfSignedTlsClientAuth => {
                self.validate_self_signed_certificate(&cert, client_config)
            }
        };

        Ok(MutualTlsAuthResult {
            client_id: client_id.to_string(),
            certificate_info: cert_info,
            is_valid,
            validation_errors,
        })
    }

    /// Create certificate-bound access token confirmation
    pub fn create_certificate_confirmation(
        &self,
        client_certificate: &[u8],
    ) -> Result<CertificateConfirmation> {
        let thumbprint = self.calculate_certificate_thumbprint(client_certificate)?;

        Ok(CertificateConfirmation {
            x5t_s256: thumbprint,
        })
    }

    /// Validate certificate-bound access token
    pub fn validate_certificate_bound_token(
        &self,
        token_confirmation: &CertificateConfirmation,
        client_certificate: &[u8],
    ) -> Result<bool> {
        let current_thumbprint = self.calculate_certificate_thumbprint(client_certificate)?;

        Ok(token_confirmation.x5t_s256 == current_thumbprint)
    }

    /// Validate a client certificate for mTLS authentication, returning an error unless
    /// the certificate authenticates `client_id`.
    ///
    /// The same rule applies as for [`authenticate_client`](Self::authenticate_client): the
    /// bytes must come from the TLS handshake (or a proxy that strips client-supplied copies),
    /// never from data the client chose.
    ///
    /// Uses the same validation as [`authenticate_client`](Self::authenticate_client).
    pub async fn validate_client_certificate(
        &self,
        client_certificate: &[u8],
        client_id: &str,
    ) -> Result<()> {
        self.validate_client_certificate_with_chain(client_certificate, &[], client_id)
            .await
    }

    /// Like [`validate_client_certificate`](Self::validate_client_certificate), with the
    /// intermediate certificates presented by the client.
    pub async fn validate_client_certificate_with_chain(
        &self,
        client_certificate: &[u8],
        intermediates: &[Vec<u8>],
        client_id: &str,
    ) -> Result<()> {
        let result = self
            .authenticate_client_with_chain(client_id, client_certificate, intermediates)
            .await?;
        if result.is_valid {
            Ok(())
        } else {
            Err(AuthError::auth_method(
                "mtls",
                format!(
                    "Client certificate rejected: {}",
                    result.validation_errors.join("; ")
                ),
            ))
        }
    }

    /// Extract certificate information from X.509 certificate
    fn extract_certificate_info(
        &self,
        cert: &X509Certificate,
        cert_der: &[u8],
    ) -> Result<X509CertificateInfo> {
        // Calculate SHA-256 thumbprint
        let thumbprint = self.calculate_certificate_thumbprint(cert_der)?;

        // Extract subject and issuer DN
        let subject_dn = cert.subject().to_string();
        let issuer_dn = cert.issuer().to_string();

        // Extract serial number
        let serial_number = hex::encode(cert.serial.to_bytes_be());

        // Extract validity period
        let not_before =
            chrono::DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
                .unwrap_or_default();
        let not_after = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_default();

        // Extract Subject Alternative Names
        let mut san_dns = Vec::new();
        let mut san_uri = Vec::new();
        let mut san_email = Vec::new();

        // Parse Subject Alternative Names using current x509-parser API
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        san_dns.push(dns.to_string());
                    }
                    x509_parser::extensions::GeneralName::URI(uri) => {
                        san_uri.push(uri.to_string());
                    }
                    x509_parser::extensions::GeneralName::RFC822Name(email) => {
                        san_email.push(email.to_string());
                    }
                    x509_parser::extensions::GeneralName::IPAddress(ip) => {
                        // Optionally handle IP addresses as well
                        if ip.len() == 4 {
                            // IPv4
                            let ip_addr = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                            san_dns.push(ip_addr); // Add to DNS list for simplicity
                        } else if ip.len() == 16 {
                            // IPv6 - basic formatting
                            let ip_addr = format!(
                                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                ip[0],
                                ip[1],
                                ip[2],
                                ip[3],
                                ip[4],
                                ip[5],
                                ip[6],
                                ip[7],
                                ip[8],
                                ip[9],
                                ip[10],
                                ip[11],
                                ip[12],
                                ip[13],
                                ip[14],
                                ip[15]
                            );
                            san_dns.push(ip_addr);
                        }
                    }
                    _ => {
                        // Ignore other name types for now
                    }
                }
            }
        }

        Ok(X509CertificateInfo {
            thumbprint,
            subject_dn,
            issuer_dn,
            serial_number,
            not_before,
            not_after,
            san_dns,
            san_uri,
            san_email,
        })
    }

    /// Calculate SHA-256 thumbprint of certificate
    fn calculate_certificate_thumbprint(&self, cert_der: &[u8]) -> Result<String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();

        Ok(URL_SAFE_NO_PAD.encode(hash))
    }

    /// Validate a PKI certificate: verified chain to a trusted anchor, then identity binding.
    fn validate_pki_certificate(
        &self,
        cert: &X509Certificate<'_>,
        cert_der: &[u8],
        intermediates: &[Vec<u8>],
        client_config: &MutualTlsClientConfig,
    ) -> (bool, Vec<String>) {
        let mut errors = Vec::new();

        // Trust anchors: the client's own CA list when set, otherwise the manager's store.
        let anchors: &[Vec<u8>] = if client_config.ca_certificates.is_empty() {
            &self.ca_store
        } else {
            &client_config.ca_certificates
        };

        if let Err(e) = verify_certificate_chain(cert_der, intermediates, anchors) {
            errors.push(e);
        }

        // keyUsage (webpki does not look at it): when present it must allow digital signatures
        // (TLS client authentication); a malformed extension is a rejection, never a pass.
        match cert.key_usage() {
            Ok(None) => {}
            Ok(Some(key_usage)) if key_usage.value.digital_signature() => {}
            Ok(Some(_)) => errors.push("Certificate does not allow digital signatures".to_string()),
            Err(_) => errors.push("Certificate has a malformed keyUsage extension".to_string()),
        }

        // The certificate must belong to THIS client, not merely to some client of the CA.
        if let Err(e) = check_identity_binding(cert, cert_der, client_config) {
            errors.push(e);
        }

        (errors.is_empty(), errors)
    }

    /// Validate self-signed certificate
    fn validate_self_signed_certificate(
        &self,
        cert: &X509Certificate<'_>,
        client_config: &MutualTlsClientConfig,
    ) -> (bool, Vec<String>) {
        let mut errors = Vec::new();

        // Check certificate validity period
        let now = chrono::Utc::now().timestamp();
        if cert.validity().not_before.timestamp() > now {
            errors.push("Certificate is not yet valid".to_string());
        }
        if cert.validity().not_after.timestamp() < now {
            errors.push("Certificate has expired".to_string());
        }

        // For self-signed, check if it matches the registered certificate
        if let Some(registered_cert_der) = &client_config.client_certificate {
            if let Ok((_, registered_cert)) = parse_x509_certificate(registered_cert_der) {
                // Compare public keys
                if cert.public_key().raw != registered_cert.public_key().raw {
                    errors.push("Certificate does not match registered certificate".to_string());
                }
            } else {
                errors.push("Invalid registered certificate".to_string());
            }
        } else {
            errors.push("No registered certificate for self-signed authentication".to_string());
        }

        // Check subject DN if specified (structural, exact match)
        if let Some(expected_subject) = &client_config.expected_subject_dn {
            match subject_matches(cert, expected_subject) {
                Ok(true) => {}
                Ok(false) => errors.push(format!(
                    "Subject DN does not match the registered subject: {expected_subject}"
                )),
                Err(e) => errors.push(e),
            }
        }

        (errors.is_empty(), errors)
    }

    /// Validate client configuration
    fn validate_client_config(&self, config: &MutualTlsClientConfig) -> Result<()> {
        // A registered DN must parse as RFC 4514 and be non-empty, for every method: an
        // unparsable or empty value must never end up meaning "matches anything".
        if let Some(dn) = &config.expected_subject_dn {
            parse_rfc4514(dn).map_err(|e| AuthError::auth_method("mtls", e))?;
        }
        if let Some(pin) = &config.client_certificate
            && pin.is_empty()
        {
            return Err(AuthError::auth_method(
                "mtls",
                "client_certificate must not be empty",
            ));
        }

        match config.auth_method {
            MutualTlsMethod::PkiMutualTls => {
                if config.ca_certificates.is_empty() && self.ca_store.is_empty() {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "PKI authentication requires CA certificates",
                    ));
                }
                for ca in &config.ca_certificates {
                    ensure_ca_certificate(ca)?;
                }
                if config.client_certificate.is_none() && config.expected_subject_dn.is_none() {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "PKI authentication requires binding the client to its certificate: \
                         set client_certificate (pin) or expected_subject_dn",
                    ));
                }
                if let Some(pin) = &config.client_certificate
                    && parse_single_certificate(pin).is_err()
                {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "client_certificate must be a single DER certificate",
                    ));
                }
            }
            MutualTlsMethod::SelfSignedTlsClientAuth => {
                if config.client_certificate.is_none() {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "Self-signed authentication requires registered client certificate",
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Parse exactly one DER certificate; trailing bytes are rejected.
fn parse_single_certificate(der: &[u8]) -> std::result::Result<X509Certificate<'_>, ()> {
    match parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(()),
    }
}

/// Require a parseable certificate that asserts `basicConstraints: cA = TRUE`.
fn ensure_ca_certificate(ca_der: &[u8]) -> Result<()> {
    let cert = parse_single_certificate(ca_der)
        .map_err(|_| AuthError::auth_method("mtls", "Invalid CA certificate format"))?;

    if !cert
        .basic_constraints()
        .map(|bc| bc.map(|b| b.value.ca).unwrap_or(false))
        .unwrap_or(false)
    {
        return Err(AuthError::auth_method(
            "mtls",
            "Certificate is not a CA certificate",
        ));
    }

    // It must also be usable as a trust anchor by the verifier: one anchor webpki cannot parse
    // would otherwise make every authentication that uses this store fail at validation time.
    // (webpki does not enforce an anchor's own pathLen; set pathLen on intermediates instead.)
    let der = CertificateDer::from(ca_der);
    anchor_from_trusted_cert(&der).map_err(|e| {
        AuthError::auth_method(
            "mtls",
            format!("CA certificate is not a usable trust anchor: {e}"),
        )
    })?;
    Ok(())
}

/// Build and verify the certification path of a TLS client certificate with `rustls-webpki`
/// (ring backend): signature algorithms RSA PKCS#1/PSS, ECDSA P-256/P-384 and Ed25519,
/// validity of every certificate on the path (the anchors included), basicConstraints and
/// pathLen, name constraints and the `clientAuth` extended key usage. The result is
/// fail-closed: an empty anchor list is an error, never a pass.
fn verify_certificate_chain(
    leaf_der: &[u8],
    intermediates_der: &[Vec<u8>],
    anchors_der: &[Vec<u8>],
) -> std::result::Result<(), String> {
    if anchors_der.is_empty() {
        return Err("No trusted CA certificates configured".to_string());
    }

    // webpki checks the validity period of every certificate on the path EXCEPT the trust
    // anchor (an anchor is just a name, a key and constraints to it), so an expired CA would
    // stay trusted forever. Drop anchors that are not valid right now.
    let now = chrono::Utc::now().timestamp();
    let current_anchors: Vec<&Vec<u8>> = anchors_der
        .iter()
        .filter(|der| {
            parse_x509_certificate(der)
                .map(|(_, ca)| {
                    ca.validity().not_before.timestamp() <= now
                        && now <= ca.validity().not_after.timestamp()
                })
                .unwrap_or(false)
        })
        .collect();
    if current_anchors.is_empty() {
        return Err(
            "No currently valid trusted CA certificate (expired or not yet valid)".to_string(),
        );
    }

    let leaf = CertificateDer::from(leaf_der);
    let end_entity =
        EndEntityCert::try_from(&leaf).map_err(|e| format!("Invalid client certificate: {e}"))?;

    let anchor_ders: Vec<CertificateDer<'_>> = current_anchors
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let anchors = anchor_ders
        .iter()
        .map(|der| {
            anchor_from_trusted_cert(der)
                .map_err(|e| format!("Invalid trusted CA certificate: {e}"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let intermediates: Vec<CertificateDer<'_>> = intermediates_der
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::now(),
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| format!("Certificate chain validation failed: {e}"))
}

/// A distinguished name as structure: RDNs in certificate (DER) order, each RDN a sorted list of
/// `(attribute OID, value)`.
type RdnList = Vec<Vec<(String, String)>>;

/// OID of an RFC 4514 attribute keyword (or a dotted OID, passed through).
fn attribute_oid(name: &str) -> Option<String> {
    let upper = name.to_ascii_uppercase();
    let oid = match upper.as_str() {
        "CN" => "2.5.4.3",
        "SN" => "2.5.4.4",
        "SERIALNUMBER" => "2.5.4.5",
        "C" => "2.5.4.6",
        "L" => "2.5.4.7",
        "ST" => "2.5.4.8",
        "STREET" => "2.5.4.9",
        "O" => "2.5.4.10",
        "OU" => "2.5.4.11",
        "T" | "TITLE" => "2.5.4.12",
        "GN" => "2.5.4.42",
        "DC" => "0.9.2342.19200300.100.1.25",
        "UID" => "0.9.2342.19200300.100.1.1",
        "EMAILADDRESS" => "1.2.840.113549.1.9.1",
        other => {
            let dotted = other.split('.').count() >= 2
                && other
                    .split('.')
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
            return dotted.then(|| other.to_string());
        }
    };
    Some(oid.to_string())
}

/// Parse an RFC 4514 distinguished-name string (`CN=Alice,O=Corp`, most specific RDN first,
/// `\,` `\+` `\"` `\\` `\<` `\>` `\;` `\=` `\ ` `\#` and `\XX` hex escapes, `+` joins attributes
/// of one RDN) into structure, returned in certificate (DER) order. Anything it cannot parse
/// exactly is an error; there is no lenient mode.
fn parse_rfc4514(dn: &str) -> std::result::Result<RdnList, String> {
    let shown: String = dn.chars().take(80).collect();
    let suffix = if dn.chars().count() > 80 {
        format!("... ({} chars)", dn.chars().count())
    } else {
        String::new()
    };
    let bad = |why: &str| format!("Invalid distinguished name '{shown}{suffix}': {why}");
    if dn.trim().is_empty() {
        return Err(bad("empty"));
    }
    let chars: Vec<char> = dn.chars().collect();
    let mut i = 0;
    let mut rdns: RdnList = Vec::new();
    let mut rdn: Vec<(String, String)> = Vec::new();

    loop {
        while i < chars.len() && chars[i] == ' ' {
            i += 1;
        }
        let start = i;
        while i < chars.len() && chars[i] != '=' {
            if matches!(chars[i], ',' | '+' | '\\' | '"') {
                return Err(bad("attribute type expected before '='"));
            }
            i += 1;
        }
        if i >= chars.len() {
            return Err(bad("missing '='"));
        }
        let keyword: String = chars[start..i].iter().collect();
        let oid = attribute_oid(&keyword)
            .ok_or_else(|| bad(&format!("unknown attribute type '{}'", keyword.trim())))?;
        i += 1; // '='

        let mut value: Vec<u8> = Vec::new();
        let mut leading = true;
        let mut trailing_spaces = 0usize;
        while i < chars.len() {
            match chars[i] {
                ',' | '+' => break,
                '"' | '<' | '>' | ';' => return Err(bad("unescaped special character in value")),
                '\\' => {
                    i += 1;
                    let next = *chars.get(i).ok_or_else(|| bad("dangling backslash"))?;
                    if next.is_ascii_hexdigit() {
                        let second = *chars.get(i + 1).ok_or_else(|| bad("bad hex escape"))?;
                        if !second.is_ascii_hexdigit() {
                            return Err(bad("bad hex escape"));
                        }
                        let byte = u8::from_str_radix(&format!("{next}{second}"), 16)
                            .map_err(|_| bad("bad hex escape"))?;
                        value.push(byte);
                        i += 2;
                    } else if matches!(
                        next,
                        ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' | ' ' | '#'
                    ) {
                        let mut buf = [0u8; 4];
                        value.extend_from_slice(next.encode_utf8(&mut buf).as_bytes());
                        i += 1;
                    } else {
                        return Err(bad("invalid escape"));
                    }
                    leading = false;
                    trailing_spaces = 0;
                }
                ' ' if leading => {
                    return Err(bad(
                        "unescaped leading space in a value; escape edge spaces as '\\ '",
                    ));
                }
                ' ' => {
                    value.push(b' ');
                    trailing_spaces += 1;
                    i += 1;
                }
                '#' if leading => return Err(bad("hex-string values are not supported")),
                c => {
                    let mut buf = [0u8; 4];
                    value.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    leading = false;
                    trailing_spaces = 0;
                    i += 1;
                }
            }
        }
        if trailing_spaces > 0 {
            return Err(bad(
                "unescaped trailing space in a value; escape edge spaces as '\\ '",
            ));
        }
        let value = String::from_utf8(value).map_err(|_| bad("value is not valid UTF-8"))?;
        if value.is_empty() {
            return Err(bad("empty attribute value"));
        }
        rdn.push((oid, value));

        if i < chars.len() && chars[i] == '+' {
            i += 1;
            continue;
        }
        rdn.sort();
        rdns.push(std::mem::take(&mut rdn));
        if i >= chars.len() {
            break;
        }
        i += 1; // ','
    }
    rdns.reverse(); // RFC 4514 lists the most specific RDN first; certificates store it last
    Ok(rdns)
}

/// The subject of a certificate as structure (see [`RdnList`]). An attribute whose value
/// x509-parser cannot read as a string (BMPString, T61String, binary values) makes the subject
/// unmatchable: it is refused (fail closed), never skipped or guessed at.
fn subject_rdns(cert: &X509Certificate<'_>) -> std::result::Result<RdnList, String> {
    cert.subject()
        .iter_rdn()
        .map(|rdn| {
            let mut attrs = rdn
                .iter()
                .map(|attr| {
                    attr.as_str()
                        .map(|v| (attr.attr_type().to_id_string(), v.to_string()))
                        .map_err(|_| "Certificate subject has a non-string attribute".to_string())
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            attrs.sort();
            Ok(attrs)
        })
        .collect()
}

/// Does the certificate subject equal the RFC 4514 string `expected`? Compared as structure:
/// the same RDNs in the same order, attribute types by OID, attribute values EXACTLY (case-
/// and whitespace-sensitive), so one CN containing ", O=Corp" never equals the two attributes
/// CN and O. Rendering the subject to text and comparing text would conflate those.
fn subject_matches(
    cert: &X509Certificate<'_>,
    expected: &str,
) -> std::result::Result<bool, String> {
    Ok(subject_rdns(cert)? == parse_rfc4514(expected)?)
}

/// A certificate that chains to a trusted CA only proves the CA issued it; this ties it to the
/// registered client: exact pin if `client_certificate` is set, else the exact subject DN
/// (compared as structure, see [`subject_matches`]).
fn check_identity_binding(
    cert: &X509Certificate<'_>,
    cert_der: &[u8],
    client_config: &MutualTlsClientConfig,
) -> std::result::Result<(), String> {
    if let Some(pinned) = &client_config.client_certificate {
        return if pinned.as_slice() == cert_der {
            Ok(())
        } else {
            Err("Client certificate does not match the registered certificate".to_string())
        };
    }
    if let Some(expected) = &client_config.expected_subject_dn {
        return if subject_matches(cert, expected)? {
            Ok(())
        } else {
            Err(format!(
                "Certificate subject does not match the registered subject: {expected}"
            ))
        };
    }
    Err(
        "Client has no certificate binding configured (client_certificate or expected_subject_dn)"
            .to_string(),
    )
}

impl Default for MutualTlsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_client_config() -> MutualTlsClientConfig {
        MutualTlsClientConfig {
            client_id: "test_client".to_string(),
            auth_method: MutualTlsMethod::SelfSignedTlsClientAuth,
            ca_certificates: Vec::new(),
            client_certificate: Some(b"dummy_cert".to_vec()), // Would be real cert in practice
            expected_subject_dn: Some("CN=test_client".to_string()),
            certificate_bound_access_tokens: true,
        }
    }

    #[tokio::test]
    async fn test_mtls_manager_creation() {
        let manager = MutualTlsManager::new();
        assert!(manager.ca_store.is_empty());
    }

    #[tokio::test]
    async fn test_client_registration() {
        let manager = MutualTlsManager::new();
        let config = create_test_client_config();
        manager.register_client(config).await.unwrap();
    }

    #[test]
    fn test_certificate_confirmation() {
        let manager = MutualTlsManager::new();

        // Test with dummy certificate data
        let cert_data = b"dummy_certificate_data";
        let confirmation = manager.create_certificate_confirmation(cert_data).unwrap();

        assert!(!confirmation.x5t_s256.is_empty());

        // Validate the same certificate
        let is_valid = manager
            .validate_certificate_bound_token(&confirmation, cert_data)
            .unwrap();
        assert!(is_valid);

        // Validate different certificate (should fail)
        let different_cert = b"different_certificate_data";
        let is_valid = manager
            .validate_certificate_bound_token(&confirmation, different_cert)
            .unwrap();
        assert!(!is_valid);
    }

    // ---- Certificate validation tests built on real rcgen certificate chains ----

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
        date_time_ymd,
    };

    type TestIssuer = Issuer<'static, KeyPair>;

    fn dn(cn: &str) -> DistinguishedName {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        d
    }

    fn ca_params(cn: &str, path_len: Option<u8>) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = dn(cn);
        p.is_ca = match path_len {
            Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
            None => IsCa::Ca(BasicConstraints::Unconstrained),
        };
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p
    }

    /// A self-signed root: (DER, issuer handle for signing children).
    fn new_root(cn: &str) -> (Vec<u8>, TestIssuer) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = ca_params(cn, None);
        let cert = params.clone().self_signed(&key).unwrap();
        (cert.der().to_vec(), Issuer::new(params, key))
    }

    /// An intermediate CA signed by `parent`: (DER, issuer handle).
    fn new_intermediate(
        cn: &str,
        path_len: Option<u8>,
        parent: &TestIssuer,
    ) -> (Vec<u8>, TestIssuer) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let params = ca_params(cn, path_len);
        let cert = params.clone().signed_by(&key, parent).unwrap();
        (cert.der().to_vec(), Issuer::new(params, key))
    }

    fn leaf_params(cn: &str) -> CertificateParams {
        let mut p = CertificateParams::new(vec![format!("{cn}.example.test")]).unwrap();
        p.distinguished_name = dn(cn);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p
    }

    fn issue_leaf(cn: &str, issuer: &TestIssuer) -> Vec<u8> {
        issue_leaf_with(leaf_params(cn), issuer)
    }

    fn issue_leaf_with(params: CertificateParams, issuer: &TestIssuer) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        params.signed_by(&key, issuer).unwrap().der().to_vec()
    }

    fn pki_client(
        client_id: &str,
        subject_dn: Option<&str>,
        pin: Option<&[u8]>,
    ) -> MutualTlsClientConfig {
        MutualTlsClientConfig {
            client_id: client_id.to_string(),
            auth_method: MutualTlsMethod::PkiMutualTls,
            ca_certificates: Vec::new(),
            client_certificate: pin.map(|p| p.to_vec()),
            expected_subject_dn: subject_dn.map(str::to_string),
            certificate_bound_access_tokens: false,
        }
    }

    /// A manager that trusts `root_der` and has `client_id` registered bound to `CN=<client_id>`.
    async fn manager_trusting(root_der: &[u8], client_ids: &[&str]) -> MutualTlsManager {
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root_der.to_vec()).unwrap();
        for id in client_ids {
            m.register_client(pki_client(id, Some(&format!("CN={id}")), None))
                .await
                .unwrap();
        }
        m
    }

    async fn accepted(
        m: &MutualTlsManager,
        client_id: &str,
        cert: &[u8],
        chain: &[Vec<u8>],
    ) -> bool {
        let auth = m
            .authenticate_client_with_chain(client_id, cert, chain)
            .await
            .unwrap();
        let validated = m
            .validate_client_certificate_with_chain(cert, chain, client_id)
            .await;
        // The two entry points share one validator and must never disagree.
        assert_eq!(
            auth.is_valid,
            validated.is_ok(),
            "{:?}",
            auth.validation_errors
        );
        auth.is_valid
    }

    #[tokio::test]
    async fn accepts_a_certificate_issued_by_the_trusted_ca() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf = issue_leaf("client-a", &issuer);
        assert!(accepted(&m, "client-a", &leaf, &[]).await);
    }

    #[tokio::test]
    async fn rejects_a_forged_certificate_with_the_trusted_issuer_dn() {
        // A certificate that merely carries the CA's issuer DN, signed by another key, must fail.
        let (root, _) = new_root("Trusted Root");
        let (_, attacker_ca) = new_root("Trusted Root"); // same DN, different key
        let m = manager_trusting(&root, &["client-a"]).await;
        let forged = issue_leaf("client-a", &attacker_ca);
        assert!(!accepted(&m, "client-a", &forged, &[]).await);
    }

    #[tokio::test]
    async fn rejects_a_self_signed_certificate_for_a_pki_client() {
        let (root, _) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let selfsigned = leaf_params("client-a")
            .self_signed(&key)
            .unwrap()
            .der()
            .to_vec();
        assert!(!accepted(&m, "client-a", &selfsigned, &[]).await);
    }

    #[tokio::test]
    async fn an_empty_trust_store_never_authenticates() {
        // With no trust anchor available nothing may authenticate.
        let m = MutualTlsManager::new();
        // Registration of a PKI client with no CA anywhere is refused...
        assert!(
            m.register_client(pki_client("client-a", Some("CN=client-a"), None))
                .await
                .is_err()
        );
        // ...and a store that is emptied of anchors cannot validate: a client that carries only
        // a per-client CA list validates against that list and nothing else.
        let (root, issuer) = new_root("Trusted Root");
        let mut cfg = pki_client("client-a", Some("CN=client-a"), None);
        cfg.ca_certificates = vec![root.clone()];
        m.register_client(cfg).await.unwrap();
        let good = issue_leaf("client-a", &issuer);
        assert!(accepted(&m, "client-a", &good, &[]).await);
        let (_, other_ca) = new_root("Other Root");
        let wrong_ca = issue_leaf("client-a", &other_ca);
        assert!(!accepted(&m, "client-a", &wrong_ca, &[]).await);
    }

    #[tokio::test]
    async fn rejects_a_certificate_presented_as_a_different_client() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a", "client-b"]).await;
        let leaf_a = issue_leaf("client-a", &issuer);
        assert!(accepted(&m, "client-a", &leaf_a, &[]).await);
        assert!(!accepted(&m, "client-b", &leaf_a, &[]).await);
    }

    #[tokio::test]
    async fn subject_dn_must_match_exactly_not_as_a_substring() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let evil = issue_leaf("client-a-evil", &issuer);
        assert!(!accepted(&m, "client-a", &evil, &[]).await);
    }

    #[tokio::test]
    async fn a_pinned_certificate_must_match_byte_for_byte() {
        let (root, issuer) = new_root("Trusted Root");
        let pinned = issue_leaf("client-a", &issuer);
        let other = issue_leaf("client-a", &issuer); // same subject, different key
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        m.register_client(pki_client("client-a", None, Some(&pinned)))
            .await
            .unwrap();
        assert!(accepted(&m, "client-a", &pinned, &[]).await);
        assert!(!accepted(&m, "client-a", &other, &[]).await);
    }

    #[tokio::test]
    async fn a_pki_client_without_a_binding_cannot_be_registered() {
        let (root, _) = new_root("Trusted Root");
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        assert!(
            m.register_client(pki_client("client-a", None, None))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_a_server_auth_only_certificate() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let mut p = leaf_params("client-a");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_only = issue_leaf_with(p, &issuer);
        assert!(!accepted(&m, "client-a", &server_only, &[]).await);
    }

    #[tokio::test]
    async fn a_ca_certificate_is_not_accepted_as_a_client_certificate() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let mut p = ca_params("client-a", None);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let ca_as_leaf = issue_leaf_with(p, &issuer);
        assert!(!accepted(&m, "client-a", &ca_as_leaf, &[]).await);
    }

    #[tokio::test]
    async fn a_non_ca_leaf_cannot_issue_client_certificates() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-x"]).await;
        // A legitimate end-entity certificate (CA:false) tries to act as a CA.
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_p = leaf_params("not-a-ca");
        let leaf_der = leaf_p
            .clone()
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .to_vec();
        let leaf_issuer = Issuer::new(leaf_p, leaf_key);
        let x = issue_leaf("client-x", &leaf_issuer);
        assert!(!accepted(&m, "client-x", &x, &[]).await);
        assert!(!accepted(&m, "client-x", &x, std::slice::from_ref(&leaf_der)).await);
    }

    #[tokio::test]
    async fn rejects_an_expired_ca() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = ca_params("Old Root", None);
        params.not_before = date_time_ymd(2019, 1, 1);
        params.not_after = date_time_ymd(2021, 1, 1);
        let root = params.clone().self_signed(&key).unwrap().der().to_vec();
        let issuer = Issuer::new(params, key);
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf = issue_leaf("client-a", &issuer); // leaf itself is valid now
        assert!(!accepted(&m, "client-a", &leaf, &[]).await);
    }

    #[tokio::test]
    async fn rejects_an_expired_client_certificate() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let mut p = leaf_params("client-a");
        p.not_before = date_time_ymd(2019, 1, 1);
        p.not_after = date_time_ymd(2021, 1, 1);
        let expired = issue_leaf_with(p, &issuer);
        assert!(!accepted(&m, "client-a", &expired, &[]).await);
    }

    #[tokio::test]
    async fn builds_a_chain_through_an_intermediate() {
        let (root, root_issuer) = new_root("Trusted Root");
        let (inter, inter_issuer) = new_intermediate("Intermediate", None, &root_issuer);
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf = issue_leaf("client-a", &inter_issuer);
        // Without the intermediate the path cannot be built.
        assert!(!accepted(&m, "client-a", &leaf, &[]).await);
        assert!(accepted(&m, "client-a", &leaf, std::slice::from_ref(&inter)).await);
    }

    #[tokio::test]
    async fn enforces_the_path_length_constraint() {
        let (root, root_issuer) = new_root("Trusted Root");
        // pathLen 0: this intermediate may only issue end-entity certificates.
        let (inter1, inter1_issuer) = new_intermediate("Intermediate 1", Some(0), &root_issuer);
        let (inter2, inter2_issuer) = new_intermediate("Intermediate 2", None, &inter1_issuer);
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf = issue_leaf("client-a", &inter2_issuer);
        assert!(!accepted(&m, "client-a", &leaf, &[inter1, inter2]).await);
    }

    #[tokio::test]
    async fn accepts_rsa_signed_chains() {
        let key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
        let params = ca_params("RSA Root", None);
        let root = params.clone().self_signed(&key).unwrap().der().to_vec();
        let issuer = Issuer::new(params, key);
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf_key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
        let leaf = leaf_params("client-a")
            .signed_by(&leaf_key, &issuer)
            .unwrap()
            .der()
            .to_vec();
        assert!(accepted(&m, "client-a", &leaf, &[]).await);
    }

    #[tokio::test]
    async fn rejects_malformed_and_trailing_data() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let leaf = issue_leaf("client-a", &issuer);
        assert!(
            m.authenticate_client("client-a", b"not a certificate")
                .await
                .is_err()
        );
        let mut padded = leaf.clone();
        padded.extend_from_slice(b"\x00\x00");
        assert!(m.authenticate_client("client-a", &padded).await.is_err());
        assert!(
            m.authenticate_client("unknown-client", &leaf)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn only_ca_certificates_are_accepted_as_trust_anchors() {
        let (root, issuer) = new_root("Trusted Root");
        let leaf = issue_leaf("client-a", &issuer);
        let mut m = MutualTlsManager::new();
        assert!(m.add_ca_certificate(leaf.clone()).is_err());
        assert!(m.add_ca_certificate(root).is_ok());
        let mut cfg = pki_client("client-a", Some("CN=client-a"), None);
        cfg.ca_certificates = vec![leaf];
        assert!(m.register_client(cfg).await.is_err());
    }

    #[tokio::test]
    async fn self_signed_client_auth_matches_the_registered_key() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = leaf_params("sc").self_signed(&key).unwrap().der().to_vec();
        let other_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let other = leaf_params("sc")
            .self_signed(&other_key)
            .unwrap()
            .der()
            .to_vec();

        let m = MutualTlsManager::new();
        m.register_client(MutualTlsClientConfig {
            client_id: "sc".to_string(),
            auth_method: MutualTlsMethod::SelfSignedTlsClientAuth,
            ca_certificates: Vec::new(),
            client_certificate: Some(cert.clone()),
            expected_subject_dn: Some("CN=sc".to_string()),
            certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();
        assert!(accepted(&m, "sc", &cert, &[]).await);
        assert!(!accepted(&m, "sc", &other, &[]).await);
    }

    // ---- distinguished-name binding is structural ----

    /// A leaf whose subject is exactly the given (type, value) RDNs, one attribute per RDN, in
    /// certificate order.
    fn leaf_with_subject(rdns: &[(DnType, &str)], issuer: &TestIssuer) -> Vec<u8> {
        let mut p = leaf_params("unused");
        let mut d = DistinguishedName::new();
        for (ty, value) in rdns {
            d.push(ty.clone(), *value);
        }
        p.distinguished_name = d;
        issue_leaf_with(p, issuer)
    }

    #[tokio::test]
    async fn one_cn_containing_a_comma_is_not_two_attributes() {
        // CN="Alice, O=Corp" (ONE attribute) renders like CN=Alice + O=Corp (TWO) as text, but
        // they are different subjects and must not be interchangeable.
        let (root, issuer) = new_root("Trusted Root");
        let single = leaf_with_subject(&[(DnType::CommonName, "Alice, O=Corp")], &issuer);
        let two = leaf_with_subject(
            &[
                (DnType::OrganizationName, "Corp"),
                (DnType::CommonName, "Alice"),
            ],
            &issuer,
        );

        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        // Registered for the two-attribute subject (RFC 4514: most specific RDN first).
        m.register_client(pki_client("a", Some("CN=Alice,O=Corp"), None))
            .await
            .unwrap();
        assert!(accepted(&m, "a", &two, &[]).await);
        assert!(!accepted(&m, "a", &single, &[]).await);

        // Registered for the single-attribute subject (the comma escaped).
        m.register_client(pki_client("b", Some(r"CN=Alice\, O=Corp"), None))
            .await
            .unwrap();
        assert!(accepted(&m, "b", &single, &[]).await);
        assert!(!accepted(&m, "b", &two, &[]).await);
    }

    #[tokio::test]
    async fn the_self_signed_path_compares_the_subject_as_structure_too() {
        let single = {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut p = leaf_params("x");
            let mut d = DistinguishedName::new();
            d.push(DnType::CommonName, "Alice, O=Corp");
            p.distinguished_name = d;
            p.self_signed(&key).unwrap().der().to_vec()
        };
        let m = MutualTlsManager::new();
        m.register_client(MutualTlsClientConfig {
            client_id: "sc".to_string(),
            auth_method: MutualTlsMethod::SelfSignedTlsClientAuth,
            ca_certificates: Vec::new(),
            client_certificate: Some(single.clone()),
            expected_subject_dn: Some("CN=Alice,O=Corp".to_string()), // two attributes
            certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();
        // Same key as the registered certificate, but the subject is a different structure.
        assert!(!accepted(&m, "sc", &single, &[]).await);
    }

    #[tokio::test]
    async fn attribute_values_are_compared_exactly_including_case() {
        let (root, issuer) = new_root("Trusted Root");
        let leaf = issue_leaf("Client-A", &issuer);
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        m.register_client(pki_client("exact", Some("CN=Client-A"), None))
            .await
            .unwrap();
        m.register_client(pki_client("lower", Some("CN=client-a"), None))
            .await
            .unwrap();
        // Attribute TYPES are case-insensitive keywords, VALUES are exact.
        m.register_client(pki_client("kw", Some("cn=Client-A"), None))
            .await
            .unwrap();
        assert!(accepted(&m, "exact", &leaf, &[]).await);
        assert!(accepted(&m, "kw", &leaf, &[]).await);
        assert!(!accepted(&m, "lower", &leaf, &[]).await);
    }

    #[tokio::test]
    async fn registration_rejects_empty_or_unparsable_subject_dns() {
        let (root, _) = new_root("Trusted Root");
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        for bad in [
            "",
            "   ",
            "Alice",
            "CN=",
            "CN=Alice,",
            "FOO=Alice",
            "CN=Alice;O=Corp",
            "CN=\"Alice\"",
            "CN=#0403414243",
            "CN=Alice\\",
            "CN= Alice",
            "CN=Alice ",
        ] {
            assert!(
                m.register_client(pki_client("c", Some(bad), None))
                    .await
                    .is_err(),
                "{bad:?} must not register"
            );
        }
        // The same rule applies to self-signed clients.
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = leaf_params("sc").self_signed(&key).unwrap().der().to_vec();
        let cfg = MutualTlsClientConfig {
            client_id: "sc".to_string(),
            auth_method: MutualTlsMethod::SelfSignedTlsClientAuth,
            ca_certificates: Vec::new(),
            client_certificate: Some(cert),
            expected_subject_dn: Some(String::new()),
            certificate_bound_access_tokens: false,
        };
        assert!(m.register_client(cfg).await.is_err());
        // An empty pin is as meaningless as an empty DN, and a PKI pin must be a certificate.
        assert!(
            m.register_client(pki_client("c", None, Some(&[])))
                .await
                .is_err()
        );
        assert!(
            m.register_client(pki_client("c", None, Some(b"not a certificate")))
                .await
                .is_err()
        );
    }

    #[test]
    fn rfc4514_parsing_covers_escapes_multi_valued_rdns_and_order() {
        // Most specific RDN first in the string, last in the certificate.
        let parsed = parse_rfc4514("CN=Alice,OU=Eng,O=Corp").unwrap();
        let oid = |s: &str| s.to_string();
        assert_eq!(
            parsed,
            vec![
                vec![(oid("2.5.4.10"), "Corp".to_string())],
                vec![(oid("2.5.4.11"), "Eng".to_string())],
                vec![(oid("2.5.4.3"), "Alice".to_string())],
            ]
        );
        // A space after a separator, before the attribute type, is just layout; escaped edge
        // spaces belong to the value; interior spaces are kept.
        assert_eq!(
            parse_rfc4514(r"CN=a\ , O=b c").unwrap(),
            vec![
                vec![(oid("2.5.4.10"), "b c".to_string())],
                vec![(oid("2.5.4.3"), "a ".to_string())],
            ]
        );
        // Unescaped edge spaces in a value are refused, not normalised away.
        for bad in [
            "CN= Alice",
            "CN=Alice ",
            "CN=Alice , O=Corp",
            "CN =Alice",
            "O=Corp,CN= a",
        ] {
            assert!(parse_rfc4514(bad).is_err(), "{bad:?} must be refused");
        }
        let long = format!("CN={}", "x ".repeat(100));
        let err = parse_rfc4514(&long).unwrap_err();
        assert!(err.contains("chars)") && err.len() < 200, "{err}");
        // Escapes: special characters and hex pairs (UTF-8 bytes).
        assert_eq!(
            parse_rfc4514(r"CN=a\,b\+c\\d\3d\C3\A9").unwrap(),
            vec![vec![(oid("2.5.4.3"), "a,b+c\\d=é".to_string())]]
        );
        // '+' joins attributes of ONE RDN, order-insensitively.
        assert_eq!(
            parse_rfc4514("CN=Alice+O=Corp").unwrap(),
            parse_rfc4514("O=Corp+CN=Alice").unwrap()
        );
        assert_ne!(
            parse_rfc4514("CN=Alice+O=Corp").unwrap(),
            parse_rfc4514("CN=Alice,O=Corp").unwrap()
        );
        // Dotted OIDs are accepted.
        assert_eq!(
            parse_rfc4514("2.5.4.3=Alice").unwrap(),
            parse_rfc4514("CN=Alice").unwrap()
        );
    }

    // ---- keyUsage, trust anchors ----

    #[tokio::test]
    async fn key_usage_without_digital_signature_is_rejected() {
        // webpki does not look at keyUsage, so this rule is ours: a client certificate whose
        // keyUsage lacks digitalSignature (here keyEncipherment only) must fail even though it
        // chains to the CA and carries the clientAuth EKU.
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let mut p = leaf_params("client-a");
        p.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = issue_leaf_with(p, &issuer);
        assert!(!accepted(&m, "client-a", &cert, &[]).await);
        // The same certificate with digitalSignature added passes.
        let mut ok = leaf_params("client-a");
        ok.key_usages = vec![
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::DigitalSignature,
        ];
        let good = issue_leaf_with(ok, &issuer);
        assert!(accepted(&m, "client-a", &good, &[]).await);
    }

    #[tokio::test]
    async fn an_unusable_trust_anchor_is_refused_up_front() {
        let (_, issuer) = new_root("Trusted Root");
        let leaf = issue_leaf("client-a", &issuer);
        let mut m = MutualTlsManager::new();
        // Garbage, a non-CA and truncated DER never enter the store.
        assert!(m.add_ca_certificate(b"junk".to_vec()).is_err());
        assert!(m.add_ca_certificate(leaf).is_err());
        let (root, _) = new_root("Other Root");
        assert!(
            m.add_ca_certificate(root[..root.len() - 4].to_vec())
                .is_err()
        );
    }

    #[tokio::test]
    async fn rdn_order_is_part_of_the_subject() {
        // Same attributes, opposite order: different subjects.
        let (root, issuer) = new_root("Trusted Root");
        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        // RFC 4514 string order is most specific first, so this is O=Corp then CN=Alice in the
        // certificate.
        m.register_client(pki_client("a", Some("CN=Alice,O=Corp"), None))
            .await
            .unwrap();
        let in_order = leaf_with_subject(
            &[
                (DnType::OrganizationName, "Corp"),
                (DnType::CommonName, "Alice"),
            ],
            &issuer,
        );
        let swapped = leaf_with_subject(
            &[
                (DnType::CommonName, "Alice"),
                (DnType::OrganizationName, "Corp"),
            ],
            &issuer,
        );
        assert!(accepted(&m, "a", &in_order, &[]).await);
        assert!(!accepted(&m, "a", &swapped, &[]).await);
    }

    #[tokio::test]
    async fn a_malformed_key_usage_extension_never_passes() {
        let (root, issuer) = new_root("Trusted Root");
        let m = manager_trusting(&root, &["client-a"]).await;
        let mut p = leaf_params("client-a");
        p.key_usages = Vec::new();
        // keyUsage (2.5.29.15) whose value is an OCTET STRING instead of a BIT STRING.
        p.custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 15],
                vec![0x04, 0x01, 0xFF],
            ));
        let cert = issue_leaf_with(p, &issuer);
        assert!(!accepted(&m, "client-a", &cert, &[]).await);
    }

    #[tokio::test]
    async fn edge_spaces_in_a_common_name_are_not_normalised_away() {
        let (root, issuer) = new_root("Trusted Root");
        let plain = issue_leaf("client-a", &issuer);
        let spaced = issue_leaf("client-a ", &issuer);

        let mut m = MutualTlsManager::new();
        m.add_ca_certificate(root).unwrap();
        // "CN=client-a " with an unescaped trailing space cannot be registered at all...
        assert!(
            m.register_client(pki_client("x", Some("CN=client-a "), None))
                .await
                .is_err()
        );
        // ...a registration for the plain name matches only the plain certificate...
        m.register_client(pki_client("plain", Some("CN=client-a"), None))
            .await
            .unwrap();
        assert!(accepted(&m, "plain", &plain, &[]).await);
        assert!(!accepted(&m, "plain", &spaced, &[]).await);
        // ...and the escaped form matches only the spaced one.
        m.register_client(pki_client("spaced", Some(r"CN=client-a\ "), None))
            .await
            .unwrap();
        assert!(accepted(&m, "spaced", &spaced, &[]).await);
        assert!(!accepted(&m, "spaced", &plain, &[]).await);
    }
}
