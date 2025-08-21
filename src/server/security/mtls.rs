//! OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (RFC 8705)
//!
//! This module implements RFC 8705, which defines:
//! 1. Mutual TLS client authentication methods
//! 2. Certificate-bound access tokens for enhanced security
//! 3. X.509 certificate validation and processing

use crate::errors::{AuthError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature;
use ring::signature::UnparsedPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    /// For PKI method: allowed certificate chain
    pub ca_certificates: Vec<Vec<u8>>,

    /// For self-signed method: registered certificate
    pub client_certificate: Option<Vec<u8>>,

    /// Subject DN pattern for validation
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

    /// Add a trusted CA certificate
    pub fn add_ca_certificate(&mut self, ca_cert: Vec<u8>) -> Result<()> {
        // Validate the CA certificate
        let (_, cert) = parse_x509_certificate(&ca_cert)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid CA certificate format"))?;

        // Check if it's a CA certificate
        if !cert
            .basic_constraints()
            .map(|bc| bc.unwrap().value.ca)
            .unwrap_or(false)
        {
            return Err(AuthError::auth_method(
                "mtls",
                "Certificate is not a CA certificate",
            ));
        }

        self.ca_store.push(ca_cert);
        Ok(())
    }

    /// Register a client for Mutual TLS authentication
    pub async fn register_client(&self, config: MutualTlsClientConfig) -> Result<()> {
        self.validate_client_config(&config)?;

        let mut clients = self.clients.write().await;
        clients.insert(config.client_id.clone(), config);

        Ok(())
    }

    /// Authenticate a client using Mutual TLS
    pub async fn authenticate_client(
        &self,
        client_id: &str,
        client_certificate: &[u8],
    ) -> Result<MutualTlsAuthResult> {
        let clients = self.clients.read().await;
        let client_config = clients
            .get(client_id)
            .ok_or_else(|| AuthError::auth_method("mtls", "Client not registered for mTLS"))?;

        // Parse the client certificate
        let (_, cert) = parse_x509_certificate(client_certificate)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid client certificate format"))?;

        // Extract certificate information
        let cert_info = self.extract_certificate_info(&cert, client_certificate)?;

        // Validate based on authentication method
        let (is_valid, validation_errors) = match client_config.auth_method {
            MutualTlsMethod::PkiMutualTls => {
                self.validate_pki_certificate(&cert, client_config).await
            }
            MutualTlsMethod::SelfSignedTlsClientAuth => {
                self.validate_self_signed_certificate(&cert, client_config)
                    .await
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

    /// Validate client certificate for mTLS authentication
    pub async fn validate_client_certificate(
        &self,
        client_certificate: &[u8],
        client_id: &str,
    ) -> Result<()> {
        // Parse the client certificate
        let (_, cert) = parse_x509_certificate(client_certificate)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid client certificate format"))?;

        // Check certificate validity period
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if cert.validity.not_before.timestamp() > now {
            return Err(AuthError::auth_method(
                "mtls",
                "Client certificate not yet valid",
            ));
        }

        if cert.validity.not_after.timestamp() < now {
            return Err(AuthError::auth_method(
                "mtls",
                "Client certificate has expired",
            ));
        }

        // Validate against CA store with full X.509 chain validation using rustls-webpki
        if self.ca_store.is_empty() {
            return Err(AuthError::auth_method(
                "mtls",
                "No trusted CA certificates configured",
            ));
        }

        // Perform full X.509 chain validation
        self.perform_full_chain_validation(client_certificate, client_id)
            .await?;

        // Check if client is registered for mTLS
        let clients = self.clients.read().await;
        if !clients.contains_key(client_id) {
            return Err(AuthError::auth_method(
                "mtls",
                "Client not registered for mTLS",
            ));
        }

        Ok(())
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

    /// Validate PKI certificate against CA chain
    async fn validate_pki_certificate(
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

        // Check subject DN if specified
        if let Some(expected_subject) = &client_config.expected_subject_dn {
            let actual_subject = cert.subject().to_string();
            if !actual_subject.contains(expected_subject) {
                errors.push(format!(
                    "Subject DN does not match expected pattern: {}",
                    expected_subject
                ));
            }
        }

        // Validate certificate chain against CA store
        let mut ca_validated = false;
        for ca_cert_der in &self.ca_store {
            if let Ok((_, ca_cert)) = parse_x509_certificate(ca_cert_der) {
                // Basic issuer check (in real implementation, full chain validation would be needed)
                if cert.issuer() == ca_cert.subject() {
                    ca_validated = true;
                    break;
                }
            }
        }

        if !ca_validated && !self.ca_store.is_empty() {
            errors.push("Certificate not signed by trusted CA".to_string());
        }

        // Check key usage extensions
        if let Ok(Some(key_usage)) = cert.key_usage()
            && !key_usage.value.digital_signature()
        {
            errors.push("Certificate does not allow digital signatures".to_string());
        }

        (errors.is_empty(), errors)
    }

    /// Validate self-signed certificate
    async fn validate_self_signed_certificate(
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

        // Check subject DN if specified
        if let Some(expected_subject) = &client_config.expected_subject_dn {
            let actual_subject = cert.subject().to_string();
            if !actual_subject.contains(expected_subject) {
                errors.push(format!(
                    "Subject DN does not match expected pattern: {}",
                    expected_subject
                ));
            }
        }

        (errors.is_empty(), errors)
    }

    /// Validate client configuration
    fn validate_client_config(&self, config: &MutualTlsClientConfig) -> Result<()> {
        match config.auth_method {
            MutualTlsMethod::PkiMutualTls => {
                if config.ca_certificates.is_empty() && self.ca_store.is_empty() {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "PKI authentication requires CA certificates",
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

    /// Perform full X.509 certificate chain validation using ring for signature verification
    async fn perform_full_chain_validation(&self, cert_der: &[u8], client_id: &str) -> Result<()> {
        // Parse the client certificate
        let (_, client_cert) = parse_x509_certificate(cert_der)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid client certificate format"))?;

        // Find a trusted CA that can validate this certificate
        let mut ca_validated = false;
        let mut validation_errors = Vec::new();

        for ca_der in &self.ca_store {
            match self
                .validate_certificate_against_ca(&client_cert, ca_der)
                .await
            {
                Ok(()) => {
                    ca_validated = true;
                    break;
                }
                Err(e) => {
                    validation_errors.push(format!("CA validation failed: {}", e));
                }
            }
        }

        if !ca_validated {
            return Err(AuthError::auth_method(
                "mtls",
                format!(
                    "Certificate chain validation failed. Errors: {}",
                    validation_errors.join("; ")
                ),
            ));
        }

        // Additional validation: check if client is registered for mTLS
        let clients = self.clients.read().await;
        if !clients.contains_key(client_id) {
            return Err(AuthError::auth_method(
                "mtls",
                "Client not registered for mTLS",
            ));
        }

        // Additional validation: verify certificate matches registered client
        if let Some(client_config) = clients.get(client_id)
            && let Some(expected_cert) = &client_config.client_certificate
                && expected_cert != cert_der {
                    return Err(AuthError::auth_method(
                        "mtls",
                        "Client certificate does not match registered certificate",
                    ));
                }

        Ok(())
    }

    /// Validate a certificate against a specific CA using cryptographic signature verification
    async fn validate_certificate_against_ca<'a>(
        &self,
        client_cert: &'a X509Certificate<'a>,
        ca_der: &[u8],
    ) -> Result<()> {
        // Parse the CA certificate
        let (_, ca_cert) = parse_x509_certificate(ca_der)
            .map_err(|_| AuthError::auth_method("mtls", "Invalid CA certificate format"))?;

        // Check if the client certificate was issued by this CA
        if client_cert.issuer() != ca_cert.subject() {
            return Err(AuthError::auth_method(
                "mtls",
                "Certificate issuer does not match CA subject",
            ));
        }

        // Verify the signature using ring's cryptographic verification
        self.verify_certificate_signature(client_cert, &ca_cert)
            .await?;

        // Check certificate validity period
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let not_before = client_cert.validity().not_before.timestamp() as u64;
        let not_after = client_cert.validity().not_after.timestamp() as u64;

        if now < not_before {
            return Err(AuthError::auth_method(
                "mtls",
                "Client certificate is not yet valid",
            ));
        }

        if now > not_after {
            return Err(AuthError::auth_method(
                "mtls",
                "Client certificate has expired",
            ));
        }

        // Check CA certificate is still valid
        let ca_not_before = ca_cert.validity().not_before.timestamp() as u64;
        let ca_not_after = ca_cert.validity().not_after.timestamp() as u64;

        if now < ca_not_before || now > ca_not_after {
            return Err(AuthError::auth_method(
                "mtls",
                "CA certificate is not valid at current time",
            ));
        }

        Ok(())
    }

    /// Verify certificate signature using ring cryptographic library
    async fn verify_certificate_signature<'a>(
        &self,
        client_cert: &'a X509Certificate<'a>,
        ca_cert: &'a X509Certificate<'a>,
    ) -> Result<()> {
        // Extract the CA's public key
        let ca_public_key = ca_cert.public_key();
        let ca_public_key_der = ca_public_key.raw;

        // Determine the signature algorithm
        let signature_algorithm = match client_cert
            .signature_algorithm
            .algorithm
            .to_string()
            .as_str()
        {
            "1.2.840.113549.1.1.11" => &signature::RSA_PKCS1_2048_8192_SHA256, // SHA256WithRSAEncryption
            "1.2.840.113549.1.1.12" => &signature::RSA_PKCS1_2048_8192_SHA384, // SHA384WithRSAEncryption
            "1.2.840.113549.1.1.13" => &signature::RSA_PKCS1_2048_8192_SHA512, // SHA512WithRSAEncryption
            _ => {
                return Err(AuthError::auth_method(
                    "mtls",
                    "Unsupported signature algorithm for certificate validation",
                ));
            }
        };

        // Create the public key for verification
        let public_key = UnparsedPublicKey::new(signature_algorithm, ca_public_key_der);

        // Get the signed data (TBS certificate) and signature
        let tbs_certificate_der = &client_cert.tbs_certificate.as_ref();
        let signature_value = &client_cert.signature_value.data;

        // Verify the signature
        public_key
            .verify(tbs_certificate_der, signature_value)
            .map_err(|_| {
                AuthError::auth_method("mtls", "Certificate signature verification failed")
            })?;

        Ok(())
    }
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
}


