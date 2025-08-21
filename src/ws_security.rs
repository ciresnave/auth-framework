//! WS-Security 1.1 Client Implementation
//!
//! This module provides client-side WS-Security 1.1 support for legacy enterprise systems.
//! Includes UsernameToken, Timestamp, X.509 Certificate Signing, and SAML 2.0 token support.

use crate::errors::{AuthError, Result};
use crate::saml_assertions::SamlAssertion;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WS-Security Header builder
#[derive(Debug, Clone, Default)]
pub struct WsSecurityHeader {
    /// Username token (if used)
    pub username_token: Option<UsernameToken>,

    /// Timestamp (if used)
    pub timestamp: Option<Timestamp>,

    /// Binary security token (X.509 certificate)
    pub binary_security_token: Option<BinarySecurityToken>,

    /// SAML assertions
    pub saml_assertions: Vec<SamlAssertionRef>,

    /// Signature elements
    pub signature: Option<WsSecuritySignature>,

    /// Additional custom elements
    pub custom_elements: Vec<String>,
}

/// UsernameToken for basic authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameToken {
    /// Username
    pub username: String,

    /// Password (optional - can be omitted for cert-based auth)
    pub password: Option<UsernamePassword>,

    /// Nonce for replay protection
    pub nonce: Option<String>,

    /// Created timestamp
    pub created: Option<DateTime<Utc>>,

    /// WSU ID for referencing in signatures
    pub wsu_id: Option<String>,
}

/// Password element with type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernamePassword {
    /// Password value
    pub value: String,

    /// Password type (PasswordText or PasswordDigest)
    pub password_type: PasswordType,
}

/// Password types for UsernameToken
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordType {
    /// Plain text password (not recommended)
    PasswordText,

    /// SHA-1 digest of password, nonce, and created time
    PasswordDigest,
}

/// Timestamp for message freshness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    /// When the message was created
    pub created: DateTime<Utc>,

    /// When the message expires
    pub expires: DateTime<Utc>,

    /// WSU ID for referencing in signatures
    pub wsu_id: Option<String>,
}

/// Binary Security Token (typically X.509 certificate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySecurityToken {
    /// Token value (base64 encoded certificate)
    pub value: String,

    /// Value type (X.509 certificate identifier)
    pub value_type: String,

    /// Encoding type (Base64Binary)
    pub encoding_type: String,

    /// WSU ID for referencing
    pub wsu_id: Option<String>,
}

/// SAML Assertion for identity/attribute exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertionRef {
    /// Reference to the SAML assertion
    pub assertion: SamlAssertion,

    /// WSU ID for referencing in signatures
    pub wsu_id: Option<String>,
}

/// WS-Security Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSecuritySignature {
    /// Signature method algorithm
    pub signature_method: String,

    /// Canonicalization method
    pub canonicalization_method: String,

    /// Digest method
    pub digest_method: String,

    /// References to signed elements
    pub references: Vec<SignatureReference>,

    /// Key info (certificate reference)
    pub key_info: Option<KeyInfo>,

    /// Signature value
    pub signature_value: Option<String>,
}

/// Reference to a signed element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureReference {
    /// URI reference to the element
    pub uri: String,

    /// Digest value
    pub digest_value: String,

    /// Transforms applied
    pub transforms: Vec<String>,
}

/// Key information for signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Reference to security token
    pub security_token_reference: Option<String>,

    /// Direct key value
    pub key_value: Option<String>,

    /// X.509 certificate data
    pub x509_data: Option<String>,
}

/// WS-Security configuration
#[derive(Debug, Clone)]
pub struct WsSecurityConfig {
    /// Whether to include timestamp
    pub include_timestamp: bool,

    /// Timestamp TTL
    pub timestamp_ttl: Duration,

    /// Whether to sign the message
    pub sign_message: bool,

    /// Elements to sign (by local name)
    pub elements_to_sign: Vec<String>,

    /// Certificate for signing (PEM format)
    pub signing_certificate: Option<Vec<u8>>,

    /// Private key for signing (PEM format)
    pub signing_private_key: Option<Vec<u8>>,

    /// Whether to include certificate in message
    pub include_certificate: bool,

    /// SAML token provider endpoint
    pub saml_token_endpoint: Option<String>,

    /// Actor value for delegation scenarios
    pub actor: Option<String>,
}

/// WS-Security client for generating secure SOAP headers
pub struct WsSecurityClient {
    /// Configuration
    config: WsSecurityConfig,

    /// XML namespace prefixes
    namespaces: HashMap<String, String>,
}

impl WsSecurityClient {
    /// Create a new WS-Security client
    pub fn new(config: WsSecurityConfig) -> Self {
        let mut namespaces = HashMap::new();
        namespaces.insert(
            "wsse".to_string(),
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                .to_string(),
        );
        namespaces.insert(
            "wsu".to_string(),
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                .to_string(),
        );
        namespaces.insert(
            "ds".to_string(),
            "http://www.w3.org/2000/09/xmldsig#".to_string(),
        );
        namespaces.insert(
            "saml".to_string(),
            "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
        );

        Self { config, namespaces }
    }

    /// Create WS-Security header with UsernameToken
    pub fn create_username_token_header(
        &self,
        username: &str,
        password: Option<&str>,
        password_type: PasswordType,
    ) -> Result<WsSecurityHeader> {
        let mut header = WsSecurityHeader::default();

        let (nonce, created) = if password_type == PasswordType::PasswordDigest {
            (Some(self.generate_nonce()), Some(Utc::now()))
        } else {
            (None, None)
        };

        let password_element = if let Some(pwd) = password {
            let pwd_value = match password_type {
                PasswordType::PasswordText => pwd.to_string(),
                PasswordType::PasswordDigest => {
                    self.compute_password_digest(pwd, nonce.as_ref().unwrap(), &created.unwrap())?
                }
            };

            Some(UsernamePassword {
                value: pwd_value,
                password_type,
            })
        } else {
            None
        };

        header.username_token = Some(UsernameToken {
            username: username.to_string(),
            password: password_element,
            nonce,
            created,
            wsu_id: Some(format!("UsernameToken-{}", uuid::Uuid::new_v4())),
        });

        if self.config.include_timestamp {
            header.timestamp = Some(self.create_timestamp());
        }

        Ok(header)
    }

    /// Create WS-Security header with X.509 certificate
    pub fn create_certificate_header(&self, certificate: &[u8]) -> Result<WsSecurityHeader> {
        let mut header = WsSecurityHeader::default();

        // Encode certificate as base64
        let cert_b64 = STANDARD.encode(certificate);

        header.binary_security_token = Some(BinarySecurityToken {
            value: cert_b64,
            value_type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3".to_string(),
            encoding_type: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary".to_string(),
            wsu_id: Some(format!("X509Token-{}", uuid::Uuid::new_v4())),
        });

        if self.config.include_timestamp {
            header.timestamp = Some(self.create_timestamp());
        }

        if self.config.sign_message {
            header.signature = Some(self.create_signature_template()?);
        }

        Ok(header)
    }

    /// Create WS-Security header with SAML assertion
    pub fn create_saml_header(&self, assertion: SamlAssertion) -> Result<WsSecurityHeader> {
        let mut header = WsSecurityHeader::default();

        let assertion_ref = SamlAssertionRef {
            assertion,
            wsu_id: Some(format!("SamlAssertion-{}", uuid::Uuid::new_v4())),
        };

        header.saml_assertions.push(assertion_ref);

        if self.config.include_timestamp {
            header.timestamp = Some(self.create_timestamp());
        }

        Ok(header)
    }
    /// Convert WS-Security header to XML
    pub fn header_to_xml(&self, header: &WsSecurityHeader) -> Result<String> {
        let mut xml = String::new();

        // Start Security header
        xml.push_str(&format!(
            r#"<wsse:Security xmlns:wsse="{}" xmlns:wsu="{}">"#,
            self.namespaces["wsse"], self.namespaces["wsu"]
        ));

        // Add timestamp
        if let Some(ref timestamp) = header.timestamp {
            xml.push_str(&self.timestamp_to_xml(timestamp));
        }

        // Add username token
        if let Some(ref username_token) = header.username_token {
            xml.push_str(&self.username_token_to_xml(username_token));
        }

        // Add binary security token
        if let Some(ref bst) = header.binary_security_token {
            xml.push_str(&self.binary_security_token_to_xml(bst));
        }

        // Add SAML assertions
        for assertion_ref in &header.saml_assertions {
            let assertion_xml = assertion_ref.assertion.to_xml()?;
            xml.push_str(&assertion_xml);
        }

        // Add signature
        if let Some(ref signature) = header.signature {
            xml.push_str(&self.signature_to_xml(signature));
        }

        // End Security header
        xml.push_str("</wsse:Security>");

        Ok(xml)
    }

    /// Generate a random nonce
    fn generate_nonce(&self) -> String {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        STANDARD.encode(nonce)
    }

    /// Compute password digest (SHA-1 of nonce + created + password)
    fn compute_password_digest(
        &self,
        password: &str,
        nonce: &str,
        created: &DateTime<Utc>,
    ) -> Result<String> {
        use sha1::{Digest, Sha1};

        let nonce_bytes = STANDARD
            .decode(nonce)
            .map_err(|_| AuthError::auth_method("ws_security", "Invalid nonce encoding"))?;
        let created_str = created.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut hasher = Sha1::new();
        hasher.update(&nonce_bytes);
        hasher.update(created_str.as_bytes());
        hasher.update(password.as_bytes());

        let digest = hasher.finalize();
        Ok(STANDARD.encode(digest))
    }

    /// Create timestamp element
    fn create_timestamp(&self) -> Timestamp {
        let now = Utc::now();
        let expires = now + self.config.timestamp_ttl;

        Timestamp {
            created: now,
            expires,
            wsu_id: Some(format!("Timestamp-{}", uuid::Uuid::new_v4())),
        }
    }

    /// Create signature template
    fn create_signature_template(&self) -> Result<WsSecuritySignature> {
        Ok(WsSecuritySignature {
            signature_method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string(),
            canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
            digest_method: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            references: self
                .config
                .elements_to_sign
                .iter()
                .map(|element| {
                    SignatureReference {
                        uri: format!("#{}", element),
                        digest_value: String::new(), // Will be computed during signing
                        transforms: vec!["http://www.w3.org/2001/10/xml-exc-c14n#".to_string()],
                    }
                })
                .collect(),
            key_info: None,        // Will be set based on certificate
            signature_value: None, // Will be computed during signing
        })
    }

    /// Convert timestamp to XML
    fn timestamp_to_xml(&self, timestamp: &Timestamp) -> String {
        let mut xml = String::new();

        if let Some(ref id) = timestamp.wsu_id {
            xml.push_str(&format!(r#"<wsu:Timestamp wsu:Id="{}">"#, id));
        } else {
            xml.push_str("<wsu:Timestamp>");
        }

        xml.push_str(&format!(
            "<wsu:Created>{}</wsu:Created>",
            timestamp.created.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        ));

        xml.push_str(&format!(
            "<wsu:Expires>{}</wsu:Expires>",
            timestamp.expires.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        ));

        xml.push_str("</wsu:Timestamp>");
        xml
    }

    /// Convert username token to XML
    fn username_token_to_xml(&self, token: &UsernameToken) -> String {
        let mut xml = String::new();

        if let Some(ref id) = token.wsu_id {
            xml.push_str(&format!(r#"<wsse:UsernameToken wsu:Id="{}">"#, id));
        } else {
            xml.push_str("<wsse:UsernameToken>");
        }

        xml.push_str(&format!(
            "<wsse:Username>{}</wsse:Username>",
            token.username
        ));

        if let Some(ref password) = token.password {
            let type_attr = match password.password_type {
                PasswordType::PasswordText => {
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
                }
                PasswordType::PasswordDigest => {
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
                }
            };

            xml.push_str(&format!(
                r#"<wsse:Password Type="{}">{}</wsse:Password>"#,
                type_attr, password.value
            ));
        }

        if let Some(ref nonce) = token.nonce {
            xml.push_str(&format!(
                r#"<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{}</wsse:Nonce>"#,
                nonce
            ));
        }

        if let Some(ref created) = token.created {
            xml.push_str(&format!(
                "<wsu:Created>{}</wsu:Created>",
                created.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        xml.push_str("</wsse:UsernameToken>");
        xml
    }

    /// Convert binary security token to XML
    fn binary_security_token_to_xml(&self, token: &BinarySecurityToken) -> String {
        let mut xml = String::new();

        xml.push_str(&format!(
            r#"<wsse:BinarySecurityToken ValueType="{}" EncodingType="{}""#,
            token.value_type, token.encoding_type
        ));

        if let Some(ref id) = token.wsu_id {
            xml.push_str(&format!(r#" wsu:Id="{}""#, id));
        }

        xml.push('>');
        xml.push_str(&token.value);
        xml.push_str("</wsse:BinarySecurityToken>");

        xml
    }

    /// Convert signature to XML (simplified template)
    fn signature_to_xml(&self, signature: &WsSecuritySignature) -> String {
        format!(
            r#"<ds:Signature xmlns:ds="{}">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="{}"/>
                    <ds:SignatureMethod Algorithm="{}"/>
                    {}
                </ds:SignedInfo>
                <ds:SignatureValue></ds:SignatureValue>
                <ds:KeyInfo></ds:KeyInfo>
            </ds:Signature>"#,
            self.namespaces["ds"],
            signature.canonicalization_method,
            signature.signature_method,
            signature
                .references
                .iter()
                .map(|r| format!(
                    r#"<ds:Reference URI="{}">
                        <ds:Transforms>
                            {}
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="{}"/>
                        <ds:DigestValue></ds:DigestValue>
                    </ds:Reference>"#,
                    r.uri,
                    r.transforms
                        .iter()
                        .map(|t| format!(r#"<ds:Transform Algorithm="{}"/>"#, t))
                        .collect::<Vec<_>>()
                        .join(""),
                    signature.digest_method
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    }
}

impl Default for WsSecurityConfig {
    fn default() -> Self {
        Self {
            include_timestamp: true,
            timestamp_ttl: Duration::minutes(5),
            sign_message: false,
            elements_to_sign: vec!["Body".to_string(), "Timestamp".to_string()],
            signing_certificate: None,
            signing_private_key: None,
            include_certificate: true,
            saml_token_endpoint: None,
            actor: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_token_creation() {
        let config = WsSecurityConfig::default();
        let client = WsSecurityClient::new(config);

        let header = client
            .create_username_token_header("testuser", Some("testpass"), PasswordType::PasswordText)
            .unwrap();

        assert!(header.username_token.is_some());
        let token = header.username_token.unwrap();
        assert_eq!(token.username, "testuser");
        assert!(token.password.is_some());
    }

    #[test]
    fn test_password_digest() {
        let config = WsSecurityConfig::default();
        let client = WsSecurityClient::new(config);

        let nonce = "MTIzNDU2Nzg5MDEyMzQ1Ng=="; // base64 of "1234567890123456"
        let created = DateTime::parse_from_rfc3339("2023-01-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let password = "secret";

        let digest = client
            .compute_password_digest(password, nonce, &created)
            .unwrap();
        assert!(!digest.is_empty());
    }

    #[test]
    fn test_timestamp_creation() {
        let config = WsSecurityConfig::default();
        let client = WsSecurityClient::new(config);

        let timestamp = client.create_timestamp();
        assert!(timestamp.expires > timestamp.created);
        assert!(timestamp.wsu_id.is_some());
    }

    #[test]
    fn test_xml_generation() {
        let config = WsSecurityConfig::default();
        let client = WsSecurityClient::new(config);

        let header = client
            .create_username_token_header("testuser", Some("testpass"), PasswordType::PasswordText)
            .unwrap();

        let xml = client.header_to_xml(&header).unwrap();
        assert!(xml.contains("<wsse:Security"));
        assert!(xml.contains("<wsse:UsernameToken"));
        assert!(xml.contains("testuser"));
        assert!(xml.contains("</wsse:Security>"));
    }

    #[test]
    fn test_certificate_header() {
        let config = WsSecurityConfig::default();
        let client = WsSecurityClient::new(config);

        let dummy_cert = b"dummy certificate data";
        let header = client.create_certificate_header(dummy_cert).unwrap();

        assert!(header.binary_security_token.is_some());
        let bst = header.binary_security_token.unwrap();
        assert_eq!(bst.value, STANDARD.encode(dummy_cert));
    }
}


