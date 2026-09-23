// Pure Rust SAML XML Signature Validation
// Implementation of XML-DSIG using ring, x509-parser, and quick-xml

#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_borrow)]

use crate::errors::{AuthError, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use quick_xml::{Reader, Writer, XmlVersion, events::Event};
use ring::signature;
use std::collections::BTreeMap;
use std::io::Cursor;
use x509_parser::{parse_x509_certificate, public_key::PublicKey};

/// XML Canonicalizer implementing C14N (Canonical XML) per W3C specification
pub struct XmlCanonicalizer;

impl Default for XmlCanonicalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl XmlCanonicalizer {
    /// Create a new XML canonicalizer
    pub fn new() -> Self {
        Self
    }

    /// Canonicalize XML according to W3C C14N specification
    pub fn canonicalize_xml(&self, xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut canonical = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut canonical));

        let mut namespace_stack: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    // Push new namespace context
                    let mut ns_ctx = namespace_stack
                        .last()
                        .expect("namespace stack initialized before loop")
                        .clone();

                    // Process namespace declarations
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| {
                            AuthError::validation(&format!("XML attribute error: {}", e))
                        })?;
                        let key = std::str::from_utf8(attr.key.as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in attribute key: {}", e))
                        })?;
                        let value = std::str::from_utf8(&attr.value).map_err(|e| {
                            AuthError::validation(&format!(
                                "Invalid UTF-8 in attribute value: {}",
                                e
                            ))
                        })?;

                        if key.starts_with("xmlns:") || key == "xmlns" {
                            let prefix = if key == "xmlns" {
                                String::new()
                            } else {
                                key[6..].to_string()
                            };
                            ns_ctx.insert(prefix, value.to_string());
                        }
                    }
                    namespace_stack.push(ns_ctx);

                    // Write canonicalized start element
                    let canonicalized_element = self.canonicalize_element(e, &namespace_stack)?;
                    writer
                        .write_event(Event::Start(canonicalized_element))
                        .map_err(|e| AuthError::validation(&format!("XML write error: {}", e)))?;
                }
                Ok(Event::End(ref e)) => {
                    // Pop namespace context
                    namespace_stack.pop();
                    writer
                        .write_event(Event::End(e.clone()))
                        .map_err(|e| AuthError::validation(&format!("XML write error: {}", e)))?;
                }
                Ok(Event::Text(ref e)) => {
                    // No XML declaration is tracked here; quick-xml's own docs say to
                    // assume 1.0 when the version is unknown, which matches SAML XML
                    // in practice.
                    let text = e.xml_content(XmlVersion::Implicit1_0).map_err(|e| {
                        AuthError::validation(&format!("XML text decode error: {}", e))
                    })?;
                    if !text.trim().is_empty() {
                        writer
                            .write_event(Event::Text(quick_xml::events::BytesText::new(&text)))
                            .map_err(|e| {
                                AuthError::validation(&format!("XML write error: {}", e))
                            })?;
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let canonicalized_element = self.canonicalize_element(e, &namespace_stack)?;
                    writer
                        .write_event(Event::Empty(canonicalized_element))
                        .map_err(|e| AuthError::validation(&format!("XML write error: {}", e)))?;
                }
                Ok(Event::Eof) => break,
                // Skip comments, processing instructions, and CDATA as per C14N
                Ok(Event::Comment(_)) | Ok(Event::PI(_)) | Ok(Event::CData(_)) => continue,
                Ok(Event::Decl(_)) => continue, // Skip XML declaration
                Ok(Event::DocType(_)) => continue, // Skip DOCTYPE declarations
                Ok(Event::GeneralRef(_)) => continue, // Skip general references
                Err(e) => return Err(AuthError::validation(&format!("XML parsing error: {}", e))),
            }
        }

        String::from_utf8(canonical).map_err(|e| {
            AuthError::validation(&format!("Invalid UTF-8 in canonicalized XML: {}", e))
        })
    }

    /// Canonicalize element attributes (sort lexicographically)
    fn canonicalize_element(
        &self,
        element: &quick_xml::events::BytesStart,
        _namespace_stack: &[BTreeMap<String, String>],
    ) -> Result<quick_xml::events::BytesStart<'static>> {
        let mut attrs: BTreeMap<String, String> = BTreeMap::new();

        // Collect all attributes
        for attr in element.attributes() {
            let attr =
                attr.map_err(|e| AuthError::validation(&format!("XML attribute error: {}", e)))?;
            let key = std::str::from_utf8(attr.key.as_ref()).map_err(|e| {
                AuthError::validation(&format!("Invalid UTF-8 in attribute key: {}", e))
            })?;
            let value = std::str::from_utf8(&attr.value).map_err(|e| {
                AuthError::validation(&format!("Invalid UTF-8 in attribute value: {}", e))
            })?;
            attrs.insert(key.to_string(), value.to_string());
        }

        // Create element name as owned string
        let element_name = std::str::from_utf8(element.name().as_ref())
            .map_err(|e| AuthError::validation(&format!("Invalid UTF-8 in element name: {}", e)))?
            .to_string();

        // Store length before moving the string
        let element_name_len = element_name.len();

        // Create new element with sorted attributes using owned data
        let mut new_element =
            quick_xml::events::BytesStart::from_content(element_name, element_name_len);

        // Add attributes in lexicographical order
        for (key, value) in attrs {
            new_element.push_attribute((key.as_str(), value.as_str()));
        }

        Ok(new_element)
    }
}

/// SAML XML Digital Signature Validator
pub struct SamlSignatureValidator;

impl SamlSignatureValidator {
    fn local_name<'a>(&self, name: &'a [u8]) -> &'a [u8] {
        name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
    }

    /// Validate XML signature using pure Rust cryptography
    pub fn validate_xml_signature(&self, xml: &str, cert_der: &[u8]) -> Result<bool> {
        // 1. Parse certificate and extract public key
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| AuthError::validation(&format!("Certificate parsing error: {}", e)))?;

        let public_key_info = cert.public_key();

        // 2. Extract SignedInfo element from XML
        let signed_info = self.extract_signed_info(xml)?;

        // 3. Canonicalize SignedInfo
        let canonicalizer = XmlCanonicalizer::new();
        let canonical_signed_info = canonicalizer.canonicalize_xml(&signed_info)?;

        // 4. Extract signature value from XML
        let signature_value = self.extract_signature_value(xml)?;
        let signature_bytes = BASE64
            .decode(&signature_value)
            .map_err(|e| AuthError::validation(&format!("Invalid base64 signature: {}", e)))?;

        // 5. Verify signature using Ring - handle different algorithm types
        match &public_key_info.algorithm.algorithm {
            // RSA with SHA-256
            oid if oid.to_string() == "1.2.840.113549.1.1.1" => {
                let public_key_bytes = match &public_key_info.parsed() {
                    Ok(PublicKey::RSA(rsa_key)) => self.construct_rsa_public_key(&rsa_key)?,
                    _ => {
                        return Err(AuthError::validation("Invalid RSA public key"));
                    }
                };
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    &public_key_bytes,
                );
                match public_key.verify(canonical_signed_info.as_bytes(), &signature_bytes) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            // ECDSA with SHA-256 (P-256)
            oid if oid.to_string() == "1.2.840.10045.2.1" => {
                let public_key_bytes = match &public_key_info.parsed() {
                    Ok(PublicKey::EC(ec_key)) => self.construct_ecdsa_public_key(&ec_key)?,
                    _ => {
                        return Err(AuthError::validation("Invalid ECDSA public key"));
                    }
                };
                let public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &public_key_bytes,
                );
                match public_key.verify(canonical_signed_info.as_bytes(), &signature_bytes) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            oid => Err(AuthError::validation(&format!(
                "Unsupported signature algorithm: {}",
                oid
            ))),
        }
    }

    /// Extract SignedInfo element from SAML assertion
    fn extract_signed_info(&self, xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        let mut signed_info = String::new();
        let mut inside_signed_info = false;
        let mut depth = 0;

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) if self.local_name(e.name().as_ref()) == b"SignedInfo" => {
                    inside_signed_info = true;
                    depth = 1;
                    signed_info.push_str(&format!(
                        "<{}>",
                        std::str::from_utf8(e.name().as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in element name: {}", e))
                        })?
                    ));

                    // Add attributes
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| {
                            AuthError::validation(&format!("XML attribute error: {}", e))
                        })?;
                        let key = std::str::from_utf8(attr.key.as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in attribute key: {}", e))
                        })?;
                        let value = std::str::from_utf8(&attr.value).map_err(|e| {
                            AuthError::validation(&format!(
                                "Invalid UTF-8 in attribute value: {}",
                                e
                            ))
                        })?;
                        signed_info.push_str(&format!(" {}=\"{}\"", key, value));
                    }
                    signed_info.push('>');
                }
                Ok(Event::Start(ref e)) if inside_signed_info => {
                    depth += 1;
                    signed_info.push_str(&format!(
                        "<{}>",
                        std::str::from_utf8(e.name().as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in element name: {}", e))
                        })?
                    ));

                    // Add attributes
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| {
                            AuthError::validation(&format!("XML attribute error: {}", e))
                        })?;
                        let key = std::str::from_utf8(attr.key.as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in attribute key: {}", e))
                        })?;
                        let value = std::str::from_utf8(&attr.value).map_err(|e| {
                            AuthError::validation(&format!(
                                "Invalid UTF-8 in attribute value: {}",
                                e
                            ))
                        })?;
                        signed_info.push_str(&format!(" {}=\"{}\"", key, value));
                    }
                    signed_info.push('>');
                }
                Ok(Event::End(ref e)) if inside_signed_info => {
                    depth -= 1;
                    signed_info.push_str(&format!(
                        "</{}>",
                        std::str::from_utf8(e.name().as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in element name: {}", e))
                        })?
                    ));

                    if depth == 0 {
                        break;
                    }
                }
                Ok(Event::Text(ref e)) if inside_signed_info => {
                    // No XML declaration is tracked here; quick-xml's own docs say to
                    // assume 1.0 when the version is unknown, which matches SAML XML
                    // in practice.
                    let text = e.xml_content(XmlVersion::Implicit1_0).map_err(|e| {
                        AuthError::validation(&format!("XML text decode error: {}", e))
                    })?;
                    signed_info.push_str(&text);
                }
                Ok(Event::Empty(ref e)) if inside_signed_info => {
                    signed_info.push_str(&format!(
                        "<{}",
                        std::str::from_utf8(e.name().as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in element name: {}", e))
                        })?
                    ));

                    // Add attributes
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| {
                            AuthError::validation(&format!("XML attribute error: {}", e))
                        })?;
                        let key = std::str::from_utf8(attr.key.as_ref()).map_err(|e| {
                            AuthError::validation(&format!("Invalid UTF-8 in attribute key: {}", e))
                        })?;
                        let value = std::str::from_utf8(&attr.value).map_err(|e| {
                            AuthError::validation(&format!(
                                "Invalid UTF-8 in attribute value: {}",
                                e
                            ))
                        })?;
                        signed_info.push_str(&format!(" {}=\"{}\"", key, value));
                    }
                    signed_info.push_str(" />");
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(AuthError::validation(&format!("XML parsing error: {}", e))),
                _ => continue,
            }
        }

        if signed_info.is_empty() {
            return Err(AuthError::validation("SignedInfo element not found"));
        }

        Ok(signed_info)
    }

    /// Extract signature value from SAML assertion
    fn extract_signature_value(&self, xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        let mut inside_signature_value = false;
        let mut signature_value = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e))
                    if self.local_name(e.name().as_ref()) == b"SignatureValue" =>
                {
                    inside_signature_value = true;
                }
                Ok(Event::Text(ref e)) if inside_signature_value => {
                    // No XML declaration is tracked here; quick-xml's own docs say to
                    // assume 1.0 when the version is unknown, which matches SAML XML
                    // in practice.
                    let text = e.xml_content(XmlVersion::Implicit1_0).map_err(|e| {
                        AuthError::validation(&format!("XML text decode error: {}", e))
                    })?;
                    signature_value.push_str(&text);
                }
                Ok(Event::End(ref e))
                    if self.local_name(e.name().as_ref()) == b"SignatureValue" =>
                {
                    break;
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(AuthError::validation(&format!("XML parsing error: {}", e))),
                _ => continue,
            }
        }

        if signature_value.is_empty() {
            return Err(AuthError::validation("SignatureValue element not found"));
        }

        // Remove whitespace and newlines
        Ok(signature_value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect())
    }

    /// Extract an embedded X.509 certificate from KeyInfo/X509Certificate.
    pub fn extract_embedded_certificate(&self, xml: &str) -> Result<Vec<u8>> {
        let mut reader = Reader::from_str(xml);
        let mut inside_certificate = false;
        let mut certificate = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e))
                    if self.local_name(e.name().as_ref()) == b"X509Certificate" =>
                {
                    inside_certificate = true;
                }
                Ok(Event::Text(ref e)) if inside_certificate => {
                    // No XML declaration is tracked here; quick-xml's own docs say to
                    // assume 1.0 when the version is unknown, which matches SAML XML
                    // in practice.
                    let text = e.xml_content(XmlVersion::Implicit1_0).map_err(|e| {
                        AuthError::validation(&format!("XML text decode error: {}", e))
                    })?;
                    certificate.push_str(&text);
                }
                Ok(Event::End(ref e))
                    if self.local_name(e.name().as_ref()) == b"X509Certificate" =>
                {
                    break;
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(AuthError::validation(&format!("XML parsing error: {}", e))),
                _ => continue,
            }
        }

        if certificate.trim().is_empty() {
            return Err(AuthError::validation(
                "No embedded X509Certificate element found in SAML assertion",
            ));
        }

        BASE64
            .decode(
                certificate
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>(),
            )
            .map_err(|e| AuthError::validation(&format!("Invalid embedded certificate: {}", e)))
    }

    /// Construct RSA public key in PKCS#1 DER format for Ring
    ///
    /// Ring's `RSA_PKCS1_2048_8192_SHA256` expects the key as a DER-encoded
    /// `RSAPublicKey` (PKCS#1) per RFC 8017:
    /// ```text
    /// RSAPublicKey ::= SEQUENCE {
    ///   modulus           INTEGER,
    ///   publicExponent    INTEGER
    /// }
    /// ```
    fn construct_rsa_public_key(
        &self,
        rsa_key: &x509_parser::public_key::RSAPublicKey,
    ) -> Result<Vec<u8>> {
        /// Encode a byte slice as a DER INTEGER.
        /// Prepends a leading 0x00 byte if the high bit is set (positive sign).
        fn der_encode_integer(value: &[u8]) -> Vec<u8> {
            // Strip leading zero bytes (but keep at least one byte)
            let stripped = match value.iter().position(|&b| b != 0) {
                Some(pos) => &value[pos..],
                None => &[0u8],
            };

            let needs_pad = stripped[0] & 0x80 != 0;
            let len = stripped.len() + if needs_pad { 1 } else { 0 };

            let mut out = Vec::with_capacity(2 + len);
            out.push(0x02); // INTEGER tag
            der_push_length(&mut out, len);
            if needs_pad {
                out.push(0x00);
            }
            out.extend_from_slice(stripped);
            out
        }

        /// Push a DER length encoding (supports lengths up to 65535).
        fn der_push_length(buf: &mut Vec<u8>, len: usize) {
            if len < 0x80 {
                buf.push(len as u8);
            } else if len <= 0xFF {
                buf.push(0x81);
                buf.push(len as u8);
            } else {
                buf.push(0x82);
                buf.push((len >> 8) as u8);
                buf.push(len as u8);
            }
        }

        let modulus_der = der_encode_integer(rsa_key.modulus);
        let exponent_der = der_encode_integer(rsa_key.exponent);

        let seq_content_len = modulus_der.len() + exponent_der.len();
        let mut key_data = Vec::with_capacity(4 + seq_content_len);
        key_data.push(0x30); // SEQUENCE tag
        der_push_length(&mut key_data, seq_content_len);
        key_data.extend_from_slice(&modulus_der);
        key_data.extend_from_slice(&exponent_der);

        Ok(key_data)
    }

    fn construct_ecdsa_public_key(
        &self,
        ec_key: &x509_parser::public_key::ECPoint,
    ) -> Result<Vec<u8>> {
        // For ECDSA, extract the public key point data
        Ok(ec_key.data().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_canonicalization() {
        let xml = r#"<test xmlns:ns="http://example.com" attr2="value2" attr1="value1">
            <child>content</child>
        </test>"#;

        let canonicalizer = XmlCanonicalizer::new();
        let result = canonicalizer.canonicalize_xml(xml);
        assert!(result.is_ok());

        let canonical = result.unwrap();
        // Should have sorted attributes and normalized whitespace
        assert!(canonical.contains("attr1"));
        assert!(canonical.contains("attr2"));
    }

    #[test]
    fn test_signed_info_extraction() {
        let xml = r#"
        <Assertion>
            <Signature>
                <SignedInfo>
                    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                    <Reference URI="">
                        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                        <DigestValue>base64digest</DigestValue>
                    </Reference>
                </SignedInfo>
                <SignatureValue>base64signature</SignatureValue>
            </Signature>
        </Assertion>"#;

        let validator = SamlSignatureValidator;
        let result = validator.extract_signed_info(xml);
        assert!(result.is_ok());

        let signed_info = result.unwrap();
        assert!(signed_info.contains("SignedInfo"));
        assert!(signed_info.contains("CanonicalizationMethod"));
        assert!(signed_info.contains("SignatureMethod"));
        assert!(signed_info.contains("Reference"));
    }

    #[test]
    fn test_signature_value_extraction() {
        let xml = r#"
        <Signature>
            <SignatureValue>
                YmFzZTY0c2lnbmF0dXJl
            </SignatureValue>
        </Signature>"#;

        let validator = SamlSignatureValidator;
        let result = validator.extract_signature_value(xml);
        assert!(result.is_ok());

        let signature_value = result.unwrap();
        assert_eq!(signature_value, "YmFzZTY0c2lnbmF0dXJl");
    }
}
