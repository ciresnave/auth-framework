//! Compatibility shim for the old signature validator.
//!
//! The canonicalizer and validator that lived here rebuilt `SignedInfo` by hand (the text it
//! signed was not well-formed XML), never checked a `Reference` digest, and the token-exchange
//! caller took the verification certificate from the document under test. They are replaced by
//! [`super::dsig`], which verifies with `bergshamra` under certificates the caller configured.

use crate::errors::Result;

/// Verifies an XML signature under one given certificate.
///
/// This answers only "is there a signature under this certificate whose references all check
/// out". It does not say which element is signed, so it is not enough to decide what to trust in
/// a document: use [`verify_signed_assertion`](super::dsig::verify_signed_assertion), which
/// returns the signed assertion and nothing else.
pub struct SamlSignatureValidator;

impl SamlSignatureValidator {
    /// `Ok(true)` when `xml` carries a signature made with `cert_der` (an X.509 certificate, DER)
    /// and every reference digest was recomputed and matches; `Ok(false)` when it does not.
    pub fn validate_xml_signature(&self, xml: &str, cert_der: &[u8]) -> Result<bool> {
        match super::dsig::verify_under(xml, cert_der) {
            Ok(_) => Ok(true),
            Err(reason) => {
                tracing::debug!("SAML signature not verified: {reason}");
                Ok(false)
            }
        }
    }
}
