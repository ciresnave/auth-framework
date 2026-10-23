//! XML-DSig verification for SAML, against keys the caller has configured.
//!
//! The rules, each of which closes a way to forge a login:
//!
//! * **The key comes from configuration, never from the document.** Verification is done with
//!   the certificates pinned for the assertion's issuer in a [`SamlTrustAnchors`]; the
//!   certificate a document carries in its own `KeyInfo` is ignored. An issuer with nothing
//!   pinned is refused, so an unconfigured deployment accepts no assertion.
//! * **Every digest is checked.** `bergshamra` recomputes the digest of each `Reference` and
//!   checks it against the signed `SignedInfo`; a signature that covers no reference, or one whose
//!   digest was not recomputed, is refused.
//! * **Only the signed element is read.** A signature proves one element is genuine, not that the
//!   first `Assertion` in the text is that element (signature wrapping). The element a reference
//!   points at is found by its `ID`, which must be unique in the document, and the caller is given
//!   that element's text and nothing else.

use crate::errors::{AuthError, Result};
use base64::Engine;
use bergshamra::{DsigContext, Key, KeyData, KeysManager, VerifyResult, verify};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(message: impl Into<String>) -> AuthError {
    AuthError::validation(message.into())
}

/// The certificates an issuer's signatures are accepted under.
#[derive(Clone, Default)]
pub struct SamlTrustAnchors {
    by_issuer: BTreeMap<String, Vec<Vec<u8>>>,
}

impl std::fmt::Debug for SamlTrustAnchors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SamlTrustAnchors")
            .field("issuers", &self.by_issuer.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SamlTrustAnchors {
    /// No issuer is trusted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept signatures made with `certificate_der` (an X.509 certificate, DER) for `issuer`, the
    /// `saml:Issuer` the assertion names. May be called again to pin a second certificate (a
    /// rollover).
    ///
    /// A certificate that does not parse, or holds a key type or size the verifier cannot use, is
    /// refused here, at configuration time, rather than on the first login.
    pub fn trust(&mut self, issuer: impl Into<String>, certificate_der: Vec<u8>) -> Result<()> {
        let issuer = issuer.into();
        key_from_x509_der(&certificate_der).map_err(|e| {
            invalid(format!(
                "The certificate configured for SAML issuer '{issuer}' is unusable: {e}"
            ))
        })?;
        self.by_issuer
            .entry(issuer)
            .or_default()
            .push(certificate_der);
        Ok(())
    }

    /// As [`trust`](Self::trust), from a PEM `CERTIFICATE` block or bare base64 DER.
    pub fn trust_pem(&mut self, issuer: impl Into<String>, certificate: &str) -> Result<()> {
        let b64: String = certificate
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
            .map(str::trim)
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| invalid(format!("Invalid certificate encoding: {e}")))?;
        self.trust(issuer, der)
    }

    /// Whether nothing is trusted.
    pub fn is_empty(&self) -> bool {
        self.by_issuer.is_empty()
    }

    fn certificates(&self, issuer: &str) -> Option<&[Vec<u8>]> {
        self.by_issuer.get(issuer).map(Vec::as_slice)
    }

    fn issuers(&self) -> impl Iterator<Item = &str> {
        self.by_issuer.keys().map(String::as_str)
    }
}

/// An assertion whose signature was verified under a pinned certificate.
#[derive(Clone)]
pub struct VerifiedAssertion {
    /// The issuer, equal to the one the certificate was pinned for.
    pub issuer: String,
    /// The `ID` of the signed element.
    pub signed_id: String,
    /// The text of the `Assertion` element that is covered by the signature, and only that.
    pub assertion_xml: String,
    /// Whether the enclosing `Response` is itself covered, so its attributes (`InResponseTo`,
    /// `Destination`) can be believed. When only the assertion is signed they cannot.
    pub response_signed: bool,
}

impl std::fmt::Debug for VerifiedAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedAssertion")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

/// An X.509 certificate's public key as a verification key (RSA, P-256 or P-384).
pub(crate) fn key_from_x509_der(der: &[u8]) -> std::result::Result<Key, String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    let spki = cert.public_key();
    let spki_der = spki.raw;

    // `KeyData` is an opaque handle (bergshamra 0.9.2): `from_spki_der` takes an algorithm per
    // attempt, so try RSA, then the two curves.
    let mut last_err = None;
    for algorithm in [
        kryptering::KeyAlgorithm::Rsa,
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
        kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P384),
    ] {
        match KeyData::from_spki_der(algorithm, spki_der) {
            Ok(key_data) => return Ok(Key::new(key_data, bergshamra::KeyUsage::Verify)),
            Err(e) => last_err = Some(e),
        }
    }

    // `last_err` is diagnostic only: it keeps a size/strength rejection (a sub-2048-bit RSA key)
    // from being collapsed into "unsupported algorithm".
    Err(format!(
        "Unsupported IdP signing key algorithm (OID: {}). RSA, P-256, and P-384 are supported.{}",
        cert.public_key().algorithm.oid(),
        last_err
            .map(|e| format!(" Last error: {e}"))
            .unwrap_or_default()
    ))
}

/// Bytes of a name or attribute value, whichever the XML crate's version hands out.
fn bytes_of<T: AsRef<[u8]> + ?Sized>(value: &T) -> &[u8] {
    value.as_ref()
}

struct Element {
    local: String,
    id: Option<String>,
    /// Byte range of the whole element in the document.
    start: usize,
    end: usize,
    parent: Option<usize>,
    /// Unescaped text of the first text child, kept for `Issuer` only.
    text: Option<String>,
}

fn unescaped(raw: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(raw).map_err(|_| invalid("SAML text is not UTF-8"))?;
    quick_xml::escape::unescape(s)
        .map(|c| c.into_owned())
        .map_err(|e| invalid(format!("Invalid entity in SAML text: {e}")))
}

fn element_of(
    start: &quick_xml::events::BytesStart<'_>,
    begin: usize,
    parent: Option<usize>,
) -> Result<Element> {
    let local = String::from_utf8_lossy(bytes_of(start.local_name().into_inner())).into_owned();
    let mut id = None;
    for attr in start.attributes() {
        let attr = attr.map_err(|e| invalid(format!("XML attribute error: {e}")))?;
        let key = String::from_utf8_lossy(bytes_of(attr.key.local_name().into_inner()));
        // Only unprefixed ID attributes name a signable element (xml:id and friends do not).
        if matches!(key.as_ref(), "ID" | "Id" | "id")
            && bytes_of(attr.key.as_ref()) == key.as_bytes()
        {
            id = Some(unescaped(bytes_of(&*attr.value))?);
        }
    }
    Ok(Element {
        local,
        id,
        start: begin,
        end: begin,
        parent,
        text: None,
    })
}

/// Every element of `xml` with its byte range, parent and ID. Refuses a document type
/// declaration: SAML has no use for one, and entity definitions are how documents change
/// meaning under a parser.
fn scan(xml: &str) -> Result<Vec<Element>> {
    let mut reader = Reader::from_str(xml);
    let mut elements: Vec<Element> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    loop {
        let begin = reader.buffer_position() as usize;
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let parent = stack.last().copied();
                elements.push(element_of(&e, begin, parent)?);
                stack.push(elements.len() - 1);
            }
            Ok(Event::Empty(e)) => {
                let parent = stack.last().copied();
                let mut element = element_of(&e, begin, parent)?;
                element.end = reader.buffer_position() as usize;
                elements.push(element);
            }
            Ok(Event::End(_)) => {
                let index = stack
                    .pop()
                    .ok_or_else(|| invalid("Unbalanced XML in SAML document"))?;
                elements[index].end = reader.buffer_position() as usize;
            }
            Ok(Event::Text(t)) => {
                if let Some(&index) = stack.last()
                    && elements[index].local == "Issuer"
                    && elements[index].text.is_none()
                {
                    elements[index].text = Some(unescaped(bytes_of(&*t))?.trim().to_string());
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(invalid("A SAML document may not carry a DOCTYPE"));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(invalid(format!("XML parsing error: {e}"))),
        }
    }
    if !stack.is_empty() {
        return Err(invalid("Unbalanced XML in SAML document"));
    }
    Ok(elements)
}

fn direct_children<'a>(
    elements: &'a [Element],
    parent: usize,
    local: &'a str,
) -> impl Iterator<Item = usize> + 'a {
    elements
        .iter()
        .enumerate()
        .filter(move |(_, e)| e.parent == Some(parent) && e.local == local)
        .map(|(i, _)| i)
}

/// Verify the signature on `xml` against the pinned certificates of the issuer it names, and give
/// back the one assertion that signature covers.
pub fn verify_signed_assertion(xml: &str, anchors: &SamlTrustAnchors) -> Result<VerifiedAssertion> {
    if anchors.is_empty() {
        return Err(invalid(
            "No trusted SAML issuer is configured, so no assertion can be accepted",
        ));
    }
    let elements = scan(xml)?;

    // The issuers the document names that we hold a certificate for. Which one is genuine is
    // decided by the signature, not by this list.
    let named: BTreeSet<&str> = elements
        .iter()
        .filter(|e| e.local == "Issuer")
        .filter_map(|e| e.text.as_deref())
        .collect();
    let candidates: Vec<&str> = anchors.issuers().filter(|i| named.contains(i)).collect();
    if candidates.is_empty() {
        return Err(invalid(
            "The SAML document names no issuer that is configured as trusted",
        ));
    }

    let mut last_reason = String::from("no signature");
    for issuer in candidates {
        let Some(certificates) = anchors.certificates(issuer) else {
            continue;
        };
        for der in certificates {
            match verify_under(xml, der) {
                Ok(references) => {
                    return covered_assertion(xml, &elements, issuer, &references);
                }
                Err(reason) => last_reason = reason,
            }
        }
    }
    Err(invalid(format!(
        "XML signature verification failed: {last_reason}"
    )))
}

/// Verify with `der` as the only key; the URIs of the references whose digests were checked.
pub(crate) fn verify_under(xml: &str, der: &[u8]) -> std::result::Result<Vec<String>, String> {
    let key = key_from_x509_der(der)?;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    keys.add_trusted_cert(der.to_vec());

    let ctx = DsigContext::new(keys)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_verify_keys(true);
    match verify(&ctx, xml).map_err(|e| format!("XML-DSig verification error: {e}"))? {
        result @ VerifyResult::Valid { .. } => {
            if !result.all_reference_digests_verified() {
                return Err("a reference digest was not verified, or none was signed".to_string());
            }
            let VerifyResult::Valid { references, .. } = result else {
                unreachable!("matched Valid above")
            };
            Ok(references.into_iter().map(|r| r.uri).collect())
        }
        VerifyResult::Invalid { reason } => Err(format!("Signature invalid: {reason}")),
    }
}

/// The single assertion the verified references cover, with its issuer checked.
fn covered_assertion(
    xml: &str,
    elements: &[Element],
    issuer: &str,
    reference_uris: &[String],
) -> Result<VerifiedAssertion> {
    let root = elements
        .iter()
        .position(|e| e.parent.is_none())
        .ok_or_else(|| invalid("SAML document has no root element"))?;
    let mut found: BTreeSet<usize> = BTreeSet::new();
    let mut signed_id = String::new();
    let mut response_signed = false;

    for uri in reference_uris {
        let signed = if uri.is_empty() {
            root
        } else if let Some(id) = uri.strip_prefix('#') {
            let mut holders = elements
                .iter()
                .enumerate()
                .filter(|(_, e)| e.id.as_deref() == Some(id))
                .map(|(i, _)| i);
            let (Some(first), None) = (holders.next(), holders.next()) else {
                return Err(invalid(format!(
                    "Signed reference '{uri}' does not name exactly one element"
                )));
            };
            signed_id = id.to_string();
            first
        } else {
            return Err(invalid(format!("Unsupported signature reference '{uri}'")));
        };
        match elements[signed].local.as_str() {
            "Assertion" => {
                found.insert(signed);
            }
            "Response" => {
                // A signed Response vouches for the assertions inside it.
                response_signed = true;
                found.extend(direct_children(elements, signed, "Assertion"));
            }
            _ => {}
        }
    }

    let mut found = found.into_iter();
    let (Some(assertion), None) = (found.next(), found.next()) else {
        return Err(invalid(
            "The signature must cover exactly one SAML assertion",
        ));
    };

    let assertion_issuer = direct_children(elements, assertion, "Issuer")
        .next()
        .and_then(|i| elements[i].text.as_deref())
        .ok_or_else(|| invalid("The signed assertion names no issuer"))?;
    if assertion_issuer != issuer {
        return Err(invalid(format!(
            "The signed assertion's issuer '{assertion_issuer}' is not the issuer the signing certificate is pinned for"
        )));
    }

    let e = &elements[assertion];
    Ok(VerifiedAssertion {
        issuer: issuer.to_string(),
        signed_id,
        assertion_xml: xml[e.start..e.end].to_string(),
        response_signed,
    })
}
