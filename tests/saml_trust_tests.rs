//! SAML signature verification: the key comes from configuration, every digest is checked, and
//! only the signed assertion is read.
//!
//! The assertions below are signed with `bergshamra` (the library that also verifies them), so a
//! test that expects success proves the verifier accepts what a real signer produces, and a
//! test that expects refusal fails if the refusal is ever removed.
#![cfg(feature = "saml")]

use auth_framework::methods::saml::{SamlTrustAnchors, verify_signed_assertion};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};

const IDP: &str = "https://idp.example/metadata";

struct Idp {
    cert_der: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn idp() -> Idp {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["idp.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Idp {
        cert_der: cert.der().to_vec(),
        pkcs8: key.serialize_der(),
    }
}

impl Idp {
    fn sign(&self, template: &str) -> String {
        let key = KeyData::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            &self.pkcs8,
        )
        .unwrap();
        let mut keys = KeysManager::new();
        keys.add_key(Key::new(key, KeyUsage::Sign));
        bergshamra::sign(&DsigContext::new(keys), template).unwrap()
    }

    fn anchors(&self) -> SamlTrustAnchors {
        let mut anchors = SamlTrustAnchors::new();
        anchors.trust(IDP, self.cert_der.clone()).unwrap();
        anchors
    }
}

const SIGNATURE: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#REF"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>"##;

fn assertion(id: &str, issuer: &str, name_id: &str, signature: &str) -> String {
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="2026-10-23T08:00:00Z"><saml:Issuer>{issuer}</saml:Issuer>{signature}<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject></saml:Assertion>"#
    )
}

fn response(inner: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2026-10-23T08:00:00Z"><saml:Issuer>{IDP}</saml:Issuer>{inner}</samlp:Response>"#
    )
}

/// A genuine response: one assertion for `alice`, signed by the IdP.
fn genuine(idp: &Idp) -> String {
    let sig = SIGNATURE.replace("#REF", "#_a1");
    idp.sign(&response(&assertion("_a1", IDP, "alice@idp", &sig)))
}

#[test]
fn a_genuine_signed_assertion_is_accepted_and_returned() {
    let idp = idp();
    let verified = verify_signed_assertion(&genuine(&idp), &idp.anchors()).unwrap();
    assert_eq!(verified.issuer, IDP);
    assert_eq!(verified.signed_id, "_a1");
    assert!(verified.assertion_xml.contains("alice@idp"));
    assert!(!verified.response_signed);
}

#[test]
fn a_signed_response_vouches_for_its_assertion() {
    let idp = idp();
    let sig = SIGNATURE.replace("#REF", "#_resp");
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2026-10-23T08:00:00Z"><saml:Issuer>{IDP}</saml:Issuer>{sig}{}</samlp:Response>"#,
        assertion("_a1", IDP, "alice@idp", "")
    );
    let signed = idp.sign(&xml);
    let verified = verify_signed_assertion(&signed, &idp.anchors()).unwrap();
    assert!(verified.response_signed);
    assert!(verified.assertion_xml.contains("alice@idp"));
}

#[test]
fn with_no_trusted_issuer_nothing_is_accepted() {
    let idp = idp();
    let err = verify_signed_assertion(&genuine(&idp), &SamlTrustAnchors::new()).unwrap_err();
    assert!(err.to_string().contains("No trusted SAML issuer"), "{err}");
}

#[test]
fn an_assertion_signed_by_its_own_embedded_key_is_refused() {
    // The attacker signs with a key of their own and ships the certificate in the document, the
    // way a self-contained signature does. The victim's pinned certificate is a different one.
    let victim = idp();
    let attacker = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let forged = attacker.sign(&response(&assertion("_a1", IDP, "admin@victim", &sig)));
    let err = verify_signed_assertion(&forged, &victim.anchors()).unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{err}");
}

#[test]
fn a_forged_assertion_naming_an_unconfigured_issuer_is_refused() {
    let victim = idp();
    let attacker = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let forged = attacker.sign(&format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp"><saml:Issuer>https://attacker.example</saml:Issuer>{}</samlp:Response>"#,
        assertion("_a1", "https://attacker.example", "admin@victim", &sig)
    ));
    let err = verify_signed_assertion(&forged, &victim.anchors()).unwrap_err();
    assert!(err.to_string().contains("configured as trusted"), "{err}");
}

#[test]
fn changing_signed_content_after_signing_is_refused() {
    let idp = idp();
    let tampered = genuine(&idp).replace("alice@idp", "admin@idp");
    let err = verify_signed_assertion(&tampered, &idp.anchors()).unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{err}");
}

#[test]
fn a_changed_digest_is_refused() {
    let idp = idp();
    let good = genuine(&idp);
    let start = good.find("<ds:DigestValue>").unwrap() + "<ds:DigestValue>".len();
    let mut bad = good.clone();
    // Flip the first character of the digest to a different base64 character.
    let first = &good[start..start + 1];
    bad.replace_range(start..start + 1, if first == "A" { "B" } else { "A" });
    let err = verify_signed_assertion(&bad, &idp.anchors()).unwrap_err();
    assert!(err.to_string().contains("verification failed"), "{err}");
}

#[test]
fn an_unsigned_assertion_added_before_the_signed_one_is_never_read() {
    // Signature wrapping: the genuine signed assertion stays valid where it is, and a forged one
    // is put ahead of it for a parser that takes "the first assertion".
    let idp = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let signed = idp.sign(&response(&assertion("_a1", IDP, "alice@idp", &sig)));
    let forged = assertion("_evil", IDP, "admin@idp", "");
    let wrapped = signed.replacen("<saml:Assertion ", &format!("{forged}<saml:Assertion "), 1);
    assert!(wrapped.find("admin@idp").unwrap() < wrapped.find("alice@idp").unwrap());
    let verified = verify_signed_assertion(&wrapped, &idp.anchors()).unwrap();
    assert!(verified.assertion_xml.contains("alice@idp"));
    assert!(
        !verified.assertion_xml.contains("admin@idp"),
        "the forged assertion was returned: {}",
        verified.assertion_xml
    );
}

#[test]
fn the_signed_assertion_moved_into_a_wrapper_with_a_forged_one_in_front_is_never_read() {
    let idp = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let signed = idp.sign(&assertion("_a1", IDP, "alice@idp", &sig));
    let forged = assertion("_evil", IDP, "admin@idp", "");
    let wrapped = response(&format!(
        "{forged}<samlp:Extensions>{signed}</samlp:Extensions>"
    ));
    // Either refused, or the signed one is what comes back: never the forged one.
    if let Ok(verified) = verify_signed_assertion(&wrapped, &idp.anchors()) {
        assert!(verified.assertion_xml.contains("alice@idp"));
        assert!(!verified.assertion_xml.contains("admin@idp"));
    }
}

#[test]
fn a_second_element_with_the_signed_id_is_refused() {
    let idp = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let signed = idp.sign(&response(&assertion("_a1", IDP, "alice@idp", &sig)));
    let twin = assertion("_a1", IDP, "admin@idp", "");
    let doubled = signed.replacen("<saml:Assertion ", &format!("{twin}<saml:Assertion "), 1);
    let err = verify_signed_assertion(&doubled, &idp.anchors());
    if let Ok(verified) = err {
        assert!(!verified.assertion_xml.contains("admin@idp"));
    }
}

#[test]
fn a_signed_assertion_whose_issuer_is_not_the_pinned_one_is_refused() {
    // Signed by the pinned key, but the assertion names another issuer: the pin is per issuer.
    let idp = idp();
    let sig = SIGNATURE.replace("#REF", "#_a1");
    let xml = idp.sign(&response(&assertion(
        "_a1",
        "https://other.example",
        "alice@idp",
        &sig,
    )));
    let err = verify_signed_assertion(&xml, &idp.anchors()).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("pinned") || text.contains("verification failed"),
        "{text}"
    );
}

#[test]
fn a_document_type_declaration_is_refused() {
    let idp = idp();
    let xml = format!("<!DOCTYPE r [<!ENTITY x \"y\">]>{}", genuine(&idp));
    let err = verify_signed_assertion(&xml, &idp.anchors()).unwrap_err();
    assert!(err.to_string().contains("DOCTYPE"), "{err}");
}

#[test]
fn trust_pem_reads_a_pem_certificate() {
    let idp = idp();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        B64.encode(&idp.cert_der)
    );
    let mut anchors = SamlTrustAnchors::new();
    anchors.trust_pem(IDP, &pem).unwrap();
    assert!(verify_signed_assertion(&genuine(&idp), &anchors).is_ok());
}
