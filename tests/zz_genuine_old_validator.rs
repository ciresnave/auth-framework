#![cfg(feature = "saml")]
use auth_framework::methods::saml::SamlSignatureValidator;
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};

#[test]
fn old_validator_on_a_genuine_signature() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["idp".to_string()]).unwrap().self_signed(&key).unwrap();
    let template = r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>https://idp</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#_a1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"##;
    let kd = KeyData::from_pkcs8_der(kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256), &key.serialize_der()).unwrap();
    let mut km = KeysManager::new();
    km.add_key(Key::new(kd, KeyUsage::Sign));
    let signed = bergshamra::sign(&DsigContext::new(km), template).unwrap();
    let ok = SamlSignatureValidator.validate_xml_signature(&signed, cert.der()).unwrap();
    println!("OLD VALIDATOR ON A GENUINE SIGNATURE: {ok}");
    assert!(!ok);
}
