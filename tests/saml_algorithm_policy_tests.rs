//! `SamlAlgorithmPolicy`: an opt-in refusal of SHA-1 signatures and digests, applied to the
//! signature that verified, not to any signature in the document.
//!
//! Assertions are signed with `bergshamra`. Its AWS-LC backend signs no SHA-1 signature
//! (`ecdsa-sha1`, `rsa-sha1`: "aws-lc does not support Sign(..Sha1)", probed), so the end-to-end
//! documents here use a SHA-256 signature over a SHA-1 digest, which it does sign and verify;
//! the `SignatureMethod` side of the policy is covered by unit tests in `dsig.rs`. Each refusal is
//! paired with the accepted case built the same way, so a test cannot pass because every
//! document fails for one shared reason, and the default policy (SHA-1 accepted) is pinned too.
#![cfg(feature = "saml")]

use auth_framework::methods::saml::{
    SamlAlgorithmPolicy, SamlTrustAnchors, verify_signed_assertion,
};
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};

const IDP: &str = "https://idp.example/metadata";
const SIG_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

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

    fn anchors(&self, policy: SamlAlgorithmPolicy) -> SamlTrustAnchors {
        let mut anchors = SamlTrustAnchors::new().with_algorithm_policy(policy);
        anchors.trust(IDP, self.cert_der.clone()).unwrap();
        anchors
    }
}

const REFUSE_SHA1: SamlAlgorithmPolicy = SamlAlgorithmPolicy { allow_sha1: false };

fn signature(reference: &str, signature_method: &str, digest_method: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="{signature_method}"/><ds:Reference URI="#{reference}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="{digest_method}"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>"##
    )
}

fn assertion(id: &str, name_id: &str, signature: &str) -> String {
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="2026-10-23T08:00:00Z"><saml:Issuer>{IDP}</saml:Issuer>{signature}<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject></saml:Assertion>"#
    )
}

fn response(inner: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" IssueInstant="2026-10-23T08:00:00Z"><saml:Issuer>{IDP}</saml:Issuer>{inner}</samlp:Response>"#
    )
}

/// A response with one assertion for `alice`, signed with the given algorithms.
fn signed_with(idp: &Idp, signature_method: &str, digest_method: &str) -> String {
    let sig = signature("_a1", signature_method, digest_method);
    idp.sign(&response(&assertion("_a1", "alice@idp", &sig)))
}

fn refusal(result: auth_framework::errors::Result<impl std::fmt::Debug>) -> String {
    result
        .expect_err("the document must be refused")
        .to_string()
}

#[test]
fn the_default_policy_accepts_sha256_and_sha1() {
    let idp = idp();
    let default = SamlAlgorithmPolicy::default();
    assert!(default.allow_sha1);
    for (name, doc) in [
        ("sha256", signed_with(&idp, SIG_SHA256, DIGEST_SHA256)),
        (
            "sha256 signature, sha1 digest",
            signed_with(&idp, SIG_SHA256, DIGEST_SHA1),
        ),
    ] {
        let verified = verify_signed_assertion(&doc, &idp.anchors(default))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(verified.assertion_xml.contains("alice@idp"), "{name}");
    }
}

#[test]
fn refusing_sha1_still_accepts_sha256() {
    let idp = idp();
    let doc = signed_with(&idp, SIG_SHA256, DIGEST_SHA256);
    let verified = verify_signed_assertion(&doc, &idp.anchors(REFUSE_SHA1)).unwrap();
    assert!(verified.assertion_xml.contains("alice@idp"));
}

#[test]
fn refusing_sha1_refuses_a_sha1_digest() {
    let idp = idp();
    let doc = signed_with(&idp, SIG_SHA256, DIGEST_SHA1);
    // The same document is valid under the default policy: only the policy refuses it.
    verify_signed_assertion(&doc, &idp.anchors(SamlAlgorithmPolicy::default())).unwrap();
    let message = refusal(verify_signed_assertion(&doc, &idp.anchors(REFUSE_SHA1)));
    assert!(message.contains("SHA-1"), "{message}");
}

/// Two signed assertions in one response; `first` is the one verification reads and returns.
fn two_signed(idp: &Idp, first: (&str, &str), second: (&str, &str)) -> String {
    let a = assertion("_a1", "alice@idp", &signature("_a1", first.0, first.1));
    let b = assertion("_a2", "mallory@idp", &signature("_a2", second.0, second.1));
    idp.sign(&response(&format!("{a}{b}")))
}

#[test]
fn a_sha256_decoy_does_not_hide_a_sha1_signature() {
    let idp = idp();
    let doc = two_signed(&idp, (SIG_SHA256, DIGEST_SHA1), (SIG_SHA256, DIGEST_SHA256));
    // Control: under the default policy the first assertion is what comes back.
    let verified =
        verify_signed_assertion(&doc, &idp.anchors(SamlAlgorithmPolicy::default())).unwrap();
    assert!(verified.assertion_xml.contains("alice@idp"));
    // The signature that verified is the SHA-1 one, so the policy refuses, whatever else is in
    // the document.
    let message = refusal(verify_signed_assertion(&doc, &idp.anchors(REFUSE_SHA1)));
    assert!(message.contains("SHA-1"), "{message}");
}

#[test]
fn a_sha1_decoy_does_not_trip_the_policy_for_a_sha256_signature() {
    let idp = idp();
    let doc = two_signed(&idp, (SIG_SHA256, DIGEST_SHA256), (SIG_SHA256, DIGEST_SHA1));
    let verified =
        verify_signed_assertion(&doc, &idp.anchors(SamlAlgorithmPolicy::default())).unwrap();
    assert!(verified.assertion_xml.contains("alice@idp"));
    // The policy looks at the signature over the assertion that is consumed, not at the other
    // one: the document is accepted and the consumed assertion is alice's.
    let verified = verify_signed_assertion(&doc, &idp.anchors(REFUSE_SHA1)).unwrap();
    assert!(verified.assertion_xml.contains("alice@idp"));
    assert!(!verified.assertion_xml.contains("mallory@idp"));
}

#[test]
fn a_signature_wrapped_into_an_extension_keeps_the_policy_in_force() {
    // The SHA-1 signed assertion is moved inside an Extensions element, with a SHA-256 signed
    // one in front. Whatever verification returns must pass the policy; here, the SHA-1 signed
    // assertion is never returned under a policy that refuses SHA-1.
    let idp = idp();
    let real = idp.sign(&assertion(
        "_a1",
        "alice@idp",
        &signature("_a1", SIG_SHA256, DIGEST_SHA1),
    ));
    let decoy = idp.sign(&assertion(
        "_a2",
        "mallory@idp",
        &signature("_a2", SIG_SHA256, DIGEST_SHA256),
    ));
    let wrapped = response(&format!(
        "{decoy}<samlp:Extensions>{real}</samlp:Extensions>"
    ));
    if let Ok(verified) = verify_signed_assertion(&wrapped, &idp.anchors(REFUSE_SHA1)) {
        assert!(
            !verified.assertion_xml.contains("alice@idp"),
            "a SHA-1 signed assertion was accepted under a policy that refuses SHA-1"
        );
    }
}

#[test]
fn extending_anchors_never_relaxes_the_policy() {
    let idp = idp();
    let mut strict = idp.anchors(REFUSE_SHA1);
    strict.extend(idp.anchors(SamlAlgorithmPolicy::default()));
    assert!(!strict.algorithm_policy().allow_sha1);
    let doc = signed_with(&idp, SIG_SHA256, DIGEST_SHA1);
    assert!(refusal(verify_signed_assertion(&doc, &strict)).contains("SHA-1"));
}
