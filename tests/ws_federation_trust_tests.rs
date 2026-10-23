//! WS-Federation sign-in: a token is accepted only when its signature verifies under a key the
//! relying party configured (a pinned certificate for the issuer, or a pinned thumbprint of a
//! certificate the token carries), and only the signed assertion is read.
#![cfg(feature = "saml")]

use auth_framework::protocols::ws_federation::{WsFederationClient, WsFederationConfig};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://adfs.example/adfs/services/trust";
const REALM: &str = "https://app.example";

struct Sts {
    cert_der: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn sts() -> Sts {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["adfs.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Sts {
        cert_der: cert.der().to_vec(),
        pkcs8: key.serialize_der(),
    }
}

fn stamp(minutes: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(minutes))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

impl Sts {
    fn pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(&self.cert_der)
        )
    }

    fn thumbprint(&self) -> String {
        hex::encode(Sha256::digest(&self.cert_der))
    }

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

    fn signature(&self, id: &str) -> String {
        format!(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
            B64.encode(&self.cert_der)
        )
    }

    /// A SAML 2.0 RSTR for `name_id`, signed by this STS.
    fn rstr(&self, name_id: &str) -> String {
        wrap(&self.sign(&assertion20(name_id, Some(&self.signature("_a1")))))
    }

    /// A SAML 1.1 RSTR for `name_id`, signed by this STS.
    fn rstr11(&self, name_id: &str) -> String {
        let template = format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_a11" Issuer="{ISSUER}" IssueInstant="{now}">{sig}<saml:Conditions NotBefore="{before}" NotOnOrAfter="{after}"><saml:AudienceRestrictionCondition><saml:Audience>{REALM}</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="{now}"><saml:Subject><saml:NameIdentifier>{name_id}</saml:NameIdentifier></saml:Subject></saml:AuthenticationStatement></saml:Assertion>"#,
            now = stamp(0),
            before = stamp(-1),
            after = stamp(10),
            sig = self.signature("_a11"),
        );
        wrap(&self.sign(&template))
    }
}

fn assertion20(name_id: &str, signature: Option<&str>) -> String {
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{ISSUER}</saml:Issuer>{sig}<saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{after}"><saml:AudienceRestriction><saml:Audience>{REALM}</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#,
        id = if signature.is_some() { "_a1" } else { "_evil" },
        now = stamp(0),
        before = stamp(-1),
        after = stamp(10),
        sig = signature.unwrap_or_default(),
    )
}

fn wrap(assertion: &str) -> String {
    format!(
        r#"<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>{assertion}</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>"#
    )
}

fn client(trust: impl FnOnce(&mut WsFederationConfig)) -> WsFederationClient {
    let mut config = WsFederationConfig {
        sts_url: "https://adfs.example/adfs/ls".into(),
        realm: REALM.into(),
        reply_url: "https://app.example/auth/wsfed".into(),
        ..Default::default()
    };
    trust(&mut config);
    WsFederationClient::new(config).unwrap()
}

fn process(client: &WsFederationClient, rstr: &str) -> auth_framework::errors::Result<String> {
    let (_, wctx) = client.sign_in_url().unwrap();
    client
        .process_sign_in_response("wsignin1.0", rstr, Some(&wctx), &wctx)
        .map(|t| t.subject)
}

#[test]
fn a_client_with_nothing_to_trust_cannot_be_built() {
    let err = WsFederationClient::new(WsFederationConfig {
        sts_url: "https://adfs.example/adfs/ls".into(),
        realm: REALM.into(),
        ..Default::default()
    })
    .unwrap_err();
    assert!(
        err.to_string().contains("trusted signing certificate"),
        "{err}"
    );
}

#[test]
fn an_unsigned_hand_written_token_is_refused() {
    let sts = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), sts.pem())]);
    let unsigned = wrap(&assertion20("admin@example", None));
    assert!(process(&c, &unsigned).is_err());
}

#[test]
fn a_token_signed_under_the_pinned_certificate_is_accepted() {
    let sts = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), sts.pem())]);
    assert_eq!(
        process(&c, &sts.rstr("alice@example")).unwrap(),
        "alice@example"
    );
}

#[test]
fn a_saml_1_1_token_signed_under_the_pinned_certificate_is_accepted() {
    let sts = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), sts.pem())]);
    assert_eq!(
        process(&c, &sts.rstr11("alice@example")).unwrap(),
        "alice@example"
    );
}

#[test]
fn a_token_signed_by_its_own_unpinned_certificate_is_refused() {
    let pinned = sts();
    let attacker = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), pinned.pem())]);
    assert!(process(&c, &attacker.rstr("admin@example")).is_err());
}

#[test]
fn a_certificate_the_token_carries_is_used_only_if_its_thumbprint_is_pinned() {
    let sts = sts();
    let other = sts_other();
    let accepted = client(|c| c.trusted_cert_thumbprints = vec![sts.thumbprint()]);
    assert_eq!(
        process(&accepted, &sts.rstr("alice@example")).unwrap(),
        "alice@example"
    );

    let refused = client(|c| c.trusted_cert_thumbprints = vec![other.thumbprint()]);
    assert!(process(&refused, &sts.rstr("alice@example")).is_err());
}

fn sts_other() -> Sts {
    sts()
}

#[test]
fn an_unsigned_assertion_added_ahead_of_the_signed_one_is_never_read() {
    let sts = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), sts.pem())]);
    let forged = assertion20("admin@example", None);
    let signed = sts.sign(&assertion20("alice@example", Some(&sts.signature("_a1"))));
    let rstr = format!(
        r#"<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>{forged}{signed}</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>"#
    );
    // Accepted as alice, or refused: never admin.
    if let Ok(subject) = process(&c, &rstr) {
        assert_eq!(subject, "alice@example");
    }
}

#[test]
fn changing_a_signed_token_breaks_it() {
    let sts = sts();
    let c = client(|c| c.trusted_signing_certificates = vec![(ISSUER.into(), sts.pem())]);
    let tampered = sts
        .rstr("alice@example")
        .replace("alice@example", "admin@example");
    assert!(process(&c, &tampered).is_err());
}
