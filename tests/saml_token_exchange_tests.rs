//! Token exchange with a SAML subject token: the assertion is accepted only when it is signed by a
//! key configured for its issuer. A key the token carries itself is not a source of trust.
#![cfg(feature = "saml")]

use auth_framework::server::token_exchange::core::TokenType;
use auth_framework::server::token_exchange::{
    TokenExchangeManager, TokenExchangePolicy, TokenExchangeRequest,
};
use auth_framework::{SecureJwtConfig, SecureJwtValidator};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};

const IDP: &str = "https://idp.example/metadata";

struct Signer {
    cert_der: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn signer() -> Signer {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["idp.example".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Signer {
        cert_der: cert.der().to_vec(),
        pkcs8: key.serialize_der(),
    }
}

impl Signer {
    fn pem(&self) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(&self.cert_der)
        )
    }

    /// A SAML 2.0 assertion for `name_id`, issued now, signed with this key, carrying this key's
    /// certificate in its own `KeyInfo` (as most IdPs' assertions do).
    fn assertion(&self, name_id: &str) -> String {
        let now = chrono::Utc::now();
        let template = format!(
            r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="{issued}"><saml:Issuer>{IDP}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#_a1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID>{name_id}</saml:NameID></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{after}"/></saml:Assertion>"##,
            issued = now.format("%Y-%m-%dT%H:%M:%SZ"),
            before = (now - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ"),
            after = (now + chrono::Duration::minutes(4)).format("%Y-%m-%dT%H:%M:%SZ"),
            cert = B64.encode(&self.cert_der),
        );
        let key = KeyData::from_pkcs8_der(
            kryptering::KeyAlgorithm::Ec(kryptering::EcCurve::P256),
            &self.pkcs8,
        )
        .unwrap();
        let mut keys = KeysManager::new();
        keys.add_key(Key::new(key, KeyUsage::Sign));
        bergshamra::sign(&DsigContext::new(keys), &template).unwrap()
    }
}

fn manager() -> TokenExchangeManager {
    TokenExchangeManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap())
}

async fn with_saml_allowed(manager: TokenExchangeManager) -> TokenExchangeManager {
    manager
        .register_policy(
            "client".to_string(),
            TokenExchangePolicy::builder()
                .subject_token_types(vec![TokenType::Saml2])
                .require_actor_for_delegation(false)
                .build(),
        )
        .await;
    manager
}

fn request(assertion: &str) -> TokenExchangeRequest {
    TokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: B64.encode(assertion),
        subject_token_type: "urn:ietf:params:oauth:token-type:saml2".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        audience: None,
        scope: None,
        resource: None,
    }
}

#[tokio::test]
async fn an_assertion_signed_by_its_own_embedded_key_is_refused() {
    // The forger holds a key pair of their own, signs an assertion for the victim's admin, and
    // embeds their certificate. Nothing about the victim's IdP is configured to match it.
    let attacker = signer();
    let victim = signer();
    let forged = attacker.assertion("admin@victim");

    let unconfigured = with_saml_allowed(manager()).await;
    let err = unconfigured
        .exchange_token(request(&forged), "client")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("SAML"), "{err}");

    let configured = with_saml_allowed(
        manager()
            .with_trusted_saml_issuer(IDP, &victim.pem())
            .unwrap(),
    )
    .await;
    let err = configured
        .exchange_token(request(&forged), "client")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("SAML signature validation failed"),
        "{err}"
    );
}

#[tokio::test]
async fn with_no_trusted_issuer_a_genuine_assertion_is_refused_too() {
    // Fail closed: a deployment that has configured nothing accepts nothing.
    let idp = signer();
    let unconfigured = with_saml_allowed(manager()).await;
    let err = unconfigured
        .exchange_token(request(&idp.assertion("alice@idp")), "client")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("No trusted SAML issuer"), "{err}");
}

#[tokio::test]
async fn a_genuine_assertion_from_the_configured_issuer_is_exchanged() {
    let idp = signer();
    let configured =
        with_saml_allowed(manager().with_trusted_saml_issuer(IDP, &idp.pem()).unwrap()).await;
    let response = configured
        .exchange_token(request(&idp.assertion("alice@idp")), "client")
        .await
        .expect("a genuine assertion from the configured issuer is accepted");
    assert!(!response.access_token.is_empty());
}

#[tokio::test]
async fn changing_the_subject_of_a_genuine_assertion_breaks_it() {
    let idp = signer();
    let configured =
        with_saml_allowed(manager().with_trusted_saml_issuer(IDP, &idp.pem()).unwrap()).await;
    let tampered = idp.assertion("alice@idp").replace("alice@idp", "admin@idp");
    let err = configured
        .exchange_token(request(&tampered), "client")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("SAML signature validation failed"),
        "{err}"
    );
}
