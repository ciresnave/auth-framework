//! The SAML assertion consumer endpoint (`/api/v1/saml/acs`): who is logged in is decided by the
//! assertion the IdP's signature covers, not by whichever assertion comes first in the document.
#![cfg(all(feature = "saml", feature = "api-server"))]

use auth_framework::api::ApiServer;
use auth_framework::{AuthConfig, AuthFramework};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bergshamra::{DsigContext, Key, KeyData, KeyUsage, KeysManager};
use std::sync::Arc;
use tower::ServiceExt;

const IDP: &str = "https://idp.example.com";
const SP: &str = "https://sp.example.com";

struct Signer {
    cert_der: Vec<u8>,
    pkcs8: Vec<u8>,
}

fn signer() -> Signer {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["idp.example.com".to_string()])
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
}

fn now_plus(minutes: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(minutes))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

const SIGNATURE: &str = r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#ID"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue></ds:Signature>"##;

/// An assertion for `name_id`, answering the request `in_response_to`. `signed` leaves a signature
/// template in it for the IdP to fill.
fn assertion(id: &str, name_id: &str, in_response_to: &str, signed: bool) -> String {
    let signature = if signed {
        SIGNATURE.replace("#ID", &format!("#{id}"))
    } else {
        String::new()
    };
    format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issued}"><saml:Issuer>{IDP}</saml:Issuer>{signature}<saml:Subject><saml:NameID>{name_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{after}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{before}" NotOnOrAfter="{after}"><saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#,
        issued = now_plus(0),
        before = now_plus(-1),
        after = now_plus(4),
    )
}

/// An unsigned Response wrapper (as most IdPs send when they sign only the assertion).
fn response(wrapper_in_response_to: &str, inner: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp" Version="2.0" InResponseTo="{wrapper_in_response_to}" IssueInstant="{issued}"><saml:Issuer>{IDP}</saml:Issuer>{inner}</samlp:Response>"#,
        issued = now_plus(0)
    )
}

/// An app that trusts `idp`'s certificate, with `pending` AuthnRequest ids outstanding.
async fn app(idp: &Signer, pending: &[&str]) -> axum::Router {
    let framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    let storage = framework.storage();
    storage
        .store_kv(
            "saml_sp:config",
            serde_json::json!({
                "entity_id": SP,
                "acs_url": "https://sp.example.com/api/saml/acs",
            })
            .to_string()
            .as_bytes(),
            None,
        )
        .await
        .unwrap();
    storage
        .store_kv(
            &format!("saml_idp:{IDP}"),
            serde_json::json!({ "entity_id": IDP, "signing_cert": idp.pem() })
                .to_string()
                .as_bytes(),
            None,
        )
        .await
        .unwrap();
    for id in pending {
        storage
            .store_kv(&format!("saml_request:{id}"), b"1", None)
            .await
            .unwrap();
    }
    ApiServer::new(framework)
        .build_router()
        .await
        .expect("router for tests")
}

/// POST the response to the ACS and return `(status, JSON body)`.
async fn post_acs(app: axum::Router, xml: &str) -> (StatusCode, serde_json::Value) {
    let body = format!("SAMLResponse={}", urlencoding::encode(&B64.encode(xml)));
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/saml/acs")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn a_genuine_assertion_logs_the_signed_user_in() {
    let idp = signer();
    let signed = idp.sign(&assertion("_a1", "alice@idp", "req1", true));
    let (_, body) = post_acs(app(&idp, &["req1"]).await, &response("req1", &signed)).await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["data"]["user_id"], "alice@idp");
}

#[tokio::test]
async fn an_assertion_signed_by_some_other_key_is_refused() {
    let idp = signer();
    let attacker = signer();
    let forged = attacker.sign(&assertion("_a1", "admin@idp", "req1", true));
    let (_, body) = post_acs(app(&idp, &["req1"]).await, &response("req1", &forged)).await;
    assert_eq!(body["success"], false, "{body}");
    assert!(
        body.to_string().contains("SAML_SIGNATURE_INVALID"),
        "{body}"
    );
}

#[tokio::test]
async fn a_forged_assertion_placed_ahead_of_the_signed_one_does_not_log_anyone_in_as_admin() {
    let idp = signer();
    let signed = idp.sign(&assertion("_a1", "alice@idp", "req1", true));
    let forged = assertion("_evil", "admin@idp", "req1", false);
    let wrapped = response("req1", &format!("{forged}{signed}"));
    assert!(wrapped.find("admin@idp").unwrap() < wrapped.find("alice@idp").unwrap());

    let (_, body) = post_acs(app(&idp, &["req1"]).await, &wrapped).await;
    assert!(
        !body.to_string().contains("admin@idp"),
        "the forged assertion was consumed: {body}"
    );
    // The signed one is what is read.
    assert_eq!(body["data"]["user_id"], "alice@idp", "{body}");
}

#[tokio::test]
async fn the_wrapper_cannot_redirect_a_signed_assertion_to_another_pending_request() {
    // A genuine assertion that answered someone else's request ("victim"), replayed under a
    // Response wrapper that claims it answers the attacker's own pending request. The wrapper is
    // not signed, so only the assertion's own InResponseTo counts.
    let idp = signer();
    let signed = idp.sign(&assertion("_a1", "alice@idp", "victim", true));
    let (_, body) = post_acs(
        app(&idp, &["attacker_req"]).await,
        &response("attacker_req", &signed),
    )
    .await;
    assert_eq!(body["success"], false, "{body}");
    assert!(body.to_string().contains("SAML_INVALID_RESPONSE"), "{body}");
}

#[tokio::test]
async fn sso_is_not_started_for_an_idp_without_a_pinned_certificate() {
    let idp = signer();
    // The IdP is registered, but with no signing certificate: its responses could never be verified.
    let framework = Arc::new(AuthFramework::new(AuthConfig::default()));
    let storage = framework.storage();
    storage
        .store_kv(
            "saml_sp:config",
            serde_json::json!({ "entity_id": SP, "acs_url": "https://sp.example.com/api/saml/acs" })
                .to_string()
                .as_bytes(),
            None,
        )
        .await
        .unwrap();
    for (entity, config) in [
        (
            "https://nocert.example",
            serde_json::json!({ "sso_url": "https://nocert.example/sso" }),
        ),
        (
            "https://emptycert.example",
            serde_json::json!({ "sso_url": "https://emptycert.example/sso", "signing_cert": "" }),
        ),
        (
            "https://badcert.example",
            serde_json::json!({ "sso_url": "https://badcert.example/sso", "signing_cert": "not a certificate" }),
        ),
        (
            "https://good.example",
            serde_json::json!({ "sso_url": "https://good.example/sso", "signing_cert": idp.pem() }),
        ),
    ] {
        storage
            .store_kv(
                &format!("saml_idp:{entity}"),
                config.to_string().as_bytes(),
                None,
            )
            .await
            .unwrap();
    }
    let app = ApiServer::new(framework).build_router().await.unwrap();

    for (entity, usable) in [
        ("https://nocert.example", false),
        ("https://emptycert.example", false),
        ("https://badcert.example", false),
        ("https://good.example", true),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/saml/sso")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "idp_entity_id": entity }).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["success"], usable, "{entity}: {body}");
        if !usable {
            assert!(
                body.to_string().contains("SAML_CONFIG_ERROR"),
                "{entity}: {body}"
            );
        }
    }
}
