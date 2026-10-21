//! `PasskeyAuthMethod` verifies the credentials the `passkey` crates really produce.
//!
//! The method's verification code read the assertion as base64url text and found the public key at a JSON
//! path the serialized credential does not have, so no genuine credential could ever authenticate. These
//! tests use a credential and an assertion recorded with `passkey` 0.5.0
//! (`tests/fixtures/passkey_wire_format.json`, serialized with byte arrays) and live ceremonies.
#![cfg(feature = "passkeys")]

use auth_framework::methods::passkey::{PasskeyAuthMethod, PasskeyConfig};
use auth_framework::tokens::TokenManager;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/passkey_wire_format.json"))
        .expect("fixture is JSON")
}

fn method() -> PasskeyAuthMethod {
    let config = PasskeyConfig {
        rp_id: "example.com".to_string(),
        rp_name: "Test App".to_string(),
        origin: "https://example.com".to_string(),
        timeout_ms: 60000,
        user_verification: "preferred".to_string(),
        authenticator_attachment: None,
        require_resident_key: false,
        ..Default::default()
    };
    PasskeyAuthMethod::new(
        config,
        TokenManager::new_hmac(b"test-secret", "test-issuer", "test-audience"),
    )
    .expect("passkeys feature is on")
}

fn bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Array(a) => a.iter().map(|b| b.as_u64().unwrap() as u8).collect(),
        Value::String(s) => URL_SAFE_NO_PAD.decode(s).expect("base64url"),
        other => panic!("not a byte field: {other}"),
    }
}

/// The recorded P-256 key as the JWK the verifier takes (the last 64 bytes of the SPKI are x and y).
fn recorded_jwk() -> Value {
    let spki = bytes(&fixture()["credential"]["response"]["publicKey"]);
    let xy = &spki[spki.len() - 64..];
    json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(&xy[..32]),
        "y": URL_SAFE_NO_PAD.encode(&xy[32..]),
    })
}

fn recorded_challenge() -> Vec<u8> {
    (100u8..132).collect()
}

/// The recorded assertion with its byte fields written as base64url text.
fn assertion_as_text() -> Value {
    let mut a = fixture()["assertion"].clone();
    for field in ["clientDataJSON", "authenticatorData", "signature"] {
        let b = bytes(&a["response"][field]);
        a["response"][field] = Value::String(URL_SAFE_NO_PAD.encode(b));
    }
    a
}

/// An assertion serialized with byte arrays (what `passkey-types` writes by default) verifies.
#[tokio::test]
async fn a_recorded_assertion_with_byte_arrays_verifies() {
    let m = method();
    let result = m
        .advanced_verification_flow(
            &fixture()["assertion"].to_string(),
            &recorded_challenge(),
            0,
            &recorded_jwk(),
        )
        .await
        .expect("a genuine assertion verifies");
    assert!(result.signature_valid && result.user_present);
}

/// The same assertion written as base64url text (the WebAuthn JSON form) verifies too.
#[tokio::test]
async fn a_recorded_assertion_with_base64url_text_verifies() {
    let m = method();
    let result = m
        .advanced_verification_flow(
            &assertion_as_text().to_string(),
            &recorded_challenge(),
            0,
            &recorded_jwk(),
        )
        .await
        .expect("the text form verifies");
    assert!(result.signature_valid);
}

/// Bad input still fails, in both forms: a wrong challenge, a flipped signature byte, another key.
#[tokio::test]
async fn bad_assertions_are_rejected_in_both_forms() {
    let m = method();
    for assertion in [fixture()["assertion"].clone(), assertion_as_text()] {
        let mut wrong_challenge = recorded_challenge();
        wrong_challenge[0] ^= 0xff;
        assert!(
            m.advanced_verification_flow(
                &assertion.to_string(),
                &wrong_challenge,
                0,
                &recorded_jwk()
            )
            .await
            .is_err(),
            "wrong challenge accepted"
        );

        let mut tampered = assertion.clone();
        let mut sig = bytes(&tampered["response"]["signature"]);
        let last = sig.len() - 1;
        sig[last] ^= 0xff;
        tampered["response"]["signature"] = if assertion["response"]["signature"].is_array() {
            json!(sig)
        } else {
            Value::String(URL_SAFE_NO_PAD.encode(sig))
        };
        assert!(
            m.advanced_verification_flow(
                &tampered.to_string(),
                &recorded_challenge(),
                0,
                &recorded_jwk()
            )
            .await
            .is_err(),
            "tampered signature accepted"
        );

        let mut other_key = recorded_jwk();
        other_key["x"] = Value::String(URL_SAFE_NO_PAD.encode([7u8; 32]));
        assert!(
            m.advanced_verification_flow(
                &assertion.to_string(),
                &recorded_challenge(),
                0,
                &other_key
            )
            .await
            .is_err(),
            "another key accepted"
        );
    }
}

use passkey::authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
use passkey::client::Client;
use passkey::crypto::rust_crypto::RustCryptoBackend;
use passkey::types::{
    Bytes, Passkey,
    ctap2::{Aaguid, Ctap2Error},
    webauthn::{
        AttestationConveyancePreference, AuthenticatedPublicKeyCredential,
        CreatedPublicKeyCredential, CredentialCreationOptions, PublicKeyCredentialCreationOptions,
        PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        PublicKeyCredentialUserEntity,
    },
};
use passkey_client::DefaultClientData;
use url::Url;

struct Verified;

#[async_trait::async_trait]
impl UserValidationMethod for Verified {
    type PasskeyItem = Passkey;
    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Passkey>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence,
            verification,
        })
    }
    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
    fn is_presence_enabled(&self) -> bool {
        true
    }
}

fn creation_options() -> CredentialCreationOptions {
    CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: None,
                name: "Test App".into(),
            },
            user: PublicKeyCredentialUserEntity {
                id: Bytes::from(b"user-1".to_vec()),
                display_name: "User One".into(),
                name: "user1".into(),
            },
            challenge: Bytes::from((0u8..32).collect::<Vec<u8>>()),
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: coset::iana::Algorithm::ES256,
            }],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: AttestationConveyancePreference::Direct,
            attestation_formats: None,
            extensions: None,
        },
    }
}

fn recorded_credential() -> CreatedPublicKeyCredential {
    serde_json::from_value(fixture()["credential"].clone()).expect("recorded credential")
}

/// Registering a recorded credential stores its public key as a usable JWK and its sign count, and the
/// recorded assertion verifies against what was stored.
#[tokio::test]
async fn a_registered_credential_stores_a_usable_public_key() {
    let mut m = method();
    let credential = recorded_credential();
    m.register_credential("user-1", "user1", "User One", &credential)
        .expect("a genuine credential registers");
    let registration = m
        .registered_passkey(credential.raw_id.as_slice())
        .expect("the registration is kept");
    let data: Value = serde_json::from_str(&registration.passkey_data).unwrap();
    assert_eq!(data["public_key"], recorded_jwk(), "{data}");
    assert_eq!(data["signature_counter"], 0);

    let result = m
        .advanced_verification_flow(
            &fixture()["assertion"].to_string(),
            &recorded_challenge(),
            data["signature_counter"].as_u64().unwrap() as u32,
            &data["public_key"],
        )
        .await
        .expect("verifies against the stored key");
    assert!(result.signature_valid);
}

/// A credential whose public key is missing, malformed or of another type is refused, not stored.
#[tokio::test]
async fn a_credential_without_a_usable_public_key_is_refused() {
    let mut m = method();
    let good = fixture()["credential"].clone();
    for (name, mutate) in [
        ("empty key", json!([])),
        ("garbage key", json!(vec![0u8; 91])),
        ("truncated key", json!(vec![0x30u8, 0x59, 0x30])),
    ] {
        let mut c = good.clone();
        c["response"]["publicKey"] = mutate;
        let credential: CreatedPublicKeyCredential = serde_json::from_value(c).unwrap();
        assert!(
            m.register_credential("user-1", "user1", "User One", &credential)
                .is_err(),
            "{name} was accepted"
        );
        assert!(
            m.registered_passkey(credential.raw_id.as_slice()).is_none(),
            "{name} was stored"
        );
    }
    let mut c = good.clone();
    c["response"]["publicKeyAlgorithm"] = json!(-8);
    let credential: CreatedPublicKeyCredential = serde_json::from_value(c).unwrap();
    assert!(
        m.register_credential("user-1", "user1", "User One", &credential)
            .is_err(),
        "an unsupported algorithm was accepted"
    );
}

/// A real registration and a real assertion from the `passkey` client authenticate the user once; the
/// same assertion cannot be replayed, and a tampered or unknown one is refused.
#[tokio::test]
async fn a_live_ceremony_authenticates_once() {
    let origin = Url::parse("https://example.com").unwrap();
    let mut client = Client::new(Authenticator::new(
        Aaguid::new_empty(),
        None::<Passkey>,
        Verified,
        RustCryptoBackend,
    ));
    let credential = client
        .register(&origin, creation_options(), DefaultClientData)
        .await
        .expect("registration");
    let mut m = method();
    m.register_credential("user-1", "user1", "User One", &credential)
        .expect("registers");

    let options = m.initiate_authentication(Some("user-1")).await.unwrap();
    let assertion = client
        .authenticate(&origin, options, DefaultClientData)
        .await
        .expect("assertion");

    // A tampered signature is refused (and spends the challenge).
    let mut tampered: Value = serde_json::to_value(&assertion).unwrap();
    let mut sig = bytes(&tampered["response"]["signature"]);
    let last = sig.len() - 1;
    sig[last] ^= 0xff;
    tampered["response"]["signature"] = json!(sig);
    let tampered: AuthenticatedPublicKeyCredential = serde_json::from_value(tampered).unwrap();
    assert!(m.complete_authentication(&tampered).await.is_err());

    // A fresh challenge and a genuine assertion succeed.
    let options = m.initiate_authentication(Some("user-1")).await.unwrap();
    let assertion = client
        .authenticate(&origin, options, DefaultClientData)
        .await
        .expect("assertion");
    let token = m
        .complete_authentication(&assertion)
        .await
        .expect("a genuine assertion authenticates");
    assert_eq!(token.user_id, "user-1");

    // Replaying it fails: the challenge was single use.
    assert!(
        m.complete_authentication(&assertion).await.is_err(),
        "an assertion was accepted twice"
    );

    // An assertion for a credential this method never registered is refused.
    let mut other = method();
    other.initiate_authentication(None).await.unwrap();
    assert!(other.complete_authentication(&assertion).await.is_err());
}
