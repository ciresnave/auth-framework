//! What the `passkey` crates produce, pinned so that a release which changes it fails here.
//!
//! The crate drives `passkey`'s client and authenticator to register and to assert, then reads the
//! serialized `CreatedPublicKeyCredential` / `AuthenticatedPublicKeyCredential`. Those shapes belong to
//! the `passkey` crates and can change in a release without a compile error. These tests check a
//! credential and an assertion recorded once (`tests/fixtures/passkey_wire_format.json`, recorded with
//! `passkey` 0.5.0) and a live registration, and verify the recorded signature with `ring` alone, so
//! they must pass on every `passkey` release the crate accepts.
#![cfg(feature = "passkeys")]

use auth_framework::methods::passkey::{PasskeyAuthMethod, PasskeyConfig};
use auth_framework::tokens::TokenManager;
use ring::digest;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::Value;

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

/// A JSON byte field, whether the crate writes bytes as an array of numbers or as base64url text.
fn bytes(v: &Value) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    match v {
        Value::Array(a) => a.iter().map(|b| b.as_u64().unwrap() as u8).collect(),
        Value::String(s) => URL_SAFE_NO_PAD.decode(s).expect("base64url"),
        other => panic!("not a byte field: {other}"),
    }
}

/// The fields of a registration the crate and a relying party read.
fn check_registration_shape(credential: &Value) {
    assert_eq!(credential["type"], "public-key", "{credential}");
    assert_eq!(credential["response"]["publicKeyAlgorithm"], -7, "ES256");
    // SubjectPublicKeyInfo of a P-256 key: 91 bytes, ending in the 65-byte uncompressed point.
    let spki = bytes(&credential["response"]["publicKey"]);
    assert_eq!(spki.len(), 91, "public key is not a P-256 SPKI");
    assert_eq!(spki[spki.len() - 65], 0x04, "uncompressed point marker");
    assert!(!bytes(&credential["response"]["clientDataJSON"]).is_empty());
    assert!(bytes(&credential["response"]["authenticatorData"]).len() > 37);
    assert!(!bytes(&credential["rawId"]).is_empty());
    // Control: a field that is not there is not found, so the checks above can fail.
    assert!(credential["response"].get("noSuchField").is_none());
}

#[test]
fn a_recorded_registration_has_the_expected_shape() {
    check_registration_shape(&fixture()["credential"]);
}

#[tokio::test]
async fn a_live_registration_has_the_expected_shape() {
    let mut m = method();
    let credential = m
        .register_passkey("user-1", "user1", "User One")
        .await
        .expect("registration succeeds");
    check_registration_shape(&serde_json::to_value(&credential).unwrap());
    // The registration is offered back as an allowed credential for that user.
    let options = m.initiate_authentication(Some("user-1")).await.unwrap();
    assert_eq!(
        options
            .public_key
            .allow_credentials
            .unwrap_or_default()
            .len(),
        1
    );
}

/// The recorded assertion's signature verifies, with `ring` alone, against the recorded public key
/// over `authenticatorData || SHA-256(clientDataJSON)`, and the client data carries the recorded
/// challenge and origin.
#[test]
fn a_recorded_assertion_verifies_against_the_recorded_key() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let fx = fixture();
    let spki = bytes(&fx["credential"]["response"]["publicKey"]);
    let point = &spki[spki.len() - 65..];
    let auth_data = bytes(&fx["assertion"]["response"]["authenticatorData"]);
    let client_data = bytes(&fx["assertion"]["response"]["clientDataJSON"]);
    let signature = bytes(&fx["assertion"]["response"]["signature"]);

    let mut message = auth_data.clone();
    message.extend_from_slice(digest::digest(&digest::SHA256, &client_data).as_ref());
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point);
    assert!(
        key.verify(&message, &signature).is_ok(),
        "recorded signature no longer verifies"
    );

    let client: Value = serde_json::from_slice(&client_data).unwrap();
    assert_eq!(client["type"], "webauthn.get");
    assert_eq!(client["origin"], "https://example.com");
    let challenge: Vec<u8> = (100u8..132).collect();
    assert_eq!(client["challenge"], URL_SAFE_NO_PAD.encode(&challenge));

    // Controls: a changed message or signature must not verify.
    let mut bad = message.clone();
    bad[0] ^= 0xff;
    assert!(key.verify(&bad, &signature).is_err());
    let mut bad_sig = signature.clone();
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xff;
    assert!(key.verify(&message, &bad_sig).is_err());
}

/// The relying-party id hash in the recorded authenticator data is `SHA-256("example.com")`, and the
/// user-present and user-verified flags are set.
#[test]
fn a_recorded_assertion_binds_the_relying_party_and_user_flags() {
    let fx = fixture();
    let auth_data = bytes(&fx["assertion"]["response"]["authenticatorData"]);
    assert_eq!(
        &auth_data[..32],
        digest::digest(&digest::SHA256, b"example.com").as_ref()
    );
    assert_eq!(auth_data[32] & 0x01, 0x01, "user present");
    assert_eq!(auth_data[32] & 0x04, 0x04, "user verified");
}
