//! Replays the language-neutral GNAP vectors in `tests/conformance/gnap/vectors.json`
//! against `GnapService`.

use async_trait::async_trait;
use auth_framework::protocols::gnap::{
    GnapAccessPolicy, GnapAccessRequest, GnapConfig, GnapJwk, GnapProof, GnapService,
    GnapTransactionRequest,
};
use auth_framework::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
use auth_framework::server::security::dpop::DpopManager;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::Value;
use std::sync::Arc;

const URI: &str = "https://as.example.test/api/gnap/tx";

/// The server under test grants whatever is requested; the vectors test the protocol, not a policy.
struct GrantAll;

#[async_trait]
impl GnapAccessPolicy for GrantAll {
    async fn grant(
        &self,
        _thumbprint: &str,
        requested: &[GnapAccessRequest],
    ) -> Vec<GnapAccessRequest> {
        requested.to_vec()
    }
}

struct ClientKey {
    signing: EncodingKey,
    jwk: GnapJwk,
}

/// A fresh P-256 key, as a replayer in any language would generate.
fn client_key() -> ClientKey {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let raw = key.public_key_raw();
    let point = &raw[raw.len() - 65..];
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    ClientKey {
        signing: EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap(),
        jwk: GnapJwk {
            kty: "EC".to_string(),
            kid: None,
            crv: Some("P-256".to_string()),
            x: Some(b64.encode(&point[1..33])),
            y: Some(b64.encode(&point[33..65])),
            n: None,
            e: None,
        },
    }
}

/// A DPoP proof for `POST` `URI`, signed by `signer`, naming `named` in its header.
fn dpop_header(signer: &ClientKey, named: &ClientKey, jti: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": named.jwk});
    let claims = serde_json::json!({
        "jti": jti, "htm": "POST", "htu": URI, "iat": chrono::Utc::now().timestamp()
    });
    let si = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims.to_string())
    );
    let sig = jsonwebtoken::crypto::sign(si.as_bytes(), &signer.signing, Algorithm::ES256).unwrap();
    format!("{si}.{sig}")
}

const VECTORS: &str = include_str!("conformance/gnap/vectors.json");

fn config_from(v: &Value) -> GnapConfig {
    GnapConfig {
        enabled: v["enabled"].as_bool().expect("config.enabled"),
        transaction_endpoint: v["transaction_endpoint"]
            .as_str()
            .expect("config.transaction_endpoint")
            .to_string(),
        interaction_base_url: v["interaction_base_url"].as_str().map(str::to_string),
        token_lifetime_secs: 3600,
        transaction_lifetime_secs: 600,
    }
}

fn check(id: &str, response: &Value, a: &Value) {
    let path = a["path"].as_str().expect("assert.path");
    let got = response.pointer(path);
    match a["op"].as_str().expect("assert.op") {
        "exists" => assert!(got.is_some(), "{id}: {path} should exist in {response}"),
        "absent" => assert!(got.is_none(), "{id}: {path} should be absent in {response}"),
        "is_string" => assert!(
            got.is_some_and(Value::is_string),
            "{id}: {path} not a string in {response}"
        ),
        "is_number" => assert!(
            got.is_some_and(Value::is_number),
            "{id}: {path} not a number in {response}"
        ),
        "is_array" => assert!(
            got.is_some_and(Value::is_array),
            "{id}: {path} not an array in {response}"
        ),
        "equals" => assert_eq!(got, Some(&a["value"]), "{id}: {path} in {response}"),
        other => panic!("{id}: unknown op {other}"),
    }
}

#[tokio::test]
async fn gnap_transaction_vectors() {
    let suite: Value = serde_json::from_str(VECTORS).expect("vectors.json is valid JSON");
    let vectors = suite["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "no vectors loaded");

    let dpop = DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
    let mut positive = 0;
    let mut negative = 0;
    for v in vectors {
        let id = v["id"].as_str().expect("id");
        assert!(
            v["rfc"].is_string() && v["section"].is_string(),
            "{id}: rfc and section required"
        );
        match v["kind"].as_str() {
            Some("positive") => positive += 1,
            Some("negative") => negative += 1,
            other => panic!("{id}: kind must be positive or negative, got {other:?}"),
        }

        let service =
            GnapService::new(config_from(&v["config"])).with_access_policy(Arc::new(GrantAll));
        let mut body = v["request"].clone();
        let key = client_key();
        let mut header = None;
        match v["client_key"].as_str() {
            None => {}
            Some("dpop") => {
                body["client"] = serde_json::json!({"key": {"proof": "dpop", "jwk": key.jwk}});
                let other = client_key();
                header = match v["proof"].as_str().expect("proof") {
                    "valid" => Some(dpop_header(&key, &key, id)),
                    "absent" => None,
                    "wrong_key" => Some(dpop_header(&other, &key, id)),
                    p => panic!("{id}: unknown proof {p}"),
                };
            }
            Some(k) => panic!("{id}: unknown client_key {k}"),
        }
        let request: GnapTransactionRequest = match serde_json::from_value(body) {
            Ok(r) => r,
            Err(e) => {
                // A body the server cannot even parse counts as a refusal.
                assert_eq!(
                    v["expect"]["outcome"], "error",
                    "{id}: request did not parse: {e}"
                );
                continue;
            }
        };
        let proof = GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: header.as_deref(),
            expected_nonce: None,
        };
        let result = service
            .handle_transaction_with_proof(&dpop, &proof, request)
            .await;
        match v["expect"]["outcome"].as_str().expect("expect.outcome") {
            "error" => assert!(result.is_err(), "{id}: expected a refusal, got {result:?}"),
            "response" => {
                let response =
                    result.unwrap_or_else(|e| panic!("{id}: expected a response, got {e}"));
                for a in v["expect"]["assert"].as_array().expect("expect.assert") {
                    check(id, &response, a);
                }
            }
            other => panic!("{id}: unknown outcome {other}"),
        }
    }
    assert!(
        positive > 0 && negative > 0,
        "suite needs both kinds ({positive}/{negative})"
    );
}
