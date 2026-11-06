// SPDX-License-Identifier: MIT OR Apache-2.0
//! Replays the language-neutral GNAP vectors in `tests/conformance/gnap/vectors.json`
//! against `GnapService`. The format is described in `tests/conformance/gnap/README.md`.

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
use std::collections::HashMap;
use std::sync::Arc;

const URI: &str = "https://as.example.test/api/gnap/tx";
const CONTINUE_URI: &str = "https://as.example.test/api/gnap/tx/continue";
const VECTORS: &str = include_str!("conformance/gnap/vectors.json");

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

/// A DPoP proof for `POST` `htu`, signed by `signer`, naming `named` in its header.
fn dpop_header(signer: &ClientKey, named: &ClientKey, htu: &str, jti: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": named.jwk});
    let claims = serde_json::json!({
        "jti": jti, "htm": "POST", "htu": htu, "iat": chrono::Utc::now().timestamp()
    });
    let si = format!(
        "{}.{}",
        b64.encode(header.to_string()),
        b64.encode(claims.to_string())
    );
    let sig = jsonwebtoken::crypto::sign(si.as_bytes(), &signer.signing, Algorithm::ES256).unwrap();
    format!("{si}.{sig}")
}

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

/// A `$name` string is replaced by the value a previous step saved under that name.
fn subst(vars: &HashMap<String, String>, v: &Value) -> Option<String> {
    let s = v.as_str()?;
    match s.strip_prefix('$') {
        Some(name) => Some(
            vars.get(name)
                .unwrap_or_else(|| panic!("no saved value named {name}"))
                .clone(),
        ),
        None => Some(s.to_string()),
    }
}

fn check(id: &str, vars: &HashMap<String, String>, response: &Value, a: &Value) {
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
        "not_equals_saved" => {
            let saved = subst(vars, &a["value"]).expect("value");
            let g = got.and_then(Value::as_str);
            assert!(
                g.is_some() && g != Some(saved.as_str()),
                "{id}: {path} should be a string different from the saved value in {response}"
            );
        }
        other => panic!("{id}: unknown op {other}"),
    }
}

/// Which proof (if any) accompanies a request, per the step's `proof` field.
fn make_header(
    id: &str,
    proof: Option<&str>,
    key: &ClientKey,
    other: &ClientKey,
    htu: &str,
    jti: &str,
) -> Option<String> {
    match proof {
        None | Some("absent") => None,
        Some("valid") => Some(dpop_header(key, key, htu, jti)),
        Some("wrong_key") => Some(dpop_header(other, key, htu, jti)),
        Some(p) => panic!("{id}: unknown proof {p}"),
    }
}

/// Check `result` against the step's `expect`, then save what the step asks to keep.
fn finish_step(
    id: &str,
    step: &Value,
    vars: &mut HashMap<String, String>,
    result: Result<Value, impl std::fmt::Display + std::fmt::Debug>,
) {
    match step["expect"]["outcome"].as_str().unwrap_or("response") {
        "error" => {
            assert!(result.is_err(), "{id}: expected a refusal, got {result:?}");
        }
        "response" => {
            let response = result.unwrap_or_else(|e| panic!("{id}: expected a response, got {e}"));
            if let Some(asserts) = step["expect"]["assert"].as_array() {
                for a in asserts {
                    check(id, vars, &response, a);
                }
            }
            if let Some(save) = step["save"].as_object() {
                for (name, spec) in save {
                    let ptr = spec["pointer"].as_str().expect("save.pointer");
                    let mut val = response
                        .pointer(ptr)
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("{id}: nothing at {ptr} to save in {response}"))
                        .to_string();
                    if spec["tail"].as_bool() == Some(true) {
                        val = val.rsplit('/').next().unwrap_or_default().to_string();
                    }
                    vars.insert(name.clone(), val);
                }
            }
        }
        other => panic!("{id}: unknown outcome {other}"),
    }
}

#[tokio::test]
async fn gnap_vectors() {
    let suite: Value = serde_json::from_str(VECTORS).expect("vectors.json is valid JSON");
    let vectors = suite["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "no vectors loaded");

    let dpop = DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
    let (mut positive, mut negative) = (0, 0);
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
        let (key, other) = (client_key(), client_key());
        let mut vars: HashMap<String, String> = HashMap::new();

        // A vector without `steps` is one transaction step made of its own fields.
        let single = [serde_json::json!({
            "do": "transaction", "request": v["request"], "proof": v["proof"], "expect": v["expect"]
        })];
        let steps: &[Value] = v["steps"].as_array().map_or(&single[..], |s| &s[..]);

        for (n, step) in steps.iter().enumerate() {
            let jti = format!("{id}-{n}");
            let proof_kind = step["proof"].as_str();
            match step["do"].as_str().expect("step.do") {
                "transaction" => {
                    let mut body = step["request"].clone();
                    if v["client_key"].as_str() == Some("dpop") {
                        body["client"] =
                            serde_json::json!({"key": {"proof": "dpop", "jwk": key.jwk}});
                    }
                    let header = make_header(id, proof_kind, &key, &other, URI, &jti);
                    let request: GnapTransactionRequest = match serde_json::from_value(body) {
                        Ok(r) => r,
                        Err(e) => {
                            // A body the server cannot even parse counts as a refusal.
                            assert_eq!(
                                step["expect"]["outcome"], "error",
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
                    finish_step(id, step, &mut vars, result);
                }
                "approve" => {
                    // The resource owner's decision happens at the server, not on the wire.
                    let tx = subst(&vars, &step["transaction"]).expect("step.transaction");
                    let result = service.approve_transaction(&tx, None).await.map(
                        |c| serde_json::json!({"interact_ref": c.interact_ref, "hash": c.hash}),
                    );
                    finish_step(id, step, &mut vars, result);
                }
                "continue" => {
                    let tx = subst(&vars, &step["transaction"]).expect("step.transaction");
                    let token = subst(&vars, &step["token"]).expect("step.token");
                    let iref = subst(&vars, &step["interact_ref"]);
                    let hash = subst(&vars, &step["interact_hash"]);
                    let header = make_header(id, proof_kind, &key, &other, CONTINUE_URI, &jti);
                    let proof = GnapProof {
                        http_method: "POST",
                        http_uri: CONTINUE_URI,
                        dpop_proof: header.as_deref(),
                        expected_nonce: None,
                    };
                    let result = service
                        .continue_transaction_with_proof(
                            &dpop,
                            &proof,
                            &tx,
                            &token,
                            iref.as_deref(),
                            hash.as_deref(),
                        )
                        .await;
                    finish_step(id, step, &mut vars, result);
                }
                other => panic!("{id}: unknown step {other}"),
            }
        }
    }
    assert!(
        positive > 0 && negative > 0,
        "suite needs both kinds ({positive}/{negative})"
    );
}
