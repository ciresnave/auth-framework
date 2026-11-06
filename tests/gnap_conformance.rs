//! Replays the language-neutral GNAP vectors in `tests/conformance/gnap/vectors.json`
//! against `GnapService`.

use auth_framework::protocols::gnap::{GnapConfig, GnapService, GnapTransactionRequest};
use serde_json::Value;

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

        let service = GnapService::new(config_from(&v["config"]));
        let request: GnapTransactionRequest = match serde_json::from_value(v["request"].clone()) {
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
        let result = service.handle_transaction(request).await;
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
