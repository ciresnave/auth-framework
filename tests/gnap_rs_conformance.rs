// SPDX-License-Identifier: MIT OR Apache-2.0
//! Replays the language-neutral RFC 9767 vectors in `tests/conformance/gnap/rs-vectors.json`
//! against the RS-facing HTTP handler. The format is described in
//! `tests/conformance/gnap/README.md`.

use async_trait::async_trait;
use auth_framework::protocols::gnap_http::{GnapHttpRequest, GnapRsHttp};
use auth_framework::protocols::gnap_rs::{
    AuthenticatedRs, GnapResourceServerApi, GnapRsConfig, RegisteredResources,
    ResourceRegistration, ResourceRegistry, ResourceServerAuthenticator, RsCall, RsError,
    RsTokenInfo, TokenInfoSource,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

const VECTORS: &str = include_str!("conformance/gnap/rs-vectors.json");

struct Tokens(HashMap<String, RsTokenInfo>);

#[async_trait]
impl TokenInfoSource for Tokens {
    async fn token_info(&self, value: &str) -> Option<RsTokenInfo> {
        self.0.get(value).cloned()
    }
}

/// Recognizes a resource server by the value of one request header.
struct HeaderAuthenticator(String);

#[async_trait]
impl ResourceServerAuthenticator for HeaderAuthenticator {
    async fn authenticate(&self, call: &RsCall<'_>) -> Option<AuthenticatedRs> {
        call.headers
            .iter()
            .find(|(k, _)| *k == self.0)
            .map(|(_, v)| AuthenticatedRs { id: v.clone() })
    }
}

/// The fixture registration policy described in `rs-vectors.json`.
struct FixtureRegistry {
    forbidden: Vec<Value>,
    resource_reference: String,
    instance_id_prefix: String,
}

#[async_trait]
impl ResourceRegistry for FixtureRegistry {
    async fn register(
        &self,
        rs: &AuthenticatedRs,
        request: &ResourceRegistration,
    ) -> Result<RegisteredResources, RsError> {
        if request.access.iter().any(|a| self.forbidden.contains(a)) {
            return Err(RsError::InvalidAccess(
                "access is not permitted for this resource server".into(),
            ));
        }
        Ok(RegisteredResources {
            resource_reference: self.resource_reference.clone(),
            instance_id: Some(format!("{}{}", self.instance_id_prefix, rs.id)),
        })
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn token_from(server: &Value, spec: &Value) -> RsTokenInfo {
    let expires_in = spec["expires_in"].as_i64().expect("expires_in");
    RsTokenInfo {
        access: spec["access"].as_array().expect("access").clone(),
        key: spec.get("key").cloned(),
        proof: spec["proof"].as_str().map(str::to_string),
        expires_at: (now() + expires_in).max(0) as u64,
        issued_at: now().max(0) as u64,
        grant_endpoint: server["grant_request_endpoint"]
            .as_str()
            .unwrap()
            .to_string(),
        instance_id: spec["instance_id"].as_str().map(str::to_string),
        flags: vec![],
        audience: spec["audience"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default(),
    }
}

fn check(id: &str, body: &Value, a: &Value) {
    let path = a["path"].as_str().expect("assert.path");
    let got = body.pointer(path);
    match a["op"].as_str().expect("assert.op") {
        "exists" => assert!(got.is_some(), "{id}: {path} should exist in {body}"),
        "absent" => assert!(got.is_none(), "{id}: {path} should be absent in {body}"),
        "is_string" => assert!(
            got.is_some_and(Value::is_string),
            "{id}: {path} not a string in {body}"
        ),
        "is_number" => assert!(
            got.is_some_and(Value::is_number),
            "{id}: {path} not a number in {body}"
        ),
        "equals" => assert_eq!(got, Some(&a["value"]), "{id}: {path} in {body}"),
        other => panic!("{id}: unknown op {other}"),
    }
}

#[tokio::test]
async fn gnap_rs_vectors() {
    let suite: Value = serde_json::from_str(VECTORS).expect("rs-vectors.json is valid JSON");
    let server = &suite["server"];
    let rs_header = server["rs_credential_header"]
        .as_str()
        .expect("rs_credential_header");

    let tokens = server["tokens"]
        .as_object()
        .expect("tokens")
        .iter()
        .map(|(k, spec)| (k.clone(), token_from(server, spec)))
        .collect();
    let config = GnapRsConfig {
        grant_request_endpoint: server["grant_request_endpoint"]
            .as_str()
            .unwrap()
            .to_string(),
        introspection_endpoint: server["introspection_endpoint"]
            .as_str()
            .unwrap()
            .to_string(),
        key_proofs_supported: vec![],
        token_formats_supported: server["token_formats_supported"]
            .as_array()
            .expect("token_formats_supported")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
    };
    let policy = &server["registration"];
    let registry = FixtureRegistry {
        forbidden: policy["forbidden_access"]
            .as_array()
            .expect("forbidden_access")
            .clone(),
        resource_reference: policy["resource_reference"].as_str().unwrap().to_string(),
        instance_id_prefix: policy["instance_id_prefix"].as_str().unwrap().to_string(),
    };
    let api = GnapResourceServerApi::new(
        config,
        Arc::new(Tokens(tokens)),
        Arc::new(HeaderAuthenticator(rs_header.to_string())),
    )
    .and_then(|api| {
        api.with_registry(
            server["resource_registration_endpoint"].as_str().unwrap(),
            Arc::new(registry),
        )
    })
    .expect("the fixture server's endpoints are valid");
    let http = GnapRsHttp::new(Arc::new(api));

    let vectors = suite["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "no vectors loaded");
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

        let req = &v["request"];
        let mut headers = Vec::new();
        if let Some(rs) = req["rs"].as_str() {
            headers.push((rs_header.to_string(), rs.to_string()));
        }
        let body = match (req.get("body"), req["raw_body"].as_str()) {
            (Some(b), _) => b.to_string().into_bytes(),
            (None, Some(raw)) => raw.as_bytes().to_vec(),
            (None, None) => Vec::new(),
        };
        let request = GnapHttpRequest {
            method: req["method"].as_str().expect("method").to_string(),
            uri: req["path"].as_str().expect("path").to_string(),
            headers,
            body,
        };
        let response = http.handle(&request).await;

        let expect = &v["expect"];
        assert_eq!(
            u64::from(response.status),
            expect["status"].as_u64().expect("expect.status"),
            "{id}: status"
        );
        if let Some(hs) = expect["headers"].as_object() {
            for (name, want) in hs {
                assert_eq!(response.header(name), want.as_str(), "{id}: header {name}");
            }
        }
        let text = String::from_utf8_lossy(&response.body).to_string();
        if let Some(asserts) = expect["assert"].as_array() {
            let json: Value = serde_json::from_slice(&response.body)
                .unwrap_or_else(|e| panic!("{id}: body is not JSON ({e}): {text}"));
            for a in asserts {
                check(id, &json, a);
            }
        }
        if let Some(secret) = expect["body_lacks"].as_str() {
            assert!(
                !text.contains(secret),
                "{id}: the body must not contain {secret}: {text}"
            );
        }
    }
    assert!(
        positive > 0 && negative > 0,
        "suite needs both kinds ({positive}/{negative})"
    );
}
