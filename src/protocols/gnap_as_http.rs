// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport-neutral HTTP handling for the GNAP authorization-server API (RFC 9635).
//!
//! [`GnapAsHttp::handle`] takes a request already read off the wire and returns the response to
//! send, like [`GnapRsHttp`](super::gnap_http::GnapRsHttp) does for the resource-server side. It
//! routes three things for a [`GnapService`]:
//!
//! - the grant endpoint: `POST` starts a transaction (section 2) and `OPTIONS` answers the
//!   discovery document (section 9.2);
//! - the token management endpoint (`<grant endpoint>/token`, section 6): `POST` rotates the
//!   token named in the `Authorization: GNAP <token>` header and `DELETE` revokes it.
//!
//! - the continuation endpoint (`<grant endpoint>/continue/<transaction id>`, section 5): `POST`
//!   polls or, after the resource owner approved, presents the `interact_ref` in the body. The
//!   continuation token is in `Authorization: GNAP <token>` and rotates on every success.
//!
//!   `PATCH` on the same URI modifies a pending request (section 5.3) and `DELETE` cancels it
//!   (section 5.4). A poll that comes before the announced `wait` is 429 `too_fast` (section 3.6)
//!   and keeps the continuation token usable.
//!
//! A proof is bound to the authorization server's own URL, the one this handler is given, and
//! never to the `Host` the request arrived with. Only the `dpop` proof method verifies today (see
//! `docs/GNAP_RFC9635_GAP.md`), so that is the only one the discovery document lists.
//!
//! Every refusal is a JSON `error` object (section 3.6). RFC 9635 fixes the error codes but not
//! the HTTP status; the status chosen here is 401 for a missing or invalid proof, 403 for a
//! request the policy denied, 404 for a token that is not held and 400 for any other refused
//! request. A failure that is not a refusal (a store error) is a bare 500. A response never
//! carries a token or key the request did not already hold, and none is cacheable.

use crate::errors::AuthError;
use crate::protocols::gnap::{GnapProof, GnapService, GnapTransactionRequest};
use crate::protocols::gnap_http::{GnapHttpRequest, GnapHttpResponse, MAX_BODY_BYTES, path_of};
use crate::server::security::dpop::DpopManager;
use serde_json::{Value, json};
use std::sync::Arc;

/// Routes the authorization-server API of one [`GnapService`].
pub struct GnapAsHttp {
    service: Arc<GnapService>,
    dpop: Arc<DpopManager>,
    grant_url: String,
    grant_path: String,
    manage_url: String,
    manage_path: String,
    continue_prefix: String,
}

impl GnapAsHttp {
    /// Serve `service`. `grant_url` is the public, absolute URL of the grant endpoint and must
    /// end with the service's configured `transaction_endpoint`, because the token management
    /// URI the service issues is that endpoint plus `/token`; proofs are checked against these
    /// URLs. `dpop` verifies (and remembers, to refuse a replay) the `DPoP` proofs.
    pub fn new(
        service: Arc<GnapService>,
        dpop: Arc<DpopManager>,
        grant_url: impl Into<String>,
    ) -> Self {
        let grant_url = grant_url.into().trim_end_matches('/').to_string();
        let manage_url = format!("{grant_url}/token");
        Self {
            service,
            dpop,
            grant_path: path_of(&grant_url).to_string(),
            manage_path: path_of(&manage_url).to_string(),
            continue_prefix: format!("{}/continue/", path_of(&grant_url)),
            grant_url,
            manage_url,
        }
    }

    /// The continuation route pattern, `<grant endpoint>/continue/{id}`, in the `{id}` syntax axum
    /// and actix both use.
    pub fn continue_route(&self) -> String {
        format!("{}{{id}}", self.continue_prefix)
    }

    /// The grant endpoint path and the token management path, so an adapter can register them.
    pub fn paths(&self) -> (&str, &str) {
        (&self.grant_path, &self.manage_path)
    }

    /// Answer one request.
    pub async fn handle(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let path = path_of(&req.uri);
        let method = req.method.to_ascii_uppercase();
        if path == self.grant_path {
            return match method.as_str() {
                "POST" => self.grant(req).await,
                "OPTIONS" => GnapHttpResponse::json(200, &self.discovery_document(), false),
                _ => GnapHttpResponse::empty(405, vec![("Allow".into(), "POST, OPTIONS".into())]),
            };
        }
        if path == self.manage_path {
            return match method.as_str() {
                "POST" => self.rotate(req).await,
                "DELETE" => self.revoke(req).await,
                _ => GnapHttpResponse::empty(405, vec![("Allow".into(), "POST, DELETE".into())]),
            };
        }
        if let Some(id) = self.continue_id(path) {
            return match method.as_str() {
                "POST" => self.continue_grant(req, id).await,
                "PATCH" => self.modify_grant(req, id).await,
                "DELETE" => self.cancel_grant(req, id).await,
                _ => GnapHttpResponse::empty(
                    405,
                    vec![("Allow".into(), "POST, PATCH, DELETE".into())],
                ),
            };
        }
        GnapHttpResponse::empty(404, Vec::new())
    }

    /// The transaction id of a continuation path: exactly one non-empty segment after
    /// `<grant endpoint>/continue/`, of a sane length.
    fn continue_id<'a>(&self, path: &'a str) -> Option<&'a str> {
        let id = path.strip_prefix(self.continue_prefix.as_str())?;
        (!id.is_empty() && id.len() <= 128 && !id.contains('/')).then_some(id)
    }

    /// The document `OPTIONS` on the grant endpoint answers (RFC 9635 section 9.2). It lists only
    /// what this crate does: the `dpop`, `httpsig` and `jwsd` proof methods, the `redirect` start mode and finish
    /// method, and no key rotation.
    fn discovery_document(&self) -> Value {
        json!({
            "grant_request_endpoint": self.grant_url,
            "interaction_start_modes_supported": ["redirect"],
            "interaction_finish_methods_supported": ["redirect"],
            "key_proofs_supported": ["dpop", "httpsig", "jwsd"],
            "key_rotation_supported": false,
        })
    }

    async fn grant(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let request = match read_json::<GnapTransactionRequest>(req) {
            Ok(r) => r,
            Err(refused) => return refused,
        };
        let headers = header_pairs(req);
        let proof = proof_for(req, &self.grant_url, &headers);
        match self
            .service
            .handle_transaction_with_proof(&self.dpop, &proof, request)
            .await
        {
            Ok(answer) => GnapHttpResponse::json(200, &answer, true),
            Err(e) => refuse(&e),
        }
    }

    async fn continue_grant(&self, req: &GnapHttpRequest, id: &str) -> GnapHttpResponse {
        let Some(token) = gnap_token(req) else {
            return unauthorized();
        };
        // The body is optional (a poll has none); when present it is a JSON object.
        let interact_ref =
            if req.body.len() <= MAX_BODY_BYTES && req.body.iter().all(u8::is_ascii_whitespace) {
                None
            } else {
                match read_json::<Value>(req) {
                    Ok(body) => match body.get("interact_ref") {
                        None => None,
                        Some(Value::String(r)) => Some(r.clone()),
                        Some(_) => {
                            return error(400, "invalid_request", "interact_ref must be a string");
                        }
                    },
                    Err(refused) => return refused,
                }
            };
        let url = format!("{}/continue/{id}", self.grant_url);
        let headers = header_pairs(req);
        let proof = proof_for(req, &url, &headers);
        match self
            .service
            .continue_transaction_with_proof(
                &self.dpop,
                &proof,
                id,
                token,
                interact_ref.as_deref(),
                None,
            )
            .await
        {
            Ok(answer) => GnapHttpResponse::json(200, &answer, true),
            Err(e) => refuse(&e),
        }
    }

    async fn modify_grant(&self, req: &GnapHttpRequest, id: &str) -> GnapHttpResponse {
        let Some(token) = gnap_token(req) else {
            return unauthorized();
        };
        let modification = match read_json::<GnapTransactionRequest>(req) {
            Ok(m) => m,
            Err(refused) => return refused,
        };
        let url = format!("{}/continue/{id}", self.grant_url);
        let headers = header_pairs(req);
        let proof = proof_for(req, &url, &headers);
        match self
            .service
            .modify_transaction_with_proof(&self.dpop, &proof, id, token, &modification)
            .await
        {
            Ok(answer) => GnapHttpResponse::json(200, &answer, true),
            Err(e) => refuse(&e),
        }
    }

    async fn cancel_grant(&self, req: &GnapHttpRequest, id: &str) -> GnapHttpResponse {
        let Some(token) = gnap_token(req) else {
            return unauthorized();
        };
        let url = format!("{}/continue/{id}", self.grant_url);
        let headers = header_pairs(req);
        let proof = proof_for(req, &url, &headers);
        match self
            .service
            .delete_transaction_with_proof(&self.dpop, &proof, id, token)
            .await
        {
            // RFC 9635 section 5.4: 204 with no body.
            Ok(()) => {
                GnapHttpResponse::empty(204, vec![("Cache-Control".into(), "no-store".into())])
            }
            Err(e) => refuse(&e),
        }
    }

    async fn rotate(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let Some(token) = gnap_token(req) else {
            return unauthorized();
        };
        let headers = header_pairs(req);
        let proof = proof_for(req, &self.manage_url, &headers);
        match self
            .service
            .rotate_token_with_proof(&self.dpop, &proof, token)
            .await
        {
            // RFC 9635 section 6.1: the new token comes back as `access_token`.
            Ok(answer) => GnapHttpResponse::json(200, &json!({ "access_token": answer }), true),
            Err(e) => refuse(&e),
        }
    }

    async fn revoke(&self, req: &GnapHttpRequest) -> GnapHttpResponse {
        let Some(token) = gnap_token(req) else {
            return unauthorized();
        };
        let headers = header_pairs(req);
        let proof = proof_for(req, &self.manage_url, &headers);
        match self
            .service
            .revoke_token_with_proof(&self.dpop, &proof, token)
            .await
        {
            // RFC 9635 section 6.2: 204 with no body.
            Ok(()) => {
                GnapHttpResponse::empty(204, vec![("Cache-Control".into(), "no-store".into())])
            }
            Err(e) => refuse(&e),
        }
    }
}

/// The request's own proof material, bound to the server's `url` and not to the request target.
fn proof_for<'a>(
    req: &'a GnapHttpRequest,
    url: &'a str,
    headers: &'a [(&'a str, &'a str)],
) -> GnapProof<'a> {
    // `GnapProof` borrows the method; the methods routed here are static strings.
    let http_method = match req.method.to_ascii_uppercase().as_str() {
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        _ => "POST",
    };
    GnapProof {
        http_method,
        http_uri: url,
        dpop_proof: req.header_value("dpop"),
        expected_nonce: None,
        // The TLS peer certificate is the terminator's to give; this layer never sees it, so a
        // client key proved by `mtls` is refused here, and discovery does not list `mtls`.
        client_certificate_der: None,
        // The `httpsig` proof method signs the request's headers and body.
        http_headers: headers,
        http_body: &req.body,
    }
}

/// The request's headers as borrowed pairs, for [`GnapProof::http_headers`].
fn header_pairs(req: &GnapHttpRequest) -> Vec<(&str, &str)> {
    req.headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect()
}

/// The token of an `Authorization: GNAP <token>` header (RFC 9635 section 7.2), if the request has one.
fn gnap_token(req: &GnapHttpRequest) -> Option<&str> {
    let (scheme, token) = req.header_value("authorization")?.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("GNAP") && !token.is_empty()).then_some(token)
}

/// The size-capped JSON body.
fn read_json<T: serde::de::DeserializeOwned>(req: &GnapHttpRequest) -> Result<T, GnapHttpResponse> {
    if req.body.len() > MAX_BODY_BYTES {
        return Err(error(400, "invalid_request", "request body too large"));
    }
    serde_json::from_slice(&req.body)
        .map_err(|_| error(400, "invalid_request", "request body is not a GNAP request"))
}

fn error(status: u16, code: &str, description: &str) -> GnapHttpResponse {
    let body = json!({"error": {"code": code, "description": description}});
    GnapHttpResponse::json(status, &body, true)
}

fn unauthorized() -> GnapHttpResponse {
    let mut r = error(
        401,
        "invalid_client",
        "a GNAP token and its proof are required",
    );
    r.headers.push(("WWW-Authenticate".into(), "GNAP".into()));
    r
}

/// The answer to a refused request. The status and code come from the kind of refusal, never from
/// echoing the service's message back: a client learns that its proof or request failed, not why
/// a particular token or transaction did.
fn refuse(e: &AuthError) -> GnapHttpResponse {
    let AuthError::Validation { message } = e else {
        // A store or internal failure is not a refusal and carries no detail.
        return GnapHttpResponse::empty(500, vec![("Cache-Control".into(), "no-store".into())]);
    };
    let m = message.to_ascii_lowercase();
    if m.contains("too_fast") {
        // RFC 9635 section 3.6; the continuation token is still good, so the client may retry.
        error(429, "too_fast", "poll again after the announced wait")
    } else if m.contains("denied by the resource owner") {
        error(403, "user_denied", "the resource owner denied the request")
    } else if m.contains("invalid continuation") {
        // Every refused continuation reads the same: a client cannot tell an unknown transaction
        // from a wrong token, a spent token or a wrong interaction reference.
        error(
            401,
            "invalid_continuation",
            "the continuation request was refused",
        )
    } else if m.contains("proof") || m.contains("client key required") {
        unauthorized()
    } else if m.contains("access denied") {
        error(403, "request_denied", "the request was denied")
    } else if m.contains("not found") {
        error(404, "unknown_request", "no such token")
    } else {
        error(400, "invalid_request", "the request was refused")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocols::gnap::{GnapAccessPolicy, GnapAccessRequest, GnapConfig, GnapJwk};
    use crate::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
    use async_trait::async_trait;
    use base64::Engine as _;
    use jsonwebtoken::{Algorithm, EncodingKey};

    const GRANT: &str = "https://as.example.test/api/gnap/tx";
    const MANAGE: &str = "https://as.example.test/api/gnap/tx/token";

    struct AllowAll;

    #[async_trait]
    impl GnapAccessPolicy for AllowAll {
        async fn grant(
            &self,
            _thumb: &str,
            wanted: &[GnapAccessRequest],
        ) -> Vec<GnapAccessRequest> {
            wanted.to_vec()
        }
    }

    struct DenyAll;

    #[async_trait]
    impl GnapAccessPolicy for DenyAll {
        async fn grant(
            &self,
            _thumb: &str,
            _wanted: &[GnapAccessRequest],
        ) -> Vec<GnapAccessRequest> {
            Vec::new()
        }
    }

    struct Key {
        signing: EncodingKey,
        jwk: GnapJwk,
    }

    fn key() -> Key {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let raw = pair.public_key_raw();
        let point = &raw[raw.len() - 65..];
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Key {
            signing: EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap(),
            jwk: GnapJwk {
                kty: "EC".into(),
                kid: None,
                crv: Some("P-256".into()),
                x: Some(b64.encode(&point[1..33])),
                y: Some(b64.encode(&point[33..65])),
                n: None,
                e: None,
            },
        }
    }

    /// A DPoP proof for `htm` and `htu` signed by `signer`, naming `named` in its header.
    fn dpop(signer: &Key, named: &Key, htm: &str, htu: &str, jti: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": serde_json::to_value(&named.jwk).unwrap()});
        let claims =
            json!({"jti": jti, "htm": htm, "htu": htu, "iat": chrono::Utc::now().timestamp()});
        let si = format!(
            "{}.{}",
            b64.encode(header.to_string()),
            b64.encode(claims.to_string())
        );
        let sig =
            jsonwebtoken::crypto::sign(si.as_bytes(), &signer.signing, Algorithm::ES256).unwrap();
        format!("{si}.{sig}")
    }

    fn parts_with(policy: Arc<dyn GnapAccessPolicy>) -> (GnapAsHttp, Arc<GnapService>) {
        parts_waiting(policy, 0)
    }

    fn parts_waiting(
        policy: Arc<dyn GnapAccessPolicy>,
        poll_wait_secs: u64,
    ) -> (GnapAsHttp, Arc<GnapService>) {
        let service = Arc::new(
            GnapService::new(GnapConfig {
                enabled: true,
                transaction_endpoint: "/api/gnap/tx".into(),
                interaction_base_url: Some("https://as.example.test".into()),
                token_lifetime_secs: 3600,
                transaction_lifetime_secs: 600,
            })
            .with_poll_wait_secs(poll_wait_secs)
            .with_access_policy(policy),
        );
        let manager =
            DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
        (
            GnapAsHttp::new(service.clone(), Arc::new(manager), GRANT),
            service,
        )
    }

    fn handler_with(policy: Arc<dyn GnapAccessPolicy>) -> GnapAsHttp {
        parts_with(policy).0
    }

    pub(crate) fn handler() -> GnapAsHttp {
        handler_with(Arc::new(AllowAll))
    }

    fn body_of(k: &Key) -> Vec<u8> {
        json!({
            "client": {"key": {"proof": "dpop", "jwk": serde_json::to_value(&k.jwk).unwrap()}},
            "access_token": {"access": [{"type": "read"}]},
        })
        .to_string()
        .into_bytes()
    }

    fn req(
        method: &str,
        uri: &str,
        headers: Vec<(&str, String)>,
        body: Vec<u8>,
    ) -> GnapHttpRequest {
        GnapHttpRequest {
            method: method.into(),
            uri: uri.into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            body,
        }
    }

    /// A grant request signed by `k`, with proof id `jti`.
    fn grant_req(k: &Key, jti: &str) -> GnapHttpRequest {
        let proof = dpop(k, k, "POST", GRANT, jti);
        req("POST", "/api/gnap/tx", vec![("DPoP", proof)], body_of(k))
    }

    fn json_of(r: &GnapHttpResponse) -> Value {
        serde_json::from_slice(&r.body).unwrap_or(Value::Null)
    }

    fn code_of(r: &GnapHttpResponse) -> String {
        json_of(r)["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }

    /// Obtain a token for `k` through the handler.
    async fn token_for(h: &GnapAsHttp, k: &Key, jti: &str) -> String {
        let r = h.handle(&grant_req(k, jti)).await;
        assert_eq!(r.status, 200, "setup grant must succeed");
        json_of(&r)["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn manage(h_method: &str, k: &Key, token: &str, jti: &str) -> GnapHttpRequest {
        let proof = dpop(k, k, h_method, MANAGE, jti);
        req(
            h_method,
            "/api/gnap/tx/token",
            vec![("Authorization", format!("GNAP {token}")), ("DPoP", proof)],
            Vec::new(),
        )
    }

    // ── grant ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_proved_grant_request_gets_a_token() {
        let (h, k) = (handler(), key());
        let r = h.handle(&grant_req(&k, "g1")).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let body = json_of(&r);
        assert!(body["access_token"]["value"].is_string());
        assert_eq!(body["access_token"]["manage"], "/api/gnap/tx/token");
    }

    #[tokio::test]
    async fn a_grant_request_with_no_proof_is_refused_401() {
        let (h, k) = (handler(), key());
        let r = h
            .handle(&req("POST", "/api/gnap/tx", vec![], body_of(&k)))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(code_of(&r), "invalid_client");
        assert!(!String::from_utf8_lossy(&r.body).contains("access_token"));
    }

    #[tokio::test]
    async fn a_grant_proof_signed_by_another_key_is_refused() {
        let (h, k, other) = (handler(), key(), key());
        let proof = dpop(&other, &k, "POST", GRANT, "g-wrong-signer");
        let r = h
            .handle(&req(
                "POST",
                "/api/gnap/tx",
                vec![("DPoP", proof)],
                body_of(&k),
            ))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(code_of(&r), "invalid_client");
    }

    #[tokio::test]
    async fn a_grant_proof_for_another_url_is_refused() {
        let (h, k) = (handler(), key());
        let proof = dpop(
            &k,
            &k,
            "POST",
            "https://evil.example.test/api/gnap/tx",
            "g-url",
        );
        let r = h
            .handle(&req(
                "POST",
                "/api/gnap/tx",
                vec![("DPoP", proof)],
                body_of(&k),
            ))
            .await;
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn a_replayed_grant_proof_is_refused() {
        let (h, k) = (handler(), key());
        let first = grant_req(&k, "g-replay");
        assert_eq!(h.handle(&first).await.status, 200);
        let again = h.handle(&first).await;
        assert_eq!(again.status, 401);
        assert!(!String::from_utf8_lossy(&again.body).contains("access_token"));
    }

    #[tokio::test]
    async fn a_policy_that_grants_nothing_is_403_request_denied() {
        let (h, k) = (handler_with(Arc::new(DenyAll)), key());
        let r = h.handle(&grant_req(&k, "g-deny")).await;
        assert_eq!(r.status, 403);
        assert_eq!(code_of(&r), "request_denied");
    }

    #[tokio::test]
    async fn a_grant_body_that_is_not_json_is_400() {
        let h = handler();
        let r = h
            .handle(&req("POST", "/api/gnap/tx", vec![], b"not json".to_vec()))
            .await;
        assert_eq!(r.status, 400);
        assert_eq!(code_of(&r), "invalid_request");
    }

    #[tokio::test]
    async fn an_oversized_grant_body_is_400() {
        let h = handler();
        let r = h
            .handle(&req(
                "POST",
                "/api/gnap/tx",
                vec![],
                vec![b' '; MAX_BODY_BYTES + 1],
            ))
            .await;
        assert_eq!(r.status, 400);
        assert_eq!(code_of(&r), "invalid_request");
    }

    #[tokio::test]
    async fn the_grant_endpoint_refuses_other_methods_with_allow() {
        let h = handler();
        for m in ["GET", "PUT", "DELETE", "PATCH"] {
            let r = h.handle(&req(m, "/api/gnap/tx", vec![], Vec::new())).await;
            assert_eq!(r.status, 405, "{m}");
            assert_eq!(r.header("Allow"), Some("POST, OPTIONS"));
        }
    }

    // ── discovery (9.2) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn options_on_the_grant_endpoint_is_the_discovery_document() {
        let h = handler();
        let r = h
            .handle(&req("OPTIONS", "/api/gnap/tx", vec![], Vec::new()))
            .await;
        assert_eq!(r.status, 200);
        let doc = json_of(&r);
        assert_eq!(doc["grant_request_endpoint"], GRANT);
        assert_eq!(
            doc["key_proofs_supported"],
            json!(["dpop", "httpsig", "jwsd"])
        );
        assert_eq!(
            doc["interaction_start_modes_supported"],
            json!(["redirect"])
        );
        assert_eq!(
            doc["interaction_finish_methods_supported"],
            json!(["redirect"])
        );
        assert_eq!(doc["key_rotation_supported"], false);
    }

    #[tokio::test]
    async fn the_discovery_document_needs_no_proof_and_issues_nothing() {
        let h = handler();
        let r = h
            .handle(&req("OPTIONS", "/api/gnap/tx", vec![], Vec::new()))
            .await;
        assert_eq!(r.status, 200);
        assert!(!String::from_utf8_lossy(&r.body).contains("value"));
    }

    // ── token management ────────────────────────────────────────────────

    #[tokio::test]
    async fn a_proved_post_rotates_the_token() {
        let (h, k) = (handler(), key());
        let old = token_for(&h, &k, "m-r0").await;
        let r = h.handle(&manage("POST", &k, &old, "m-r1")).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let body = json_of(&r);
        let new = body["access_token"]["value"].as_str().unwrap().to_string();
        assert_ne!(new, old);
        // The old value is spent: a second rotation of it finds nothing.
        let again = h.handle(&manage("POST", &k, &old, "m-r2")).await;
        assert_eq!(again.status, 404);
    }

    #[tokio::test]
    async fn a_proved_delete_revokes_the_token() {
        let (h, k) = (handler(), key());
        let t = token_for(&h, &k, "m-d0").await;
        let r = h.handle(&manage("DELETE", &k, &t, "m-d1")).await;
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
        let again = h.handle(&manage("DELETE", &k, &t, "m-d2")).await;
        assert_eq!(again.status, 404);
        assert_eq!(code_of(&again), "unknown_request");
    }

    #[tokio::test]
    async fn management_without_a_proof_is_401_and_the_token_survives() {
        let (h, k) = (handler(), key());
        let t = token_for(&h, &k, "m-n0").await;
        let no_proof = req(
            "DELETE",
            "/api/gnap/tx/token",
            vec![("Authorization", format!("GNAP {t}"))],
            Vec::new(),
        );
        let r = h.handle(&no_proof).await;
        assert_eq!(r.status, 401);
        assert_eq!(code_of(&r), "invalid_client");
        // Still live: a proved revoke now succeeds.
        assert_eq!(
            h.handle(&manage("DELETE", &k, &t, "m-n1")).await.status,
            204
        );
    }

    #[tokio::test]
    async fn management_without_an_authorization_header_is_401() {
        let (h, k) = (handler(), key());
        let proof = dpop(&k, &k, "DELETE", MANAGE, "m-a0");
        let r = h
            .handle(&req(
                "DELETE",
                "/api/gnap/tx/token",
                vec![("DPoP", proof)],
                Vec::new(),
            ))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(r.header("WWW-Authenticate"), Some("GNAP"));
    }

    #[tokio::test]
    async fn a_bearer_scheme_is_not_a_gnap_token() {
        let (h, k) = (handler(), key());
        let t = token_for(&h, &k, "m-b0").await;
        let proof = dpop(&k, &k, "DELETE", MANAGE, "m-b1");
        let r = h
            .handle(&req(
                "DELETE",
                "/api/gnap/tx/token",
                vec![("Authorization", format!("Bearer {t}")), ("DPoP", proof)],
                Vec::new(),
            ))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(
            h.handle(&manage("DELETE", &k, &t, "m-b2")).await.status,
            204
        );
    }

    #[tokio::test]
    async fn a_management_proof_signed_by_another_key_is_refused_and_the_token_survives() {
        let (h, k, other) = (handler(), key(), key());
        let t = token_for(&h, &k, "m-o0").await;
        let r = h.handle(&manage("DELETE", &other, &t, "m-o1")).await;
        assert_eq!(r.status, 401);
        assert_eq!(
            h.handle(&manage("DELETE", &k, &t, "m-o2")).await.status,
            204
        );
    }

    #[tokio::test]
    async fn a_replayed_management_proof_is_refused() {
        let (h, k) = (handler(), key());
        let first = token_for(&h, &k, "m-p0").await;
        let second = token_for(&h, &k, "m-p1").await;
        let used = manage("DELETE", &k, &first, "m-p-once");
        assert_eq!(h.handle(&used).await.status, 204);
        // Same proof, other token: refused, and that token survives.
        let replay = req(
            "DELETE",
            "/api/gnap/tx/token",
            vec![
                ("Authorization", format!("GNAP {second}")),
                (
                    "DPoP",
                    used.headers
                        .iter()
                        .find(|(n, _)| n == "DPoP")
                        .unwrap()
                        .1
                        .clone(),
                ),
            ],
            Vec::new(),
        );
        assert_eq!(h.handle(&replay).await.status, 401);
        assert_eq!(
            h.handle(&manage("DELETE", &k, &second, "m-p-fresh"))
                .await
                .status,
            204
        );
    }

    #[tokio::test]
    async fn the_management_endpoint_refuses_other_methods_with_allow() {
        let (h, k) = (handler(), key());
        let t = token_for(&h, &k, "m-w0").await;
        for m in ["GET", "PUT", "PATCH", "OPTIONS"] {
            let r = h.handle(&manage(m, &k, &t, &format!("m-w-{m}"))).await;
            assert_eq!(r.status, 405, "{m}");
            assert_eq!(r.header("Allow"), Some("POST, DELETE"));
        }
        // None of those touched the token.
        assert_eq!(
            h.handle(&manage("DELETE", &k, &t, "m-w-end")).await.status,
            204
        );
    }

    // ── continuation (section 5) ────────────────────────────────────────

    /// A grant that needs interaction: the transaction id and continue token from the response.
    async fn interactive(h: &GnapAsHttp, k: &Key, jti: &str) -> (String, String) {
        let body = json!({
            "client": {"key": {"proof": "dpop", "jwk": serde_json::to_value(&k.jwk).unwrap()}},
            "access_token": {"access": [{"type": "read"}]},
            "interact": {"start": ["redirect"],
                "finish": {"method": "redirect", "uri": "https://client.test/cb", "nonce": "client-nonce"}},
        });
        let proof = dpop(k, k, "POST", GRANT, jti);
        let r = h
            .handle(&req(
                "POST",
                "/api/gnap/tx",
                vec![("DPoP", proof)],
                body.to_string().into_bytes(),
            ))
            .await;
        assert_eq!(r.status, 200, "setup grant must succeed");
        let out = json_of(&r);
        let uri = out["continue"]["uri"].as_str().unwrap();
        let id = uri.rsplit('/').next().unwrap().to_string();
        (
            id,
            out["continue"]["access_token"]["value"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    }

    fn cont(k: &Key, id: &str, token: &str, jti: &str, body: &str) -> GnapHttpRequest {
        let url = format!("{GRANT}/continue/{id}");
        let proof = dpop(k, k, "POST", &url, jti);
        req(
            "POST",
            &format!("/api/gnap/tx/continue/{id}"),
            vec![("Authorization", format!("GNAP {token}")), ("DPoP", proof)],
            body.as_bytes().to_vec(),
        )
    }

    #[tokio::test]
    async fn a_proved_poll_keeps_waiting_and_rotates_the_continue_token() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-p0").await;
        let r = h.handle(&cont(&k, &id, &t0, "c-p1", "")).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let out = json_of(&r);
        let t1 = out["continue"]["access_token"]["value"].as_str().unwrap();
        assert_ne!(t1, t0);
        assert!(
            out.get("access_token").is_none(),
            "no token before approval"
        );
        // The old continue token is spent.
        let again = h.handle(&cont(&k, &id, &t0, "c-p2", "")).await;
        assert_eq!(again.status, 401);
        assert_eq!(code_of(&again), "invalid_continuation");
        // The new one works.
        assert_eq!(h.handle(&cont(&k, &id, t1, "c-p3", "")).await.status, 200);
    }

    #[tokio::test]
    async fn an_approved_transaction_continues_with_its_interact_ref_to_a_token() {
        let (h, service) = parts_with(Arc::new(AllowAll));
        let k = key();
        let (id, t0) = interactive(&h, &k, "c-a0").await;
        let done = service
            .approve_transaction(&id, Some("alice"))
            .await
            .unwrap();
        let iref = done.interact_ref.clone().unwrap();
        // Without the reference the continuation is refused, and the token survives.
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-a1", "")).await.status, 401);
        let body = json!({"interact_ref": iref}).to_string();
        let r = h.handle(&cont(&k, &id, &t0, "c-a2", &body)).await;
        assert_eq!(r.status, 200);
        assert!(json_of(&r)["access_token"]["value"].is_string());
    }

    #[tokio::test]
    async fn a_denied_transaction_is_403_user_denied() {
        let (h, service) = parts_with(Arc::new(AllowAll));
        let k = key();
        let (id, t0) = interactive(&h, &k, "c-d0").await;
        service.deny_transaction(&id).await.unwrap();
        let body = "{}";
        let r = h.handle(&cont(&k, &id, &t0, "c-d1", body)).await;
        assert_eq!(r.status, 403);
        assert_eq!(code_of(&r), "user_denied");
    }

    #[tokio::test]
    async fn a_replayed_continue_request_is_refused() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-r0").await;
        let first = cont(&k, &id, &t0, "c-r-once", "");
        assert_eq!(h.handle(&first).await.status, 200);
        // The very same request again: the proof was spent and the token rotated.
        let again = h.handle(&first).await;
        assert_eq!(again.status, 401);
        assert!(!String::from_utf8_lossy(&again.body).contains("access_token"));
    }

    #[tokio::test]
    async fn a_continue_without_a_proof_is_401_and_the_token_survives() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-n0").await;
        let bare = req(
            "POST",
            &format!("/api/gnap/tx/continue/{id}"),
            vec![("Authorization", format!("GNAP {t0}"))],
            Vec::new(),
        );
        let r = h.handle(&bare).await;
        assert_eq!(r.status, 401);
        assert_eq!(code_of(&r), "invalid_client");
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-n1", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_continue_proof_signed_by_another_key_is_refused_and_the_token_survives() {
        let (h, k, other) = (handler(), key(), key());
        let (id, t0) = interactive(&h, &k, "c-o0").await;
        assert_eq!(
            h.handle(&cont(&other, &id, &t0, "c-o1", "")).await.status,
            401
        );
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-o2", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_continue_proof_for_another_transaction_url_is_refused() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-u0").await;
        let proof = dpop(&k, &k, "POST", &format!("{GRANT}/continue/other"), "c-u1");
        let r = h
            .handle(&req(
                "POST",
                &format!("/api/gnap/tx/continue/{id}"),
                vec![("Authorization", format!("GNAP {t0}")), ("DPoP", proof)],
                Vec::new(),
            ))
            .await;
        assert_eq!(r.status, 401);
    }

    #[tokio::test]
    async fn a_continue_without_an_authorization_header_is_401() {
        let (h, k) = (handler(), key());
        let (id, _t0) = interactive(&h, &k, "c-h0").await;
        let proof = dpop(&k, &k, "POST", &format!("{GRANT}/continue/{id}"), "c-h1");
        let r = h
            .handle(&req(
                "POST",
                &format!("/api/gnap/tx/continue/{id}"),
                vec![("DPoP", proof)],
                Vec::new(),
            ))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(r.header("WWW-Authenticate"), Some("GNAP"));
    }

    #[tokio::test]
    async fn an_unknown_transaction_is_401_invalid_continuation() {
        let (h, k) = (handler(), key());
        let r = h
            .handle(&cont(&k, "no-such-id", "whatever", "c-x0", ""))
            .await;
        assert_eq!(r.status, 401);
        assert_eq!(code_of(&r), "invalid_continuation");
    }

    fn cont_as(
        method: &str,
        k: &Key,
        id: &str,
        token: &str,
        jti: &str,
        body: &str,
    ) -> GnapHttpRequest {
        let url = format!("{GRANT}/continue/{id}");
        let proof = dpop(k, k, method, &url, jti);
        req(
            method,
            &format!("/api/gnap/tx/continue/{id}"),
            vec![("Authorization", format!("GNAP {token}")), ("DPoP", proof)],
            body.as_bytes().to_vec(),
        )
    }

    #[tokio::test]
    async fn a_proved_patch_modifies_the_pending_request_and_rotates_the_token() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-pa0").await;
        let body = json!({"access_token": {"access": [{"type": "write"}]}}).to_string();
        let r = h
            .handle(&cont_as("PATCH", &k, &id, &t0, "c-pa1", &body))
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let out = json_of(&r);
        let t1 = out["continue"]["access_token"]["value"].as_str().unwrap();
        assert_ne!(t1, t0);
        // The old token is spent, the new one works.
        let old = h.handle(&cont(&k, &id, &t0, "c-pa2", "")).await;
        assert_eq!(code_of(&old), "invalid_continuation");
        assert_eq!(h.handle(&cont(&k, &id, t1, "c-pa3", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_patch_that_carries_a_client_or_an_interaction_is_400_and_the_token_survives() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-pb0").await;
        let jwk = serde_json::to_value(&k.jwk).unwrap();
        let with_client = json!({"client": {"key": {"proof": "dpop", "jwk": jwk}}}).to_string();
        let r = h
            .handle(&cont_as("PATCH", &k, &id, &t0, "c-pb1", &with_client))
            .await;
        assert_eq!(r.status, 400);
        let with_interact = json!({"interact": {"start": ["redirect"]}}).to_string();
        let r = h
            .handle(&cont_as("PATCH", &k, &id, &t0, "c-pb2", &with_interact))
            .await;
        assert_eq!(r.status, 400);
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-pb3", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_patch_with_no_proof_a_bad_body_or_no_header_is_refused() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-pc0").await;
        let uri = format!("/api/gnap/tx/continue/{id}");
        let no_proof = req(
            "PATCH",
            &uri,
            vec![("Authorization", format!("GNAP {t0}"))],
            b"{}".to_vec(),
        );
        assert_eq!(h.handle(&no_proof).await.status, 401);
        let no_header = req("PATCH", &uri, vec![], b"{}".to_vec());
        assert_eq!(h.handle(&no_header).await.status, 401);
        let not_json = cont_as("PATCH", &k, &id, &t0, "c-pc1", "not json");
        assert_eq!(h.handle(&not_json).await.status, 400);
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-pc2", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_proved_delete_cancels_the_grant_and_it_cannot_continue() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-d0").await;
        let r = h.handle(&cont_as("DELETE", &k, &id, &t0, "c-d1", "")).await;
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let after = h.handle(&cont(&k, &id, &t0, "c-d2", "")).await;
        assert_eq!(after.status, 401);
        assert_eq!(code_of(&after), "invalid_continuation");
        // A second cancel is refused the same way.
        let twice = h.handle(&cont_as("DELETE", &k, &id, &t0, "c-d3", "")).await;
        assert_eq!(twice.status, 401);
    }

    #[tokio::test]
    async fn a_delete_without_a_proof_or_signed_by_another_key_leaves_the_grant() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-dn0").await;
        let uri = format!("/api/gnap/tx/continue/{id}");
        let no_proof = req(
            "DELETE",
            &uri,
            vec![("Authorization", format!("GNAP {t0}"))],
            Vec::new(),
        );
        assert_eq!(h.handle(&no_proof).await.status, 401);
        let other = key();
        let wrong = cont_as("DELETE", &other, &id, &t0, "c-dn1", "");
        assert_eq!(h.handle(&wrong).await.status, 401);
        // A POST proof does not authorize a DELETE.
        let proof = dpop(&k, &k, "POST", &format!("{GRANT}/continue/{id}"), "c-dn2");
        let swapped = req(
            "DELETE",
            &uri,
            vec![("Authorization", format!("GNAP {t0}")), ("DPoP", proof)],
            Vec::new(),
        );
        assert_eq!(h.handle(&swapped).await.status, 401);
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-dn3", "")).await.status, 200);
    }

    #[tokio::test]
    async fn a_poll_before_the_wait_is_429_too_fast_and_the_token_survives() {
        let (h, _) = parts_waiting(Arc::new(AllowAll), 3600);
        let k = key();
        let (id, t0) = interactive(&h, &k, "c-w0").await;
        let early = h.handle(&cont(&k, &id, &t0, "c-w1", "")).await;
        assert_eq!(early.status, 429);
        assert_eq!(code_of(&early), "too_fast");
        assert_eq!(early.header("Cache-Control"), Some("no-store"));
        // The refusal kept the token usable: a cancel with it still works.
        let cancel = h.handle(&cont_as("DELETE", &k, &id, &t0, "c-w2", "")).await;
        assert_eq!(cancel.status, 204);
    }

    #[tokio::test]
    async fn the_continue_route_refuses_other_methods_with_allow() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-m0").await;
        for m in ["GET", "PUT", "OPTIONS"] {
            let r = h
                .handle(&req(
                    m,
                    &format!("/api/gnap/tx/continue/{id}"),
                    vec![],
                    Vec::new(),
                ))
                .await;
            assert_eq!(r.status, 405, "{m}");
            assert_eq!(r.header("Allow"), Some("POST, PATCH, DELETE"));
        }
        // None of those touched the transaction.
        assert_eq!(
            h.handle(&cont(&k, &id, &t0, "c-m-end", "")).await.status,
            200
        );
    }

    #[tokio::test]
    async fn a_continue_path_that_does_not_name_one_transaction_is_not_ours() {
        let h = handler();
        for p in [
            "/api/gnap/tx/continue",
            "/api/gnap/tx/continue/",
            "/api/gnap/tx/continue/a/b",
        ] {
            assert_eq!(
                h.handle(&req("POST", p, vec![], Vec::new())).await.status,
                404,
                "{p}"
            );
        }
    }

    #[tokio::test]
    async fn a_continue_body_that_is_not_json_or_is_oversized_is_400() {
        let (h, k) = (handler(), key());
        let (id, t0) = interactive(&h, &k, "c-b0").await;
        let r = h.handle(&cont(&k, &id, &t0, "c-b1", "not json")).await;
        assert_eq!(r.status, 400);
        assert_eq!(code_of(&r), "invalid_request");
        let big = " ".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(
            h.handle(&cont(&k, &id, &t0, "c-b2", &big)).await.status,
            400
        );
        // Neither attempt spent the token.
        assert_eq!(h.handle(&cont(&k, &id, &t0, "c-b3", "")).await.status, 200);
    }

    // ── routing and hygiene ─────────────────────────────────────────────

    #[tokio::test]
    async fn an_unregistered_path_is_not_ours() {
        let h = handler();
        assert_eq!(
            h.handle(&req("POST", "/elsewhere", vec![], Vec::new()))
                .await
                .status,
            404
        );
        assert_eq!(
            h.handle(&req("POST", "/api/gnap/tx/continue", vec![], Vec::new()))
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn an_absolute_target_and_a_query_route_by_path() {
        let (h, k) = (handler(), key());
        let proof = dpop(&k, &k, "POST", GRANT, "g-abs");
        let r = h
            .handle(&req(
                "post",
                "https://as.example.test/api/gnap/tx?x=1",
                vec![("dpop", proof)],
                body_of(&k),
            ))
            .await;
        assert_eq!(r.status, 200);
    }

    #[tokio::test]
    async fn paths_are_those_to_register() {
        assert_eq!(handler().paths(), ("/api/gnap/tx", "/api/gnap/tx/token"));
    }
}
