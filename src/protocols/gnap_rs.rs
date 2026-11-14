// SPDX-License-Identifier: MIT OR Apache-2.0
//! The resource-server-facing half of GNAP (RFC 9767 section 3): the discovery document, token
//! introspection and resource set registration.
//!
//! This module holds the protocol logic only. It does not parse HTTP and it does not verify an RS's
//! key proof itself: the deployer supplies two things.
//!
//! - a [`ResourceServerAuthenticator`], which decides who is calling (RFC 9767 section 3.2: the RS
//!   signs its calls to the AS with its own key, never the client instance's or the token's key);
//! - a [`TokenInfoSource`], which says what the AS knows about an access token value;
//! - optionally a [`ResourceRegistry`], which decides and records resource set registrations
//!   (RFC 9767 section 3.4); without one the AS does not offer registration.
//!
//! A route layer (HTTP) hands each request here and must send introspection and registration
//! responses with `Cache-Control: no-store` (RFC 9767 sections 3.3 and 3.4).

use crate::errors::{AuthError, Result};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::Arc;

/// Path of the RS-facing discovery document, under the grant endpoint's scheme and authority.
pub const DISCOVERY_PATH: &str = "/.well-known/gnap-as-rs";

/// Why an RS call was refused (as opposed to answered with an inactive token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsError {
    /// The call was not proved by a known resource server key (`invalid_resource_server`).
    Unauthenticated,
    /// The request body is not a valid request (`invalid_request`).
    BadRequest(String),
    /// The resource server may not register or introspect for the requested access
    /// (`invalid_access`).
    InvalidAccess(String),
}

impl std::fmt::Display for RsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsError::Unauthenticated => write!(f, "resource server not authenticated"),
            RsError::BadRequest(why) | RsError::InvalidAccess(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for RsError {}

/// What the AS knows about one issued access token.
#[derive(Debug, Clone)]
pub struct RsTokenInfo {
    /// The access rights of the token (RFC 9635 section 8 format).
    pub access: Vec<Value>,
    /// The key the token is bound to, by value, or `None` for a bearer token.
    pub key: Option<Value>,
    /// The key proofing method the token is bound with (for example `httpsig`); `None` for bearer.
    pub proof: Option<String>,
    /// Seconds since the Unix epoch after which the token is not valid.
    pub expires_at: u64,
    /// Seconds since the Unix epoch at which the token was issued.
    pub issued_at: u64,
    /// The grant endpoint URL of the AS that issued the token.
    pub grant_endpoint: String,
    /// The client instance the token was issued to, if the AS keeps one.
    pub instance_id: Option<String>,
    /// Token flags.
    pub flags: Vec<String>,
    /// Identifiers of the resource servers the token may be presented at; empty means any.
    pub audience: Vec<String>,
}

/// Where the AS looks tokens up.
#[async_trait]
pub trait TokenInfoSource: Send + Sync {
    /// The token's information, or `None` when this AS did not issue it or no longer holds it
    /// (revoked tokens included).
    async fn token_info(&self, value: &str) -> Option<RsTokenInfo>;
}

/// A resource set registration request, as the AS reads it (RFC 9767 section 3.4).
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRegistration {
    /// The access rights to register (RFC 9635 section 8 format): strings and objects, at least one.
    pub access: Vec<Value>,
    /// Token formats the RS can process; empty when the RS did not say, which leaves the choice to
    /// the AS. When [`GnapRsConfig::token_formats_supported`] is not empty the API has already
    /// checked that at least one listed format is one the AS issues.
    pub token_formats_supported: Vec<String>,
    /// Whether the RS expects to introspect tokens for these resources.
    pub token_introspection_required: bool,
}

/// What the AS answers a registration with (RFC 9767 section 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredResources {
    /// The opaque handle for the registered resource list, which a client instance later uses as a
    /// string access reference. The AS may return the same value for a repeated registration.
    pub resource_reference: String,
    /// An identifier the RS may use to refer to itself in later calls instead of sending its key.
    pub instance_id: Option<String>,
}

/// Decides and records resource set registrations; supplied by the deployer.
#[async_trait]
pub trait ResourceRegistry: Send + Sync {
    /// Register `request.access` for the authenticated resource server `rs`.
    ///
    /// Refuse with [`RsError::InvalidAccess`] when `rs` may not register an access value, or
    /// [`RsError::BadRequest`] for a request the AS cannot honor. Both are answered with HTTP 400
    /// (RFC 9767 section 3.5).
    async fn register(
        &self,
        rs: &AuthenticatedRs,
        request: &ResourceRegistration,
    ) -> std::result::Result<RegisteredResources, RsError>;
}

/// An RS call as the route layer saw it, for the authenticator to check.
#[derive(Debug, Clone)]
pub struct RsCall<'a> {
    /// HTTP method of the call.
    pub http_method: &'a str,
    /// HTTP URI of the call.
    pub http_uri: &'a str,
    /// The `resource_server` member of the request body: an object (by value) or a string (a
    /// reference).
    pub resource_server: &'a Value,
    /// The request headers the proof lives in (for example `signature`, `signature-input`), with
    /// their names in lower case.
    pub headers: &'a [(String, String)],
}

/// Who an authenticated RS is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRs {
    /// The identifier the AS uses for this RS; compared with [`RsTokenInfo::audience`].
    pub id: String,
}

/// Decides which resource server is calling, from its own key proof.
#[async_trait]
pub trait ResourceServerAuthenticator: Send + Sync {
    /// The RS identity, or `None` when the call is not proved by a known RS key.
    async fn authenticate(&self, call: &RsCall<'_>) -> Option<AuthenticatedRs>;
}

/// Settings of the RS-facing API.
#[derive(Debug, Clone)]
pub struct GnapRsConfig {
    /// The grant request endpoint clients use (RFC 9767 section 3.1). Must be an `https` URL
    /// without a fragment.
    pub grant_request_endpoint: String,
    /// The introspection endpoint. Same URL rules.
    pub introspection_endpoint: String,
    /// Key proofing methods the AS can verify, by their registered names. List only methods that
    /// really are verified; an empty list leaves the member out of the document.
    pub key_proofs_supported: Vec<String>,
    /// Token formats the AS issues, by their registered names. Empty leaves the member out.
    pub token_formats_supported: Vec<String>,
}

fn check_https_url(name: &str, url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| AuthError::config(format!("{name} must be an https URL")))?;
    if rest.is_empty() || rest.starts_with('/') || url.contains('#') {
        return Err(AuthError::config(format!(
            "{name} must have a host and no fragment"
        )));
    }
    Ok(())
}

/// The path of an `https` URL (no query), `/` when it has none.
fn url_path(url: &str) -> &str {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let path = rest.find('/').map_or("/", |i| &rest[i..]);
    path.split('?').next().unwrap_or("/")
}

/// The RS-facing API of one AS.
pub struct GnapResourceServerApi {
    config: GnapRsConfig,
    tokens: Arc<dyn TokenInfoSource>,
    authenticator: Arc<dyn ResourceServerAuthenticator>,
    registration: Option<(String, Arc<dyn ResourceRegistry>)>,
}

impl GnapResourceServerApi {
    /// Build the API; refuses an endpoint that RFC 9767 section 3.1 does not allow.
    pub fn new(
        config: GnapRsConfig,
        tokens: Arc<dyn TokenInfoSource>,
        authenticator: Arc<dyn ResourceServerAuthenticator>,
    ) -> Result<Self> {
        check_https_url("grant_request_endpoint", &config.grant_request_endpoint)?;
        check_https_url("introspection_endpoint", &config.introspection_endpoint)?;
        Ok(Self {
            config,
            tokens,
            authenticator,
            registration: None,
        })
    }

    /// Offer resource set registration (RFC 9767 section 3.4) at `endpoint`, decided by `registry`.
    ///
    /// The endpoint must be an `https` URL without a fragment, and not the introspection endpoint.
    pub fn with_registry(
        mut self,
        endpoint: &str,
        registry: Arc<dyn ResourceRegistry>,
    ) -> Result<Self> {
        check_https_url("resource_registration_endpoint", endpoint)?;
        // The route layer matches on the path alone, so a clash there would shadow a route.
        let path = url_path(endpoint);
        if path == url_path(&self.config.introspection_endpoint) || path == DISCOVERY_PATH {
            return Err(AuthError::config(
                "resource_registration_endpoint must not share a path with the introspection endpoint or the discovery document",
            ));
        }
        self.registration = Some((endpoint.to_string(), registry));
        Ok(self)
    }

    /// The registration endpoint URL, or `None` when registration is not offered.
    pub fn registration_endpoint(&self) -> Option<&str> {
        self.registration.as_ref().map(|(url, _)| url.as_str())
    }

    /// The introspection endpoint URL, as configured.
    pub fn introspection_endpoint(&self) -> &str {
        &self.config.introspection_endpoint
    }

    /// The document served at [`DISCOVERY_PATH`] (RFC 9767 section 3.1).
    pub fn discovery_document(&self) -> Value {
        let mut doc = Map::new();
        doc.insert(
            "grant_request_endpoint".into(),
            self.config.grant_request_endpoint.clone().into(),
        );
        doc.insert(
            "introspection_endpoint".into(),
            self.config.introspection_endpoint.clone().into(),
        );
        if let Some(endpoint) = self.registration_endpoint() {
            doc.insert("resource_registration_endpoint".into(), endpoint.into());
        }
        if !self.config.token_formats_supported.is_empty() {
            doc.insert(
                "token_formats_supported".into(),
                self.config.token_formats_supported.clone().into(),
            );
        }
        if !self.config.key_proofs_supported.is_empty() {
            doc.insert(
                "key_proofs_supported".into(),
                self.config.key_proofs_supported.clone().into(),
            );
        }
        Value::Object(doc)
    }

    /// Register a resource set for an RS (RFC 9767 section 3.4).
    ///
    /// `Err` is any refusal, answered with HTTP 400 (section 3.5). `Ok` is the response object:
    /// `resource_reference`, `instance_id` when the registry gave one, and this AS's
    /// `introspection_endpoint`.
    pub async fn register(
        &self,
        call: &RsCall<'_>,
        body: &Value,
    ) -> std::result::Result<Value, RsError> {
        let Some((_, registry)) = &self.registration else {
            return Err(RsError::BadRequest(
                "resource registration is not supported".into(),
            ));
        };
        let Some(rs) = self.authenticator.authenticate(call).await else {
            return Err(RsError::Unauthenticated);
        };
        let bad = |why: &str| RsError::BadRequest(why.into());

        let access = body
            .get("access")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("registration request needs an access array"))?;
        if access.is_empty() {
            return Err(bad("access must list at least one access right"));
        }
        if !access.iter().all(|a| a.is_string() || a.is_object()) {
            return Err(bad("each access entry must be a string or an object"));
        }
        if body.get("resource_server").is_none() {
            return Err(bad("registration request needs resource_server"));
        }
        let token_formats: Vec<String> = match body.get("token_formats_supported") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .and_then(|a| {
                    a.iter()
                        .map(|f| f.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| bad("token_formats_supported must be an array of strings"))?,
        };
        // The AS must refuse when it issues none of the formats the RS can process.
        if !token_formats.is_empty()
            && !self.config.token_formats_supported.is_empty()
            && !token_formats
                .iter()
                .any(|f| self.config.token_formats_supported.contains(f))
        {
            return Err(bad("none of the requested token formats is supported"));
        }
        let introspection_required = match body.get("token_introspection_required") {
            None => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| bad("token_introspection_required must be a boolean"))?,
        };

        let request = ResourceRegistration {
            access: access.clone(),
            token_formats_supported: token_formats,
            token_introspection_required: introspection_required,
        };
        let done = registry.register(&rs, &request).await?;
        let mut out = Map::new();
        out.insert("resource_reference".into(), done.resource_reference.into());
        if let Some(id) = done.instance_id {
            out.insert("instance_id".into(), id.into());
        }
        // Every API built here offers introspection, so the RS may be told where.
        out.insert(
            "introspection_endpoint".into(),
            self.config.introspection_endpoint.clone().into(),
        );
        Ok(Value::Object(out))
    }

    /// Introspect an access token for an RS (RFC 9767 section 3.3).
    ///
    /// `Err` means the call itself is refused: [`RsError::Unauthenticated`] or
    /// [`RsError::BadRequest`]; RFC 9767 section 3.5 answers both with HTTP 400. A token that is not active is an `Ok`
    /// response, `{"active": false}`, with no other member.
    pub async fn introspect(
        &self,
        call: &RsCall<'_>,
        body: &Value,
    ) -> std::result::Result<Value, RsError> {
        let Some(rs) = self.authenticator.authenticate(call).await else {
            return Err(RsError::Unauthenticated);
        };
        let value = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                RsError::BadRequest("introspection request needs access_token".into())
            })?;
        // The authenticator saw `resource_server` in the call; the member itself is required.
        if body.get("resource_server").is_none() {
            return Err(RsError::BadRequest(
                "introspection request needs resource_server".into(),
            ));
        }

        let inactive = || Ok(serde_json::json!({ "active": false }));
        let Some(info) = self.tokens.token_info(value).await else {
            return inactive();
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= info.expires_at {
            return inactive();
        }
        if !info.audience.is_empty() && !info.audience.contains(&rs.id) {
            return inactive();
        }
        // A proof method the RS says the client used must be the one the token is bound with.
        if let Some(proof) = body.get("proof") {
            match (proof.as_str(), info.proof.as_deref()) {
                (Some(asked), Some(bound)) if asked == bound => {}
                _ => return inactive(),
            }
        }
        // Every access right the RS needs must be among the token's. A request this cannot read is
        // never answered as active.
        if let Some(needed) = body.get("access") {
            let Some(needed) = needed.as_array() else {
                return inactive();
            };
            if !needed.iter().all(|n| info.access.contains(n)) {
                return inactive();
            }
        }

        let mut out = Map::new();
        out.insert("active".into(), true.into());
        out.insert("access".into(), Value::Array(info.access.clone()));
        if let Some(key) = &info.key {
            out.insert("key".into(), key.clone());
        }
        if !info.flags.is_empty() {
            out.insert("flags".into(), info.flags.clone().into());
        }
        out.insert("exp".into(), info.expires_at.into());
        out.insert("iat".into(), info.issued_at.into());
        out.insert("iss".into(), info.grant_endpoint.clone().into());
        if let Some(id) = &info.instance_id {
            out.insert("instance_id".into(), id.clone().into());
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    struct Tokens(HashMap<String, RsTokenInfo>);

    #[async_trait]
    impl TokenInfoSource for Tokens {
        async fn token_info(&self, value: &str) -> Option<RsTokenInfo> {
            self.0.get(value).cloned()
        }
    }

    /// Authenticates every call as the RS named `id`, or none when `id` is `None`.
    struct Rs(Option<&'static str>);

    #[async_trait]
    impl ResourceServerAuthenticator for Rs {
        async fn authenticate(&self, _call: &RsCall<'_>) -> Option<AuthenticatedRs> {
            self.0.map(|id| AuthenticatedRs { id: id.to_string() })
        }
    }

    /// Counts its calls; refuses the access value `"forbidden"`.
    struct Registry(std::sync::atomic::AtomicUsize);

    #[async_trait]
    impl ResourceRegistry for Registry {
        async fn register(
            &self,
            rs: &AuthenticatedRs,
            request: &ResourceRegistration,
        ) -> std::result::Result<RegisteredResources, RsError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if request.access.contains(&json!("forbidden")) {
                return Err(RsError::InvalidAccess("not permitted".into()));
            }
            Ok(RegisteredResources {
                resource_reference: format!("ref-for-{}", rs.id),
                instance_id: None,
            })
        }
    }

    const REGISTER_URL: &str = "https://as.example.test/gnap/resource";

    fn registering(
        c: GnapRsConfig,
        rs: Option<&'static str>,
    ) -> (GnapResourceServerApi, Arc<Registry>) {
        let registry = Arc::new(Registry(Default::default()));
        let api = build(c, vec![], rs)
            .unwrap()
            .with_registry(REGISTER_URL, registry.clone())
            .unwrap();
        (api, registry)
    }

    async fn register(
        api: &GnapResourceServerApi,
        body: Value,
    ) -> std::result::Result<Value, RsError> {
        let rs = json!("rs-1");
        let call = RsCall {
            http_method: "POST",
            http_uri: REGISTER_URL,
            resource_server: &rs,
            headers: &[],
        };
        api.register(&call, &body).await
    }

    fn registration(extra: Value) -> Value {
        let mut b = json!({"access": ["dolphin-metadata", {"type": "photo-api"}], "resource_server": "rs-1"});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn info() -> RsTokenInfo {
        RsTokenInfo {
            access: vec![
                json!("dolphin-metadata"),
                json!({"type": "photo-api", "actions": ["read"]}),
            ],
            key: Some(json!({"proof": "httpsig", "jwk": {"kty": "EC", "crv": "P-256"}})),
            proof: Some("httpsig".into()),
            expires_at: now() + 600,
            issued_at: now(),
            grant_endpoint: "https://as.example.test/tx".into(),
            instance_id: Some("client-1".into()),
            flags: vec![],
            audience: vec![],
        }
    }

    fn config() -> GnapRsConfig {
        GnapRsConfig {
            grant_request_endpoint: "https://as.example.test/tx".into(),
            introspection_endpoint: "https://as.example.test/introspect".into(),
            key_proofs_supported: vec![],
            token_formats_supported: vec![],
        }
    }

    fn build(
        c: GnapRsConfig,
        tokens: Vec<(&str, RsTokenInfo)>,
        rs: Option<&'static str>,
    ) -> Result<GnapResourceServerApi> {
        let map = tokens
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        GnapResourceServerApi::new(c, Arc::new(Tokens(map)), Arc::new(Rs(rs)))
    }

    fn api_with(
        tokens: Vec<(&str, RsTokenInfo)>,
        rs: Option<&'static str>,
    ) -> GnapResourceServerApi {
        build(config(), tokens, rs).unwrap()
    }

    async fn introspect(
        api: &GnapResourceServerApi,
        body: Value,
    ) -> std::result::Result<Value, RsError> {
        let rs = json!("rs-1");
        let call = RsCall {
            http_method: "POST",
            http_uri: "https://as.example.test/introspect",
            resource_server: &rs,
            headers: &[],
        };
        api.introspect(&call, &body).await
    }

    fn req(extra: Value) -> Value {
        let mut b = json!({"access_token": "tok-1", "resource_server": "rs-1"});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    }

    fn inactive() -> Value {
        json!({"active": false})
    }

    #[test]
    fn discovery_document_carries_the_required_members() {
        let doc = api_with(vec![], Some("rs-1")).discovery_document();
        assert_eq!(doc["grant_request_endpoint"], "https://as.example.test/tx");
        assert_eq!(
            doc["introspection_endpoint"],
            "https://as.example.test/introspect"
        );
        assert!(doc.get("key_proofs_supported").is_none(), "{doc}");
        assert!(doc.get("token_formats_supported").is_none(), "{doc}");
        assert!(doc.get("resource_registration_endpoint").is_none(), "{doc}");
    }

    #[test]
    fn discovery_lists_proofs_and_formats_only_when_configured() {
        let mut c = config();
        c.key_proofs_supported = vec!["httpsig".into()];
        c.token_formats_supported = vec!["opaque".into()];
        let doc = build(c, vec![], None).unwrap().discovery_document();
        assert_eq!(doc["key_proofs_supported"], json!(["httpsig"]));
        assert_eq!(doc["token_formats_supported"], json!(["opaque"]));
    }

    #[test]
    fn endpoints_must_be_https_urls_without_a_fragment() {
        for bad in [
            "http://as.example.test/tx",
            "/tx",
            "https://",
            "https:///tx",
            "https://as.example.test/tx#f",
        ] {
            let mut c = config();
            c.grant_request_endpoint = bad.into();
            assert!(build(c, vec![], None).is_err(), "{bad} must be refused");
            let mut c = config();
            c.introspection_endpoint = bad.into();
            assert!(build(c, vec![], None).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn the_registration_endpoint_is_checked_and_advertised() {
        let (api, _) = registering(config(), Some("rs-1"));
        assert_eq!(api.registration_endpoint(), Some(REGISTER_URL));
        assert_eq!(
            api.discovery_document()["resource_registration_endpoint"],
            REGISTER_URL
        );
        for bad in [
            "http://as.example.test/gnap/resource",
            "https://as.example.test/gnap/resource#f",
            "https://",
            // the same path as the introspection endpoint or the discovery document
            "https://other.example.test/introspect",
            "https://as.example.test/introspect?x=1",
            "https://as.example.test/.well-known/gnap-as-rs",
        ] {
            let r = build(config(), vec![], None)
                .unwrap()
                .with_registry(bad, Arc::new(Registry(Default::default())));
            assert!(r.is_err(), "{bad} must be refused");
        }
    }

    #[tokio::test]
    async fn registration_needs_a_registry_and_an_authenticated_rs() {
        let api = api_with(vec![], Some("rs-1"));
        assert!(matches!(
            register(&api, registration(json!({}))).await,
            Err(RsError::BadRequest(_))
        ));
        let (api, registry) = registering(config(), None);
        assert_eq!(
            register(&api, registration(json!({}))).await,
            Err(RsError::Unauthenticated)
        );
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_registration_is_answered_with_the_reference_and_the_introspection_endpoint() {
        let (api, registry) = registering(config(), Some("rs-1"));
        let r = register(&api, registration(json!({}))).await.unwrap();
        assert_eq!(r["resource_reference"], "ref-for-rs-1");
        assert_eq!(
            r["introspection_endpoint"],
            "https://as.example.test/introspect"
        );
        assert!(r.get("instance_id").is_none(), "{r}");
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_registry_refusal_passes_through_and_bad_requests_never_reach_it() {
        let (api, registry) = registering(config(), Some("rs-1"));
        assert_eq!(
            register(&api, registration(json!({"access": ["forbidden"]}))).await,
            Err(RsError::InvalidAccess("not permitted".into()))
        );
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        for bad in [
            json!({"resource_server": "rs-1"}),
            json!({"access": [], "resource_server": "rs-1"}),
            json!({"access": "a", "resource_server": "rs-1"}),
            json!({"access": [1], "resource_server": "rs-1"}),
            json!({"access": [null], "resource_server": "rs-1"}),
            json!({"access": ["a"]}),
            registration(json!({"token_formats_supported": "opaque"})),
            registration(json!({"token_formats_supported": ["opaque", 1]})),
            registration(json!({"token_introspection_required": "yes"})),
            registration(json!({"token_introspection_required": 1})),
        ] {
            assert!(
                matches!(
                    register(&api, bad.clone()).await,
                    Err(RsError::BadRequest(_))
                ),
                "{bad} must be a bad request"
            );
        }
        assert_eq!(registry.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn token_formats_are_checked_against_the_ones_the_as_issues() {
        let mut c = config();
        c.token_formats_supported = vec!["opaque".into()];
        let (api, _) = registering(c, Some("rs-1"));
        assert!(
            register(
                &api,
                registration(json!({"token_formats_supported": ["jwt"]}))
            )
            .await
            .is_err()
        );
        for ok in [
            json!({}),
            json!({"token_formats_supported": ["jwt", "opaque"]}),
        ] {
            assert!(register(&api, registration(ok)).await.is_ok());
        }
        // An AS that does not list its formats leaves the choice to itself.
        let (api, _) = registering(config(), Some("rs-1"));
        assert!(
            register(
                &api,
                registration(json!({"token_formats_supported": ["jwt"]}))
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn an_active_token_is_described_without_its_value() {
        let api = api_with(vec![("tok-1", info())], Some("rs-1"));
        let r = introspect(&api, req(json!({}))).await.unwrap();
        assert_eq!(r["active"], true);
        assert_eq!(r["access"][0], "dolphin-metadata");
        assert_eq!(r["key"]["proof"], "httpsig");
        assert_eq!(r["iss"], "https://as.example.test/tx");
        assert_eq!(r["instance_id"], "client-1");
        assert!(r["exp"].is_u64() && r["iat"].is_u64());
        assert!(
            !r.to_string().contains("tok-1"),
            "the token value must not come back: {r}"
        );
    }

    #[tokio::test]
    async fn a_bearer_token_has_no_key_member() {
        let mut t = info();
        t.key = None;
        t.proof = None;
        let api = api_with(vec![("tok-1", t)], Some("rs-1"));
        let r = introspect(&api, req(json!({}))).await.unwrap();
        assert_eq!(r["active"], true);
        assert!(r.get("key").is_none(), "{r}");
    }

    #[tokio::test]
    async fn an_unknown_or_revoked_token_is_inactive_and_nothing_else() {
        let api = api_with(vec![], Some("rs-1"));
        assert_eq!(introspect(&api, req(json!({}))).await.unwrap(), inactive());
    }

    #[tokio::test]
    async fn an_expired_token_is_inactive() {
        let mut t = info();
        t.expires_at = now() - 1;
        let api = api_with(vec![("tok-1", t)], Some("rs-1"));
        assert_eq!(introspect(&api, req(json!({}))).await.unwrap(), inactive());
    }

    #[tokio::test]
    async fn a_token_for_other_resource_servers_is_inactive_here() {
        let mut t = info();
        t.audience = vec!["rs-2".into()];
        let other = api_with(vec![("tok-1", t.clone())], Some("rs-1"));
        assert_eq!(
            introspect(&other, req(json!({}))).await.unwrap(),
            inactive()
        );
        let own = api_with(vec![("tok-1", t)], Some("rs-2"));
        assert_eq!(
            introspect(&own, req(json!({}))).await.unwrap()["active"],
            true
        );
    }

    #[tokio::test]
    async fn the_proof_method_must_match_the_one_the_token_is_bound_with() {
        let api = api_with(vec![("tok-1", info())], Some("rs-1"));
        let same = introspect(&api, req(json!({"proof": "httpsig"})))
            .await
            .unwrap();
        assert_eq!(same["active"], true);
        let other = introspect(&api, req(json!({"proof": "mtls"})))
            .await
            .unwrap();
        assert_eq!(other, inactive());
        let odd = introspect(&api, req(json!({"proof": 7}))).await.unwrap();
        assert_eq!(odd, inactive());
        let mut bearer = info();
        bearer.key = None;
        bearer.proof = None;
        let api = api_with(vec![("tok-1", bearer)], Some("rs-1"));
        let r = introspect(&api, req(json!({"proof": "httpsig"})))
            .await
            .unwrap();
        assert_eq!(r, inactive());
    }

    #[tokio::test]
    async fn the_access_the_rs_needs_must_be_covered_by_the_token() {
        let api = api_with(vec![("tok-1", info())], Some("rs-1"));
        let covered = req(json!({"access": ["dolphin-metadata"]}));
        assert_eq!(introspect(&api, covered).await.unwrap()["active"], true);
        let not_covered = req(json!({"access": ["dolphin-metadata", "something-else"]}));
        assert_eq!(introspect(&api, not_covered).await.unwrap(), inactive());
        let unreadable = req(json!({"access": "dolphin-metadata"}));
        assert_eq!(introspect(&api, unreadable).await.unwrap(), inactive());
    }

    #[tokio::test]
    async fn an_unauthenticated_rs_is_refused_before_the_token_is_looked_up() {
        let api = api_with(vec![("tok-1", info())], None);
        assert_eq!(
            introspect(&api, req(json!({}))).await,
            Err(RsError::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn a_body_without_the_required_members_is_refused() {
        let api = api_with(vec![("tok-1", info())], Some("rs-1"));
        let no_token = json!({"resource_server": "rs-1"});
        assert!(matches!(
            introspect(&api, no_token).await,
            Err(RsError::BadRequest(_))
        ));
        let no_rs = json!({"access_token": "tok-1"});
        assert!(matches!(
            introspect(&api, no_rs).await,
            Err(RsError::BadRequest(_))
        ));
        let bad_token = json!({"access_token": 5, "resource_server": "rs-1"});
        assert!(matches!(
            introspect(&api, bad_token).await,
            Err(RsError::BadRequest(_))
        ));
    }
}
