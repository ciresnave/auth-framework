// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP (Grant Negotiation and Authorization Protocol) implementation.
//!
//! This module implements the GNAP specification (draft-ietf-gnap-core-protocol),
//! providing an emerging next-generation alternative to OAuth 2.0 with stronger
//! cryptographic binding and a unified request structure.
//!
//! # Implemented Features
//!
//! - Transaction lifecycle (create, continue, approve, deny)
//! - Client key binding via JWK (ES256, RS256, EdDSA); a client key is required
//! - Access granted only through a [`GnapAccessPolicy`] (default deny)
//! - One-time interaction reference and hash (draft §4.2, §4.2.3)
//! - Continuation token rotation on each use
//! - Token management (revocation)
//! - Subject information responses
//! - Transaction expiration and cleanup

use crate::errors::{AuthError, Result};
use crate::protocols::gnap_consent::{GnapConsent, GnapConsentStore, InMemoryConsentStore};
use crate::protocols::gnap_interaction::{
    FinishMethod, FinishRequest, HashMethod, StartMode, generate_user_code, interaction_hash,
    normalize_user_code, parse_start, parse_ui_locales, validate_push_target,
};
use crate::protocols::gnap_push::{PushResolver, PushSender, deliver_push};
use crate::protocols::gnap_store::{
    GnapIssuedToken, GnapTokenStore, GnapTransactionStore, InMemoryTokenStore,
    InMemoryTransactionStore,
};
use crate::protocols::gnap_wire::{
    GnapAccess, GnapAccessObject, GnapAccessTokenRequest, GnapAccessTokenRequests,
    validate_access_token_requests_with_flags,
};
use crate::server::security::dpop::DpopManager;
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapConfig {
    pub enabled: bool,
    pub transaction_endpoint: String,
    /// Base URL for interaction redirects (must be configured for production)
    pub interaction_base_url: Option<String>,
    /// Default access token lifetime in seconds
    pub token_lifetime_secs: u64,
    /// Transaction lifetime in seconds before expiration (default: 600 = 10 minutes)
    pub transaction_lifetime_secs: u64,
}

impl Default for GnapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: None,
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        }
    }
}

/// A GNAP transaction request representing the client's intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapTransactionRequest {
    pub client: Option<GnapClientInfo>,
    pub interact: Option<GnapInteractionRequirements>,
    /// The access tokens requested (RFC 9635 section 2.1): one token request, or an array of them, in the
    /// RFC's own shape. Build one from grant-level rights with `vec_of_rights.into()`; read the rights with
    /// [`GnapService::requested_rights`].
    #[serde(rename = "access_token")]
    // sec012: public - this is the request for access rights (RFC 9635 section 2.1: type, actions, locations), not a token value;
    // the token itself is issued later and is not held here.
    pub access_token_request: Option<GnapAccessTokenRequests>,
    /// Subject information request
    pub subject: Option<GnapSubjectRequest>,
}

/// Description of a single access right being requested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapAccessRequest {
    /// Type of access (e.g. "read", "write", or an API-specific identifier)
    #[serde(rename = "type")]
    pub access_type: String,
    /// Actions within this type
    #[serde(default)]
    pub actions: Vec<String>,
    /// Locations/URIs where this access applies
    #[serde(default)]
    pub locations: Vec<String>,
}

impl From<Vec<GnapAccessRequest>> for GnapAccessTokenRequests {
    /// One token request that asks for all of `rights` (no label, no flags).
    fn from(rights: Vec<GnapAccessRequest>) -> Self {
        let non_empty = |v: Vec<String>| if v.is_empty() { None } else { Some(v) };
        GnapAccessTokenRequests::One(GnapAccessTokenRequest {
            access: rights
                .into_iter()
                .map(|right| {
                    GnapAccess::Object(GnapAccessObject {
                        access_type: right.access_type,
                        actions: non_empty(right.actions),
                        locations: non_empty(right.locations),
                        ..GnapAccessObject::default()
                    })
                })
                .collect(),
            label: None,
            flags: Vec::new(),
        })
    }
}

/// Subject information the client is requesting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapSubjectRequest {
    /// Requested subject identifier formats
    #[serde(default)]
    pub sub_id_formats: Vec<String>,
    /// Requested assertion formats (e.g. "id_token", "saml2")
    #[serde(default)]
    pub assertion_formats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientInfo {
    /// Client key in JWK format for cryptographic binding
    pub key: Option<GnapClientKey>,
    /// Client display information
    pub display: Option<GnapClientDisplay>,
}

/// Client key with proof method (draft §7.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientKey {
    /// Proof method: "httpsig", "mtls", "dpop", "jws", "jwsd", or "test"
    pub proof: String,
    /// The client's public key as a JWK. Exactly one of `jwk`, `cert` and `cert#S256` is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<GnapJwk>,
    /// The key as an X.509 certificate, base64 DER (RFC 9635 section 7.1). Proved by `mtls`, which
    /// matches the presented certificate against this one; the chain is **not** validated here
    /// (see [`GnapProof::client_certificate_der`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// The key as the base64url SHA-256 of a certificate's DER (RFC 9635 section 7.1). Proved by
    /// `mtls` like `cert`, and equally without any chain validation.
    #[serde(default, rename = "cert#S256", skip_serializing_if = "Option::is_none")]
    pub cert_s256: Option<String>,
}

/// Minimal JWK representation sufficient for GNAP key binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapJwk {
    /// Key type: "EC", "RSA", or "OKP"
    pub kty: String,
    /// Key ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    // EC fields (P-256 / ES256)
    /// EC curve name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // RSA fields
    /// RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientDisplay {
    pub name: Option<String>,
    pub uri: Option<String>,
}

/// How many characters the short code of a `user_code` start has (RFC 9635 section 3.3.3 recommends six to eight).
const USER_CODE_LEN: usize = 8;

/// Read `interact.start` entries: a string, or an object carrying a string `mode` (RFC 9635 section 2.5.1).
fn deserialize_start_modes<'de, D>(d: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let entries = Vec::<serde_json::Value>::deserialize(d)?;
    entries
        .into_iter()
        .map(|e| match e {
            serde_json::Value::String(mode) => Ok(mode),
            serde_json::Value::Object(o) => match o.get("mode") {
                Some(serde_json::Value::String(mode)) => Ok(mode.clone()),
                _ => Err(D::Error::custom(
                    "interact.start object entries need a string `mode`",
                )),
            },
            _ => Err(D::Error::custom(
                "interact.start entries are strings or objects",
            )),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapInteractionRequirements {
    /// The start modes offered (RFC 9635 section 2.5.1). On the wire an entry is a string or an object with a
    /// string `mode` (`{"mode":"redirect"}`); both read as the mode name. An object without a string `mode`
    /// is refused when the request is read.
    #[serde(deserialize_with = "deserialize_start_modes")]
    pub start: Vec<String>,
    pub finish: Option<GnapInteractionFinish>,
    /// `interact.hints` (RFC 9635 section 2.5.3). Only `ui_locales` is read, and its shape is checked at
    /// transaction open; read it back with [`GnapService::interaction_locales`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapInteractionFinish {
    pub method: String,
    pub uri: String,
    pub nonce: String,
    /// The hash method the client asked for (RFC 9635 section 2.5.2). The service computes
    /// `sha-256` only, so any other value is refused at transaction open, never ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_method: Option<String>,
}

impl GnapTransactionRequest {
    /// Create a builder for a GNAP transaction request.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::gnap::GnapTransactionRequest;
    ///
    /// let req = GnapTransactionRequest::builder()
    ///     .access("read", &["list"], &["https://api.example.com"])
    ///     .subject_formats(vec!["opaque".into()])
    ///     .build();
    /// ```
    pub fn builder() -> GnapTransactionRequestBuilder {
        GnapTransactionRequestBuilder {
            client: None,
            interact: None,
            access_token: Vec::new(),
            subject: None,
        }
    }
}

/// Builder for [`GnapTransactionRequest`].
pub struct GnapTransactionRequestBuilder {
    client: Option<GnapClientInfo>,
    interact: Option<GnapInteractionRequirements>,
    access_token: Vec<GnapAccessRequest>,
    subject: Option<GnapSubjectRequest>,
}

impl GnapTransactionRequestBuilder {
    /// Set the client info with a key binding.
    pub fn client(mut self, client: GnapClientInfo) -> Self {
        self.client = Some(client);
        self
    }

    /// Set client info from a key and proof method.
    pub fn client_key(mut self, jwk: GnapJwk, proof: impl Into<String>) -> Self {
        self.client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: proof.into(),
                jwk: Some(jwk),
                cert: None,
                cert_s256: None,
            }),
            display: None,
        });
        self
    }

    /// Set client info from a certificate (base64 DER), proved with `mtls`.
    pub fn client_key_cert(mut self, cert_der_base64: impl Into<String>) -> Self {
        self.client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "mtls".to_string(),
                jwk: None,
                cert: Some(cert_der_base64.into()),
                cert_s256: None,
            }),
            display: None,
        });
        self
    }

    /// Set client info from a certificate's SHA-256 thumbprint (base64url), proved with `mtls`.
    pub fn client_key_cert_s256(mut self, thumbprint: impl Into<String>) -> Self {
        self.client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "mtls".to_string(),
                jwk: None,
                cert: None,
                cert_s256: Some(thumbprint.into()),
            }),
            display: None,
        });
        self
    }

    /// Set interaction requirements for redirect flow.
    pub fn redirect_interaction(
        mut self,
        callback_uri: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        self.interact = Some(GnapInteractionRequirements {
            start: vec!["redirect".to_string()],
            finish: Some(GnapInteractionFinish {
                method: "redirect".to_string(),
                uri: callback_uri.into(),
                nonce: nonce.into(),
                hash_method: None,
            }),
            hints: None,
        });
        self
    }

    /// Set interaction requirements (raw).
    pub fn interact(mut self, interact: GnapInteractionRequirements) -> Self {
        self.interact = Some(interact);
        self
    }

    /// Add an access request with type, actions, and locations.
    pub fn access(
        mut self,
        access_type: impl Into<String>,
        actions: &[impl AsRef<str>],
        locations: &[impl AsRef<str>],
    ) -> Self {
        self.access_token.push(GnapAccessRequest {
            access_type: access_type.into(),
            actions: actions.iter().map(|a| a.as_ref().to_string()).collect(),
            locations: locations.iter().map(|l| l.as_ref().to_string()).collect(),
        });
        self
    }

    /// Add a simple access request (type only, no actions/locations).
    pub fn access_type(self, access_type: impl Into<String>) -> Self {
        self.access(access_type, &[] as &[&str], &[] as &[&str])
    }

    /// Request subject information with the given identifier formats.
    pub fn subject_formats(mut self, formats: Vec<String>) -> Self {
        self.subject = Some(GnapSubjectRequest {
            sub_id_formats: formats,
            assertion_formats: vec![],
        });
        self
    }

    /// Request subject information (raw).
    pub fn subject(mut self, subject: GnapSubjectRequest) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Build the [`GnapTransactionRequest`].
    pub fn build(self) -> GnapTransactionRequest {
        GnapTransactionRequest {
            client: self.client,
            interact: self.interact,
            access_token_request: if self.access_token.is_empty() {
                None
            } else {
                Some(self.access_token.into())
            },
            subject: self.subject,
        }
    }
}

/// State of a GNAP transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GnapTransactionState {
    /// Waiting for user interaction
    Pending,
    /// User has approved; access token can be issued
    Approved,
    /// Transaction was denied or expired
    Denied,
}

/// An open GNAP transaction, as a [`GnapTransactionStore`] keeps it.
#[derive(Clone, Serialize, Deserialize)]
pub struct GnapTransaction {
    /// The transaction id, the store's key.
    pub id: String,
    /// Where the transaction stands.
    pub state: GnapTransactionState,
    /// What the client asked for.
    pub request: GnapTransactionRequest,
    /// The continuation token the client must present next; rotated on every poll.
    pub continue_token: String,
    /// When the transaction was created (epoch seconds).
    pub created_at: u64,
    /// Server-generated nonce for interaction hash verification (draft §4.2.3)
    pub interact_nonce: Option<String>,
    /// Subject identifier assigned after approval
    pub subject_id: Option<String>,
    /// One-time interaction reference issued when a finish-method transaction is approved
    pub interact_ref: Option<String>,
    /// The short code a person types at the AS when the client asked for the `user_code` start
    /// (RFC 9635 section 3.3.3), kept in its normalised form.
    #[serde(default)]
    pub user_code: Option<String>,
    /// How many times the store has replaced this transaction. The store's compare-and-swap
    /// ([`GnapTransactionStore::replace_if_unchanged`]) keys on it; nothing else writes it.
    #[serde(default)]
    pub revision: u64,
    /// When the client last polled this pending transaction (epoch seconds), 0 if it never has;
    /// the next poll must come `wait` seconds after this, or after `created_at` for the first.
    #[serde(default)]
    pub last_poll_at: u64,
    /// How many continuation requests presented a wrong interaction hash or reference. At the service's cap
    /// the transaction is invalidated (`too_many_attempts`, RFC 9635 section 3.6); never reset.
    #[serde(default)]
    pub bad_attempts: u32,
}

impl std::fmt::Debug for GnapTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("GnapTransaction");
        d.field("id", &self.id);
        d.field("state", &self.state);
        d.field("request", &self.request);
        d.field(
            "continue_token",
            &crate::utils::redact::redacted(&self.continue_token),
        );
        d.field("created_at", &self.created_at);
        d.field(
            "interact_nonce",
            &crate::utils::redact::redacted(&self.interact_nonce),
        );
        d.field("subject_id", &self.subject_id);
        d.field(
            "interact_ref",
            &crate::utils::redact::redacted(&self.interact_ref),
        );
        d.field(
            "user_code",
            &crate::utils::redact::redacted(&self.user_code),
        );
        d.field("revision", &self.revision);
        d.finish()
    }
}

/// The HTTP request a client key signs, handed to the `_with_proof` entry points.
///
/// Only the `dpop` proof method can be verified here: the proof is the request's `DPoP` header
/// and must be signed by the key the client named in its request, for this method and URI.
#[derive(Debug, Clone, Copy)]
pub struct GnapProof<'a> {
    /// HTTP method of the request (`htm`).
    pub http_method: &'a str,
    /// HTTP URI of the request, without query or fragment (`htu`).
    pub http_uri: &'a str,
    /// The request's `DPoP` header, if it had one.
    pub dpop_proof: Option<&'a str>,
    /// A server-issued DPoP nonce the proof must carry, if the caller uses them.
    pub expected_nonce: Option<&'a str>,
    /// The DER of the client certificate the TLS layer authenticated on this request, for the
    /// `mtls` proof method. The caller's TLS terminator must have verified the handshake (proof
    /// of the private key); this crate then checks the certificate is the one the key names.
    ///
    /// **Chain validation stays with the integrator.** The `cert` and `cert#S256` key forms are
    /// matched by value or thumbprint only: this crate does not build or validate a certificate
    /// chain, check revocation or expiry, or decide which CAs to trust. RFC 9635 sections 11.3 and
    /// 11.4 leave that trust to registration or first use, so an integrator who needs it must
    /// enforce it in the TLS terminator or before calling the `_with_proof` entry points.
    pub client_certificate_der: Option<&'a [u8]>,
    /// The request's header fields as `(name, value)` pairs, for the `httpsig` proof method (RFC 9421
    /// covers headers such as `content-digest` and `authorization`). Empty when the caller has none.
    pub http_headers: &'a [(&'a str, &'a str)],
    /// The request content the `httpsig` proof method's `content-digest` covers (empty when none).
    pub http_body: &'a [u8],
}

/// Decides which access rights a client key is granted.
///
/// [`GnapService`] never issues an access token on its own authority: an integrator supplies a
/// policy with [`GnapService::with_access_policy`], and the token carries exactly what the policy
/// returns, which can be less than the client asked for. An empty return denies the request. A
/// service without a policy denies every request for an access token.
#[async_trait]
pub trait GnapAccessPolicy: Send + Sync {
    /// The rights to grant to the client key with this RFC 7638 `client_key_thumbprint` out of
    /// the `requested` ones. Return an empty list to deny.
    async fn grant(
        &self,
        client_key_thumbprint: &str,
        requested: &[GnapAccessRequest],
    ) -> Vec<GnapAccessRequest>;
}

/// What the authorization server hands back to the client when the resource owner approves a
/// transaction that uses an interaction `finish` method (RFC 9635 section 4.2).
///
/// The integrator delivers both values to the client's finish URI. The client checks `hash`
/// (section 4.2.3) and presents `interact_ref`, once, in its continuation request.
#[derive(Clone, PartialEq, Eq)]
pub struct GnapInteractionCompletion {
    /// The one-time interaction reference, `None` when the transaction has no finish method.
    pub interact_ref: Option<String>,
    /// The interaction hash the client verifies, `None` when the transaction has no finish method.
    pub hash: Option<String>,
}

impl std::fmt::Debug for GnapInteractionCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("GnapInteractionCompletion");
        d.field(
            "interact_ref",
            &crate::utils::redact::redacted(&self.interact_ref),
        );
        d.field("hash", &crate::utils::redact::redacted(&self.hash));
        d.finish()
    }
}

/// What [`GnapService::revoke_client_key`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientKeyRevocation {
    /// Access tokens removed from the token store.
    pub tokens: usize,
    /// Consent records marked withdrawn.
    pub consents: usize,
    /// Pending or approved transactions dropped, so no continuation can still issue a token.
    pub transactions: usize,
}

pub struct GnapService {
    config: GnapConfig,
    /// Decides what is granted; without one no access token is issued.
    policy: Option<Arc<dyn GnapAccessPolicy>>,
    /// Active transactions (keyed by transaction ID)
    transactions: Arc<dyn GnapTransactionStore>,
    /// Issued access tokens (keyed by token value)
    issued_tokens: Arc<dyn GnapTokenStore>,
    /// Where the resource owner's approvals are recorded (RFC 9635 section 4).
    consents: Arc<dyn GnapConsentStore>,
    /// Wrong user codes typed per caller: (count, when the window began). See
    /// [`GnapService::transaction_for_user_code`].
    code_failures: std::sync::Mutex<std::collections::HashMap<String, (u32, u64)>>,
    /// Rotations answered in the last [`ROTATION_RETRY_SECS`] seconds, keyed by the old token value, so a client
    /// that lost the response can retry (RFC 9635 section 11.33). Kept in this process only.
    rotated: std::sync::Mutex<std::collections::HashMap<String, RotatedToken>>,
    /// Seconds a client must leave between two polls of a pending transaction (RFC 9635 section
    /// 3.1 `wait`); 0 turns the check off.
    poll_wait_secs: u64,
    /// The authorization server's issuer identifier, the `iss` of an `iss_sub` subject identifier (RFC 9635
    /// section 3.4, RFC 9493). See [`GnapService::with_issuer`].
    issuer: Option<String>,
    /// The short page a person types a `user_code_uri` code into (RFC 9635 section 3.3.4); without
    /// one that start mode is not offered. See [`GnapService::with_user_code_uri`].
    user_code_uri: Option<url::Url>,
    max_bad_attempts: u32,
    /// The application URI an `app` start launches (RFC 9635 section 3.3.2); without one that start mode is
    /// not offered. See [`GnapService::with_app_uri`].
    app_uri: Option<url::Url>,
    /// Nonces of `httpsig` signatures already accepted, so a captured request cannot be replayed.
    httpsig_nonces: Arc<std::sync::Mutex<super::gnap_httpsig::NonceCache>>,
    /// Seconds since the epoch; the system clock unless [`GnapService::with_clock`] replaced it.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// The system clock, in seconds since the epoch.
fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// What a poll that came before the `wait` the server announced is refused with (RFC 9635 section
/// 3.6 `too_fast`). The refusal keeps the continuation token usable.
pub const TOO_FAST: &str =
    "too_fast: Client polled too fast: wait before the next continuation request";

/// How many wrong interaction hashes or references one transaction tolerates before it is invalidated.
const DEFAULT_MAX_BAD_ATTEMPTS: u32 = 5;

/// The default `wait` between polls, in seconds.
const DEFAULT_POLL_WAIT_SECS: u64 = 5;

/// Wrong user codes one caller may type within [`USER_CODE_LOCKOUT_SECS`] before every further
/// attempt is refused unread (RFC 9635 section 3.3.3: the AS limits guesses).
const USER_CODE_MAX_FAILURES: u32 = 5;
/// How long a caller that typed [`USER_CODE_MAX_FAILURES`] wrong codes is refused.
const USER_CODE_LOCKOUT_SECS: u64 = 300;
/// The one message for a user code that matches no open transaction, so a caller cannot tell
/// a wrong code from an expired or already-decided one.
const USER_CODE_REFUSED: &str = "Invalid user code";
/// Refusal of a caller that has typed too many wrong codes.
const USER_CODE_LOCKED: &str = "Too many wrong user codes; try again later";

/// The one message every refused `continue_transaction` call returns, so a caller cannot tell an
/// unknown transaction from an expired one, a wrong token or a wrong interaction hash.
///
/// It starts with the RFC 9635 section 3.6 code, so the AS layer reads the typed error (`GnapError::from_service_message`).
/// What the request that reaches the attempt cap is refused with (RFC 9635 section 3.6
/// `too_many_attempts`); the transaction is gone.
pub const TOO_MANY_ATTEMPTS: &str =
    "too_many_attempts: Too many wrong interaction references: start a new transaction";

const INVALID_CONTINUATION: &str = "invalid_continuation: Invalid continuation request";

/// How far a JWS proof's `created` may differ from now, in seconds; its signature is remembered for twice that.
const JWS_MAX_SKEW_SECS: u64 = 300;

/// Refusal of a client key whose proof method this crate cannot verify.
const PROOF_NOT_SUPPORTED: &str = "GNAP proof method not supported";
/// Refusal of a client key that came without the proof material to check it.
const PROOF_REQUIRED: &str = "GNAP client key proof required: use the _with_proof entry point with the request's DPoP header";
/// Refusal of a certificate key that came without the client certificate the TLS layer saw.
const MTLS_REQUIRED: &str =
    "GNAP client key proof required: the request's client certificate (mtls) was not presented";
/// Refusal of a client key proof that did not verify.
const PROOF_INVALID: &str = "GNAP client key proof invalid";
/// Refusal of a request that names no client key (RFC 9635 section 2.3).
const KEY_REQUIRED: &str = "GNAP client key required";
/// Refusal to issue an access token when the service has no access policy.
const POLICY_REQUIRED: &str = "GNAP access denied: no access policy is configured";
/// Refusal to issue an access token when the policy grants nothing.
const ACCESS_DENIED: &str = "request_denied: GNAP access denied by policy";

/// Seconds after a rotation during which a retry with the old token gets the same new token (RFC 9635
/// section 11.33: "a few seconds since the first rotation attempt").
const ROTATION_RETRY_SECS: u64 = 30;

/// What a retried rotation needs: the answer already given, and the retired token's key to prove again.
#[derive(Clone)]
struct RotatedToken {
    new_value: String,
    response: serde_json::Value,
    thumbprint: Option<String>,
    method: Option<String>,
    jwk: Option<serde_json::Value>,
    at: u64,
}

impl GnapService {
    pub fn new(config: GnapConfig) -> Self {
        Self {
            config,
            policy: None,
            transactions: Arc::new(InMemoryTransactionStore::new()),
            issued_tokens: Arc::new(InMemoryTokenStore::new()),
            consents: Arc::new(InMemoryConsentStore::new()),
            code_failures: std::sync::Mutex::new(std::collections::HashMap::new()),
            rotated: std::sync::Mutex::new(std::collections::HashMap::new()),
            poll_wait_secs: DEFAULT_POLL_WAIT_SECS,
            issuer: None,
            user_code_uri: None,
            max_bad_attempts: DEFAULT_MAX_BAD_ATTEMPTS,
            app_uri: None,
            httpsig_nonces: Arc::new(std::sync::Mutex::new(super::gnap_httpsig::NonceCache::new(
                system_now(),
            ))),
            clock: Arc::new(system_now),
        }
    }

    /// Replace the clock the service reads for token expiry, poll interval and `httpsig`/`jws`/`jwsd`
    /// freshness (DPoP proof freshness and resource-server introspection still read the wall clock), so a test can
    /// move time instead of sleeping. `clock` returns seconds since the epoch. The `httpsig` nonce cache keeps
    /// what it has remembered; only its floor moves back if the new clock is earlier. Production services keep
    /// the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        if let Ok(mut cache) = self.httpsig_nonces.lock() {
            cache.lower_floor_to(clock());
        }
        self.clock = Arc::new(clock);
        self
    }

    /// Set the issuer identifier this server uses as the `iss` of an `iss_sub` subject identifier (RFC 9635
    /// section 3.4, RFC 9493): an absolute `https` URL with no query or fragment. Without one the
    /// `interaction_base_url` is used, and without that the `iss_sub` format is not offered.
    pub fn with_issuer(mut self, issuer: &str) -> Result<Self> {
        let parsed = url::Url::parse(issuer)
            .map_err(|e| AuthError::config(format!("GNAP issuer is not a URL: {e}")))?;
        if parsed.scheme() != "https" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(AuthError::config(
                "GNAP issuer must be an https URL without query or fragment",
            ));
        }
        self.issuer = Some(issuer.to_string());
        Ok(self)
    }

    /// The `iss` for `iss_sub`: the configured issuer, else the interaction base URL.
    fn issuer_identifier(&self) -> Option<&str> {
        self.issuer
            .as_deref()
            .or(self.config.interaction_base_url.as_deref())
    }

    /// Set the seconds a client must wait between polls of a pending transaction (default 5). A
    /// poll that comes sooner is refused with [`TOO_FAST`] and does not rotate the continuation
    /// token; the refused poll restarts the clock, so a client that hammers stays refused. `0`
    /// turns the check off.
    pub fn with_poll_wait_secs(mut self, secs: u64) -> Self {
        self.poll_wait_secs = secs;
        self
    }

    /// Set the short page where a person types a code (RFC 9635 section 3.3.4). A client that
    /// starts with `user_code_uri` is then answered `{code, uri}`; the code is the transaction's
    /// one user code, so [`GnapService::transaction_for_user_code`] finds it. Without this the mode
    /// is not offered (the response carries only the modes the server supports, section 3.3).
    /// The URI must be an absolute http(s) URI without a query or fragment, so no code can end up
    /// in it.
    pub fn with_user_code_uri(mut self, uri: &str) -> Result<Self> {
        let parsed = url::Url::parse(uri)
            .map_err(|e| AuthError::config(format!("GNAP user_code_uri is not a URI: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.cannot_be_a_base()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AuthError::config(
                "GNAP user_code_uri must be an absolute http(s) URI without a query or fragment",
            ));
        }
        self.user_code_uri = Some(parsed);
        Ok(self)
    }

    /// Set how many continuation requests with a wrong interaction hash or reference one transaction
    /// tolerates (default 5). The request that reaches the cap deletes the transaction and is refused
    /// with `too_many_attempts`; the count is per transaction and never resets. `0` turns the cap off.
    /// Only a holder of the continuation token reaches the count, so a third party cannot burn a
    /// transaction.
    pub fn with_max_bad_attempts(mut self, attempts: u32) -> Self {
        self.max_bad_attempts = attempts;
        self
    }

    /// Count a wrong interaction hash or reference against the transaction and answer the refusal.
    async fn bad_interaction(&self, mut txn: GnapTransaction) -> AuthError {
        txn.bad_attempts = txn.bad_attempts.saturating_add(1);
        let spent = self.max_bad_attempts > 0 && txn.bad_attempts >= self.max_bad_attempts;
        let id = txn.id.clone();
        let outcome = if spent {
            self.transactions.remove(&id).await.map(|_| ())
        } else {
            self.transactions
                .replace_if_unchanged(txn)
                .await
                .map(|_| ())
        };
        match outcome {
            Ok(()) if spent => AuthError::validation(TOO_MANY_ATTEMPTS),
            Ok(()) => AuthError::validation(INVALID_CONTINUATION),
            Err(e) => e,
        }
    }

    /// Set the application URI an `app` start launches (RFC 9635 sections 2.5.1.2 and 3.3.2): a client that
    /// starts with `app` is answered this URI with the transaction's id added as the `txn` query parameter,
    /// which makes it unique to the transaction as the RFC requires. Without this the mode is not offered
    /// (the response carries only the modes the server supports, section 3.3). The URI must be absolute,
    /// either http(s) or an application scheme, without credentials, query or fragment.
    pub fn with_app_uri(mut self, uri: &str) -> Result<Self> {
        let parsed = url::Url::parse(uri)
            .map_err(|e| AuthError::config(format!("GNAP app uri is not a URI: {e}")))?;
        if matches!(parsed.scheme(), "javascript" | "data" | "file" | "blob")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AuthError::config(
                "GNAP app uri must be absolute, without credentials, query or fragment, and not a javascript/data/file/blob scheme",
            ));
        }
        self.app_uri = Some(parsed);
        Ok(self)
    }

    /// Set the policy that decides what access tokens carry. Without one, every request for an
    /// access token is denied.
    pub fn with_access_policy(mut self, policy: Arc<dyn GnapAccessPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Keep consent records in this store instead of the default in-memory one. A record is
    /// written for every access token issued after a resource owner approved an interactive
    /// transaction; if the store cannot record it, no token is issued.
    pub fn with_consent_store(mut self, store: Arc<dyn GnapConsentStore>) -> Self {
        self.consents = store;
        self
    }

    /// Keep issued access tokens in this store instead of the default in-memory one. A store
    /// error refuses the request it happens in; it is never read as "no such token".
    pub fn with_token_store(mut self, store: Arc<dyn GnapTokenStore>) -> Self {
        self.issued_tokens = store;
        self
    }

    /// Keep open transactions in this store instead of the default in-memory one. A store error
    /// refuses the request it happens in; it is never read as "no such transaction".
    pub fn with_transaction_store(mut self, store: Arc<dyn GnapTransactionStore>) -> Self {
        self.transactions = store;
        self
    }

    /// The consent records of this resource owner, oldest first, withdrawn ones included.
    pub async fn consents_for_owner(&self, resource_owner: &str) -> Result<Vec<GnapConsent>> {
        self.consents.list_for_owner(resource_owner).await
    }

    /// Withdraw a consent: mark the record withdrawn and revoke every access token issued under
    /// the approval it records. Withdrawing twice is harmless.
    pub async fn revoke_consent(&self, consent_id: &str) -> Result<()> {
        let now = self.now();
        let consent = self
            .consents
            .revoke(consent_id, now)
            .await?
            .ok_or_else(|| AuthError::validation("Consent not found"))?;
        self.issued_tokens
            .remove_for_transaction(&consent.transaction_id)
            .await?;
        Ok(())
    }

    /// Kill every grant bound to the client key with this RFC 7638 `thumbprint` (KM5): drop its
    /// pending and approved transactions (so no continuation can still issue a token), withdraw
    /// its consent records and remove its access tokens. Order matters: transactions go first so
    /// nothing new can be issued while the rest is removed. A store error is returned and what
    /// was not yet removed stays, so calling again finishes the job. Repeating a completed
    /// revocation removes nothing and succeeds.
    pub async fn revoke_client_key(&self, thumbprint: &str) -> Result<ClientKeyRevocation> {
        let now = self.now();
        let mut transactions = 0;
        for id in self.transactions.ids().await? {
            let Some(txn) = self.transactions.get(&id).await? else {
                continue;
            };
            let bound = txn
                .request
                .client
                .as_ref()
                .and_then(|c| c.key.as_ref())
                .and_then(|k| Self::key_binding(k).ok());
            // Only the caller whose remove lands counts it, so a repeat reports nothing.
            if bound.as_deref() == Some(thumbprint)
                && self.transactions.remove(&id).await?.is_some()
            {
                transactions += 1;
            }
        }
        // Count only records this call withdrew, so a repeat reports nothing.
        let consents = self.consents.revoke_for_key(thumbprint, now).await?;
        let newly_withdrawn = consents
            .iter()
            .filter(|c| c.revoked_at == Some(now))
            .count();
        let mut tokens = self.issued_tokens.remove_for_key(thumbprint).await?;
        for consent in &consents {
            tokens += self
                .issued_tokens
                .remove_for_transaction(&consent.transaction_id)
                .await?;
        }
        Ok(ClientKeyRevocation {
            tokens,
            consents: newly_withdrawn,
            transactions,
        })
    }

    /// Revoke `kid` in the key `store` (it stops verifying and leaves the JWKS) and then kill
    /// every grant bound to its thumbprint (KM5).
    pub async fn revoke_client_key_by_kid(
        &self,
        store: &dyn crate::keys::KeyStore,
        kid: &crate::keys::Kid,
    ) -> Result<ClientKeyRevocation> {
        let info = store.info(kid).await?;
        let thumbprint = info
            .public
            .as_ref()
            .ok_or_else(|| AuthError::validation("a key with no public half has no GNAP grants"))?
            .thumbprint()?;
        crate::keys::revoke(store, kid).await?;
        self.revoke_client_key(&thumbprint).await
    }

    // ── Key Binding Helpers ──────────────────────────────────────────────

    /// The identifier a client key binds a token to, after checking the key is well formed.
    /// A JWK binds by its RFC 7638 thumbprint; a certificate (`cert` or `cert#S256`) binds as
    /// `x5t#S256:` followed by the base64url SHA-256 of its DER, so the two forms of one
    /// certificate are the same key and can never collide with a JWK thumbprint.
    fn key_binding(key: &GnapClientKey) -> Result<String> {
        use base64::Engine;
        let given = [
            key.jwk.is_some(),
            key.cert.is_some(),
            key.cert_s256.is_some(),
        ]
        .iter()
        .filter(|g| **g)
        .count();
        if given != 1 {
            return Err(AuthError::validation(
                "GNAP client key needs exactly one of jwk, cert and cert#S256",
            ));
        }
        let is_cert = key.jwk.is_none();
        if is_cert != (key.proof == "mtls") && key.proof != "test" {
            return Err(AuthError::validation(
                "GNAP certificate keys use the mtls proof method, and mtls needs a certificate key",
            ));
        }
        if let Some(jwk) = &key.jwk {
            Self::validate_jwk_fields(jwk)?;
            return Self::jwk_thumbprint(jwk);
        }
        let hash = if let Some(cert) = &key.cert {
            use sha2::Digest;
            let der = base64::engine::general_purpose::STANDARD
                .decode(cert)
                .map_err(|_| AuthError::validation("GNAP cert is not base64"))?;
            x509_parser::parse_x509_certificate(&der)
                .map_err(|_| AuthError::validation("GNAP cert is not an X.509 certificate"))?;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&der))
        } else {
            let given = key.cert_s256.as_deref().unwrap_or_default();
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(given)
                .map_err(|_| AuthError::validation("GNAP cert#S256 is not base64url"))?;
            if raw.len() != 32 {
                return Err(AuthError::validation(
                    "GNAP cert#S256 is not a SHA-256 thumbprint",
                ));
            }
            // Re-encode so a non-canonical spelling cannot bind a second identifier.
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        };
        Ok(format!("x5t#S256:{hash}"))
    }

    /// Compute the JWK thumbprint (RFC 7638) for key binding.
    /// Uses the required members in lexicographic order per key type.
    fn jwk_thumbprint(jwk: &GnapJwk) -> Result<String> {
        let canonical = match jwk.kty.as_str() {
            "EC" => {
                let crv = jwk.crv.as_deref().unwrap_or("");
                let x = jwk.x.as_deref().unwrap_or("");
                let y = jwk.y.as_deref().unwrap_or("");
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            "RSA" => {
                let e = jwk.e.as_deref().unwrap_or("");
                let n = jwk.n.as_deref().unwrap_or("");
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            "OKP" => {
                let crv = jwk.crv.as_deref().unwrap_or("");
                let x = jwk.x.as_deref().unwrap_or("");
                format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
            }
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported JWK key type: {other}"
                )));
            }
        };
        let hash = Sha256::digest(canonical.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
    }

    /// Reconstruct the raw public key bytes from a JWK and verify a
    /// signature using `ring`. Supports ES256 (P-256) and RS256.
    ///
    /// This is called by middleware or application code that extracts the
    /// HTTP message signature from the request before invoking the GNAP
    /// transaction endpoints.
    pub fn verify_jwk_signature(jwk: &GnapJwk, message: &[u8], signature: &[u8]) -> Result<()> {
        use base64::Engine;
        use ring::signature;

        match jwk.kty.as_str() {
            "EC" => {
                let crv = jwk.crv.as_deref().unwrap_or("P-256");
                if crv != "P-256" {
                    return Err(AuthError::validation(format!(
                        "Unsupported EC curve for GNAP: {crv}"
                    )));
                }
                let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.x.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK x: {e}")))?;
                let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.y.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK y: {e}")))?;

                // Uncompressed point: 0x04 || x || y
                let mut pk_bytes = Vec::with_capacity(1 + x.len() + y.len());
                pk_bytes.push(0x04);
                pk_bytes.extend_from_slice(&x);
                pk_bytes.extend_from_slice(&y);

                let key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &pk_bytes,
                );
                key.verify(message, signature).map_err(|_| {
                    AuthError::validation("GNAP client key signature verification failed (ES256)")
                })
            }
            "RSA" => {
                let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.n.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK n: {e}")))?;
                let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.e.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK e: {e}")))?;

                // DER-encode the RSA public key (PKCS#1)
                let pk_der = Self::encode_rsa_public_key_der(&n, &e);

                let key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    &pk_der,
                );
                key.verify(message, signature).map_err(|_| {
                    AuthError::validation("GNAP client key signature verification failed (RS256)")
                })
            }
            other => Err(AuthError::validation(format!(
                "Unsupported JWK key type for signature: {other}"
            ))),
        }
    }

    /// Encode RSA n,e into a DER SubjectPublicKeyInfo structure for ring.
    fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
        // Build PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        fn der_integer(val: &[u8]) -> Vec<u8> {
            // Strip leading zeros but ensure positive
            let v = if !val.is_empty() && val[0] == 0 {
                let stripped = val.iter().position(|&b| b != 0).unwrap_or(val.len() - 1);
                &val[stripped..]
            } else {
                val
            };
            let needs_pad = !v.is_empty() && v[0] & 0x80 != 0;
            let len = v.len() + if needs_pad { 1 } else { 0 };
            let mut out = vec![0x02]; // INTEGER tag
            der_encode_length(len, &mut out);
            if needs_pad {
                out.push(0x00);
            }
            out.extend_from_slice(v);
            out
        }

        fn der_encode_length(len: usize, out: &mut Vec<u8>) {
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x100 {
                out.push(0x81);
                out.push(len as u8);
            } else if len < 0x10000 {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            } else {
                out.push(0x83);
                out.push((len >> 16) as u8);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            }
        }

        let n_der = der_integer(n);
        let e_der = der_integer(e);
        let rsa_seq_content_len = n_der.len() + e_der.len();
        let mut rsa_seq = vec![0x30]; // SEQUENCE tag
        der_encode_length(rsa_seq_content_len, &mut rsa_seq);
        rsa_seq.extend_from_slice(&n_der);
        rsa_seq.extend_from_slice(&e_der);

        // Wrap in SubjectPublicKeyInfo:
        // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { rsa_seq } }
        let rsa_oid: &[u8] = &[
            0x30, 0x0d, // SEQUENCE (AlgorithmIdentifier)
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, // OID 1.2.840.113549.1.1.1
            0x05, 0x00, // NULL
        ];
        let bitstring_len = 1 + rsa_seq.len(); // 1 byte for unused-bits count
        let mut bitstring = vec![0x03]; // BIT STRING tag
        der_encode_length(bitstring_len, &mut bitstring);
        bitstring.push(0x00); // 0 unused bits
        bitstring.extend_from_slice(&rsa_seq);

        let spki_content_len = rsa_oid.len() + bitstring.len();
        let mut spki = vec![0x30]; // outer SEQUENCE
        der_encode_length(spki_content_len, &mut spki);
        spki.extend_from_slice(rsa_oid);
        spki.extend_from_slice(&bitstring);
        spki
    }

    /// Validate the client key binding on a request.
    /// Returns the key thumbprint if a key is present and valid.
    ///
    /// When `proof_message` and `proof_signature` are provided, the actual
    /// cryptographic signature is verified against the client's JWK. For
    /// proof methods other than "test", the caller (typically HTTP middleware)
    /// must extract and supply the message and signature bytes from the
    /// request (e.g. the HTTP Signature input string and its signature value).
    pub fn validate_client_key_with_proof(
        client: &Option<GnapClientInfo>,
        proof_message: Option<&[u8]>,
        proof_signature: Option<&[u8]>,
    ) -> Result<Option<String>> {
        let client = match client {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = match &client.key {
            Some(k) => k,
            None => return Ok(None),
        };

        // Validate proof method is recognized
        match key.proof.as_str() {
            "httpsig" | "mtls" | "dpop" | "jws" | "jwsd" | "test" => {}
            other => {
                return Err(AuthError::validation(format!(
                    "GNAP proof method not supported: {other}"
                )));
            }
        }

        // Validate the key's form and required fields
        let thumbprint = Self::key_binding(key)?;

        // A signature over bytes the caller chose is not a proof of the request, so no method
        // is accepted here: use `handle_transaction_with_proof` for `dpop`. Only the unit-test
        // method, which checks nothing, passes, and only in test builds.
        let _ = (proof_message, proof_signature);
        if !cfg!(test) || key.proof != "test" {
            return Err(AuthError::validation(format!(
                "{PROOF_NOT_SUPPORTED}: {}",
                key.proof
            )));
        }

        Ok(Some(thumbprint))
    }

    /// Validate that a JWK has the required fields for its key type.
    fn validate_jwk_fields(jwk: &GnapJwk) -> Result<()> {
        match jwk.kty.as_str() {
            "EC" => {
                if jwk.x.is_none() || jwk.y.is_none() {
                    return Err(AuthError::validation(
                        "EC JWK must include x and y coordinates",
                    ));
                }
            }
            "RSA" => {
                if jwk.n.is_none() || jwk.e.is_none() {
                    return Err(AuthError::validation(
                        "RSA JWK must include n and e components",
                    ));
                }
            }
            "OKP" => {
                if jwk.x.is_none() {
                    return Err(AuthError::validation("OKP JWK must include x coordinate"));
                }
            }
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported JWK key type: {other}"
                )));
            }
        }
        Ok(())
    }

    /// Validate the client key binding on a request (structural only, no
    /// signature verification). Used internally when proof material is
    /// not available at the protocol level (e.g., continuation polling).
    fn validate_client_key(client: &Option<GnapClientInfo>) -> Result<Option<String>> {
        let client = match client {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = match &client.key {
            Some(k) => k,
            None => return Ok(None),
        };

        // Validate proof method is recognized
        match key.proof.as_str() {
            "httpsig" | "mtls" | "dpop" | "jws" | "jwsd" | "test" => {}
            other => {
                return Err(AuthError::validation(format!(
                    "GNAP proof method not supported: {other}"
                )));
            }
        }

        Ok(Some(Self::key_binding(key)?))
    }

    /// Prove the client holds the key it named, and return that key's thumbprint.
    ///
    /// A request that names no client key is refused (RFC 9635 section 2.3). A request
    /// that names one is accepted only when its proof is verified here: `dpop` against `dpop`'s
    /// manager and the request's `DPoP` header. Every other method (`httpsig`, `mtls`, `jws`,
    /// anything unknown) is refused, as is a `dpop` key with no proof material, so no proof
    /// that was never checked can authorize a request.
    async fn verify_client_proof(
        &self,
        client: &Option<GnapClientInfo>,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
        bound_to_token: bool,
    ) -> Result<Option<String>> {
        let Some(thumbprint) = Self::validate_client_key(client)? else {
            return Err(AuthError::validation(KEY_REQUIRED));
        };
        let Some(key) = client.as_ref().and_then(|c| c.key.as_ref()) else {
            return Err(AuthError::validation(KEY_REQUIRED));
        };
        let jwk = key.jwk.as_ref().and_then(|j| serde_json::to_value(j).ok());
        self.check_key_proof(&key.proof, &thumbprint, jwk.as_ref(), dpop, bound_to_token)
            .await?;
        Ok(Some(thumbprint))
    }

    /// The one place that decides which proof methods this build can verify, and verifies them. Issuance
    /// (`verify_client_proof`) and token management (`verify_token_key_proof`) both call it, so a method cannot
    /// be admitted at issuance and then have no way to rotate or revoke its token: a method added here is
    /// added to both, and a method refused here is refused at both. Only `dpop` is verified; `test`, which
    /// checks nothing, exists in unit-test builds only.
    async fn check_key_proof(
        &self,
        method: &str,
        thumbprint: &str,
        jwk: Option<&serde_json::Value>,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
        bound_to_token: bool,
    ) -> Result<()> {
        match method {
            "dpop" => Self::check_dpop_proof(thumbprint, dpop).await,
            "httpsig" => self.check_httpsig_proof(
                thumbprint,
                jwk,
                dpop.map(|(_, proof)| proof),
                bound_to_token,
            ),
            "jws" => self.check_jws_proof(
                thumbprint,
                jwk,
                dpop.map(|(_, proof)| proof),
                bound_to_token,
            ),
            "jwsd" => self.check_jwsd_proof(
                thumbprint,
                jwk,
                dpop.map(|(_, proof)| proof),
                bound_to_token,
            ),
            "mtls" => Self::check_mtls_proof(thumbprint, dpop.map(|(_, proof)| proof)),
            #[cfg(test)]
            "test" => Ok(()),
            other => Err(AuthError::validation(format!(
                "{PROOF_NOT_SUPPORTED}: {other}"
            ))),
        }
    }

    /// Check that the request carries an RFC 9421 signature by the key (RFC 9635 section 7.3.1), fresh and
    /// not seen before. No signature material, or no key to check it against, is a refusal, never a pass.
    fn check_httpsig_proof(
        &self,
        thumbprint: &str,
        jwk: Option<&serde_json::Value>,
        proof: Option<&GnapProof<'_>>,
        bound_to_token: bool,
    ) -> Result<()> {
        let (Some(jwk), Some(proof)) = (jwk, proof) else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        if proof.http_headers.is_empty() {
            return Err(AuthError::validation(PROOF_REQUIRED));
        }
        let request = super::gnap_httpsig::HttpRequest {
            method: proof.http_method,
            target_uri: proof.http_uri,
            headers: proof.http_headers,
            body: proof.http_body,
        };
        let context = super::gnap_httpsig::GnapHttpsigContext {
            jwk,
            proof_alg: None,
            content_digest_alg: None,
            bound_to_token,
            now: self.now(),
            nonce_scope: thumbprint,
        };
        let mut nonces = self
            .httpsig_nonces
            .lock()
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        super::gnap_httpsig::verify_gnap_request(
            &request,
            &context,
            &super::gnap_httpsig::HttpsigPolicy::default(),
            &mut nonces,
        )
        .map(|_| ())
        .map_err(|_| AuthError::validation(PROOF_INVALID))
    }

    /// Check that the request's `Detached-JWS` header is a JWS by the key over this request's content
    /// (RFC 9635 section 7.3.3), fresh and not seen before. The JWS carries no nonce, so its signature, unique
    /// to the signed header and content, is what is remembered: a captured request replayed inside the skew
    /// window is refused. No header, or no key to check it against, is a refusal, never a pass.
    fn check_jwsd_proof(
        &self,
        thumbprint: &str,
        jwk: Option<&serde_json::Value>,
        proof: Option<&GnapProof<'_>>,
        bound_to_token: bool,
    ) -> Result<()> {
        let (Some(jwk), Some(proof)) = (jwk, proof) else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        let header = |name: &str| {
            proof
                .http_headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        };
        let Some(detached) = header("detached-jws") else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        // A token request presents its token as `Authorization: GNAP <token>`, and `ath` binds the JWS to it.
        let access_token = if bound_to_token {
            match Self::bearer_gnap_token(proof) {
                Some(t) => Some(t),
                None => return Err(AuthError::validation(PROOF_REQUIRED)),
            }
        } else {
            None
        };
        let now = self.now();
        let context = super::gnap_jws::JwsProofContext {
            jwk,
            method: proof.http_method,
            uri: proof.http_uri,
            body: proof.http_body,
            access_token,
            now,
            max_skew_secs: JWS_MAX_SKEW_SECS,
        };
        super::gnap_jws::verify_detached(detached, &context)
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        self.remember_jws(thumbprint, detached, now)
    }

    /// Check a request whose content is a compact JWS (`jws`, RFC 9635 section 7.3.4): `proof.http_body` is the
    /// whole JWS, whose payload is the request. A request with no content cannot carry one, so it is proved
    /// with a `Detached-JWS` header exactly as `jwsd` is. The caller must hand the payload of `http_body` to
    /// the entry point as the request; the AS HTTP layer does.
    fn check_jws_proof(
        &self,
        thumbprint: &str,
        jwk: Option<&serde_json::Value>,
        proof: Option<&GnapProof<'_>>,
        bound_to_token: bool,
    ) -> Result<()> {
        let (Some(jwk), Some(proof)) = (jwk, proof) else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        if proof.http_body.is_empty() {
            return self.check_jwsd_proof(thumbprint, Some(jwk), Some(proof), bound_to_token);
        }
        let access_token = if bound_to_token {
            match Self::bearer_gnap_token(proof) {
                Some(t) => Some(t),
                None => return Err(AuthError::validation(PROOF_REQUIRED)),
            }
        } else {
            None
        };
        let compact = std::str::from_utf8(proof.http_body)
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        let now = self.now();
        let context = super::gnap_jws::JwsProofContext {
            jwk,
            method: proof.http_method,
            uri: proof.http_uri,
            body: &[],
            access_token,
            now,
            max_skew_secs: JWS_MAX_SKEW_SECS,
        };
        super::gnap_jws::verify_attached(compact, &context)
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        self.remember_jws(thumbprint, compact, now)
    }

    /// The token of the request's `Authorization: GNAP <token>` header, if it has one.
    fn bearer_gnap_token<'p>(proof: &GnapProof<'p>) -> Option<&'p str> {
        proof
            .http_headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("GNAP"))
            .map(|(_, t)| t.trim())
    }

    /// Remember the signature of a verified JWS so the same request is refused a second time inside the skew
    /// window. Recorded only after the signature checked out, so a forged request cannot burn a real one's slot.
    fn remember_jws(&self, thumbprint: &str, jws: &str, now: u64) -> Result<()> {
        let signature = jws.trim().rsplit('.').next().unwrap_or_default();
        let mut nonces = self
            .httpsig_nonces
            .lock()
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        nonces
            .check_and_insert(
                thumbprint,
                &format!("jws:{signature}"),
                now,
                2 * JWS_MAX_SKEW_SECS,
            )
            .map_err(|_| AuthError::validation(PROOF_INVALID))
    }

    /// The current time in seconds since the epoch, from the service's clock (see [`Self::with_clock`]).
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Check that the certificate the TLS layer authenticated on this request is the one the key
    /// names (RFC 9635 section 7.3.2). `binding` is `x5t#S256:` and the certificate's SHA-256, which
    /// both the `cert` and `cert#S256` forms reduce to, so one comparison serves both. No
    /// certificate is a refusal, never a pass; the TLS handshake itself (proof of the private
    /// key) is the integrator's terminator's job and is stated on [`GnapProof`].
    fn check_mtls_proof(binding: &str, proof: Option<&GnapProof<'_>>) -> Result<()> {
        let Some(der) = proof.and_then(|p| p.client_certificate_der) else {
            return Err(AuthError::validation(MTLS_REQUIRED));
        };
        let Some(hash) = binding.strip_prefix("x5t#S256:") else {
            return Err(AuthError::validation(PROOF_INVALID));
        };
        super::gnap_jws::verify_mtls(der, None, Some(hash))
            .map_err(|_| AuthError::validation(PROOF_INVALID))
    }

    /// Check that the request's `DPoP` header is a fresh proof signed by the key with `thumbprint`, for this
    /// method and URI. No proof material is a refusal, never a pass.
    async fn check_dpop_proof(
        thumbprint: &str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<()> {
        let Some((manager, proof)) = dpop else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        let Some(header) = proof.dpop_proof else {
            return Err(AuthError::validation(PROOF_REQUIRED));
        };
        match manager
            .validate_dpop_proof_for_key(
                header,
                proof.http_method,
                proof.http_uri,
                None,
                proof.expected_nonce,
                Some(thumbprint),
            )
            .await
        {
            Ok(result) if result.is_valid => Ok(()),
            _ => Err(AuthError::validation(PROOF_INVALID)),
        }
    }

    /// The public JWK of the key a request names, if it names one as a JWK.
    fn key_jwk_value(client: &Option<GnapClientInfo>) -> Option<serde_json::Value> {
        client
            .as_ref()
            .and_then(|c| c.key.as_ref())
            .and_then(|key| key.jwk.as_ref())
            .and_then(|jwk| serde_json::to_value(jwk).ok())
    }

    /// The proof method of the key a request names, if it names one.
    fn key_proof_method(client: &Option<GnapClientInfo>) -> Option<&str> {
        client
            .as_ref()
            .and_then(|c| c.key.as_ref())
            .map(|key| key.proof.as_str())
    }

    /// A request about a key-bound token is accepted only with a proof from that key (RFC 9635 section 6:
    /// the management request is signed with the key the token is bound to). A bearer token has no key and
    /// needs none. A token bound under a method this build cannot verify is refused, not waved through.
    async fn verify_token_key_proof(
        &self,
        key_thumbprint: Option<&str>,
        key_proof: Option<&str>,
        key_jwk: Option<&serde_json::Value>,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<()> {
        let Some(thumbprint) = key_thumbprint else {
            return Ok(());
        };
        match key_proof {
            Some(method) => {
                self.check_key_proof(method, thumbprint, key_jwk, dpop, true)
                    .await
            }
            None => Err(AuthError::validation(PROOF_NOT_SUPPORTED)),
        }
    }

    /// Look the token up and require the proof its key calls for, before anything is changed.
    async fn require_token_key_proof(
        &self,
        token_value: &str,
        not_found: &'static str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<()> {
        let (thumbprint, method, jwk) = {
            let token = self
                .issued_tokens
                .get(token_value)
                .await?
                .ok_or_else(|| AuthError::validation(not_found))?;
            (
                token.key_thumbprint.clone(),
                token.key_proof.clone(),
                token.key_jwk.clone(),
            )
        };
        self.verify_token_key_proof(thumbprint.as_deref(), method.as_deref(), jwk.as_ref(), dpop)
            .await
    }

    // ── Interaction Hash ─────────────────────────────────────────────────

    /// Compute the interaction hash per draft §4.2.3.
    ///
    /// hash = SHA-256( client_nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + tx_endpoint )
    #[cfg(test)]
    fn compute_interact_hash(
        client_nonce: &str,
        server_nonce: &str,
        interact_ref: &str,
        transaction_endpoint: &str,
    ) -> String {
        Self::compute_interact_hash_with(
            client_nonce,
            server_nonce,
            interact_ref,
            transaction_endpoint,
            HashMethod::Sha256,
        )
    }

    /// The hash with the method the client named in `finish.hash_method` (RFC 9635 section 4.2.3). An input
    /// that cannot be hashed (a control character) gives the empty string, which never verifies.
    fn compute_interact_hash_with(
        client_nonce: &str,
        server_nonce: &str,
        interact_ref: &str,
        transaction_endpoint: &str,
        method: HashMethod,
    ) -> String {
        interaction_hash(
            client_nonce,
            server_nonce,
            interact_ref,
            transaction_endpoint,
            method,
        )
        .unwrap_or_default()
    }

    /// The method a stored `hash_method` names. It was checked when the transaction opened, so the
    /// fallback to the default is unreachable for a stored transaction.
    fn hash_method_of(name: Option<&str>) -> HashMethod {
        HashMethod::from_name(name).unwrap_or_default()
    }

    // ── Token Issuance Helper ────────────────────────────────────────────

    /// The start modes the client offered (RFC 9635 section 2.5.1), read by
    /// [`parse_start`]; an unknown mode is kept, not an error.
    fn interaction_start_modes(interact: &GnapInteractionRequirements) -> Result<Vec<StartMode>> {
        let start = serde_json::Value::Array(
            interact
                .start
                .iter()
                .map(|m| serde_json::Value::String(m.clone()))
                .collect(),
        );
        parse_start(&start).map_err(|e| AuthError::validation(e.to_string()))
    }

    /// Check `interact.hints` (section 2.5.3): the shape of `ui_locales`, refused at transaction open.
    fn validate_hints(interact: &GnapInteractionRequirements) -> Result<()> {
        match &interact.hints {
            Some(hints) if !hints.is_object() => {
                Err(AuthError::validation("interact.hints must be an object"))
            }
            Some(hints) => parse_ui_locales(hints)
                .map(|_| ())
                .map_err(|e| AuthError::validation(e.to_string())),
            None => Ok(()),
        }
    }

    /// Check the `finish` object (section 2.5.2) and, for `push`, the target the server would call
    /// (section 11.34): refused here, at transaction open.
    fn validate_finish(interact: &GnapInteractionRequirements) -> Result<()> {
        let Some(finish) = &interact.finish else {
            return Ok(());
        };
        if let Some(name) = finish.hash_method.as_deref()
            && HashMethod::from_name(Some(name)).is_err()
        {
            return Err(AuthError::validation(format!(
                "interact.finish.hash_method {name} is not supported: this server computes sha-256, sha-384 and sha-512"
            )));
        }
        let parsed = FinishRequest::parse(&serde_json::json!({
            "method": finish.method,
            "uri": finish.uri,
            "nonce": finish.nonce,
        }))
        .map_err(|e| AuthError::validation(e.to_string()))?;
        if parsed.method == FinishMethod::Push {
            validate_push_target(&parsed.uri).map_err(|e| AuthError::validation(e.to_string()))?;
        }
        Ok(())
    }

    /// The rights a request asks for, after the checks of RFC 9635 sections 2.1.1 and 2.1.2: an empty token
    /// request, an empty access type, or a flag this server does not support is refused (this server supports
    /// no flag, so any is `invalid_flag`), and so is more than one access token in a request, which this
    /// server does not issue. An access right given as a reference string (section 8.1) is carried as a right
    /// whose type is that string; `datatypes`, `identifier` and `privileges` of an access object are not
    /// carried by the grant-level right and are dropped before the policy sees it (G6).
    pub fn requested_rights(requests: &GnapAccessTokenRequests) -> Result<Vec<GnapAccessRequest>> {
        validate_access_token_requests_with_flags(requests, &[])
            .map_err(|e| AuthError::validation(e.to_string()))?;
        let [request] = requests.as_slice() else {
            return Err(AuthError::validation(
                "this server issues one access token per request",
            ));
        };
        Ok(request
            .access
            .iter()
            .map(|access| match access {
                GnapAccess::Reference(reference) => GnapAccessRequest {
                    access_type: reference.clone(),
                    actions: Vec::new(),
                    locations: Vec::new(),
                },
                GnapAccess::Object(object) => GnapAccessRequest {
                    access_type: object.access_type.clone(),
                    actions: object.actions.clone().unwrap_or_default(),
                    locations: object.locations.clone().unwrap_or_default(),
                },
            })
            .collect())
    }

    async fn build_access_token_response(
        &self,
        access_requests: &[GnapAccessRequest],
        key_thumbprint: &Option<String>,
        key_proof: Option<&str>,
        key_jwk: Option<serde_json::Value>,
        transaction_id: &str,
        consent_owner: Option<Option<&str>>,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        // The policy, not the request, decides what the token carries.
        let policy = self
            .policy
            .as_ref()
            .ok_or_else(|| AuthError::validation(POLICY_REQUIRED))?;
        let thumbprint = key_thumbprint
            .as_deref()
            .ok_or_else(|| AuthError::validation(KEY_REQUIRED))?;
        let granted = policy.grant(thumbprint, access_requests).await;
        if granted.is_empty() {
            return Err(AuthError::validation(ACCESS_DENIED));
        }
        let access_requests = granted.as_slice();

        let access_token = uuid::Uuid::new_v4().to_string();
        let now = self.now();

        let issued = GnapIssuedToken {
            value: access_token.clone(),
            access: access_requests.to_vec(),
            expires_at: now + self.config.token_lifetime_secs,
            key_thumbprint: key_thumbprint.clone(),
            key_proof: key_proof.map(str::to_string),
            key_jwk,
            transaction_id: transaction_id.to_string(),
        };

        // An approved interactive transaction leaves a consent record, written before the token
        // exists: a token whose consent could not be recorded is never issued.
        // `consent_owner` is `Some` exactly for such a transaction; its inner value is the
        // resource owner the integrator named at approval, if any.
        let mut consent_id = None;
        if let Some(resource_owner) = consent_owner {
            let id = uuid::Uuid::new_v4().to_string();
            self.consents
                .record(GnapConsent {
                    id: id.clone(),
                    transaction_id: transaction_id.to_string(),
                    resource_owner: resource_owner.map(str::to_string),
                    client_key_thumbprint: thumbprint.to_string(),
                    access: access_requests.to_vec(),
                    granted_at: now,
                    revoked_at: None,
                })
                .await?;
            consent_id = Some(id);
        }

        // Stored before the response is returned: a client that uses the token at once finds it.
        if let Err(e) = self.issued_tokens.insert(issued).await {
            // The consent written above has no token behind it: withdraw it.
            if let Some(id) = consent_id {
                let _ = self.consents.revoke(&id, now).await;
            }
            return Err(e);
        }

        let mut token_obj = serde_json::Map::new();
        token_obj.insert("value".to_string(), serde_json::Value::String(access_token));
        token_obj.insert(
            "expires_in".to_string(),
            serde_json::Value::Number(self.config.token_lifetime_secs.into()),
        );

        // Include manage URI for token lifecycle operations
        token_obj.insert(
            "manage".to_string(),
            serde_json::Value::String(format!("{}/token", self.config.transaction_endpoint)),
        );

        // No `key` field: the token is bound to the key the client presented, which RFC 9635 section 3.2.1
        // says is shown by omitting `key` (it is only for a key different from the presented one).

        let access_json: Vec<serde_json::Value> = access_requests
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();
        token_obj.insert("access".to_string(), serde_json::Value::Array(access_json));

        Ok(token_obj)
    }

    // ── Transaction Lifecycle ────────────────────────────────────────────

    /// Handle a new transaction request without proof material. Tests only: in a build every
    /// request must come through [`Self::handle_transaction_with_proof`].
    #[cfg(test)]
    async fn handle_transaction(
        &self,
        request: GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        self.handle_transaction_inner(request, None).await
    }

    /// Handle a new GNAP transaction request (RFC 9635 section 2). The request must name a
    /// client key with the `dpop` proof method, and `proof` carries the request's `DPoP` header,
    /// which must be signed by that key. A request that names no client key is refused, and no
    /// access token is issued unless the service has an access policy that grants something.
    pub async fn handle_transaction_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        request: GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        self.handle_transaction_inner(request, Some((dpop, proof)))
            .await
    }

    async fn handle_transaction_inner(
        &self,
        request: GnapTransactionRequest,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<serde_json::Value> {
        if !self.config.enabled {
            return Err(AuthError::config("GNAP protocol is currently disabled"));
        }

        // Validate that the request asks for something
        if request.access_token_request.is_none() && request.subject.is_none() {
            return Err(AuthError::validation(
                "GNAP request must include at least one of access_token or subject",
            ));
        }

        // The access token request is checked before anything is stored or issued (RFC 9635 section 2.1)
        let requested = match &request.access_token_request {
            Some(requests) => Some(Self::requested_rights(requests)?),
            None => None,
        };

        // Validate client key if provided (draft §7.1)
        let key_thumbprint = self
            .verify_client_proof(&request.client, dpop, false)
            .await?;

        let transaction_id = uuid::Uuid::new_v4().to_string();
        let continue_token = uuid::Uuid::new_v4().to_string();

        let now = self.now();

        let mut response = serde_json::Map::new();

        // Generate a server nonce for interaction hash verification
        let interact_nonce = if request.interact.is_some() {
            let nonce = uuid::Uuid::new_v4().to_string();
            Some(nonce)
        } else {
            None
        };

        // If interaction is requested, generate interaction response
        if let Some(ref interact) = request.interact {
            // Read the request with the interaction module before anything is stored: a malformed
            // `start`/`finish`, or a `push` target the server must not call (section 11.34), is
            // refused here. Delivering the push, and re-checking the target after name resolution,
            // is a later slice.
            let start_modes = Self::interaction_start_modes(interact)?;
            Self::validate_finish(interact)?;
            Self::validate_hints(interact)?;
            let offer_code_uri =
                start_modes.contains(&StartMode::UserCodeUri) && self.user_code_uri.is_some();
            let user_code = if start_modes.contains(&StartMode::UserCode) || offer_code_uri {
                Some(
                    generate_user_code(USER_CODE_LEN)
                        .map_err(|e| AuthError::validation(e.to_string()))?,
                )
            } else {
                None
            };

            let base_url = self.config.interaction_base_url.as_deref().ok_or_else(|| {
                AuthError::config(
                    "GNAP interaction_base_url must be configured for interactive flows",
                )
            })?;

            let interact_url = format!("{}/interact/{}", base_url, transaction_id);

            let mut interact_res = serde_json::Map::new();

            if interact.start.iter().any(|m| m == "redirect") {
                interact_res.insert(
                    "redirect".to_string(),
                    serde_json::Value::String(interact_url),
                );
            }

            if let (true, Some(app)) =
                (start_modes.contains(&StartMode::App), self.app_uri.as_ref())
            {
                let mut app = app.clone();
                app.query_pairs_mut().append_pair("txn", &transaction_id);
                interact_res.insert(
                    "app".to_string(),
                    serde_json::Value::String(app.to_string()),
                );
            }

            if let Some(ref code) = user_code {
                if start_modes.contains(&StartMode::UserCode) {
                    interact_res.insert(
                        "user_code".to_string(),
                        serde_json::Value::String(code.clone()),
                    );
                }
                if let (true, Some(uri)) = (offer_code_uri, self.user_code_uri.as_ref()) {
                    interact_res.insert(
                        "user_code_uri".to_string(),
                        serde_json::json!({"code": code, "uri": uri.as_str()}),
                    );
                }
            }

            if let Some(ref finish) = interact.finish {
                // Return server nonce for client to compute interaction hash
                interact_res.insert(
                    "finish".to_string(),
                    serde_json::Value::String(interact_nonce.clone().unwrap_or_default()),
                );
                // Echo the finish method + nonce so client knows the protocol
                let _ = &finish.nonce; // client_nonce is used later for hash
            }

            // RFC 9635 section 3.3: the interaction lives as long as the transaction does.
            interact_res.insert(
                "expires_in".to_string(),
                serde_json::json!(self.config.transaction_lifetime_secs),
            );

            response.insert(
                "interact".to_string(),
                serde_json::Value::Object(interact_res),
            );

            // Store pending transaction
            let txn = GnapTransaction {
                id: transaction_id.clone(),
                state: GnapTransactionState::Pending,
                request: request.clone(),
                continue_token: continue_token.clone(),
                created_at: now,
                interact_nonce: interact_nonce.clone(),
                subject_id: None,
                interact_ref: None,
                user_code,
                revision: 0,
                last_poll_at: 0,
                bad_attempts: 0,
            };
            self.transactions.insert(txn).await?;
        } else {
            // No interaction required — issue token directly if access requested
            if let Some(ref access_requests) = requested {
                let token_obj = self
                    .build_access_token_response(
                        access_requests,
                        &key_thumbprint,
                        Self::key_proof_method(&request.client),
                        Self::key_jwk_value(&request.client),
                        "direct",
                        None,
                    )
                    .await?;
                response.insert(
                    "access_token".to_string(),
                    serde_json::Value::Object(token_obj),
                );
            }

            // If subject info was requested, include it (draft §2.2)
            if let Some(ref subject_req) = request.subject {
                let subject_resp =
                    Self::build_subject_response(subject_req, None, self.issuer_identifier());
                response.insert(
                    "subject".to_string(),
                    serde_json::Value::Object(subject_resp),
                );
            }
        }

        // Provide continuation endpoint (with rotatable token)
        let mut continue_obj = serde_json::Map::new();
        let mut ct_token = serde_json::Map::new();
        ct_token.insert(
            "value".to_string(),
            serde_json::Value::String(continue_token),
        );
        continue_obj.insert(
            "access_token".to_string(),
            serde_json::Value::Object(ct_token),
        );
        continue_obj.insert(
            "uri".to_string(),
            serde_json::Value::String(self.continue_uri(&transaction_id)),
        );

        // A pending grant tells the client how long to wait before its first poll (RFC 9635 sections 3.1 and
        // 11.27), the same `wait` every poll answer carries and the one `too_fast` is judged against.
        if response.contains_key("interact") && self.poll_wait_secs > 0 {
            continue_obj.insert(
                "wait".to_string(),
                serde_json::Value::Number(self.poll_wait_secs.into()),
            );
        }

        response.insert(
            "continue".to_string(),
            serde_json::Value::Object(continue_obj),
        );

        Ok(serde_json::Value::Object(response))
    }

    /// The continuation URI of a transaction: `{transaction_endpoint}/continue/{id}`, made absolute on the
    /// origin of the interaction base URL when there is one (RFC 9635 section 3.1: "MUST be an absolute
    /// URI"); without one only the path can be given. RFC 9635 section 5 lets the AS choose it, and naming
    /// the transaction lets a request that carries only the continuation token and a proof be routed to it.
    fn continue_uri(&self, transaction_id: &str) -> String {
        let path = format!(
            "{}/continue/{}",
            self.config.transaction_endpoint, transaction_id
        );
        let origin = self
            .config
            .interaction_base_url
            .as_deref()
            .and_then(|base| url::Url::parse(base).ok())
            .filter(|u| u.has_host());
        match origin.and_then(|u| u.join(&path).ok()) {
            Some(absolute) => absolute.to_string(),
            None => path,
        }
    }

    /// Continue a transaction without proof material. Tests only: in a build every continuation
    /// must come through [`Self::continue_transaction_with_proof`].
    #[cfg(test)]
    async fn continue_transaction(
        &self,
        transaction_id: &str,
        continue_token: &str,
        interact_ref: Option<&str>,
        interact_hash: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.continue_transaction_inner(
            transaction_id,
            continue_token,
            interact_ref,
            interact_hash,
            None,
        )
        .await
    }

    /// Continue a GNAP transaction (polling or post-interaction), RFC 9635 section 5.
    ///
    /// The continuation request must carry a `DPoP` proof signed by the transaction's client
    /// key. A transaction that uses a finish method continues only with the one-time
    /// `interact_ref` that [`Self::approve_transaction`] returned. The continuation token is
    /// **rotated on every successful call**, preventing replay of old continuation responses.
    pub async fn continue_transaction_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        transaction_id: &str,
        continue_token: &str,
        interact_ref: Option<&str>,
        interact_hash: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.continue_transaction_inner(
            transaction_id,
            continue_token,
            interact_ref,
            interact_hash,
            Some((dpop, proof)),
        )
        .await
    }

    async fn continue_transaction_inner(
        &self,
        transaction_id: &str,
        continue_token: &str,
        interact_ref: Option<&str>,
        interact_hash: Option<&str>,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<serde_json::Value> {
        // The checks below run on a copy. Every write back is atomic in the store (a
        // compare-and-swap on the revision read here, or a remove only one caller wins), so two
        // requests for one transaction cannot both rotate its token or both spend it.
        let mut txn = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| AuthError::validation(INVALID_CONTINUATION))?;

        // Enforce transaction expiration
        let now = self.now();
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            self.transactions.remove(transaction_id).await?;
            return Err(AuthError::validation(INVALID_CONTINUATION));
        }

        // Verify continuation token. `ct_eq` examines every byte of two slices of equal
        // length; a length mismatch returns early, which reveals only the length of a
        // UUID-formatted token.
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            txn.continue_token.as_bytes(),
            continue_token.as_bytes(),
        )) {
            return Err(AuthError::validation(INVALID_CONTINUATION));
        }

        // If interaction hash is provided, verify it (draft §4.2.3). This runs before the
        // token is rotated, so a request that fails the check leaves the holder's token usable.
        if let (Some(hash), Some(iref)) = (interact_hash, interact_ref) {
            let server_nonce = txn.interact_nonce.as_deref().ok_or_else(|| {
                AuthError::validation("No interaction nonce for this transaction")
            })?;
            let finish = txn
                .request
                .interact
                .as_ref()
                .and_then(|i| i.finish.as_ref());
            let client_nonce = finish.map(|f| f.nonce.as_str()).unwrap_or("");
            let method = Self::hash_method_of(finish.and_then(|f| f.hash_method.as_deref()));

            let expected = Self::compute_interact_hash_with(
                client_nonce,
                server_nonce,
                iref,
                &self.config.transaction_endpoint,
                method,
            );
            if !bool::from(subtle::ConstantTimeEq::ct_eq(
                hash.as_bytes(),
                expected.as_bytes(),
            )) {
                return Err(self.bad_interaction(txn).await);
            }
        }

        // An approved transaction that uses a finish method continues only with the one-time
        // interaction reference issued at approval, and a reference nobody issued is refused.
        // Checked before the token is rotated, like the hash.
        match (txn.interact_ref.as_deref(), interact_ref) {
            (Some(issued), Some(given)) => {
                if !bool::from(subtle::ConstantTimeEq::ct_eq(
                    issued.as_bytes(),
                    given.as_bytes(),
                )) {
                    return Err(self.bad_interaction(txn).await);
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(AuthError::validation(INVALID_CONTINUATION));
            }
            (None, None) => {}
        }

        // A transaction whose client named a key continues only for that key: verify the proof
        // before the token is rotated, so a refused request leaves the holder's token usable.
        let verified_thumbprint = self
            .verify_client_proof(&txn.request.client, dpop, true)
            .await?;

        match txn.state {
            GnapTransactionState::Pending => {
                // Polling too soon (RFC 9635 section 5.2) is refused, the token is kept, and the
                // refused poll restarts the clock.
                let since = if txn.last_poll_at == 0 {
                    txn.created_at
                } else {
                    txn.last_poll_at
                };
                if self.poll_wait_secs > 0 && now.saturating_sub(since) < self.poll_wait_secs {
                    txn.last_poll_at = now;
                    if !self.transactions.replace_if_unchanged(txn).await? {
                        return Err(AuthError::validation(INVALID_CONTINUATION));
                    }
                    return Err(AuthError::validation(TOO_FAST));
                }
                // Rotate the continuation token (draft §5.1). Of two requests that presented
                // the same token only the one whose swap lands gets the new one.
                let new_continue_token = uuid::Uuid::new_v4().to_string();
                txn.continue_token = new_continue_token.clone();
                txn.last_poll_at = now;
                if !self.transactions.replace_if_unchanged(txn).await? {
                    return Err(AuthError::validation(INVALID_CONTINUATION));
                }
                // Still waiting for user interaction
                Ok(self.pending_response(transaction_id, &new_continue_token))
            }
            GnapTransactionState::Approved => {
                // An approved transaction is spent by one continuation: whoever removes it
                // issues the token. One that changed since it was read (a concurrent denial)
                // is refused, and is gone either way.
                let spent = self.transactions.remove(transaction_id).await?;
                let txn = match spent {
                    Some(spent) if spent.revision == txn.revision => spent,
                    _ => return Err(AuthError::validation(INVALID_CONTINUATION)),
                };
                let key_thumbprint = verified_thumbprint;

                let mut response = serde_json::Map::new();

                // Issue access token (the policy decides what it carries)
                let mut refused = None;
                let requested = match &txn.request.access_token_request {
                    Some(requests) => Some(Self::requested_rights(requests)?),
                    None => None,
                };
                if let Some(ref access_requests) = requested {
                    match self
                        .build_access_token_response(
                            access_requests,
                            &key_thumbprint,
                            Self::key_proof_method(&txn.request.client),
                            Self::key_jwk_value(&txn.request.client),
                            transaction_id,
                            Some(txn.subject_id.as_deref()),
                        )
                        .await
                    {
                        Ok(token_obj) => {
                            response.insert(
                                "access_token".to_string(),
                                serde_json::Value::Object(token_obj),
                            );
                        }
                        Err(e) => refused = Some(e),
                    }
                }

                // Include subject info if requested and available
                if let Some(ref subject_req) = txn.request.subject {
                    let subject_resp = Self::build_subject_response(
                        subject_req,
                        txn.subject_id.as_deref(),
                        self.issuer_identifier(),
                    );
                    response.insert(
                        "subject".to_string(),
                        serde_json::Value::Object(subject_resp),
                    );
                }

                match refused {
                    Some(e) => Err(e),
                    None => Ok(serde_json::Value::Object(response)),
                }
            }
            GnapTransactionState::Denied => {
                self.transactions.remove(transaction_id).await?;
                Err(AuthError::validation(
                    "user_denied: Transaction was denied by the resource owner",
                ))
            }
        }
    }

    /// The grant response of a transaction that is still waiting: where to continue, how long to
    /// wait, and the continuation token to present next.
    fn pending_response(&self, transaction_id: &str, continue_token: &str) -> serde_json::Value {
        serde_json::json!({
            "continue": {
                "uri": self.continue_uri(transaction_id),
                "wait": self.poll_wait_secs.max(1),
                "access_token": { "value": continue_token },
            }
        })
    }

    /// Read a transaction for a continuation-level request (modify, cancel): it must exist and be
    /// unexpired, the continuation token must match, and the client's key proof must verify. Every
    /// refusal before the proof reads the same ([`INVALID_CONTINUATION`]).
    async fn load_for_continuation(
        &self,
        transaction_id: &str,
        continue_token: &str,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
    ) -> Result<GnapTransaction> {
        let txn = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| AuthError::validation(INVALID_CONTINUATION))?;
        let now = self.now();
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            self.transactions.remove(transaction_id).await?;
            return Err(AuthError::validation(INVALID_CONTINUATION));
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            txn.continue_token.as_bytes(),
            continue_token.as_bytes(),
        )) {
            return Err(AuthError::validation(INVALID_CONTINUATION));
        }
        self.verify_client_proof(&txn.request.client, Some((dpop, proof)), true)
            .await?;
        Ok(txn)
    }

    /// Modify a pending grant request (RFC 9635 section 5.3, `PATCH` on the continue URI).
    ///
    /// `modification` replaces the transaction's requested `access_token` and `subject` where it
    /// carries them; the requested rights are checked as at the first request. It must not carry a
    /// `client` (key rotation is not supported) or an `interact` (interaction is fixed when the
    /// transaction opens). Only a transaction still waiting can be modified: an approved one was
    /// approved for what was asked then. The continuation token rotates, and the answer is the
    /// waiting grant response with the new token.
    pub async fn modify_transaction_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        transaction_id: &str,
        continue_token: &str,
        modification: &GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        let mut txn = self
            .load_for_continuation(transaction_id, continue_token, dpop, proof)
            .await?;
        if modification.client.is_some() {
            return Err(AuthError::validation(
                "GNAP modification must not carry a client (key rotation is not supported)",
            ));
        }
        if modification.interact.is_some() {
            return Err(AuthError::validation(
                "GNAP modification must not change the interaction",
            ));
        }
        if !matches!(txn.state, GnapTransactionState::Pending) {
            return Err(AuthError::validation(
                "GNAP transaction cannot be modified: it is not pending",
            ));
        }
        if let Some(requests) = &modification.access_token_request {
            Self::requested_rights(requests)?;
            txn.request.access_token_request = Some(requests.clone());
        }
        if let Some(subject) = &modification.subject {
            txn.request.subject = Some(subject.clone());
        }
        let new_continue_token = uuid::Uuid::new_v4().to_string();
        txn.continue_token = new_continue_token.clone();
        if !self.transactions.replace_if_unchanged(txn).await? {
            return Err(AuthError::validation(INVALID_CONTINUATION));
        }
        Ok(self.pending_response(transaction_id, &new_continue_token))
    }

    /// Cancel a grant request (RFC 9635 section 5.4, `DELETE` on the continue URI): the client
    /// presents its continuation token and key proof, and the transaction is removed, pending or
    /// approved. Of two cancels (or a cancel and a continuation) only one wins. A grant that
    /// already issued its token is gone from the transaction store; revoke that token through
    /// its management URI.
    pub async fn delete_transaction_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        transaction_id: &str,
        continue_token: &str,
    ) -> Result<()> {
        let txn = self
            .load_for_continuation(transaction_id, continue_token, dpop, proof)
            .await?;
        match self.transactions.remove(transaction_id).await? {
            Some(gone) if gone.revision == txn.revision => {
                // RFC 9635 section 5.4: the AS SHOULD revoke the tokens issued under a cancelled grant.
                self.issued_tokens
                    .remove_for_transaction(transaction_id)
                    .await?;
                Ok(())
            }
            _ => Err(AuthError::validation(INVALID_CONTINUATION)),
        }
    }

    /// How many times a read-modify-write of one transaction is retried when another request
    /// changes it in between.
    const UPDATE_ATTEMPTS: usize = 8;

    /// Change a stored transaction: read it, let `change` edit a copy, and write it back only if
    /// nobody changed it meanwhile (retrying a few times when somebody did).
    async fn update_transaction<T>(
        &self,
        transaction_id: &str,
        mut change: impl FnMut(&mut GnapTransaction) -> T,
    ) -> Result<T> {
        for _ in 0..Self::UPDATE_ATTEMPTS {
            let mut txn = self
                .transactions
                .get(transaction_id)
                .await?
                .ok_or_else(|| AuthError::validation("Transaction not found"))?;
            let out = change(&mut txn);
            if self.transactions.replace_if_unchanged(txn).await? {
                return Ok(out);
            }
        }
        Err(AuthError::validation(
            "Transaction is being changed by another request; try again",
        ))
    }

    /// Approve a pending transaction (called after user interaction).
    /// Optionally sets the subject identifier for subject-info responses.
    ///
    /// For a transaction that uses a finish method this issues the one-time interaction
    /// reference and its hash (RFC 9635 section 4.2); deliver both to the client's finish URI.
    pub async fn approve_transaction(
        &self,
        transaction_id: &str,
        subject_id: Option<&str>,
    ) -> Result<GnapInteractionCompletion> {
        let endpoint = &self.config.transaction_endpoint;
        self.update_transaction(transaction_id, |txn| {
            txn.state = GnapTransactionState::Approved;
            if let Some(sid) = subject_id {
                txn.subject_id = Some(sid.to_string());
            }
            let finish = txn
                .request
                .interact
                .as_ref()
                .and_then(|i| i.finish.as_ref());
            let method = Self::hash_method_of(finish.and_then(|f| f.hash_method.as_deref()));
            let client_nonce = finish.map(|f| f.nonce.clone());
            let Some(client_nonce) = client_nonce else {
                return GnapInteractionCompletion {
                    interact_ref: None,
                    hash: None,
                };
            };
            let interact_ref = txn
                .interact_ref
                .get_or_insert_with(|| uuid::Uuid::new_v4().simple().to_string())
                .clone();
            let hash = Self::compute_interact_hash_with(
                &client_nonce,
                txn.interact_nonce.as_deref().unwrap_or(""),
                &interact_ref,
                endpoint,
                method,
            );
            GnapInteractionCompletion {
                interact_ref: Some(interact_ref),
                hash: Some(hash),
            }
        })
        .await
    }

    /// Deliver the `push` callback of an approved transaction (RFC 9635 section 4.2.2): the one-time
    /// `interact_ref` and its hash, to the client's `finish.uri`.
    ///
    /// The target is checked again here, after the host name is resolved, and the connection goes to the
    /// address that was checked ([`deliver_push`], section 11.34): a name that resolves to a loopback,
    /// private or metadata address is refused and nothing is sent. A transaction that is not approved, has
    /// no `push` finish, or has no reference yet is refused, as is one past its lifetime (continuation
    /// would refuse its reference anyway).
    ///
    /// **Deviation from RFC 9635 section 4.2:** the RFC says `finish` is also enacted when the resource
    /// owner denies access, so the client can learn of it and modify its request. This method pushes only
    /// an approved transaction; a client that asked for `push` and was denied is not told and finds out at
    /// its next poll. Pushing a denial needs a denial body the RFC does not define for `push`.
    pub async fn push_interaction(
        &self,
        transaction_id: &str,
        resolver: &dyn PushResolver,
        sender: &dyn PushSender,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.push_interaction_at(transaction_id, resolver, sender, now)
            .await
    }

    async fn push_interaction_at(
        &self,
        transaction_id: &str,
        resolver: &dyn PushResolver,
        sender: &dyn PushSender,
        now: u64,
    ) -> Result<()> {
        let txn = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| AuthError::validation("Transaction not found"))?;
        if !matches!(txn.state, GnapTransactionState::Approved) {
            return Err(AuthError::validation("the transaction is not approved"));
        }
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            return Err(AuthError::validation("the transaction has expired"));
        }
        let finish = txn
            .request
            .interact
            .as_ref()
            .and_then(|i| i.finish.as_ref())
            .filter(|f| f.method == "push")
            .ok_or_else(|| AuthError::validation("the transaction has no push finish method"))?;
        let interact_ref = txn
            .interact_ref
            .as_deref()
            .ok_or_else(|| AuthError::validation("the transaction has no interaction reference"))?;
        let uri = url::Url::parse(&finish.uri)
            .map_err(|_| AuthError::validation("the push finish uri is not a valid URI"))?;
        let hash = Self::compute_interact_hash_with(
            &finish.nonce,
            txn.interact_nonce.as_deref().unwrap_or(""),
            interact_ref,
            &self.config.transaction_endpoint,
            Self::hash_method_of(finish.hash_method.as_deref()),
        );
        deliver_push(&uri, &hash, interact_ref, resolver, sender)
            .await
            .map_err(|e| AuthError::validation(e.to_string()))
    }

    /// The URI to send the end user to for the `redirect` callback of an approved transaction (RFC 9635
    /// section 4.2.1): the client's `finish.uri` with `hash` and `interact_ref` added. Answer the user's
    /// browser with it as a `303` ([`CALLBACK_REDIRECT_STATUS`], section 11.19), never a `307`.
    ///
    /// A transaction that is not approved, has no `redirect` finish, or has no reference yet is refused, as
    /// is one past its lifetime. Nothing is fetched: the browser makes the request, so there is no SSRF
    /// surface (contrast [`Self::push_interaction`]). The URI was validated at transaction open.
    pub async fn redirect_callback(&self, transaction_id: &str) -> Result<url::Url> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.redirect_callback_at(transaction_id, now).await
    }

    async fn redirect_callback_at(&self, transaction_id: &str, now: u64) -> Result<url::Url> {
        let txn = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| AuthError::validation("Transaction not found"))?;
        if !matches!(txn.state, GnapTransactionState::Approved) {
            return Err(AuthError::validation("the transaction is not approved"));
        }
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            return Err(AuthError::validation("the transaction has expired"));
        }
        let finish = txn
            .request
            .interact
            .as_ref()
            .and_then(|i| i.finish.as_ref())
            .filter(|f| f.method == "redirect")
            .ok_or_else(|| {
                AuthError::validation("the transaction has no redirect finish method")
            })?;
        let interact_ref = txn
            .interact_ref
            .as_deref()
            .ok_or_else(|| AuthError::validation("the transaction has no interaction reference"))?;
        let uri = url::Url::parse(&finish.uri)
            .map_err(|_| AuthError::validation("the redirect finish uri is not a valid URI"))?;
        let hash = Self::compute_interact_hash_with(
            &finish.nonce,
            txn.interact_nonce.as_deref().unwrap_or(""),
            interact_ref,
            &self.config.transaction_endpoint,
            Self::hash_method_of(finish.hash_method.as_deref()),
        );
        Ok(crate::protocols::gnap_interaction::callback_redirect_url(
            &uri,
            &hash,
            interact_ref,
        ))
    }

    /// The languages the client asked the consent page to use (`interact.hints.ui_locales`, RFC 9635
    /// section 2.5.3.1), in the client's order of preference; empty when it gave none. The AS decides what
    /// it can serve. Refused for an unknown or expired transaction.
    pub async fn interaction_locales(&self, transaction_id: &str) -> Result<Vec<String>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let txn = self
            .transactions
            .get(transaction_id)
            .await?
            .ok_or_else(|| AuthError::validation("Transaction not found"))?;
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            return Err(AuthError::validation("the transaction has expired"));
        }
        match txn.request.interact.as_ref().and_then(|i| i.hints.as_ref()) {
            Some(h) => parse_ui_locales(h).map_err(|e| AuthError::validation(e.to_string())),
            None => Ok(Vec::new()),
        }
    }

    /// Find the pending transaction a person's typed `user_code` belongs to (RFC 9635 sections
    /// 3.3.3 and 4.1) and return its id, for the page that then shows the consent and calls
    /// [`Self::approve_transaction`] or [`Self::deny_transaction`].
    ///
    /// `caller` names who is typing (an address, a session): after five wrong codes within five
    /// minutes every attempt by that caller is refused unread, a right code included, until the
    /// window passes. A wrong, malformed, expired or already-decided code all give the same
    /// refusal. A right code clears the caller's count. The counts are kept in this process
    /// only. The caller key must be stable and invariant to the attacker: an attacker who can vary it
    /// (a spoofable header, a cookie they can drop, an address they can rotate) gets a fresh allowance each
    /// time and defeats the limit. Key on something the attacker cannot choose, such as an authenticated
    /// session or the peer address of a connection you terminate.
    pub async fn transaction_for_user_code(&self, typed: &str, caller: &str) -> Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.transaction_for_user_code_at(typed, caller, now).await
    }

    async fn transaction_for_user_code_at(
        &self,
        typed: &str,
        caller: &str,
        now: u64,
    ) -> Result<String> {
        if self.user_code_locked(caller, now) {
            return Err(AuthError::validation(USER_CODE_LOCKED));
        }
        let found = match normalize_user_code(typed) {
            Ok(code) => self.transactions.find_by_user_code(&code).await?,
            Err(_) => None,
        };
        let usable = found.filter(|t| {
            matches!(t.state, GnapTransactionState::Pending)
                && now.saturating_sub(t.created_at) <= self.config.transaction_lifetime_secs
        });
        match usable {
            Some(txn) => {
                self.code_failures_lock().remove(caller);
                Ok(txn.id)
            }
            None => {
                self.note_user_code_failure(caller, now);
                Err(AuthError::validation(USER_CODE_REFUSED))
            }
        }
    }

    fn code_failures_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, (u32, u64)>> {
        self.code_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn user_code_locked(&self, caller: &str, now: u64) -> bool {
        self.code_failures_lock()
            .get(caller)
            .is_some_and(|&(count, since)| {
                count >= USER_CODE_MAX_FAILURES
                    && now.saturating_sub(since) < USER_CODE_LOCKOUT_SECS
            })
    }

    fn note_user_code_failure(&self, caller: &str, now: u64) {
        let mut failures = self.code_failures_lock();
        // Windows that have passed are dropped here, so the map holds only recent callers.
        failures.retain(|_, &mut (_, since)| now.saturating_sub(since) < USER_CODE_LOCKOUT_SECS);
        let entry = failures.entry(caller.to_string()).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
    }

    /// Deny a pending transaction
    pub async fn deny_transaction(&self, transaction_id: &str) -> Result<()> {
        self.update_transaction(transaction_id, |txn| {
            txn.state = GnapTransactionState::Denied;
        })
        .await
    }

    // ── Token Management (draft §6) ─────────────────────────────────────

    /// Revoke an issued access token (draft §6.2 — DELETE on manage URI).
    pub async fn revoke_token_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        token_value: &str,
    ) -> Result<()> {
        self.revoke_token_inner(token_value, Some((dpop, proof)))
            .await
    }

    /// Unit tests only: revoke without a proof. A bound token is refused unless its method is the test one.
    #[cfg(test)]
    pub async fn revoke_token(&self, token_value: &str) -> Result<()> {
        self.revoke_token_inner(token_value, None).await
    }

    async fn revoke_token_inner(
        &self,
        token_value: &str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<()> {
        self.require_token_key_proof(token_value, "Token not found", dpop)
            .await?;
        if self.issued_tokens.remove(token_value).await?.is_none() {
            return Err(AuthError::validation("Token not found"));
        }
        Ok(())
    }

    /// Rotate an issued access token (draft §6.1 — POST on manage URI).
    /// Returns a new token with the same access rights and key binding.
    pub async fn rotate_token_with_proof(
        &self,
        dpop: &DpopManager,
        proof: &GnapProof<'_>,
        old_token_value: &str,
    ) -> Result<serde_json::Value> {
        self.rotate_token_inner(old_token_value, Some((dpop, proof)), None)
            .await
    }

    /// Rotate an issued token and bind the replacement to a new key (RFC 9635 section 6.1.1).
    ///
    /// The request is the `jws` or `jwsd` rotation of `gnap_jws`: both keys prove, the old one over the new
    /// key's value and the new one over the old signature. Only a token bound under `jws` or `jwsd` can
    /// rotate its key (`key_rotation_not_supported` otherwise, since `dpop`, `httpsig` and `mtls` define no
    /// two-proof form here); a bearer token cannot (`invalid_rotation`). Any failure leaves the token as it
    /// was. The message of every refusal starts with the RFC error code.
    pub async fn rotate_token_key_with_proof(
        &self,
        proof: &GnapProof<'_>,
        old_token_value: &str,
    ) -> Result<serde_json::Value> {
        const NOT_SUPPORTED: &str =
            "key_rotation_not_supported: this token's key cannot be rotated";
        const INVALID: &str = "invalid_rotation: the rotation request is not valid";
        let token = self
            .issued_tokens
            .get(old_token_value)
            .await?
            .ok_or_else(|| AuthError::validation("Token not found or already revoked"))?;
        let (Some(thumbprint), Some(method)) = (token.key_thumbprint, token.key_proof) else {
            return Err(AuthError::validation(INVALID));
        };
        let Some(old_jwk) = token.key_jwk else {
            return Err(AuthError::validation(NOT_SUPPORTED));
        };
        let now = self.now();
        let context = super::gnap_jws::JwsProofContext {
            jwk: &old_jwk,
            method: proof.http_method,
            uri: proof.http_uri,
            body: proof.http_body,
            access_token: Some(old_token_value),
            now,
            max_skew_secs: JWS_MAX_SKEW_SECS,
        };
        let invalid = |_| AuthError::validation(INVALID);
        let (rotation, signed) = match method.as_str() {
            "jwsd" => {
                let detached = proof
                    .http_headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("detached-jws"))
                    .map(|(_, v)| *v)
                    .ok_or_else(|| AuthError::validation(INVALID))?;
                (
                    super::gnap_jws::verify_detached_rotation(detached, &context)
                        .map_err(invalid)?,
                    detached,
                )
            }
            "jws" => {
                let compact = std::str::from_utf8(proof.http_body)
                    .map_err(|_| AuthError::validation(INVALID))?;
                (
                    super::gnap_jws::verify_attached_rotation(compact, &context)
                        .map_err(invalid)?
                        .0,
                    compact,
                )
            }
            _ => return Err(AuthError::validation(NOT_SUPPORTED)),
        };
        let new_jwk: GnapJwk = serde_json::from_value(rotation.new_jwk.clone())
            .map_err(|_| AuthError::validation(INVALID))?;
        let new_thumbprint =
            Self::jwk_thumbprint(&new_jwk).map_err(|_| AuthError::validation(INVALID))?;
        self.remember_jws(&thumbprint, signed, now)
            .map_err(|_| AuthError::validation(INVALID))?;
        self.rotate_token_inner(
            old_token_value,
            None,
            Some((new_thumbprint, rotation.new_jwk)),
        )
        .await
    }

    /// Unit tests only: rotate without a proof. A bound token is refused unless its method is the test one.
    #[cfg(test)]
    pub async fn rotate_token(&self, old_token_value: &str) -> Result<serde_json::Value> {
        self.rotate_token_inner(old_token_value, None, None).await
    }

    async fn rotate_token_inner(
        &self,
        old_token_value: &str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
        new_key: Option<(String, serde_json::Value)>,
    ) -> Result<serde_json::Value> {
        // A key rotation has been proved by both keys already; every other rotation needs the token's key.
        if new_key.is_none() {
            if let Some(again) = self.retried_rotation(old_token_value, dpop).await? {
                return Ok(again);
            }
            self.require_token_key_proof(
                old_token_value,
                "Token not found or already revoked",
                dpop,
            )
            .await?;
        }
        let old = self
            .issued_tokens
            .remove(old_token_value)
            .await?
            .ok_or_else(|| AuthError::validation("Token not found or already revoked"))?;

        let now = self.now();

        if now >= old.expires_at {
            return Err(AuthError::validation("Token has expired"));
        }

        let new_value = uuid::Uuid::new_v4().to_string();
        let key_rotated = new_key.is_some();
        let (key_thumbprint, key_jwk) = match new_key {
            Some((thumbprint, jwk)) => (Some(thumbprint), Some(jwk)),
            None => (old.key_thumbprint.clone(), old.key_jwk.clone()),
        };
        let new_token = GnapIssuedToken {
            value: new_value.clone(),
            access: old.access.clone(),
            expires_at: now + self.config.token_lifetime_secs,
            key_thumbprint,
            key_proof: old.key_proof.clone(),
            key_jwk,
            transaction_id: old.transaction_id,
        };

        let mut token_obj = serde_json::Map::new();
        token_obj.insert(
            "value".to_string(),
            serde_json::Value::String(new_value.clone()),
        );
        token_obj.insert(
            "expires_in".to_string(),
            serde_json::Value::Number(self.config.token_lifetime_secs.into()),
        );
        token_obj.insert(
            "manage".to_string(),
            serde_json::Value::String(format!("{}/token", self.config.transaction_endpoint)),
        );
        let access_json: Vec<serde_json::Value> = old
            .access
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();
        token_obj.insert("access".to_string(), serde_json::Value::Array(access_json));

        self.issued_tokens.insert(new_token).await?;

        let response = serde_json::Value::Object(token_obj);
        // A key rotation is not remembered: a retry would need both keys' proofs again.
        // A token with no key has nothing to prove a retry with: it is not remembered either.
        if !key_rotated && old.key_thumbprint.is_some() {
            let mut map = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, r| now.saturating_sub(r.at) <= ROTATION_RETRY_SECS);
            map.insert(
                old_token_value.to_string(),
                RotatedToken {
                    new_value,
                    response: response.clone(),
                    thumbprint: old.key_thumbprint,
                    method: old.key_proof,
                    jwk: old.key_jwk,
                    at: now,
                },
            );
        }
        Ok(response)
    }

    /// The answer to a rotation the client is repeating because it never saw the response (RFC 9635
    /// section 11.33). The retry proves the retired token's key again; once the new token has been seen
    /// in use (see `introspect_token`) the record is gone and the retry is refused like any retired token.
    async fn retried_rotation(
        &self,
        old_token_value: &str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<Option<serde_json::Value>> {
        let now = self.now();
        let record = {
            let mut map = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, r| now.saturating_sub(r.at) <= ROTATION_RETRY_SECS);
            map.get(old_token_value).cloned()
        };
        let Some(record) = record else {
            return Ok(None);
        };
        // The store does not filter by expiry: a token already past its lifetime is not handed back.
        match self.issued_tokens.get(&record.new_value).await? {
            Some(new) if now < new.expires_at => {}
            _ => return Ok(None),
        }
        self.verify_token_key_proof(
            record.thumbprint.as_deref(),
            record.method.as_deref(),
            record.jwk.as_ref(),
            dpop,
        )
        .await?;
        Ok(Some(record.response))
    }

    /// Introspect a token — check if it is valid and return its access rights.
    pub async fn introspect_token(&self, token_value: &str) -> Result<Option<serde_json::Value>> {
        let token = match self.issued_tokens.get(token_value).await? {
            Some(t) => t,
            None => return Ok(None),
        };

        // The client has shown it holds the new token, so the old one is no longer needed for a retry
        // (RFC 9635 section 11.33).
        self.rotated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, r| r.new_value != token_value);

        let now = self.now();

        if now >= token.expires_at {
            return Ok(None);
        }

        let access_json: Vec<serde_json::Value> = token
            .access
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();

        let mut result = serde_json::Map::new();
        result.insert("active".to_string(), serde_json::Value::Bool(true));
        result.insert("access".to_string(), serde_json::Value::Array(access_json));
        result.insert(
            "expires_in".to_string(),
            serde_json::Value::Number((token.expires_at - now).into()),
        );
        if let Some(ref tp) = token.key_thumbprint {
            result.insert(
                "key_thumbprint".to_string(),
                serde_json::Value::String(tp.clone()),
            );
        }
        result.insert(
            "key_bound".to_string(),
            serde_json::Value::Bool(token.key_thumbprint.is_some()),
        );

        Ok(Some(serde_json::Value::Object(result)))
    }

    /// Validate that a key-bound token is being used with the correct key.
    ///
    /// For tokens issued with a client key binding, verify that the
    /// presenting client's JWK thumbprint matches the stored binding.
    /// Returns `Ok(true)` if the token is not key-bound (no restriction).
    pub async fn validate_token_key_binding(
        &self,
        token_value: &str,
        presenting_jwk: &GnapJwk,
    ) -> Result<bool> {
        let token = match self.issued_tokens.get(token_value).await? {
            Some(t) => t,
            None => return Err(AuthError::validation("Token not found")),
        };

        let now = self.now();
        if now >= token.expires_at {
            return Err(AuthError::validation("Token has expired"));
        }

        match &token.key_thumbprint {
            None => Ok(true), // Not key-bound → any presenter is fine
            Some(expected_tp) => {
                let presenting_tp = Self::jwk_thumbprint(presenting_jwk)?;
                Ok(
                    subtle::ConstantTimeEq::ct_eq(expected_tp.as_bytes(), presenting_tp.as_bytes())
                        .into(),
                )
            }
        }
    }

    // ── Subject Info Response (draft §2.2) ───────────────────────────────

    /// Build a subject information response based on what was requested.
    fn build_subject_response(
        request: &GnapSubjectRequest,
        subject_id: Option<&str>,
        issuer: Option<&str>,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut resp = serde_json::Map::new();

        // Return sub_ids in requested formats
        if let Some(sid) = subject_id {
            let mut sub_ids = Vec::new();
            for fmt in &request.sub_id_formats {
                match fmt.as_str() {
                    "opaque" => {
                        sub_ids.push(serde_json::json!({
                            "format": "opaque",
                            "id": sid,
                        }));
                    }
                    "email" => {
                        // Only include if the subject ID looks like an email
                        if sid.contains('@') {
                            sub_ids.push(serde_json::json!({
                                "format": "email",
                                "email": sid,
                            }));
                        }
                    }
                    "iss_sub" => {
                        // Without an issuer identifier there is no valid `iss`: not offered.
                        if let Some(iss) = issuer {
                            sub_ids.push(serde_json::json!({
                                "format": "iss_sub",
                                "iss": iss,
                                "sub": sid,
                            }));
                        }
                    }
                    _ => {} // Unknown format — skip
                }
            }
            if sub_ids.is_empty() {
                // Default to opaque if no recognized format
                sub_ids.push(serde_json::json!({
                    "format": "opaque",
                    "id": sid,
                }));
            }
            resp.insert("sub_ids".to_string(), serde_json::Value::Array(sub_ids));
        }

        resp
    }

    // ── Cleanup ──────────────────────────────────────────────────────────

    /// Unit tests only: ids of the stored transactions.
    #[cfg(test)]
    async fn test_txn_ids(&self) -> Vec<String> {
        self.transactions.ids().await.unwrap()
    }

    /// Unit tests only: the one stored transaction with this id.
    #[cfg(test)]
    async fn test_txn(&self, id: &str) -> GnapTransaction {
        self.transactions.get(id).await.unwrap().unwrap()
    }

    /// Unit tests only: the first stored transaction.
    #[cfg(test)]
    async fn test_first_txn(&self) -> GnapTransaction {
        let id = self.test_txn_ids().await.remove(0);
        self.test_txn(&id).await
    }

    /// Remove expired transactions from the transaction store.
    pub async fn cleanup_expired_transactions(&self) {
        let now = self.now();
        // Expired is `now - created_at > lifetime`, that is `created_at < now - lifetime`.
        let cutoff = now.saturating_sub(self.config.transaction_lifetime_secs);
        if let Err(e) = self.transactions.purge_created_before(cutoff).await {
            tracing::warn!("GNAP transaction store could not purge expired transactions: {e}");
        }
    }

    /// Remove expired access tokens from the token store.
    pub async fn cleanup_expired_tokens(&self) {
        let now = self.now();
        if let Err(e) = self.issued_tokens.purge_expired(now).await {
            tracing::warn!("GNAP token store could not purge expired tokens: {e}");
        }
    }
}

/// Test policy: grants everything requested.
#[cfg(test)]
struct AllowAllPolicy;

#[cfg(test)]
#[async_trait]
impl GnapAccessPolicy for AllowAllPolicy {
    async fn grant(
        &self,
        _client_key_thumbprint: &str,
        requested: &[GnapAccessRequest],
    ) -> Vec<GnapAccessRequest> {
        requested.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> GnapService {
        GnapService::new(test_config())
            .with_poll_wait_secs(0)
            .with_access_policy(Arc::new(AllowAllPolicy))
    }

    fn test_config() -> GnapConfig {
        GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://auth.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        }
    }

    fn test_ec_jwk() -> GnapJwk {
        GnapJwk {
            kty: "EC".to_string(),
            kid: Some("test-key-1".to_string()),
            crv: Some("P-256".to_string()),
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
            n: None,
            e: None,
        }
    }

    fn test_rsa_jwk() -> GnapJwk {
        GnapJwk {
            kty: "RSA".to_string(),
            kid: Some("test-rsa-1".to_string()),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM".to_string()),
            e: Some("AQAB".to_string()),
        }
    }

    fn test_client_info(jwk: GnapJwk) -> GnapClientInfo {
        GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "test".to_string(),
                jwk: Some(jwk),
                cert: None,
                cert_s256: None,
            }),
            display: Some(GnapClientDisplay {
                name: Some("Test Client".to_string()),
                uri: Some("https://client.example.test".to_string()),
            }),
        }
    }

    // ── Config & Construction ────────────────────────────────────────────

    #[test]
    fn test_gnap_config_defaults() {
        let config = GnapConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.token_lifetime_secs, 3600);
        assert_eq!(config.transaction_lifetime_secs, 600);
        assert!(config.interaction_base_url.is_none());
    }

    #[test]
    fn test_gnap_service_creation() {
        let service = test_service();
        assert!(service.config.enabled);
    }

    // ── JWK Thumbprint (RFC 7638) ────────────────────────────────────────

    #[test]
    fn test_jwk_thumbprint_ec() {
        let jwk = test_ec_jwk();
        let tp = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        // Thumbprint is base64url-encoded SHA-256 → 43 chars
        assert_eq!(tp.len(), 43);
    }

    #[test]
    fn test_jwk_thumbprint_rsa() {
        let jwk = test_rsa_jwk();
        let tp = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        assert_eq!(tp.len(), 43);
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let jwk = test_ec_jwk();
        let tp1 = GnapService::jwk_thumbprint(&jwk).unwrap();
        let tp2 = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert_eq!(tp1, tp2);
    }

    #[test]
    fn test_jwk_thumbprint_different_keys() {
        let tp_ec = GnapService::jwk_thumbprint(&test_ec_jwk()).unwrap();
        let tp_rsa = GnapService::jwk_thumbprint(&test_rsa_jwk()).unwrap();
        assert_ne!(tp_ec, tp_rsa);
    }

    #[test]
    fn test_jwk_thumbprint_unsupported_type() {
        let jwk = GnapJwk {
            kty: "UNKNOWN".to_string(),
            kid: None,
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
        };
        assert!(GnapService::jwk_thumbprint(&jwk).is_err());
    }

    // ── Client Key Validation ────────────────────────────────────────────

    #[test]
    fn test_validate_client_key_ec() {
        let client = Some(test_client_info(test_ec_jwk()));
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_some());
    }

    #[test]
    fn test_validate_client_key_rsa() {
        let client = Some(test_client_info(test_rsa_jwk()));
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_some());
    }

    #[test]
    fn test_validate_client_key_none() {
        let tp = GnapService::validate_client_key(&None).unwrap();
        assert!(tp.is_none());
    }

    #[test]
    fn test_validate_client_key_no_key() {
        let client = Some(GnapClientInfo {
            key: None,
            display: None,
        });
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_none());
    }

    #[test]
    fn test_validate_client_key_invalid_proof_method() {
        let client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "invalid_method".to_string(),
                jwk: Some(test_ec_jwk()),
                cert: None,
                cert_s256: None,
            }),
            display: None,
        });
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_ec_missing_y() {
        let mut jwk = test_ec_jwk();
        jwk.y = None;
        let client = Some(test_client_info(jwk));
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_rsa_missing_e() {
        let mut jwk = test_rsa_jwk();
        jwk.e = None;
        let client = Some(test_client_info(jwk));
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_with_proof_test_mode() {
        let client = Some(test_client_info(test_ec_jwk()));
        let tp = GnapService::validate_client_key_with_proof(&client, None, None).unwrap();
        assert!(tp.is_some());
    }

    // ── Interaction Hash ─────────────────────────────────────────────────

    #[test]
    fn test_compute_interact_hash_deterministic() {
        let h1 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        let h2 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_interact_hash_different_inputs() {
        let h1 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        let h2 = GnapService::compute_interact_hash("cn2", "sn1", "ref1", "/tx");
        assert_ne!(h1, h2);
    }

    // ── Transaction Lifecycle ────────────────────────────────────────────

    #[tokio::test]
    async fn test_transaction_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let service = GnapService::new(config).with_access_policy(Arc::new(AllowAllPolicy));
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        assert!(service.handle_transaction(req).await.is_err());
    }

    #[tokio::test]
    async fn test_transaction_requires_access_or_subject() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: None,
            subject: None,
        };
        assert!(service.handle_transaction(req).await.is_err());
    }

    #[tokio::test]
    async fn test_transaction_direct_token_issuance() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec!["list".to_string()],
                    locations: vec!["https://api.test/resources".to_string()],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("access_token"));
        assert!(obj.contains_key("continue"));

        let token_obj = obj["access_token"].as_object().unwrap();
        assert!(token_obj.contains_key("value"));
        assert!(token_obj.contains_key("expires_in"));
        assert!(token_obj.contains_key("manage"));
        assert!(
            !token_obj.contains_key("key"),
            "bound to the presented key: no key field"
        );
    }

    #[tokio::test]
    async fn test_transaction_with_interaction() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/callback".to_string(),
                    nonce: "client-nonce-123".to_string(),
                    hash_method: None,
                }),
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "write".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("interact"));
        assert!(obj.contains_key("continue"));

        let interact = obj["interact"].as_object().unwrap();
        assert!(interact.contains_key("redirect"));
        assert!(interact.contains_key("finish"));
        assert_eq!(interact["expires_in"], serde_json::json!(600));
    }

    #[tokio::test]
    async fn test_transaction_subject_only() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("subject"));
    }

    // ── Approve / Deny / Continue ────────────────────────────────────────

    #[tokio::test]
    async fn test_approve_and_continue() {
        let service = test_service();

        // Create interactive transaction
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let cont = resp["continue"]["access_token"]["value"].as_str().unwrap();

        // Get transaction ID from the stored transactions
        let txn_id = service.test_first_txn().await.id;

        // Continue before approval → pending
        let poll = service
            .continue_transaction(&txn_id, cont, None, None)
            .await;
        assert!(
            poll.is_err() || {
                let r = poll.unwrap();
                r.as_object().unwrap().contains_key("continue")
            }
        );

        // Get updated continuation token
        let new_cont = service.test_txn(&txn_id).await.continue_token;

        // Approve
        service
            .approve_transaction(&txn_id, Some("user-42"))
            .await
            .unwrap();

        // Continue after approval → get token
        let result = service
            .continue_transaction(&txn_id, &new_cont, None, None)
            .await
            .unwrap();
        assert!(result.as_object().unwrap().contains_key("access_token"));
    }

    #[tokio::test]
    async fn test_deny_transaction() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let txn_id = service.test_first_txn().await.id;

        service.deny_transaction(&txn_id).await.unwrap();

        let cont = service.test_txn(&txn_id).await.continue_token;
        let result = service
            .continue_transaction(&txn_id, &cont, None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_continue_invalid_token() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let txn_id = service.test_first_txn().await.id;
        let result = service
            .continue_transaction(&txn_id, "bad-token", None, None)
            .await;
        assert!(result.is_err());
    }

    // ── Token Management ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_token_revocation() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let token_value = resp["access_token"]["value"].as_str().unwrap();

        // Small delay so the spawned insert task completes
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Introspect before revocation
        let info = service.introspect_token(token_value).await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.as_ref().unwrap()["active"], true);

        // Revoke
        service.revoke_token(token_value).await.unwrap();

        // Introspect after revocation
        let info = service.introspect_token(token_value).await.unwrap();
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn test_token_rotation() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "write".to_string(),
                    actions: vec!["create".to_string()],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let old_token = resp["access_token"]["value"].as_str().unwrap().to_string();

        // Wait for spawned insert
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Rotate
        let new_resp = service.rotate_token(&old_token).await.unwrap();
        let new_token = new_resp["value"].as_str().unwrap();
        assert_ne!(old_token, new_token);

        // Old token should be gone
        let old_info = service.introspect_token(&old_token).await.unwrap();
        assert!(old_info.is_none());

        // New token should be active
        let new_info = service.introspect_token(new_token).await.unwrap();
        assert!(new_info.is_some());
        assert_eq!(new_info.unwrap()["active"], true);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_token() {
        let service = test_service();
        assert!(service.revoke_token("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_introspect_nonexistent_token() {
        let service = test_service();
        let info = service.introspect_token("nonexistent").await.unwrap();
        assert!(info.is_none());
    }

    // ── Key Binding Verification ─────────────────────────────────────────

    #[tokio::test]
    async fn test_token_key_binding_check() {
        let service = test_service();
        let ec_jwk = test_ec_jwk();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(ec_jwk.clone())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let token_value = resp["access_token"]["value"].as_str().unwrap();

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Same key → should pass
        let ok = service
            .validate_token_key_binding(token_value, &ec_jwk)
            .await
            .unwrap();
        assert!(ok);

        // Different key → should fail
        let other_jwk = test_rsa_jwk();
        let bad = service
            .validate_token_key_binding(token_value, &other_jwk)
            .await
            .unwrap();
        assert!(!bad);
    }

    /// RFC 9635 section 11.8, "Generation of Access Tokens": the contents of a token must be "such that only
    /// the generating AS would be able to create them", for example "a cryptographically random value ... with
    /// sufficiently high entropy". And 11.9 / 11.10: "key-bound access tokens are the default". Identical
    /// requests give distinct, long values that carry nothing about the grant, a value one character off is
    /// not a token, and the token is key-bound unless the client had no key.
    #[tokio::test]
    async fn section_11_8_access_tokens_are_random_opaque_and_key_bound_by_default() {
        let service = test_service();
        let ec_jwk = test_ec_jwk();
        let mut values = std::collections::HashSet::new();
        let mut first = None;
        for _ in 0..50 {
            let req = GnapTransactionRequest {
                client: Some(test_client_info(ec_jwk.clone())),
                interact: None,
                access_token_request: Some(
                    vec![GnapAccessRequest {
                        access_type: "read".to_string(),
                        actions: vec![],
                        locations: vec![],
                    }]
                    .into(),
                ),
                subject: None,
            };
            let resp = service.handle_transaction(req).await.unwrap();
            let token = &resp["access_token"];
            let value = token["value"].as_str().unwrap().to_string();
            assert!(value.len() >= 32, "enough characters for 122 random bits");
            assert!(
                !value.contains("read"),
                "the value says nothing of the access it stands for"
            );
            assert!(
                token.get("key").is_none(),
                "bound to the presented key by default"
            );
            assert!(values.insert(value.clone()), "no two tokens are equal");
            first.get_or_insert(value);
        }
        // A value one character off is not a token (control: the original is).
        let real = first.unwrap();
        assert!(service.introspect_token(&real).await.unwrap().is_some());
        let mut altered = real.clone();
        let last = altered.pop().unwrap();
        altered.push(if last == '0' { '1' } else { '0' });
        assert!(service.introspect_token(&altered).await.unwrap().is_none());
    }

    /// RFC 9635 section 2.5.1: an `interact.start` entry may be the object form `{"mode": "redirect"}`. It must
    /// read through the wire type, not only through `parse_start`; an object with no string `mode` is refused.
    #[test]
    fn section_2_5_1_the_object_form_of_start_reads_on_the_wire() {
        let request = |start: serde_json::Value| {
            serde_json::from_value::<GnapTransactionRequest>(serde_json::json!({
                "interact": { "start": start }
            }))
        };
        let both = request(serde_json::json!([{"mode": "redirect"}, "user_code"])).unwrap();
        assert_eq!(both.interact.unwrap().start, ["redirect", "user_code"]);
        assert!(
            request(serde_json::json!(["redirect"])).is_ok(),
            "control: the string form"
        );
        for bad in [
            serde_json::json!([{}]),
            serde_json::json!([{"mode": 7}]),
            serde_json::json!([7]),
        ] {
            assert!(request(bad.clone()).is_err(), "{bad} must be refused");
        }
    }

    /// RFC 9635 section 3.1: the continuation `uri` "MUST be an absolute URI". With an interaction base URL the
    /// AS builds it on that origin; clients still read the grant id from its last segment.
    #[tokio::test]
    async fn section_3_1_the_continue_uri_is_absolute() {
        let interactive = || GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        };
        let svc = test_service();
        let started = svc.handle_transaction(interactive()).await.unwrap();
        let uri = started["continue"]["uri"].as_str().unwrap();
        assert!(
            uri.starts_with("https://auth.example.test/api/gnap/tx/continue/"),
            "{uri}"
        );

        // Control: no base URL, no interactive flow at all, so a pending grant always has an origin to build on.
        let bare = GnapService::new(GnapConfig {
            interaction_base_url: None,
            ..test_config()
        })
        .with_access_policy(Arc::new(AllowAllPolicy));
        assert!(bare.handle_transaction(interactive()).await.is_err());
    }

    /// RFC 9635 section 3.2.1: `key` is "the key that the token is bound to, if different from the client
    /// instance's presented key", an object or a string; "if the bearer flag and the key field ... are omitted,
    /// the token is bound to the key used by the client instance". A boolean is no defined value, so a token
    /// bound to the presented key (the only binding this AS makes) carries no `key`, on issue and rotation.
    #[tokio::test]
    async fn section_3_2_1_a_token_bound_to_the_presented_key_carries_no_key_field() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let issued = service.handle_transaction(req).await.unwrap();
        let value = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let rotated = service.rotate_token(&value).await.unwrap();
        for (label, token) in [("issue", &issued["access_token"]), ("rotation", &rotated)] {
            assert!(token.get("key").is_none(), "{label}: {token}");
            assert!(
                token.get("flags").is_none(),
                "{label}: not a bearer token, so no bearer flag"
            );
        }
        // Still bound: the stored token carries the presented key's thumbprint.
        let info = service
            .introspect_token(rotated["value"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info["key_bound"], true);
    }

    /// RFC 9635 section 12.4.2, "Correlation by Resource Servers": an AS that puts a stable user identifier in
    /// introspection output lets unrelated resource servers correlate users. The introspection answer names
    /// only the token facts, never a user (the field set is pinned, so adding one is a deliberate change).
    #[tokio::test]
    async fn section_12_4_2_introspection_names_no_user() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let value = resp["access_token"]["value"].as_str().unwrap().to_string();
        let info = service.introspect_token(&value).await.unwrap().unwrap();
        let mut keys: Vec<&str> = info
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "access",
                "active",
                "expires_in",
                "key_bound",
                "key_thumbprint"
            ],
            "only token facts; a new field naming a user must be a deliberate change"
        );
    }

    /// RFC 9635 section 11.35, "Multiple Key Formats": "All keys presented by value are only allowed to be in a
    /// single format", else an attacker could slip a second key into one format. A key given as a JWK and
    /// also as a certificate thumbprint is refused whole and nothing is issued; so is a key with no format.
    #[tokio::test]
    async fn section_11_35_a_key_in_two_formats_or_none_is_refused() {
        let service = test_service();
        let build = |jwk: Option<GnapJwk>, cert_s256: Option<&str>| {
            let mut client = test_client_info(test_ec_jwk());
            let key = client.key.as_mut().unwrap();
            key.jwk = jwk;
            key.cert_s256 = cert_s256.map(str::to_string);
            GnapTransactionRequest {
                client: Some(client),
                interact: None,
                access_token_request: Some(
                    vec![GnapAccessRequest {
                        access_type: "read".to_string(),
                        actions: vec![],
                        locations: vec![],
                    }]
                    .into(),
                ),
                subject: None,
            }
        };
        // Control, built the same way: one format is accepted.
        service
            .handle_transaction(build(Some(test_ec_jwk()), None))
            .await
            .expect("a key in one format is accepted");
        let issued = service.issued_tokens.count().await.unwrap();
        for (label, request) in [
            (
                "jwk and cert#S256",
                build(Some(test_ec_jwk()), Some("AAAA")),
            ),
            ("no format", build(None, None)),
        ] {
            let err = service
                .handle_transaction(request)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("exactly one"), "{label}: {err}");
        }
        assert_eq!(
            service.issued_tokens.count().await.unwrap(),
            issued,
            "nothing issued"
        );
    }

    /// RFC 9635 section 11.13, "Processing of Client-Presented User Information": it "should only ever be taken
    /// by the AS as a hint", since the client "could assert whatever it likes". A client that names a user in
    /// its request and asks for that user's subject information gets none: the AS releases subject information
    /// only for a user it has itself seen approve the grant.
    #[tokio::test]
    async fn section_11_13_a_user_the_client_names_is_a_hint_and_releases_no_subject() {
        let service = test_service();
        let mut wire = serde_json::to_value(GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        })
        .unwrap();
        wire["user"] = serde_json::json!({
            "sub_ids": [{"format": "opaque", "id": "the-victim"}]
        });
        let request: GnapTransactionRequest = serde_json::from_value(wire).unwrap();
        let response = service.handle_transaction(request).await.unwrap();
        let text = response.to_string();
        assert!(
            !text.contains("the-victim"),
            "the named user is not echoed: {text}"
        );
        assert!(
            response
                .get("subject")
                .is_none_or(|s| s.get("sub_ids").is_none()),
            "no subject identifier is released on the client's say-so: {text}"
        );

        // Control, built the same way: after the user the AS saw approves, the subject is released.
        let control = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        };
        let started = service.handle_transaction(control).await.unwrap();
        let cont = started["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let id = started["continue"]["uri"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        service
            .approve_transaction(&id, Some("user-42"))
            .await
            .unwrap();
        let done = service.continue_transaction(&id, &cont, None, None).await;
        let released = match done {
            Ok(v) => v.to_string(),
            Err(e) => panic!("the approved grant must continue: {e}"),
        };
        assert!(released.contains("user-42"), "control: {released}");
    }

    /// RFC 9635 section 11.38, "AS-Provided Token Keys": an AS that returns its own key with a token enables a
    /// substitution attack, so "returning a key ... should be limited". This service never returns key
    /// material: a token response carries no `key` (bound to the client's own key, section 3.2.1), on issue and on
    /// rotation alike, and no response carries a private key parameter.
    #[tokio::test]
    async fn section_11_38_a_token_response_never_carries_a_key_of_the_ass_choosing() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let issued = service.handle_transaction(req).await.unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let rotated = service.rotate_token(&token).await.unwrap();
        for (label, response) in [("issue", &issued["access_token"]), ("rotation", &rotated)] {
            assert!(
                response.get("key").is_none(),
                "{label}: no key object, string or reference"
            );
            let text = response.to_string();
            assert!(
                !text.contains("\"d\""),
                "{label}: no private key parameter: {text}"
            );
        }
    }

    // ── Subject Info ─────────────────────────────────────────────────────

    #[test]
    fn test_build_subject_response_opaque() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user-42"), None);
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids.len(), 1);
        assert_eq!(sub_ids[0]["format"], "opaque");
        assert_eq!(sub_ids[0]["id"], "user-42");
    }

    #[test]
    fn test_build_subject_response_email() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["email".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user@example.test"), None);
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids.len(), 1);
        assert_eq!(sub_ids[0]["format"], "email");
    }

    #[test]
    fn test_build_subject_response_email_not_email() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["email".to_string()],
            assertion_formats: vec![],
        };
        // Subject is not an email → defaults to opaque
        let resp = GnapService::build_subject_response(&req, Some("user-42"), None);
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "opaque");
    }

    #[test]
    fn test_build_subject_response_iss_sub() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["iss_sub".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(
            &req,
            Some("user-42"),
            Some("https://as.example.test"),
        );
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "iss_sub");
        assert_eq!(sub_ids[0]["sub"], "user-42");
        assert_eq!(
            sub_ids[0]["iss"], "https://as.example.test",
            "the AS identifier, not a placeholder (RFC 9635 section 3.4)"
        );
        // With no issuer identifier there is no valid `iss`, so the format is not offered; the default is opaque.
        let none = GnapService::build_subject_response(&req, Some("user-42"), None);
        assert_eq!(none["sub_ids"][0]["format"], "opaque");
        assert!(
            GnapService::new(GnapConfig::default())
                .with_issuer("http://as.example.test")
                .is_err(),
            "an issuer must be https"
        );
        assert!(
            GnapService::new(GnapConfig::default())
                .with_issuer("https://as.example.test")
                .is_ok()
        );
    }

    #[test]
    fn test_build_subject_response_no_subject() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, None, None);
        assert!(!resp.contains_key("sub_ids"));
    }

    // ── Continuation Token Rotation ──────────────────────────────────────

    #[tokio::test]
    async fn test_continuation_token_rotates() {
        let service = test_service();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let cont1 = resp["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();

        let txn_id = service.test_first_txn().await.id;

        // First continue → token is rotated
        let _ = service
            .continue_transaction(&txn_id, &cont1, None, None)
            .await;

        let cont2 = service.test_txn(&txn_id).await.continue_token;
        assert_ne!(cont1, cont2, "Continuation token must rotate on each use");

        // Old token should not work
        let reuse = service
            .continue_transaction(&txn_id, &cont1, None, None)
            .await;
        assert!(reuse.is_err(), "Old continuation token must be rejected");
    }

    // ── Cleanup ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cleanup_expired_transactions() {
        let mut config = test_config();
        config.transaction_lifetime_secs = 1; // 1 second lifetime
        let service = GnapService::new(config).with_access_policy(Arc::new(AllowAllPolicy));

        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        assert_eq!(service.transactions.count().await.unwrap(), 1);

        // Manually backdate the transaction so it appears expired
        for id in service.test_txn_ids().await {
            service
                .update_transaction(&id, |txn| {
                    txn.created_at = txn.created_at.saturating_sub(10)
                })
                .await
                .unwrap();
        }

        service.cleanup_expired_transactions().await;
        assert_eq!(service.transactions.count().await.unwrap(), 0);
    }

    // ── Interaction Hash Verification ────────────────────────────────────

    #[tokio::test]
    async fn test_interaction_hash_verification() {
        let service = test_service();
        let client_nonce = "client-nonce-abc";
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/cb".to_string(),
                    nonce: client_nonce.to_string(),
                    hash_method: None,
                }),
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();

        let (txn_id, cont, server_nonce) = {
            let txn = service.test_first_txn().await;
            (txn.id, txn.continue_token, txn.interact_nonce.unwrap())
        };

        let done = service.approve_transaction(&txn_id, None).await.unwrap();
        let interact_ref = done.interact_ref.as_deref().unwrap();
        let correct_hash = GnapService::compute_interact_hash(
            client_nonce,
            &server_nonce,
            interact_ref,
            &service.config.transaction_endpoint,
        );
        assert_eq!(done.hash.as_deref(), Some(correct_hash.as_str()));

        // Wrong hash → fails
        let bad = service
            .continue_transaction(&txn_id, &cont, Some(interact_ref), Some("bad-hash"))
            .await;
        assert!(bad.is_err());

        // The failed attempt did not use up the continuation token: the same token still works
        let good = service
            .continue_transaction(&txn_id, &cont, Some(interact_ref), Some(&correct_hash))
            .await;
        assert!(good.is_ok());
    }

    /// An approved transaction that uses a finish method: the transaction id, its continuation
    /// token, the interaction hash and the one-time interaction reference issued at approval.
    async fn interact_transaction(service: &GnapService) -> (String, String, String, String) {
        let client_nonce = "client-nonce-abc";
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/cb".to_string(),
                    nonce: client_nonce.to_string(),
                    hash_method: None,
                }),
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let (id, cont) = {
            let txn = service.test_first_txn().await;
            (txn.id, txn.continue_token)
        };
        let done = service.approve_transaction(&id, None).await.unwrap();
        let interact_ref = done.interact_ref.unwrap();
        let hash = done.hash.unwrap();
        let txn = service.test_txn(&id).await;
        assert_eq!(
            hash,
            GnapService::compute_interact_hash(
                client_nonce,
                txn.interact_nonce.as_deref().unwrap(),
                &interact_ref,
                &service.config.transaction_endpoint,
            ),
            "the hash approve returns is the section 4.2.3 hash"
        );
        (id, cont, hash, interact_ref)
    }

    #[tokio::test]
    async fn test_failed_hash_check_does_not_use_up_the_continuation_token() {
        let service = test_service();
        let (txn_id, cont, hash, iref) = interact_transaction(&service).await;

        // Same length as the real hash, one character different
        let mut wrong = hash.clone();
        wrong.pop();
        wrong.push(if hash.ends_with('a') { 'b' } else { 'a' });
        assert_eq!(wrong.len(), hash.len());

        for _ in 0..3 {
            let bad = service
                .continue_transaction(&txn_id, &cont, Some(&iref), Some(&wrong))
                .await;
            assert!(bad.is_err());
        }
        // The token the client was given is the one stored
        let stored = service.test_txn(&txn_id).await.continue_token;
        assert_eq!(stored, cont);
        assert!(
            service
                .continue_transaction(&txn_id, &cont, Some(&iref), Some(&hash))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_fifth_wrong_interaction_reference_invalidates_the_transaction() {
        let service = test_service();
        let (txn_id, cont, hash, iref) = interact_transaction(&service).await;
        let wrong = |n: u32| format!("wrong-{n}");
        // A third party without the continuation token reaches no count.
        for _ in 0..10 {
            let e = service
                .continue_transaction(&txn_id, "not-the-token", Some(&iref), Some("x"))
                .await
                .unwrap_err()
                .to_string();
            assert!(e.ends_with(INVALID_CONTINUATION), "{}", e);
        }
        // Four wrong hashes from the holder are plain refusals, and the right one still works after them
        // (control: the count alone does not spoil the transaction).
        for n in 0..4 {
            let e = service
                .continue_transaction(&txn_id, &cont, Some(&iref), Some(&wrong(n)))
                .await
                .unwrap_err()
                .to_string();
            assert!(e.ends_with(INVALID_CONTINUATION), "attempt {n}");
        }
        assert_eq!(service.test_txn(&txn_id).await.bad_attempts, 4);
        // The fifth is refused with the registered code, and the transaction is gone even for the right hash.
        let fifth = service
            .continue_transaction(&txn_id, &cont, Some(&iref), Some(&wrong(4)))
            .await
            .unwrap_err()
            .to_string();
        assert!(fifth.ends_with(TOO_MANY_ATTEMPTS), "{}", fifth);
        let after = service
            .continue_transaction(&txn_id, &cont, Some(&iref), Some(&hash))
            .await
            .unwrap_err()
            .to_string();
        assert!(after.ends_with(INVALID_CONTINUATION), "{}", after);
    }

    #[tokio::test]
    async fn the_attempt_cap_is_configurable_and_zero_turns_it_off() {
        let service = test_service().with_max_bad_attempts(2);
        let (txn_id, cont, _hash, iref) = interact_transaction(&service).await;
        let bad =
            |s: &'static str| service.continue_transaction(&txn_id, &cont, Some(&iref), Some(s));
        assert!(
            bad("a")
                .await
                .unwrap_err()
                .to_string()
                .ends_with(INVALID_CONTINUATION),
            "{}",
            bad("a").await.unwrap_err().to_string()
        );
        assert!(
            bad("b")
                .await
                .unwrap_err()
                .to_string()
                .ends_with(TOO_MANY_ATTEMPTS),
            "{}",
            bad("b").await.unwrap_err().to_string()
        );

        let open = test_service().with_max_bad_attempts(0);
        let (txn_id, cont, hash, iref) = interact_transaction(&open).await;
        for _ in 0..50 {
            assert!(
                open.continue_transaction(&txn_id, &cont, Some(&iref), Some("nope"))
                    .await
                    .is_err()
            );
        }
        assert!(
            open.continue_transaction(&txn_id, &cont, Some(&iref), Some(&hash))
                .await
                .is_ok()
        );
    }

    fn section_11_request(client_nonce: &str) -> GnapTransactionRequest {
        GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/cb".to_string(),
                    nonce: client_nonce.to_string(),
                    hash_method: None,
                }),
                hints: None,
            }),
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "read".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        }
    }

    /// RFC 9635 section 11.28 (exhaustion of the random value space) and 11.26 (what the AS stores and emits).
    #[tokio::test]
    async fn section_11_28_random_values_are_distinct_long_and_not_interchangeable() {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicU64, Ordering};
        let time = Arc::new(AtomicU64::new(1_800_000_000));
        let clock = Arc::clone(&time);
        let service = test_service().with_clock(move || clock.load(Ordering::SeqCst));
        const N: usize = 100;
        for i in 0..N {
            service
                .handle_transaction(section_11_request(&format!("cn-{i}")))
                .await
                .unwrap();
        }
        let ids = service.test_txn_ids().await;
        assert_eq!(ids.len(), N, "every transaction is stored under its own id");
        let mut txns = Vec::new();
        for id in &ids {
            txns.push(service.test_txn(id).await);
        }
        let distinct = |values: Vec<String>| values.into_iter().collect::<HashSet<_>>().len();
        assert_eq!(
            distinct(txns.iter().map(|t| t.continue_token.clone()).collect()),
            N
        );
        assert_eq!(
            distinct(
                txns.iter()
                    .filter_map(|t| t.interact_nonce.clone())
                    .collect()
            ),
            N
        );
        // Long enough to be unguessable: a UUID v4 is 36 characters and 122 random bits.
        assert!(txns.iter().all(|t| t.continue_token.len() >= 32));
        assert!(
            txns.iter()
                .all(|t| t.interact_nonce.as_deref().is_some_and(|n| n.len() >= 32))
        );
        // Section 11.26: the finish URI the AS keeps is the client's own, with nothing added.
        assert!(txns.iter().all(|t| {
            t.request
                .interact
                .as_ref()
                .unwrap()
                .finish
                .as_ref()
                .unwrap()
                .uri
                == "https://client.test/cb"
        }));

        // Values of one transaction do not work on another (control: its own works).
        let (a, b) = (&txns[0], &txns[1]);
        assert!(
            service
                .continue_transaction(&b.id, &a.continue_token, None, None)
                .await
                .is_err()
        );
        assert!(
            service
                .continue_transaction(&a.id, &a.continue_token, None, None)
                .await
                .is_ok()
        );
        // An id is not a continuation token either.
        assert!(
            service
                .continue_transaction(&b.id, &b.id, None, None)
                .await
                .is_err()
        );

        // Values are time-boxed: past the transaction lifetime the continuation token no longer works.
        time.fetch_add(
            service.config.transaction_lifetime_secs + 1,
            Ordering::SeqCst,
        );
        let rotated = service.test_txn(&b.id).await.continue_token;
        assert!(
            service
                .continue_transaction(&b.id, &rotated, None, None)
                .await
                .is_err()
        );
    }

    /// RFC 9635 section 11.25: the interaction hash covers the client nonce, the AS nonce, the interaction
    /// reference and the grant endpoint, and a continuation token cannot be used with another grant's reference.
    #[tokio::test]
    async fn section_11_25_the_hash_binds_both_nonces_the_reference_and_the_endpoint() {
        let h = GnapService::compute_interact_hash;
        let base = h("cn", "sn", "ref", "https://as.test/tx");
        assert_eq!(base, h("cn", "sn", "ref", "https://as.test/tx"));
        for changed in [
            h("cn2", "sn", "ref", "https://as.test/tx"),
            h("cn", "sn2", "ref", "https://as.test/tx"),
            h("cn", "sn", "ref2", "https://as.test/tx"),
            h("cn", "sn", "ref", "https://as.test/tx2"),
        ] {
            assert_ne!(changed, base);
        }

        // CT1 with grant B's reference and hash (the section's CT2 attack): refused, and A's own still works.
        let service = test_service();
        for nonce in ["cn-a", "cn-b"] {
            service
                .handle_transaction(section_11_request(nonce))
                .await
                .unwrap();
        }
        let mut grants = Vec::new();
        for id in service.test_txn_ids().await {
            let txn = service.test_txn(&id).await;
            let done = service.approve_transaction(&id, None).await.unwrap();
            grants.push((
                id,
                txn.continue_token,
                done.interact_ref.unwrap(),
                done.hash.unwrap(),
            ));
        }
        let (a, b) = (&grants[0], &grants[1]);
        let crossed = service
            .continue_transaction(&a.0, &a.1, Some(&b.2), Some(&b.3))
            .await
            .unwrap_err()
            .to_string();
        assert!(crossed.ends_with(INVALID_CONTINUATION), "{crossed}");
        assert!(
            service
                .continue_transaction(&a.0, &a.1, Some(&a.2), Some(&a.3))
                .await
                .is_ok(),
            "control: the grant's own token, reference and hash succeed"
        );
    }

    /// RFC 9635 section 11.23: a finish method yields a finish nonce and a hash; with none, polling still works.
    #[tokio::test]
    async fn section_11_23_finish_gives_a_nonce_and_no_finish_still_polls() {
        let service = test_service();
        let with_finish = service
            .handle_transaction(section_11_request("cn"))
            .await
            .unwrap();
        assert!(
            with_finish["interact"]["finish"]
                .as_str()
                .is_some_and(|n| n.len() >= 32)
        );
        let mut polled = section_11_request("cn");
        polled.interact.as_mut().unwrap().finish = None;
        let without = service.handle_transaction(polled).await.unwrap();
        assert!(without["interact"].get("finish").is_none());
        let id = without["continue"]["uri"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();
        let token = without["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let pending = service
            .continue_transaction(&id, &token, None, None)
            .await
            .unwrap();
        assert!(pending["continue"]["access_token"]["value"].is_string());
    }

    /// RFC 9635 section 11.24, "Session Management for Interaction Finish Methods": the client must tie the
    /// callback to the grant it started, "or make the callback URI unique per grant" (section 2.5.2). The
    /// session binding is the client's duty; the AS side is that two grants sharing one finish URI still get
    /// callbacks the client can tell apart: each carries its own interaction reference and its own hash, and one
    /// grant's reference does not finish the other.
    #[tokio::test]
    async fn section_11_24_two_grants_on_one_finish_uri_get_callbacks_that_differ() {
        let service = test_service();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let started = service
                .handle_transaction(section_11_request("same-client-nonce"))
                .await
                .unwrap();
            let id = started["continue"]["uri"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string();
            service.approve_transaction(&id, None).await.unwrap();
            ids.push(id);
        }
        let pair = |url: &url::Url| -> (String, String) {
            let get = |name: &str| {
                url.query_pairs()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            (get("interact_ref"), get("hash"))
        };
        let a = service.redirect_callback(&ids[0]).await.unwrap();
        let b = service.redirect_callback(&ids[1]).await.unwrap();
        let ((ref_a, hash_a), (ref_b, hash_b)) = (pair(&a), pair(&b));
        assert_eq!(a.path(), b.path(), "both go to the one finish URI");
        assert!(
            !ref_a.is_empty() && !hash_a.is_empty(),
            "control: a callback carries both"
        );
        assert_ne!(ref_a, ref_b, "each grant has its own interaction reference");
        assert_ne!(hash_a, hash_b, "and its own hash");
        // One grant's reference does not finish the other grant.
        let token_b = service.test_txn(&ids[1]).await.continue_token;
        assert!(
            service
                .continue_transaction(&ids[1], &token_b, Some(&ref_a), None)
                .await
                .is_err()
        );
        assert!(
            service
                .continue_transaction(&ids[1], &token_b, Some(&ref_b), None)
                .await
                .is_ok(),
            "control: its own reference finishes it"
        );
    }

    /// RFC 9635 section 11.27 (denial of service through grant continuation): the AS announces a wait, refuses
    /// a poll that comes sooner, and a client that keeps hammering keeps being refused.
    #[tokio::test]
    async fn section_11_27_polling_faster_than_the_wait_is_refused_until_the_client_backs_off() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let t0 = 1_800_000_000u64;
        let time = Arc::new(AtomicU64::new(t0));
        let clock = Arc::clone(&time);
        let service = GnapService::new(test_config())
            .with_access_policy(Arc::new(AllowAllPolicy))
            .with_clock(move || clock.load(Ordering::SeqCst));
        let started = service
            .handle_transaction(section_11_request("cn"))
            .await
            .unwrap();
        assert_eq!(
            started["continue"]["wait"], 5,
            "the response announces the wait"
        );
        let (id, mut cont) = {
            let txn = service.test_first_txn().await;
            (txn.id, txn.continue_token)
        };
        let poll = |cont: String| {
            let (service, id) = (&service, id.clone());
            async move { service.continue_transaction(&id, &cont, None, None).await }
        };
        // 1 s after the start, then 2 s later: both are inside the wait, and each refused poll restarts it.
        for step in [1u64, 2] {
            time.fetch_add(step, Ordering::SeqCst);
            let e = poll(cont.clone()).await.unwrap_err().to_string();
            assert!(e.contains("too_fast"), "{e}");
        }
        // Backing off for the full wait is accepted (control), and rotates the token.
        time.fetch_add(5, Ordering::SeqCst);
        let ok = poll(cont.clone()).await.unwrap();
        cont = ok["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(service.test_txn(&id).await.continue_token, cont);
    }

    #[tokio::test]
    async fn test_every_refused_continuation_returns_the_same_message() {
        let service = test_service();
        let (txn_id, cont, hash, iref) = interact_transaction(&service).await;

        let unknown = service
            .continue_transaction("no-such-transaction", &cont, None, None)
            .await
            .unwrap_err()
            .to_string();
        let wrong_token = service
            .continue_transaction(&txn_id, "not-the-token", None, None)
            .await
            .unwrap_err()
            .to_string();
        let wrong_hash = service
            .continue_transaction(&txn_id, &cont, Some(&iref), Some("not-the-hash"))
            .await
            .unwrap_err()
            .to_string();
        let no_ref = service
            .continue_transaction(&txn_id, &cont, None, None)
            .await
            .unwrap_err()
            .to_string();
        let wrong_ref = service
            .continue_transaction(&txn_id, &cont, Some("not-the-ref"), None)
            .await
            .unwrap_err()
            .to_string();
        service
            .update_transaction(&txn_id, |txn| txn.created_at = 0)
            .await
            .unwrap();
        let expired = service
            .continue_transaction(&txn_id, &cont, Some(&iref), Some(&hash))
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(unknown, wrong_token);
        assert_eq!(unknown, wrong_hash);
        assert_eq!(unknown, no_ref);
        assert_eq!(unknown, wrong_ref);
        assert_eq!(unknown, expired);
        assert!(unknown.contains(INVALID_CONTINUATION));
    }

    #[tokio::test]
    async fn test_continuation_token_must_match_exactly() {
        let service = test_service();
        let (txn_id, cont, _, iref) = interact_transaction(&service).await;

        let mut near_miss = cont.clone();
        near_miss.pop();
        near_miss.push(if cont.ends_with('0') { '1' } else { '0' });
        let too_long = format!("{cont}0");
        let prefix = cont[..cont.len() - 1].to_string();
        for bad in [near_miss, too_long, prefix, String::new()] {
            assert!(
                service
                    .continue_transaction(&txn_id, &bad, None, None)
                    .await
                    .is_err(),
                "token {bad:?} must be refused"
            );
        }
        assert!(
            service
                .continue_transaction(&txn_id, &cont, Some(&iref), None)
                .await
                .is_ok()
        );
    }

    #[test]
    fn test_gnap_transaction_request_builder_access() {
        let req = GnapTransactionRequest::builder()
            .access("read", &["list", "get"], &["https://api.test/resources"])
            .build();

        assert!(req.client.is_none());
        assert!(req.interact.is_none());
        let rights = GnapService::requested_rights(&req.access_token_request.unwrap()).unwrap();
        assert_eq!(rights.len(), 1);
        assert_eq!(rights[0].access_type, "read");
        assert_eq!(rights[0].actions, vec!["list", "get"]);
    }

    #[test]
    fn test_gnap_transaction_request_builder_full() {
        let jwk = test_ec_jwk();
        let req = GnapTransactionRequest::builder()
            .client_key(jwk, "test")
            .redirect_interaction("https://client.test/cb", "nonce-123")
            .access_type("write")
            .subject_formats(vec!["opaque".into()])
            .build();

        assert!(req.client.is_some());
        assert!(req.interact.is_some());
        assert!(req.access_token_request.is_some());
        assert!(req.subject.is_some());
        assert_eq!(req.subject.unwrap().sub_id_formats, vec!["opaque"]);
    }

    #[test]
    fn test_gnap_transaction_request_builder_empty() {
        let req = GnapTransactionRequest::builder().build();
        assert!(req.client.is_none());
        assert!(req.interact.is_none());
        assert!(req.access_token_request.is_none());
        assert!(req.subject.is_none());
    }

    // ── Consent records (G6) ─────────────────────────────────────────────

    use crate::protocols::gnap_consent::{GnapConsent, GnapConsentStore, InMemoryConsentStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory store that counts `record` calls and can be told to fail them.
    #[derive(Default)]
    struct CountingStore {
        inner: InMemoryConsentStore,
        recorded: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl GnapConsentStore for CountingStore {
        async fn record(&self, consent: GnapConsent) -> Result<()> {
            if self.fail {
                return Err(AuthError::validation("store down"));
            }
            self.recorded.fetch_add(1, Ordering::SeqCst);
            self.inner.record(consent).await
        }
        async fn get(&self, id: &str) -> Result<Option<GnapConsent>> {
            self.inner.get(id).await
        }
        async fn list_for_owner(&self, owner: &str) -> Result<Vec<GnapConsent>> {
            self.inner.list_for_owner(owner).await
        }
        async fn revoke(&self, id: &str, at: u64) -> Result<Option<GnapConsent>> {
            self.inner.revoke(id, at).await
        }
        async fn revoke_for_key(&self, thumbprint: &str, at: u64) -> Result<Vec<GnapConsent>> {
            self.inner.revoke_for_key(thumbprint, at).await
        }
    }

    /// Grants only the first right asked for.
    struct FirstOnlyPolicy;

    #[async_trait]
    impl GnapAccessPolicy for FirstOnlyPolicy {
        async fn grant(&self, _: &str, requested: &[GnapAccessRequest]) -> Vec<GnapAccessRequest> {
            requested.iter().take(1).cloned().collect()
        }
    }

    fn right(kind: &str) -> GnapAccessRequest {
        GnapAccessRequest {
            access_type: kind.to_string(),
            actions: vec![],
            locations: vec![],
        }
    }

    /// Run an interactive transaction for `rights` to approval by `owner` and return the result
    /// of the final continuation.
    async fn approved_by(
        service: &GnapService,
        owner: Option<&str>,
        rights: Vec<GnapAccessRequest>,
    ) -> Result<serde_json::Value> {
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(rights.into()),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let (txn_id, cont) = {
            let t = service.test_first_txn().await;
            (t.id, t.continue_token)
        };
        service.approve_transaction(&txn_id, owner).await.unwrap();
        service
            .continue_transaction(&txn_id, &cont, None, None)
            .await
    }

    #[tokio::test]
    async fn an_approved_interactive_grant_leaves_a_consent_record() {
        let service = test_service();
        let resp = approved_by(&service, Some("user-42"), vec![right("read")])
            .await
            .unwrap();
        assert!(resp["access_token"]["value"].is_string());

        let consents = service.consents_for_owner("user-42").await.unwrap();
        assert_eq!(consents.len(), 1);
        let c = &consents[0];
        assert!(c.is_active());
        assert_eq!(c.resource_owner.as_deref(), Some("user-42"));
        assert_eq!(c.access.len(), 1);
        assert_eq!(c.access[0].access_type, "read");
        assert!(!c.client_key_thumbprint.is_empty());
        assert!(
            service
                .consents_for_owner("someone-else")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_consent_records_what_the_policy_granted_not_what_was_asked() {
        let service = GnapService::new(test_config()).with_access_policy(Arc::new(FirstOnlyPolicy));
        approved_by(&service, Some("u"), vec![right("read"), right("write")])
            .await
            .unwrap();
        let consents = service.consents_for_owner("u").await.unwrap();
        assert_eq!(consents[0].access.len(), 1);
        assert_eq!(consents[0].access[0].access_type, "read");
    }

    #[tokio::test]
    async fn a_direct_grant_with_no_resource_owner_records_no_consent() {
        let store = Arc::new(CountingStore::default());
        let service = test_service().with_consent_store(store.clone());
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        assert!(resp["access_token"]["value"].is_string());
        assert_eq!(store.recorded.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn withdrawing_a_consent_revokes_the_token_it_produced() {
        let service = test_service();
        let resp = approved_by(&service, Some("user-42"), vec![right("read")])
            .await
            .unwrap();
        let token = resp["access_token"]["value"].as_str().unwrap().to_string();
        assert!(service.introspect_token(&token).await.unwrap().is_some());

        let id = service.consents_for_owner("user-42").await.unwrap()[0]
            .id
            .clone();
        service.revoke_consent(&id).await.unwrap();

        assert!(service.introspect_token(&token).await.unwrap().is_none());
        let after = service.consents_for_owner("user-42").await.unwrap();
        assert!(!after[0].is_active());
    }

    #[tokio::test]
    async fn a_rotated_token_is_revoked_with_its_consent() {
        let service = test_service();
        let resp = approved_by(&service, Some("user-42"), vec![right("read")])
            .await
            .unwrap();
        let old = resp["access_token"]["value"].as_str().unwrap().to_string();
        let rotated = service.rotate_token(&old).await.unwrap();
        let new = rotated["value"].as_str().unwrap().to_string();
        assert!(service.introspect_token(&new).await.unwrap().is_some());

        let id = service.consents_for_owner("user-42").await.unwrap()[0]
            .id
            .clone();
        service.revoke_consent(&id).await.unwrap();
        assert!(service.introspect_token(&new).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn withdrawing_twice_is_harmless_and_an_unknown_consent_is_refused() {
        let service = test_service();
        approved_by(&service, Some("u"), vec![right("read")])
            .await
            .unwrap();
        let id = service.consents_for_owner("u").await.unwrap()[0].id.clone();
        service.revoke_consent(&id).await.unwrap();
        let first = service.consents_for_owner("u").await.unwrap()[0].revoked_at;
        service.revoke_consent(&id).await.unwrap();
        let second = service.consents_for_owner("u").await.unwrap()[0].revoked_at;
        assert_eq!(first, second);
        assert!(service.revoke_consent("no-such-id").await.is_err());
    }

    #[tokio::test]
    async fn withdrawing_one_consent_leaves_another_owners_token_alone() {
        let service = test_service();
        let a = approved_by(&service, Some("alice"), vec![right("read")])
            .await
            .unwrap();
        let b = approved_by(&service, Some("bob"), vec![right("read")])
            .await
            .unwrap();
        let a_tok = a["access_token"]["value"].as_str().unwrap().to_string();
        let b_tok = b["access_token"]["value"].as_str().unwrap().to_string();
        let id = service.consents_for_owner("alice").await.unwrap()[0]
            .id
            .clone();
        service.revoke_consent(&id).await.unwrap();
        assert!(service.introspect_token(&a_tok).await.unwrap().is_none());
        assert!(service.introspect_token(&b_tok).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn no_token_is_issued_when_its_consent_cannot_be_recorded() {
        let store = Arc::new(CountingStore {
            fail: true,
            ..Default::default()
        });
        let service = test_service().with_consent_store(store);
        let result = approved_by(&service, Some("user-42"), vec![right("read")]).await;
        assert!(result.is_err());
        assert!((service.issued_tokens.count().await.unwrap() == 0));
    }

    // ── Token store (G6 slice 2) ─────────────────────────────────────────

    use crate::protocols::gnap_store::{
        GnapIssuedToken, GnapTokenStore, GnapTransactionStore, InMemoryTokenStore,
        InMemoryTransactionStore,
    };
    use std::sync::atomic::AtomicBool;

    /// A token store that can be told to fail reads or writes.
    #[derive(Default)]
    struct FlakyTokenStore {
        inner: InMemoryTokenStore,
        fail_insert: AtomicBool,
        fail_read: AtomicBool,
    }

    #[async_trait]
    impl GnapTokenStore for FlakyTokenStore {
        async fn insert(&self, token: GnapIssuedToken) -> Result<()> {
            if self.fail_insert.load(Ordering::SeqCst) {
                return Err(AuthError::validation("store down"));
            }
            self.inner.insert(token).await
        }
        async fn get(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(AuthError::validation("store down"));
            }
            self.inner.get(value).await
        }
        async fn remove(&self, value: &str) -> Result<Option<GnapIssuedToken>> {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(AuthError::validation("store down"));
            }
            self.inner.remove(value).await
        }
        async fn remove_for_transaction(&self, transaction_id: &str) -> Result<usize> {
            self.inner.remove_for_transaction(transaction_id).await
        }
        async fn remove_for_key(&self, thumbprint: &str) -> Result<usize> {
            self.inner.remove_for_key(thumbprint).await
        }
        async fn count(&self) -> Result<usize> {
            self.inner.count().await
        }
        async fn purge_expired(&self, now: u64) -> Result<usize> {
            self.inner.purge_expired(now).await
        }
    }

    async fn direct_token(service: &GnapService) -> String {
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        resp["access_token"]["value"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn tokens_live_in_the_configured_store_and_outlive_the_service() {
        let store = Arc::new(InMemoryTokenStore::new());
        let first = test_service().with_token_store(store.clone());
        let token = direct_token(&first).await;
        assert_eq!(store.count().await.unwrap(), 1);
        drop(first);

        // A new service over the same store (a restart with a durable store) still knows it.
        let second = test_service().with_token_store(store.clone());
        let info = second.introspect_token(&token).await.unwrap().unwrap();
        assert_eq!(info["active"], true);
        second.revoke_token(&token).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_store_that_cannot_read_refuses_rather_than_reporting_no_token() {
        let store = Arc::new(FlakyTokenStore::default());
        let service = test_service().with_token_store(store.clone());
        let token = direct_token(&service).await;

        store.fail_read.store(true, Ordering::SeqCst);
        assert!(service.introspect_token(&token).await.is_err());
        assert!(service.revoke_token(&token).await.is_err());
        assert!(service.rotate_token(&token).await.is_err());

        // Nothing was changed by the refused calls.
        store.fail_read.store(false, Ordering::SeqCst);
        assert!(service.introspect_token(&token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn no_token_is_returned_when_the_store_cannot_keep_it_and_its_consent_is_withdrawn() {
        let store = Arc::new(FlakyTokenStore::default());
        store.fail_insert.store(true, Ordering::SeqCst);
        let service = test_service().with_token_store(store.clone());

        let result = approved_by(&service, Some("user-42"), vec![right("read")]).await;
        assert!(result.is_err());
        assert_eq!(store.count().await.unwrap(), 0);
        let consents = service.consents_for_owner("user-42").await.unwrap();
        assert_eq!(consents.len(), 1);
        assert!(!consents[0].is_active());
    }

    #[tokio::test]
    async fn cleanup_removes_expired_tokens_from_the_store() {
        let store = Arc::new(InMemoryTokenStore::new());
        let service = test_service().with_token_store(store.clone());
        let token = direct_token(&service).await;
        let mut expired = store.get(&token).await.unwrap().unwrap();
        expired.value = "old".to_string();
        expired.expires_at = 1;
        store.insert(expired).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 2);

        service.cleanup_expired_tokens().await;
        assert_eq!(store.count().await.unwrap(), 1);
        assert!(store.get(&token).await.unwrap().is_some());
    }

    // ── KM5: a revoked client key kills the grants bound to it ───────────

    fn other_ec_jwk() -> GnapJwk {
        let key = crate::keys::LocalKey::generate(
            crate::keys::KeyKind::GnapClient,
            crate::keys::SigningAlg::Es256,
            None,
        )
        .unwrap();
        serde_json::from_value(key.public().to_value()).unwrap()
    }

    async fn direct_token_for(service: &GnapService, jwk: GnapJwk) -> String {
        let req = GnapTransactionRequest {
            client: Some(test_client_info(jwk)),
            interact: None,
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        resp["access_token"]["value"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn revoking_a_client_key_kills_its_tokens_and_only_its_tokens() {
        let service = test_service();
        let doomed_jwk = test_ec_jwk();
        let doomed_tp = GnapService::jwk_thumbprint(&doomed_jwk).unwrap();
        let doomed = direct_token_for(&service, doomed_jwk.clone()).await;
        let doomed2 = direct_token_for(&service, doomed_jwk).await;
        let bystander = direct_token_for(&service, other_ec_jwk()).await;
        // Positive control: all three are live before the revocation.
        for t in [&doomed, &doomed2, &bystander] {
            assert!(service.introspect_token(t).await.unwrap().is_some());
        }

        let report = service.revoke_client_key(&doomed_tp).await.unwrap();
        assert_eq!(report.tokens, 2);
        assert!(service.introspect_token(&doomed).await.unwrap().is_none());
        assert!(service.introspect_token(&doomed2).await.unwrap().is_none());
        // Refutation: a token bound to another key is untouched.
        assert!(
            service
                .introspect_token(&bystander)
                .await
                .unwrap()
                .is_some()
        );
        // Repeating is harmless and removes nothing more.
        assert_eq!(
            service.revoke_client_key(&doomed_tp).await.unwrap(),
            ClientKeyRevocation::default()
        );
    }

    #[tokio::test]
    async fn revoking_a_client_key_withdraws_its_consents_and_drops_its_transactions() {
        let service = test_service();
        let tp = GnapService::jwk_thumbprint(&test_ec_jwk()).unwrap();
        // One approved interactive grant (leaves a consent and a token), one still pending.
        let owner = "owner-1";
        approved_by(&service, Some(owner), vec![right("read")])
            .await
            .unwrap();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        assert!(service.consents_for_owner(owner).await.unwrap()[0].is_active());
        let before = service.transactions.count().await.unwrap();
        // The approved transaction was consumed when its token was issued; only the pending one stands.
        assert_eq!(before, 1);

        let report = service.revoke_client_key(&tp).await.unwrap();
        assert_eq!(report.consents, 1);
        assert_eq!(report.tokens, 1);
        assert_eq!(report.transactions, 1);
        assert!(!service.consents_for_owner(owner).await.unwrap()[0].is_active());
        assert_eq!(service.transactions.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_revoked_keys_pending_transaction_cannot_continue_to_a_token() {
        let service = test_service();
        let tp = GnapService::jwk_thumbprint(&test_ec_jwk()).unwrap();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let (txn_id, cont) = {
            let t = service.test_first_txn().await;
            (t.id, t.continue_token)
        };
        service.revoke_client_key(&tp).await.unwrap();
        assert!(
            service
                .approve_transaction(&txn_id, Some("o"))
                .await
                .is_err()
        );
        assert!(
            service
                .continue_transaction(&txn_id, &cont, None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn revoking_by_kid_revokes_the_key_and_kills_its_grants() {
        use crate::keys::{KeyState, KeyStore, MemoryKeyStore};
        let store = MemoryKeyStore::new();
        let key = crate::keys::LocalKey::generate(
            crate::keys::KeyKind::GnapClient,
            crate::keys::SigningAlg::Es256,
            None,
        )
        .unwrap();
        let kid = key.public().kid.clone().unwrap();
        let jwk: GnapJwk = serde_json::from_value(key.public().to_value()).unwrap();
        // The two thumbprint computations agree, so a kid can find its grants.
        assert_eq!(
            GnapService::jwk_thumbprint(&jwk).unwrap(),
            key.public().thumbprint().unwrap()
        );
        store.insert(key, KeyState::Active).await.unwrap();
        let service = test_service();
        let token = direct_token_for(&service, jwk).await;
        assert!(service.introspect_token(&token).await.unwrap().is_some());

        let report = service
            .revoke_client_key_by_kid(&store, &kid)
            .await
            .unwrap();
        assert_eq!(report.tokens, 1);
        assert_eq!(store.info(&kid).await.unwrap().state, KeyState::Revoked);
        assert!(service.introspect_token(&token).await.unwrap().is_none());
        // A key that is already revoked is an error, and nothing else is touched.
        assert!(
            service
                .revoke_client_key_by_kid(&store, &kid)
                .await
                .is_err()
        );
    }

    // ── Transaction store (G6 slice 3) ───────────────────────────────────

    /// A transaction store that can be told to fail, and that yields after every read so that
    /// concurrent requests all read the same snapshot before any of them writes.
    #[derive(Default)]
    struct RacyTransactionStore {
        inner: InMemoryTransactionStore,
        fail_insert: AtomicBool,
        fail_read: AtomicBool,
    }

    #[async_trait]
    impl GnapTransactionStore for RacyTransactionStore {
        async fn insert(&self, txn: GnapTransaction) -> Result<()> {
            if self.fail_insert.load(Ordering::SeqCst) {
                return Err(AuthError::validation("store down"));
            }
            self.inner.insert(txn).await
        }
        async fn get(&self, id: &str) -> Result<Option<GnapTransaction>> {
            if self.fail_read.load(Ordering::SeqCst) {
                return Err(AuthError::validation("store down"));
            }
            let found = self.inner.get(id).await;
            tokio::task::yield_now().await;
            found
        }
        async fn replace_if_unchanged(&self, txn: GnapTransaction) -> Result<bool> {
            self.inner.replace_if_unchanged(txn).await
        }
        async fn remove(&self, id: &str) -> Result<Option<GnapTransaction>> {
            self.inner.remove(id).await
        }
        async fn purge_created_before(&self, cutoff: u64) -> Result<usize> {
            self.inner.purge_created_before(cutoff).await
        }
        async fn count(&self) -> Result<usize> {
            self.inner.count().await
        }
        async fn ids(&self) -> Result<Vec<String>> {
            self.inner.ids().await
        }
    }

    /// Run these futures as concurrent tasks and collect their outputs in order.
    async fn run_all<T, F>(futures: impl IntoIterator<Item = F>) -> Vec<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let handles: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
        let mut out = Vec::new();
        for handle in handles {
            out.push(handle.await.unwrap());
        }
        out
    }

    /// A pending polling transaction: its id and continuation token.
    async fn pending(service: &GnapService, _finish: bool) -> (String, String) {
        let before = service.test_txn_ids().await;
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let id = service
            .test_txn_ids()
            .await
            .into_iter()
            .find(|k| !before.contains(k))
            .unwrap();
        let cont = service.test_txn(&id).await.continue_token;
        (id, cont)
    }

    #[tokio::test]
    async fn transactions_live_in_the_configured_store_and_outlive_the_service() {
        let store = Arc::new(InMemoryTransactionStore::new());
        let first = test_service().with_transaction_store(store.clone());
        let (id, cont) = pending(&first, false).await;
        assert_eq!(store.count().await.unwrap(), 1);
        drop(first);

        // A new service over the same store (a restart with a durable store) continues it.
        let second = test_service().with_transaction_store(store.clone());
        let resp = second
            .continue_transaction(&id, &cont, None, None)
            .await
            .unwrap();
        assert!(resp["continue"]["access_token"]["value"].is_string());
    }

    #[tokio::test]
    async fn a_store_that_cannot_read_refuses_instead_of_reporting_no_transaction() {
        let store = Arc::new(RacyTransactionStore::default());
        let service = test_service().with_transaction_store(store.clone());
        let (id, cont) = pending(&service, false).await;

        store.fail_read.store(true, Ordering::SeqCst);
        let msg = service
            .continue_transaction(&id, &cont, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(msg.contains("store down"), "{msg}");
        assert!(service.approve_transaction(&id, None).await.is_err());
        assert!(service.deny_transaction(&id).await.is_err());

        // The refused calls changed nothing: the same token still works.
        store.fail_read.store(false, Ordering::SeqCst);
        assert!(
            service
                .continue_transaction(&id, &cont, None, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn no_continuation_token_is_handed_out_when_the_store_cannot_keep_the_transaction() {
        let store = Arc::new(RacyTransactionStore::default());
        store.fail_insert.store(true, Ordering::SeqCst);
        let service = test_service().with_transaction_store(store.clone());
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            }),
            access_token_request: Some(vec![right("read")].into()),
            subject: None,
        };
        assert!(service.handle_transaction(req).await.is_err());
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn of_many_polls_with_one_token_exactly_one_rotates_it() {
        let store = Arc::new(RacyTransactionStore::default());
        let service = Arc::new(test_service().with_transaction_store(store));
        let (id, cont) = pending(&service, false).await;

        let polls = (0..8).map(|_| {
            let service = service.clone();
            let (id, cont) = (id.clone(), cont.clone());
            async move { service.continue_transaction(&id, &cont, None, None).await }
        });
        let results = run_all(polls).await;
        let won = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(won, 1, "exactly one poll may rotate the token");
        // And the stored token is the one that winner was given.
        let given = results
            .iter()
            .find_map(|r| r.as_ref().ok())
            .unwrap()["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(service.test_txn(&id).await.continue_token, given);
    }

    #[tokio::test]
    async fn of_many_continuations_of_an_approved_transaction_exactly_one_gets_the_token() {
        let store = Arc::new(RacyTransactionStore::default());
        let tokens = Arc::new(InMemoryTokenStore::new());
        let service = Arc::new(
            test_service()
                .with_transaction_store(store.clone())
                .with_token_store(tokens.clone()),
        );
        let (id, cont) = pending(&service, false).await;
        service
            .approve_transaction(&id, Some("user-1"))
            .await
            .unwrap();

        let polls = (0..8).map(|_| {
            let service = service.clone();
            let (id, cont) = (id.clone(), cont.clone());
            async move { service.continue_transaction(&id, &cont, None, None).await }
        });
        let results = run_all(polls).await;
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(tokens.count().await.unwrap(), 1, "one token, issued once");
        assert_eq!(store.count().await.unwrap(), 0, "the transaction is spent");
    }

    #[tokio::test]
    async fn a_denial_that_lands_between_the_read_and_the_spend_wins() {
        let store = Arc::new(RacyTransactionStore::default());
        let tokens = Arc::new(InMemoryTokenStore::new());
        let service = Arc::new(
            test_service()
                .with_transaction_store(store)
                .with_token_store(tokens.clone()),
        );
        let (id, cont) = pending(&service, false).await;
        service
            .approve_transaction(&id, Some("user-1"))
            .await
            .unwrap();

        // The continuation reads the approved transaction and yields; the denial lands then.
        let racing = {
            let (service, id, cont) = (service.clone(), id.clone(), cont.clone());
            tokio::spawn(async move { service.continue_transaction(&id, &cont, None, None).await })
        };
        service.deny_transaction(&id).await.unwrap();
        let outcome = racing.await.unwrap();
        assert!(outcome.is_err(), "a denied transaction issues nothing");
        assert_eq!(tokens.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn two_approvals_at_once_agree_on_one_interaction_reference() {
        let store = Arc::new(RacyTransactionStore::default());
        let service = Arc::new(test_service().with_transaction_store(store));
        let (id, _cont, _hash, first_ref) = interact_transaction(&service).await;

        let approvals = (0..4).map(|_| {
            let (service, id) = (service.clone(), id.clone());
            async move { service.approve_transaction(&id, Some("user-1")).await }
        });
        for done in run_all(approvals).await {
            assert_eq!(done.unwrap().interact_ref.unwrap(), first_ref);
        }
        assert_eq!(service.test_txn(&id).await.interact_ref.unwrap(), first_ref);
    }
}

/// A client key's proof is verified or refused: no proof that was never checked authorizes a
/// request. Each refusal is paired with the accepted case built the same way, so a test cannot
/// pass because every request fails for one shared reason.
#[cfg(test)]
mod proof_verification_tests {
    use super::*;
    use crate::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
    use jsonwebtoken::{Algorithm, EncodingKey};
    use serde_json::json;

    const URI: &str = "https://as.example.test/api/gnap/tx";
    const CONTINUE_URI: &str = "https://as.example.test/api/gnap/tx/continue";

    struct ClientKey {
        signing: EncodingKey,
        jwk: GnapJwk,
    }

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

    /// A DPoP proof for `htm` `htu`, signed by `signer` and naming `named` in its header.
    fn dpop_header(
        signer: &ClientKey,
        named: &ClientKey,
        htm: &str,
        htu: &str,
        jti: &str,
    ) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwk = serde_json::to_value(&named.jwk).unwrap();
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
        let claims = json!({
            "jti": jti, "htm": htm, "htu": htu, "iat": chrono::Utc::now().timestamp()
        });
        let si = format!(
            "{}.{}",
            b64.encode(header.to_string()),
            b64.encode(claims.to_string())
        );
        let sig =
            jsonwebtoken::crypto::sign(si.as_bytes(), &signer.signing, Algorithm::ES256).unwrap();
        format!("{si}.{sig}")
    }

    fn manager() -> DpopManager {
        DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap())
    }

    fn service() -> GnapService {
        GnapService::new(GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://as.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        })
        .with_poll_wait_secs(0)
        .with_access_policy(Arc::new(AllowAllPolicy))
    }

    fn request(key: &ClientKey, proof: &str, interact: bool) -> GnapTransactionRequest {
        let mut builder = GnapTransactionRequest::builder()
            .client_key(key.jwk.clone(), proof)
            .access_type("read");
        if interact {
            builder = builder.redirect_interaction("https://client.test/cb", "client-nonce");
        }
        builder.build()
    }

    fn proof<'a>(header: Option<&'a str>, uri: &'a str) -> GnapProof<'a> {
        GnapProof {
            http_method: "POST",
            http_uri: uri,
            dpop_proof: header,
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: &[],
            http_body: &[],
        }
    }

    fn refusal(result: Result<serde_json::Value>) -> String {
        result.expect_err("the request must be refused").to_string()
    }

    const MANAGE_URI: &str = "https://as.example.test/api/gnap/token/1";

    /// A token issued to `key` over a proved, non-interactive request.
    async fn issued_token(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        jti: &str,
    ) -> String {
        let header = dpop_header(key, key, "POST", URI, jti);
        let resp = svc
            .handle_transaction_with_proof(
                dpop,
                &proof(Some(&header), URI),
                request(key, "dpop", false),
            )
            .await
            .unwrap();
        resp["access_token"]["value"].as_str().unwrap().to_string()
    }

    /// A request in the RFC's own shape: `access_token` given as `access_token_json`.
    fn rfc_request(
        key: &ClientKey,
        access_token_json: serde_json::Value,
    ) -> GnapTransactionRequest {
        serde_json::from_value(json!({
            "client": {"key": {"proof": "dpop", "jwk": serde_json::to_value(&key.jwk).unwrap()}},
            "access_token": access_token_json,
        }))
        .expect("the RFC shape deserializes")
    }

    async fn send(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        jti: &str,
        request: GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        let header = dpop_header(key, key, "POST", URI, jti);
        svc.handle_transaction_with_proof(dpop, &proof(Some(&header), URI), request)
            .await
    }

    #[tokio::test]
    async fn a_request_in_the_rfc_shape_is_parsed_and_issues_a_token() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        // object form (a single token request), access as an object and as a reference string (RFC 9635 2.1, 8)
        let one = json!({"access": ["ref-right", {"type": "photo-api", "actions": ["read"]}], "label": "t1"});
        let resp = send(&svc, &dpop, &key, "rfc-one", rfc_request(&key, one))
            .await
            .unwrap();
        let access = resp["access_token"]["access"].to_string();
        assert!(
            access.contains("photo-api") && access.contains("ref-right"),
            "{access}"
        );
        // array form with one entry is the same request
        let many = json!([{"access": [{"type": "photo-api"}], "label": "only"}]);
        assert!(
            send(&svc, &dpop, &key, "rfc-arr", rfc_request(&key, many))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_access_token_request_the_server_cannot_honour_is_refused_before_anything_is_issued()
    {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let cases = [
            (
                "two tokens",
                json!([{"access": ["a"], "label": "x"}, {"access": ["b"], "label": "y"}]),
                "one access token",
            ),
            (
                "unsupported flag",
                json!({"access": ["a"], "flags": ["bearer"]}),
                "flag",
            ),
            ("no access", json!({"access": []}), "no access"),
            (
                "empty type",
                json!({"access": [{"type": ""}]}),
                "empty type",
            ),
        ];
        for (n, (what, body, expect)) in cases.into_iter().enumerate() {
            let err = refusal(
                send(
                    &svc,
                    &dpop,
                    &key,
                    &format!("neg-{n}"),
                    rfc_request(&key, body),
                )
                .await,
            );
            assert!(err.contains(expect), "{what}: {err}");
        }
        // control: the same request without the defect is served
        assert!(
            send(
                &svc,
                &dpop,
                &key,
                "neg-ok",
                rfc_request(&key, json!({"access": ["a"]}))
            )
            .await
            .is_ok()
        );
    }

    async fn is_live(svc: &GnapService, token: &str) -> bool {
        svc.introspect_token(token).await.unwrap().is_some()
    }

    fn refused_with<T: std::fmt::Debug>(result: Result<T>) -> String {
        result.expect_err("the request must be refused").to_string()
    }

    #[tokio::test]
    async fn a_key_bound_token_is_rotated_only_with_a_proof_from_its_key() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let token = issued_token(&svc, &dpop, &key, "jti-issue").await;
        // The value alone is not enough, however it is presented.
        assert!(refused_with(svc.rotate_token(&token).await).contains("proof required"));
        assert!(
            refused_with(
                svc.rotate_token_with_proof(&dpop, &proof(None, MANAGE_URI), &token)
                    .await
            )
            .contains("proof required")
        );
        // A proof signed by another key is not enough.
        let other = client_key();
        let forged = dpop_header(&other, &other, "POST", MANAGE_URI, "jti-forged");
        assert!(
            refused_with(
                svc.rotate_token_with_proof(&dpop, &proof(Some(&forged), MANAGE_URI), &token)
                    .await
            )
            .contains("proof invalid")
        );
        // A proof for another URI is not enough.
        let elsewhere = dpop_header(
            &key,
            &key,
            "POST",
            "https://as.example.test/elsewhere",
            "jti-elsewhere",
        );
        assert!(
            refused_with(
                svc.rotate_token_with_proof(&dpop, &proof(Some(&elsewhere), MANAGE_URI), &token)
                    .await
            )
            .contains("proof invalid")
        );
        assert!(
            is_live(&svc, &token).await,
            "none of the refusals touched the token"
        );
        // Control: the key's own proof rotates it, and the old value is gone.
        let good = dpop_header(&key, &key, "POST", MANAGE_URI, "jti-rotate");
        let rotated = svc
            .rotate_token_with_proof(&dpop, &proof(Some(&good), MANAGE_URI), &token)
            .await
            .unwrap();
        let new_value = rotated["value"].as_str().unwrap().to_string();
        assert_ne!(new_value, token);
        assert!(!is_live(&svc, &token).await);
        assert!(
            is_live(&svc, &new_value).await,
            "the rotated token keeps its key binding"
        );
        // The new token is bound to the same key: the value alone does not rotate it either.
        assert!(refused_with(svc.rotate_token(&new_value).await).contains("proof required"));
    }

    #[tokio::test]
    async fn a_key_bound_token_is_revoked_only_with_a_proof_from_its_key() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let token = issued_token(&svc, &dpop, &key, "jti-issue").await;
        assert!(refused_with(svc.revoke_token(&token).await).contains("proof required"));
        let other = client_key();
        let forged = dpop_header(&other, &other, "POST", MANAGE_URI, "jti-forged");
        assert!(
            refused_with(
                svc.revoke_token_with_proof(&dpop, &proof(Some(&forged), MANAGE_URI), &token)
                    .await
            )
            .contains("proof invalid")
        );
        assert!(
            is_live(&svc, &token).await,
            "the refusals left the token usable"
        );
        let good = dpop_header(&key, &key, "POST", MANAGE_URI, "jti-revoke");
        svc.revoke_token_with_proof(&dpop, &proof(Some(&good), MANAGE_URI), &token)
            .await
            .unwrap();
        assert!(!is_live(&svc, &token).await);
    }

    #[tokio::test]
    async fn a_management_proof_is_good_for_one_request() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let first = issued_token(&svc, &dpop, &key, "jti-a").await;
        let second = issued_token(&svc, &dpop, &key, "jti-b").await;
        let header = dpop_header(&key, &key, "POST", MANAGE_URI, "jti-once");
        svc.revoke_token_with_proof(&dpop, &proof(Some(&header), MANAGE_URI), &first)
            .await
            .unwrap();
        // The same proof, replayed against another token, is refused and that token survives.
        assert!(
            refused_with(
                svc.revoke_token_with_proof(&dpop, &proof(Some(&header), MANAGE_URI), &second)
                    .await
            )
            .contains("proof invalid")
        );
        assert!(is_live(&svc, &second).await);
    }

    #[tokio::test]
    async fn an_unknown_token_is_refused_whatever_the_proof() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let header = dpop_header(&key, &key, "POST", MANAGE_URI, "jti-unknown");
        let p = proof(Some(&header), MANAGE_URI);
        assert!(
            refused_with(
                svc.revoke_token_with_proof(&dpop, &p, "no-such-token")
                    .await
            )
            .contains("not found")
        );
        assert!(
            refused_with(
                svc.rotate_token_with_proof(&dpop, &p, "no-such-token")
                    .await
            )
            .contains("not found")
        );
    }

    #[tokio::test]
    async fn a_dpop_proof_signed_by_the_named_key_is_accepted() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let header = dpop_header(&key, &key, "POST", URI, "jti-ok");
        let resp = svc
            .handle_transaction_with_proof(
                &dpop,
                &proof(Some(&header), URI),
                request(&key, "dpop", false),
            )
            .await
            .unwrap();
        assert!(resp["access_token"]["value"].is_string());
    }

    #[tokio::test]
    async fn a_dpop_key_with_no_proof_is_refused() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        // Through the entry point that takes no proof at all.
        let msg = refusal(svc.handle_transaction(request(&key, "dpop", false)).await);
        assert!(msg.contains("proof required"), "{msg}");
        // And through the one that does, with no DPoP header.
        let msg = refusal(
            svc.handle_transaction_with_proof(
                &dpop,
                &proof(None, URI),
                request(&key, "dpop", false),
            )
            .await,
        );
        assert!(msg.contains("proof required"), "{msg}");
    }

    #[tokio::test]
    async fn a_dpop_proof_from_another_key_is_refused() {
        let (svc, dpop) = (service(), manager());
        let (victim, attacker) = (client_key(), client_key());
        // The attacker names the victim's key but can only sign with its own.
        let forged = dpop_header(&attacker, &victim, "POST", URI, "jti-forged");
        let msg = refusal(
            svc.handle_transaction_with_proof(
                &dpop,
                &proof(Some(&forged), URI),
                request(&victim, "dpop", false),
            )
            .await,
        );
        assert!(msg.contains("proof invalid"), "{msg}");
        // The attacker's own proof, naming the attacker's own key, is fine: the key is the
        // only thing that differs.
        let own = dpop_header(&attacker, &attacker, "POST", URI, "jti-own");
        svc.handle_transaction_with_proof(
            &dpop,
            &proof(Some(&own), URI),
            request(&attacker, "dpop", false),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_dpop_proof_for_another_method_or_uri_is_refused() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let other_uri = dpop_header(&key, &key, "POST", "https://other.example/tx", "jti-uri");
        let msg = refusal(
            svc.handle_transaction_with_proof(
                &dpop,
                &proof(Some(&other_uri), URI),
                request(&key, "dpop", false),
            )
            .await,
        );
        assert!(msg.contains("proof invalid"), "{msg}");
        let other_method = dpop_header(&key, &key, "GET", URI, "jti-method");
        let msg = refusal(
            svc.handle_transaction_with_proof(
                &dpop,
                &proof(Some(&other_method), URI),
                request(&key, "dpop", false),
            )
            .await,
        );
        assert!(msg.contains("proof invalid"), "{msg}");
    }

    #[tokio::test]
    async fn a_dpop_proof_cannot_be_replayed() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let header = dpop_header(&key, &key, "POST", URI, "jti-once");
        let go = || async {
            svc.handle_transaction_with_proof(
                &dpop,
                &proof(Some(&header), URI),
                request(&key, "dpop", false),
            )
            .await
        };
        go().await.unwrap();
        assert!(refusal(go().await).contains("proof invalid"));
    }

    #[tokio::test]
    async fn unknown_methods_are_refused_not_accepted_unverified() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        // A valid DPoP header does not rescue a method that is not DPoP.
        let header = dpop_header(&key, &key, "POST", URI, "jti-other-method");
        // `mtls` is exercised with a certificate key in the KM7 tests below: with a JWK it is a malformed key.
        for method in ["no-such-method"] {
            let msg = refusal(svc.handle_transaction(request(&key, method, false)).await);
            assert!(
                msg.contains("proof method not supported"),
                "{method}: {msg}"
            );
            let msg = refusal(
                svc.handle_transaction_with_proof(
                    &dpop,
                    &proof(Some(&header), URI),
                    request(&key, method, false),
                )
                .await,
            );
            assert!(
                msg.contains("proof method not supported"),
                "{method}: {msg}"
            );
        }
        // A request that names no key is refused too (RFC 9635 section 2.3).
        let anonymous = GnapTransactionRequest::builder()
            .access_type("read")
            .build();
        let msg = refusal(svc.handle_transaction(anonymous).await);
        assert!(msg.contains("client key required"), "{msg}");
    }

    #[tokio::test]
    async fn issuance_and_management_admit_exactly_the_same_proof_methods() {
        // A method admitted at issuance but not at management would leave a token that cannot be revoked
        // (Pip review). Both gates call `check_key_proof`; this fails if they ever diverge.
        let svc = service();
        let key = client_key();
        let thumbprint = GnapService::jwk_thumbprint(&key.jwk).unwrap();
        let not_supported = |e: AuthError| e.to_string().contains(PROOF_NOT_SUPPORTED);
        let mut admitted = Vec::new();
        for method in [
            "dpop", "test", "httpsig", "jwsd", "jws", "", "DPOP", "none", "bogus",
        ] {
            let client = Some(GnapClientInfo {
                key: Some(GnapClientKey {
                    proof: method.to_string(),
                    jwk: Some(key.jwk.clone()),
                    cert: None,
                    cert_s256: None,
                }),
                display: None,
            });
            // with no proof material, a verifiable method fails for want of a proof, an unsupported one for
            // want of support: the two outcomes tell them apart without needing a valid proof
            let issuance = svc.verify_client_proof(&client, None, false).await;
            let management = svc
                .verify_token_key_proof(Some(&thumbprint), Some(method), None, None)
                .await;
            let issued = match &issuance {
                Ok(_) => true,
                Err(e) => !not_supported(AuthError::validation(e.to_string())),
            };
            let managed = match &management {
                Ok(()) => true,
                Err(e) => !not_supported(AuthError::validation(e.to_string())),
            };
            assert_eq!(
                issued, managed,
                "{method:?}: issuance {issuance:?} but management {management:?}"
            );
            if issued {
                admitted.push(method);
            }
        }
        // the methods this build verifies, pinned: a new one has to be added on purpose
        assert_eq!(admitted, ["dpop", "test", "httpsig", "jwsd", "jws"]);
        // a token with no recorded method is refused at management, never waved through
        let none = svc
            .verify_token_key_proof(Some(&thumbprint), None, None, None)
            .await;
        assert!(none.is_err());
    }

    #[test]
    fn the_unit_test_proof_method_is_not_a_way_around_the_refusals() {
        // `validate_client_key_with_proof` has no proof to check, so it refuses a real method.
        let key = client_key();
        for method in ["dpop", "httpsig", "jws"] {
            let client = Some(GnapClientInfo {
                key: Some(GnapClientKey {
                    proof: method.to_string(),
                    jwk: Some(key.jwk.clone()),
                    cert: None,
                    cert_s256: None,
                }),
                display: None,
            });
            let err = GnapService::validate_client_key_with_proof(&client, Some(b"m"), Some(b"s"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("proof method not supported"),
                "{method}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn a_key_bound_transaction_continues_only_with_a_proof_from_that_key() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let first = dpop_header(&key, &key, "POST", URI, "jti-start");
        let resp = svc
            .handle_transaction_with_proof(
                &dpop,
                &proof(Some(&first), URI),
                request(&key, "dpop", true),
            )
            .await
            .unwrap();
        let cont = resp["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let txn_id = svc.test_first_txn().await.id;
        let iref = svc
            .approve_transaction(&txn_id, Some("user-1"))
            .await
            .unwrap()
            .interact_ref
            .unwrap();

        // The continuation token alone is not enough for a key-bound transaction.
        let msg = refusal(
            svc.continue_transaction(&txn_id, &cont, Some(&iref), None)
                .await,
        );
        assert!(msg.contains("proof required"), "{msg}");
        // Nor is a proof from another key, and neither burns the holder's token.
        let other = client_key();
        let forged = dpop_header(&other, &key, "POST", CONTINUE_URI, "jti-c-forged");
        let msg = refusal(
            svc.continue_transaction_with_proof(
                &dpop,
                &proof(Some(&forged), CONTINUE_URI),
                &txn_id,
                &cont,
                Some(&iref),
                None,
            )
            .await,
        );
        assert!(msg.contains("proof invalid"), "{msg}");
        // The key's own proof, with the same token, completes the transaction.
        let good = dpop_header(&key, &key, "POST", CONTINUE_URI, "jti-c-ok");
        let done = svc
            .continue_transaction_with_proof(
                &dpop,
                &proof(Some(&good), CONTINUE_URI),
                &txn_id,
                &cont,
                Some(&iref),
                None,
            )
            .await
            .unwrap();
        assert!(done["access_token"]["value"].is_string());
    }

    /// The continuation URI the server issues names its transaction, so a POST that carries only
    /// `Authorization: GNAP <continue token>` and a DPoP proof can be routed to it (RFC 9635
    /// section 5: the AS chooses the URI). The token and the id come from the issued response
    /// alone, as a client's HTTP request would supply them.
    #[tokio::test]
    async fn continue_uri_names_the_transaction() {
        let svc = service();
        let dpop = manager();
        let key = client_key();
        let first = dpop_header(&key, &key, "POST", URI, "jti-uri-0");
        let resp = svc
            .handle_transaction_with_proof(
                &dpop,
                &proof(Some(&first), URI),
                request(&key, "dpop", true),
            )
            .await
            .unwrap();
        let uri = resp["continue"]["uri"].as_str().unwrap().to_string();
        let token = resp["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let stored_id = svc.test_first_txn().await.id;
        assert_eq!(
            uri,
            format!("https://as.example.test/api/gnap/tx/continue/{stored_id}")
        );

        // The route's path parameter is the last segment of the issued URI.
        let routed_id = uri.rsplit('/').next().unwrap();
        let abs = format!("https://as.example.test{uri}");
        let h1 = dpop_header(&key, &key, "POST", &abs, "jti-uri-1");
        let polled = svc
            .continue_transaction_with_proof(
                &dpop,
                &proof(Some(&h1), &abs),
                routed_id,
                &token,
                None,
                None,
            )
            .await
            .expect("a continuation at the issued URI finds its transaction");
        // The next URI names the transaction too, and the rotated token works there.
        let next_uri = polled["continue"]["uri"].as_str().unwrap().to_string();
        assert_eq!(next_uri, uri);
        let next_token = polled["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(next_token, token);
        let abs2 = format!("https://as.example.test{next_uri}");
        let h2 = dpop_header(&key, &key, "POST", &abs2, "jti-uri-2");
        svc.continue_transaction_with_proof(
            &dpop,
            &proof(Some(&h2), &abs2),
            next_uri.rsplit('/').next().unwrap(),
            &next_token,
            None,
            None,
        )
        .await
        .expect("the rotated token works at the URI the poll returned");
    }

    // ── KM7: certificate key forms (RFC 9635 section 7.1) proved by mtls ──

    /// A self-signed certificate as DER, its standard-base64 form (`cert`) and its base64url
    /// SHA-256 (`cert#S256`).
    fn certificate() -> (Vec<u8>, String, String) {
        use sha2::Digest;
        let key = crate::keys::LocalKey::generate(
            crate::keys::KeyKind::GnapClient,
            crate::keys::SigningAlg::Es256,
            None,
        )
        .unwrap();
        let pem = crate::keys::self_signed_certificate(
            &key,
            &crate::keys::CertSubject {
                common_name: "gnap-client.example.test".to_string(),
                dns_names: vec![],
                valid_for: std::time::Duration::from_secs(3600),
            },
        )
        .unwrap();
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let der = parsed.contents;
        let std = base64::engine::general_purpose::STANDARD.encode(&der);
        let s256 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&der));
        (der, std, s256)
    }

    fn mtls_proof(der: Option<&[u8]>) -> GnapProof<'_> {
        GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: None,
            expected_nonce: None,
            client_certificate_der: der,
            http_headers: &[],
            http_body: &[],
        }
    }

    fn cert_request(form: &str, std: &str, s256: &str) -> GnapTransactionRequest {
        let builder = GnapTransactionRequest::builder().access_type("read");
        match form {
            "cert" => builder.client_key_cert(std),
            _ => builder.client_key_cert_s256(s256),
        }
        .build()
    }

    // ── G5: polling back-off, modify (PATCH) and cancel (DELETE) ────────────────────────────

    fn waiting_service() -> GnapService {
        // The default `wait` (5 s) is in force, unlike `service()`.
        GnapService::new(GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://as.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        })
        .with_access_policy(Arc::new(AllowAllPolicy))
    }

    /// Open an interactive transaction; returns its id and first continuation token.
    async fn open_pending(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        jti: &str,
    ) -> (String, String) {
        let h = dpop_header(key, key, "POST", URI, jti);
        let resp = svc
            .handle_transaction_with_proof(dpop, &proof(Some(&h), URI), request(key, "dpop", true))
            .await
            .unwrap();
        let token = resp["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        (svc.test_first_txn().await.id, token)
    }

    /// Make the stored transaction look `secs` older (the clock cannot be moved).
    async fn age(svc: &GnapService, id: &str, secs: u64) {
        let mut txn = svc.test_txn(id).await;
        txn.created_at -= secs;
        if txn.last_poll_at > 0 {
            txn.last_poll_at -= secs;
        }
        assert!(svc.transactions.replace_if_unchanged(txn).await.unwrap());
    }

    fn continue_url(id: &str) -> String {
        format!("https://as.example.test/api/gnap/tx/continue/{id}")
    }

    fn proof_for_method<'a>(method: &'static str, header: &'a str, uri: &'a str) -> GnapProof<'a> {
        GnapProof {
            http_method: method,
            http_uri: uri,
            dpop_proof: Some(header),
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: &[],
            http_body: &[],
        }
    }

    async fn poll(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        id: &str,
        token: &str,
        jti: &str,
    ) -> Result<serde_json::Value> {
        let url = continue_url(id);
        let h = dpop_header(key, key, "POST", &url, jti);
        svc.continue_transaction_with_proof(
            dpop,
            &proof_for_method("POST", &h, &url),
            id,
            token,
            None,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn a_poll_before_the_wait_is_too_fast_and_keeps_the_token() {
        let svc = waiting_service();
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "tf-0").await;

        // Immediately after the grant response (which said `wait`): too fast, token untouched.
        let early = refusal(poll(&svc, &dpop, &key, &id, &token, "tf-1").await);
        assert!(early.contains("too_fast"), "{early}");
        assert_eq!(svc.test_txn(&id).await.continue_token, token);

        // After the wait the same token works, and rotates.
        age(&svc, &id, 10).await;
        let ok = poll(&svc, &dpop, &key, &id, &token, "tf-2")
            .await
            .expect("a poll after the wait is answered");
        let next = ok["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(next, token);
        assert_eq!(ok["continue"]["wait"], 5);

        // Polling again at once is too fast again, and the new token survives it.
        let again = refusal(poll(&svc, &dpop, &key, &id, &next, "tf-3").await);
        assert!(again.contains("too_fast"), "{again}");
        age(&svc, &id, 10).await;
        poll(&svc, &dpop, &key, &id, &next, "tf-4")
            .await
            .expect("the token kept through a too_fast refusal still works");
    }

    #[tokio::test]
    async fn a_zero_wait_turns_the_check_off() {
        let svc = waiting_service().with_poll_wait_secs(0);
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "z-0").await;
        poll(&svc, &dpop, &key, &id, &token, "z-1")
            .await
            .expect("no wait is enforced at 0");
    }

    fn write_request() -> GnapTransactionRequest {
        GnapTransactionRequest {
            client: None,
            interact: None,
            access_token_request: Some(
                vec![GnapAccessRequest {
                    access_type: "write-things".to_string(),
                    actions: vec![],
                    locations: vec![],
                }]
                .into(),
            ),
            subject: None,
        }
    }

    async fn patch(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        id: &str,
        token: &str,
        jti: &str,
        body: &GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        let url = continue_url(id);
        let h = dpop_header(key, key, "PATCH", &url, jti);
        svc.modify_transaction_with_proof(
            dpop,
            &proof_for_method("PATCH", &h, &url),
            id,
            token,
            body,
        )
        .await
    }

    #[tokio::test]
    async fn patch_replaces_the_request_and_rotates_the_token() {
        let svc = service();
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "p-0").await;

        let answer = patch(&svc, &dpop, &key, &id, &token, "p-1", &write_request())
            .await
            .expect("a pending grant can be modified");
        let next = answer["continue"]["access_token"]["value"]
            .as_str()
            .unwrap();
        assert_ne!(next, token);
        let stored = format!("{:?}", svc.test_txn(&id).await.request);
        assert!(stored.contains("write-things"), "{stored}");

        // The old token is spent by the modification.
        let old = refusal(poll(&svc, &dpop, &key, &id, &token, "p-2").await);
        assert!(old.contains(INVALID_CONTINUATION), "{old}");
        poll(&svc, &dpop, &key, &id, next, "p-3")
            .await
            .expect("the new token continues the modified grant");
    }

    #[tokio::test]
    async fn patch_refuses_a_client_an_interaction_and_an_approved_grant() {
        let svc = service();
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "pr-0").await;

        let mut with_client = write_request();
        with_client.client = request(&key, "dpop", false).client;
        let e = refusal(patch(&svc, &dpop, &key, &id, &token, "pr-1", &with_client).await);
        assert!(e.contains("client"), "{e}");
        let mut with_interact = write_request();
        with_interact.interact = request(&key, "dpop", true).interact;
        let e = refusal(patch(&svc, &dpop, &key, &id, &token, "pr-2", &with_interact).await);
        assert!(e.contains("interaction"), "{e}");
        assert_eq!(
            svc.test_txn(&id).await.continue_token,
            token,
            "a refused modification keeps the token"
        );

        svc.approve_transaction(&id, Some("alice")).await.unwrap();
        let e = refusal(patch(&svc, &dpop, &key, &id, &token, "pr-3", &write_request()).await);
        assert!(e.contains("not pending"), "{e}");

        // A wrong token is the one uniform refusal.
        let e = refusal(patch(&svc, &dpop, &key, &id, "nope", "pr-4", &write_request()).await);
        assert!(e.contains(INVALID_CONTINUATION), "{e}");
    }

    async fn cancel(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        id: &str,
        token: &str,
        jti: &str,
    ) -> Result<()> {
        let url = continue_url(id);
        let h = dpop_header(key, key, "DELETE", &url, jti);
        svc.delete_transaction_with_proof(dpop, &proof_for_method("DELETE", &h, &url), id, token)
            .await
    }

    #[tokio::test]
    async fn delete_cancels_a_pending_or_approved_grant_once() {
        let svc = service();
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "d-0").await;

        // A wrong token cancels nothing.
        let e = cancel(&svc, &dpop, &key, &id, "nope", "d-1")
            .await
            .expect_err("a wrong token cannot cancel")
            .to_string();
        assert!(e.contains(INVALID_CONTINUATION), "{e}");
        assert_eq!(svc.test_txn_ids().await.len(), 1);

        cancel(&svc, &dpop, &key, &id, &token, "d-2")
            .await
            .expect("the holder cancels its grant request");
        assert!(svc.test_txn_ids().await.is_empty());
        let again = cancel(&svc, &dpop, &key, &id, &token, "d-3").await;
        assert!(
            again.is_err(),
            "a cancelled grant cannot be cancelled again"
        );
        let cont = refusal(poll(&svc, &dpop, &key, &id, &token, "d-4").await);
        assert!(cont.contains(INVALID_CONTINUATION), "{cont}");

        // An approved grant can be cancelled before its token is collected.
        let (id2, token2) = open_pending(&svc, &dpop, &key, "d-5").await;
        svc.approve_transaction(&id2, Some("alice")).await.unwrap();
        cancel(&svc, &dpop, &key, &id2, &token2, "d-6")
            .await
            .expect("an approved grant can still be cancelled");
        assert!(svc.test_txn_ids().await.is_empty());
    }

    /// RFC 9635 section 5.4: "The AS SHOULD revoke all associated access tokens". Cancelling a grant takes
    /// the tokens issued under it with it, and leaves another grant's tokens alone (control).
    #[tokio::test]
    async fn delete_revokes_the_tokens_issued_under_the_grant() {
        let store = Arc::new(InMemoryTokenStore::new());
        let svc = service().with_token_store(store.clone());
        let (dpop, key) = (manager(), client_key());
        let (id, token) = open_pending(&svc, &dpop, &key, "dt-0").await;
        let issued = |value: &str, txn: &str| GnapIssuedToken {
            value: value.to_string(),
            access: vec![],
            expires_at: u64::MAX,
            key_thumbprint: None,
            key_proof: None,
            key_jwk: None,
            transaction_id: txn.to_string(),
        };
        store.insert(issued("mine", &id)).await.unwrap();
        store
            .insert(issued("other", "another-grant"))
            .await
            .unwrap();

        cancel(&svc, &dpop, &key, &id, &token, "dt-1")
            .await
            .unwrap();
        assert!(
            store.get("mine").await.unwrap().is_none(),
            "its token is revoked"
        );
        assert!(
            store.get("other").await.unwrap().is_some(),
            "another grant's token is untouched"
        );
    }

    #[tokio::test]
    async fn a_certificate_key_is_proved_by_the_presented_certificate_in_both_forms() {
        let (der, std, s256) = certificate();
        let (other_der, _, _) = certificate();
        let dpop = manager();
        for form in ["cert", "cert#S256"] {
            let svc = service();
            // Refutations: no certificate, and another certificate, are refused.
            let none = svc
                .handle_transaction_with_proof(
                    &dpop,
                    &mtls_proof(None),
                    cert_request(form, &std, &s256),
                )
                .await;
            assert!(none.is_err(), "{form}: no certificate presented must fail");
            let wrong = svc
                .handle_transaction_with_proof(
                    &dpop,
                    &mtls_proof(Some(&other_der)),
                    cert_request(form, &std, &s256),
                )
                .await;
            assert!(wrong.is_err(), "{form}: another certificate must fail");
            // Positive control, built the same way: the named certificate is accepted.
            let ok = svc
                .handle_transaction_with_proof(
                    &dpop,
                    &mtls_proof(Some(&der)),
                    cert_request(form, &std, &s256),
                )
                .await
                .unwrap_or_else(|e| panic!("{form}: the named certificate must be accepted: {e}"));
            assert!(ok["access_token"]["value"].is_string());
        }
    }

    #[tokio::test]
    async fn both_forms_of_one_certificate_bind_the_same_identifier_and_never_a_jwk_thumbprint() {
        let (der, std, s256) = certificate();
        let dpop = manager();
        let svc = service();
        let mut bindings = Vec::new();
        for form in ["cert", "cert#S256"] {
            let resp = svc
                .handle_transaction_with_proof(
                    &dpop,
                    &mtls_proof(Some(&der)),
                    cert_request(form, &std, &s256),
                )
                .await
                .unwrap();
            let token = resp["access_token"]["value"].as_str().unwrap().to_string();
            let info = svc.introspect_token(&token).await.unwrap().unwrap();
            bindings.push(info["key_thumbprint"].as_str().unwrap().to_string());
        }
        assert_eq!(bindings[0], bindings[1]);
        assert_eq!(bindings[0], format!("x5t#S256:{s256}"));
    }

    #[tokio::test]
    async fn managing_a_certificate_bound_token_needs_the_same_certificate() {
        let (der, std, s256) = certificate();
        let (other_der, _, _) = certificate();
        let dpop = manager();
        let svc = service();
        let resp = svc
            .handle_transaction_with_proof(
                &dpop,
                &mtls_proof(Some(&der)),
                cert_request("cert", &std, &s256),
            )
            .await
            .unwrap();
        let token = resp["access_token"]["value"].as_str().unwrap().to_string();
        // Another certificate cannot rotate or revoke it, and the token survives the attempt.
        assert!(
            svc.rotate_token_with_proof(&dpop, &mtls_proof(Some(&other_der)), &token)
                .await
                .is_err()
        );
        assert!(
            svc.revoke_token_with_proof(&dpop, &mtls_proof(Some(&other_der)), &token)
                .await
                .is_err()
        );
        assert!(svc.introspect_token(&token).await.unwrap().is_some());
        // The named certificate can: rotation issues a replacement, revocation removes it.
        let rotated = svc
            .rotate_token_with_proof(&dpop, &mtls_proof(Some(&der)), &token)
            .await
            .unwrap();
        let new_token = rotated["value"].as_str().unwrap().to_string();
        svc.revoke_token_with_proof(&dpop, &mtls_proof(Some(&der)), &new_token)
            .await
            .unwrap();
        assert!(svc.introspect_token(&new_token).await.unwrap().is_none());
    }

    #[test]
    fn malformed_certificate_keys_are_refused() {
        let (_, std, s256) = certificate();
        let key = |proof: &str, jwk: bool, cert: Option<&str>, s: Option<&str>| {
            Some(GnapClientInfo {
                key: Some(GnapClientKey {
                    proof: proof.to_string(),
                    jwk: jwk.then(|| client_key().jwk),
                    cert: cert.map(str::to_string),
                    cert_s256: s.map(str::to_string),
                }),
                display: None,
            })
        };
        let bad: Vec<(&str, Option<GnapClientInfo>)> = vec![
            ("no key form", key("mtls", false, None, None)),
            ("two forms", key("mtls", false, Some(&std), Some(&s256))),
            ("jwk and cert", key("mtls", true, Some(&std), None)),
            ("cert under dpop", key("dpop", false, Some(&std), None)),
            ("jwk under mtls", key("mtls", true, None, None)),
            ("cert not base64", key("mtls", false, Some("!!!"), None)),
            ("cert not x509", key("mtls", false, Some("AAAA"), None)),
            ("hash not base64url", key("mtls", false, None, Some("!!!"))),
            ("hash wrong length", key("mtls", false, None, Some("AAAA"))),
        ];
        for (why, client) in bad {
            assert!(
                GnapService::validate_client_key(&client).is_err(),
                "{why} must be refused"
            );
        }
        // Positive controls: the two well formed certificate keys pass.
        assert!(GnapService::validate_client_key(&key("mtls", false, Some(&std), None)).is_ok());
        assert!(GnapService::validate_client_key(&key("mtls", false, None, Some(&s256))).is_ok());
    }

    #[test]
    fn a_non_canonical_hash_spelling_binds_the_same_identifier() {
        let (_, _, s256) = certificate();
        let mut padded = s256.clone();
        padded.push('=');
        let key = |s: &str| {
            Some(GnapClientInfo {
                key: Some(GnapClientKey {
                    proof: "mtls".to_string(),
                    jwk: None,
                    cert: None,
                    cert_s256: Some(s.to_string()),
                }),
                display: None,
            })
        };
        let canonical = GnapService::validate_client_key(&key(&s256));
        let other = GnapService::validate_client_key(&key(&padded));
        assert_eq!(
            canonical.as_ref().unwrap(),
            &Some(format!("x5t#S256:{s256}"))
        );
        // Padding is either refused or normalised to the same identifier, never a second one.
        assert!(other.is_err() || other.unwrap() == canonical.unwrap());
    }

    // ---- interaction wiring (G4 slice 1) ----

    fn interact_request(key: &ClientKey, interact: serde_json::Value) -> GnapTransactionRequest {
        serde_json::from_value(json!({
            "client": {"key": {"proof": "dpop", "jwk": serde_json::to_value(&key.jwk).unwrap()}},
            "access_token": {"access": ["read"]},
            "interact": interact,
        }))
        .expect("the request deserializes")
    }

    #[tokio::test]
    async fn a_push_to_a_target_the_server_must_not_call_is_refused_at_transaction_open() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        for (n, uri) in [
            "https://127.0.0.1/cb",
            "https://localhost/cb",
            "https://10.0.0.5/cb",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/cb",
            "http://client.test/cb",
            "https://user:pw@client.test/cb",
        ]
        .into_iter()
        .enumerate()
        {
            let interact = json!({
                "start": ["redirect"],
                "finish": {"method": "push", "uri": uri, "nonce": "client-nonce"},
            });
            let r = send(
                &svc,
                &dpop,
                &key,
                &format!("push-{n}"),
                interact_request(&key, interact),
            )
            .await;
            assert!(r.is_err(), "a push to {uri} must be refused");
        }
        assert!(
            svc.test_txn_ids().await.is_empty(),
            "a refused request opens no transaction"
        );
        // the same request with a public https target is accepted (the control for the loop above)
        let ok = json!({
            "start": ["redirect"],
            "finish": {"method": "push", "uri": "https://client.test/cb", "nonce": "client-nonce"},
        });
        send(&svc, &dpop, &key, "push-ok", interact_request(&key, ok))
            .await
            .expect("a public https push target is accepted");
        assert_eq!(svc.test_txn_ids().await.len(), 1);
    }

    #[tokio::test]
    async fn an_invalid_finish_is_refused_at_transaction_open() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        for (n, finish) in [
            json!({"method": "carrier-pigeon", "uri": "https://client.test/cb", "nonce": "n"}),
            json!({"method": "redirect", "uri": "not a uri", "nonce": "n"}),
        ]
        .into_iter()
        .enumerate()
        {
            let interact = json!({"start": ["redirect"], "finish": finish});
            let r = send(
                &svc,
                &dpop,
                &key,
                &format!("fin-{n}"),
                interact_request(&key, interact),
            )
            .await;
            assert!(r.is_err(), "finish {finish} must be refused");
        }
        assert!(svc.test_txn_ids().await.is_empty());
    }

    // ---- push delivery (G4 slice 2) ----

    use crate::protocols::gnap_push::tests::{FakeResolver, FakeSender};

    async fn approved_push_txn(
        svc: &GnapService,
        dpop: &DpopManager,
        key: &ClientKey,
        method: &str,
    ) -> (String, GnapInteractionCompletion) {
        let interact = json!({
            "start": ["redirect"],
            "finish": {"method": method, "uri": "https://client.test/cb", "nonce": "client-nonce"},
        });
        send(svc, dpop, key, "push-txn", interact_request(key, interact))
            .await
            .expect("opened");
        let id = svc.test_first_txn().await.id;
        let done = svc.approve_transaction(&id, Some("sub-1")).await.unwrap();
        (id, done)
    }

    #[tokio::test]
    async fn an_approved_push_transaction_delivers_its_reference_and_hash() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (id, done) = approved_push_txn(&svc, &dpop, &key, "push").await;
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender::default(),
        );
        svc.push_interaction(&id, &r, &s).await.unwrap();
        let calls = s.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://client.test/cb");
        assert_eq!(
            calls[0].2["interact_ref"],
            done.interact_ref.clone().unwrap()
        );
        assert_eq!(calls[0].2["hash"], done.hash.clone().unwrap());
    }

    #[tokio::test]
    async fn a_push_whose_name_now_resolves_to_a_private_address_is_refused_at_delivery() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (id, _) = approved_push_txn(&svc, &dpop, &key, "push").await;
        // the name passed the open-time check; at delivery it resolves to an internal address
        for answers in [vec!["10.0.0.5"], vec!["93.184.216.34", "169.254.169.254"]] {
            let (r, s) = (FakeResolver::answering(&answers), FakeSender::default());
            let e = svc
                .push_interaction(&id, &r, &s)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("AddressNotAllowed"), "{e}");
            assert!(
                s.calls.lock().unwrap().is_empty(),
                "nothing was sent to {answers:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_an_approved_transaction_with_a_push_finish_is_pushed() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender::default(),
        );
        // a redirect-finish transaction
        let (id, _) = approved_push_txn(&svc, &dpop, &key, "redirect").await;
        assert!(svc.push_interaction(&id, &r, &s).await.is_err());
        // a push-finish transaction that was never approved
        let svc2 = service();
        let interact = json!({
            "start": ["redirect"],
            "finish": {"method": "push", "uri": "https://client.test/cb", "nonce": "n"},
        });
        send(
            &svc2,
            &dpop,
            &key,
            "pending",
            interact_request(&key, interact),
        )
        .await
        .unwrap();
        let id2 = svc2.test_first_txn().await.id;
        assert!(svc2.push_interaction(&id2, &r, &s).await.is_err());
        assert!(svc2.push_interaction("no-such-id", &r, &s).await.is_err());
        assert!(s.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_transaction_denied_after_approval_is_not_pushed() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (id, _) = approved_push_txn(&svc, &dpop, &key, "push").await;
        svc.deny_transaction(&id).await.unwrap();
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender::default(),
        );
        let e = svc
            .push_interaction(&id, &r, &s)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("not approved"), "{e}");
        assert!(s.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_expired_approved_transaction_is_not_pushed() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (id, _) = approved_push_txn(&svc, &dpop, &key, "push").await;
        let (r, s) = (
            FakeResolver::answering(&["93.184.216.34"]),
            FakeSender::default(),
        );
        let created = svc.test_first_txn().await.created_at;
        let life = svc.config.transaction_lifetime_secs;
        let e = svc
            .push_interaction_at(&id, &r, &s, created + life + 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
        assert!(s.calls.lock().unwrap().is_empty());
        svc.push_interaction_at(&id, &r, &s, created + life)
            .await
            .unwrap();
        assert_eq!(s.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_approved_redirect_transaction_yields_the_callback_uri() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let (id, done) = approved_push_txn(&svc, &dpop, &key, "redirect").await;
        let url = svc.redirect_callback(&id).await.unwrap();
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://client.test/cb")
        );
        assert_eq!(q["interact_ref"], done.interact_ref.clone().unwrap());
        assert_eq!(q["hash"], done.hash.clone().unwrap());
    }

    #[tokio::test]
    async fn only_an_approved_unexpired_redirect_transaction_gets_a_callback_uri() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        // a push-finish transaction has no redirect callback
        let (pid, _) = approved_push_txn(&svc, &dpop, &key, "push").await;
        assert!(svc.redirect_callback(&pid).await.is_err());
        assert!(svc.redirect_callback("no-such-id").await.is_err());
        // a redirect transaction that is denied, or expired
        let svc2 = service();
        let (id, _) = approved_push_txn(&svc2, &manager(), &key, "redirect").await;
        let created = svc2.test_first_txn().await.created_at;
        let life = svc2.config.transaction_lifetime_secs;
        let e = svc2
            .redirect_callback_at(&id, created + life + 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
        svc2.redirect_callback_at(&id, created + life)
            .await
            .unwrap();
        svc2.deny_transaction(&id).await.unwrap();
        let e = svc2.redirect_callback(&id).await.unwrap_err().to_string();
        assert!(e.contains("not approved"), "{e}");
    }

    #[tokio::test]
    async fn the_hash_uses_the_method_the_client_asked_for() {
        use crate::protocols::gnap_interaction::interaction_hash;
        for (name, method) in [
            ("sha-256", HashMethod::Sha256),
            ("sha-384", HashMethod::Sha384),
            ("sha-512", HashMethod::Sha512),
        ] {
            let (svc, dpop, key) = (service(), manager(), client_key());
            let interact = json!({
                "start": ["redirect"],
                "finish": {"method": "redirect", "uri": "https://client.test/cb", "nonce": "cn", "hash_method": name},
            });
            send(&svc, &dpop, &key, "hm", interact_request(&key, interact))
                .await
                .unwrap();
            let txn = svc.test_first_txn().await;
            let done = svc.approve_transaction(&txn.id, None).await.unwrap();
            let iref = done.interact_ref.unwrap();
            let expected = interaction_hash(
                "cn",
                txn.interact_nonce.as_deref().unwrap(),
                &iref,
                &svc.config.transaction_endpoint,
                method,
            )
            .unwrap();
            assert_eq!(done.hash.unwrap(), expected, "{name}");
            // the length tells the algorithm apart: 32, 48, 64 bytes in base64url without padding
            assert_eq!(
                expected.len(),
                match method {
                    HashMethod::Sha256 => 43,
                    HashMethod::Sha384 => 64,
                    HashMethod::Sha512 => 86,
                }
            );
        }
    }

    #[tokio::test]
    async fn a_hash_method_the_server_does_not_honour_is_refused_not_ignored() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        for (n, name) in ["sha3-512", "md5", "SHA-256"].into_iter().enumerate() {
            let interact = json!({
                "start": ["redirect"],
                "finish": {"method": "redirect", "uri": "https://client.test/cb", "nonce": "n", "hash_method": name},
            });
            let r = send(
                &svc,
                &dpop,
                &key,
                &format!("hm-{n}"),
                interact_request(&key, interact),
            )
            .await;
            let msg = r
                .expect_err(&format!("hash_method {name} must be refused"))
                .to_string();
            assert!(
                msg.contains("hash_method") && msg.contains(name),
                "the refusal names the input: {msg}"
            );
        }
        assert!(svc.test_txn_ids().await.is_empty(), "nothing was stored");
        // the values the server does honour: sha-256/384/512 named, and absent (the default)
        for (n, finish) in [
            json!({"method": "redirect", "uri": "https://client.test/cb", "nonce": "n", "hash_method": "sha-384"}),
            json!({"method": "redirect", "uri": "https://client.test/cb", "nonce": "n", "hash_method": "sha-512"}),
            json!({"method": "redirect", "uri": "https://client.test/cb", "nonce": "n", "hash_method": "sha-256"}),
            json!({"method": "redirect", "uri": "https://client.test/cb", "nonce": "n"}),
        ]
        .into_iter()
        .enumerate()
        {
            let interact = json!({"start": ["redirect"], "finish": finish});
            send(&svc, &dpop, &key, &format!("hm-ok-{n}"), interact_request(&key, interact))
                .await
                .expect("sha-256 is honoured");
        }
    }

    #[tokio::test]
    async fn a_user_code_start_is_answered_with_a_code_the_server_keeps() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let interact = json!({"start": ["user_code"], "finish": {"method": "redirect", "uri": "https://client.test/cb", "nonce": "n"}});
        let resp = send(&svc, &dpop, &key, "uc-1", interact_request(&key, interact))
            .await
            .unwrap();
        let code = resp["interact"]["user_code"]
            .as_str()
            .expect("a user_code is offered");
        assert!(
            (6..=8).contains(&code.len())
                && super::super::gnap_interaction::normalize_user_code(code).as_deref() == Ok(code),
            "a typeable code of the recommended length: {code}"
        );
        assert!(
            resp["interact"].get("redirect").is_none(),
            "redirect was not asked for"
        );
        let txn = svc.test_first_txn().await;
        assert!(
            txn.user_code
                .as_deref()
                .is_some_and(|k| super::super::gnap_interaction::user_codes_equal(code, k)),
            "the transaction keeps the code so a person can type it in later"
        );
        // two transactions never share a code, and a redirect-only start offers none
        let again = json!({"start": ["user_code"]});
        let r2 = send(&svc, &dpop, &key, "uc-2", interact_request(&key, again))
            .await
            .unwrap();
        assert_ne!(r2["interact"]["user_code"], resp["interact"]["user_code"]);
        let only = json!({"start": ["redirect"]});
        let r3 = send(&svc, &dpop, &key, "uc-3", interact_request(&key, only))
            .await
            .unwrap();
        assert!(r3["interact"].get("user_code").is_none());
        assert!(r3["interact"].get("redirect").is_some());
    }

    #[tokio::test]
    async fn a_user_code_uri_start_is_answered_with_the_code_and_the_page_when_configured() {
        let (dpop, key) = (manager(), client_key());
        let svc = service()
            .with_user_code_uri("https://as.test/device")
            .unwrap();
        let ask = |start: serde_json::Value| json!({"start": start});
        let resp = send(
            &svc,
            &dpop,
            &key,
            "ucu-1",
            interact_request(&key, ask(json!(["user_code_uri"]))),
        )
        .await
        .unwrap();
        let obj = &resp["interact"]["user_code_uri"];
        let code = obj["code"].as_str().expect("a code is offered");
        assert_eq!(obj["uri"], "https://as.test/device");
        assert!(
            resp["interact"].get("user_code").is_none(),
            "user_code was not asked for"
        );
        // the code is the transaction's one code, so a typed code finds it
        let id = svc.test_first_txn().await.id;
        assert_eq!(svc.transaction_for_user_code(code, "c").await.unwrap(), id);
        // both modes asked: both answered with the SAME code
        let both = send(
            &svc,
            &dpop,
            &key,
            "ucu-2",
            interact_request(&key, ask(json!(["user_code", "user_code_uri"]))),
        )
        .await
        .unwrap();
        assert_eq!(
            both["interact"]["user_code"],
            both["interact"]["user_code_uri"]["code"]
        );
        // not asked for: not offered, and no code is kept
        let none = send(
            &svc,
            &dpop,
            &key,
            "ucu-3",
            interact_request(&key, ask(json!(["redirect"]))),
        )
        .await
        .unwrap();
        assert!(none["interact"].get("user_code_uri").is_none());
    }

    #[tokio::test]
    async fn an_app_start_is_answered_with_a_per_transaction_uri_when_configured() {
        let (dpop, key) = (manager(), client_key());
        let svc = service().with_app_uri("com.example.as:/launch").unwrap();
        let resp = send(
            &svc,
            &dpop,
            &key,
            "app-1",
            interact_request(&key, json!({"start": ["app"]})),
        )
        .await
        .unwrap();
        let id = svc.test_first_txn().await.id;
        assert_eq!(
            resp["interact"]["app"],
            format!("com.example.as:/launch?txn={id}")
        );
        assert!(resp["interact"].get("redirect").is_none(), "not asked for");
        // not configured: not offered
        let plain = service();
        let none = send(
            &plain,
            &dpop,
            &key,
            "app-2",
            interact_request(&key, json!({"start": ["redirect", "app"]})),
        )
        .await
        .unwrap();
        assert!(none["interact"].get("app").is_none());
        assert!(none["interact"].get("redirect").is_some());
    }

    #[tokio::test]
    async fn ui_locales_hints_are_checked_at_open_and_readable_for_the_consent_page() {
        let (dpop, key) = (manager(), client_key());
        let svc = service();
        for (n, bad) in [
            json!({"start": ["redirect"], "hints": {"ui_locales": "en"}}),
            json!({"start": ["redirect"], "hints": {"ui_locales": ["en_US"]}}),
            json!({"start": ["redirect"], "hints": ["en"]}),
        ]
        .into_iter()
        .enumerate()
        {
            let r = send(
                &svc,
                &dpop,
                &key,
                &format!("hint-bad-{n}"),
                interact_request(&key, bad.clone()),
            )
            .await;
            assert!(r.is_err(), "{bad}");
        }
        // Positive control, built the same way: a well-formed hint opens and reads back in order.
        send(
            &svc,
            &dpop,
            &key,
            "hint-ok",
            interact_request(
                &key,
                json!({"start": ["redirect"], "hints": {"ui_locales": ["fr-CA", "en"]}}),
            ),
        )
        .await
        .unwrap();
        let id = svc.test_first_txn().await.id;
        assert_eq!(svc.interaction_locales(&id).await.unwrap(), ["fr-CA", "en"]);
        assert!(svc.interaction_locales("no-such").await.is_err());
        // no hints: empty, not an error
        let plain = service();
        send(
            &plain,
            &dpop,
            &key,
            "hint-none",
            interact_request(&key, json!({"start": ["redirect"]})),
        )
        .await
        .unwrap();
        let pid = plain.test_first_txn().await.id;
        assert!(plain.interaction_locales(&pid).await.unwrap().is_empty());
    }

    #[test]
    fn the_app_uri_must_be_absolute_without_credentials_query_or_fragment() {
        for bad in [
            "not a uri",
            "https://u:p@as.test/app",
            "https://as.test/app?x=1",
            "https://as.test/app#f",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            assert!(service().with_app_uri(bad).is_err(), "{bad}");
        }
        assert!(service().with_app_uri("https://as.test/app").is_ok());
        assert!(service().with_app_uri("com.example.as:/launch").is_ok());
    }

    #[tokio::test]
    async fn a_user_code_uri_start_without_a_configured_page_is_not_offered() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let resp = send(
            &svc,
            &dpop,
            &key,
            "ucu-4",
            interact_request(&key, json!({"start": ["redirect", "user_code_uri"]})),
        )
        .await
        .unwrap();
        assert!(resp["interact"].get("user_code_uri").is_none());
        assert!(resp["interact"].get("redirect").is_some());
        assert!(svc.test_first_txn().await.user_code.is_none());
    }

    #[test]
    fn the_user_code_uri_page_must_be_absolute_http_without_query_or_fragment() {
        for bad in [
            "/device",
            "not a uri",
            "ftp://as.test/d",
            "mailto:a@b.test",
            "https://as.test/d?code=1",
            "https://as.test/d#x",
        ] {
            assert!(
                GnapService::new(GnapConfig::default())
                    .with_user_code_uri(bad)
                    .is_err(),
                "{bad} must be refused"
            );
        }
        assert!(
            GnapService::new(GnapConfig::default())
                .with_user_code_uri("http://as.test/device")
                .is_ok()
        );
    }

    /// A service holding one pending user-code transaction: (service, its code, its id).
    async fn with_code() -> (GnapService, String, String) {
        let (svc, dpop, key) = (service(), manager(), client_key());
        let interact = json!({"start": ["user_code"], "finish": {"method": "redirect", "uri": "https://client.test/cb", "nonce": "n"}});
        let resp = send(
            &svc,
            &dpop,
            &key,
            "uc-find",
            interact_request(&key, interact),
        )
        .await
        .unwrap();
        let code = resp["interact"]["user_code"].as_str().unwrap().to_string();
        let id = svc.test_first_txn().await.id;
        (svc, code, id)
    }

    fn wrong(code: &str) -> String {
        // a well-formed code that is not this one
        let first = if code.starts_with('A') { 'B' } else { 'A' };
        format!("{first}{}", &code[1..])
    }

    #[tokio::test]
    async fn a_typed_code_finds_its_transaction_however_it_is_written() {
        let (svc, code, id) = with_code().await;
        let lower = code.to_lowercase();
        let hyphen = format!("{}-{}", &code[..4], &code[4..]);
        for typed in [code.clone(), lower, hyphen] {
            let got = svc.transaction_for_user_code_at(&typed, "c", 1_000).await;
            assert_eq!(got.unwrap(), id, "typed as {typed}");
        }
    }

    #[tokio::test]
    async fn a_wrong_malformed_expired_or_decided_code_gets_one_refusal() {
        let (svc, code, id) = with_code().await;
        let now = svc.test_first_txn().await.created_at;
        let refused = |r: Result<String>| r.expect_err("refused").to_string();
        let baseline = refused(
            svc.transaction_for_user_code_at(&wrong(&code), "a", now)
                .await,
        );
        assert!(baseline.contains(USER_CODE_REFUSED), "{baseline}");
        assert_eq!(
            baseline,
            refused(svc.transaction_for_user_code_at("!!", "b", now).await),
            "malformed"
        );
        // past the transaction lifetime the right code is refused, with the same words
        let late = now + svc.config.transaction_lifetime_secs + 1;
        assert_eq!(
            baseline,
            refused(svc.transaction_for_user_code_at(&code, "c", late).await),
            "expired"
        );
        // at the last second it still works
        let edge = now + svc.config.transaction_lifetime_secs;
        assert_eq!(
            svc.transaction_for_user_code_at(&code, "d", edge)
                .await
                .unwrap(),
            id
        );
        svc.approve_transaction(&id, Some("alice")).await.unwrap();
        assert_eq!(
            baseline,
            refused(svc.transaction_for_user_code_at(&code, "e", now).await),
            "approved"
        );
    }

    #[tokio::test]
    async fn a_denied_transactions_code_is_refused() {
        let (svc, code, id) = with_code().await;
        svc.deny_transaction(&id).await.unwrap();
        assert!(
            svc.transaction_for_user_code_at(&code, "a", 1_000)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn five_wrong_codes_lock_the_caller_out_even_for_the_right_one() {
        let (svc, code, id) = with_code().await;
        let t = svc.test_first_txn().await.created_at;
        for _ in 0..USER_CODE_MAX_FAILURES {
            assert!(
                svc.transaction_for_user_code_at(&wrong(&code), "mallory", t)
                    .await
                    .is_err()
            );
        }
        let locked = svc
            .transaction_for_user_code_at(&code, "mallory", t + 1)
            .await
            .expect_err("locked")
            .to_string();
        assert!(locked.contains(USER_CODE_LOCKED), "{locked}");
        // someone else is not affected
        assert_eq!(
            svc.transaction_for_user_code_at(&code, "alice", t + 1)
                .await
                .unwrap(),
            id
        );
        // the lockout ends when the window has passed
        let after = t + USER_CODE_LOCKOUT_SECS;
        assert_eq!(
            svc.transaction_for_user_code_at(&code, "mallory", after)
                .await
                .unwrap(),
            id
        );
    }

    #[tokio::test]
    async fn a_right_code_clears_the_count_and_four_wrong_ones_do_not_lock() {
        let (svc, code, id) = with_code().await;
        let t = svc.test_first_txn().await.created_at;
        for round in 0..3 {
            for _ in 0..USER_CODE_MAX_FAILURES - 1 {
                let _ = svc
                    .transaction_for_user_code_at(&wrong(&code), "bob", t)
                    .await;
            }
            assert_eq!(
                svc.transaction_for_user_code_at(&code, "bob", t)
                    .await
                    .unwrap(),
                id,
                "round {round}"
            );
        }
    }

    #[tokio::test]
    async fn counts_of_callers_whose_window_has_passed_are_dropped() {
        let (svc, code, _) = with_code().await;
        let t = svc.test_first_txn().await.created_at;
        let _ = svc
            .transaction_for_user_code_at(&wrong(&code), "old", t)
            .await;
        let _ = svc
            .transaction_for_user_code_at(&wrong(&code), "new", t + USER_CODE_LOCKOUT_SECS)
            .await;
        let kept: Vec<String> = svc.code_failures_lock().keys().cloned().collect();
        assert_eq!(kept, vec!["new".to_string()]);
    }
}

/// Access is granted by an integrator's policy, a client key is required, a finished interaction
/// is proved by its one-time reference, and an issued token is usable at once.
#[cfg(test)]
mod hardening_tests {
    use super::*;
    use std::sync::Mutex;

    fn config() -> GnapConfig {
        GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://as.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        }
    }

    fn jwk() -> GnapJwk {
        GnapJwk {
            kty: "EC".to_string(),
            kid: None,
            crv: Some("P-256".to_string()),
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
            n: None,
            e: None,
        }
    }

    fn keyed() -> Option<GnapClientInfo> {
        Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "test".to_string(),
                jwk: Some(jwk()),
                cert: None,
                cert_s256: None,
            }),
            display: None,
        })
    }

    fn rights(kinds: &[&str]) -> Vec<GnapAccessRequest> {
        kinds
            .iter()
            .map(|k| GnapAccessRequest {
                access_type: (*k).to_string(),
                actions: vec![],
                locations: vec![],
            })
            .collect()
    }

    fn request(
        client: Option<GnapClientInfo>,
        kinds: &[&str],
        finish: bool,
    ) -> GnapTransactionRequest {
        GnapTransactionRequest {
            client,
            interact: finish.then(|| GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/cb".to_string(),
                    nonce: "client-nonce".to_string(),
                    hash_method: None,
                }),
                hints: None,
            }),
            access_token_request: Some(rights(kinds).into()),
            subject: None,
        }
    }

    struct Records(Mutex<Vec<String>>);

    #[async_trait]
    impl GnapAccessPolicy for Records {
        async fn grant(
            &self,
            thumbprint: &str,
            requested: &[GnapAccessRequest],
        ) -> Vec<GnapAccessRequest> {
            self.0.lock().unwrap().push(thumbprint.to_string());
            requested.to_vec()
        }
    }

    /// Grants only `read`, whatever was asked for.
    struct ReadOnly;

    #[async_trait]
    impl GnapAccessPolicy for ReadOnly {
        async fn grant(&self, _: &str, requested: &[GnapAccessRequest]) -> Vec<GnapAccessRequest> {
            requested
                .iter()
                .filter(|r| r.access_type == "read")
                .cloned()
                .collect()
        }
    }

    fn with(policy: impl GnapAccessPolicy + 'static) -> GnapService {
        GnapService::new(config()).with_access_policy(Arc::new(policy))
    }

    fn message<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => "accepted".to_string(),
            Err(e) => e.to_string(),
        }
    }

    // ── Policy ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_service_without_a_policy_issues_no_access_token() {
        let none = GnapService::new(config());
        let msg = message(
            none.handle_transaction(request(keyed(), &["read"], false))
                .await,
        );
        assert!(msg.contains("no access policy"), "{msg}");
        assert!((none.issued_tokens.count().await.unwrap() == 0));

        // Control: the same request is served once a policy grants it.
        let served = with(AllowAllPolicy)
            .handle_transaction(request(keyed(), &["read"], false))
            .await
            .unwrap();
        assert!(served["access_token"]["value"].is_string());
    }

    #[tokio::test]
    async fn the_token_carries_what_the_policy_grants_not_what_was_requested() {
        let svc = with(ReadOnly);
        let resp = svc
            .handle_transaction(request(keyed(), &["admin", "read"], false))
            .await
            .unwrap();
        let granted = resp["access_token"]["access"].as_array().unwrap();
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0]["type"], "read");
        let value = resp["access_token"]["value"].as_str().unwrap();
        let introspected = svc.introspect_token(value).await.unwrap().unwrap();
        assert_eq!(introspected["access"].as_array().unwrap().len(), 1);

        // A request for nothing the policy grants is denied, and nothing is stored.
        let before = svc.issued_tokens.count().await.unwrap();
        let msg = message(
            svc.handle_transaction(request(keyed(), &["admin"], false))
                .await,
        );
        assert!(msg.contains("denied by policy"), "{msg}");
        assert_eq!(svc.issued_tokens.count().await.unwrap(), before);
    }

    #[tokio::test]
    async fn the_policy_is_told_which_key_is_asking() {
        let records = Arc::new(Records(Mutex::new(Vec::new())));
        let svc = GnapService::new(config()).with_access_policy(records.clone());
        svc.handle_transaction(request(keyed(), &["read"], false))
            .await
            .unwrap();
        let expected = GnapService::jwk_thumbprint(&jwk()).unwrap();
        assert_eq!(*records.0.lock().unwrap(), vec![expected]);
    }

    #[tokio::test]
    async fn a_policy_that_denies_after_approval_ends_the_transaction() {
        let svc = with(ReadOnly);
        svc.handle_transaction(request(keyed(), &["admin"], true))
            .await
            .unwrap();
        let (id, cont) = {
            let t = svc.test_first_txn().await;
            (t.id, t.continue_token)
        };
        let iref = svc
            .approve_transaction(&id, None)
            .await
            .unwrap()
            .interact_ref
            .unwrap();
        let msg = message(
            svc.continue_transaction(&id, &cont, Some(&iref), None)
                .await,
        );
        assert!(msg.contains("denied by policy"), "{msg}");
        assert_eq!(svc.transactions.count().await.unwrap(), 0);
    }

    // ── Client key ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_request_without_a_client_key_is_refused() {
        let svc = with(AllowAllPolicy);
        for client in [
            None,
            Some(GnapClientInfo {
                key: None,
                display: None,
            }),
        ] {
            let msg = message(
                svc.handle_transaction(request(client, &["read"], false))
                    .await,
            );
            assert!(msg.contains("client key required"), "{msg}");
        }
        // A subject-only request needs a key as well.
        let subject_only = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token_request: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        };
        let msg = message(svc.handle_transaction(subject_only).await);
        assert!(msg.contains("client key required"), "{msg}");
        assert!((svc.issued_tokens.count().await.unwrap() == 0));

        // Control: with a key the same request is served.
        assert!(
            svc.handle_transaction(request(keyed(), &["read"], false))
                .await
                .is_ok()
        );
    }

    // ── Interaction reference ────────────────────────────────────────────

    async fn pending(svc: &GnapService, finish: bool) -> (String, String) {
        let before = svc.test_txn_ids().await;
        let mut req = request(keyed(), &["read"], finish);
        if !finish {
            // Polling: interaction starts at the AS but the client names no finish method.
            req.interact = Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
                hints: None,
            });
        }
        svc.handle_transaction(req).await.unwrap();
        let id = svc
            .test_txn_ids()
            .await
            .into_iter()
            .find(|k| !before.contains(k))
            .unwrap();
        let t = svc.test_txn(&id).await;
        (id, t.continue_token)
    }

    #[tokio::test]
    async fn an_approved_finish_transaction_continues_only_with_its_own_reference() {
        let svc = with(AllowAllPolicy);
        let (id, cont) = pending(&svc, true).await;
        let (other_id, _) = pending(&svc, true).await;
        let iref = svc
            .approve_transaction(&id, None)
            .await
            .unwrap()
            .interact_ref
            .unwrap();
        let other_ref = svc
            .approve_transaction(&other_id, None)
            .await
            .unwrap()
            .interact_ref
            .unwrap();
        assert_ne!(iref, other_ref);

        // No reference, a made-up one, and another transaction's one are all refused ...
        for given in [None, Some("garbage"), Some(other_ref.as_str())] {
            let msg = message(svc.continue_transaction(&id, &cont, given, None).await);
            assert!(msg.contains(INVALID_CONTINUATION), "{given:?}: {msg}");
        }
        // ... and none of them used up the continuation token or the reference.
        let done = svc
            .continue_transaction(&id, &cont, Some(&iref), None)
            .await
            .unwrap();
        assert!(done["access_token"]["value"].is_string());

        // The reference works once: the finished transaction is gone.
        let msg = message(
            svc.continue_transaction(&id, &cont, Some(&iref), None)
                .await,
        );
        assert!(msg.contains(INVALID_CONTINUATION), "{msg}");
    }

    #[tokio::test]
    async fn a_polling_transaction_needs_no_reference_and_refuses_one_nobody_issued() {
        let svc = with(AllowAllPolicy);
        let (id, cont) = pending(&svc, false).await;
        svc.approve_transaction(&id, None).await.unwrap();
        let msg = message(
            svc.continue_transaction(&id, &cont, Some("garbage"), None)
                .await,
        );
        assert!(msg.contains(INVALID_CONTINUATION), "{msg}");
        // Control: polling without a reference gets the token.
        let done = svc
            .continue_transaction(&id, &cont, None, None)
            .await
            .unwrap();
        assert!(done["access_token"]["value"].is_string());
    }

    #[tokio::test]
    async fn approval_returns_the_reference_and_hash_only_for_a_finish_transaction() {
        let svc = with(AllowAllPolicy);
        let (finishing, _) = pending(&svc, true).await;
        let (polling, _) = pending(&svc, false).await;
        let with_finish = svc.approve_transaction(&finishing, None).await.unwrap();
        assert!(with_finish.interact_ref.is_some() && with_finish.hash.is_some());
        let without = svc.approve_transaction(&polling, None).await.unwrap();
        assert_eq!(
            without,
            GnapInteractionCompletion {
                interact_ref: None,
                hash: None
            }
        );
        // Approving twice does not mint a second reference.
        let again = svc.approve_transaction(&finishing, None).await.unwrap();
        assert_eq!(again, with_finish);
    }

    // ── Token is stored before it is returned ────────────────────────────

    async fn use_at_once(svc: &GnapService, n: usize) -> usize {
        let mut unknown = 0;
        for _ in 0..n {
            let resp = svc
                .handle_transaction(request(keyed(), &["read"], false))
                .await
                .unwrap();
            let value = resp["access_token"]["value"].as_str().unwrap();
            if svc.introspect_token(value).await.unwrap().is_none() {
                unknown += 1;
            }
        }
        unknown
    }

    #[tokio::test]
    async fn a_token_is_known_the_moment_it_is_returned_on_one_thread() {
        assert_eq!(use_at_once(&with(AllowAllPolicy), 100).await, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_token_is_known_the_moment_it_is_returned_on_many_threads() {
        assert_eq!(use_at_once(&with(AllowAllPolicy), 300).await, 0);
    }

    /// The Rust field was renamed (SEC-012, #463); the RFC 9635 wire name must not move.
    #[test]
    fn request_keeps_the_access_token_wire_name() {
        let req: GnapTransactionRequest =
            serde_json::from_value(serde_json::json!({"access_token": {"access": ["read"]}}))
                .unwrap();
        assert!(req.access_token_request.is_some());
        let out = serde_json::to_value(&req).unwrap();
        assert!(out.get("access_token").is_some());
        assert!(out.get("access_token_request").is_none());
    }
}

/// The `httpsig` proof method (RFC 9635 section 7.3.1): the request must carry an RFC 9421 signature
/// by the key it names, and a captured request cannot be replayed.
#[cfg(test)]
mod httpsig_proof_tests {
    use super::*;
    use crate::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    const URI: &str = "https://as.example.test/api/gnap/tx";
    const BODY: &[u8] = b"{}";

    struct Signer {
        pair: EcdsaKeyPair,
        jwk: GnapJwk,
    }

    fn signer() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let point = pair.public_key().as_ref().to_vec();
        let jwk = GnapJwk {
            kty: "EC".to_string(),
            kid: None,
            crv: Some("P-256".to_string()),
            x: Some(b64.encode(&point[1..33])),
            y: Some(b64.encode(&point[33..65])),
            n: None,
            e: None,
        };
        Signer { pair, jwk }
    }

    /// The headers of a POST to `URI` with `BODY`, signed by `signer` with `nonce`.
    fn signed_headers(signer: &Signer, nonce: &str, token: Option<&str>) -> Vec<(String, String)> {
        let digest = super::super::gnap_httpsig::content_digest_header("sha-256", BODY).unwrap();
        let created = chrono::Utc::now().timestamp();
        let auth = token.map(|t| format!("GNAP {t}"));
        let (covered, auth_line) = match &auth {
            Some(a) => (
                "\"@method\" \"@target-uri\" \"content-digest\" \"authorization\"",
                format!(
                    "\"authorization\": {a}
"
                ),
            ),
            None => (
                "\"@method\" \"@target-uri\" \"content-digest\"",
                String::new(),
            ),
        };
        let params = format!("({covered});created={created};nonce=\"{nonce}\";tag=\"gnap\"");
        let base = format!(
            "\"@method\": POST
\"@target-uri\": {URI}
\"content-digest\": {digest}
{auth_line}\"@signature-params\": {params}"
        );
        let sig = signer
            .pair
            .sign(&SystemRandom::new(), base.as_bytes())
            .unwrap();
        let mut headers = vec![("Content-Digest".to_string(), digest)];
        if let Some(a) = auth {
            headers.push(("Authorization".to_string(), a));
        }
        headers.extend([
            ("Signature-Input".to_string(), format!("sig1={params}")),
            (
                "Signature".to_string(),
                format!(
                    "sig1=:{}:",
                    base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
                ),
            ),
        ]);
        headers
    }

    fn service() -> GnapService {
        GnapService::new(GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://as.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        })
        .with_poll_wait_secs(0)
        .with_access_policy(Arc::new(AllowAllPolicy))
    }

    fn request(key: &Signer, method: &str) -> GnapTransactionRequest {
        GnapTransactionRequest::builder()
            .client_key(key.jwk.clone(), method)
            .access_type("read")
            .build()
    }

    async fn issue(
        svc: &GnapService,
        key: &Signer,
        headers: &[(String, String)],
        method: &str,
    ) -> Result<serde_json::Value> {
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let proof = GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: None,
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: &borrowed,
            http_body: BODY,
        };
        let dpop = DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
        svc.handle_transaction_with_proof(&dpop, &proof, request(key, method))
            .await
    }

    fn proof_of<'a>(headers: &'a [(&'a str, &'a str)]) -> GnapProof<'a> {
        GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: None,
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: headers,
            http_body: BODY,
        }
    }

    #[tokio::test]
    async fn an_httpsig_bound_token_is_rotated_and_revoked_only_by_its_key() {
        let svc = service();
        let key = signer();
        let other = signer();
        let dpop = DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
        let issued = issue(&svc, &key, &signed_headers(&key, "i-1", None), "httpsig")
            .await
            .unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let pairs = |h: &[(String, String)]| -> Vec<(String, String)> { h.to_vec() };
        let go = |h: Vec<(String, String)>, rotate: bool| {
            let (svc, dpop, token) = (&svc, &dpop, token.clone());
            async move {
                let borrowed: Vec<(&str, &str)> =
                    h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                let proof = proof_of(&borrowed);
                if rotate {
                    svc.rotate_token_with_proof(dpop, &proof, &token)
                        .await
                        .map(|_| ())
                } else {
                    svc.revoke_token_with_proof(dpop, &proof, &token).await
                }
            }
        };
        // Refutations: another key, and an unsigned request, cannot manage the token.
        assert!(
            go(pairs(&signed_headers(&other, "m-1", Some(&token))), false)
                .await
                .is_err()
        );
        assert!(go(vec![], false).await.is_err());
        // Positive control: the bound key can, once per signed request.
        let good = signed_headers(&key, "m-2", Some(&token));
        go(pairs(&good), false)
            .await
            .unwrap_or_else(|e| panic!("the bound key must revoke its token: {e}"));
        assert!(svc.introspect_token(&token).await.unwrap().is_none());
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A `Detached-JWS` header value (RFC 9635 section 7.3.3) over `BODY`, signed by `signer`.
    fn detached_jws(signer: &Signer, created: i64, token: Option<&str>) -> String {
        use sha2::{Digest, Sha256};
        let mut header = serde_json::json!({
            "alg": "ES256", "typ": "gnap-binding-jwsd", "htm": "POST", "uri": URI, "created": created
        });
        if let Some(t) = token {
            header["ath"] = serde_json::json!(b64(&Sha256::digest(t.as_bytes())));
        }
        let (h, p) = (
            b64(header.to_string().as_bytes()),
            b64(&Sha256::digest(BODY)),
        );
        let sig = signer
            .pair
            .sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes())
            .unwrap();
        format!("{h}.{p}.{}", b64(sig.as_ref()))
    }

    #[tokio::test]
    async fn a_token_expires_when_the_injected_clock_passes_its_lifetime() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let time = Arc::new(AtomicU64::new(1_800_000_000));
        let clock = Arc::clone(&time);
        let svc = service().with_clock(move || clock.load(Ordering::SeqCst));
        let key = signer();
        let issued = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        // Control: the token is live one second before its 3600 s lifetime ends, and gone at the end.
        time.fetch_add(3599, Ordering::SeqCst);
        assert!(svc.introspect_token(&token).await.unwrap().is_some());
        time.fetch_add(1, Ordering::SeqCst);
        assert!(svc.introspect_token(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_replay_is_still_refused_after_the_clock_is_replaced() {
        let t = 1_800_000_000u64;
        let svc = service().with_clock(move || t);
        let key = signer();
        let good = attached_jws(&key, b"{}", t as i64);
        issue_attached(&svc, &key, good.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("the first presentation must be accepted: {e}"));
        // Control: the same service refuses the replay.
        assert!(issue_attached(&svc, &key, good.as_bytes()).await.is_err());
        // Replacing the clock with an earlier one must not make the cache forget.
        let svc = svc.with_clock(move || t - 100);
        assert!(
            issue_attached(&svc, &key, good.as_bytes()).await.is_err(),
            "the replay cache must survive with_clock"
        );
    }

    /// A compact (attached) JWS (RFC 9635 section 7.3.4) over `payload`, signed by `signer`.
    fn attached_jws(signer: &Signer, payload: &[u8], created: i64) -> String {
        let header = serde_json::json!({
            "alg": "ES256", "typ": "gnap-binding-jws", "htm": "POST", "uri": URI, "created": created
        });
        let (h, p) = (b64(header.to_string().as_bytes()), b64(payload));
        let sig = signer
            .pair
            .sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes())
            .unwrap();
        format!("{h}.{p}.{}", b64(sig.as_ref()))
    }

    async fn issue_attached(
        svc: &GnapService,
        key: &Signer,
        body: &[u8],
    ) -> Result<serde_json::Value> {
        let proof = GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: None,
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: &[],
            http_body: body,
        };
        let dpop = DpopManager::new(SecureJwtValidator::new(SecureJwtConfig::default()).unwrap());
        svc.handle_transaction_with_proof(&dpop, &proof, request(key, "jws"))
            .await
    }

    #[tokio::test]
    async fn a_jws_key_is_proved_by_an_attached_jws_and_a_replay_is_refused() {
        let svc = service();
        let key = signer();
        let other = signer();
        let now = chrono::Utc::now().timestamp();
        let good = attached_jws(&key, b"{}", now);

        // Refutations: no body, and a JWS by another key, are refused.
        assert!(issue_attached(&svc, &key, b"").await.is_err());
        let forged = attached_jws(&other, b"{}", now);
        assert!(issue_attached(&svc, &key, forged.as_bytes()).await.is_err());

        // Positive control, built the same way: the named key's JWS is accepted, once.
        let ok = issue_attached(&svc, &key, good.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("an attached JWS by the named key must be accepted: {e}"));
        assert!(ok["access_token"]["value"].is_string());
        assert!(
            issue_attached(&svc, &key, good.as_bytes()).await.is_err(),
            "the same attached JWS must not be accepted twice"
        );
    }

    #[tokio::test]
    async fn a_jwsd_key_is_proved_by_a_detached_jws_and_a_replay_is_refused() {
        let svc = service();
        let key = signer();
        let other = signer();
        let now = chrono::Utc::now().timestamp();
        let header = |s: &Signer| vec![("Detached-JWS".to_string(), detached_jws(s, now, None))];

        // Refutations: no header, and a signature by another key, are refused.
        assert!(issue(&svc, &key, &[], "jwsd").await.is_err());
        assert!(issue(&svc, &key, &header(&other), "jwsd").await.is_err());

        // Positive control, built the same way: the named key's JWS is accepted, once.
        let good = header(&key);
        let ok = issue(&svc, &key, &good, "jwsd")
            .await
            .unwrap_or_else(|e| panic!("a detached JWS by the named key must be accepted: {e}"));
        assert!(ok["access_token"]["value"].is_string());
        assert!(
            issue(&svc, &key, &good, "jwsd").await.is_err(),
            "the same detached JWS must not be accepted twice"
        );
    }

    /// One signed link of a `jws` key rotation (RFC 9635 section 7.3.4.1).
    fn rotation_jws(signer: &Signer, payload: &[u8], token: &str) -> String {
        use sha2::{Digest, Sha256};
        let header = serde_json::json!({
            "alg": "ES256", "typ": "gnap-binding-rotation-jws", "htm": "POST", "uri": URI,
            "created": chrono::Utc::now().timestamp(),
            "ath": b64(&Sha256::digest(token.as_bytes())),
        });
        let (h, p) = (b64(header.to_string().as_bytes()), b64(payload));
        let sig = signer
            .pair
            .sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes())
            .unwrap();
        format!("{h}.{p}.{}", b64(sig.as_ref()))
    }

    async fn rotate_key(svc: &GnapService, body: &str, token: &str) -> Result<serde_json::Value> {
        let auth = format!("GNAP {token}");
        let headers = [("Authorization", auth.as_str())];
        let proof = GnapProof {
            http_method: "POST",
            http_uri: URI,
            dpop_proof: None,
            expected_nonce: None,
            client_certificate_der: None,
            http_headers: &headers,
            http_body: body.as_bytes(),
        };
        svc.rotate_token_key_with_proof(&proof, token).await
    }

    #[tokio::test]
    async fn a_jws_bound_token_rotates_to_a_new_key_only_with_both_keys_proofs() {
        let svc = service();
        let (key, new, other) = (signer(), signer(), signer());
        let now = chrono::Utc::now().timestamp();
        let issued = issue_attached(&svc, &key, attached_jws(&key, b"{}", now).as_bytes())
            .await
            .unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let content = serde_json::json!({ "key": new.jwk }).to_string();
        let nest = |old: &Signer, new: &Signer| {
            rotation_jws(
                new,
                rotation_jws(old, content.as_bytes(), &token).as_bytes(),
                &token,
            )
        };
        let thumbprint = |s: &Signer| GnapService::jwk_thumbprint(&s.jwk).unwrap();

        // Refutations: a wrong old key, a wrong new key and the new key alone each fail with
        // `invalid_rotation`, and the token still works afterwards.
        for bad in [
            nest(&other, &new),
            nest(&key, &other),
            rotation_jws(&new, content.as_bytes(), &token),
        ] {
            let err = rotate_key(&svc, &bad, &token)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("invalid_rotation"), "{err}");
        }
        let live = svc.introspect_token(&token).await.unwrap().unwrap();
        assert_eq!(live["key_thumbprint"], thumbprint(&key));

        // Positive control, built the same way: both keys prove, the token is replaced and re-bound.
        let rotated = rotate_key(&svc, &nest(&key, &new), &token)
            .await
            .unwrap_or_else(|e| panic!("a rotation proved by both keys must succeed: {e}"));
        let fresh = rotated["value"].as_str().unwrap().to_string();
        assert_ne!(fresh, token);
        assert!(svc.introspect_token(&token).await.unwrap().is_none());
        let bound = svc.introspect_token(&fresh).await.unwrap().unwrap();
        assert_eq!(bound["key_thumbprint"], thumbprint(&new));
    }

    #[tokio::test]
    async fn section_11_21_and_11_22_the_token_is_bound_to_the_presented_key_and_rotation_retires_the_old_one()
     {
        let svc = service();
        let (key, new) = (signer(), signer());
        let now = chrono::Utc::now().timestamp();
        let thumbprint = |s: &Signer| GnapService::jwk_thumbprint(&s.jwk).unwrap();

        // 11.21 / 11.31: the token is bound to the key the client presented, not to any key the
        // AS substitutes.
        let issued = issue_attached(&svc, &key, attached_jws(&key, b"{}", now).as_bytes())
            .await
            .unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let live = svc.introspect_token(&token).await.unwrap().unwrap();
        assert_eq!(live["key_thumbprint"], thumbprint(&key));
        assert_ne!(live["key_thumbprint"], thumbprint(&new));

        // 11.22: after a rotation the old token is gone, so the old key cannot rotate it again,
        // and the replacement is bound to the new key alone.
        let content = serde_json::json!({ "key": new.jwk }).to_string();
        let nested = rotation_jws(
            &new,
            rotation_jws(&key, content.as_bytes(), &token).as_bytes(),
            &token,
        );
        let rotated = rotate_key(&svc, &nested, &token).await.unwrap();
        let fresh = rotated["value"].as_str().unwrap().to_string();
        let bound = svc.introspect_token(&fresh).await.unwrap().unwrap();
        assert_eq!(bound["key_thumbprint"], thumbprint(&new));
        assert!(svc.introspect_token(&token).await.unwrap().is_none());
        assert!(
            rotate_key(&svc, &nested, &token).await.is_err(),
            "the retired token must not rotate again"
        );
    }

    /// RFC 9635 section 11.32, "Self-Contained Stateless Access Tokens": revocation and rotation are hard
    /// when tokens are self-contained, "during which both the old and new access tokens are valid". This
    /// service keeps its tokens as state, so a revocation and a rotation take effect at once, and every
    /// token lifetime is bounded by the configured one ("keeping the validity time windows ... short").
    #[tokio::test]
    async fn section_11_32_revocation_and_rotation_take_effect_at_once_with_no_overlap() {
        let svc = service();
        let key = signer();
        let first = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let token = first["access_token"]["value"].as_str().unwrap().to_string();
        assert_eq!(first["access_token"]["expires_in"], 3600);

        let rotated = svc.rotate_token(&token).await.unwrap();
        let fresh = rotated["value"].as_str().unwrap().to_string();
        assert_eq!(rotated["expires_in"], 3600);
        assert!(svc.introspect_token(&fresh).await.unwrap().is_some());
        assert!(
            svc.introspect_token(&token).await.unwrap().is_none(),
            "the old token must not stay valid beside the new one"
        );

        svc.revoke_token(&fresh).await.unwrap();
        assert!(svc.introspect_token(&fresh).await.unwrap().is_none());
    }

    /// RFC 9635 section 11.33, "Network Problems and Token and Grant Management": "multiple calls to rotate
    /// the same access token need to result in the same rotated token value, within a reasonable time
    /// window." A client that lost the response to a rotation retries with the old token and must get the
    /// same new value, not a refusal. Once the new token is seen in use "the original token can be discarded".
    #[tokio::test]
    async fn section_11_33_a_retried_rotation_returns_the_same_new_token() {
        let svc = service();
        let key = signer();
        let first = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let token = first["access_token"]["value"].as_str().unwrap().to_string();

        let rotated = svc.rotate_token(&token).await.unwrap();
        let fresh = rotated["value"].as_str().unwrap().to_string();
        let retried = svc
            .rotate_token(&token)
            .await
            .expect("a retry within the window must succeed");
        assert_eq!(retried["value"], fresh, "the same rotated value");

        // Control: a token the AS never issued is still refused.
        assert!(svc.rotate_token("never-issued").await.is_err());
        // Once the new token is in use, the old one is discarded.
        assert!(svc.introspect_token(&fresh).await.unwrap().is_some());
        assert!(
            svc.rotate_token(&token).await.is_err(),
            "discarded after use"
        );
    }

    /// A retried rotation never hands back a token that is already dead: with a token lifetime shorter than the
    /// 30 s retry window the new token can expire inside it, and the retry is then the normal refusal.
    #[tokio::test]
    async fn a_retried_rotation_does_not_return_an_expired_token() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let time = Arc::new(AtomicU64::new(1_800_000_000));
        let clock = Arc::clone(&time);
        let svc = GnapService::new(GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://as.example.test".to_string()),
            token_lifetime_secs: 5,
            transaction_lifetime_secs: 600,
        })
        .with_poll_wait_secs(0)
        .with_access_policy(Arc::new(AllowAllPolicy))
        .with_clock(move || clock.load(Ordering::SeqCst));
        let key = signer();
        let issued = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let rotated = svc.rotate_token(&token).await.unwrap();
        let fresh = rotated["value"].as_str().unwrap().to_string();

        // Control: inside the new token's lifetime the retry gets the same token.
        time.fetch_add(2, Ordering::SeqCst);
        assert_eq!(svc.rotate_token(&token).await.unwrap()["value"], fresh);
        // Past its lifetime (still inside the 30 s window) the retry is refused.
        time.fetch_add(8, Ordering::SeqCst);
        // (Not introspected: seeing the new token in use would drop the retry record.)
        assert!(
            svc.issued_tokens.get(&fresh).await.unwrap().is_some(),
            "stored, but expired"
        );
        assert!(
            svc.rotate_token(&token).await.is_err(),
            "no expired token is handed back"
        );
    }

    /// A token that carries no key has nothing to prove a retry with, so a rotation of it leaves no retry
    /// record: the retired value is the normal refusal at once (RFC 9635 section 11.33).
    #[tokio::test]
    async fn a_keyless_token_leaves_no_retry_record_when_rotated() {
        let store = Arc::new(InMemoryTokenStore::new());
        let svc = service().with_token_store(store.clone());
        store
            .insert(GnapIssuedToken {
                value: "keyless".to_string(),
                access: vec![],
                expires_at: u64::MAX,
                key_thumbprint: None,
                key_proof: None,
                key_jwk: None,
                transaction_id: "t".to_string(),
            })
            .await
            .unwrap();
        let rotated = svc.rotate_token("keyless").await.unwrap();
        assert!(rotated["value"].is_string());
        assert!(
            svc.rotate_token("keyless").await.is_err(),
            "the retired keyless value is not answered again"
        );

        // Control: a key-bound token still gets its retry.
        let key = signer();
        let issued = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let bound = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let first = svc.rotate_token(&bound).await.unwrap();
        assert_eq!(
            svc.rotate_token(&bound).await.unwrap()["value"],
            first["value"]
        );
    }

    #[tokio::test]
    async fn a_token_bound_under_another_method_or_none_cannot_rotate_its_key() {
        let svc = service();
        let key = signer();
        let issued = svc.handle_transaction(request(&key, "test")).await.unwrap();
        let token = issued["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();
        let err = rotate_key(&svc, "x.y.z", &token)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("key_rotation_not_supported"), "{err}");
        assert!(svc.introspect_token(&token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn an_httpsig_key_is_proved_by_a_signed_request_and_a_replay_is_refused() {
        let svc = service();
        let key = signer();
        let other = signer();
        let headers = signed_headers(&key, "n-1", None);

        // Refutations: no headers, and a signature by another key, are refused.
        assert!(
            issue(&svc, &key, &[], "httpsig").await.is_err(),
            "no signature must fail"
        );
        let forged = signed_headers(&other, "n-2", None);
        assert!(
            issue(&svc, &key, &forged, "httpsig").await.is_err(),
            "another key must fail"
        );

        // Positive control, built the same way: the named key's signature is accepted, once.
        let ok = issue(&svc, &key, &headers, "httpsig")
            .await
            .unwrap_or_else(|e| panic!("a signature by the named key must be accepted: {e}"));
        assert!(ok["access_token"]["value"].is_string());
        assert!(
            issue(&svc, &key, &headers, "httpsig").await.is_err(),
            "the same signed request must not be accepted twice"
        );
    }
}
