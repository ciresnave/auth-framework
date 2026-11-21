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
    FinishMethod, FinishRequest, StartMode, generate_user_code, parse_start, validate_push_target,
};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapInteractionRequirements {
    pub start: Vec<String>,
    pub finish: Option<GnapInteractionFinish>,
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
    /// Seconds a client must leave between two polls of a pending transaction (RFC 9635 section
    /// 3.1 `wait`); 0 turns the check off.
    poll_wait_secs: u64,
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
    "Client polled too fast (too_fast): wait before the next continuation request";

/// The default `wait` between polls, in seconds.
const DEFAULT_POLL_WAIT_SECS: u64 = 5;

/// The one message every refused `continue_transaction` call returns, so a caller cannot tell an
/// unknown transaction from an expired one, a wrong token or a wrong interaction hash.
const INVALID_CONTINUATION: &str = "Invalid continuation request";

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
const ACCESS_DENIED: &str = "GNAP access denied by policy";

impl GnapService {
    pub fn new(config: GnapConfig) -> Self {
        Self {
            config,
            policy: None,
            transactions: Arc::new(InMemoryTransactionStore::new()),
            issued_tokens: Arc::new(InMemoryTokenStore::new()),
            consents: Arc::new(InMemoryConsentStore::new()),
            poll_wait_secs: DEFAULT_POLL_WAIT_SECS,
            httpsig_nonces: Arc::new(std::sync::Mutex::new(super::gnap_httpsig::NonceCache::new(
                system_now(),
            ))),
            clock: Arc::new(system_now),
        }
    }

    /// Replace the clock every expiry, poll-interval and signature-freshness decision reads, so a test can
    /// move time instead of sleeping. `clock` returns seconds since the epoch. The `httpsig` nonce cache is
    /// restarted at the new clock's current time. Production services keep the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.httpsig_nonces = Arc::new(std::sync::Mutex::new(
            super::gnap_httpsig::NonceCache::new(clock()),
        ));
        self.clock = Arc::new(clock);
        self
    }

    /// Set the seconds a client must wait between polls of a pending transaction (default 5). A
    /// poll that comes sooner is refused with [`TOO_FAST`] and does not rotate the continuation
    /// token; the refused poll restarts the clock, so a client that hammers stays refused. `0`
    /// turns the check off.
    pub fn with_poll_wait_secs(mut self, secs: u64) -> Self {
        self.poll_wait_secs = secs;
        self
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
        const MAX_SKEW_SECS: u64 = 300;
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
            let token = header("authorization")
                .and_then(|v| v.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("GNAP"))
                .map(|(_, t)| t.trim());
            match token {
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
            max_skew_secs: MAX_SKEW_SECS,
        };
        super::gnap_jws::verify_detached(detached, &context)
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        // Recorded only after the signature checked out, so a forged request cannot burn a real one's slot.
        let signature = detached.trim().rsplit('.').next().unwrap_or_default();
        let mut nonces = self
            .httpsig_nonces
            .lock()
            .map_err(|_| AuthError::validation(PROOF_INVALID))?;
        nonces
            .check_and_insert(
                thumbprint,
                &format!("jwsd:{signature}"),
                now,
                2 * MAX_SKEW_SECS,
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
    fn compute_interact_hash(
        client_nonce: &str,
        server_nonce: &str,
        interact_ref: &str,
        transaction_endpoint: &str,
    ) -> String {
        let input =
            format!("{client_nonce}\n{server_nonce}\n{interact_ref}\n{transaction_endpoint}");
        let hash = Sha256::digest(input.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
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

    /// Check the `finish` object (section 2.5.2) and, for `push`, the target the server would call
    /// (section 11.34): refused here, at transaction open.
    fn validate_finish(interact: &GnapInteractionRequirements) -> Result<()> {
        let Some(finish) = &interact.finish else {
            return Ok(());
        };
        if let Some(name) = finish.hash_method.as_deref()
            && name != "sha-256"
        {
            return Err(AuthError::validation(format!(
                "interact.finish.hash_method {name} is not supported: this server computes sha-256 only"
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

        // If key-bound, indicate the key binding
        if key_thumbprint.is_some() {
            token_obj.insert("key".to_string(), serde_json::Value::Bool(true));
        }

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
            let user_code = if start_modes.contains(&StartMode::UserCode) {
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

            if let Some(ref code) = user_code {
                interact_res.insert(
                    "user_code".to_string(),
                    serde_json::Value::String(code.clone()),
                );
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
                let subject_resp = Self::build_subject_response(subject_req, None);
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

        response.insert(
            "continue".to_string(),
            serde_json::Value::Object(continue_obj),
        );

        Ok(serde_json::Value::Object(response))
    }

    /// The continuation URI of a transaction: `{transaction_endpoint}/continue/{id}`. RFC 9635
    /// section 5 lets the AS choose it, and naming the transaction lets a request that carries only
    /// the continuation token and a proof be routed to it.
    fn continue_uri(&self, transaction_id: &str) -> String {
        format!(
            "{}/continue/{}",
            self.config.transaction_endpoint, transaction_id
        )
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
            let client_nonce = txn
                .request
                .interact
                .as_ref()
                .and_then(|i| i.finish.as_ref())
                .map(|f| f.nonce.as_str())
                .unwrap_or("");

            let expected = Self::compute_interact_hash(
                client_nonce,
                server_nonce,
                iref,
                &self.config.transaction_endpoint,
            );
            if !bool::from(subtle::ConstantTimeEq::ct_eq(
                hash.as_bytes(),
                expected.as_bytes(),
            )) {
                return Err(AuthError::validation(INVALID_CONTINUATION));
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
                    return Err(AuthError::validation(INVALID_CONTINUATION));
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
                    let subject_resp =
                        Self::build_subject_response(subject_req, txn.subject_id.as_deref());
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
                    "Transaction was denied by the resource owner",
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
            Some(gone) if gone.revision == txn.revision => Ok(()),
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
            let client_nonce = txn
                .request
                .interact
                .as_ref()
                .and_then(|i| i.finish.as_ref())
                .map(|f| f.nonce.clone());
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
            let hash = Self::compute_interact_hash(
                &client_nonce,
                txn.interact_nonce.as_deref().unwrap_or(""),
                &interact_ref,
                endpoint,
            );
            GnapInteractionCompletion {
                interact_ref: Some(interact_ref),
                hash: Some(hash),
            }
        })
        .await
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
        self.rotate_token_inner(old_token_value, Some((dpop, proof)))
            .await
    }

    /// Unit tests only: rotate without a proof. A bound token is refused unless its method is the test one.
    #[cfg(test)]
    pub async fn rotate_token(&self, old_token_value: &str) -> Result<serde_json::Value> {
        self.rotate_token_inner(old_token_value, None).await
    }

    async fn rotate_token_inner(
        &self,
        old_token_value: &str,
        dpop: Option<(&DpopManager, &GnapProof<'_>)>,
    ) -> Result<serde_json::Value> {
        self.require_token_key_proof(old_token_value, "Token not found or already revoked", dpop)
            .await?;
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
        let new_token = GnapIssuedToken {
            value: new_value.clone(),
            access: old.access.clone(),
            expires_at: now + self.config.token_lifetime_secs,
            key_thumbprint: old.key_thumbprint.clone(),
            key_proof: old.key_proof.clone(),
            key_jwk: old.key_jwk.clone(),
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
        if new_token.key_thumbprint.is_some() {
            token_obj.insert("key".to_string(), serde_json::Value::Bool(true));
        }
        let access_json: Vec<serde_json::Value> = old
            .access
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();
        token_obj.insert("access".to_string(), serde_json::Value::Array(access_json));

        self.issued_tokens.insert(new_token).await?;

        Ok(serde_json::Value::Object(token_obj))
    }

    /// Introspect a token — check if it is valid and return its access rights.
    pub async fn introspect_token(&self, token_value: &str) -> Result<Option<serde_json::Value>> {
        let token = match self.issued_tokens.get(token_value).await? {
            Some(t) => t,
            None => return Ok(None),
        };

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
                        sub_ids.push(serde_json::json!({
                            "format": "iss_sub",
                            "iss": "self",
                            "sub": sid,
                        }));
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
        assert_eq!(token_obj.get("key").and_then(|v| v.as_bool()), Some(true));
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

    // ── Subject Info ─────────────────────────────────────────────────────

    #[test]
    fn test_build_subject_response_opaque() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
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
        let resp = GnapService::build_subject_response(&req, Some("user@example.test"));
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
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "opaque");
    }

    #[test]
    fn test_build_subject_response_iss_sub() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["iss_sub".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "iss_sub");
        assert_eq!(sub_ids[0]["sub"], "user-42");
    }

    #[test]
    fn test_build_subject_response_no_subject() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, None);
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
    async fn jws_and_unknown_methods_are_refused_not_accepted_unverified() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        // A valid DPoP header does not rescue a method that is not DPoP.
        let header = dpop_header(&key, &key, "POST", URI, "jti-other-method");
        // `mtls` is exercised with a certificate key in the KM7 tests below: with a JWK it is a malformed key.
        for method in ["jws", "no-such-method"] {
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
        assert_eq!(admitted, ["dpop", "test", "httpsig", "jwsd"]);
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
        assert_eq!(uri, format!("/api/gnap/tx/continue/{stored_id}"));

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

    #[tokio::test]
    async fn a_hash_method_the_server_does_not_honour_is_refused_not_ignored() {
        let (svc, dpop, key) = (service(), manager(), client_key());
        for (n, name) in ["sha-384", "sha-512", "sha3-512", "md5"]
            .into_iter()
            .enumerate()
        {
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
        // the two values the server does honour: sha-256 named, and absent (the default)
        for (n, finish) in [
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
