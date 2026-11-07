// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP `httpsig` proofing: HTTP message signatures (RFC 9421) with content digests (RFC 9530), as
//! RFC 9635 section 7.3.1 profiles them (slice G2 of `docs/GNAP_RFC9635_GAP.md`).
//!
//! What this verifies, and what it refuses:
//!
//! * the signature base of RFC 9421 section 2.5, built from the request and the covered components the
//!   signer named, and a signature over it by the client's public JWK (ES256, ES384, Ed25519 through
//!   `ring`; `PS512` through `aws-lc-rs` when the `rsa-verify` feature is on);
//! * the GNAP rules of RFC 9635 section 7.3.1: `tag` = `gnap`; `created` close to now; no `alg` parameter
//!   (the algorithm comes from the key or the proof object); `keyid` equal to the JWK's `kid`; `@method` and
//!   `@target-uri` covered; `content-digest` covered and correct when there is a body; `authorization`
//!   covered when the request presents an access token; a `nonce`, when present, not seen before;
//! * RFC 9530 `Content-Digest` with `sha-256` and `sha-512`.
//!
//! Not supported, and refused rather than guessed: component parameters (`sf`, `bs`, `key`, `req`, `tr`,
//! `name`), `@request-target`, `@query-param`, `@status`, response signatures, HMAC (a GNAP key is a public
//! key), `rsa-v1_5-sha256`, `ecdsa-secp256k1`. A key that is not a public JWK is refused.

use serde_json::Value;
use sfv::{Dictionary, List, ListEntry, Parser};
use std::collections::HashMap;
use std::fmt;

/// The request being verified. Headers are `(name, value)` pairs in the order received; names are matched
/// without regard to case. `target_uri` is the full absolute URI of the request (RFC 9421 section 2.2.2).
#[derive(Debug, Clone, Copy)]
pub struct HttpRequest<'a> {
    /// The request method, as received (`POST`).
    pub method: &'a str,
    /// The absolute request URI.
    pub target_uri: &'a str,
    /// The header fields.
    pub headers: &'a [(&'a str, &'a str)],
    /// The request content (empty when there is none).
    pub body: &'a [u8],
}

/// A signature algorithm of the RFC 9421 registry that GNAP keys can use here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsigAlgorithm {
    /// `ecdsa-p256-sha256` (JWS `ES256`).
    EcdsaP256Sha256,
    /// `ecdsa-p384-sha384` (JWS `ES384`).
    EcdsaP384Sha384,
    /// `ed25519` (JWS `EdDSA`).
    Ed25519,
    /// `rsa-pss-sha512` (JWS `PS512`); needs the `rsa-verify` feature.
    RsaPssSha512,
}

impl HttpsigAlgorithm {
    /// The registry name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Self::Ed25519 => "ed25519",
            Self::RsaPssSha512 => "rsa-pss-sha512",
        }
    }

    fn from_registry(name: &str) -> Option<Self> {
        match name {
            "ecdsa-p256-sha256" => Some(Self::EcdsaP256Sha256),
            "ecdsa-p384-sha384" => Some(Self::EcdsaP384Sha384),
            "ed25519" => Some(Self::Ed25519),
            "rsa-pss-sha512" => Some(Self::RsaPssSha512),
            _ => None,
        }
    }

    fn from_jws(alg: &str) -> Option<Self> {
        match alg {
            "ES256" => Some(Self::EcdsaP256Sha256),
            "ES384" => Some(Self::EcdsaP384Sha384),
            "EdDSA" => Some(Self::Ed25519),
            "PS512" => Some(Self::RsaPssSha512),
            _ => None,
        }
    }
}

/// Why a message was refused. `Malformed` is a bad request; the others are a failed proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsigError {
    /// The request or its signature headers are not well formed, or use something this verifier refuses.
    Malformed(String),
    /// A GNAP rule of RFC 9635 section 7.3.1 is not met.
    PolicyViolation(String),
    /// The `Content-Digest` does not match the content.
    DigestMismatch,
    /// The signature does not verify under the key.
    BadSignature,
    /// The nonce was already used.
    NonceReplayed,
}

impl fmt::Display for HttpsigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed http signature: {why}"),
            Self::PolicyViolation(why) => write!(f, "http signature breaks a GNAP rule: {why}"),
            Self::DigestMismatch => f.write_str("content-digest does not match the content"),
            Self::BadSignature => f.write_str("http signature does not verify"),
            Self::NonceReplayed => f.write_str("http signature nonce was already used"),
        }
    }
}

impl std::error::Error for HttpsigError {}

fn malformed(why: impl Into<String>) -> HttpsigError {
    HttpsigError::Malformed(why.into())
}

fn violation(why: impl Into<String>) -> HttpsigError {
    HttpsigError::PolicyViolation(why.into())
}

/// A public key parsed from a JWK, with its algorithm.
struct PublicKey {
    alg: HttpsigAlgorithm,
    /// `0x04 || x || y` for EC, the 32 raw bytes for Ed25519, unused for RSA.
    bytes: Vec<u8>,
    /// `(n, e)` big-endian without leading zeros, for RSA.
    rsa: Option<(Vec<u8>, Vec<u8>)>,
}

fn b64url(value: &Value, member: &str) -> Result<Vec<u8>, HttpsigError> {
    use base64::Engine as _;
    let text = value
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("the JWK has no {member}")))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| malformed(format!("the JWK member {member} is not base64url")))
}

/// Parse a public JWK for `httpsig` and choose the algorithm (RFC 9635 section 7.3.1): `proof_alg` when the
/// proof is in object form, else the JWS algorithm named by the JWK's `alg`, else the one its curve implies.
/// A private member, an `alg` that disagrees with the key type, or a key of another type is refused.
fn parse_key(jwk: &Value, proof_alg: Option<&str>) -> Result<PublicKey, HttpsigError> {
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        if jwk.get(private).is_some() {
            return Err(malformed("the JWK must be a public key"));
        }
    }
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or("");
    let crv = jwk.get("crv").and_then(Value::as_str);
    let implied = match (kty, crv) {
        ("EC", Some("P-256")) => Some(HttpsigAlgorithm::EcdsaP256Sha256),
        ("EC", Some("P-384")) => Some(HttpsigAlgorithm::EcdsaP384Sha384),
        ("OKP", Some("Ed25519")) => Some(HttpsigAlgorithm::Ed25519),
        // RSA: the modulus alone does not say PSS or PKCS#1 v1.5, so the algorithm must be named.
        ("RSA", _) => None,
        _ => {
            return Err(malformed(
                "the JWK type or curve is not supported for httpsig",
            ));
        }
    };
    let from_jwk = match jwk.get("alg").and_then(Value::as_str) {
        Some(alg) => Some(
            HttpsigAlgorithm::from_jws(alg)
                .ok_or_else(|| malformed("the JWK alg is not an httpsig algorithm"))?,
        ),
        None => None,
    };
    let from_proof = match proof_alg {
        Some(alg) => Some(
            HttpsigAlgorithm::from_registry(alg)
                .ok_or_else(|| malformed("the proof alg is not supported"))?,
        ),
        None => None,
    };
    if let (Some(a), Some(b)) = (from_proof, from_jwk)
        && a != b
    {
        return Err(malformed("the proof alg and the JWK alg disagree"));
    }
    let alg = from_proof.or(from_jwk).or(implied).ok_or_else(|| {
        malformed(
            "the algorithm cannot be derived from this key: name it in the proof or the JWK alg",
        )
    })?;
    if let Some(implied) = implied
        && implied != alg
    {
        return Err(malformed("the algorithm does not fit the key type"));
    }
    match alg {
        HttpsigAlgorithm::EcdsaP256Sha256 | HttpsigAlgorithm::EcdsaP384Sha384 => {
            let size = if alg == HttpsigAlgorithm::EcdsaP256Sha256 {
                32
            } else {
                48
            };
            if kty != "EC" {
                return Err(malformed("the algorithm needs an EC key"));
            }
            let (x, y) = (b64url(jwk, "x")?, b64url(jwk, "y")?);
            if x.len() != size || y.len() != size {
                return Err(malformed("the EC coordinates have the wrong length"));
            }
            let mut bytes = vec![0x04];
            bytes.extend_from_slice(&x);
            bytes.extend_from_slice(&y);
            Ok(PublicKey {
                alg,
                bytes,
                rsa: None,
            })
        }
        HttpsigAlgorithm::Ed25519 => {
            if kty != "OKP" {
                return Err(malformed("ed25519 needs an OKP key"));
            }
            let x = b64url(jwk, "x")?;
            if x.len() != 32 {
                return Err(malformed("the Ed25519 key is not 32 bytes"));
            }
            Ok(PublicKey {
                alg,
                bytes: x,
                rsa: None,
            })
        }
        HttpsigAlgorithm::RsaPssSha512 => {
            if kty != "RSA" {
                return Err(malformed("rsa-pss-sha512 needs an RSA key"));
            }
            let (n, e) = (b64url(jwk, "n")?, b64url(jwk, "e")?);
            if n.first() == Some(&0) || e.first() == Some(&0) {
                return Err(malformed("an RSA component has a leading zero"));
            }
            Ok(PublicKey {
                alg,
                bytes: Vec::new(),
                rsa: Some((n, e)),
            })
        }
    }
}

impl PublicKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), HttpsigError> {
        use ring::signature::{
            ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, UnparsedPublicKey,
        };
        let ok = match self.alg {
            HttpsigAlgorithm::EcdsaP256Sha256 => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.bytes)
                    .verify(message, signature)
                    .is_ok()
            }
            HttpsigAlgorithm::EcdsaP384Sha384 => {
                UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &self.bytes)
                    .verify(message, signature)
                    .is_ok()
            }
            HttpsigAlgorithm::Ed25519 => UnparsedPublicKey::new(&ED25519, &self.bytes)
                .verify(message, signature)
                .is_ok(),
            HttpsigAlgorithm::RsaPssSha512 => self.verify_rsa_pss(message, signature),
        };
        if ok {
            Ok(())
        } else {
            Err(HttpsigError::BadSignature)
        }
    }

    #[cfg(feature = "rsa-verify")]
    fn verify_rsa_pss(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.rsa {
            Some((n, e)) => aws_lc_rs::rsa::PublicKeyComponents {
                n: n.as_slice(),
                e: e.as_slice(),
            }
            .verify(
                &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA512,
                message,
                signature,
            )
            .is_ok(),
            None => false,
        }
    }

    #[cfg(not(feature = "rsa-verify"))]
    fn verify_rsa_pss(&self, _message: &[u8], _signature: &[u8]) -> bool {
        // Without the `rsa-verify` feature no RSA verifier is compiled in: refuse, never accept.
        let _ = &self.rsa;
        false
    }
}

/// One signature of the request: its label, covered components, the serialized parameters and the value.
struct SignatureEntry {
    label: String,
    components: Vec<String>,
    /// The inner list with its parameters, serialized (RFC 9421 section 2.3).
    params_line: String,
    params: Vec<(String, sfv::BareItem)>,
    signature: Vec<u8>,
}

fn header_values(request: &HttpRequest<'_>, name: &str) -> Vec<String> {
    request
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

fn parse_signatures(request: &HttpRequest<'_>) -> Result<Vec<SignatureEntry>, HttpsigError> {
    let inputs = header_values(request, "signature-input");
    let signatures = header_values(request, "signature");
    if inputs.is_empty() || signatures.is_empty() {
        return Err(malformed(
            "the request has no Signature-Input or Signature header",
        ));
    }
    let input: Dictionary = Parser::new(&inputs.join(", "))
        .parse_dictionary()
        .map_err(|e| malformed(format!("Signature-Input: {e}")))?;
    let values: Dictionary = Parser::new(&signatures.join(", "))
        .parse_dictionary()
        .map_err(|e| malformed(format!("Signature: {e}")))?;
    let mut entries = Vec::new();
    for (label, entry) in &input {
        let ListEntry::InnerList(inner) = entry else {
            return Err(malformed("a Signature-Input member is not an inner list"));
        };
        let mut components = Vec::new();
        for item in &inner.items {
            if !item.params.is_empty() {
                return Err(malformed(
                    "component parameters (sf, bs, key, req, tr, name) are not supported",
                ));
            }
            let name = item
                .bare_item
                .as_string()
                .ok_or_else(|| malformed("a covered component is not a string"))?
                .as_str()
                .to_string();
            if name.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(malformed("component names must be lowercase"));
            }
            if components.contains(&name) {
                return Err(malformed("a component is covered twice"));
            }
            components.push(name);
        }
        let line: List = vec![ListEntry::InnerList(inner.clone())];
        let params_line = sfv::FieldType::serialize(&line)
            .ok_or_else(|| malformed("cannot serialize the signature parameters"))?;
        let signature = values
            .get(label.as_str())
            .and_then(|entry| match entry {
                ListEntry::Item(item) => item.bare_item.as_byte_sequence().map(<[u8]>::to_vec),
                ListEntry::InnerList(_) => None,
            })
            .ok_or_else(|| malformed("a Signature-Input label has no byte-sequence Signature"))?;
        entries.push(SignatureEntry {
            label: label.as_str().to_string(),
            components,
            params_line,
            params: inner
                .params
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.clone()))
                .collect(),
            signature,
        });
    }
    Ok(entries)
}

impl SignatureEntry {
    fn param(&self, name: &str) -> Option<&sfv::BareItem> {
        self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
}

/// Split an absolute URI into scheme, authority, path and query without normalizing anything.
fn split_uri(uri: &str) -> Result<(String, String, String, Option<String>), HttpsigError> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| malformed("the target URI is not absolute"))?;
    let rest = rest.split('#').next().unwrap_or("");
    let (authority_and_path, query) = match rest.split_once('?') {
        Some((before, query)) => (before, Some(query.to_string())),
        None => (rest, None),
    };
    let (authority, path) = match authority_and_path.find('/') {
        Some(at) => (&authority_and_path[..at], &authority_and_path[at..]),
        None => (authority_and_path, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(malformed("the target URI has no usable authority"));
    }
    Ok((
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase(),
        path.to_string(),
        query,
    ))
}

fn component_value(request: &HttpRequest<'_>, name: &str) -> Result<String, HttpsigError> {
    let value = if let Some(derived) = name.strip_prefix('@') {
        match derived {
            "method" => request.method.to_string(),
            "target-uri" => request.target_uri.to_string(),
            "authority" => {
                let (scheme, authority, _, _) = split_uri(request.target_uri)?;
                // The default port is dropped (RFC 9421 section 2.2.3).
                let default = if scheme == "https" {
                    ":443"
                } else if scheme == "http" {
                    ":80"
                } else {
                    ""
                };
                if !default.is_empty() && authority.ends_with(default) {
                    authority[..authority.len() - default.len()].to_string()
                } else {
                    authority
                }
            }
            "scheme" => split_uri(request.target_uri)?.0,
            "path" => split_uri(request.target_uri)?.2,
            "query" => format!("?{}", split_uri(request.target_uri)?.3.unwrap_or_default()),
            other => {
                return Err(malformed(format!(
                    "the derived component @{other} is not supported"
                )));
            }
        }
    } else {
        let values = header_values(request, name);
        if values.is_empty() {
            return Err(malformed(format!(
                "the covered header {name} is not in the request"
            )));
        }
        values.join(", ")
    };
    if value
        .bytes()
        .any(|b| b == b'\n' || b == b'\r' || !b.is_ascii())
    {
        return Err(malformed(format!(
            "the value of {name} cannot be put in a signature base"
        )));
    }
    Ok(value)
}

/// The signature base of RFC 9421 section 2.5 for one signature of the request.
fn signature_base(
    request: &HttpRequest<'_>,
    entry: &SignatureEntry,
) -> Result<String, HttpsigError> {
    let mut base = String::new();
    for name in &entry.components {
        base.push('"');
        base.push_str(name);
        base.push_str("\": ");
        base.push_str(&component_value(request, name)?);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(&entry.params_line);
    Ok(base)
}

/// Verify one signature of the request cryptographically, with no GNAP rule applied: the signature base is
/// rebuilt from the request and checked under the JWK. `label` picks a signature (`None` requires exactly one).
/// This is the RFC 9421 layer; use [`verify_gnap_request`] for a GNAP request.
pub fn verify_message_signature(
    request: &HttpRequest<'_>,
    jwk: &Value,
    alg: Option<&str>,
    label: Option<&str>,
) -> Result<HttpsigAlgorithm, HttpsigError> {
    let key = parse_key(jwk, alg)?;
    let entries = parse_signatures(request)?;
    let entry = match label {
        Some(label) => entries
            .iter()
            .find(|e| e.label == label)
            .ok_or_else(|| malformed("no signature with that label"))?,
        None if entries.len() == 1 => &entries[0],
        None => return Err(malformed("several signatures and no label named")),
    };
    key.verify(signature_base(request, entry)?.as_bytes(), &entry.signature)?;
    Ok(key.alg)
}

/// Digest algorithms of RFC 9530 this verifier computes.
fn digest(alg: &str, body: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256, Sha512};
    match alg {
        "sha-256" => Some(Sha256::digest(body).to_vec()),
        "sha-512" => Some(Sha512::digest(body).to_vec()),
        _ => None,
    }
}

/// The `Content-Digest` header value for `body` (RFC 9530): `sha-256=:...:`.
pub fn content_digest_header(alg: &str, body: &[u8]) -> Option<String> {
    use base64::Engine as _;
    digest(alg, body).map(|d| {
        format!(
            "{alg}=:{}:",
            base64::engine::general_purpose::STANDARD.encode(d)
        )
    })
}

/// Check the request's `Content-Digest` against its content for the algorithm the proof names (RFC 9635
/// section 7.3.1: `sha-256` when the proof is in string form). Any digest of a supported algorithm that is
/// present must be right, and the named one must be present.
fn verify_content_digest(request: &HttpRequest<'_>, alg: &str) -> Result<(), HttpsigError> {
    if digest(alg, b"").is_none() {
        return Err(malformed("the content-digest-alg is not supported"));
    }
    let values = header_values(request, "content-digest");
    if values.is_empty() {
        return Err(violation("the request has content but no Content-Digest"));
    }
    let parsed: Dictionary = Parser::new(&values.join(", "))
        .parse_dictionary()
        .map_err(|e| malformed(format!("Content-Digest: {e}")))?;
    let mut named_seen = false;
    for (name, entry) in &parsed {
        let Some(expected) = digest(name.as_str(), request.body) else {
            continue;
        };
        let ListEntry::Item(item) = entry else {
            return Err(malformed("a Content-Digest member is not an item"));
        };
        let given = item
            .bare_item
            .as_byte_sequence()
            .ok_or_else(|| malformed("a Content-Digest value is not a byte sequence"))?;
        if given != expected.as_slice() {
            return Err(HttpsigError::DigestMismatch);
        }
        if name.as_str() == alg {
            named_seen = true;
        }
    }
    if !named_seen {
        return Err(violation(
            "the Content-Digest does not carry the algorithm the proof names",
        ));
    }
    Ok(())
}

/// Nonces seen in the last `window_secs`, per scope (use the key's thumbprint as the scope). The caller keeps
/// one cache per verifier and guards it with a lock.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: HashMap<(String, String), u64>,
}

impl NonceCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` in `scope` at `now`; false when it was already recorded within `window_secs`.
    pub fn check_and_insert(
        &mut self,
        scope: &str,
        nonce: &str,
        now: u64,
        window_secs: u64,
    ) -> bool {
        self.seen
            .retain(|_, at| now.saturating_sub(*at) <= window_secs);
        let key = (scope.to_string(), nonce.to_string());
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        true
    }
}

/// How strictly a GNAP request is checked.
#[derive(Debug, Clone, Copy)]
pub struct HttpsigPolicy {
    /// How far `created` may differ from now, in seconds, either way.
    pub max_skew_secs: u64,
    /// How long a nonce is remembered, in seconds. Must be at least `max_skew_secs` or a replay slips through.
    pub nonce_window_secs: u64,
    /// Refuse a signature without a `nonce` (RFC 9635 says the signer SHOULD include one).
    pub require_nonce: bool,
}

impl Default for HttpsigPolicy {
    fn default() -> Self {
        Self {
            max_skew_secs: 300,
            nonce_window_secs: 600,
            require_nonce: false,
        }
    }
}

/// What a GNAP request must be checked against.
#[derive(Debug, Clone, Copy)]
pub struct GnapHttpsigContext<'a> {
    /// The client's public JWK.
    pub jwk: &'a Value,
    /// The proof object's `alg`, when the proof is in object form.
    pub proof_alg: Option<&'a str>,
    /// The proof object's `content-digest-alg`; `sha-256` when absent (string form).
    pub content_digest_alg: Option<&'a str>,
    /// True when the request presents an access token, so `authorization` must be covered.
    pub bound_to_token: bool,
    /// The current time, seconds since the epoch.
    pub now: u64,
    /// The nonce scope: the key's thumbprint.
    pub nonce_scope: &'a str,
}

/// The facts of an accepted signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The label in `Signature-Input`.
    pub label: String,
    /// The algorithm used.
    pub algorithm: HttpsigAlgorithm,
    /// When the signer says it signed.
    pub created: u64,
    /// The covered components, in order.
    pub covered: Vec<String>,
}

/// Verify a GNAP `httpsig` request (RFC 9635 section 7.3.1 over RFC 9421 and RFC 9530). Exactly one signature
/// must carry `tag="gnap"`; others are ignored. The nonce is recorded only when everything else passed.
pub fn verify_gnap_request(
    request: &HttpRequest<'_>,
    context: &GnapHttpsigContext<'_>,
    policy: &HttpsigPolicy,
    nonces: &mut NonceCache,
) -> Result<VerifiedSignature, HttpsigError> {
    let key = parse_key(context.jwk, context.proof_alg)?;
    let entries = parse_signatures(request)?;
    let mut tagged = entries.iter().filter(|e| {
        e.param("tag")
            .and_then(|t| t.as_string())
            .map(|s| s.as_str() == "gnap")
            .unwrap_or(false)
    });
    let entry = tagged
        .next()
        .ok_or_else(|| violation("no signature carries tag=\"gnap\""))?;
    if tagged.next().is_some() {
        return Err(violation("more than one signature carries tag=\"gnap\""));
    }
    if entry.param("alg").is_some() {
        return Err(violation("the alg signature parameter must not be present"));
    }
    let created = entry
        .param("created")
        .and_then(sfv::BareItem::as_integer)
        .map(i64::from)
        .ok_or_else(|| violation("the created parameter is missing"))?;
    let created = u64::try_from(created).map_err(|_| violation("created is negative"))?;
    if created.abs_diff(context.now) > policy.max_skew_secs {
        return Err(violation("created is too far from the current time"));
    }
    if let Some(expires) = entry
        .param("expires")
        .and_then(sfv::BareItem::as_integer)
        .map(i64::from)
        && expires < i64::try_from(context.now).unwrap_or(i64::MAX)
    {
        return Err(violation("the signature has expired"));
    }
    if let Some(kid) = context.jwk.get("kid").and_then(Value::as_str) {
        let keyid = entry
            .param("keyid")
            .and_then(|k| k.as_string())
            .map(|s| s.as_str().to_string());
        if keyid.as_deref() != Some(kid) {
            return Err(violation("keyid must equal the kid of the JWK"));
        }
    }
    let covers = |name: &str| entry.components.iter().any(|c| c == name);
    if !covers("@method") || !covers("@target-uri") {
        return Err(violation("@method and @target-uri must be covered"));
    }
    if !request.body.is_empty() {
        if !covers("content-digest") {
            return Err(violation(
                "content-digest must be covered when the request has content",
            ));
        }
        verify_content_digest(request, context.content_digest_alg.unwrap_or("sha-256"))?;
    }
    if context.bound_to_token && !covers("authorization") {
        return Err(violation(
            "authorization must be covered when the request presents an access token",
        ));
    }
    let nonce = entry
        .param("nonce")
        .and_then(|n| n.as_string())
        .map(|s| s.as_str().to_string());
    if policy.require_nonce && nonce.is_none() {
        return Err(violation("the signature has no nonce"));
    }
    key.verify(signature_base(request, entry)?.as_bytes(), &entry.signature)?;
    if let Some(nonce) = nonce
        && !nonces.check_and_insert(
            context.nonce_scope,
            &nonce,
            context.now,
            policy.nonce_window_secs,
        )
    {
        return Err(HttpsigError::NonceReplayed);
    }
    Ok(VerifiedSignature {
        label: entry.label.clone(),
        algorithm: key.alg,
        created,
        covered: entry.components.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use serde_json::json;

    const URL_SAFE: base64::engine::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;
    const STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    // RFC 9421 appendix B.2: the test-request message and the test keys. The signature values are the RFC's.
    const RFC_BODY: &[u8] = b"{\"hello\": \"world\"}";
    const RFC_DIGEST: &str = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

    fn rfc_headers(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut headers = vec![
            ("Host", "example.com"),
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
            ("Content-Digest", RFC_DIGEST),
            ("Content-Length", "18"),
        ];
        headers.extend_from_slice(extra);
        headers
    }

    #[test]
    fn the_rfc_9421_digest_example_is_what_this_code_computes() {
        assert_eq!(
            content_digest_header("sha-512", RFC_BODY).unwrap(),
            RFC_DIGEST
        );
        assert!(content_digest_header("md5", RFC_BODY).is_none());
    }

    #[test]
    fn rfc_9421_b_2_6_ed25519_signature_verifies() {
        let signature_input = "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
        let signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:";
        let headers = rfc_headers(&[
            ("Signature-Input", signature_input),
            ("Signature", signature),
        ]);
        let request = HttpRequest {
            method: "POST",
            target_uri: "https://example.com/foo?param=Value&Pet=dog",
            headers: &headers,
            body: RFC_BODY,
        };
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "kid": "test-key-ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"});
        assert_eq!(
            verify_message_signature(&request, &jwk, None, None).unwrap(),
            HttpsigAlgorithm::Ed25519
        );
        // Controls: another key, another path and another covered header value each break it.
        let other = json!({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        assert_eq!(
            verify_message_signature(&request, &other, None, None).unwrap_err(),
            HttpsigError::BadSignature
        );
        let moved = HttpRequest {
            target_uri: "https://example.com/bar?param=Value&Pet=dog",
            ..request
        };
        assert_eq!(
            verify_message_signature(&moved, &jwk, None, None).unwrap_err(),
            HttpsigError::BadSignature
        );
        let mut later = headers.clone();
        later[1] = ("Date", "Tue, 20 Apr 2021 02:07:56 GMT");
        let changed = HttpRequest {
            headers: &later,
            ..request
        };
        assert_eq!(
            verify_message_signature(&changed, &jwk, None, None).unwrap_err(),
            HttpsigError::BadSignature
        );
    }

    #[cfg(feature = "rsa-verify")]
    #[test]
    fn rfc_9421_b_2_3_rsa_pss_signature_verifies() {
        let signature_input = "sig-b23=(\"date\" \"@method\" \"@path\" \"@query\" \"@authority\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-rsa-pss\"";
        let signature = "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:";
        let headers = rfc_headers(&[
            ("Signature-Input", signature_input),
            ("Signature", signature),
        ]);
        let request = HttpRequest {
            method: "POST",
            target_uri: "https://example.com/foo?param=Value&Pet=dog",
            headers: &headers,
            body: RFC_BODY,
        };
        let jwk = json!({"kty": "RSA", "alg": "PS512", "e": "AQAB",
            "n": "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w"});
        assert_eq!(
            verify_message_signature(&request, &jwk, None, None).unwrap(),
            HttpsigAlgorithm::RsaPssSha512
        );
        let moved = HttpRequest {
            target_uri: "https://example.com/foo?param=Value&Pet=cat",
            ..request
        };
        assert_eq!(
            verify_message_signature(&moved, &jwk, None, None).unwrap_err(),
            HttpsigError::BadSignature
        );
    }

    #[cfg(not(feature = "rsa-verify"))]
    #[test]
    fn rsa_pss_is_refused_without_the_rsa_verify_feature() {
        let key = parse_key(
            &json!({"kty": "RSA", "alg": "PS512", "n": "r4tm", "e": "AQAB"}),
            None,
        )
        .unwrap();
        assert_eq!(
            key.verify(b"m", b"s").unwrap_err(),
            HttpsigError::BadSignature
        );
    }

    #[test]
    fn the_signature_base_is_the_one_of_rfc_9421_b_2_6() {
        let signature_input = "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
        let headers = rfc_headers(&[
            ("Signature-Input", signature_input),
            ("Signature", "sig-b26=:AAAA:"),
        ]);
        let request = HttpRequest {
            method: "POST",
            target_uri: "https://example.com/foo?param=Value&Pet=dog",
            headers: &headers,
            body: RFC_BODY,
        };
        let entry = &parse_signatures(&request).unwrap()[0];
        let expected = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"";
        assert_eq!(signature_base(&request, entry).unwrap(), expected);
    }

    // ---- GNAP rules, with keys made here ----

    struct Signer {
        pair: EcdsaKeyPair,
        jwk: Value,
    }

    fn signer() -> Signer {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public = pair.public_key().as_ref();
        let jwk = json!({"kty": "EC", "crv": "P-256", "kid": "gnap-ec", "alg": "ES256",
            "x": URL_SAFE.encode(&public[1..33]), "y": URL_SAFE.encode(&public[33..65])});
        Signer { pair, jwk }
    }

    const NOW: u64 = 1_700_000_000;
    const URI: &str = "https://as.example/gnap";

    /// Sign a POST with the given covered components and parameter text; returns the headers.
    fn signed(
        signer: &Signer,
        body: &[u8],
        covered: &str,
        params: &str,
        token: Option<&str>,
    ) -> Vec<(String, String)> {
        let digest = content_digest_header("sha-256", body).unwrap();
        let mut headers = vec![
            ("Content-Digest".to_string(), digest),
            ("Content-Type".to_string(), "application/json".into()),
        ];
        if let Some(token) = token {
            headers.push(("Authorization".to_string(), format!("GNAP {token}")));
        }
        let params_line = format!("({covered}){params}");
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let probe = HttpRequest {
            method: "POST",
            target_uri: URI,
            headers: &borrowed,
            body,
        };
        let mut base = String::new();
        for name in covered.split(' ').filter(|c| !c.is_empty()) {
            let name = name.trim_matches('"');
            base.push_str(&format!(
                "\"{name}\": {}\n",
                component_value(&probe, name).unwrap()
            ));
        }
        base.push_str(&format!("\"@signature-params\": {params_line}"));
        let signature = signer
            .pair
            .sign(&SystemRandom::new(), base.as_bytes())
            .unwrap();
        headers.push(("Signature-Input".to_string(), format!("sig1={params_line}")));
        headers.push((
            "Signature".to_string(),
            format!("sig1=:{}:", STD.encode(signature.as_ref())),
        ));
        headers
    }

    fn check(
        signer: &Signer,
        headers: &[(String, String)],
        body: &[u8],
        bound: bool,
        nonces: &mut NonceCache,
    ) -> Result<VerifiedSignature, HttpsigError> {
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let request = HttpRequest {
            method: "POST",
            target_uri: URI,
            headers: &borrowed,
            body,
        };
        let context = GnapHttpsigContext {
            jwk: &signer.jwk,
            proof_alg: None,
            content_digest_alg: None,
            bound_to_token: bound,
            now: NOW,
            nonce_scope: "thumb",
        };
        verify_gnap_request(&request, &context, &HttpsigPolicy::default(), nonces)
    }

    const FULL: &str = "\"@method\" \"@target-uri\" \"content-digest\"";
    fn params(extra: &str) -> String {
        format!(";created={NOW};keyid=\"gnap-ec\";tag=\"gnap\"{extra}")
    }

    #[test]
    fn a_correct_gnap_request_verifies_and_reports_its_facts() {
        let s = signer();
        let body = b"{\"access_token\":{\"access\":[\"x\"]}}";
        let headers = signed(&s, body, FULL, &params(";nonce=\"n-1\""), None);
        let got = check(&s, &headers, body, false, &mut NonceCache::new()).unwrap();
        assert_eq!(got.algorithm, HttpsigAlgorithm::EcdsaP256Sha256);
        assert_eq!(got.created, NOW);
        assert_eq!(
            got.covered,
            vec!["@method", "@target-uri", "content-digest"]
        );
    }

    fn refused(headers: &[(String, String)], s: &Signer, body: &[u8], bound: bool) -> HttpsigError {
        check(s, headers, body, bound, &mut NonceCache::new()).unwrap_err()
    }

    #[test]
    fn each_gnap_rule_of_section_7_3_1_is_enforced() {
        let s = signer();
        let body = b"{}";
        // Control first: the unmodified request passes, so every refusal below is about its one change.
        assert!(
            check(
                &s,
                &signed(&s, body, FULL, &params(""), None),
                body,
                false,
                &mut NonceCache::new()
            )
            .is_ok()
        );
        // tag must be gnap
        let bad_tag = format!(";created={NOW};keyid=\"gnap-ec\";tag=\"other\"");
        assert!(matches!(
            refused(&signed(&s, body, FULL, &bad_tag, None), &s, body, false),
            HttpsigError::PolicyViolation(_)
        ));
        let no_tag = format!(";created={NOW};keyid=\"gnap-ec\"");
        assert!(matches!(
            refused(&signed(&s, body, FULL, &no_tag, None), &s, body, false),
            HttpsigError::PolicyViolation(_)
        ));
        // alg must not be present
        assert!(matches!(
            refused(
                &signed(&s, body, FULL, &params(";alg=\"ecdsa-p256-sha256\""), None),
                &s,
                body,
                false
            ),
            HttpsigError::PolicyViolation(_)
        ));
        // created missing, too old, too new
        let no_created = ";keyid=\"gnap-ec\";tag=\"gnap\"".to_string();
        assert!(matches!(
            refused(&signed(&s, body, FULL, &no_created, None), &s, body, false),
            HttpsigError::PolicyViolation(_)
        ));
        for skewed in [NOW - 301, NOW + 301] {
            let p = format!(";created={skewed};keyid=\"gnap-ec\";tag=\"gnap\"");
            assert!(
                matches!(
                    refused(&signed(&s, body, FULL, &p, None), &s, body, false),
                    HttpsigError::PolicyViolation(_)
                ),
                "{skewed}"
            );
        }
        for fine in [NOW - 300, NOW + 300] {
            let p = format!(";created={fine};keyid=\"gnap-ec\";tag=\"gnap\"");
            assert!(
                check(
                    &s,
                    &signed(&s, body, FULL, &p, None),
                    body,
                    false,
                    &mut NonceCache::new()
                )
                .is_ok(),
                "{fine}"
            );
        }
        // keyid must be the kid
        let wrong_kid = format!(";created={NOW};keyid=\"someone-else\";tag=\"gnap\"");
        assert!(matches!(
            refused(&signed(&s, body, FULL, &wrong_kid, None), &s, body, false),
            HttpsigError::PolicyViolation(_)
        ));
        // @method and @target-uri must be covered
        assert!(matches!(
            refused(
                &signed(
                    &s,
                    body,
                    "\"@target-uri\" \"content-digest\"",
                    &params(""),
                    None
                ),
                &s,
                body,
                false
            ),
            HttpsigError::PolicyViolation(_)
        ));
        assert!(matches!(
            refused(
                &signed(
                    &s,
                    body,
                    "\"@method\" \"content-digest\"",
                    &params(""),
                    None
                ),
                &s,
                body,
                false
            ),
            HttpsigError::PolicyViolation(_)
        ));
        // content-digest must be covered when there is a body ...
        assert!(matches!(
            refused(
                &signed(&s, body, "\"@method\" \"@target-uri\"", &params(""), None),
                &s,
                body,
                false
            ),
            HttpsigError::PolicyViolation(_)
        ));
        // ... but is not needed when there is none
        assert!(
            check(
                &s,
                &signed(&s, b"", "\"@method\" \"@target-uri\"", &params(""), None),
                b"",
                false,
                &mut NonceCache::new()
            )
            .is_ok()
        );
        // authorization must be covered when a token is presented
        assert!(matches!(
            refused(
                &signed(&s, body, FULL, &params(""), Some("TOKEN")),
                &s,
                body,
                true
            ),
            HttpsigError::PolicyViolation(_)
        ));
        let with_auth = format!("{FULL} \"authorization\"");
        assert!(
            check(
                &s,
                &signed(&s, body, &with_auth, &params(""), Some("TOKEN")),
                body,
                true,
                &mut NonceCache::new()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_body_that_does_not_match_its_content_digest_is_refused() {
        let s = signer();
        let headers = signed(&s, b"{\"a\":1}", FULL, &params(""), None);
        assert_eq!(
            refused(&headers, &s, b"{\"a\":2}", false),
            HttpsigError::DigestMismatch
        );
        assert!(check(&s, &headers, b"{\"a\":1}", false, &mut NonceCache::new()).is_ok());
    }

    #[test]
    fn a_digest_of_the_wrong_algorithm_for_the_proof_is_refused() {
        let s = signer();
        let body = b"{}";
        let headers = signed(&s, body, FULL, &params(""), None); // sha-256
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let request = HttpRequest {
            method: "POST",
            target_uri: URI,
            headers: &borrowed,
            body,
        };
        let context = GnapHttpsigContext {
            jwk: &s.jwk,
            proof_alg: None,
            content_digest_alg: Some("sha-512"),
            bound_to_token: false,
            now: NOW,
            nonce_scope: "t",
        };
        let err = verify_gnap_request(
            &request,
            &context,
            &HttpsigPolicy::default(),
            &mut NonceCache::new(),
        )
        .unwrap_err();
        assert!(matches!(err, HttpsigError::PolicyViolation(_)), "{err:?}");
    }

    #[test]
    fn a_nonce_is_accepted_once_and_a_failed_request_does_not_burn_it() {
        let s = signer();
        let body = b"{}";
        let headers = signed(&s, body, FULL, &params(";nonce=\"once\""), None);
        let mut nonces = NonceCache::new();
        assert!(check(&s, &headers, body, false, &mut nonces).is_ok());
        assert_eq!(
            check(&s, &headers, body, false, &mut nonces).unwrap_err(),
            HttpsigError::NonceReplayed
        );
        // a request whose signature is wrong records nothing: its nonce is still free for the real signer
        let fresh = signed(&s, body, FULL, &params(";nonce=\"second\""), None);
        let forged: Vec<(String, String)> = fresh
            .iter()
            .map(|(n, v)| {
                if n == "Signature" {
                    (n.clone(), "sig1=:AAAA:".to_string())
                } else {
                    (n.clone(), v.clone())
                }
            })
            .collect();
        let mut other = NonceCache::new();
        assert_eq!(
            check(&s, &forged, body, false, &mut other).unwrap_err(),
            HttpsigError::BadSignature
        );
        assert!(
            check(&s, &fresh, body, false, &mut other).is_ok(),
            "the nonce of a refused request is not burned"
        );
    }

    #[test]
    fn a_nonce_is_remembered_for_the_window_then_forgotten() {
        let mut cache = NonceCache::new();
        assert!(cache.check_and_insert("k", "n", 100, 600));
        assert!(!cache.check_and_insert("k", "n", 700, 600));
        assert!(
            cache.check_and_insert("k", "n", 701, 600),
            "after the window it may be used again"
        );
        assert!(
            cache.check_and_insert("other-key", "n", 701, 600),
            "scopes are separate"
        );
    }

    #[test]
    fn require_nonce_refuses_a_signature_without_one() {
        let s = signer();
        let body = b"{}";
        let headers = signed(&s, body, FULL, &params(""), None);
        let borrowed: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let request = HttpRequest {
            method: "POST",
            target_uri: URI,
            headers: &borrowed,
            body,
        };
        let context = GnapHttpsigContext {
            jwk: &s.jwk,
            proof_alg: None,
            content_digest_alg: None,
            bound_to_token: false,
            now: NOW,
            nonce_scope: "t",
        };
        let strict = HttpsigPolicy {
            require_nonce: true,
            ..HttpsigPolicy::default()
        };
        assert!(matches!(
            verify_gnap_request(&request, &context, &strict, &mut NonceCache::new()),
            Err(HttpsigError::PolicyViolation(_))
        ));
        assert!(
            verify_gnap_request(
                &request,
                &context,
                &HttpsigPolicy::default(),
                &mut NonceCache::new()
            )
            .is_ok()
        );
    }

    #[test]
    fn two_tagged_signatures_are_ambiguous_and_an_untagged_one_is_ignored() {
        let s = signer();
        let body = b"{}";
        let mut headers = signed(&s, body, FULL, &params(""), None);
        // add an unrelated, untagged second signature: ignored
        headers.push((
            "Signature-Input".into(),
            "other=(\"@method\");created=1".into(),
        ));
        headers.push(("Signature".into(), "other=:AAAA:".into()));
        assert!(check(&s, &headers, body, false, &mut NonceCache::new()).is_ok());
        // a second tagged one: ambiguous
        headers.push((
            "Signature-Input".into(),
            format!(
                "sig2=(\"@method\" \"@target-uri\" \"content-digest\"){}",
                params("")
            ),
        ));
        headers.push(("Signature".into(), "sig2=:AAAA:".into()));
        assert!(matches!(
            refused(&headers, &s, body, false),
            HttpsigError::PolicyViolation(_)
        ));
    }

    #[test]
    fn keys_that_cannot_be_used_are_refused() {
        // private members: each is refused although the rest of the key is well formed
        let s = signer();
        assert!(
            parse_key(&s.jwk, None).is_ok(),
            "control: the public key parses"
        );
        for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            let mut with_private = s.jwk.clone();
            with_private[private] = json!("AAAA");
            assert!(
                parse_key(&with_private, None).is_err(),
                "{private} must be refused"
            );
        }
        // alg that does not fit the key
        assert!(
            parse_key(
                &json!({"kty": "EC", "crv": "P-256", "alg": "ES384", "x": "AA", "y": "AA"}),
                None
            )
            .is_err()
        );
        // proof alg and JWK alg disagree
        assert!(parse_key(&s.jwk, Some("ecdsa-p384-sha384")).is_err());
        assert!(parse_key(&s.jwk, Some("ecdsa-p256-sha256")).is_ok());
        // RSA without an algorithm cannot be derived
        assert!(parse_key(&json!({"kty": "RSA", "n": "AQAB", "e": "AQAB"}), None).is_err());
        // HMAC and unknown types
        assert!(parse_key(&json!({"kty": "oct"}), None).is_err());
        // wrong coordinate length
        assert!(
            parse_key(
                &json!({"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_components_and_parameters_are_refused_not_guessed() {
        let s = signer();
        let body = b"{}";
        for covered in [
            "\"@method\" \"@target-uri\" \"content-digest\" \"@status\"",
            "\"@method\" \"@target-uri\" \"content-digest\" \"@request-target\"",
            "\"@method\" \"@target-uri\" \"content-digest\" \"@query-param\"",
        ] {
            let headers = signed_unchecked(&s, body, covered);
            assert!(
                matches!(
                    refused(&headers, &s, body, false),
                    HttpsigError::Malformed(_)
                ),
                "{covered}"
            );
        }
        // a component with a parameter
        let headers = signed_unchecked(
            &s,
            body,
            "\"@method\" \"@target-uri\" \"content-digest\" \"x-dict\";key=\"a\"",
        );
        assert!(matches!(
            refused(&headers, &s, body, false),
            HttpsigError::Malformed(_)
        ));
        // uppercase names
        let headers = signed_unchecked(&s, body, "\"@method\" \"@target-uri\" \"Content-Digest\"");
        assert!(matches!(
            refused(&headers, &s, body, false),
            HttpsigError::Malformed(_)
        ));
    }

    /// Headers with a Signature-Input that names components the signer cannot produce a base for; the
    /// signature is a placeholder, because the request must be refused before any signature is checked.
    fn signed_unchecked(_s: &Signer, body: &[u8], covered: &str) -> Vec<(String, String)> {
        vec![
            (
                "Content-Digest".into(),
                content_digest_header("sha-256", body).unwrap(),
            ),
            (
                "Signature-Input".into(),
                format!("sig1=({covered}){}", params("")),
            ),
            ("Signature".into(), "sig1=:AAAA:".into()),
        ]
    }

    #[test]
    fn derived_components_follow_rfc_9421_section_2_2() {
        let headers: Vec<(&str, &str)> = vec![];
        let request = HttpRequest {
            method: "GET",
            target_uri: "HTTPS://Example.COM:443/a/b?x=1&y=2#frag",
            headers: &headers,
            body: b"",
        };
        assert_eq!(component_value(&request, "@method").unwrap(), "GET");
        assert_eq!(component_value(&request, "@scheme").unwrap(), "https");
        assert_eq!(
            component_value(&request, "@authority").unwrap(),
            "example.com",
            "default port dropped, lowercased"
        );
        assert_eq!(component_value(&request, "@path").unwrap(), "/a/b");
        assert_eq!(component_value(&request, "@query").unwrap(), "?x=1&y=2");
        let non_default = HttpRequest {
            target_uri: "https://example.com:8443/",
            ..request
        };
        assert_eq!(
            component_value(&non_default, "@authority").unwrap(),
            "example.com:8443"
        );
        let no_query = HttpRequest {
            target_uri: "https://example.com",
            ..request
        };
        assert_eq!(component_value(&no_query, "@path").unwrap(), "/");
        assert_eq!(component_value(&no_query, "@query").unwrap(), "?");
        assert!(
            component_value(
                &HttpRequest {
                    target_uri: "/relative",
                    ..request
                },
                "@path"
            )
            .is_err()
        );
        assert!(
            component_value(
                &HttpRequest {
                    target_uri: "https://user@example.com/",
                    ..request
                },
                "@authority"
            )
            .is_err()
        );
    }

    #[test]
    fn header_values_are_joined_and_trimmed_and_a_newline_is_refused() {
        let headers = vec![("X-Multi", "  a "), ("x-multi", "b")];
        let request = HttpRequest {
            method: "GET",
            target_uri: "https://e.example/",
            headers: &headers,
            body: b"",
        };
        assert_eq!(component_value(&request, "x-multi").unwrap(), "a, b");
        assert!(component_value(&request, "x-missing").is_err());
        let folded = vec![("X-Fold", "a\r\n b")];
        let request = HttpRequest {
            headers: &folded,
            ..request
        };
        assert!(component_value(&request, "x-fold").is_err());
    }

    #[test]
    fn ed25519_keys_sign_and_verify_through_the_gnap_path() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": URL_SAFE.encode(pair.public_key().as_ref())});
        let params_line =
            format!("(\"@method\" \"@target-uri\");created={NOW};keyid=\"ed\";tag=\"gnap\"");
        let base = format!(
            "\"@method\": POST\n\"@target-uri\": {URI}\n\"@signature-params\": {params_line}"
        );
        let sig = pair.sign(base.as_bytes());
        let headers = [
            ("Signature-Input", format!("s={params_line}")),
            ("Signature", format!("s=:{}:", STD.encode(sig.as_ref()))),
        ];
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let request = HttpRequest {
            method: "POST",
            target_uri: URI,
            headers: &borrowed,
            body: b"",
        };
        let context = GnapHttpsigContext {
            jwk: &jwk,
            proof_alg: None,
            content_digest_alg: None,
            bound_to_token: false,
            now: NOW,
            nonce_scope: "t",
        };
        let got = verify_gnap_request(
            &request,
            &context,
            &HttpsigPolicy::default(),
            &mut NonceCache::new(),
        )
        .unwrap();
        assert_eq!(got.algorithm, HttpsigAlgorithm::Ed25519);
    }
}
