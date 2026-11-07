// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP interaction (RFC 9635 sections 2.5, 3.3 and 4.2), slice G4.
//!
//! The pure parts of interaction, with no state and no HTTP:
//!
//! * [`parse_start`], [`FinishRequest::parse`] and [`parse_ui_locales`] read the `interact` request
//!   (sections 2.5.1 to 2.5.3) and refuse what the RFC forbids.
//! * [`InteractionResponse`] builds the `interact` response (section 3.3): `redirect`, `app`, `user_code`,
//!   `user_code_uri`, `finish` and `expires_in`.
//! * [`interaction_hash`] and [`verify_interaction_hash`] are section 4.2.3, for `sha-256`, `sha-384` and
//!   `sha-512`. `sha3-*` and the other registry names are refused (`unsupported hash_method`) rather than
//!   guessed at.
//! * [`callback_redirect_url`] and [`callback_push_body`] build the two callbacks of sections 4.2.1 and 4.2.2.
//! * [`generate_user_code`], [`normalize_user_code`] and [`user_codes_equal`] implement the case-insensitive,
//!   typeable, unguessable short code of sections 3.3.3 and 3.3.4.
//! * [`validate_push_target`] is the SSRF guard section 11.34 asks of an AS that pushes.
//!
//! Which transactions exist, when an `interact_ref` is one-time, and how many wrong user codes are tolerated
//! are state, and belong to the grant state machine (slice G5).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use url::{Host, Url};

/// What went wrong, as a value that carries no request data (so it can be logged and compared freely).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionErrorKind {
    /// A field is missing, has the wrong type, or breaks a MUST of the RFC.
    InvalidRequest,
    /// `finish.method` is not `redirect` or `push`.
    UnknownFinishMethod,
    /// `finish.hash_method` is not one this implementation computes.
    UnsupportedHashMethod,
    /// `finish.uri` is not an absolute URI without a fragment, or its scheme is not allowed.
    BadCallbackUri,
    /// A nonce, reference or endpoint contains a control character, which would make the hash base string
    /// ambiguous.
    BadHashInput,
    /// A user code is outside the alphabet, or has a length the RFC does not recommend.
    BadUserCode,
    /// A response URI is relative, or (for `user_code_uri`) contains the code.
    BadResponseUri,
    /// The push target would make the AS call something on its own network (section 11.34).
    PushTargetNotAllowed,
}

/// An interaction error. [`InteractionError::gnap_error_code`] gives the RFC 9635 section 3.6 code to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractionError {
    /// The kind of failure.
    pub kind: InteractionErrorKind,
}

impl InteractionError {
    fn new(kind: InteractionErrorKind) -> Self {
        Self { kind }
    }

    /// The registered section 3.6 error code for this failure.
    pub fn gnap_error_code(&self) -> &'static str {
        match self.kind {
            InteractionErrorKind::InvalidRequest
            | InteractionErrorKind::UnknownFinishMethod
            | InteractionErrorKind::UnsupportedHashMethod
            | InteractionErrorKind::BadCallbackUri
            | InteractionErrorKind::BadHashInput
            | InteractionErrorKind::BadUserCode
            | InteractionErrorKind::BadResponseUri => "invalid_request",
            InteractionErrorKind::PushTargetNotAllowed => "invalid_interaction",
        }
    }
}

impl std::fmt::Display for InteractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "interaction refused: {:?}", self.kind)
    }
}

impl std::error::Error for InteractionError {}

fn err<T>(kind: InteractionErrorKind) -> Result<T, InteractionError> {
    Err(InteractionError::new(kind))
}

// ---- start modes (2.5.1) ----

/// An interaction start mode the client says it can perform (section 2.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartMode {
    /// `redirect`: send the end user to an arbitrary URI (2.5.1.1).
    Redirect,
    /// `app`: launch an application URI (2.5.1.2).
    App,
    /// `user_code`: display a short code (2.5.1.3).
    UserCode,
    /// `user_code_uri`: display a short code and a short URI (2.5.1.4).
    UserCodeUri,
    /// A mode this implementation does not know. The AS MAY respond to none of the modes it is offered
    /// (section 2.5), so an unknown mode is kept, not an error.
    Other,
}

/// Read the `interact.start` array: strings, or objects for extension modes (section 2.5.1).
///
/// The array may be empty (a client that cannot start interaction but can receive a push finish).
pub fn parse_start(start: &Value) -> Result<Vec<StartMode>, InteractionError> {
    let items = start
        .as_array()
        .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
    items
        .iter()
        .map(|item| match item {
            Value::String(name) => Ok(match name.as_str() {
                "redirect" => StartMode::Redirect,
                "app" => StartMode::App,
                "user_code" => StartMode::UserCode,
                "user_code_uri" => StartMode::UserCodeUri,
                _ => StartMode::Other,
            }),
            Value::Object(_) => Ok(StartMode::Other),
            _ => err(InteractionErrorKind::InvalidRequest),
        })
        .collect()
}

// ---- finish (2.5.2) ----

/// The `interact.finish` method (section 2.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishMethod {
    /// The AS sends the end user's browser to the client's URI with `hash` and `interact_ref` (4.2.1).
    Redirect,
    /// The AS POSTs `hash` and `interact_ref` to the client's URI (4.2.2).
    Push,
}

/// A hash method of the IANA Named Information Hash Algorithm Registry that this module computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashMethod {
    /// `sha-256`, the default when `hash_method` is absent (section 4.2.3).
    #[default]
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl HashMethod {
    /// Read `hash_method`; `None` is the default, `sha-256`. Any other name is refused.
    pub fn from_name(name: Option<&str>) -> Result<Self, InteractionError> {
        match name {
            None | Some("sha-256") => Ok(Self::Sha256),
            Some("sha-384") => Ok(Self::Sha384),
            Some("sha-512") => Ok(Self::Sha512),
            Some(_) => err(InteractionErrorKind::UnsupportedHashMethod),
        }
    }

    fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }
}

/// A validated `interact.finish` object.
#[derive(Clone, PartialEq, Eq)]
pub struct FinishRequest {
    /// `redirect` or `push`.
    pub method: FinishMethod,
    /// The client's callback URI: absolute, no fragment, https, loopback, or an application-specific scheme.
    pub uri: Url,
    /// The client's nonce, used in the interaction hash.
    pub nonce: String,
    /// The hash method for the callback hash.
    pub hash_method: HashMethod,
}

impl std::fmt::Debug for FinishRequest {
    // the nonce is a secret that only the two parties know until the callback
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishRequest")
            .field("method", &self.method)
            .field("uri_scheme", &self.uri.scheme())
            .field("nonce", &"[redacted]")
            .field("hash_method", &self.hash_method)
            .finish()
    }
}

/// Hierarchical schemes an application-specific callback must never use: they are not "an application-specific
/// URI scheme that is loaded on the end user's device" (2.5.2.1). Opaque schemes (`javascript:`, `data:`,
/// `blob:`, `about:`) are refused earlier, because a URI that cannot be a base has no place as a callback.
const FORBIDDEN_CALLBACK_SCHEMES: &[&str] = &["file", "ftp", "ws", "wss", "gopher"];

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

impl FinishRequest {
    /// Read and validate the `finish` object (section 2.5.2).
    ///
    /// * `method` is `redirect` or `push`.
    /// * `uri` is absolute and has no fragment; `http` is accepted only for a loopback host (2.5.2.1 and
    ///   2.5.2.2: HTTPS, "localhost", or an application-specific scheme).
    /// * `nonce` is non-empty ASCII with no control character, because it is joined with newlines in the hash
    ///   base string.
    /// * `hash_method`, if present, is one this module computes.
    pub fn parse(finish: &Value) -> Result<Self, InteractionError> {
        let object = finish
            .as_object()
            .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
        let method = match object.get("method").and_then(Value::as_str) {
            Some("redirect") => FinishMethod::Redirect,
            Some("push") => FinishMethod::Push,
            Some(_) => return err(InteractionErrorKind::UnknownFinishMethod),
            None => return err(InteractionErrorKind::InvalidRequest),
        };
        let uri_text = object
            .get("uri")
            .and_then(Value::as_str)
            .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
        let uri = Url::parse(uri_text)
            .map_err(|_| InteractionError::new(InteractionErrorKind::BadCallbackUri))?;
        if uri.fragment().is_some() || uri.cannot_be_a_base() {
            return err(InteractionErrorKind::BadCallbackUri);
        }
        match uri.scheme() {
            "https" => {
                if uri.host().is_none() {
                    return err(InteractionErrorKind::BadCallbackUri);
                }
            }
            "http" => {
                let loopback = uri.host().as_ref().is_some_and(is_loopback_host);
                if !loopback {
                    return err(InteractionErrorKind::BadCallbackUri);
                }
            }
            scheme if FORBIDDEN_CALLBACK_SCHEMES.contains(&scheme) => {
                return err(InteractionErrorKind::BadCallbackUri);
            }
            _ => {
                // an application-specific scheme, which is only meaningful for a browser redirect
                if method == FinishMethod::Push {
                    return err(InteractionErrorKind::BadCallbackUri);
                }
            }
        }
        let nonce = object
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
        if nonce.is_empty() {
            return err(InteractionErrorKind::InvalidRequest);
        }
        check_hash_input(nonce)?;
        let hash_method = match object.get("hash_method") {
            None => HashMethod::Sha256,
            Some(Value::String(name)) => HashMethod::from_name(Some(name))?,
            Some(_) => return err(InteractionErrorKind::InvalidRequest),
        };
        Ok(Self {
            method,
            uri,
            nonce: nonce.to_string(),
            hash_method,
        })
    }
}

// ---- hints (2.5.3) ----

/// Read `interact.hints.ui_locales` (section 2.5.3.1): an array of RFC 5646 language tags. Only the shape is
/// checked (ASCII letters, digits and hyphens, at most 35 characters, which covers every registered tag);
/// the AS decides what it can serve.
pub fn parse_ui_locales(hints: &Value) -> Result<Vec<String>, InteractionError> {
    let Some(locales) = hints.get("ui_locales") else {
        return Ok(Vec::new());
    };
    let items = locales
        .as_array()
        .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
    items
        .iter()
        .map(|item| {
            let tag = item
                .as_str()
                .ok_or(InteractionError::new(InteractionErrorKind::InvalidRequest))?;
            let ok = !tag.is_empty()
                && tag.len() <= 35
                && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !tag.starts_with('-')
                && !tag.ends_with('-')
                && !tag.contains("--");
            if ok {
                Ok(tag.to_string())
            } else {
                err(InteractionErrorKind::InvalidRequest)
            }
        })
        .collect()
}

// ---- the interaction hash (4.2.3) ----

fn check_hash_input(value: &str) -> Result<(), InteractionError> {
    if value.is_ascii() && !value.chars().any(|c| c.is_ascii_control()) {
        Ok(())
    } else {
        err(InteractionErrorKind::BadHashInput)
    }
}

/// The interaction hash of RFC 9635 section 4.2.3: the hash, in the chosen method, of
/// `client_nonce \n as_nonce \n interact_ref \n grant_endpoint` (no padding, no trailing newline), as
/// URL-safe base64 without padding.
///
/// `grant_endpoint` is the absolute URI the client used for its initial request (section 2), not a path.
/// Every input must be ASCII without control characters, so that no value can contain the separator.
pub fn interaction_hash(
    client_nonce: &str,
    as_nonce: &str,
    interact_ref: &str,
    grant_endpoint: &str,
    method: HashMethod,
) -> Result<String, InteractionError> {
    for part in [client_nonce, as_nonce, interact_ref, grant_endpoint] {
        check_hash_input(part)?;
    }
    let base = format!("{client_nonce}\n{as_nonce}\n{interact_ref}\n{grant_endpoint}");
    Ok(B64.encode(method.digest(base.as_bytes())))
}

/// Check a received `hash` against the one computed from the same inputs, in constant time. `false` for
/// anything that does not match, including inputs that cannot be hashed.
pub fn verify_interaction_hash(
    client_nonce: &str,
    as_nonce: &str,
    interact_ref: &str,
    grant_endpoint: &str,
    method: HashMethod,
    given: &str,
) -> bool {
    match interaction_hash(client_nonce, as_nonce, interact_ref, grant_endpoint, method) {
        Ok(expected) => bool::from(expected.as_bytes().ct_eq(given.as_bytes())),
        Err(_) => false,
    }
}

// ---- callbacks (4.2.1, 4.2.2, 11.19) ----

/// The status code for the redirect that sends the end user back to the client (section 11.19): never 307,
/// which would resubmit a credential form to the client.
pub const CALLBACK_REDIRECT_STATUS: u16 = 303;

/// The URI of a `redirect` callback (section 4.2.1): the client's URI with `hash` and `interact_ref` added as
/// query parameters, keeping any query the client already had.
pub fn callback_redirect_url(finish_uri: &Url, hash: &str, interact_ref: &str) -> Url {
    let mut url = finish_uri.clone();
    url.query_pairs_mut()
        .append_pair("hash", hash)
        .append_pair("interact_ref", interact_ref);
    url
}

/// The JSON body of a `push` callback (section 4.2.2).
pub fn callback_push_body(hash: &str, interact_ref: &str) -> Value {
    json!({ "hash": hash, "interact_ref": interact_ref })
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.octets()[0] == 0
        // 100.64.0.0/10 shared address space (carrier-grade NAT)
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40)
        || ip.octets()[0] >= 240
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return blocked_v4(v4);
    }
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        // fc00::/7 unique local, fe80::/10 link local
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        // 2001:db8::/32 documentation
        || (first == 0x2001 && ip.segments()[1] == 0x0db8)
}

/// The SSRF guard for a `push` callback (section 11.34): refuse a URI the AS should not call. It must be
/// `https` with a host; `localhost` and every IP literal in a loopback, private, link-local (including the
/// cloud metadata address), shared or documentation range is refused, as are credentials in the URI.
///
/// A host name can still resolve to such an address: the integrator must resolve it itself and apply
/// [`push_address_allowed`] to the result before connecting.
pub fn validate_push_target(uri: &Url) -> Result<(), InteractionError> {
    let blocked = InteractionError::new(InteractionErrorKind::PushTargetNotAllowed);
    if uri.scheme() != "https" || !uri.username().is_empty() || uri.password().is_some() {
        return Err(blocked);
    }
    match uri.host() {
        None => Err(blocked),
        Some(Host::Domain(name)) => {
            let lower = name.to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal")
            {
                Err(blocked)
            } else {
                Ok(())
            }
        }
        Some(Host::Ipv4(ip)) => (!blocked_v4(ip)).then_some(()).ok_or(blocked),
        Some(Host::Ipv6(ip)) => (!blocked_v6(ip)).then_some(()).ok_or(blocked),
    }
}

/// Whether the AS may connect to an address a push target resolved to (section 11.34).
pub fn push_address_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !blocked_v4(v4),
        IpAddr::V6(v6) => !blocked_v6(v6),
    }
}

// ---- user codes (3.3.3, 3.3.4) ----

/// The characters of a generated user code: ASCII upper-case letters and digits without the pairs that are
/// easily confused (`I`/`1`, `O`/`0`). 32 symbols, so each random byte maps to a symbol without bias.
const USER_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Generate a random user code of `len` characters. The RFC recommends six to eight (3.3.3); other lengths
/// are refused. With 32 symbols, six characters are 30 bits: the AS must still expire the code in minutes
/// and limit wrong guesses (state, slice G5).
pub fn generate_user_code(len: usize) -> Result<String, InteractionError> {
    if !(6..=8).contains(&len) {
        return err(InteractionErrorKind::BadUserCode);
    }
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes[..len])
        .map_err(|_| InteractionError::new(InteractionErrorKind::BadUserCode))?;
    Ok(bytes[..len]
        .iter()
        .map(|b| USER_CODE_ALPHABET[(b & 31) as usize] as char)
        .collect())
}

/// Normalise what a person typed so a code is matched case-insensitively (sections 3.3.3 and 3.3.4): ASCII
/// letters are upper-cased, and spaces and hyphens (a code is often shown as `ABCD-EFGH`) are dropped. Anything
/// else outside the alphabet is refused.
pub fn normalize_user_code(input: &str) -> Result<String, InteractionError> {
    let normalized: String = input
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty()
        || normalized.len() > 8
        || !normalized.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))
    {
        return err(InteractionErrorKind::BadUserCode);
    }
    Ok(normalized)
}

/// Compare a typed code with the issued one, case-insensitively and in constant time.
pub fn user_codes_equal(typed: &str, issued: &str) -> bool {
    match (normalize_user_code(typed), normalize_user_code(issued)) {
        (Ok(a), Ok(b)) => bool::from(a.as_bytes().ct_eq(b.as_bytes())),
        _ => false,
    }
}

// ---- the interact response (3.3) ----

/// The pieces of an `interact` response (section 3.3). Fill in only what the AS offers; a mode the client did
/// not ask for should not be set (the AS decides, section 2.5).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct InteractionResponse {
    /// `redirect` (3.3.1): an absolute URI the end user is sent to.
    pub redirect: Option<Url>,
    /// `app` (3.3.2): an absolute application URI.
    pub app: Option<Url>,
    /// `user_code` (3.3.3): the short code.
    pub user_code: Option<String>,
    /// `user_code_uri` (3.3.4): the short code and the absolute URI to type it into.
    pub user_code_uri: Option<(String, Url)>,
    /// `finish` (3.3.5): the AS's nonce, present when the client asked for a finish method.
    pub finish_nonce: Option<String>,
    /// `expires_in` (3.3): seconds until the interaction expires.
    pub expires_in: Option<u64>,
}

impl std::fmt::Debug for InteractionResponse {
    // codes and nonces are the secrets of the exchange
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractionResponse")
            .field("redirect", &self.redirect.as_ref().map(Url::as_str))
            .field("app", &self.app.as_ref().map(Url::as_str))
            .field("user_code", &self.user_code.as_ref().map(|_| "[redacted]"))
            .field(
                "user_code_uri",
                &self.user_code_uri.as_ref().map(|(_, u)| u.as_str()),
            )
            .field(
                "finish_nonce",
                &self.finish_nonce.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl InteractionResponse {
    /// Build the `interact` JSON object, checking what the RFC requires: codes are in the user-code alphabet,
    /// the `user_code_uri` URI is absolute and does not contain its code, the finish nonce can be hashed, and
    /// `expires_in` is not zero.
    pub fn to_json(&self) -> Result<Value, InteractionError> {
        let mut out = Map::new();
        if let Some(url) = &self.redirect {
            check_absolute(url)?;
            out.insert("redirect".into(), json!(url.as_str()));
        }
        if let Some(url) = &self.app {
            check_absolute(url)?;
            out.insert("app".into(), json!(url.as_str()));
        }
        if let Some(code) = &self.user_code {
            out.insert("user_code".into(), json!(checked_code(code)?));
        }
        if let Some((code, url)) = &self.user_code_uri {
            check_absolute(url)?;
            let code = checked_code(code)?;
            let haystack = url.as_str().to_ascii_uppercase();
            if haystack.contains(&code) {
                return err(InteractionErrorKind::BadResponseUri);
            }
            out.insert(
                "user_code_uri".into(),
                json!({ "code": code, "uri": url.as_str() }),
            );
        }
        if let Some(nonce) = &self.finish_nonce {
            if nonce.is_empty() {
                return err(InteractionErrorKind::InvalidRequest);
            }
            check_hash_input(nonce)?;
            out.insert("finish".into(), json!(nonce));
        }
        if let Some(seconds) = self.expires_in {
            if seconds == 0 {
                return err(InteractionErrorKind::InvalidRequest);
            }
            out.insert("expires_in".into(), json!(seconds));
        }
        Ok(Value::Object(out))
    }
}

/// A response URI must be absolute (a parsed [`Url`] always is) and must not be a scheme that makes a browser
/// run or read something instead of showing a page to the user.
fn check_absolute(url: &Url) -> Result<(), InteractionError> {
    if url.cannot_be_a_base() || FORBIDDEN_CALLBACK_SCHEMES.contains(&url.scheme()) {
        err(InteractionErrorKind::BadResponseUri)
    } else {
        Ok(())
    }
}

fn checked_code(code: &str) -> Result<String, InteractionError> {
    let normalized = normalize_user_code(code)?;
    if (6..=8).contains(&normalized.len()) {
        Ok(normalized)
    } else {
        err(InteractionErrorKind::BadUserCode)
    }
}

/// Whether an interaction issued at `issued_at` with a lifetime of `ttl_secs` has expired at `now` (all Unix
/// seconds). Expired exactly at the deadline, so a code is never accepted late; a clock that went backwards
/// does not extend it past `ttl_secs` of the issue time.
pub fn interaction_expired(issued_at: u64, ttl_secs: u64, now: u64) -> bool {
    now >= issued_at.saturating_add(ttl_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9635 section 4.2.3 example inputs and outputs
    const CLIENT_NONCE: &str = "VJLO6A4CATR0KRO";
    const AS_NONCE: &str = "MBDOFXG4Y5CVJCX821LH";
    const INTERACT_REF: &str = "4IFWWIKYB2PQ6U56NL1";
    const GRANT: &str = "https://server.example.com/tx";
    const SHA256_EXPECTED: &str = "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY";

    #[test]
    fn the_rfc_hash_example_is_reproduced() {
        let hash = interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            HashMethod::Sha256,
        )
        .unwrap();
        assert_eq!(hash, SHA256_EXPECTED);
        assert!(verify_interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            HashMethod::Sha256,
            SHA256_EXPECTED
        ));
    }

    #[test]
    fn each_input_of_the_hash_matters_and_the_methods_differ() {
        let ok = |c: &str, a: &str, r: &str, g: &str, m| {
            verify_interaction_hash(c, a, r, g, m, SHA256_EXPECTED)
        };
        let m = HashMethod::Sha256;
        assert!(ok(CLIENT_NONCE, AS_NONCE, INTERACT_REF, GRANT, m));
        assert!(!ok("X", AS_NONCE, INTERACT_REF, GRANT, m));
        assert!(!ok(CLIENT_NONCE, "X", INTERACT_REF, GRANT, m));
        assert!(!ok(CLIENT_NONCE, AS_NONCE, "X", GRANT, m));
        assert!(!ok(CLIENT_NONCE, AS_NONCE, INTERACT_REF, "/tx", m));
        // a relative endpoint is a different input (the existing code hashed the path)
        assert!(!ok(CLIENT_NONCE, AS_NONCE, INTERACT_REF, "tx", m));
        // other methods give other values; a hash of the wrong method is refused
        let h512 = interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            HashMethod::Sha512,
        )
        .unwrap();
        let h384 = interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            HashMethod::Sha384,
        )
        .unwrap();
        assert_eq!(B64.decode(&h512).unwrap().len(), 64);
        assert_eq!(B64.decode(&h384).unwrap().len(), 48);
        assert_ne!(h512, h384);
        assert!(!ok(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            HashMethod::Sha512
        ));
        // a truncated or extended hash is refused
        let cut = &SHA256_EXPECTED[..SHA256_EXPECTED.len() - 1];
        assert!(!verify_interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            m,
            cut
        ));
        assert!(!verify_interaction_hash(
            CLIENT_NONCE,
            AS_NONCE,
            INTERACT_REF,
            GRANT,
            m,
            &format!("{SHA256_EXPECTED}A")
        ));
    }

    #[test]
    fn a_separator_inside_an_input_cannot_move_the_boundary() {
        // "a\nb" + "c" and "a" + "b\nc" would hash alike if newlines were allowed in a part
        for bad in ["a\nb", "a\r", "caf\u{e9}", "a\u{0}b"] {
            assert_eq!(
                interaction_hash(bad, AS_NONCE, INTERACT_REF, GRANT, HashMethod::Sha256)
                    .unwrap_err()
                    .kind,
                InteractionErrorKind::BadHashInput,
                "{bad:?}"
            );
        }
        assert!(!verify_interaction_hash(
            "a\nb",
            "c",
            "d",
            GRANT,
            HashMethod::Sha256,
            "anything"
        ));
    }

    #[test]
    fn hash_method_defaults_to_sha256_and_refuses_the_unknown() {
        assert_eq!(HashMethod::from_name(None).unwrap(), HashMethod::Sha256);
        assert_eq!(
            HashMethod::from_name(Some("sha-512")).unwrap(),
            HashMethod::Sha512
        );
        for name in ["sha3-512", "SHA-256", "md5", "sha-1", ""] {
            assert_eq!(
                HashMethod::from_name(Some(name)).unwrap_err().kind,
                InteractionErrorKind::UnsupportedHashMethod,
                "{name}"
            );
        }
    }

    #[test]
    fn the_rfc_finish_examples_parse() {
        let redirect = json!({
            "method": "redirect",
            "uri": "https://client.example.net/return/123455",
            "nonce": "LKLTI25DK82FX4T4QFZC"
        });
        let f = FinishRequest::parse(&redirect).unwrap();
        assert_eq!(f.method, FinishMethod::Redirect);
        assert_eq!(f.hash_method, HashMethod::Sha256);
        let push = json!({
            "method": "push",
            "uri": "https://client.example.net/return/123455",
            "nonce": "LKLTI25DK82FX4T4QFZC",
            "hash_method": "sha-512"
        });
        let f = FinishRequest::parse(&push).unwrap();
        assert_eq!(
            (f.method, f.hash_method),
            (FinishMethod::Push, HashMethod::Sha512)
        );
        assert!(!format!("{f:?}").contains("LKLTI25DK82FX4T4QFZC"));
    }

    fn finish_with(patch: impl FnOnce(&mut Value)) -> Result<FinishRequest, InteractionError> {
        let mut v = json!({
            "method": "redirect",
            "uri": "https://client.example.net/return/123455",
            "nonce": "LKLTI25DK82FX4T4QFZC"
        });
        patch(&mut v);
        FinishRequest::parse(&v)
    }

    #[test]
    fn each_finish_rule_is_enforced() {
        use InteractionErrorKind::*;
        let kind = |r: Result<FinishRequest, InteractionError>| r.unwrap_err().kind;
        assert_eq!(
            kind(finish_with(|v| v["method"] = json!("poll"))),
            UnknownFinishMethod
        );
        assert_eq!(
            kind(finish_with(|v| {
                v.as_object_mut().unwrap().remove("method");
            })),
            InvalidRequest
        );
        assert_eq!(
            kind(finish_with(|v| {
                v.as_object_mut().unwrap().remove("uri");
            })),
            InvalidRequest
        );
        assert_eq!(
            kind(finish_with(|v| {
                v.as_object_mut().unwrap().remove("nonce");
            })),
            InvalidRequest
        );
        assert_eq!(
            kind(finish_with(|v| v["nonce"] = json!(""))),
            InvalidRequest
        );
        assert_eq!(
            kind(finish_with(|v| v["nonce"] = json!("a\nb"))),
            BadHashInput
        );
        assert_eq!(
            kind(finish_with(|v| v["uri"] = json!("/return/1"))),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(|v| v["uri"] = json!("https://c.example/r#frag"))),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(
                |v| v["uri"] = json!("http://client.example.net/r")
            )),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(|v| v["uri"] = json!("javascript:alert(1)"))),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(|v| v["uri"] = json!("data:text/html,x"))),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(|v| v["uri"] = json!("file:///etc/passwd"))),
            BadCallbackUri
        );
        assert_eq!(
            kind(finish_with(|v| v["hash_method"] = json!("sha3-512"))),
            UnsupportedHashMethod
        );
        assert_eq!(
            kind(finish_with(|v| v["hash_method"] = json!(5))),
            InvalidRequest
        );
        for bad in [
            "ftp://c.example/x",
            "ws://c.example/x",
            "wss://c.example/x",
            "gopher://c.example/x",
        ] {
            assert_eq!(
                kind(finish_with(|v| v["uri"] = json!(bad))),
                BadCallbackUri,
                "{bad}"
            );
        }
        // push needs a URI the AS can call: an application scheme is for a browser redirect only
        assert_eq!(
            kind(finish_with(|v| {
                v["method"] = json!("push");
                v["uri"] = json!("com.example.app:/cb");
            })),
            BadCallbackUri
        );
        // controls: loopback http, an application scheme for redirect, and an https push are accepted
        assert!(finish_with(|v| v["uri"] = json!("http://localhost:8080/cb")).is_ok());
        assert!(finish_with(|v| v["uri"] = json!("http://127.0.0.1:8080/cb")).is_ok());
        assert!(finish_with(|v| v["uri"] = json!("http://[::1]:8080/cb")).is_ok());
        assert!(finish_with(|v| v["uri"] = json!("com.example.app:/cb")).is_ok());
        assert!(finish_with(|v| v["method"] = json!("push")).is_ok());
        assert_eq!(
            kind(FinishRequest::parse(&json!("redirect"))),
            InvalidRequest
        );
    }

    #[test]
    fn start_modes_are_read_and_the_unknown_are_kept() {
        let modes = parse_start(
            &json!(["redirect", "app", "user_code", "user_code_uri", "qr", {"mode": "x"}]),
        )
        .unwrap();
        assert_eq!(
            modes,
            vec![
                StartMode::Redirect,
                StartMode::App,
                StartMode::UserCode,
                StartMode::UserCodeUri,
                StartMode::Other,
                StartMode::Other
            ]
        );
        assert!(parse_start(&json!([])).unwrap().is_empty());
        assert!(parse_start(&json!("redirect")).is_err());
        assert!(parse_start(&json!([1])).is_err());
    }

    #[test]
    fn ui_locales_are_checked_for_shape() {
        assert_eq!(
            parse_ui_locales(&json!({"ui_locales": ["en-US", "fr-CA"]})).unwrap(),
            vec!["en-US", "fr-CA"]
        );
        assert!(parse_ui_locales(&json!({})).unwrap().is_empty());
        for bad in [
            json!({"ui_locales": "en"}),
            json!({"ui_locales": [1]}),
            json!({"ui_locales": [""]}),
            json!({"ui_locales": ["en_US"]}),
            json!({"ui_locales": ["-en"]}),
            json!({"ui_locales": ["en--US"]}),
            json!({"ui_locales": ["x".repeat(36)]}),
        ] {
            assert!(parse_ui_locales(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_rfc_callback_examples_are_built() {
        let url = callback_redirect_url(
            &Url::parse("https://client.example.net/return/123455").unwrap(),
            "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY",
            "4IFWWIKYBC2PQ6U56NL1",
        );
        assert_eq!(
            url.as_str(),
            "https://client.example.net/return/123455?hash=x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY&interact_ref=4IFWWIKYBC2PQ6U56NL1"
        );
        // an existing query is kept and a value that needs escaping is escaped
        let url = callback_redirect_url(
            &Url::parse("https://c.example/r?state=abc").unwrap(),
            "h",
            "a&b=c",
        );
        assert_eq!(
            url.as_str(),
            "https://c.example/r?state=abc&hash=h&interact_ref=a%26b%3Dc"
        );
        assert_eq!(
            callback_push_body("h", "r"),
            json!({"hash": "h", "interact_ref": "r"})
        );
        assert_eq!(CALLBACK_REDIRECT_STATUS, 303);
    }

    #[test]
    fn the_push_target_guard_refuses_the_ases_own_network() {
        let blocked = |s: &str| validate_push_target(&Url::parse(s).unwrap()).is_err();
        for s in [
            "https://localhost/cb",
            "https://LOCALHOST/cb",
            "https://app.localhost/cb",
            "https://metadata.internal/cb",
            "https://127.0.0.1/cb",
            "https://10.0.0.5/cb",
            "https://172.16.0.1/cb",
            "https://192.168.1.1/cb",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/cb",
            "https://0.0.0.0/cb",
            "https://[::1]/cb",
            "https://[fd00::1]/cb",
            "https://[fe80::1]/cb",
            "https://[::ffff:10.0.0.1]/cb",
            "http://client.example.net/cb",
            "https://user:pw@client.example.net/cb",
            "https://u@client.example.net/cb",
        ] {
            assert!(blocked(s), "{s}");
        }
        for s in [
            "https://client.example.net/cb",
            "https://93.184.216.34/x",
            "https://[2606:2800:220:1::1]/cb",
        ] {
            assert!(!blocked(s), "{s}");
        }
        assert!(!push_address_allowed("10.1.2.3".parse().unwrap()));
        assert!(!push_address_allowed("::1".parse().unwrap()));
        assert!(push_address_allowed("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn user_codes_are_random_typeable_and_case_insensitive() {
        for len in 6..=8 {
            let code = generate_user_code(len).unwrap();
            assert_eq!(code.len(), len);
            assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
        }
        for bad in [0, 5, 9, 64] {
            assert_eq!(
                generate_user_code(bad).unwrap_err().kind,
                InteractionErrorKind::BadUserCode
            );
        }
        // every symbol of the alphabet is reachable (no byte-to-symbol mapping that drops half of them)
        let seen: std::collections::HashSet<char> = (0..400)
            .flat_map(|_| generate_user_code(8).unwrap().chars().collect::<Vec<_>>())
            .collect();
        assert_eq!(seen.len(), USER_CODE_ALPHABET.len());
        let a = generate_user_code(8).unwrap();
        let b = generate_user_code(8).unwrap();
        assert_ne!(a, b, "two 40-bit codes collided");
        // typing: lower case, a space, a hyphen
        assert!(user_codes_equal("a2bc3dff", "A2BC3DFF"));
        assert!(user_codes_equal("abcd-efgh", "ABCDEFGH"));
        assert!(user_codes_equal(" ab cd efgh ", "ABCDEFGH"));
        assert!(!user_codes_equal("ABCDEFGJ", "ABCDEFGH"));
        assert!(!user_codes_equal("ABCDEFG", "ABCDEFGH"));
        assert!(!user_codes_equal("", ""));
        // characters outside the alphabet are refused, not ignored
        for bad in [
            "ABCDEF0H",
            "ABCDEFIH",
            "ABCDEF!H",
            "ABCDEFGHJ",
            "\u{e9}BCDEFGH",
        ] {
            assert_eq!(
                normalize_user_code(bad).unwrap_err().kind,
                InteractionErrorKind::BadUserCode,
                "{bad}"
            );
        }
    }

    #[test]
    fn the_rfc_response_examples_are_built() {
        let user_code = InteractionResponse {
            user_code: Some("A2BC3DFF".into()),
            ..Default::default()
        };
        assert_eq!(
            user_code.to_json().unwrap(),
            json!({"user_code": "A2BC3DFF"})
        );
        let both = InteractionResponse {
            redirect: Some(
                Url::parse("https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ").unwrap(),
            ),
            app: Some(Url::parse("https://app.example/launch?tx=1").unwrap()),
            user_code_uri: Some((
                "A2BC3DFF".into(),
                Url::parse("https://s.example/device").unwrap(),
            )),
            finish_nonce: Some("MBDOFXG4Y5CVJCX821LH".into()),
            expires_in: Some(300),
            ..Default::default()
        };
        assert_eq!(
            both.to_json().unwrap(),
            json!({
                "redirect": "https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ",
                "app": "https://app.example/launch?tx=1",
                "user_code_uri": {"code": "A2BC3DFF", "uri": "https://s.example/device"},
                "finish": "MBDOFXG4Y5CVJCX821LH",
                "expires_in": 300
            })
        );
        assert_eq!(InteractionResponse::default().to_json().unwrap(), json!({}));
        let debug = format!("{both:?}");
        assert!(!debug.contains("MBDOFXG4Y5CVJCX821LH") && !debug.contains("A2BC3DFF"));
    }

    #[test]
    fn each_response_rule_is_enforced() {
        use InteractionErrorKind::*;
        let kind = |r: InteractionResponse| r.to_json().unwrap_err().kind;
        // a user_code_uri URI must not contain the code, in any case
        let leaky = |u: &str| InteractionResponse {
            user_code_uri: Some(("A2BC3DFF".into(), Url::parse(u).unwrap())),
            ..Default::default()
        };
        assert_eq!(
            kind(leaky("https://s.example/device?c=A2BC3DFF")),
            BadResponseUri
        );
        assert_eq!(kind(leaky("https://s.example/a2bc3dff")), BadResponseUri);
        assert!(leaky("https://s.example/device").to_json().is_ok());
        // codes: alphabet and length (the RFC recommends six to eight)
        for bad in ["SHORT", "A2BC3DF0", "A2BC3DFFG"] {
            let r = InteractionResponse {
                user_code: Some(bad.into()),
                ..Default::default()
            };
            assert_eq!(kind(r), BadUserCode, "{bad}");
        }
        let r = InteractionResponse {
            user_code: Some("A2B".into()),
            ..Default::default()
        };
        assert_eq!(kind(r), BadUserCode);
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
        ] {
            let r = InteractionResponse {
                redirect: Some(Url::parse(bad).unwrap()),
                ..Default::default()
            };
            assert_eq!(kind(r), BadResponseUri, "{bad}");
        }
        // finish nonce and expiry
        let r = InteractionResponse {
            finish_nonce: Some("a\nb".into()),
            ..Default::default()
        };
        assert_eq!(kind(r), BadHashInput);
        let r = InteractionResponse {
            finish_nonce: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(kind(r), InvalidRequest);
        let r = InteractionResponse {
            expires_in: Some(0),
            ..Default::default()
        };
        assert_eq!(kind(r), InvalidRequest);
    }

    #[test]
    fn expiry_is_exact_and_does_not_overflow() {
        assert!(!interaction_expired(100, 300, 399));
        assert!(interaction_expired(100, 300, 400));
        assert!(interaction_expired(100, 300, 401));
        assert!(
            !interaction_expired(100, 300, 50),
            "a clock before the issue time is not expired"
        );
        assert!(!interaction_expired(u64::MAX, 300, u64::MAX - 1));
        assert!(interaction_expired(u64::MAX, 300, u64::MAX));
    }

    #[test]
    fn errors_map_to_registered_codes() {
        use InteractionErrorKind::*;
        for kind in [
            InvalidRequest,
            UnknownFinishMethod,
            UnsupportedHashMethod,
            BadCallbackUri,
            BadHashInput,
            BadUserCode,
            BadResponseUri,
        ] {
            assert_eq!(
                InteractionError::new(kind).gnap_error_code(),
                "invalid_request"
            );
        }
        assert_eq!(
            InteractionError::new(PushTargetNotAllowed).gnap_error_code(),
            "invalid_interaction"
        );
    }
}
