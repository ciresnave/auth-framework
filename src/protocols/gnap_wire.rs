// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP wire types of RFC 9635 (slice G1 of `docs/GNAP_RFC9635_GAP.md`).
//!
//! These are the JSON structures of the protocol, with the polymorphism of RFC 9635 Appendix E: a field that
//! is "an object or an array of objects" (`access_token`), "an object or a string" (`client`, `user`, `key`,
//! an access right) is one Rust type that accepts both and serializes the form it holds. They validate what
//! the RFC says a message must satisfy and nothing else; no HTTP, no proofing, no state. The types of
//! [`crate::protocols::gnap`] are unchanged, and later slices (G2 to G5) move the service onto these.
//!
//! Every rule below cites the RFC section it comes from.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// A value that the RFC allows as one item or as an array of items (RFC 9635 section 2.1: `access_token`
/// is "an object ... or an array of these objects").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single item.
    One(T),
    /// An array of items.
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// The items as a slice, whichever form arrived.
    pub fn as_slice(&self) -> &[T] {
        match self {
            OneOrMany::One(one) => std::slice::from_ref(one),
            OneOrMany::Many(many) => many,
        }
    }

    /// True when the sender used the array form (multiple access tokens, section 2.1.2).
    pub fn is_many(&self) -> bool {
        matches!(self, OneOrMany::Many(_))
    }
}

/// An access right (RFC 9635 section 8): an object (8.2) or a string that references a right the AS and
/// the client both know (8.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapAccess {
    /// A reference to a pre-agreed right (section 8.1).
    Reference(String),
    /// A described right (section 8.2).
    Object(GnapAccessObject),
}

/// An access right object (RFC 9635 section 8.2). `type` is the only required field.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GnapAccessObject {
    /// The API type (section 8.2, REQUIRED).
    #[serde(rename = "type")]
    pub access_type: String,
    /// What may be done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    /// Where the API is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    /// The kinds of data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,
    /// A specific resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Privileges at the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,
    /// Fields an extension defines; kept so a round trip loses nothing.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One requested access token (RFC 9635 section 2.1.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapAccessTokenRequest {
    /// The rights requested (REQUIRED).
    pub access: Vec<GnapAccess>,
    /// The client's name for the token; echoed in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Requested attributes (`bearer`, or an extension's flag).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

/// The `access_token` field of a request: one token request or an array of them (section 2.1).
pub type GnapAccessTokenRequests = OneOrMany<GnapAccessTokenRequest>;

/// The flag that asks for a bearer token (RFC 9635 sections 2.1.1 and 3.2.1).
pub const FLAG_BEARER: &str = "bearer";

/// Check the rules of RFC 9635 sections 2.1.1 and 2.1.2 for a request's `access_token`.
///
/// * A flag listed twice is `invalid_flag` (2.1.1: "the AS MUST return an invalid_flag error").
/// * In the array form every entry needs a `label`, and labels are unique, else `invalid_request`
///   (2.1.2).
/// * A request with an empty array of tokens, or a token with no access, is `invalid_request`; so is an access
///   right whose `type` (or reference string) is empty.
///
/// This layer does not know which flags the AS supports, so it does **not** refuse an unknown flag: RFC 9635
/// section 2.1.1 requires the AS to answer `invalid_flag` for one, and the AS does that by calling
/// [`validate_access_token_requests_with_flags`] (or [`validate_request`]) with its own list. A caller that
/// uses only this function accepts any flag string.
pub fn validate_access_token_requests(requests: &GnapAccessTokenRequests) -> Result<(), GnapError> {
    let items = requests.as_slice();
    if items.is_empty() {
        return Err(GnapError::new(
            GnapErrorCode::InvalidRequest,
            "access_token is an empty array",
        ));
    }
    let mut labels = HashSet::new();
    for item in items {
        if item.access.is_empty() {
            return Err(GnapError::new(
                GnapErrorCode::InvalidRequest,
                "an access_token has no access",
            ));
        }
        for access in &item.access {
            let empty = match access {
                GnapAccess::Reference(reference) => reference.is_empty(),
                GnapAccess::Object(object) => object.access_type.is_empty(),
            };
            if empty {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidRequest,
                    "an access right has an empty type",
                ));
            }
        }
        let mut seen = HashSet::new();
        for flag in &item.flags {
            if !seen.insert(flag.as_str()) {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidFlag,
                    format!("the flag {flag:?} appears more than once"),
                ));
            }
        }
        if requests.is_many() {
            match &item.label {
                None => {
                    return Err(GnapError::new(
                        GnapErrorCode::InvalidRequest,
                        "every access_token in an array needs a label",
                    ));
                }
                Some(label) => {
                    if !labels.insert(label.as_str()) {
                        return Err(GnapError::new(
                            GnapErrorCode::InvalidRequest,
                            format!("the label {label:?} is not unique"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// [`validate_access_token_requests`], and every flag must be one of `supported_flags`, else `invalid_flag`
/// (RFC 9635 section 2.1.1: the AS MUST return `invalid_flag` for a flag it does not support).
pub fn validate_access_token_requests_with_flags(
    requests: &GnapAccessTokenRequests,
    supported_flags: &[&str],
) -> Result<(), GnapError> {
    validate_access_token_requests(requests)?;
    for item in requests.as_slice() {
        for flag in &item.flags {
            if !supported_flags.contains(&flag.as_str()) {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidFlag,
                    format!("the flag {flag:?} is not supported"),
                ));
            }
        }
    }
    Ok(())
}

/// Validate the parts of a grant request that this module models: the `access_token`, the `client` (and its
/// key) and the `user`. This is the one call the AS makes on an incoming request, so that no check depends on
/// the caller remembering it (the key and user checks are otherwise methods the caller has to know to call).
pub fn validate_request(
    access_token: Option<&GnapAccessTokenRequests>,
    client: Option<&GnapClientRef>,
    user: Option<&GnapUserRef>,
    supported_flags: &[&str],
) -> Result<(), GnapError> {
    if let Some(requests) = access_token {
        validate_access_token_requests_with_flags(requests, supported_flags)?;
    }
    if let Some(client) = client {
        client.validate()?;
    }
    if let Some(user) = user {
        user.validate()?;
    }
    Ok(())
}

/// A key (RFC 9635 section 7.1): an object, or a string that references a key both sides know (7.1.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapKeyRef {
    /// A key reference (section 7.1.1).
    Reference(String),
    /// A key by value (section 7.1).
    Object(GnapKeyObject),
}

/// A key by value (RFC 9635 section 7.1). `proof` and exactly one key format are required.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapKeyObject {
    /// The proofing method (`httpsig`, `mtls`, `jwsd`, `jws`; section 7.3).
    pub proof: String,
    /// The key as a JWK (section 7.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
    /// The key as a certificate, base64 DER (section 7.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    /// The key as the SHA-256 thumbprint of a certificate (section 7.1).
    #[serde(default, rename = "cert#S256", skip_serializing_if = "Option::is_none")]
    pub cert_s256: Option<String>,
}

impl fmt::Debug for GnapKeyObject {
    // A JWK may hold private members if a caller misuses the type; print the shape, never the values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnapKeyObject")
            .field("proof", &self.proof)
            .field("jwk", &self.jwk.as_ref().map(|_| "<jwk>"))
            .field("cert", &self.cert.as_ref().map(|_| "<cert>"))
            .field("cert#S256", &self.cert_s256)
            .finish()
    }
}

impl GnapKeyObject {
    /// Check that exactly one key format is present (section 7.1: a key is given in one format) and that a
    /// JWK carries no private member (section 7.1 requires a public key).
    pub fn validate(&self) -> Result<(), GnapError> {
        let formats = [
            self.jwk.is_some(),
            self.cert.is_some(),
            self.cert_s256.is_some(),
        ];
        if formats.iter().filter(|present| **present).count() != 1 {
            return Err(GnapError::new(
                GnapErrorCode::InvalidRequest,
                "a key needs exactly one of jwk, cert and cert#S256",
            ));
        }
        if let Some(jwk) = &self.jwk {
            for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
                if jwk.get(private).is_some() {
                    return Err(GnapError::new(
                        GnapErrorCode::InvalidRequest,
                        "a jwk must be a public key",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// How a client instance names itself (RFC 9635 section 2.3): an object, or a string that is an
/// `instance_id` the AS issued (2.3.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapClientRef {
    /// An instance identifier from an earlier response (section 3.5).
    Reference(String),
    /// The client by value (boxed: the object is much larger than a reference string).
    Object(Box<GnapClientObject>),
}

impl fmt::Debug for GnapClientRef {
    // A reference is a handle the AS issued for this party: it names the party to the AS, so it is not printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(_) => f.debug_tuple("Reference").field(&"<redacted>").finish(),
            Self::Object(object) => f.debug_tuple("Object").field(object).finish(),
        }
    }
}

/// The client instance by value (RFC 9635 section 2.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapClientObject {
    /// The instance's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<GnapKeyRef>,
    /// The class of software (section 2.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,
    /// Display information for the RO (section 2.3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<GnapClientDisplay>,
}

impl GnapClientRef {
    /// Validate the client's key when it is given by value (see [`GnapKeyObject::validate`]).
    pub fn validate(&self) -> Result<(), GnapError> {
        match self {
            Self::Reference(reference) if reference.is_empty() => Err(GnapError::new(
                GnapErrorCode::InvalidRequest,
                "the client reference is empty",
            )),
            Self::Reference(_) => Ok(()),
            Self::Object(object) => match &object.key {
                Some(GnapKeyRef::Object(key)) => key.validate(),
                Some(GnapKeyRef::Reference(_)) | None => Ok(()),
            },
        }
    }
}

/// Client display information (RFC 9635 section 2.3.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapClientDisplay {
    /// Human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Home page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Logo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

/// The user (RFC 9635 section 2.4): an object, or a string that is a user reference (2.4.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapUserRef {
    /// A reference from an earlier response (section 3.4).
    Reference(String),
    /// Identifiers and assertions the client holds about the user.
    Object(GnapUserObject),
}

impl fmt::Debug for GnapUserRef {
    // A reference is a handle the AS issued for this party: it names the party to the AS, so it is not printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reference(_) => f.debug_tuple("Reference").field(&"<redacted>").finish(),
            Self::Object(object) => f.debug_tuple("Object").field(object).finish(),
        }
    }
}

/// The user by value (RFC 9635 section 2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapUserObject {
    /// Subject identifiers (each an object with a `format`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_ids: Option<Vec<Value>>,
    /// Assertions (each an object with a `format` and a `value`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertions: Option<Vec<Value>>,
}

impl GnapUserRef {
    /// Check the shape the documentation of [`GnapUserObject`] promises: each `sub_ids` entry is an object with
    /// a string `format`; each `assertions` entry is an object with a string `format` and a `value`.
    pub fn validate(&self) -> Result<(), GnapError> {
        let bad = |why: &str| Err(GnapError::new(GnapErrorCode::InvalidRequest, why));
        let object = match self {
            Self::Reference(reference) if reference.is_empty() => {
                return bad("the user reference is empty");
            }
            Self::Reference(_) => return Ok(()),
            Self::Object(object) => object,
        };
        let has_format =
            |entry: &Value| entry.get("format").is_some_and(|format| format.is_string());
        for entry in object.sub_ids.iter().flatten() {
            if !entry.is_object() || !has_format(entry) {
                return bad("a sub_ids entry must be an object with a format");
            }
        }
        for entry in object.assertions.iter().flatten() {
            if !entry.is_object() || !has_format(entry) || entry.get("value").is_none() {
                return bad("an assertions entry must be an object with a format and a value");
            }
        }
        Ok(())
    }
}

/// One issued access token (RFC 9635 section 3.2.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapAccessTokenResponse {
    /// The token value; opaque, token68 characters only (REQUIRED).
    pub value: String,
    /// The label from the request, if there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Token management (section 3.2.1 `manage`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manage: Option<GnapManage>,
    /// The rights the token carries (REQUIRED); may differ from the request.
    pub access: Vec<GnapAccess>,
    /// Seconds until expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The key the token is bound to when it is not the presented key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<GnapKeyRef>,
    /// Attributes of the token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

impl fmt::Debug for GnapAccessTokenResponse {
    // The value is a credential: never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GnapAccessTokenResponse")
            .field("value", &"<redacted>")
            .field("label", &self.label)
            .field("manage", &self.manage)
            .field("access", &self.access)
            .field("expires_in", &self.expires_in)
            .field("key", &self.key)
            .field("flags", &self.flags)
            .finish()
    }
}

/// The `manage` object of a token (RFC 9635 section 3.2.1): the management URI and its own token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GnapManage {
    /// An absolute URI, per token, that holds neither the managed token nor the management token.
    pub uri: String,
    /// The token that protects the management URI.
    pub access_token: Box<GnapAccessTokenResponse>,
}

impl GnapAccessTokenResponse {
    /// Check RFC 9635 section 3.2.1: a bearer token has no `key`; the `manage` URI is absolute, differs from
    /// neither token's value (it must not contain either), and the management token is bound (no `bearer`
    /// flag, no `key`, no `manage` of its own) and is a different token.
    pub fn validate(&self) -> Result<(), GnapError> {
        if self.value.is_empty() || !is_token68(&self.value) {
            return Err(GnapError::new(
                GnapErrorCode::InvalidRequest,
                "the token value is empty or not in the token68 character set",
            ));
        }
        if self.flags.iter().any(|flag| flag == FLAG_BEARER) && self.key.is_some() {
            return Err(GnapError::new(
                GnapErrorCode::InvalidFlag,
                "a bearer token must not carry a key",
            ));
        }
        if let Some(manage) = &self.manage {
            let uri = manage.uri.as_str();
            if !(uri.starts_with("https://") || uri.starts_with("http://")) {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidRequest,
                    "the manage uri must be absolute",
                ));
            }
            let management = &manage.access_token;
            if uri.contains(self.value.as_str()) || uri.contains(management.value.as_str()) {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidRequest,
                    "the manage uri must not contain a token value",
                ));
            }
            if management.value == self.value {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidRequest,
                    "the management token must differ from the token it manages",
                ));
            }
            if management.flags.iter().any(|flag| flag == FLAG_BEARER)
                || management.key.is_some()
                || management.manage.is_some()
            {
                return Err(GnapError::new(
                    GnapErrorCode::InvalidRequest,
                    "the management token must be key-bound, without key, bearer flag or manage",
                ));
            }
            management.validate()?;
        }
        Ok(())
    }
}

/// The token68 character set of RFC 9110 section 11.2: ALPHA, DIGIT and `-._~+/` followed by any `=`.
fn is_token68(value: &str) -> bool {
    let body = value.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// The registered GNAP error codes (RFC 9635 section 3.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GnapErrorCode {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_client`
    InvalidClient,
    /// `invalid_interaction`
    InvalidInteraction,
    /// `invalid_flag`
    InvalidFlag,
    /// `invalid_rotation`
    InvalidRotation,
    /// `key_rotation_not_supported`
    KeyRotationNotSupported,
    /// `invalid_continuation`
    InvalidContinuation,
    /// `user_denied`
    UserDenied,
    /// `request_denied`
    RequestDenied,
    /// `unknown_user`
    UnknownUser,
    /// `unknown_interaction`
    UnknownInteraction,
    /// `too_fast`
    TooFast,
    /// `too_many_attempts`
    TooManyAttempts,
    /// A code registered by an extension (section 10.15).
    Other(String),
}

impl GnapErrorCode {
    /// The code as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidInteraction => "invalid_interaction",
            Self::InvalidFlag => "invalid_flag",
            Self::InvalidRotation => "invalid_rotation",
            Self::KeyRotationNotSupported => "key_rotation_not_supported",
            Self::InvalidContinuation => "invalid_continuation",
            Self::UserDenied => "user_denied",
            Self::RequestDenied => "request_denied",
            Self::UnknownUser => "unknown_user",
            Self::UnknownInteraction => "unknown_interaction",
            Self::TooFast => "too_fast",
            Self::TooManyAttempts => "too_many_attempts",
            Self::Other(code) => code,
        }
    }

    /// Parse a wire code; an unregistered one is kept as `Other`.
    pub fn from_code(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "invalid_client" => Self::InvalidClient,
            "invalid_interaction" => Self::InvalidInteraction,
            "invalid_flag" => Self::InvalidFlag,
            "invalid_rotation" => Self::InvalidRotation,
            "key_rotation_not_supported" => Self::KeyRotationNotSupported,
            "invalid_continuation" => Self::InvalidContinuation,
            "user_denied" => Self::UserDenied,
            "request_denied" => Self::RequestDenied,
            "unknown_user" => Self::UnknownUser,
            "unknown_interaction" => Self::UnknownInteraction,
            "too_fast" => Self::TooFast,
            "too_many_attempts" => Self::TooManyAttempts,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A GNAP error (RFC 9635 section 3.6): a code and an optional description for the client's developer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnapError {
    /// The registered code.
    pub code: GnapErrorCode,
    /// Free text for the developer; never put a secret in it.
    pub description: Option<String>,
}

impl GnapError {
    /// An error with a description.
    pub fn new(code: GnapErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
        }
    }

    /// The `error` field of a response, as the object form (section 3.6).
    pub fn to_value(&self) -> Value {
        match &self.description {
            Some(description) => {
                serde_json::json!({ "code": self.code.as_str(), "description": description })
            }
            None => serde_json::json!({ "code": self.code.as_str() }),
        }
    }

    /// The whole response body: `{"error": ...}`.
    pub fn to_response(&self) -> Value {
        serde_json::json!({ "error": self.to_value() })
    }

    /// Read the `error` field of a response: the object form or the string form (section 3.6).
    pub fn from_value(error: &Value) -> Option<Self> {
        match error {
            Value::String(code) => Some(Self {
                code: GnapErrorCode::from_code(code),
                description: None,
            }),
            Value::Object(map) => {
                let code = map.get("code")?.as_str()?;
                Some(Self {
                    code: GnapErrorCode::from_code(code),
                    description: map
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                })
            }
            _ => None,
        }
    }
}

impl fmt::Display for GnapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.description {
            Some(description) => write!(f, "{}: {description}", self.code.as_str()),
            None => f.write_str(self.code.as_str()),
        }
    }
}

impl std::error::Error for GnapError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The examples below are the non-normative ones of RFC 9635 (copied from the RFC text).

    #[test]
    fn a_single_access_token_object_parses_and_keeps_its_shape() {
        let wire = json!({
            "access": [
                {"type": "photo-api", "actions": ["read", "write", "delete"],
                 "locations": ["https://server.example.net/", "https://resource.local/other"],
                 "datatypes": ["metadata", "images"]},
                {"type": "walrus-access", "actions": ["foo", "bar"],
                 "locations": ["https://resource.other/"],
                 "datatypes": ["data", "pictures", "walrus whiskers"]}
            ],
            "label": "token1-23"
        });
        let parsed: GnapAccessTokenRequests = serde_json::from_value(wire.clone()).unwrap();
        assert!(!parsed.is_many());
        assert_eq!(parsed.as_slice().len(), 1);
        assert_eq!(parsed.as_slice()[0].label.as_deref(), Some("token1-23"));
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            wire,
            "the object form serializes as an object"
        );
        validate_access_token_requests(&parsed).unwrap();
    }

    #[test]
    fn multiple_access_tokens_parse_from_an_array_with_string_references() {
        let wire = json!([
            {"label": "token1", "access": [
                {"type": "photo-api", "actions": ["read", "write", "dolphin"],
                 "locations": ["https://server.example.net/", "https://resource.local/other"],
                 "datatypes": ["metadata", "images"]},
                "dolphin-metadata"]},
            {"label": "token2", "access": [
                {"type": "walrus-access", "actions": ["foo", "bar"],
                 "locations": ["https://resource.other/"],
                 "datatypes": ["data", "pictures", "walrus whiskers"]}],
             "flags": ["bearer"]}
        ]);
        let parsed: GnapAccessTokenRequests = serde_json::from_value(wire.clone()).unwrap();
        assert!(parsed.is_many());
        assert_eq!(parsed.as_slice().len(), 2);
        assert_eq!(
            parsed.as_slice()[0].access[1],
            GnapAccess::Reference("dolphin-metadata".into()),
            "a string is a reference (8.1)"
        );
        assert_eq!(parsed.as_slice()[1].flags, vec!["bearer".to_string()]);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        validate_access_token_requests(&parsed).unwrap();
    }

    #[test]
    fn a_missing_or_duplicate_label_in_the_array_form_is_invalid_request() {
        let missing: GnapAccessTokenRequests = serde_json::from_value(json!([
            {"label": "a", "access": ["x"]}, {"access": ["y"]}
        ]))
        .unwrap();
        assert_eq!(
            validate_access_token_requests(&missing).unwrap_err().code,
            GnapErrorCode::InvalidRequest
        );
        let duplicate: GnapAccessTokenRequests = serde_json::from_value(json!([
            {"label": "a", "access": ["x"]}, {"label": "a", "access": ["y"]}
        ]))
        .unwrap();
        assert_eq!(
            validate_access_token_requests(&duplicate).unwrap_err().code,
            GnapErrorCode::InvalidRequest
        );
        // Control: the same shape with unique labels is accepted, so the refusals above are about the labels.
        let fine: GnapAccessTokenRequests = serde_json::from_value(json!([
            {"label": "a", "access": ["x"]}, {"label": "b", "access": ["y"]}
        ]))
        .unwrap();
        validate_access_token_requests(&fine).unwrap();
    }

    #[test]
    fn a_label_is_optional_for_a_single_token() {
        let single: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": ["x"]})).unwrap();
        validate_access_token_requests(&single).unwrap();
    }

    #[test]
    fn an_unsupported_flag_is_invalid_flag_when_the_as_names_what_it_supports() {
        let request = |flags: Value| -> GnapAccessTokenRequests {
            serde_json::from_value(json!({"access": ["x"], "flags": flags})).unwrap()
        };
        // the base check cannot know the AS's flags and accepts any (control)
        assert!(validate_access_token_requests(&request(json!(["no-such-flag"]))).is_ok());
        let code = |r: Result<(), GnapError>| r.unwrap_err().code;
        assert_eq!(
            code(validate_access_token_requests_with_flags(
                &request(json!(["no-such-flag"])),
                &["bearer"]
            )),
            GnapErrorCode::InvalidFlag
        );
        assert_eq!(
            code(validate_access_token_requests_with_flags(
                &request(json!(["bearer", "split"])),
                &["bearer"]
            )),
            GnapErrorCode::InvalidFlag
        );
        assert!(
            validate_access_token_requests_with_flags(
                &request(json!(["bearer", "split"])),
                &["bearer", "split"]
            )
            .is_ok()
        );
        assert!(
            validate_access_token_requests_with_flags(&request(json!([])), &[]).is_ok(),
            "no flags, none to refuse"
        );
    }

    #[test]
    fn an_empty_access_type_is_invalid_request() {
        for access in [json!({"type": ""}), json!("")] {
            let request: GnapAccessTokenRequests =
                serde_json::from_value(json!({"access": [access]})).unwrap();
            assert_eq!(
                validate_access_token_requests(&request).unwrap_err().code,
                GnapErrorCode::InvalidRequest
            );
        }
        let fine: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": [{"type": "photo-api"}, "ref"]})).unwrap();
        assert!(validate_access_token_requests(&fine).is_ok());
    }

    #[test]
    fn the_whole_request_check_reaches_the_key_and_the_user() {
        let access: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": ["x"]})).unwrap();
        let client =
            |key: Value| -> GnapClientRef { serde_json::from_value(json!({"key": key})).unwrap() };
        let user = |value: Value| -> GnapUserRef { serde_json::from_value(value).unwrap() };
        let ok_client = client(json!({"proof": "httpsig", "jwk": {"kty": "EC"}}));
        let ok_user = user(json!({"sub_ids": [{"format": "opaque", "id": "1"}],
            "assertions": [{"format": "id_token", "value": "a.b.c"}]}));
        assert!(validate_request(Some(&access), Some(&ok_client), Some(&ok_user), &[]).is_ok());
        // a key with two formats, and a private JWK, are refused through the one entry point
        let two = client(json!({"proof": "httpsig", "jwk": {"kty": "EC"}, "cert": "AAAA"}));
        let private = client(json!({"proof": "httpsig", "jwk": {"kty": "EC", "d": "x"}}));
        for bad in [&two, &private] {
            assert_eq!(
                validate_request(Some(&access), Some(bad), None, &[])
                    .unwrap_err()
                    .code,
                GnapErrorCode::InvalidRequest
            );
        }
        // unstructured user entries are refused
        for bad in [
            json!({"sub_ids": [42]}),
            json!({"sub_ids": [{"id": "1"}]}),
            json!({"assertions": [{"format": "id_token"}]}),
            json!({"assertions": ["x"]}),
        ] {
            assert_eq!(
                validate_request(None, None, Some(&user(bad)), &[])
                    .unwrap_err()
                    .code,
                GnapErrorCode::InvalidRequest
            );
        }
        // and the flag list reaches the access token
        let flagged: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": ["x"], "flags": ["odd"]})).unwrap();
        assert_eq!(
            validate_request(Some(&flagged), None, None, &["bearer"])
                .unwrap_err()
                .code,
            GnapErrorCode::InvalidFlag
        );
    }

    #[test]
    fn a_repeated_flag_is_invalid_flag() {
        let repeated: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": ["x"], "flags": ["bearer", "bearer"]}))
                .unwrap();
        assert_eq!(
            validate_access_token_requests(&repeated).unwrap_err().code,
            GnapErrorCode::InvalidFlag
        );
        let once: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": ["x"], "flags": ["bearer", "split"]})).unwrap();
        validate_access_token_requests(&once).unwrap();
    }

    #[test]
    fn an_empty_array_or_no_access_is_invalid_request() {
        let empty: GnapAccessTokenRequests = serde_json::from_value(json!([])).unwrap();
        assert!(validate_access_token_requests(&empty).is_err());
        let no_access: GnapAccessTokenRequests =
            serde_json::from_value(json!({"access": []})).unwrap();
        assert!(validate_access_token_requests(&no_access).is_err());
        assert!(serde_json::from_value::<GnapAccessTokenRequests>(json!({"label": "x"})).is_err());
    }

    #[test]
    fn an_access_object_keeps_extension_fields_and_requires_a_type() {
        let object: GnapAccess =
            serde_json::from_value(json!({"type": "t", "x-extra": 1})).unwrap();
        match &object {
            GnapAccess::Object(o) => assert_eq!(o.extensions.get("x-extra"), Some(&json!(1))),
            other => panic!("expected an object, got {other:?}"),
        }
        assert_eq!(
            serde_json::to_value(&object).unwrap(),
            json!({"type": "t", "x-extra": 1})
        );
        assert!(serde_json::from_value::<GnapAccess>(json!({"actions": ["read"]})).is_err());
    }

    #[test]
    fn the_client_is_an_object_or_an_instance_id_string() {
        let by_value: GnapClientRef = serde_json::from_value(json!({
            "key": {"proof": "httpsig", "jwk": {"kty": "RSA", "e": "AQAB", "kid": "xyz-1", "alg": "RS256", "n": "abc"}},
            "class_id": "web-server-1234",
            "display": {"name": "My Client Display Name", "uri": "https://example.net/client", "logo_uri": "https://example.net/logo.png"}
        }))
        .unwrap();
        match by_value {
            GnapClientRef::Object(client) => {
                assert_eq!(client.class_id.as_deref(), Some("web-server-1234"));
                assert_eq!(
                    client.display.unwrap().logo_uri.as_deref(),
                    Some("https://example.net/logo.png")
                );
            }
            other => panic!("expected an object, got {other:?}"),
        }
        let by_reference: GnapClientRef =
            serde_json::from_value(json!("7C7C4AZ9KHRS6X63AJAO")).unwrap();
        assert_eq!(
            by_reference,
            GnapClientRef::Reference("7C7C4AZ9KHRS6X63AJAO".into())
        );
        assert_eq!(
            serde_json::to_value(&by_reference).unwrap(),
            json!("7C7C4AZ9KHRS6X63AJAO")
        );
    }

    #[test]
    fn a_key_is_an_object_or_a_reference_and_has_exactly_one_format() {
        let key: GnapKeyRef = serde_json::from_value(
            json!({"proof": "mtls", "cert#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}),
        )
        .unwrap();
        match &key {
            GnapKeyRef::Object(object) => object.validate().unwrap(),
            other => panic!("expected an object, got {other:?}"),
        }
        let reference: GnapKeyRef = serde_json::from_value(json!("keys-1")).unwrap();
        assert_eq!(reference, GnapKeyRef::Reference("keys-1".into()));
        let two: GnapKeyObject =
            serde_json::from_value(json!({"proof": "jws", "jwk": {"kty": "EC"}, "cert": "AAAA"}))
                .unwrap();
        assert_eq!(
            two.validate().unwrap_err().code,
            GnapErrorCode::InvalidRequest
        );
        let none: GnapKeyObject = serde_json::from_value(json!({"proof": "jws"})).unwrap();
        assert!(none.validate().is_err());
    }

    #[test]
    fn a_jwk_with_a_private_member_is_refused() {
        for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            let mut jwk = json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"});
            jwk[private] = json!("secret");
            let key = GnapKeyObject {
                proof: "httpsig".into(),
                jwk: Some(jwk),
                cert: None,
                cert_s256: None,
            };
            assert!(key.validate().is_err(), "{private} must be refused");
        }
        let public = GnapKeyObject {
            proof: "httpsig".into(),
            jwk: Some(json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"})),
            cert: None,
            cert_s256: None,
        };
        public.validate().unwrap();
    }

    #[test]
    fn the_debug_of_a_key_and_a_token_never_prints_a_value() {
        let key = GnapKeyObject {
            proof: "httpsig".into(),
            jwk: Some(json!({"kty": "oct", "k": "SECRETSECRET"})),
            cert: None,
            cert_s256: None,
        };
        assert!(!format!("{key:?}").contains("SECRETSECRET"));
        let token = GnapAccessTokenResponse {
            value: "TOKENVALUE123".into(),
            label: None,
            manage: None,
            access: vec![],
            expires_in: None,
            key: None,
            flags: vec![],
        };
        assert!(!format!("{token:?}").contains("TOKENVALUE123"));
        assert!(
            !format!("{:?}", GnapUserRef::Reference("USERHANDLE9".into())).contains("USERHANDLE9")
        );
        assert!(
            !format!("{:?}", GnapClientRef::Reference("INSTANCE77".into())).contains("INSTANCE77")
        );
    }

    fn token(value: &str) -> GnapAccessTokenResponse {
        GnapAccessTokenResponse {
            value: value.into(),
            label: None,
            manage: None,
            access: vec![GnapAccess::Reference("x".into())],
            expires_in: Some(3600),
            key: None,
            flags: vec![],
        }
    }

    #[test]
    fn the_token_response_example_round_trips() {
        let wire = json!({
            "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
            "label": "token1-23",
            "manage": {
                "uri": "https://server.example.com/token/PRY5NM33",
                "access_token": {"value": "B8CDFONP21-4TB8N6.BW7ONM", "access": ["management"]}
            },
            "access": [{"type": "photo-api", "actions": ["read"]}],
            "expires_in": 3600
        });
        let parsed: GnapAccessTokenResponse = serde_json::from_value(wire.clone()).unwrap();
        parsed.validate().unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    }

    #[test]
    fn a_bearer_token_with_a_key_is_refused() {
        let mut bearer = token("AAAA");
        bearer.flags = vec!["bearer".into()];
        bearer.validate().unwrap();
        bearer.key = Some(GnapKeyRef::Reference("k".into()));
        assert_eq!(
            bearer.validate().unwrap_err().code,
            GnapErrorCode::InvalidFlag
        );
        let mut bound = token("AAAA");
        bound.key = Some(GnapKeyRef::Reference("k".into()));
        bound.validate().unwrap();
    }

    #[test]
    fn the_manage_object_rules_of_section_3_2_1_hold() {
        let manage = |uri: &str, management: GnapAccessTokenResponse| {
            let mut t = token("MANAGED1");
            t.manage = Some(GnapManage {
                uri: uri.into(),
                access_token: Box::new(management),
            });
            t
        };
        manage("https://as.example/token/1", token("MGMT1"))
            .validate()
            .unwrap();
        assert!(
            manage("/token/1", token("MGMT1")).validate().is_err(),
            "relative uri"
        );
        assert!(
            manage("https://as.example/token/MANAGED1", token("MGMT1"))
                .validate()
                .is_err(),
            "contains the token"
        );
        assert!(
            manage("https://as.example/token/MGMT1", token("MGMT1"))
                .validate()
                .is_err(),
            "contains the management token"
        );
        assert!(
            manage("https://as.example/token/1", token("MANAGED1"))
                .validate()
                .is_err(),
            "same value"
        );
        let mut bearer = token("MGMT1");
        bearer.flags = vec!["bearer".into()];
        assert!(
            manage("https://as.example/token/1", bearer)
                .validate()
                .is_err(),
            "bearer management token"
        );
        let mut keyed = token("MGMT1");
        keyed.key = Some(GnapKeyRef::Reference("k".into()));
        assert!(
            manage("https://as.example/token/1", keyed)
                .validate()
                .is_err(),
            "management token with a key"
        );
        let mut nested = token("MGMT1");
        nested.manage = Some(GnapManage {
            uri: "https://as.example/x".into(),
            access_token: Box::new(token("MGMT2")),
        });
        assert!(
            manage("https://as.example/token/1", nested)
                .validate()
                .is_err(),
            "management token with manage"
        );
    }

    #[test]
    fn a_token_value_must_be_token68() {
        assert!(token("abc-._~+/=").validate().is_ok());
        for bad in ["", "has space", "quo\"te", "semi;colon", "==="] {
            assert!(token(bad).validate().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn every_registered_error_code_round_trips_and_the_object_and_string_forms_read_the_same() {
        let codes = [
            "invalid_request",
            "invalid_client",
            "invalid_interaction",
            "invalid_flag",
            "invalid_rotation",
            "key_rotation_not_supported",
            "invalid_continuation",
            "user_denied",
            "request_denied",
            "unknown_user",
            "unknown_interaction",
            "too_fast",
            "too_many_attempts",
        ];
        for code in codes {
            let parsed = GnapErrorCode::from_code(code);
            assert!(
                !matches!(parsed, GnapErrorCode::Other(_)),
                "{code} is registered"
            );
            assert_eq!(parsed.as_str(), code);
        }
        assert_eq!(
            GnapErrorCode::from_code("x-custom"),
            GnapErrorCode::Other("x-custom".into())
        );
        let object =
            json!({"error": {"code": "user_denied", "description": "The RO denied the request"}});
        let string = json!({"error": "user_denied"});
        let from_object = GnapError::from_value(&object["error"]).unwrap();
        let from_string = GnapError::from_value(&string["error"]).unwrap();
        assert_eq!(from_object.code, GnapErrorCode::UserDenied);
        assert_eq!(from_string.code, GnapErrorCode::UserDenied);
        assert_eq!(from_object.to_response(), object);
        assert_eq!(from_string.to_value(), json!({"code": "user_denied"}));
        assert!(GnapError::from_value(&json!(5)).is_none());
        assert!(GnapError::from_value(&json!({"description": "no code"})).is_none());
    }

    #[test]
    fn the_user_is_an_object_or_a_reference() {
        let by_value: GnapUserRef = serde_json::from_value(json!({
            "sub_ids": [{"format": "iss_sub", "iss": "https://idp.example.com/", "sub": "user-1"}],
            "assertions": [{"format": "id_token", "value": "eyJ"}]
        }))
        .unwrap();
        assert!(matches!(by_value, GnapUserRef::Object(_)));
        let reference: GnapUserRef = serde_json::from_value(json!("XUT2MFM1XBIKJKSDU8QM")).unwrap();
        assert_eq!(
            reference,
            GnapUserRef::Reference("XUT2MFM1XBIKJKSDU8QM".into())
        );
    }
}
