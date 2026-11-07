// SPDX-License-Identifier: MIT OR Apache-2.0
//! GNAP `jwsd` (detached JWS) and `jws` (attached JWS) proofing, and `mtls` certificate matching, as RFC 9635
//! sections 7.3.2 to 7.3.4 define them (slice G3 of `docs/GNAP_RFC9635_GAP.md`).
//!
//! * [`verify_detached`] checks the `Detached-JWS` header of a request (`jwsd`): the JOSE header's `typ`, `htm`,
//!   `uri`, `created`, `kid`, `alg` and `ath` against the request, the payload against the SHA-256 of the
//!   content, and the signature under the client's public JWK.
//! * [`verify_attached`] checks a request whose body is a compact JWS (`jws`) the same way and returns the
//!   payload, which is the request content.
//! * [`verify_mtls`] matches the certificate a TLS terminator vouches for against the key the client gave
//!   (`cert` or `cert#S256`).
//!
//! The `typ` values are the normative ones of RFC 9635 sections 7.3.3 and 7.3.4 (`gnap-binding-jwsd`,
//! `gnap-binding-jws`). The RFC's own `jwsd` example header spells it `gnap-binding+jwsd`, which disagrees with its
//! text and with its IANA media type; a message carrying that spelling is refused here. `alg` `none`, the HMAC
//! algorithms and any private JWK member are refused. Key rotation (RFC 9635 sections 7.3.3.1 and 7.3.4.1) is not
//! handled here.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `typ` of a `jwsd` JOSE header (RFC 9635 section 7.3.3).
pub const TYP_JWSD: &str = "gnap-binding-jwsd";
/// `typ` of a `jws` JOSE header (RFC 9635 section 7.3.4).
pub const TYP_JWS: &str = "gnap-binding-jws";

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwsProofError {
    /// The message or the key is not well formed, or uses something refused here.
    Malformed(String),
    /// A field of the JOSE header does not match the request or the key, as RFC 9635 requires.
    Mismatch(String),
    /// The signature does not verify under the key.
    BadSignature,
}

impl fmt::Display for JwsProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed jws proof: {why}"),
            Self::Mismatch(why) => write!(f, "jws proof does not match the request: {why}"),
            Self::BadSignature => f.write_str("jws proof signature does not verify"),
        }
    }
}

impl std::error::Error for JwsProofError {}

fn malformed(why: impl Into<String>) -> JwsProofError {
    JwsProofError::Malformed(why.into())
}

fn mismatch(why: impl Into<String>) -> JwsProofError {
    JwsProofError::Mismatch(why.into())
}

/// What the request is checked against.
#[derive(Debug, Clone, Copy)]
pub struct JwsProofContext<'a> {
    /// The client's public JWK.
    pub jwk: &'a Value,
    /// The HTTP method of the request, case-sensitive.
    pub method: &'a str,
    /// The absolute request URI with path and query and no fragment.
    pub uri: &'a str,
    /// The request content (empty when there is none). Used by `jwsd`; ignored by `jws`.
    pub body: &'a [u8],
    /// The access token the request presents, when it is bound to one (`ath` is then required).
    pub access_token: Option<&'a str>,
    /// The current time, seconds since the epoch.
    pub now: u64,
    /// How far `created` may differ from now, in seconds, either way.
    pub max_skew_secs: u64,
}

/// The facts of an accepted proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJws {
    /// The JWS algorithm used.
    pub algorithm: Algorithm,
    /// When the signer says it signed.
    pub created: u64,
    /// The `kid` of the header, when it had one.
    pub kid: Option<String>,
}

fn b64_json(segment: &str, what: &str) -> Result<Value, JwsProofError> {
    let bytes = B64
        .decode(segment)
        .map_err(|_| malformed(format!("the {what} is not base64url")))?;
    serde_json::from_slice(&bytes).map_err(|_| malformed(format!("the {what} is not JSON")))
}

fn algorithm_of(name: &str) -> Result<Algorithm, JwsProofError> {
    match name {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        "none" => Err(malformed("alg none is refused")),
        other => Err(malformed(format!(
            "the algorithm {other:?} is not allowed (symmetric and unknown algorithms are refused)"
        ))),
    }
}

fn member<'a>(jwk: &'a Value, name: &str) -> Result<&'a str, JwsProofError> {
    jwk.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("the JWK has no {name}")))
}

/// The verification key for `algorithm`, from a public JWK whose type and curve fit the algorithm.
fn decoding_key(jwk: &Value, algorithm: Algorithm) -> Result<DecodingKey, JwsProofError> {
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        if jwk.get(private).is_some() {
            return Err(malformed("the JWK must be a public key"));
        }
    }
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or("");
    let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or("");
    let key = match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            if kty != "RSA" {
                return Err(mismatch("an RSA algorithm needs an RSA key"));
            }
            DecodingKey::from_rsa_components(member(jwk, "n")?, member(jwk, "e")?)
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let want = if algorithm == Algorithm::ES256 {
                "P-256"
            } else {
                "P-384"
            };
            if kty != "EC" || crv != want {
                return Err(mismatch(format!("{algorithm:?} needs an EC key on {want}")));
            }
            DecodingKey::from_ec_components(member(jwk, "x")?, member(jwk, "y")?)
        }
        Algorithm::EdDSA => {
            if kty != "OKP" || crv != "Ed25519" {
                return Err(mismatch("EdDSA needs an Ed25519 key"));
            }
            DecodingKey::from_ed_components(member(jwk, "x")?)
        }
        _ => return Err(malformed("the algorithm is not allowed")),
    };
    key.map_err(|_| malformed("the JWK is not a usable key"))
}

/// Check a compact JWS signature over `signing_input` (`header.payload`) with the key and the header's `alg`.
fn verify_signature(
    header: &Value,
    jwk: &Value,
    signing_input: &str,
    signature_b64: &str,
) -> Result<(Algorithm, Option<String>), JwsProofError> {
    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("the JOSE header has no alg"))?;
    let algorithm = algorithm_of(alg_name)?;
    // The algorithm must be the one the JWK names (RFC 9635 section 7.3.3 `alg`).
    if let Some(jwk_alg) = jwk.get("alg").and_then(Value::as_str)
        && jwk_alg != alg_name
    {
        return Err(mismatch("the header alg is not the alg of the JWK"));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(jwk_kid) = jwk.get("kid").and_then(Value::as_str)
        && kid.as_deref() != Some(jwk_kid)
    {
        return Err(mismatch("kid is required and must be the kid of the JWK"));
    }
    let key = decoding_key(jwk, algorithm)?;
    match jsonwebtoken::crypto::verify(signature_b64, signing_input.as_bytes(), &key, algorithm) {
        Ok(true) => Ok((algorithm, kid)),
        _ => Err(JwsProofError::BadSignature),
    }
}

/// The fields RFC 9635 requires in the JOSE header, checked against the request.
fn check_header(
    header: &Value,
    typ: &str,
    context: &JwsProofContext<'_>,
) -> Result<u64, JwsProofError> {
    if header.get("typ").and_then(Value::as_str) != Some(typ) {
        return Err(mismatch(format!("typ must be {typ}")));
    }
    if header.get("htm").and_then(Value::as_str) != Some(context.method) {
        return Err(mismatch("htm is not the request method"));
    }
    if header.get("uri").and_then(Value::as_str) != Some(context.uri) {
        return Err(mismatch("uri is not the request URI"));
    }
    if context.uri.contains('#') || !context.uri.contains("://") {
        return Err(malformed(
            "the request URI must be absolute and have no fragment",
        ));
    }
    let created = header
        .get("created")
        .and_then(Value::as_u64)
        .ok_or_else(|| mismatch("created is missing or not a non-negative integer"))?;
    if created.abs_diff(context.now) > context.max_skew_secs {
        return Err(mismatch("created is too far from the current time"));
    }
    if let Some(token) = context.access_token {
        let expected = B64.encode(Sha256::digest(token.as_bytes()));
        let given = header.get("ath").and_then(Value::as_str).unwrap_or("");
        if !bool::from(given.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(mismatch(
                "ath is missing or is not the hash of the access token",
            ));
        }
    }
    Ok(created)
}

/// Verify the `Detached-JWS` header of a request (`jwsd`, RFC 9635 section 7.3.3).
///
/// The header value is a compact JWS whose payload segment is empty when the request has no content, and the
/// base64url SHA-256 of the content when it has; the verifier recomputes that from `context.body`, with no
/// normalization.
pub fn verify_detached(
    detached_jws: &str,
    context: &JwsProofContext<'_>,
) -> Result<VerifiedJws, JwsProofError> {
    let mut parts = detached_jws.trim().split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("a detached JWS has three dot-separated parts"));
    };
    let header = b64_json(header_b64, "JOSE header")?;
    let created = check_header(&header, TYP_JWSD, context)?;
    let expected_payload = if context.body.is_empty() {
        String::new()
    } else {
        B64.encode(Sha256::digest(context.body))
    };
    if payload_b64 != expected_payload {
        return Err(mismatch(
            "the payload is not the hash of the request content",
        ));
    }
    let signing_input = format!("{header_b64}.{expected_payload}");
    let (algorithm, kid) = verify_signature(&header, context.jwk, &signing_input, signature_b64)?;
    Ok(VerifiedJws {
        algorithm,
        created,
        kid,
    })
}

/// Verify a request whose content is a compact JWS (`jws`, RFC 9635 section 7.3.4) and return the payload, which
/// is the request content from then on. A request with no content uses [`verify_detached`] instead.
pub fn verify_attached(
    compact_jws: &str,
    context: &JwsProofContext<'_>,
) -> Result<(VerifiedJws, Vec<u8>), JwsProofError> {
    let mut parts = compact_jws.trim().split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("a compact JWS has three dot-separated parts"));
    };
    let header = b64_json(header_b64, "JOSE header")?;
    let created = check_header(&header, TYP_JWS, context)?;
    let payload = B64
        .decode(payload_b64)
        .map_err(|_| malformed("the payload is not base64url"))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let (algorithm, kid) = verify_signature(&header, context.jwk, &signing_input, signature_b64)?;
    Ok((
        VerifiedJws {
            algorithm,
            created,
            kid,
        },
        payload,
    ))
}

/// The DER of the certificate in a `Client-Cert` header (RFC 9440: one byte sequence, `:base64:`). A TLS
/// terminator sets it; the integrator must make sure a client cannot, by stripping it on the way in.
pub fn client_cert_from_header(value: &str) -> Result<Vec<u8>, JwsProofError> {
    let inner = value
        .trim()
        .strip_prefix(':')
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or_else(|| malformed("Client-Cert is a single byte sequence between colons"))?;
    base64::engine::general_purpose::STANDARD
        .decode(inner)
        .map_err(|_| malformed("Client-Cert is not base64"))
        .and_then(|der| {
            if der.is_empty() {
                Err(malformed("Client-Cert is empty"))
            } else {
                Ok(der)
            }
        })
}

/// Match the certificate the TLS layer presented (`presented_der`) against the key the client gave in
/// `mtls` proofing (RFC 9635 sections 7.1 and 7.3.2): `cert` is the certificate's DER in standard base64,
/// `cert_s256` the base64url SHA-256 of that DER. Exactly one must be given. This does not validate a chain: the
/// RFC leaves trust to static registration or trust on first use (its sections 11.3 and 11.4), and that is the
/// integrator's decision.
pub fn verify_mtls(
    presented_der: &[u8],
    cert: Option<&str>,
    cert_s256: Option<&str>,
) -> Result<(), JwsProofError> {
    if presented_der.is_empty() {
        return Err(malformed("no certificate was presented"));
    }
    let matches = match (cert, cert_s256) {
        (Some(cert), None) => {
            let expected = base64::engine::general_purpose::STANDARD
                .decode(cert)
                .map_err(|_| malformed("cert is not base64"))?;
            expected.len() == presented_der.len()
                && bool::from(expected.as_slice().ct_eq(presented_der))
        }
        (None, Some(thumbprint)) => {
            let actual = B64.encode(Sha256::digest(presented_der));
            bool::from(actual.as_bytes().ct_eq(thumbprint.as_bytes()))
        }
        _ => return Err(malformed("a key has exactly one of cert and cert#S256")),
    };
    if matches {
        Ok(())
    } else {
        Err(JwsProofError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- the RFC 9635 section 7.3.3 example: a real RS256 signature, checked at the signature layer ----

    const RFC_JWSD: &str = include_str!("gnap_jws_rfc_example.txt");
    const RFC_N: &str = "hYOJ-XOKISdMMShn_G4W9m20mT0VWtQBsmBBkI2cmRt4Ai8BfYdHsFzAtYKOjpBR1RpKpJmVKxIGNy0g6Z3ad2XYsh8KowlyVy8IkZ8NMwSrcUIBZGYXjHpwjzvfGvXH_5KJlnR3_uRUp4Z4Ujk2bCaKegDn11V2vxE41hqaPUnhRZxe0jRETddzsE3mu1SK8dTCROjwUl14mUNo8iTrTm4n0qDadz8BkPo-uv4BC0bunS0K3bA_3UgVp7zBlQFoFnLTO2uWp_muLEWGl67gBq9MO3brKXfGhi3kOzywzwPTuq-cVQDyEN7aL0SxCb3Hc4IdqDaMg8qHUyObpPitDQ";

    fn rfc_jwk() -> Value {
        json!({"kid": "gnap-rsa", "kty": "RSA", "e": "AQAB", "alg": "RS256", "n": RFC_N})
    }

    #[test]
    fn the_rfc_example_signature_verifies_at_the_signature_layer() {
        let compact = RFC_JWSD.trim();
        let mut parts = compact.split('.');
        let (h, p, s) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let header = b64_json(h, "header").unwrap();
        let (alg, kid) = verify_signature(&header, &rfc_jwk(), &format!("{h}.{p}"), s).unwrap();
        assert_eq!(alg, Algorithm::RS256);
        assert_eq!(kid.as_deref(), Some("gnap-rsa"));
        // Controls: a changed payload, another key and a changed alg each break it.
        assert!(matches!(
            verify_signature(
                &header,
                &rfc_jwk(),
                &format!("{h}.{}x", &p[..p.len() - 1]),
                s
            ),
            Err(JwsProofError::BadSignature)
        ));
        let mut other = rfc_jwk();
        other["n"] = json!(&RFC_N.replace("hYOJ", "hYOK"));
        assert!(verify_signature(&header, &other, &format!("{h}.{p}"), s).is_err());
        let mut wrong_alg = rfc_jwk();
        wrong_alg["alg"] = json!("PS256");
        assert!(matches!(
            verify_signature(&header, &wrong_alg, &format!("{h}.{p}"), s),
            Err(JwsProofError::Mismatch(_))
        ));
    }

    #[test]
    fn the_rfc_example_header_spells_typ_with_a_plus_and_is_refused_by_the_normative_check() {
        let header = b64_json(RFC_JWSD.trim().split('.').next().unwrap(), "header").unwrap();
        assert_eq!(
            header["typ"], "gnap-binding+jwsd",
            "the RFC example disagrees with its own text"
        );
        let jwk = rfc_jwk();
        let context = JwsProofContext {
            jwk: &jwk,
            method: "POST",
            uri: "https://server.example.com/gnap",
            body: b"",
            access_token: None,
            now: 1_618_884_475,
            max_skew_secs: 300,
        };
        assert!(matches!(
            check_header(&header, TYP_JWSD, &context),
            Err(JwsProofError::Mismatch(_))
        ));
    }

    // ---- verification with keys made here ----

    use jsonwebtoken::EncodingKey;

    struct Signer {
        key: EncodingKey,
        jwk: Value,
        alg: &'static str,
    }

    fn es256_signer() -> Signer {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let raw = pair.public_key_raw();
        let point = &raw[raw.len() - 65..];
        Signer {
            key: EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap(),
            jwk: json!({"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
                "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65])}),
            alg: "ES256",
        }
    }

    fn ed_signer() -> Signer {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let raw = pair.public_key_raw();
        Signer {
            key: EncodingKey::from_ed_pem(pair.serialize_pem().as_bytes()).unwrap(),
            jwk: json!({"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "x": B64.encode(raw)}),
            alg: "EdDSA",
        }
    }

    const NOW: u64 = 1_700_000_000;
    const URI: &str = "https://as.example/gnap";

    fn algorithm(name: &str) -> Algorithm {
        algorithm_of(name).unwrap()
    }

    fn sign(signer: &Signer, header: &Value, payload_b64: &str) -> String {
        let h = B64.encode(header.to_string());
        let input = format!("{h}.{payload_b64}");
        let sig = jsonwebtoken::crypto::sign(input.as_bytes(), &signer.key, algorithm(signer.alg))
            .unwrap();
        format!("{h}.{payload_b64}.{sig}")
    }

    fn header(signer: &Signer, typ: &str) -> Value {
        json!({"alg": signer.alg, "kid": "k1", "typ": typ, "htm": "POST", "uri": URI, "created": NOW})
    }

    fn ctx<'a>(signer: &'a Signer, body: &'a [u8], token: Option<&'a str>) -> JwsProofContext<'a> {
        JwsProofContext {
            jwk: &signer.jwk,
            method: "POST",
            uri: URI,
            body,
            access_token: token,
            now: NOW,
            max_skew_secs: 300,
        }
    }

    fn detached(signer: &Signer, body: &[u8], h: &Value) -> String {
        let payload = if body.is_empty() {
            String::new()
        } else {
            B64.encode(Sha256::digest(body))
        };
        sign(signer, h, &payload)
    }

    #[test]
    fn a_correct_detached_jws_verifies_with_es256_and_eddsa() {
        for signer in [es256_signer(), ed_signer()] {
            let body = b"{\"access_token\":{}}";
            let jws = detached(&signer, body, &header(&signer, TYP_JWSD));
            let got = verify_detached(&jws, &ctx(&signer, body, None)).unwrap();
            assert_eq!(got.algorithm, algorithm(signer.alg));
            assert_eq!(got.created, NOW);
            assert_eq!(got.kid.as_deref(), Some("k1"));
            // no content: the payload is empty
            let empty = detached(&signer, b"", &header(&signer, TYP_JWSD));
            verify_detached(&empty, &ctx(&signer, b"", None)).unwrap();
        }
    }

    fn refused_detached(
        signer: &Signer,
        body: &[u8],
        h: &Value,
        token: Option<&str>,
    ) -> JwsProofError {
        verify_detached(&detached(signer, body, h), &ctx(signer, body, token)).unwrap_err()
    }

    #[test]
    fn each_rule_of_section_7_3_3_is_enforced_for_jwsd() {
        let s = es256_signer();
        let body = b"{}";
        let good = header(&s, TYP_JWSD);
        assert!(
            verify_detached(&detached(&s, body, &good), &ctx(&s, body, None)).is_ok(),
            "control"
        );
        let with = |k: &str, v: Value| {
            let mut h = good.clone();
            h[k] = v;
            h
        };
        let without = |k: &str| {
            let mut h = good.clone();
            h.as_object_mut().unwrap().remove(k);
            h
        };
        // typ, including the RFC example's spelling
        for typ in [TYP_JWS, "gnap-binding+jwsd", "JWT"] {
            assert!(
                matches!(
                    refused_detached(&s, body, &with("typ", json!(typ)), None),
                    JwsProofError::Mismatch(_)
                ),
                "{typ}"
            );
        }
        assert!(matches!(
            refused_detached(&s, body, &without("typ"), None),
            JwsProofError::Mismatch(_)
        ));
        // htm, uri
        assert!(matches!(
            refused_detached(&s, body, &with("htm", json!("GET")), None),
            JwsProofError::Mismatch(_)
        ));
        assert!(
            matches!(
                refused_detached(&s, body, &with("htm", json!("post")), None),
                JwsProofError::Mismatch(_)
            ),
            "case-sensitive"
        );
        assert!(matches!(
            refused_detached(
                &s,
                body,
                &with("uri", json!("https://as.example/other")),
                None
            ),
            JwsProofError::Mismatch(_)
        ));
        assert!(matches!(
            refused_detached(&s, body, &without("uri"), None),
            JwsProofError::Mismatch(_)
        ));
        // created: missing, stale, future, boundaries accepted
        assert!(matches!(
            refused_detached(&s, body, &without("created"), None),
            JwsProofError::Mismatch(_)
        ));
        assert!(matches!(
            refused_detached(&s, body, &with("created", json!(NOW - 301)), None),
            JwsProofError::Mismatch(_)
        ));
        assert!(matches!(
            refused_detached(&s, body, &with("created", json!(NOW + 301)), None),
            JwsProofError::Mismatch(_)
        ));
        for ok in [NOW - 300, NOW + 300] {
            assert!(
                verify_detached(
                    &detached(&s, body, &with("created", json!(ok))),
                    &ctx(&s, body, None)
                )
                .is_ok()
            );
        }
        // kid is required for a JWK that has one, and must match
        assert!(matches!(
            refused_detached(&s, body, &without("kid"), None),
            JwsProofError::Mismatch(_)
        ));
        assert!(matches!(
            refused_detached(&s, body, &with("kid", json!("other")), None),
            JwsProofError::Mismatch(_)
        ));
        // alg: must be the JWK's alg; none and HMAC are refused
        assert!(matches!(
            refused_detached(&s, body, &with("alg", json!("ES384")), None),
            JwsProofError::Mismatch(_)
        ));
        for alg in ["none", "HS256", "HS512", ""] {
            assert!(
                matches!(
                    refused_detached(&s, body, &with("alg", json!(alg)), None),
                    JwsProofError::Malformed(_)
                ),
                "{alg:?}"
            );
        }
        assert!(matches!(
            refused_detached(&s, body, &without("alg"), None),
            JwsProofError::Malformed(_)
        ));
    }

    #[test]
    fn the_payload_must_be_the_hash_of_the_content_and_the_ath_of_the_token() {
        let s = es256_signer();
        let good = header(&s, TYP_JWSD);
        let jws = detached(&s, b"{\"a\":1}", &good);
        // a body that differs by one byte, or by whitespace, is refused: no normalization
        for other in [&b"{\"a\":2}"[..], b"{\"a\": 1}", b""] {
            assert!(matches!(
                verify_detached(&jws, &ctx(&s, other, None)),
                Err(JwsProofError::Mismatch(_))
            ));
        }
        verify_detached(&jws, &ctx(&s, b"{\"a\":1}", None)).unwrap();
        // a bound request needs ath
        assert!(matches!(
            refused_detached(&s, b"{}", &good, Some("TOKEN")),
            JwsProofError::Mismatch(_)
        ));
        let mut with_ath = good.clone();
        with_ath["ath"] = json!(B64.encode(Sha256::digest(b"TOKEN")));
        assert!(
            verify_detached(
                &detached(&s, b"{}", &with_ath),
                &ctx(&s, b"{}", Some("TOKEN"))
            )
            .is_ok()
        );
        assert!(matches!(
            verify_detached(
                &detached(&s, b"{}", &with_ath),
                &ctx(&s, b"{}", Some("OTHER"))
            ),
            Err(JwsProofError::Mismatch(_))
        ));
    }

    #[test]
    fn a_signature_from_another_key_or_a_tampered_header_is_refused() {
        let s = es256_signer();
        let other = es256_signer();
        let body = b"{}";
        // signed by another key (same kid, same alg)
        let forged = detached(&other, body, &header(&other, TYP_JWSD));
        assert_eq!(
            verify_detached(&forged, &ctx(&s, body, None)).unwrap_err(),
            JwsProofError::BadSignature
        );
        // the header changed after signing
        let jws = detached(&s, body, &header(&s, TYP_JWSD));
        let mut parts: Vec<&str> = jws.split('.').collect();
        let tampered = B64.encode(
            header(&s, TYP_JWSD)
                .to_string()
                .replace("POST", "POST ")
                .replace("\"created\":1700000000", "\"created\":1700000001"),
        );
        parts[0] = &tampered;
        assert!(verify_detached(&parts.join("."), &ctx(&s, body, None)).is_err());
    }

    #[test]
    fn malformed_input_is_refused_not_panicked_on() {
        let s = es256_signer();
        for bad in ["", "a.b", "a.b.c.d", "!!!.!!!.!!!", ".."] {
            assert!(
                verify_detached(bad, &ctx(&s, b"", None)).is_err(),
                "{bad:?}"
            );
            assert!(
                verify_attached(bad, &ctx(&s, b"", None)).is_err(),
                "{bad:?}"
            );
        }
        // a private member in the JWK
        let mut jwk = s.jwk.clone();
        jwk["d"] = json!("AAAA");
        let jws = detached(&s, b"", &header(&s, TYP_JWSD));
        let context = JwsProofContext {
            jwk: &jwk,
            ..ctx(&s, b"", None)
        };
        assert!(matches!(
            verify_detached(&jws, &context),
            Err(JwsProofError::Malformed(_))
        ));
        // an RSA algorithm against an EC key
        let mut h = header(&s, TYP_JWSD);
        h["alg"] = json!("RS256");
        let mut jwk = s.jwk.clone();
        jwk.as_object_mut().unwrap().remove("alg");
        let jws = sign(
            &s,
            &json!({"alg": "ES256", "kid": "k1", "typ": TYP_JWSD, "htm": "POST", "uri": URI, "created": NOW}),
            "",
        );
        // swap the alg in the header only: the signature no longer matches and the key type mismatch is refused first
        let swapped = jws.replacen(&B64.encode(json!({"alg": "ES256", "kid": "k1", "typ": TYP_JWSD, "htm": "POST", "uri": URI, "created": NOW}).to_string()), &B64.encode(h.to_string()), 1);
        let context = JwsProofContext {
            jwk: &jwk,
            ..ctx(&s, b"", None)
        };
        assert!(matches!(
            verify_detached(&swapped, &context),
            Err(JwsProofError::Mismatch(_))
        ));
    }

    #[test]
    fn an_attached_jws_returns_its_payload_and_needs_the_jws_typ() {
        for signer in [es256_signer(), ed_signer()] {
            let payload = b"{\"access_token\":{\"access\":[\"x\"]}}";
            let jws = sign(&signer, &header(&signer, TYP_JWS), &B64.encode(payload));
            let (got, body) = verify_attached(&jws, &ctx(&signer, b"", None)).unwrap();
            assert_eq!(body, payload);
            assert_eq!(got.created, NOW);
            // the jwsd typ is refused on an attached request, and the reverse
            let wrong = sign(&signer, &header(&signer, TYP_JWSD), &B64.encode(payload));
            assert!(matches!(
                verify_attached(&wrong, &ctx(&signer, b"", None)),
                Err(JwsProofError::Mismatch(_))
            ));
            let detached_with_jws_typ = detached(&signer, b"{}", &header(&signer, TYP_JWS));
            assert!(matches!(
                verify_detached(&detached_with_jws_typ, &ctx(&signer, b"{}", None)),
                Err(JwsProofError::Mismatch(_))
            ));
        }
    }

    #[test]
    fn a_changed_attached_payload_is_refused() {
        let s = es256_signer();
        let jws = sign(&s, &header(&s, TYP_JWS), &B64.encode(b"{\"a\":1}"));
        let mut parts: Vec<&str> = jws.split('.').collect();
        let forged = B64.encode(b"{\"a\":2}");
        parts[1] = &forged;
        assert_eq!(
            verify_attached(&parts.join("."), &ctx(&s, b"", None)).unwrap_err(),
            JwsProofError::BadSignature
        );
    }

    // ---- mtls ----

    #[test]
    fn mtls_matches_a_certificate_by_value_or_by_thumbprint() {
        let der = b"\x30\x82\x01\x0a not really a certificate but opaque bytes".to_vec();
        let std_b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let thumb = B64.encode(Sha256::digest(&der));
        verify_mtls(&der, Some(&std_b64), None).unwrap();
        verify_mtls(&der, None, Some(&thumb)).unwrap();
        // controls: another certificate, both or neither format, empty input, bad base64
        let other = b"another certificate".to_vec();
        assert_eq!(
            verify_mtls(&other, Some(&std_b64), None).unwrap_err(),
            JwsProofError::BadSignature
        );
        assert_eq!(
            verify_mtls(&other, None, Some(&thumb)).unwrap_err(),
            JwsProofError::BadSignature
        );
        assert!(matches!(
            verify_mtls(&der, Some(&std_b64), Some(&thumb)),
            Err(JwsProofError::Malformed(_))
        ));
        assert!(matches!(
            verify_mtls(&der, None, None),
            Err(JwsProofError::Malformed(_))
        ));
        assert!(matches!(
            verify_mtls(b"", Some(&std_b64), None),
            Err(JwsProofError::Malformed(_))
        ));
        assert!(matches!(
            verify_mtls(&der, Some("***"), None),
            Err(JwsProofError::Malformed(_))
        ));
        // a prefix or an extension of the certificate is not the certificate
        assert!(verify_mtls(&der[..der.len() - 1], Some(&std_b64), None).is_err());
        let mut longer = der.clone();
        longer.push(0);
        assert!(verify_mtls(&longer, Some(&std_b64), None).is_err());
        // a thumbprint that shares a prefix with the right one, or is cut short, is not the thumbprint
        let mut tail_changed = thumb.clone();
        tail_changed.pop();
        tail_changed.push(if thumb.ends_with('A') { 'B' } else { 'A' });
        assert!(verify_mtls(&der, None, Some(&tail_changed)).is_err());
        assert!(verify_mtls(&der, None, Some(&thumb[..thumb.len() - 1])).is_err());
        assert!(verify_mtls(&der, None, Some(&thumb[..4])).is_err());
    }

    #[test]
    fn the_client_cert_header_is_one_byte_sequence() {
        let der = vec![1u8, 2, 3, 4];
        let header = format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        assert_eq!(client_cert_from_header(&header).unwrap(), der);
        assert_eq!(
            client_cert_from_header(&format!("  {header}  ")).unwrap(),
            der
        );
        for bad in ["", "::", "AQIDBA==", ":AQIDBA==", "AQIDBA==:", ":***:"] {
            assert!(client_cert_from_header(bad).is_err(), "{bad:?}");
        }
    }
}
