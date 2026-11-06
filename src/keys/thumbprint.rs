// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one RFC 7638 JWK thumbprint (SHA-256) for RSA, EC and OKP keys.

use crate::errors::{AuthError, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn member<'a>(jwk: &'a Value, name: &str) -> Result<&'a str> {
    jwk.get(name).and_then(Value::as_str).ok_or_else(|| {
        AuthError::validation(format!("JWK is missing the '{name}' member as a string"))
    })
}

fn quoted(s: &str) -> String {
    Value::String(s.to_owned()).to_string()
}

/// Thumbprint of a JWK given as JSON. Only the required members count (RFC 7638
/// section 3.2), in lexicographic order, so extra members (`kid`, `use`, `alg`,
/// private parameters) never change the result. A missing or non-string required
/// member, an unknown `kty`, or an RSA integer with a leading zero octet (which
/// would give one key two thumbprints) is an error, never an empty-string default.
pub fn jwk_thumbprint_value(jwk: &Value) -> Result<String> {
    let canonical = match member(jwk, "kty")? {
        "RSA" => {
            for name in ["n", "e"] {
                let raw = URL_SAFE_NO_PAD.decode(member(jwk, name)?).ok();
                if raw
                    .as_deref()
                    .is_none_or(|r| r.first().is_none_or(|&b| b == 0))
                {
                    return Err(AuthError::validation(format!(
                        "RSA JWK member '{name}' is not a minimal base64url integer"
                    )));
                }
            }
            format!(
                r#"{{"e":{},"kty":"RSA","n":{}}}"#,
                quoted(member(jwk, "e")?),
                quoted(member(jwk, "n")?)
            )
        }
        "EC" => format!(
            r#"{{"crv":{},"kty":"EC","x":{},"y":{}}}"#,
            quoted(member(jwk, "crv")?),
            quoted(member(jwk, "x")?),
            quoted(member(jwk, "y")?)
        ),
        "OKP" => format!(
            r#"{{"crv":{},"kty":"OKP","x":{}}}"#,
            quoted(member(jwk, "crv")?),
            quoted(member(jwk, "x")?)
        ),
        other => {
            return Err(AuthError::validation(format!(
                "unsupported JWK key type for a thumbprint: {other}"
            )));
        }
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

/// Thumbprint of a JWK given as JSON text.
pub fn jwk_thumbprint(jwk_json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(jwk_json)
        .map_err(|e| AuthError::validation(format!("JWK is not valid JSON: {e}")))?;
    jwk_thumbprint_value(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // RFC 7638 section 3.1.
    const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    #[test]
    fn rfc7638_rsa_vector() {
        let jwk = json!({"kty":"RSA","n":RFC7638_N,"e":"AQAB","alg":"RS256","kid":"2011-04-29"});
        assert_eq!(
            jwk_thumbprint_value(&jwk).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn rfc8037_okp_vector() {
        let jwk =
            json!({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        assert_eq!(
            jwk_thumbprint_value(&jwk).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn extra_and_private_members_do_not_change_it() {
        let a = json!({"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"});
        let b = json!({"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB","d":"secret","kid":"k","use":"sig"});
        assert_eq!(
            jwk_thumbprint_value(&a).unwrap(),
            jwk_thumbprint_value(&b).unwrap()
        );
    }

    #[test]
    fn missing_member_is_an_error_not_an_empty_default() {
        assert!(jwk_thumbprint_value(&json!({"kty":"EC","crv":"P-256","x":"AAAA"})).is_err());
        assert!(jwk_thumbprint_value(&json!({"kty":"OKP","x":"AAAA"})).is_err());
        assert!(jwk_thumbprint_value(&json!({"kty":"EC","crv":"P-256","x":1,"y":"B"})).is_err());
        assert!(jwk_thumbprint_value(&json!({"crv":"P-256"})).is_err());
    }

    #[test]
    fn unknown_kty_and_oct_are_refused() {
        assert!(jwk_thumbprint_value(&json!({"kty":"oct","k":"AAAA"})).is_err());
        assert!(jwk_thumbprint_value(&json!({"kty":"XYZ"})).is_err());
    }

    #[test]
    fn rsa_leading_zero_octet_is_refused() {
        // "AAEAAQ" decodes to 00 01 00 01.
        let jwk = json!({"kty":"RSA","n":RFC7638_N,"e":"AAEAAQ"});
        assert!(jwk_thumbprint_value(&jwk).is_err());
    }

    #[test]
    fn quote_in_a_member_is_escaped_not_injected() {
        let a = json!({"kty":"OKP","crv":"Ed25519","x":"a\",\"y\":\"b"});
        let b = json!({"kty":"OKP","crv":"Ed25519","x":"a"});
        assert_ne!(
            jwk_thumbprint_value(&a).unwrap(),
            jwk_thumbprint_value(&b).unwrap()
        );
    }

    #[test]
    fn text_form_matches_value_form() {
        let s =
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        assert_eq!(
            jwk_thumbprint(s).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert!(jwk_thumbprint("not json").is_err());
    }
}
