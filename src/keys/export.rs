//! Public export forms: JWK, JWKS and SPKI PEM. Nothing here can hold or print a
//! private parameter: [`PublicJwk::from_value`] refuses a JWK that carries one.

use super::{Kid, jwk_thumbprint_value};
use crate::errors::{AuthError, Result};
use base64::Engine;
use serde_json::{Map, Value, json};

/// A public JWK for an RSA, EC or OKP key, with its optional metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicJwk {
    /// The key-type parameters (`kty` and the public members).
    params: Map<String, Value>,
    /// `kid`.
    pub kid: Option<Kid>,
    /// `use` (`sig` or `enc`).
    pub use_: Option<String>,
    /// `alg`.
    pub alg: Option<String>,
    /// `key_ops`.
    pub key_ops: Option<Vec<String>>,
}

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl PublicJwk {
    /// RSA public key from base64url `n` and `e`.
    pub fn rsa(n: &str, e: &str) -> Result<Self> {
        Self::from_value(&json!({"kty":"RSA","n":n,"e":e}))
    }

    /// EC public key (`P-256`, `P-384`, `P-521`).
    pub fn ec(crv: &str, x: &str, y: &str) -> Result<Self> {
        Self::from_value(&json!({"kty":"EC","crv":crv,"x":x,"y":y}))
    }

    /// OKP public key (`Ed25519`, `X25519`, ...).
    pub fn okp(crv: &str, x: &str) -> Result<Self> {
        Self::from_value(&json!({"kty":"OKP","crv":crv,"x":x}))
    }

    /// Parse a JWK. Fails if it carries a private member or has no thumbprint
    /// (so a symmetric `oct` key can never be exported as public).
    pub fn from_value(v: &Value) -> Result<Self> {
        let obj = v
            .as_object()
            .ok_or_else(|| AuthError::validation("JWK must be a JSON object"))?;
        if let Some(name) = PRIVATE_MEMBERS.iter().find(|m| obj.contains_key(**m)) {
            return Err(AuthError::validation(format!(
                "refusing a JWK with the private member '{name}' as a public export"
            )));
        }
        jwk_thumbprint_value(v)?;
        let s = |n: &str| obj.get(n).and_then(Value::as_str).map(str::to_owned);
        let mut params = Map::new();
        for name in ["kty", "crv", "x", "y", "n", "e"] {
            if let Some(val) = obj.get(name) {
                params.insert(name.to_owned(), val.clone());
            }
        }
        Ok(Self {
            params,
            kid: s("kid").map(Kid::new).transpose()?,
            use_: s("use"),
            alg: s("alg"),
            key_ops: obj.get("key_ops").and_then(|k| {
                k.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
            }),
        })
    }

    /// RFC 7638 thumbprint of this key.
    pub fn thumbprint(&self) -> Result<String> {
        jwk_thumbprint_value(&Value::Object(self.params.clone()))
    }

    /// Set `kid` to this key's own thumbprint (the default key id).
    pub fn with_thumbprint_kid(mut self) -> Result<Self> {
        self.kid = Some(Kid::new(self.thumbprint()?)?);
        Ok(self)
    }

    /// JSON form.
    pub fn to_value(&self) -> Value {
        let mut m = self.params.clone();
        if let Some(k) = &self.kid {
            m.insert("kid".into(), json!(k.as_str()));
        }
        if let Some(u) = &self.use_ {
            m.insert("use".into(), json!(u));
        }
        if let Some(a) = &self.alg {
            m.insert("alg".into(), json!(a));
        }
        if let Some(o) = &self.key_ops {
            m.insert("key_ops".into(), json!(o));
        }
        Value::Object(m)
    }
}

/// A JWK Set (RFC 7517 section 5).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JwkSet {
    /// The keys, in publication order.
    pub keys: Vec<PublicJwk>,
}

impl JwkSet {
    /// JSON form: `{"keys":[...]}`.
    pub fn to_value(&self) -> Value {
        json!({"keys": self.keys.iter().map(PublicJwk::to_value).collect::<Vec<_>>()})
    }
}

/// PEM-encode a DER `SubjectPublicKeyInfo` as `PUBLIC KEY` (RFC 7468).
pub fn spki_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    #[test]
    fn private_members_are_refused() {
        for m in PRIVATE_MEMBERS {
            let mut v = json!({"kty":"OKP","crv":"Ed25519","x":X});
            v[m] = json!("AAAA");
            assert!(PublicJwk::from_value(&v).is_err(), "{m}");
        }
        assert!(PublicJwk::from_value(&json!({"kty":"oct","k":"AAAA"})).is_err());
    }

    #[test]
    fn thumbprint_kid_round_trips_and_is_published() {
        let j = PublicJwk::okp("Ed25519", X)
            .unwrap()
            .with_thumbprint_kid()
            .unwrap();
        let tp = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
        assert_eq!(j.kid.as_ref().unwrap().as_str(), tp);
        let set = JwkSet {
            keys: vec![j.clone()],
        }
        .to_value();
        assert_eq!(set["keys"][0]["kid"], tp);
        assert_eq!(set["keys"][0]["x"], X);
        assert!(set["keys"][0].get("d").is_none());
        assert_eq!(PublicJwk::from_value(&set["keys"][0]).unwrap(), j);
    }

    #[test]
    fn metadata_is_exported() {
        let mut j = PublicJwk::ec("P-256", "AAAA", "BBBB").unwrap();
        j.use_ = Some("sig".into());
        j.alg = Some("ES256".into());
        j.key_ops = Some(vec!["verify".into()]);
        let v = j.to_value();
        assert_eq!(
            (v["use"].as_str(), v["alg"].as_str()),
            (Some("sig"), Some("ES256"))
        );
        assert_eq!(v["key_ops"], json!(["verify"]));
    }

    #[test]
    fn spki_pem_wraps_at_64_columns() {
        let pem = spki_pem(&[7u8; 100]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN PUBLIC KEY-----");
        assert_eq!(*lines.last().unwrap(), "-----END PUBLIC KEY-----");
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 64));
        assert_eq!(lines[1].len(), 64);
    }
}
