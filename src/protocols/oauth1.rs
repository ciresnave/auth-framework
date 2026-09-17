//! OAuth 1.0a protocol support (RFC 5849).
//!
//! Provides HMAC-SHA1 signature generation, authorization header construction,
//! and the three-legged OAuth 1.0a flow data structures.

use crate::errors::{AuthError, Result};
use base64::Engine;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// OAuth 1.0a consumer credentials (application).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConsumer {
    pub key: String,
    pub secret: String,
}

/// OAuth 1.0a token credentials (user-authorized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub token: String,
    pub secret: String,
}

/// OAuth 1.0a signature method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureMethod {
    HmacSha1,
    HmacSha256,
    Plaintext,
}

impl SignatureMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HmacSha1 => "HMAC-SHA1",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::Plaintext => "PLAINTEXT",
        }
    }
}

/// A signed OAuth 1.0a request.
#[derive(Debug, Clone)]
pub struct OAuthSignedRequest {
    /// The Authorization header value.
    pub authorization_header: String,
    /// The signature base string (useful for debugging).
    pub signature_base_string: String,
    /// The computed signature.
    pub signature: String,
}

/// OAuth 1.0a request token response (temporary credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTokenResponse {
    pub oauth_token: String,
    pub oauth_token_secret: String,
    pub oauth_callback_confirmed: bool,
}

/// OAuth 1.0a access token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub oauth_token: String,
    pub oauth_token_secret: String,
}

/// OAuth 1.0a client for constructing signed requests.
pub struct OAuth1Client {
    consumer: OAuthConsumer,
    signature_method: SignatureMethod,
}

impl OAuth1Client {
    /// Create a new OAuth 1.0a client.
    pub fn new(consumer: OAuthConsumer, signature_method: SignatureMethod) -> Result<Self> {
        if consumer.key.is_empty() || consumer.secret.is_empty() {
            return Err(AuthError::validation(
                "Consumer key and secret must not be empty",
            ));
        }
        Ok(Self {
            consumer,
            signature_method,
        })
    }

    /// Sign an HTTP request using OAuth 1.0a.
    ///
    /// Returns the signed request with the Authorization header value.
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        token: Option<&OAuthToken>,
        extra_params: Option<&BTreeMap<String, String>>,
    ) -> Result<OAuthSignedRequest> {
        let nonce = generate_nonce()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        // Collect OAuth parameters
        let mut params = BTreeMap::new();
        params.insert("oauth_consumer_key".to_string(), self.consumer.key.clone());
        params.insert("oauth_nonce".to_string(), nonce);
        params.insert(
            "oauth_signature_method".to_string(),
            self.signature_method.as_str().to_string(),
        );
        params.insert("oauth_timestamp".to_string(), timestamp);
        params.insert("oauth_version".to_string(), "1.0".to_string());

        if let Some(t) = token {
            params.insert("oauth_token".to_string(), t.token.clone());
        }

        if let Some(extra) = extra_params {
            for (k, v) in extra {
                params.insert(k.clone(), v.clone());
            }
        }

        // Build signature base string
        let param_string: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let base_string = format!(
            "{}&{}&{}",
            method.to_uppercase(),
            percent_encode(url),
            percent_encode(&param_string)
        );

        // Compute signature
        let token_secret = token.map(|t| t.secret.as_str()).unwrap_or("");
        let signing_key = format!(
            "{}&{}",
            percent_encode(&self.consumer.secret),
            percent_encode(token_secret)
        );

        let signature = match self.signature_method {
            SignatureMethod::HmacSha1 => {
                let key =
                    hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, signing_key.as_bytes());
                let tag = hmac::sign(&key, base_string.as_bytes());
                base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
            }
            SignatureMethod::HmacSha256 => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key.as_bytes());
                let tag = hmac::sign(&key, base_string.as_bytes());
                base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
            }
            SignatureMethod::Plaintext => signing_key.clone(),
        };

        // Build Authorization header
        params.insert("oauth_signature".to_string(), signature.clone());

        let auth_header = format!(
            "OAuth {}",
            params
                .iter()
                .filter(|(k, _)| k.starts_with("oauth_"))
                .map(|(k, v)| format!("{}=\"{}\"", percent_encode(k), percent_encode(v)))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(OAuthSignedRequest {
            authorization_header: auth_header,
            signature_base_string: base_string,
            signature,
        })
    }

    /// Build the authorization URL for the user to visit.
    pub fn build_authorize_url(&self, base_url: &str, request_token: &str) -> String {
        format!("{}?oauth_token={}", base_url, percent_encode(request_token))
    }

    /// Parse a request token response body (form-encoded).
    pub fn parse_request_token_response(body: &str) -> Result<RequestTokenResponse> {
        let params = parse_form_body(body);
        let token = params
            .get("oauth_token")
            .ok_or_else(|| AuthError::validation("Missing oauth_token"))?
            .clone();
        let secret = params
            .get("oauth_token_secret")
            .ok_or_else(|| AuthError::validation("Missing oauth_token_secret"))?
            .clone();
        let confirmed = params
            .get("oauth_callback_confirmed")
            .map(|v| v == "true")
            .unwrap_or(false);

        Ok(RequestTokenResponse {
            oauth_token: token,
            oauth_token_secret: secret,
            oauth_callback_confirmed: confirmed,
        })
    }

    /// Parse an access token response body (form-encoded).
    pub fn parse_access_token_response(body: &str) -> Result<AccessTokenResponse> {
        let params = parse_form_body(body);
        let token = params
            .get("oauth_token")
            .ok_or_else(|| AuthError::validation("Missing oauth_token"))?
            .clone();
        let secret = params
            .get("oauth_token_secret")
            .ok_or_else(|| AuthError::validation("Missing oauth_token_secret"))?
            .clone();

        Ok(AccessTokenResponse {
            oauth_token: token,
            oauth_token_secret: secret,
        })
    }
}

/// RFC 3986 percent-encoding.
fn percent_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Parse application/x-www-form-urlencoded response body.
fn parse_form_body(body: &str) -> BTreeMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Generate a cryptographically random nonce.
fn generate_nonce() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)
        .map_err(|_| AuthError::crypto("Failed to generate nonce".to_string()))?;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_consumer() -> OAuthConsumer {
        OAuthConsumer {
            key: "dpf43f3p2l4k3l03".to_string(),
            secret: "kd94hf93k423kf44".to_string(),
        }
    }

    #[test]
    fn test_create_client() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha1).unwrap();
        assert_eq!(client.consumer.key, "dpf43f3p2l4k3l03");
    }

    #[test]
    fn test_empty_consumer_rejected() {
        let consumer = OAuthConsumer {
            key: String::new(),
            secret: "secret".to_string(),
        };
        assert!(OAuth1Client::new(consumer, SignatureMethod::HmacSha1).is_err());
    }

    #[test]
    fn test_sign_request_hmac_sha1() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha1).unwrap();
        let signed = client
            .sign_request("GET", "https://api.example.com/resource", None, None)
            .unwrap();

        assert!(signed.authorization_header.starts_with("OAuth "));
        assert!(signed.authorization_header.contains("oauth_consumer_key="));
        assert!(signed.authorization_header.contains("oauth_signature="));
        assert!(signed.authorization_header.contains("oauth_nonce="));
        assert!(!signed.signature.is_empty());
    }

    #[test]
    fn test_sign_request_with_token() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha1).unwrap();
        let token = OAuthToken {
            token: "nnch734d00sl2jdk".to_string(),
            secret: "pfkkdhi9sl3r4s00".to_string(),
        };
        let signed = client
            .sign_request("POST", "https://api.example.com/post", Some(&token), None)
            .unwrap();

        assert!(signed.authorization_header.contains("oauth_token="));
        assert!(!signed.signature.is_empty());
    }

    #[test]
    fn test_sign_request_hmac_sha256() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha256).unwrap();
        let signed = client
            .sign_request("GET", "https://api.example.com/resource", None, None)
            .unwrap();
        assert!(signed.authorization_header.contains("HMAC-SHA256"));
    }

    #[test]
    fn test_sign_request_plaintext() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::Plaintext).unwrap();
        let signed = client
            .sign_request("GET", "https://api.example.com/resource", None, None)
            .unwrap();
        // Plaintext signature = consumer_secret&token_secret
        assert!(signed.signature.contains("kd94hf93k423kf44"));
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello"), "hello");
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("~.-_"), "~.-_");
    }

    #[test]
    fn test_signature_base_string_format() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha1).unwrap();
        let signed = client
            .sign_request("GET", "https://api.example.com/1/resource", None, None)
            .unwrap();
        assert!(signed.signature_base_string.starts_with("GET&"));
        assert!(
            signed
                .signature_base_string
                .contains("https%3A%2F%2Fapi.example.com%2F1%2Fresource")
        );
    }

    #[test]
    fn test_build_authorize_url() {
        let client = OAuth1Client::new(test_consumer(), SignatureMethod::HmacSha1).unwrap();
        let url =
            client.build_authorize_url("https://api.example.com/authorize", "hh5s93j4hdidpola");
        assert_eq!(
            url,
            "https://api.example.com/authorize?oauth_token=hh5s93j4hdidpola"
        );
    }

    #[test]
    fn test_parse_request_token_response() {
        let body = "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true";
        let resp = OAuth1Client::parse_request_token_response(body).unwrap();
        assert_eq!(resp.oauth_token, "hh5s93j4hdidpola");
        assert_eq!(resp.oauth_token_secret, "hdhd0244k9j7ao03");
        assert!(resp.oauth_callback_confirmed);
    }

    #[test]
    fn test_parse_request_token_missing_field() {
        let body = "oauth_token=xyz";
        assert!(OAuth1Client::parse_request_token_response(body).is_err());
    }

    #[test]
    fn test_parse_access_token_response() {
        let body = "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00";
        let resp = OAuth1Client::parse_access_token_response(body).unwrap();
        assert_eq!(resp.oauth_token, "nnch734d00sl2jdk");
        assert_eq!(resp.oauth_token_secret, "pfkkdhi9sl3r4s00");
    }

    #[test]
    fn test_different_consumers_different_signatures() {
        let c1 = OAuth1Client::new(
            OAuthConsumer {
                key: "key1".to_string(),
                secret: "secret1".to_string(),
            },
            SignatureMethod::HmacSha1,
        )
        .unwrap();
        let c2 = OAuth1Client::new(
            OAuthConsumer {
                key: "key2".to_string(),
                secret: "secret2".to_string(),
            },
            SignatureMethod::HmacSha1,
        )
        .unwrap();

        let s1 = c1
            .sign_request("GET", "https://example.com", None, None)
            .unwrap();
        let s2 = c2
            .sign_request("GET", "https://example.com", None, None)
            .unwrap();
        assert_ne!(s1.signature, s2.signature);
    }

    #[test]
    fn test_signature_method_as_str() {
        assert_eq!(SignatureMethod::HmacSha1.as_str(), "HMAC-SHA1");
        assert_eq!(SignatureMethod::HmacSha256.as_str(), "HMAC-SHA256");
        assert_eq!(SignatureMethod::Plaintext.as_str(), "PLAINTEXT");
    }
}
