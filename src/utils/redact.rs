// SPDX-License-Identifier: MIT OR Apache-2.0
//! Helpers for `Debug` impls that must not print secret values.
//!
//! A field that holds a secret is shown as `<redacted>`; an optional one keeps its shape
//! (`None` stays `None`, `Some(..)` becomes `Some(<redacted>)`), so a log line still says whether
//! the secret is configured.

use std::fmt;

/// What a secret field prints as.
pub(crate) enum Redacted {
    Absent,
    Present,
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Redacted::Absent => f.write_str("None"),
            Redacted::Present => f.write_str("<redacted>"),
        }
    }
}

/// Anything a secret can be stored in.
pub(crate) trait Secret {
    fn redacted(&self) -> Redacted;
}

impl Secret for String {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl Secret for Vec<String> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl Secret for Vec<u8> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T> Secret for Option<T> {
    fn redacted(&self) -> Redacted {
        if self.is_some() {
            Redacted::Present
        } else {
            Redacted::Absent
        }
    }
}

/// Maps, sets, JSON values and shared wrappers: the whole container is hidden, keys included (a map
/// keyed by a token or session id would print it).
impl Secret for serde_json::Value {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K, V, S> Secret for std::collections::HashMap<K, V, S> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K, V> Secret for std::collections::BTreeMap<K, V> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T, S> Secret for std::collections::HashSet<T, S> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<K: Eq + std::hash::Hash, V> Secret for dashmap::DashMap<K, V> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::Arc<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for tokio::sync::RwLock<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for tokio::sync::Mutex<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::Mutex<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

impl<T: ?Sized> Secret for std::sync::RwLock<T> {
    fn redacted(&self) -> Redacted {
        Redacted::Present
    }
}

/// `Zeroizing<T>` forwards `Debug` to the secret it wraps, so a derived `Debug` prints it.
impl<T: zeroize::Zeroize + Secret> Secret for zeroize::Zeroizing<T> {
    fn redacted(&self) -> Redacted {
        (**self).redacted()
    }
}

/// A `Debug` impl that prints the `plain` fields as they are and the `secret` ones as `<redacted>`.
/// The struct is destructured **without** `..`, so adding a field to it is a compile error until it is
/// listed as plain or secret: a new secret cannot silently join the output.
macro_rules! redacting_debug {
    ($ty:ident $(<$lt:lifetime>)?, plain: [$($p:ident),* $(,)?], secret: [$($s:ident),+ $(,)?]) => {
        impl $(<$lt>)? ::std::fmt::Debug for $ty $(<$lt>)? {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let $ty { $($p,)* $($s,)* } = self;
                let mut d = f.debug_struct(stringify!($ty));
                $( d.field(stringify!($p), $p); )*
                $( d.field(stringify!($s), &$crate::utils::redact::redacted($s)); )*
                d.finish()
            }
        }
    };
}
pub(crate) use redacting_debug;

/// The value to hand to `DebugStruct::field` in place of a secret.
pub(crate) fn redacted<T: Secret>(value: &T) -> Redacted {
    value.redacted()
}

/// A short reference to a high-entropy identifier (a session id, a token) that is safe to put in a log
/// line: it lets two lines about the same value be matched, and it cannot be turned back into the
/// value. Low-entropy secrets (one-time codes, passwords) must not be fingerprinted -- a 32-bit prefix
/// of their hash can be brute-forced -- and are logged as `"<redacted>"` instead.
pub(crate) struct Fingerprint(String);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `sha256:` and the first four bytes of the SHA-256 of `value`, in hex.
pub(crate) fn fingerprint(value: &str) -> Fingerprint {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::from("sha256:");
    for byte in &digest[..4] {
        out.push_str(&format!("{byte:02x}"));
    }
    Fingerprint(out)
}

/// `scheme://host[:port]` of a URL, for a log line: user info, path, query and fragment are dropped,
/// because a webhook URL carries its secret in the path or the query (`hooks.slack.com/services/..`).
/// Text that is not an absolute URL is logged as `<invalid url>`.
pub(crate) fn url_origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<invalid url>".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let scheme_ok = !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !scheme_ok || host.is_empty() {
        return "<invalid url>".to_string();
    }
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_origin_keeps_only_scheme_and_host() {
        assert_eq!(
            url_origin("https://hooks.slack.com/services/T000/B000/SECRET-MARKER"),
            "https://hooks.slack.com"
        );
        assert_eq!(
            url_origin("https://user:SECRET-MARKER@example.com:8443/p?license_key=SECRET-MARKER#f"),
            "https://example.com:8443"
        );
        assert_eq!(
            url_origin("https://example.com?key=SECRET-MARKER"),
            "https://example.com"
        );
    }

    #[test]
    fn url_origin_does_not_echo_text_that_is_not_a_url() {
        assert_eq!(url_origin("SECRET-MARKER"), "<invalid url>");
        assert_eq!(url_origin("https:///SECRET-MARKER"), "<invalid url>");
        assert_eq!(url_origin("://example.com"), "<invalid url>");
    }

    /// SHA-256("abc") starts ba7816bf (FIPS 180-2 test vector).
    #[test]
    fn fingerprint_is_a_prefix_of_the_sha256_digest() {
        assert_eq!(fingerprint("abc").to_string(), "sha256:ba7816bf");
        assert_eq!(format!("{:?}", fingerprint("abc")), "sha256:ba7816bf");
    }

    #[test]
    fn fingerprint_does_not_contain_the_value() {
        let secret = "SECRET-MARKER-7f3a9c";
        assert!(!fingerprint(secret).to_string().contains(secret));
        assert_ne!(
            fingerprint(secret).to_string(),
            fingerprint("other").to_string()
        );
    }
}

/// `{:?}` of a type that holds a secret must not print the secret. Each test builds the type with a
/// distinctive secret, checks the ordinary fields still print (the control: the output is a real
/// `Debug` of the value, not an empty string) and that the secret does not. A failure names the type
/// and never prints the value.
#[cfg(test)]
mod secret_field_debug_tests {
    use zeroize::Zeroizing;

    const SECRET: &str = "s3cr3t-value-0b6f1d2a-never-in-a-log";

    fn hides(type_name: &str, debug: String, shown: &str) {
        assert!(
            debug.contains(shown),
            "{type_name}: the Debug output lost its ordinary field `{shown}`"
        );
        assert!(
            debug.contains("<redacted>"),
            "{type_name}: the Debug output does not show that a secret is present"
        );
        assert!(
            !debug.contains(SECRET),
            "{type_name}: Debug prints its secret"
        );
    }

    fn z() -> Zeroizing<String> {
        Zeroizing::new(SECRET.to_string())
    }

    #[test]
    fn grafana_config() {
        let v = crate::deployment::monitoring::GrafanaConfig {
            endpoint: "https://grafana.example.test".into(),
            api_key: z(),
            organization: "org".into(),
            datasource: "ds".into(),
            auto_provision: true,
        };
        hides("GrafanaConfig", format!("{v:?}"), "grafana.example.test");
    }

    #[test]
    fn sms_config() {
        let v = crate::security::SmsConfig {
            provider: "twilio-test".into(),
            api_key: z(),
            from_number: "+100".into(),
        };
        hides("SmsConfig", format!("{v:?}"), "twilio-test");
    }

    #[test]
    fn secure_jwt_config() {
        let v = crate::security::secure_jwt::SecureJwtConfig {
            jwt_secret: z(),
            ..Default::default()
        };
        hides("SecureJwtConfig", format!("{v:?}"), "require_jti");
    }

    #[test]
    fn radius_config() {
        let v = crate::protocols::radius::RadiusConfig {
            server_addr: "radius.example.test:1812".into(),
            shared_secret: z(),
            ..Default::default()
        };
        hides("RadiusConfig", format!("{v:?}"), "radius.example.test");
    }

    #[test]
    fn sts_config() {
        let v = crate::protocols::ws_trust::StsConfig {
            issuer: "sts-issuer-test".into(),
            jwt_signing_secret: z(),
            ..Default::default()
        };
        hides("StsConfig", format!("{v:?}"), "sts-issuer-test");
    }

    #[test]
    fn caep_config() {
        let v = crate::server::security::caep_continuous_access::CaepConfig {
            event_stream_url: "https://caep.example.test".into(),
            signing_secret: z(),
            ..Default::default()
        };
        hides("CaepConfig", format!("{v:?}"), "caep.example.test");
    }

    #[test]
    fn oauth1_consumer_and_token() {
        let consumer = crate::protocols::oauth1::OAuthConsumer {
            key: "consumer-key-test".into(),
            secret: z(),
        };
        hides(
            "OAuthConsumer",
            format!("{consumer:?}"),
            "consumer-key-test",
        );
        let token = crate::protocols::oauth1::OAuthToken {
            token: SECRET.to_string(),
            secret: z(),
        };
        let shown = format!("{token:?}");
        assert!(!shown.contains(SECRET), "OAuthToken: Debug prints a secret");
        assert!(shown.contains("<redacted>"), "OAuthToken: no marker");
    }

    #[test]
    fn enhanced_client_credentials() {
        let v = crate::server::oauth::oauth2_enhanced_storage::EnhancedClientCredentials {
            client_id: "client-id-test".into(),
            client_secret_hash: z(),
            client_type: crate::client::ClientType::Confidential,
            redirect_uris: vec![],
            allowed_scopes: vec![],
            grant_types: vec![],
            created_at: std::time::SystemTime::UNIX_EPOCH,
            is_active: true,
        };
        hides(
            "EnhancedClientCredentials",
            format!("{v:?}"),
            "client-id-test",
        );
    }

    #[test]
    fn jws_proof_context() {
        let jwk = serde_json::json!({"kty": "EC"});
        let v = crate::protocols::gnap_jws::JwsProofContext {
            jwk: &jwk,
            method: "POST",
            uri: "https://as.example.test/tx",
            body: b"",
            access_token: Some(SECRET),
            now: 1,
            max_skew_secs: 60,
        };
        hides("JwsProofContext", format!("{v:?}"), "as.example.test");
    }

    #[test]
    fn rar_resource_discovery_response() {
        let v = crate::server::oauth::rich_authorization_requests::RarResourceDiscoveryResponse {
            resources: vec![],
            has_more: true,
            continuation_token: Some(SECRET.to_string()),
        };
        hides("RarResourceDiscoveryResponse", format!("{v:?}"), "has_more");
    }
}
