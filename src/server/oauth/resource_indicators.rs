// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8707 — Resource Indicators for OAuth 2.0
//!
//! Adds the `resource` parameter to authorization and token requests so clients
//! can signal which protected resource(s) they intend to access.  The
//! authorization server can use this to audience-restrict issued tokens.
//!
//! <https://datatracker.ietf.org/doc/html/rfc8707>

use crate::errors::{AuthError, Result};

/// Validate that every entry in `resources` is an absolute URI without a
/// fragment component, as required by RFC 8707 §2.
///
/// Returns `Ok(())` when all entries are valid, or an error describing the
/// first invalid entry.
pub fn validate_resource_indicators(resources: &[String]) -> Result<()> {
    for res in resources {
        if res.is_empty() {
            return Err(AuthError::validation(
                "resource parameter must not be empty".to_string(),
            ));
        }

        // Must be a valid absolute URI.
        let parsed = url::Url::parse(res).map_err(|e| {
            AuthError::validation(format!(
                "resource indicator is not a valid URI: {res} ({e})"
            ))
        })?;

        // RFC 8707 §2: "MUST NOT include a fragment component."
        if parsed.fragment().is_some() {
            return Err(AuthError::validation(format!(
                "resource indicator must not contain a fragment: {res}"
            )));
        }

        // Must be an absolute URI (scheme is required).
        if parsed.scheme().is_empty() {
            return Err(AuthError::validation(format!(
                "resource indicator must be an absolute URI: {res}"
            )));
        }
    }
    Ok(())
}

/// Check that the `resource` values presented at the token endpoint are a
/// subset of those originally requested at the authorization endpoint.
///
/// RFC 8707 §2: when the token request includes a `resource` parameter, it
/// MUST be a subset of the resources requested in the corresponding
/// authorization request.
pub fn validate_token_resource_subset(
    token_resources: &[String],
    authz_resources: &[String],
) -> Result<()> {
    for res in token_resources {
        if !authz_resources.contains(res) {
            return Err(AuthError::validation(format!(
                "resource '{res}' was not requested in the authorization request"
            )));
        }
    }
    Ok(())
}

/// Build the `aud` (audience) claim for a token based on the requested
/// resources.  If no resources were requested, returns `None` so the caller
/// can fall back to its default audience.
pub fn audience_from_resources(resources: &[String]) -> Option<Vec<String>> {
    if resources.is_empty() {
        None
    } else {
        Some(resources.to_vec())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_https_resource() {
        let res = vec!["https://api.example.com/v1".to_string()];
        assert!(validate_resource_indicators(&res).is_ok());
    }

    #[test]
    fn valid_multiple_resources() {
        let res = vec![
            "https://api.example.com/v1".to_string(),
            "https://data.example.com".to_string(),
        ];
        assert!(validate_resource_indicators(&res).is_ok());
    }

    #[test]
    fn rejects_empty_resource() {
        let res = vec!["".to_string()];
        assert!(validate_resource_indicators(&res).is_err());
    }

    #[test]
    fn rejects_fragment() {
        let res = vec!["https://api.example.com/v1#section".to_string()];
        let err = validate_resource_indicators(&res).unwrap_err();
        assert!(err.to_string().contains("fragment"));
    }

    #[test]
    fn rejects_relative_uri() {
        let res = vec!["/relative/path".to_string()];
        assert!(validate_resource_indicators(&res).is_err());
    }

    #[test]
    fn subset_check_passes() {
        let authz = vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string(),
        ];
        let token = vec!["https://a.example.com".to_string()];
        assert!(validate_token_resource_subset(&token, &authz).is_ok());
    }

    #[test]
    fn subset_check_fails_on_extra_resource() {
        let authz = vec!["https://a.example.com".to_string()];
        let token = vec![
            "https://a.example.com".to_string(),
            "https://c.example.com".to_string(),
        ];
        assert!(validate_token_resource_subset(&token, &authz).is_err());
    }

    #[test]
    fn audience_from_resources_none_when_empty() {
        assert!(audience_from_resources(&[]).is_none());
    }

    #[test]
    fn audience_from_resources_returns_list() {
        let res = vec!["https://api.example.com".to_string()];
        let aud = audience_from_resources(&res).unwrap();
        assert_eq!(aud, res);
    }
}
