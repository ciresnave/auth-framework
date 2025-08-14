//! Common Validation Utilities
//!
//! This module provides shared validation functions to eliminate
//! duplication across server modules.

use crate::errors::{AuthError, Result};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Common JWT validation utilities
pub mod jwt {
    use super::*;
    use jsonwebtoken::decode_header;

    /// Validate JWT structure and format
    pub fn validate_jwt_format(token: &str) -> Result<()> {
        if token.is_empty() {
            return Err(AuthError::validation("JWT token is empty"));
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::validation(
                "Invalid JWT format: must have 3 parts",
            ));
        }

        // Validate header can be decoded
        decode_header(token)
            .map_err(|e| AuthError::validation(format!("Invalid JWT header: {}", e)))?;

        Ok(())
    }

    /// Extract claims without signature validation (for inspection)
    pub fn extract_claims_unsafe(token: &str) -> Result<serde_json::Value> {
        validate_jwt_format(token)?;

        let parts: Vec<&str> = token.split('.').collect();
        let payload = parts[1];

        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| AuthError::validation(format!("Invalid JWT payload encoding: {}", e)))?;

        let claims: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| AuthError::validation(format!("Invalid JWT payload JSON: {}", e)))?;

        Ok(claims)
    }

    /// Validate JWT timestamp claims (exp, iat, nbf)
    pub fn validate_time_claims(claims: &serde_json::Value) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Check expiration
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64())
            && now >= exp {
                return Err(AuthError::validation("Token has expired"));
            }

        // Check not before
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64())
            && now < nbf {
                return Err(AuthError::validation("Token not yet valid (nbf)"));
            }

        // Check issued at (reasonable bounds)
        if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
            let max_age = 24 * 60 * 60; // 24 hours
            if now - iat > max_age {
                return Err(AuthError::validation("Token too old"));
            }
        }

        Ok(())
    }

    /// Validate required JWT claims
    pub fn validate_required_claims(claims: &serde_json::Value, required: &[&str]) -> Result<()> {
        for claim in required {
            if claims.get(claim).is_none() {
                return Err(AuthError::validation(format!(
                    "Missing required claim: {}",
                    claim
                )));
            }
        }
        Ok(())
    }
}

/// Common token validation utilities
pub mod token {
    use super::*;

    /// Token type validation
    pub fn validate_token_type(token_type: &str, allowed_types: &[&str]) -> Result<()> {
        if !allowed_types.contains(&token_type) {
            return Err(AuthError::validation(format!(
                "Unsupported token type: {}",
                token_type
            )));
        }
        Ok(())
    }

    /// Validate token format (basic structure)
    pub fn validate_token_format(token: &str, token_type: &str) -> Result<()> {
        if token.is_empty() {
            return Err(AuthError::validation("Token is empty"));
        }

        match token_type {
            "urn:ietf:params:oauth:token-type:jwt" => jwt::validate_jwt_format(token),
            "urn:ietf:params:oauth:token-type:access_token" => {
                // Bearer token validation
                if token.len() < 10 {
                    return Err(AuthError::validation("Access token too short"));
                }
                Ok(())
            }
            "urn:ietf:params:oauth:token-type:refresh_token" => {
                // Refresh token validation
                if token.len() < 20 {
                    return Err(AuthError::validation("Refresh token too short"));
                }
                Ok(())
            }
            _ => Ok(()), // Allow other token types
        }
    }

    /// Validate scope format
    pub fn validate_scope(scope: &str) -> Result<Vec<String>> {
        if scope.is_empty() {
            return Ok(vec![]);
        }

        let scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();

        // Validate each scope
        for scope in &scopes {
            if scope.is_empty() {
                return Err(AuthError::validation("Empty scope value"));
            }

            // Basic scope format validation
            if !scope.chars().all(|c| {
                c.is_alphanumeric() || c == ':' || c == '/' || c == '.' || c == '-' || c == '_'
            }) {
                return Err(AuthError::validation(format!(
                    "Invalid scope format: {}",
                    scope
                )));
            }
        }

        Ok(scopes)
    }
}

/// Common client validation utilities
pub mod client {
    use super::*;

    /// Validate client ID format
    pub fn validate_client_id(client_id: &str) -> Result<()> {
        if client_id.is_empty() {
            return Err(AuthError::validation("Client ID is empty"));
        }

        if client_id.len() < 3 {
            return Err(AuthError::validation("Client ID too short"));
        }

        if client_id.len() > 255 {
            return Err(AuthError::validation("Client ID too long"));
        }

        // Validate character set
        if !client_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AuthError::validation(
                "Client ID contains invalid characters",
            ));
        }

        Ok(())
    }

    /// Validate redirect URI
    pub fn validate_redirect_uri(uri: &str) -> Result<()> {
        if uri.is_empty() {
            return Err(AuthError::validation("Redirect URI is empty"));
        }

        // Must be absolute URI
        if !uri.starts_with("http://")
            && !uri.starts_with("https://")
            && !uri.starts_with("custom://")
        {
            return Err(AuthError::validation("Redirect URI must be absolute"));
        }

        // No fragments allowed
        if uri.contains('#') {
            return Err(AuthError::validation(
                "Redirect URI cannot contain fragments",
            ));
        }

        Ok(())
    }

    /// Validate grant type
    pub fn validate_grant_type(grant_type: &str, allowed_grants: &[&str]) -> Result<()> {
        if !allowed_grants.contains(&grant_type) {
            return Err(AuthError::validation(format!(
                "Unsupported grant type: {}",
                grant_type
            )));
        }
        Ok(())
    }
}

/// Common request validation utilities
pub mod request {
    use super::*;

    /// Validate required parameters
    pub fn validate_required_params(
        params: &HashMap<String, String>,
        required: &[&str],
    ) -> Result<()> {
        for param in required {
            if !params.contains_key(*param) || params[*param].trim().is_empty() {
                return Err(AuthError::validation(format!(
                    "Missing parameter: {}",
                    param
                )));
            }
        }
        Ok(())
    }

    /// Validate parameter format
    pub fn validate_param_format(value: &str, param_name: &str, pattern: &str) -> Result<()> {
        // Basic validation without regex for now
        if value.is_empty() {
            return Err(AuthError::validation(format!(
                "Parameter {} cannot be empty",
                param_name
            )));
        }

        // Basic pattern checks
        match pattern {
            "alphanum" => {
                if !value.chars().all(|c| c.is_alphanumeric()) {
                    return Err(AuthError::validation(format!(
                        "Parameter {} must be alphanumeric",
                        param_name
                    )));
                }
            }
            _ => {
                // For now, just check it's not empty
                if value.trim().is_empty() {
                    return Err(AuthError::validation(format!(
                        "Parameter {} has invalid format",
                        param_name
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validate code challenge method
    pub fn validate_code_challenge_method(method: &str) -> Result<()> {
        match method {
            "plain" | "S256" => Ok(()),
            _ => Err(AuthError::validation("Invalid code challenge method")),
        }
    }

    /// Validate response type
    pub fn validate_response_type(response_type: &str, allowed_types: &[&str]) -> Result<()> {
        let types: Vec<&str> = response_type.split_whitespace().collect();

        for response_type in &types {
            if !allowed_types.contains(response_type) {
                return Err(AuthError::validation(format!(
                    "Unsupported response type: {}",
                    response_type
                )));
            }
        }

        Ok(())
    }
}

/// Common URL validation utilities
pub mod url {
    use super::*;

    /// Validate URL format and accessibility
    pub fn validate_url_format(url: &str) -> Result<()> {
        if url.is_empty() {
            return Err(AuthError::validation("URL is empty"));
        }

        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AuthError::validation("URL must use HTTP or HTTPS scheme"));
        }

        // Basic URL parsing validation - simplified without url crate for now
        if !url.contains("://") {
            return Err(AuthError::validation("Invalid URL format"));
        }

        Ok(())
    }

    /// Validate HTTPS requirement
    pub fn validate_https_required(url: &str) -> Result<()> {
        validate_url_format(url)?;

        if !url.starts_with("https://") {
            return Err(AuthError::validation("HTTPS is required"));
        }

        Ok(())
    }
}

/// Common validation result aggregation
pub fn collect_validation_errors(validations: Vec<Result<()>>) -> Result<()> {
    let errors: Vec<String> = validations
        .into_iter()
        .filter_map(|result| result.err())
        .map(|e| format!("{}", e))
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(AuthError::validation(errors.join("; ")))
    }
}
