//! OpenID Connect Response Modes Extension
//!
//! This module implements additional OAuth 2.0 and OpenID Connect response modes
//! beyond the standard 'query' and 'fragment' modes defined in the core specifications.
//!
//! # Implemented Response Modes
//!
//! - **Form Post Response Mode** (OAuth 2.0 Form Post Response Mode)
//! - **JWT Response Mode** (JARM - JWT Secured Authorization Response Mode)
//! - **Multiple Response Types** (OAuth 2.0 Multiple Response Types)
//!
//! These form the foundation for many other OpenID specifications.

use crate::errors::{AuthError, Result};
use html_escape;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Response Mode types supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseMode {
    /// Standard query parameter response
    Query,
    /// Fragment-based response
    Fragment,
    /// Form POST response
    FormPost,
    /// JWT-secured response (JARM)
    JwtQuery,
    /// JWT-secured fragment response
    JwtFragment,
    /// JWT-secured form POST response
    JwtFormPost,
}

/// Multiple Response Types handler
#[derive(Debug, Clone)]
pub struct MultipleResponseTypesManager {
    /// Configuration for response types
    config: MultipleResponseTypesConfig,
}

#[derive(Debug, Clone)]
pub struct MultipleResponseTypesConfig {
    /// Supported response types
    pub supported_response_types: Vec<String>,
    /// Enable multiple response types in single request
    pub enable_multiple_types: bool,
}

impl Default for MultipleResponseTypesConfig {
    fn default() -> Self {
        Self {
            supported_response_types: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "code id_token".to_string(),
                "token id_token".to_string(),
                "code token id_token".to_string(),
            ],
            enable_multiple_types: true,
        }
    }
}

/// Form Post Response Mode implementation
#[derive(Debug, Clone)]
pub struct FormPostResponseMode {
    /// Target redirect URI
    pub redirect_uri: String,
    /// Form parameters to post
    pub parameters: HashMap<String, String>,
}

/// JARM (JWT Response Mode) implementation
#[derive(Debug, Clone)]
pub struct JarmResponseMode {
    /// JWT response token
    pub response_token: String,
    /// Response mode for JWT delivery
    pub delivery_mode: ResponseMode,
}

impl MultipleResponseTypesManager {
    /// Create new manager
    pub fn new(config: MultipleResponseTypesConfig) -> Self {
        Self { config }
    }

    /// Parse and validate response type parameter
    pub fn parse_response_type(&self, response_type: &str) -> Result<Vec<String>> {
        let types: Vec<String> = response_type
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Validate each type
        for response_type in &types {
            if !self.is_supported_response_type(response_type) {
                return Err(AuthError::validation(format!(
                    "Unsupported response_type: {}",
                    response_type
                )));
            }
        }

        // Validate combinations
        self.validate_response_type_combination(&types)?;

        Ok(types)
    }

    /// Check if response type is supported
    pub fn is_supported_response_type(&self, response_type: &str) -> bool {
        let full_type = match response_type {
            "code" | "token" | "id_token" => response_type.to_string(),
            _ => return false,
        };

        self.config.supported_response_types.contains(&full_type)
            || self
                .config
                .supported_response_types
                .iter()
                .any(|t| t.contains(response_type))
    }

    /// Validate response type combinations
    fn validate_response_type_combination(&self, types: &[String]) -> Result<()> {
        if types.is_empty() {
            return Err(AuthError::validation("Empty response_type"));
        }

        // Specific validation rules for combinations
        if types.contains(&"token".to_string()) || types.contains(&"id_token".to_string()) {
            // Implicit flow requirements - should have nonce for id_token
            // This will be validated at the authorization level
        }

        if types.len() > 3 {
            return Err(AuthError::validation("Too many response types"));
        }

        Ok(())
    }

    /// Generate response based on types
    pub async fn generate_response(
        &self,
        response_types: &[String],
        authorization_code: Option<String>,
        access_token: Option<String>,
        id_token: Option<String>,
    ) -> Result<HashMap<String, String>> {
        let mut response = HashMap::new();

        for response_type in response_types {
            match response_type.as_str() {
                "code" => {
                    if let Some(code) = &authorization_code {
                        response.insert("code".to_string(), code.clone());
                    }
                }
                "token" => {
                    if let Some(token) = &access_token {
                        response.insert("access_token".to_string(), token.clone());
                        response.insert("token_type".to_string(), "Bearer".to_string());
                        // Add expires_in, scope, etc.
                        response.insert("expires_in".to_string(), "3600".to_string());
                    }
                }
                "id_token" => {
                    if let Some(token) = &id_token {
                        response.insert("id_token".to_string(), token.clone());
                    }
                }
                _ => {
                    return Err(AuthError::validation(format!(
                        "Unsupported response type: {}",
                        response_type
                    )));
                }
            }
        }

        Ok(response)
    }
}

impl FormPostResponseMode {
    /// Create new form post response
    pub fn new(redirect_uri: String, parameters: HashMap<String, String>) -> Self {
        Self {
            redirect_uri,
            parameters,
        }
    }

    /// Generate HTML form for auto-submission
    pub fn generate_html_form(&self) -> String {
        let mut form = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Response</title>
</head>
<body>
    <form method="post" action="{}" id="response_form">
"#,
            self.redirect_uri
        );

        for (name, value) in &self.parameters {
            form.push_str(&format!(
                r#"        <input type="hidden" name="{}" value="{}" />
"#,
                html_escape::encode_text(name),
                html_escape::encode_text(value)
            ));
        }

        form.push_str(
            r#"    </form>
    <script>
        window.onload = function() {
            document.getElementById('response_form').submit();
        };
    </script>
</body>
</html>"#,
        );

        form
    }
}

impl JarmResponseMode {
    /// Create new JARM response
    pub fn new(response_token: String, delivery_mode: ResponseMode) -> Self {
        Self {
            response_token,
            delivery_mode,
        }
    }

    /// Generate JARM response parameters
    pub fn generate_response_parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("response".to_string(), self.response_token.clone());
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiple_response_types_parsing() {
        let manager = MultipleResponseTypesManager::new(MultipleResponseTypesConfig::default());

        // Test single response type
        let result = manager.parse_response_type("code").unwrap();
        assert_eq!(result, vec!["code"]);

        // Test multiple response types
        let result = manager.parse_response_type("code token").unwrap();
        assert_eq!(result, vec!["code", "token"]);

        // Test invalid response type
        assert!(manager.parse_response_type("invalid").is_err());
    }

    #[test]
    fn test_form_post_html_generation() {
        let mut params = HashMap::new();
        params.insert("code".to_string(), "auth_code_123".to_string());
        params.insert("state".to_string(), "client_state".to_string());

        let form_post =
            FormPostResponseMode::new("https://client.example.com/callback".to_string(), params);

        let html = form_post.generate_html_form();
        assert!(html.contains("auth_code_123"));
        assert!(html.contains("client_state"));
        assert!(html.contains("https://client.example.com/callback"));
    }

    #[test]
    fn test_jarm_response_generation() {
        let jarm = JarmResponseMode::new(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...".to_string(),
            ResponseMode::JwtQuery,
        );

        let params = jarm.generate_response_parameters();
        assert!(params.contains_key("response"));
        assert!(params["response"].starts_with("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"));
    }
}


