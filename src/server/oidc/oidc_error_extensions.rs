//! OpenID Connect Core Error Code Extensions
//!
//! This module implements additional error codes for OpenID Connect,
//! including the `unmet_authentication_requirements` error code and other
//! enhanced error handling capabilities.
//!
//! # Implemented Error Extensions
//!
//! - `unmet_authentication_requirements` - Authentication requirements not met
//! - Enhanced error descriptions and URIs
//! - Structured error reporting
//! - Error code validation and mapping
//! - Custom error code mappings for extensible error handling
//!
//! # Custom Error Mappings
//!
//! The `OidcErrorManager` supports custom error code mappings that allow:
//! - Mapping custom string identifiers to standard or extended error codes
//! - Runtime extensibility for domain-specific error codes
//! - Override standard error code mappings for specialized behavior
//! - Error code resolution from string identifiers
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use auth_framework::server::oidc::oidc_error_extensions::{OidcErrorManager, OidcErrorCode, OidcErrorResponse};
//!
//! // Parse error codes from strings (e.g. from HTTP query params):
//! let code: OidcErrorCode = "invalid_request".parse().unwrap();
//! assert_eq!(code.to_string(), "invalid_request");
//!
//! // Build an error response fluently:
//! let response = OidcErrorResponse::new(OidcErrorCode::LoginRequired)
//!     .description("Session expired, please log in again")
//!     .state("state123")
//!     .detail("session_age", serde_json::json!(7200))
//!     .build();
//!
//! // OidcErrorManager with custom mappings:
//! let mut manager = OidcErrorManager::default();
//! manager.add_custom_error_mapping(
//!     "payment_required".to_string(),
//!     OidcErrorCode::InsufficientIdentityAssurance,
//! );
//! let error_code = manager.resolve_error_code("payment_required");
//! ```

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extended OpenID Connect error codes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OidcErrorCode {
    // Standard OAuth 2.0 errors
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,

    // Standard OpenID Connect errors
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,

    // Extended error codes
    /// Authentication requirements specified in the request were not met
    UnmetAuthenticationRequirements,
    /// The requested authentication context class reference values were not satisfied
    UnmetAuthenticationContextRequirements,
    /// Session selection required for multi-session scenarios
    SessionSelectionRequired,
    /// The authorization server requires user authentication via a different method
    AuthenticationMethodRequired,
    /// The requested identity verification level could not be satisfied
    InsufficientIdentityAssurance,
    /// The authorization server temporarily cannot service the request
    TemporarilyUnavailable,
    /// The request requires user registration/enrollment
    RegistrationRequired,
    /// The requested prompt value is not supported
    UnsupportedPromptValue,
    /// Multiple matching users found, selection required
    UserSelectionRequired,
}

impl std::fmt::Display for OidcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InteractionRequired => "interaction_required",
            Self::LoginRequired => "login_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::ConsentRequired => "consent_required",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::RegistrationNotSupported => "registration_not_supported",
            Self::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            Self::UnmetAuthenticationContextRequirements => {
                "unmet_authentication_context_requirements"
            }
            Self::SessionSelectionRequired => "session_selection_required",
            Self::AuthenticationMethodRequired => "authentication_method_required",
            Self::InsufficientIdentityAssurance => "insufficient_identity_assurance",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::RegistrationRequired => "registration_required",
            Self::UnsupportedPromptValue => "unsupported_prompt_value",
            Self::UserSelectionRequired => "user_selection_required",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for OidcErrorCode {
    type Err = AuthError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "invalid_request" => Ok(Self::InvalidRequest),
            "invalid_client" => Ok(Self::InvalidClient),
            "invalid_grant" => Ok(Self::InvalidGrant),
            "unauthorized_client" => Ok(Self::UnauthorizedClient),
            "unsupported_grant_type" => Ok(Self::UnsupportedGrantType),
            "invalid_scope" => Ok(Self::InvalidScope),
            "interaction_required" => Ok(Self::InteractionRequired),
            "login_required" => Ok(Self::LoginRequired),
            "account_selection_required" => Ok(Self::AccountSelectionRequired),
            "consent_required" => Ok(Self::ConsentRequired),
            "invalid_request_uri" => Ok(Self::InvalidRequestUri),
            "invalid_request_object" => Ok(Self::InvalidRequestObject),
            "request_not_supported" => Ok(Self::RequestNotSupported),
            "request_uri_not_supported" => Ok(Self::RequestUriNotSupported),
            "registration_not_supported" => Ok(Self::RegistrationNotSupported),
            "unmet_authentication_requirements" => Ok(Self::UnmetAuthenticationRequirements),
            "unmet_authentication_context_requirements" => {
                Ok(Self::UnmetAuthenticationContextRequirements)
            }
            "session_selection_required" => Ok(Self::SessionSelectionRequired),
            "authentication_method_required" => Ok(Self::AuthenticationMethodRequired),
            "insufficient_identity_assurance" => Ok(Self::InsufficientIdentityAssurance),
            "temporarily_unavailable" => Ok(Self::TemporarilyUnavailable),
            "registration_required" => Ok(Self::RegistrationRequired),
            "unsupported_prompt_value" => Ok(Self::UnsupportedPromptValue),
            "user_selection_required" => Ok(Self::UserSelectionRequired),
            other => Err(AuthError::validation(format!(
                "Unknown OIDC error code: {other}"
            ))),
        }
    }
}

/// OpenID Connect error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcErrorResponse {
    /// The error code
    pub error: OidcErrorCode,
    /// Human-readable error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// URI to error documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    /// State parameter from the request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Additional error details
    #[serde(flatten)]
    pub additional_details: HashMap<String, serde_json::Value>,
}

impl OidcErrorResponse {
    /// Start building an error response for the given error code.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use auth_framework::server::oidc::oidc_error_extensions::{OidcErrorCode, OidcErrorResponse};
    ///
    /// let resp = OidcErrorResponse::new(OidcErrorCode::LoginRequired)
    ///     .description("Session expired")
    ///     .state("abc123")
    ///     .build();
    /// ```
    pub fn new(error: OidcErrorCode) -> OidcErrorResponseBuilder {
        OidcErrorResponseBuilder {
            inner: OidcErrorResponse {
                error,
                error_description: None,
                error_uri: None,
                state: None,
                additional_details: HashMap::new(),
            },
        }
    }
}

/// Fluent builder for [`OidcErrorResponse`].
pub struct OidcErrorResponseBuilder {
    inner: OidcErrorResponse,
}

impl OidcErrorResponseBuilder {
    /// Set a human-readable error description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.inner.error_description = Some(desc.into());
        self
    }

    /// Set the error documentation URI.
    pub fn error_uri(mut self, uri: impl Into<String>) -> Self {
        self.inner.error_uri = Some(uri.into());
        self
    }

    /// Set the OAuth `state` parameter.
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.inner.state = Some(state.into());
        self
    }

    /// Add a single additional detail.
    pub fn detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.inner.additional_details.insert(key.into(), value);
        self
    }

    /// Set all additional details at once (replaces any previously added).
    pub fn details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.inner.additional_details = details;
        self
    }

    /// Consume the builder and return the [`OidcErrorResponse`].
    pub fn build(self) -> OidcErrorResponse {
        self.inner
    }
}

/// Authentication requirements details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequirements {
    /// Required authentication context class references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<Vec<String>>,
    /// Required authentication methods references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr_values: Option<Vec<String>>,
    /// Maximum authentication age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// Required identity assurance level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_assurance_level: Option<String>,
}

/// Error handling manager for OpenID Connect
#[derive(Debug, Clone)]
pub struct OidcErrorManager {
    /// Base error documentation URI
    error_base_uri: String,
    /// Custom error mappings
    custom_error_mappings: HashMap<String, OidcErrorCode>,
}

impl Default for OidcErrorManager {
    fn default() -> Self {
        Self {
            error_base_uri: "https://openid.net/specs/openid-connect-core-1_0.html#AuthError"
                .to_string(),
            custom_error_mappings: HashMap::new(),
        }
    }
}

impl OidcErrorCode {
    /// Get standard error description for error code
    pub fn get_description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => {
                "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
            }
            Self::InvalidClient => {
                "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)."
            }
            Self::InvalidGrant => {
                "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
            }
            Self::UnauthorizedClient => {
                "The authenticated client is not authorized to use this authorization grant type."
            }
            Self::UnsupportedGrantType => {
                "The authorization grant type is not supported by the authorization server."
            }
            Self::InvalidScope => "The requested scope is invalid, unknown, or malformed.",

            Self::InteractionRequired => {
                "The authorization server requires end-user interaction of some form to proceed."
            }
            Self::LoginRequired => "The authorization server requires end-user authentication.",
            Self::AccountSelectionRequired => {
                "The end-user is required to select a session at the authorization server."
            }
            Self::ConsentRequired => "The authorization server requires end-user consent.",
            Self::InvalidRequestUri => {
                "The request_uri in the authorization request returns an error or contains invalid data."
            }
            Self::InvalidRequestObject => {
                "The request parameter contains an invalid request object."
            }
            Self::RequestNotSupported => {
                "The authorization server does not support use of the request parameter."
            }
            Self::RequestUriNotSupported => {
                "The authorization server does not support use of the request_uri parameter."
            }
            Self::RegistrationNotSupported => {
                "The authorization server does not support use of the registration parameter."
            }

            // Extended error codes
            Self::UnmetAuthenticationRequirements => {
                "The authentication performed does not meet the authentication requirements specified in the request."
            }
            Self::UnmetAuthenticationContextRequirements => {
                "The requested authentication context class reference values were not satisfied by the performed authentication."
            }
            Self::SessionSelectionRequired => {
                "Multiple active sessions exist, and the end-user must select which session to use."
            }
            Self::AuthenticationMethodRequired => {
                "The authorization server requires the end-user to authenticate using a specific authentication method."
            }
            Self::InsufficientIdentityAssurance => {
                "The level of identity assurance achieved does not meet the requirements for this request."
            }
            Self::TemporarilyUnavailable => {
                "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
            }
            Self::RegistrationRequired => {
                "The end-user must complete a registration process before authentication can proceed."
            }
            Self::UnsupportedPromptValue => {
                "The authorization server does not support the requested prompt value."
            }
            Self::UserSelectionRequired => {
                "Multiple users match the provided identification, and selection is required."
            }
        }
    }

    /// Check if this error code requires user interaction
    pub fn requires_interaction(&self) -> bool {
        matches!(
            self,
            Self::InteractionRequired
                | Self::LoginRequired
                | Self::AccountSelectionRequired
                | Self::ConsentRequired
                | Self::SessionSelectionRequired
                | Self::AuthenticationMethodRequired
                | Self::RegistrationRequired
                | Self::UserSelectionRequired
        )
    }

    /// Check if this error code indicates an authentication issue
    pub fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Self::LoginRequired
                | Self::UnmetAuthenticationRequirements
                | Self::UnmetAuthenticationContextRequirements
                | Self::AuthenticationMethodRequired
                | Self::InsufficientIdentityAssurance
        )
    }
}

impl OidcErrorManager {
    /// Create new error manager
    pub fn new(error_base_uri: String) -> Self {
        Self {
            error_base_uri,
            custom_error_mappings: HashMap::new(),
        }
    }

    /// Create error response for unmet authentication requirements
    pub fn create_unmet_auth_requirements_error(
        &self,
        requirements: AuthenticationRequirements,
        state: Option<String>,
    ) -> OidcErrorResponse {
        let mut builder = OidcErrorResponse::new(OidcErrorCode::UnmetAuthenticationRequirements)
            .description(
                OidcErrorCode::UnmetAuthenticationRequirements
                    .get_description()
                    .to_string(),
            )
            .error_uri(format!(
                "{}#UnmetAuthenticationRequirements",
                self.error_base_uri
            ));

        if let Some(s) = state {
            builder = builder.state(s);
        }

        if let Some(acr_values) = &requirements.acr_values {
            builder = builder.detail(
                "required_acr_values",
                serde_json::to_value(acr_values).unwrap_or_default(),
            );
        }

        if let Some(amr_values) = &requirements.amr_values {
            builder = builder.detail(
                "required_amr_values",
                serde_json::to_value(amr_values).unwrap_or_default(),
            );
        }

        if let Some(max_age) = requirements.max_age {
            builder = builder.detail(
                "max_age",
                serde_json::Value::Number(serde_json::Number::from(max_age)),
            );
        }

        builder.build()
    }

    /// Create error response for insufficient ACR
    pub fn create_insufficient_acr_error(
        &self,
        required_acr: Vec<String>,
        achieved_acr: Option<String>,
        state: Option<String>,
    ) -> OidcErrorResponse {
        let mut builder =
            OidcErrorResponse::new(OidcErrorCode::UnmetAuthenticationContextRequirements)
                .description(
                    OidcErrorCode::UnmetAuthenticationContextRequirements
                        .get_description()
                        .to_string(),
                )
                .error_uri(format!("{}#ACRRequirements", self.error_base_uri))
                .detail(
                    "required_acr_values",
                    serde_json::to_value(required_acr).unwrap_or_default(),
                );

        if let Some(acr) = achieved_acr {
            builder = builder.detail("achieved_acr", serde_json::Value::String(acr));
        }

        if let Some(s) = state {
            builder = builder.state(s);
        }

        builder.build()
    }

    /// Create generic error response
    pub fn create_error_response(
        &self,
        error_code: OidcErrorCode,
        custom_description: Option<String>,
        state: Option<String>,
        additional_details: HashMap<String, serde_json::Value>,
    ) -> OidcErrorResponse {
        let mut builder = OidcErrorResponse::new(error_code.clone())
            .description(
                custom_description.unwrap_or_else(|| error_code.get_description().to_string()),
            )
            .error_uri(format!("{}#{:?}", self.error_base_uri, error_code))
            .details(additional_details);

        if let Some(s) = state {
            builder = builder.state(s);
        }

        builder.build()
    }

    /// Add custom error mapping
    pub fn add_custom_error_mapping(&mut self, identifier: String, error_code: OidcErrorCode) {
        self.custom_error_mappings.insert(identifier, error_code);
    }

    /// Remove custom error mapping
    pub fn remove_custom_error_mapping(&mut self, identifier: &str) -> Option<OidcErrorCode> {
        self.custom_error_mappings.remove(identifier)
    }

    /// Get error code from string identifier (checks custom mappings first, then standard codes)
    pub fn resolve_error_code(&self, identifier: &str) -> Option<OidcErrorCode> {
        // Check custom mappings first
        if let Some(error_code) = self.custom_error_mappings.get(identifier) {
            return Some(error_code.clone());
        }

        // Delegate to FromStr for standard error codes
        identifier.parse::<OidcErrorCode>().ok()
    }

    /// Create error response from string identifier
    pub fn create_error_response_from_identifier(
        &self,
        error_identifier: &str,
        custom_description: Option<String>,
        state: Option<String>,
        additional_details: HashMap<String, serde_json::Value>,
    ) -> Result<OidcErrorResponse> {
        match self.resolve_error_code(error_identifier) {
            Some(error_code) => Ok(self.create_error_response(
                error_code,
                custom_description,
                state,
                additional_details,
            )),
            None => Err(AuthError::validation(format!(
                "Unknown error code identifier: {}",
                error_identifier
            ))),
        }
    }

    /// Get all custom error mappings
    pub fn get_custom_mappings(&self) -> &HashMap<String, OidcErrorCode> {
        &self.custom_error_mappings
    }

    /// Clear all custom error mappings
    pub fn clear_custom_mappings(&mut self) {
        self.custom_error_mappings.clear();
    }

    /// Check if custom mapping exists
    pub fn has_custom_mapping(&self, identifier: &str) -> bool {
        self.custom_error_mappings.contains_key(identifier)
    }

    /// Validate authentication requirements against performed authentication
    pub fn validate_authentication_requirements(
        &self,
        requirements: &AuthenticationRequirements,
        performed_acr: Option<&str>,
        performed_amr: Option<&[String]>,
        auth_time: Option<u64>,
        current_time: u64,
    ) -> Result<()> {
        // Check ACR requirements
        if let Some(required_acr) = &requirements.acr_values {
            match performed_acr {
                Some(acr) => {
                    if !required_acr.contains(&acr.to_string()) {
                        return Err(AuthError::validation(
                            "Authentication context class requirements not met",
                        ));
                    }
                }
                None => {
                    return Err(AuthError::validation(
                        "No authentication context class provided",
                    ));
                }
            }
        }

        // Check AMR requirements
        if let Some(required_amr) = &requirements.amr_values {
            match performed_amr {
                Some(amr) => {
                    for required in required_amr {
                        if !amr.contains(required) {
                            return Err(AuthError::validation(
                                "Authentication method requirements not met",
                            ));
                        }
                    }
                }
                None => {
                    return Err(AuthError::validation("No authentication methods provided"));
                }
            }
        }

        // Check max_age requirement
        if let Some(max_age) = requirements.max_age {
            if let Some(auth_time) = auth_time {
                if current_time - auth_time > max_age {
                    return Err(AuthError::validation(
                        "Authentication is too old (exceeds max_age)",
                    ));
                }
            } else {
                return Err(AuthError::validation(
                    "Authentication time not available for max_age validation",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_descriptions() {
        assert!(
            !OidcErrorCode::UnmetAuthenticationRequirements
                .get_description()
                .is_empty()
        );
        assert!(OidcErrorCode::LoginRequired.requires_interaction());
        assert!(OidcErrorCode::UnmetAuthenticationRequirements.is_authentication_error());
    }

    #[test]
    fn test_oidc_error_code_display_roundtrip() {
        // Every variant should round-trip through Display → FromStr
        let codes = vec![
            OidcErrorCode::InvalidRequest,
            OidcErrorCode::InvalidClient,
            OidcErrorCode::InvalidGrant,
            OidcErrorCode::UnauthorizedClient,
            OidcErrorCode::UnsupportedGrantType,
            OidcErrorCode::InvalidScope,
            OidcErrorCode::InteractionRequired,
            OidcErrorCode::LoginRequired,
            OidcErrorCode::AccountSelectionRequired,
            OidcErrorCode::ConsentRequired,
            OidcErrorCode::InvalidRequestUri,
            OidcErrorCode::InvalidRequestObject,
            OidcErrorCode::RequestNotSupported,
            OidcErrorCode::RequestUriNotSupported,
            OidcErrorCode::RegistrationNotSupported,
            OidcErrorCode::UnmetAuthenticationRequirements,
            OidcErrorCode::UnmetAuthenticationContextRequirements,
            OidcErrorCode::SessionSelectionRequired,
            OidcErrorCode::AuthenticationMethodRequired,
            OidcErrorCode::InsufficientIdentityAssurance,
            OidcErrorCode::TemporarilyUnavailable,
            OidcErrorCode::RegistrationRequired,
            OidcErrorCode::UnsupportedPromptValue,
            OidcErrorCode::UserSelectionRequired,
        ];

        for code in codes {
            let s = code.to_string();
            let parsed: OidcErrorCode = s.parse().unwrap();
            assert_eq!(parsed, code);
        }
    }

    #[test]
    fn test_oidc_error_code_from_str_invalid() {
        let result = "not_a_real_error".parse::<OidcErrorCode>();
        assert!(result.is_err());
    }

    #[test]
    fn test_oidc_error_response_builder() {
        let resp = OidcErrorResponse::new(OidcErrorCode::LoginRequired)
            .description("Session expired")
            .error_uri("https://example.com/errors#login")
            .state("abc123")
            .detail("session_id", serde_json::json!("sess-42"))
            .build();

        assert_eq!(resp.error, OidcErrorCode::LoginRequired);
        assert_eq!(resp.error_description.as_deref(), Some("Session expired"));
        assert_eq!(
            resp.error_uri.as_deref(),
            Some("https://example.com/errors#login")
        );
        assert_eq!(resp.state.as_deref(), Some("abc123"));
        assert_eq!(
            resp.additional_details.get("session_id"),
            Some(&serde_json::json!("sess-42"))
        );
    }

    #[test]
    fn test_unmet_auth_requirements_error() {
        let manager = OidcErrorManager::default();
        let requirements = AuthenticationRequirements {
            acr_values: Some(vec!["urn:mace:incommon:iap:silver".to_string()]),
            amr_values: Some(vec!["pwd".to_string(), "mfa".to_string()]),
            max_age: Some(3600),
            identity_assurance_level: None,
        };

        let error = manager
            .create_unmet_auth_requirements_error(requirements, Some("state123".to_string()));

        assert_eq!(error.error, OidcErrorCode::UnmetAuthenticationRequirements);
        assert!(error.error_description.is_some());
        assert_eq!(error.state.as_ref().unwrap(), "state123");
        assert!(error.additional_details.contains_key("required_acr_values"));
        assert!(error.additional_details.contains_key("required_amr_values"));
    }

    #[test]
    fn test_custom_error_mappings() {
        let mut manager = OidcErrorManager::default();

        // Test adding custom error mapping
        manager.add_custom_error_mapping(
            "custom_validation_failed".to_string(),
            OidcErrorCode::InvalidRequest,
        );

        // Test resolving custom error code
        let resolved = manager.resolve_error_code("custom_validation_failed");
        assert_eq!(resolved, Some(OidcErrorCode::InvalidRequest));

        // Test resolving standard error code
        let standard = manager.resolve_error_code("login_required");
        assert_eq!(standard, Some(OidcErrorCode::LoginRequired));

        // Test resolving unknown error code
        let unknown = manager.resolve_error_code("nonexistent_error");
        assert_eq!(unknown, None);

        // Test has_custom_mapping
        assert!(manager.has_custom_mapping("custom_validation_failed"));
        assert!(!manager.has_custom_mapping("login_required"));

        // Test creating error response from identifier
        let error_response = manager
            .create_error_response_from_identifier(
                "custom_validation_failed",
                Some("Custom validation error".to_string()),
                Some("state123".to_string()),
                HashMap::new(),
            )
            .unwrap();

        assert_eq!(error_response.error, OidcErrorCode::InvalidRequest);
        assert_eq!(error_response.state.as_ref().unwrap(), "state123");

        // Test remove custom mapping
        let removed = manager.remove_custom_error_mapping("custom_validation_failed");
        assert_eq!(removed, Some(OidcErrorCode::InvalidRequest));
        assert!(!manager.has_custom_mapping("custom_validation_failed"));

        // Test clear all mappings
        manager.add_custom_error_mapping("test1".to_string(), OidcErrorCode::InvalidScope);
        manager.add_custom_error_mapping("test2".to_string(), OidcErrorCode::ConsentRequired);
        assert_eq!(manager.get_custom_mappings().len(), 2);

        manager.clear_custom_mappings();
        assert_eq!(manager.get_custom_mappings().len(), 0);
    }

    #[test]
    fn test_error_response_from_unknown_identifier() {
        let manager = OidcErrorManager::default();

        let result = manager.create_error_response_from_identifier(
            "unknown_error_code",
            None,
            None,
            HashMap::new(),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown error code identifier")
        );
    }

    #[test]
    fn test_custom_error_mappings_real_world_scenario() {
        let mut manager = OidcErrorManager::default();

        // Add domain-specific error mappings for a banking application
        manager.add_custom_error_mapping(
            "account_frozen".to_string(),
            OidcErrorCode::AuthenticationMethodRequired,
        );
        manager.add_custom_error_mapping(
            "kyc_verification_required".to_string(),
            OidcErrorCode::InsufficientIdentityAssurance,
        );
        manager.add_custom_error_mapping(
            "payment_limit_exceeded".to_string(),
            OidcErrorCode::ConsentRequired,
        );

        // Demonstrate custom error response creation
        let mut additional_details = HashMap::new();
        additional_details.insert(
            "account_id".to_string(),
            serde_json::Value::String("acc-12345".to_string()),
        );
        additional_details.insert(
            "freeze_reason".to_string(),
            serde_json::Value::String("Suspicious activity detected".to_string()),
        );

        let error_response = manager
            .create_error_response_from_identifier(
                "account_frozen",
                Some("Account authentication required due to security freeze".to_string()),
                Some("banking-session-456".to_string()),
                additional_details,
            )
            .unwrap();

        assert_eq!(
            error_response.error,
            OidcErrorCode::AuthenticationMethodRequired
        );
        assert_eq!(
            error_response.error_description.as_ref().unwrap(),
            "Account authentication required due to security freeze"
        );
        assert_eq!(
            error_response.state.as_ref().unwrap(),
            "banking-session-456"
        );
        assert!(error_response.additional_details.contains_key("account_id"));
        assert!(
            error_response
                .additional_details
                .contains_key("freeze_reason")
        );

        // Verify custom mappings take precedence over standard ones
        manager.add_custom_error_mapping(
            "login_required".to_string(),
            OidcErrorCode::RegistrationRequired, // Override standard behavior
        );

        let overridden_response = manager
            .create_error_response_from_identifier(
                "login_required",
                Some("User registration required before login".to_string()),
                None,
                HashMap::new(),
            )
            .unwrap();

        assert_eq!(
            overridden_response.error,
            OidcErrorCode::RegistrationRequired
        );

        // Verify management functions
        assert_eq!(manager.get_custom_mappings().len(), 4);
        assert!(manager.has_custom_mapping("account_frozen"));
        assert!(!manager.has_custom_mapping("nonexistent_mapping"));

        // Clean up specific mapping
        let removed = manager.remove_custom_error_mapping("account_frozen");
        assert_eq!(removed, Some(OidcErrorCode::AuthenticationMethodRequired));
        assert!(!manager.has_custom_mapping("account_frozen"));

        // Test clear all
        manager.clear_custom_mappings();
        assert_eq!(manager.get_custom_mappings().len(), 0);
    }

    #[test]
    fn test_standard_error_code_resolution() {
        let manager = OidcErrorManager::default();

        // Test all standard error codes
        assert_eq!(
            manager.resolve_error_code("invalid_request"),
            Some(OidcErrorCode::InvalidRequest)
        );
        assert_eq!(
            manager.resolve_error_code("unmet_authentication_requirements"),
            Some(OidcErrorCode::UnmetAuthenticationRequirements)
        );
        assert_eq!(
            manager.resolve_error_code("session_selection_required"),
            Some(OidcErrorCode::SessionSelectionRequired)
        );

        // Custom mappings take precedence over standard codes
        let mut manager = OidcErrorManager::default();
        manager.add_custom_error_mapping(
            "login_required".to_string(),
            OidcErrorCode::ConsentRequired, // Override standard mapping
        );

        assert_eq!(
            manager.resolve_error_code("login_required"),
            Some(OidcErrorCode::ConsentRequired) // Should return custom mapping
        );
    }
}
