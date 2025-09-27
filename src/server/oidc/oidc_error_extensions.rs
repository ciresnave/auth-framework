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
//! ```rust,ignore
//! use auth_framework::server::oidc_error_extensions::{OidcErrorManager, OidcErrorCode};
//!
//! let mut manager = OidcErrorManager::default();
//!
//! // Add custom error mapping
//! manager.add_custom_error_mapping(
//!     "payment_required".to_string(),
//!     OidcErrorCode::InsufficientIdentityAssurance,
//! );
//!
//! // Resolve error from identifier
//! let error_code = manager.resolve_error_code("payment_required");
//!
//! // Create error response from identifier
//! let response = manager.create_error_response_from_identifier(
//!     "payment_required",
//!     Some("Payment verification required".to_string()),
//!     Some("state123".to_string()),
//!     std::collections::HashMap::new(),
//! ).unwrap();
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
        let mut additional_details = HashMap::new();

        if let Some(acr_values) = &requirements.acr_values {
            additional_details.insert(
                "required_acr_values".to_string(),
                serde_json::to_value(acr_values).unwrap(),
            );
        }

        if let Some(amr_values) = &requirements.amr_values {
            additional_details.insert(
                "required_amr_values".to_string(),
                serde_json::to_value(amr_values).unwrap(),
            );
        }

        if let Some(max_age) = requirements.max_age {
            additional_details.insert(
                "max_age".to_string(),
                serde_json::Value::Number(serde_json::Number::from(max_age)),
            );
        }

        OidcErrorResponse {
            error: OidcErrorCode::UnmetAuthenticationRequirements,
            error_description: Some(
                OidcErrorCode::UnmetAuthenticationRequirements
                    .get_description()
                    .to_string(),
            ),
            error_uri: Some(format!(
                "{}#UnmetAuthenticationRequirements",
                self.error_base_uri
            )),
            state,
            additional_details,
        }
    }

    /// Create error response for insufficient ACR
    pub fn create_insufficient_acr_error(
        &self,
        required_acr: Vec<String>,
        achieved_acr: Option<String>,
        state: Option<String>,
    ) -> OidcErrorResponse {
        let mut additional_details = HashMap::new();
        additional_details.insert(
            "required_acr_values".to_string(),
            serde_json::to_value(required_acr).unwrap(),
        );

        if let Some(acr) = achieved_acr {
            additional_details.insert("achieved_acr".to_string(), serde_json::Value::String(acr));
        }

        OidcErrorResponse {
            error: OidcErrorCode::UnmetAuthenticationContextRequirements,
            error_description: Some(
                OidcErrorCode::UnmetAuthenticationContextRequirements
                    .get_description()
                    .to_string(),
            ),
            error_uri: Some(format!("{}#ACRRequirements", self.error_base_uri)),
            state,
            additional_details,
        }
    }

    /// Create generic error response
    pub fn create_error_response(
        &self,
        error_code: OidcErrorCode,
        custom_description: Option<String>,
        state: Option<String>,
        additional_details: HashMap<String, serde_json::Value>,
    ) -> OidcErrorResponse {
        OidcErrorResponse {
            error: error_code.clone(),
            error_description: custom_description
                .or_else(|| Some(error_code.get_description().to_string())),
            error_uri: Some(format!("{}#{:?}", self.error_base_uri, error_code)),
            state,
            additional_details,
        }
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

        // Check standard error codes
        match identifier {
            "invalid_request" => Some(OidcErrorCode::InvalidRequest),
            "invalid_client" => Some(OidcErrorCode::InvalidClient),
            "invalid_grant" => Some(OidcErrorCode::InvalidGrant),
            "unauthorized_client" => Some(OidcErrorCode::UnauthorizedClient),
            "unsupported_grant_type" => Some(OidcErrorCode::UnsupportedGrantType),
            "invalid_scope" => Some(OidcErrorCode::InvalidScope),
            "interaction_required" => Some(OidcErrorCode::InteractionRequired),
            "login_required" => Some(OidcErrorCode::LoginRequired),
            "account_selection_required" => Some(OidcErrorCode::AccountSelectionRequired),
            "consent_required" => Some(OidcErrorCode::ConsentRequired),
            "invalid_request_uri" => Some(OidcErrorCode::InvalidRequestUri),
            "invalid_request_object" => Some(OidcErrorCode::InvalidRequestObject),
            "request_not_supported" => Some(OidcErrorCode::RequestNotSupported),
            "request_uri_not_supported" => Some(OidcErrorCode::RequestUriNotSupported),
            "registration_not_supported" => Some(OidcErrorCode::RegistrationNotSupported),
            "unmet_authentication_requirements" => {
                Some(OidcErrorCode::UnmetAuthenticationRequirements)
            }
            "unmet_authentication_context_requirements" => {
                Some(OidcErrorCode::UnmetAuthenticationContextRequirements)
            }
            "session_selection_required" => Some(OidcErrorCode::SessionSelectionRequired),
            "authentication_method_required" => Some(OidcErrorCode::AuthenticationMethodRequired),
            "insufficient_identity_assurance" => Some(OidcErrorCode::InsufficientIdentityAssurance),
            "temporarily_unavailable" => Some(OidcErrorCode::TemporarilyUnavailable),
            "registration_required" => Some(OidcErrorCode::RegistrationRequired),
            "unsupported_prompt_value" => Some(OidcErrorCode::UnsupportedPromptValue),
            "user_selection_required" => Some(OidcErrorCode::UserSelectionRequired),
            _ => None,
        }
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
