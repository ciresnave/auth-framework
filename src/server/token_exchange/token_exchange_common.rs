//! # Common Token Exchange Components
//!
//! This module provides shared interfaces, utilities, and types used by both
//! the basic `TokenExchangeManager` and the advanced `AdvancedTokenExchangeManager`.
//!
//! ## Architecture
//!
//! - **TokenExchangeService**: Common trait implemented by both managers
//! - **ValidationUtils**: Shared validation logic to reduce code duplication
//! - **CommonTypes**: Shared data structures and enums
//! - **TokenExchangeFactory**: Factory for creating appropriate manager instances

use crate::errors::{AuthError, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Common token exchange service trait implemented by both managers
#[async_trait]
pub trait TokenExchangeService: Send + Sync {
    /// Exchange token request type
    type Request: Send + Sync;

    /// Exchange token response type
    type Response: Send + Sync;

    /// Configuration type
    type Config: Send + Sync;

    /// Exchange a token according to RFC 8693
    async fn exchange_token(&self, request: Self::Request) -> Result<Self::Response>;

    /// Validate a token of the specified type
    async fn validate_token(&self, token: &str, token_type: &str) -> Result<TokenValidationResult>;

    /// Get supported subject token types
    fn supported_subject_token_types(&self) -> Vec<String>;

    /// Get supported requested token types
    fn supported_requested_token_types(&self) -> Vec<String>;
    /// Get service capabilities
    fn capabilities(&self) -> TokenExchangeCapabilities;
}

/// Result of token validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResult {
    /// Whether the token is valid
    pub is_valid: bool,

    /// Token subject/principal
    pub subject: Option<String>,

    /// Token issuer
    pub issuer: Option<String>,

    /// Token audience
    pub audience: Vec<String>,

    /// Token scopes
    pub scopes: Vec<String>,

    /// Token expiration time
    pub expires_at: Option<DateTime<Utc>>,

    /// Additional token metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Validation errors/warnings
    pub validation_messages: Vec<String>,
}

/// Capabilities of a token exchange service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeCapabilities {
    /// Supports basic RFC 8693 token exchange
    pub basic_exchange: bool,

    /// Supports multi-party delegation chains
    pub multi_party_chains: bool,

    /// Supports context preservation
    pub context_preservation: bool,

    /// Supports audit trail generation
    pub audit_trail: bool,

    /// Supports session integration
    pub session_integration: bool,

    /// Supports JWT cryptographic operations
    pub jwt_operations: bool,

    /// Supports policy-driven exchange control
    pub policy_control: bool,

    /// Supports cross-domain exchanges
    pub cross_domain_exchange: bool,

    /// Maximum delegation depth supported (0 = no limit for advanced)
    pub max_delegation_depth: usize,

    /// Service complexity level
    pub complexity_level: ServiceComplexityLevel,
}

/// Service complexity level for choosing appropriate manager
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceComplexityLevel {
    /// Simple, lightweight operations
    Basic,
    /// Enterprise-grade with advanced features
    Advanced,
}

/// Common token exchange validation utilities
pub struct ValidationUtils;

impl ValidationUtils {
    /// Validate RFC 8693 grant type
    pub fn validate_grant_type(grant_type: &str) -> Result<()> {
        if grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
            return Err(AuthError::InvalidRequest(
                "Invalid grant type for token exchange".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate token type against supported types
    pub fn validate_token_type(token_type: &str, supported_types: &[String]) -> Result<()> {
        if !supported_types.contains(&token_type.to_string()) {
            return Err(AuthError::InvalidRequest(format!(
                "Unsupported token type: {}",
                token_type
            )));
        }
        Ok(())
    }

    /// Extract subject from token metadata
    pub fn extract_subject(metadata: &HashMap<String, serde_json::Value>) -> Option<String> {
        metadata
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Extract scopes from token metadata or scope string
    pub fn extract_scopes(
        metadata: &HashMap<String, serde_json::Value>,
        scope_string: Option<&str>,
    ) -> Vec<String> {
        // Try to get scopes from metadata first
        if let Some(scopes) = metadata.get("scope").or_else(|| metadata.get("scopes")) {
            if let Some(scope_str) = scopes.as_str() {
                return scope_str
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            } else if let Some(scope_array) = scopes.as_array() {
                return scope_array
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        // Fall back to scope string parameter
        scope_string
            .map(|s| {
                s.split_whitespace()
                    .map(|scope| scope.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validate delegation chain depth
    pub fn validate_delegation_depth(current_depth: usize, max_depth: usize) -> Result<()> {
        if current_depth > max_depth {
            return Err(AuthError::InvalidRequest(
                "Maximum delegation depth exceeded".to_string(),
            ));
        }
        Ok(())
    }

    /// Normalize token type URN
    pub fn normalize_token_type(token_type: &str) -> String {
        match token_type {
            "jwt" => "urn:ietf:params:oauth:token-type:jwt".to_string(),
            "access_token" => "urn:ietf:params:oauth:token-type:access_token".to_string(),
            "refresh_token" => "urn:ietf:params:oauth:token-type:refresh_token".to_string(),
            "id_token" => "urn:ietf:params:oauth:token-type:id_token".to_string(),
            "saml2" => "urn:ietf:params:oauth:token-type:saml2".to_string(),
            _ => token_type.to_string(),
        }
    }

    /// Check if token type is JWT-based
    pub fn is_jwt_token_type(token_type: &str) -> bool {
        matches!(
            token_type,
            "urn:ietf:params:oauth:token-type:jwt"
                | "urn:ietf:params:oauth:token-type:access_token"
                | "urn:ietf:params:oauth:token-type:id_token"
        )
    }

    /// Validate scope requirements
    pub fn validate_scope_requirements(
        requested_scopes: &[String],
        available_scopes: &[String],
        require_all: bool,
    ) -> Result<()> {
        if require_all {
            for scope in requested_scopes {
                if !available_scopes.contains(scope) {
                    return Err(AuthError::InvalidRequest(format!(
                        "Required scope not available: {}",
                        scope
                    )));
                }
            }
        } else {
            let has_any = requested_scopes
                .iter()
                .any(|scope| available_scopes.contains(scope));
            if !has_any && !requested_scopes.is_empty() {
                return Err(AuthError::InvalidRequest(
                    "None of the requested scopes are available".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Factory for creating appropriate token exchange managers
pub struct TokenExchangeFactory;

impl TokenExchangeFactory {
    /// Create the appropriate token exchange manager based on requirements
    pub async fn create_manager(
        requirements: &ExchangeRequirements,
    ) -> Result<Box<dyn TokenExchangeService<Request = (), Response = (), Config = ()>>> {
        // Determine complexity level based on requirements
        let complexity = Self::determine_manager_type(requirements);

        // Return error indicating users should use the specific factory methods
        // The generic create_manager cannot work due to different type parameters
        match complexity {
            ServiceComplexityLevel::Advanced => Err(AuthError::InvalidRequest(
                "Use TokenExchangeFactory::create_advanced_manager() for advanced requirements"
                    .to_string(),
            )),
            ServiceComplexityLevel::Basic => Err(AuthError::InvalidRequest(
                "Use TokenExchangeFactory::create_basic_manager() for basic requirements"
                    .to_string(),
            )),
        }
    }

    /// Determine which manager type to use based on requirements
    pub fn determine_manager_type(requirements: &ExchangeRequirements) -> ServiceComplexityLevel {
        // Use advanced manager if any advanced features are needed
        if requirements.needs_audit_trail
            || requirements.needs_session_integration
            || requirements.needs_context_preservation
            || requirements.needs_multi_party_chains
            || requirements.needs_jwt_operations
            || requirements.needs_policy_control
            || requirements.needs_cross_domain
            || requirements.max_delegation_depth > 3
        {
            ServiceComplexityLevel::Advanced
        } else {
            ServiceComplexityLevel::Basic
        }
    }

    /// Get recommended configuration based on use case
    pub fn get_recommended_config(use_case: &TokenExchangeUseCase) -> ExchangeRequirements {
        match use_case {
            TokenExchangeUseCase::SimpleServiceToService => ExchangeRequirements {
                needs_audit_trail: false,
                needs_session_integration: false,
                needs_context_preservation: false,
                needs_multi_party_chains: false,
                needs_jwt_operations: false,
                needs_policy_control: false,
                needs_cross_domain: false,
                max_delegation_depth: 1,
            },
            TokenExchangeUseCase::MicroserviceChain => ExchangeRequirements {
                needs_audit_trail: true,
                needs_session_integration: false,
                needs_context_preservation: true,
                needs_multi_party_chains: true,
                needs_jwt_operations: false,
                needs_policy_control: true,
                needs_cross_domain: false,
                max_delegation_depth: 5,
            },
            TokenExchangeUseCase::EnterpriseIntegration => ExchangeRequirements {
                needs_audit_trail: true,
                needs_session_integration: true,
                needs_context_preservation: true,
                needs_multi_party_chains: true,
                needs_jwt_operations: true,
                needs_policy_control: true,
                needs_cross_domain: true,
                max_delegation_depth: 10,
            },
            TokenExchangeUseCase::CrossDomainFederation => ExchangeRequirements {
                needs_audit_trail: true,
                needs_session_integration: false,
                needs_context_preservation: true,
                needs_multi_party_chains: false,
                needs_jwt_operations: true,
                needs_policy_control: true,
                needs_cross_domain: true,
                max_delegation_depth: 3,
            },
        }
    }
}

/// Requirements for token exchange functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRequirements {
    /// Requires complete audit trail
    pub needs_audit_trail: bool,

    /// Requires session integration
    pub needs_session_integration: bool,

    /// Requires context preservation
    pub needs_context_preservation: bool,

    /// Requires multi-party delegation chains
    pub needs_multi_party_chains: bool,

    /// Requires JWT cryptographic operations
    pub needs_jwt_operations: bool,

    /// Requires policy-driven control
    pub needs_policy_control: bool,

    /// Requires cross-domain exchanges
    pub needs_cross_domain: bool,

    /// Maximum delegation depth needed
    pub max_delegation_depth: usize,
}

/// Common use cases for token exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenExchangeUseCase {
    /// Simple service-to-service authentication
    SimpleServiceToService,

    /// Microservice chain with delegation
    MicroserviceChain,

    /// Full enterprise integration
    EnterpriseIntegration,

    /// Cross-domain identity federation
    CrossDomainFederation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_utils_grant_type() {
        // Valid grant type
        assert!(
            ValidationUtils::validate_grant_type("urn:ietf:params:oauth:grant-type:token-exchange")
                .is_ok()
        );

        // Invalid grant type
        assert!(ValidationUtils::validate_grant_type("authorization_code").is_err());
    }

    #[test]
    fn test_validation_utils_token_type() {
        let supported = vec!["urn:ietf:params:oauth:token-type:jwt".to_string()];

        assert!(
            ValidationUtils::validate_token_type(
                "urn:ietf:params:oauth:token-type:jwt",
                &supported
            )
            .is_ok()
        );

        assert!(ValidationUtils::validate_token_type("unsupported", &supported).is_err());
    }

    #[test]
    fn test_extract_scopes() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "scope".to_string(),
            serde_json::Value::String("read write".to_string()),
        );

        let scopes = ValidationUtils::extract_scopes(&metadata, None);
        assert_eq!(scopes, vec!["read", "write"]);

        // Test with scope parameter
        let scopes = ValidationUtils::extract_scopes(&HashMap::new(), Some("admin user"));
        assert_eq!(scopes, vec!["admin", "user"]);
    }

    #[test]
    fn test_normalize_token_type() {
        assert_eq!(
            ValidationUtils::normalize_token_type("jwt"),
            "urn:ietf:params:oauth:token-type:jwt"
        );

        assert_eq!(
            ValidationUtils::normalize_token_type("urn:ietf:params:oauth:token-type:jwt"),
            "urn:ietf:params:oauth:token-type:jwt"
        );
    }

    #[test]
    fn test_factory_manager_type_determination() {
        // Simple requirements should use basic
        let simple_req = ExchangeRequirements {
            needs_audit_trail: false,
            needs_session_integration: false,
            needs_context_preservation: false,
            needs_multi_party_chains: false,
            needs_jwt_operations: false,
            needs_policy_control: false,
            needs_cross_domain: false,
            max_delegation_depth: 1,
        };

        assert_eq!(
            TokenExchangeFactory::determine_manager_type(&simple_req),
            ServiceComplexityLevel::Basic
        );

        // Complex requirements should use advanced
        let complex_req = ExchangeRequirements {
            needs_audit_trail: true,
            needs_session_integration: true,
            needs_context_preservation: true,
            needs_multi_party_chains: true,
            needs_jwt_operations: true,
            needs_policy_control: true,
            needs_cross_domain: true,
            max_delegation_depth: 10,
        };

        assert_eq!(
            TokenExchangeFactory::determine_manager_type(&complex_req),
            ServiceComplexityLevel::Advanced
        );
    }

    #[test]
    fn test_use_case_recommendations() {
        let simple_config = TokenExchangeFactory::get_recommended_config(
            &TokenExchangeUseCase::SimpleServiceToService,
        );
        assert!(!simple_config.needs_audit_trail);
        assert_eq!(simple_config.max_delegation_depth, 1);

        let enterprise_config = TokenExchangeFactory::get_recommended_config(
            &TokenExchangeUseCase::EnterpriseIntegration,
        );
        assert!(enterprise_config.needs_audit_trail);
        assert!(enterprise_config.needs_session_integration);
        assert_eq!(enterprise_config.max_delegation_depth, 10);
    }
}


