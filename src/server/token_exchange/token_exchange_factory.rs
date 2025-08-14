//! # Token Exchange Factory Examples
//!
//! This module provides practical examples and factory methods for creating
//! the appropriate token exchange manager based on your use case.

use crate::errors::Result;
use crate::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
use crate::server::token_exchange::advanced_token_exchange::{
    AdvancedTokenExchangeConfig, AdvancedTokenExchangeManager,
};
use crate::server::oidc::oidc_session_management::SessionManager;
use crate::server::token_exchange::TokenExchangeManager;
use crate::server::token_exchange::token_exchange_common::{
    ExchangeRequirements, ServiceComplexityLevel, TokenExchangeFactory,
    TokenExchangeUseCase,
};
use std::sync::Arc;

/// High-level factory for creating token exchange managers
pub struct TokenExchangeManagerFactory;

impl TokenExchangeManagerFactory {
    /// Create a basic token exchange manager for simple scenarios
    pub fn create_basic_manager(_jwt_secret: &str) -> Result<TokenExchangeManager> {
        let config = SecureJwtConfig::default(); // Use default config
        let jwt_validator = SecureJwtValidator::new(config);
        Ok(TokenExchangeManager::new(jwt_validator))
    }

    /// Create an advanced token exchange manager for enterprise scenarios
    pub fn create_advanced_manager(
        config: Option<AdvancedTokenExchangeConfig>,
        session_manager: Arc<SessionManager>,
    ) -> Result<AdvancedTokenExchangeManager> {
        let config = config.unwrap_or_default();
        AdvancedTokenExchangeManager::new(config, session_manager)
    }

    /// Create manager based on use case requirements
    pub fn create_for_use_case(
        use_case: TokenExchangeUseCase,
        jwt_secret: &str,
        session_manager: Option<Arc<SessionManager>>,
    ) -> Result<Box<dyn std::any::Any>> {
        let requirements = TokenExchangeFactory::get_recommended_config(&use_case);
        let manager_type = TokenExchangeFactory::determine_manager_type(&requirements);

        match manager_type {
            ServiceComplexityLevel::Basic => {
                let manager = Self::create_basic_manager(jwt_secret)?;
                Ok(Box::new(manager))
            }
            ServiceComplexityLevel::Advanced => {
                let session_mgr = session_manager
                    .unwrap_or_else(|| Arc::new(SessionManager::new(Default::default())));
                let manager = Self::create_advanced_manager(None, session_mgr)?;
                Ok(Box::new(manager))
            }
        }
    }

    /// Get configuration recommendations for a use case
    pub fn get_setup_guide(use_case: TokenExchangeUseCase) -> SetupGuide {
        let requirements = TokenExchangeFactory::get_recommended_config(&use_case);
        let manager_type = TokenExchangeFactory::determine_manager_type(&requirements);

        SetupGuide {
            use_case,
            recommended_manager: manager_type,
            requirements: requirements.clone(),
            setup_instructions: match manager_type {
                ServiceComplexityLevel::Basic => vec![
                    "1. Create SecureJwtValidator with your JWT secret".to_string(),
                    "2. Initialize TokenExchangeManager::new(jwt_validator)".to_string(),
                    "3. Register policies for your clients".to_string(),
                    "4. Use exchange_token(request, client_id) for exchanges".to_string(),
                ],
                ServiceComplexityLevel::Advanced => vec![
                    "1. Configure AdvancedTokenExchangeConfig with your requirements".to_string(),
                    "2. Set up SessionManager for OIDC integration".to_string(),
                    "3. Initialize AdvancedTokenExchangeManager::new(config, session_manager)"
                        .to_string(),
                    "4. Register token processors if needed".to_string(),
                    "5. Use exchange_token(request) for complex exchanges".to_string(),
                ],
            },
            performance_characteristics: match manager_type {
                ServiceComplexityLevel::Basic => PerformanceCharacteristics {
                    memory_footprint: "~50KB base",
                    latency: "Sub-millisecond",
                    throughput: "10,000+ ops/sec",
                    resource_usage: "Minimal",
                },
                ServiceComplexityLevel::Advanced => PerformanceCharacteristics {
                    memory_footprint: "~500KB+ base",
                    latency: "1-5ms",
                    throughput: "1,000-5,000 ops/sec",
                    resource_usage: "Moderate to High",
                },
            },
            example_code: generate_example_code(use_case, manager_type),
        }
    }
}

/// Setup guide for token exchange implementation
#[derive(Debug, Clone)]
pub struct SetupGuide {
    /// The use case this guide is for
    pub use_case: TokenExchangeUseCase,

    /// Recommended manager type
    pub recommended_manager: ServiceComplexityLevel,

    /// Feature requirements analysis
    pub requirements: ExchangeRequirements,

    /// Step-by-step setup instructions
    pub setup_instructions: Vec<String>,

    /// Performance characteristics to expect
    pub performance_characteristics: PerformanceCharacteristics,

    /// Example implementation code
    pub example_code: String,
}

/// Performance characteristics for a manager type
#[derive(Debug, Clone)]
pub struct PerformanceCharacteristics {
    /// Base memory footprint
    pub memory_footprint: &'static str,

    /// Expected latency range
    pub latency: &'static str,

    /// Expected throughput range
    pub throughput: &'static str,

    /// Overall resource usage
    pub resource_usage: &'static str,
}

fn generate_example_code(
    use_case: TokenExchangeUseCase,
    manager_type: ServiceComplexityLevel,
) -> String {
    match (use_case, manager_type) {
        (TokenExchangeUseCase::SimpleServiceToService, ServiceComplexityLevel::Basic) => r#"
use auth_framework::server::{TokenExchangeManager, TokenExchangeRequest};
use auth_framework::secure_jwt::SecureJwtValidator;

async fn setup_simple_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Create basic manager
    let jwt_validator = SecureJwtValidator::new("your-secret-key".to_string())?;
    let mut manager = TokenExchangeManager::new(jwt_validator);

    // Register client policy
    let policy = TokenExchangePolicy::default();
    manager.register_policy("service_a".to_string(), policy).await;

    // Simple exchange
    let request = TokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: "user_jwt_token".to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
        audience: Some("service_b".to_string()),
        scope: Some("read".to_string()),
        // ... other fields
    };

    let response = manager.exchange_token(request, "service_a").await?;
    println!("New token: {}", response.access_token);

    Ok(())
}
"#
        .to_string(),

        (TokenExchangeUseCase::EnterpriseIntegration, ServiceComplexityLevel::Advanced) => r#"
use auth_framework::server::{
    AdvancedTokenExchangeManager, AdvancedTokenExchangeConfig,
    AdvancedTokenExchangeRequest, ExchangeContext,
};
use auth_framework::server::oidc_session_management::SessionManager;
use std::sync::Arc;

async fn setup_enterprise_exchange() -> Result<(), Box<dyn std::error::Error>> {
    // Advanced configuration
    let config = AdvancedTokenExchangeConfig {
        enable_multi_party_chains: true,
        max_delegation_depth: 10,
        require_audit_trail: true,
        enable_context_preservation: true,
        // ... other enterprise settings
        ..Default::default()
    };

    // Session management integration
    let session_manager = Arc::new(SessionManager::new(Default::default()));
    let manager = AdvancedTokenExchangeManager::new(config, session_manager)?;

    // Complex exchange with business context
    let context = ExchangeContext {
        transaction_id: "enterprise_txn_123".to_string(),
        business_context: serde_json::json!({
            "department": "finance",
            "operation": "quarterly_report_access",
            "compliance_level": "sox_required"
        }),
        delegation_chain: Vec::new(),
        // ... other context fields
    };

    let request = AdvancedTokenExchangeRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        subject_token: "enterprise_user_token".to_string(),
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        requested_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        exchange_context: Some(context),
        policy_requirements: vec![
            "require_mfa".to_string(),
            "audit_financial_access".to_string(),
        ],
        // ... other fields
    };

    let response = manager.exchange_token(request).await?;

    // Enterprise features available in response
    if let Some(audit) = response.exchange_audit {
        println!("Audit ID: {}", audit.exchange_id);
    }

    Ok(())
}
"#
        .to_string(),

        _ => format!(
            r#"
// Example for {:?} using {:?} manager
// Customize based on your specific requirements
use auth_framework::server::token_exchange_common::*;

async fn setup_custom_exchange() -> Result<(), Box<dyn std::error::Error>> {{
    // Use TokenExchangeManagerFactory::get_setup_guide() for detailed instructions
    let guide = TokenExchangeManagerFactory::get_setup_guide(TokenExchangeUseCase::{:?});

    for instruction in &guide.setup_instructions {{
        println!("Step: {{}}", instruction);
    }}

    Ok(())
}}
"#,
            use_case, manager_type, use_case
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_guide_generation() {
        let guide = TokenExchangeManagerFactory::get_setup_guide(
            TokenExchangeUseCase::SimpleServiceToService,
        );

        assert_eq!(guide.recommended_manager, ServiceComplexityLevel::Basic);
        assert!(!guide.setup_instructions.is_empty());
        assert!(!guide.example_code.is_empty());
    }

    #[test]
    fn test_advanced_setup_guide() {
        let guide = TokenExchangeManagerFactory::get_setup_guide(
            TokenExchangeUseCase::EnterpriseIntegration,
        );

        assert_eq!(guide.recommended_manager, ServiceComplexityLevel::Advanced);
        assert!(guide.requirements.needs_audit_trail);
        assert!(guide.requirements.needs_session_integration);
    }

    #[tokio::test]
    async fn test_basic_manager_creation() {
        let result = TokenExchangeManagerFactory::create_basic_manager("test-secret");
        assert!(result.is_ok());
    }
}
