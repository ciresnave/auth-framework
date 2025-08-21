//! Server-side authentication and authorization implementations.
//!
//! This module provides comprehensive server-side capabilities including:
//! - OAuth 2.0 Authorization Server (RFC 6749, RFC 8628) ✅ Working
//! - OAuth 2.1 Authorization Framework ✅ Working
//! - OpenID Connect Provider (OIDC 1.0) [Testing needed]
//! - JWT Token Server
//! - API Gateway Authentication
//! - SAML Identity Provider
//! - WebAuthn Relying Party Server

// Hierarchical module organization
pub mod core; // Core server functionality
pub mod jwt; // JWT-related modules
pub mod oauth; // OAuth 2.0/2.1 components
pub mod oidc; // OpenID Connect components
pub mod security;
pub mod token_exchange; // Token exchange components // Security & compliance modules

// Re-export modules from hierarchical structure for convenience

// Core functionality re-exports
pub use core::{
    additional_modules::{
        api_gateway, consent, device_flow_server, introspection, jwt_server, saml_idp,
    },
    client_registration::{
        ClientRegistrationConfig, ClientRegistrationManager, ClientRegistrationRequest,
        ClientRegistrationResponse, RegisteredClient,
    },
    client_registry::ClientRegistry,
    federated_authentication_orchestration::{
        AlternativeIdp, AppliedTransformation, AttributeMappingConfig, AttributeTransformation,
        AuthenticationProtocol, CircuitBreakerConfig, CircuitBreakerState, FederationOrchestrator,
        FederationOrchestratorConfig, FederationOrchestratorImpl, IdentityProvider, IdpCapability,
        IdpHealthMetrics, IdpRecommendation, IdpRoutingRule, IdpSessionInfo, OrchestrationMetadata,
        OrchestrationPattern, OrchestrationPreferences, OrchestrationRequest,
        OrchestrationResponse, OrchestrationSessionInfo, ProtocolTranslationConfig,
        SelectedIdpInfo, SessionFederationConfig, SessionProtocol, StringOperation, TimeConstraint,
        TrustLevel, TrustValidationConfig,
    },
    metadata::MetadataProvider,
    stepped_up_auth::{
        AuthenticationLevel, AuthenticationMethod, LocationInfo, StepUpConfig, StepUpContext,
        StepUpEvaluationResult, StepUpRequest, StepUpResponse, StepUpRule, StepUpStatus,
        StepUpTrigger, SteppedUpAuthManager,
    },
};

// OAuth 2.0/2.1 re-exports
pub use oauth::{
    oauth2::OAuth2Server,
    oauth21::OAuth21Server,
    par::PARManager,
    rich_authorization_requests::{
        AuthorizationDetail, RarAuthorizationDecision, RarAuthorizationProcessor,
        RarAuthorizationRequest, RarCondition, RarConfig, RarDecisionType, RarDetailDecision,
        RarManager, RarPermissionGrant, RarResourceAccess, RarResourceDiscoveryRequest,
        RarResourceDiscoveryResponse, RarRestriction, RarValidationResult,
    },
};

// OIDC re-exports
pub use oidc::{
    core::OidcProvider,
    oidc_advanced_jarm::{
        AdvancedJarmConfig, AdvancedJarmManager, AuthorizationResponse, DeliveryResult,
        JarmDeliveryMode, JarmResponse, JarmValidationResult,
    },
    oidc_backchannel_logout::{
        BackChannelLogoutConfig, BackChannelLogoutManager, BackChannelLogoutRequest,
        BackChannelLogoutResponse, LogoutEvents, LogoutTokenClaims, NotificationResult,
        RpBackChannelConfig,
    },
    oidc_enhanced_ciba::{
        AuthenticationContext, AuthenticationMode, CibaRequestStatus, CibaTokenResponse,
        ConsentInfo, ConsentStatus, DeviceBinding, DeviceInfo, EnhancedCibaAuthRequest,
        EnhancedCibaAuthResponse, EnhancedCibaConfig, EnhancedCibaManager, GeoLocation,
        UserIdentifierHint,
    },
    oidc_error_extensions::{
        AuthenticationRequirements, OidcErrorCode, OidcErrorManager, OidcErrorResponse,
    },
    oidc_extensions::OidcExtensionsManager,
    oidc_frontchannel_logout::{
        FailedNotification, FrontChannelLogoutConfig, FrontChannelLogoutManager,
        FrontChannelLogoutRequest, FrontChannelLogoutResponse, RpFrontChannelConfig,
    },
    oidc_response_modes::{
        FormPostResponseMode, JarmResponseMode, MultipleResponseTypesManager, ResponseMode,
    },
    // Temporarily disabled: oidc_rp_initiated_logout module
    // oidc_rp_initiated_logout::{
    //     ClientLogoutConfig, RpInitiatedLogoutConfig, RpInitiatedLogoutManager,
    //     RpInitiatedLogoutRequest, RpInitiatedLogoutResponse,
    // },
    oidc_session_management::{
        OidcSession, SessionCheckRequest, SessionCheckResponse, SessionManager, SessionState,
    },
    oidc_user_registration::{
        RegistrationData, RegistrationManager, RegistrationRequest, RegistrationResponse,
    },
};

// JWT re-exports
pub use jwt::{
    jwt_access_tokens::{JwtAccessTokenBuilder, JwtAccessTokenValidator},
    jwt_best_practices::{
        CryptoStrength, JwtBestPracticesConfig, JwtBestPracticesValidator, SecureJwtClaims,
        SecurityLevel,
    },
    jwt_introspection::{
        BasicIntrospectionResponse, JwtIntrospectionClaims, JwtIntrospectionConfig,
        JwtIntrospectionManager,
    },
    private_key_jwt::PrivateKeyJwtManager,
};

// Token Exchange re-exports
pub use token_exchange::{
    advanced_token_exchange::{AdvancedTokenExchangeConfig, AdvancedTokenExchangeManager},
    core::TokenExchangeManager,
    token_exchange_common::{
        ExchangeRequirements, ServiceComplexityLevel, TokenExchangeCapabilities,
        TokenExchangeFactory, TokenExchangeService, TokenExchangeUseCase, TokenValidationResult,
        ValidationUtils,
    },
    token_exchange_factory::{PerformanceCharacteristics, SetupGuide, TokenExchangeManagerFactory},
    token_introspection::{TokenIntrospectionHandler, TokenIntrospectionService},
};

// Security re-exports
pub use security::{
    caep_continuous_access::{
        CaepAccessDecision, CaepConfig, CaepDeviceInfo, CaepEvaluationResult, CaepEvaluationRule,
        CaepEvent, CaepEventHandler, CaepEventSeverity, CaepEventSource, CaepEventType,
        CaepLocationInfo, CaepManager, CaepRuleAction, CaepRuleCondition, CaepSessionState,
    },
    dpop::DpopManager,
    fapi::FapiManager,
    mtls::MutualTlsManager,
    x509_signing::X509CertificateManager,
};

use crate::errors::Result;
use crate::permissions::Permission;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

// Temporarily commenting out the full AuthServer struct until OAuth modules are fixed
// This will be re-enabled once the base64 and type system issues are resolved

/// Minimal server configuration for working components
#[derive(Debug, Clone, Default)]
pub struct WorkingServerConfig {
    // Temporarily simplified until hierarchical imports are resolved
}

/// Client type for minimal functionality
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientType {
    /// Public client (cannot securely store credentials)
    Public,
    /// Confidential client (can securely store credentials)
    Confidential,
}

/// Trait for server-side authentication providers
#[async_trait]
pub trait AuthenticationProvider {
    /// Provider name
    fn name(&self) -> &str;

    /// Initialize the provider
    async fn initialize(&self) -> Result<()>;

    /// Handle authentication request
    async fn handle_auth_request(&self, request: AuthRequest) -> Result<AuthResponse>;

    /// Validate credentials
    async fn validate_credentials(&self, credentials: &str) -> Result<ValidationResult>;

    /// Get provider metadata
    async fn get_metadata(&self) -> Result<ProviderMetadata>;
}

/// Generic authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Request type
    pub request_type: String,

    /// Request parameters
    pub parameters: HashMap<String, String>,

    /// Client information
    pub client_id: Option<String>,

    /// User information
    pub user_id: Option<String>,

    /// Request timestamp
    pub timestamp: SystemTime,
}

/// Generic authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Response type
    pub response_type: String,

    /// Response data
    pub data: HashMap<String, serde_json::Value>,

    /// Success indicator
    pub success: bool,

    /// Error message if any
    pub error: Option<String>,

    /// Response timestamp
    pub timestamp: SystemTime,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the credentials are valid
    pub valid: bool,

    /// User ID if valid
    pub user_id: Option<String>,

    /// Client ID if applicable
    pub client_id: Option<String>,

    /// Scopes granted
    pub scopes: Vec<String>,

    /// Permissions granted
    pub permissions: Vec<Permission>,

    /// Token expiration time
    pub expires_at: Option<SystemTime>,

    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Provider metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// Provider name
    pub name: String,

    /// Supported endpoints
    pub endpoints: HashMap<String, String>,

    /// Supported grant types
    pub grant_types: Vec<String>,

    /// Supported response types
    pub response_types: Vec<String>,

    /// Supported scopes
    pub scopes: Vec<String>,

    /// Additional metadata
    pub additional: HashMap<String, serde_json::Value>,
}


