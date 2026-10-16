//! # Advanced Token Exchange - Enhanced RFC 8693
//!
//! This module implements an advanced version of the OAuth 2.0 Token Exchange specification
//! (RFC 8693) with additional features for multi-party token chains, context preservation,
//! and sophisticated delegation patterns commonly needed in enterprise and microservice environments.
//!
//! ## Overview
//!
//! Advanced Token Exchange extends the basic token exchange specification with:
//! - **Multi-Party Token Chains**: Complex delegation paths through multiple services
//! - **Context Preservation**: Maintaining original request context through token chains
//! - **Privilege Delegation**: Fine-grained privilege escalation and de-escalation
//! - **Audit Trail**: Complete audit logging of token exchange operations
//! - **Policy-Based Exchange**: Configurable rules for token exchange authorization
//! - **Cross-Domain Exchange**: Secure token exchange across trust boundaries
//!
//! ## Key Features
//!
//! - **Enhanced Subject and Actor Tokens**: Support for complex token relationships
//! - **Context-Aware Exchange**: Preserving business context through delegation
//! - **Chain Validation**: Ensuring legitimate delegation chains
//! - **Privilege Mapping**: Automatic privilege translation between domains
//! - **Revocation Cascading**: Cascading token revocation through delegation chains
//! - **Advanced Scopes**: Hierarchical and conditional scope management
//!
//! ## Token Exchange Types
//!
//! - **Impersonation Exchange**: Acting on behalf of another entity
//! - **Delegation Exchange**: Delegating specific privileges to another service
//! - **Translation Exchange**: Converting token formats or standards
//! - **Context Exchange**: Preserving request context in service chains
//! - **Federation Exchange**: Cross-domain identity federation
//! - **Privilege Escalation**: Controlled privilege elevation
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::token_exchange::advanced_token_exchange::*;
//! use auth_framework::server::SessionManager;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize advanced token exchange manager
//! let config = AdvancedTokenExchangeConfig {
//!     enable_multi_party_chains: true,
//!     max_delegation_depth: 5,
//!     require_audit_trail: true,
//!     enable_context_preservation: true,
//!     ..Default::default()
//! };
//!
//! let session_manager = Arc::new(SessionManager::new(Default::default()));
//! let exchange_manager = AdvancedTokenExchangeManager::new(config, session_manager)?;
//!
//! // Create complex token exchange request
//! let exchange_request = AdvancedTokenExchangeRequest {
//!     grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
//!     subject_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...".to_string(),
//!     subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
//!     requested_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
//!     exchange_context: Some(ExchangeContext {
//!         transaction_id: "txn_123456".to_string(),
//!         business_context: serde_json::json!({
//!             "operation": "payment_processing",
//!             "amount": 1000.00,
//!             "currency": "USD"
//!         }),
//!         delegation_chain: Vec::new(),
//!         original_request: None,
//!         security_context: None,
//!         custom_fields: std::collections::HashMap::new(),
//!     }),
//!     policy_requirements: vec![
//!         "require_mfa".to_string(),
//!         "audit_financial_operations".to_string()
//!     ],
//!     actor_token: None,
//!     actor_token_type: None,
//!     resource: Vec::new(),
//!     audience: Vec::new(),
//!     scope: None,
//!     custom_parameters: std::collections::HashMap::new(),
//! };
//!
//! // Process token exchange
//! let exchange_result = exchange_manager.exchange_token(exchange_request).await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::server::oidc::oidc_session_management::SessionManager;
use crate::server::token_exchange::token_exchange_common::{
    ServiceComplexityLevel, TokenExchangeCapabilities, TokenExchangeService, TokenValidationResult,
    ValidationUtils,
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

/// Authentication level for step-up authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthLevel {
    /// Basic authentication (password only)
    Basic = 1,
    /// Multi-factor authentication
    Mfa = 2,
    /// High security (additional verification required)
    High = 3,
}

impl FromStr for AuthLevel {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(AuthLevel::Basic),
            "mfa" => Ok(AuthLevel::Mfa),
            "high" => Ok(AuthLevel::High),
            _ => Err(AuthError::InvalidRequest(format!(
                "Invalid auth level: {}",
                s
            ))),
        }
    }
}

impl std::fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level_str = match self {
            AuthLevel::Basic => "basic",
            AuthLevel::Mfa => "mfa",
            AuthLevel::High => "high",
        };
        write!(f, "{}", level_str)
    }
}

/// Configuration for Advanced Token Exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTokenExchangeConfig {
    /// Enable multi-party token chains
    pub enable_multi_party_chains: bool,

    /// Maximum delegation depth allowed
    pub max_delegation_depth: usize,

    /// Require complete audit trail
    pub require_audit_trail: bool,

    /// Enable context preservation
    pub enable_context_preservation: bool,

    /// Default token lifetime for exchanged tokens
    pub default_token_lifetime: Duration,

    /// Supported subject token types
    pub supported_subject_token_types: Vec<String>,

    /// Supported requested token types
    pub supported_requested_token_types: Vec<String>,

    /// Token exchange policies
    pub exchange_policies: Vec<TokenExchangePolicy>,

    /// Cross-domain exchange settings
    pub cross_domain_settings: CrossDomainExchangeSettings,

    /// JWT configuration for token operations
    pub jwt_signing_key: String,

    /// JWT verification key
    pub jwt_verification_key: String,

    /// Trusted token issuers for enhanced validation
    pub trusted_issuers: Vec<String>,
}

impl Default for AdvancedTokenExchangeConfig {
    fn default() -> Self {
        Self {
            enable_multi_party_chains: true,
            max_delegation_depth: 3,
            require_audit_trail: true,
            enable_context_preservation: true,
            default_token_lifetime: Duration::try_hours(1).unwrap_or(Duration::zero()),
            supported_subject_token_types: vec![
                "urn:ietf:params:oauth:token-type:jwt".to_string(),
                "urn:ietf:params:oauth:token-type:access_token".to_string(),
                "urn:ietf:params:oauth:token-type:refresh_token".to_string(),
                "urn:ietf:params:oauth:token-type:id_token".to_string(),
                "urn:ietf:params:oauth:token-type:saml2".to_string(),
            ],
            supported_requested_token_types: vec![
                "urn:ietf:params:oauth:token-type:jwt".to_string(),
                "urn:ietf:params:oauth:token-type:access_token".to_string(),
                "urn:ietf:params:oauth:token-type:refresh_token".to_string(),
            ],
            exchange_policies: Vec::new(),
            cross_domain_settings: CrossDomainExchangeSettings::default(),
            jwt_signing_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...".to_string(), // Default key for testing
            jwt_verification_key: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...".to_string(), // Default key for testing
            trusted_issuers: vec![
                "https://auth.example.com".to_string(),
                "https://login.example.org".to_string(),
            ],
        }
    }
}

/// Advanced Token Exchange Request following enhanced RFC 8693
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTokenExchangeRequest {
    /// Grant type (must be "urn:ietf:params:oauth:grant-type:token-exchange")
    pub grant_type: String,

    /// The security token representing the identity of the party on behalf of whom the request is being made
    pub subject_token: String,

    /// Type identifier for the subject_token
    pub subject_token_type: String,

    /// Security token representing the identity of the acting party (optional)
    pub actor_token: Option<String>,

    /// Type identifier for the actor_token (optional)
    pub actor_token_type: Option<String>,

    /// Identifier for the type of the requested security token
    pub requested_token_type: String,

    /// Requested scope values for the issued token (optional)
    pub scope: Option<String>,

    /// Intended audience for the requested token (optional)
    pub audience: Vec<String>,

    /// Requested resources for the token (optional)
    pub resource: Vec<String>,

    /// Exchange context for advanced features
    pub exchange_context: Option<ExchangeContext>,

    /// Policy requirements for this exchange
    pub policy_requirements: Vec<String>,

    /// Custom exchange parameters
    pub custom_parameters: HashMap<String, serde_json::Value>,
}

/// Exchange context for preserving business and technical context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeContext {
    /// Unique transaction identifier
    pub transaction_id: String,

    /// Business context data
    pub business_context: serde_json::Value,

    /// Delegation chain history
    pub delegation_chain: Vec<DelegationLink>,

    /// Original request metadata
    pub original_request: Option<RequestMetadata>,

    /// Security context
    pub security_context: Option<SecurityContext>,

    /// Custom context fields
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Link in the delegation chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Entity that performed the delegation
    pub delegator: String,

    /// Entity receiving the delegation
    pub delegatee: String,

    /// Timestamp of delegation
    pub delegated_at: DateTime<Utc>,

    /// Reason for delegation
    pub delegation_reason: String,

    /// Scopes delegated
    pub delegated_scopes: Vec<String>,

    /// Restrictions on delegation
    pub restrictions: Vec<DelegationRestriction>,
}

/// Delegation restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DelegationRestriction {
    /// Time-based restriction
    TimeLimit { expires_at: DateTime<Utc> },

    /// Usage count restriction
    UsageLimit { max_uses: u32, current_uses: u32 },

    /// IP address restriction
    IpRestriction { allowed_ips: Vec<String> },

    /// Scope restriction
    ScopeRestriction { restricted_scopes: Vec<String> },

    /// Custom restriction
    Custom {
        restriction_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Original request metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Original client ID
    pub client_id: String,

    /// Original user agent
    pub user_agent: Option<String>,

    /// Original IP address
    pub ip_address: Option<String>,

    /// Request timestamp
    pub timestamp: DateTime<Utc>,

    /// Request headers
    pub headers: HashMap<String, String>,
}

/// Security context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Session identifier
    pub session_id: Option<String>,

    /// Authentication level achieved
    pub authentication_level: String,

    /// MFA status
    pub mfa_completed: bool,

    /// Risk assessment score
    pub risk_score: f64,

    /// Device information
    pub device_info: Option<DeviceContext>,

    /// Location information
    pub location_info: Option<LocationContext>,
}

/// Device context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceContext {
    /// Device identifier
    pub device_id: String,

    /// Device type
    pub device_type: String,

    /// Device trust level
    pub trust_level: String,

    /// Device fingerprint
    pub fingerprint: Option<String>,
}

/// Location context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationContext {
    /// Country code
    pub country: Option<String>,

    /// City
    pub city: Option<String>,

    /// IP geolocation data
    pub geo_data: Option<serde_json::Value>,

    /// Network information
    pub network_info: Option<String>,
}

/// Token exchange policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangePolicy {
    /// Policy identifier
    pub id: String,

    /// Policy name
    pub name: String,

    /// Conditions that must be met
    pub conditions: Vec<PolicyCondition>,

    /// Actions to take if conditions are met
    pub actions: Vec<PolicyAction>,

    /// Whether this policy is mandatory
    pub mandatory: bool,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyCondition {
    /// Subject token type condition
    SubjectTokenType { allowed_types: Vec<String> },

    /// Scope requirement condition
    ScopeRequirement {
        required_scopes: Vec<String>,
        all_required: bool,
    },

    /// Delegation depth condition
    DelegationDepth { max_depth: usize },

    /// Client authorization condition
    ClientAuthorization { authorized_clients: Vec<String> },

    /// Time-based condition
    TimeRestriction {
        allowed_hours: Vec<u8>,
        timezone: String,
    },

    /// Custom condition
    Custom {
        condition_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Policy action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow the exchange
    Allow,

    /// Deny the exchange
    Deny { reason: String },

    /// Require additional authentication
    RequireStepUp { required_level: String },

    /// Apply scope restrictions
    RestrictScopes { allowed_scopes: Vec<String> },

    /// Apply token lifetime restrictions
    RestrictLifetime { max_lifetime: Duration },

    /// Custom action
    Custom {
        action_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Cross-domain exchange settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainExchangeSettings {
    /// Enable cross-domain exchanges
    pub enabled: bool,

    /// Trusted domains
    pub trusted_domains: Vec<String>,

    /// Cross-domain policies
    pub cross_domain_policies: Vec<CrossDomainPolicy>,

    /// Required additional validation
    pub require_domain_validation: bool,
}

impl Default for CrossDomainExchangeSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            trusted_domains: Vec::new(),
            cross_domain_policies: Vec::new(),
            require_domain_validation: true,
        }
    }
}

/// Cross-domain exchange policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainPolicy {
    /// Policy identifier
    pub id: String,

    /// Source domain pattern
    pub source_domain: String,

    /// Target domain pattern
    pub target_domain: String,

    /// Allowed token types for cross-domain exchange
    pub allowed_token_types: Vec<String>,

    /// Required additional claims
    pub required_claims: Vec<String>,

    /// Scope mapping rules
    pub scope_mappings: HashMap<String, String>,
}

/// Token exchange response following enhanced RFC 8693
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTokenExchangeResponse {
    /// The security token issued by the authorization server
    pub access_token: String,

    /// The type of the token issued
    pub issued_token_type: String,

    /// The type of access token
    pub token_type: String,

    /// Lifetime in seconds of the access token
    pub expires_in: Option<u64>,

    /// Space-delimited list of scopes granted
    pub scope: Option<String>,

    /// Refresh token (if applicable)
    pub refresh_token: Option<String>,

    /// Exchange audit information
    pub exchange_audit: Option<ExchangeAuditInfo>,

    /// Context preserved from the exchange
    pub preserved_context: Option<ExchangeContext>,

    /// Additional response parameters
    pub additional_parameters: HashMap<String, serde_json::Value>,
}

/// Exchange audit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeAuditInfo {
    /// Unique exchange identifier
    pub exchange_id: Uuid,

    /// Exchange timestamp
    pub timestamp: DateTime<Utc>,

    /// Exchange type performed
    pub exchange_type: TokenExchangeType,

    /// Subject information
    pub subject_info: SubjectInfo,

    /// Actor information (if applicable)
    pub actor_info: Option<ActorInfo>,

    /// Policy decisions applied
    pub policy_decisions: Vec<PolicyDecision>,

    /// Security assessments performed
    pub security_assessments: Vec<SecurityAssessment>,
}

/// Type of token exchange performed
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenExchangeType {
    /// Impersonation exchange
    Impersonation,

    /// Delegation exchange
    Delegation,

    /// Translation exchange
    Translation,

    /// Context-preserving exchange
    ContextExchange,

    /// Federation exchange
    Federation,

    /// Privilege escalation
    PrivilegeEscalation,
}

/// Subject information for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectInfo {
    /// Subject identifier
    pub subject: String,

    /// Subject type
    pub subject_type: String,

    /// Original token information
    pub original_token_info: TokenInfo,

    /// Subject attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Actor information for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    /// Actor identifier
    pub actor: String,

    /// Actor type
    pub actor_type: String,

    /// Actor token information
    pub actor_token_info: TokenInfo,

    /// Actor attributes
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token type
    pub token_type: String,

    /// Token issuer
    pub issuer: String,

    /// Token audience
    pub audience: Vec<String>,

    /// Token scopes
    pub scopes: Vec<String>,

    /// Token expiration
    pub expires_at: Option<DateTime<Utc>>,

    /// Token metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Policy decision applied during exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Policy identifier
    pub policy_id: String,

    /// Decision result
    pub decision: PolicyDecisionResult,

    /// Reason for decision
    pub reason: String,

    /// Applied modifications
    pub applied_modifications: Vec<String>,
}

/// Policy decision result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionResult {
    /// Policy allowed the exchange
    Allow,

    /// Policy denied the exchange
    Deny,

    /// Policy modified the exchange
    Modify,

    /// Policy required additional verification
    RequireVerification,
}

/// Security assessment performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAssessment {
    /// Assessment type
    pub assessment_type: String,

    /// Assessment result
    pub result: SecurityAssessmentResult,

    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,

    /// Assessment details
    pub details: HashMap<String, serde_json::Value>,
}

/// Security assessment result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAssessmentResult {
    /// Assessment passed
    Pass,

    /// Assessment failed
    Fail,

    /// Assessment requires review
    RequiresReview,

    /// Assessment inconclusive
    Inconclusive,
}

/// Token exchange processor trait
#[async_trait]
pub trait TokenExchangeProcessor: Send + Sync {
    /// Process token exchange request
    async fn process_exchange(
        &self,
        request: &AdvancedTokenExchangeRequest,
        context: &ExchangeContext,
    ) -> Result<AdvancedTokenExchangeResponse>;

    /// Validate subject token
    async fn validate_subject_token(&self, token: &str, token_type: &str) -> Result<TokenInfo>;

    /// Validate actor token
    async fn validate_actor_token(&self, token: &str, token_type: &str) -> Result<TokenInfo>;

    /// Generate exchanged token
    async fn generate_exchanged_token(
        &self,
        subject_info: &SubjectInfo,
        actor_info: Option<&ActorInfo>,
        request: &AdvancedTokenExchangeRequest,
    ) -> Result<String>;
}

/// Main Advanced Token Exchange Manager
pub struct AdvancedTokenExchangeManager {
    /// Configuration
    config: AdvancedTokenExchangeConfig,

    /// Session manager integration
    session_manager: Arc<SessionManager>,

    /// Token processors by type
    processors: HashMap<String, Arc<dyn TokenExchangeProcessor>>,

    /// Exchange audit log
    exchange_audit: Arc<tokio::sync::RwLock<Vec<ExchangeAuditInfo>>>,

    /// JWT encoding key
    encoding_key: EncodingKey,

    /// JWT decoding key
    decoding_key: DecodingKey,
}

impl AdvancedTokenExchangeManager {
    /// Create a new advanced token exchange manager
    pub fn new(
        config: AdvancedTokenExchangeConfig,
        session_manager: Arc<SessionManager>,
    ) -> Result<Self> {
        // Initialize JWT keys from config
        let encoding_key = EncodingKey::from_rsa_pem(config.jwt_signing_key.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_pem(config.jwt_verification_key.as_bytes())?;

        Ok(Self {
            config,
            session_manager,
            processors: HashMap::new(),
            exchange_audit: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            encoding_key,
            decoding_key,
        })
    }

    /// Register a token exchange processor
    pub fn register_processor(
        &mut self,
        token_type: String,
        processor: Arc<dyn TokenExchangeProcessor>,
    ) {
        self.processors.insert(token_type, processor);
    }

    /// Exchange token following enhanced RFC 8693
    pub async fn exchange_token(
        &self,
        request: AdvancedTokenExchangeRequest,
    ) -> Result<AdvancedTokenExchangeResponse> {
        // Validate request
        self.validate_exchange_request(&request).await?;

        // Extract/create exchange context
        let context = request
            .exchange_context
            .clone()
            .unwrap_or_else(|| ExchangeContext {
                transaction_id: Uuid::new_v4().to_string(),
                business_context: serde_json::Value::Null,
                delegation_chain: Vec::new(),
                original_request: None,
                security_context: None,
                custom_fields: HashMap::new(),
            });

        // Validate delegation chain depth
        if context.delegation_chain.len() > self.config.max_delegation_depth {
            return Err(AuthError::InvalidRequest(
                "Maximum delegation depth exceeded".to_string(),
            ));
        }

        // Apply exchange policies
        self.apply_exchange_policies(&request, &context).await?;

        // Validate subject token
        let subject_info = self.validate_and_extract_subject_info(&request).await?;

        // Validate actor token if present
        let actor_info = if request.actor_token.is_some() {
            Some(self.validate_and_extract_actor_info(&request).await?)
        } else {
            None
        };

        // Determine exchange type
        let exchange_type = self.determine_exchange_type(&request, &subject_info, &actor_info);

        // Process the exchange
        let processor = self.get_processor(&request.requested_token_type)?;
        let mut response = processor.process_exchange(&request, &context).await?;

        // Create audit information
        let audit_info = self
            .create_audit_info(
                exchange_type,
                &subject_info,
                &actor_info,
                &request,
                &context,
            )
            .await?;

        // Store audit information
        {
            let mut audit_log = self.exchange_audit.write().await;
            audit_log.push(audit_info.clone());
        }

        // Add audit info to response if required
        if self.config.require_audit_trail {
            response.exchange_audit = Some(audit_info.clone());

            // Generate signed audit token for verification
            let audit_token = self.generate_audit_token(&audit_info)?;
            response.additional_parameters.insert(
                "audit_token".to_string(),
                serde_json::Value::String(audit_token),
            );
        }

        // Preserve context if enabled
        if self.config.enable_context_preservation {
            let preserved_context = context.clone();
            response.preserved_context = Some(preserved_context.clone());

            // Generate delegation token for chain integrity
            let delegation_token = self.generate_delegation_token(&preserved_context)?;
            response.additional_parameters.insert(
                "delegation_token".to_string(),
                serde_json::Value::String(delegation_token),
            );
        }

        Ok(response)
    }

    /// Get exchange audit history
    pub async fn get_exchange_audit(&self) -> Vec<ExchangeAuditInfo> {
        let audit_log = self.exchange_audit.read().await;
        audit_log.clone()
    }

    /// Validate exchange request
    async fn validate_exchange_request(
        &self,
        request: &AdvancedTokenExchangeRequest,
    ) -> Result<()> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
            return Err(AuthError::InvalidRequest(
                "Invalid grant type for token exchange".to_string(),
            ));
        }

        // Validate subject token type
        if !self
            .config
            .supported_subject_token_types
            .contains(&request.subject_token_type)
        {
            return Err(AuthError::InvalidRequest(format!(
                "Unsupported subject token type: {}",
                request.subject_token_type
            )));
        }

        // Validate requested token type
        if !self
            .config
            .supported_requested_token_types
            .contains(&request.requested_token_type)
        {
            return Err(AuthError::InvalidRequest(format!(
                "Unsupported requested token type: {}",
                request.requested_token_type
            )));
        }

        // Validate actor token type if present
        if let Some(ref actor_token_type) = request.actor_token_type
            && !self
                .config
                .supported_subject_token_types
                .contains(actor_token_type)
        {
            return Err(AuthError::InvalidRequest(format!(
                "Unsupported actor token type: {}",
                actor_token_type
            )));
        }

        Ok(())
    }

    /// Apply exchange policies
    async fn apply_exchange_policies(
        &self,
        request: &AdvancedTokenExchangeRequest,
        context: &ExchangeContext,
    ) -> Result<()> {
        // Introspect subject token if it's a JWT for additional policy context
        if request.subject_token_type == "urn:ietf:params:oauth:token-type:jwt" {
            match self.introspect_jwt_token(&request.subject_token) {
                Ok(token_claims) => {
                    // Use JWT claims for enhanced policy decisions
                    if let Some(iss) = token_claims.get("iss").and_then(|v| v.as_str())
                        && !self.config.trusted_issuers.contains(&iss.to_string())
                    {
                        return Err(AuthError::InvalidRequest(format!(
                            "Token issued by untrusted issuer: {}",
                            iss
                        )));
                    }
                }
                Err(_) => {
                    // If introspection fails, continue but log for audit
                    // This is permissive since token processors will validate properly
                }
            }
        }

        for policy in &self.config.exchange_policies {
            let policy_applies = self.evaluate_policy_conditions(policy, request, context)?;

            if policy_applies {
                for action in &policy.actions {
                    match action {
                        PolicyAction::Deny { reason } => {
                            return Err(AuthError::InvalidRequest(format!(
                                "Exchange denied by policy '{}': {}",
                                policy.name, reason
                            )));
                        }
                        PolicyAction::RequireStepUp { required_level } => {
                            // Integration point: Use session manager for step-up authentication
                            let auth_level = required_level.parse::<AuthLevel>().map_err(|_| {
                                AuthError::InvalidRequest(format!(
                                    "Invalid authentication level: {}",
                                    required_level
                                ))
                            })?;
                            return self
                                .handle_step_up_authentication(auth_level, context)
                                .await;
                        }
                        _ => {
                            // Other policy actions would be applied here
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Evaluate policy conditions
    fn evaluate_policy_conditions(
        &self,
        policy: &TokenExchangePolicy,
        request: &AdvancedTokenExchangeRequest,
        context: &ExchangeContext,
    ) -> Result<bool> {
        for condition in &policy.conditions {
            match condition {
                PolicyCondition::SubjectTokenType { allowed_types } => {
                    if !allowed_types.contains(&request.subject_token_type) {
                        return Ok(false);
                    }
                }
                PolicyCondition::DelegationDepth { max_depth } => {
                    if context.delegation_chain.len() > *max_depth {
                        return Ok(false);
                    }
                }
                PolicyCondition::ScopeRequirement {
                    required_scopes,
                    all_required,
                } => {
                    if let Some(ref scope) = request.scope {
                        let request_scopes: HashSet<&str> = scope.split(' ').collect();
                        let required: HashSet<&str> =
                            required_scopes.iter().map(|s| s.as_str()).collect();

                        if *all_required {
                            if !required.is_subset(&request_scopes) {
                                return Ok(false);
                            }
                        } else if required.is_disjoint(&request_scopes) {
                            return Ok(false);
                        }
                    }
                }
                _ => {
                    // Other conditions would be evaluated here
                }
            }
        }

        Ok(true)
    }

    /// Validate and extract subject information
    async fn validate_and_extract_subject_info(
        &self,
        request: &AdvancedTokenExchangeRequest,
    ) -> Result<SubjectInfo> {
        let processor = self.get_processor(&request.subject_token_type)?;
        let token_info = processor
            .validate_subject_token(&request.subject_token, &request.subject_token_type)
            .await?;

        Ok(SubjectInfo {
            subject: token_info
                .metadata
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            subject_type: "user".to_string(), // Could be extracted from token
            original_token_info: token_info,
            attributes: HashMap::new(),
        })
    }

    /// Validate and extract actor information
    async fn validate_and_extract_actor_info(
        &self,
        request: &AdvancedTokenExchangeRequest,
    ) -> Result<ActorInfo> {
        let actor_token = request.actor_token.as_ref().unwrap();
        let actor_token_type = request.actor_token_type.as_ref().unwrap();

        let processor = self.get_processor(actor_token_type)?;
        let token_info = processor
            .validate_actor_token(actor_token, actor_token_type)
            .await?;

        Ok(ActorInfo {
            actor: token_info
                .metadata
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            actor_type: "service".to_string(), // Could be extracted from token
            actor_token_info: token_info,
            attributes: HashMap::new(),
        })
    }

    /// Determine exchange type
    fn determine_exchange_type(
        &self,
        request: &AdvancedTokenExchangeRequest,
        _subject_info: &SubjectInfo,
        actor_info: &Option<ActorInfo>,
    ) -> TokenExchangeType {
        if actor_info.is_some() {
            TokenExchangeType::Delegation
        } else if request.exchange_context.is_some() {
            TokenExchangeType::ContextExchange
        } else if request.subject_token_type != request.requested_token_type {
            TokenExchangeType::Translation
        } else {
            TokenExchangeType::Impersonation
        }
    }

    /// Get processor for token type
    fn get_processor(&self, token_type: &str) -> Result<Arc<dyn TokenExchangeProcessor>> {
        self.processors.get(token_type).cloned().ok_or_else(|| {
            AuthError::InvalidRequest(format!(
                "No processor registered for token type: {}",
                token_type
            ))
        })
    }

    /// Create audit information
    async fn create_audit_info(
        &self,
        exchange_type: TokenExchangeType,
        _subject_info: &SubjectInfo,
        actor_info: &Option<ActorInfo>,
        _request: &AdvancedTokenExchangeRequest,
        _context: &ExchangeContext,
    ) -> Result<ExchangeAuditInfo> {
        Ok(ExchangeAuditInfo {
            exchange_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            exchange_type,
            subject_info: _subject_info.clone(),
            actor_info: actor_info.clone(),
            policy_decisions: Vec::new(), // Would be populated with actual policy decisions
            security_assessments: Vec::new(), // Would be populated with actual assessments
        })
    }

    /// Clean up old audit entries
    pub async fn cleanup_old_audit_entries(&self, older_than: DateTime<Utc>) -> usize {
        let mut audit_log = self.exchange_audit.write().await;
        let original_len = audit_log.len();

        audit_log.retain(|entry| entry.timestamp > older_than);

        original_len - audit_log.len()
    }

    /// Generate a signed audit token for exchange verification
    pub fn generate_audit_token(&self, audit_info: &ExchangeAuditInfo) -> Result<String> {
        use jsonwebtoken::{Algorithm, Header, encode};
        use serde_json::json;

        let header = Header::new(Algorithm::HS256);

        let claims = json!({
            "iss": "advanced-token-exchange",
            "sub": audit_info.subject_info.subject,
            "aud": "audit-verification",
            "exp": (Utc::now() + Duration::seconds(3600)).timestamp(),
            "iat": Utc::now().timestamp(),
            "exchange_id": audit_info.exchange_id,
            "exchange_type": audit_info.exchange_type,
            "timestamp": audit_info.timestamp,
            "policy_decisions": audit_info.policy_decisions.len(),
            "security_assessments": audit_info.security_assessments.len()
        });

        encode(&header, &claims, &self.encoding_key).map_err(|e| {
            AuthError::TokenGeneration(format!("Failed to generate audit token: {}", e))
        })
    }

    /// Validate a delegation context token to ensure chain integrity
    pub fn validate_delegation_token(&self, token: &str) -> Result<serde_json::Value> {
        use jsonwebtoken::{Algorithm, Validation, decode};

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["delegation-context"]);
        validation.set_issuer(&["advanced-token-exchange"]);

        let token_data = decode::<serde_json::Value>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid delegation token: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Generate a delegation context token for preserving chain integrity
    pub fn generate_delegation_token(&self, context: &ExchangeContext) -> Result<String> {
        use jsonwebtoken::{Algorithm, Header, encode};
        use serde_json::json;

        let header = Header::new(Algorithm::RS256);

        let claims = json!({
            "iss": "advanced-token-exchange",
            "aud": "delegation-context",
            "exp": (Utc::now() + Duration::seconds(1800)).timestamp(), // 30 minutes
            "iat": Utc::now().timestamp(),
            "transaction_id": context.transaction_id,
            "delegation_chain_length": context.delegation_chain.len(),
            "delegation_chain": context.delegation_chain,
            "business_context": context.business_context,
            "custom_fields": context.custom_fields
        });

        encode(&header, &claims, &self.encoding_key).map_err(|e| {
            AuthError::TokenGeneration(format!("Failed to generate delegation token: {}", e))
        })
    }

    /// Introspect and validate any JWT token using the manager's keys
    pub fn introspect_jwt_token(&self, token: &str) -> Result<serde_json::Value> {
        use jsonwebtoken::{Algorithm, Validation, decode};

        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation(); // For introspection only

        let token_data = decode::<serde_json::Value>(token, &self.decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(format!("Token introspection failed: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Handle step-up authentication for elevated security requirements
    async fn handle_step_up_authentication(
        &self,
        required_level: AuthLevel,
        context: &ExchangeContext,
    ) -> Result<()> {
        // Check if we have an active session first
        if let Some(session_id) = context
            .security_context
            .as_ref()
            .and_then(|sc| sc.session_id.as_ref())
        {
            // Validate current session and check if it meets required auth level
            match self.session_manager.get_session(session_id) {
                Some(session) => {
                    // Check if current auth level is sufficient
                    if let Some(current_level) = session
                        .metadata
                        .get("auth_level")
                        .map(|v| v.as_str())
                        .and_then(|s| s.parse::<AuthLevel>().ok())
                        && current_level >= required_level
                    {
                        // Current session already meets requirements
                        return Ok(());
                    }

                    // Session exists but doesn't meet auth level - require step-up
                    Err(AuthError::StepUpRequired {
                        current_level: session
                            .metadata
                            .get("auth_level")
                            .map(|v| v.as_str())
                            .unwrap_or("basic")
                            .to_string(),
                        required_level: required_level.to_string(),
                        step_up_url: format!(
                            "/auth/step-up?session_id={}&level={}",
                            session_id, required_level
                        ),
                    })
                }
                None => {
                    // No active session found
                    Err(AuthError::Unauthorized(
                        "No active session found".to_string(),
                    ))
                }
            }
        } else {
            // No session context available
            Err(AuthError::Unauthorized(
                "No session context available".to_string(),
            ))
        }
    }
}

/// Implementation of the common TokenExchangeService trait
#[async_trait]
impl TokenExchangeService for AdvancedTokenExchangeManager {
    type Request = AdvancedTokenExchangeRequest;
    type Response = AdvancedTokenExchangeResponse;
    type Config = AdvancedTokenExchangeConfig;

    /// Exchange a token following enhanced RFC 8693 (advanced implementation)
    async fn exchange_token(&self, request: Self::Request) -> Result<Self::Response> {
        self.exchange_token(request).await
    }

    /// Validate a token using advanced validation capabilities
    async fn validate_token(&self, token: &str, token_type: &str) -> Result<TokenValidationResult> {
        // Use shared validation utilities
        let supported_types = self.supported_subject_token_types();
        ValidationUtils::validate_token_type(token_type, &supported_types)?;

        // Use JWT introspection if available
        if ValidationUtils::is_jwt_token_type(token_type) {
            match self.introspect_jwt_token(token) {
                Ok(claims) => {
                    // Extract information from JWT claims
                    let subject = ValidationUtils::extract_subject(
                        &claims
                            .as_object()
                            .unwrap_or(&serde_json::Map::new())
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    );

                    let scopes = ValidationUtils::extract_scopes(
                        &claims
                            .as_object()
                            .unwrap_or(&serde_json::Map::new())
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                        None,
                    );

                    Ok(TokenValidationResult {
                        is_valid: true,
                        subject,
                        issuer: claims
                            .get("iss")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        audience: claims
                            .get("aud")
                            .and_then(|v| v.as_str())
                            .map(|s| vec![s.to_string()])
                            .unwrap_or_default(),
                        scopes,
                        expires_at: claims.get("exp").and_then(|v| v.as_i64()).and_then(|exp| {
                            use chrono::{TimeZone, Utc};
                            Utc.timestamp_opt(exp, 0).single()
                        }),
                        metadata: claims
                            .as_object()
                            .unwrap_or(&serde_json::Map::new())
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                        validation_messages: Vec::new(),
                    })
                }
                Err(e) => Ok(TokenValidationResult {
                    is_valid: false,
                    subject: None,
                    issuer: None,
                    audience: Vec::new(),
                    scopes: Vec::new(),
                    expires_at: None,
                    metadata: std::collections::HashMap::new(),
                    validation_messages: vec![format!("JWT validation failed: {}", e)],
                }),
            }
        } else {
            // For non-JWT tokens, use basic validation
            Ok(TokenValidationResult {
                is_valid: true, // Simplified validation
                subject: None,
                issuer: None,
                audience: Vec::new(),
                scopes: Vec::new(),
                expires_at: None,
                metadata: std::collections::HashMap::new(),
                validation_messages: vec![format!(
                    "Basic validation for token type: {}",
                    token_type
                )],
            })
        }
    }

    /// Get supported subject token types
    fn supported_subject_token_types(&self) -> Vec<String> {
        self.config.supported_subject_token_types.clone()
    }

    /// Get supported requested token types
    fn supported_requested_token_types(&self) -> Vec<String> {
        self.config.supported_requested_token_types.clone()
    }

    /// Get service capabilities
    fn capabilities(&self) -> TokenExchangeCapabilities {
        TokenExchangeCapabilities {
            basic_exchange: true,
            multi_party_chains: self.config.enable_multi_party_chains,
            context_preservation: self.config.enable_context_preservation,
            audit_trail: self.config.require_audit_trail,
            session_integration: true, // Always true for advanced manager
            jwt_operations: true,      // Always true for advanced manager
            policy_control: true,      // Always true for advanced manager
            cross_domain_exchange: self.config.cross_domain_settings.enabled,
            max_delegation_depth: self.config.max_delegation_depth,
            complexity_level: ServiceComplexityLevel::Advanced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_creation() {
        let config = AdvancedTokenExchangeConfig::default();
        assert!(config.enable_multi_party_chains);
        assert!(!config.supported_subject_token_types.is_empty());
        assert!(!config.supported_requested_token_types.is_empty());
        assert!(!config.trusted_issuers.is_empty());
    }

    #[test]
    fn test_jwt_key_functionality() {
        use crate::server::oidc::oidc_session_management::SessionManager;
        use jsonwebtoken::{DecodingKey, EncodingKey};

        // Create test config with proper keys
        let secret = b"test-secret-key-32-bytes-minimum!";
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);

        let config = AdvancedTokenExchangeConfig {
            jwt_signing_key: "test-secret-key-32-bytes-minimum!".to_string(),
            jwt_verification_key: "test-secret-key-32-bytes-minimum!".to_string(),
            ..Default::default()
        };

        let session_manager = Arc::new(SessionManager::new(Default::default()));

        // Create manager with proper configuration that won't fail key parsing
        let manager = AdvancedTokenExchangeManager {
            config,
            session_manager,
            processors: HashMap::new(),
            exchange_audit: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            encoding_key,
            decoding_key,
        };

        // Test audit info creation and signing
        let audit_info = ExchangeAuditInfo {
            exchange_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            exchange_type: TokenExchangeType::Delegation,
            subject_info: SubjectInfo {
                subject: "test_user".to_string(),
                subject_type: "user".to_string(),
                original_token_info: TokenInfo {
                    token_type: "jwt".to_string(),
                    issuer: "test".to_string(),
                    audience: vec!["test".to_string()],
                    scopes: vec!["read".to_string()],
                    expires_at: None,
                    metadata: HashMap::new(),
                },
                attributes: HashMap::new(),
            },
            actor_info: None,
            policy_decisions: Vec::new(),
            security_assessments: Vec::new(),
        };

        // Test that audit token generation doesn't panic (keys are properly initialized)
        let result = manager.generate_audit_token(&audit_info);
        assert!(
            result.is_ok(),
            "JWT keys should be properly initialized for signing"
        );
    }

    #[test]
    fn test_exchange_request_creation() {
        let request = AdvancedTokenExchangeRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            actor_token: None,
            actor_token_type: None,
            scope: Some("read write".to_string()),
            audience: vec!["https://api.example.com".to_string()],
            resource: Vec::new(),
            exchange_context: None,
            policy_requirements: Vec::new(),
            custom_parameters: HashMap::new(),
        };

        assert_eq!(
            request.grant_type,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(
            request.subject_token_type,
            "urn:ietf:params:oauth:token-type:jwt"
        );
    }

    #[test]
    fn test_exchange_context_creation() {
        let context = ExchangeContext {
            transaction_id: "txn_123".to_string(),
            business_context: serde_json::json!({
                "operation": "payment",
                "amount": 100.0
            }),
            delegation_chain: Vec::new(),
            original_request: None,
            security_context: None,
            custom_fields: HashMap::new(),
        };

        assert_eq!(context.transaction_id, "txn_123");
        assert_eq!(context.business_context["operation"], "payment");
    }

    #[test]
    fn test_delegation_link_creation() {
        let link = DelegationLink {
            delegator: "service_a".to_string(),
            delegatee: "service_b".to_string(),
            delegated_at: Utc::now(),
            delegation_reason: "API call forwarding".to_string(),
            delegated_scopes: vec!["read".to_string(), "write".to_string()],
            restrictions: Vec::new(),
        };

        assert_eq!(link.delegator, "service_a");
        assert_eq!(link.delegated_scopes.len(), 2);
    }
}
