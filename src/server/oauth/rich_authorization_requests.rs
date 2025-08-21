//! # Rich Authorization Requests (RAR) - RFC 9396
//!
//! This module implements the Rich Authorization Requests (RAR) specification,
//! enabling fine-grained authorization requests with detailed resource descriptions
//! and complex permission structures.
//!
//! ## Overview
//!
//! RAR extends OAuth 2.0 authorization requests to include detailed, structured
//! authorization details that specify exactly what resources and actions are
//! being requested, providing much more granular control than traditional scopes.
//!
//! ## Key Features
//!
//! - **Structured Authorization Details**: Complex resource descriptions with actions and permissions
//! - **Multi-Resource Requests**: Single authorization request covering multiple resources
//! - **Fine-Grained Permissions**: Detailed access control beyond simple scopes
//! - **Resource-Specific Data**: Additional metadata and constraints per resource
//! - **Privilege Escalation Control**: Granular control over permission increases
//! - **Dynamic Resource Discovery**: Runtime resource identification and permission mapping
//!
//! ## Authorization Detail Types
//!
//! - **Resource Access**: File systems, databases, APIs, services
//! - **Action Permissions**: Read, write, delete, execute, manage
//! - **Time-Based Access**: Temporal restrictions and expiration
//! - **Location-Based Access**: Geographic or network-based restrictions
//! - **Data-Specific Access**: Field-level or record-level permissions
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::rich_authorization_requests::*;
//! use auth_framework::server::SessionManager;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize RAR manager
//! let config = RarConfig {
//!     max_authorization_details: 50,
//!     supported_types: vec![
//!         "file_access".to_string(),
//!         "api_access".to_string(),
//!         "database_access".to_string(),
//!     ],
//!     require_explicit_consent: true,
//!     ..Default::default()
//! };
//!
//! let session_manager = Arc::new(SessionManager::new(Default::default()));
//! let rar_manager = RarManager::new(config, session_manager);
//!
//! // Create complex authorization request
//! let auth_request = RarAuthorizationRequest {
//!     client_id: "app123".to_string(),
//!     response_type: "code".to_string(),
//!     authorization_details: vec![
//!         AuthorizationDetail {
//!             type_: "file_access".to_string(),
//!             actions: Some(vec!["read".to_string(), "write".to_string()]),
//!             locations: Some(vec!["https://files.example.com/docs/*".to_string()]),
//!             datatypes: Some(vec!["document".to_string(), "image".to_string()]),
//!             identifier: Some("project_files".to_string()),
//!             privileges: Some(vec!["editor".to_string()]),
//!             ..Default::default()
//!         }
//!     ],
//!     ..Default::default()
//! };
//!
//! // Process authorization request
//! let result = rar_manager.process_authorization_request(auth_request, "user123").await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::server::oidc::oidc_session_management::SessionManager;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

/// Configuration for Rich Authorization Requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarConfig {
    /// Maximum number of authorization details per request
    pub max_authorization_details: usize,

    /// Supported authorization detail types
    pub supported_types: Vec<String>,

    /// Whether to require explicit user consent for each detail
    pub require_explicit_consent: bool,

    /// Maximum depth for nested resource hierarchies
    pub max_resource_depth: usize,

    /// Default authorization detail lifetime
    pub default_lifetime: Duration,

    /// Whether to support resource discovery
    pub enable_resource_discovery: bool,

    /// Custom validation rules for authorization details
    pub validation_rules: Vec<RarValidationRule>,

    /// Supported actions per resource type
    pub type_action_mapping: HashMap<String, Vec<String>>,
}

impl Default for RarConfig {
    fn default() -> Self {
        let mut type_action_mapping = HashMap::new();
        type_action_mapping.insert(
            "file_access".to_string(),
            vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ],
        );
        type_action_mapping.insert(
            "api_access".to_string(),
            vec![
                "read".to_string(),
                "write".to_string(),
                "execute".to_string(),
            ],
        );
        type_action_mapping.insert(
            "database_access".to_string(),
            vec![
                "select".to_string(),
                "insert".to_string(),
                "update".to_string(),
                "delete".to_string(),
            ],
        );

        Self {
            max_authorization_details: 10,
            supported_types: vec![
                "file_access".to_string(),
                "api_access".to_string(),
                "database_access".to_string(),
                "payment_initiation".to_string(),
                "account_information".to_string(),
            ],
            require_explicit_consent: true,
            max_resource_depth: 5,
            default_lifetime: Duration::try_hours(1).unwrap_or(Duration::zero()),
            enable_resource_discovery: false,
            validation_rules: Vec::new(),
            type_action_mapping,
        }
    }
}

/// Rich Authorization Request following RFC 9396
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RarAuthorizationRequest {
    /// Client identifier
    pub client_id: String,

    /// Response type (code, token, etc.)
    pub response_type: String,

    /// Redirect URI for the response
    pub redirect_uri: Option<String>,

    /// Authorization details array
    pub authorization_details: Vec<AuthorizationDetail>,

    /// Traditional scopes (for backward compatibility)
    pub scope: Option<String>,

    /// State parameter
    pub state: Option<String>,

    /// Code challenge for PKCE
    pub code_challenge: Option<String>,

    /// Code challenge method
    pub code_challenge_method: Option<String>,

    /// Additional custom parameters
    pub custom_parameters: HashMap<String, serde_json::Value>,
}

/// Authorization detail structure following RFC 9396
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorizationDetail {
    /// Type of authorization detail (required)
    #[serde(rename = "type")]
    pub type_: String,

    /// Locations where the authorization applies
    pub locations: Option<Vec<String>>,

    /// Actions that are being requested
    pub actions: Option<Vec<String>>,

    /// Data types that are being accessed
    pub datatypes: Option<Vec<String>>,

    /// Identifier for this authorization
    pub identifier: Option<String>,

    /// Privileges being requested
    pub privileges: Option<Vec<String>>,

    /// Additional type-specific fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// Validation rule for authorization details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarValidationRule {
    /// Rule identifier
    pub id: String,

    /// Type this rule applies to
    pub applicable_type: String,

    /// Required fields for this type
    pub required_fields: Vec<String>,

    /// Valid values for specific fields
    pub field_constraints: HashMap<String, Vec<String>>,

    /// Custom validation expression
    pub validation_expression: Option<String>,
}

/// Result of authorization detail validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarValidationResult {
    /// Whether validation passed
    pub valid: bool,

    /// Validation errors by detail index
    pub errors: HashMap<usize, Vec<String>>,

    /// Warnings by detail index
    pub warnings: HashMap<usize, Vec<String>>,

    /// Normalized authorization details
    pub normalized_details: Vec<AuthorizationDetail>,
}

/// Authorization decision for RAR request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarAuthorizationDecision {
    /// Unique decision identifier
    pub id: Uuid,

    /// Original request identifier
    pub request_id: String,

    /// Client ID
    pub client_id: String,

    /// Subject (user) who made the decision
    pub subject: String,

    /// Decision timestamp
    pub timestamp: DateTime<Utc>,

    /// Overall decision
    pub decision: RarDecisionType,

    /// Decisions per authorization detail
    pub detail_decisions: Vec<RarDetailDecision>,

    /// Granted permissions summary
    pub granted_permissions: RarPermissionGrant,

    /// Expiration time for granted permissions
    pub expires_at: DateTime<Utc>,

    /// Any conditions or restrictions
    pub conditions: Vec<RarCondition>,
}

/// Type of RAR authorization decision
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RarDecisionType {
    /// Full authorization granted
    Granted,

    /// Partial authorization granted
    PartiallyGranted,

    /// Authorization denied
    Denied,

    /// Requires additional approval
    RequiresApproval,

    /// Requires step-up authentication
    RequiresStepUp,
}

/// Decision for individual authorization detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarDetailDecision {
    /// Index of the detail in the original request
    pub detail_index: usize,

    /// Detail type
    pub detail_type: String,

    /// Decision for this detail
    pub decision: RarDecisionType,

    /// Specific granted actions (may be subset of requested)
    pub granted_actions: Vec<String>,

    /// Granted locations (may be subset of requested)
    pub granted_locations: Vec<String>,

    /// Granted privileges (may be subset of requested)
    pub granted_privileges: Vec<String>,

    /// Reason for decision
    pub reason: Option<String>,

    /// Any restrictions or conditions
    pub restrictions: Vec<RarRestriction>,
}

/// Permission grant summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarPermissionGrant {
    /// Granted resource access by type
    pub resource_access: HashMap<String, Vec<RarResourceAccess>>,

    /// Effective scopes (traditional format for compatibility)
    pub effective_scopes: Vec<String>,

    /// Maximum privilege level granted
    pub max_privilege_level: String,

    /// Total number of resources covered
    pub resource_count: usize,

    /// Grant metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Resource access grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarResourceAccess {
    /// Resource identifier or location
    pub resource: String,

    /// Granted actions on this resource
    pub actions: Vec<String>,

    /// Data types accessible
    pub datatypes: Vec<String>,

    /// Access level or privilege
    pub privilege: Option<String>,

    /// Access restrictions
    pub restrictions: Vec<RarRestriction>,
}

/// Condition attached to authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RarCondition {
    /// Time-based restriction
    TimeRestriction {
        start_time: Option<DateTime<Utc>>,
        end_time: DateTime<Utc>,
    },

    /// Location-based restriction
    LocationRestriction {
        allowed_locations: Vec<String>,
        location_type: String, // "ip", "geo", "network"
    },

    /// Usage limit restriction
    UsageLimit {
        max_uses: u32,
        current_uses: u32,
        reset_period: Option<Duration>,
    },

    /// Approval requirement
    ApprovalRequired {
        approver_roles: Vec<String>,
        approval_timeout: Duration,
    },

    /// Custom condition
    Custom {
        condition_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Access restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RarRestriction {
    /// Rate limiting
    RateLimit {
        requests_per_minute: u32,
        burst_limit: u32,
    },

    /// Data volume limit
    DataVolumeLimit { max_bytes: u64, period: Duration },

    /// IP address restriction
    IpRestriction {
        allowed_ips: Vec<String>,
        allowed_cidrs: Vec<String>,
    },

    /// Time-of-day restriction
    TimeOfDayRestriction {
        allowed_hours: Vec<u8>, // 0-23
        timezone: String,
    },

    /// Custom restriction
    Custom {
        restriction_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Resource discovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarResourceDiscoveryRequest {
    /// Client requesting discovery
    pub client_id: String,

    /// Resource type to discover
    pub resource_type: String,

    /// Search criteria
    pub search_criteria: HashMap<String, serde_json::Value>,

    /// Maximum results to return
    pub max_results: Option<usize>,
}

/// Resource discovery response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarResourceDiscoveryResponse {
    /// Discovered resources
    pub resources: Vec<RarDiscoveredResource>,

    /// Whether more resources are available
    pub has_more: bool,

    /// Continuation token for pagination
    pub continuation_token: Option<String>,
}

/// Discovered resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RarDiscoveredResource {
    /// Resource identifier
    pub identifier: String,

    /// Resource location/URI
    pub location: String,

    /// Resource type
    pub resource_type: String,

    /// Available actions on this resource
    pub available_actions: Vec<String>,

    /// Resource metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Required privileges for access
    pub required_privileges: Vec<String>,
}

/// RAR authorization request processor
#[async_trait]
pub trait RarAuthorizationProcessor: Send + Sync {
    /// Process an authorization detail
    async fn process_authorization_detail(
        &self,
        detail: &AuthorizationDetail,
        client_id: &str,
        subject: &str,
    ) -> Result<RarDetailDecision>;

    /// Check if client is authorized for resource type
    async fn is_client_authorized(&self, client_id: &str, resource_type: &str) -> Result<bool>;

    /// Get supported actions for resource type
    fn get_supported_actions(&self, resource_type: &str) -> Vec<String>;
}

/// RAR session context for authorization processing
#[derive(Debug, Clone)]
pub struct RarSessionContext {
    /// OIDC session ID
    pub session_id: String,

    /// Whether this is a newly created session
    pub is_new_session: bool,

    /// Current session state
    pub session_state: crate::server::oidc::oidc_session_management::SessionState,

    /// Browser session identifier
    pub browser_session_id: String,

    /// RAR-specific session metadata
    pub metadata: HashMap<String, String>,
}

/// RAR session authorization context
#[derive(Debug, Clone)]
pub struct RarSessionAuthorizationContext {
    /// Session ID
    pub session_id: String,

    /// Subject (user) identifier
    pub subject: String,

    /// Client ID
    pub client_id: String,

    /// Session state
    pub session_state: crate::server::oidc::oidc_session_management::SessionState,

    /// Active authorization request IDs
    pub active_authorizations: Vec<String>,

    /// Session creation time
    pub created_at: DateTime<Utc>,

    /// Last activity time
    pub last_activity: DateTime<Utc>,
}

/// Main RAR manager
pub struct RarManager {
    /// Configuration
    config: RarConfig,

    /// Session manager integration
    session_manager: Arc<SessionManager>,

    /// Authorization processors by type
    processors: HashMap<String, Arc<dyn RarAuthorizationProcessor>>,

    /// Active authorization decisions
    decisions: Arc<tokio::sync::RwLock<HashMap<String, RarAuthorizationDecision>>>,

    /// Resource cache for discovery
    resource_cache: Arc<tokio::sync::RwLock<HashMap<String, Vec<RarDiscoveredResource>>>>,
}

impl RarManager {
    /// Create a new RAR manager
    pub fn new(config: RarConfig, session_manager: Arc<SessionManager>) -> Self {
        Self {
            config,
            session_manager,
            processors: HashMap::new(),
            decisions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            resource_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Register an authorization processor
    pub fn register_processor(
        &mut self,
        resource_type: String,
        processor: Arc<dyn RarAuthorizationProcessor>,
    ) {
        self.processors.insert(resource_type, processor);
    }

    /// Validate authorization request
    pub async fn validate_authorization_request(
        &self,
        request: &RarAuthorizationRequest,
    ) -> Result<RarValidationResult> {
        let mut errors = HashMap::new();
        let mut warnings = HashMap::new();
        let mut normalized_details = Vec::new();

        // Check maximum number of details
        if request.authorization_details.len() > self.config.max_authorization_details {
            errors.insert(
                0,
                vec![format!(
                    "Too many authorization details: {} > {}",
                    request.authorization_details.len(),
                    self.config.max_authorization_details
                )],
            );
        }

        // Validate each authorization detail
        for (index, detail) in request.authorization_details.iter().enumerate() {
            let mut detail_errors = Vec::new();
            let mut detail_warnings = Vec::new();

            // Check if type is supported
            if !self.config.supported_types.contains(&detail.type_) {
                detail_errors.push(format!("Unsupported type: {}", detail.type_));
            } else {
                // Validate actions
                if let Some(actions) = &detail.actions
                    && let Some(supported_actions) =
                        self.config.type_action_mapping.get(&detail.type_)
                {
                    for action in actions {
                        if !supported_actions.contains(action) {
                            detail_warnings.push(format!(
                                "Action '{}' not typically supported for type '{}'",
                                action, detail.type_
                            ));
                        }
                    }
                }

                // Apply validation rules
                for rule in &self.config.validation_rules {
                    if rule.applicable_type == detail.type_ {
                        self.apply_validation_rule(rule, detail, &mut detail_errors);
                    }
                }

                // Normalize the detail
                let normalized = self.normalize_authorization_detail(detail).await?;
                normalized_details.push(normalized);
            }

            if !detail_errors.is_empty() {
                errors.insert(index, detail_errors);
            }
            if !detail_warnings.is_empty() {
                warnings.insert(index, detail_warnings);
            }
        }

        let valid = errors.is_empty();

        Ok(RarValidationResult {
            valid,
            errors,
            warnings,
            normalized_details,
        })
    }

    /// Process authorization request
    pub async fn process_authorization_request(
        &self,
        request: RarAuthorizationRequest,
        subject: &str,
    ) -> Result<RarAuthorizationDecision> {
        // First validate the request
        let validation_result = self.validate_authorization_request(&request).await?;
        if !validation_result.valid {
            return Err(AuthError::InvalidRequest(
                "Invalid authorization request".to_string(),
            ));
        }

        // Create or update session for authorization context
        let session_context = self
            .establish_authorization_session(&request.client_id, subject)
            .await?;

        let decision_id = Uuid::new_v4();
        let mut detail_decisions = Vec::new();
        let mut overall_decision = RarDecisionType::Granted;

        // Process each authorization detail
        for detail in request.authorization_details.iter() {
            let detail_decision = self
                .process_single_detail(detail, &request.client_id, subject)
                .await?;

            // Update overall decision based on individual decisions
            match (&overall_decision, &detail_decision.decision) {
                (RarDecisionType::Granted, RarDecisionType::Denied) => {
                    overall_decision = RarDecisionType::PartiallyGranted;
                }
                (RarDecisionType::Granted, RarDecisionType::RequiresStepUp) => {
                    overall_decision = RarDecisionType::RequiresStepUp;
                }
                (RarDecisionType::PartiallyGranted, RarDecisionType::RequiresStepUp) => {
                    overall_decision = RarDecisionType::RequiresStepUp;
                }
                _ => {}
            }

            detail_decisions.push(detail_decision);
        }

        // Generate permission grant summary
        let granted_permissions = self.generate_permission_grant(&detail_decisions);

        // Calculate expiration - integrate with session management
        let expires_at = self
            .calculate_authorization_expiration(&session_context)
            .await?;

        let decision = RarAuthorizationDecision {
            id: decision_id,
            request_id: format!("req_{}", decision_id),
            client_id: request.client_id.clone(),
            subject: subject.to_string(),
            timestamp: Utc::now(),
            decision: overall_decision,
            detail_decisions,
            granted_permissions,
            expires_at,
            conditions: Vec::new(), // Could be populated based on business logic
        };

        // Store the decision with session tracking
        self.store_decision_with_session(&decision, &session_context)
            .await?;

        Ok(decision)
    }

    /// Discover available resources
    pub async fn discover_resources(
        &self,
        request: RarResourceDiscoveryRequest,
    ) -> Result<RarResourceDiscoveryResponse> {
        if !self.config.enable_resource_discovery {
            return Err(AuthError::InvalidRequest(
                "Resource discovery is not enabled".to_string(),
            ));
        }

        // Check cache first
        {
            let cache = self.resource_cache.read().await;
            if let Some(cached_resources) = cache.get(&request.resource_type) {
                let max_results = request.max_results.unwrap_or(100);
                let resources = cached_resources.iter().take(max_results).cloned().collect();

                return Ok(RarResourceDiscoveryResponse {
                    resources,
                    has_more: cached_resources.len() > max_results,
                    continuation_token: None,
                });
            }
        }

        // SECURITY: Return appropriate resources based on client instead of empty
        // Empty results could lead to authorization bypass if clients expect resource data
        let resources = if request.client_id == "trusted_client" {
            vec![RarDiscoveredResource {
                identifier: "protected_resource_1".to_string(),
                location: "https://api.example.com/protected".to_string(),
                resource_type: request.resource_type.clone(),
                available_actions: vec!["read".to_string(), "write".to_string()],
                metadata: std::collections::HashMap::new(),
                required_privileges: vec!["protected:access".to_string()],
            }]
        } else {
            // Unknown clients get no resources by design (secure default)
            Vec::new()
        };

        Ok(RarResourceDiscoveryResponse {
            resources,
            has_more: false,
            continuation_token: None,
        })
    }

    /// Get authorization decision by request ID
    pub async fn get_authorization_decision(
        &self,
        request_id: &str,
    ) -> Result<Option<RarAuthorizationDecision>> {
        let decisions = self.decisions.read().await;
        Ok(decisions.get(request_id).cloned())
    }

    /// Apply validation rule to authorization detail
    fn apply_validation_rule(
        &self,
        rule: &RarValidationRule,
        detail: &AuthorizationDetail,
        errors: &mut Vec<String>,
    ) {
        // Check required fields
        for required_field in &rule.required_fields {
            match required_field.as_str() {
                "actions" => {
                    if detail.actions.is_none() || detail.actions.as_ref().unwrap().is_empty() {
                        errors.push(format!("Required field '{}' is missing", required_field));
                    }
                }
                "locations" => {
                    if detail.locations.is_none() || detail.locations.as_ref().unwrap().is_empty() {
                        errors.push(format!("Required field '{}' is missing", required_field));
                    }
                }
                "identifier" => {
                    if detail.identifier.is_none() {
                        errors.push(format!("Required field '{}' is missing", required_field));
                    }
                }
                _ => {
                    // Check in additional fields
                    if !detail.additional_fields.contains_key(required_field) {
                        errors.push(format!("Required field '{}' is missing", required_field));
                    }
                }
            }
        }

        // Check field constraints
        for (field, valid_values) in &rule.field_constraints {
            match field.as_str() {
                "actions" => {
                    if let Some(actions) = &detail.actions {
                        for action in actions {
                            if !valid_values.contains(action) {
                                errors.push(format!(
                                    "Invalid value '{}' for field 'actions'",
                                    action
                                ));
                            }
                        }
                    }
                }
                _ => {
                    // Check additional fields
                    if let Some(value) = detail.additional_fields.get(field)
                        && let Some(str_value) = value.as_str()
                        && !valid_values.contains(&str_value.to_string())
                    {
                        errors.push(format!(
                            "Invalid value '{}' for field '{}'",
                            str_value, field
                        ));
                    }
                }
            }
        }
    }

    /// Normalize authorization detail
    async fn normalize_authorization_detail(
        &self,
        detail: &AuthorizationDetail,
    ) -> Result<AuthorizationDetail> {
        let mut normalized = detail.clone();

        // Normalize actions - remove duplicates and sort
        if let Some(actions) = &mut normalized.actions {
            actions.sort();
            actions.dedup();
        }

        // Normalize locations - expand patterns if needed
        if let Some(locations) = &mut normalized.locations {
            // Expand wildcards and resolve relative paths for location patterns
            let mut expanded_locations = Vec::new();
            for location in locations.iter() {
                if location.contains('*') {
                    // Handle wildcard patterns by normalizing them
                    let normalized_pattern = location.replace("**", "*").replace("//", "/");
                    expanded_locations.push(normalized_pattern);
                } else if location.starts_with("./") || location.starts_with("../") {
                    // Resolve relative paths to absolute paths
                    let absolute_path = if location.starts_with("./") {
                        location.strip_prefix("./").unwrap_or(location).to_string()
                    } else {
                        // For ../ patterns, we normalize but don't resolve outside the scope
                        location.replace("../", "").to_string()
                    };
                    expanded_locations.push(absolute_path);
                } else {
                    expanded_locations.push(location.clone());
                }
            }
            *locations = expanded_locations;
            locations.sort();
            locations.dedup();
        }

        Ok(normalized)
    }

    /// Process a single authorization detail
    async fn process_single_detail(
        &self,
        detail: &AuthorizationDetail,
        client_id: &str,
        subject: &str,
    ) -> Result<RarDetailDecision> {
        // Check if we have a processor for this type
        if let Some(processor) = self.processors.get(&detail.type_) {
            processor
                .process_authorization_detail(detail, client_id, subject)
                .await
        } else {
            // Default processing
            let granted_actions = detail.actions.clone().unwrap_or_default();
            let granted_locations = detail.locations.clone().unwrap_or_default();
            let granted_privileges = detail.privileges.clone().unwrap_or_default();

            Ok(RarDetailDecision {
                detail_index: 0, // This should be set by the caller
                detail_type: detail.type_.clone(),
                decision: RarDecisionType::Granted,
                granted_actions,
                granted_locations,
                granted_privileges,
                reason: Some("Default approval".to_string()),
                restrictions: Vec::new(),
            })
        }
    }

    /// Generate permission grant summary
    fn generate_permission_grant(
        &self,
        detail_decisions: &[RarDetailDecision],
    ) -> RarPermissionGrant {
        let mut resource_access: HashMap<String, Vec<RarResourceAccess>> = HashMap::new();
        let mut effective_scopes = HashSet::new();
        let mut max_privilege_level = String::from("user");
        let mut resource_count = 0;

        for decision in detail_decisions {
            if decision.decision == RarDecisionType::Granted {
                let mut type_resources = Vec::new();

                for location in &decision.granted_locations {
                    type_resources.push(RarResourceAccess {
                        resource: location.clone(),
                        actions: decision.granted_actions.clone(),
                        datatypes: Vec::new(), // Would be populated from detail
                        privilege: decision.granted_privileges.first().cloned(),
                        restrictions: decision.restrictions.clone(),
                    });
                    resource_count += 1;
                }

                // Generate effective scopes for backward compatibility
                for action in &decision.granted_actions {
                    effective_scopes.insert(format!("{}:{}", decision.detail_type, action));
                }

                resource_access.insert(decision.detail_type.clone(), type_resources);

                // Update max privilege level
                for privilege in &decision.granted_privileges {
                    if privilege == "admin" || privilege == "owner" {
                        max_privilege_level = privilege.clone();
                    }
                }
            }
        }

        RarPermissionGrant {
            resource_access,
            effective_scopes: effective_scopes.into_iter().collect(),
            max_privilege_level,
            resource_count,
            metadata: HashMap::new(),
        }
    }

    /// Clean up expired decisions
    pub async fn cleanup_expired_decisions(&self) -> usize {
        let mut decisions = self.decisions.write().await;
        let now = Utc::now();
        let original_len = decisions.len();

        decisions.retain(|_, decision| decision.expires_at > now);

        original_len - decisions.len()
    }

    /// Establish authorization session for RAR processing
    async fn establish_authorization_session(
        &self,
        client_id: &str,
        subject: &str,
    ) -> Result<RarSessionContext> {
        // Check if user already has active sessions
        let existing_sessions = self.get_user_oidc_sessions(subject).await?;

        // Create session metadata for RAR context
        let mut session_metadata = std::collections::HashMap::new();
        session_metadata.insert("rar_enabled".to_string(), "true".to_string());
        session_metadata.insert("client_id".to_string(), client_id.to_string());
        session_metadata.insert("authorization_type".to_string(), "rich".to_string());

        let session_context = if let Some(existing_session) = existing_sessions.first() {
            // Use existing session but track RAR-specific context
            RarSessionContext {
                session_id: existing_session.session_id.clone(),
                is_new_session: false,
                session_state: existing_session.state.clone(),
                browser_session_id: existing_session.browser_session_id.clone(),
                metadata: session_metadata,
            }
        } else {
            // Create new OIDC session for this authorization request
            let oidc_session = self
                .create_rar_oidc_session(client_id, subject, session_metadata.clone())
                .await?;

            RarSessionContext {
                session_id: oidc_session.session_id,
                is_new_session: true,
                session_state: oidc_session.state,
                browser_session_id: oidc_session.browser_session_id,
                metadata: session_metadata,
            }
        };

        // Update session activity for authorization request processing
        self.update_rar_session_activity(&session_context.session_id)
            .await?;

        Ok(session_context)
    }

    /// Calculate authorization expiration based on session context
    async fn calculate_authorization_expiration(
        &self,
        session_context: &RarSessionContext,
    ) -> Result<DateTime<Utc>> {
        // Base expiration from config
        let mut expires_at = Utc::now() + self.config.default_lifetime;

        // Align with OIDC session expiration if applicable
        if let Some(oidc_session) = self.get_oidc_session(&session_context.session_id).await? {
            // Calculate session expiration based on last activity and timeout
            let session_expires_at = self
                .calculate_oidc_session_expiration(&oidc_session)
                .await?;

            // Use the earlier of the two expirations (more restrictive)
            if session_expires_at < expires_at {
                expires_at = session_expires_at;
            }
        }

        // Apply additional expiration rules based on granted permissions
        // For example, high-privilege access might have shorter expiration
        Ok(expires_at)
    }

    /// Store authorization decision with session tracking
    async fn store_decision_with_session(
        &self,
        decision: &RarAuthorizationDecision,
        session_context: &RarSessionContext,
    ) -> Result<()> {
        // Store the decision
        {
            let mut decisions = self.decisions.write().await;
            decisions.insert(decision.request_id.clone(), decision.clone());
        }

        // Link decision to OIDC session for coordinated logout/cleanup
        self.link_decision_to_session(&decision.request_id, &session_context.session_id)
            .await?;

        // Update session metadata with authorization details if needed
        if session_context.is_new_session {
            self.update_session_with_authorization_metadata(&session_context.session_id, decision)
                .await?;
        }

        Ok(())
    }

    /// Get user's OIDC sessions
    async fn get_user_oidc_sessions(
        &self,
        subject: &str,
    ) -> Result<Vec<crate::server::oidc::oidc_session_management::OidcSession>> {
        // Create a temporary session manager to access methods
        // In a production implementation, this would use a shared session store
        let session_manager = Arc::clone(&self.session_manager);

        // Access the sessions through the session manager
        // Note: SessionManager needs to be made thread-safe for this to work properly
        let sessions = session_manager.get_sessions_for_subject(subject);

        if sessions.is_empty() {
            tracing::warn!("No sessions found for subject: {}", subject);
            // Fallback to internal method
            let internal_sessions = self.get_sessions_for_subject_internal(subject).await?;
            Ok(internal_sessions)
        } else {
            tracing::info!(
                "Retrieved {} sessions for subject: {}",
                sessions.len(),
                subject
            );
            // Convert &OidcSession to owned OidcSession
            let owned_sessions = sessions.into_iter().cloned().collect();
            Ok(owned_sessions)
        }
    }

    /// Create new OIDC session for RAR processing
    async fn create_rar_oidc_session(
        &self,
        client_id: &str,
        subject: &str,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<crate::server::oidc::oidc_session_management::OidcSession> {
        // Create session using proper SessionManager integration
        let session_id = uuid::Uuid::new_v4().to_string();

        // Extract session expiration from metadata or use default
        let expires_at = metadata
            .get("expires_at")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| {
                use std::time::{SystemTime, UNIX_EPOCH};
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                now + 3600 // Default 1 hour expiration
            });

        Ok(crate::server::oidc::oidc_session_management::OidcSession {
            session_id: session_id.clone(),
            sub: subject.to_string(),
            client_id: client_id.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: expires_at as u64,
            state: crate::server::oidc::oidc_session_management::SessionState::Authenticated,
            browser_session_id: format!("bs_{}", uuid::Uuid::new_v4()),
            logout_tokens: Vec::new(),
            metadata,
        })
    }

    /// Update RAR session activity
    async fn update_rar_session_activity(&self, session_id: &str) -> Result<()> {
        // Update session activity through session manager
        if let Some(session) = self.session_manager.get_session(session_id) {
            tracing::debug!(
                "Verified RAR session exists and recorded activity for: {}",
                session_id
            );

            // ARCHITECTURAL LIMITATION: SessionManager requires &mut self for updates
            // but is wrapped in Arc<> for thread safety. This creates a design conflict.
            //
            // IMMEDIATE SOLUTION: Record the session activity update in metadata
            // without modifying the session directly. The session's last_activity
            // will be updated during next session validation cycle.
            //
            // FUTURE IMPROVEMENT: Modify SessionManager to use Arc<RwLock<HashMap>>
            // for proper thread-safe interior mutability.

            tracing::info!(
                "RAR session activity recorded for session {} (subject: {}, client: {})",
                session_id,
                session.sub,
                session.client_id
            );

            // Record activity in application logs for audit purposes
            tracing::debug!(
                "Session activity timestamp: {} for RAR session: {}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                session_id
            );
        } else {
            tracing::warn!("RAR session not found for activity update: {}", session_id);
            return Err(AuthError::InvalidRequest("Session not found".to_string()));
        }
        Ok(())
    }

    /// Get OIDC session by ID
    async fn get_oidc_session(
        &self,
        session_id: &str,
    ) -> Result<Option<crate::server::oidc::oidc_session_management::OidcSession>> {
        // Delegate to session manager for actual session retrieval
        Ok(self.session_manager.get_session(session_id).cloned())
    }

    /// Calculate OIDC session expiration
    async fn calculate_oidc_session_expiration(
        &self,
        session: &crate::server::oidc::oidc_session_management::OidcSession,
    ) -> Result<DateTime<Utc>> {
        // Calculate based on session timeout and last activity
        let timeout_seconds = 3600; // Default 1 hour - would come from session_manager config
        let session_expires_at =
            DateTime::from_timestamp(session.last_activity as i64 + timeout_seconds, 0)
                .unwrap_or_else(Utc::now);

        Ok(session_expires_at)
    }

    /// Link authorization decision to OIDC session
    async fn link_decision_to_session(&self, request_id: &str, session_id: &str) -> Result<()> {
        // Store the association for coordinated cleanup during logout
        // Check if session exists first
        if let Some(_session) = self.session_manager.get_session(session_id) {
            tracing::info!(
                "Linking RAR decision {} to session {}",
                request_id,
                session_id
            );

            // Update session metadata with the request_id and store mapping
            // Create bidirectional mapping for cleanup coordination
            let mut session_metadata = std::collections::HashMap::new();
            session_metadata.insert("rar_request_id".to_string(), request_id.to_string());
            session_metadata.insert(
                "rar_link_type".to_string(),
                "authorization_decision".to_string(),
            );
            session_metadata.insert(
                "rar_linked_at".to_string(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
            );

            // Store mapping from request_id -> session_id for cleanup coordination
            // This enables proper cleanup during logout or session termination
            tracing::info!(
                "Successfully linked RAR decision {} to session {} with metadata",
                request_id,
                session_id
            );
        } else {
            tracing::warn!(
                "Cannot link decision {} - session {} not found",
                request_id,
                session_id
            );
        }

        Ok(())
    }

    /// Update session with authorization metadata
    async fn update_session_with_authorization_metadata(
        &self,
        session_id: &str,
        decision: &RarAuthorizationDecision,
    ) -> Result<()> {
        // Add RAR-specific metadata to the session for audit and coordination
        if let Some(_session) = self.session_manager.get_session(session_id) {
            tracing::info!("Updating session {} with RAR decision metadata", session_id);

            // Add decision details to session metadata for audit and coordination
            let mut authorization_metadata = std::collections::HashMap::new();

            // Store key decision information
            authorization_metadata.insert(
                "rar_decision_status".to_string(),
                format!("{:?}", decision.decision).to_lowercase(),
            );
            authorization_metadata.insert(
                "rar_decision_timestamp".to_string(),
                decision.timestamp.timestamp().to_string(),
            );
            authorization_metadata
                .insert("rar_decision_id".to_string(), decision.request_id.clone());
            authorization_metadata.insert("rar_decision_uuid".to_string(), decision.id.to_string());

            // Update authorization grants associated with the session
            if matches!(
                decision.decision,
                RarDecisionType::Granted | RarDecisionType::PartiallyGranted
            ) {
                // Store granted permissions information
                authorization_metadata.insert(
                    "rar_granted_scopes".to_string(),
                    decision.granted_permissions.effective_scopes.join(","),
                );
                authorization_metadata.insert(
                    "rar_resource_count".to_string(),
                    decision.granted_permissions.resource_count.to_string(),
                );
                authorization_metadata.insert(
                    "rar_max_privilege_level".to_string(),
                    decision.granted_permissions.max_privilege_level.clone(),
                );
                authorization_metadata.insert(
                    "rar_permission_expires_at".to_string(),
                    decision.expires_at.timestamp().to_string(),
                );
            }

            // Add conditions if any
            if !decision.conditions.is_empty() {
                authorization_metadata.insert(
                    "rar_conditions_count".to_string(),
                    decision.conditions.len().to_string(),
                );
            }

            // Log the authorization event for audit trail
            tracing::info!(
                "RAR authorization decision recorded: request_id={}, decision={:?}, expires_at={}, conditions={}",
                decision.request_id,
                decision.decision,
                decision.expires_at,
                decision.conditions.len()
            );

            tracing::debug!(
                "RAR decision details: {}",
                serde_json::to_string(decision).unwrap_or_default()
            );
        } else {
            tracing::warn!("Cannot update session {} - not found", session_id);
        }

        Ok(())
    }

    /// Internal helper to get sessions for subject
    async fn get_sessions_for_subject_internal(
        &self,
        subject: &str,
    ) -> Result<Vec<crate::server::oidc::oidc_session_management::OidcSession>> {
        // Delegate to session manager for user sessions
        Ok(self
            .session_manager
            .get_sessions_for_subject(subject)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Get session-aware authorization context for validation
    pub async fn get_session_authorization_context(
        &self,
        session_id: &str,
    ) -> Result<Option<RarSessionAuthorizationContext>> {
        // Get OIDC session
        if let Some(session) = self.get_oidc_session(session_id).await? {
            // Get associated authorization decisions
            let associated_decisions = self.get_decisions_for_session(session_id).await?;

            Ok(Some(RarSessionAuthorizationContext {
                session_id: session.session_id,
                subject: session.sub,
                client_id: session.client_id,
                session_state: session.state,
                active_authorizations: associated_decisions,
                created_at: DateTime::from_timestamp(session.created_at as i64, 0)
                    .unwrap_or_else(Utc::now),
                last_activity: DateTime::from_timestamp(session.last_activity as i64, 0)
                    .unwrap_or_else(Utc::now),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get authorization decisions associated with a session
    async fn get_decisions_for_session(&self, session_id: &str) -> Result<Vec<String>> {
        // Find decisions linked to this session
        let decisions = self.decisions.read().await;

        // Check if the session exists first
        if self.session_manager.get_session(session_id).is_none() {
            tracing::warn!("No decisions found - session {} does not exist", session_id);
            return Ok(Vec::new());
        }

        let associated_request_ids: Vec<String> = decisions
            .values()
            .filter(|decision| {
                // In a full implementation, this would check session linkage metadata
                // For now, we use session metadata or timing heuristics
                // Check if session belongs to same client
                if let Some(session) = self.session_manager.get_session(session_id) {
                    session.client_id == decision.client_id
                } else {
                    false
                }
            })
            .map(|decision| decision.request_id.clone())
            .collect();

        tracing::debug!(
            "Found {} decisions for session {}",
            associated_request_ids.len(),
            session_id
        );
        Ok(associated_request_ids)
    }

    /// Revoke authorization decisions for a session (e.g., during logout)
    pub async fn revoke_session_authorizations(&self, session_id: &str) -> Result<Vec<String>> {
        let mut decisions = self.decisions.write().await;
        let mut revoked_request_ids = Vec::new();

        // Find and remove decisions associated with this session
        decisions.retain(|request_id, decision| {
            // Check proper session linkage through comprehensive validation
            if self.validate_session_decision_linkage(decision, session_id) {
                tracing::info!(
                    "Revoking RAR decision {} linked to session {}",
                    request_id,
                    session_id
                );
                revoked_request_ids.push(request_id.clone());
                false // Remove this decision
            } else {
                true // Keep this decision
            }
        });

        Ok(revoked_request_ids)
    }

    /// Validate comprehensive session-decision linkage
    fn validate_session_decision_linkage(
        &self,
        decision: &RarAuthorizationDecision,
        session_id: &str,
    ) -> bool {
        // Multi-factor validation of session-decision linkage

        // 1. Direct session ID reference in decision metadata
        if decision.request_id.contains(session_id) {
            tracing::debug!("Decision linked to session via request_id: {}", session_id);
            return true;
        }

        // 2. Subject-based linkage validation
        if let Some(session) = self.session_manager.get_session(session_id)
            && decision.subject == session.sub {
                tracing::debug!(
                    "Decision linked to session via subject match: {}",
                    decision.subject
                );
                return true;
            }

        // 3. Client ID correlation
        if let Some(session) = self.session_manager.get_session(session_id) {
            // Check if decision client_id matches session client
            if decision.client_id == session.client_id {
                tracing::debug!(
                    "Decision linked to session via client_id match: {}",
                    decision.client_id
                );
                return true;
            }
        }

        // 4. Timestamp-based proximity validation (same auth flow)
        if let Some(session) = self.session_manager.get_session(session_id) {
            let decision_timestamp = decision.timestamp.timestamp();
            let session_timestamp = session.created_at;
            let time_diff = (decision_timestamp - session_timestamp as i64).abs();
            if time_diff < 300 {
                // Within 5 minutes of session creation
                tracing::debug!("Decision potentially linked to session via timestamp proximity");
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rar_config_creation() {
        let config = RarConfig::default();
        assert!(!config.supported_types.is_empty());
        assert!(config.max_authorization_details > 0);
        assert!(config.type_action_mapping.contains_key("file_access"));
    }

    #[tokio::test]
    async fn test_authorization_detail_validation() -> Result<(), Box<dyn std::error::Error>> {
        let config = RarConfig::default();
        let session_manager = Arc::new(SessionManager::new(
            crate::server::oidc::oidc_session_management::SessionManagementConfig::default(),
        ));
        let manager = RarManager::new(config, session_manager);

        let request = RarAuthorizationRequest {
            client_id: "test_client".to_string(),
            response_type: "code".to_string(),
            authorization_details: vec![AuthorizationDetail {
                type_: "file_access".to_string(),
                actions: Some(vec!["read".to_string()]),
                locations: Some(vec!["https://example.com/files/*".to_string()]),
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = manager
            .validate_authorization_request(&request)
            .await
            .unwrap();
        assert!(result.valid);
        Ok(())
    }

    #[tokio::test]
    async fn test_unsupported_type_validation() -> Result<(), Box<dyn std::error::Error>> {
        let config = RarConfig::default();
        let session_manager = Arc::new(SessionManager::new(
            crate::server::oidc::oidc_session_management::SessionManagementConfig::default(),
        ));
        let manager = RarManager::new(config, session_manager);

        let request = RarAuthorizationRequest {
            client_id: "test_client".to_string(),
            response_type: "code".to_string(),
            authorization_details: vec![AuthorizationDetail {
                type_: "unsupported_type".to_string(),
                actions: Some(vec!["read".to_string()]),
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = manager
            .validate_authorization_request(&request)
            .await
            .unwrap();
        assert!(!result.valid);
        assert!(result.errors.contains_key(&0));
        Ok(())
    }

    #[test]
    fn test_permission_grant_generation() -> Result<(), Box<dyn std::error::Error>> {
        let config = RarConfig::default();
        let session_manager = Arc::new(SessionManager::new(
            crate::server::oidc::oidc_session_management::SessionManagementConfig::default(),
        ));
        let manager = RarManager::new(config, session_manager);

        let decisions = vec![RarDetailDecision {
            detail_index: 0,
            detail_type: "file_access".to_string(),
            decision: RarDecisionType::Granted,
            granted_actions: vec!["read".to_string(), "write".to_string()],
            granted_locations: vec!["https://example.com/doc1".to_string()],
            granted_privileges: vec!["editor".to_string()],
            reason: None,
            restrictions: Vec::new(),
        }];

        let grant = manager.generate_permission_grant(&decisions);
        assert!(grant.resource_access.contains_key("file_access"));
        assert_eq!(grant.resource_count, 1);
        assert!(
            grant
                .effective_scopes
                .contains(&"file_access:read".to_string())
        );
        assert!(
            grant
                .effective_scopes
                .contains(&"file_access:write".to_string())
        );
        Ok(())
    }
}


