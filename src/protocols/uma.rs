//! UMA 2.0 (User-Managed Access) implementation.
//!
//! Provides federated authorization where Resource Owners (RO) delegate access
//! to their protected resources using OAuth 2.0 workflows.

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── UMA 2.0 Discovery Metadata ─────────────────────────────────────

/// UMA 2.0 Authorization Server discovery metadata (`.well-known/uma2-configuration`).
///
/// Defined by UMA 2.0 Grant for OAuth 2.0 Authorization, Section 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmaDiscoveryMetadata {
    /// The base URI of the UMA authorization server.
    pub issuer: String,
    /// Protection API Token (PAT) endpoint (OAuth 2.0 token endpoint).
    pub token_endpoint: String,
    /// Resource registration endpoint.
    pub resource_registration_endpoint: String,
    /// Permission endpoint (where resource servers register permission requests).
    pub permission_endpoint: String,
    /// RPT (Requesting Party Token) endpoint (same as token_endpoint).
    pub rpt_endpoint: String,
    /// Introspection endpoint for RPTs (RFC 7662).
    pub introspection_endpoint: String,
    /// Claims interaction endpoint for interactive claims gathering.
    pub claims_interaction_endpoint: String,
    /// Supported UMA grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported token endpoint authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported UMA profiles.
    pub uma_profiles_supported: Vec<String>,
}

impl UmaDiscoveryMetadata {
    /// Create discovery metadata for a given issuer base URL.
    pub fn new(issuer: impl Into<String>) -> Self {
        let base = issuer.into();
        Self {
            token_endpoint: format!("{base}/oauth/token"),
            resource_registration_endpoint: format!("{base}/uma/resource_set"),
            permission_endpoint: format!("{base}/uma/permission"),
            rpt_endpoint: format!("{base}/oauth/token"),
            introspection_endpoint: format!("{base}/oauth/introspect"),
            claims_interaction_endpoint: format!("{base}/uma/claims"),
            grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:uma-ticket".to_string()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ],
            uma_profiles_supported: vec![],
            issuer: base,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmaConfig {
    pub enabled: bool,
    pub pat_lifetime: u64, // Protection API Token lifetime in seconds
    pub rpt_lifetime: u64, // Requesting Party Token lifetime in seconds
    pub claims_interaction_endpoint: String,
    /// Permission ticket lifetime in seconds (default: 300 = 5 minutes)
    pub ticket_lifetime: u64,
}

impl Default for UmaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pat_lifetime: 3600,
            rpt_lifetime: 3600,
            claims_interaction_endpoint: "/api/uma/claims".to_string(),
            ticket_lifetime: 300,
        }
    }
}

/// Thread-safe UMA service
pub struct UmaService {
    config: UmaConfig,
    resource_sets: Arc<RwLock<HashMap<String, UmaResourceSet>>>,
    permission_tickets: Arc<RwLock<HashMap<String, PermissionTicket>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UmaResourceSet {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub owner_id: String,
    /// Optional policy: required claims for access (claim_name → expected_value)
    pub required_claims: HashMap<String, String>,
}

/// A permission ticket issued when a resource server encounters an unauthorized request
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermissionTicket {
    pub ticket: String,
    pub resource_id: String,
    pub requested_scopes: Vec<String>,
    pub created_at: u64,
}

impl UmaService {
    pub fn new(config: UmaConfig) -> Self {
        Self {
            config,
            resource_sets: Arc::new(RwLock::new(HashMap::new())),
            permission_tickets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a resource set as part of the Resource Registration API (UMA §3.1).
    pub async fn register_resource_set(&self, mut resource_set: UmaResourceSet) -> Result<String> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        if resource_set.id.is_empty() {
            resource_set.id = uuid::Uuid::new_v4().to_string();
        }

        let id = resource_set.id.clone();
        self.resource_sets
            .write()
            .await
            .insert(id.clone(), resource_set);
        Ok(id)
    }

    /// Create a permission ticket when a resource server encounters an unauthorized request (UMA §3.2).
    pub async fn create_permission_ticket(
        &self,
        resource_id: &str,
        requested_scopes: Vec<String>,
    ) -> Result<String> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        // Verify the resource exists
        let resources = self.resource_sets.read().await;
        let resource = resources
            .get(resource_id)
            .ok_or_else(|| AuthError::validation("Resource set not found"))?;

        // Verify requested scopes are valid for this resource
        for scope in &requested_scopes {
            if !resource.scopes.contains(scope) {
                return Err(AuthError::validation(format!(
                    "Scope '{}' is not valid for resource '{}'",
                    scope, resource_id
                )));
            }
        }

        let ticket = format!("urn:uma:ticket:{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let permission = PermissionTicket {
            ticket: ticket.clone(),
            resource_id: resource_id.to_string(),
            requested_scopes,
            created_at: now,
        };

        self.permission_tickets
            .write()
            .await
            .insert(ticket.clone(), permission);

        Ok(ticket)
    }

    /// Request an RPT (Requesting Party Token) by presenting a permission ticket and claims (UMA §3.3).
    pub async fn request_rpt(
        &self,
        ticket: &str,
        claims: Option<HashMap<String, String>>,
    ) -> Result<String> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        if ticket.is_empty() {
            return Err(AuthError::validation("Missing permission ticket"));
        }

        // Look up the permission ticket
        let tickets = self.permission_tickets.read().await;
        let permission = tickets
            .get(ticket)
            .ok_or_else(|| AuthError::validation("Permission ticket not found or expired"))?;

        // Enforce ticket expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(permission.created_at) > self.config.ticket_lifetime {
            drop(tickets);
            self.permission_tickets.write().await.remove(ticket);
            return Err(AuthError::validation("Permission ticket has expired"));
        };

        // Look up the resource to evaluate policies
        let resources = self.resource_sets.read().await;
        let resource = resources.get(&permission.resource_id).ok_or_else(|| {
            AuthError::internal("Resource for permission ticket no longer exists")
        })?;

        // Evaluate claims against resource policies
        if !resource.required_claims.is_empty() {
            let provided_claims = claims.as_ref().ok_or_else(|| {
                AuthError::validation(format!(
                    "UMA need_info: Redirect to {} with ticket {}",
                    self.config.claims_interaction_endpoint, ticket
                ))
            })?;

            for (required_claim, expected_value) in &resource.required_claims {
                match provided_claims.get(required_claim) {
                    Some(actual_value) if actual_value == expected_value => {}
                    Some(_) => {
                        return Err(AuthError::validation(format!(
                            "Claim '{}' does not match required policy",
                            required_claim
                        )));
                    }
                    None => {
                        return Err(AuthError::validation(format!(
                            "UMA need_info: Missing required claim '{}'",
                            required_claim
                        )));
                    }
                }
            }
        }

        // Claims satisfied — issue RPT
        let rpt = format!("urn:uma:rpt:{}", uuid::Uuid::new_v4());

        // Remove the consumed permission ticket
        drop(tickets);
        drop(resources);
        self.permission_tickets.write().await.remove(ticket);

        Ok(rpt)
    }

    /// List registered resource sets for an owner
    pub async fn list_resource_sets(&self, owner_id: &str) -> Result<Vec<UmaResourceSet>> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        let resources = self.resource_sets.read().await;
        Ok(resources
            .values()
            .filter(|r| r.owner_id == owner_id)
            .cloned()
            .collect())
    }

    /// Delete a resource set
    pub async fn delete_resource_set(&self, resource_id: &str, owner_id: &str) -> Result<()> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        let mut resources = self.resource_sets.write().await;
        if let Some(resource) = resources.get(resource_id) {
            if resource.owner_id != owner_id {
                return Err(AuthError::validation(
                    "Only the resource owner can delete a resource set",
                ));
            }
            resources.remove(resource_id);
            Ok(())
        } else {
            Err(AuthError::validation("Resource set not found"))
        }
    }

    /// Remove expired permission tickets from the in-memory store.
    pub async fn cleanup_expired_tickets(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let lifetime = self.config.ticket_lifetime;
        self.permission_tickets
            .write()
            .await
            .retain(|_, t| now.saturating_sub(t.created_at) <= lifetime);
    }

    /// Get the UMA discovery metadata for this service.
    pub fn discovery_metadata(&self, issuer: &str) -> UmaDiscoveryMetadata {
        let mut meta = UmaDiscoveryMetadata::new(issuer);
        meta.claims_interaction_endpoint = self.config.claims_interaction_endpoint.clone();
        meta
    }

    /// Count of active permission tickets.
    pub async fn ticket_count(&self) -> usize {
        self.permission_tickets.read().await.len()
    }

    /// Count of registered resource sets.
    pub async fn resource_count(&self) -> usize {
        self.resource_sets.read().await.len()
    }

    /// Get a resource set by ID.
    pub async fn get_resource_set(&self, resource_id: &str) -> Option<UmaResourceSet> {
        self.resource_sets.read().await.get(resource_id).cloned()
    }

    /// Update a resource set (owner must match).
    pub async fn update_resource_set(
        &self,
        resource_id: &str,
        owner_id: &str,
        name: Option<String>,
        scopes: Option<Vec<String>>,
        required_claims: Option<HashMap<String, String>>,
    ) -> Result<()> {
        if !self.config.enabled {
            return Err(AuthError::config("UMA 2.0 protocol is currently disabled"));
        }

        let mut resources = self.resource_sets.write().await;
        let resource = resources
            .get_mut(resource_id)
            .ok_or_else(|| AuthError::validation("Resource set not found"))?;

        if resource.owner_id != owner_id {
            return Err(AuthError::validation(
                "Only the resource owner can update a resource set",
            ));
        }

        if let Some(n) = name {
            resource.name = n;
        }
        if let Some(s) = scopes {
            resource.scopes = s;
        }
        if let Some(rc) = required_claims {
            resource.required_claims = rc;
        }
        Ok(())
    }
}

// ── Protection API Token (PAT) ──────────────────────────────────────

/// A PAT (Protection API Token) record.
///
/// PATs are OAuth 2.0 access tokens with the `uma_protection` scope that
/// resource servers use to access the UMA protection API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pat {
    /// The PAT access token value.
    pub access_token: String,
    /// Client ID of the resource server that owns this PAT.
    pub client_id: String,
    /// When the PAT was issued (UNIX timestamp).
    pub issued_at: u64,
    /// When the PAT expires (UNIX timestamp).
    pub expires_at: u64,
}

impl Pat {
    /// Check if PAT has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }
}

/// In-memory PAT store for managing Protection API Tokens.
pub struct PatStore {
    tokens: Arc<RwLock<HashMap<String, Pat>>>,
}

impl PatStore {
    /// Create a new empty PAT store.
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Issue a new PAT for a resource server.
    pub async fn issue(&self, client_id: &str, lifetime_secs: u64) -> Pat {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pat = Pat {
            access_token: format!("pat_{}", uuid::Uuid::new_v4()),
            client_id: client_id.to_string(),
            issued_at: now,
            expires_at: now + lifetime_secs,
        };
        self.tokens
            .write()
            .await
            .insert(pat.access_token.clone(), pat.clone());
        pat
    }

    /// Validate a PAT and return its record if valid.
    pub async fn validate(&self, token: &str) -> Result<Pat> {
        let tokens = self.tokens.read().await;
        let pat = tokens
            .get(token)
            .ok_or_else(|| AuthError::invalid_credential("PAT", "Invalid or unknown PAT"))?;
        if pat.is_expired() {
            return Err(AuthError::invalid_credential("PAT", "PAT has expired"));
        }
        Ok(pat.clone())
    }

    /// Revoke a PAT.
    pub async fn revoke(&self, token: &str) -> bool {
        self.tokens.write().await.remove(token).is_some()
    }

    /// Remove expired PATs.
    pub async fn cleanup_expired(&self) {
        self.tokens.write().await.retain(|_, p| !p.is_expired());
    }

    /// Count of stored PATs.
    pub async fn count(&self) -> usize {
        self.tokens.read().await.len()
    }
}

impl Default for PatStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── RPT Introspection ───────────────────────────────────────────────

/// Result of RPT (Requesting Party Token) introspection (RFC 7662 + UMA 2.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RptIntrospectionResponse {
    /// Whether the RPT is currently active.
    pub active: bool,
    /// The permissions granted by this RPT.
    #[serde(default)]
    pub permissions: Vec<RptPermission>,
    /// When the RPT expires (UNIX timestamp).
    #[serde(default)]
    pub exp: Option<u64>,
    /// When the RPT was issued (UNIX timestamp).
    #[serde(default)]
    pub iat: Option<u64>,
}

/// A single permission within an RPT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RptPermission {
    /// The resource set ID this permission applies to.
    pub resource_id: String,
    /// The scopes granted.
    pub scopes: Vec<String>,
}

/// In-memory RPT store with introspection support.
pub struct RptStore {
    tokens: Arc<RwLock<HashMap<String, RptIntrospectionResponse>>>,
}

impl RptStore {
    /// Create a new RPT store.
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an issued RPT with its permissions.
    pub async fn register(
        &self,
        rpt: &str,
        resource_id: &str,
        scopes: Vec<String>,
        lifetime_secs: u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let resp = RptIntrospectionResponse {
            active: true,
            permissions: vec![RptPermission {
                resource_id: resource_id.to_string(),
                scopes,
            }],
            exp: Some(now + lifetime_secs),
            iat: Some(now),
        };
        self.tokens.write().await.insert(rpt.to_string(), resp);
    }

    /// Introspect an RPT (RFC 7662).
    pub async fn introspect(&self, rpt: &str) -> RptIntrospectionResponse {
        let tokens = self.tokens.read().await;
        match tokens.get(rpt) {
            Some(resp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expired = resp.exp.is_some_and(|exp| now >= exp);
                if expired {
                    RptIntrospectionResponse {
                        active: false,
                        permissions: vec![],
                        exp: resp.exp,
                        iat: resp.iat,
                    }
                } else {
                    resp.clone()
                }
            }
            None => RptIntrospectionResponse {
                active: false,
                permissions: vec![],
                exp: None,
                iat: None,
            },
        }
    }

    /// Revoke an RPT.
    pub async fn revoke(&self, rpt: &str) -> bool {
        self.tokens.write().await.remove(rpt).is_some()
    }

    /// Remove expired RPTs.
    pub async fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.tokens
            .write()
            .await
            .retain(|_, r| r.exp.is_none_or(|exp| now < exp));
    }

    /// Number of stored RPTs.
    pub async fn count(&self) -> usize {
        self.tokens.read().await.len()
    }
}

impl Default for RptStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> UmaConfig {
        UmaConfig {
            enabled: true,
            ..UmaConfig::default()
        }
    }

    fn sample_resource(owner: &str) -> UmaResourceSet {
        UmaResourceSet {
            id: String::new(),
            name: "Photos".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            owner_id: owner.to_string(),
            required_claims: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_register_resource_set() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_list_resource_sets_filters_by_owner() {
        let svc = UmaService::new(enabled_config());
        svc.register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        svc.register_resource_set(sample_resource("bob"))
            .await
            .unwrap();
        let alice_rs = svc.list_resource_sets("alice").await.unwrap();
        assert_eq!(alice_rs.len(), 1);
        assert_eq!(alice_rs[0].owner_id, "alice");
    }

    #[tokio::test]
    async fn test_delete_resource_set() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        svc.delete_resource_set(&id, "alice").await.unwrap();
        let resources = svc.list_resource_sets("alice").await.unwrap();
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn test_delete_resource_wrong_owner_rejected() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        let result = svc.delete_resource_set(&id, "eve").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_permission_ticket() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        let ticket = svc
            .create_permission_ticket(&id, vec!["read".to_string()])
            .await
            .unwrap();
        assert!(!ticket.is_empty());
    }

    #[tokio::test]
    async fn test_permission_ticket_invalid_scope_rejected() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        let result = svc
            .create_permission_ticket(&id, vec!["delete".to_string()])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_rpt_with_valid_ticket() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        let ticket = svc
            .create_permission_ticket(&id, vec!["read".to_string()])
            .await
            .unwrap();
        let rpt = svc.request_rpt(&ticket, None).await.unwrap();
        assert!(!rpt.is_empty());
    }

    #[tokio::test]
    async fn test_request_rpt_invalid_ticket_rejected() {
        let svc = UmaService::new(enabled_config());
        let result = svc.request_rpt("bogus-ticket", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_disabled_service_rejects() {
        let svc = UmaService::new(UmaConfig::default()); // enabled: false
        let result = svc.register_resource_set(sample_resource("alice")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_required_claims_enforced() {
        let svc = UmaService::new(enabled_config());
        let mut rs = sample_resource("alice");
        rs.required_claims
            .insert("country".to_string(), "US".to_string());
        let id = svc.register_resource_set(rs).await.unwrap();
        let ticket = svc
            .create_permission_ticket(&id, vec!["read".to_string()])
            .await
            .unwrap();

        // Without claims → should fail
        let result = svc.request_rpt(&ticket, None).await;
        assert!(result.is_err());

        // Re-create ticket (old one consumed)
        let ticket2 = svc
            .create_permission_ticket(&id, vec!["read".to_string()])
            .await
            .unwrap();
        // With correct claims → should succeed
        let mut claims = HashMap::new();
        claims.insert("country".to_string(), "US".to_string());
        let rpt = svc.request_rpt(&ticket2, Some(claims)).await.unwrap();
        assert!(!rpt.is_empty());
    }

    // ── UMA Discovery Metadata ──────────────────────────────────

    #[test]
    fn test_uma_discovery_metadata() {
        let meta = UmaDiscoveryMetadata::new("https://auth.example.com");
        assert_eq!(meta.issuer, "https://auth.example.com");
        assert_eq!(meta.token_endpoint, "https://auth.example.com/oauth/token");
        assert_eq!(
            meta.resource_registration_endpoint,
            "https://auth.example.com/uma/resource_set"
        );
        assert_eq!(
            meta.permission_endpoint,
            "https://auth.example.com/uma/permission"
        );
        assert_eq!(
            meta.introspection_endpoint,
            "https://auth.example.com/oauth/introspect"
        );
        assert!(
            meta.grant_types_supported
                .contains(&"urn:ietf:params:oauth:grant-type:uma-ticket".to_string())
        );
    }

    #[test]
    fn test_uma_discovery_serialization() {
        let meta = UmaDiscoveryMetadata::new("https://auth.example.com");
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert!(!json["grant_types_supported"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_uma_service_discovery() {
        let svc = UmaService::new(enabled_config());
        let meta = svc.discovery_metadata("https://auth.example.com");
        assert_eq!(meta.claims_interaction_endpoint, "/api/uma/claims");
    }

    // ── Resource Set Updates ────────────────────────────────────

    #[tokio::test]
    async fn test_update_resource_set() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        svc.update_resource_set(
            &id,
            "alice",
            Some("Updated Photos".to_string()),
            Some(vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ]),
            None,
        )
        .await
        .unwrap();
        let rs = svc.get_resource_set(&id).await.unwrap();
        assert_eq!(rs.name, "Updated Photos");
        assert_eq!(rs.scopes.len(), 3);
    }

    #[tokio::test]
    async fn test_update_resource_set_wrong_owner() {
        let svc = UmaService::new(enabled_config());
        let id = svc
            .register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        assert!(
            svc.update_resource_set(&id, "eve", Some("Hacked".to_string()), None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_resource_count() {
        let svc = UmaService::new(enabled_config());
        assert_eq!(svc.resource_count().await, 0);
        svc.register_resource_set(sample_resource("alice"))
            .await
            .unwrap();
        assert_eq!(svc.resource_count().await, 1);
    }

    // ── PAT Store ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_pat_issue_and_validate() {
        let store = PatStore::new();
        let pat = store.issue("client1", 3600).await;
        assert!(pat.access_token.starts_with("pat_"));
        assert_eq!(pat.client_id, "client1");
        assert!(!pat.is_expired());

        let validated = store.validate(&pat.access_token).await.unwrap();
        assert_eq!(validated.client_id, "client1");
    }

    #[tokio::test]
    async fn test_pat_validate_unknown() {
        let store = PatStore::new();
        assert!(store.validate("bogus").await.is_err());
    }

    #[tokio::test]
    async fn test_pat_revoke() {
        let store = PatStore::new();
        let pat = store.issue("client1", 3600).await;
        assert!(store.revoke(&pat.access_token).await);
        assert!(!store.revoke(&pat.access_token).await);
        assert!(store.validate(&pat.access_token).await.is_err());
    }

    #[tokio::test]
    async fn test_pat_count() {
        let store = PatStore::new();
        store.issue("c1", 3600).await;
        store.issue("c2", 3600).await;
        assert_eq!(store.count().await, 2);
    }

    // ── RPT Store & Introspection ───────────────────────────────

    #[tokio::test]
    async fn test_rpt_register_and_introspect() {
        let store = RptStore::new();
        store
            .register("rpt-123", "resource-1", vec!["read".to_string()], 3600)
            .await;
        let resp = store.introspect("rpt-123").await;
        assert!(resp.active);
        assert_eq!(resp.permissions.len(), 1);
        assert_eq!(resp.permissions[0].resource_id, "resource-1");
        assert_eq!(resp.permissions[0].scopes, vec!["read"]);
    }

    #[tokio::test]
    async fn test_rpt_introspect_unknown() {
        let store = RptStore::new();
        let resp = store.introspect("unknown").await;
        assert!(!resp.active);
        assert!(resp.permissions.is_empty());
    }

    #[tokio::test]
    async fn test_rpt_revoke() {
        let store = RptStore::new();
        store
            .register("rpt-456", "res-1", vec!["write".to_string()], 3600)
            .await;
        assert!(store.revoke("rpt-456").await);
        let resp = store.introspect("rpt-456").await;
        assert!(!resp.active);
    }

    #[tokio::test]
    async fn test_rpt_count() {
        let store = RptStore::new();
        store
            .register("rpt-1", "r1", vec!["read".to_string()], 3600)
            .await;
        store
            .register("rpt-2", "r2", vec!["write".to_string()], 3600)
            .await;
        assert_eq!(store.count().await, 2);
    }

    #[tokio::test]
    async fn test_rpt_introspection_serialization() {
        let resp = RptIntrospectionResponse {
            active: true,
            permissions: vec![RptPermission {
                resource_id: "res-1".to_string(),
                scopes: vec!["read".to_string()],
            }],
            exp: Some(9999999999),
            iat: Some(1000000000),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["active"], true);
        assert_eq!(json["permissions"][0]["resource_id"], "res-1");
    }
}
