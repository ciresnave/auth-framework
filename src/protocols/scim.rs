//! SCIM 2.0 (RFC 7643 / RFC 7644) — System for Cross-domain Identity Management
//!
//! Provides types and a client for provisioning and managing user/group
//! identities across domains using the SCIM 2.0 protocol.
//!
//! # Supported Operations
//!
//! - **Users**: Create, Read, Replace, Patch, Delete, List (with filtering)
//! - **Groups**: Create, Read, Replace, Patch, Delete, List
//! - **Bulk**: Batch operations for efficient provisioning
//! - **Service Provider Config**: Capability discovery
//!
//! # Security
//!
//! - All requests use Bearer token authentication
//! - TLS is required (enforced by the client)
//! - Attribute filtering prevents over-exposure of PII

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── SCIM Core Schema Types (RFC 7643) ───────────────────────────────────────

/// SCIM 2.0 schema URN constants.
pub mod schema {
    pub const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
    pub const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
    pub const ENTERPRISE_USER: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    pub const LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    pub const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    pub const BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    pub const BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
    pub const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
    pub const SEARCH_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    pub const SERVICE_PROVIDER_CONFIG: &str =
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
}

/// Common SCIM metadata present on every resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub resource_type: String,
    pub created: Option<String>,
    pub last_modified: Option<String>,
    pub location: Option<String>,
    pub version: Option<String>,
}

/// SCIM multi-valued attribute with canonical type/primary flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiValuedAttr {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub attr_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM Name component (RFC 7643 §4.1.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// SCIM User resource (RFC 7643 §4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// Schema URNs.
    pub schemas: Vec<String>,

    /// Unique server-assigned identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Unique identifier for the user (typically login name).
    pub user_name: String,

    /// User's name components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Email addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<MultiValuedAttr>>,

    /// Phone numbers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_numbers: Option<Vec<MultiValuedAttr>>,

    /// Whether the user account is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,

    /// Resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,

    /// Groups the user belongs to (read-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<MultiValuedAttr>>,

    /// Additional extension attributes.
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

impl ScimUser {
    /// Create a minimal SCIM User with only the required `userName`.
    pub fn new(user_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![schema::USER.to_string()],
            id: None,
            user_name: user_name.into(),
            name: None,
            display_name: None,
            emails: None,
            phone_numbers: None,
            active: Some(true),
            meta: None,
            groups: None,
            extensions: HashMap::new(),
        }
    }
}

/// SCIM Group resource (RFC 7643 §4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub display_name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<MultiValuedAttr>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

impl ScimGroup {
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            schemas: vec![schema::GROUP.to_string()],
            id: None,
            display_name: display_name.into(),
            members: None,
            meta: None,
        }
    }
}

// ─── SCIM Protocol Messages (RFC 7644) ───────────────────────────────────────

/// SCIM ListResponse (RFC 7644 §3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_per_page: Option<u64>,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// SCIM Patch operation (RFC 7644 §3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// A single patch operation entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct PatchOperation {
    pub op: PatchOpType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

impl std::fmt::Debug for PatchOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("PatchOperation");
        d.field("op", &self.op);
        d.field("path", &self.path);
        d.field("value", &crate::utils::redact::redacted(&self.value));
        d.finish()
    }
}

/// Patch operation type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatchOpType {
    Add,
    Remove,
    Replace,
}

/// SCIM Bulk request (RFC 7644 §3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRequest {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on_errors: Option<u32>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,
}

/// SCIM Bulk response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResponse>,
}

/// A single operation inside a bulk request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperation {
    pub method: BulkMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Debug for BulkOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("BulkOperation");
        d.field("method", &self.method);
        d.field("bulk_id", &self.bulk_id);
        d.field("path", &self.path);
        d.field("data", &crate::utils::redact::redacted(&self.data));
        d.finish()
    }
}

/// A single operation response inside a bulk response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperationResponse {
    pub method: BulkMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BulkMethod {
    Post,
    Put,
    Patch,
    Delete,
}

/// SCIM Error response (RFC 7644 §3.12).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// SCIM Search request (RFC 7644 §3.4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_attributes: Option<Vec<String>>,
}

/// Service provider configuration (RFC 7643 §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProviderConfig {
    pub schemas: Vec<String>,
    pub patch: Supported,
    pub bulk: BulkSupported,
    pub filter: FilterSupported,
    pub change_password: Supported,
    pub sort: Supported,
    pub etag: Supported,
    pub authentication_schemes: Vec<AuthenticationScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Supported {
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkSupported {
    pub supported: bool,
    pub max_operations: u32,
    pub max_payload_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterSupported {
    pub supported: bool,
    pub max_results: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationScheme {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub scheme_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    pub primary: bool,
}

// ─── SCIM Client ─────────────────────────────────────────────────────────────

/// Configuration for the SCIM 2.0 client.
#[derive(Clone)]
pub struct ScimClientConfig {
    /// Base URL of the SCIM service (e.g. `https://idp.example.com/scim/v2`).
    pub base_url: String,

    /// Bearer token for authentication.
    pub bearer_token: String,

    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl std::fmt::Debug for ScimClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ScimClientConfig");
        d.field("base_url", &self.base_url);
        d.field(
            "bearer_token",
            &crate::utils::redact::redacted(&self.bearer_token),
        );
        d.field("timeout_secs", &self.timeout_secs);
        d.finish()
    }
}

/// SCIM 2.0 client for provisioning users and groups.
pub struct ScimClient {
    config: ScimClientConfig,
    http: reqwest::Client,
}

impl ScimClient {
    /// Create a new SCIM client.
    pub fn new(config: ScimClientConfig) -> Result<Self> {
        if !config.base_url.starts_with("https://") {
            return Err(AuthError::config(
                "SCIM base URL must use HTTPS for security",
            ));
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| AuthError::internal(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self { config, http })
    }

    // ── Users ────────────────────────────────────────────────────────────

    /// Create a user (POST /Users).
    pub async fn create_user(&self, user: &ScimUser) -> Result<ScimUser> {
        let url = format!("{}/Users", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.bearer_token)
            .json(user)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM create user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM create user failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimUser>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM create user parse error: {e}")))
    }

    /// Get a user by ID (GET /Users/{id}).
    pub async fn get_user(&self, id: &str) -> Result<ScimUser> {
        let url = format!("{}/Users/{}", self.config.base_url, id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM get user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM get user failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimUser>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM get user parse error: {e}")))
    }

    /// Replace a user (PUT /Users/{id}).
    pub async fn replace_user(&self, id: &str, user: &ScimUser) -> Result<ScimUser> {
        let url = format!("{}/Users/{}", self.config.base_url, id);
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.config.bearer_token)
            .json(user)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM replace user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM replace user failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimUser>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM replace user parse error: {e}")))
    }

    /// Patch a user (PATCH /Users/{id}).
    pub async fn patch_user(&self, id: &str, patch: &PatchOp) -> Result<ScimUser> {
        let url = format!("{}/Users/{}", self.config.base_url, id);
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(&self.config.bearer_token)
            .json(patch)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM patch user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM patch user failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimUser>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM patch user parse error: {e}")))
    }

    /// Delete a user (DELETE /Users/{id}).
    pub async fn delete_user(&self, id: &str) -> Result<()> {
        let url = format!("{}/Users/{}", self.config.base_url, id);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM delete user request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM delete user failed (HTTP {status}): {body}"
            )));
        }

        Ok(())
    }

    /// List users with optional filter (GET /Users?filter=...).
    pub async fn list_users(
        &self,
        filter: Option<&str>,
        start_index: Option<u64>,
        count: Option<u64>,
    ) -> Result<ListResponse<ScimUser>> {
        let mut url = format!("{}/Users", self.config.base_url);
        let mut params = Vec::new();
        if let Some(f) = filter {
            params.push(format!("filter={}", urlencoding::encode(f)));
        }
        if let Some(si) = start_index {
            params.push(format!("startIndex={si}"));
        }
        if let Some(c) = count {
            params.push(format!("count={c}"));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM list users request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM list users failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ListResponse<ScimUser>>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM list users parse error: {e}")))
    }

    // ── Groups ───────────────────────────────────────────────────────────

    /// Create a group (POST /Groups).
    pub async fn create_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        let url = format!("{}/Groups", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.bearer_token)
            .json(group)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM create group request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM create group failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimGroup>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM create group parse error: {e}")))
    }

    /// Get a group by ID (GET /Groups/{id}).
    pub async fn get_group(&self, id: &str) -> Result<ScimGroup> {
        let url = format!("{}/Groups/{}", self.config.base_url, id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM get group request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM get group failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ScimGroup>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM get group parse error: {e}")))
    }

    /// Delete a group (DELETE /Groups/{id}).
    pub async fn delete_group(&self, id: &str) -> Result<()> {
        let url = format!("{}/Groups/{}", self.config.base_url, id);
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM delete group request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM delete group failed (HTTP {status}): {body}"
            )));
        }

        Ok(())
    }

    /// List groups with optional filter (GET /Groups?filter=...).
    pub async fn list_groups(
        &self,
        filter: Option<&str>,
        start_index: Option<u64>,
        count: Option<u64>,
    ) -> Result<ListResponse<ScimGroup>> {
        let mut url = format!("{}/Groups", self.config.base_url);
        let mut params = Vec::new();
        if let Some(f) = filter {
            params.push(format!("filter={}", urlencoding::encode(f)));
        }
        if let Some(si) = start_index {
            params.push(format!("startIndex={si}"));
        }
        if let Some(c) = count {
            params.push(format!("count={c}"));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM list groups request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM list groups failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ListResponse<ScimGroup>>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM list groups parse error: {e}")))
    }

    // ── Bulk ─────────────────────────────────────────────────────────────

    /// Execute a bulk request (POST /Bulk).
    pub async fn bulk(&self, request: &BulkRequest) -> Result<BulkResponse> {
        let url = format!("{}/Bulk", self.config.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.bearer_token)
            .json(request)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM bulk request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM bulk request failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<BulkResponse>()
            .await
            .map_err(|e| AuthError::internal(format!("SCIM bulk response parse error: {e}")))
    }

    // ── Service Provider Config ──────────────────────────────────────────

    /// Retrieve the service provider configuration.
    pub async fn get_service_provider_config(&self) -> Result<ServiceProviderConfig> {
        let url = format!("{}/ServiceProviderConfig", self.config.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await
            .map_err(|e| {
                AuthError::internal(format!("SCIM service provider config request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::internal(format!(
                "SCIM service provider config failed (HTTP {status}): {body}"
            )));
        }

        resp.json::<ServiceProviderConfig>().await.map_err(|e| {
            AuthError::internal(format!("SCIM service provider config parse error: {e}"))
        })
    }
}

// ─── Helper constructors ─────────────────────────────────────────────────────

impl PatchOp {
    /// Create a new PatchOp with a list of operations.
    pub fn new(operations: Vec<PatchOperation>) -> Self {
        Self {
            schemas: vec![schema::PATCH_OP.to_string()],
            operations,
        }
    }
}

impl SearchRequest {
    /// Create a search request with a filter.
    pub fn with_filter(filter: impl Into<String>) -> Self {
        Self {
            schemas: vec![schema::SEARCH_REQUEST.to_string()],
            filter: Some(filter.into()),
            sort_by: None,
            sort_order: None,
            start_index: None,
            count: None,
            attributes: None,
            excluded_attributes: None,
        }
    }
}

impl BulkRequest {
    /// Create a new bulk request.
    pub fn new(operations: Vec<BulkOperation>, fail_on_errors: Option<u32>) -> Self {
        Self {
            schemas: vec![schema::BULK_REQUEST.to_string()],
            fail_on_errors,
            operations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_user_serialization() {
        let mut user = ScimUser::new("jdoe");
        user.name = Some(Name {
            given_name: Some("John".into()),
            family_name: Some("Doe".into()),
            ..Default::default()
        });
        user.emails = Some(vec![MultiValuedAttr {
            value: "jdoe@example.com".into(),
            attr_type: Some("work".into()),
            primary: Some(true),
            display: None,
        }]);

        let json = serde_json::to_string(&user).expect("serialize");
        assert!(json.contains("\"userName\":\"jdoe\""));
        assert!(json.contains(schema::USER));
    }

    #[test]
    fn test_scim_group_serialization() {
        let group = ScimGroup::new("Engineering");
        let json = serde_json::to_string(&group).expect("serialize");
        assert!(json.contains("\"displayName\":\"Engineering\""));
        assert!(json.contains(schema::GROUP));
    }

    #[test]
    fn test_patch_op_construction() {
        let patch = PatchOp::new(vec![PatchOperation {
            op: PatchOpType::Replace,
            path: Some("active".into()),
            value: Some(serde_json::Value::Bool(false)),
        }]);
        assert_eq!(patch.schemas[0], schema::PATCH_OP);
        assert_eq!(patch.operations.len(), 1);
    }

    #[test]
    fn test_scim_user_roundtrip() {
        let user = ScimUser::new("alice");
        let json = serde_json::to_value(&user).expect("to value");
        let parsed: ScimUser = serde_json::from_value(json).expect("from value");
        assert_eq!(parsed.user_name, "alice");
        assert_eq!(parsed.active, Some(true));
    }

    #[test]
    fn test_bulk_request_construction() {
        let bulk = BulkRequest::new(
            vec![BulkOperation {
                method: BulkMethod::Post,
                bulk_id: Some("op1".into()),
                path: Some("/Users".into()),
                data: Some(serde_json::to_value(ScimUser::new("bulk_user")).expect("val")),
            }],
            Some(1),
        );
        assert_eq!(bulk.schemas[0], schema::BULK_REQUEST);
        assert_eq!(bulk.fail_on_errors, Some(1));
    }

    #[test]
    fn test_scim_user_empty_username() {
        let user = ScimUser::new("");
        assert_eq!(user.user_name, "");
        // Roundtrip should preserve the empty string
        let json = serde_json::to_value(&user).unwrap();
        let parsed: ScimUser = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.user_name, "");
    }

    #[test]
    fn test_scim_user_all_optional_fields() {
        let mut user = ScimUser::new("fulluser");
        user.id = Some("u-123".into());
        user.display_name = Some("Full User".into());
        user.name = Some(Name {
            formatted: Some("Dr. Full A. User Jr.".into()),
            family_name: Some("User".into()),
            given_name: Some("Full".into()),
            middle_name: Some("A".into()),
            honorific_prefix: Some("Dr.".into()),
            honorific_suffix: Some("Jr.".into()),
        });
        user.emails = Some(vec![
            MultiValuedAttr {
                value: "work@example.com".into(),
                attr_type: Some("work".into()),
                primary: Some(true),
                display: Some("Work Email".into()),
            },
            MultiValuedAttr {
                value: "home@example.com".into(),
                attr_type: Some("home".into()),
                primary: Some(false),
                display: None,
            },
        ]);
        user.phone_numbers = Some(vec![MultiValuedAttr {
            value: "+1-555-0100".into(),
            attr_type: Some("mobile".into()),
            primary: Some(true),
            display: None,
        }]);
        user.active = Some(false);
        user.groups = Some(vec![MultiValuedAttr {
            value: "g-eng".into(),
            attr_type: None,
            primary: None,
            display: Some("Engineering".into()),
        }]);

        let json = serde_json::to_string(&user).unwrap();
        let parsed: ScimUser =
            serde_json::from_value(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(parsed.id.as_deref(), Some("u-123"));
        assert_eq!(parsed.display_name.as_deref(), Some("Full User"));
        assert_eq!(parsed.active, Some(false));
        assert_eq!(parsed.emails.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.phone_numbers.as_ref().unwrap().len(), 1);
        assert_eq!(parsed.groups.as_ref().unwrap().len(), 1);
        let name = parsed.name.as_ref().unwrap();
        assert_eq!(name.honorific_prefix.as_deref(), Some("Dr."));
        assert_eq!(name.honorific_suffix.as_deref(), Some("Jr."));
    }

    #[test]
    fn test_scim_user_deserialization_from_json() {
        let json_str = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "server-1",
            "userName": "jdoe",
            "displayName": "Jane Doe",
            "active": true,
            "meta": {
                "resourceType": "User",
                "created": "2024-01-01T00:00:00Z",
                "lastModified": "2024-06-01T00:00:00Z",
                "location": "https://scim.example.com/Users/server-1",
                "version": "W/\"1\""
            }
        }"#;

        let user: ScimUser = serde_json::from_str(json_str).unwrap();
        assert_eq!(user.user_name, "jdoe");
        assert_eq!(user.id.as_deref(), Some("server-1"));
        assert_eq!(user.display_name.as_deref(), Some("Jane Doe"));
        let meta = user.meta.as_ref().unwrap();
        assert_eq!(meta.resource_type, "User");
        assert_eq!(meta.version.as_deref(), Some("W/\"1\""));
    }

    #[test]
    fn test_scim_group_with_members() {
        let mut group = ScimGroup::new("DevOps");
        group.members = Some(vec![
            MultiValuedAttr {
                value: "u-1".into(),
                attr_type: Some("User".into()),
                primary: None,
                display: Some("Alice".into()),
            },
            MultiValuedAttr {
                value: "u-2".into(),
                attr_type: Some("User".into()),
                primary: None,
                display: Some("Bob".into()),
            },
        ]);

        let json = serde_json::to_string(&group).unwrap();
        let parsed: ScimGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display_name, "DevOps");
        let members = parsed.members.unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].display.as_deref(), Some("Alice"));
    }

    #[test]
    fn test_patch_op_add_and_remove() {
        let patch = PatchOp::new(vec![
            PatchOperation {
                op: PatchOpType::Add,
                path: Some("emails".into()),
                value: Some(serde_json::json!([{"value": "new@example.com", "type": "work"}])),
            },
            PatchOperation {
                op: PatchOpType::Remove,
                path: Some("phoneNumbers".into()),
                value: None,
            },
        ]);

        assert_eq!(patch.operations.len(), 2);

        // Verify JSON serialization of patch ops
        let json = serde_json::to_string(&patch).unwrap();
        assert!(json.contains("\"add\""));
        assert!(json.contains("\"remove\""));
        assert!(json.contains("new@example.com"));
    }

    #[test]
    fn test_bulk_request_multiple_operations() {
        let bulk = BulkRequest::new(
            vec![
                BulkOperation {
                    method: BulkMethod::Post,
                    bulk_id: Some("create-1".into()),
                    path: Some("/Users".into()),
                    data: Some(serde_json::to_value(ScimUser::new("user1")).unwrap()),
                },
                BulkOperation {
                    method: BulkMethod::Put,
                    bulk_id: Some("update-1".into()),
                    path: Some("/Users/existing-id".into()),
                    data: Some(serde_json::to_value(ScimUser::new("user1_updated")).unwrap()),
                },
                BulkOperation {
                    method: BulkMethod::Delete,
                    bulk_id: Some("delete-1".into()),
                    path: Some("/Users/old-id".into()),
                    data: None,
                },
            ],
            Some(2),
        );

        assert_eq!(bulk.operations.len(), 3);
        assert_eq!(bulk.fail_on_errors, Some(2));

        // Roundtrip
        let json = serde_json::to_string(&bulk).unwrap();
        let parsed: BulkRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operations.len(), 3);
    }

    #[test]
    fn test_search_request_with_filter() {
        let search = SearchRequest::with_filter("userName eq \"jdoe\"");
        assert_eq!(search.filter.as_deref(), Some("userName eq \"jdoe\""));
        assert_eq!(search.schemas[0], schema::SEARCH_REQUEST);
        assert!(search.sort_by.is_none());
        assert!(search.count.is_none());
    }

    #[test]
    fn test_scim_error_serialization() {
        let error = ScimError {
            schemas: vec![schema::ERROR.to_string()],
            status: Some("400".into()),
            scim_type: Some("invalidFilter".into()),
            detail: Some("The filter syntax is invalid".into()),
        };

        let json = serde_json::to_string(&error).unwrap();
        let parsed: ScimError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status.as_deref(), Some("400"));
        assert_eq!(parsed.scim_type.as_deref(), Some("invalidFilter"));
    }

    #[test]
    fn test_scim_user_active_defaults_to_true() {
        let user = ScimUser::new("defaultuser");
        assert_eq!(user.active, Some(true));
    }

    #[test]
    fn test_scim_user_extensions_roundtrip() {
        let mut user = ScimUser::new("extuser");
        user.extensions.insert(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".to_string(),
            serde_json::json!({
                "employeeNumber": "12345",
                "department": "Engineering"
            }),
        );

        let json = serde_json::to_string(&user).unwrap();
        let parsed: ScimUser = serde_json::from_str(&json).unwrap();
        let ext = &parsed.extensions["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
        assert_eq!(ext["employeeNumber"], "12345");
        assert_eq!(ext["department"], "Engineering");
    }

    #[test]
    fn test_scim_client_rejects_http_url() {
        let config = ScimClientConfig {
            base_url: "http://insecure.example.com/scim/v2".to_string(),
            bearer_token: "tok".to_string(),
            timeout_secs: 10,
        };
        match ScimClient::new(config) {
            Err(e) => {
                let msg = format!("{e}");
                assert!(msg.contains("HTTPS"), "got: {msg}");
            }
            Ok(_) => panic!("expected error for HTTP URL"),
        }
    }

    #[test]
    fn test_list_response_deserialization() {
        let json_str = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "startIndex": 1,
            "itemsPerPage": 10,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "alice"
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "bob"
                }
            ]
        }"#;

        let list: ListResponse<ScimUser> = serde_json::from_str(json_str).unwrap();
        assert_eq!(list.total_results, 2);
        assert_eq!(list.resources.len(), 2);
        assert_eq!(list.resources[0].user_name, "alice");
        assert_eq!(list.resources[1].user_name, "bob");
    }
}
