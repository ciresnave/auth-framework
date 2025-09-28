//! Delegation, ABAC, Resource Mapping, and Backup Code Management
//! Core data models and traits for advanced authorization features

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Delegation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DelegationType {
    UserToUser,
    UserToRole,
    RoleToRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub id: String,
    pub delegator: String, // user or role id
    pub delegatee: String, // user or role id
    pub delegation_type: DelegationType,
    pub scopes: Vec<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub explicit: bool,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub audit_log: Vec<String>, // log entries
}

// ABAC Policy DSL (initial design)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub dsl: String,                         // DSL string for policy
    pub attributes: HashMap<String, String>, // attribute bindings
    pub enabled: bool,
    pub dynamic: bool, // true if stored in DB
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

// Resource mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedResource {
    pub id: String,
    pub resource_type: String, // e.g., "file", "api", "custom"
    pub uri: String,
    pub attributes: HashMap<String, String>,
    pub registered_by: String,
    pub registered_at: DateTime<Utc>,
    pub permissions: Vec<String>, // fine/coarse-grained
}

// Backup code management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupCodeConfig {
    pub code_count: usize,
    pub code_length: usize,
    pub code_format: String,     // e.g., "numeric", "alphanumeric"
    pub code_complexity: String, // e.g., "simple", "strong"
    pub expiry_seconds: u64,
    pub rotate_on_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBackupCodes {
    pub user_id: String,
    pub codes: Vec<String>,
    pub used_codes: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub config: BackupCodeConfig,
}

// Traits for storage and management
pub trait DelegationManager {
    fn create_delegation(&mut self, delegation: Delegation) -> Result<(), String>;
    fn revoke_delegation(&mut self, delegation_id: &str, by: &str) -> Result<(), String>;
    fn get_delegations_for(&self, user_or_role: &str) -> Vec<Delegation>;
    fn audit_delegation(&mut self, delegation_id: &str, entry: &str);
}

pub trait AbacPolicyManager {
    fn add_policy(&mut self, policy: AbacPolicy) -> Result<(), String>;
    fn update_policy(&mut self, policy_id: &str, dsl: &str) -> Result<(), String>;
    fn evaluate_policy(&self, policy_id: &str, attributes: &HashMap<String, String>) -> bool;
}

pub trait ResourceManager {
    fn register_resource(&mut self, resource: ManagedResource) -> Result<(), String>;
    fn update_resource(
        &mut self,
        resource_id: &str,
        attributes: &HashMap<String, String>,
    ) -> Result<(), String>;
    fn get_resource(&self, resource_id: &str) -> Option<ManagedResource>;
}

pub trait BackupCodeManager {
    fn generate_codes(&mut self, user_id: &str, config: &BackupCodeConfig) -> UserBackupCodes;
    fn verify_code(&mut self, user_id: &str, code: &str) -> bool;
    fn rotate_codes(&mut self, user_id: &str);
}
