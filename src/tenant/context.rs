// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tenant context and identity management

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a tenant
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Create a new TenantId
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the tenant ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the inner string
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Validate the tenant ID format
    ///
    /// Tenant IDs must:
    /// - Be non-empty
    /// - Only contain alphanumeric characters, hyphens, and underscores
    /// - Be between 1 and 64 characters
    pub fn validate(&self) -> Result<(), String> {
        if self.0.is_empty() {
            return Err("Tenant ID cannot be empty".to_string());
        }

        if self.0.len() > 64 {
            return Err("Tenant ID cannot exceed 64 characters".to_string());
        }

        if !self
            .0
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(
                "Tenant ID can only contain alphanumeric characters, hyphens, and underscores"
                    .to_string(),
            );
        }

        Ok(())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Metadata about a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMetadata {
    /// Display name for the tenant
    pub name: String,

    /// Optional description
    pub description: Option<String>,

    /// When the tenant was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Custom attributes for the tenant
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
}

impl TenantMetadata {
    /// Create new tenant metadata
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            created_at: chrono::Utc::now(),
            attributes: std::collections::HashMap::new(),
        }
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a custom attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }
}

/// Context for a specific tenant
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Unique identifier for the tenant
    pub id: TenantId,

    /// Metadata about the tenant
    pub metadata: TenantMetadata,

    /// Whether the tenant is active
    pub active: bool,
}

impl TenantContext {
    /// Create a new tenant context
    pub fn new(id: TenantId, metadata: TenantMetadata) -> Result<Self, String> {
        id.validate()?;

        Ok(Self {
            id,
            metadata,
            active: true,
        })
    }

    /// Create a new tenant with name only
    pub fn with_name(id: impl Into<String>, name: impl Into<String>) -> Result<Self, String> {
        let id = TenantId::new(id);
        id.validate()?;

        Ok(Self {
            id,
            metadata: TenantMetadata::new(name),
            active: true,
        })
    }

    /// Deactivate the tenant
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Activate the tenant
    pub fn activate(&mut self) {
        self.active = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_validation() {
        // Valid IDs
        assert!(TenantId::new("tenant-123").validate().is_ok());
        assert!(TenantId::new("tenant_123").validate().is_ok());
        assert!(TenantId::new("acme-corp").validate().is_ok());

        // Invalid IDs
        assert!(TenantId::new("").validate().is_err());
        assert!(TenantId::new("tenant@123").validate().is_err());
        assert!(TenantId::new("a".repeat(65)).validate().is_err());
    }

    #[test]
    fn test_tenant_context_creation() {
        let context = TenantContext::with_name("acme", "ACME Corp").unwrap();
        assert_eq!(context.id.as_str(), "acme");
        assert_eq!(context.metadata.name, "ACME Corp");
        assert!(context.active);
    }

    #[test]
    fn test_tenant_activation() {
        let mut context = TenantContext::with_name("test", "Test Tenant").unwrap();
        assert!(context.active);

        context.deactivate();
        assert!(!context.active);

        context.activate();
        assert!(context.active);
    }
}
