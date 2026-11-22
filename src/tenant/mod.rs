// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multi-tenant support for AuthFramework
//!
//! This module provides native multi-tenant capabilities, allowing multiple
//! isolated authentication and authorization contexts to coexist within
//! the same process with complete data isolation.

pub mod context;
pub mod registry;

pub use context::{TenantContext, TenantId, TenantMetadata};
pub use registry::{TenantRegistry, TenantRegistryError};

use crate::config::AuthConfig;

/// Builder for creating TenantRegistry instances
pub struct TenantRegistryBuilder {
    default_config: AuthConfig,
}

impl TenantRegistryBuilder {
    /// Create a new TenantRegistryBuilder with default config
    pub fn new() -> Self {
        Self {
            default_config: AuthConfig::default(),
        }
    }

    /// Set the default configuration for new tenants
    pub fn with_config(mut self, config: AuthConfig) -> Self {
        self.default_config = config;
        self
    }

    /// Build the TenantRegistry
    pub fn build(self) -> TenantRegistry {
        TenantRegistry::new(self.default_config)
    }
}

impl Default for TenantRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_registry_builder() {
        let registry = TenantRegistryBuilder::new().build();
        assert_eq!(registry.tenant_count().await, 0);
    }
}
