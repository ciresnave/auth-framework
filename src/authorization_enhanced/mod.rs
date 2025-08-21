//! Enhanced Authorization Module with role-system v1.0 integration
//!
//! This module provides enterprise-grade role-based access control (RBAC) using the
//! role-system crate, offering hierarchical roles, conditional permissions, and
//! comprehensive audit logging.

#[cfg(feature = "enhanced-rbac")]
pub mod service;

#[cfg(feature = "enhanced-rbac")]
pub mod middleware;

#[cfg(feature = "enhanced-rbac")]
pub mod context;

#[cfg(feature = "enhanced-rbac")]
mod hierarchy_tests_fixed;

// #[cfg(feature = "enhanced-rbac")]
// pub mod storage;

// Re-export core role-system types for convenience
#[cfg(feature = "enhanced-rbac")]
pub use role_system::{
    Permission, Resource, Role, Subject,
    async_support::AsyncRoleSystem,
    storage::{MemoryStorage, Storage},
};

// Legacy authorization support (deprecated)
#[cfg(not(feature = "enhanced-rbac"))]
pub use crate::permissions::PermissionChecker;

#[cfg(not(feature = "enhanced-rbac"))]
pub use crate::authorization as legacy_authorization;

// Export the authorization service
#[cfg(feature = "enhanced-rbac")]
pub use service::AuthorizationService;

// Export enhanced middleware
#[cfg(feature = "enhanced-rbac")]
pub use middleware::{
    conditional_permission_middleware, rbac_middleware, require_permission,
    role_elevation_middleware,
};

// Export context builders
#[cfg(feature = "enhanced-rbac")]
pub use context::{
    AuthorizationContext, ConditionalEvaluator, ConnectionType, ContextBuilder, DayType,
    DeviceType, SecurityLevel, TimeOfDay,
};

// Export storage adapters
// #[cfg(feature = "enhanced-rbac")]
// pub use storage::{DatabaseStorage, MemoryStorage};


