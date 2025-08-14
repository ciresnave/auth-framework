//! Core Server Implementation Module
//!
//! This module contains core server functionality including:
//! - Client registration and registry
//! - Metadata management
//! - Stepped-up authentication
//! - Federated authentication orchestration
//! - Additional server modules
//! - Common configuration framework

pub mod additional_modules;
pub mod client_registration;
pub mod client_registry;
pub mod common_config;
pub mod common_http;
pub mod common_jwt;
pub mod common_validation;
pub mod federated_authentication_orchestration;
pub mod metadata;
pub mod stepped_up_auth;

// Re-export commonly used types
pub use additional_modules::*;
pub use client_registration::*;
pub use client_registry::*;
pub use common_config::*;
pub use common_jwt::*;
pub use common_validation::*;
pub use federated_authentication_orchestration::*;
pub use metadata::*;
pub use stepped_up_auth::*;
