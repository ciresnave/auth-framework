// SPDX-License-Identifier: MIT OR Apache-2.0
//! OAuth 2.0/2.1 Implementation Module
//!
//! This module contains OAuth 2.0 and OAuth 2.1 implementations including:
//! - OAuth 2.0 core functionality
//! - OAuth 2.1 enhanced security features
//! - Pushed Authorization Requests (PAR)
//! - Rich Authorization Requests
//! - Device Authorization Grant (RFC 8628)

pub mod device;
pub mod oauth2;
pub mod oauth21;
pub mod oauth2_enhanced_storage;
pub mod oauth2_server;
pub mod par;
pub mod resource_indicators;
pub mod rich_authorization_requests;

// Re-export commonly used types - avoid wildcard imports to prevent duplicate definitions
pub use oauth2::OAuth2Server;
pub use oauth21::OAuth21Server;
pub use par::PARManager;
