//! OAuth 2.0/2.1 Implementation Module
//!
//! This module contains OAuth 2.0 and OAuth 2.1 implementations including:
//! - OAuth 2.0 core functionality
//! - OAuth 2.1 enhanced security features
//! - Pushed Authorization Requests (PAR)
//! - Rich Authorization Requests

pub mod oauth2;
pub mod oauth21;
pub mod par;
pub mod rich_authorization_requests;

// Re-export commonly used types
pub use oauth2::*;
pub use oauth21::*;
pub use par::*;
pub use rich_authorization_requests::*;
