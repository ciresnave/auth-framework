//! OpenID Connect (OIDC) Implementation Module
//!
//! This module contains comprehensive OpenID Connect implementations including:
//! - Core OIDC functionality
//! - Session Management
//! - Logout mechanisms (Backchannel & Frontchannel)
//! - Advanced features (JARM, CIBA)
//! - Response modes and extensions

pub mod core;
pub mod oidc_advanced_jarm;
pub mod oidc_backchannel_logout;
pub mod oidc_enhanced_ciba;
pub mod oidc_error_extensions;
pub mod oidc_extensions;
pub mod oidc_frontchannel_logout;
pub mod oidc_response_modes;
// Temporarily disabled due to compilation issues
// pub mod oidc_rp_initiated_logout;
pub mod oidc_session_management;
pub mod oidc_user_registration;

// Re-export commonly used types
pub use core::*;
