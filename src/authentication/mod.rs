// SPDX-License-Identifier: MIT OR Apache-2.0
//! Authentication modules
//!
//! This module provides various authentication mechanisms including
//! advanced authentication, multi-factor authentication, and credential management.
//!
//! This is a supporting module for auth-related data types and helpers.
//! Most applications should start from [`crate::AuthFramework`] or
//! [`crate::prelude`] rather than treating this as a parallel framework entry point.

pub mod advanced_auth;
pub mod credentials;
pub mod mfa;

pub use advanced_auth::*;
pub use credentials::*;
pub use mfa::*;
