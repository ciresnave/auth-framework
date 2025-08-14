//! Security Implementation Module
//!
//! This module contains security and compliance functionality including:
//! - DPoP (Demonstration of Proof-of-Possession)
//! - mTLS (Mutual TLS) authentication
//! - FAPI (Financial-grade API) compliance
//! - X.509 certificate signing
//! - CAEP (Continuous Access Evaluation Protocol)

pub mod caep_continuous_access;
pub mod dpop;
pub mod fapi;
pub mod mtls;
pub mod x509_signing;

// Re-export commonly used types
pub use caep_continuous_access::*;
pub use dpop::*;
pub use fapi::*;
pub use mtls::*;
pub use x509_signing::*;
