//! Comprehensive security implementation module for enterprise-grade authentication.
//!
//! This module provides advanced security features and compliance implementations
//! designed for high-security environments including financial services, healthcare,
//! and government applications. All implementations follow current security best
//! practices and relevant industry standards.
//!
//! # Security Features
//!
//! - **DPoP (Demonstration of Proof-of-Possession)**: RFC 9449 implementation
//! - **mTLS (Mutual TLS)**: Client certificate authentication
//! - **FAPI (Financial-grade API)**: Financial industry security profile
//! - **X.509 Certificate Management**: PKI-based authentication
//! - **CAEP (Continuous Access Evaluation)**: Real-time access revocation
//!
//! # Compliance Standards
//!
//! - **FAPI 1.0 & 2.0**: Financial-grade API security profiles
//! - **Open Banking**: European and UK open banking standards
//! - **PCI DSS**: Payment card industry compliance
//! - **NIST Cybersecurity Framework**: Government security guidelines
//! - **ISO 27001**: Information security management
//!
//! # Advanced Security Properties
//!
//! - **Zero-Trust Architecture**: Never trust, always verify
//! - **Defense in Depth**: Multiple layers of security
//! - **Principle of Least Privilege**: Minimal necessary access
//! - **Continuous Monitoring**: Real-time threat detection
//! - **Cryptographic Agility**: Algorithm flexibility and rotation
//!
//! # Use Cases
//!
//! - **Financial Services**: Banking, payment processing, trading platforms
//! - **Healthcare**: HIPAA-compliant medical record systems
//! - **Government**: Classified information systems
//! - **Enterprise**: High-security corporate applications
//! - **IoT Security**: Device-to-device authentication
//!
//! # Example
//!
//! ```rust
//! use auth_framework::server::security::{DpopManager, FapiManager};
//!
//! // DPoP for token binding
//! let dpop_manager = DpopManager::new(jwt_validator);
//! let dpop_result = dpop_manager.validate_dpop_proof(
//!     dpop_proof,
//!     "POST",
//!     "https://api.example.com/resource",
//!     Some(&access_token),
//!     None
//! ).await?;
//!
//! // FAPI compliance validation
//! let fapi_manager = FapiManager::new(config);
//! let fapi_validation = fapi_manager.validate_request(&request).await?;
//! ```
//!
//! # Performance Considerations
//!
//! Security operations are optimized for production use with:
//! - Efficient cryptographic operations
//! - Minimal memory allocation
//! - Concurrent-safe implementations
//! - Connection pooling for external services

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


