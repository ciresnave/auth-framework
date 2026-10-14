//! RFC 8725 - JSON Web Token Best Current Practices
//!
//! This module implements security best practices for JSON Web Tokens (JWTs)
//! as defined in RFC 8725, providing enhanced security validation and
//! configuration guidelines.

use crate::errors::{AuthError, Result};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// JWT Security Level according to RFC 8725
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Minimum security requirements
    Minimum,
    /// Recommended security practices
    Recommended,
    /// Maximum security (defense in depth)
    Maximum,
}

/// Cryptographic strength classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CryptoStrength {
    /// Weak algorithms (not recommended)
    Weak,
    /// Acceptable algorithms
    Acceptable,
    /// Strong algorithms (recommended)
    Strong,
    /// High-strength algorithms (maximum security)
    High,
}

/// JWT Best Practices Configuration
#[derive(Debug, Clone)]
pub struct JwtBestPracticesConfig {
    /// Required security level
    pub security_level: SecurityLevel,

    /// Allowed signing algorithms (in order of preference)
    pub allowed_algorithms: Vec<Algorithm>,

    /// Forbidden algorithms (explicitly denied)
    pub forbidden_algorithms: Vec<Algorithm>,

    /// Maximum token lifetime (seconds)
    pub max_lifetime: i64,

    /// Minimum token lifetime (seconds)
    pub min_lifetime: i64,

    /// Clock skew tolerance (seconds)
    pub clock_skew: i64,

    /// Required issuer(s)
    pub required_issuers: HashSet<String>,

    /// Required audience(s)
    pub required_audiences: HashSet<String>,

    /// Whether to require the 'sub' claim
    pub require_subject: bool,

    /// Whether to require the 'iat' claim
    pub require_issued_at: bool,

    /// Whether to require the 'exp' claim
    pub require_expiration: bool,

    /// Whether to require the 'nbf' claim
    pub require_not_before: bool,

    /// Whether to require the 'jti' claim (replay protection)
    pub require_jwt_id: bool,

    /// Maximum allowed nested JWT depth
    pub max_nested_depth: u8,
}

impl Default for JwtBestPracticesConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Recommended,
            allowed_algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::ES256,
                Algorithm::ES384,
                Algorithm::EdDSA,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
                Algorithm::EdDSA,
            ],
            forbidden_algorithms: vec![],
            max_lifetime: 3600, // 1 hour
            min_lifetime: 60,   // 1 minute
            clock_skew: 30,     // 30 seconds
            required_issuers: HashSet::new(),
            required_audiences: HashSet::new(),
            require_subject: true,
            require_issued_at: true,
            require_expiration: true,
            require_not_before: false,
            require_jwt_id: false,
            max_nested_depth: 1,
        }
    }
}

impl JwtBestPracticesConfig {
    /// Create configuration for minimum security level
    pub fn minimum_security() -> Self {
        Self {
            security_level: SecurityLevel::Minimum,
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256, Algorithm::PS256],
            max_lifetime: 86400, // 24 hours
            require_subject: false,
            require_issued_at: false,
            require_jwt_id: false,
            ..Default::default()
        }
    }

    /// Create configuration for maximum security level
    pub fn maximum_security() -> Self {
        Self {
            security_level: SecurityLevel::Maximum,
            allowed_algorithms: vec![
                Algorithm::ES384,
                Algorithm::EdDSA,
                Algorithm::PS384,
                Algorithm::PS512,
                Algorithm::EdDSA,
            ],
            forbidden_algorithms: vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            max_lifetime: 900, // 15 minutes
            min_lifetime: 30,  // 30 seconds
            clock_skew: 5,     // 5 seconds
            require_subject: true,
            require_issued_at: true,
            require_expiration: true,
            require_not_before: true,
            require_jwt_id: true,
            max_nested_depth: 0, // No nesting
            ..Default::default()
        }
    }
}

/// Algorithm security classification functions
pub fn get_algorithm_crypto_strength(algorithm: &Algorithm) -> CryptoStrength {
    match algorithm {
        Algorithm::HS256 => CryptoStrength::Acceptable,
        Algorithm::HS384 => CryptoStrength::Strong,
        Algorithm::HS512 => CryptoStrength::Strong,
        Algorithm::RS256 => CryptoStrength::Acceptable,
        Algorithm::RS384 => CryptoStrength::Strong,
        Algorithm::RS512 => CryptoStrength::Strong,
        Algorithm::ES256 => CryptoStrength::Strong,
        Algorithm::ES384 => CryptoStrength::High,
        Algorithm::EdDSA => CryptoStrength::High,
        Algorithm::PS256 => CryptoStrength::Strong,
        Algorithm::PS384 => CryptoStrength::High,
        Algorithm::PS512 => CryptoStrength::High,
    }
}

pub fn is_algorithm_symmetric(algorithm: &Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    )
}

pub fn is_algorithm_asymmetric(algorithm: &Algorithm) -> bool {
    !is_algorithm_symmetric(algorithm)
}

/// Standard JWT claims with validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureJwtClaims {
    /// Issuer
    pub iss: String,

    /// Subject
    pub sub: String,

    /// Audience
    pub aud: Vec<String>,

    /// Expiration time
    pub exp: i64,

    /// Not before
    pub nbf: Option<i64>,

    /// Issued at
    pub iat: i64,

    /// JWT ID
    pub jti: String,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

/// JWT Best Practices Validator
pub struct JwtBestPracticesValidator {
    config: JwtBestPracticesConfig,
    used_jtis: HashSet<String>, // Simple replay protection
}

impl JwtBestPracticesValidator {
    /// Create a new validator with configuration
    pub fn new(config: JwtBestPracticesConfig) -> Self {
        Self {
            config,
            used_jtis: HashSet::new(),
        }
    }

    /// Validate JWT token format
    pub fn validate_token_format(&self, token: &str) -> Result<()> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidToken("Invalid JWT format".to_string()));
        }

        // Check for excessive size (potential DoS)
        if token.len() > 8192 {
            return Err(AuthError::InvalidToken("Token too large".to_string()));
        }

        Ok(())
    }

    /// Validate algorithm security
    pub fn validate_algorithm(&self, algorithm: &Algorithm) -> Result<()> {
        // Check if algorithm is forbidden
        if self.config.forbidden_algorithms.contains(algorithm) {
            return Err(AuthError::InvalidToken(format!(
                "Forbidden algorithm: {:?}",
                algorithm
            )));
        }

        // Check if algorithm is allowed
        if !self.config.allowed_algorithms.contains(algorithm) {
            return Err(AuthError::InvalidToken(format!(
                "Algorithm not allowed: {:?}",
                algorithm
            )));
        }

        // Check crypto strength
        let strength = get_algorithm_crypto_strength(algorithm);
        match self.config.security_level {
            SecurityLevel::Minimum => {
                if strength < CryptoStrength::Acceptable {
                    return Err(AuthError::InvalidToken("Algorithm too weak".to_string()));
                }
            }
            SecurityLevel::Recommended => {
                if strength < CryptoStrength::Strong {
                    return Err(AuthError::InvalidToken(
                        "Algorithm not recommended".to_string(),
                    ));
                }
            }
            SecurityLevel::Maximum => {
                if strength < CryptoStrength::High {
                    return Err(AuthError::InvalidToken(
                        "Algorithm insufficient for maximum security".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate standard JWT claims
    pub fn validate_standard_claims(&mut self, claims: &SecureJwtClaims) -> Result<()> {
        let now = Utc::now().timestamp();

        // Validate expiration
        if claims.exp <= now {
            return Err(AuthError::InvalidToken("Token has expired".to_string()));
        }

        // Validate not before
        if let Some(nbf) = claims.nbf
            && nbf > now + self.config.clock_skew
        {
            return Err(AuthError::InvalidToken(
                "Token is not yet valid".to_string(),
            ));
        }

        // Validate issued at
        if claims.iat > now + self.config.clock_skew {
            return Err(AuthError::InvalidToken(
                "Token issued in the future".to_string(),
            ));
        }

        // Validate lifetime
        let lifetime = claims.exp - claims.iat;
        if lifetime > self.config.max_lifetime {
            return Err(AuthError::InvalidToken(
                "Token lifetime too long".to_string(),
            ));
        }
        if lifetime < self.config.min_lifetime {
            return Err(AuthError::InvalidToken(
                "Token lifetime too short".to_string(),
            ));
        }

        // Validate issuer
        if !self.config.required_issuers.is_empty()
            && !self.config.required_issuers.contains(&claims.iss)
        {
            return Err(AuthError::InvalidToken("Invalid issuer".to_string()));
        }

        // Validate audience
        if !self.config.required_audiences.is_empty() {
            let has_valid_audience = claims
                .aud
                .iter()
                .any(|aud| self.config.required_audiences.contains(aud));
            if !has_valid_audience {
                return Err(AuthError::InvalidToken("Invalid audience".to_string()));
            }
        }

        // Validate JWT ID for replay protection
        if self.config.require_jwt_id {
            if self.used_jtis.contains(&claims.jti) {
                return Err(AuthError::InvalidToken("Token replay detected".to_string()));
            }
            self.used_jtis.insert(claims.jti.clone());
        }

        Ok(())
    }

    /// Create validation rules based on configuration
    pub fn create_validation_rules(&self, algorithm: Algorithm) -> Result<Validation> {
        let mut validation = Validation::new(algorithm);

        // Configure time-based validation
        validation.leeway = self.config.clock_skew as u64;
        validation.validate_exp = self.config.require_expiration;
        validation.validate_nbf = self.config.require_not_before;

        // Configure issuer validation
        if !self.config.required_issuers.is_empty() {
            let issuers: Vec<&str> = self
                .config
                .required_issuers
                .iter()
                .map(|s| s.as_str())
                .collect();
            validation.set_issuer(&issuers);
        }

        // Configure audience validation
        if !self.config.required_audiences.is_empty() {
            let audiences: Vec<&str> = self
                .config
                .required_audiences
                .iter()
                .map(|s| s.as_str())
                .collect();
            validation.set_audience(&audiences);
        }

        Ok(validation)
    }

    /// Get security recommendations for current configuration
    pub fn get_security_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Algorithm recommendations
        if self
            .config
            .allowed_algorithms
            .iter()
            .any(is_algorithm_symmetric)
        {
            recommendations.push(
                "Consider using asymmetric algorithms (RS*, ES*, PS*) for better security"
                    .to_string(),
            );
        }

        // Lifetime recommendations
        if self.config.max_lifetime > 3600 {
            recommendations.push("Consider reducing token lifetime to 1 hour or less".to_string());
        }

        // Claims recommendations
        if !self.config.require_jwt_id {
            recommendations
                .push("Consider enabling JWT ID (jti) claim for replay protection".to_string());
        }

        if !self.config.require_issued_at {
            recommendations
                .push("Consider requiring issued at (iat) claim for better validation".to_string());
        }

        recommendations
    }

    /// Clear used JWT IDs (for cleanup)
    pub fn clear_used_jtis(&mut self) {
        self.used_jtis.clear();
    }

    /// Get current configuration
    pub fn get_config(&self) -> &JwtBestPracticesConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_strength_classification() {
        assert_eq!(
            get_algorithm_crypto_strength(&Algorithm::HS256),
            CryptoStrength::Acceptable
        );
        assert_eq!(
            get_algorithm_crypto_strength(&Algorithm::ES384),
            CryptoStrength::High
        );
        assert_eq!(
            get_algorithm_crypto_strength(&Algorithm::EdDSA),
            CryptoStrength::High
        );
    }

    #[test]
    fn test_security_level_configuration() {
        let min_config = JwtBestPracticesConfig::minimum_security();
        let max_config = JwtBestPracticesConfig::maximum_security();

        assert_eq!(min_config.security_level, SecurityLevel::Minimum);
        assert_eq!(max_config.security_level, SecurityLevel::Maximum);
        assert!(max_config.max_lifetime < min_config.max_lifetime);
        assert!(max_config.require_jwt_id);
        assert!(!min_config.require_jwt_id);
    }

    #[test]
    fn test_jwt_best_practices_validation() {
        let config = JwtBestPracticesConfig::default();
        let validator = JwtBestPracticesValidator::new(config);

        // Test algorithm validation
        assert!(validator.validate_algorithm(&Algorithm::ES256).is_ok());
    }

    #[test]
    fn test_token_format_validation() {
        let config = JwtBestPracticesConfig::default();
        let validator = JwtBestPracticesValidator::new(config);

        assert!(
            validator
                .validate_token_format("header.payload.signature")
                .is_ok()
        );
        assert!(validator.validate_token_format("invalid.format").is_err());
        assert!(
            validator
                .validate_token_format("too.many.parts.here")
                .is_err()
        );
    }
}
