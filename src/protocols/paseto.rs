//! PASETO (Platform-Agnostic Security Tokens) v4 implementation.
//!
//! Provides local (symmetric, encrypted) PASETO v4 token operations
//! as a secure alternative to JWT.

use crate::errors::{AuthError, Result};
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::footer::Footer;
use pasetors::keys::{Generate, SymmetricKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{Local, local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Configuration for PASETO token operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasetoConfig {
    pub issuer: String,
    pub token_lifetime: Duration,
    pub audience: Option<String>,
    pub footer: Option<String>,
}

impl Default for PasetoConfig {
    fn default() -> Self {
        Self {
            issuer: "auth-framework".to_string(),
            token_lifetime: Duration::from_secs(3600),
            audience: None,
            footer: None,
        }
    }
}

/// Decoded PASETO token payload.
#[derive(Clone)]
pub struct PasetoToken {
    pub subject: String,
    pub issuer: String,
    pub token_id: Option<String>,
    pub audience: Option<String>,
    pub custom_claims: HashMap<String, String>,
}

impl std::fmt::Debug for PasetoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("PasetoToken");
        d.field("subject", &self.subject);
        d.field("issuer", &self.issuer);
        d.field("token_id", &crate::utils::redact::redacted(&self.token_id));
        d.field("audience", &self.audience);
        d.field("custom_claims", &self.custom_claims);
        d.finish()
    }
}

/// PASETO v4.local token manager (symmetric encryption).
pub struct PasetoLocalManager {
    config: PasetoConfig,
    key: SymmetricKey<V4>,
}

impl PasetoLocalManager {
    /// Create a new manager by generating a fresh random key.
    pub fn new(config: PasetoConfig) -> Result<Self> {
        let key = SymmetricKey::<V4>::generate()
            .map_err(|e| AuthError::crypto(format!("Failed to generate PASETO key: {e}")))?;
        Ok(Self { config, key })
    }

    /// Create from existing raw 32-byte key material.
    pub fn from_key_bytes(config: PasetoConfig, key_bytes: &[u8; 32]) -> Result<Self> {
        let key = SymmetricKey::<V4>::from(key_bytes)
            .map_err(|e| AuthError::crypto(format!("Invalid PASETO key: {e}")))?;
        Ok(Self { config, key })
    }

    /// Issue an encrypted PASETO v4.local token.
    pub fn issue_token(
        &self,
        subject: &str,
        additional_claims: Option<&HashMap<String, String>>,
    ) -> Result<String> {
        if subject.is_empty() {
            return Err(AuthError::validation("Subject cannot be empty"));
        }

        let mut claims = Claims::new()
            .map_err(|e| AuthError::crypto(format!("Failed to create claims: {e}")))?;

        claims
            .subject(subject)
            .map_err(|e| AuthError::crypto(format!("Failed to set subject: {e}")))?;
        claims
            .issuer(&self.config.issuer)
            .map_err(|e| AuthError::crypto(format!("Failed to set issuer: {e}")))?;
        claims
            .token_identifier(&uuid::Uuid::new_v4().to_string())
            .map_err(|e| AuthError::crypto(format!("Failed to set jti: {e}")))?;

        if let Some(ref aud) = self.config.audience {
            claims
                .audience(aud)
                .map_err(|e| AuthError::crypto(format!("Failed to set audience: {e}")))?;
        }

        if let Some(extra) = additional_claims {
            for (key, value) in extra {
                claims
                    .add_additional(key, value.clone())
                    .map_err(|e| AuthError::crypto(format!("Failed to add claim '{key}': {e}")))?;
            }
        }

        let footer = match self.config.footer.as_deref() {
            Some(f) => {
                let mut ft = Footer::new();
                ft.add_additional("data", f)
                    .map_err(|e| AuthError::crypto(format!("Invalid PASETO footer: {e}")))?;
                Some(ft)
            }
            None => None,
        };

        local::encrypt(&self.key, &claims, footer.as_ref(), None)
            .map_err(|e| AuthError::crypto(format!("PASETO encryption failed: {e}")))
    }

    /// Decrypt and validate a PASETO v4.local token.
    pub fn validate_token(&self, token: &str) -> Result<PasetoToken> {
        if !token.starts_with("v4.local.") {
            return Err(AuthError::validation("Not a v4.local PASETO token"));
        }

        let validation_rules = ClaimsValidationRules::new();
        let untrusted = UntrustedToken::<Local, V4>::try_from(token)
            .map_err(|e| AuthError::validation(format!("Invalid PASETO token format: {e}")))?;

        let footer = match self.config.footer.as_deref() {
            Some(f) => {
                let mut ft = Footer::new();
                ft.add_additional("data", f)
                    .map_err(|e| AuthError::validation(format!("Invalid PASETO footer: {e}")))?;
                Some(ft)
            }
            None => None,
        };

        let trusted = local::decrypt(
            &self.key,
            &untrusted,
            &validation_rules,
            footer.as_ref(),
            None,
        )
        .map_err(|e| AuthError::validation(format!("PASETO decryption/validation failed: {e}")))?;

        let payload = trusted
            .payload_claims()
            .ok_or_else(|| AuthError::validation("PASETO token has no claims"))?;

        let subject = payload
            .get_claim("sub")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let issuer = payload
            .get_claim("iss")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let token_id = payload
            .get_claim("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let audience = payload
            .get_claim("aud")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if !self.config.issuer.is_empty() && issuer != self.config.issuer {
            return Err(AuthError::validation(format!(
                "Issuer mismatch: expected '{}', got '{}'",
                self.config.issuer, issuer
            )));
        }

        Ok(PasetoToken {
            subject,
            issuer,
            token_id,
            audience,
            custom_claims: HashMap::new(),
        })
    }
}

/// Generate a new random 32-byte key for PASETO v4.local, returned as hex.
pub fn generate_local_key_hex() -> Result<String> {
    let key = SymmetricKey::<V4>::generate()
        .map_err(|e| AuthError::crypto(format!("Failed to generate key: {e}")))?;
    Ok(hex::encode(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_manager() -> PasetoLocalManager {
        PasetoLocalManager::new(PasetoConfig::default()).unwrap()
    }

    #[test]
    fn test_issue_and_validate_token() {
        let mgr = default_manager();
        let token = mgr.issue_token("user-42", None).unwrap();
        assert!(token.starts_with("v4.local."));
        let decoded = mgr.validate_token(&token).unwrap();
        assert_eq!(decoded.subject, "user-42");
        assert_eq!(decoded.issuer, "auth-framework");
        assert!(decoded.token_id.is_some());
    }

    #[test]
    fn test_issue_with_custom_claims() {
        let mgr = default_manager();
        let mut extra = HashMap::new();
        extra.insert("role".to_string(), "admin".to_string());
        let token = mgr.issue_token("user-1", Some(&extra)).unwrap();
        let decoded = mgr.validate_token(&token).unwrap();
        assert_eq!(decoded.subject, "user-1");
    }

    #[test]
    fn test_issue_with_audience() {
        let config = PasetoConfig {
            audience: Some("https://api.example.com".to_string()),
            ..PasetoConfig::default()
        };
        let mgr = PasetoLocalManager::new(config).unwrap();
        let token = mgr.issue_token("user-1", None).unwrap();
        let decoded = mgr.validate_token(&token).unwrap();
        assert_eq!(decoded.audience.as_deref(), Some("https://api.example.com"));
    }

    #[test]
    fn test_reject_empty_subject() {
        let mgr = default_manager();
        assert!(mgr.issue_token("", None).is_err());
    }

    #[test]
    fn test_reject_wrong_prefix() {
        let mgr = default_manager();
        assert!(mgr.validate_token("v4.public.garbage").is_err());
    }

    #[test]
    fn test_reject_tampered_token() {
        let mgr = default_manager();
        let token = mgr.issue_token("user-1", None).unwrap();
        let tampered = format!("{}tampered", token);
        assert!(mgr.validate_token(&tampered).is_err());
    }

    #[test]
    fn test_different_keys_reject() {
        let mgr1 = default_manager();
        let mgr2 = default_manager();
        let token = mgr1.issue_token("user-1", None).unwrap();
        assert!(mgr2.validate_token(&token).is_err());
    }

    #[test]
    fn test_from_key_bytes_roundtrip() {
        let key_bytes = [42u8; 32];
        let config = PasetoConfig::default();
        let mgr = PasetoLocalManager::from_key_bytes(config.clone(), &key_bytes).unwrap();
        let token = mgr.issue_token("user-1", None).unwrap();
        let mgr2 = PasetoLocalManager::from_key_bytes(config, &key_bytes).unwrap();
        let decoded = mgr2.validate_token(&token).unwrap();
        assert_eq!(decoded.subject, "user-1");
    }

    #[test]
    fn test_issuer_mismatch_rejected() {
        let key_bytes = [99u8; 32];
        let cfg_a = PasetoConfig {
            issuer: "server-a".to_string(),
            ..PasetoConfig::default()
        };
        let cfg_b = PasetoConfig {
            issuer: "server-b".to_string(),
            ..PasetoConfig::default()
        };
        let mgr_a = PasetoLocalManager::from_key_bytes(cfg_a, &key_bytes).unwrap();
        let mgr_b = PasetoLocalManager::from_key_bytes(cfg_b, &key_bytes).unwrap();
        let token = mgr_a.issue_token("user-1", None).unwrap();
        assert!(mgr_b.validate_token(&token).is_err());
    }

    #[test]
    fn test_with_footer() {
        let config = PasetoConfig {
            footer: Some("key-id:v1".to_string()),
            ..PasetoConfig::default()
        };
        let mgr = PasetoLocalManager::new(config).unwrap();
        let token = mgr.issue_token("user-1", None).unwrap();
        let decoded = mgr.validate_token(&token).unwrap();
        assert_eq!(decoded.subject, "user-1");
    }

    #[test]
    fn test_footer_mismatch_rejected() {
        let key_bytes = [77u8; 32];
        let cfg1 = PasetoConfig {
            footer: Some("footer-a".to_string()),
            ..PasetoConfig::default()
        };
        let cfg2 = PasetoConfig {
            footer: Some("footer-b".to_string()),
            ..PasetoConfig::default()
        };
        let mgr1 = PasetoLocalManager::from_key_bytes(cfg1, &key_bytes).unwrap();
        let mgr2 = PasetoLocalManager::from_key_bytes(cfg2, &key_bytes).unwrap();
        let token = mgr1.issue_token("user-1", None).unwrap();
        assert!(mgr2.validate_token(&token).is_err());
    }

    #[test]
    fn test_generate_local_key_hex() {
        let key1 = generate_local_key_hex().unwrap();
        let key2 = generate_local_key_hex().unwrap();
        assert_eq!(key1.len(), 64);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_default_config() {
        let config = PasetoConfig::default();
        assert_eq!(config.issuer, "auth-framework");
        assert_eq!(config.token_lifetime, Duration::from_secs(3600));
        assert!(config.audience.is_none());
        assert!(config.footer.is_none());
    }
}
