//! Sign-In with Ethereum (SIWE / ERC-4361) support.
//!
//! Provides message construction, parsing, and validation for the
//! ERC-4361 standard which allows Ethereum account holders to authenticate
//! with off-chain services by signing a structured message.
//!
//! # References
//!
//! - [ERC-4361: Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361)

use crate::errors::{AuthError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A SIWE message conforming to ERC-4361.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiweMessage {
    /// RFC 4501 `dns` authority (e.g., "example.com").
    pub domain: String,
    /// Ethereum address performing the signing (EIP-55 mixed-case).
    pub address: String,
    /// Human-readable statement (optional).
    pub statement: Option<String>,
    /// RFC 3986 URI for the signing request.
    pub uri: String,
    /// EIP-155 Chain ID (1 = mainnet).
    pub chain_id: u64,
    /// Random nonce to prevent replay attacks.
    pub nonce: String,
    /// ISO 8601 datetime when the message was issued.
    pub issued_at: DateTime<Utc>,
    /// ISO 8601 datetime when the message expires (optional).
    pub expiration_time: Option<DateTime<Utc>>,
    /// ISO 8601 datetime before which the message is not valid (optional).
    pub not_before: Option<DateTime<Utc>>,
    /// System-specific request ID (optional).
    pub request_id: Option<String>,
    /// List of resources the user wishes to access (optional).
    pub resources: Vec<String>,
    /// ERC-4361 version ("1").
    pub version: String,
}

impl SiweMessage {
    /// Create a new SIWE message with required fields.
    pub fn new(domain: &str, address: &str, uri: &str, chain_id: u64) -> Result<Self> {
        validate_address(address)?;
        if domain.is_empty() {
            return Err(AuthError::validation("Domain cannot be empty"));
        }
        if uri.is_empty() {
            return Err(AuthError::validation("URI cannot be empty"));
        }
        let nonce = generate_nonce()?;
        Ok(Self {
            domain: domain.to_string(),
            address: address.to_string(),
            statement: None,
            uri: uri.to_string(),
            chain_id,
            nonce,
            issued_at: Utc::now(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
            version: "1".to_string(),
        })
    }

    /// Render the SIWE message to the ERC-4361 plaintext signing format.
    pub fn to_message_string(&self) -> String {
        let mut msg = format!(
            "{domain} wants you to sign in with your Ethereum account:\n\
             {address}\n",
            domain = self.domain,
            address = self.address,
        );

        if let Some(ref stmt) = self.statement {
            msg.push('\n');
            msg.push_str(stmt);
            msg.push('\n');
        }

        msg.push_str(&format!(
            "\nURI: {uri}\n\
             Version: {ver}\n\
             Chain ID: {chain}\n\
             Nonce: {nonce}\n\
             Issued At: {iat}",
            uri = self.uri,
            ver = self.version,
            chain = self.chain_id,
            nonce = self.nonce,
            iat = self.issued_at.to_rfc3339(),
        ));

        if let Some(ref exp) = self.expiration_time {
            msg.push_str(&format!("\nExpiration Time: {}", exp.to_rfc3339()));
        }
        if let Some(ref nb) = self.not_before {
            msg.push_str(&format!("\nNot Before: {}", nb.to_rfc3339()));
        }
        if let Some(ref rid) = self.request_id {
            msg.push_str(&format!("\nRequest ID: {}", rid));
        }
        if !self.resources.is_empty() {
            msg.push_str("\nResources:");
            for r in &self.resources {
                msg.push_str(&format!("\n- {}", r));
            }
        }

        msg
    }

    /// Compute the EIP-191 hash of the message (SHA-256 for verification).
    pub fn message_hash(&self) -> [u8; 32] {
        let msg = self.to_message_string();
        let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg);
        Sha256::digest(prefixed.as_bytes()).into()
    }
}

/// Parse a SIWE plaintext message string back into a `SiweMessage`.
pub fn parse_siwe_message(text: &str) -> Result<SiweMessage> {
    let lines: Vec<&str> = text.lines().collect();

    if lines.len() < 7 {
        return Err(AuthError::validation("SIWE message has too few lines"));
    }

    // Line 0: "{domain} wants you to sign in with your Ethereum account:"
    let domain = lines[0]
        .strip_suffix(" wants you to sign in with your Ethereum account:")
        .ok_or_else(|| AuthError::validation("Missing SIWE preamble"))?
        .to_string();

    // Line 1: address
    let address = lines[1].trim().to_string();
    validate_address(&address)?;

    // Find field lines
    let mut statement = None;
    let mut uri = String::new();
    let mut version = String::new();
    let mut chain_id: u64 = 1;
    let mut nonce = String::new();
    let mut issued_at = Utc::now();
    let mut expiration_time = None;
    let mut not_before = None;
    let mut request_id = None;
    let mut resources = Vec::new();
    let mut in_resources = false;

    for line in &lines[2..] {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if in_resources {
            if let Some(r) = line.strip_prefix("- ") {
                resources.push(r.to_string());
                continue;
            }
            in_resources = false;
        }

        if let Some(v) = line.strip_prefix("URI: ") {
            uri = v.to_string();
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version = v.to_string();
        } else if let Some(v) = line.strip_prefix("Chain ID: ") {
            chain_id = v.parse().unwrap_or(1);
        } else if let Some(v) = line.strip_prefix("Nonce: ") {
            nonce = v.to_string();
        } else if let Some(v) = line.strip_prefix("Issued At: ") {
            issued_at = DateTime::parse_from_rfc3339(v)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
        } else if let Some(v) = line.strip_prefix("Expiration Time: ") {
            expiration_time = DateTime::parse_from_rfc3339(v)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
        } else if let Some(v) = line.strip_prefix("Not Before: ") {
            not_before = DateTime::parse_from_rfc3339(v)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
        } else if let Some(v) = line.strip_prefix("Request ID: ") {
            request_id = Some(v.to_string());
        } else if line == "Resources:" {
            in_resources = true;
        } else if statement.is_none() && !line.starts_with("URI:") && !line.starts_with("Version:")
        {
            statement = Some(line.to_string());
        }
    }

    Ok(SiweMessage {
        domain,
        address,
        statement,
        uri,
        chain_id,
        nonce,
        issued_at,
        expiration_time,
        not_before,
        request_id,
        resources,
        version,
    })
}

/// Verify the SIWE message fields are valid (time constraints, nonce, etc.).
///
/// **Note:** Signature verification against the Ethereum address requires
/// an ECC library (secp256k1). This function validates the message structure
/// and time windows only.
pub fn verify_siwe_message(
    msg: &SiweMessage,
    expected_domain: &str,
    expected_nonce: Option<&str>,
) -> Result<()> {
    if msg.domain != expected_domain {
        return Err(AuthError::validation("Domain mismatch"));
    }

    if let Some(expected) = expected_nonce {
        if msg.nonce != expected {
            return Err(AuthError::validation("Nonce mismatch"));
        }
    }

    let now = Utc::now();
    if let Some(ref exp) = msg.expiration_time {
        if &now > exp {
            return Err(AuthError::validation("SIWE message has expired"));
        }
    }
    if let Some(ref nb) = msg.not_before {
        if &now < nb {
            return Err(AuthError::validation("SIWE message is not yet valid"));
        }
    }

    validate_address(&msg.address)?;

    Ok(())
}

/// Basic Ethereum address validation (EIP-55 format: 0x + 40 hex chars).
fn validate_address(address: &str) -> Result<()> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(AuthError::validation(
            "Invalid Ethereum address: must be 0x followed by 40 hex characters",
        ));
    }
    if !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthError::validation(
            "Invalid Ethereum address: contains non-hex characters",
        ));
    }
    Ok(())
}

/// Generate a cryptographically random 16-byte nonce (hex-encoded).
fn generate_nonce() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf)
        .map_err(|_| AuthError::crypto("Failed to generate nonce".to_string()))?;
    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const TEST_ADDR: &str = "0xAb5801a7D398351b8bE11C439e05C5b3259aec9B";

    #[test]
    fn test_create_siwe_message() {
        let msg =
            SiweMessage::new("example.com", TEST_ADDR, "https://example.com/login", 1).unwrap();
        assert_eq!(msg.domain, "example.com");
        assert_eq!(msg.address, TEST_ADDR);
        assert_eq!(msg.version, "1");
        assert_eq!(msg.chain_id, 1);
        assert!(!msg.nonce.is_empty());
    }

    #[test]
    fn test_empty_domain_rejected() {
        assert!(SiweMessage::new("", TEST_ADDR, "https://example.com", 1).is_err());
    }

    #[test]
    fn test_invalid_address_rejected() {
        assert!(
            SiweMessage::new("example.com", "not-an-address", "https://example.com", 1).is_err()
        );
        assert!(SiweMessage::new("example.com", "0xZZZZ", "https://example.com", 1).is_err());
    }

    #[test]
    fn test_message_string_format() {
        let msg =
            SiweMessage::new("example.com", TEST_ADDR, "https://example.com/login", 1).unwrap();
        let text = msg.to_message_string();
        assert!(text.contains("example.com wants you to sign in with your Ethereum account:"));
        assert!(text.contains(TEST_ADDR));
        assert!(text.contains("URI: https://example.com/login"));
        assert!(text.contains("Version: 1"));
        assert!(text.contains("Chain ID: 1"));
        assert!(text.contains("Nonce: "));
    }

    #[test]
    fn test_message_string_with_statement() {
        let mut msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        msg.statement = Some("I accept the Terms of Service".to_string());
        let text = msg.to_message_string();
        assert!(text.contains("I accept the Terms of Service"));
    }

    #[test]
    fn test_message_string_with_resources() {
        let mut msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        msg.resources = vec![
            "https://example.com/resource1".to_string(),
            "https://example.com/resource2".to_string(),
        ];
        let text = msg.to_message_string();
        assert!(text.contains("Resources:"));
        assert!(text.contains("- https://example.com/resource1"));
        assert!(text.contains("- https://example.com/resource2"));
    }

    #[test]
    fn test_parse_siwe_message_roundtrip() {
        let msg =
            SiweMessage::new("example.com", TEST_ADDR, "https://example.com/login", 1).unwrap();
        let text = msg.to_message_string();
        let parsed = parse_siwe_message(&text).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.address, TEST_ADDR);
        assert_eq!(parsed.uri, "https://example.com/login");
        assert_eq!(parsed.chain_id, 1);
        assert_eq!(parsed.nonce, msg.nonce);
    }

    #[test]
    fn test_verify_valid_message() {
        let msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        let nonce = msg.nonce.clone();
        verify_siwe_message(&msg, "example.com", Some(&nonce)).unwrap();
    }

    #[test]
    fn test_verify_domain_mismatch() {
        let msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        assert!(verify_siwe_message(&msg, "other.com", None).is_err());
    }

    #[test]
    fn test_verify_nonce_mismatch() {
        let msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        assert!(verify_siwe_message(&msg, "example.com", Some("wrong-nonce")).is_err());
    }

    #[test]
    fn test_verify_expired_message() {
        let mut msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        msg.expiration_time = Some(Utc::now() - Duration::hours(1));
        assert!(verify_siwe_message(&msg, "example.com", None).is_err());
    }

    #[test]
    fn test_verify_not_yet_valid() {
        let mut msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        msg.not_before = Some(Utc::now() + Duration::hours(1));
        assert!(verify_siwe_message(&msg, "example.com", None).is_err());
    }

    #[test]
    fn test_message_hash_deterministic() {
        let msg = SiweMessage::new("example.com", TEST_ADDR, "https://example.com", 1).unwrap();
        let h1 = msg.message_hash();
        let h2 = msg.message_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_validate_address_formats() {
        assert!(validate_address("0xAb5801a7D398351b8bE11C439e05C5b3259aec9B").is_ok());
        assert!(validate_address("0x0000000000000000000000000000000000000000").is_ok());
        assert!(validate_address("Ab5801a7D398351b8bE11C439e05C5b3259aec9B").is_err()); // missing 0x
        assert!(validate_address("0xAb5801").is_err()); // too short
    }
}
