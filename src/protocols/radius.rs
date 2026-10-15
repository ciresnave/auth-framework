//! RADIUS (RFC 2865 / RFC 2866) — Remote Authentication Dial-In User Service
//!
//! Provides a RADIUS client for authenticating users against a RADIUS server
//! (e.g. FreeRADIUS, Microsoft NPS, Cisco ISE). Supports Access-Request /
//! Access-Accept / Access-Reject / Access-Challenge flows and basic
//! accounting (RFC 2866).
//!
//! # Protocol Overview
//!
//! RADIUS uses UDP with a shared secret for packet authentication.
//! The authenticator field is an MD5 hash that binds the request/response
//! to the shared secret, providing integrity (but not confidentiality
//! unless RadSec / TLS is used).
//!
//! # Security Considerations
//!
//! - The shared secret must be strong (≥16 random bytes recommended)
//! - User-Password attribute is encrypted with MD5(secret + authenticator)
//! - Consider RadSec (RADIUS over TLS, RFC 6614) for transport security

use crate::errors::{AuthError, Result};
use md5::Digest;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// ─── Constants ───────────────────────────────────────────────────────────────

/// RADIUS packet type codes (RFC 2865 §4).
pub mod code {
    pub const ACCESS_REQUEST: u8 = 1;
    pub const ACCESS_ACCEPT: u8 = 2;
    pub const ACCESS_REJECT: u8 = 3;
    pub const ACCOUNTING_REQUEST: u8 = 4;
    pub const ACCOUNTING_RESPONSE: u8 = 5;
    pub const ACCESS_CHALLENGE: u8 = 11;
}

/// RADIUS attribute type codes (RFC 2865 §5).
pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const NAS_PORT: u8 = 5;
    pub const SERVICE_TYPE: u8 = 6;
    pub const FRAMED_PROTOCOL: u8 = 7;
    pub const FILTER_ID: u8 = 11;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const STATE: u8 = 24;
    pub const SESSION_TIMEOUT: u8 = 27;
    pub const CALLING_STATION_ID: u8 = 31;
    pub const NAS_IDENTIFIER: u8 = 32;
    pub const ACCT_STATUS_TYPE: u8 = 40;
    pub const ACCT_SESSION_ID: u8 = 44;
    pub const NAS_PORT_TYPE: u8 = 61;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

/// Maximum RADIUS packet size (RFC 2865 §3).
const MAX_PACKET_SIZE: usize = 4096;

/// RADIUS header length (code + id + length + authenticator).
const HEADER_LEN: usize = 20;

/// Authenticator field length.
const AUTHENTICATOR_LEN: usize = 16;

// ─── Configuration ───────────────────────────────────────────────────────────

/// RADIUS client configuration.
#[derive(Debug, Clone)]
pub struct RadiusConfig {
    /// RADIUS server address (host:port, default port 1812).
    pub server_addr: String,

    /// Shared secret between client and server.
    pub shared_secret: String,

    /// Request timeout.
    pub timeout: Duration,

    /// Number of retries on timeout.
    pub retries: u32,

    /// NAS-Identifier sent in requests.
    pub nas_identifier: String,

    /// Accounting server address (host:port, default port 1813).
    pub accounting_addr: Option<String>,
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:1812".into(),
            shared_secret: String::new(),
            timeout: Duration::from_secs(5),
            retries: 3,
            nas_identifier: "auth-framework".into(),
            accounting_addr: None,
        }
    }
}

impl RadiusConfig {
    /// Create a config with the two required fields pre-filled.
    ///
    /// All other fields are set to their [`Default`] values.
    /// Returns an error if `shared_secret` is shorter than 6 bytes
    /// (the minimum enforced by [`RadiusClient::new`]).
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::protocols::radius::RadiusConfig;
    ///
    /// let config = RadiusConfig::with_server("radius.corp:1812", "s3cret-key")?;
    /// ```
    pub fn with_server(
        server_addr: impl Into<String>,
        shared_secret: impl Into<String>,
    ) -> Result<Self> {
        let secret = shared_secret.into();
        if secret.len() < 6 {
            return Err(AuthError::config(
                "RADIUS shared_secret must be at least 6 bytes",
            ));
        }
        Ok(Self {
            server_addr: server_addr.into(),
            shared_secret: secret,
            ..Default::default()
        })
    }

    /// Create a config and override the default timeout and retries.
    ///
    /// # Example
    /// ```rust,ignore
    /// use std::time::Duration;
    /// use auth_framework::protocols::radius::RadiusConfig;
    ///
    /// let config = RadiusConfig::with_options(
    ///     "radius.corp:1812",
    ///     "s3cret-key",
    ///     Duration::from_secs(10),
    ///     5, // retries
    /// )?;
    /// ```
    pub fn with_options(
        server_addr: impl Into<String>,
        shared_secret: impl Into<String>,
        timeout: Duration,
        retries: u32,
    ) -> Result<Self> {
        let mut cfg = Self::with_server(server_addr, shared_secret)?;
        cfg.timeout = timeout;
        cfg.retries = retries;
        Ok(cfg)
    }
}

// ─── Data Types ──────────────────────────────────────────────────────────────

/// A RADIUS attribute (type-length-value).
#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attr_type: u8,
    pub value: Vec<u8>,
}

/// A RADIUS packet.
#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; AUTHENTICATOR_LEN],
    pub attributes: Vec<RadiusAttribute>,
}

impl RadiusPacket {
    /// Append an attribute to this packet.
    ///
    /// Uses the constants from [`attr`] for type safety.
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::protocols::radius::{RadiusPacket, attr, code};
    ///
    /// let mut packet = RadiusPacket {
    ///     code: code::ACCESS_REQUEST,
    ///     identifier: 1,
    ///     authenticator: [0u8; 16],
    ///     attributes: Vec::new(),
    /// };
    /// packet.add_attribute(attr::USER_NAME, b"alice");
    /// packet.add_attribute(attr::NAS_IDENTIFIER, b"my-nas");
    /// ```
    pub fn add_attribute(&mut self, attr_type: u8, value: impl AsRef<[u8]>) {
        self.attributes.push(RadiusAttribute {
            attr_type,
            value: value.as_ref().to_vec(),
        });
    }
}

/// Result of a RADIUS authentication attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusAuthResult {
    /// Whether authentication succeeded.
    pub accepted: bool,

    /// Reply message from the server (if any).
    pub reply_message: Option<String>,

    /// Session timeout returned by the server (seconds).
    pub session_timeout: Option<u32>,

    /// Filter ID for authorization.
    pub filter_id: Option<String>,

    /// Whether a challenge was issued (requires further interaction).
    pub challenge: bool,

    /// State attribute for challenge-response flows.
    pub state: Option<Vec<u8>>,

    /// All reply attributes as key-value pairs.
    pub reply_attributes: HashMap<u8, Vec<Vec<u8>>>,
}

// ─── Client ──────────────────────────────────────────────────────────────────

/// RADIUS authentication and accounting client.
#[derive(Debug)]
pub struct RadiusClient {
    config: RadiusConfig,
}

impl RadiusClient {
    /// Create a new RADIUS client.
    pub fn new(config: RadiusConfig) -> Result<Self> {
        if config.shared_secret.is_empty() {
            return Err(AuthError::config("RADIUS shared secret must not be empty"));
        }
        if config.shared_secret.len() < 6 {
            return Err(AuthError::config(
                "RADIUS shared secret should be at least 6 bytes",
            ));
        }
        Ok(Self { config })
    }

    /// Authenticate a user with username and password (PAP).
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<RadiusAuthResult> {
        self.authenticate_with_state(username, password, None).await
    }

    /// Authenticate with optional state (for challenge-response).
    pub async fn authenticate_with_state(
        &self,
        username: &str,
        password: &str,
        state: Option<&[u8]>,
    ) -> Result<RadiusAuthResult> {
        let rng = ring::rand::SystemRandom::new();
        let mut authenticator = [0u8; AUTHENTICATOR_LEN];
        rng.fill(&mut authenticator)
            .map_err(|_| AuthError::crypto("Failed to generate RADIUS authenticator"))?;

        let mut id_buf = [0u8; 1];
        rng.fill(&mut id_buf)
            .map_err(|_| AuthError::crypto("Failed to generate RADIUS identifier"))?;

        let mut packet = RadiusPacket {
            code: code::ACCESS_REQUEST,
            identifier: id_buf[0],
            authenticator,
            attributes: Vec::new(),
        };

        // User-Name
        packet.attributes.push(RadiusAttribute {
            attr_type: attr::USER_NAME,
            value: username.as_bytes().to_vec(),
        });

        // User-Password (PAP — RFC 2865 §5.2)
        let encrypted_password =
            encrypt_pap_password(password, &self.config.shared_secret, &authenticator);
        packet.attributes.push(RadiusAttribute {
            attr_type: attr::USER_PASSWORD,
            value: encrypted_password,
        });

        // NAS-Identifier
        packet.attributes.push(RadiusAttribute {
            attr_type: attr::NAS_IDENTIFIER,
            value: self.config.nas_identifier.as_bytes().to_vec(),
        });

        // State (for challenge-response continuation)
        if let Some(state_val) = state {
            packet.attributes.push(RadiusAttribute {
                attr_type: attr::STATE,
                value: state_val.to_vec(),
            });
        }

        // Message-Authenticator (RFC 3579 §3.2)
        let msg_auth =
            compute_message_authenticator(&packet, self.config.shared_secret.as_bytes())?;
        packet.attributes.push(RadiusAttribute {
            attr_type: attr::MESSAGE_AUTHENTICATOR,
            value: msg_auth.to_vec(),
        });

        let response = self.send_request(&packet).await?;
        self.parse_response(&response, &authenticator)
    }

    /// Send an accounting start/stop/update request.
    pub async fn send_accounting(
        &self,
        username: &str,
        session_id: &str,
        status_type: u32,
    ) -> Result<bool> {
        let addr = self
            .config
            .accounting_addr
            .as_deref()
            .unwrap_or("127.0.0.1:1813");

        let rng = ring::rand::SystemRandom::new();
        let mut authenticator = [0u8; AUTHENTICATOR_LEN];
        rng.fill(&mut authenticator)
            .map_err(|_| AuthError::crypto("Failed to generate RADIUS authenticator"))?;

        let mut id_buf = [0u8; 1];
        rng.fill(&mut id_buf)
            .map_err(|_| AuthError::crypto("Failed to generate RADIUS identifier"))?;

        let mut packet = RadiusPacket {
            code: code::ACCOUNTING_REQUEST,
            identifier: id_buf[0],
            authenticator,
            attributes: Vec::new(),
        };

        packet.attributes.push(RadiusAttribute {
            attr_type: attr::USER_NAME,
            value: username.as_bytes().to_vec(),
        });

        packet.attributes.push(RadiusAttribute {
            attr_type: attr::ACCT_SESSION_ID,
            value: session_id.as_bytes().to_vec(),
        });

        packet.attributes.push(RadiusAttribute {
            attr_type: attr::ACCT_STATUS_TYPE,
            value: status_type.to_be_bytes().to_vec(),
        });

        packet.attributes.push(RadiusAttribute {
            attr_type: attr::NAS_IDENTIFIER,
            value: self.config.nas_identifier.as_bytes().to_vec(),
        });

        // Accounting-Request authenticator is computed differently (RFC 2866 §3)
        let encoded = encode_packet(&packet);
        let acct_auth =
            compute_accounting_authenticator(&encoded, self.config.shared_secret.as_bytes());
        let mut final_packet = packet;
        final_packet.authenticator = acct_auth;

        let response = self
            .send_packet(&encode_packet(&final_packet), addr)
            .await?;
        Ok(response[0] == code::ACCOUNTING_RESPONSE)
    }

    /// Send a RADIUS request and receive the response.
    async fn send_request(&self, packet: &RadiusPacket) -> Result<Vec<u8>> {
        let encoded = encode_packet(packet);
        self.send_packet(&encoded, &self.config.server_addr).await
    }

    /// Low-level packet send/receive over UDP.
    async fn send_packet(&self, data: &[u8], addr: &str) -> Result<Vec<u8>> {
        let server_addr: SocketAddr = addr
            .parse()
            .map_err(|e| AuthError::config(format!("Invalid RADIUS server address: {e}")))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| AuthError::internal(format!("Failed to bind UDP socket: {e}")))?;

        for attempt in 0..=self.config.retries {
            socket
                .send_to(data, server_addr)
                .await
                .map_err(|e| AuthError::internal(format!("RADIUS send failed: {e}")))?;

            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            match tokio::time::timeout(self.config.timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => return Ok(buf[..len].to_vec()),
                Ok(Err(e)) => {
                    return Err(AuthError::internal(format!("RADIUS recv failed: {e}")));
                }
                Err(_) if attempt < self.config.retries => continue,
                Err(_) => {
                    return Err(AuthError::internal("RADIUS request timed out"));
                }
            }
        }

        Err(AuthError::internal("RADIUS request failed after retries"))
    }

    /// Parse a RADIUS response packet.
    fn parse_response(
        &self,
        data: &[u8],
        request_authenticator: &[u8; AUTHENTICATOR_LEN],
    ) -> Result<RadiusAuthResult> {
        if data.len() < HEADER_LEN {
            return Err(AuthError::validation("RADIUS response too short"));
        }

        let response_code = data[0];
        let _identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if length > data.len() {
            return Err(AuthError::validation("RADIUS response length mismatch"));
        }

        // Verify response authenticator (RFC 2865 §3)
        let expected_auth = compute_response_authenticator(
            data,
            request_authenticator,
            self.config.shared_secret.as_bytes(),
        );
        let actual_auth = &data[4..20];
        if !constant_time_eq(actual_auth, &expected_auth) {
            return Err(AuthError::validation(
                "RADIUS response authenticator verification failed",
            ));
        }

        // Parse attributes
        let mut reply_attributes: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
        let mut pos = HEADER_LEN;
        while pos + 2 <= length {
            let attr_type = data[pos];
            let attr_len = data[pos + 1] as usize;
            if attr_len < 2 || pos + attr_len > length {
                break;
            }
            let value = data[pos + 2..pos + attr_len].to_vec();
            reply_attributes.entry(attr_type).or_default().push(value);
            pos += attr_len;
        }

        let reply_message = reply_attributes
            .get(&attr::REPLY_MESSAGE)
            .and_then(|v| v.first())
            .and_then(|b| String::from_utf8(b.clone()).ok());

        let session_timeout = reply_attributes
            .get(&attr::SESSION_TIMEOUT)
            .and_then(|v| v.first())
            .and_then(|b| {
                if b.len() == 4 {
                    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                } else {
                    None
                }
            });

        let filter_id = reply_attributes
            .get(&attr::FILTER_ID)
            .and_then(|v| v.first())
            .and_then(|b| String::from_utf8(b.clone()).ok());

        let state = reply_attributes
            .get(&attr::STATE)
            .and_then(|v| v.first())
            .cloned();

        Ok(RadiusAuthResult {
            accepted: response_code == code::ACCESS_ACCEPT,
            reply_message,
            session_timeout,
            filter_id,
            challenge: response_code == code::ACCESS_CHALLENGE,
            state,
            reply_attributes,
        })
    }
}

// ─── Packet Encoding / Crypto ────────────────────────────────────────────────

/// Encode a RADIUS packet to bytes.
fn encode_packet(packet: &RadiusPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAX_PACKET_SIZE);

    // Header placeholder (will set length after attributes)
    buf.push(packet.code);
    buf.push(packet.identifier);
    buf.extend_from_slice(&[0, 0]); // length placeholder
    buf.extend_from_slice(&packet.authenticator);

    // Attributes
    for attr in &packet.attributes {
        let attr_len = (2 + attr.value.len()) as u8;
        buf.push(attr.attr_type);
        buf.push(attr_len);
        buf.extend_from_slice(&attr.value);
    }

    // Set length
    let len = buf.len() as u16;
    buf[2..4].copy_from_slice(&len.to_be_bytes());

    buf
}

/// Encrypt a password using PAP (RFC 2865 §5.2).
///
/// c[0] = p[0] XOR MD5(S + RA)
/// c[i] = p[i] XOR MD5(S + c[i-1])
fn encrypt_pap_password(
    password: &str,
    shared_secret: &str,
    authenticator: &[u8; AUTHENTICATOR_LEN],
) -> Vec<u8> {
    let pwd_bytes = password.as_bytes();
    // Pad to 16-byte boundary
    let padded_len = pwd_bytes.len().div_ceil(16) * 16;
    let padded_len = padded_len.max(16);
    let mut padded = vec![0u8; padded_len];
    padded[..pwd_bytes.len()].copy_from_slice(pwd_bytes);

    let mut result = vec![0u8; padded_len];
    let mut prev_block = authenticator.to_vec();

    for i in 0..(padded_len / 16) {
        let hasher = md5_hash(shared_secret.as_bytes(), &prev_block);
        let chunk_start = i * 16;
        for j in 0..16 {
            result[chunk_start + j] = padded[chunk_start + j] ^ hasher[j];
        }
        prev_block = result[chunk_start..chunk_start + 16].to_vec();
    }

    result
}

/// Compute MD5(a || b) per RFC 2865.
fn md5_hash(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Compute the Message-Authenticator HMAC-MD5 (RFC 3579 §3.2).
fn compute_message_authenticator(packet: &RadiusPacket, secret: &[u8]) -> Result<[u8; 16]> {
    // The Message-Authenticator is HMAC-MD5 over the entire packet
    // with the Message-Authenticator field set to 16 zero bytes.
    let mut temp_packet = packet.clone();
    // Remove any existing Message-Authenticator
    temp_packet
        .attributes
        .retain(|a| a.attr_type != attr::MESSAGE_AUTHENTICATOR);
    // Add placeholder
    temp_packet.attributes.push(RadiusAttribute {
        attr_type: attr::MESSAGE_AUTHENTICATOR,
        value: vec![0u8; 16],
    });

    let encoded = encode_packet(&temp_packet);
    let hmac_result = hmac_md5_truncated(secret, &encoded);
    Ok(hmac_result)
}

/// Compute HMAC-MD5 for Message-Authenticator (RFC 3579 §3.2).
fn hmac_md5_truncated(key: &[u8], data: &[u8]) -> [u8; 16] {
    use hmac::Mac;
    type HmacMd5 = hmac::Hmac<md5::Md5>;
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Compute response authenticator (RFC 2865 §3).
///
/// ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
fn compute_response_authenticator(
    response: &[u8],
    request_auth: &[u8; AUTHENTICATOR_LEN],
    secret: &[u8],
) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(&response[..4]); // Code, ID, Length
    hasher.update(request_auth); // RequestAuth (not ResponseAuth)
    if response.len() > HEADER_LEN {
        hasher.update(&response[HEADER_LEN..]); // Attributes
    }
    hasher.update(secret);
    hasher.finalize().into()
}

/// Compute accounting request authenticator (RFC 2866 §3).
fn compute_accounting_authenticator(packet_bytes: &[u8], secret: &[u8]) -> [u8; AUTHENTICATOR_LEN] {
    let mut hasher = md5::Md5::new();
    hasher.update(&packet_bytes[..4]); // Code, ID, Length
    hasher.update([0u8; AUTHENTICATOR_LEN]); // Zero authenticator
    if packet_bytes.len() > HEADER_LEN {
        hasher.update(&packet_bytes[HEADER_LEN..]); // Attributes
    }
    hasher.update(secret);
    hasher.finalize().into()
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RadiusConfig::default();
        assert_eq!(config.server_addr, "127.0.0.1:1812");
        assert_eq!(config.retries, 3);
    }

    #[test]
    fn test_client_requires_secret() {
        let config = RadiusConfig::default();
        let err = RadiusClient::new(config).unwrap_err();
        assert!(err.to_string().contains("secret"));
    }

    #[test]
    fn test_client_rejects_short_secret() {
        let config = RadiusConfig {
            shared_secret: "abc".into(),
            ..Default::default()
        };
        let err = RadiusClient::new(config).unwrap_err();
        assert!(err.to_string().contains("6 bytes"));
    }

    #[test]
    fn test_client_creation() {
        let config = RadiusConfig {
            shared_secret: "testing123".into(),
            ..Default::default()
        };
        assert!(RadiusClient::new(config).is_ok());
    }

    #[test]
    fn test_packet_encoding() {
        let packet = RadiusPacket {
            code: code::ACCESS_REQUEST,
            identifier: 42,
            authenticator: [0u8; AUTHENTICATOR_LEN],
            attributes: vec![RadiusAttribute {
                attr_type: attr::USER_NAME,
                value: b"test".to_vec(),
            }],
        };

        let encoded = encode_packet(&packet);
        assert_eq!(encoded[0], code::ACCESS_REQUEST);
        assert_eq!(encoded[1], 42);
        let length = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(length as usize, encoded.len());
    }

    #[test]
    fn test_pap_password_encryption() {
        let auth = [1u8; AUTHENTICATOR_LEN];
        let encrypted = encrypt_pap_password("password", "secret", &auth);
        assert_eq!(encrypted.len(), 16); // padded to 16 bytes
        // Encrypted should not be the plaintext
        assert_ne!(&encrypted[..8], b"password");
    }

    #[test]
    fn test_radius_attribute_codes() {
        assert_eq!(attr::USER_NAME, 1);
        assert_eq!(attr::USER_PASSWORD, 2);
        assert_eq!(attr::MESSAGE_AUTHENTICATOR, 80);
    }

    #[test]
    fn test_radius_config_with_server() {
        let config = RadiusConfig::with_server("10.0.0.1:1812", "testing123").unwrap();
        assert_eq!(config.server_addr, "10.0.0.1:1812");
        assert_eq!(config.shared_secret, "testing123");
        assert_eq!(config.retries, 3); // default
    }

    #[test]
    fn test_radius_config_with_server_rejects_short_secret() {
        let err = RadiusConfig::with_server("10.0.0.1:1812", "abc").unwrap_err();
        assert!(err.to_string().contains("6 bytes"));
    }

    #[test]
    fn test_radius_config_with_options() {
        let config =
            RadiusConfig::with_options("10.0.0.1:1812", "testing123", Duration::from_secs(10), 5)
                .unwrap();
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.retries, 5);
    }

    #[test]
    fn test_radius_packet_add_attribute() {
        let mut packet = RadiusPacket {
            code: code::ACCESS_REQUEST,
            identifier: 1,
            authenticator: [0u8; AUTHENTICATOR_LEN],
            attributes: Vec::new(),
        };
        packet.add_attribute(attr::USER_NAME, b"alice");
        packet.add_attribute(attr::NAS_IDENTIFIER, b"my-nas");

        assert_eq!(packet.attributes.len(), 2);
        assert_eq!(packet.attributes[0].attr_type, attr::USER_NAME);
        assert_eq!(packet.attributes[0].value, b"alice");
        assert_eq!(packet.attributes[1].attr_type, attr::NAS_IDENTIFIER);
    }
}
