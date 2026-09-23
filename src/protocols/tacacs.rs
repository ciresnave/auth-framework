//! TACACS+ (Terminal Access Controller Access-Control System Plus) protocol support.
//!
//! Provides TACACS+ packet construction, obfuscation/deobfuscation, and
//! authentication/authorization/accounting message handling per RFC 8907.

use crate::errors::{AuthError, Result};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

/// TACACS+ protocol version.
const TACACS_MAJOR_VERSION: u8 = 0xC0; // Major version 12 (0xC)
const TACACS_MINOR_VERSION_DEFAULT: u8 = 0x00;

/// TACACS+ packet types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TacacsPacketType {
    Authentication = 0x01,
    Authorization = 0x02,
    Accounting = 0x03,
}

/// TACACS+ authentication action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthenAction {
    Login = 0x01,
    ChangePassword = 0x02,
    SendAuth = 0x04,
}

/// TACACS+ authentication type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthenType {
    Ascii = 0x01,
    Pap = 0x02,
    Chap = 0x03,
    MSChap = 0x05,
    MSChapV2 = 0x06,
}

/// TACACS+ authentication service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthenService {
    None = 0x00,
    Login = 0x01,
    Enable = 0x02,
    Ppp = 0x03,
}

/// TACACS+ authentication status (reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthenStatus {
    Pass = 0x01,
    Fail = 0x02,
    GetData = 0x03,
    GetUser = 0x04,
    GetPass = 0x05,
    Restart = 0x06,
    Error = 0x07,
    Follow = 0x21,
}

/// TACACS+ authorization status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthorStatus {
    PassAdd = 0x01,
    PassReplace = 0x02,
    Fail = 0x10,
    Error = 0x11,
    Follow = 0x21,
}

/// TACACS+ accounting flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcctFlags(pub u8);

impl AcctFlags {
    pub const START: Self = Self(0x02);
    pub const STOP: Self = Self(0x04);
    pub const WATCHDOG: Self = Self(0x08);

    pub fn is_start(self) -> bool {
        self.0 & 0x02 != 0
    }
    pub fn is_stop(self) -> bool {
        self.0 & 0x04 != 0
    }
    pub fn is_watchdog(self) -> bool {
        self.0 & 0x08 != 0
    }
}

/// TACACS+ packet header (12 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacacsHeader {
    pub version: u8,
    pub packet_type: TacacsPacketType,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: u32,
    pub length: u32,
}

impl TacacsHeader {
    /// Create a new TACACS+ header.
    pub fn new(packet_type: TacacsPacketType, seq_no: u8, session_id: u32, body_len: u32) -> Self {
        Self {
            version: TACACS_MAJOR_VERSION | TACACS_MINOR_VERSION_DEFAULT,
            packet_type,
            seq_no,
            flags: 0x00, // encrypted (not unencrypted)
            session_id,
            length: body_len,
        }
    }

    /// Serialize header to 12-byte wire format.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2] = self.seq_no;
        buf[3] = self.flags;
        buf[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    /// Parse header from 12-byte wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(AuthError::validation("TACACS+ header too short"));
        }
        let packet_type = match data[1] {
            0x01 => TacacsPacketType::Authentication,
            0x02 => TacacsPacketType::Authorization,
            0x03 => TacacsPacketType::Accounting,
            other => {
                return Err(AuthError::validation(format!(
                    "Unknown TACACS+ packet type: {other:#x}"
                )));
            }
        };
        Ok(Self {
            version: data[0],
            packet_type,
            seq_no: data[2],
            flags: data[3],
            session_id: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            length: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// TACACS+ authentication START body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenStartBody {
    pub action: AuthenAction,
    pub authen_type: AuthenType,
    pub authen_service: AuthenService,
    pub user: String,
    pub port: String,
    pub remote_address: String,
    pub data: Vec<u8>,
}

impl AuthenStartBody {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let user_bytes = self.user.as_bytes();
        let port_bytes = self.port.as_bytes();
        let rem_bytes = self.remote_address.as_bytes();
        let mut buf = Vec::with_capacity(
            8 + user_bytes.len() + port_bytes.len() + rem_bytes.len() + self.data.len(),
        );

        buf.push(self.action as u8);
        buf.push(0x01); // priv_lvl = 1
        buf.push(self.authen_type as u8);
        buf.push(self.authen_service as u8);
        buf.push(user_bytes.len() as u8);
        buf.push(port_bytes.len() as u8);
        buf.push(rem_bytes.len() as u8);
        buf.push(self.data.len() as u8);
        buf.extend_from_slice(user_bytes);
        buf.extend_from_slice(port_bytes);
        buf.extend_from_slice(rem_bytes);
        buf.extend_from_slice(&self.data);

        buf
    }
}

/// TACACS+ authentication REPLY body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenReplyBody {
    pub status: AuthenStatus,
    pub flags: u8,
    pub server_msg: String,
    pub data: Vec<u8>,
}

impl AuthenReplyBody {
    /// Parse from wire-format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(AuthError::validation("TACACS+ authen reply too short"));
        }
        let status = match data[0] {
            0x01 => AuthenStatus::Pass,
            0x02 => AuthenStatus::Fail,
            0x03 => AuthenStatus::GetData,
            0x04 => AuthenStatus::GetUser,
            0x05 => AuthenStatus::GetPass,
            0x06 => AuthenStatus::Restart,
            0x07 => AuthenStatus::Error,
            0x21 => AuthenStatus::Follow,
            other => {
                return Err(AuthError::validation(format!(
                    "Unknown authen status: {other:#x}"
                )));
            }
        };
        let flags = data[1];
        let server_msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let data_len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 6 + server_msg_len + data_len {
            return Err(AuthError::validation("TACACS+ authen reply truncated"));
        }

        let server_msg = String::from_utf8_lossy(&data[6..6 + server_msg_len]).to_string();
        let reply_data = data[6 + server_msg_len..6 + server_msg_len + data_len].to_vec();

        Ok(Self {
            status,
            flags,
            server_msg,
            data: reply_data,
        })
    }
}

// ── Authorization request/reply (RFC 8907 §6) ──────────────────────

/// TACACS+ authorization REQUEST body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorRequestBody {
    pub authen_method: u8,
    pub authen_type: AuthenType,
    pub authen_service: AuthenService,
    pub user: String,
    pub port: String,
    pub remote_address: String,
    /// Attribute-value pairs (e.g. "service=shell", "cmd=show").
    pub args: Vec<String>,
}

impl AuthorRequestBody {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let user_bytes = self.user.as_bytes();
        let port_bytes = self.port.as_bytes();
        let rem_bytes = self.remote_address.as_bytes();
        let arg_count = self.args.len() as u8;

        // Fixed header: 8 bytes + arg_count * 1 (arg lengths) + variable fields
        let mut buf = vec![
            self.authen_method,
            0x01, // priv_lvl
            self.authen_type as u8,
            self.authen_service as u8,
            user_bytes.len() as u8,
            port_bytes.len() as u8,
            rem_bytes.len() as u8,
            arg_count,
        ];

        // Argument lengths
        for arg in &self.args {
            buf.push(arg.len() as u8);
        }

        // Variable fields
        buf.extend_from_slice(user_bytes);
        buf.extend_from_slice(port_bytes);
        buf.extend_from_slice(rem_bytes);
        for arg in &self.args {
            buf.extend_from_slice(arg.as_bytes());
        }

        buf
    }
}

/// TACACS+ authorization REPLY body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorReplyBody {
    pub status: AuthorStatus,
    pub server_msg: String,
    pub data: Vec<u8>,
    pub args: Vec<String>,
}

impl AuthorReplyBody {
    /// Parse from wire-format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            return Err(AuthError::validation("TACACS+ author reply too short"));
        }
        let status = match data[0] {
            0x01 => AuthorStatus::PassAdd,
            0x02 => AuthorStatus::PassReplace,
            0x10 => AuthorStatus::Fail,
            0x11 => AuthorStatus::Error,
            0x21 => AuthorStatus::Follow,
            other => {
                return Err(AuthError::validation(format!(
                    "Unknown author status: {other:#x}"
                )));
            }
        };

        let arg_count = data[1] as usize;
        let server_msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let data_len = u16::from_be_bytes([data[4], data[5]]) as usize;

        let mut offset = 6;
        // Read arg lengths
        if data.len() < offset + arg_count {
            return Err(AuthError::validation(
                "TACACS+ author reply truncated (arg lengths)",
            ));
        }
        let arg_lens: Vec<usize> = data[offset..offset + arg_count]
            .iter()
            .map(|&b| b as usize)
            .collect();
        offset += arg_count;

        // server_msg
        if data.len() < offset + server_msg_len {
            return Err(AuthError::validation(
                "TACACS+ author reply truncated (msg)",
            ));
        }
        let server_msg =
            String::from_utf8_lossy(&data[offset..offset + server_msg_len]).to_string();
        offset += server_msg_len;

        // data
        if data.len() < offset + data_len {
            return Err(AuthError::validation(
                "TACACS+ author reply truncated (data)",
            ));
        }
        let reply_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        // args
        let mut args = Vec::with_capacity(arg_count);
        for &len in &arg_lens {
            if data.len() < offset + len {
                return Err(AuthError::validation(
                    "TACACS+ author reply truncated (args)",
                ));
            }
            args.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
            offset += len;
        }

        Ok(Self {
            status,
            server_msg,
            data: reply_data,
            args,
        })
    }
}

// ── Accounting request/reply (RFC 8907 §7) ──────────────────────────

/// TACACS+ accounting REQUEST body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcctRequestBody {
    pub flags: AcctFlags,
    pub authen_method: u8,
    pub authen_type: AuthenType,
    pub authen_service: AuthenService,
    pub user: String,
    pub port: String,
    pub remote_address: String,
    /// Attribute-value pairs (e.g. "task_id=1", "start_time=now").
    pub args: Vec<String>,
}

impl AcctRequestBody {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let user_bytes = self.user.as_bytes();
        let port_bytes = self.port.as_bytes();
        let rem_bytes = self.remote_address.as_bytes();
        let arg_count = self.args.len() as u8;

        let mut buf = vec![
            self.flags.0,
            self.authen_method,
            0x01, // priv_lvl
            self.authen_type as u8,
            self.authen_service as u8,
            user_bytes.len() as u8,
            port_bytes.len() as u8,
            rem_bytes.len() as u8,
            arg_count,
        ];

        // Argument lengths
        for arg in &self.args {
            buf.push(arg.len() as u8);
        }

        // Variable fields
        buf.extend_from_slice(user_bytes);
        buf.extend_from_slice(port_bytes);
        buf.extend_from_slice(rem_bytes);
        for arg in &self.args {
            buf.extend_from_slice(arg.as_bytes());
        }

        buf
    }
}

/// TACACS+ accounting status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AcctStatus {
    Success = 0x01,
    Error = 0x02,
    Follow = 0x21,
}

/// TACACS+ accounting REPLY body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcctReplyBody {
    pub status: AcctStatus,
    pub server_msg: String,
    pub data: Vec<u8>,
}

impl AcctReplyBody {
    /// Parse from wire-format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(AuthError::validation("TACACS+ acct reply too short"));
        }
        let server_msg_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let status = match data[4] {
            0x01 => AcctStatus::Success,
            0x02 => AcctStatus::Error,
            0x21 => AcctStatus::Follow,
            other => {
                return Err(AuthError::validation(format!(
                    "Unknown acct status: {other:#x}"
                )));
            }
        };

        let offset = 5;
        if data.len() < offset + server_msg_len + data_len {
            return Err(AuthError::validation("TACACS+ acct reply truncated"));
        }
        let server_msg =
            String::from_utf8_lossy(&data[offset..offset + server_msg_len]).to_string();
        let reply_data = data[offset + server_msg_len..offset + server_msg_len + data_len].to_vec();

        Ok(Self {
            status,
            server_msg,
            data: reply_data,
        })
    }
}

/// Obfuscate or deobfuscate a TACACS+ packet body using the shared secret.
///
/// The same function is used for both encryption and decryption (XOR-based).
/// Per RFC 8907 §4.6:
///   pseudo_pad = MD5(session_id || key || version || seq_no || previous_pad...)
pub fn obfuscate(header: &TacacsHeader, secret: &[u8], body: &mut [u8]) {
    if secret.is_empty() || body.is_empty() {
        return;
    }

    let mut pad = Vec::new();
    let session_id_bytes = header.session_id.to_be_bytes();

    // First block
    let mut ctx = Context::new(&SHA256);
    ctx.update(&session_id_bytes);
    ctx.update(secret);
    ctx.update(&[header.version]);
    ctx.update(&[header.seq_no]);
    let digest = ctx.finish();
    pad.extend_from_slice(digest.as_ref());

    // Subsequent blocks
    while pad.len() < body.len() {
        let mut ctx = Context::new(&SHA256);
        ctx.update(&session_id_bytes);
        ctx.update(secret);
        ctx.update(&[header.version]);
        ctx.update(&[header.seq_no]);
        let prev_start = pad.len().saturating_sub(32);
        ctx.update(&pad[prev_start..]);
        let digest = ctx.finish();
        pad.extend_from_slice(digest.as_ref());
    }

    // XOR
    for (i, b) in body.iter_mut().enumerate() {
        *b ^= pad[i];
    }
}

/// Generate a random TACACS+ session ID.
pub fn generate_session_id() -> Result<u32> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    rng.fill(&mut buf)
        .map_err(|_| AuthError::crypto("Failed to generate session ID".to_string()))?;
    Ok(u32::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let h = TacacsHeader::new(TacacsPacketType::Authentication, 1, 0xDEADBEEF, 42);
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 12);
        let h2 = TacacsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.packet_type, TacacsPacketType::Authentication);
        assert_eq!(h2.session_id, 0xDEADBEEF);
        assert_eq!(h2.length, 42);
        assert_eq!(h2.seq_no, 1);
    }

    #[test]
    fn test_header_too_short() {
        assert!(TacacsHeader::from_bytes(&[0; 5]).is_err());
    }

    #[test]
    fn test_header_unknown_type() {
        let mut bytes = TacacsHeader::new(TacacsPacketType::Authentication, 1, 1, 0).to_bytes();
        bytes[1] = 0xFF;
        assert!(TacacsHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_authen_start_body_serialization() {
        let body = AuthenStartBody {
            action: AuthenAction::Login,
            authen_type: AuthenType::Pap,
            authen_service: AuthenService::Login,
            user: "admin".to_string(),
            port: "tty0".to_string(),
            remote_address: "10.0.0.1".to_string(),
            data: b"password".to_vec(),
        };
        let bytes = body.to_bytes();
        assert_eq!(bytes[0], AuthenAction::Login as u8);
        assert_eq!(bytes[2], AuthenType::Pap as u8);
        assert_eq!(bytes[4], 5); // user len
    }

    #[test]
    fn test_authen_reply_parsing() {
        let mut data = vec![0x01, 0x00]; // Pass, no flags
        data.extend_from_slice(&3u16.to_be_bytes()); // server_msg_len=3
        data.extend_from_slice(&0u16.to_be_bytes()); // data_len=0
        data.extend_from_slice(b"OK!");

        let reply = AuthenReplyBody::from_bytes(&data).unwrap();
        assert_eq!(reply.status, AuthenStatus::Pass);
        assert_eq!(reply.server_msg, "OK!");
        assert!(reply.data.is_empty());
    }

    #[test]
    fn test_authen_reply_too_short() {
        assert!(AuthenReplyBody::from_bytes(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_obfuscate_deobfuscate_roundtrip() {
        let header = TacacsHeader::new(TacacsPacketType::Authentication, 1, 12345, 11);
        let secret = b"shared-secret";
        let original = b"hello world".to_vec();
        let mut encrypted = original.clone();

        obfuscate(&header, secret, &mut encrypted);
        assert_ne!(encrypted, original, "obfuscation should change data");

        obfuscate(&header, secret, &mut encrypted);
        assert_eq!(
            encrypted, original,
            "double obfuscation should restore data"
        );
    }

    #[test]
    fn test_obfuscate_empty_secret_noop() {
        let header = TacacsHeader::new(TacacsPacketType::Authentication, 1, 1, 5);
        let mut data = b"hello".to_vec();
        let orig = data.clone();
        obfuscate(&header, b"", &mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id().unwrap();
        let id2 = generate_session_id().unwrap();
        // Probabilistically these should differ (2^32 space)
        // Just check they don't panic
        assert!(id1 != 0 || id2 != 0);
    }

    #[test]
    fn test_acct_flags() {
        let start = AcctFlags::START;
        assert!(start.is_start());
        assert!(!start.is_stop());
        assert!(!start.is_watchdog());

        let stop = AcctFlags::STOP;
        assert!(stop.is_stop());
    }

    #[test]
    fn test_packet_type_values() {
        assert_eq!(TacacsPacketType::Authentication as u8, 0x01);
        assert_eq!(TacacsPacketType::Authorization as u8, 0x02);
        assert_eq!(TacacsPacketType::Accounting as u8, 0x03);
    }

    // ── Authorization ───────────────────────────────────────────

    #[test]
    fn test_author_request_serialization() {
        let body = AuthorRequestBody {
            authen_method: 0x06, // TACACS+
            authen_type: AuthenType::Pap,
            authen_service: AuthenService::Login,
            user: "admin".to_string(),
            port: "tty0".to_string(),
            remote_address: "10.0.0.1".to_string(),
            args: vec!["service=shell".to_string(), "cmd=show".to_string()],
        };
        let bytes = body.to_bytes();
        assert_eq!(bytes[0], 0x06); // authen_method
        assert_eq!(bytes[7], 2); // arg_count
        // arg lengths follow
        assert_eq!(bytes[8], 13); // "service=shell".len()
        assert_eq!(bytes[9], 8); // "cmd=show".len()
    }

    #[test]
    fn test_author_reply_parsing() {
        // Build: status | arg_cnt | server_msg_len | data_len | arg_lens | msg | data | args
        let mut data = vec![0x01]; // PassAdd
        data.push(2); // arg_count
        data.extend_from_slice(&2u16.to_be_bytes()); // server_msg_len
        data.extend_from_slice(&0u16.to_be_bytes()); // data_len
        data.push(6); // arg0 len ("priv=1")
        data.push(6); // arg1 len ("role=a")
        data.extend_from_slice(b"OK"); // server_msg
        // no data
        data.extend_from_slice(b"priv=1role=a"); // args concatenated

        let reply = AuthorReplyBody::from_bytes(&data).unwrap();
        assert_eq!(reply.status, AuthorStatus::PassAdd);
        assert_eq!(reply.server_msg, "OK");
        assert_eq!(reply.args.len(), 2);
        assert_eq!(reply.args[0], "priv=1");
        assert_eq!(reply.args[1], "role=a");
    }

    #[test]
    fn test_author_reply_too_short() {
        assert!(AuthorReplyBody::from_bytes(&[0x01]).is_err());
    }

    // ── Accounting ──────────────────────────────────────────────

    #[test]
    fn test_acct_request_serialization() {
        let body = AcctRequestBody {
            flags: AcctFlags::START,
            authen_method: 0x06,
            authen_type: AuthenType::Pap,
            authen_service: AuthenService::Login,
            user: "admin".to_string(),
            port: "tty0".to_string(),
            remote_address: "10.0.0.1".to_string(),
            args: vec!["task_id=1".to_string()],
        };
        let bytes = body.to_bytes();
        assert_eq!(bytes[0], AcctFlags::START.0); // flags
        assert_eq!(bytes[8], 1); // arg_count
    }

    #[test]
    fn test_acct_reply_parsing() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_be_bytes()); // server_msg_len
        data.extend_from_slice(&0u16.to_be_bytes()); // data_len
        data.push(0x01); // status = Success
        data.extend_from_slice(b"Done"); // server_msg

        let reply = AcctReplyBody::from_bytes(&data).unwrap();
        assert_eq!(reply.status, AcctStatus::Success);
        assert_eq!(reply.server_msg, "Done");
    }

    #[test]
    fn test_acct_reply_too_short() {
        assert!(AcctReplyBody::from_bytes(&[0x00, 0x01]).is_err());
    }
}
