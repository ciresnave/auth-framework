//! Kerberos / SPNEGO Authentication Protocol Support
//!
//! Implements Kerberos 5 (RFC 4120) ticket validation and SPNEGO (RFC 4178)
//! negotiation for HTTP-based authentication, enabling seamless SSO with
//! Active Directory and MIT Kerberos environments.
//!
//! # Supported Encryption Types
//!
//! - AES256-CTS-HMAC-SHA1-96 (etype 18) — recommended
//! - AES128-CTS-HMAC-SHA1-96 (etype 17) — fallback
//!
//! # Architecture
//!
//! This module operates as a **service-side ticket validator**:
//!
//! 1. Client sends an `Authorization: Negotiate <token>` header
//! 2. Server decodes the SPNEGO wrapper and extracts the Kerberos AP-REQ
//! 3. Server decrypts the ticket using keytab keys (AES-CTS-HMAC-SHA1-96)
//! 4. Server decrypts and verifies the authenticator using the session key
//! 5. On success, extracts the client principal and returns an auth result
//!
//! # Security Considerations
//!
//! - Keytab files must be protected with strict filesystem permissions
//! - Replay protection uses a time-windowed nonce cache
//! - Clock skew tolerance is configurable (default: 5 minutes per RFC 4120)
//! - All cryptographic comparisons use constant-time operations

use crate::errors::{AuthError, Result};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::Engine as _;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

// ─── Constants ───────────────────────────────────────────────────────────────

/// Encryption type: AES128-CTS-HMAC-SHA1-96 (RFC 3962).
const ETYPE_AES128: i32 = 17;
/// Encryption type: AES256-CTS-HMAC-SHA1-96 (RFC 3962).
const ETYPE_AES256: i32 = 18;

/// Key usage for ticket encryption (RFC 4120 §7.5.1).
const KEY_USAGE_TICKET: u32 = 2;
/// Key usage for AP-REQ authenticator (RFC 4120 §7.5.1, for AES etypes).
const KEY_USAGE_AP_REQ_AUTH: u32 = 11;

/// AES block size.
const AES_BLOCK: usize = 16;
/// HMAC-SHA1-96 output length (truncated to 96 bits = 12 bytes).
const HMAC_LEN: usize = 12;
/// Confounder length (one AES block).
const CONFOUNDER_LEN: usize = 16;

/// SPNEGO OID bytes (1.3.6.1.5.5.2) as encoded in DER (after tag+length).
const SPNEGO_OID_BYTES: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos 5 OID bytes (1.2.840.113554.1.2.2) as encoded in DER.
const KRB5_OID_BYTES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

// ─── Minimal DER Parser ──────────────────────────────────────────────────────

/// A parsed DER Tag-Length-Value.
#[allow(dead_code)]
#[derive(Debug)]
struct DerTlv<'a> {
    /// Tag class: 0=Universal, 1=Application, 2=Context-specific, 3=Private.
    class: u8,
    /// Whether this is a constructed encoding.
    constructed: bool,
    /// Tag number.
    tag_num: u32,
    /// The value bytes (content octets).
    value: &'a [u8],
}

/// Parse one DER TLV from the front of `data`. Returns (tlv, remaining_bytes).
fn parse_der(data: &[u8]) -> Result<(DerTlv<'_>, &[u8])> {
    if data.is_empty() {
        return Err(AuthError::validation("Empty DER data"));
    }

    let b0 = data[0];
    let class = b0 >> 6;
    let constructed = (b0 & 0x20) != 0;
    let mut pos: usize = 1;

    // Tag number
    let tag_num = if (b0 & 0x1f) == 0x1f {
        let mut t: u32 = 0;
        loop {
            if pos >= data.len() {
                return Err(AuthError::validation("DER tag truncated"));
            }
            let b = data[pos];
            pos += 1;
            t = t
                .checked_shl(7)
                .ok_or_else(|| AuthError::validation("DER tag too large"))?
                | (b & 0x7f) as u32;
            if (b & 0x80) == 0 {
                break;
            }
        }
        t
    } else {
        (b0 & 0x1f) as u32
    };

    // Length
    if pos >= data.len() {
        return Err(AuthError::validation("DER length missing"));
    }
    let len_byte = data[pos];
    pos += 1;

    let length = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x80 {
        return Err(AuthError::validation(
            "Indefinite length not supported in DER",
        ));
    } else {
        let num_bytes = (len_byte & 0x7f) as usize;
        if num_bytes > 4 || pos + num_bytes > data.len() {
            return Err(AuthError::validation("DER length overflow"));
        }
        let mut l: usize = 0;
        for &b in &data[pos..pos + num_bytes] {
            l = l
                .checked_shl(8)
                .ok_or_else(|| AuthError::validation("DER length too large"))?
                | b as usize;
        }
        pos += num_bytes;
        l
    };

    if pos + length > data.len() {
        return Err(AuthError::validation("DER value truncated"));
    }

    Ok((
        DerTlv {
            class,
            constructed,
            tag_num,
            value: &data[pos..pos + length],
        },
        &data[pos + length..],
    ))
}

/// Parse all consecutive TLVs from the content of a constructed DER object.
fn parse_der_contents(data: &[u8]) -> Result<Vec<DerTlv<'_>>> {
    let mut result = Vec::new();
    let mut remaining = data;
    while !remaining.is_empty() {
        let (tlv, rest) = parse_der(remaining)?;
        result.push(tlv);
        remaining = rest;
    }
    Ok(result)
}

/// Find a context-tagged field ([n] EXPLICIT) in a list of DER TLVs.
fn get_ctx_field<'a, 'b>(fields: &'b [DerTlv<'a>], tag: u32) -> Option<&'b DerTlv<'a>> {
    fields.iter().find(|f| f.class == 2 && f.tag_num == tag)
}

/// Unwrap an explicit context tag: parse the inner TLV from the tag's value.
fn unwrap_explicit<'a>(tlv: &DerTlv<'a>) -> Result<DerTlv<'a>> {
    let (inner, _) = parse_der(tlv.value)?;
    Ok(inner)
}

/// Parse a DER INTEGER value as i64.
fn parse_der_integer(data: &[u8]) -> Result<i64> {
    if data.is_empty() {
        return Err(AuthError::validation("Empty INTEGER"));
    }
    let mut val: i64 = if data[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in data {
        val = (val << 8) | b as i64;
    }
    Ok(val)
}

/// Parse a DER GeneralString / GeneralizedTime / IA5String as UTF-8.
fn parse_der_string(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec())
        .map_err(|e| AuthError::validation(format!("Invalid string encoding: {e}")))
}

/// Parse KerberosTime (GeneralizedTime: "YYYYMMDDHHmmSSZ") to Unix timestamp.
fn parse_kerberos_time(data: &[u8]) -> Result<u64> {
    let s = parse_der_string(data)?;
    if s.len() < 15 || !s.ends_with('Z') {
        return Err(AuthError::validation("Invalid KerberosTime format"));
    }
    let dt = chrono::NaiveDateTime::parse_from_str(&s[..14], "%Y%m%d%H%M%S")
        .map_err(|e| AuthError::validation(format!("Invalid KerberosTime: {e}")))?;
    Ok(dt.and_utc().timestamp() as u64)
}

/// Test a single bit in a BIT STRING value (after the unused-bits byte).
/// Bit numbering follows ASN.1: bit 0 is the MSB of the first content octet.
fn test_bit_flag(flags_data: &[u8], bit_num: usize) -> bool {
    if flags_data.is_empty() {
        return false;
    }
    // First byte is unused-bits count; actual flag bytes start at index 1
    let byte_idx = 1 + bit_num / 8;
    let bit_idx = 7 - (bit_num % 8);
    if byte_idx >= flags_data.len() {
        return false;
    }
    (flags_data[byte_idx] >> bit_idx) & 1 == 1
}

/// Compare a DER OID's value bytes against a known OID byte pattern.
fn oid_matches(tlv: &DerTlv<'_>, expected: &[u8]) -> bool {
    tlv.class == 0 && tlv.tag_num == 6 && tlv.value == expected
}

// ─── Kerberos ASN.1 Structures ───────────────────────────────────────────────

/// Parsed EncryptedData (RFC 4120 §5.2.9).
struct ParsedEncryptedData<'a> {
    etype: i32,
    kvno: Option<u32>,
    cipher: &'a [u8],
}

/// Parsed PrincipalName (RFC 4120 §5.2.2).
struct ParsedPrincipalName {
    components: Vec<String>,
}

impl ParsedPrincipalName {
    /// Reconstruct as "comp1/comp2/...".
    fn to_string_without_realm(&self) -> String {
        self.components.join("/")
    }
}

/// Parsed Ticket fields (RFC 4120 §5.3).
struct ParsedTicket<'a> {
    realm: String,
    sname: ParsedPrincipalName,
    enc_part: ParsedEncryptedData<'a>,
}

/// Parsed AP-REQ (RFC 4120 §5.5.1).
#[allow(dead_code)]
struct ParsedApReq<'a> {
    ap_options: u32,
    ticket: ParsedTicket<'a>,
    authenticator: ParsedEncryptedData<'a>,
}

/// Decrypted EncTicketPart (RFC 4120 §5.3).
#[allow(dead_code)]
struct DecryptedTicketPart {
    flags_raw: Vec<u8>,
    session_key_type: i32,
    session_key_value: Vec<u8>,
    crealm: String,
    cname: ParsedPrincipalName,
    auth_time: u64,
    end_time: u64,
    start_time: Option<u64>,
    renew_till: Option<u64>,
}

/// Decrypted Authenticator (RFC 4120 §5.5.1).
struct DecryptedAuthenticator {
    crealm: String,
    cname: ParsedPrincipalName,
    cusec: u32,
    ctime: u64,
}

fn parse_encrypted_data<'a>(data: &'a [u8]) -> Result<ParsedEncryptedData<'a>> {
    let (seq, _) = parse_der(data)?;
    if seq.tag_num != 16 {
        return Err(AuthError::validation("EncryptedData: expected SEQUENCE"));
    }
    let fields = parse_der_contents(seq.value)?;

    let etype_f = get_ctx_field(&fields, 0)
        .ok_or_else(|| AuthError::validation("EncryptedData missing etype"))?;
    let etype = parse_der_integer(unwrap_explicit(etype_f)?.value)? as i32;

    let kvno = if let Some(f) = get_ctx_field(&fields, 1) {
        Some(parse_der_integer(unwrap_explicit(f)?.value)? as u32)
    } else {
        None
    };

    let cipher_f = get_ctx_field(&fields, 2)
        .ok_or_else(|| AuthError::validation("EncryptedData missing cipher"))?;
    let cipher_tlv = unwrap_explicit(cipher_f)?;

    Ok(ParsedEncryptedData {
        etype,
        kvno,
        cipher: cipher_tlv.value,
    })
}

fn parse_principal_name(data: &[u8]) -> Result<ParsedPrincipalName> {
    let (seq, _) = parse_der(data)?;
    let fields = parse_der_contents(seq.value)?;

    // [1] SEQUENCE OF KerberosString
    let strings_f = get_ctx_field(&fields, 1)
        .ok_or_else(|| AuthError::validation("PrincipalName missing name-string"))?;
    let (strings_seq, _) = parse_der(strings_f.value)?;
    let string_tlvs = parse_der_contents(strings_seq.value)?;

    let mut components = Vec::new();
    for tlv in &string_tlvs {
        components.push(parse_der_string(tlv.value)?);
    }

    Ok(ParsedPrincipalName { components })
}

fn parse_ticket<'a>(data: &'a [u8]) -> Result<ParsedTicket<'a>> {
    // [APPLICATION 1] SEQUENCE
    let (app, _) = parse_der(data)?;
    if app.class != 1 || app.tag_num != 1 {
        return Err(AuthError::validation("Expected Ticket (APPLICATION 1)"));
    }
    let (seq, _) = parse_der(app.value)?;
    let fields = parse_der_contents(seq.value)?;

    // [0] tkt-vno INTEGER
    let vno_f =
        get_ctx_field(&fields, 0).ok_or_else(|| AuthError::validation("Ticket missing tkt-vno"))?;
    let vno = parse_der_integer(unwrap_explicit(vno_f)?.value)?;
    if vno != 5 {
        return Err(AuthError::validation(format!(
            "Unsupported ticket version: {vno}"
        )));
    }

    // [1] realm GeneralString
    let realm_f =
        get_ctx_field(&fields, 1).ok_or_else(|| AuthError::validation("Ticket missing realm"))?;
    let realm = parse_der_string(unwrap_explicit(realm_f)?.value)?;

    // [2] sname PrincipalName
    let sname_f =
        get_ctx_field(&fields, 2).ok_or_else(|| AuthError::validation("Ticket missing sname"))?;
    let sname = parse_principal_name(sname_f.value)?;

    // [3] enc-part EncryptedData
    let enc_f = get_ctx_field(&fields, 3)
        .ok_or_else(|| AuthError::validation("Ticket missing enc-part"))?;
    let enc_part = parse_encrypted_data(enc_f.value)?;

    Ok(ParsedTicket {
        realm,
        sname,
        enc_part,
    })
}

fn parse_ap_req<'a>(data: &'a [u8]) -> Result<ParsedApReq<'a>> {
    // [APPLICATION 14] SEQUENCE
    let (app, _) = parse_der(data)?;
    if app.class != 1 || app.tag_num != 14 {
        return Err(AuthError::validation("Expected AP-REQ (APPLICATION 14)"));
    }
    let (seq, _) = parse_der(app.value)?;
    let fields = parse_der_contents(seq.value)?;

    // [0] pvno INTEGER (must be 5)
    let pvno_f =
        get_ctx_field(&fields, 0).ok_or_else(|| AuthError::validation("AP-REQ missing pvno"))?;
    let pvno = parse_der_integer(unwrap_explicit(pvno_f)?.value)?;
    if pvno != 5 {
        return Err(AuthError::validation(format!(
            "Unsupported Kerberos version: {pvno}"
        )));
    }

    // [1] msg-type INTEGER (must be 14)
    let mt_f = get_ctx_field(&fields, 1)
        .ok_or_else(|| AuthError::validation("AP-REQ missing msg-type"))?;
    let mt = parse_der_integer(unwrap_explicit(mt_f)?.value)?;
    if mt != 14 {
        return Err(AuthError::validation(format!(
            "Expected AP-REQ msg-type 14, got {mt}"
        )));
    }

    // [2] ap-options BIT STRING
    let opts_f = get_ctx_field(&fields, 2)
        .ok_or_else(|| AuthError::validation("AP-REQ missing ap-options"))?;
    let opts_tlv = unwrap_explicit(opts_f)?;
    let ap_options = parse_ap_options(&opts_tlv)?;

    // [3] ticket Ticket
    let ticket_f =
        get_ctx_field(&fields, 3).ok_or_else(|| AuthError::validation("AP-REQ missing ticket"))?;
    let ticket = parse_ticket(ticket_f.value)?;

    // [4] authenticator EncryptedData
    let auth_f = get_ctx_field(&fields, 4)
        .ok_or_else(|| AuthError::validation("AP-REQ missing authenticator"))?;
    let authenticator = parse_encrypted_data(auth_f.value)?;

    Ok(ParsedApReq {
        ap_options,
        ticket,
        authenticator,
    })
}

/// Parse AP-REQ options BIT STRING into a u32 flags word.
fn parse_ap_options(tlv: &DerTlv<'_>) -> Result<u32> {
    if tlv.value.len() < 2 {
        return Ok(0);
    }
    // First byte = unused bits count, rest = flag bytes
    let mut flags: u32 = 0;
    for (i, &b) in tlv.value[1..].iter().enumerate() {
        if i >= 4 {
            break;
        }
        flags |= (b as u32) << (24 - i * 8);
    }
    Ok(flags)
}

/// Parse decrypted EncTicketPart ([APPLICATION 3] SEQUENCE).
fn parse_enc_ticket_part(data: &[u8]) -> Result<DecryptedTicketPart> {
    let (app, _) = parse_der(data)?;
    if app.class != 1 || app.tag_num != 3 {
        return Err(AuthError::validation(
            "Expected EncTicketPart (APPLICATION 3)",
        ));
    }
    let (seq, _) = parse_der(app.value)?;
    let fields = parse_der_contents(seq.value)?;

    // [0] flags BIT STRING
    let flags_f = get_ctx_field(&fields, 0)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing flags"))?;
    let flags_tlv = unwrap_explicit(flags_f)?;
    let flags_raw = flags_tlv.value.to_vec();

    // [1] key EncryptionKey
    let key_f = get_ctx_field(&fields, 1)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing key"))?;
    let (key_seq, _) = parse_der(key_f.value)?;
    let key_fields = parse_der_contents(key_seq.value)?;
    let key_type_f = get_ctx_field(&key_fields, 0)
        .ok_or_else(|| AuthError::validation("EncryptionKey missing keytype"))?;
    let key_type = parse_der_integer(unwrap_explicit(key_type_f)?.value)? as i32;
    let key_val_f = get_ctx_field(&key_fields, 1)
        .ok_or_else(|| AuthError::validation("EncryptionKey missing keyvalue"))?;
    let key_value = unwrap_explicit(key_val_f)?.value.to_vec();

    // [2] crealm GeneralString
    let crealm_f = get_ctx_field(&fields, 2)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing crealm"))?;
    let crealm = parse_der_string(unwrap_explicit(crealm_f)?.value)?;

    // [3] cname PrincipalName
    let cname_f = get_ctx_field(&fields, 3)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing cname"))?;
    let cname = parse_principal_name(cname_f.value)?;

    // [5] authtime KerberosTime
    let authtime_f = get_ctx_field(&fields, 5)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing authtime"))?;
    let auth_time = parse_kerberos_time(unwrap_explicit(authtime_f)?.value)?;

    // [6] starttime KerberosTime OPTIONAL
    let start_time = if let Some(f) = get_ctx_field(&fields, 6) {
        Some(parse_kerberos_time(unwrap_explicit(f)?.value)?)
    } else {
        None
    };

    // [7] endtime KerberosTime
    let endtime_f = get_ctx_field(&fields, 7)
        .ok_or_else(|| AuthError::validation("EncTicketPart missing endtime"))?;
    let end_time = parse_kerberos_time(unwrap_explicit(endtime_f)?.value)?;

    // [8] renew-till KerberosTime OPTIONAL
    let renew_till = if let Some(f) = get_ctx_field(&fields, 8) {
        Some(parse_kerberos_time(unwrap_explicit(f)?.value)?)
    } else {
        None
    };

    Ok(DecryptedTicketPart {
        flags_raw,
        session_key_type: key_type,
        session_key_value: key_value,
        crealm,
        cname,
        auth_time,
        end_time,
        start_time,
        renew_till,
    })
}

/// Parse decrypted Authenticator ([APPLICATION 2] SEQUENCE).
fn parse_authenticator(data: &[u8]) -> Result<DecryptedAuthenticator> {
    let (app, _) = parse_der(data)?;
    if app.class != 1 || app.tag_num != 2 {
        return Err(AuthError::validation(
            "Expected Authenticator (APPLICATION 2)",
        ));
    }
    let (seq, _) = parse_der(app.value)?;
    let fields = parse_der_contents(seq.value)?;

    // [0] authenticator-vno INTEGER (5)
    let vno_f = get_ctx_field(&fields, 0)
        .ok_or_else(|| AuthError::validation("Authenticator missing vno"))?;
    let vno = parse_der_integer(unwrap_explicit(vno_f)?.value)?;
    if vno != 5 {
        return Err(AuthError::validation(format!(
            "Unsupported authenticator version: {vno}"
        )));
    }

    // [1] crealm GeneralString
    let crealm_f = get_ctx_field(&fields, 1)
        .ok_or_else(|| AuthError::validation("Authenticator missing crealm"))?;
    let crealm = parse_der_string(unwrap_explicit(crealm_f)?.value)?;

    // [2] cname PrincipalName
    let cname_f = get_ctx_field(&fields, 2)
        .ok_or_else(|| AuthError::validation("Authenticator missing cname"))?;
    let cname = parse_principal_name(cname_f.value)?;

    // [3] cusec Microseconds (INTEGER)
    let cusec_f = get_ctx_field(&fields, 3)
        .ok_or_else(|| AuthError::validation("Authenticator missing cusec"))?;
    let cusec = parse_der_integer(unwrap_explicit(cusec_f)?.value)? as u32;

    // [4] ctime KerberosTime
    let ctime_f = get_ctx_field(&fields, 4)
        .ok_or_else(|| AuthError::validation("Authenticator missing ctime"))?;
    let ctime = parse_kerberos_time(unwrap_explicit(ctime_f)?.value)?;

    Ok(DecryptedAuthenticator {
        crealm,
        cname,
        cusec,
        ctime,
    })
}

// ─── Kerberos Cryptography ───────────────────────────────────────────────────

/// Greatest common divisor.
fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Least common multiple.
fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

/// n-fold algorithm (RFC 3961 §5.1).
///
/// Folds an arbitrary-length input to an `output_len`-byte output.
/// Direct port of the MIT Kerberos reference implementation.
fn nfold(input: &[u8], output_len: usize) -> Vec<u8> {
    let in_bytes = input.len();
    let out_bytes = output_len;
    let lcm_val = lcm(in_bytes, out_bytes);
    let in_bits = in_bytes * 8;

    let mut out = vec![0u8; out_bytes];
    let mut byte: u32 = 0;

    for i in (0..lcm_val).rev() {
        // Compute the msbit in the input which gets added into this byte
        let msbit =
            ((in_bits - 1) + ((in_bits + 13) * (i / in_bytes)) + ((in_bytes - i % in_bytes) * 8))
                % in_bits;

        // Pull out the byte value from the input at the computed bit position
        let high = input[((in_bytes - 1).wrapping_sub(msbit >> 3)) % in_bytes] as u32;
        let low = input[(in_bytes.wrapping_sub(msbit >> 3)) % in_bytes] as u32;
        byte += ((high << 8 | low) >> ((msbit & 7) + 1)) & 0xff;

        // Do the addition
        byte += out[i % out_bytes] as u32;
        out[i % out_bytes] = (byte & 0xff) as u8;

        // Keep around the carry bit
        byte >>= 8;
    }

    // If there's a carry bit left over, add it back in
    if byte != 0 {
        for i in (0..out_bytes).rev() {
            byte += out[i] as u32;
            out[i] = (byte & 0xff) as u8;
            byte >>= 8;
        }
    }

    out
}

/// AES-ECB encrypt a single 16-byte block. Supports 16-byte (AES-128) or
/// 32-byte (AES-256) keys.
fn aes_ecb_encrypt(key: &[u8], block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
    let mut blk = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
    match key.len() {
        16 => {
            let cipher =
                aes::Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(key));
            cipher.encrypt_block(&mut blk);
        }
        32 => {
            let cipher =
                aes::Aes256::new(aes::cipher::generic_array::GenericArray::from_slice(key));
            cipher.encrypt_block(&mut blk);
        }
        _ => unreachable!("aes_ecb_encrypt: unsupported key length"),
    }
    let mut out = [0u8; AES_BLOCK];
    out.copy_from_slice(&blk);
    out
}

/// AES-ECB decrypt a single 16-byte block.
fn aes_ecb_decrypt(key: &[u8], block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
    let mut blk = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
    match key.len() {
        16 => {
            let cipher =
                aes::Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(key));
            cipher.decrypt_block(&mut blk);
        }
        32 => {
            let cipher =
                aes::Aes256::new(aes::cipher::generic_array::GenericArray::from_slice(key));
            cipher.decrypt_block(&mut blk);
        }
        _ => unreachable!("aes_ecb_decrypt: unsupported key length"),
    }
    let mut out = [0u8; AES_BLOCK];
    out.copy_from_slice(&blk);
    out
}

/// XOR two byte slices of the same length.
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

/// Derive a Kerberos sub-key from a base key using the RFC 3961 DK function.
///
/// `key_type` selects the derivative:
///   - `0xAA` → Ke (encryption key)
///   - `0x55` → Ki (integrity / HMAC key)
///   - `0x99` → Kc (checksum key)
fn derive_key_aes(base_key: &[u8], usage: u32, key_type: u8) -> Vec<u8> {
    let constant = [
        (usage >> 24) as u8,
        (usage >> 16) as u8,
        (usage >> 8) as u8,
        usage as u8,
        key_type,
    ];

    // n-fold the constant to the AES block size
    let nfolded = nfold(&constant, AES_BLOCK);

    let key_size = base_key.len(); // 16 for AES-128, 32 for AES-256
    let mut derived = Vec::with_capacity(key_size);

    let mut input: [u8; AES_BLOCK] = nfolded.try_into().expect("nfold produced wrong size");
    while derived.len() < key_size {
        let encrypted = aes_ecb_encrypt(base_key, &input);
        derived.extend_from_slice(&encrypted);
        input = encrypted;
    }

    derived.truncate(key_size);
    derived
}

/// AES-CBC decrypt with a zero IV. Returns the full plaintext (same length as
/// ciphertext, which must be a multiple of 16).
fn aes_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(AES_BLOCK) || ciphertext.is_empty() {
        return Err(AuthError::crypto(
            "AES-CBC ciphertext must be a non-empty multiple of block size",
        ));
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev = [0u8; AES_BLOCK]; // IV = all zeros for Kerberos

    let (chunks, _remainder) = ciphertext.as_chunks::<AES_BLOCK>();
    for chunk in chunks {
        let ct_block: [u8; AES_BLOCK] = *chunk;
        let decrypted = aes_ecb_decrypt(key, &ct_block);
        let pt_block = xor_bytes(&decrypted, &prev);
        plaintext.extend_from_slice(&pt_block);
        prev = ct_block;
    }

    Ok(plaintext)
}

/// AES-CTS (Cipher Text Stealing) decryption (RFC 3962 / RFC 3961).
///
/// Handles three cases:
///   - Exactly 1 block: ECB decrypt with zero IV
///   - Multiple of block size: standard CBC decrypt
///   - Non-multiple: CBC-CTS with last-two-block swap
fn aes_cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let n = ciphertext.len();
    if n < AES_BLOCK {
        return Err(AuthError::crypto("AES-CTS ciphertext too short"));
    }

    if n == AES_BLOCK {
        // Single block: ECB decrypt XOR with zero IV = just ECB decrypt
        let ct: [u8; AES_BLOCK] = ciphertext.try_into().unwrap();
        return Ok(aes_ecb_decrypt(key, &ct).to_vec());
    }

    if n.is_multiple_of(AES_BLOCK) {
        // Exact multiple: standard CBC
        return aes_cbc_decrypt(key, ciphertext);
    }

    // CTS case: non-multiple of block size
    let partial_len = n % AES_BLOCK;
    let num_full_blocks = n / AES_BLOCK; // at least 1
    let preceding_len = (num_full_blocks - 1) * AES_BLOCK;

    let c_second_last: [u8; AES_BLOCK] = ciphertext[preceding_len..preceding_len + AES_BLOCK]
        .try_into()
        .unwrap();
    let c_last = &ciphertext[preceding_len + AES_BLOCK..];

    // Determine the CBC IV for the CTS pair
    let prev_cipher = if preceding_len >= AES_BLOCK {
        &ciphertext[preceding_len - AES_BLOCK..preceding_len]
    } else {
        &[0u8; AES_BLOCK][..] // zero IV
    };

    // ECB decrypt the second-to-last ciphertext block
    let d = aes_ecb_decrypt(key, &c_second_last);

    // Recover the partial plaintext (last block)
    let p_last = xor_bytes(&d[..partial_len], c_last);

    // Recover the full "un-swapped" penultimate ciphertext block
    let mut c_recovered = [0u8; AES_BLOCK];
    c_recovered[..partial_len].copy_from_slice(c_last);
    c_recovered[partial_len..].copy_from_slice(&d[partial_len..]);

    // CBC decrypt the recovered block
    let decrypted_recovered = aes_ecb_decrypt(key, &c_recovered);
    let p_second_last = xor_bytes(&decrypted_recovered, prev_cipher);

    // CBC decrypt the preceding blocks (if any)
    let mut plaintext = if preceding_len > 0 {
        aes_cbc_decrypt(key, &ciphertext[..preceding_len])?
    } else {
        Vec::new()
    };

    plaintext.extend_from_slice(&p_second_last);
    plaintext.extend_from_slice(&p_last);

    Ok(plaintext)
}

/// Compute HMAC-SHA1 over the given data, returning the full 20-byte output.
fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;

    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Decrypt a Kerberos AES-CTS-HMAC-SHA1-96 ciphertext (RFC 3962).
///
/// Layout: `ciphertext_body || hmac_sha1_96` where
///   - `ciphertext_body` = AES-CTS encrypted `confounder || plaintext`
///   - `hmac_sha1_96`    = HMAC-SHA1 truncated to 96 bits (12 bytes)
fn decrypt_aes_cts(base_key: &[u8], ciphertext: &[u8], etype: i32, usage: u32) -> Result<Vec<u8>> {
    let expected_key_len = match etype {
        ETYPE_AES128 => 16,
        ETYPE_AES256 => 32,
        _ => {
            return Err(AuthError::crypto(format!(
                "Unsupported encryption type {etype}; only AES etypes 17/18 are supported"
            )));
        }
    };

    if base_key.len() != expected_key_len {
        return Err(AuthError::crypto(format!(
            "Key length mismatch: expected {expected_key_len}, got {}",
            base_key.len()
        )));
    }

    if ciphertext.len() < CONFOUNDER_LEN + HMAC_LEN {
        return Err(AuthError::crypto(
            "Ciphertext too short for AES-CTS envelope",
        ));
    }

    let ct_body = &ciphertext[..ciphertext.len() - HMAC_LEN];
    let expected_hmac = &ciphertext[ciphertext.len() - HMAC_LEN..];

    // Derive Ke (encryption) and Ki (integrity) sub-keys
    let ke = derive_key_aes(base_key, usage, 0xAA);
    let ki = derive_key_aes(base_key, usage, 0x55);

    // Decrypt
    let plaintext_with_confounder = aes_cts_decrypt(&ke, ct_body)?;

    // Verify HMAC-SHA1-96 over the decrypted plaintext (including confounder)
    let computed_hmac = hmac_sha1(&ki, &plaintext_with_confounder);
    if computed_hmac[..HMAC_LEN].ct_eq(expected_hmac).unwrap_u8() != 1 {
        return Err(AuthError::crypto(
            "Kerberos HMAC verification failed — wrong key or corrupted ticket",
        ));
    }

    // Strip confounder
    Ok(plaintext_with_confounder[CONFOUNDER_LEN..].to_vec())
}

// ─── SPNEGO Parsing ──────────────────────────────────────────────────────────

/// Parse a GSS-API / SPNEGO initial context token.
///
/// Structure:
/// ```text
/// [APPLICATION 0] SEQUENCE {
///     thisMech  OID (SPNEGO),
///     innerToken  NegTokenInit (as [CONTEXT 0])
/// }
/// ```
fn parse_spnego_init_token(data: &[u8]) -> Result<SpnegoToken> {
    // [APPLICATION 0] wrapper
    let (app, _) = parse_der(data)?;
    if app.class != 1 || app.tag_num != 0 {
        return Err(AuthError::validation(
            "Expected GSS-API InitialContextToken (APPLICATION 0)",
        ));
    }

    // Inner: OID followed by NegTokenInit
    let (oid_tlv, rest) = parse_der(app.value)?;
    if !oid_matches(&oid_tlv, SPNEGO_OID_BYTES) {
        return Err(AuthError::validation("Not an SPNEGO token"));
    }

    // NegTokenInit is [CONTEXT 0] IMPLICIT SEQUENCE
    let (neg_init_wrapper, _) = parse_der(rest)?;
    if neg_init_wrapper.class != 2 || neg_init_wrapper.tag_num != 0 {
        return Err(AuthError::validation("Expected NegTokenInit ([CONTEXT 0])"));
    }

    // Inner SEQUENCE
    let (neg_init_seq, _) = parse_der(neg_init_wrapper.value)?;
    let fields = parse_der_contents(neg_init_seq.value)?;

    // [0] mechTypes: SEQUENCE OF OID
    let mech_types_f = get_ctx_field(&fields, 0)
        .ok_or_else(|| AuthError::validation("NegTokenInit missing mechTypes"))?;
    let (mech_seq, _) = parse_der(mech_types_f.value)?;
    let mech_oids = parse_der_contents(mech_seq.value)?;

    // Check if Kerberos 5 is among the offered mechanisms
    let has_krb5 = mech_oids.iter().any(|o| oid_matches(o, KRB5_OID_BYTES));
    if !has_krb5 {
        return Err(AuthError::validation(
            "SPNEGO NegTokenInit does not offer Kerberos 5",
        ));
    }

    // [2] mechToken: OCTET STRING (the AP-REQ)
    let mech_token_f = get_ctx_field(&fields, 2)
        .ok_or_else(|| AuthError::validation("NegTokenInit missing mechToken"))?;
    let mech_token_tlv = unwrap_explicit(mech_token_f)?;

    Ok(SpnegoToken {
        mech_oid: oid::KERBEROS_V5.to_string(),
        mech_token: mech_token_tlv.value.to_vec(),
        state: SpnegoState::Initial,
    })
}

/// Parse a SPNEGO NegTokenResp ([CONTEXT 1]).
fn parse_spnego_resp_token(data: &[u8]) -> Result<SpnegoToken> {
    let (wrapper, _) = parse_der(data)?;
    if wrapper.class != 2 || wrapper.tag_num != 1 {
        return Err(AuthError::validation("Expected NegTokenResp ([CONTEXT 1])"));
    }

    let (seq, _) = parse_der(wrapper.value)?;
    let fields = parse_der_contents(seq.value)?;

    // [2] responseToken OCTET STRING OPTIONAL
    let mech_token = if let Some(f) = get_ctx_field(&fields, 2) {
        unwrap_explicit(f)?.value.to_vec()
    } else {
        Vec::new()
    };

    Ok(SpnegoToken {
        mech_oid: oid::KERBEROS_V5.to_string(),
        mech_token,
        state: SpnegoState::Continue,
    })
}

// ─── Configuration ───────────────────────────────────────────────────────────

/// Kerberos / SPNEGO configuration.
#[derive(Debug, Clone)]
pub struct KerberosConfig {
    /// Service principal name (e.g. `HTTP/server.example.com@REALM`).
    pub service_principal: String,

    /// Kerberos realm (e.g. `EXAMPLE.COM`).
    pub realm: String,

    /// Path to the keytab file.
    pub keytab_path: Option<String>,

    /// KDC addresses for ticket verification.
    pub kdc_addresses: Vec<String>,

    /// Maximum allowed clock skew (default: 300 seconds / 5 minutes).
    pub max_clock_skew_secs: u64,

    /// Whether to allow delegation (forwarded tickets).
    pub allow_delegation: bool,

    /// Maximum replay cache entries before eviction.
    pub replay_cache_max_entries: usize,
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            service_principal: String::new(),
            realm: String::new(),
            keytab_path: None,
            kdc_addresses: Vec::new(),
            max_clock_skew_secs: 300,
            allow_delegation: false,
            replay_cache_max_entries: 100_000,
        }
    }
}

impl KerberosConfig {
    /// Start building a [`KerberosConfig`] with the two required fields.
    ///
    /// All optional fields default to [`KerberosConfig::default()`] values.
    /// Call [`.build()`](KerberosConfigBuilder::build) to validate and obtain
    /// the finished config.
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::protocols::kerberos::KerberosConfig;
    ///
    /// let config = KerberosConfig::builder(
    ///         "HTTP/server.example.com@EXAMPLE.COM",
    ///         "EXAMPLE.COM",
    ///     )
    ///     .keytab_path("/etc/krb5.keytab")
    ///     .add_kdc("kdc1.example.com:88")
    ///     .add_kdc("kdc2.example.com:88")
    ///     .build();
    /// ```
    pub fn builder(
        service_principal: impl Into<String>,
        realm: impl Into<String>,
    ) -> KerberosConfigBuilder {
        KerberosConfigBuilder {
            config: KerberosConfig {
                service_principal: service_principal.into(),
                realm: realm.into(),
                ..Default::default()
            },
        }
    }

    /// Shorthand for an Active Directory environment.
    ///
    /// Sets `allow_delegation` to `true` (common in AD) and leaves the
    /// rest at defaults.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = KerberosConfig::active_directory(
    ///     "HTTP/server.corp.example.com@CORP.EXAMPLE.COM",
    ///     "CORP.EXAMPLE.COM",
    /// );
    /// ```
    pub fn active_directory(
        service_principal: impl Into<String>,
        realm: impl Into<String>,
    ) -> Self {
        Self {
            service_principal: service_principal.into(),
            realm: realm.into(),
            allow_delegation: true,
            ..Default::default()
        }
    }
}

/// Builder for [`KerberosConfig`].
///
/// Created via [`KerberosConfig::builder()`].
pub struct KerberosConfigBuilder {
    config: KerberosConfig,
}

impl KerberosConfigBuilder {
    /// Set the path to the keytab file.
    pub fn keytab_path(mut self, path: impl Into<String>) -> Self {
        self.config.keytab_path = Some(path.into());
        self
    }

    /// Append a KDC address (e.g. `"kdc.example.com:88"`).
    pub fn add_kdc(mut self, addr: impl Into<String>) -> Self {
        self.config.kdc_addresses.push(addr.into());
        self
    }

    /// Set the maximum allowed clock skew in seconds (default: 300).
    pub fn max_clock_skew_secs(mut self, secs: u64) -> Self {
        self.config.max_clock_skew_secs = secs;
        self
    }

    /// Enable or disable ticket delegation (default: `false`).
    pub fn allow_delegation(mut self, allow: bool) -> Self {
        self.config.allow_delegation = allow;
        self
    }

    /// Set the maximum replay-cache size (default: 100 000).
    pub fn replay_cache_max_entries(mut self, max: usize) -> Self {
        self.config.replay_cache_max_entries = max;
        self
    }

    /// Consume the builder and return the finished [`KerberosConfig`].
    pub fn build(self) -> KerberosConfig {
        self.config
    }
}

// ─── Data Types ──────────────────────────────────────────────────────────────

/// Kerberos authentication token OID constants.
pub mod oid {
    /// SPNEGO OID: 1.3.6.1.5.5.2
    pub const SPNEGO: &str = "1.3.6.1.5.5.2";
    /// Kerberos 5 OID: 1.2.840.113554.1.2.2
    pub const KERBEROS_V5: &str = "1.2.840.113554.1.2.2";
}

/// Result of Kerberos authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosAuthResult {
    /// Authenticated client principal (e.g. `user@REALM`).
    pub client_principal: String,

    /// Kerberos realm.
    pub realm: String,

    /// When the ticket was issued.
    pub auth_time: u64,

    /// When the ticket expires.
    pub end_time: u64,

    /// Whether this is a delegated (forwarded) ticket.
    pub is_delegated: bool,

    /// Session flags extracted from the ticket.
    pub flags: KerberosTicketFlags,

    /// SPNEGO response token to return to the client (mutual auth).
    pub response_token: Option<String>,
}

/// Kerberos ticket flags (RFC 4120 §5.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KerberosTicketFlags {
    pub forwardable: bool,
    pub forwarded: bool,
    pub proxiable: bool,
    pub proxy: bool,
    pub may_postdate: bool,
    pub postdated: bool,
    pub renewable: bool,
    pub pre_authent: bool,
    pub hw_authent: bool,
}

/// SPNEGO negotiation state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SpnegoState {
    /// Initial negotiation — expecting NegTokenInit.
    Initial,
    /// Continuation — expecting NegTokenResp.
    Continue,
    /// Negotiation complete.
    Completed,
    /// Negotiation rejected.
    Rejected,
}

/// Parsed SPNEGO token (simplified).
#[derive(Debug, Clone)]
pub struct SpnegoToken {
    /// Which mechanism was selected.
    pub mech_oid: String,
    /// The mechanism-specific token bytes (AP-REQ for Kerberos).
    pub mech_token: Vec<u8>,
    /// Negotiation state.
    pub state: SpnegoState,
}

/// Kerberos keytab entry.
#[derive(Debug, Clone)]
pub struct KeytabEntry {
    pub principal: String,
    pub realm: String,
    pub kvno: u32,
    pub key_type: u32,
    pub key_data: Vec<u8>,
}

// ─── Manager ─────────────────────────────────────────────────────────────────

/// Kerberos / SPNEGO authentication manager.
#[derive(Debug)]
pub struct KerberosManager {
    config: KerberosConfig,
    /// Replay cache: authenticator hash → timestamp.
    replay_cache: Arc<RwLock<HashMap<Vec<u8>, u64>>>,
    /// Loaded keytab entries.
    keytab_entries: Arc<RwLock<Vec<KeytabEntry>>>,
}

impl KerberosManager {
    /// Create a new Kerberos manager.
    pub fn new(config: KerberosConfig) -> Result<Self> {
        if config.service_principal.is_empty() {
            return Err(AuthError::config("Kerberos service principal must be set"));
        }
        if config.realm.is_empty() {
            return Err(AuthError::config("Kerberos realm must be set"));
        }

        Ok(Self {
            config,
            replay_cache: Arc::new(RwLock::new(HashMap::new())),
            keytab_entries: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Load keytab entries from file.
    pub async fn load_keytab(&self, path: &str) -> Result<usize> {
        let data = tokio::fs::read(path)
            .await
            .map_err(|e| AuthError::config(format!("Failed to read keytab file: {e}")))?;

        let entries = parse_keytab(&data)?;
        let count = entries.len();

        let mut kt = self.keytab_entries.write().await;
        *kt = entries;

        Ok(count)
    }

    /// Process an HTTP `Authorization: Negotiate <token>` header.
    ///
    /// Returns the authentication result on success, or an appropriate error.
    /// The caller should return the `response_token` (if any) in a
    /// `WWW-Authenticate: Negotiate <token>` response header.
    pub async fn authenticate(&self, negotiate_token: &str) -> Result<KerberosAuthResult> {
        let token_bytes = base64::engine::general_purpose::STANDARD
            .decode(negotiate_token.trim())
            .map_err(|e| AuthError::validation(format!("Invalid Negotiate token encoding: {e}")))?;

        if token_bytes.is_empty() {
            return Err(AuthError::validation("Empty Negotiate token"));
        }

        // Parse SPNEGO wrapper
        let spnego = self.parse_spnego_token(&token_bytes)?;

        if spnego.mech_oid != oid::KERBEROS_V5 {
            return Err(AuthError::validation(format!(
                "Unsupported SPNEGO mechanism: {}",
                spnego.mech_oid
            )));
        }

        // Validate the Kerberos AP-REQ
        let result = self.validate_ap_req(&spnego.mech_token).await?;

        Ok(result)
    }

    /// Generate a `WWW-Authenticate: Negotiate` challenge header value.
    pub fn generate_challenge(&self) -> String {
        "Negotiate".to_string()
    }

    /// Parse an SPNEGO token wrapper using proper ASN.1 DER parsing.
    fn parse_spnego_token(&self, data: &[u8]) -> Result<SpnegoToken> {
        if data.len() < 2 {
            return Err(AuthError::validation("SPNEGO token too short"));
        }

        match data[0] {
            // APPLICATION 0 CONSTRUCTED — GSS-API InitialContextToken
            0x60 => parse_spnego_init_token(data),
            // CONTEXT 1 — NegTokenResp
            0xa1 => parse_spnego_resp_token(data),
            // Assume raw Kerberos AP-REQ (no SPNEGO wrapper)
            _ => Ok(SpnegoToken {
                mech_oid: oid::KERBEROS_V5.to_string(),
                mech_token: data.to_vec(),
                state: SpnegoState::Initial,
            }),
        }
    }

    /// Validate a Kerberos AP-REQ message.
    ///
    /// Performs full cryptographic validation:
    /// 1. Parses the AP-REQ ASN.1 structure
    /// 2. Looks up the service key from the keytab
    /// 3. Decrypts the ticket using AES-CTS-HMAC-SHA1-96
    /// 4. Decrypts the authenticator using the session key
    /// 5. Verifies timestamps and checks for replay attacks
    async fn validate_ap_req(&self, ap_req_bytes: &[u8]) -> Result<KerberosAuthResult> {
        let keytab = self.keytab_entries.read().await;
        if keytab.is_empty() {
            return Err(AuthError::config(
                "No keytab loaded — cannot validate Kerberos tickets",
            ));
        }

        // ── Step 1: Parse AP-REQ ──
        let ap_req = parse_ap_req(ap_req_bytes)?;

        // ── Step 2: Find matching keytab entry ──
        let ticket_etype = ap_req.ticket.enc_part.etype;
        let ticket_kvno = ap_req.ticket.enc_part.kvno;
        let ticket_sname = format!(
            "{}@{}",
            ap_req.ticket.sname.to_string_without_realm(),
            ap_req.ticket.realm
        );

        let entry = keytab
            .iter()
            .find(|e| {
                e.principal == ticket_sname
                    && e.key_type == ticket_etype as u32
                    && ticket_kvno.is_none_or(|v| e.kvno == v)
            })
            .or_else(|| {
                // Fallback: match by realm and key type only
                keytab
                    .iter()
                    .find(|e| e.realm == ap_req.ticket.realm && e.key_type == ticket_etype as u32)
            })
            .ok_or_else(|| {
                AuthError::config(format!(
                    "No keytab entry for principal={ticket_sname} etype={ticket_etype}"
                ))
            })?;

        // ── Step 3: Decrypt the ticket ──
        let ticket_plaintext = decrypt_aes_cts(
            &entry.key_data,
            ap_req.ticket.enc_part.cipher,
            ticket_etype,
            KEY_USAGE_TICKET,
        )?;

        let ticket_part = parse_enc_ticket_part(&ticket_plaintext)?;

        // ── Step 4: Check ticket expiration ──
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::internal(format!("Clock error: {e}")))?
            .as_secs();

        if now > ticket_part.end_time + self.config.max_clock_skew_secs {
            return Err(AuthError::validation("Kerberos ticket has expired"));
        }

        if let Some(start) = ticket_part.start_time
            && now + self.config.max_clock_skew_secs < start
        {
            return Err(AuthError::validation("Kerberos ticket is not yet valid"));
        }

        // ── Step 5: Decrypt the authenticator using the session key ──
        let auth_etype = ap_req.authenticator.etype;
        let auth_plaintext = decrypt_aes_cts(
            &ticket_part.session_key_value,
            ap_req.authenticator.cipher,
            auth_etype,
            KEY_USAGE_AP_REQ_AUTH,
        )?;

        let authenticator = parse_authenticator(&auth_plaintext)?;

        // ── Step 6: Verify authenticator matches ticket ──
        if authenticator.crealm != ticket_part.crealm {
            return Err(AuthError::validation(
                "Authenticator crealm does not match ticket",
            ));
        }

        if authenticator.cname.to_string_without_realm()
            != ticket_part.cname.to_string_without_realm()
        {
            return Err(AuthError::validation(
                "Authenticator cname does not match ticket",
            ));
        }

        // ── Step 7: Check clock skew ──
        let time_diff = now.abs_diff(authenticator.ctime);

        if time_diff > self.config.max_clock_skew_secs {
            return Err(AuthError::validation(format!(
                "Authenticator clock skew too large: {time_diff}s (max {}s)",
                self.config.max_clock_skew_secs
            )));
        }

        // ── Step 8: Replay detection (ctime + cusec + cname) ──
        self.check_replay_authenticator(
            authenticator.ctime,
            authenticator.cusec,
            &authenticator.cname.to_string_without_realm(),
        )
        .await?;

        // ── Build result ──
        let client_principal = format!(
            "{}@{}",
            ticket_part.cname.to_string_without_realm(),
            ticket_part.crealm
        );
        let is_delegated = test_bit_flag(&ticket_part.flags_raw, 2); // bit 2 = forwarded

        let flags = KerberosTicketFlags {
            forwardable: test_bit_flag(&ticket_part.flags_raw, 1),
            forwarded: test_bit_flag(&ticket_part.flags_raw, 2),
            proxiable: test_bit_flag(&ticket_part.flags_raw, 3),
            proxy: test_bit_flag(&ticket_part.flags_raw, 4),
            may_postdate: test_bit_flag(&ticket_part.flags_raw, 5),
            postdated: test_bit_flag(&ticket_part.flags_raw, 6),
            renewable: test_bit_flag(&ticket_part.flags_raw, 8),
            pre_authent: test_bit_flag(&ticket_part.flags_raw, 10),
            hw_authent: test_bit_flag(&ticket_part.flags_raw, 11),
        };

        // Reject delegated tickets if not allowed
        if is_delegated && !self.config.allow_delegation {
            return Err(AuthError::validation(
                "Delegated (forwarded) tickets are not allowed by policy",
            ));
        }

        Ok(KerberosAuthResult {
            client_principal,
            realm: ticket_part.crealm,
            auth_time: ticket_part.auth_time,
            end_time: ticket_part.end_time,
            is_delegated,
            flags,
            response_token: None,
        })
    }

    /// Check for authenticator replay using (ctime, cusec, cname) tuple.
    async fn check_replay_authenticator(&self, ctime: u64, cusec: u32, cname: &str) -> Result<()> {
        // Build a unique key from the authenticator's identifying fields
        let mut hasher = sha2::Sha256::new();
        hasher.update(ctime.to_be_bytes());
        hasher.update(cusec.to_be_bytes());
        hasher.update(cname.as_bytes());
        let hash = hasher.finalize().to_vec();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::internal(format!("Clock error: {e}")))?
            .as_secs();

        let mut cache = self.replay_cache.write().await;

        // Evict stale entries
        let cutoff = now.saturating_sub(self.config.max_clock_skew_secs * 2);
        cache.retain(|_, &mut ts| ts > cutoff);

        if cache.contains_key(&hash) {
            return Err(AuthError::validation("Kerberos replay attack detected"));
        }

        if cache.len() >= self.config.replay_cache_max_entries {
            return Err(AuthError::internal("Kerberos replay cache full"));
        }

        cache.insert(hash, now);
        Ok(())
    }

    /// Check for replay attacks using a raw token hash (for backwards compat).
    pub async fn check_replay(&self, token_data: &[u8]) -> Result<()> {
        let hash = sha2::Sha256::digest(token_data).to_vec();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::internal(format!("Clock error: {e}")))?
            .as_secs();

        let mut cache = self.replay_cache.write().await;

        let cutoff = now.saturating_sub(self.config.max_clock_skew_secs * 2);
        cache.retain(|_, &mut ts| ts > cutoff);

        if cache.contains_key(&hash) {
            return Err(AuthError::validation("Kerberos replay attack detected"));
        }

        if cache.len() >= self.config.replay_cache_max_entries {
            return Err(AuthError::internal("Kerberos replay cache full"));
        }

        cache.insert(hash, now);
        Ok(())
    }

    /// Generate a mutual-authentication response token.
    #[allow(dead_code)]
    fn generate_response_token(&self) -> Result<Option<String>> {
        let rng = ring::rand::SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce)
            .map_err(|_| AuthError::crypto("Failed to generate SPNEGO response nonce"))?;

        let encoded = base64::engine::general_purpose::STANDARD.encode(nonce);
        Ok(Some(encoded))
    }
}

// ─── Keytab Parsing ──────────────────────────────────────────────────────────

/// Parse a Kerberos keytab file (MIT format).
///
/// Keytab format:
/// - 2 bytes: version (0x0502 for v2)
/// - Repeated entries: length-prefixed principal + key data
fn parse_keytab(data: &[u8]) -> Result<Vec<KeytabEntry>> {
    if data.len() < 4 {
        return Err(AuthError::config("Keytab file too short"));
    }

    // Check magic number
    let version = u16::from_be_bytes([data[0], data[1]]);
    if version != 0x0502 && version != 0x0501 {
        return Err(AuthError::config(format!(
            "Unsupported keytab version: 0x{version:04x}"
        )));
    }

    let mut entries = Vec::new();
    let mut pos = 2;

    while pos + 4 <= data.len() {
        let entry_len =
            i32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        if entry_len <= 0 {
            // Deleted/empty entry — skip
            pos += entry_len.unsigned_abs() as usize;
            continue;
        }
        let entry_len = entry_len as usize;

        if pos + entry_len > data.len() {
            break;
        }

        let entry_data = &data[pos..pos + entry_len];
        if let Ok(entry) = parse_keytab_entry(entry_data, version) {
            entries.push(entry);
        }

        pos += entry_len;
    }

    Ok(entries)
}

/// Parse a single keytab entry.
fn parse_keytab_entry(data: &[u8], _version: u16) -> Result<KeytabEntry> {
    if data.len() < 8 {
        return Err(AuthError::config("Keytab entry too short"));
    }

    // Read number of principal components
    let num_components = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;

    // Read realm
    if pos + 2 > data.len() {
        return Err(AuthError::config("Keytab entry truncated at realm length"));
    }
    let realm_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + realm_len > data.len() {
        return Err(AuthError::config("Keytab entry truncated at realm data"));
    }
    let realm = String::from_utf8_lossy(&data[pos..pos + realm_len]).to_string();
    pos += realm_len;

    // Read principal components
    let mut principal_parts = Vec::new();
    for _ in 0..num_components {
        if pos + 2 > data.len() {
            return Err(AuthError::config("Keytab entry truncated at component"));
        }
        let comp_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + comp_len > data.len() {
            return Err(AuthError::config(
                "Keytab entry truncated at component data",
            ));
        }
        principal_parts.push(String::from_utf8_lossy(&data[pos..pos + comp_len]).to_string());
        pos += comp_len;
    }
    let principal = format!("{}@{}", principal_parts.join("/"), realm);

    // Skip name_type (4 bytes), timestamp (4 bytes)
    pos += 8;
    if pos >= data.len() {
        return Err(AuthError::config("Keytab entry truncated at kvno"));
    }

    // Read kvno (1 byte in v1, may have 4-byte extension at end)
    let kvno = data.get(pos).copied().unwrap_or(0) as u32;
    pos += 1;

    // Read key type
    if pos + 2 > data.len() {
        return Err(AuthError::config("Keytab entry truncated at key type"));
    }
    let key_type = u16::from_be_bytes([data[pos], data[pos + 1]]) as u32;
    pos += 2;

    // Read key data
    if pos + 2 > data.len() {
        return Err(AuthError::config("Keytab entry truncated at key length"));
    }
    let key_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + key_len > data.len() {
        return Err(AuthError::config("Keytab entry truncated at key data"));
    }
    let key_data = data[pos..pos + key_len].to_vec();

    Ok(KeytabEntry {
        principal,
        realm,
        kvno,
        key_type,
        key_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = KerberosConfig::default();
        assert_eq!(config.max_clock_skew_secs, 300);
        assert!(!config.allow_delegation);
    }

    #[test]
    fn test_manager_requires_principal() {
        let config = KerberosConfig::default();
        let err = KerberosManager::new(config).unwrap_err();
        assert!(err.to_string().contains("service principal"));
    }

    #[test]
    fn test_manager_requires_realm() {
        let config = KerberosConfig {
            service_principal: "HTTP/server.example.com".into(),
            ..Default::default()
        };
        let err = KerberosManager::new(config).unwrap_err();
        assert!(err.to_string().contains("realm"));
    }

    #[test]
    fn test_manager_creation() {
        let config = KerberosConfig {
            service_principal: "HTTP/server.example.com@EXAMPLE.COM".into(),
            realm: "EXAMPLE.COM".into(),
            ..Default::default()
        };
        let mgr = KerberosManager::new(config);
        assert!(mgr.is_ok());
    }

    #[test]
    fn test_generate_challenge() {
        let config = KerberosConfig {
            service_principal: "HTTP/server.example.com@EXAMPLE.COM".into(),
            realm: "EXAMPLE.COM".into(),
            ..Default::default()
        };
        let mgr = KerberosManager::new(config).unwrap();
        assert_eq!(mgr.generate_challenge(), "Negotiate");
    }

    #[tokio::test]
    async fn test_replay_detection() {
        let config = KerberosConfig {
            service_principal: "HTTP/server.example.com@EXAMPLE.COM".into(),
            realm: "EXAMPLE.COM".into(),
            ..Default::default()
        };
        let mgr = KerberosManager::new(config).unwrap();

        let token_data = b"test_token_data";

        // First check should succeed
        mgr.check_replay(token_data).await.unwrap();

        // Second check with same data should fail (replay)
        let err = mgr.check_replay(token_data).await.unwrap_err();
        assert!(err.to_string().contains("replay"));
    }

    #[test]
    fn test_invalid_keytab() {
        let result = parse_keytab(&[0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_spnego_state_variants() {
        assert_eq!(SpnegoState::Initial, SpnegoState::Initial);
        assert_ne!(SpnegoState::Initial, SpnegoState::Completed);
    }

    // ── DER parser tests ─────────────────────────────────────────────────

    #[test]
    fn test_parse_der_integer() {
        // DER INTEGER: 02 01 05 → value = 5
        let data = [0x02, 0x01, 0x05];
        let (tlv, rest) = parse_der(&data).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.class, 0); // Universal
        assert_eq!(tlv.tag_num, 2); // INTEGER
        assert_eq!(parse_der_integer(tlv.value).unwrap(), 5);
    }

    #[test]
    fn test_parse_der_sequence() {
        // SEQUENCE { INTEGER 5, INTEGER 14 }
        // 30 06 02 01 05 02 01 0e
        let data = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0e];
        let (tlv, _) = parse_der(&data).unwrap();
        assert_eq!(tlv.tag_num, 16); // SEQUENCE
        assert!(tlv.constructed);
        let contents = parse_der_contents(tlv.value).unwrap();
        assert_eq!(contents.len(), 2);
        assert_eq!(parse_der_integer(contents[0].value).unwrap(), 5);
        assert_eq!(parse_der_integer(contents[1].value).unwrap(), 14);
    }

    #[test]
    fn test_parse_der_context_tag() {
        // [0] EXPLICIT INTEGER 5 → a0 03 02 01 05
        let data = [0xa0, 0x03, 0x02, 0x01, 0x05];
        let (tlv, _) = parse_der(&data).unwrap();
        assert_eq!(tlv.class, 2); // Context-specific
        assert_eq!(tlv.tag_num, 0);
        let inner = unwrap_explicit(&tlv).unwrap();
        assert_eq!(parse_der_integer(inner.value).unwrap(), 5);
    }

    #[test]
    fn test_parse_der_oid() {
        // OID 1.3.6.1.5.5.2 (SPNEGO)
        let data = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        let (tlv, _) = parse_der(&data).unwrap();
        assert!(oid_matches(&tlv, SPNEGO_OID_BYTES));
        assert!(!oid_matches(&tlv, KRB5_OID_BYTES));
    }

    #[test]
    fn test_parse_der_truncated_fails() {
        assert!(parse_der(&[]).is_err());
        assert!(parse_der(&[0x02]).is_err()); // missing length
        assert!(parse_der(&[0x02, 0x05, 0x01]).is_err()); // length says 5, only 1 byte
    }

    // ── n-fold tests (RFC 3961 test vectors) ─────────────────────────────

    #[test]
    fn test_nfold_64bit() {
        // n-fold("012345", 64) = be072631276b1955 (RFC 3961 §A.1)
        let result = nfold(b"012345", 8);
        assert_eq!(result, vec![0xBE, 0x07, 0x26, 0x31, 0x27, 0x6B, 0x19, 0x55]);
    }

    #[test]
    fn test_nfold_56bit() {
        // n-fold("password", 56) = 78 A0 7B 6C AF 85 FA
        let result = nfold(b"password", 7);
        assert_eq!(result, vec![0x78, 0xA0, 0x7B, 0x6C, 0xAF, 0x85, 0xFA]);
    }

    #[test]
    fn test_nfold_64bit_long_input() {
        // n-fold("Rough Consensus, and Running Code", 64) = bb6ed30870b7f0e0 (RFC 3961 §A.1)
        let result = nfold(b"Rough Consensus, and Running Code", 8);
        assert_eq!(result, vec![0xBB, 0x6E, 0xD3, 0x08, 0x70, 0xB7, 0xF0, 0xE0]);
    }

    #[test]
    fn test_nfold_168bit() {
        // n-fold("password", 168) = 59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e (RFC 3961 §A.1)
        let result = nfold(b"password", 21);
        assert_eq!(
            result,
            vec![
                0x59, 0xE4, 0xA8, 0xCA, 0x7C, 0x03, 0x85, 0xC3, 0xC3, 0x7B, 0x3F, 0x6D, 0x20, 0x00,
                0x24, 0x7C, 0xB6, 0xE6, 0xBD, 0x5B, 0x3E,
            ]
        );
    }

    // ── AES crypto tests ─────────────────────────────────────────────────

    #[test]
    fn test_aes_ecb_roundtrip() {
        let key = [0x42u8; 16];
        let block = [0x01u8; 16];
        let encrypted = aes_ecb_encrypt(&key, &block);
        let decrypted = aes_ecb_decrypt(&key, &encrypted);
        assert_eq!(decrypted, block);
    }

    #[test]
    fn test_aes_ecb_256_roundtrip() {
        let key = [0x42u8; 32];
        let block = [0xABu8; 16];
        let encrypted = aes_ecb_encrypt(&key, &block);
        let decrypted = aes_ecb_decrypt(&key, &encrypted);
        assert_eq!(decrypted, block);
    }

    #[test]
    fn test_aes_cbc_decrypt_two_blocks() {
        let key = [0x00u8; 16];
        // Encrypt two zero blocks with zero key and zero IV using CBC
        let p0 = [0u8; 16];
        let p1 = [0u8; 16];
        // CBC encrypt: C0 = E(P0 XOR 0) = E(0), C1 = E(P1 XOR C0)
        let c0 = aes_ecb_encrypt(&key, &p0);
        let p1_xor_c0: [u8; 16] = xor_bytes(&p1, &c0).try_into().unwrap();
        let c1 = aes_ecb_encrypt(&key, &p1_xor_c0);
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&c0);
        ciphertext.extend_from_slice(&c1);

        let plaintext = aes_cbc_decrypt(&key, &ciphertext).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&p0);
        expected.extend_from_slice(&p1);
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_aes_cts_decrypt_single_block() {
        let key = [0x00u8; 16];
        let plaintext = [0x42u8; 16];
        // Single block: CTS = just ECB
        let ciphertext = aes_ecb_encrypt(&key, &plaintext);
        let decrypted = aes_cts_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_derive_key_produces_correct_length() {
        let key_128 = [0x42u8; 16];
        let derived = derive_key_aes(&key_128, 2, 0xAA);
        assert_eq!(derived.len(), 16);

        let key_256 = [0x42u8; 32];
        let derived = derive_key_aes(&key_256, 2, 0xAA);
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_hmac_sha1_produces_20_bytes() {
        let result = hmac_sha1(b"key", b"data");
        assert_eq!(result.len(), 20);
    }

    // ── Keytab tests ─────────────────────────────────────────────────────

    #[test]
    fn test_valid_keytab_v2_header() {
        // Minimal valid keytab: version 0x0502, followed by zero-length remaining data
        let data = [0x05, 0x02, 0x00, 0x00];
        let entries = parse_keytab(&data).unwrap();
        assert!(entries.is_empty());
    }

    // ── Ticket flag tests ────────────────────────────────────────────────

    #[test]
    fn test_ticket_flags_parsing() {
        // Bit 1 = forwardable, bit 8 = renewable
        // Bit 1 in byte 0 is position 6 (0x40), bit 8 in byte 1 is position 7 (0x80)
        let flags = [0x00, 0x40, 0x80, 0x00, 0x00]; // [unused_bits=0] [byte0] [byte1] ...
        assert!(test_bit_flag(&flags, 1)); // forwardable
        assert!(!test_bit_flag(&flags, 2)); // forwarded
        assert!(test_bit_flag(&flags, 8)); // renewable
        assert!(!test_bit_flag(&flags, 10)); // pre_authent
    }

    // ── Builder & preset tests ───────────────────────────────────────────

    #[test]
    fn test_kerberos_config_builder() {
        let config = KerberosConfig::builder("HTTP/srv@REALM", "REALM")
            .keytab_path("/etc/krb5.keytab")
            .add_kdc("kdc1:88")
            .add_kdc("kdc2:88")
            .max_clock_skew_secs(600)
            .build();

        assert_eq!(config.service_principal, "HTTP/srv@REALM");
        assert_eq!(config.realm, "REALM");
        assert_eq!(config.keytab_path.as_deref(), Some("/etc/krb5.keytab"));
        assert_eq!(config.kdc_addresses, vec!["kdc1:88", "kdc2:88"]);
        assert_eq!(config.max_clock_skew_secs, 600);
        assert!(!config.allow_delegation);
    }

    #[test]
    fn test_kerberos_config_active_directory() {
        let config = KerberosConfig::active_directory("HTTP/srv@AD.COM", "AD.COM");
        assert_eq!(config.service_principal, "HTTP/srv@AD.COM");
        assert_eq!(config.realm, "AD.COM");
        assert!(config.allow_delegation);
        // Should produce a valid manager
        let mgr = KerberosManager::new(config);
        assert!(mgr.is_ok());
    }

    #[test]
    fn test_kerberos_builder_override() {
        let config = KerberosConfig::builder("HTTP/srv@REALM", "REALM")
            .allow_delegation(true)
            .replay_cache_max_entries(500)
            .build();

        assert!(config.allow_delegation);
        assert_eq!(config.replay_cache_max_entries, 500);
    }
}
