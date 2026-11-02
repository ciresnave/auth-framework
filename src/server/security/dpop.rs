//! OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP) - RFC 9449
//!
//! This module implements DPoP (Demonstrating Proof-of-Possession), which provides:
//! 1. Application-layer proof-of-possession for OAuth 2.0 access tokens
//! 2. Protection against token theft and replay attacks
//! 3. JWT-based proof tokens bound to HTTP requests

use crate::errors::{AuthError, Result};
use crate::security::secure_jwt::SecureJwtValidator;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DPoP proof token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofClaims {
    /// JWT ID - unique identifier for this proof
    pub jti: String,

    /// HTTP method of the request
    pub htm: String,

    /// HTTP URI of the request (without query and fragment)
    pub htu: String,

    /// Issued at time
    pub iat: i64,

    /// Access token hash (only for access token requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,

    /// Nonce (for authorization server to prevent replay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// DPoP key binding configuration
#[derive(Debug, Clone)]
pub struct DpopKeyBinding {
    /// Public key in JWK format
    pub public_key_jwk: serde_json::Value,

    /// Key algorithm (ES256, RS256, etc.)
    pub algorithm: String,

    /// Key ID (optional)
    pub key_id: Option<String>,
}

/// DPoP-bound access token confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopConfirmation {
    /// JWK thumbprint of the public key
    pub jkt: String,
}

/// DPoP validation result
#[derive(Debug, Clone)]
pub struct DpopValidationResult {
    /// Whether the DPoP proof is valid
    pub is_valid: bool,

    /// Validation errors (if any)
    pub errors: Vec<String>,

    /// Extracted public key JWK
    pub public_key_jwk: Option<serde_json::Value>,

    /// JWK thumbprint
    pub jwk_thumbprint: Option<String>,
}

/// A DPoP proof that passed every check but has not been recorded yet.
///
/// Recording a proof's `jti` uses a cache slot, so a caller that still has to authenticate
/// something else (the access token, the request) holds the proof here and commits it with
/// `commit_dpop_proof` only once that has succeeded.
#[must_use = "a verified proof is not recorded until it is committed"]
#[derive(Debug)]
pub(crate) struct VerifiedDpopProof {
    result: DpopValidationResult,
    replay_id: String,
    keep_until: DateTime<Utc>,
}

/// Append a DER length: one byte below 128, otherwise `0x80 | n` and the `n` length bytes.
fn der_push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = &bytes[skip..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

/// A DER INTEGER holding the unsigned big-endian number `value` (not empty).
fn der_unsigned_integer(value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(value.len() + 1);
    if value[0] & 0x80 != 0 {
        body.push(0x00); // keep it positive
    }
    body.extend_from_slice(value);
    let mut out = vec![0x02];
    der_push_length(&mut out, body.len());
    out.extend(body);
    out
}

/// DPoP manager for handling proof-of-possession
pub struct DpopManager {
    /// Used nonces to prevent replay attacks
    used_nonces: tokio::sync::RwLock<HashMap<String, DateTime<Utc>>>,

    /// DPoP proof expiration time (default: 60 seconds)
    proof_expiration: Duration,

    /// Most replay records kept at once.
    max_replay_entries: usize,

    /// The shortest time between two sweeps of a full cache.
    sweep_interval: Duration,

    /// When the cache was last swept.
    last_sweep: std::sync::Mutex<DateTime<Utc>>,

    /// The earliest time any held record expires (the far future when none is held).
    earliest_expiry: std::sync::Mutex<DateTime<Utc>>,

    /// Validates the signature and standard claims of JWT access tokens.
    jwt_validator: SecureJwtValidator,

    /// Maximum clock skew allowed (default: 30 seconds)
    clock_skew: Duration,
}

impl std::fmt::Debug for DpopManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("DpopManager");
        d.field(
            "used_nonces",
            &crate::utils::redact::redacted(&self.used_nonces),
        );
        d.field("proof_expiration", &self.proof_expiration);
        d.field("clock_skew", &self.clock_skew);
        d.finish()
    }
}

#[cfg(test)]
impl DpopManager {
    /// How many replay records are held (tests).
    pub(crate) async fn replay_record_count(&self) -> usize {
        self.used_nonces.read().await.len()
    }
}

#[cfg(test)]
impl DpopManager {
    /// Put a replay record in place, valid until `until` (tests).
    pub(crate) async fn insert_record_for_test(&self, key: &str, until: DateTime<Utc>) {
        {
            let mut earliest = self
                .earliest_expiry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *earliest = (*earliest).min(until);
        }
        self.used_nonces
            .write()
            .await
            .insert(key.to_string(), until);
    }
}

impl DpopManager {
    /// Create a new DPoP manager
    pub fn new(jwt_validator: SecureJwtValidator) -> Self {
        Self {
            used_nonces: tokio::sync::RwLock::new(HashMap::new()),
            proof_expiration: Duration::seconds(60),
            max_replay_entries: 100_000,
            sweep_interval: Duration::seconds(1),
            last_sweep: std::sync::Mutex::new(DateTime::<Utc>::UNIX_EPOCH),
            earliest_expiry: std::sync::Mutex::new(DateTime::<Utc>::MAX_UTC),
            jwt_validator,
            clock_skew: Duration::seconds(30),
        }
    }

    /// Validate a DPoP proof JWT
    pub async fn validate_dpop_proof(
        &self,
        dpop_proof: &str,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> Result<DpopValidationResult> {
        self.validate_dpop_proof_for_key(
            dpop_proof,
            http_method,
            http_uri,
            access_token,
            expected_nonce,
            None,
        )
        .await
    }

    /// Like [`Self::validate_dpop_proof`]; when `expected_jkt` is given, the proof must also be
    /// signed by the key with that thumbprint. That is checked before the proof's `jti` is
    /// recorded, so a proof from any other key leaves no record behind.
    pub async fn validate_dpop_proof_for_key(
        &self,
        dpop_proof: &str,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        expected_nonce: Option<&str>,
        expected_jkt: Option<&str>,
    ) -> Result<DpopValidationResult> {
        let verified = self
            .verify_dpop_proof(
                dpop_proof,
                http_method,
                http_uri,
                access_token,
                expected_nonce,
                expected_jkt,
            )
            .await?;
        self.commit_dpop_proof(verified).await
    }

    /// Check a proof without recording it: signature, key binding, claims and a read-only look
    /// at the replay cache. The caller commits it with `commit_dpop_proof` after it has
    /// authenticated whatever else the request carries.
    pub(crate) async fn verify_dpop_proof(
        &self,
        dpop_proof: &str,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        expected_nonce: Option<&str>,
        expected_jkt: Option<&str>,
    ) -> Result<VerifiedDpopProof> {
        let mut errors = Vec::new();

        // Parse the DPoP proof JWT
        let (header, claims) = self.parse_dpop_proof(dpop_proof).map_err(|e| {
            errors.push(format!("Failed to parse DPoP proof: {}", e));
            e
        })?;

        // Validate JWT header; a header that is not a DPoP header stops here.
        self.validate_dpop_header(&header, &mut errors)?;
        if !errors.is_empty() {
            return Err(Self::rejected(&errors));
        }

        // Extract public key from header
        let public_key_jwk = header
            .get("jwk")
            .ok_or_else(|| AuthError::auth_method("dpop", "Missing JWK in DPoP proof header"))?
            .clone();

        // RFC 9449 section 4.2: the jwk header MUST NOT contain a private key.
        if let Some(obj) = public_key_jwk.as_object() {
            for private_member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                if obj.contains_key(private_member) {
                    return Err(AuthError::auth_method(
                        "dpop",
                        "DPoP proof jwk header contains private key material",
                    ));
                }
            }
        }

        // Calculate JWK thumbprint
        let jwk_thumbprint = self.calculate_jwk_thumbprint(&public_key_jwk)?;

        // Verify the signature first: nothing unsigned reaches the replay cache.
        self.verify_dpop_signature(dpop_proof, &public_key_jwk, &mut errors)?;

        // The key the token is bound to, compared before anything is recorded.
        if let Some(expected) = expected_jkt
            && !bool::from(subtle::ConstantTimeEq::ct_eq(
                jwk_thumbprint.as_bytes(),
                expected.as_bytes(),
            ))
        {
            return Err(AuthError::auth_method(
                "dpop",
                "DPoP proof key does not match the token's key binding",
            ));
        }

        // Validate DPoP proof claims
        self.validate_dpop_claims(
            &claims,
            http_method,
            http_uri,
            access_token,
            expected_nonce,
            &mut errors,
        )
        .await?;

        // The jti is the replay key: bound its size before it is used for anything.
        if claims.jti.is_empty() || claims.jti.len() > 256 {
            errors.push("DPoP proof jti must be 1 to 256 bytes".to_string());
        }

        // A claim that fails is a refusal, not a result for the caller to remember to read.
        if !errors.is_empty() {
            return Err(Self::rejected(&errors));
        }

        // Only now, with an iat inside the clock skew, is there arithmetic to do on it.
        let keep_until = chrono::TimeZone::timestamp_opt(&Utc, claims.iat, 0)
            .single()
            .and_then(|iat| iat.checked_add_signed(self.proof_expiration + self.clock_skew))
            .ok_or_else(|| AuthError::auth_method("dpop", "DPoP proof iat is out of range"))?;
        let key = Self::replay_key(&jwk_thumbprint, &claims.jti);
        if self.used_nonces.read().await.contains_key(&key) {
            return Err(Self::rejected(&["DPoP proof JTI already used".to_string()]));
        }

        Ok(VerifiedDpopProof {
            result: DpopValidationResult {
                is_valid: true,
                errors,
                public_key_jwk: Some(public_key_jwk),
                jwk_thumbprint: Some(jwk_thumbprint),
            },
            replay_id: key,
            keep_until,
        })
    }

    /// Record a verified proof so it cannot be used again.
    ///
    /// A record is kept until the proof could no longer be accepted (iat + lifetime + skew), is
    /// keyed by a hash of the proof key and the jti (a fixed size, and one client cannot spend
    /// another's jti), and the cache is bounded: when it is full of live records the proof is
    /// refused rather than an older record evicted, since an evicted record could be replayed.
    /// A full cache is swept at most once per sweep interval.
    pub(crate) async fn commit_dpop_proof(
        &self,
        verified: VerifiedDpopProof,
    ) -> Result<DpopValidationResult> {
        let now = Utc::now();
        let mut used = self.used_nonces.write().await;
        let full = used.len() >= self.max_replay_entries;
        if full || used.len().is_multiple_of(256) {
            let due = {
                let mut last = self.last_sweep.lock().unwrap_or_else(|e| e.into_inner());
                if now - *last >= self.sweep_interval {
                    *last = now;
                    true
                } else {
                    false
                }
            };
            // A full cache that holds an expired record is swept whatever the interval: the
            // proof in hand must not be refused for room that expired records are taking.
            let expired_waiting = *self
                .earliest_expiry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                <= now;
            if due || (full && expired_waiting) {
                used.retain(|_, until| *until > now);
                *self
                    .earliest_expiry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = used
                    .values()
                    .min()
                    .copied()
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
            }
        }
        if used.contains_key(&verified.replay_id) {
            return Err(Self::rejected(&["DPoP proof JTI already used".to_string()]));
        }
        if used.len() >= self.max_replay_entries {
            return Err(Self::rejected(&["DPoP replay cache is full".to_string()]));
        }
        {
            let mut earliest = self
                .earliest_expiry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *earliest = (*earliest).min(verified.keep_until);
        }
        used.insert(verified.replay_id, verified.keep_until);
        Ok(verified.result)
    }

    /// The replay record key: a fixed-size hash of the proof key and the jti.
    fn replay_key(jwk_thumbprint: &str, jti: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(jwk_thumbprint.as_bytes());
        hasher.update([0x1f]);
        hasher.update(jti.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    /// The error returned when a proof fails any check.
    fn rejected(errors: &[String]) -> AuthError {
        AuthError::auth_method(
            "dpop",
            format!("DPoP proof rejected: {}", errors.join("; ")),
        )
    }

    /// Create DPoP confirmation for access token
    pub fn create_dpop_confirmation(
        &self,
        public_key_jwk: &serde_json::Value,
    ) -> Result<DpopConfirmation> {
        let jkt = self.calculate_jwk_thumbprint(public_key_jwk)?;

        Ok(DpopConfirmation { jkt })
    }

    /// Validate DPoP-bound access token
    pub fn validate_dpop_bound_token(
        &self,
        token_confirmation: &DpopConfirmation,
        dpop_proof_jwk: &serde_json::Value,
    ) -> Result<bool> {
        let proof_thumbprint = self.calculate_jwk_thumbprint(dpop_proof_jwk)?;

        if bool::from(subtle::ConstantTimeEq::ct_eq(
            token_confirmation.jkt.as_bytes(),
            proof_thumbprint.as_bytes(),
        )) {
            Ok(true)
        } else {
            Err(AuthError::auth_method(
                "dpop",
                "DPoP proof key does not match the token's key binding",
            ))
        }
    }

    /// Validate a DPoP-bound JWT access token and the proof presented with it.
    ///
    /// The token is validated first, with `key`: signature, expiry and the other standard
    /// claims, by the [`SecureJwtValidator`] this manager was built with. It must be an access
    /// token (`typ` of `access`; a refresh token, or a token with no `typ`, is refused) issued for
    /// `audience`, which is required: the validator checks an audience only when it is configured
    /// with one. Only then is its `cnf` claim read, and the proof must be signed by the key with
    /// the `jkt` it names, carry the token's hash (`ath`), and match the request. The proof is
    /// recorded last.
    pub async fn validate_dpop_bound_jwt(
        &self,
        access_token: &str,
        key: &DecodingKey,
        audience: &str,
        dpop_proof: &str,
        http_method: &str,
        http_uri: &str,
    ) -> Result<()> {
        let claims = self
            .jwt_validator
            .validate_token(access_token, key)
            .map_err(|e| {
                tracing::warn!("DPoP-bound access token refused: {e}");
                AuthError::token("Invalid DPoP-bound access token".to_string())
            })?;

        // The validator skips its token-type check for an empty `typ` and, by default, allows
        // refresh tokens: this function takes access tokens only.
        if claims.typ != "access" {
            return Err(AuthError::token("Not an access token".to_string()));
        }
        // And it checks an audience only if it was configured with one.
        if claims.aud != audience {
            return Err(AuthError::token(
                "Access token is for another audience".to_string(),
            ));
        }

        // The signature has been checked, so the payload can be read.
        let payload = access_token
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok())
            .ok_or_else(|| AuthError::token("Invalid access token payload".to_string()))?;
        let jkt = payload
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                AuthError::token("Access token carries no DPoP key binding (cnf.jkt)".to_string())
            })?;

        self.validate_dpop_proof_for_key(
            dpop_proof,
            http_method,
            http_uri,
            Some(access_token),
            None,
            Some(jkt),
        )
        .await?;
        Ok(())
    }

    /// Formerly "validated" a DPoP-bound access token. It never checked the token's signature:
    /// it read the claims of a JWT as they stood, so a forged token naming the proof's key was
    /// accepted, and it could not look at an opaque token at all. It now always refuses.
    #[deprecated(
        since = "0.6.0-rc202",
        note = "it could not establish that the access token is genuine; use `validate_dpop_bound_jwt`, or validate the token yourself and call `validate_dpop_proof_for_key` with its `jkt`"
    )]
    pub async fn validate_dpop_bound_access_token(
        &self,
        _access_token: &str,
        _token_confirmation: &DpopConfirmation,
        _dpop_proof: &str,
        _http_method: &str,
        _http_uri: &str,
    ) -> Result<bool> {
        Err(AuthError::token(
            "validate_dpop_bound_access_token cannot establish that the access token is genuine; use validate_dpop_bound_jwt, or validate the token and call validate_dpop_proof_for_key"
                .to_string(),
        ))
    }

    /// Generate a nonce for DPoP proof
    pub fn generate_nonce(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        URL_SAFE_NO_PAD.encode(nonce)
    }

    /// Clean up expired nonces
    pub async fn cleanup_expired_nonces(&self) {
        self.sweep(Utc::now()).await;
    }

    /// Drop the replay records that no longer matter at time `at`.
    async fn sweep(&self, at: DateTime<Utc>) {
        let mut nonces = self.used_nonces.write().await;
        // Each record is the time until which its proof could still be accepted.
        nonces.retain(|_, until| *until > at);
    }

    /// Parse DPoP proof JWT and extract header and claims
    fn parse_dpop_proof(&self, dpop_proof: &str) -> Result<(serde_json::Value, DpopProofClaims)> {
        if dpop_proof.len() > 16 * 1024 {
            return Err(AuthError::auth_method("dpop", "DPoP proof is too large"));
        }
        // Split JWT into parts
        let parts: Vec<&str> = dpop_proof.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::auth_method("dpop", "Invalid JWT format"));
        }

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| AuthError::auth_method("dpop", "Invalid JWT header encoding"))?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| AuthError::auth_method("dpop", "Invalid JWT header JSON"))?;

        // Decode claims
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::auth_method("dpop", "Invalid JWT claims encoding"))?;
        let claims: DpopProofClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| AuthError::auth_method("dpop", "Invalid DPoP proof claims"))?;

        Ok((header, claims))
    }

    /// Validate DPoP JWT header
    fn validate_dpop_header(
        &self,
        header: &serde_json::Value,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        // Check required fields
        if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
            errors.push("DPoP proof must have 'typ' header value 'dpop+jwt'".to_string());
        }

        if header.get("alg").and_then(|v| v.as_str()).is_none() {
            errors.push("DPoP proof missing 'alg' header".to_string());
        }

        if header.get("jwk").is_none() {
            errors.push("DPoP proof missing 'jwk' header".to_string());
        }

        // Validate algorithm is not 'none'
        if let Some(alg) = header.get("alg").and_then(|v| v.as_str())
            && alg == "none"
        {
            errors.push("DPoP proof algorithm cannot be 'none'".to_string());
        }

        Ok(())
    }

    /// Validate DPoP proof claims
    async fn validate_dpop_claims(
        &self,
        claims: &DpopProofClaims,
        http_method: &str,
        http_uri: &str,
        access_token: Option<&str>,
        expected_nonce: Option<&str>,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        let now = Utc::now();
        let iat = Utc
            .timestamp_opt(claims.iat, 0)
            .single()
            .unwrap_or_else(|| now - Duration::hours(1));

        // Validate timestamp
        let min_time = now - self.proof_expiration - self.clock_skew;
        let max_time = now + self.clock_skew;

        if iat < min_time {
            errors.push("DPoP proof is too old".to_string());
        }

        if iat > max_time {
            errors.push("DPoP proof timestamp is in the future".to_string());
        }

        // Validate HTTP method and URI
        if claims.htm != http_method {
            errors.push(format!(
                "DPoP proof HTTP method '{}' does not match request method '{}'",
                claims.htm, http_method
            ));
        }

        // Parse and compare URIs (normalize by removing query and fragment)
        let expected_uri = self.normalize_uri(http_uri)?;
        let proof_uri = self.normalize_uri(&claims.htu)?;

        if proof_uri != expected_uri {
            errors.push(format!(
                "DPoP proof HTTP URI '{}' does not match request URI '{}'",
                claims.htu, http_uri
            ));
        }

        // RFC 9449 section 4.2/7.1: a proof presented with an access token MUST carry its hash.
        if let Some(token) = access_token {
            let expected_ath = self.calculate_access_token_hash(token)?;
            match &claims.ath {
                Some(ath) => {
                    use subtle::ConstantTimeEq as _;
                    if !bool::from(ath.as_bytes().ct_eq(expected_ath.as_bytes())) {
                        errors.push("DPoP proof access token hash does not match".to_string());
                    }
                }
                None => errors.push(
                    "DPoP proof is missing the 'ath' claim required with an access token"
                        .to_string(),
                ),
            }
        }

        // Validate nonce if expected
        if let Some(expected) = expected_nonce {
            match &claims.nonce {
                Some(nonce) if nonce == expected => {}
                Some(_) => {
                    errors.push("DPoP proof nonce does not match expected value".to_string());
                }
                None => {
                    errors.push("DPoP proof missing required nonce".to_string());
                }
            }
        }

        Ok(())
    }

    /// Verify DPoP JWT signature with REAL cryptographic validation using Ring
    fn verify_dpop_signature(
        &self,
        dpop_proof: &str,
        public_key_jwk: &serde_json::Value,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        use ring::signature;

        // Extract algorithm from JWT header
        let parts: Vec<&str> = dpop_proof.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::validation("Invalid JWT format for DPoP proof"));
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| {
            AuthError::validation("Invalid JWT header encoding for signature verification")
        })?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| AuthError::validation("Invalid JWT header JSON"))?;

        let alg_str = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::validation("Missing algorithm in JWT header"))?;

        // Prepare JWT signature verification data
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| AuthError::validation("Invalid JWT signature encoding"))?;

        // Extract key material from JWK for direct Ring cryptographic validation
        let key_type = public_key_jwk
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::validation("Missing key type in JWK"))?;

        // Perform REAL cryptographic validation using Ring
        match key_type {
            "RSA" => {
                // Extract RSA public key components
                let n = public_key_jwk
                    .get("n")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::validation("Missing 'n' parameter in RSA JWK"))?;
                let e = public_key_jwk
                    .get("e")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::validation("Missing 'e' parameter in RSA JWK"))?;

                // Decode RSA components
                let n_bytes = URL_SAFE_NO_PAD.decode(n.as_bytes()).map_err(|e| {
                    AuthError::validation(format!("Invalid base64url 'n' parameter: {}", e))
                })?;
                let e_bytes = URL_SAFE_NO_PAD.decode(e.as_bytes()).map_err(|e| {
                    AuthError::validation(format!("Invalid base64url 'e' parameter: {}", e))
                })?;

                if n_bytes.is_empty() || e_bytes.is_empty() {
                    return Err(AuthError::validation("Empty RSA JWK parameter"));
                }

                // The key as a DER RSAPublicKey: SEQUENCE { modulus INTEGER, exponent INTEGER },
                // lengths in the long form when they need it (a 2048-bit modulus does).
                let mut content = der_unsigned_integer(&n_bytes);
                content.extend(der_unsigned_integer(&e_bytes));
                let mut public_key_der = vec![0x30];
                der_push_length(&mut public_key_der, content.len());
                public_key_der.extend_from_slice(&content);

                // Select Ring verification algorithm
                let verification_algorithm = match alg_str {
                    "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                    "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                    "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                    "PS256" => &signature::RSA_PSS_2048_8192_SHA256,
                    "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
                    "PS512" => &signature::RSA_PSS_2048_8192_SHA512,
                    _ => {
                        return Err(AuthError::validation(format!(
                            "Unsupported RSA algorithm: {}",
                            alg_str
                        )));
                    }
                };

                // Create public key and verify with timing-safe operations
                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, &public_key_der);

                // Use constant-time verification to prevent timing attacks
                match public_key.verify(signing_input.as_bytes(), &signature_bytes) {
                    Ok(()) => {
                        // Add timing protection: always do the same amount of work
                        let _ = std::hint::black_box(alg_str);
                        tracing::debug!(
                            "DPoP proof RSA signature successfully verified using Ring with algorithm {}",
                            alg_str
                        );
                    }
                    Err(_) => {
                        // Add timing protection: always do the same amount of work
                        let _ = std::hint::black_box(alg_str);
                        let error_msg = format!(
                            "DPoP proof RSA signature verification failed with algorithm {}",
                            alg_str
                        );
                        errors.push(error_msg.clone());
                        tracing::warn!("{}", error_msg);
                        return Err(AuthError::validation(
                            "DPoP RSA signature verification failed",
                        ));
                    }
                }
            }
            "EC" => {
                // Extract elliptic curve public key components
                let curve = public_key_jwk
                    .get("crv")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::validation("Missing 'crv' parameter in EC JWK"))?;
                let x = public_key_jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::validation("Missing 'x' parameter in EC JWK"))?;
                let y = public_key_jwk
                    .get("y")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AuthError::validation("Missing 'y' parameter in EC JWK"))?;

                // Decode EC coordinates
                let x_bytes = URL_SAFE_NO_PAD.decode(x.as_bytes()).map_err(|e| {
                    AuthError::validation(format!("Invalid base64url 'x' parameter: {}", e))
                })?;
                let y_bytes = URL_SAFE_NO_PAD.decode(y.as_bytes()).map_err(|e| {
                    AuthError::validation(format!("Invalid base64url 'y' parameter: {}", e))
                })?;

                // Select verification algorithm and coordinate length
                let (verification_algorithm, expected_coord_len) = match (curve, alg_str) {
                    ("P-256", "ES256") => (&signature::ECDSA_P256_SHA256_FIXED, 32),
                    ("P-384", "ES384") => (&signature::ECDSA_P384_SHA384_FIXED, 48),
                    _ => {
                        return Err(AuthError::validation(format!(
                            "Unsupported EC curve/algorithm combination: {}/{}",
                            curve, alg_str
                        )));
                    }
                };

                // Validate coordinate lengths
                if x_bytes.len() != expected_coord_len || y_bytes.len() != expected_coord_len {
                    return Err(AuthError::validation(format!(
                        "Invalid coordinate length for curve {}: expected {}, got x={}, y={}",
                        curve,
                        expected_coord_len,
                        x_bytes.len(),
                        y_bytes.len()
                    )));
                }

                // A JWS ECDSA signature is exactly r || s, two coordinates wide (RFC 7518 3.4);
                // a DER-encoded signature is not one.
                if signature_bytes.len() != expected_coord_len * 2 {
                    return Err(AuthError::validation(format!(
                        "DPoP {alg_str} signature must be the {}-byte r||s form (RFC 7518 section 3.4), got {} bytes",
                        expected_coord_len * 2,
                        signature_bytes.len()
                    )));
                }

                // Create uncompressed point format (0x04 || x || y)
                let mut public_key_bytes = Vec::with_capacity(1 + expected_coord_len * 2);
                public_key_bytes.push(0x04); // Uncompressed point indicator
                public_key_bytes.extend_from_slice(&x_bytes);
                public_key_bytes.extend_from_slice(&y_bytes);

                // Create public key for verification
                let public_key =
                    signature::UnparsedPublicKey::new(verification_algorithm, &public_key_bytes);

                // Verify ECDSA signature with timing protection
                match public_key.verify(signing_input.as_bytes(), &signature_bytes) {
                    Ok(()) => {
                        // Add timing protection: always do the same amount of work
                        let _ = std::hint::black_box((curve, alg_str));
                        tracing::debug!(
                            "DPoP proof ECDSA signature successfully verified using Ring with curve {} and algorithm {}",
                            curve,
                            alg_str
                        );
                    }
                    Err(_) => {
                        // Add timing protection: always do the same amount of work
                        let _ = std::hint::black_box((curve, alg_str));
                        let error_msg = format!(
                            "DPoP proof ECDSA signature verification failed with curve {} and algorithm {}",
                            curve, alg_str
                        );
                        errors.push(error_msg.clone());
                        tracing::warn!("{}", error_msg);
                        return Err(AuthError::validation(
                            "DPoP ECDSA signature verification failed",
                        ));
                    }
                }
            }
            _ => {
                return Err(AuthError::validation(format!(
                    "Unsupported key type for cryptographic verification: {}",
                    key_type
                )));
            }
        }

        // Additional validation: verify that the JWT contains required DPoP claims
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| AuthError::validation("Invalid JWT claims encoding"))?;
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|_| AuthError::validation("Invalid JWT claims JSON"))?;

        // Check for required DPoP claims
        if claims.get("htm").is_none() {
            errors.push("DPoP proof missing 'htm' claim".to_string());
        }
        if claims.get("htu").is_none() {
            errors.push("DPoP proof missing 'htu' claim".to_string());
        }
        if claims.get("jti").is_none() {
            errors.push("DPoP proof missing 'jti' claim".to_string());
        }
        if claims.get("iat").is_none() {
            errors.push("DPoP proof missing 'iat' claim".to_string());
        }

        Ok(())
    }

    /// Calculate JWK thumbprint (RFC 7638)
    fn calculate_jwk_thumbprint(&self, jwk: &serde_json::Value) -> Result<String> {
        use sha2::{Digest, Sha256};

        // RFC 7638 section 3: only the required members, in lexicographic order, no whitespace.
        let text = |name: &str| -> Result<String> {
            let value = jwk.get(name).and_then(|v| v.as_str()).ok_or_else(|| {
                AuthError::auth_method("dpop", format!("JWK is missing the '{name}' member"))
            })?;
            Ok(serde_json::Value::String(value.to_string()).to_string())
        };
        let kty = jwk
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::auth_method("dpop", "JWK is missing the 'kty' member"))?;
        if kty == "RSA" {
            for name in ["n", "e"] {
                let raw = jwk
                    .get(name)
                    .and_then(|v| v.as_str())
                    .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok());
                // A leading zero octet would give the same key a second thumbprint.
                if raw
                    .as_deref()
                    .is_none_or(|r| r.first().is_none_or(|&b| b == 0))
                {
                    return Err(AuthError::auth_method(
                        "dpop",
                        format!("RSA JWK member '{name}' is not a minimal base64url integer"),
                    ));
                }
            }
        }
        let canonical_json = match kty {
            "EC" => format!(
                r#"{{"crv":{},"kty":"EC","x":{},"y":{}}}"#,
                text("crv")?,
                text("x")?,
                text("y")?
            ),
            "RSA" => format!(r#"{{"e":{},"kty":"RSA","n":{}}}"#, text("e")?, text("n")?),
            "OKP" => format!(
                r#"{{"crv":{},"kty":"OKP","x":{}}}"#,
                text("crv")?,
                text("x")?
            ),
            other => {
                return Err(AuthError::auth_method(
                    "dpop",
                    format!("Unsupported JWK key type for a thumbprint: {other}"),
                ));
            }
        };

        // Calculate SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let hash = hasher.finalize();

        Ok(URL_SAFE_NO_PAD.encode(hash))
    }

    /// Calculate access token hash for DPoP proof
    fn calculate_access_token_hash(&self, access_token: &str) -> Result<String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let hash = hasher.finalize();

        Ok(URL_SAFE_NO_PAD.encode(hash))
    }

    /// Normalize URI by removing query and fragment components
    fn normalize_uri(&self, uri: &str) -> Result<String> {
        let url = url::Url::parse(uri)
            .map_err(|_| AuthError::auth_method("dpop", "Invalid URI format"))?;

        // Reconstruct URL without query and fragment
        let normalized = match url.port() {
            Some(port) => format!(
                "{}://{}:{}{}",
                url.scheme(),
                url.host_str().unwrap_or(""),
                port,
                url.path()
            ),
            None => format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or(""),
                url.path()
            ),
        };

        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::secure_jwt::SecureJwtConfig;

    fn create_test_dpop_manager() -> DpopManager {
        let jwt_config = SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config).expect("test JWT config");
        DpopManager::new(jwt_validator)
    }
    fn create_test_jwk() -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use": "sig",
            "alg": "ES256"
        })
    }

    #[tokio::test]
    async fn test_dpop_manager_creation() {
        let manager = create_test_dpop_manager();
        let nonce = manager.generate_nonce();
        assert!(!nonce.is_empty());
    }

    #[test]
    fn test_jwk_thumbprint_calculation() {
        let manager = create_test_dpop_manager();
        let jwk = create_test_jwk();

        let thumbprint = manager.calculate_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());

        // Same JWK should produce same thumbprint
        let thumbprint2 = manager.calculate_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumbprint, thumbprint2);
    }

    #[test]
    fn test_dpop_confirmation() {
        let manager = create_test_dpop_manager();
        let jwk = create_test_jwk();

        let confirmation = manager.create_dpop_confirmation(&jwk).unwrap();
        assert!(!confirmation.jkt.is_empty());

        // Validate with same JWK
        let is_valid = manager
            .validate_dpop_bound_token(&confirmation, &jwk)
            .unwrap();
        assert!(is_valid);

        // Validate with different JWK (should fail)
        let different_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "different_x_value_here_for_testing_purposes",
            "y": "different_y_value_here_for_testing_purposes",
            "use": "sig",
            "alg": "ES256"
        });

        let mismatch = manager.validate_dpop_bound_token(&confirmation, &different_jwk);
        assert!(mismatch.is_err(), "another key is an error, not Ok(false)");
    }

    #[test]
    fn test_uri_normalization() {
        let manager = create_test_dpop_manager();

        let uri = "https://example.com/api/resource?param=value#fragment";
        let normalized = manager.normalize_uri(uri).unwrap();
        assert_eq!(normalized, "https://example.com/api/resource");

        let uri2 = "https://example.com/api/resource";
        let normalized2 = manager.normalize_uri(uri2).unwrap();
        assert_eq!(normalized2, "https://example.com/api/resource");
    }

    #[test]
    fn test_access_token_hash() {
        let manager = create_test_dpop_manager();

        let token = "test_access_token_value";
        let hash = manager.calculate_access_token_hash(token).unwrap();
        assert!(!hash.is_empty());

        // Same token should produce same hash
        let hash2 = manager.calculate_access_token_hash(token).unwrap();
        assert_eq!(hash, hash2);
    }

    #[tokio::test]
    async fn test_nonce_cleanup() {
        let manager = create_test_dpop_manager();

        // Add some test nonces
        {
            let mut nonces = manager.used_nonces.write().await;
            nonces.insert("old_nonce".to_string(), Utc::now() - Duration::hours(1));
            nonces.insert(
                "recent_nonce".to_string(),
                Utc::now() + Duration::seconds(60),
            );
        }

        // Cleanup should remove old nonces
        manager.cleanup_expired_nonces().await;

        let nonces = manager.used_nonces.read().await;
        assert!(!nonces.contains_key("old_nonce"));
        assert!(nonces.contains_key("recent_nonce"));
    }
}

#[cfg(test)]
mod dpop_regression {
    //! `validate_dpop_proof` refuses every wrong proof, with its own reason, and accepts the right
    //! one. Each refusal is paired with the accepted case built the same way, so a test cannot
    //! pass because every proof fails for one shared reason.
    use super::*;
    use crate::security::secure_jwt::{SecureJwtConfig, SecureJwtValidator};
    use jsonwebtoken::{Algorithm, EncodingKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const URI: &str = "https://rs.example.com/resource";
    const TOKEN: &str = "access-token-1";

    fn ec_key() -> (EncodingKey, serde_json::Value) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let raw = key.public_key_raw();
        let point = &raw[raw.len() - 65..];
        let jwk = json!({
            "kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        });
        (
            EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap(),
            jwk,
        )
    }

    fn ath_of(token: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
    }

    struct Proof<'a> {
        key: &'a (EncodingKey, serde_json::Value),
        htm: &'a str,
        htu: &'a str,
        iat: i64,
        jti: &'a str,
        ath: Option<String>,
        der: bool,
        jwk_extra: Option<(&'a str, &'a str)>,
    }

    impl Proof<'_> {
        fn build(&self) -> String {
            let mut jwk = self.key.1.clone();
            if let Some((k, v)) = self.jwk_extra {
                jwk[k] = json!(v);
            }
            let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
            let mut claims =
                json!({"jti": self.jti, "htm": self.htm, "htu": self.htu, "iat": self.iat});
            if let Some(a) = &self.ath {
                claims["ath"] = json!(a);
            }
            let si = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            // jsonwebtoken signs in the JWS form: r || s.
            let sig =
                jsonwebtoken::crypto::sign(si.as_bytes(), &self.key.0, Algorithm::ES256).unwrap();
            if !self.der {
                return format!("{si}.{sig}");
            }
            let raw = URL_SAFE_NO_PAD.decode(sig).unwrap();
            let int = |v: &[u8]| {
                let mut v: Vec<u8> = v.iter().copied().skip_while(|&x| x == 0).collect();
                if v.is_empty() || v[0] & 0x80 != 0 {
                    v.insert(0, 0);
                }
                let mut o = vec![0x02, v.len() as u8];
                o.extend(v);
                o
            };
            let mut body = int(&raw[..32]);
            body.extend(int(&raw[32..]));
            let mut der = vec![0x30, body.len() as u8];
            der.extend(body);
            format!("{si}.{}", URL_SAFE_NO_PAD.encode(der))
        }
    }

    struct Fixture {
        dpop: DpopManager,
        key: (EncodingKey, serde_json::Value),
        now: i64,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                dpop: DpopManager::new(
                    SecureJwtValidator::new(SecureJwtConfig::default()).unwrap(),
                ),
                key: ec_key(),
                now: Utc::now().timestamp(),
            }
        }

        fn good<'a>(&'a self, jti: &'a str) -> Proof<'a> {
            Proof {
                key: &self.key,
                htm: "GET",
                htu: URI,
                iat: self.now,
                jti,
                ath: Some(ath_of(TOKEN)),
                der: false,
                jwk_extra: None,
            }
        }

        async fn present(&self, proof: &str) -> Result<DpopValidationResult> {
            self.dpop
                .validate_dpop_proof(proof, "GET", URI, Some(TOKEN), None)
                .await
        }
    }

    fn refused(r: Result<DpopValidationResult>, reason: &str, what: &str) {
        match r {
            Ok(v) => panic!(
                "{what}: ACCEPTED (is_valid={}, errors={:?})",
                v.is_valid, v.errors
            ),
            Err(e) => assert!(
                e.to_string().contains(reason),
                "{what}: refused with {e:?}, expected a reason containing {reason:?}"
            ),
        }
    }

    #[tokio::test]
    async fn a_correct_proof_is_accepted() {
        let f = Fixture::new();
        let ok = f
            .present(&f.good("j-ok").build())
            .await
            .expect("a correct proof is accepted");
        assert!(ok.is_valid && ok.errors.is_empty());
        assert_eq!(
            ok.jwk_thumbprint.as_deref(),
            Some(
                f.dpop
                    .create_dpop_confirmation(&f.key.1)
                    .unwrap()
                    .jkt
                    .as_str()
            )
        );
    }

    #[tokio::test]
    async fn a_proof_for_another_method_url_or_time_is_refused() {
        let f = Fixture::new();
        let p = Proof {
            htm: "DELETE",
            ..f.good("j-htm")
        }
        .build();
        refused(f.present(&p).await, "HTTP method", "wrong htm");
        let p = Proof {
            htu: "https://evil.example/x",
            ..f.good("j-htu")
        }
        .build();
        refused(f.present(&p).await, "HTTP URI", "wrong htu");
        let p = Proof {
            iat: f.now - 86_400,
            ..f.good("j-old")
        }
        .build();
        refused(f.present(&p).await, "too old", "one-day-old iat");
        let p = Proof {
            iat: f.now + 86_400,
            ..f.good("j-future")
        }
        .build();
        refused(f.present(&p).await, "in the future", "future iat");
    }

    #[tokio::test]
    async fn a_proof_without_an_access_token_needs_no_ath() {
        // The token endpoint: a proof is presented before any access token exists.
        let f = Fixture::new();
        let p = Proof {
            ath: None,
            ..f.good("j-endpoint")
        }
        .build();
        f.dpop
            .validate_dpop_proof(&p, "GET", URI, None, None)
            .await
            .expect("no access token, so no ath is required");
    }

    #[tokio::test]
    async fn a_proof_used_twice_is_refused_the_second_time() {
        let f = Fixture::new();
        let once = f.good("j-replay").build();
        f.present(&once).await.expect("first use");
        refused(f.present(&once).await, "already used", "replayed proof");
    }

    #[tokio::test]
    async fn a_proof_must_name_the_access_token() {
        let f = Fixture::new();
        let p = Proof {
            ath: None,
            ..f.good("j-no-ath")
        }
        .build();
        refused(f.present(&p).await, "'ath'", "no ath");
        let p = Proof {
            ath: Some(ath_of("another-token")),
            ..f.good("j-bad-ath")
        }
        .build();
        refused(f.present(&p).await, "access token hash", "wrong ath");
    }

    #[tokio::test]
    async fn a_der_signature_or_a_private_key_in_the_header_is_refused() {
        let f = Fixture::new();
        let p = Proof {
            der: true,
            ..f.good("j-der")
        }
        .build();
        refused(f.present(&p).await, "r||s", "DER-encoded ES256 signature");
        let p = Proof {
            jwk_extra: Some(("d", "AAAA")),
            ..f.good("j-priv")
        }
        .build();
        refused(f.present(&p).await, "private key", "private key in jwk");
    }

    #[tokio::test]
    async fn a_proof_refused_for_another_reason_does_not_use_up_its_jti() {
        let f = Fixture::new();
        let p = f.good("j-keep").build();
        // Presented for the wrong method: refused.
        refused(
            f.dpop
                .validate_dpop_proof(&p, "POST", URI, Some(TOKEN), None)
                .await,
            "HTTP method",
            "wrong method",
        );
        // The same proof, presented correctly afterwards, has not been spent.
        f.present(&p)
            .await
            .expect("a proof refused earlier for its method is not spent");
    }

    #[tokio::test]
    async fn a_replay_record_outlives_the_proof_it_guards() {
        let f = Fixture::new();
        // An iat 25 s ahead is inside the 30 s skew: the proof stays acceptable until
        // iat + 60 s lifetime + 30 s skew.
        let p = Proof {
            iat: f.now + 25,
            ..f.good("j-late")
        }
        .build();
        f.present(&p).await.expect("within the clock skew");
        let acceptable_until = chrono::TimeZone::timestamp_opt(&Utc, f.now + 25 + 90, 0)
            .single()
            .unwrap();
        f.dpop.sweep(acceptable_until - Duration::seconds(1)).await;
        assert_eq!(
            f.dpop.used_nonces.read().await.len(),
            1,
            "record dropped while the proof could still be replayed"
        );
        f.dpop.sweep(acceptable_until + Duration::seconds(1)).await;
        assert!(
            f.dpop.used_nonces.read().await.is_empty(),
            "record kept after the proof can no longer be accepted"
        );
    }

    #[tokio::test]
    async fn the_replay_cache_is_swept_and_bounded() {
        let mut f = Fixture::new();
        f.dpop.max_replay_entries = 4;
        let stale = Utc::now() - Duration::seconds(1);
        let live = Utc::now() + Duration::seconds(600);
        {
            let mut used = f.dpop.used_nonces.write().await;
            used.insert("stale-1".into(), stale);
            used.insert("stale-2".into(), stale);
            used.insert("live-1".into(), live);
            used.insert("live-2".into(), live);
        }
        // Two stale and two live records fill it: the stale ones are swept and the proof fits.
        f.present(&f.good("j-fits").build())
            .await
            .expect("a swept cache has room");
        {
            let used = f.dpop.used_nonces.read().await;
            assert!(
                !used.contains_key("stale-1") && !used.contains_key("stale-2"),
                "stale records survive a full cache"
            );
            assert_eq!(used.len(), 3);
        }
        // Filled with live records, a further proof is refused rather than recorded past the bound.
        f.dpop
            .used_nonces
            .write()
            .await
            .insert("live-3".into(), live);
        refused(
            f.present(&f.good("j-overflow").build()).await,
            "replay cache is full",
            "a full cache",
        );
    }

    #[tokio::test]
    async fn one_key_cannot_spend_anothers_jti() {
        let f = Fixture::new();
        let other = ec_key();
        let mine = f.good("j-shared").build();
        let theirs = Proof {
            key: &other,
            ..f.good("j-shared")
        }
        .build();
        f.present(&mine).await.expect("first key");
        f.present(&theirs)
            .await
            .expect("a different key may use the same jti");
        refused(
            f.present(&mine).await,
            "already used",
            "the first key again",
        );
    }

    #[tokio::test]
    async fn a_method_in_another_case_is_refused() {
        let f = Fixture::new();
        let p = f.good("j-case").build();
        refused(
            f.dpop
                .validate_dpop_proof(&p, "get", URI, Some(TOKEN), None)
                .await,
            "HTTP method",
            "lower-case method",
        );
    }

    #[test]
    fn a_key_that_is_not_the_bound_key_is_an_error() {
        let f = Fixture::new();
        let other = ec_key();
        let bound = f.dpop.create_dpop_confirmation(&f.key.1).unwrap();
        assert!(f.dpop.validate_dpop_bound_token(&bound, &f.key.1).unwrap());
        assert!(
            f.dpop.validate_dpop_bound_token(&bound, &other.1).is_err(),
            "another key must be an error, not Ok(false)"
        );
    }

    #[test]
    fn thumbprints_match_rfc_7638_and_an_independent_hash() {
        let f = Fixture::new();
        // RFC 7638 section 3.1.
        let rsa = json!({
            "kty": "RSA", "alg": "RS256", "kid": "2011-04-29", "e": "AQAB",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        });
        assert_eq!(
            f.dpop.calculate_jwk_thumbprint(&rsa).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        // SHA-256 of {"crv":"P-256","kty":"EC","x":...,"y":...}, computed with Python's hashlib.
        let ec = json!({
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        });
        assert_eq!(
            f.dpop.calculate_jwk_thumbprint(&ec).unwrap(),
            "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
        );
        // A key without all its required members has no thumbprint.
        assert!(
            f.dpop
                .calculate_jwk_thumbprint(&json!({"kty": "EC", "crv": "P-256", "x": "AA"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_iat_at_the_end_of_time_is_refused_not_a_panic() {
        let f = Fixture::new();
        // The largest timestamp chrono can represent, and one a minute short of it.
        for iat in [8_210_298_412_799_i64, 8_210_298_412_740] {
            let p = Proof {
                iat,
                ..f.good("j-forever")
            }
            .build();
            // Out of chrono's range counts as too old, in range but far ahead as in the future:
            // either way it is refused, and nothing panics on the way.
            refused(f.present(&p).await, "rejected", "iat at the end of time");
        }
    }

    #[tokio::test]
    async fn a_jti_that_is_empty_or_too_long_is_refused() {
        let f = Fixture::new();
        let long = "a".repeat(257);
        for (jti, what) in [("", "empty jti"), (long.as_str(), "257-byte jti")] {
            let p = f.good(jti).build();
            refused(f.present(&p).await, "jti", what);
        }
        let ok = "a".repeat(256);
        f.present(&f.good(&ok).build())
            .await
            .expect("256 bytes is allowed");
    }

    #[tokio::test]
    async fn replay_records_have_a_fixed_size() {
        let f = Fixture::new();
        let jti = "j".repeat(200);
        f.present(&f.good(&jti).build()).await.expect("a long jti");
        f.present(&f.good("short").build())
            .await
            .expect("a short jti");
        let used = f.dpop.used_nonces.read().await;
        assert_eq!(used.len(), 2);
        assert!(
            used.keys().all(|k| k.len() == 43),
            "record keys are not a fixed-size hash: {:?}",
            used.keys().map(String::len).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_full_cache_is_swept_at_most_once_per_interval() {
        let mut f = Fixture::new();
        f.dpop.max_replay_entries = 2;
        f.dpop.sweep_interval = Duration::hours(1);
        let stale = Utc::now() - Duration::seconds(1);
        {
            let mut used = f.dpop.used_nonces.write().await;
            used.insert("stale-1".into(), stale);
            used.insert("stale-2".into(), stale);
        }
        f.present(&f.good("j-first").build())
            .await
            .expect("the first full cache is swept");
        f.dpop
            .used_nonces
            .write()
            .await
            .insert("stale-3".into(), stale);
        // Full again, and the last sweep was moments ago: no new sweep, so the proof is refused.
        refused(
            f.present(&f.good("j-second").build()).await,
            "replay cache is full",
            "a cache swept a moment ago",
        );
    }

    #[test]
    fn an_rsa_jwk_with_a_leading_zero_octet_has_no_thumbprint() {
        let f = Fixture::new();
        // "AAEAAQ" is 00 01 00 01: the exponent 65537 with a leading zero.
        for jwk in [
            json!({"kty": "RSA", "n": "AQAB", "e": "AAEAAQ"}),
            json!({"kty": "RSA", "n": "AP8", "e": "AQAB"}),
        ] {
            assert!(f.dpop.calculate_jwk_thumbprint(&jwk).is_err(), "{jwk}");
        }
        assert!(
            f.dpop
                .calculate_jwk_thumbprint(&json!({"kty": "RSA", "n": "_w", "e": "AQAB"}))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_full_cache_of_expired_records_does_not_refuse_a_proof() {
        let mut f = Fixture::new();
        f.dpop.max_replay_entries = 2;
        f.dpop.sweep_interval = Duration::hours(1);
        // The first proof uses the sweep that has been due since the epoch.
        f.present(&f.good("j-warm").build()).await.expect("warm-up");
        // The cache is now full, one record of it expired, and the next sweep is an hour away.
        f.dpop
            .insert_record_for_test("expired-1", Utc::now() - Duration::seconds(5))
            .await;
        f.present(&f.good("j-after").build())
            .await
            .expect("room taken by an expired record must not refuse a proof");
        assert!(
            !f.dpop.used_nonces.read().await.contains_key("expired-1"),
            "the expired record was not swept"
        );
    }

    /// The modulus and exponent (base64url, no leading zero) of an RSA key, read from its DER
    /// `RSAPublicKey`.
    fn rsa_parts(key: &rcgen::KeyPair) -> (String, String) {
        fn int(b: &[u8]) -> (&[u8], &[u8]) {
            assert_eq!(b[0], 0x02);
            let (len, off) = if b[1] & 0x80 == 0 {
                (b[1] as usize, 2)
            } else {
                let n = (b[1] & 0x7f) as usize;
                let len = b[2..2 + n]
                    .iter()
                    .fold(0usize, |a, &x| (a << 8) | x as usize);
                (len, 2 + n)
            };
            let v = &b[off..off + len];
            (v.strip_prefix(&[0]).unwrap_or(v), &b[off + len..])
        }
        let raw = key.public_key_raw();
        let body = if raw[1] & 0x80 == 0 {
            &raw[2..]
        } else {
            &raw[2 + (raw[1] & 0x7f) as usize..]
        };
        let (n, rest) = int(body);
        let (e, _) = int(rest);
        (URL_SAFE_NO_PAD.encode(n), URL_SAFE_NO_PAD.encode(e))
    }

    #[tokio::test]
    async fn rs256_and_ps256_proofs_from_a_2048_bit_key_are_accepted() {
        let f = Fixture::new();
        let key =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap();
        let (n, e) = rsa_parts(&key);
        assert_eq!(URL_SAFE_NO_PAD.decode(&n).unwrap().len(), 256);
        let enc = EncodingKey::from_rsa_pem(key.serialize_pem().as_bytes()).unwrap();
        for (alg, name) in [(Algorithm::RS256, "RS256"), (Algorithm::PS256, "PS256")] {
            let header = json!({
                "typ": "dpop+jwt", "alg": name,
                "jwk": {"kty": "RSA", "n": n, "e": e},
            });
            let claims = |htm: &str| {
                json!({
                    "jti": format!("j-{name}-{htm}"), "htm": htm, "htu": URI,
                    "iat": f.now, "ath": ath_of(TOKEN),
                })
            };
            let b64 = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
            let si = format!("{}.{}", b64(&header), b64(&claims("GET")));
            let sig = jsonwebtoken::crypto::sign(si.as_bytes(), &enc, alg).unwrap();
            f.present(&format!("{si}.{sig}"))
                .await
                .unwrap_or_else(|err| panic!("{name}: a correct proof was refused: {err:?}"));

            // The same signature over different claims is refused.
            let forged = format!("{}.{}.{sig}", b64(&header), b64(&claims("POST")));
            let r = f
                .dpop
                .validate_dpop_proof(&forged, "POST", URI, Some(TOKEN), None)
                .await;
            refused(
                r,
                "signature",
                &format!("{name}: a signature over other claims"),
            );
        }
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn the_deprecated_function_always_refuses_even_a_forged_jwt() {
        let f = Fixture::new();
        let confirmation = f.dpop.create_dpop_confirmation(&f.key.1).unwrap();
        // A JWT nobody signed, whose claims name the proof's key: the old function said Ok(true).
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD
            .encode(json!({"sub": "admin", "cnf": {"jkt": confirmation.jkt}}).to_string());
        let forged = format!(
            "{header}.{claims}.{}",
            URL_SAFE_NO_PAD.encode(b"not a signature")
        );
        let p = Proof {
            ath: Some(ath_of(&forged)),
            ..f.good("j-forged")
        }
        .build();
        let r = f
            .dpop
            .validate_dpop_bound_access_token(&forged, &confirmation, &p, "GET", URI)
            .await;
        assert!(
            r.is_err(),
            "a forged JWT was reported as a valid bound token: {r:?}"
        );
    }

    const AUD: &str = "https://api.example.com";
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// An access token as the validator wants it; `edit` changes one thing about it.
    fn jwt_with(secret: &[u8], jkt: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let now = Utc::now().timestamp();
        let mut claims = json!({
            "iss": "auth-framework", "sub": "user-1", "aud": AUD, "exp": now + 300,
            "nbf": now - 1, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
            "scope": "read", "typ": "access", "cnf": {"jkt": jkt},
        });
        edit(&mut claims);
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn jwt_manager() -> DpopManager {
        DpopManager::new(
            SecureJwtValidator::new(SecureJwtConfig {
                require_secure_transport: false,
                ..SecureJwtConfig::default()
            })
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn a_genuine_bound_jwt_is_accepted_once() {
        let key = jsonwebtoken::DecodingKey::from_secret(SECRET);
        let f = Fixture::new();
        let dpop = jwt_manager();
        let jkt = dpop.create_dpop_confirmation(&f.key.1).unwrap().jkt;
        let tok = jwt_with(SECRET, &jkt, |_| {});
        let p = Proof {
            ath: Some(ath_of(&tok)),
            ..f.good("j-genuine")
        }
        .build();
        dpop.validate_dpop_bound_jwt(&tok, &key, AUD, &p, "GET", URI)
            .await
            .expect("a genuine bound token with its key's proof");
        let again = dpop
            .validate_dpop_bound_jwt(&tok, &key, AUD, &p, "GET", URI)
            .await;
        assert!(again.unwrap_err().to_string().contains("already used"));
        assert_eq!(dpop.used_nonces.read().await.len(), 1);
    }

    /// Each of these is a token or proof that must be refused for its own reason, and none of
    /// them may take a replay-cache slot. Removing the check each one exercises turns exactly
    /// that case green-to-red (run as mutations in the PR).
    #[tokio::test]
    async fn a_bound_jwt_that_is_not_a_valid_access_token_for_this_request_is_refused() {
        let key = jsonwebtoken::DecodingKey::from_secret(SECRET);
        let f = Fixture::new();
        let dpop = jwt_manager();
        let jkt = dpop.create_dpop_confirmation(&f.key.1).unwrap().jkt;
        let other = ec_key();
        let now = Utc::now().timestamp();

        // (token, signer of the proof, ath override, audience asked for, reason)
        let cases = vec![
            (
                "signed by someone else",
                jwt_with(b"another-secret-another-secret-1234", &jkt, |_| {}),
                &f.key,
                None,
                AUD,
                "Invalid DPoP-bound access token",
            ),
            (
                "expired",
                jwt_with(SECRET, &jkt, |c| {
                    c["exp"] = json!(now - 3600);
                    c["iat"] = json!(now - 3700);
                    c["nbf"] = json!(now - 3700);
                }),
                &f.key,
                None,
                AUD,
                "Invalid DPoP-bound access token",
            ),
            (
                "a refresh token",
                jwt_with(SECRET, &jkt, |c| c["typ"] = json!("refresh")),
                &f.key,
                None,
                AUD,
                "Not an access token",
            ),
            (
                "an empty typ",
                jwt_with(SECRET, &jkt, |c| c["typ"] = json!("")),
                &f.key,
                None,
                AUD,
                "Not an access token",
            ),
            (
                "issued for another audience",
                jwt_with(SECRET, &jkt, |c| {
                    c["aud"] = json!("https://other.example.com")
                }),
                &f.key,
                None,
                AUD,
                "another audience",
            ),
            (
                "no cnf.jkt",
                jwt_with(SECRET, &jkt, |c| {
                    c.as_object_mut().unwrap().remove("cnf");
                }),
                &f.key,
                None,
                AUD,
                "no DPoP key binding",
            ),
            (
                "a proof from another key",
                jwt_with(SECRET, &jkt, |_| {}),
                &other,
                None,
                AUD,
                "key binding",
            ),
            (
                "a proof for another token",
                jwt_with(SECRET, &jkt, |_| {}),
                &f.key,
                Some(ath_of("another-token")),
                AUD,
                "access token hash",
            ),
        ];
        for (i, (what, tok, signer, ath, aud, reason)) in cases.into_iter().enumerate() {
            let jti = format!("j-case-{i}");
            let p = Proof {
                key: signer,
                ath: Some(ath.unwrap_or_else(|| ath_of(&tok))),
                ..f.good(&jti)
            }
            .build();
            match dpop
                .validate_dpop_bound_jwt(&tok, &key, aud, &p, "GET", URI)
                .await
            {
                Ok(()) => panic!("{what}: ACCEPTED"),
                Err(e) => assert!(
                    e.to_string().contains(reason),
                    "{what}: refused with {e:?}, expected {reason:?}"
                ),
            }
        }
        assert_eq!(
            dpop.used_nonces.read().await.len(),
            0,
            "a refused token must not use a replay-cache slot"
        );

        // The same manager, key and request still accept the genuine token afterwards.
        let tok = jwt_with(SECRET, &jkt, |_| {});
        let p = Proof {
            ath: Some(ath_of(&tok)),
            ..f.good("j-after")
        }
        .build();
        dpop.validate_dpop_bound_jwt(&tok, &key, AUD, &p, "GET", URI)
            .await
            .expect("a genuine token after the refusals");
        assert_eq!(dpop.used_nonces.read().await.len(), 1);
    }

    /// The validator's algorithm allow-list decides, whatever the key: an HS256 token "signed"
    /// with the RSA public key's bytes (the classic confusion) is refused when only RS256 is
    /// allowed, and a genuine RS256 token is accepted.
    #[tokio::test]
    async fn an_algorithm_outside_the_allow_list_is_refused() {
        let rsa =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap();
        let dpop = DpopManager::new(
            SecureJwtValidator::new(SecureJwtConfig {
                allowed_algorithms: vec![Algorithm::RS256],
                rsa_public_key_pem: Some(rsa.public_key_pem()),
                require_secure_transport: false,
                ..SecureJwtConfig::default()
            })
            .unwrap(),
        );
        let dec = jsonwebtoken::DecodingKey::from_rsa_der(rsa.public_key_raw());
        let f = Fixture::new();
        let jkt = dpop.create_dpop_confirmation(&f.key.1).unwrap().jkt;
        let claims = |jti: &str| {
            let now = Utc::now().timestamp();
            json!({
                "iss": "auth-framework", "sub": "user-1", "aud": AUD, "exp": now + 300,
                "nbf": now - 1, "iat": now, "jti": jti, "scope": "read", "typ": "access",
                "cnf": {"jkt": jkt},
            })
        };
        let genuine = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::RS256),
            &claims("t-rs256"),
            &EncodingKey::from_rsa_pem(rsa.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
        let p = Proof {
            ath: Some(ath_of(&genuine)),
            ..f.good("j-rs")
        }
        .build();
        dpop.validate_dpop_bound_jwt(&genuine, &dec, AUD, &p, "GET", URI)
            .await
            .expect("a genuine RS256 token");

        for (secret, what) in [
            (
                rsa.public_key_pem().into_bytes(),
                "HS256 keyed with the public key PEM",
            ),
            (
                rsa.public_key_raw().to_vec(),
                "HS256 keyed with the public key DER",
            ),
        ] {
            let confused = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(Algorithm::HS256),
                &claims("t-hs256"),
                &EncodingKey::from_secret(&secret),
            )
            .unwrap();
            let p = Proof {
                ath: Some(ath_of(&confused)),
                ..f.good("j-conf")
            }
            .build();
            let r = dpop
                .validate_dpop_bound_jwt(&confused, &dec, AUD, &p, "GET", URI)
                .await;
            assert!(r.is_err(), "{what}: ACCEPTED");
        }
        assert_eq!(dpop.used_nonces.read().await.len(), 1);
    }
}
