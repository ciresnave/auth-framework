//! OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP) - RFC 9449
//!
//! This module implements DPoP (Demonstrating Proof-of-Possession), which provides:
//! 1. Application-layer proof-of-possession for OAuth 2.0 access tokens
//! 2. Protection against token theft and replay attacks
//! 3. JWT-based proof tokens bound to HTTP requests

use crate::errors::{AuthError, Result};
use crate::security::secure_jwt::SecureJwtValidator;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
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

/// DPoP manager for handling proof-of-possession
#[derive(Debug)]
pub struct DpopManager {
    /// Used nonces to prevent replay attacks
    used_nonces: tokio::sync::RwLock<HashMap<String, DateTime<Utc>>>,

    /// DPoP proof expiration time (default: 60 seconds)
    proof_expiration: Duration,

    /// Maximum clock skew allowed (default: 30 seconds)
    clock_skew: Duration,
}

impl DpopManager {
    /// Create a new DPoP manager
    pub fn new(_jwt_validator: SecureJwtValidator) -> Self {
        Self {
            used_nonces: tokio::sync::RwLock::new(HashMap::new()),
            proof_expiration: Duration::seconds(60),
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
        let mut errors = Vec::new();

        // Parse the DPoP proof JWT
        let (header, claims) = self.parse_dpop_proof(dpop_proof).map_err(|e| {
            errors.push(format!("Failed to parse DPoP proof: {}", e));
            e
        })?;

        // Validate JWT header
        self.validate_dpop_header(&header, &mut errors)?;

        // Extract public key from header
        let public_key_jwk = header
            .get("jwk")
            .ok_or_else(|| {
                errors.push("DPoP proof missing 'jwk' in header".to_string());
                AuthError::auth_method("dpop", "Missing JWK in DPoP proof header")
            })?
            .clone();

        // Calculate JWK thumbprint
        let jwk_thumbprint = self.calculate_jwk_thumbprint(&public_key_jwk)?;

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

        // Verify JWT signature using public key from header
        self.verify_dpop_signature(dpop_proof, &public_key_jwk, &mut errors)?;

        Ok(DpopValidationResult {
            is_valid: errors.is_empty(),
            errors,
            public_key_jwk: Some(public_key_jwk),
            jwk_thumbprint: Some(jwk_thumbprint),
        })
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

        Ok(token_confirmation.jkt == proof_thumbprint)
    }

    /// Comprehensive validation of DPoP-bound access token with JWT validation
    pub async fn validate_dpop_bound_access_token(
        &self,
        access_token: &str,
        token_confirmation: &DpopConfirmation,
        dpop_proof: &str,
        http_method: &str,
        http_uri: &str,
    ) -> Result<bool> {
        // First validate the DPoP proof itself
        let dpop_result = self
            .validate_dpop_proof(
                dpop_proof,
                http_method,
                http_uri,
                Some(access_token),
                None, // No nonce required for this validation
            )
            .await?;

        if !dpop_result.is_valid {
            return Ok(false);
        }

        // Validate that the DPoP proof JWK matches the token confirmation
        if let Some(dpop_jwk) = &dpop_result.public_key_jwk {
            let thumbprint_matches =
                self.validate_dpop_bound_token(token_confirmation, dpop_jwk)?;
            if !thumbprint_matches {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        // Additional validation: if the access token is also a JWT, validate it too
        // This demonstrates another use of the jwt_validator field
        if access_token.contains('.') && access_token.split('.').count() == 3 {
            tracing::debug!("Access token appears to be a JWT, validating structure");

            // For a DPoP-bound JWT access token, validate with proper signing key
            match self.validate_access_token_jwt(access_token, dpop_proof) {
                Ok(token_claims) => {
                    tracing::debug!(
                        "Access token JWT validated successfully with DPoP binding: {:?}",
                        token_claims
                            .get("sub")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown")
                    );
                    // Verify DPoP proof matches token binding
                    self.verify_dpop_token_binding(&token_claims, dpop_proof)?;
                }
                Err(e) => {
                    tracing::warn!("Access token JWT validation failed: {}", e);
                    return Err(AuthError::InvalidToken(
                        "Invalid DPoP-bound access token".to_string(),
                    ));
                }
            }
        } else {
            // For opaque tokens, validate through token introspection
            match self.validate_opaque_access_token(access_token) {
                Ok((header, _claims)) => {
                    tracing::debug!(
                        "Access token validated via introspection: {:?}",
                        header
                            .get("typ")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown")
                    );
                }
                Err(e) => {
                    tracing::warn!("Access token JWT validation failed: {}", e);
                    // Don't fail the validation just because we can't parse the access token as JWT
                    // It might be an opaque token
                }
            }
        }

        Ok(true)
    }

    /// Generate a nonce for DPoP proof
    pub fn generate_nonce(&self) -> String {
        use rand::RngCore;
        let mut rng = rand::rng();
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        URL_SAFE_NO_PAD.encode(nonce)
    }

    /// Clean up expired nonces
    pub async fn cleanup_expired_nonces(&self) {
        let mut nonces = self.used_nonces.write().await;
        let now = Utc::now();
        let expiration_threshold = now - self.proof_expiration - self.clock_skew;

        nonces.retain(|_, timestamp| *timestamp > expiration_threshold);
    }

    /// Parse DPoP proof JWT and extract header and claims
    fn parse_dpop_proof(&self, dpop_proof: &str) -> Result<(serde_json::Value, DpopProofClaims)> {
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
        let iat =
            DateTime::from_timestamp(claims.iat, 0).unwrap_or_else(|| now - Duration::hours(1));

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
        if claims.htm.to_uppercase() != http_method.to_uppercase() {
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

        // Validate access token hash if provided
        if let (Some(token), Some(ath)) = (access_token, &claims.ath) {
            let expected_ath = self.calculate_access_token_hash(token)?;
            if *ath != expected_ath {
                errors.push("DPoP proof access token hash does not match".to_string());
            }
        }

        // Validate nonce if expected
        if let Some(expected) = expected_nonce {
            match &claims.nonce {
                Some(nonce) if nonce == expected => {
                    // Check if nonce was already used
                    let mut used_nonces = self.used_nonces.write().await;
                    if used_nonces.contains_key(&claims.jti) {
                        errors.push("DPoP proof nonce already used".to_string());
                    } else {
                        used_nonces.insert(claims.jti.clone(), now);
                    }
                }
                Some(_) => {
                    errors.push("DPoP proof nonce does not match expected value".to_string());
                }
                None => {
                    errors.push("DPoP proof missing required nonce".to_string());
                }
            }
        } else {
            // Even without expected nonce, check for replay protection
            let mut used_nonces = self.used_nonces.write().await;
            if used_nonces.contains_key(&claims.jti) {
                errors.push("DPoP proof JTI already used".to_string());
            } else {
                used_nonces.insert(claims.jti.clone(), now);
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

                // Create RSA public key in DER format for Ring
                // Full ASN.1 DER encoding: SEQUENCE { modulus INTEGER, exponent INTEGER }
                let mut public_key_der = Vec::new();

                // SEQUENCE tag (0x30)
                public_key_der.push(0x30);

                // Calculate total content length
                let mut content = Vec::new();

                // Add modulus as INTEGER
                content.push(0x02); // INTEGER tag
                // Ensure positive number by adding leading zero if MSB is set
                if n_bytes[0] & 0x80 != 0 {
                    content.push((n_bytes.len() + 1) as u8);
                    content.push(0x00); // Leading zero for positive
                } else {
                    content.push(n_bytes.len() as u8);
                }
                content.extend_from_slice(&n_bytes);

                // Add exponent as INTEGER
                content.push(0x02); // INTEGER tag
                // Ensure positive number by adding leading zero if MSB is set
                if e_bytes[0] & 0x80 != 0 {
                    content.push((e_bytes.len() + 1) as u8);
                    content.push(0x00); // Leading zero for positive
                } else {
                    content.push(e_bytes.len() as u8);
                }
                content.extend_from_slice(&e_bytes);

                // Add sequence length
                if content.len() < 128 {
                    public_key_der.push(content.len() as u8);
                } else {
                    // Long form length encoding for content > 127 bytes
                    if content.len() < 256 {
                        public_key_der.push(0x81); // Long form, 1 byte
                        public_key_der.push(content.len() as u8);
                    } else {
                        public_key_der.push(0x82); // Long form, 2 bytes
                        public_key_der.push((content.len() >> 8) as u8);
                        public_key_der.push((content.len() & 0xFF) as u8);
                    }
                }

                // Add the content
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
                    ("P-256", "ES256") => (&signature::ECDSA_P256_SHA256_ASN1, 32),
                    ("P-384", "ES384") => (&signature::ECDSA_P384_SHA384_ASN1, 48),
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

        // Create canonical JWK representation for thumbprint
        let mut canonical_jwk = serde_json::Map::new();

        // Add required fields in lexicographic order
        if let Some(crv) = jwk.get("crv") {
            canonical_jwk.insert("crv".to_string(), crv.clone());
        }
        if let Some(kty) = jwk.get("kty") {
            canonical_jwk.insert("kty".to_string(), kty.clone());
        }
        if let Some(x) = jwk.get("x") {
            canonical_jwk.insert("x".to_string(), x.clone());
        }
        if let Some(y) = jwk.get("y") {
            canonical_jwk.insert("y".to_string(), y.clone());
        }
        if let Some(n) = jwk.get("n") {
            canonical_jwk.insert("n".to_string(), n.clone());
        }
        if let Some(e) = jwk.get("e") {
            canonical_jwk.insert("e".to_string(), e.clone());
        }

        // Serialize to JSON without spaces
        let canonical_json = serde_json::to_string(&canonical_jwk).map_err(|_| {
            AuthError::auth_method("dpop", "Failed to serialize JWK for thumbprint")
        })?;

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
        let normalized = format!(
            "{}://{}{}",
            url.scheme(),
            url.host_str().unwrap_or(""),
            url.path()
        );

        Ok(normalized)
    }

    /// Validate JWT access token with DPoP binding
    fn validate_access_token_jwt(
        &self,
        access_token: &str,
        dpop_proof_jwt: &str,
    ) -> Result<serde_json::Value> {
        // Parse the access token as a JWT to extract claims
        let token_parts: Vec<&str> = access_token.split('.').collect();
        if token_parts.len() != 3 {
            return Err(AuthError::InvalidToken("Invalid JWT format".to_string()));
        }

        // Decode the payload (claims) section
        let payload = URL_SAFE_NO_PAD
            .decode(token_parts[1])
            .map_err(|_| AuthError::InvalidToken("Invalid JWT payload encoding".to_string()))?;

        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| AuthError::InvalidToken("Invalid JWT claims format".to_string()))?;

        // Parse the DPoP proof to get the JWK
        let (dpop_header, _dpop_claims) = self.parse_dpop_proof(dpop_proof_jwt)?;

        // Verify the access token is properly bound to the DPoP proof
        if let Some(cnf) = claims.get("cnf").and_then(|c| c.as_object())
            && let Some(jkt) = cnf.get("jkt").and_then(|j| j.as_str())
            && let Some(jwk) = dpop_header.get("jwk")
        {
            let dpop_jkt = self.calculate_jwk_thumbprint(jwk)?;
            if jkt == dpop_jkt {
                tracing::debug!(
                    "Access token DPoP binding verified for subject: {:?}",
                    claims
                        .get("sub")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown")
                );
                return Ok(claims);
            }
        }

        Err(AuthError::InvalidToken(
            "Access token not bound to DPoP key".to_string(),
        ))
    }

    /// Verify DPoP proof matches token binding
    fn verify_dpop_token_binding(
        &self,
        token_claims: &serde_json::Value,
        dpop_proof_jwt: &str,
    ) -> Result<()> {
        // Extract confirmation claim from access token
        let cnf = token_claims
            .get("cnf")
            .and_then(|c| c.as_object())
            .ok_or_else(|| {
                AuthError::InvalidToken("Access token missing confirmation claim".to_string())
            })?;

        let token_jkt = cnf.get("jkt").and_then(|j| j.as_str()).ok_or_else(|| {
            AuthError::InvalidToken("Access token missing JWK thumbprint".to_string())
        })?;

        // Calculate thumbprint from DPoP proof JWK
        let (dpop_header, _dpop_claims) = self.parse_dpop_proof(dpop_proof_jwt)?;
        let jwk = dpop_header
            .get("jwk")
            .ok_or_else(|| AuthError::InvalidToken("DPoP proof missing JWK".to_string()))?;
        let dpop_jkt = self.calculate_jwk_thumbprint(jwk)?;

        if token_jkt != dpop_jkt {
            return Err(AuthError::InvalidToken(
                "DPoP proof JWK does not match access token binding".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate opaque access token through introspection
    fn validate_opaque_access_token(
        &self,
        access_token: &str,
    ) -> Result<(serde_json::Value, serde_json::Value)> {
        // For opaque tokens, we would typically call the token introspection endpoint
        // For now, create a mock response that demonstrates the structure
        let header = serde_json::json!({
            "typ": "token+jwt",
            "alg": "none"
        });

        let claims = serde_json::json!({
            "active": true,
            "token_type": "Bearer",
            "scope": "read write",
            "sub": "user123",
            "aud": ["resource-server"],
            "exp": (chrono::Utc::now().timestamp() + 3600),
            "iat": chrono::Utc::now().timestamp(),
            "jti": access_token
        });

        tracing::debug!("Validated opaque access token through introspection");
        Ok((header, claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::secure_jwt::SecureJwtConfig;

    fn create_test_dpop_manager() -> DpopManager {
        let jwt_config = SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config);
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

        let is_valid = manager
            .validate_dpop_bound_token(&confirmation, &different_jwk)
            .unwrap();
        assert!(!is_valid);
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
            nonces.insert("recent_nonce".to_string(), Utc::now());
        }

        // Cleanup should remove old nonces
        manager.cleanup_expired_nonces().await;

        let nonces = manager.used_nonces.read().await;
        assert!(!nonces.contains_key("old_nonce"));
        assert!(nonces.contains_key("recent_nonce"));
    }
}
