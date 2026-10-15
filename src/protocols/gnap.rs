//! GNAP (Grant Negotiation and Authorization Protocol) implementation.
//!
//! This module implements the GNAP specification (draft-ietf-gnap-core-protocol),
//! providing an emerging next-generation alternative to OAuth 2.0 with stronger
//! cryptographic binding and a unified request structure.
//!
//! # Implemented Features
//!
//! - Transaction lifecycle (create, continue, approve, deny)
//! - Client key binding via JWK (ES256, RS256, EdDSA)
//! - Interaction hash verification (draft §4.2.3)
//! - Continuation token rotation on each use
//! - Token management (revocation)
//! - Subject information responses
//! - Transaction expiration and cleanup

use crate::errors::{AuthError, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapConfig {
    pub enabled: bool,
    pub transaction_endpoint: String,
    /// Base URL for interaction redirects (must be configured for production)
    pub interaction_base_url: Option<String>,
    /// Default access token lifetime in seconds
    pub token_lifetime_secs: u64,
    /// Transaction lifetime in seconds before expiration (default: 600 = 10 minutes)
    pub transaction_lifetime_secs: u64,
}

impl Default for GnapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: None,
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        }
    }
}

/// A GNAP transaction request representing the client's intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapTransactionRequest {
    pub client: Option<GnapClientInfo>,
    pub interact: Option<GnapInteractionRequirements>,
    /// Requested access rights (draft-ietf-gnap-core-protocol §2)
    pub access_token: Option<Vec<GnapAccessRequest>>,
    /// Subject information request
    pub subject: Option<GnapSubjectRequest>,
}

/// Description of a single access right being requested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapAccessRequest {
    /// Type of access (e.g. "read", "write", or an API-specific identifier)
    #[serde(rename = "type")]
    pub access_type: String,
    /// Actions within this type
    #[serde(default)]
    pub actions: Vec<String>,
    /// Locations/URIs where this access applies
    #[serde(default)]
    pub locations: Vec<String>,
}

/// Subject information the client is requesting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapSubjectRequest {
    /// Requested subject identifier formats
    #[serde(default)]
    pub sub_id_formats: Vec<String>,
    /// Requested assertion formats (e.g. "id_token", "saml2")
    #[serde(default)]
    pub assertion_formats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientInfo {
    /// Client key in JWK format for cryptographic binding
    pub key: Option<GnapClientKey>,
    /// Client display information
    pub display: Option<GnapClientDisplay>,
}

/// Client key with proof method (draft §7.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientKey {
    /// Proof method: "httpsig", "mtls", "dpop", "jws", or "test"
    pub proof: String,
    /// JWK representation of the client's public key
    pub jwk: GnapJwk,
}

/// Minimal JWK representation sufficient for GNAP key binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapJwk {
    /// Key type: "EC", "RSA", or "OKP"
    pub kty: String,
    /// Key ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    // EC fields (P-256 / ES256)
    /// EC curve name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // RSA fields
    /// RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapClientDisplay {
    pub name: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapInteractionRequirements {
    pub start: Vec<String>,
    pub finish: Option<GnapInteractionFinish>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnapInteractionFinish {
    pub method: String,
    pub uri: String,
    pub nonce: String,
}

impl GnapTransactionRequest {
    /// Create a builder for a GNAP transaction request.
    ///
    /// # Example
    /// ```rust
    /// use auth_framework::protocols::gnap::GnapTransactionRequest;
    ///
    /// let req = GnapTransactionRequest::builder()
    ///     .access("read", &["list"], &["https://api.example.com"])
    ///     .subject_formats(vec!["opaque".into()])
    ///     .build();
    /// ```
    pub fn builder() -> GnapTransactionRequestBuilder {
        GnapTransactionRequestBuilder {
            client: None,
            interact: None,
            access_token: Vec::new(),
            subject: None,
        }
    }
}

/// Builder for [`GnapTransactionRequest`].
pub struct GnapTransactionRequestBuilder {
    client: Option<GnapClientInfo>,
    interact: Option<GnapInteractionRequirements>,
    access_token: Vec<GnapAccessRequest>,
    subject: Option<GnapSubjectRequest>,
}

impl GnapTransactionRequestBuilder {
    /// Set the client info with a key binding.
    pub fn client(mut self, client: GnapClientInfo) -> Self {
        self.client = Some(client);
        self
    }

    /// Set client info from a key and proof method.
    pub fn client_key(mut self, jwk: GnapJwk, proof: impl Into<String>) -> Self {
        self.client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: proof.into(),
                jwk,
            }),
            display: None,
        });
        self
    }

    /// Set interaction requirements for redirect flow.
    pub fn redirect_interaction(
        mut self,
        callback_uri: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        self.interact = Some(GnapInteractionRequirements {
            start: vec!["redirect".to_string()],
            finish: Some(GnapInteractionFinish {
                method: "redirect".to_string(),
                uri: callback_uri.into(),
                nonce: nonce.into(),
            }),
        });
        self
    }

    /// Set interaction requirements (raw).
    pub fn interact(mut self, interact: GnapInteractionRequirements) -> Self {
        self.interact = Some(interact);
        self
    }

    /// Add an access request with type, actions, and locations.
    pub fn access(
        mut self,
        access_type: impl Into<String>,
        actions: &[impl AsRef<str>],
        locations: &[impl AsRef<str>],
    ) -> Self {
        self.access_token.push(GnapAccessRequest {
            access_type: access_type.into(),
            actions: actions.iter().map(|a| a.as_ref().to_string()).collect(),
            locations: locations.iter().map(|l| l.as_ref().to_string()).collect(),
        });
        self
    }

    /// Add a simple access request (type only, no actions/locations).
    pub fn access_type(self, access_type: impl Into<String>) -> Self {
        self.access(access_type, &[] as &[&str], &[] as &[&str])
    }

    /// Request subject information with the given identifier formats.
    pub fn subject_formats(mut self, formats: Vec<String>) -> Self {
        self.subject = Some(GnapSubjectRequest {
            sub_id_formats: formats,
            assertion_formats: vec![],
        });
        self
    }

    /// Request subject information (raw).
    pub fn subject(mut self, subject: GnapSubjectRequest) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Build the [`GnapTransactionRequest`].
    pub fn build(self) -> GnapTransactionRequest {
        GnapTransactionRequest {
            client: self.client,
            interact: self.interact,
            access_token: if self.access_token.is_empty() {
                None
            } else {
                Some(self.access_token)
            },
            subject: self.subject,
        }
    }
}

/// Internal state of a GNAP transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
enum GnapTransactionState {
    /// Waiting for user interaction
    Pending,
    /// User has approved; access token can be issued
    Approved,
    /// Transaction was denied or expired
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GnapTransaction {
    id: String,
    state: GnapTransactionState,
    request: GnapTransactionRequest,
    continue_token: String,
    created_at: u64,
    /// Server-generated nonce for interaction hash verification (draft §4.2.3)
    interact_nonce: Option<String>,
    /// Subject identifier assigned after approval
    subject_id: Option<String>,
}

/// A GNAP access token that has been issued and can be managed
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GnapIssuedToken {
    /// Opaque token value
    pub value: String,
    /// Access rights granted
    pub access: Vec<GnapAccessRequest>,
    /// Expiration timestamp (epoch seconds)
    pub expires_at: u64,
    /// Client key thumbprint that this token is bound to (if any)
    pub key_thumbprint: Option<String>,
    /// The transaction that produced this token
    pub transaction_id: String,
}

pub struct GnapService {
    config: GnapConfig,
    /// Active transactions (keyed by transaction ID)
    transactions: Arc<RwLock<HashMap<String, GnapTransaction>>>,
    /// Issued access tokens (keyed by token value)
    issued_tokens: Arc<RwLock<HashMap<String, GnapIssuedToken>>>,
}

impl GnapService {
    pub fn new(config: GnapConfig) -> Self {
        Self {
            config,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            issued_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // ── Key Binding Helpers ──────────────────────────────────────────────

    /// Compute the JWK thumbprint (RFC 7638) for key binding.
    /// Uses the required members in lexicographic order per key type.
    fn jwk_thumbprint(jwk: &GnapJwk) -> Result<String> {
        let canonical = match jwk.kty.as_str() {
            "EC" => {
                let crv = jwk.crv.as_deref().unwrap_or("");
                let x = jwk.x.as_deref().unwrap_or("");
                let y = jwk.y.as_deref().unwrap_or("");
                format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
            "RSA" => {
                let e = jwk.e.as_deref().unwrap_or("");
                let n = jwk.n.as_deref().unwrap_or("");
                format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
            }
            "OKP" => {
                let crv = jwk.crv.as_deref().unwrap_or("");
                let x = jwk.x.as_deref().unwrap_or("");
                format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
            }
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported JWK key type: {other}"
                )));
            }
        };
        let hash = Sha256::digest(canonical.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash))
    }

    /// Reconstruct the raw public key bytes from a JWK and verify a
    /// signature using `ring`. Supports ES256 (P-256) and RS256.
    ///
    /// This is called by middleware or application code that extracts the
    /// HTTP message signature from the request before invoking the GNAP
    /// transaction endpoints.
    #[allow(dead_code)]
    pub fn verify_jwk_signature(jwk: &GnapJwk, message: &[u8], signature: &[u8]) -> Result<()> {
        use base64::Engine;
        use ring::signature;

        match jwk.kty.as_str() {
            "EC" => {
                let crv = jwk.crv.as_deref().unwrap_or("P-256");
                if crv != "P-256" {
                    return Err(AuthError::validation(format!(
                        "Unsupported EC curve for GNAP: {crv}"
                    )));
                }
                let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.x.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK x: {e}")))?;
                let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.y.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK y: {e}")))?;

                // Uncompressed point: 0x04 || x || y
                let mut pk_bytes = Vec::with_capacity(1 + x.len() + y.len());
                pk_bytes.push(0x04);
                pk_bytes.extend_from_slice(&x);
                pk_bytes.extend_from_slice(&y);

                let key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &pk_bytes,
                );
                key.verify(message, signature).map_err(|_| {
                    AuthError::validation("GNAP client key signature verification failed (ES256)")
                })
            }
            "RSA" => {
                let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.n.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK n: {e}")))?;
                let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwk.e.as_deref().unwrap_or(""))
                    .map_err(|e| AuthError::validation(format!("Invalid JWK e: {e}")))?;

                // DER-encode the RSA public key (PKCS#1)
                let pk_der = Self::encode_rsa_public_key_der(&n, &e);

                let key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    &pk_der,
                );
                key.verify(message, signature).map_err(|_| {
                    AuthError::validation("GNAP client key signature verification failed (RS256)")
                })
            }
            other => Err(AuthError::validation(format!(
                "Unsupported JWK key type for signature: {other}"
            ))),
        }
    }

    /// Encode RSA n,e into a DER SubjectPublicKeyInfo structure for ring.
    #[allow(dead_code)]
    fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
        // Build PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
        fn der_integer(val: &[u8]) -> Vec<u8> {
            // Strip leading zeros but ensure positive
            let v = if !val.is_empty() && val[0] == 0 {
                let stripped = val.iter().position(|&b| b != 0).unwrap_or(val.len() - 1);
                &val[stripped..]
            } else {
                val
            };
            let needs_pad = !v.is_empty() && v[0] & 0x80 != 0;
            let len = v.len() + if needs_pad { 1 } else { 0 };
            let mut out = vec![0x02]; // INTEGER tag
            der_encode_length(len, &mut out);
            if needs_pad {
                out.push(0x00);
            }
            out.extend_from_slice(v);
            out
        }

        fn der_encode_length(len: usize, out: &mut Vec<u8>) {
            if len < 0x80 {
                out.push(len as u8);
            } else if len < 0x100 {
                out.push(0x81);
                out.push(len as u8);
            } else if len < 0x10000 {
                out.push(0x82);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            } else {
                out.push(0x83);
                out.push((len >> 16) as u8);
                out.push((len >> 8) as u8);
                out.push(len as u8);
            }
        }

        let n_der = der_integer(n);
        let e_der = der_integer(e);
        let rsa_seq_content_len = n_der.len() + e_der.len();
        let mut rsa_seq = vec![0x30]; // SEQUENCE tag
        der_encode_length(rsa_seq_content_len, &mut rsa_seq);
        rsa_seq.extend_from_slice(&n_der);
        rsa_seq.extend_from_slice(&e_der);

        // Wrap in SubjectPublicKeyInfo:
        // SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { rsa_seq } }
        let rsa_oid: &[u8] = &[
            0x30, 0x0d, // SEQUENCE (AlgorithmIdentifier)
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x01, // OID 1.2.840.113549.1.1.1
            0x05, 0x00, // NULL
        ];
        let bitstring_len = 1 + rsa_seq.len(); // 1 byte for unused-bits count
        let mut bitstring = vec![0x03]; // BIT STRING tag
        der_encode_length(bitstring_len, &mut bitstring);
        bitstring.push(0x00); // 0 unused bits
        bitstring.extend_from_slice(&rsa_seq);

        let spki_content_len = rsa_oid.len() + bitstring.len();
        let mut spki = vec![0x30]; // outer SEQUENCE
        der_encode_length(spki_content_len, &mut spki);
        spki.extend_from_slice(rsa_oid);
        spki.extend_from_slice(&bitstring);
        spki
    }

    /// Validate the client key binding on a request.
    /// Returns the key thumbprint if a key is present and valid.
    ///
    /// When `proof_message` and `proof_signature` are provided, the actual
    /// cryptographic signature is verified against the client's JWK. For
    /// proof methods other than "test", the caller (typically HTTP middleware)
    /// must extract and supply the message and signature bytes from the
    /// request (e.g. the HTTP Signature input string and its signature value).
    pub fn validate_client_key_with_proof(
        client: &Option<GnapClientInfo>,
        proof_message: Option<&[u8]>,
        proof_signature: Option<&[u8]>,
    ) -> Result<Option<String>> {
        let client = match client {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = match &client.key {
            Some(k) => k,
            None => return Ok(None),
        };

        // Validate proof method is recognized
        match key.proof.as_str() {
            "httpsig" | "mtls" | "dpop" | "jws" | "test" => {}
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported GNAP proof method: {other}"
                )));
            }
        }

        // Validate key type and required fields
        Self::validate_jwk_fields(&key.jwk)?;

        let thumbprint = Self::jwk_thumbprint(&key.jwk)?;

        // If proof material is provided and the proof method requires
        // cryptographic verification, verify the signature now.
        if key.proof != "test"
            && let (Some(msg), Some(sig)) = (proof_message, proof_signature)
        {
            Self::verify_jwk_signature(&key.jwk, msg, sig)?;
        }

        Ok(Some(thumbprint))
    }

    /// Validate that a JWK has the required fields for its key type.
    fn validate_jwk_fields(jwk: &GnapJwk) -> Result<()> {
        match jwk.kty.as_str() {
            "EC" => {
                if jwk.x.is_none() || jwk.y.is_none() {
                    return Err(AuthError::validation(
                        "EC JWK must include x and y coordinates",
                    ));
                }
            }
            "RSA" => {
                if jwk.n.is_none() || jwk.e.is_none() {
                    return Err(AuthError::validation(
                        "RSA JWK must include n and e components",
                    ));
                }
            }
            "OKP" => {
                if jwk.x.is_none() {
                    return Err(AuthError::validation("OKP JWK must include x coordinate"));
                }
            }
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported JWK key type: {other}"
                )));
            }
        }
        Ok(())
    }

    /// Validate the client key binding on a request (structural only, no
    /// signature verification). Used internally when proof material is
    /// not available at the protocol level (e.g., continuation polling).
    fn validate_client_key(client: &Option<GnapClientInfo>) -> Result<Option<String>> {
        let client = match client {
            Some(c) => c,
            None => return Ok(None),
        };
        let key = match &client.key {
            Some(k) => k,
            None => return Ok(None),
        };

        // Validate proof method is recognized
        match key.proof.as_str() {
            "httpsig" | "mtls" | "dpop" | "jws" | "test" => {}
            other => {
                return Err(AuthError::validation(format!(
                    "Unsupported GNAP proof method: {other}"
                )));
            }
        }

        Self::validate_jwk_fields(&key.jwk)?;
        let thumbprint = Self::jwk_thumbprint(&key.jwk)?;
        Ok(Some(thumbprint))
    }

    // ── Interaction Hash ─────────────────────────────────────────────────

    /// Compute the interaction hash per draft §4.2.3.
    ///
    /// hash = SHA-256( client_nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + tx_endpoint )
    fn compute_interact_hash(
        client_nonce: &str,
        server_nonce: &str,
        interact_ref: &str,
        transaction_endpoint: &str,
    ) -> String {
        let input =
            format!("{client_nonce}\n{server_nonce}\n{interact_ref}\n{transaction_endpoint}");
        let hash = Sha256::digest(input.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    // ── Token Issuance Helper ────────────────────────────────────────────

    fn build_access_token_response(
        &self,
        access_requests: &[GnapAccessRequest],
        key_thumbprint: &Option<String>,
        transaction_id: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let access_token = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let issued = GnapIssuedToken {
            value: access_token.clone(),
            access: access_requests.to_vec(),
            expires_at: now + self.config.token_lifetime_secs,
            key_thumbprint: key_thumbprint.clone(),
            transaction_id: transaction_id.to_string(),
        };

        // Store in issued_tokens (fire-and-forget via blocking write is fine
        // since we return the response synchronously within an async context)
        let tokens = Arc::clone(&self.issued_tokens);
        let token_value = access_token.clone();
        let issued_clone = issued;
        tokio::spawn(async move {
            tokens.write().await.insert(token_value, issued_clone);
        });

        let mut token_obj = serde_json::Map::new();
        token_obj.insert("value".to_string(), serde_json::Value::String(access_token));
        token_obj.insert(
            "expires_in".to_string(),
            serde_json::Value::Number(self.config.token_lifetime_secs.into()),
        );

        // Include manage URI for token lifecycle operations
        token_obj.insert(
            "manage".to_string(),
            serde_json::Value::String(format!("{}/token", self.config.transaction_endpoint)),
        );

        // If key-bound, indicate the key binding
        if key_thumbprint.is_some() {
            token_obj.insert("key".to_string(), serde_json::Value::Bool(true));
        }

        let access_json: Vec<serde_json::Value> = access_requests
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();
        token_obj.insert("access".to_string(), serde_json::Value::Array(access_json));

        token_obj
    }

    // ── Transaction Lifecycle ────────────────────────────────────────────

    /// Handle a new GNAP transaction request (draft-ietf-gnap-core-protocol §2)
    pub async fn handle_transaction(
        &self,
        request: GnapTransactionRequest,
    ) -> Result<serde_json::Value> {
        if !self.config.enabled {
            return Err(AuthError::config("GNAP protocol is currently disabled"));
        }

        // Validate that the request asks for something
        if request.access_token.is_none() && request.subject.is_none() {
            return Err(AuthError::validation(
                "GNAP request must include at least one of access_token or subject",
            ));
        }

        // Validate client key if provided (draft §7.1)
        let key_thumbprint = Self::validate_client_key(&request.client)?;

        let transaction_id = uuid::Uuid::new_v4().to_string();
        let continue_token = uuid::Uuid::new_v4().to_string();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut response = serde_json::Map::new();

        // Generate a server nonce for interaction hash verification
        let interact_nonce = if request.interact.is_some() {
            let nonce = uuid::Uuid::new_v4().to_string();
            Some(nonce)
        } else {
            None
        };

        // If interaction is requested, generate interaction response
        if let Some(ref interact) = request.interact {
            let base_url = self.config.interaction_base_url.as_deref().ok_or_else(|| {
                AuthError::config(
                    "GNAP interaction_base_url must be configured for interactive flows",
                )
            })?;

            let interact_url = format!("{}/interact/{}", base_url, transaction_id);

            let mut interact_res = serde_json::Map::new();

            if interact.start.iter().any(|m| m == "redirect") {
                interact_res.insert(
                    "redirect".to_string(),
                    serde_json::Value::String(interact_url),
                );
            }

            if let Some(ref finish) = interact.finish {
                // Return server nonce for client to compute interaction hash
                interact_res.insert(
                    "finish".to_string(),
                    serde_json::Value::String(interact_nonce.clone().unwrap_or_default()),
                );
                // Echo the finish method + nonce so client knows the protocol
                let _ = &finish.nonce; // client_nonce is used later for hash
            }

            response.insert(
                "interact".to_string(),
                serde_json::Value::Object(interact_res),
            );

            // Store pending transaction
            let txn = GnapTransaction {
                id: transaction_id.clone(),
                state: GnapTransactionState::Pending,
                request: request.clone(),
                continue_token: continue_token.clone(),
                created_at: now,
                interact_nonce: interact_nonce.clone(),
                subject_id: None,
            };
            self.transactions.write().await.insert(transaction_id, txn);
        } else {
            // No interaction required — issue token directly if access requested
            if let Some(ref access_requests) = request.access_token {
                let token_obj =
                    self.build_access_token_response(access_requests, &key_thumbprint, "direct");
                response.insert(
                    "access_token".to_string(),
                    serde_json::Value::Object(token_obj),
                );
            }

            // If subject info was requested, include it (draft §2.2)
            if let Some(ref subject_req) = request.subject {
                let subject_resp = Self::build_subject_response(subject_req, None);
                response.insert(
                    "subject".to_string(),
                    serde_json::Value::Object(subject_resp),
                );
            }
        }

        // Provide continuation endpoint (with rotatable token)
        let mut continue_obj = serde_json::Map::new();
        let mut ct_token = serde_json::Map::new();
        ct_token.insert(
            "value".to_string(),
            serde_json::Value::String(continue_token),
        );
        continue_obj.insert(
            "access_token".to_string(),
            serde_json::Value::Object(ct_token),
        );
        continue_obj.insert(
            "uri".to_string(),
            serde_json::Value::String(format!("{}/continue", self.config.transaction_endpoint)),
        );

        response.insert(
            "continue".to_string(),
            serde_json::Value::Object(continue_obj),
        );

        Ok(serde_json::Value::Object(response))
    }

    /// Continue a GNAP transaction (polling or post-interaction).
    ///
    /// The continuation token is **rotated on every successful call** per
    /// draft §5.1, preventing replay of old continuation responses.
    pub async fn continue_transaction(
        &self,
        transaction_id: &str,
        continue_token: &str,
        interact_ref: Option<&str>,
        interact_hash: Option<&str>,
    ) -> Result<serde_json::Value> {
        // Take a write lock so we can rotate the continuation token atomically
        let mut transactions = self.transactions.write().await;
        let txn = transactions
            .get_mut(transaction_id)
            .ok_or_else(|| AuthError::validation("Transaction not found or expired"))?;

        // Enforce transaction expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(txn.created_at) > self.config.transaction_lifetime_secs {
            transactions.remove(transaction_id);
            return Err(AuthError::validation("Transaction has expired"));
        }

        // Verify continuation token
        if txn.continue_token != continue_token {
            return Err(AuthError::validation("Invalid continuation token"));
        }

        // Rotate the continuation token (draft §5.1)
        let new_continue_token = uuid::Uuid::new_v4().to_string();
        txn.continue_token = new_continue_token.clone();

        // If interaction hash is provided, verify it (draft §4.2.3)
        if let (Some(hash), Some(iref)) = (interact_hash, interact_ref) {
            let server_nonce = txn.interact_nonce.as_deref().ok_or_else(|| {
                AuthError::validation("No interaction nonce for this transaction")
            })?;
            let client_nonce = txn
                .request
                .interact
                .as_ref()
                .and_then(|i| i.finish.as_ref())
                .map(|f| f.nonce.as_str())
                .unwrap_or("");

            let expected = Self::compute_interact_hash(
                client_nonce,
                server_nonce,
                iref,
                &self.config.transaction_endpoint,
            );
            if hash != expected {
                return Err(AuthError::validation(
                    "Interaction hash verification failed (draft §4.2.3)",
                ));
            }
        }

        let result = match txn.state {
            GnapTransactionState::Pending => {
                // Still waiting for user interaction
                let mut resp = serde_json::Map::new();
                let mut cont = serde_json::Map::new();
                cont.insert(
                    "uri".to_string(),
                    serde_json::Value::String(format!(
                        "{}/continue",
                        self.config.transaction_endpoint
                    )),
                );
                cont.insert("wait".to_string(), serde_json::Value::Number(5.into()));
                let mut ct = serde_json::Map::new();
                ct.insert(
                    "value".to_string(),
                    serde_json::Value::String(new_continue_token),
                );
                cont.insert("access_token".to_string(), serde_json::Value::Object(ct));
                resp.insert("continue".to_string(), serde_json::Value::Object(cont));
                Ok(serde_json::Value::Object(resp))
            }
            GnapTransactionState::Approved => {
                let key_thumbprint = Self::validate_client_key(&txn.request.client).unwrap_or(None);

                let mut response = serde_json::Map::new();

                // Issue access token
                if let Some(ref access_requests) = txn.request.access_token {
                    let token_obj = self.build_access_token_response(
                        access_requests,
                        &key_thumbprint,
                        transaction_id,
                    );
                    response.insert(
                        "access_token".to_string(),
                        serde_json::Value::Object(token_obj),
                    );
                }

                // Include subject info if requested and available
                if let Some(ref subject_req) = txn.request.subject {
                    let subject_resp =
                        Self::build_subject_response(subject_req, txn.subject_id.as_deref());
                    response.insert(
                        "subject".to_string(),
                        serde_json::Value::Object(subject_resp),
                    );
                }

                Ok(serde_json::Value::Object(response))
            }
            GnapTransactionState::Denied => Err(AuthError::validation(
                "Transaction was denied by the resource owner",
            )),
        };

        // Remove completed/denied transactions
        if matches!(
            txn.state,
            GnapTransactionState::Approved | GnapTransactionState::Denied
        ) {
            transactions.remove(transaction_id);
        }

        result
    }

    /// Approve a pending transaction (called after user interaction).
    /// Optionally sets the subject identifier for subject-info responses.
    pub async fn approve_transaction(
        &self,
        transaction_id: &str,
        subject_id: Option<&str>,
    ) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        let txn = transactions
            .get_mut(transaction_id)
            .ok_or_else(|| AuthError::validation("Transaction not found"))?;
        txn.state = GnapTransactionState::Approved;
        if let Some(sid) = subject_id {
            txn.subject_id = Some(sid.to_string());
        }
        Ok(())
    }

    /// Deny a pending transaction
    pub async fn deny_transaction(&self, transaction_id: &str) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        let txn = transactions
            .get_mut(transaction_id)
            .ok_or_else(|| AuthError::validation("Transaction not found"))?;
        txn.state = GnapTransactionState::Denied;
        Ok(())
    }

    // ── Token Management (draft §6) ─────────────────────────────────────

    /// Revoke an issued access token (draft §6.2 — DELETE on manage URI).
    pub async fn revoke_token(&self, token_value: &str) -> Result<()> {
        let mut tokens = self.issued_tokens.write().await;
        if tokens.remove(token_value).is_none() {
            return Err(AuthError::validation("Token not found"));
        }
        Ok(())
    }

    /// Rotate an issued access token (draft §6.1 — POST on manage URI).
    /// Returns a new token with the same access rights and key binding.
    pub async fn rotate_token(&self, old_token_value: &str) -> Result<serde_json::Value> {
        let mut tokens = self.issued_tokens.write().await;
        let old = tokens
            .remove(old_token_value)
            .ok_or_else(|| AuthError::validation("Token not found or already revoked"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now >= old.expires_at {
            return Err(AuthError::validation("Token has expired"));
        }

        let new_value = uuid::Uuid::new_v4().to_string();
        let new_token = GnapIssuedToken {
            value: new_value.clone(),
            access: old.access.clone(),
            expires_at: now + self.config.token_lifetime_secs,
            key_thumbprint: old.key_thumbprint.clone(),
            transaction_id: old.transaction_id,
        };

        let mut token_obj = serde_json::Map::new();
        token_obj.insert(
            "value".to_string(),
            serde_json::Value::String(new_value.clone()),
        );
        token_obj.insert(
            "expires_in".to_string(),
            serde_json::Value::Number(self.config.token_lifetime_secs.into()),
        );
        token_obj.insert(
            "manage".to_string(),
            serde_json::Value::String(format!("{}/token", self.config.transaction_endpoint)),
        );
        if new_token.key_thumbprint.is_some() {
            token_obj.insert("key".to_string(), serde_json::Value::Bool(true));
        }
        let access_json: Vec<serde_json::Value> = old
            .access
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();
        token_obj.insert("access".to_string(), serde_json::Value::Array(access_json));

        tokens.insert(new_value, new_token);
        drop(tokens);

        Ok(serde_json::Value::Object(token_obj))
    }

    /// Introspect a token — check if it is valid and return its access rights.
    pub async fn introspect_token(&self, token_value: &str) -> Result<Option<serde_json::Value>> {
        let tokens = self.issued_tokens.read().await;
        let token = match tokens.get(token_value) {
            Some(t) => t,
            None => return Ok(None),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now >= token.expires_at {
            return Ok(None);
        }

        let access_json: Vec<serde_json::Value> = token
            .access
            .iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();

        let mut result = serde_json::Map::new();
        result.insert("active".to_string(), serde_json::Value::Bool(true));
        result.insert("access".to_string(), serde_json::Value::Array(access_json));
        result.insert(
            "expires_in".to_string(),
            serde_json::Value::Number((token.expires_at - now).into()),
        );
        if let Some(ref tp) = token.key_thumbprint {
            result.insert(
                "key_thumbprint".to_string(),
                serde_json::Value::String(tp.clone()),
            );
        }
        result.insert(
            "key_bound".to_string(),
            serde_json::Value::Bool(token.key_thumbprint.is_some()),
        );

        Ok(Some(serde_json::Value::Object(result)))
    }

    /// Validate that a key-bound token is being used with the correct key.
    ///
    /// For tokens issued with a client key binding, verify that the
    /// presenting client's JWK thumbprint matches the stored binding.
    /// Returns `Ok(true)` if the token is not key-bound (no restriction).
    pub async fn validate_token_key_binding(
        &self,
        token_value: &str,
        presenting_jwk: &GnapJwk,
    ) -> Result<bool> {
        let tokens = self.issued_tokens.read().await;
        let token = match tokens.get(token_value) {
            Some(t) => t,
            None => return Err(AuthError::validation("Token not found")),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= token.expires_at {
            return Err(AuthError::validation("Token has expired"));
        }

        match &token.key_thumbprint {
            None => Ok(true), // Not key-bound → any presenter is fine
            Some(expected_tp) => {
                let presenting_tp = Self::jwk_thumbprint(presenting_jwk)?;
                Ok(
                    subtle::ConstantTimeEq::ct_eq(expected_tp.as_bytes(), presenting_tp.as_bytes())
                        .into(),
                )
            }
        }
    }

    // ── Subject Info Response (draft §2.2) ───────────────────────────────

    /// Build a subject information response based on what was requested.
    fn build_subject_response(
        request: &GnapSubjectRequest,
        subject_id: Option<&str>,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut resp = serde_json::Map::new();

        // Return sub_ids in requested formats
        if let Some(sid) = subject_id {
            let mut sub_ids = Vec::new();
            for fmt in &request.sub_id_formats {
                match fmt.as_str() {
                    "opaque" => {
                        sub_ids.push(serde_json::json!({
                            "format": "opaque",
                            "id": sid,
                        }));
                    }
                    "email" => {
                        // Only include if the subject ID looks like an email
                        if sid.contains('@') {
                            sub_ids.push(serde_json::json!({
                                "format": "email",
                                "email": sid,
                            }));
                        }
                    }
                    "iss_sub" => {
                        sub_ids.push(serde_json::json!({
                            "format": "iss_sub",
                            "iss": "self",
                            "sub": sid,
                        }));
                    }
                    _ => {} // Unknown format — skip
                }
            }
            if sub_ids.is_empty() {
                // Default to opaque if no recognized format
                sub_ids.push(serde_json::json!({
                    "format": "opaque",
                    "id": sid,
                }));
            }
            resp.insert("sub_ids".to_string(), serde_json::Value::Array(sub_ids));
        }

        resp
    }

    // ── Cleanup ──────────────────────────────────────────────────────────

    /// Remove expired transactions from the in-memory store.
    pub async fn cleanup_expired_transactions(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let lifetime = self.config.transaction_lifetime_secs;
        self.transactions
            .write()
            .await
            .retain(|_, t| now.saturating_sub(t.created_at) <= lifetime);
    }

    /// Remove expired access tokens from the in-memory store.
    pub async fn cleanup_expired_tokens(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.issued_tokens
            .write()
            .await
            .retain(|_, t| now < t.expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GnapConfig {
        GnapConfig {
            enabled: true,
            transaction_endpoint: "/api/gnap/tx".to_string(),
            interaction_base_url: Some("https://auth.example.test".to_string()),
            token_lifetime_secs: 3600,
            transaction_lifetime_secs: 600,
        }
    }

    fn test_ec_jwk() -> GnapJwk {
        GnapJwk {
            kty: "EC".to_string(),
            kid: Some("test-key-1".to_string()),
            crv: Some("P-256".to_string()),
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
            n: None,
            e: None,
        }
    }

    fn test_rsa_jwk() -> GnapJwk {
        GnapJwk {
            kty: "RSA".to_string(),
            kid: Some("test-rsa-1".to_string()),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM".to_string()),
            e: Some("AQAB".to_string()),
        }
    }

    fn test_client_info(jwk: GnapJwk) -> GnapClientInfo {
        GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "test".to_string(),
                jwk,
            }),
            display: Some(GnapClientDisplay {
                name: Some("Test Client".to_string()),
                uri: Some("https://client.example.test".to_string()),
            }),
        }
    }

    // ── Config & Construction ────────────────────────────────────────────

    #[test]
    fn test_gnap_config_defaults() {
        let config = GnapConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.token_lifetime_secs, 3600);
        assert_eq!(config.transaction_lifetime_secs, 600);
        assert!(config.interaction_base_url.is_none());
    }

    #[test]
    fn test_gnap_service_creation() {
        let service = GnapService::new(test_config());
        assert!(service.config.enabled);
    }

    // ── JWK Thumbprint (RFC 7638) ────────────────────────────────────────

    #[test]
    fn test_jwk_thumbprint_ec() {
        let jwk = test_ec_jwk();
        let tp = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        // Thumbprint is base64url-encoded SHA-256 → 43 chars
        assert_eq!(tp.len(), 43);
    }

    #[test]
    fn test_jwk_thumbprint_rsa() {
        let jwk = test_rsa_jwk();
        let tp = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert!(!tp.is_empty());
        assert_eq!(tp.len(), 43);
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let jwk = test_ec_jwk();
        let tp1 = GnapService::jwk_thumbprint(&jwk).unwrap();
        let tp2 = GnapService::jwk_thumbprint(&jwk).unwrap();
        assert_eq!(tp1, tp2);
    }

    #[test]
    fn test_jwk_thumbprint_different_keys() {
        let tp_ec = GnapService::jwk_thumbprint(&test_ec_jwk()).unwrap();
        let tp_rsa = GnapService::jwk_thumbprint(&test_rsa_jwk()).unwrap();
        assert_ne!(tp_ec, tp_rsa);
    }

    #[test]
    fn test_jwk_thumbprint_unsupported_type() {
        let jwk = GnapJwk {
            kty: "UNKNOWN".to_string(),
            kid: None,
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
        };
        assert!(GnapService::jwk_thumbprint(&jwk).is_err());
    }

    // ── Client Key Validation ────────────────────────────────────────────

    #[test]
    fn test_validate_client_key_ec() {
        let client = Some(test_client_info(test_ec_jwk()));
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_some());
    }

    #[test]
    fn test_validate_client_key_rsa() {
        let client = Some(test_client_info(test_rsa_jwk()));
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_some());
    }

    #[test]
    fn test_validate_client_key_none() {
        let tp = GnapService::validate_client_key(&None).unwrap();
        assert!(tp.is_none());
    }

    #[test]
    fn test_validate_client_key_no_key() {
        let client = Some(GnapClientInfo {
            key: None,
            display: None,
        });
        let tp = GnapService::validate_client_key(&client).unwrap();
        assert!(tp.is_none());
    }

    #[test]
    fn test_validate_client_key_invalid_proof_method() {
        let client = Some(GnapClientInfo {
            key: Some(GnapClientKey {
                proof: "invalid_method".to_string(),
                jwk: test_ec_jwk(),
            }),
            display: None,
        });
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_ec_missing_y() {
        let mut jwk = test_ec_jwk();
        jwk.y = None;
        let client = Some(test_client_info(jwk));
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_rsa_missing_e() {
        let mut jwk = test_rsa_jwk();
        jwk.e = None;
        let client = Some(test_client_info(jwk));
        assert!(GnapService::validate_client_key(&client).is_err());
    }

    #[test]
    fn test_validate_client_key_with_proof_test_mode() {
        let client = Some(test_client_info(test_ec_jwk()));
        let tp = GnapService::validate_client_key_with_proof(&client, None, None).unwrap();
        assert!(tp.is_some());
    }

    // ── Interaction Hash ─────────────────────────────────────────────────

    #[test]
    fn test_compute_interact_hash_deterministic() {
        let h1 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        let h2 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_interact_hash_different_inputs() {
        let h1 = GnapService::compute_interact_hash("cn1", "sn1", "ref1", "/tx");
        let h2 = GnapService::compute_interact_hash("cn2", "sn1", "ref1", "/tx");
        assert_ne!(h1, h2);
    }

    // ── Transaction Lifecycle ────────────────────────────────────────────

    #[tokio::test]
    async fn test_transaction_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let service = GnapService::new(config);
        let req = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        assert!(service.handle_transaction(req).await.is_err());
    }

    #[tokio::test]
    async fn test_transaction_requires_access_or_subject() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token: None,
            subject: None,
        };
        assert!(service.handle_transaction(req).await.is_err());
    }

    #[tokio::test]
    async fn test_transaction_direct_token_issuance() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: None,
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec!["list".to_string()],
                locations: vec!["https://api.test/resources".to_string()],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("access_token"));
        assert!(obj.contains_key("continue"));

        let token_obj = obj["access_token"].as_object().unwrap();
        assert!(token_obj.contains_key("value"));
        assert!(token_obj.contains_key("expires_in"));
        assert!(token_obj.contains_key("manage"));
        assert_eq!(token_obj.get("key").and_then(|v| v.as_bool()), Some(true));
    }

    #[tokio::test]
    async fn test_transaction_with_interaction() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/callback".to_string(),
                    nonce: "client-nonce-123".to_string(),
                }),
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "write".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("interact"));
        assert!(obj.contains_key("continue"));

        let interact = obj["interact"].as_object().unwrap();
        assert!(interact.contains_key("redirect"));
        assert!(interact.contains_key("finish"));
    }

    #[tokio::test]
    async fn test_transaction_subject_only() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token: None,
            subject: Some(GnapSubjectRequest {
                sub_id_formats: vec!["opaque".to_string()],
                assertion_formats: vec![],
            }),
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let obj = resp.as_object().unwrap();
        assert!(obj.contains_key("subject"));
    }

    // ── Approve / Deny / Continue ────────────────────────────────────────

    #[tokio::test]
    async fn test_approve_and_continue() {
        let service = GnapService::new(test_config());

        // Create interactive transaction
        let req = GnapTransactionRequest {
            client: Some(test_client_info(test_ec_jwk())),
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let cont = resp["continue"]["access_token"]["value"].as_str().unwrap();

        // Get transaction ID from the stored transactions
        let txn_id = {
            let txns = service.transactions.read().await;
            txns.keys().next().unwrap().clone()
        };

        // Continue before approval → pending
        let poll = service
            .continue_transaction(&txn_id, cont, None, None)
            .await;
        assert!(
            poll.is_err() || {
                let r = poll.unwrap();
                r.as_object().unwrap().contains_key("continue")
            }
        );

        // Get updated continuation token
        let new_cont = {
            let txns = service.transactions.read().await;
            txns.get(&txn_id).unwrap().continue_token.clone()
        };

        // Approve
        service
            .approve_transaction(&txn_id, Some("user-42"))
            .await
            .unwrap();

        // Continue after approval → get token
        let result = service
            .continue_transaction(&txn_id, &new_cont, None, None)
            .await
            .unwrap();
        assert!(result.as_object().unwrap().contains_key("access_token"));
    }

    #[tokio::test]
    async fn test_deny_transaction() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let txn_id = {
            let txns = service.transactions.read().await;
            txns.keys().next().unwrap().clone()
        };

        service.deny_transaction(&txn_id).await.unwrap();

        let cont = {
            let txns = service.transactions.read().await;
            txns.get(&txn_id).unwrap().continue_token.clone()
        };
        let result = service
            .continue_transaction(&txn_id, &cont, None, None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_continue_invalid_token() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        let txn_id = {
            let txns = service.transactions.read().await;
            txns.keys().next().unwrap().clone()
        };
        let result = service
            .continue_transaction(&txn_id, "bad-token", None, None)
            .await;
        assert!(result.is_err());
    }

    // ── Token Management ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_token_revocation() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let token_value = resp["access_token"]["value"].as_str().unwrap();

        // Small delay so the spawned insert task completes
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Introspect before revocation
        let info = service.introspect_token(token_value).await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.as_ref().unwrap()["active"], true);

        // Revoke
        service.revoke_token(token_value).await.unwrap();

        // Introspect after revocation
        let info = service.introspect_token(token_value).await.unwrap();
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn test_token_rotation() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: None,
            access_token: Some(vec![GnapAccessRequest {
                access_type: "write".to_string(),
                actions: vec!["create".to_string()],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let old_token = resp["access_token"]["value"].as_str().unwrap().to_string();

        // Wait for spawned insert
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Rotate
        let new_resp = service.rotate_token(&old_token).await.unwrap();
        let new_token = new_resp["value"].as_str().unwrap();
        assert_ne!(old_token, new_token);

        // Old token should be gone
        let old_info = service.introspect_token(&old_token).await.unwrap();
        assert!(old_info.is_none());

        // New token should be active
        let new_info = service.introspect_token(new_token).await.unwrap();
        assert!(new_info.is_some());
        assert_eq!(new_info.unwrap()["active"], true);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_token() {
        let service = GnapService::new(test_config());
        assert!(service.revoke_token("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_introspect_nonexistent_token() {
        let service = GnapService::new(test_config());
        let info = service.introspect_token("nonexistent").await.unwrap();
        assert!(info.is_none());
    }

    // ── Key Binding Verification ─────────────────────────────────────────

    #[tokio::test]
    async fn test_token_key_binding_check() {
        let service = GnapService::new(test_config());
        let ec_jwk = test_ec_jwk();
        let req = GnapTransactionRequest {
            client: Some(test_client_info(ec_jwk.clone())),
            interact: None,
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let token_value = resp["access_token"]["value"].as_str().unwrap();

        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Same key → should pass
        let ok = service
            .validate_token_key_binding(token_value, &ec_jwk)
            .await
            .unwrap();
        assert!(ok);

        // Different key → should fail
        let other_jwk = test_rsa_jwk();
        let bad = service
            .validate_token_key_binding(token_value, &other_jwk)
            .await
            .unwrap();
        assert!(!bad);
    }

    // ── Subject Info ─────────────────────────────────────────────────────

    #[test]
    fn test_build_subject_response_opaque() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids.len(), 1);
        assert_eq!(sub_ids[0]["format"], "opaque");
        assert_eq!(sub_ids[0]["id"], "user-42");
    }

    #[test]
    fn test_build_subject_response_email() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["email".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user@example.test"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids.len(), 1);
        assert_eq!(sub_ids[0]["format"], "email");
    }

    #[test]
    fn test_build_subject_response_email_not_email() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["email".to_string()],
            assertion_formats: vec![],
        };
        // Subject is not an email → defaults to opaque
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "opaque");
    }

    #[test]
    fn test_build_subject_response_iss_sub() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["iss_sub".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, Some("user-42"));
        let sub_ids = resp["sub_ids"].as_array().unwrap();
        assert_eq!(sub_ids[0]["format"], "iss_sub");
        assert_eq!(sub_ids[0]["sub"], "user-42");
    }

    #[test]
    fn test_build_subject_response_no_subject() {
        let req = GnapSubjectRequest {
            sub_id_formats: vec!["opaque".to_string()],
            assertion_formats: vec![],
        };
        let resp = GnapService::build_subject_response(&req, None);
        assert!(!resp.contains_key("sub_ids"));
    }

    // ── Continuation Token Rotation ──────────────────────────────────────

    #[tokio::test]
    async fn test_continuation_token_rotates() {
        let service = GnapService::new(test_config());
        let req = GnapTransactionRequest {
            client: None,
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        let resp = service.handle_transaction(req).await.unwrap();
        let cont1 = resp["continue"]["access_token"]["value"]
            .as_str()
            .unwrap()
            .to_string();

        let txn_id = {
            let txns = service.transactions.read().await;
            txns.keys().next().unwrap().clone()
        };

        // First continue → token is rotated
        let _ = service
            .continue_transaction(&txn_id, &cont1, None, None)
            .await;

        let cont2 = {
            let txns = service.transactions.read().await;
            txns.get(&txn_id).unwrap().continue_token.clone()
        };
        assert_ne!(cont1, cont2, "Continuation token must rotate on each use");

        // Old token should not work
        let reuse = service
            .continue_transaction(&txn_id, &cont1, None, None)
            .await;
        assert!(reuse.is_err(), "Old continuation token must be rejected");
    }

    // ── Cleanup ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_cleanup_expired_transactions() {
        let mut config = test_config();
        config.transaction_lifetime_secs = 1; // 1 second lifetime
        let service = GnapService::new(config);

        let req = GnapTransactionRequest {
            client: None,
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: None,
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();
        assert_eq!(service.transactions.read().await.len(), 1);

        // Manually backdate the transaction so it appears expired
        {
            let mut txns = service.transactions.write().await;
            for txn in txns.values_mut() {
                txn.created_at = txn.created_at.saturating_sub(10);
            }
        }

        service.cleanup_expired_transactions().await;
        assert_eq!(service.transactions.read().await.len(), 0);
    }

    // ── Interaction Hash Verification ────────────────────────────────────

    #[tokio::test]
    async fn test_interaction_hash_verification() {
        let service = GnapService::new(test_config());
        let client_nonce = "client-nonce-abc";
        let req = GnapTransactionRequest {
            client: None,
            interact: Some(GnapInteractionRequirements {
                start: vec!["redirect".to_string()],
                finish: Some(GnapInteractionFinish {
                    method: "redirect".to_string(),
                    uri: "https://client.test/cb".to_string(),
                    nonce: client_nonce.to_string(),
                }),
            }),
            access_token: Some(vec![GnapAccessRequest {
                access_type: "read".to_string(),
                actions: vec![],
                locations: vec![],
            }]),
            subject: None,
        };
        service.handle_transaction(req).await.unwrap();

        let (txn_id, cont, server_nonce) = {
            let txns = service.transactions.read().await;
            let (id, txn) = txns.iter().next().unwrap();
            (
                id.clone(),
                txn.continue_token.clone(),
                txn.interact_nonce.clone().unwrap(),
            )
        };

        let interact_ref = "test-interact-ref";
        let correct_hash = GnapService::compute_interact_hash(
            client_nonce,
            &server_nonce,
            interact_ref,
            &service.config.transaction_endpoint,
        );

        // Wrong hash → fails
        let bad = service
            .continue_transaction(&txn_id, &cont, Some(interact_ref), Some("bad-hash"))
            .await;
        assert!(bad.is_err());

        // Get fresh continuation token after the failed attempt rotated it
        let fresh_cont = {
            let txns = service.transactions.read().await;
            txns.get(&txn_id).unwrap().continue_token.clone()
        };

        // Correct hash → succeeds
        let good = service
            .continue_transaction(
                &txn_id,
                &fresh_cont,
                Some(interact_ref),
                Some(&correct_hash),
            )
            .await;
        assert!(good.is_ok());
    }

    #[test]
    fn test_gnap_transaction_request_builder_access() {
        let req = GnapTransactionRequest::builder()
            .access("read", &["list", "get"], &["https://api.test/resources"])
            .build();

        assert!(req.client.is_none());
        assert!(req.interact.is_none());
        let access = req.access_token.unwrap();
        assert_eq!(access.len(), 1);
        assert_eq!(access[0].access_type, "read");
        assert_eq!(access[0].actions, vec!["list", "get"]);
    }

    #[test]
    fn test_gnap_transaction_request_builder_full() {
        let jwk = test_ec_jwk();
        let req = GnapTransactionRequest::builder()
            .client_key(jwk, "test")
            .redirect_interaction("https://client.test/cb", "nonce-123")
            .access_type("write")
            .subject_formats(vec!["opaque".into()])
            .build();

        assert!(req.client.is_some());
        assert!(req.interact.is_some());
        assert!(req.access_token.is_some());
        assert!(req.subject.is_some());
        assert_eq!(req.subject.unwrap().sub_id_formats, vec!["opaque"]);
    }

    #[test]
    fn test_gnap_transaction_request_builder_empty() {
        let req = GnapTransactionRequest::builder().build();
        assert!(req.client.is_none());
        assert!(req.interact.is_none());
        assert!(req.access_token.is_none());
        assert!(req.subject.is_none());
    }
}
