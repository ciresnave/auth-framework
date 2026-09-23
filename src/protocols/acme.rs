//! ACME (Automatic Certificate Management Environment) protocol — RFC 8555.
//!
//! Provides automated X.509 certificate issuance and lifecycle management.
//! Supports HTTP-01 and DNS-01 challenge types for domain validation.
//!
//! # Architecture
//!
//! The module implements the client side of the ACME protocol:
//!
//! 1. **Account registration** — create an ACME account with the CA
//! 2. **Order creation** — request a certificate for one or more domains
//! 3. **Authorization** — prove control over the requested domains
//! 4. **Challenge fulfillment** — HTTP-01 or DNS-01 validation
//! 5. **Finalization** — submit CSR and receive the signed certificate
//!
//! # Example
//!
//! ```rust,no_run
//! use auth_framework::protocols::acme::{AcmeClient, AcmeConfig};
//!
//! # async fn example() -> auth_framework::errors::Result<()> {
//! let config = AcmeConfig {
//!     directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
//!     ..Default::default()
//! };
//! let client = AcmeClient::new(config).await?;
//! let order = client.create_order(&["example.com"]).await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── Configuration ───────────────────────────────────────────────────

/// ACME client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// ACME directory URL (e.g., Let's Encrypt production or staging).
    pub directory_url: String,
    /// Contact email addresses for the ACME account.
    pub contact_emails: Vec<String>,
    /// Whether to agree to the CA's terms of service.
    pub agree_to_tos: bool,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            contact_emails: Vec::new(),
            agree_to_tos: false,
            timeout_secs: 30,
        }
    }
}

// ── ACME Directory ──────────────────────────────────────────────────

/// ACME directory resource (RFC 8555 §7.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    #[serde(default)]
    pub new_authz: Option<String>,
    #[serde(default)]
    pub revoke_cert: Option<String>,
    #[serde(default)]
    pub key_change: Option<String>,
    #[serde(default)]
    pub meta: Option<AcmeDirectoryMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectoryMeta {
    #[serde(default)]
    pub terms_of_service: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub caa_identities: Vec<String>,
    #[serde(default)]
    pub external_account_required: bool,
}

// ── ACME Account ────────────────────────────────────────────────────

/// ACME account status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

/// ACME account resource (RFC 8555 §7.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeAccount {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    #[serde(default)]
    pub orders: Option<String>,
}

// ── ACME Order ──────────────────────────────────────────────────────

/// ACME order status (RFC 8555 §7.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// Identifier in an ACME order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

/// ACME order resource (RFC 8555 §7.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeOrder {
    pub status: OrderStatus,
    #[serde(default)]
    pub expires: Option<String>,
    pub identifiers: Vec<AcmeIdentifier>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(default)]
    pub certificate: Option<String>,
}

// ── ACME Authorization ──────────────────────────────────────────────

/// ACME authorization status (RFC 8555 §7.1.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

/// ACME authorization resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthorization {
    pub identifier: AcmeIdentifier,
    pub status: AuthorizationStatus,
    #[serde(default)]
    pub expires: Option<String>,
    pub challenges: Vec<AcmeChallenge>,
    #[serde(default)]
    pub wildcard: bool,
}

// ── ACME Challenge ──────────────────────────────────────────────────

/// ACME challenge types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// ACME challenge status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// ACME challenge resource (RFC 8555 §7.1.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    pub url: String,
    pub status: ChallengeStatus,
    pub token: String,
    #[serde(default)]
    pub validated: Option<String>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

// ── JWS / JWK helpers ───────────────────────────────────────────────

/// Compute the JWK Thumbprint (RFC 7638) of an ECDSA P-256 public key.
fn jwk_thumbprint_p256(public_key: &[u8]) -> String {
    // P-256 public key is 65 bytes: 0x04 || x(32) || y(32)
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return String::new();
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x = b64.encode(&public_key[1..33]);
    let y = b64.encode(&public_key[33..65]);

    // RFC 7638: lexicographic JSON with required members only
    let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = Sha256::digest(thumbprint_input.as_bytes());
    b64.encode(digest)
}

/// Build a JWK object from an ECDSA P-256 public key.
fn build_p256_jwk(public_key: &[u8]) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if public_key.len() == 65 && public_key[0] == 0x04 {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64.encode(&public_key[1..33]),
            "y": b64.encode(&public_key[33..65]),
        })
    } else {
        serde_json::json!({})
    }
}

/// Create a JWS (JSON Web Signature) in Flattened JSON Serialization.
///
/// Per RFC 8555 §6.2, ACME requests use JWS with either `jwk` (for new accounts)
/// or `kid` (for authenticated requests).
fn create_jws(
    key_pair: &EcdsaKeyPair,
    url: &str,
    nonce: &str,
    payload: &str,
    kid: Option<&str>,
) -> Result<serde_json::Value> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut header = serde_json::json!({
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
    });

    if let Some(kid_url) = kid {
        header["kid"] = serde_json::json!(kid_url);
    } else {
        header["jwk"] = build_p256_jwk(key_pair.public_key().as_ref());
    }

    let protected = b64.encode(header.to_string().as_bytes());
    let payload_b64 = if payload.is_empty() {
        String::new() // POST-as-GET (RFC 8555 §6.3)
    } else {
        b64.encode(payload.as_bytes())
    };

    let signing_input = format!("{protected}.{payload_b64}");
    let rng = SystemRandom::new();
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|_| AuthError::internal("ACME JWS signing failed"))?;

    Ok(serde_json::json!({
        "protected": protected,
        "payload": payload_b64,
        "signature": b64.encode(signature.as_ref()),
    }))
}

// ── ACME Client ─────────────────────────────────────────────────────

/// ACME protocol client for automated certificate management.
pub struct AcmeClient {
    config: AcmeConfig,
    http: reqwest::Client,
    key_pair: EcdsaKeyPair,
    directory: AcmeDirectory,
    account_url: Arc<RwLock<Option<String>>>,
    nonce: Arc<RwLock<Option<String>>>,
}

impl AcmeClient {
    /// Create a new ACME client and fetch the directory.
    pub async fn new(config: AcmeConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| AuthError::internal(format!("HTTP client init failed: {e}")))?;

        // Generate ECDSA P-256 key pair for account operations
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| AuthError::internal("Failed to generate ACME account key"))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|_| AuthError::internal("Failed to parse generated PKCS#8 key"))?;

        // Fetch the ACME directory
        let resp = http
            .get(&config.directory_url)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("ACME directory fetch failed: {e}")))?;

        let directory: AcmeDirectory = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Invalid ACME directory response: {e}")))?;

        Ok(Self {
            config,
            http,
            key_pair,
            directory,
            account_url: Arc::new(RwLock::new(None)),
            nonce: Arc::new(RwLock::new(None)),
        })
    }

    /// Create an ACME client from an existing key pair and directory (for testing).
    pub fn from_parts(
        config: AcmeConfig,
        key_pair: EcdsaKeyPair,
        directory: AcmeDirectory,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
            key_pair,
            directory,
            account_url: Arc::new(RwLock::new(None)),
            nonce: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the ACME directory resource.
    pub fn directory(&self) -> &AcmeDirectory {
        &self.directory
    }

    /// Fetch a fresh anti-replay nonce from the ACME server.
    async fn fetch_nonce(&self) -> Result<String> {
        let resp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("Nonce fetch failed: {e}")))?;

        let nonce = resp
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AuthError::internal("ACME server did not return Replay-Nonce header"))?
            .to_string();

        *self.nonce.write().await = Some(nonce.clone());
        Ok(nonce)
    }

    /// Get the current nonce, fetching a new one if needed.
    async fn get_nonce(&self) -> Result<String> {
        let current = self.nonce.read().await.clone();
        match current {
            Some(n) => {
                // Consume the nonce (single-use)
                *self.nonce.write().await = None;
                Ok(n)
            }
            None => self.fetch_nonce().await,
        }
    }

    /// Make a signed ACME POST request.
    async fn signed_request(&self, url: &str, payload: &str) -> Result<reqwest::Response> {
        let nonce = self.get_nonce().await?;
        let kid = self.account_url.read().await.clone();
        let jws = create_jws(&self.key_pair, url, &nonce, payload, kid.as_deref())?;

        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&jws)
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("ACME request failed: {e}")))?;

        // Capture the new nonce from the response
        if let Some(new_nonce) = resp
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
        {
            *self.nonce.write().await = Some(new_nonce.to_string());
        }

        Ok(resp)
    }

    /// Register a new ACME account (RFC 8555 §7.3).
    pub async fn register_account(&self) -> Result<AcmeAccount> {
        let contacts: Vec<String> = self
            .config
            .contact_emails
            .iter()
            .map(|e| format!("mailto:{e}"))
            .collect();

        let payload = serde_json::json!({
            "termsOfServiceAgreed": self.config.agree_to_tos,
            "contact": contacts,
        });

        let resp = self
            .signed_request(&self.directory.new_account, &payload.to_string())
            .await?;

        // Store the account URL from the Location header
        if let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
            *self.account_url.write().await = Some(location.to_string());
        }

        let account: AcmeAccount = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Invalid account response: {e}")))?;

        Ok(account)
    }

    /// Create a new certificate order (RFC 8555 §7.4).
    pub async fn create_order(&self, domains: &[&str]) -> Result<AcmeOrder> {
        if domains.is_empty() {
            return Err(AuthError::validation(
                "At least one domain is required for an ACME order",
            ));
        }

        let identifiers: Vec<AcmeIdentifier> = domains
            .iter()
            .map(|d| AcmeIdentifier {
                id_type: "dns".to_string(),
                value: d.to_string(),
            })
            .collect();

        let payload = serde_json::json!({
            "identifiers": identifiers,
        });

        let resp = self
            .signed_request(&self.directory.new_order, &payload.to_string())
            .await?;

        let order: AcmeOrder = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Invalid order response: {e}")))?;

        Ok(order)
    }

    /// Fetch an authorization resource (RFC 8555 §7.5).
    pub async fn get_authorization(&self, authz_url: &str) -> Result<AcmeAuthorization> {
        let resp = self.signed_request(authz_url, "").await?;
        let authz: AcmeAuthorization = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Invalid authorization response: {e}")))?;
        Ok(authz)
    }

    /// Compute the key authorization string for a challenge (RFC 8555 §8.1).
    ///
    /// `key_authorization = token || '.' || base64url(JWK_Thumbprint)`
    pub fn key_authorization(&self, token: &str) -> String {
        let thumbprint = jwk_thumbprint_p256(self.key_pair.public_key().as_ref());
        format!("{token}.{thumbprint}")
    }

    /// Compute the DNS-01 challenge record value (RFC 8555 §8.4).
    ///
    /// Returns the base64url-encoded SHA-256 of the key authorization.
    pub fn dns01_record_value(&self, token: &str) -> String {
        let key_authz = self.key_authorization(token);
        let digest = Sha256::digest(key_authz.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Respond to a challenge to begin validation (RFC 8555 §7.5.1).
    pub async fn respond_to_challenge(&self, challenge_url: &str) -> Result<AcmeChallenge> {
        let resp = self.signed_request(challenge_url, "{}").await?;
        let challenge: AcmeChallenge = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Challenge response error: {e}")))?;
        Ok(challenge)
    }

    /// Finalize an order by submitting a CSR (RFC 8555 §7.4).
    pub async fn finalize_order(&self, finalize_url: &str, csr_der: &[u8]) -> Result<AcmeOrder> {
        let csr_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(csr_der);
        let payload = serde_json::json!({
            "csr": csr_b64,
        });

        let resp = self
            .signed_request(finalize_url, &payload.to_string())
            .await?;

        let order: AcmeOrder = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Finalize response error: {e}")))?;

        Ok(order)
    }

    /// Download the issued certificate chain (RFC 8555 §7.4.2).
    pub async fn download_certificate(&self, cert_url: &str) -> Result<String> {
        let resp = self.signed_request(cert_url, "").await?;
        let pem = resp
            .text()
            .await
            .map_err(|e| AuthError::internal(format!("Certificate download error: {e}")))?;
        Ok(pem)
    }

    /// Get the JWK thumbprint of the account key.
    pub fn account_thumbprint(&self) -> String {
        jwk_thumbprint_p256(self.key_pair.public_key().as_ref())
    }

    /// Revoke a certificate (RFC 8555 §7.6).
    ///
    /// The `cert_der` must be the DER-encoded end-entity certificate.
    /// `reason` is an optional RFC 5280 CRLReason code (0–10).
    pub async fn revoke_certificate(&self, cert_der: &[u8], reason: Option<u8>) -> Result<()> {
        let revoke_url =
            self.directory.revoke_cert.as_ref().ok_or_else(|| {
                AuthError::config("ACME directory does not provide a revokeCert URL")
            })?;

        let cert_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload = serde_json::json!({
            "certificate": cert_b64,
        });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }

        let resp = self
            .signed_request(revoke_url, &payload.to_string())
            .await?;
        let status = resp.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(AuthError::internal(format!(
                "Certificate revocation failed (HTTP {status}): {body}"
            )))
        }
    }
}

// ── Certificate Renewal Tracker ─────────────────────────────────────

/// Tracks certificate expiry and manages renewal scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Domains covered by this certificate.
    pub domains: Vec<String>,
    /// PEM-encoded certificate chain.
    pub pem_chain: String,
    /// When the certificate was issued (UNIX timestamp).
    pub issued_at: u64,
    /// When the certificate expires (UNIX timestamp).
    pub expires_at: u64,
    /// When renewal should be attempted (UNIX timestamp).
    /// Typically 30 days before expiry for 90-day Let's Encrypt certs.
    pub renew_at: u64,
    /// ACME order finalize URL (for reference in logs/debugging).
    pub order_url: Option<String>,
}

impl CertificateRecord {
    /// Create a new certificate record.
    ///
    /// `renew_before_secs` is how many seconds before expiry to schedule renewal
    /// (default: 30 days = 2_592_000 seconds).
    pub fn new(
        domains: Vec<String>,
        pem_chain: String,
        issued_at: u64,
        expires_at: u64,
        renew_before_secs: u64,
    ) -> Self {
        let renew_at = expires_at.saturating_sub(renew_before_secs);
        Self {
            domains,
            pem_chain,
            issued_at,
            expires_at,
            renew_at,
            order_url: None,
        }
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if it's time to schedule a renewal.
    pub fn needs_renewal(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.renew_at
    }

    /// Remaining time until expiry (seconds), or 0 if already expired.
    pub fn remaining_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at.saturating_sub(now)
    }
}

/// In-memory tracker for certificate lifecycle management.
///
/// Stores issued certificates and provides methods to identify which
/// certificates need renewal or have expired.
pub struct CertificateTracker {
    records: Arc<RwLock<HashMap<String, CertificateRecord>>>,
    /// Default renewal window in seconds (how long before expiry to renew).
    renew_before_secs: u64,
}

impl CertificateTracker {
    /// Create a new tracker with a default 30-day renewal window.
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            renew_before_secs: 30 * 24 * 3600, // 30 days
        }
    }

    /// Create a tracker with a custom renewal window.
    pub fn with_renew_window(renew_before_secs: u64) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            renew_before_secs,
        }
    }

    /// Store a certificate record. The key is the primary domain name.
    pub async fn track(
        &self,
        domains: Vec<String>,
        pem_chain: String,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        let key = domains.first().cloned().unwrap_or_default();
        let record = CertificateRecord::new(
            domains,
            pem_chain,
            issued_at,
            expires_at,
            self.renew_before_secs,
        );
        self.records.write().await.insert(key.clone(), record);
        key
    }

    /// Get a certificate record by primary domain.
    pub async fn get(&self, domain: &str) -> Option<CertificateRecord> {
        self.records.read().await.get(domain).cloned()
    }

    /// List all domains that need renewal.
    pub async fn due_for_renewal(&self) -> Vec<String> {
        self.records
            .read()
            .await
            .iter()
            .filter(|(_, r)| r.needs_renewal())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// List all domains with expired certificates.
    pub async fn expired(&self) -> Vec<String> {
        self.records
            .read()
            .await
            .iter()
            .filter(|(_, r)| r.is_expired())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Remove expired certificate records.
    pub async fn remove_expired(&self) -> usize {
        let mut records = self.records.write().await;
        let before = records.len();
        records.retain(|_, r| !r.is_expired());
        before - records.len()
    }

    /// Remove a specific record.
    pub async fn remove(&self, domain: &str) -> bool {
        self.records.write().await.remove(domain).is_some()
    }

    /// Count of tracked certificates.
    pub async fn count(&self) -> usize {
        self.records.read().await.len()
    }
}

impl Default for CertificateTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Pending challenge tracker ───────────────────────────────────────

/// Tracks pending ACME challenges for HTTP-01 validation.
///
/// Stores token → key_authorization mappings so the HTTP server can
/// respond to `/.well-known/acme-challenge/{token}` requests.
#[derive(Debug, Clone, Default)]
pub struct Http01ChallengeStore {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl Http01ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a challenge token with its key authorization.
    pub async fn add(&self, token: String, key_authorization: String) {
        self.challenges
            .write()
            .await
            .insert(token, key_authorization);
    }

    /// Look up a key authorization by token.
    pub async fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().await.get(token).cloned()
    }

    /// Remove a completed challenge.
    pub async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
    }

    /// Count of pending challenges.
    pub async fn count(&self) -> usize {
        self.challenges.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config defaults ─────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let config = AcmeConfig::default();
        assert!(config.directory_url.contains("staging"));
        assert!(!config.agree_to_tos);
        assert!(config.contact_emails.is_empty());
        assert_eq!(config.timeout_secs, 30);
    }

    // ── JWK Thumbprint ──────────────────────────────────────────

    #[test]
    fn test_jwk_thumbprint_p256_format() {
        // Create a synthetic 65-byte uncompressed P-256 point
        let mut key = vec![0x04];
        key.extend_from_slice(&[0xAA; 32]); // x
        key.extend_from_slice(&[0xBB; 32]); // y

        let thumbprint = jwk_thumbprint_p256(&key);
        assert!(!thumbprint.is_empty());

        // Thumbprint should be a base64url-encoded SHA-256 (43 chars)
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let mut key = vec![0x04];
        key.extend_from_slice(&[0x11; 32]);
        key.extend_from_slice(&[0x22; 32]);

        let t1 = jwk_thumbprint_p256(&key);
        let t2 = jwk_thumbprint_p256(&key);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_jwk_thumbprint_different_keys() {
        let mut k1 = vec![0x04];
        k1.extend_from_slice(&[0x01; 32]);
        k1.extend_from_slice(&[0x02; 32]);

        let mut k2 = vec![0x04];
        k2.extend_from_slice(&[0x03; 32]);
        k2.extend_from_slice(&[0x04; 32]);

        assert_ne!(jwk_thumbprint_p256(&k1), jwk_thumbprint_p256(&k2));
    }

    #[test]
    fn test_jwk_thumbprint_invalid_key() {
        assert_eq!(jwk_thumbprint_p256(&[0x00; 10]), "");
        assert_eq!(jwk_thumbprint_p256(&[]), "");
    }

    // ── JWK Builder ─────────────────────────────────────────────

    #[test]
    fn test_build_p256_jwk() {
        let mut key = vec![0x04];
        key.extend_from_slice(&[0xCC; 32]);
        key.extend_from_slice(&[0xDD; 32]);

        let jwk = build_p256_jwk(&key);
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].as_str().is_some());
        assert!(jwk["y"].as_str().is_some());
    }

    #[test]
    fn test_build_p256_jwk_invalid() {
        let jwk = build_p256_jwk(&[0x00; 10]);
        assert!(jwk.as_object().unwrap().is_empty());
    }

    // ── JWS Creation ────────────────────────────────────────────

    #[test]
    fn test_create_jws_with_jwk() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let jws = create_jws(&kp, "https://example.com/new-acct", "nonce1", "{}", None).unwrap();
        assert!(jws.get("protected").is_some());
        assert!(jws.get("payload").is_some());
        assert!(jws.get("signature").is_some());
    }

    #[test]
    fn test_create_jws_with_kid() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let jws = create_jws(
            &kp,
            "https://example.com/order",
            "nonce2",
            "{}",
            Some("https://example.com/acct/1"),
        )
        .unwrap();

        // Decode the protected header to verify kid is present
        let protected = jws["protected"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(header["kid"], "https://example.com/acct/1");
        assert!(header.get("jwk").is_none());
    }

    #[test]
    fn test_create_jws_post_as_get() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let jws = create_jws(&kp, "https://example.com/authz", "nonce3", "", None).unwrap();
        // POST-as-GET: empty payload
        assert_eq!(jws["payload"].as_str().unwrap(), "");
    }

    // ── Key Authorization ───────────────────────────────────────

    #[test]
    fn test_key_authorization_format() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let dir = AcmeDirectory {
            new_nonce: String::new(),
            new_account: String::new(),
            new_order: String::new(),
            new_authz: None,
            revoke_cert: None,
            key_change: None,
            meta: None,
        };

        let client = AcmeClient::from_parts(AcmeConfig::default(), kp, dir);
        let key_authz = client.key_authorization("test-token");
        assert!(key_authz.starts_with("test-token."));
        assert!(key_authz.len() > 20); // token + '.' + thumbprint
    }

    #[test]
    fn test_dns01_record_value() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let dir = AcmeDirectory {
            new_nonce: String::new(),
            new_account: String::new(),
            new_order: String::new(),
            new_authz: None,
            revoke_cert: None,
            key_change: None,
            meta: None,
        };

        let client = AcmeClient::from_parts(AcmeConfig::default(), kp, dir);
        let value = client.dns01_record_value("dns-token");
        // Should be base64url-encoded SHA-256 = 43 chars
        assert_eq!(value.len(), 43);
    }

    // ── HTTP-01 Challenge Store ─────────────────────────────────

    #[tokio::test]
    async fn test_http01_challenge_store() {
        let store = Http01ChallengeStore::new();
        assert_eq!(store.count().await, 0);

        store.add("token1".to_string(), "authz1".to_string()).await;
        store.add("token2".to_string(), "authz2".to_string()).await;
        assert_eq!(store.count().await, 2);

        assert_eq!(store.get("token1").await, Some("authz1".to_string()));
        assert_eq!(store.get("token2").await, Some("authz2".to_string()));
        assert_eq!(store.get("missing").await, None);

        store.remove("token1").await;
        assert_eq!(store.count().await, 1);
        assert_eq!(store.get("token1").await, None);
    }

    // ── Data model serialization ────────────────────────────────

    #[test]
    fn test_order_status_serialization() {
        assert_eq!(
            serde_json::to_string(&OrderStatus::Pending).unwrap(),
            r#""pending""#
        );
        assert_eq!(
            serde_json::to_string(&OrderStatus::Ready).unwrap(),
            r#""ready""#
        );
    }

    #[test]
    fn test_challenge_type_serialization() {
        assert_eq!(
            serde_json::to_string(&ChallengeType::Http01).unwrap(),
            r#""http-01""#
        );
        assert_eq!(
            serde_json::to_string(&ChallengeType::Dns01).unwrap(),
            r#""dns-01""#
        );
    }

    #[test]
    fn test_acme_identifier() {
        let id = AcmeIdentifier {
            id_type: "dns".to_string(),
            value: "example.com".to_string(),
        };
        let json = serde_json::to_value(&id).unwrap();
        assert_eq!(json["type"], "dns");
        assert_eq!(json["value"], "example.com");
    }

    #[test]
    fn test_acme_directory_deserialization() {
        let json = r#"{
            "newNonce": "https://acme.example/nonce",
            "newAccount": "https://acme.example/account",
            "newOrder": "https://acme.example/order",
            "revokeCert": "https://acme.example/revoke",
            "meta": {
                "termsOfService": "https://acme.example/tos",
                "externalAccountRequired": false
            }
        }"#;
        let dir: AcmeDirectory = serde_json::from_str(json).unwrap();
        assert_eq!(dir.new_nonce, "https://acme.example/nonce");
        assert_eq!(dir.new_account, "https://acme.example/account");
        assert!(dir.meta.is_some());
        assert!(!dir.meta.unwrap().external_account_required);
    }

    #[test]
    fn test_acme_authorization_deserialization() {
        let json = r#"{
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "challenges": [
                {
                    "type": "http-01",
                    "url": "https://acme.example/chall/1",
                    "status": "pending",
                    "token": "abc123"
                }
            ]
        }"#;
        let authz: AcmeAuthorization = serde_json::from_str(json).unwrap();
        assert_eq!(authz.status, AuthorizationStatus::Pending);
        assert_eq!(authz.challenges.len(), 1);
        assert_eq!(authz.challenges[0].challenge_type, ChallengeType::Http01);
        assert_eq!(authz.challenges[0].token, "abc123");
    }

    #[test]
    fn test_account_thumbprint() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

        let dir = AcmeDirectory {
            new_nonce: String::new(),
            new_account: String::new(),
            new_order: String::new(),
            new_authz: None,
            revoke_cert: None,
            key_change: None,
            meta: None,
        };

        let client = AcmeClient::from_parts(AcmeConfig::default(), kp, dir);
        let tp = client.account_thumbprint();
        assert_eq!(tp.len(), 43);

        // Must be deterministic
        assert_eq!(tp, client.account_thumbprint());
    }

    // ── Certificate Record ──────────────────────────────────────

    #[test]
    fn test_certificate_record_not_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = CertificateRecord::new(
            vec!["example.com".to_string()],
            "PEM".to_string(),
            now,
            now + 90 * 24 * 3600, // 90 days from now
            30 * 24 * 3600,       // renew 30 days before
        );
        assert!(!record.is_expired());
        assert!(!record.needs_renewal());
        assert!(record.remaining_secs() > 0);
    }

    #[test]
    fn test_certificate_record_expired() {
        let record = CertificateRecord::new(
            vec!["old.com".to_string()],
            "PEM".to_string(),
            1000,
            2000, // expired long ago
            300,
        );
        assert!(record.is_expired());
        assert!(record.needs_renewal());
        assert_eq!(record.remaining_secs(), 0);
    }

    #[test]
    fn test_certificate_record_needs_renewal() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expires in 10 days, renew window is 30 days → needs renewal
        let record = CertificateRecord::new(
            vec!["renew.com".to_string()],
            "PEM".to_string(),
            now - 80 * 24 * 3600,
            now + 10 * 24 * 3600,
            30 * 24 * 3600,
        );
        assert!(!record.is_expired());
        assert!(record.needs_renewal());
    }

    // ── Certificate Tracker ─────────────────────────────────────

    #[tokio::test]
    async fn test_certificate_tracker_track_and_get() {
        let tracker = CertificateTracker::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = tracker
            .track(
                vec!["example.com".to_string()],
                "-----BEGIN CERT-----".to_string(),
                now,
                now + 90 * 24 * 3600,
            )
            .await;
        assert_eq!(key, "example.com");
        assert_eq!(tracker.count().await, 1);

        let record = tracker.get("example.com").await.unwrap();
        assert_eq!(record.domains, vec!["example.com"]);
    }

    #[tokio::test]
    async fn test_certificate_tracker_due_for_renewal() {
        let tracker = CertificateTracker::with_renew_window(30 * 24 * 3600);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Cert expiring in 10 days (within 30-day window)
        tracker
            .track(
                vec!["renew-me.com".to_string()],
                "PEM".to_string(),
                now - 80 * 24 * 3600,
                now + 10 * 24 * 3600,
            )
            .await;

        // Cert expiring in 60 days (outside 30-day window)
        tracker
            .track(
                vec!["still-good.com".to_string()],
                "PEM".to_string(),
                now,
                now + 60 * 24 * 3600,
            )
            .await;

        let due = tracker.due_for_renewal().await;
        assert_eq!(due.len(), 1);
        assert!(due.contains(&"renew-me.com".to_string()));
    }

    #[tokio::test]
    async fn test_certificate_tracker_expired() {
        let tracker = CertificateTracker::new();
        tracker
            .track(
                vec!["expired.com".to_string()],
                "PEM".to_string(),
                1000,
                2000,
            )
            .await;
        let expired = tracker.expired().await;
        assert_eq!(expired, vec!["expired.com"]);
    }

    #[tokio::test]
    async fn test_certificate_tracker_remove_expired() {
        let tracker = CertificateTracker::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        tracker
            .track(vec!["old.com".to_string()], "PEM".to_string(), 100, 200)
            .await;
        tracker
            .track(
                vec!["fresh.com".to_string()],
                "PEM".to_string(),
                now,
                now + 9999,
            )
            .await;

        assert_eq!(tracker.count().await, 2);
        let removed = tracker.remove_expired().await;
        assert_eq!(removed, 1);
        assert_eq!(tracker.count().await, 1);
        assert!(tracker.get("fresh.com").await.is_some());
    }

    #[tokio::test]
    async fn test_certificate_tracker_remove() {
        let tracker = CertificateTracker::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        tracker
            .track(
                vec!["rm.com".to_string()],
                "PEM".to_string(),
                now,
                now + 9999,
            )
            .await;
        assert!(tracker.remove("rm.com").await);
        assert!(!tracker.remove("rm.com").await);
        assert_eq!(tracker.count().await, 0);
    }
}
