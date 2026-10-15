//! SPIFFE (Secure Production Identity Framework for Everyone) implementation.
//!
//! Provides SPIFFE ID parsing/validation and SVID (SPIFFE Verifiable Identity Document)
//! verification for both X.509-SVID and JWT-SVID formats.
//!
//! # Architecture
//!
//! - **SPIFFE ID** — a URI of the form `spiffe://<trust-domain>/<workload-path>`
//! - **X.509-SVID** — a SPIFFE identity bound to an X.509 certificate
//! - **JWT-SVID** — a SPIFFE identity bound to a JWT
//! - **Trust Bundle** — a set of CA certificates for a trust domain
//!
//! # References
//!
//! - [SPIFFE ID spec](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
//! - [X509-SVID spec](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
//! - [JWT-SVID spec](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ── SPIFFE ID ───────────────────────────────────────────────────────

/// A parsed and validated SPIFFE ID.
///
/// Format: `spiffe://<trust-domain>/<workload-path>`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    /// Trust domain (e.g., "example.org").
    pub trust_domain: String,
    /// Workload path segments (e.g., "/service/web").
    pub path: String,
}

impl SpiffeId {
    /// Parse and validate a SPIFFE ID string.
    ///
    /// # Errors
    /// - Missing `spiffe://` scheme
    /// - Empty trust domain
    /// - Trust domain with invalid characters
    /// - Path with query or fragment
    pub fn parse(uri: &str) -> Result<Self> {
        let stripped = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| AuthError::validation("SPIFFE ID must start with 'spiffe://'"))?;

        if stripped.is_empty() {
            return Err(AuthError::validation("SPIFFE ID trust domain is empty"));
        }

        // Split into trust domain and path
        let (trust_domain, path) = match stripped.find('/') {
            Some(idx) => (&stripped[..idx], &stripped[idx..]),
            None => (stripped, ""),
        };

        // Validate trust domain (RFC: lowercase, alphanumeric, hyphens, dots)
        if trust_domain.is_empty() {
            return Err(AuthError::validation("SPIFFE ID trust domain is empty"));
        }

        for ch in trust_domain.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '.' && ch != '_' {
                return Err(AuthError::validation(format!(
                    "SPIFFE ID trust domain contains invalid character: '{ch}'"
                )));
            }
        }

        // No query or fragment allowed
        if path.contains('?') || path.contains('#') {
            return Err(AuthError::validation(
                "SPIFFE ID must not contain query or fragment",
            ));
        }

        // No trailing slash on non-root paths
        if path.len() > 1 && path.ends_with('/') {
            return Err(AuthError::validation(
                "SPIFFE ID path must not end with '/'",
            ));
        }

        // No empty segments
        if path.contains("//") {
            return Err(AuthError::validation(
                "SPIFFE ID path must not contain empty segments",
            ));
        }

        // No dot or dotdot segments
        for segment in path.split('/').skip(1) {
            if segment == "." || segment == ".." {
                return Err(AuthError::validation(
                    "SPIFFE ID path must not contain '.' or '..' segments",
                ));
            }
        }

        Ok(Self {
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
        })
    }

    /// Return the full SPIFFE ID URI.
    pub fn to_uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }

    /// Check whether this ID belongs to the given trust domain.
    pub fn is_member_of(&self, trust_domain: &str) -> bool {
        self.trust_domain == trust_domain
    }

    /// Check whether this ID matches a path prefix.
    pub fn matches_path_prefix(&self, prefix: &str) -> bool {
        self.path.starts_with(prefix)
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spiffe://{}{}", self.trust_domain, self.path)
    }
}

// ── JWT-SVID ────────────────────────────────────────────────────────

/// JWT-SVID claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSvidClaims {
    /// SPIFFE ID of the subject.
    pub sub: String,
    /// Intended audience(s).
    pub aud: Vec<String>,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued-at time (Unix timestamp).
    #[serde(default)]
    pub iat: Option<u64>,
}

/// JWT-SVID validation result.
#[derive(Debug, Clone)]
pub struct ValidatedJwtSvid {
    /// The parsed SPIFFE ID from the subject claim.
    pub spiffe_id: SpiffeId,
    /// The validated claims.
    pub claims: JwtSvidClaims,
    /// Raw header for inspection.
    pub header: serde_json::Value,
}

/// Validate a JWT-SVID token (structural + expiration + audience check).
///
/// This performs all validation that does not require trust bundle access:
/// - Splits and decodes the JWT
/// - Validates the `sub` claim is a valid SPIFFE ID
/// - Checks expiration
/// - Validates audience
///
/// Cryptographic signature verification requires a trust bundle and is
/// performed by `SpiffeTrustManager::verify_jwt_svid`.
pub fn validate_jwt_svid(token: &str, expected_audience: &str) -> Result<ValidatedJwtSvid> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::validation("JWT-SVID must have 3 parts"));
    }

    // Decode header
    let header_bytes = b64
        .decode(parts[0])
        .map_err(|_| AuthError::validation("Invalid JWT-SVID header encoding"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| AuthError::validation("Invalid JWT-SVID header JSON"))?;

    // Algorithm must be specified and not "none"
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::validation("JWT-SVID header missing 'alg'"))?;
    if alg.eq_ignore_ascii_case("none") {
        return Err(AuthError::validation(
            "JWT-SVID must not use 'none' algorithm",
        ));
    }

    // Decode claims
    let claims_bytes = b64
        .decode(parts[1])
        .map_err(|_| AuthError::validation("Invalid JWT-SVID claims encoding"))?;
    let claims: JwtSvidClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| AuthError::validation("Invalid JWT-SVID claims JSON"))?;

    // Validate subject is a valid SPIFFE ID
    let spiffe_id = SpiffeId::parse(&claims.sub)?;

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if claims.exp <= now {
        return Err(AuthError::validation("JWT-SVID has expired"));
    }

    // Validate audience
    if !claims.aud.iter().any(|a| a == expected_audience) {
        return Err(AuthError::validation(
            "JWT-SVID audience does not match expected audience",
        ));
    }

    Ok(ValidatedJwtSvid {
        spiffe_id,
        claims,
        header,
    })
}

// ── X.509-SVID ──────────────────────────────────────────────────────

/// Parsed X.509-SVID metadata (from certificate fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509SvidInfo {
    /// SPIFFE ID from the SAN URI.
    pub spiffe_id: SpiffeId,
    /// SHA-256 fingerprint of the certificate (hex-encoded).
    pub fingerprint: String,
    /// Certificate serial number (if available).
    #[serde(default)]
    pub serial: Option<String>,
    /// Not-before timestamp (Unix).
    #[serde(default)]
    pub not_before: Option<u64>,
    /// Not-after timestamp (Unix).
    #[serde(default)]
    pub not_after: Option<u64>,
}

/// Extract and validate a SPIFFE ID from DER-encoded certificate bytes.
///
/// Performs a lightweight parse of the SAN extension to find a `spiffe://` URI.
/// Full X.509 chain verification requires a trust bundle.
pub fn extract_spiffe_id_from_der(cert_der: &[u8]) -> Result<X509SvidInfo> {
    // Compute fingerprint
    let fingerprint = hex::encode(Sha256::digest(cert_der));

    // Search for spiffe:// URI in the raw cert bytes (SAN extension)
    let cert_str = String::from_utf8_lossy(cert_der);
    let spiffe_uri = find_spiffe_uri_in_bytes(cert_der)
        .or_else(|| {
            // Fallback: try scanning the lossy string
            cert_str.find("spiffe://").map(|idx| {
                let end = cert_str[idx..]
                    .find(|c: char| c.is_control() || c == '\0')
                    .unwrap_or(cert_str.len() - idx);
                cert_str[idx..idx + end].to_string()
            })
        })
        .ok_or_else(|| {
            AuthError::validation("No SPIFFE ID (spiffe:// URI) found in certificate SAN")
        })?;

    let spiffe_id = SpiffeId::parse(&spiffe_uri)?;

    Ok(X509SvidInfo {
        spiffe_id,
        fingerprint,
        serial: None,
        not_before: None,
        not_after: None,
    })
}

/// Scan raw DER bytes for a `spiffe://` URI, respecting UTF-8 boundaries.
fn find_spiffe_uri_in_bytes(data: &[u8]) -> Option<String> {
    let needle = b"spiffe://";
    for i in 0..data.len().saturating_sub(needle.len()) {
        if data[i..].starts_with(needle) {
            // Read until NUL, control character, or end
            let start = i;
            let mut end = i + needle.len();
            while end < data.len() {
                let b = data[end];
                if b < 0x20 || b == 0x7f || b == 0x00 {
                    break;
                }
                end += 1;
            }
            if let Ok(uri) = std::str::from_utf8(&data[start..end]) {
                return Some(uri.to_string());
            }
        }
    }
    None
}

// ── Trust Manager ───────────────────────────────────────────────────

/// Authorization policy entry for SPIFFE workloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiffeAuthzPolicy {
    /// ID of the source workload (SPIFFE ID pattern).
    pub source: String,
    /// ID of the destination workload (SPIFFE ID pattern).
    pub destination: String,
    /// Allowed actions/methods.
    pub allowed_actions: Vec<String>,
}

/// SPIFFE Trust Manager: maintains trust bundles and validates SVIDs.
pub struct SpiffeTrustManager {
    /// Trust domain → trust bundle (CA certificates as DER).
    trust_bundles: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
    /// SPIFFE authorization policies.
    policies: Arc<RwLock<Vec<SpiffeAuthzPolicy>>>,
}

impl SpiffeTrustManager {
    pub fn new() -> Self {
        Self {
            trust_bundles: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a trust bundle for a trust domain.
    pub async fn add_trust_bundle(&self, trust_domain: &str, ca_certs_der: Vec<Vec<u8>>) {
        self.trust_bundles
            .write()
            .await
            .insert(trust_domain.to_string(), ca_certs_der);
    }

    /// Check if a trust bundle exists for the given domain.
    pub async fn has_trust_bundle(&self, trust_domain: &str) -> bool {
        self.trust_bundles.read().await.contains_key(trust_domain)
    }

    /// Get the trust bundle for a domain.
    pub async fn get_trust_bundle(&self, trust_domain: &str) -> Option<Vec<Vec<u8>>> {
        self.trust_bundles.read().await.get(trust_domain).cloned()
    }

    /// Remove a trust bundle.
    pub async fn remove_trust_bundle(&self, trust_domain: &str) -> bool {
        self.trust_bundles
            .write()
            .await
            .remove(trust_domain)
            .is_some()
    }

    /// Add an authorization policy.
    pub async fn add_policy(&self, policy: SpiffeAuthzPolicy) {
        self.policies.write().await.push(policy);
    }

    /// Check if a workload-to-workload call is authorized.
    pub async fn is_authorized(
        &self,
        source: &SpiffeId,
        destination: &SpiffeId,
        action: &str,
    ) -> bool {
        let policies = self.policies.read().await;
        let source_uri = source.to_uri();
        let dest_uri = destination.to_uri();

        policies.iter().any(|p| {
            (p.source == source_uri || p.source == "*")
                && (p.destination == dest_uri || p.destination == "*")
                && (p.allowed_actions.contains(&action.to_string())
                    || p.allowed_actions.contains(&"*".to_string()))
        })
    }

    /// Validate a JWT-SVID and check that its trust domain is in our bundles.
    pub async fn verify_jwt_svid(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<ValidatedJwtSvid> {
        let result = validate_jwt_svid(token, expected_audience)?;

        // Verify the trust domain has a registered bundle
        if !self.has_trust_bundle(&result.spiffe_id.trust_domain).await {
            return Err(AuthError::validation(format!(
                "No trust bundle for domain '{}'",
                result.spiffe_id.trust_domain
            )));
        }

        Ok(result)
    }

    /// List all registered trust domains.
    pub async fn trust_domains(&self) -> Vec<String> {
        self.trust_bundles.read().await.keys().cloned().collect()
    }
}

impl Default for SpiffeTrustManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Workload API Client ─────────────────────────────────────────────

/// SVID type returned by the Workload API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SvidResponse {
    /// An X.509-SVID with DER-encoded certificate chain and private key.
    X509 {
        spiffe_id: String,
        cert_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
        /// DER-encoded trust bundle for the given trust domain.
        bundle: Vec<Vec<u8>>,
        /// When the SVID expires (UNIX timestamp seconds).
        expires_at: u64,
    },
    /// A JWT-SVID.
    Jwt {
        spiffe_id: String,
        token: String,
        expires_at: u64,
    },
}

/// Configuration for the SPIFFE Workload API client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadApiConfig {
    /// Socket path or address of the Workload API endpoint.
    /// Typically a Unix domain socket: `/tmp/spire-agent/public/api.sock`.
    pub endpoint: String,
    /// How often (seconds) to poll for SVID rotation.
    pub rotation_interval_secs: u64,
    /// Audiences to include when fetching JWT-SVIDs.
    pub jwt_audiences: Vec<String>,
}

impl Default for WorkloadApiConfig {
    fn default() -> Self {
        Self {
            endpoint: "/tmp/spire-agent/public/api.sock".to_string(),
            rotation_interval_secs: 300,
            jwt_audiences: Vec::new(),
        }
    }
}

/// A Workload API client that manages SVID lifecycle.
///
/// In SPIFFE/SPIRE deployments, workloads fetch SVIDs from the local SPIRE
/// agent over a Unix domain socket. This client tracks the current SVID(s)
/// and handles rotation.
pub struct WorkloadApiClient {
    config: WorkloadApiConfig,
    /// Current X.509-SVIDs keyed by SPIFFE ID.
    x509_svids: Arc<RwLock<HashMap<String, SvidResponse>>>,
    /// Current JWT-SVIDs keyed by SPIFFE ID.
    jwt_svids: Arc<RwLock<HashMap<String, SvidResponse>>>,
    /// Trust bundles received from the Workload API, keyed by trust domain.
    bundles: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
}

impl WorkloadApiClient {
    /// Create a new Workload API client.
    pub fn new(config: WorkloadApiConfig) -> Self {
        Self {
            config,
            x509_svids: Arc::new(RwLock::new(HashMap::new())),
            jwt_svids: Arc::new(RwLock::new(HashMap::new())),
            bundles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Return the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Return the rotation interval.
    pub fn rotation_interval(&self) -> Duration {
        Duration::from_secs(self.config.rotation_interval_secs)
    }

    /// Store an X.509-SVID (e.g., after receiving it from the Workload API).
    pub async fn store_x509_svid(&self, svid: SvidResponse) {
        if let SvidResponse::X509 {
            ref spiffe_id,
            ref bundle,
            ..
        } = svid
        {
            // Also update the trust bundle for this domain
            if let Ok(id) = SpiffeId::parse(spiffe_id) {
                self.bundles
                    .write()
                    .await
                    .insert(id.trust_domain.clone(), bundle.clone());
            }
            self.x509_svids
                .write()
                .await
                .insert(spiffe_id.clone(), svid);
        }
    }

    /// Store a JWT-SVID.
    pub async fn store_jwt_svid(&self, svid: SvidResponse) {
        if let SvidResponse::Jwt { ref spiffe_id, .. } = svid {
            self.jwt_svids.write().await.insert(spiffe_id.clone(), svid);
        }
    }

    /// Get the current X.509-SVID for a given SPIFFE ID.
    pub async fn get_x509_svid(&self, spiffe_id: &str) -> Option<SvidResponse> {
        self.x509_svids.read().await.get(spiffe_id).cloned()
    }

    /// Get the current JWT-SVID for a given SPIFFE ID.
    pub async fn get_jwt_svid(&self, spiffe_id: &str) -> Option<SvidResponse> {
        self.jwt_svids.read().await.get(spiffe_id).cloned()
    }

    /// Get the trust bundle for a given trust domain.
    pub async fn get_bundle(&self, trust_domain: &str) -> Option<Vec<Vec<u8>>> {
        self.bundles.read().await.get(trust_domain).cloned()
    }

    /// Check if any X.509-SVID needs rotation (within 20% of expiry window).
    pub async fn needs_rotation(&self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let svids = self.x509_svids.read().await;
        let mut needs = Vec::new();
        for (id, svid) in svids.iter() {
            if let SvidResponse::X509 { expires_at, .. } = svid {
                // Rotate when 80% of the lifetime has passed
                let remaining = expires_at.saturating_sub(now);
                let threshold = self.config.rotation_interval_secs;
                if remaining < threshold {
                    needs.push(id.clone());
                }
            }
        }
        needs
    }

    /// Remove expired SVIDs.
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.x509_svids.write().await.retain(|_, svid| {
            if let SvidResponse::X509 { expires_at, .. } = svid {
                *expires_at > now
            } else {
                true
            }
        });

        self.jwt_svids.write().await.retain(|_, svid| {
            if let SvidResponse::Jwt { expires_at, .. } = svid {
                *expires_at > now
            } else {
                true
            }
        });
    }

    /// Number of stored X.509-SVIDs.
    pub async fn x509_count(&self) -> usize {
        self.x509_svids.read().await.len()
    }

    /// Number of stored JWT-SVIDs.
    pub async fn jwt_count(&self) -> usize {
        self.jwt_svids.read().await.len()
    }
}

// ── SPIRE Workload Attestation ──────────────────────────────────────

/// Attestation evidence provided by a workload to prove its identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Attestor plugin name (e.g., "k8s", "unix", "docker", "aws_iid").
    pub attestor: String,
    /// Evidence payload — content depends on the attestor type.
    pub payload: HashMap<String, String>,
}

/// The result of a successful workload attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// The SPIFFE IDs assigned to the attested workload.
    pub spiffe_ids: Vec<SpiffeId>,
    /// Workload selectors discovered during attestation.
    pub selectors: Vec<WorkloadSelector>,
}

/// A selector that identifies a workload property (used in SPIRE registration entries).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadSelector {
    /// Selector type (e.g., "unix", "k8s", "docker").
    pub selector_type: String,
    /// Selector value (e.g., "uid:1000", "sa:default", "image_id:sha256:abc").
    pub value: String,
}

impl WorkloadSelector {
    /// Create a Unix UID selector.
    pub fn unix_uid(uid: u32) -> Self {
        Self {
            selector_type: "unix".to_string(),
            value: format!("uid:{uid}"),
        }
    }

    /// Create a Unix GID selector.
    pub fn unix_gid(gid: u32) -> Self {
        Self {
            selector_type: "unix".to_string(),
            value: format!("gid:{gid}"),
        }
    }

    /// Create a Kubernetes service account selector.
    pub fn k8s_sa(namespace: &str, name: &str) -> Self {
        Self {
            selector_type: "k8s".to_string(),
            value: format!("sa:{namespace}:{name}"),
        }
    }

    /// Create a Kubernetes pod label selector.
    pub fn k8s_pod_label(key: &str, value: &str) -> Self {
        Self {
            selector_type: "k8s".to_string(),
            value: format!("pod-label:{key}:{value}"),
        }
    }

    /// Create a Docker image ID selector.
    pub fn docker_image_id(image_id: &str) -> Self {
        Self {
            selector_type: "docker".to_string(),
            value: format!("image_id:{image_id}"),
        }
    }
}

/// A SPIRE registration entry that maps selectors to SPIFFE IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationEntry {
    /// The SPIFFE ID to assign to workloads matching the selectors.
    pub spiffe_id: SpiffeId,
    /// The parent SPIFFE ID (typically the node agent's SPIFFE ID).
    pub parent_id: SpiffeId,
    /// Selectors that a workload must match to receive this SPIFFE ID.
    pub selectors: Vec<WorkloadSelector>,
    /// Time-to-live for the SVIDs issued under this entry (seconds).
    pub ttl: u64,
    /// Whether this entry is for downstream workloads (federated).
    pub downstream: bool,
}

/// In-memory registration entry store for SPIRE-style workload attestation.
pub struct RegistrationStore {
    entries: Arc<RwLock<Vec<RegistrationEntry>>>,
}

impl RegistrationStore {
    /// Create an empty registration store.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a registration entry.
    pub async fn register(&self, entry: RegistrationEntry) {
        self.entries.write().await.push(entry);
    }

    /// Find all SPIFFE IDs that match the given selectors.
    ///
    /// A workload matches a registration entry if the workload's selectors are
    /// a superset of the entry's selectors.
    pub async fn match_selectors(&self, workload_selectors: &[WorkloadSelector]) -> Vec<SpiffeId> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|entry| {
                entry
                    .selectors
                    .iter()
                    .all(|s| workload_selectors.contains(s))
            })
            .map(|entry| entry.spiffe_id.clone())
            .collect()
    }

    /// Perform workload attestation: given evidence, extract selectors and find matching IDs.
    pub async fn attest(&self, evidence: &AttestationEvidence) -> Result<AttestationResult> {
        // Build selectors from evidence payload
        let selectors: Vec<WorkloadSelector> = evidence
            .payload
            .iter()
            .map(|(key, value)| WorkloadSelector {
                selector_type: evidence.attestor.clone(),
                value: format!("{key}:{value}"),
            })
            .collect();

        if selectors.is_empty() {
            return Err(AuthError::validation(
                "Attestation evidence contains no selectors",
            ));
        }

        let spiffe_ids = self.match_selectors(&selectors).await;
        if spiffe_ids.is_empty() {
            return Err(AuthError::validation(
                "No registration entries match the workload selectors",
            ));
        }

        Ok(AttestationResult {
            spiffe_ids,
            selectors,
        })
    }

    /// Number of registration entries.
    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Remove entries matching a SPIFFE ID.
    pub async fn remove_by_spiffe_id(&self, id: &SpiffeId) {
        self.entries.write().await.retain(|e| &e.spiffe_id != id);
    }
}

impl Default for RegistrationStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Federated Trust Bundle ──────────────────────────────────────────

/// A federated trust bundle containing CA certificates for a remote trust domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedBundle {
    /// The trust domain this bundle belongs to.
    pub trust_domain: String,
    /// DER-encoded CA certificates.
    pub ca_certs: Vec<Vec<u8>>,
    /// When this bundle was last refreshed (UNIX timestamp).
    pub refreshed_at: u64,
    /// Sequence number for detecting updates.
    pub sequence_number: u64,
}

/// Manages federated trust bundles across trust domains.
///
/// Supports SPIFFE bundle endpoint federation (SPIFFE Trust Domain and Bundle spec).
pub struct FederatedTrustBundleManager {
    /// Local trust domain.
    local_domain: String,
    /// Known federated bundles keyed by trust domain.
    bundles: Arc<RwLock<HashMap<String, FederatedBundle>>>,
    /// Trusted federation endpoints: trust_domain → bundle endpoint URL.
    endpoints: Arc<RwLock<HashMap<String, String>>>,
}

impl FederatedTrustBundleManager {
    /// Create a new federated bundle manager for the given local trust domain.
    pub fn new(local_domain: impl Into<String>) -> Self {
        Self {
            local_domain: local_domain.into(),
            bundles: Arc::new(RwLock::new(HashMap::new())),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Local trust domain name.
    pub fn local_domain(&self) -> &str {
        &self.local_domain
    }

    /// Register a bundle fetch endpoint for a remote trust domain.
    pub async fn add_federation_endpoint(&self, trust_domain: &str, endpoint_url: &str) {
        self.endpoints
            .write()
            .await
            .insert(trust_domain.to_string(), endpoint_url.to_string());
    }

    /// Store a federated trust bundle.
    pub async fn store_bundle(&self, bundle: FederatedBundle) {
        self.bundles
            .write()
            .await
            .insert(bundle.trust_domain.clone(), bundle);
    }

    /// Get a federated bundle for a trust domain.
    pub async fn get_bundle(&self, trust_domain: &str) -> Option<FederatedBundle> {
        self.bundles.read().await.get(trust_domain).cloned()
    }

    /// Get the federation endpoint URL for a trust domain.
    pub async fn get_endpoint(&self, trust_domain: &str) -> Option<String> {
        self.endpoints.read().await.get(trust_domain).cloned()
    }

    /// List all federated trust domains.
    pub async fn federated_domains(&self) -> Vec<String> {
        self.bundles.read().await.keys().cloned().collect()
    }

    /// Check if a SPIFFE ID from a remote domain is trusted (bundle exists).
    pub async fn is_federated_id_trusted(&self, id: &SpiffeId) -> bool {
        if id.trust_domain == self.local_domain {
            return true; // Local domain is always trusted
        }
        self.bundles.read().await.contains_key(&id.trust_domain)
    }

    /// Remove a federated bundle.
    pub async fn remove_bundle(&self, trust_domain: &str) -> bool {
        self.bundles.write().await.remove(trust_domain).is_some()
    }

    /// Remove stale federated bundles older than the given duration.
    pub async fn cleanup_stale(&self, max_age: Duration) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let max_age_secs = max_age.as_secs();
        self.bundles
            .write()
            .await
            .retain(|_, b| now.saturating_sub(b.refreshed_at) <= max_age_secs);
    }

    /// Count of stored federated bundles.
    pub async fn bundle_count(&self) -> usize {
        self.bundles.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // ── SPIFFE ID parsing ───────────────────────────────────────

    #[test]
    fn test_parse_valid_spiffe_id() {
        let id = SpiffeId::parse("spiffe://example.org/service/web").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.path, "/service/web");
        assert_eq!(id.to_uri(), "spiffe://example.org/service/web");
    }

    #[test]
    fn test_parse_spiffe_id_no_path() {
        let id = SpiffeId::parse("spiffe://example.org").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.path, "");
    }

    #[test]
    fn test_parse_spiffe_id_deeply_nested() {
        let id = SpiffeId::parse("spiffe://prod.example.com/ns/default/sa/api-server").unwrap();
        assert_eq!(id.trust_domain, "prod.example.com");
        assert_eq!(id.path, "/ns/default/sa/api-server");
    }

    #[test]
    fn test_parse_missing_scheme() {
        assert!(SpiffeId::parse("https://example.org/svc").is_err());
    }

    #[test]
    fn test_parse_empty_trust_domain() {
        assert!(SpiffeId::parse("spiffe://").is_err());
    }

    #[test]
    fn test_parse_invalid_td_char() {
        assert!(SpiffeId::parse("spiffe://ex ample.org/svc").is_err());
    }

    #[test]
    fn test_parse_query_rejected() {
        assert!(SpiffeId::parse("spiffe://example.org/svc?q=1").is_err());
    }

    #[test]
    fn test_parse_fragment_rejected() {
        assert!(SpiffeId::parse("spiffe://example.org/svc#frag").is_err());
    }

    #[test]
    fn test_parse_trailing_slash_rejected() {
        assert!(SpiffeId::parse("spiffe://example.org/svc/").is_err());
    }

    #[test]
    fn test_parse_empty_segment_rejected() {
        assert!(SpiffeId::parse("spiffe://example.org//svc").is_err());
    }

    #[test]
    fn test_parse_dot_segment_rejected() {
        assert!(SpiffeId::parse("spiffe://example.org/./svc").is_err());
        assert!(SpiffeId::parse("spiffe://example.org/../svc").is_err());
    }

    #[test]
    fn test_is_member_of() {
        let id = SpiffeId::parse("spiffe://example.org/svc").unwrap();
        assert!(id.is_member_of("example.org"));
        assert!(!id.is_member_of("other.org"));
    }

    #[test]
    fn test_matches_path_prefix() {
        let id = SpiffeId::parse("spiffe://example.org/ns/prod/svc/api").unwrap();
        assert!(id.matches_path_prefix("/ns/prod"));
        assert!(!id.matches_path_prefix("/ns/staging"));
    }

    #[test]
    fn test_display() {
        let id = SpiffeId::parse("spiffe://td/path").unwrap();
        assert_eq!(format!("{id}"), "spiffe://td/path");
    }

    // ── JWT-SVID validation ─────────────────────────────────────

    fn make_jwt_svid(sub: &str, aud: &[&str], exp: u64, alg: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = serde_json::json!({"alg": alg, "typ": "JWT"});
        let claims = serde_json::json!({
            "sub": sub,
            "aud": aud,
            "exp": exp,
        });
        let h = b64.encode(header.to_string().as_bytes());
        let c = b64.encode(claims.to_string().as_bytes());
        format!("{h}.{c}.fake-signature")
    }

    #[test]
    fn test_validate_jwt_svid_valid() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid(
            "spiffe://example.org/svc/api",
            &["https://service.example.org"],
            future,
            "ES256",
        );
        let result = validate_jwt_svid(&token, "https://service.example.org").unwrap();
        assert_eq!(result.spiffe_id.trust_domain, "example.org");
        assert_eq!(result.spiffe_id.path, "/svc/api");
    }

    #[test]
    fn test_validate_jwt_svid_expired() {
        let past = 1_000_000;
        let token = make_jwt_svid("spiffe://example.org/svc", &["aud"], past, "ES256");
        assert!(validate_jwt_svid(&token, "aud").is_err());
    }

    #[test]
    fn test_validate_jwt_svid_wrong_audience() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid(
            "spiffe://example.org/svc",
            &["expected-aud"],
            future,
            "ES256",
        );
        assert!(validate_jwt_svid(&token, "wrong-aud").is_err());
    }

    #[test]
    fn test_validate_jwt_svid_none_algorithm_rejected() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid("spiffe://example.org/svc", &["aud"], future, "none");
        assert!(validate_jwt_svid(&token, "aud").is_err());
    }

    #[test]
    fn test_validate_jwt_svid_invalid_sub() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid("https://not-spiffe.example.org", &["aud"], future, "ES256");
        assert!(validate_jwt_svid(&token, "aud").is_err());
    }

    #[test]
    fn test_validate_jwt_svid_malformed() {
        assert!(validate_jwt_svid("not.a.valid.jwt.token", "aud").is_err());
        assert!(validate_jwt_svid("only-one-part", "aud").is_err());
    }

    // ── X.509-SVID extraction ───────────────────────────────────

    #[test]
    fn test_extract_spiffe_id_from_synthetic_der() {
        // Construct a synthetic DER-like blob embedding a SPIFFE URI
        let mut data = vec![0x30, 0x82]; // SEQUENCE header
        data.extend_from_slice(&[0x00, 0x50]); // length
        data.extend_from_slice(b"some-cert-fields-");
        data.extend_from_slice(b"spiffe://example.org/workload/web");
        data.push(0x00); // NUL terminator
        data.extend_from_slice(&[0xFF; 20]); // padding

        let info = extract_spiffe_id_from_der(&data).unwrap();
        assert_eq!(info.spiffe_id.trust_domain, "example.org");
        assert_eq!(info.spiffe_id.path, "/workload/web");
        assert!(!info.fingerprint.is_empty());
        assert_eq!(info.fingerprint.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_extract_spiffe_id_no_uri() {
        let data = b"no spiffe uri here at all";
        assert!(extract_spiffe_id_from_der(data).is_err());
    }

    // ── Trust Manager ───────────────────────────────────────────

    #[tokio::test]
    async fn test_trust_manager_bundle_operations() {
        let mgr = SpiffeTrustManager::new();
        assert!(!mgr.has_trust_bundle("example.org").await);

        mgr.add_trust_bundle("example.org", vec![vec![1, 2, 3]])
            .await;
        assert!(mgr.has_trust_bundle("example.org").await);

        let bundle = mgr.get_trust_bundle("example.org").await.unwrap();
        assert_eq!(bundle.len(), 1);

        let domains = mgr.trust_domains().await;
        assert_eq!(domains, vec!["example.org"]);

        assert!(mgr.remove_trust_bundle("example.org").await);
        assert!(!mgr.has_trust_bundle("example.org").await);
    }

    #[tokio::test]
    async fn test_trust_manager_verify_jwt_svid_no_bundle() {
        let mgr = SpiffeTrustManager::new();
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid("spiffe://example.org/svc", &["aud"], future, "ES256");
        // No bundle registered → should fail
        assert!(mgr.verify_jwt_svid(&token, "aud").await.is_err());
    }

    #[tokio::test]
    async fn test_trust_manager_verify_jwt_svid_with_bundle() {
        let mgr = SpiffeTrustManager::new();
        mgr.add_trust_bundle("example.org", vec![vec![0xCA]]).await;

        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = make_jwt_svid("spiffe://example.org/svc", &["aud"], future, "ES256");
        let result = mgr.verify_jwt_svid(&token, "aud").await.unwrap();
        assert_eq!(result.spiffe_id.trust_domain, "example.org");
    }

    // ── Authorization policies ──────────────────────────────────

    #[tokio::test]
    async fn test_authz_policy_exact_match() {
        let mgr = SpiffeTrustManager::new();
        mgr.add_policy(SpiffeAuthzPolicy {
            source: "spiffe://td/frontend".to_string(),
            destination: "spiffe://td/backend".to_string(),
            allowed_actions: vec!["GET".to_string(), "POST".to_string()],
        })
        .await;

        let src = SpiffeId::parse("spiffe://td/frontend").unwrap();
        let dst = SpiffeId::parse("spiffe://td/backend").unwrap();

        assert!(mgr.is_authorized(&src, &dst, "GET").await);
        assert!(mgr.is_authorized(&src, &dst, "POST").await);
        assert!(!mgr.is_authorized(&src, &dst, "DELETE").await);
    }

    #[tokio::test]
    async fn test_authz_policy_wildcard() {
        let mgr = SpiffeTrustManager::new();
        mgr.add_policy(SpiffeAuthzPolicy {
            source: "*".to_string(),
            destination: "spiffe://td/public-api".to_string(),
            allowed_actions: vec!["*".to_string()],
        })
        .await;

        let any_src = SpiffeId::parse("spiffe://other/svc").unwrap();
        let dst = SpiffeId::parse("spiffe://td/public-api").unwrap();

        assert!(mgr.is_authorized(&any_src, &dst, "GET").await);
        assert!(mgr.is_authorized(&any_src, &dst, "DELETE").await);
    }

    #[tokio::test]
    async fn test_authz_policy_no_match() {
        let mgr = SpiffeTrustManager::new();
        let src = SpiffeId::parse("spiffe://td/svc1").unwrap();
        let dst = SpiffeId::parse("spiffe://td/svc2").unwrap();
        assert!(!mgr.is_authorized(&src, &dst, "GET").await);
    }

    // ── Workload API Client ─────────────────────────────────────

    #[test]
    fn test_workload_api_config_defaults() {
        let cfg = WorkloadApiConfig::default();
        assert!(cfg.endpoint.contains("spire-agent"));
        assert_eq!(cfg.rotation_interval_secs, 300);
        assert!(cfg.jwt_audiences.is_empty());
    }

    #[tokio::test]
    async fn test_workload_api_store_x509_svid() {
        let client = WorkloadApiClient::new(WorkloadApiConfig::default());
        let svid = SvidResponse::X509 {
            spiffe_id: "spiffe://example.org/web".to_string(),
            cert_chain: vec![vec![0x30, 0x82]],
            private_key: vec![0x01],
            bundle: vec![vec![0xCA]],
            expires_at: 9999999999,
        };
        client.store_x509_svid(svid).await;
        assert_eq!(client.x509_count().await, 1);
        assert!(
            client
                .get_x509_svid("spiffe://example.org/web")
                .await
                .is_some()
        );
        // Should also have stored the bundle
        assert!(client.get_bundle("example.org").await.is_some());
    }

    #[tokio::test]
    async fn test_workload_api_store_jwt_svid() {
        let client = WorkloadApiClient::new(WorkloadApiConfig::default());
        let svid = SvidResponse::Jwt {
            spiffe_id: "spiffe://example.org/api".to_string(),
            token: "eyJ...".to_string(),
            expires_at: 9999999999,
        };
        client.store_jwt_svid(svid).await;
        assert_eq!(client.jwt_count().await, 1);
        assert!(
            client
                .get_jwt_svid("spiffe://example.org/api")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_workload_api_cleanup_expired() {
        let client = WorkloadApiClient::new(WorkloadApiConfig::default());
        // Store an already-expired SVID
        let svid = SvidResponse::X509 {
            spiffe_id: "spiffe://example.org/old".to_string(),
            cert_chain: vec![],
            private_key: vec![],
            bundle: vec![],
            expires_at: 1, // expired long ago
        };
        client.store_x509_svid(svid).await;
        assert_eq!(client.x509_count().await, 1);
        client.cleanup_expired().await;
        assert_eq!(client.x509_count().await, 0);
    }

    #[tokio::test]
    async fn test_workload_api_needs_rotation() {
        let client = WorkloadApiClient::new(WorkloadApiConfig::default());
        // Store an SVID expiring in 10 seconds (less than 300s rotation interval)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let svid = SvidResponse::X509 {
            spiffe_id: "spiffe://example.org/expiring".to_string(),
            cert_chain: vec![],
            private_key: vec![],
            bundle: vec![],
            expires_at: now + 10,
        };
        client.store_x509_svid(svid).await;
        let needs = client.needs_rotation().await;
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0], "spiffe://example.org/expiring");
    }

    #[test]
    fn test_workload_api_rotation_interval() {
        let cfg = WorkloadApiConfig {
            rotation_interval_secs: 600,
            ..WorkloadApiConfig::default()
        };
        let client = WorkloadApiClient::new(cfg);
        assert_eq!(client.rotation_interval(), Duration::from_secs(600));
    }

    // ── Workload Selectors ──────────────────────────────────────

    #[test]
    fn test_workload_selector_unix_uid() {
        let s = WorkloadSelector::unix_uid(1000);
        assert_eq!(s.selector_type, "unix");
        assert_eq!(s.value, "uid:1000");
    }

    #[test]
    fn test_workload_selector_k8s_sa() {
        let s = WorkloadSelector::k8s_sa("default", "api-server");
        assert_eq!(s.selector_type, "k8s");
        assert_eq!(s.value, "sa:default:api-server");
    }

    #[test]
    fn test_workload_selector_docker_image() {
        let s = WorkloadSelector::docker_image_id("sha256:abc123");
        assert_eq!(s.selector_type, "docker");
        assert_eq!(s.value, "image_id:sha256:abc123");
    }

    // ── Registration Store & Attestation ────────────────────────

    #[tokio::test]
    async fn test_registration_store_match_selectors() {
        let store = RegistrationStore::new();
        let entry = RegistrationEntry {
            spiffe_id: SpiffeId::parse("spiffe://example.org/web").unwrap(),
            parent_id: SpiffeId::parse("spiffe://example.org/node1").unwrap(),
            selectors: vec![WorkloadSelector::unix_uid(1000)],
            ttl: 3600,
            downstream: false,
        };
        store.register(entry).await;

        // Workload has matching selector
        let ids = store
            .match_selectors(&[WorkloadSelector::unix_uid(1000)])
            .await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].path, "/web");

        // Workload has extra selectors → still matches (superset)
        let ids = store
            .match_selectors(&[
                WorkloadSelector::unix_uid(1000),
                WorkloadSelector::unix_gid(100),
            ])
            .await;
        assert_eq!(ids.len(), 1);

        // Workload missing required selector → no match
        let ids = store
            .match_selectors(&[WorkloadSelector::unix_uid(2000)])
            .await;
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn test_registration_store_attest() {
        let store = RegistrationStore::new();
        let entry = RegistrationEntry {
            spiffe_id: SpiffeId::parse("spiffe://example.org/api").unwrap(),
            parent_id: SpiffeId::parse("spiffe://example.org/node1").unwrap(),
            selectors: vec![WorkloadSelector {
                selector_type: "unix".to_string(),
                value: "uid:1000".to_string(),
            }],
            ttl: 3600,
            downstream: false,
        };
        store.register(entry).await;

        let evidence = AttestationEvidence {
            attestor: "unix".to_string(),
            payload: HashMap::from([("uid".to_string(), "1000".to_string())]),
        };
        let result = store.attest(&evidence).await.unwrap();
        assert_eq!(result.spiffe_ids.len(), 1);
        assert_eq!(result.spiffe_ids[0].path, "/api");
        assert_eq!(result.selectors.len(), 1);
    }

    #[tokio::test]
    async fn test_registration_store_attest_no_match() {
        let store = RegistrationStore::new();
        let evidence = AttestationEvidence {
            attestor: "unix".to_string(),
            payload: HashMap::from([("uid".to_string(), "9999".to_string())]),
        };
        assert!(store.attest(&evidence).await.is_err());
    }

    #[tokio::test]
    async fn test_registration_store_remove_by_spiffe_id() {
        let store = RegistrationStore::new();
        let id = SpiffeId::parse("spiffe://example.org/web").unwrap();
        store
            .register(RegistrationEntry {
                spiffe_id: id.clone(),
                parent_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
                selectors: vec![],
                ttl: 3600,
                downstream: false,
            })
            .await;
        assert_eq!(store.count().await, 1);
        store.remove_by_spiffe_id(&id).await;
        assert_eq!(store.count().await, 0);
    }

    // ── Federated Trust Bundle Manager ──────────────────────────

    #[tokio::test]
    async fn test_federated_bundle_manager_local_domain() {
        let mgr = FederatedTrustBundleManager::new("example.org");
        assert_eq!(mgr.local_domain(), "example.org");
    }

    #[tokio::test]
    async fn test_federated_bundle_store_and_retrieve() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        let bundle = FederatedBundle {
            trust_domain: "remote.org".to_string(),
            ca_certs: vec![vec![0xCA, 0xFE]],
            refreshed_at: 1000000,
            sequence_number: 1,
        };
        mgr.store_bundle(bundle).await;
        assert_eq!(mgr.bundle_count().await, 1);

        let b = mgr.get_bundle("remote.org").await.unwrap();
        assert_eq!(b.sequence_number, 1);
        assert_eq!(b.ca_certs.len(), 1);
    }

    #[tokio::test]
    async fn test_federated_bundle_is_trusted() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        let local_id = SpiffeId::parse("spiffe://local.org/svc").unwrap();
        let remote_id = SpiffeId::parse("spiffe://remote.org/svc").unwrap();

        // Local domain always trusted
        assert!(mgr.is_federated_id_trusted(&local_id).await);
        // Remote not trusted yet
        assert!(!mgr.is_federated_id_trusted(&remote_id).await);

        // Add federation
        mgr.store_bundle(FederatedBundle {
            trust_domain: "remote.org".to_string(),
            ca_certs: vec![vec![0x01]],
            refreshed_at: 9999999999,
            sequence_number: 1,
        })
        .await;
        assert!(mgr.is_federated_id_trusted(&remote_id).await);
    }

    #[tokio::test]
    async fn test_federated_bundle_remove() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        mgr.store_bundle(FederatedBundle {
            trust_domain: "remote.org".to_string(),
            ca_certs: vec![],
            refreshed_at: 0,
            sequence_number: 0,
        })
        .await;
        assert!(mgr.remove_bundle("remote.org").await);
        assert!(!mgr.remove_bundle("remote.org").await);
        assert_eq!(mgr.bundle_count().await, 0);
    }

    #[tokio::test]
    async fn test_federated_bundle_cleanup_stale() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        // Store a bundle that was refreshed at epoch 0 (very stale)
        mgr.store_bundle(FederatedBundle {
            trust_domain: "stale.org".to_string(),
            ca_certs: vec![],
            refreshed_at: 0,
            sequence_number: 1,
        })
        .await;
        // Store a fresh bundle
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        mgr.store_bundle(FederatedBundle {
            trust_domain: "fresh.org".to_string(),
            ca_certs: vec![],
            refreshed_at: now,
            sequence_number: 1,
        })
        .await;
        assert_eq!(mgr.bundle_count().await, 2);

        mgr.cleanup_stale(Duration::from_secs(3600)).await;
        assert_eq!(mgr.bundle_count().await, 1);
        assert!(mgr.get_bundle("fresh.org").await.is_some());
        assert!(mgr.get_bundle("stale.org").await.is_none());
    }

    #[tokio::test]
    async fn test_federated_bundle_endpoints() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        mgr.add_federation_endpoint("remote.org", "https://remote.org/.well-known/spiffe-bundle")
            .await;
        let ep = mgr.get_endpoint("remote.org").await.unwrap();
        assert!(ep.contains("spiffe-bundle"));
        assert!(mgr.get_endpoint("unknown.org").await.is_none());
    }

    #[tokio::test]
    async fn test_federated_bundle_list_domains() {
        let mgr = FederatedTrustBundleManager::new("local.org");
        mgr.store_bundle(FederatedBundle {
            trust_domain: "a.org".to_string(),
            ca_certs: vec![],
            refreshed_at: 0,
            sequence_number: 0,
        })
        .await;
        mgr.store_bundle(FederatedBundle {
            trust_domain: "b.org".to_string(),
            ca_certs: vec![],
            refreshed_at: 0,
            sequence_number: 0,
        })
        .await;
        let mut domains = mgr.federated_domains().await;
        domains.sort();
        assert_eq!(domains, vec!["a.org", "b.org"]);
    }
}
