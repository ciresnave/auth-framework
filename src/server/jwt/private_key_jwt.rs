//! RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants
//!
//! This module implements private key JWT client authentication, allowing clients
//! to authenticate using JWTs signed with their private keys.
//!
//! ## Security properties
//!
//! - **Real public-key verification**: the registered JWK is turned into a genuine
//!   RSA / EC / Ed25519 verification key. Symmetric (`HS*`) algorithms are refused at
//!   registration, and the algorithm used for verification is the one in the
//!   assertion's header, accepted only if it is on the client's allow-list *and*
//!   belongs to the registered key's family.
//! - **Audience**: every client must be registered with the audience value(s) it may
//!   present (the token endpoint URL(s)); an assertion is accepted only if its `aud`
//!   is one of them.
//! - **Verified claims only**: the client is looked up from the unverified `iss`
//!   solely to find its key; every decision afterwards uses the claims returned by
//!   signature verification.
//! - **Replay protection**: a `jti` is claimed atomically, per client, and only after
//!   everything else has passed; it is remembered until the assertion can no longer be
//!   accepted (`exp` plus the clock skew), whatever the cleanup interval. Revoked `jti`s are
//!   refused.
//! - **No client enumeration by answer**: an unknown client and an assertion whose signature
//!   does not verify get the same answer. Detailed reasons are given only once the key has
//!   proved the assertion genuine. (The unknown-client path does not parse a key or verify a
//!   signature, so it is faster; a `client_id` is not a secret, and rate limiting belongs at
//!   the edge.)
//! - **Bounded memory**: at most 5,000 unexpired `jti`s per client
//!   (default 5,000) and 100,000 in all, so one client cannot lock the others out.
//!
//! ## Things to know
//!
//! - Replay protection and `jti` revocation are in memory, per manager instance. Revoked
//!   assertion `jti`s are kept in their own namespace (`private_key_jwt:` prefix) of the
//!   validator's revocation list, so they never collide with access-token `jti`s.
//! - `iat` is optional (RFC 7523 does not require it). With it, `exp - iat` is bounded by the
//!   client's maximum lifetime; without it, `exp` may not be further ahead than that maximum
//!   plus the clock skew.
//! - There is no `kid` handling or key rotation: one JWK per client; replace it by registering
//!   the client again. A JWK's own `alg` member is not consulted (the allow-list decides, which
//!   is the safe direction).
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! use auth_framework::server::jwt::private_key_jwt::{PrivateKeyJwtManager, ClientJwtConfig};
//! use auth_framework::{SecureJwtValidator, SecureJwtConfig};
//! use chrono::Duration;
//! use jsonwebtoken::Algorithm;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // `Default` generates a fresh random secret per instance.
//! // Pass an explicit `jwt_secret` when running multiple nodes that share a key.
//! let jwt_config = SecureJwtConfig {
//!     jwt_secret: std::env::var("JWT_SECRET").expect("JWT_SECRET must be set").into(),
//!     ..SecureJwtConfig::default()
//! };
//! let jwt_validator = SecureJwtValidator::new(jwt_config)?;
//!
//! // Create manager with custom cleanup interval
//! let manager = PrivateKeyJwtManager::new(jwt_validator)
//!     .with_cleanup_interval(Duration::minutes(30));
//!
//! // Configure client for JWT authentication
//! let config = ClientJwtConfig::builder(
//!     "example_client",
//!     serde_json::json!({"kty": "RSA", "n": "...", "e": "AQAB"}),
//! )
//! .rs256_only()
//! .audience("https://api.example.com")
//! .build();
//!
//! manager.register_client(config).await?;
//!
//! // Authenticate client with JWT assertion
//! let client_assertion = "eyJ..."; // JWT assertion from client
//! let auth_result = manager.authenticate_client(client_assertion).await?;
//!
//! if auth_result.authenticated {
//!     println!("Client authenticated successfully");
//!     // Process authenticated client...
//! }
//!
//! // Perform scheduled cleanup
//! manager.schedule_automatic_cleanup().await;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::security::secure_jwt::SecureJwtValidator;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Smallest RSA modulus (in bits) accepted for a registered client key.
const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Largest assertion (bytes) that is looked at at all.
const MAX_ASSERTION_BYTES: usize = 8 * 1024;

/// Longest `jti` accepted.
const MAX_JTI_BYTES: usize = 256;

/// Longest `client_id` accepted at registration.
const MAX_CLIENT_ID_BYTES: usize = 256;

/// Most unexpired `jti`s remembered in all; beyond this new assertions are refused (fail closed).
const MAX_TRACKED_JTIS: usize = 100_000;

/// Most unexpired assertions (distinct `jti`s) remembered per client; further ones are refused
/// until older ones expire, so one client cannot use up the room of the others.
const DEFAULT_MAX_OUTSTANDING_ASSERTIONS: usize = 5_000;

/// Above this many remembered `jti`s, expired ones are dropped on a claim...
const JTI_SWEEP_THRESHOLD: usize = 1024;

/// ...but at most this often (seconds): a sweep scans the whole map under the write lock.
const JTI_SWEEP_INTERVAL_SECS: i64 = 5;

/// Namespace of assertion `jti`s in the validator's revocation list.
const REVOCATION_NAMESPACE: &str = "private_key_jwt:";

/// What is said about an unknown client or an assertion that is not proven genuine.
const GENERIC_REJECTION: &str = "Client authentication failed";

/// JWK members that only a private or symmetric key carries. A registered
/// client key must be a public key.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Private Key JWT claims for client authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyJwtClaims {
    /// Issuer - must equal the client_id
    pub iss: String,

    /// Subject - must equal the client_id
    pub sub: String,

    /// Audience - authorization server token endpoint
    pub aud: String,

    /// JWT ID for replay protection
    pub jti: String,

    /// Expiration time
    pub exp: i64,

    /// Issued at time. RFC 7523 does not require it: an assertion without one is read as `0`,
    /// which is treated as "absent" (the lifetime is then bounded through `exp` alone).
    #[serde(default)]
    pub iat: i64,

    /// Not before time (optional)
    pub nbf: Option<i64>,
}

/// Client JWT configuration for private key authentication
#[derive(Debug, Clone)]
pub struct ClientJwtConfig {
    /// Client identifier
    pub client_id: String,

    /// Public key for JWT verification (JWK format)
    pub public_key_jwk: serde_json::Value,

    /// Allowed signing algorithms (asymmetric only; `HS*` is refused at registration)
    pub allowed_algorithms: Vec<Algorithm>,

    /// Maximum JWT lifetime (default: 5 minutes)
    pub max_jwt_lifetime: Duration,

    /// Clock skew tolerance (default: 60 seconds)
    pub clock_skew: Duration,

    /// Audience values (token endpoint URLs) an assertion may be addressed to.
    /// Registration requires at least one.
    pub expected_audiences: Vec<String>,
}

impl ClientJwtConfig {
    /// Create a builder for private key JWT client configuration.
    pub fn builder(
        client_id: impl Into<String>,
        public_key_jwk: serde_json::Value,
    ) -> ClientJwtConfigBuilder {
        ClientJwtConfigBuilder {
            client_id: client_id.into(),
            public_key_jwk,
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            max_jwt_lifetime: Duration::minutes(5),
            clock_skew: Duration::seconds(60),
            expected_audiences: Vec::new(),
        }
    }
}

/// Builder for private key JWT client configuration.
pub struct ClientJwtConfigBuilder {
    client_id: String,
    public_key_jwk: serde_json::Value,
    allowed_algorithms: Vec<Algorithm>,
    max_jwt_lifetime: Duration,
    clock_skew: Duration,
    expected_audiences: Vec<String>,
}

impl ClientJwtConfigBuilder {
    /// Restrict signing to RS256 only.
    pub fn rs256_only(mut self) -> Self {
        self.allowed_algorithms = vec![Algorithm::RS256];
        self
    }

    /// Replace the allowed algorithm list.
    pub fn algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Set the maximum JWT lifetime.
    pub fn max_jwt_lifetime(mut self, max_jwt_lifetime: Duration) -> Self {
        self.max_jwt_lifetime = max_jwt_lifetime;
        self
    }

    /// Set the clock skew tolerance.
    pub fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }

    /// Add one expected audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audiences.push(audience.into());
        self
    }

    /// Replace the expected audience list.
    pub fn audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.expected_audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Build the client JWT configuration.
    pub fn build(self) -> ClientJwtConfig {
        ClientJwtConfig {
            client_id: self.client_id,
            public_key_jwk: self.public_key_jwk,
            allowed_algorithms: self.allowed_algorithms,
            max_jwt_lifetime: self.max_jwt_lifetime,
            clock_skew: self.clock_skew,
            expected_audiences: self.expected_audiences,
        }
    }
}

/// JWT authentication result
#[derive(Debug, Clone)]
pub struct JwtAuthResult {
    /// Client identifier
    pub client_id: String,

    /// Whether authentication was successful
    pub authenticated: bool,

    /// JWT claims if valid
    pub claims: Option<PrivateKeyJwtClaims>,

    /// Validation errors
    pub errors: Vec<String>,

    /// JWT ID for tracking (only set for a verified assertion)
    pub jti: Option<String>,
}

/// The claims as they arrive: `aud` may be a string or an array (RFC 7519, 4.1.3).
#[derive(Deserialize)]
struct ReceivedClaims {
    iss: String,
    sub: String,
    aud: ReceivedAudience,
    jti: String,
    exp: i64,
    iat: Option<i64>,
    nbf: Option<i64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReceivedAudience {
    One(String),
    Many(Vec<String>),
}

impl ReceivedAudience {
    /// The first audience value, if any (used when no audience is configured).
    fn first(&self) -> Option<String> {
        match self {
            ReceivedAudience::One(one) => Some(one.clone()),
            ReceivedAudience::Many(many) => many.first().cloned(),
        }
    }

    /// The configured audience this assertion is addressed to, if any: exact membership.
    fn matching(&self, configured: &[String]) -> Option<String> {
        let listed: &[String] = match self {
            ReceivedAudience::One(one) => std::slice::from_ref(one),
            ReceivedAudience::Many(many) => many,
        };
        listed.iter().find(|a| configured.contains(a)).cloned()
    }
}

/// The remembered `jti`s: key -> deadline, with a per-client count for the quota.
#[derive(Debug, Default)]
struct JtiStore {
    entries: HashMap<String, DateTime<Utc>>,
    per_client: HashMap<String, usize>,
    last_sweep: Option<DateTime<Utc>>,
}

impl std::ops::Deref for JtiStore {
    type Target = HashMap<String, DateTime<Utc>>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl std::ops::DerefMut for JtiStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

impl JtiStore {
    /// Drop the entries whose deadline has passed and recount the clients.
    fn sweep(&mut self, now: DateTime<Utc>) {
        self.entries.retain(|_, deadline| *deadline > now);
        self.per_client.clear();
        for key in self.entries.keys() {
            *self
                .per_client
                .entry(client_of_key(key).to_string())
                .or_default() += 1;
        }
        self.last_sweep = Some(now);
    }
}

/// The client id inside a key made by `PrivateKeyJwtManager::jti_key` ("len:client:jti").
fn client_of_key(key: &str) -> &str {
    key.split_once(':')
        .and_then(|(len, rest)| len.parse::<usize>().ok().and_then(|n| rest.get(..n)))
        .unwrap_or("")
}

/// Why verification failed, split by whether the client's key vouched for the assertion.
enum Rejection {
    /// Nothing is proven: the answer must not depend on the client or on why.
    Unproven(String),
    /// The signature verified; the reason may be told to the (genuine) caller.
    Proven(String),
}

/// The kind of public key a JWK describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Rsa,
    EcP256,
    EcP384,
    Ed25519,
}

impl KeyKind {
    /// Whether `algorithm` is a signature algorithm for this kind of key.
    fn supports(self, algorithm: Algorithm) -> bool {
        match self {
            KeyKind::Rsa => matches!(
                algorithm,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            KeyKind::EcP256 => algorithm == Algorithm::ES256,
            KeyKind::EcP384 => algorithm == Algorithm::ES384,
            KeyKind::Ed25519 => algorithm == Algorithm::EdDSA,
        }
    }
}

/// `true` for the HMAC family, whose "public" key would be a shared secret.
fn is_symmetric(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    )
}

/// Private Key JWT Manager
#[derive(Debug)]
pub struct PrivateKeyJwtManager {
    /// Client configurations indexed by client_id
    client_configs: tokio::sync::RwLock<HashMap<String, ClientJwtConfig>>,

    /// Used JTIs (scoped per client) for replay protection, each with the time after which the
    /// assertion could no longer be accepted anyway (`exp` plus the clock skew)
    used_jtis: tokio::sync::RwLock<JtiStore>,

    /// Holds the `jti` revocation list
    jwt_validator: SecureJwtValidator,

    /// How long revoked-`jti` records are kept by `schedule_automatic_cleanup`; never less
    /// than the longest time an assertion of a registered client can stay acceptable
    cleanup_interval: Duration,

    /// Whether registration refuses a client without an expected audience (opt-in).
    require_audiences: bool,

    /// Most unexpired `jti`s remembered per client.
    max_outstanding_assertions: usize,
}

impl PrivateKeyJwtManager {
    /// Create a new Private Key JWT Manager
    pub fn new(jwt_validator: SecureJwtValidator) -> Self {
        Self {
            client_configs: tokio::sync::RwLock::new(HashMap::new()),
            used_jtis: tokio::sync::RwLock::new(JtiStore::default()),
            jwt_validator,
            cleanup_interval: Duration::hours(1),
            require_audiences: false,
            max_outstanding_assertions: DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
        }
    }

    /// Make registration refuse a client that configures no expected audience.
    ///
    /// Without an audience an assertion cannot be bound to this server, so a genuine assertion
    /// captured elsewhere could be presented here. It is off by default so that a patch release
    /// does not start refusing existing registrations; a registration without an audience logs
    /// a warning. Turn it on once every client has its token endpoint configured.
    pub fn require_audiences(mut self, require: bool) -> Self {
        self.require_audiences = require;
        self
    }

    #[cfg(test)]
    fn with_max_outstanding_assertions(mut self, max: usize) -> Self {
        self.max_outstanding_assertions = max;
        self
    }

    /// Register a client for private key JWT authentication
    ///
    /// Registration fails unless the key is a well-formed public RSA / EC (P-256,
    /// P-384) / Ed25519 JWK, no symmetric algorithm is allowed, and at least one allowed
    /// algorithm fits the key. A client without an expected audience is accepted with a
    /// warning unless [`require_audiences`](Self::require_audiences) is on.
    pub async fn register_client(&self, config: ClientJwtConfig) -> Result<()> {
        self.validate_client_config(&config)?;

        let mut configs = self.client_configs.write().await;
        configs.insert(config.client_id.clone(), config);

        Ok(())
    }

    /// Authenticate a client using private key JWT
    ///
    /// Returns `Err` only for input that is not an assertion at all (oversized, not a JWT).
    /// An unknown client and an assertion that does not verify both return `Ok` with
    /// `authenticated == false` and the same single message; a refusal after the signature has
    /// verified (wrong audience, expired, replayed, ...) names its reason.
    pub async fn authenticate_client(&self, client_assertion: &str) -> Result<JwtAuthResult> {
        if client_assertion.len() > MAX_ASSERTION_BYTES {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Client assertion is too large",
            ));
        }
        let header = self.parse_jwt_header(client_assertion)?;

        // The unverified `iss` is used only to find which key to verify with.
        let claimed_client_id = self.extract_claimed_client_id(client_assertion)?;
        let rejected = |errors: Vec<String>| JwtAuthResult {
            client_id: claimed_client_id.clone(),
            authenticated: false,
            claims: None,
            errors,
            jti: None,
        };
        let config = {
            let configs = self.client_configs.read().await;
            configs.get(&claimed_client_id).cloned()
        };
        let Some(config) = config else {
            tracing::debug!("private_key_jwt: assertion for an unregistered client");
            return Ok(rejected(vec![GENERIC_REJECTION.to_string()]));
        };

        // Everything below uses the claims that signature verification returned.
        let claims = match self.verify_jwt_signature(client_assertion, &header, &config) {
            Ok(claims) => claims,
            Err(Rejection::Unproven(reason)) => {
                tracing::debug!("private_key_jwt: assertion not verified: {}", reason);
                return Ok(rejected(vec![GENERIC_REJECTION.to_string()]));
            }
            Err(Rejection::Proven(reason)) => return Ok(rejected(vec![reason])),
        };

        let mut errors = Vec::new();
        self.validate_jwt_structure(&claims, &config, &mut errors);
        self.validate_jwt_timing(&claims, &config, &mut errors);

        match self
            .jwt_validator
            .is_token_revoked(&Self::revocation_id(&claims.jti))
        {
            Ok(false) => {}
            Ok(true) => errors.push("JWT has been revoked".to_string()),
            Err(e) => errors.push(format!("Revocation check failed: {}", e)),
        }

        // Claim the JTI last, so an assertion that fails any check above does not
        // consume it, and check-and-record is a single step. It is remembered until the
        // assertion could no longer be accepted.
        if errors.is_empty() {
            let deadline = claims
                .exp
                .saturating_add(config.clock_skew.num_seconds())
                .saturating_add(1);
            let deadline =
                DateTime::from_timestamp(deadline, 0).unwrap_or(DateTime::<Utc>::MAX_UTC);
            if let Err(e) = self
                .claim_jti(
                    &config.client_id,
                    &claims.jti,
                    deadline,
                    self.max_outstanding_assertions,
                )
                .await
            {
                errors.push(format!("JTI rejected: {}", e));
            }
        }

        if !errors.is_empty() {
            return Ok(rejected(errors));
        }

        let jti = claims.jti.clone();
        Ok(JwtAuthResult {
            client_id: config.client_id,
            authenticated: true,
            claims: Some(claims),
            errors,
            jti: Some(jti),
        })
    }

    /// Create a client assertion JWT (for testing/client-side use).
    ///
    /// # Key encoding by algorithm
    /// - **HS256/384/512**: `signing_key` is the raw HMAC secret bytes (such an assertion is
    ///   refused by `authenticate_client`: symmetric algorithms cannot be registered).
    /// - **RS256/384/512, PS256/384/512**: a PEM-encoded RSA private key.
    /// - **ES256/384**: a PEM-encoded EC private key.
    /// - **EdDSA**: a PEM-encoded Ed25519 private key.
    pub fn create_client_assertion(
        &self,
        client_id: &str,
        audience: &str,
        signing_key: &[u8],
        algorithm: Algorithm,
    ) -> Result<String> {
        let now = Utc::now();
        let claims = PrivateKeyJwtClaims {
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            aud: audience.to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            exp: (now + Duration::minutes(5)).timestamp(),
            iat: now.timestamp(),
            nbf: Some(now.timestamp()),
        };

        let bad_key = |e: jsonwebtoken::errors::Error| {
            AuthError::auth_method(
                "private_key_jwt",
                format!("Invalid signing key for {:?}: {}", algorithm, e),
            )
        };
        let encoding_key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(signing_key)
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => EncodingKey::from_rsa_pem(signing_key).map_err(bad_key)?,
            Algorithm::ES256 | Algorithm::ES384 => {
                EncodingKey::from_ec_pem(signing_key).map_err(bad_key)?
            }
            Algorithm::EdDSA => EncodingKey::from_ed_pem(signing_key).map_err(bad_key)?,
        };

        let header = Header::new(algorithm);
        encode(&header, &claims, &encoding_key).map_err(|e| {
            AuthError::auth_method("private_key_jwt", format!("Failed to encode JWT: {}", e))
        })
    }

    /// Drop the remembered JTIs whose assertions could no longer be accepted anyway. A JTI is
    /// kept until its own deadline (`exp` plus the client's clock skew), never for a fixed
    /// interval, so cleanup cannot reopen a replay window.
    pub async fn cleanup_expired_jtis(&self) {
        self.used_jtis.write().await.sweep(Utc::now());
    }

    /// Set the cleanup interval for JTI management
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Get the current cleanup interval
    pub fn get_cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Update the cleanup interval
    pub fn update_cleanup_interval(&mut self, interval: Duration) {
        self.cleanup_interval = interval;
    }

    /// Revoke a JWT by its JTI using the enhanced validator
    pub fn revoke_jwt_token(&self, jti: &str) -> Result<()> {
        self.jwt_validator.revoke_token(&Self::revocation_id(jti))
    }

    /// Check if a JWT is revoked using the enhanced validator
    pub fn is_jwt_token_revoked(&self, jti: &str) -> Result<bool> {
        self.jwt_validator
            .is_token_revoked(&Self::revocation_id(jti))
    }

    /// Clean up expired JTIs, and revocation records older than the cleanup interval. The
    /// interval is raised to the longest time an assertion of a registered client can stay
    /// acceptable (`max_jwt_lifetime + 2 * clock_skew`), so a revoked `jti` is never forgotten
    /// while an assertion carrying it could still be presented.
    pub async fn schedule_automatic_cleanup(&self) {
        // In a production system, this would run on a background task
        // For now, we'll perform the cleanup immediately
        self.cleanup_expired_jtis().await;

        let longest_acceptance = self
            .client_configs
            .read()
            .await
            .values()
            .map(|c| c.max_jwt_lifetime + c.clock_skew + c.clock_skew)
            .max()
            .unwrap_or_else(Duration::zero);
        let retention = self.cleanup_interval.max(longest_acceptance);

        // Clean up expired revoked tokens from the validator as well
        let expired_cutoff = std::time::SystemTime::now()
            .checked_sub(retention.to_std().unwrap_or_default())
            .unwrap_or_else(std::time::SystemTime::now);

        // Clean up expired tokens, ignoring cleanup errors
        let _ = self.jwt_validator.cleanup_revoked_tokens(expired_cutoff);
    }

    /// Parse JWT header without verification
    fn parse_jwt_header(&self, jwt: &str) -> Result<Header> {
        jsonwebtoken::decode_header(jwt).map_err(|e| {
            AuthError::auth_method("private_key_jwt", format!("Invalid JWT header: {}", e))
        })
    }

    /// Read the claimed `iss` without verifying anything. The result may only be
    /// used to choose which registered key to verify with.
    fn extract_claimed_client_id(&self, jwt: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Unverified {
            iss: String,
        }

        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Invalid JWT format",
            ));
        }

        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
            AuthError::auth_method("private_key_jwt", "Invalid JWT claims encoding")
        })?;

        let claims: Unverified = serde_json::from_slice(&claims_bytes)
            .map_err(|_| AuthError::auth_method("private_key_jwt", "Invalid JWT claims format"))?;

        Ok(claims.iss)
    }

    /// Validate the claims of a verified assertion.
    fn validate_jwt_structure(
        &self,
        claims: &PrivateKeyJwtClaims,
        config: &ClientJwtConfig,
        errors: &mut Vec<String>,
    ) {
        // Check issuer equals subject and client_id
        if claims.iss != claims.sub {
            errors.push("Issuer must equal subject".to_string());
        }

        if claims.iss != config.client_id {
            errors.push("Issuer must equal client_id".to_string());
        }

        // Check audience (unless the client was registered without one: see `require_audiences`)
        if !config.expected_audiences.is_empty() && !config.expected_audiences.contains(&claims.aud)
        {
            errors.push(format!("Audience '{}' not allowed", claims.aud));
        }

        // Check JTI is present and of sensible size
        if claims.jti.trim().is_empty() {
            errors.push("JTI (JWT ID) is required".to_string());
        }
        if claims.jti.len() > MAX_JTI_BYTES {
            errors.push(format!("JTI is longer than {} bytes", MAX_JTI_BYTES));
        }
    }

    /// Verify the assertion's signature with the client's registered public key and
    /// return the verified claims.
    ///
    /// The algorithm is the one in the (signed-over) header, accepted only if it is
    /// on the client's allow-list and fits the registered key. `iss`, `aud`, `exp`
    /// and `nbf` are checked here against the configuration, independent of any
    /// issuer pinned on the authorization server's own token validator. `aud` may be a
    /// string or an array; one of its values must be a configured audience, exactly.
    fn verify_jwt_signature(
        &self,
        jwt: &str,
        header: &Header,
        config: &ClientJwtConfig,
    ) -> std::result::Result<PrivateKeyJwtClaims, Rejection> {
        let algorithm = header.alg;
        if !config.allowed_algorithms.contains(&algorithm) {
            return Err(Rejection::Unproven(format!(
                "Algorithm {:?} not allowed",
                algorithm
            )));
        }

        let (decoding_key, kind) = self
            .jwk_to_decoding_key(&config.public_key_jwk)
            .map_err(|e| Rejection::Unproven(e.to_string()))?;
        if is_symmetric(algorithm) || !kind.supports(algorithm) {
            return Err(Rejection::Unproven(format!(
                "Algorithm {:?} does not match the registered {:?} key",
                algorithm, kind
            )));
        }

        let mut validation = Validation::new(algorithm);
        if config.expected_audiences.is_empty() {
            // Registered without an audience (see `require_audiences`): the `aud` claim must be
            // present but cannot be matched against anything.
            validation.validate_aud = false;
        } else {
            validation.set_audience(&config.expected_audiences);
        }
        validation.set_issuer(&[&config.client_id]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = config.clock_skew.num_seconds().max(0) as u64;

        let token_data =
            decode::<ReceivedClaims>(jwt, &decoding_key, &validation).map_err(|e| {
                use jsonwebtoken::errors::ErrorKind as K;
                // jsonwebtoken checks the signature before any claim, so these kinds can only
                // occur once it has verified; anything else (including kinds added later) is
                // treated as "not proven".
                match e.kind() {
                    K::ExpiredSignature
                    | K::ImmatureSignature
                    | K::InvalidIssuer
                    | K::InvalidAudience
                    | K::InvalidSubject
                    | K::MissingRequiredClaim(_) => {
                        Rejection::Proven(format!("Invalid assertion: {}", e))
                    }
                    // A claim of the wrong shape: say so without echoing the parser's text.
                    K::Json(_) => Rejection::Proven("Invalid assertion claims".to_string()),
                    _ => Rejection::Unproven(format!("JWT verification failed: {}", e)),
                }
            })?;

        let received = token_data.claims;
        let aud = if config.expected_audiences.is_empty() {
            received
                .aud
                .first()
                .ok_or_else(|| Rejection::Proven("Audience missing".to_string()))?
        } else {
            received
                .aud
                .matching(&config.expected_audiences)
                .ok_or_else(|| Rejection::Proven("Audience not allowed".to_string()))?
        };
        Ok(PrivateKeyJwtClaims {
            iss: received.iss,
            sub: received.sub,
            aud,
            jti: received.jti,
            exp: received.exp,
            iat: received.iat.unwrap_or(0),
            nbf: received.nbf,
        })
    }

    /// Convert a public JWK into a real verification key.
    ///
    /// Supports RSA (modulus of at least 2048 bits), EC P-256 / P-384 and OKP
    /// Ed25519. Anything that carries private or symmetric key material is refused.
    fn jwk_to_decoding_key(&self, jwk: &serde_json::Value) -> Result<(DecodingKey, KeyKind)> {
        let fail = |message: String| AuthError::auth_method("private_key_jwt", message);
        let text = |name: &str| -> Result<&str> {
            jwk.get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| fail(format!("Missing '{}' in JWK", name)))
        };
        let bytes = |name: &str| -> Result<Vec<u8>> {
            URL_SAFE_NO_PAD
                .decode(text(name)?.as_bytes())
                .map_err(|_| fail(format!("Invalid base64url '{}' parameter", name)))
        };

        if !jwk.is_object() {
            return Err(fail("JWK must be a JSON object".to_string()));
        }
        if let Some(member) = PRIVATE_JWK_MEMBERS
            .iter()
            .find(|member| jwk.get(**member).is_some())
        {
            return Err(fail(format!(
                "JWK contains private or symmetric key parameter '{}'; register the public key only",
                member
            )));
        }
        if let Some(usage) = jwk.get("use")
            && usage.as_str() != Some("sig")
        {
            return Err(fail("JWK 'use' must be 'sig'".to_string()));
        }

        match text("kty")? {
            "RSA" => {
                let n = bytes("n")?;
                let e = bytes("e")?;
                let first = n.iter().position(|b| *b != 0).unwrap_or(n.len());
                let significant = &n[first..];
                let bits = match significant.first() {
                    Some(top) => (significant.len() - 1) * 8 + (8 - top.leading_zeros() as usize),
                    None => 0,
                };
                if bits < MIN_RSA_MODULUS_BITS {
                    return Err(fail(format!(
                        "RSA modulus of {} bits is below the {}-bit minimum",
                        bits, MIN_RSA_MODULUS_BITS
                    )));
                }
                let exponent: Vec<u8> = e.iter().copied().skip_while(|b| *b == 0).collect();
                if exponent.len() < 2 && exponent.first().is_none_or(|b| *b < 3) {
                    return Err(fail(
                        "RSA public exponent must be greater than 1".to_string(),
                    ));
                }
                if exponent.last().is_some_and(|b| b % 2 == 0) {
                    return Err(fail("RSA public exponent must be odd".to_string()));
                }
                let key = DecodingKey::from_rsa_components(text("n")?, text("e")?)
                    .map_err(|e| fail(format!("Invalid RSA JWK: {}", e)))?;
                Ok((key, KeyKind::Rsa))
            }
            "EC" => {
                let (kind, len) = match text("crv")? {
                    "P-256" => (KeyKind::EcP256, 32),
                    "P-384" => (KeyKind::EcP384, 48),
                    other => {
                        return Err(fail(format!("Unsupported EC curve: {}", other)));
                    }
                };
                if bytes("x")?.len() != len || bytes("y")?.len() != len {
                    return Err(fail(format!(
                        "EC coordinates must be {} bytes for this curve",
                        len
                    )));
                }
                let key = DecodingKey::from_ec_components(text("x")?, text("y")?)
                    .map_err(|e| fail(format!("Invalid EC JWK: {}", e)))?;
                Ok((key, kind))
            }
            "OKP" => {
                if text("crv")? != "Ed25519" {
                    return Err(fail("Unsupported OKP curve (only Ed25519)".to_string()));
                }
                if bytes("x")?.len() != 32 {
                    return Err(fail("Ed25519 public key must be 32 bytes".to_string()));
                }
                let key = DecodingKey::from_ed_components(text("x")?)
                    .map_err(|e| fail(format!("Invalid OKP JWK: {}", e)))?;
                Ok((key, KeyKind::Ed25519))
            }
            other => Err(fail(format!("Unsupported key type: {}", other))),
        }
    }

    /// Name of an assertion `jti` in the validator's revocation list, which also holds
    /// access-token `jti`s: the prefix keeps the two apart.
    fn revocation_id(jti: &str) -> String {
        format!("{}{}", REVOCATION_NAMESPACE, jti)
    }

    /// Key under which a client's JTI is remembered: length-prefixed, so no (client, jti) pair
    /// can collide with another whatever characters either contains.
    fn jti_key(client_id: &str, jti: &str) -> String {
        format!("{}:{}:{}", client_id.len(), client_id, jti)
    }

    /// Atomically check that a client's JTI is unused and record it until `deadline`.
    ///
    /// Expired entries are swept when the map is large, but at most every few seconds (a sweep
    /// scans the whole map under the write lock). A full map refuses new claims, and so does a
    /// client that already has `quota` unexpired ones, so one client cannot use up the room of
    /// the others.
    async fn claim_jti(
        &self,
        client_id: &str,
        jti: &str,
        deadline: DateTime<Utc>,
        quota: usize,
    ) -> Result<()> {
        let mut guard = self.used_jtis.write().await;
        let store = &mut *guard;
        let now = Utc::now();
        if store.entries.len() >= JTI_SWEEP_THRESHOLD
            && store
                .last_sweep
                .is_none_or(|at| now - at >= Duration::seconds(JTI_SWEEP_INTERVAL_SECS))
        {
            store.sweep(now);
        }
        if store.entries.len() >= MAX_TRACKED_JTIS {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Too many unexpired assertions are being tracked",
            ));
        }
        if store.per_client.get(client_id).copied().unwrap_or(0) >= quota {
            return Err(AuthError::auth_method(
                "private_key_jwt",
                "Too many unexpired assertions for this client",
            ));
        }
        match store.entries.entry(Self::jti_key(client_id, jti)) {
            std::collections::hash_map::Entry::Occupied(_) => Err(AuthError::auth_method(
                "private_key_jwt",
                "JTI already used: replay detected",
            )),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(deadline);
                *store.per_client.entry(client_id.to_string()).or_default() += 1;
                Ok(())
            }
        }
    }

    /// Validate JWT timing constraints (all arithmetic is checked or saturating: the claims
    /// are attacker-chosen integers)
    fn validate_jwt_timing(
        &self,
        claims: &PrivateKeyJwtClaims,
        config: &ClientJwtConfig,
        errors: &mut Vec<String>,
    ) {
        let now = Utc::now().timestamp();
        let skew = config.clock_skew.num_seconds();

        // Check expiration
        if claims.exp <= now.saturating_sub(skew) {
            errors.push("JWT has expired".to_string());
        }

        // Check not before
        if let Some(nbf) = claims.nbf
            && nbf > now.saturating_add(skew)
        {
            errors.push("JWT not yet valid".to_string());
        }

        let max_lifetime = config.max_jwt_lifetime.num_seconds();
        let iat = (claims.iat != 0).then_some(claims.iat);
        match iat {
            Some(iat) => {
                // Issued at, and the maximum lifetime measured from it
                if iat > now.saturating_add(skew) {
                    errors.push("JWT issued in the future".to_string());
                }
                match claims.exp.checked_sub(iat) {
                    Some(lifetime) if lifetime <= 0 => {
                        errors.push("JWT expiry is not after its issue time".to_string());
                    }
                    Some(lifetime) if lifetime > max_lifetime => {
                        errors.push(format!(
                            "JWT lifetime {} exceeds maximum {}",
                            lifetime, max_lifetime
                        ));
                    }
                    Some(_) => {}
                    None => errors.push("JWT lifetime is out of range".to_string()),
                }
            }
            None => {
                // No `iat` (RFC 7523 does not require one): the lifetime cannot be measured
                // from it, so `exp` may not lie further ahead than a fresh assertion's would.
                let horizon = now.saturating_add(max_lifetime).saturating_add(skew);
                if claims.exp > horizon {
                    errors.push(
                        "JWT expiry is further ahead than the maximum lifetime allows".to_string(),
                    );
                }
            }
        }
    }

    /// Validate client configuration
    fn validate_client_config(&self, config: &ClientJwtConfig) -> Result<()> {
        let fail = |message: &str| AuthError::auth_method("private_key_jwt", message);

        if config.client_id.trim().is_empty() {
            return Err(fail("Client ID cannot be empty"));
        }
        if config.client_id.len() > MAX_CLIENT_ID_BYTES
            || config.client_id.chars().any(char::is_control)
        {
            return Err(fail(
                "Client ID must be at most 256 bytes without control characters",
            ));
        }

        if config.allowed_algorithms.is_empty() {
            return Err(fail("At least one algorithm must be allowed"));
        }

        if config.allowed_algorithms.iter().any(|a| is_symmetric(*a)) {
            return Err(fail(
                "Symmetric (HS*) algorithms cannot be used with private_key_jwt",
            ));
        }

        if config
            .expected_audiences
            .iter()
            .any(|a| a.trim().is_empty())
        {
            return Err(fail("An expected audience must not be empty"));
        }
        if config.expected_audiences.is_empty() {
            if self.require_audiences {
                return Err(fail(
                    "At least one audience (token endpoint) must be configured",
                ));
            }
            tracing::warn!(
                client_id = %config.client_id,
                "private_key_jwt client registered without an expected audience: its assertions \
                 are not bound to this server (see PrivateKeyJwtManager::require_audiences)"
            );
        }

        if config.clock_skew < Duration::zero() || config.max_jwt_lifetime <= Duration::zero() {
            return Err(fail(
                "clock_skew must not be negative and max_jwt_lifetime must be positive",
            ));
        }
        if config.clock_skew > Duration::minutes(10)
            || config.max_jwt_lifetime > Duration::hours(24)
        {
            return Err(fail(
                "clock_skew must be at most 10 minutes and max_jwt_lifetime at most 24 hours",
            ));
        }

        // The key must really be usable, and at least one allowed algorithm must fit it.
        let (_, kind) = self.jwk_to_decoding_key(&config.public_key_jwk)?;
        if !config.allowed_algorithms.iter().any(|a| kind.supports(*a)) {
            return Err(fail(
                "None of the allowed algorithms can be verified with the registered key",
            ));
        }

        Ok(())
    }
}

impl Default for ClientJwtConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            public_key_jwk: serde_json::json!({}),
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            max_jwt_lifetime: Duration::minutes(5),
            clock_skew: Duration::seconds(60),
            expected_audiences: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256,
        RsaKeySize,
    };
    use serde_json::{Value, json};
    use std::sync::{Arc, OnceLock};

    const TOKEN_ENDPOINT: &str = "https://auth.example.com/token";

    fn create_test_manager() -> PrivateKeyJwtManager {
        let jwt_config = crate::security::secure_jwt::SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config);
        PrivateKeyJwtManager::new(jwt_validator)
    }

    /// A manager whose validator pins no issuer, as a deployer might set up.
    fn create_unpinned_manager() -> PrivateKeyJwtManager {
        let mut jwt_config = crate::security::secure_jwt::SecureJwtConfig::default();
        jwt_config.required_issuers.clear();
        let jwt_validator = SecureJwtValidator::new(jwt_config);
        PrivateKeyJwtManager::new(jwt_validator)
    }

    /// A real generated key: signing half, public JWK, and the algorithm it signs with.
    #[derive(Clone)]
    struct TestKey {
        encoding_key: Arc<EncodingKey>,
        pem: String,
        jwk: Value,
        algorithm: Algorithm,
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn ec_key(alg: &'static rcgen::SignatureAlgorithm, point_len: usize, crv: &str) -> TestKey {
        let key = KeyPair::generate_for(alg).unwrap();
        let raw = key.public_key_raw();
        let point = &raw[raw.len() - point_len..];
        assert_eq!(point[0], 4, "uncompressed point");
        let half = (point_len - 1) / 2;
        TestKey {
            encoding_key: Arc::new(
                EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap(),
            ),
            pem: key.serialize_pem(),
            jwk: json!({"kty": "EC", "crv": crv, "x": b64(&point[1..1 + half]), "y": b64(&point[1 + half..])}),
            algorithm: if crv == "P-256" {
                Algorithm::ES256
            } else {
                Algorithm::ES384
            },
        }
    }

    fn p256_key() -> TestKey {
        ec_key(&PKCS_ECDSA_P256_SHA256, 65, "P-256")
    }

    fn p384_key() -> TestKey {
        ec_key(&PKCS_ECDSA_P384_SHA384, 97, "P-384")
    }

    fn ed25519_key() -> TestKey {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        TestKey {
            encoding_key: Arc::new(
                EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap(),
            ),
            pem: key.serialize_pem(),
            jwk: json!({"kty": "OKP", "crv": "Ed25519", "x": b64(key.public_key_raw())}),
            algorithm: Algorithm::EdDSA,
        }
    }

    /// Read one DER INTEGER (tag, length, content) and return its content and the rest.
    fn der_integer(input: &[u8]) -> (&[u8], &[u8]) {
        assert_eq!(input[0], 0x02);
        let (len, header) = if input[1] & 0x80 == 0 {
            (input[1] as usize, 2)
        } else {
            let n = (input[1] & 0x7f) as usize;
            let len = input[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize);
            (len, 2 + n)
        };
        (&input[header..header + len], &input[header + len..])
    }

    /// One shared RSA-2048 key; generating it is slow.
    fn rsa_key() -> TestKey {
        static KEY: OnceLock<TestKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
            // public_key_raw() is the DER RSAPublicKey: SEQUENCE { n INTEGER, e INTEGER }.
            let raw = key.public_key_raw();
            assert_eq!(raw[0], 0x30);
            let body = if raw[1] & 0x80 == 0 {
                &raw[2..]
            } else {
                &raw[2 + (raw[1] & 0x7f) as usize..]
            };
            let (n, rest) = der_integer(body);
            let (e, _) = der_integer(rest);
            let n = n.strip_prefix(&[0]).unwrap_or(n);
            TestKey {
                encoding_key: Arc::new(
                    EncodingKey::from_rsa_pem(key.serialize_pem().as_bytes()).unwrap(),
                ),
                pem: key.serialize_pem(),
                jwk: json!({"kty": "RSA", "n": b64(n), "e": b64(e)}),
                algorithm: Algorithm::RS256,
            }
        })
        .clone()
    }

    /// Claims for an assertion by `client`, addressed to the token endpoint.
    fn claims(client: &str, jti: &str) -> Value {
        let now = Utc::now().timestamp();
        json!({
            "iss": client, "sub": client, "aud": TOKEN_ENDPOINT, "jti": jti,
            "exp": now + 120, "iat": now, "nbf": now
        })
    }

    fn sign(key: &TestKey, algorithm: Algorithm, claims: &Value) -> String {
        encode(&Header::new(algorithm), claims, &key.encoding_key).unwrap()
    }

    fn config(client: &str, key: &TestKey) -> ClientJwtConfig {
        ClientJwtConfig::builder(client, key.jwk.clone())
            .algorithms(vec![key.algorithm])
            .audience(TOKEN_ENDPOINT)
            .build()
    }

    async fn registered(client: &str, key: &TestKey) -> PrivateKeyJwtManager {
        let manager = create_test_manager();
        manager.register_client(config(client, key)).await.unwrap();
        manager
    }

    /// The assertion must be answered with "not authenticated"; an `Err` (which means "not an
    /// assertion at all") or an unrelated failure does not count. Returns the reasons given.
    async fn assert_rejected(
        manager: &PrivateKeyJwtManager,
        assertion: &str,
        why: &str,
    ) -> Vec<String> {
        let result = manager
            .authenticate_client(assertion)
            .await
            .unwrap_or_else(|e| panic!("{why}: expected a verdict, got an error: {e}"));
        assert!(
            !result.authenticated,
            "{why}: the assertion must not authenticate"
        );
        assert!(!result.errors.is_empty(), "{why}: a reason is required");
        result.errors
    }

    // ----- genuine assertions authenticate -----

    #[tokio::test]
    async fn genuine_es256_assertion_authenticates() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "j1")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
        assert_eq!(result.client_id, "c");
        assert_eq!(result.jti.as_deref(), Some("j1"));
    }

    #[tokio::test]
    async fn genuine_es384_assertion_authenticates() {
        let key = p384_key();
        let manager = registered("c", &key).await;
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES384, &claims("c", "j1")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn genuine_eddsa_assertion_authenticates() {
        let key = ed25519_key();
        let manager = registered("c", &key).await;
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::EdDSA, &claims("c", "j1")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn genuine_rs256_and_ps256_assertions_authenticate() {
        let key = rsa_key();
        let manager = create_test_manager();
        manager
            .register_client(
                ClientJwtConfig::builder("c", key.jwk.clone())
                    .algorithms(vec![Algorithm::RS256, Algorithm::PS256])
                    .audience(TOKEN_ENDPOINT)
                    .build(),
            )
            .await
            .unwrap();
        for (alg, jti) in [(Algorithm::RS256, "j-rs"), (Algorithm::PS256, "j-ps")] {
            let result = manager
                .authenticate_client(&sign(&key, alg, &claims("c", jti)))
                .await
                .unwrap();
            assert!(result.authenticated, "{alg:?}: {:?}", result.errors);
        }
    }

    #[tokio::test]
    async fn authentication_does_not_depend_on_the_servers_issuer_pin() {
        // The validator is configured for the authorization server's own tokens.
        // Client assertions must verify the same way whether or not it pins an issuer.
        let key = p256_key();
        for manager in [create_test_manager(), create_unpinned_manager()] {
            manager.register_client(config("c", &key)).await.unwrap();
            let result = manager
                .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "j1")))
                .await
                .unwrap();
            assert!(result.authenticated, "{:?}", result.errors);
        }
    }

    // ----- forgery: a signature made without the private key -----

    #[tokio::test]
    async fn assertion_forged_with_a_key_derived_from_the_public_jwk_is_rejected() {
        let key = p256_key();
        let x = key.jwk["x"].as_str().unwrap();
        let y = key.jwk["y"].as_str().unwrap();
        // What the earlier implementation used as its "verification key".
        let derived = format!("ec_private_key_jwt_crv:{}_x:{}_y:{}", "P-256", x, y);
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims("c", "forged"),
            &EncodingKey::from_secret(derived.as_bytes()),
        )
        .unwrap();

        // Default algorithms (HS256 is not on the list)...
        let manager = registered("c", &key).await;
        assert_rejected(&manager, &forged, "HS256 not allowed").await;

        // ...and a client that asks for HS256 cannot even be registered.
        let manager = create_test_manager();
        let hs_config = ClientJwtConfig::builder("c", key.jwk.clone())
            .algorithms(vec![Algorithm::HS256])
            .audience(TOKEN_ENDPOINT)
            .build();
        assert!(manager.register_client(hs_config).await.is_err());
        assert_rejected(&manager, &forged, "client never registered").await;

        // The same through a validator that pins no issuer.
        let manager = create_unpinned_manager();
        manager.register_client(config("c", &key)).await.unwrap();
        assert_rejected(&manager, &forged, "unpinned validator").await;
    }

    #[tokio::test]
    async fn assertion_forged_for_an_rsa_client_with_a_public_derived_secret_is_rejected() {
        let key = rsa_key();
        let n = key.jwk["n"].as_str().unwrap();
        let e = key.jwk["e"].as_str().unwrap();
        let derived = format!("rsa_private_key_jwt_n:{}_e:{}", n, e);
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims("c", "forged"),
            &EncodingKey::from_secret(derived.as_bytes()),
        )
        .unwrap();
        let manager = registered("c", &key).await;
        assert_rejected(&manager, &forged, "HS256 against an RSA client").await;
    }

    #[tokio::test]
    async fn assertion_signed_by_another_key_is_rejected() {
        let registered_key = p256_key();
        let attacker_key = p256_key();
        let manager = registered("c", &registered_key).await;
        assert_rejected(
            &manager,
            &sign(&attacker_key, Algorithm::ES256, &claims("c", "j1")),
            "signed by a different key",
        )
        .await;
    }

    #[tokio::test]
    async fn assertion_with_a_tampered_payload_is_rejected() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let genuine = sign(&key, Algorithm::ES256, &claims("c", "j1"));
        let mut parts: Vec<String> = genuine.split('.').map(str::to_string).collect();
        parts[1] = b64(claims("c", "j2").to_string().as_bytes());
        assert_rejected(&manager, &parts.join("."), "payload changed after signing").await;
    }

    #[tokio::test]
    async fn header_algorithm_outside_the_allow_list_is_rejected() {
        let key = rsa_key();
        let manager = registered("c", &key).await; // allows RS256 only
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::PS256, &claims("c", "j1")),
            "PS256 is not on the allow-list",
        )
        .await;
    }

    #[tokio::test]
    async fn header_algorithm_of_the_wrong_key_family_is_rejected() {
        // An EC key whose allow-list also (uselessly) names RS256: an RS256 header
        // must not be verified against the EC key, nor panic.
        let key = p256_key();
        let manager = create_test_manager();
        manager
            .register_client(
                ClientJwtConfig::builder("c", key.jwk.clone())
                    .algorithms(vec![Algorithm::ES256, Algorithm::RS256])
                    .audience(TOKEN_ENDPOINT)
                    .build(),
            )
            .await
            .unwrap();
        let rsa = rsa_key();
        assert_rejected(
            &manager,
            &sign(&rsa, Algorithm::RS256, &claims("c", "j1")),
            "RS256 token against an EC key",
        )
        .await;
        // The EC key still works.
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "j2")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    // ----- claims -----

    async fn assert_claim_rejected(mutate: impl FnOnce(&mut Value), why: &str) {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let mut c = claims("c", "j1");
        mutate(&mut c);
        assert_rejected(&manager, &sign(&key, Algorithm::ES256, &c), why).await;
    }

    #[tokio::test]
    async fn audience_must_be_a_configured_token_endpoint() {
        assert_claim_rejected(
            |c| c["aud"] = json!("https://evil.example/token"),
            "foreign aud",
        )
        .await;
        // The earlier code required aud == client_id; that is not a token endpoint.
        assert_claim_rejected(|c| c["aud"] = json!("c"), "aud = client_id").await;
        assert_claim_rejected(
            |c| {
                c.as_object_mut().unwrap().remove("aud");
            },
            "no aud",
        )
        .await;
    }

    #[tokio::test]
    async fn any_configured_audience_is_accepted() {
        let key = p256_key();
        let manager = create_test_manager();
        manager
            .register_client(
                ClientJwtConfig::builder("c", key.jwk.clone())
                    .algorithms(vec![Algorithm::ES256])
                    .audiences([TOKEN_ENDPOINT, "https://auth.example.com/par"])
                    .build(),
            )
            .await
            .unwrap();
        let mut c = claims("c", "j1");
        c["aud"] = json!("https://auth.example.com/par");
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &c))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn issuer_and_subject_must_both_be_the_client() {
        assert_claim_rejected(|c| c["sub"] = json!("someone-else"), "sub != iss").await;
        assert_claim_rejected(
            |c| {
                c.as_object_mut().unwrap().remove("sub");
            },
            "no sub",
        )
        .await;
    }

    #[tokio::test]
    async fn assertion_for_an_unregistered_client_is_rejected() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let errors = assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &claims("other", "j1")),
            "unregistered client",
        )
        .await;
        assert_eq!(errors, vec![GENERIC_REJECTION.to_string()]);
    }

    #[tokio::test]
    async fn assertion_must_name_a_registered_client_not_borrow_anothers_key() {
        // Two clients, two keys: client b's assertion signed with a's key but claiming b.
        let (ka, kb) = (p256_key(), p256_key());
        let manager = create_test_manager();
        manager.register_client(config("a", &ka)).await.unwrap();
        manager.register_client(config("b", &kb)).await.unwrap();
        assert_rejected(
            &manager,
            &sign(&ka, Algorithm::ES256, &claims("b", "j1")),
            "a's key used to claim b",
        )
        .await;
    }

    #[tokio::test]
    async fn expired_not_yet_valid_and_overlong_assertions_are_rejected() {
        let now = Utc::now().timestamp();
        assert_claim_rejected(
            |c| {
                c["exp"] = json!(now - 3600);
                c["iat"] = json!(now - 3700);
                c["nbf"] = json!(now - 3700);
            },
            "expired",
        )
        .await;
        assert_claim_rejected(|c| c["nbf"] = json!(now + 3600), "nbf in the future").await;
        assert_claim_rejected(|c| c["iat"] = json!(now + 3600), "iat in the future").await;
        assert_claim_rejected(
            |c| c["exp"] = json!(now + 86_400),
            "lifetime far above the maximum",
        )
        .await;
        assert_claim_rejected(
            |c| {
                c.as_object_mut().unwrap().remove("exp");
            },
            "no exp",
        )
        .await;
    }

    #[tokio::test]
    async fn jti_is_required() {
        assert_claim_rejected(|c| c["jti"] = json!(""), "empty jti").await;
        assert_claim_rejected(|c| c["jti"] = json!("   "), "blank jti").await;
        assert_claim_rejected(
            |c| {
                c.as_object_mut().unwrap().remove("jti");
            },
            "no jti",
        )
        .await;
    }

    // ----- replay and revocation -----

    #[tokio::test]
    async fn an_assertion_cannot_be_replayed() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let assertion = sign(&key, Algorithm::ES256, &claims("c", "once"));
        assert!(
            manager
                .authenticate_client(&assertion)
                .await
                .unwrap()
                .authenticated
        );
        let second = manager.authenticate_client(&assertion).await.unwrap();
        assert!(!second.authenticated);
        assert!(
            second.errors.iter().any(|e| e.contains("replay")),
            "{:?}",
            second.errors
        );
    }

    #[tokio::test]
    async fn jtis_are_scoped_to_the_client() {
        let (ka, kb) = (p256_key(), p256_key());
        let manager = create_test_manager();
        manager.register_client(config("a", &ka)).await.unwrap();
        manager.register_client(config("b", &kb)).await.unwrap();
        for (client, key) in [("a", &ka), ("b", &kb)] {
            let result = manager
                .authenticate_client(&sign(key, Algorithm::ES256, &claims(client, "shared-jti")))
                .await
                .unwrap();
            assert!(result.authenticated, "{client}: {:?}", result.errors);
        }
    }

    #[tokio::test]
    async fn a_rejected_assertion_does_not_consume_its_jti() {
        let (key, attacker) = (p256_key(), p256_key());
        let manager = registered("c", &key).await;
        assert_rejected(
            &manager,
            &sign(&attacker, Algorithm::ES256, &claims("c", "burn")),
            "forged",
        )
        .await;
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "burn")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn an_assertion_that_fails_a_later_check_does_not_consume_its_jti() {
        // Validly signed, but its lifetime is above the maximum: refused after verification.
        let key = p256_key();
        let manager = registered("c", &key).await;
        let mut too_long = claims("c", "kept");
        too_long["exp"] = json!(Utc::now().timestamp() + 86_400);
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &too_long),
            "lifetime",
        )
        .await;
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "kept")))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn concurrent_presentations_of_one_assertion_succeed_exactly_once() {
        let key = p256_key();
        let manager = Arc::new(registered("c", &key).await);
        let assertion = Arc::new(sign(&key, Algorithm::ES256, &claims("c", "race")));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (manager, assertion) = (manager.clone(), assertion.clone());
            tasks.push(tokio::spawn(async move {
                manager
                    .authenticate_client(&assertion)
                    .await
                    .unwrap()
                    .authenticated
            }));
        }
        let mut successes = 0;
        for task in tasks {
            if task.await.unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
    }

    #[tokio::test]
    async fn a_revoked_jti_is_rejected() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        manager.revoke_jwt_token("revoked").unwrap();
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &claims("c", "revoked")),
            "revoked jti",
        )
        .await;
    }

    // ----- registration -----

    #[tokio::test]
    async fn registration_refuses_symmetric_algorithms() {
        let key = p256_key();
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let manager = create_test_manager();
            let cfg = ClientJwtConfig::builder("c", key.jwk.clone())
                .algorithms(vec![Algorithm::ES256, alg])
                .audience(TOKEN_ENDPOINT)
                .build();
            assert!(manager.register_client(cfg).await.is_err(), "{alg:?}");
        }
    }

    #[tokio::test]
    async fn an_audience_is_optional_by_default_and_required_on_request() {
        let key = p256_key();

        // Default (patch-release compatible): a client without an audience registers, and its
        // signature is still verified; any `aud` value is then accepted.
        let lenient = create_test_manager();
        let none = ClientJwtConfig::builder("c", key.jwk.clone())
            .algorithms(vec![Algorithm::ES256])
            .build();
        lenient.register_client(none).await.unwrap();
        let ok = lenient
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "no-aud-1")))
            .await
            .unwrap();
        assert!(ok.authenticated, "{:?}", ok.errors);
        // ... but the signature is still checked: another key's assertion is refused.
        let other = p256_key();
        let forged = lenient
            .authenticate_client(&sign(&other, Algorithm::ES256, &claims("c", "no-aud-2")))
            .await
            .unwrap();
        assert!(!forged.authenticated);

        // Opt in: no audience, no registration.
        let strict = create_test_manager().require_audiences(true);
        let none = ClientJwtConfig::builder("c", key.jwk.clone()).build();
        assert!(strict.register_client(none).await.is_err());

        // A blank audience is refused either way.
        for manager in [
            create_test_manager(),
            create_test_manager().require_audiences(true),
        ] {
            let blank = ClientJwtConfig::builder("c", key.jwk.clone())
                .audience("  ")
                .build();
            assert!(manager.register_client(blank).await.is_err());
        }
    }

    #[tokio::test]
    async fn registration_refuses_private_or_symmetric_key_material() {
        let manager = create_test_manager();
        for member in ["d", "p", "q", "dp", "dq", "qi", "k"] {
            let mut jwk = p256_key().jwk;
            jwk[member] = json!("AQAB");
            let cfg = ClientJwtConfig::builder("c", jwk)
                .audience(TOKEN_ENDPOINT)
                .build();
            assert!(manager.register_client(cfg).await.is_err(), "{member}");
        }
        let oct = json!({"kty": "oct", "k": "c2VjcmV0"});
        let cfg = ClientJwtConfig::builder("c", oct)
            .audience(TOKEN_ENDPOINT)
            .build();
        assert!(manager.register_client(cfg).await.is_err());
    }

    #[tokio::test]
    async fn registration_refuses_unusable_keys() {
        let manager = create_test_manager();
        let good = p256_key().jwk;

        let mut cases: Vec<(&str, Value)> = vec![
            ("empty object", json!({})),
            ("not an object", json!("RSA")),
            ("unknown kty", json!({"kty": "XYZ"})),
            (
                "P-521 has no supported algorithm",
                json!({"kty": "EC", "crv": "P-521", "x": good["x"], "y": good["y"]}),
            ),
            (
                "short EC coordinate",
                json!({"kty": "EC", "crv": "P-256", "x": b64(&[1u8; 8]), "y": good["y"]}),
            ),
            (
                "bad base64",
                json!({"kty": "EC", "crv": "P-256", "x": "***", "y": good["y"]}),
            ),
            ("wrong use", {
                let mut j = good.clone();
                j["use"] = json!("enc");
                j
            }),
            (
                "1024-bit RSA",
                json!({"kty": "RSA", "n": b64(&[0xC3u8; 128]), "e": "AQAB"}),
            ),
            (
                "empty RSA modulus",
                json!({"kty": "RSA", "n": "", "e": "AQAB"}),
            ),
        ];
        let rsa = rsa_key().jwk;
        cases.push((
            "RSA exponent 1",
            json!({"kty": "RSA", "n": rsa["n"], "e": "AQ"}),
        ));
        cases.push((
            "RSA zero exponent",
            json!({"kty": "RSA", "n": rsa["n"], "e": "AA"}),
        ));
        cases.push((
            "RSA even exponent",
            json!({"kty": "RSA", "n": rsa["n"], "e": "BA"}),
        ));
        for (name, jwk) in cases {
            let cfg = ClientJwtConfig::builder("c", jwk)
                .audience(TOKEN_ENDPOINT)
                .build();
            assert!(manager.register_client(cfg).await.is_err(), "{name}");
        }
    }

    #[tokio::test]
    async fn registration_requires_an_algorithm_that_fits_the_key() {
        let manager = create_test_manager();
        let cfg = ClientJwtConfig::builder("c", p256_key().jwk)
            .algorithms(vec![Algorithm::RS256])
            .audience(TOKEN_ENDPOINT)
            .build();
        assert!(manager.register_client(cfg).await.is_err());
        let cfg = ClientJwtConfig::builder("c", p256_key().jwk)
            .algorithms(vec![])
            .audience(TOKEN_ENDPOINT)
            .build();
        assert!(manager.register_client(cfg).await.is_err());
        let cfg = ClientJwtConfig::builder("  ", p256_key().jwk)
            .audience(TOKEN_ENDPOINT)
            .build();
        assert!(manager.register_client(cfg).await.is_err());
    }

    #[tokio::test]
    async fn registration_refuses_nonsensical_time_settings() {
        let key = p256_key();
        let manager = create_test_manager();
        let negative_skew = ClientJwtConfig::builder("c", key.jwk.clone())
            .audience(TOKEN_ENDPOINT)
            .clock_skew(Duration::seconds(-5))
            .build();
        assert!(manager.register_client(negative_skew).await.is_err());
        let zero_lifetime = ClientJwtConfig::builder("c", key.jwk.clone())
            .audience(TOKEN_ENDPOINT)
            .max_jwt_lifetime(Duration::zero())
            .build();
        assert!(manager.register_client(zero_lifetime).await.is_err());
    }

    // ----- client-side helper and housekeeping (unchanged behaviour) -----

    #[test]
    fn test_create_client_assertion() {
        let manager = create_test_manager();

        // HS256 uses a raw secret.
        let assertion = manager
            .create_client_assertion(
                "test_client",
                "https://auth.example.com/token",
                b"super-secret-key-for-testing-purposes",
                Algorithm::HS256,
            )
            .unwrap();

        // Should have JWT format: header.payload.signature
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Each part must be non-empty (real base64url)
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn test_create_client_assertion_rejects_a_key_that_does_not_fit_the_algorithm() {
        // Key bytes that are not a PEM key of the algorithm's family are refused, never
        // silently signed under a different declared `alg`.
        let manager = create_test_manager();
        for algorithm in [Algorithm::ES256, Algorithm::RS256, Algorithm::EdDSA] {
            let result = manager.create_client_assertion(
                "test_client",
                "https://auth.example.com/token",
                b"super-secret-key-for-testing-purposes",
                algorithm,
            );
            assert!(
                result.is_err(),
                "{algorithm:?}: a key/algorithm mismatch must be rejected, not silently signed"
            );
        }
    }

    #[tokio::test]
    async fn a_client_built_assertion_authenticates() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let assertion = manager
            .create_client_assertion("c", TOKEN_ENDPOINT, key.pem.as_bytes(), Algorithm::ES256)
            .unwrap();
        let result = manager.authenticate_client(&assertion).await.unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
    }

    #[tokio::test]
    async fn test_jti_replay_protection() {
        let manager = create_test_manager();

        // First use is allowed, the second is not.
        assert!(
            manager
                .claim_jti(
                    "c",
                    "test_jti_123",
                    in_an_hour(),
                    DEFAULT_MAX_OUTSTANDING_ASSERTIONS
                )
                .await
                .is_ok()
        );
        assert!(
            manager
                .claim_jti(
                    "c",
                    "test_jti_123",
                    in_an_hour(),
                    DEFAULT_MAX_OUTSTANDING_ASSERTIONS
                )
                .await
                .is_err()
        );
        // Another client may use the same value.
        assert!(
            manager
                .claim_jti(
                    "d",
                    "test_jti_123",
                    in_an_hour(),
                    DEFAULT_MAX_OUTSTANDING_ASSERTIONS
                )
                .await
                .is_ok()
        );
    }

    #[test]
    fn test_jwt_timing_validation() {
        let manager = create_test_manager();
        let config = ClientJwtConfig::default();
        let mut errors = Vec::new();

        let now = Utc::now().timestamp();

        // Test expired JWT
        let expired_claims = PrivateKeyJwtClaims {
            iss: "test".to_string(),
            sub: "test".to_string(),
            aud: "test".to_string(),
            jti: "test".to_string(),
            exp: now - 3600, // Expired 1 hour ago
            iat: now - 3660,
            nbf: Some(now - 3660),
        };

        manager.validate_jwt_timing(&expired_claims, &config, &mut errors);
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("expired")));
    }

    #[tokio::test]
    async fn test_cleanup_expired_jtis() {
        let manager = create_test_manager();

        manager
            .claim_jti(
                "c",
                "old_jti",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        manager
            .claim_jti(
                "c",
                "new_jti",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();

        // Manually set old timestamp
        {
            let mut jtis = manager.used_jtis.write().await;
            jtis.insert(
                PrivateKeyJwtManager::jti_key("c", "old_jti"),
                Utc::now() - Duration::days(2),
            );
        }

        // Cleanup should remove old JTI
        manager.cleanup_expired_jtis().await;

        let jtis = manager.used_jtis.read().await;
        assert!(!jtis.contains_key(&PrivateKeyJwtManager::jti_key("c", "old_jti")));
        assert!(jtis.contains_key(&PrivateKeyJwtManager::jti_key("c", "new_jti")));
    }

    #[test]
    fn test_client_jwt_config_builder() {
        let config = ClientJwtConfig::builder("builder_client", p256_key().jwk)
            .algorithms(vec![Algorithm::RS256])
            .max_jwt_lifetime(Duration::minutes(10))
            .clock_skew(Duration::seconds(30))
            .audiences([
                "https://auth.example.com/token",
                "https://auth.example.com/par",
            ])
            .build();

        assert_eq!(config.client_id, "builder_client");
        assert_eq!(config.allowed_algorithms, vec![Algorithm::RS256]);
        assert_eq!(config.max_jwt_lifetime, Duration::minutes(10));
        assert_eq!(config.clock_skew, Duration::seconds(30));
        assert_eq!(config.expected_audiences.len(), 2);
    }

    #[test]
    fn test_cleanup_interval_configuration() {
        let jwt_config = crate::security::secure_jwt::SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config);
        let manager =
            PrivateKeyJwtManager::new(jwt_validator).with_cleanup_interval(Duration::minutes(30));

        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(30));
    }

    #[test]
    fn test_cleanup_interval_update() {
        let mut manager = create_test_manager();

        // Check default value
        assert_eq!(manager.get_cleanup_interval(), Duration::hours(1));

        // Update cleanup interval
        manager.update_cleanup_interval(Duration::minutes(15));
        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(15));
    }

    #[tokio::test]
    async fn test_jwt_token_revocation_integration() {
        let manager = create_test_manager();

        let jti = "test_revoke_jti_456";

        // Token should not be revoked initially
        let is_revoked_before = manager.is_jwt_token_revoked(jti).unwrap_or(false);
        assert!(!is_revoked_before);

        // Revoke the token
        manager.revoke_jwt_token(jti).unwrap();

        // Token should now be revoked
        let is_revoked_after = manager.is_jwt_token_revoked(jti).unwrap_or(false);
        assert!(is_revoked_after);
    }

    #[tokio::test]
    async fn test_scheduled_cleanup_integration() {
        let mut manager = create_test_manager();

        // Set a shorter cleanup interval for testing
        manager.update_cleanup_interval(Duration::minutes(1));

        // Add some test JTIs and revoked tokens
        manager
            .claim_jti(
                "c",
                "test_jti_1",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        manager.revoke_jwt_token("revoked_jti_1").unwrap();

        // Run scheduled cleanup
        manager.schedule_automatic_cleanup().await;

        // Verify cleanup was executed (this mainly tests that the method runs without errors)
        assert_eq!(manager.get_cleanup_interval(), Duration::minutes(1));
    }

    #[tokio::test]
    async fn test_cleanup_interval_used_in_cleanup_method() {
        let mut manager = create_test_manager();

        // Set custom cleanup interval
        manager.update_cleanup_interval(Duration::minutes(30));

        manager
            .claim_jti(
                "c",
                "recent_jti",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        manager
            .claim_jti(
                "c",
                "old_jti",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();

        // Manually set timestamps to test cleanup interval usage
        {
            let mut jtis = manager.used_jtis.write().await;
            jtis.insert(
                PrivateKeyJwtManager::jti_key("c", "recent_jti"),
                Utc::now() + Duration::minutes(15), // deadline still ahead: kept
            );
            jtis.insert(
                PrivateKeyJwtManager::jti_key("c", "old_jti"),
                Utc::now() - Duration::minutes(45), // deadline passed: dropped
            );
        }

        // Run cleanup - should remove old_jti but keep recent_jti
        manager.cleanup_expired_jtis().await;

        let jtis = manager.used_jtis.read().await;
        assert!(
            jtis.contains_key(&PrivateKeyJwtManager::jti_key("c", "recent_jti")),
            "Recent JTI should be retained"
        );
        assert!(
            !jtis.contains_key(&PrivateKeyJwtManager::jti_key("c", "old_jti")),
            "Old JTI should be removed"
        );
    }

    // ----- review round -----

    fn in_an_hour() -> DateTime<Utc> {
        Utc::now() + Duration::hours(1)
    }

    #[tokio::test]
    async fn unknown_clients_and_unproven_assertions_get_the_same_answer() {
        let (key, attacker) = (p256_key(), p256_key());
        let manager = registered("c", &key).await;

        let unknown = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("nobody", "j1")))
            .await
            .unwrap();
        let forged = manager
            .authenticate_client(&sign(&attacker, Algorithm::ES256, &claims("c", "j2")))
            .await
            .unwrap();
        let wrong_alg = manager
            .authenticate_client(&sign(&rsa_key(), Algorithm::RS256, &claims("c", "j3")))
            .await;
        for result in [&unknown, &forged] {
            assert!(!result.authenticated);
            assert_eq!(result.errors, vec![GENERIC_REJECTION.to_string()]);
            assert!(result.claims.is_none() && result.jti.is_none());
        }
        // A disallowed algorithm is not told apart from a bad signature either.
        let result = wrong_alg.unwrap();
        assert_eq!(result.errors, vec![GENERIC_REJECTION.to_string()]);
    }

    #[tokio::test]
    async fn reasons_are_given_only_once_the_key_has_vouched_for_the_assertion() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let reasons = |claims: Value| {
            let manager = &manager;
            let key = &key;
            async move {
                manager
                    .authenticate_client(&sign(key, Algorithm::ES256, &claims))
                    .await
                    .unwrap()
                    .errors
                    .join("; ")
                    .to_lowercase()
            }
        };
        let mut wrong_aud = claims("c", "r1");
        wrong_aud["aud"] = json!("https://evil.example/token");
        assert!(reasons(wrong_aud).await.contains("audience"));
        let mut expired = claims("c", "r2");
        let now = Utc::now().timestamp();
        expired["exp"] = json!(now - 3600);
        expired["iat"] = json!(now - 3700);
        expired["nbf"] = json!(now - 3700);
        assert!(reasons(expired).await.contains("expired"));
        let mut other_sub = claims("c", "r3");
        other_sub["sub"] = json!("someone-else");
        assert!(reasons(other_sub).await.contains("subject"));
        // None of those messages says anything about "signature".
        let mut blank_jti = claims("c", "r4");
        blank_jti["jti"] = json!(" ");
        assert!(!reasons(blank_jti).await.contains("signature"));
    }

    #[tokio::test]
    async fn the_key_family_check_rejects_a_header_that_does_not_fit_the_key() {
        let manager = create_test_manager();
        let (p256, p384, rsa) = (p256_key(), p384_key(), rsa_key());
        let everything = vec![
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::RS256,
            Algorithm::EdDSA,
        ];
        let config_for = |key: &TestKey| {
            ClientJwtConfig::builder("c", key.jwk.clone())
                .algorithms(everything.clone())
                .audience(TOKEN_ENDPOINT)
                .build()
        };
        // (key registered, algorithm in the header)
        for (key, algorithm) in [
            (&p384, Algorithm::ES256),
            (&p256, Algorithm::ES384),
            (&p256, Algorithm::RS256),
            (&rsa, Algorithm::ES256),
            (&p384, Algorithm::EdDSA),
        ] {
            let config = config_for(key);
            let outcome = manager.verify_jwt_signature("a.b.c", &Header::new(algorithm), &config);
            match outcome {
                Err(Rejection::Unproven(reason)) => assert!(
                    reason.contains("does not match"),
                    "{algorithm:?} against {:?}: {reason}",
                    key.algorithm
                ),
                other => panic!(
                    "{algorithm:?} against a {:?} key must be refused by the family check, got {}",
                    key.algorithm,
                    match other {
                        Ok(_) => "success".to_string(),
                        Err(Rejection::Unproven(r)) | Err(Rejection::Proven(r)) => r,
                    }
                ),
            }
        }
    }

    #[tokio::test]
    async fn aud_may_be_an_array_with_one_configured_audience() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let mut listed = claims("c", "a1");
        listed["aud"] = json!(["https://other.example", TOKEN_ENDPOINT]);
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &listed))
            .await
            .unwrap();
        assert!(result.authenticated, "{:?}", result.errors);
        assert_eq!(result.claims.unwrap().aud, TOKEN_ENDPOINT);

        let mut foreign = claims("c", "a2");
        foreign["aud"] = json!(["https://other.example", "https://more.example"]);
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &foreign),
            "no configured audience",
        )
        .await;
        let mut prefix = claims("c", "a3");
        prefix["aud"] = json!([format!("{TOKEN_ENDPOINT}/extra")]);
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &prefix),
            "audience is not a prefix match",
        )
        .await;
        let mut empty = claims("c", "a4");
        empty["aud"] = json!([]);
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &empty),
            "empty audience array",
        )
        .await;
    }

    #[tokio::test]
    async fn cleanup_cannot_reopen_the_replay_window() {
        let key = p256_key();
        let mut manager = registered("c", &key).await;
        // An interval far shorter than the assertion's remaining life.
        manager.update_cleanup_interval(Duration::milliseconds(1));
        let assertion = sign(&key, Algorithm::ES256, &claims("c", "window"));
        assert!(
            manager
                .authenticate_client(&assertion)
                .await
                .unwrap()
                .authenticated
        );
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        manager.cleanup_expired_jtis().await;
        manager.schedule_automatic_cleanup().await;
        let replay = manager.authenticate_client(&assertion).await.unwrap();
        assert!(!replay.authenticated, "replayed after cleanup");

        // The entry goes once its own deadline (exp + skew) has passed.
        {
            let mut jtis = manager.used_jtis.write().await;
            for deadline in jtis.values_mut() {
                *deadline = Utc::now() - Duration::seconds(1);
            }
        }
        manager.cleanup_expired_jtis().await;
        assert!(manager.used_jtis.read().await.is_empty());
    }

    #[tokio::test]
    async fn a_revoked_jti_is_not_forgotten_while_an_assertion_could_still_use_it() {
        let key = p256_key();
        let mut manager = registered("c", &key).await;
        manager.update_cleanup_interval(Duration::milliseconds(1));
        manager.revoke_jwt_token("revoked-early").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        manager.schedule_automatic_cleanup().await;
        assert!(manager.is_jwt_token_revoked("revoked-early").unwrap());
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &claims("c", "revoked-early")),
            "revocation outlived by cleanup",
        )
        .await;
    }

    #[tokio::test]
    async fn extreme_timestamps_are_refused_without_overflow() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let cases = [
            (i64::MIN + 1000, i64::MAX - 1000),
            (i64::MIN, i64::MAX),
            (0, i64::MAX),
            (i64::MAX, i64::MIN),
            (i64::MAX - 5, i64::MAX),
        ];
        for (n, (iat, exp)) in cases.into_iter().enumerate() {
            let mut c = claims("c", &format!("big{n}"));
            c["iat"] = json!(iat);
            c["exp"] = json!(exp);
            c["nbf"] = json!(iat);
            assert_rejected(
                &manager,
                &sign(&key, Algorithm::ES256, &c),
                &format!("{iat}..{exp}"),
            )
            .await;
        }
        // The timing check itself, called directly with the extremes.
        let mut errors = Vec::new();
        let config = ClientJwtConfig::default();
        let extreme = PrivateKeyJwtClaims {
            iss: "c".into(),
            sub: "c".into(),
            aud: "a".into(),
            jti: "j".into(),
            exp: i64::MAX - 1000,
            iat: i64::MIN + 1000,
            nbf: Some(i64::MIN),
        };
        manager.validate_jwt_timing(&extreme, &config, &mut errors);
        assert!(!errors.is_empty());
    }

    #[tokio::test]
    async fn client_ids_cannot_be_used_to_collide_jti_keys() {
        let manager = create_test_manager();
        let key = p256_key();
        for bad in ["a\0b", "line\nbreak", "tab\there", &"x".repeat(257)] {
            let cfg = ClientJwtConfig::builder(bad, key.jwk.clone())
                .audience(TOKEN_ENDPOINT)
                .build();
            assert!(manager.register_client(cfg).await.is_err(), "{bad:?}");
        }
        // Even if such ids existed, their (client, jti) keys do not collide.
        manager
            .claim_jti(
                "a",
                "b\0c",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        manager
            .claim_jti(
                "a\0b",
                "c",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn registration_bounds_the_clock_skew_and_lifetime() {
        let manager = create_test_manager();
        let key = p256_key();
        let build = |skew, lifetime| {
            ClientJwtConfig::builder("c", key.jwk.clone())
                .audience(TOKEN_ENDPOINT)
                .clock_skew(skew)
                .max_jwt_lifetime(lifetime)
                .build()
        };
        assert!(
            manager
                .register_client(build(Duration::minutes(11), Duration::minutes(5)))
                .await
                .is_err()
        );
        assert!(
            manager
                .register_client(build(Duration::seconds(60), Duration::hours(25)))
                .await
                .is_err()
        );
        manager
            .register_client(build(Duration::minutes(10), Duration::hours(24)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oversized_assertions_and_jtis_are_refused() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        // Genuinely signed and otherwise valid, but padded past the size limit.
        let mut padded = claims("c", "padded");
        padded["pad"] = json!("x".repeat(9000));
        let huge = sign(&key, Algorithm::ES256, &padded);
        assert!(huge.len() > MAX_ASSERTION_BYTES);
        assert!(manager.authenticate_client(&huge).await.is_err());
        // The same assertion within the limit is fine.
        let mut small = claims("c", "not-padded");
        small["pad"] = json!("x".repeat(100));
        assert!(
            manager
                .authenticate_client(&sign(&key, Algorithm::ES256, &small))
                .await
                .unwrap()
                .authenticated
        );

        let mut long_jti = claims("c", &"j".repeat(300));
        long_jti["jti"] = json!("j".repeat(300));
        let result = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &long_jti))
            .await
            .unwrap();
        assert!(!result.authenticated);
        assert!(
            result.errors.join(";").contains("JTI"),
            "{:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn the_replay_map_is_bounded() {
        let manager = create_test_manager();
        // Expired entries are swept as the map grows.
        {
            let mut jtis = manager.used_jtis.write().await;
            for i in 0..2000 {
                jtis.insert(format!("old{i}"), Utc::now() - Duration::hours(1));
            }
        }
        manager
            .claim_jti(
                "c",
                "fresh",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        assert!(manager.used_jtis.read().await.len() < 10);

        // A map full of live entries refuses more rather than growing.
        {
            let mut jtis = manager.used_jtis.write().await;
            for i in 0..MAX_TRACKED_JTIS {
                jtis.insert(format!("live{i}"), in_an_hour());
            }
        }
        assert!(
            manager
                .claim_jti(
                    "c",
                    "one-too-many",
                    in_an_hour(),
                    DEFAULT_MAX_OUTSTANDING_ASSERTIONS
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_assertion_that_is_not_a_jwt_is_an_error_not_a_verdict() {
        let manager = create_test_manager();
        for junk in ["", "a.b", "not a jwt", "a.b.c"] {
            assert!(manager.authenticate_client(junk).await.is_err(), "{junk:?}");
        }
    }

    // ----- review round 3 -----

    #[tokio::test]
    async fn one_client_cannot_use_up_the_room_of_the_others() {
        let manager = create_test_manager();
        let hour = in_an_hour();
        for i in 0..3 {
            manager
                .claim_jti("a", &format!("j{i}"), hour, 3)
                .await
                .unwrap();
        }
        assert!(manager.claim_jti("a", "j3", hour, 3).await.is_err());
        // Another client is untouched, and so is a's quota once its entries expire.
        manager.claim_jti("b", "j0", hour, 3).await.unwrap();
        {
            let mut jtis = manager.used_jtis.write().await;
            for deadline in jtis.values_mut() {
                *deadline = Utc::now() - Duration::seconds(1);
            }
        }
        manager.cleanup_expired_jtis().await;
        manager.claim_jti("a", "j3", hour, 3).await.unwrap();
    }

    #[tokio::test]
    async fn the_quota_applies_to_real_assertions_and_is_per_client() {
        let (ka, kb) = (p256_key(), p256_key());
        let manager = create_test_manager().with_max_outstanding_assertions(2);
        manager
            .register_client(
                ClientJwtConfig::builder("a", ka.jwk.clone())
                    .algorithms(vec![Algorithm::ES256])
                    .audience(TOKEN_ENDPOINT)
                    .build(),
            )
            .await
            .unwrap();
        manager.register_client(config("b", &kb)).await.unwrap();
        for i in 0..2 {
            let r = manager
                .authenticate_client(&sign(&ka, Algorithm::ES256, &claims("a", &format!("q{i}"))))
                .await
                .unwrap();
            assert!(r.authenticated, "{:?}", r.errors);
        }
        let third = assert_rejected(
            &manager,
            &sign(&ka, Algorithm::ES256, &claims("a", "q2")),
            "third outstanding assertion",
        )
        .await;
        assert!(third.join(";").contains("Too many"), "{third:?}");
        assert!(
            manager
                .authenticate_client(&sign(&kb, Algorithm::ES256, &claims("b", "q0")))
                .await
                .unwrap()
                .authenticated
        );
    }

    #[tokio::test]
    async fn the_sweep_is_throttled() {
        let manager = create_test_manager();
        let old = || Utc::now() - Duration::hours(1);
        let fill = |n: usize| {
            let manager = &manager;
            async move {
                let mut jtis = manager.used_jtis.write().await;
                for i in 0..n {
                    jtis.insert(format!("old{i}"), old());
                }
            }
        };
        fill(2000).await;
        manager
            .claim_jti(
                "c",
                "first",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        assert!(
            manager.used_jtis.read().await.len() < 10,
            "first claim sweeps"
        );

        // Right after a sweep, a large map of expired entries is left alone...
        fill(2000).await;
        manager
            .claim_jti(
                "c",
                "second",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        assert!(
            manager.used_jtis.read().await.len() >= 2000,
            "no second full scan so soon"
        );

        // ...until the interval has passed.
        manager.used_jtis.write().await.last_sweep =
            Some(Utc::now() - Duration::seconds(JTI_SWEEP_INTERVAL_SECS + 1));
        manager
            .claim_jti(
                "c",
                "third",
                in_an_hour(),
                DEFAULT_MAX_OUTSTANDING_ASSERTIONS,
            )
            .await
            .unwrap();
        assert!(manager.used_jtis.read().await.len() < 10);
    }

    #[tokio::test]
    async fn iat_is_optional_and_expiry_is_then_bounded_directly() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let now = Utc::now().timestamp();
        let without_iat = |jti: &str, exp: i64| {
            let mut c = claims("c", jti);
            c.as_object_mut().unwrap().remove("iat");
            c["exp"] = json!(exp);
            sign(&key, Algorithm::ES256, &c)
        };
        let ok = manager
            .authenticate_client(&without_iat("n1", now + 120))
            .await
            .unwrap();
        assert!(ok.authenticated, "{:?}", ok.errors);
        assert_eq!(ok.claims.unwrap().iat, 0);

        let far = assert_rejected(
            &manager,
            &without_iat("n2", now + 3600),
            "exp far ahead, no iat",
        )
        .await;
        assert!(far.join(";").contains("further ahead"), "{far:?}");
        assert_rejected(&manager, &without_iat("n3", now - 3600), "expired, no iat").await;
        // With iat the old rule still applies.
        let mut long = claims("c", "n4");
        long["exp"] = json!(now + 3600);
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &long),
            "lifetime from iat",
        )
        .await;
    }

    #[tokio::test]
    async fn malformed_claims_do_not_echo_the_parser() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        let mut wrong_type = claims("c", "w1");
        wrong_type["jti"] = json!(12345);
        let mut missing = claims("c", "w2");
        missing.as_object_mut().unwrap().remove("jti");
        for c in [wrong_type, missing] {
            let errors = assert_rejected(
                &manager,
                &sign(&key, Algorithm::ES256, &c),
                "bad claim shape",
            )
            .await;
            let text = errors.join(";");
            assert_eq!(text, "Invalid assertion claims", "{text}");
        }
    }

    #[tokio::test]
    async fn assertion_jtis_have_their_own_revocation_namespace() {
        let key = p256_key();
        let manager = registered("c", &key).await;
        // An access-token jti revoked in the shared validator does not block an assertion...
        manager.jwt_validator.revoke_token("shared-name").unwrap();
        let r = manager
            .authenticate_client(&sign(&key, Algorithm::ES256, &claims("c", "shared-name")))
            .await
            .unwrap();
        assert!(r.authenticated, "{:?}", r.errors);
        // ...and revoking an assertion jti does not revoke an access token of that name.
        manager.revoke_jwt_token("other-name").unwrap();
        assert!(manager.is_jwt_token_revoked("other-name").unwrap());
        assert!(
            !manager
                .jwt_validator
                .is_token_revoked("other-name")
                .unwrap()
        );
        assert_rejected(
            &manager,
            &sign(&key, Algorithm::ES256, &claims("c", "other-name")),
            "revoked assertion jti",
        )
        .await;
    }
}
