use crate::errors::{AuthError, Result};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureJwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub typ: String,
    pub sid: Option<String>,
    pub client_id: Option<String>,
    pub auth_ctx_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecureJwtConfig {
    pub allowed_algorithms: Vec<Algorithm>,
    pub required_issuers: HashSet<String>,
    pub required_audiences: HashSet<String>,
    pub max_token_lifetime: Duration,
    pub clock_skew: Duration,
    pub require_jti: bool,
    pub validate_nbf: bool,
    pub allowed_token_types: HashSet<String>,
    pub require_secure_transport: bool,
    /// HMAC secret for HS256/HS384/HS512
    pub jwt_secret: String,
    /// PEM-encoded RSA public key for RS256/RS384/RS512/PS256/PS384/PS512
    pub rsa_public_key_pem: Option<String>,
    /// PEM-encoded EC public key for ES256/ES384
    pub ec_public_key_pem: Option<String>,
    /// PEM-encoded Ed25519 public key for EdDSA
    pub ed_public_key_pem: Option<String>,
}

impl Default for SecureJwtConfig {
    fn default() -> Self {
        // Generate a fresh cryptographically random secret for each instance so that
        // no default-constructed config ever carries a publicly-known key.
        //
        // Callers that need a stable, shared secret (e.g. multi-node clusters that
        // must validate each other's tokens) must set `jwt_secret` explicitly after
        // construction.
        use ring::rand::{SecureRandom, SystemRandom};
        // SAFETY: CSPRNG failure at initialization is terminal; the framework
        // cannot operate without entropy.
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .expect("AuthFramework fatal: system CSPRNG unavailable â€” the operating system cannot provide cryptographic randomness");
        let jwt_secret = bytes.iter().fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });

        let mut allowed_token_types = HashSet::new();
        allowed_token_types.insert("access".to_string());
        allowed_token_types.insert("refresh".to_string());
        allowed_token_types.insert("JARM".to_string());

        let mut required_issuers = HashSet::new();
        required_issuers.insert("auth-framework".to_string());

        Self {
            // Only advertise algorithms for which key material is actually present.
            // Asymmetric algorithms require their corresponding PEM fields to be set;
            // they are excluded from the default to prevent misconfiguration.
            allowed_algorithms: vec![Algorithm::HS256],
            required_issuers,
            required_audiences: HashSet::new(),
            max_token_lifetime: Duration::from_secs(3600),
            clock_skew: Duration::from_secs(30),
            require_jti: true,
            validate_nbf: true,
            allowed_token_types,
            require_secure_transport: true,
            jwt_secret,
            rsa_public_key_pem: None,
            ec_public_key_pem: None,
            ed_public_key_pem: None,
        }
    }
}

/// Returns `true` if the algorithm belongs to the HMAC (symmetric) family.
fn is_hmac_algorithm(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

/// Validates JWT tokens with configurable algorithm support and in-memory revocation.
///
/// # Revocation Architecture
///
/// `SecureJwtValidator` maintains an **in-memory** revocation list (`HashMap<JTI, SystemTime>`)
/// protected by a `Mutex`. This list is **lost on process restart** and is intended as a
/// supplementary fast-path cache â€” not as a durable revocation store.
///
/// For production deployments, durable revocation should be handled by the storage-backed
/// layer in the API module (see `src/api/auth.rs`), which persists revoked JTIs in the
/// configured KV / database backend.
///
/// To bridge both layers, callers can register an optional `on_revoke` callback via
/// [`SecureJwtValidator::set_on_revoke`]. When set, every call to [`revoke_token`] will
/// first insert into the in-memory map and then invoke the callback with the JTI string,
/// allowing the caller to persist the revocation to external storage without changing the
/// existing API surface.
///
/// # Size Limits
///
/// [`cleanup_revoked_tokens`] enforces a hard cap of 10 000 entries and time-based eviction
/// to prevent unbounded memory growth.
impl SecureJwtConfig {
    /// Create a new builder with secure default configurations.
    pub fn builder() -> SecureJwtConfigBuilder {
        SecureJwtConfigBuilder::default()
    }
}

/// A builder for SecureJwtConfig
#[derive(Default)]
pub struct SecureJwtConfigBuilder {
    config: SecureJwtConfig,
}

impl SecureJwtConfigBuilder {
    /// Allow a specific JSON Web Signature algorithm
    pub fn with_algorithm(mut self, algo: Algorithm) -> Self {
        self.config.allowed_algorithms.push(algo);
        self
    }

    /// Set the allowed algorithms, replacing any existing
    pub fn with_algorithms(mut self, algos: Vec<Algorithm>) -> Self {
        self.config.allowed_algorithms = algos;
        self
    }

    /// Require a specific issuer string
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config.required_issuers.insert(issuer.into());
        self
    }

    /// Require a specific audience string
    pub fn require_audience(mut self, audience: impl Into<String>) -> Self {
        self.config.required_audiences.insert(audience.into());
        self
    }

    /// Set the maximum allowed lifetime of a token before it is rejected
    pub fn with_max_lifetime(mut self, lifetime: Duration) -> Self {
        self.config.max_token_lifetime = lifetime;
        self
    }

    /// Set the allowed clock skew when evaluating timestamps
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.config.clock_skew = skew;
        self
    }

    /// Set whether a JWT ID (jti) claim is required
    pub fn require_jti(mut self, require: bool) -> Self {
        self.config.require_jti = require;
        self
    }

    /// Set the HMAC signing secret (required for symmetric signing operations)
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.config.jwt_secret = secret.into();
        self
    }

    /// Build the SecureJwtConfig
    pub fn build(self) -> SecureJwtConfig {
        self.config
    }
}

pub struct SecureJwtValidator {
    config: SecureJwtConfig,
    /// Maps JTI â†’ insertion timestamp so we can evict by age in `cleanup_revoked_tokens`.
    ///
    /// **In-memory only** â€” entries do not survive process restarts. See the struct-level
    /// documentation for the recommended dual-layer revocation approach.
    revoked_tokens: std::sync::Mutex<std::collections::HashMap<String, std::time::SystemTime>>,
    /// Optional callback invoked with the JTI string each time a token is revoked.
    ///
    /// Use [`set_on_revoke`] to register a closure that persists the revocation to durable
    /// storage (database, KV store, etc.). The callback is invoked **after** the in-memory
    /// insertion succeeds.
    on_revoke: std::sync::Mutex<Option<RevokeCallback>>,
}

/// Callback invoked with a JTI string when a token is revoked.
type RevokeCallback = Box<dyn Fn(&str) + Send + Sync>;

impl std::fmt::Debug for SecureJwtValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureJwtValidator")
            .field("config", &self.config)
            .field("revoked_tokens", &self.revoked_tokens)
            .field(
                "on_revoke",
                &self.on_revoke.lock().ok().map(|g| g.is_some()),
            )
            .finish()
    }
}

impl SecureJwtValidator {
    pub fn new(config: SecureJwtConfig) -> Result<Self> {
        // Validate that every allowed algorithm has the required key material.
        let has_hmac = config
            .allowed_algorithms
            .iter()
            .any(|a| is_hmac_algorithm(*a));
        let has_rsa = config.allowed_algorithms.iter().any(|a| {
            matches!(
                a,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            )
        });
        let has_ec = config
            .allowed_algorithms
            .iter()
            .any(|a| matches!(a, Algorithm::ES256 | Algorithm::ES384));
        let has_eddsa = config
            .allowed_algorithms
            .iter()
            .any(|a| matches!(a, Algorithm::EdDSA));

        if has_hmac {
            #[cfg(not(test))]
            if config.jwt_secret.len() < 32 {
                return Err(AuthError::Configuration {
                    message: "SecureJwtConfig::jwt_secret must be at least 32 characters \
                              when HMAC algorithms are enabled"
                        .to_string(),
                    help: Some(
                        "Provide a cryptographically random secret unique to your deployment"
                            .to_string(),
                    ),
                    docs_url: None,
                    source: None,
                    suggested_fix: None,
                });
            }
        }
        if has_rsa && config.rsa_public_key_pem.is_none() {
            return Err(AuthError::Configuration {
                message: "SecureJwtConfig::rsa_public_key_pem must be set when RSA/PS algorithms are enabled".to_string(),
                help: Some("Set rsa_public_key_pem in SecureJwtConfig".to_string()),
                docs_url: None,
                source: None,
                suggested_fix: None,
            });
        }
        if has_ec && config.ec_public_key_pem.is_none() {
            return Err(AuthError::Configuration {
                message:
                    "SecureJwtConfig::ec_public_key_pem must be set when EC algorithms are enabled"
                        .to_string(),
                help: Some("Set ec_public_key_pem in SecureJwtConfig".to_string()),
                docs_url: None,
                source: None,
                suggested_fix: None,
            });
        }
        if has_eddsa && config.ed_public_key_pem.is_none() {
            return Err(AuthError::Configuration {
                message: "SecureJwtConfig::ed_public_key_pem must be set when EdDSA is enabled"
                    .to_string(),
                help: Some("Set ed_public_key_pem in SecureJwtConfig".to_string()),
                docs_url: None,
                source: None,
                suggested_fix: None,
            });
        }

        Ok(Self {
            config,
            revoked_tokens: std::sync::Mutex::new(std::collections::HashMap::new()),
            on_revoke: std::sync::Mutex::new(None),
        })
    }

    /// Register an optional callback that is invoked with the JTI every time
    /// [`revoke_token`] is called.
    ///
    /// This allows callers to persist revocations to durable storage (database,
    /// KV store, etc.) without changing the existing validation or revocation API.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// validator.set_on_revoke(|jti| {
    ///     // Persist to your storage backend
    ///     storage.insert_revoked_jti(jti);
    /// });
    /// ```
    pub fn set_on_revoke<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let mut guard = match self.on_revoke.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(Box::new(callback));
    }

    /// Get HMAC decoding key for backward-compatible call sites.
    ///
    /// Prefer `validate` which handles key selection automatically.
    pub fn get_decoding_key(&self) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_secret(self.config.jwt_secret.as_bytes())
    }

    /// Get HMAC encoding key for signing JWTs.
    pub fn get_encoding_key(&self) -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_secret(self.config.jwt_secret.as_bytes())
    }

    /// Select the appropriate [`DecodingKey`] for the given algorithm.
    fn decoding_key_for_algorithm(&self, alg: Algorithm) -> Result<DecodingKey> {
        match alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Ok(DecodingKey::from_secret(self.config.jwt_secret.as_bytes()))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                let pem = self.config.rsa_public_key_pem.as_deref().ok_or_else(|| {
                    AuthError::Configuration {
                        message: "RSA public key PEM not configured".to_string(),
                        help: Some(
                            "Set rsa_public_key_pem in SecureJwtConfig for RSA/PS algorithms"
                                .to_string(),
                        ),
                        docs_url: None,
                        source: None,
                        suggested_fix: None,
                    }
                })?;
                DecodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| AuthError::Configuration {
                    message: format!("Invalid RSA public key PEM: {e}"),
                    help: None,
                    docs_url: None,
                    source: None,
                    suggested_fix: None,
                })
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let pem = self.config.ec_public_key_pem.as_deref().ok_or_else(|| {
                    AuthError::Configuration {
                        message: "EC public key PEM not configured".to_string(),
                        help: Some(
                            "Set ec_public_key_pem in SecureJwtConfig for EC algorithms"
                                .to_string(),
                        ),
                        docs_url: None,
                        source: None,
                        suggested_fix: None,
                    }
                })?;
                DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| AuthError::Configuration {
                    message: format!("Invalid EC public key PEM: {e}"),
                    help: None,
                    docs_url: None,
                    source: None,
                    suggested_fix: None,
                })
            }
            Algorithm::EdDSA => {
                let pem = self.config.ed_public_key_pem.as_deref().ok_or_else(|| {
                    AuthError::Configuration {
                        message: "Ed25519 public key PEM not configured".to_string(),
                        help: Some(
                            "Set ed_public_key_pem in SecureJwtConfig for EdDSA".to_string(),
                        ),
                        docs_url: None,
                        source: None,
                        suggested_fix: None,
                    }
                })?;
                DecodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| AuthError::Configuration {
                    message: format!("Invalid Ed25519 public key PEM: {e}"),
                    help: None,
                    docs_url: None,
                    source: None,
                    suggested_fix: None,
                })
            }
        }
    }

    /// Validate a JWT, automatically selecting the key based on the token header algorithm.
    ///
    /// This is the preferred entry point. It:
    /// 1. Decodes the JWT header to determine the claimed algorithm.
    /// 2. Rejects the token immediately if the algorithm is not in `allowed_algorithms`.
    /// 3. Selects the correct decoding key for the algorithm family.
    /// 4. Validates the signature **and** all standard claims (exp, nbf, iss, aud).
    /// 5. Performs additional checks: revocation, max lifetime, JTI presence, token type.
    pub fn validate(&self, token: &str) -> Result<SecureJwtClaims> {
        // 1. Decode header (no signature verification yet).
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthError::Unauthorized(format!("Invalid JWT header: {e}")))?;

        // 2. Reject algorithms not in the configured allow-list.
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::Unauthorized(format!(
                "Token algorithm {:?} is not permitted; allowed: {:?}",
                header.alg, self.config.allowed_algorithms
            )));
        }

        // 3. Select the decoding key for this algorithm family.
        let decoding_key = self.decoding_key_for_algorithm(header.alg)?;

        // 4. Build validation rules â€” delegate standard claim checks to jsonwebtoken.
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.algorithms = self.config.allowed_algorithms.clone();
        validation.leeway = self.config.clock_skew.as_secs();

        // Expiration: always enforced.
        validation.validate_exp = true;

        // Not-before: honour config.
        validation.validate_nbf = self.config.validate_nbf;

        // Audience: enforce if the config specifies required audiences.
        if !self.config.required_audiences.is_empty() {
            validation.set_audience(
                &self
                    .config
                    .required_audiences
                    .iter()
                    .collect::<Vec<&String>>(),
            );
        } else {
            validation.validate_aud = false;
        }

        // Issuer: enforce if the config specifies required issuers.
        if !self.config.required_issuers.is_empty() {
            validation.set_issuer(
                &self
                    .config
                    .required_issuers
                    .iter()
                    .collect::<Vec<&String>>(),
            );
        }

        // 5. Decode & verify signature + standard claims.
        let token_data = jsonwebtoken::decode::<SecureJwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::Unauthorized(format!("JWT validation failed: {e}")))?;

        let claims = token_data.claims;

        // 6. Additional custom validations.

        // Revocation check.
        if self.is_token_revoked(&claims.jti)? {
            return Err(AuthError::Unauthorized("Token is revoked".to_string()));
        }

        // Max token lifetime.
        let token_lifetime = claims.exp.saturating_sub(claims.iat);
        if token_lifetime > 0 && (token_lifetime as u64) > self.config.max_token_lifetime.as_secs()
        {
            return Err(AuthError::Unauthorized(format!(
                "Token lifetime ({token_lifetime}s) exceeds maximum allowed ({}s)",
                self.config.max_token_lifetime.as_secs()
            )));
        }

        // JTI presence.
        if self.config.require_jti && claims.jti.is_empty() {
            return Err(AuthError::Unauthorized(
                "Token missing required JTI claim".to_string(),
            ));
        }

        // Token type restriction.
        if !self.config.allowed_token_types.is_empty()
            && !claims.typ.is_empty()
            && !self.config.allowed_token_types.contains(&claims.typ)
        {
            return Err(AuthError::Unauthorized(format!(
                "Token type '{}' is not permitted",
                claims.typ
            )));
        }

        Ok(claims)
    }

    /// Legacy validation entry point that accepts a caller-supplied decoding key.
    ///
    /// Prefer [`validate`] which handles algorithm checking and key selection internally.
    /// This method still enforces the full allow-list and all claim checks.
    pub fn validate_token(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
    ) -> Result<SecureJwtClaims> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthError::Unauthorized(format!("Invalid JWT header: {e}")))?;

        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::Unauthorized(format!(
                "Token algorithm {:?} is not permitted; allowed: {:?}",
                header.alg, self.config.allowed_algorithms
            )));
        }

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.algorithms = self.config.allowed_algorithms.clone();
        validation.leeway = self.config.clock_skew.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = self.config.validate_nbf;

        if !self.config.required_audiences.is_empty() {
            validation.set_audience(
                &self
                    .config
                    .required_audiences
                    .iter()
                    .collect::<Vec<&String>>(),
            );
        } else {
            validation.validate_aud = false;
        }

        if !self.config.required_issuers.is_empty() {
            validation.set_issuer(
                &self
                    .config
                    .required_issuers
                    .iter()
                    .collect::<Vec<&String>>(),
            );
        }

        let token_data = jsonwebtoken::decode::<SecureJwtClaims>(token, decoding_key, &validation)
            .map_err(|e| AuthError::Unauthorized(format!("JWT validation failed: {e}")))?;

        let claims = token_data.claims;

        if self.is_token_revoked(&claims.jti)? {
            return Err(AuthError::Unauthorized("Token is revoked".to_string()));
        }

        let token_lifetime = claims.exp.saturating_sub(claims.iat);
        if token_lifetime > 0 && (token_lifetime as u64) > self.config.max_token_lifetime.as_secs()
        {
            return Err(AuthError::Unauthorized(format!(
                "Token lifetime ({token_lifetime}s) exceeds maximum allowed ({}s)",
                self.config.max_token_lifetime.as_secs()
            )));
        }

        if self.config.require_jti && claims.jti.is_empty() {
            return Err(AuthError::Unauthorized(
                "Token missing required JTI claim".to_string(),
            ));
        }

        if !self.config.allowed_token_types.is_empty()
            && !claims.typ.is_empty()
            && !self.config.allowed_token_types.contains(&claims.typ)
        {
            return Err(AuthError::Unauthorized(format!(
                "Token type '{}' is not permitted",
                claims.typ
            )));
        }

        Ok(claims)
    }

    /// Check whether `jti` appears in the **in-memory** revocation list.
    ///
    /// This only consults the local cache. For a complete revocation check that
    /// also queries durable storage, combine this with the storage-backed lookup
    /// in the API layer (`src/api/auth.rs`).
    pub fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        let revoked_tokens = self.revoked_tokens.lock().map_err(|_| {
            AuthError::internal("Lock poisoned â€” a prior thread panicked while holding this lock")
        })?;
        Ok(revoked_tokens.contains_key(jti))
    }

    /// Revoke a token by its JTI.
    ///
    /// The JTI is inserted into the **in-memory** revocation map. If an
    /// [`on_revoke`](Self::set_on_revoke) callback has been registered, it is
    /// invoked with the JTI after the in-memory insertion, allowing durable
    /// persistence without changing this method's signature.
    ///
    /// **Note:** Without a registered `on_revoke` callback, revocations are
    /// volatile and will be lost on process restart.
    pub fn revoke_token(&self, jti: &str) -> Result<()> {
        {
            let mut revoked_tokens = self.revoked_tokens.lock().map_err(|_| {
                AuthError::internal(
                    "Lock poisoned â€” a prior thread panicked while holding this lock",
                )
            })?;
            revoked_tokens.insert(jti.to_string(), std::time::SystemTime::now());
        }
        // Invoke the persistence callback outside the revoked_tokens lock to
        // avoid holding two locks simultaneously.
        if let Some(ref cb) = *self.on_revoke.lock().map_err(|_| {
            AuthError::internal("Lock poisoned â€” a prior thread panicked while holding this lock")
        })? {
            cb(jti);
        }
        Ok(())
    }

    /// Remove revoked token entries that are older than `expired_cutoff`.
    ///
    /// This prevents unbounded memory growth in long-running deployments.  Callers should
    /// pass a cutoff equal to `now âˆ’ max_token_lifetime` so that every entry that could
    /// still be used by a live token is preserved, while entries that can only correspond
    /// to already-expired tokens are discarded.
    ///
    /// An additional size cap (10,000 entries) is enforced after time-based eviction:
    /// if the map still exceeds the cap the oldest 25 % of entries are removed.
    pub fn cleanup_revoked_tokens(&self, expired_cutoff: std::time::SystemTime) -> Result<()> {
        const MAX_REVOKED_TOKENS: usize = 10_000;
        let mut revoked_tokens = self.revoked_tokens.lock().map_err(|_| {
            AuthError::internal("Lock poisoned â€” a prior thread panicked while holding this lock")
        })?;

        // Phase 1: remove entries whose insertion time predates the cutoff â€” these
        // correspond to JWTs that would have expired naturally already.
        revoked_tokens.retain(|_, inserted_at| *inserted_at >= expired_cutoff);

        // Phase 2: hard size cap â€” if phase 1 was not enough (e.g. very short cleanup
        // interval or very long token lifetime), evict the oldest 25 % of remaining entries.
        if revoked_tokens.len() > MAX_REVOKED_TOKENS {
            let target_len = MAX_REVOKED_TOKENS * 3 / 4;
            let mut by_age: Vec<(String, std::time::SystemTime)> = revoked_tokens.drain().collect();
            by_age.sort_unstable_by_key(|(_, t)| *t);
            // Re-insert only the newest entries.
            for (jti, inserted_at) in by_age.into_iter().rev().take(target_len) {
                revoked_tokens.insert(jti, inserted_at);
            }
            tracing::warn!(
                "Revoked token list exceeded {} entries; oldest entries were evicted.",
                MAX_REVOKED_TOKENS
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    fn test_config() -> SecureJwtConfig {
        SecureJwtConfig {
            jwt_secret: "a]test_secret_that_is_longer_than_32_chars_for_security!".to_string(),
            ..SecureJwtConfig::default()
        }
    }

    fn issue_token(config: &SecureJwtConfig, claims: &SecureJwtClaims) -> String {
        let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), claims, &key).unwrap()
    }

    fn valid_claims() -> SecureJwtClaims {
        let now = chrono::Utc::now().timestamp();
        SecureJwtClaims {
            sub: "user123".to_string(),
            iss: "auth-framework".to_string(),
            aud: "test".to_string(),
            exp: now + 600,
            nbf: now - 10,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: "read".to_string(),
            typ: "access".to_string(),
            sid: None,
            client_id: None,
            auth_ctx_hash: None,
        }
    }

    #[test]
    fn test_default_config_generates_random_secret() {
        let c1 = SecureJwtConfig::default();
        let c2 = SecureJwtConfig::default();
        assert_ne!(c1.jwt_secret, c2.jwt_secret);
        assert!(c1.jwt_secret.len() >= 32);
    }

    #[test]
    fn test_builder_fluent_api() {
        let config = SecureJwtConfig::builder()
            .with_secret("a]test_secret_that_is_longer_than_32_chars_for_security!")
            .require_issuer("my-issuer")
            .require_audience("my-aud")
            .with_max_lifetime(Duration::from_secs(7200))
            .with_clock_skew(Duration::from_secs(60))
            .require_jti(false)
            .build();

        assert!(config.required_issuers.contains("my-issuer"));
        assert!(config.required_audiences.contains("my-aud"));
        assert_eq!(config.max_token_lifetime, Duration::from_secs(7200));
        assert_eq!(config.clock_skew, Duration::from_secs(60));
        assert!(!config.require_jti);
    }

    #[test]
    fn test_validate_valid_token() {
        let config = test_config();
        let claims = valid_claims();
        let token = issue_token(&config, &claims);
        let validator = SecureJwtValidator::new(config).unwrap();
        let result = validator.validate(&token).unwrap();
        assert_eq!(result.sub, "user123");
        assert_eq!(result.iss, "auth-framework");
    }

    #[test]
    fn test_validate_rejects_expired_token() {
        let config = test_config();
        let mut claims = valid_claims();
        claims.exp = chrono::Utc::now().timestamp() - 3600;
        claims.iat = claims.exp - 600;
        let token = issue_token(&config, &claims);
        let validator = SecureJwtValidator::new(config).unwrap();
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_issuer() {
        let config = test_config();
        let mut claims = valid_claims();
        claims.iss = "evil-issuer".to_string();
        let token = issue_token(&config, &claims);
        let validator = SecureJwtValidator::new(config).unwrap();
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_revoke_and_check() {
        let config = test_config();
        let validator = SecureJwtValidator::new(config).unwrap();
        let jti = "test-jti-123";
        assert!(!validator.is_token_revoked(jti).unwrap());
        validator.revoke_token(jti).unwrap();
        assert!(validator.is_token_revoked(jti).unwrap());
    }

    #[test]
    fn test_revoked_token_rejected() {
        let config = test_config();
        let claims = valid_claims();
        let jti = claims.jti.clone();
        let token = issue_token(&config, &claims);
        let validator = SecureJwtValidator::new(config).unwrap();
        validator.revoke_token(&jti).unwrap();
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let config = test_config();
        let validator = SecureJwtValidator::new(config).unwrap();
        validator.revoke_token("old-jti").unwrap();
        // Cleanup with a cutoff in the future removes everything
        let future = std::time::SystemTime::now() + Duration::from_secs(3600);
        validator.cleanup_revoked_tokens(future).unwrap();
        assert!(!validator.is_token_revoked("old-jti").unwrap());
    }

    #[test]
    fn test_on_revoke_callback() {
        let config = test_config();
        let validator = SecureJwtValidator::new(config).unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        validator.set_on_revoke(move |jti| {
            captured_clone.lock().unwrap().push(jti.to_string());
        });
        validator.revoke_token("cb-jti-1").unwrap();
        validator.revoke_token("cb-jti-2").unwrap();
        let jtis = captured.lock().unwrap();
        assert_eq!(jtis.len(), 2);
        assert!(jtis.contains(&"cb-jti-1".to_string()));
        assert!(jtis.contains(&"cb-jti-2".to_string()));
    }

    #[test]
    fn test_rejects_disallowed_algorithm() {
        let config = test_config();
        let claims = valid_claims();
        // Sign with HS384 but config only allows HS256
        let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let token = jsonwebtoken::encode(&Header::new(Algorithm::HS384), &claims, &key).unwrap();
        let validator = SecureJwtValidator::new(config).unwrap();
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_rejects_excessive_lifetime() {
        let mut config = test_config();
        config.max_token_lifetime = Duration::from_secs(300);
        let mut claims = valid_claims();
        let now = chrono::Utc::now().timestamp();
        claims.iat = now;
        claims.exp = now + 600; // 10 min > 5 min max
        let token = issue_token(&config, &claims);
        let validator = SecureJwtValidator::new(config).unwrap();
        assert!(validator.validate(&token).is_err());
    }

    #[test]
    fn test_missing_rsa_key_rejected() {
        let mut config = test_config();
        config.allowed_algorithms = vec![Algorithm::RS256];
        let result = SecureJwtValidator::new(config);
        assert!(result.is_err());
    }
}
