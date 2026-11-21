// SPDX-License-Identifier: MIT OR Apache-2.0
// test_infrastructure.rs - Bulletproof test isolation and container infrastructure

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Environment variable isolation for tests.
///
/// # Example
/// ```rust,ignore
/// let mut env = TestEnvironment::new();
/// env.set_var("MY_VAR", "value");
/// // Variable is restored on drop.
/// ```
pub struct TestEnvironment {
    original_vars: HashMap<String, Option<OsString>>,
    test_vars: HashMap<String, String>,
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnvironment {
    /// Create a new isolated test environment.
    ///
    /// # Example
    /// ```rust,ignore
    /// let env = TestEnvironment::new();
    /// ```
    pub fn new() -> Self {
        Self {
            original_vars: HashMap::new(),
            test_vars: HashMap::new(),
        }
    }

    /// Set an environment variable for this test only.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut env = TestEnvironment::new();
    /// env.set_var("DATABASE_URL", "postgres://localhost/test");
    /// ```
    pub fn set_var(&mut self, key: &str, value: &str) {
        // Store original value for restoration
        if !self.original_vars.contains_key(key) {
            self.original_vars.insert(key.to_string(), env::var_os(key));
        }

        // Set the test value
        self.test_vars.insert(key.to_string(), value.to_string());
        // SAFETY: Callers must hold the ENV_LOCK (via TestEnvironmentGuard) to
        // serialize all env-var mutations, preventing data races with other threads.
        unsafe {
            env::set_var(key, value);
        }
    }

    /// Set the standard JWT_SECRET for tests.
    ///
    /// # Example
    /// ```rust,ignore
    /// let env = TestEnvironment::new().with_jwt_secret("test-secret");
    /// ```
    pub fn with_jwt_secret(mut self, secret: &str) -> Self {
        self.set_var("JWT_SECRET", secret);
        self
    }

    /// Set database URL for integration tests.
    ///
    /// # Example
    /// ```rust,ignore
    /// let env = TestEnvironment::new().with_database_url("postgres://localhost/test");
    /// ```
    pub fn with_database_url(mut self, url: &str) -> Self {
        self.set_var("DATABASE_URL", url);
        self
    }

    /// Set Redis URL for session tests.
    ///
    /// # Example
    /// ```rust,ignore
    /// let env = TestEnvironment::new().with_redis_url("redis://localhost");
    /// ```
    pub fn with_redis_url(mut self, url: &str) -> Self {
        self.set_var("REDIS_URL", url);
        self
    }
}

impl Drop for TestEnvironment {
    /// Restore all environment variables to their original state
    fn drop(&mut self) {
        for (key, original_value) in &self.original_vars {
            // SAFETY: Callers hold the ENV_LOCK (via TestEnvironmentGuard) which
            // serializes all env-var mutations, preventing data races.
            unsafe {
                match original_value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

/// Serializes all tests that mutate process-global environment variables.
/// A `'static`-lifetime mutex is used so the `MutexGuard` can live in the struct.
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// RAII guard for test environment isolation.
///
/// Acquires a process-wide mutex before touching any environment variable,
/// so parallel test threads cannot race each other when setting/restoring
/// `JWT_SECRET`, `RUST_TEST`, etc.
///
/// # Example
/// ```rust,ignore
/// let _env = TestEnvironmentGuard::new().with_jwt_secret("test-secret");
/// // Environment is restored when `_env` is dropped.
/// ```
pub struct TestEnvironmentGuard {
    /// Env-var state saved for restoration on drop. Drops FIRST (declaration order).
    _env: TestEnvironment,
    /// Serialization lock. Drops SECOND, releasing the mutex AFTER env vars are restored.
    _lock: MutexGuard<'static, ()>,
}

impl Default for TestEnvironmentGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnvironmentGuard {
    pub fn new() -> Self {
        // Acquire the serialization lock BEFORE touching any env var.
        // This prevents parallel tests from interleaving set/restore operations
        // on shared process-global environment variables (e.g. JWT_SECRET).
        // The guard is held for the entire lifetime of `TestEnvironmentGuard`.
        let _lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            // If a previous test panicked while holding the lock the mutex is "poisoned".
            // Recover the inner value so tests can still run cleanly.
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut env = TestEnvironment::new();
        // Signal to the library that we are running in a test environment.
        // This allows `is_test_environment()` in config validation to relax
        // checks that would otherwise reject test-only secrets (e.g. short secrets).
        env.set_var("RUST_TEST", "1");
        Self { _env: env, _lock }
    }

    pub fn with_jwt_secret(mut self, secret: &str) -> Self {
        self._env.set_var("JWT_SECRET", secret);
        self
    }

    pub fn with_database_url(mut self, url: &str) -> Self {
        self._env.set_var("DATABASE_URL", url);
        self
    }

    pub fn with_redis_url(mut self, url: &str) -> Self {
        self._env.set_var("REDIS_URL", url);
        self
    }

    pub fn with_custom_var(mut self, key: &str, value: &str) -> Self {
        self._env.set_var(key, value);
        self
    }
}

/// Container-based test infrastructure for complex integration tests
#[cfg(feature = "docker-tests")]
pub mod containers {
    // use std::collections::HashMap; // Currently unused
    use testcontainers::{ContainerAsync, GenericImage, ImageExt, runners::AsyncRunner};

    pub struct TestDatabase {
        _container: ContainerAsync<GenericImage>,
        connection_string: String,
    }

    impl TestDatabase {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let postgres_image = GenericImage::new("postgres", "14")
                .with_env_var("POSTGRES_DB", "auth_test")
                .with_env_var("POSTGRES_USER", "test_user")
                .with_env_var("POSTGRES_PASSWORD", "test_password");

            let container = postgres_image.start().await?;
            let port = container.get_host_port_ipv4(5432).await?;

            let connection_string = format!(
                "postgresql://test_user:test_password@localhost:{}/auth_test",
                port
            );

            Ok(Self {
                _container: container,
                connection_string,
            })
        }

        pub fn connection_string(&self) -> &str {
            &self.connection_string
        }
    }

    pub struct TestRedis {
        _container: ContainerAsync<GenericImage>,
        connection_string: String,
    }

    impl TestRedis {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let redis_image = GenericImage::new("redis", "7-alpine");

            let container = redis_image.start().await?;
            let port = container.get_host_port_ipv4(6379).await?;

            let connection_string = format!("redis://localhost:{}", port);

            Ok(Self {
                _container: container,
                connection_string,
            })
        }

        pub fn connection_string(&self) -> &str {
            &self.connection_string
        }
    }

    /// Complete isolated test environment with containers
    pub struct ContainerTestEnvironment {
        pub database: TestDatabase,
        pub redis: TestRedis,
        pub env_guard: super::TestEnvironmentGuard,
    }

    impl ContainerTestEnvironment {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let database = TestDatabase::new().await?;
            let redis = TestRedis::new().await?;

            let env_guard = super::TestEnvironmentGuard::new()
                .with_jwt_secret("test-jwt-secret-for-container-tests")
                .with_database_url(database.connection_string())
                .with_redis_url(redis.connection_string());

            Ok(Self {
                database,
                redis,
                env_guard,
            })
        }
    }
}

/// Test utilities for creating secure test data
pub mod test_data {
    use crate::storage::SessionData;
    use crate::tokens::AuthToken;
    use chrono::Utc;
    use ring::rand::{SecureRandom, SystemRandom};

    /// Generate cryptographically secure test data.
    ///
    /// # Example
    /// ```rust,ignore
    /// let token = test_data::secure_test_token("user-1");
    /// assert_eq!(token.user_id, "user-1");
    /// ```
    pub fn secure_test_token(user_id: &str) -> AuthToken {
        let rng = SystemRandom::new();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes)
            .expect("Failed to generate secure random token");

        let token_id = hex::encode(token_bytes);
        let access_token = hex::encode(&token_bytes[..16]);

        AuthToken {
            token_id,
            user_id: user_id.to_string(),
            access_token,
            token_type: Some("bearer".to_string()),
            subject: Some(user_id.to_string()),
            issuer: Some("auth-framework-test".to_string()),
            refresh_token: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(3600),
            scopes: vec!["read".to_string(), "write".to_string()].into(),
            auth_method: "test".to_string(),
            client_id: Some("test-client".to_string()),
            user_profile: None,
            permissions: vec!["read:all".to_string(), "write:all".to_string()].into(),
            roles: vec!["test_user".to_string()].into(),
            metadata: crate::tokens::TokenMetadata::default(),
        }
    }

    /// Generate secure test session.
    ///
    /// # Example
    /// ```rust,ignore
    /// let session = test_data::secure_test_session("user-1");
    /// assert_eq!(session.user_id, "user-1");
    /// ```
    pub fn secure_test_session(user_id: &str) -> SessionData {
        let rng = SystemRandom::new();
        let mut session_bytes = [0u8; 32];
        rng.fill(&mut session_bytes)
            .expect("Failed to generate secure random session");

        let session_id = hex::encode(session_bytes);

        SessionData {
            session_id,
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(7200),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test Agent".to_string()),
            data: std::collections::HashMap::new(),
        }
    }

    /// Generate secure random string for testing.
    ///
    /// # Example
    /// ```rust,ignore
    /// let s = test_data::secure_random_string(16);
    /// assert_eq!(s.len(), 32); // hex-encoded, so 2x input length
    /// ```
    pub fn secure_random_string(length: usize) -> String {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; length];
        rng.fill(&mut bytes)
            .expect("Failed to generate secure random bytes");
        hex::encode(bytes)
    }
}

/// Macros for simplified test environment setup
#[macro_export]
macro_rules! test_with_env {
    ($test_name:ident, $jwt_secret:expr, $body:block) => {
        #[tokio::test]
        async fn $test_name() {
            let _env = $crate::test_infrastructure::TestEnvironmentGuard::new()
                .with_jwt_secret($jwt_secret);
            $body
        }
    };
}

#[macro_export]
macro_rules! test_with_containers {
    ($test_name:ident, $body:block) => {
        #[cfg(feature = "docker-tests")]
        #[tokio::test]
        async fn $test_name() {
            let _test_env =
                $crate::test_infrastructure::containers::ContainerTestEnvironment::new()
                    .expect("Failed to setup container test environment");
            $body
        }
    };
}

/// Ensure only one test that modifies global state runs at a time.
///
/// Reuses the same `ENV_LOCK` mutex that `TestEnvironmentGuard` uses,
/// so explicit calls to this helper compose correctly with the guard.
pub fn with_global_lock<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_isolation() {
        // Ensure environment variables are properly isolated
        let original_value = env::var("TEST_VAR").ok();

        {
            let mut test_env = TestEnvironment::new();
            test_env.set_var("TEST_VAR", "test_value");
            assert_eq!(env::var("TEST_VAR").unwrap(), "test_value");
        }

        // Variable should be restored
        assert_eq!(env::var("TEST_VAR").ok(), original_value);
    }

    #[test]
    fn test_environment_guard() {
        // Use a variable name that is unique to this test so parallel tests do not interfere.
        // JWT_SECRET is used by many tests concurrently, making it an unsuitable choice.
        const TEST_KEY: &str = "AUTH_FW_GUARD_ISOLATION_TEST_ONLY";

        // Ensure the var is absent before we start
        // SAFETY: This test runs in isolation; no concurrent env-var access.
        unsafe { env::remove_var(TEST_KEY) };
        assert!(
            env::var(TEST_KEY).is_err(),
            "TEST_KEY should not exist before test"
        );

        {
            let _guard = TestEnvironmentGuard::new().with_custom_var(TEST_KEY, "isolated-value");
            assert_eq!(env::var(TEST_KEY).unwrap(), "isolated-value");
        }

        // Variable should be removed (restored to None) after guard is dropped
        assert!(
            env::var(TEST_KEY).is_err(),
            "TEST_KEY should be absent after guard is dropped"
        );
    }

    #[test]
    fn test_secure_test_data_generation() {
        let token1 = test_data::secure_test_token("user1");
        let token2 = test_data::secure_test_token("user1");

        // Tokens should be different even for same user
        assert_ne!(token1.token_id, token2.token_id);

        // But should have same user_id
        assert_eq!(token1.user_id, token2.user_id);
    }

    #[test]
    fn test_secure_random_generation() {
        let str1 = test_data::secure_random_string(32);
        let str2 = test_data::secure_random_string(32);

        assert_ne!(str1, str2);
        assert_eq!(str1.len(), 64); // hex encoding doubles the length
        assert_eq!(str2.len(), 64);
    }
}
