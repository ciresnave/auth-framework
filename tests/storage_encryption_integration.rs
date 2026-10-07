//! Integration tests proving storage-at-rest encryption is actually wired
//! into `AuthFramework::initialize()`, not just exercised in isolation
//! against `EncryptedStorage` directly (see `src/storage/encryption.rs`'s
//! own unit tests for that).
//!
//! These tests use SQLite (a real, persistent backend) because the point
//! is to prove a REAL backend's on-disk bytes are encrypted -- an
//! in-memory backend has nothing on disk to inspect.

#![cfg(feature = "sqlite-storage")]

use auth_framework::AuthFramework;
use auth_framework::config::{AuthConfig, StorageConfig, StorageEncryptionConfig};
use auth_framework::storage::AuthStorage;
use auth_framework::storage::encryption::StorageEncryption;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Mutex;

/// `AUTH_STORAGE_ENCRYPTION_KEY` is process-global state. Serialize every
/// test in this file so one test's env var doesn't leak into another
/// running concurrently on a different thread.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn sqlite_config(path: &std::path::Path) -> StorageConfig {
    StorageConfig::Sqlite {
        connection_string: format!("sqlite://{}?mode=rwc", path.display()),
    }
}

fn base_config(storage: StorageConfig) -> AuthConfig {
    AuthConfig::new()
        .secret("integration_test_secret_key_at_least_32_chars_long!!".to_string())
        .storage(storage)
}

#[tokio::test]
async fn sqlite_backend_fails_closed_without_a_key() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEY");
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE");
    }

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("fail_closed.db");
    let config = base_config(sqlite_config(&db_path));
    // storage_encryption defaults to enabled.

    let mut framework = AuthFramework::new(config);
    let err = framework.initialize().await.expect_err(
        "initialize() must fail when encryption is on (the default) and no key is \
                      configured, not silently fall back to plaintext storage",
    );
    let message = err.to_string();
    assert!(
        message.contains("no encryption key could be loaded"),
        "error message should name the actual failure (no key loaded), got: {message}"
    );
}

#[tokio::test]
async fn sqlite_backend_succeeds_when_encryption_explicitly_disabled() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEY");
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE");
    }

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("opt_out.db");
    let config = base_config(sqlite_config(&db_path)).storage_encryption(StorageEncryptionConfig {
        enabled: false,
        allow_plaintext_reads: false,
    });

    let mut framework = AuthFramework::new(config);
    framework
        .initialize()
        .await
        .expect("explicit opt-out must start without a key");
}

#[tokio::test]
async fn sqlite_backend_encrypts_kv_values_on_disk_when_enabled() {
    let _guard = ENV_LOCK.lock().unwrap();
    let key = StorageEncryption::generate_key();
    unsafe {
        std::env::set_var("AUTH_STORAGE_ENCRYPTION_KEY", &key);
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE");
    }

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("encrypted.db");
    let config = base_config(sqlite_config(&db_path));

    let mut framework = AuthFramework::new(config);
    framework
        .initialize()
        .await
        .expect("initialize() must succeed once a key is configured");

    let plaintext = b"JBSWY3DPEHPK3PXP-this-is-a-totp-secret";
    framework
        .storage()
        .store_kv("user:alice:totp_secret", plaintext, None)
        .await
        .expect("store_kv should succeed");

    // Read back through the framework: must decrypt transparently.
    let roundtripped = framework
        .storage()
        .get_kv("user:alice:totp_secret")
        .await
        .unwrap();
    assert_eq!(roundtripped, Some(plaintext.to_vec()));

    // Read the RAW on-disk row directly, bypassing AuthFramework/
    // EncryptedStorage entirely, to prove the bytes actually on disk are
    // not the plaintext.
    drop(framework);
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{}?mode=ro", db_path.display()))
        .await
        .unwrap();
    let row: (Vec<u8>,) = sqlx::query_as("SELECT value FROM kv_store WHERE key = ?")
        .bind("user:alice:totp_secret")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_ne!(
        row.0, plaintext,
        "the raw on-disk row must not hold the plaintext TOTP secret"
    );
    assert!(
        StorageEncryption::looks_like_envelope(&row.0),
        "the raw on-disk row must hold a proper encrypted envelope"
    );

    unsafe {
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEY");
    }
}

#[tokio::test]
async fn memory_backend_is_exempt_from_the_key_requirement() {
    let _guard = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEY");
        std::env::remove_var("AUTH_STORAGE_ENCRYPTION_KEYS_FILE");
    }

    // Memory storage holds nothing across a restart, so it is exempt from
    // the fail-closed key requirement even though storage_encryption
    // defaults to enabled.
    let config = base_config(StorageConfig::Memory);
    let mut framework = AuthFramework::new(config);
    framework
        .initialize()
        .await
        .expect("memory storage must not require an encryption key");
}
