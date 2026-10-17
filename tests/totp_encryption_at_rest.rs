//! TOTP secrets can be encrypted at rest under a key the caller supplies.
//!
//! `TotpManager` stores each user's base32 secret as a KV row. Wrapped in `EncryptedStorage`
//! (`TotpManager::new_encrypted` builds the wrapper) the row in the backing store is an AES-256-GCM
//! envelope bound to its own storage key, readable only with a key from the caller's `KeyProvider`.
//!
//! Plain storage stays the default and does not change silently: `TotpManager::new` behaves as
//! before and logs ONE warning at construction when the storage does not encrypt at rest;
//! `TotpManager::new_plaintext` is the explicit, silent opt-in.

use auth_framework::auth_modular::mfa::totp::TotpManager;
use auth_framework::errors::Result;
use auth_framework::storage::encryption::{
    KeyProvider, LoadedKeys, MigrationOptions, StorageEncryption,
};
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A caller-supplied key source: fixed 32-byte keys by id, one of them current.
struct Keys {
    current: String,
    keys: HashMap<String, [u8; 32]>,
}

impl Keys {
    fn one(id: &str, byte: u8) -> Self {
        Self::many(id, &[(id, byte)])
    }
    fn many(current: &str, keys: &[(&str, u8)]) -> Self {
        Self {
            current: current.to_string(),
            keys: keys
                .iter()
                .map(|(id, byte)| (id.to_string(), [*byte; 32]))
                .collect(),
        }
    }
}

impl KeyProvider for Keys {
    fn load_keys(&self) -> Result<LoadedKeys> {
        Ok(LoadedKeys {
            current_key_id: self.current.clone(),
            keys: self.keys.clone(),
        })
    }
}

fn options() -> MigrationOptions {
    let mut options = MigrationOptions::default();
    options.accept_ttl_loss = true;
    options
}

fn dry_options() -> MigrationOptions {
    let mut options = options();
    options.dry_run = true;
    options
}

/// The secret in the clear, as the plain manager enrolls it.
async fn enroll_plain(inner: &Arc<dyn AuthStorage>, user: &str) -> String {
    TotpManager::new_plaintext(inner.clone())
        .generate_secret(user)
        .await
        .unwrap()
}

/// A valid current code for `secret`, produced independently of storage.
async fn code_for(secret: &str) -> String {
    TotpManager::new_plaintext(Arc::new(MemoryStorage::new()))
        .generate_code(secret)
        .await
        .unwrap()
}

async fn raw_row(inner: &Arc<dyn AuthStorage>, key: &str) -> Vec<u8> {
    inner.get_kv(key).await.unwrap().expect("row exists")
}

/// The behaviours that must hold on every backend.
async fn contract(inner: Arc<dyn AuthStorage>) {
    // --- encrypted enrollment: the row at rest is an envelope, not the secret ---
    let provider = Keys::one("k1", 1);
    let totp = TotpManager::new_encrypted(inner.clone(), &provider).unwrap();
    let secret = totp.generate_secret("alice").await.unwrap();
    let row = raw_row(&inner, "user:alice:totp_secret").await;
    assert!(
        StorageEncryption::parse_envelope(&row).is_some(),
        "the stored row is not an envelope"
    );
    assert!(
        !String::from_utf8_lossy(&row).contains(&secret),
        "the secret appears in the stored row"
    );
    // A different key cannot use it. (Checked BEFORE the legitimate verification below, which
    // claims this user's current TOTP window: after that, any further code would be refused as a
    // replay whatever the key, and this check would prove nothing.)
    let other = TotpManager::new_encrypted(inner.clone(), &Keys::one("k1", 2)).unwrap();
    assert!(
        !other
            .verify_code("alice", &code_for(&secret).await)
            .await
            .unwrap()
    );
    // and it works through the manager that holds the key
    assert!(
        totp.verify_code("alice", &code_for(&secret).await)
            .await
            .unwrap()
    );

    // --- a row moved to another user's key does not decrypt there (AAD) ---
    inner
        .store_kv("user:mallory:totp_secret", &row, None)
        .await
        .unwrap();
    assert!(
        !totp
            .verify_code("mallory", &code_for(&secret).await)
            .await
            .unwrap(),
        "an envelope copied to another record's key was accepted"
    );

    // --- migration of existing plain rows touches exactly the two TOTP key shapes ---
    let plain_dave = enroll_plain(&inner, "dave").await; // user:dave:totp_secret
    inner
        .store_kv("mfa_secret:erin", plain_dave.as_bytes(), None)
        .await
        .unwrap();
    inner
        .store_kv("user:frank:profile", b"{\"not\":\"a secret\"}", None)
        .await
        .unwrap();
    let enc = StorageEncryption::new(&provider).unwrap();

    let dry = TotpManager::migrate_plain_secrets(&*inner, &enc, dry_options())
        .await
        .unwrap();
    assert!(dry.dry_run);
    assert_eq!(dry.encrypted, 2, "dry run counts the two plain rows");
    assert_eq!(
        raw_row(&inner, "user:dave:totp_secret").await,
        plain_dave.as_bytes()
    );

    let report = TotpManager::migrate_plain_secrets(&*inner, &enc, options())
        .await
        .unwrap();
    assert_eq!(
        report.encrypted, 2,
        "dave and erin were encrypted: {report:?}"
    );
    assert!(report.failed.is_empty());
    assert!(
        StorageEncryption::parse_envelope(&raw_row(&inner, "user:dave:totp_secret").await)
            .is_some()
    );
    assert!(StorageEncryption::parse_envelope(&raw_row(&inner, "mfa_secret:erin").await).is_some());
    assert_eq!(
        raw_row(&inner, "user:frank:profile").await,
        b"{\"not\":\"a secret\"}",
        "an unrelated user: row was touched"
    );
    // idempotent
    let again = TotpManager::migrate_plain_secrets(&*inner, &enc, options())
        .await
        .unwrap();
    assert_eq!(again.encrypted, 0);
    assert!(again.already_encrypted >= 2);
    // the migrated secret still verifies, through the encrypted manager
    assert!(
        totp.verify_code("dave", &code_for(&plain_dave).await)
            .await
            .unwrap()
    );

    // --- key rotation: rewrap rows still under an old key id ---
    // (the copied-onto-mallory row cannot be decrypted under its new key by design: drop it)
    inner.delete_kv("user:mallory:totp_secret").await.unwrap();
    let gina_secret = totp.generate_secret("gina").await.unwrap(); // under k1, fresh user
    let rotating = Keys::many("k2", &[("k1", 1), ("k2", 3)]);
    let enc2 = StorageEncryption::new(&rotating).unwrap();
    let dry = TotpManager::rewrap_secrets(&*inner, &enc2, true)
        .await
        .unwrap();
    assert!(
        dry.dry_run && dry.rewrapped >= 4,
        "dry run counts the k1 rows: {dry:?}"
    );
    let before = raw_row(&inner, "user:gina:totp_secret").await;
    assert_eq!(
        raw_row(&inner, "user:gina:totp_secret").await,
        before,
        "a dry run wrote"
    );
    let rewrapped = TotpManager::rewrap_secrets(&*inner, &enc2, false)
        .await
        .unwrap();
    assert!(
        rewrapped.rewrapped >= 4 && rewrapped.failed.is_empty(),
        "{rewrapped:?}"
    );
    assert_ne!(
        raw_row(&inner, "user:gina:totp_secret").await,
        before,
        "the row was not rewritten under the new key"
    );
    let second = TotpManager::rewrap_secrets(&*inner, &enc2, false)
        .await
        .unwrap();
    assert_eq!(second.rewrapped, 0, "rewrap is idempotent");
    assert!(second.already_current >= 4);
    // Now only k2 is needed: k1 alone no longer reads the row (checked first, before the
    // legitimate verification claims the TOTP window), and k2 alone does.
    let code = code_for(&gina_secret).await;
    let only_old = TotpManager::new_encrypted(inner.clone(), &Keys::one("k1", 1)).unwrap();
    assert!(!only_old.verify_code("gina", &code).await.unwrap());
    let only_new =
        TotpManager::new_encrypted(inner.clone(), &Keys::many("k2", &[("k2", 3)])).unwrap();
    assert!(only_new.verify_code("gina", &code).await.unwrap());
}

#[tokio::test]
async fn memory_contract() {
    contract(Arc::new(MemoryStorage::new())).await;
}

#[cfg(feature = "sqlite-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_contract() {
    use auth_framework::storage::sqlite::SqliteStorage;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let storage = SqliteStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}

#[cfg(feature = "redis-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_contract() {
    use auth_framework::storage::redis::RedisStorage;
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let prefix = format!("totp_enc_{}:", uuid::Uuid::new_v4().simple());
    let storage = RedisStorage::with_config(&url, prefix, std::time::Duration::from_secs(600))
        .await
        .unwrap();
    contract(Arc::new(storage)).await;
}

#[cfg(feature = "postgres-storage")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_contract() {
    use auth_framework::storage::postgres::PostgresStorage;
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let storage = PostgresStorage::new(pool);
    storage.migrate().await.unwrap();
    contract(Arc::new(storage)).await;
}

// ---------------------------------------------------------------------------------------------
// Plain mode: the default does not change silently, it warns once.
// ---------------------------------------------------------------------------------------------

/// A `tracing` writer that collects everything logged on this thread.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logged_while(f: impl FnOnce()) -> String {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = capture.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).to_string()
}

#[test]
fn new_on_plain_storage_warns_once_at_construction() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let log = logged_while(|| {
        let _ = TotpManager::new(storage.clone());
    });
    assert_eq!(
        log.matches("without encryption at rest").count(),
        1,
        "expected exactly one warning, log was: {log:?}"
    );
}

#[test]
fn new_plaintext_is_the_silent_explicit_opt_in() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let log = logged_while(|| {
        let _ = TotpManager::new_plaintext(storage.clone());
    });
    assert!(log.is_empty(), "new_plaintext logged: {log:?}");
}

#[test]
fn new_encrypted_does_not_warn() {
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let log = logged_while(|| {
        let _ = TotpManager::new_encrypted(storage.clone(), &Keys::one("k1", 1)).unwrap();
    });
    assert!(log.is_empty(), "new_encrypted logged: {log:?}");
}

#[tokio::test]
async fn plain_mode_behaves_as_before() {
    let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let totp = TotpManager::new(inner.clone());
    let secret = totp.generate_secret("alice").await.unwrap();
    assert_eq!(
        raw_row(&inner, "user:alice:totp_secret").await,
        secret.as_bytes()
    );
    assert!(
        totp.verify_code("alice", &code_for(&secret).await)
            .await
            .unwrap()
    );
}

#[test]
fn a_provider_with_no_usable_key_is_an_error_not_plaintext() {
    struct Empty;
    impl KeyProvider for Empty {
        fn load_keys(&self) -> Result<LoadedKeys> {
            Ok(LoadedKeys {
                current_key_id: "missing".to_string(),
                keys: HashMap::new(),
            })
        }
    }
    let storage: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    assert!(TotpManager::new_encrypted(storage, &Empty).is_err());
}

#[test]
fn new_on_storage_that_already_encrypts_does_not_warn() {
    use auth_framework::storage::encryption::EncryptedStorage;
    let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let enc = StorageEncryption::new(&Keys::one("k1", 1)).unwrap();
    let wrapped: Arc<dyn AuthStorage> = Arc::new(EncryptedStorage::new(inner, enc, false, false));
    assert!(wrapped.encrypts_kv_at_rest());
    let log = logged_while(|| {
        let _ = TotpManager::new(wrapped.clone());
    });
    assert!(
        log.is_empty(),
        "new() warned on storage that encrypts: {log:?}"
    );
}

#[tokio::test]
async fn an_encrypted_manager_refuses_a_row_that_is_still_plain() {
    // Plain rows must be migrated first: a value that is not an envelope is never read as a secret.
    let inner: Arc<dyn AuthStorage> = Arc::new(MemoryStorage::new());
    let secret = enroll_plain(&inner, "zed").await;
    let totp = TotpManager::new_encrypted(inner.clone(), &Keys::one("k1", 1)).unwrap();
    assert!(
        !totp
            .verify_code("zed", &code_for(&secret).await)
            .await
            .unwrap()
    );
    // After migration the same secret verifies.
    let enc = StorageEncryption::new(&Keys::one("k1", 1)).unwrap();
    TotpManager::migrate_plain_secrets(&*inner, &enc, options())
        .await
        .unwrap();
    assert!(
        totp.verify_code("zed", &code_for(&secret).await)
            .await
            .unwrap()
    );
}
