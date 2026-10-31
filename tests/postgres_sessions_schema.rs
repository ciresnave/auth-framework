//! One `sessions` schema on PostgreSQL, whichever path created it (issue #147): the library's
//! `PostgresStorage::migrate()` and the CLI's `MigrationManager` (`auth-framework migrate`) must
//! leave the same table, in either order, and a database a previous release created with the old
//! CLI shape must be reconciled without losing its rows. Needs a server (`DATABASE_URL`; CI's test
//! job provides it) with rights to `CREATE DATABASE`; it fails without one rather than skips.

#![cfg(feature = "postgres-storage")]

use auth_framework::migrations::MigrationManager;
use auth_framework::storage::postgres::PostgresStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use sqlx::{PgPool, Row};
use std::collections::HashMap;

fn base_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set")
}

/// `url` with its database name replaced by `db` (the URL carries no query string here).
fn url_for(db: &str) -> String {
    let url = base_url();
    let (head, _) = url
        .rsplit_once('/')
        .expect("DATABASE_URL has a database name");
    format!("{head}/{db}")
}

async fn fresh_db() -> String {
    let db = format!("sess_{}", uuid::Uuid::new_v4().simple());
    let admin = PgPool::connect(&base_url()).await.unwrap();
    // `db` is "sess_" plus a UUID's hex digits, so it cannot carry SQL.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .execute(&admin)
        .await
        .unwrap();
    url_for(&db)
}

async fn cli_migrate(url: &str) {
    let (client, conn) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    MigrationManager::new(client).migrate().await.unwrap();
}

async fn lib_migrate(url: &str) -> PostgresStorage {
    let storage = PostgresStorage::new(PgPool::connect(url).await.unwrap());
    storage.migrate().await.unwrap();
    storage
}

/// `(column, type, nullable)` of `sessions`, then its index names, as one comparable string.
async fn shape(url: &str) -> String {
    let pool = PgPool::connect(url).await.unwrap();
    let cols = sqlx::query(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = 'sessions' ORDER BY column_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let idx = sqlx::query(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() \
         AND tablename = 'sessions' ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut out: Vec<String> = cols
        .iter()
        .map(|r| {
            format!(
                "{} {} null={}",
                r.get::<String, _>(0),
                r.get::<String, _>(1),
                r.get::<String, _>(2)
            )
        })
        .collect();
    out.extend(
        idx.iter()
            .map(|r| format!("index {}", r.get::<String, _>(0))),
    );
    out.join("\n")
}

fn session(id: &str, user: &str) -> SessionData {
    let now = chrono::Utc::now();
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        last_activity: now,
        ip_address: Some("10.0.0.1".to_string()),
        user_agent: Some("schema-test/1.0".to_string()),
        data: HashMap::new(),
    }
}

async fn assert_usable(storage: &PostgresStorage) {
    let s = session("s1", "alice");
    storage.store_session("s1", &s).await.unwrap();
    let listed = storage.list_user_sessions("alice").await.unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].session_id, "s1");
    assert_eq!(
        storage.get_session("s1").await.unwrap().unwrap().user_id,
        "alice"
    );
}

/// The shape `migrate()` alone leaves: the owner every other path must match.
async fn baseline() -> String {
    let url = fresh_db().await;
    lib_migrate(&url).await;
    shape(&url).await
}

/// The sessions table the CLI's migration 3 created before this fix, plus a row in it.
const LEGACY_SESSIONS: &str = r#"
    DROP TABLE sessions;
    CREATE TABLE sessions (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        state VARCHAR(20) DEFAULT 'active',
        device_fingerprint TEXT,
        ip_address INET,
        user_agent TEXT,
        security_flags TEXT[]
    );
    CREATE INDEX idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
    INSERT INTO users (id, username, email, password_hash)
        VALUES ('u1', 'legacy', 'legacy@example.com', 'x');
    INSERT INTO sessions (id, user_id, expires_at)
        VALUES ('legacy-1', 'u1', NOW() + INTERVAL '1 hour');
"#;

async fn legacy_count(url: &str) -> i64 {
    let pool = PgPool::connect(url).await.unwrap();
    sqlx::query("SELECT COUNT(*) FROM sessions_legacy_v3 WHERE id = 'legacy-1'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn cli_alone_matches_library_schema() {
    let want = baseline().await;
    let url = fresh_db().await;
    cli_migrate(&url).await;
    assert_eq!(
        shape(&url).await,
        want,
        "CLI-created sessions table differs"
    );
}

#[tokio::test]
async fn library_after_cli_is_usable_and_same_shape() {
    let want = baseline().await;
    let url = fresh_db().await;
    cli_migrate(&url).await;
    let storage = lib_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert_usable(&storage).await;
}

#[tokio::test]
async fn cli_after_library_keeps_library_schema() {
    let want = baseline().await;
    let url = fresh_db().await;
    let storage = lib_migrate(&url).await;
    storage
        .store_session("keep", &session("keep", "bob"))
        .await
        .unwrap();
    cli_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert!(storage.get_session("keep").await.unwrap().is_some());
    assert_usable(&storage).await;
}

#[tokio::test]
async fn library_reconciles_database_the_old_cli_created() {
    let want = baseline().await;
    let url = fresh_db().await;
    cli_migrate(&url).await;
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(LEGACY_SESSIONS).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM _auth_migrations WHERE version > 5")
        .execute(&pool)
        .await
        .unwrap();

    let storage = lib_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert_eq!(legacy_count(&url).await, 1, "legacy row kept");
    assert_usable(&storage).await;
    // A second run changes nothing.
    lib_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert_eq!(legacy_count(&url).await, 1);
}

#[tokio::test]
async fn cli_reconciles_database_it_created_before_the_fix() {
    let want = baseline().await;
    let url = fresh_db().await;
    cli_migrate(&url).await;
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(LEGACY_SESSIONS).execute(&pool).await.unwrap();
    // The state of a database migrated by the old CLI: versions 1-5 applied, nothing newer.
    sqlx::query("DELETE FROM _auth_migrations WHERE version > 5")
        .execute(&pool)
        .await
        .unwrap();

    cli_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert_eq!(legacy_count(&url).await, 1, "legacy row kept");
    cli_migrate(&url).await;
    assert_eq!(shape(&url).await, want);
    assert_usable(&lib_migrate(&url).await).await;
}
