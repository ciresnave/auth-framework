//! Time the `AuthStorage` operations of `SqliteStorage` and `PersistantStorage` (SQLite file) on one
//! workload. Run in release mode, with a directory on a local disk:
//!
//! `cargo run --release --example persistant_storage_speed --features persistant-storage,sqlite-storage -- <dir> [tokens]`
//!
//! Prints one line per operation: median and p99 per call, and calls per second, for each backend.
//! The two do different amounts of work per call by design (the PersistAnt layout writes a record plus
//! index entries in one transaction), so this measures what the switch costs, not which is "faster".

use auth_framework::storage::persistant::PersistantStorage;
use auth_framework::storage::sqlite::SqliteStorage;
use auth_framework::storage::{AuthStorage, SessionData};
use auth_framework::testing::helpers::create_test_token;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct Timings(Vec<Duration>);

impl Timings {
    fn report(&mut self, name: &str, backend: &str) {
        self.0.sort();
        let n = self.0.len();
        let total: Duration = self.0.iter().sum();
        println!(
            "{name:<34} {backend:<10} n={n:<6} median={:>8.1}us p99={:>8.1}us {:>9.0}/s",
            self.0[n / 2].as_secs_f64() * 1e6,
            self.0[(n * 99 / 100).min(n - 1)].as_secs_f64() * 1e6,
            n as f64 / total.as_secs_f64()
        );
    }
}

async fn time<F, Fut>(count: usize, mut f: F) -> Timings
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = Instant::now();
        f(i).await;
        out.push(start.elapsed());
    }
    Timings(out)
}

fn session(id: &str, user: &str) -> SessionData {
    let now = chrono::Utc::now();
    SessionData {
        session_id: id.to_string(),
        user_id: user.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        last_activity: now,
        ip_address: None,
        user_agent: None,
        data: HashMap::new(),
    }
}

async fn workload(backend: &str, s: &dyn AuthStorage, tokens: usize) {
    let users = (tokens / 5).max(1);
    let all: Vec<_> = (0..tokens)
        .map(|i| create_test_token(&format!("user{}", i % users)))
        .collect();

    time(tokens, |i| {
        let t = &all[i];
        async move { s.store_token(t).await.unwrap() }
    })
    .await
    .report("store_token (new)", backend);

    time(tokens, |i| {
        let t = &all[i];
        async move {
            assert!(s.get_token(&t.token_id).await.unwrap().is_some());
        }
    })
    .await
    .report("get_token", backend);

    time(tokens, |i| {
        let t = &all[i];
        async move {
            assert!(
                s.get_token_by_access_token(&t.access_token)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    })
    .await
    .report("get_token_by_access_token", backend);

    time(users.min(500), |i| async move {
        assert!(
            !s.list_user_tokens(&format!("user{i}"))
                .await
                .unwrap()
                .is_empty()
        );
    })
    .await
    .report("list_user_tokens (~5 each)", backend);

    time(tokens, |i| {
        let mut t = all[i].clone();
        async move {
            t.metadata.use_count += 1;
            s.update_token(&t).await.unwrap()
        }
    })
    .await
    .report("update_token (touch)", backend);

    time(tokens, |i| {
        let mut t = all[i].clone();
        async move {
            t.access_token = format!("{}-r", t.access_token);
            s.update_token(&t).await.unwrap()
        }
    })
    .await
    .report("update_token (new access token)", backend);

    time(tokens, |i| async move {
        let id = format!("sess-{backend}-{i}");
        s.store_session(&id, &session(&id, &format!("user{}", i % 50)))
            .await
            .unwrap()
    })
    .await
    .report("store_session", backend);

    time(50, |_| async move {
        assert!(s.count_active_sessions().await.unwrap() > 0);
    })
    .await
    .report("count_active_sessions", backend);

    time(tokens, |i| async move {
        s.store_kv(&format!("k{i}"), b"value", Some(Duration::from_secs(600)))
            .await
            .unwrap()
    })
    .await
    .report("store_kv", backend);

    time(tokens, |i| async move {
        assert!(s.get_kv(&format!("k{i}")).await.unwrap().is_some());
    })
    .await
    .report("get_kv", backend);

    time(tokens, |i| async move {
        assert!(
            s.store_kv_if_absent(&format!("ia{i}"), b"x", None)
                .await
                .unwrap()
        );
    })
    .await
    .report("store_kv_if_absent", backend);

    time(tokens, |i| {
        let t = &all[i];
        async move { s.delete_token(&t.token_id).await.unwrap() }
    })
    .await
    .report("delete_token", backend);
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("usage: <dir> [tokens]"));
    let tokens: usize = args.next().map_or(2000, |n| n.parse().unwrap());

    let path = dir.join("old.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .busy_timeout(Duration::from_secs(30)),
        )
        .await
        .unwrap();
    let old = SqliteStorage::new(pool);
    old.migrate().await.unwrap();
    workload("sqlite", &old, tokens).await;

    let new = PersistantStorage::open_sqlite(dir.join("new.sqlite"))
        .await
        .unwrap();
    workload("persistant", &new, tokens).await;
}
