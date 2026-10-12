//! SQLite stores `expires_at` in whole seconds. A TTL with a sub-second part must never make an
//! entry expire EARLY (it used to be truncated: `duration.as_secs()`), for `store_kv` and
//! `store_kv_if_absent` alike.

#[cfg(all(test, feature = "sqlite-storage"))]
mod sqlite_ttl_rounding_tests {
    use auth_framework::storage::AuthStorage;
    use auth_framework::storage::sqlite::SqliteStorage;
    use chrono::Utc;
    use std::time::Duration;

    async fn storage() -> SqliteStorage {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let s = SqliteStorage::new(pool);
        s.migrate().await.unwrap();
        s
    }

    /// Wait until the wall clock is 0.80 s to 0.90 s into a second: with a 1.5 s TTL the
    /// truncated expiry (whole second + 1) then falls before the true expiry (+2.3 s or so).
    async fn align_to_late_in_the_second() {
        loop {
            let ms = Utc::now().timestamp_subsec_millis();
            if (800..900).contains(&ms) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn store_kv_keeps_a_fractional_ttl_alive_for_its_full_length() {
        let s = storage().await;
        align_to_late_in_the_second().await;
        s.store_kv("frac", b"v", Some(Duration::from_millis(1500)))
            .await
            .unwrap();
        // control: a whole-second TTL stored at the same moment
        s.store_kv("whole", b"v", Some(Duration::from_secs(3)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(
            s.get_kv("whole").await.unwrap().is_some(),
            "control: a 3 s TTL is alive at 1.3 s"
        );
        assert!(
            s.get_kv("frac").await.unwrap().is_some(),
            "a 1.5 s TTL must still be alive at 1.3 s"
        );
        // and it does end: well past the TTL (including the up-to-one-second rounding) it is gone
        tokio::time::sleep(Duration::from_millis(2000)).await;
        assert!(s.get_kv("frac").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_kv_if_absent_keeps_a_fractional_ttl_alive_for_its_full_length() {
        let s = storage().await;
        align_to_late_in_the_second().await;
        assert!(
            s.store_kv_if_absent("frac", b"v", Some(Duration::from_millis(1500)))
                .await
                .unwrap()
        );
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(
            s.get_kv("frac").await.unwrap().is_some(),
            "a 1.5 s TTL must still be alive at 1.3 s"
        );
        // a live entry still blocks a second claim
        assert!(
            !s.store_kv_if_absent("frac", b"w", Some(Duration::from_secs(60)))
                .await
                .unwrap()
        );
    }
}
