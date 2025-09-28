use auth_framework::{
    auth::AuthFramework,
    config::{AuditConfig, AuthConfig, RateLimitConfig, SecurityConfig, StorageConfig},
    storage::{AuthStorage, SessionData},
    testing::MockStorage,
    tokens::{AuthToken, TokenMetadata},
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::{hint::black_box, sync::Arc};
use tokio::runtime::Runtime;

/// Benchmark authentication token operations
fn bench_token_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage = Arc::new(MockStorage::new());

    let mut group = c.benchmark_group("token_operations");

    // Benchmark token storage
    group.bench_function("store_token", |b| {
        b.to_async(&rt).iter(|| async {
            let token = AuthToken {
                token_id: format!("token_{}", fastrand::u64(..)),
                user_id: "user123".to_string(),
                access_token: "access_token_value".to_string(),
                refresh_token: Some("refresh_token_value".to_string()),
                token_type: Some("Bearer".to_string()),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                scopes: vec!["read".to_string(), "write".to_string()],
                issued_at: chrono::Utc::now(),
                auth_method: "oauth2".to_string(),
                subject: Some("subject123".to_string()),
                issuer: Some("https://auth.example.com".to_string()),
                client_id: Some("client123".to_string()),
                user_profile: None,
                permissions: vec!["read".to_string(), "write".to_string()],
                roles: vec!["user".to_string()],
                metadata: TokenMetadata::default(),
            };

            let _: () = storage.store_token(&token).await.unwrap();
            black_box(());
        });
    });

    // Benchmark token retrieval
    group.bench_function("get_token", |b| {
        let token_id = "bench_token_123";
        rt.block_on(async {
            let token = AuthToken {
                token_id: token_id.to_string(),
                user_id: "user123".to_string(),
                access_token: "access_token_value".to_string(),
                refresh_token: Some("refresh_token_value".to_string()),
                token_type: Some("Bearer".to_string()),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                scopes: vec!["read".to_string(), "write".to_string()],
                issued_at: chrono::Utc::now(),
                auth_method: "oauth2".to_string(),
                subject: Some("subject123".to_string()),
                issuer: Some("https://auth.example.com".to_string()),
                client_id: Some("client123".to_string()),
                user_profile: None,
                permissions: vec!["read".to_string(), "write".to_string()],
                roles: vec!["user".to_string()],
                metadata: TokenMetadata::default(),
            };
            storage.store_token(&token).await.unwrap();
        });

        b.to_async(&rt).iter(|| async {
            black_box(storage.get_token(token_id).await.unwrap());
        });
    });

    group.finish();
}

/// Benchmark session management operations
fn bench_session_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage = Arc::new(MockStorage::new());

    let mut group = c.benchmark_group("session_operations");

    // Benchmark session storage
    group.bench_function("store_session", |b| {
        b.to_async(&rt).iter(|| async {
            let session_id = format!("session_{}", fastrand::u64(..));
            let session_data = SessionData {
                session_id: session_id.clone(),
                user_id: "user123".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                last_activity: chrono::Utc::now(),
                ip_address: Some("192.168.1.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                data: std::collections::HashMap::new(),
            };

            let _: () = storage
                .store_session(&session_id, &session_data)
                .await
                .unwrap();
            black_box(());
        });
    });

    // Benchmark session retrieval
    group.bench_function("get_session", |b| {
        let session_id = "bench_session_123";
        rt.block_on(async {
            let session_data = SessionData {
                session_id: session_id.to_string(),
                user_id: "user123".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                last_activity: chrono::Utc::now(),
                ip_address: Some("192.168.1.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                data: std::collections::HashMap::new(),
            };
            storage
                .store_session(session_id, &session_data)
                .await
                .unwrap();
        });

        b.to_async(&rt).iter(|| async {
            black_box(storage.get_session(session_id).await.unwrap());
        });
    });

    // Benchmark active session counting
    group.bench_function("count_active_sessions", |b| {
        rt.block_on(async {
            // Pre-populate with sessions
            for i in 0..100 {
                let session_id = format!("session_{}", i);
                let session_data = SessionData {
                    session_id: session_id.clone(),
                    user_id: format!("user_{}", i % 10),
                    created_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    last_activity: chrono::Utc::now(),
                    ip_address: Some("192.168.1.1".to_string()),
                    user_agent: Some("Mozilla/5.0".to_string()),
                    data: std::collections::HashMap::new(),
                };
                storage
                    .store_session(&session_id, &session_data)
                    .await
                    .unwrap();
            }
        });

        b.to_async(&rt).iter(|| async {
            black_box(storage.count_active_sessions().await.unwrap());
        });
    });

    group.finish();
}

/// Benchmark concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let storage = Arc::new(MockStorage::new());

    let mut group = c.benchmark_group("concurrent_operations");

    for concurrent_users in [10, 50, 100, 250].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_token_operations", concurrent_users),
            concurrent_users,
            |b, &concurrent_users| {
                b.to_async(&rt).iter(|| async {
                    let handles: Vec<_> = (0..concurrent_users)
                        .map(|i| {
                            let storage = storage.clone();
                            tokio::spawn(async move {
                                let token = AuthToken {
                                    token_id: format!("concurrent_token_{}", i),
                                    user_id: format!("user_{}", i),
                                    access_token: format!("access_token_{}", i),
                                    refresh_token: Some(format!("refresh_token_{}", i)),
                                    token_type: Some("Bearer".to_string()),
                                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                                    scopes: vec!["read".to_string()],
                                    issued_at: chrono::Utc::now(),
                                    auth_method: "oauth2".to_string(),
                                    subject: Some(format!("subject_{}", i)),
                                    issuer: Some("https://auth.example.com".to_string()),
                                    client_id: Some("client123".to_string()),
                                    user_profile: None,
                                    permissions: vec!["read".to_string()],
                                    roles: vec!["user".to_string()],
                                    metadata: TokenMetadata::default(),
                                };

                                // Store and immediately retrieve
                                storage.store_token(&token).await.unwrap();
                                storage.get_token(&token.token_id).await.unwrap();
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.await.unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark authentication framework initialization
fn bench_framework_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("framework_init");

    group.bench_function("auth_framework_new", |b| {
        b.iter(|| {
            let config = AuthConfig {
                token_lifetime: std::time::Duration::from_secs(3600),
                refresh_token_lifetime: std::time::Duration::from_secs(86400),
                enable_multi_factor: false,
                issuer: "https://auth.example.com".to_string(),
                audience: "test-audience".to_string(),
                secret: Some(
                    "test_jwt_secret_that_is_definitely_longer_than_32_characters_for_security"
                        .to_string(),
                ),
                storage: StorageConfig::Memory,
                rate_limiting: RateLimitConfig::default(),
                security: SecurityConfig::default(),
                audit: AuditConfig::default(),
                method_configs: std::collections::HashMap::new(),
            };

            let _framework = black_box(AuthFramework::new(config));
        });
    });
    group.finish();
}

/// Benchmark serialization performance
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let token = AuthToken {
        token_id: "benchmark_token".to_string(),
        user_id: "user123".to_string(),
        access_token: "access_token_value".to_string(),
        refresh_token: Some("refresh_token_value".to_string()),
        token_type: Some("Bearer".to_string()),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        scopes: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
        issued_at: chrono::Utc::now(),
        auth_method: "oauth2".to_string(),
        subject: Some("subject123".to_string()),
        issuer: Some("https://auth.example.com".to_string()),
        client_id: Some("client123".to_string()),
        user_profile: None,
        permissions: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
        roles: vec!["user".to_string(), "admin".to_string()],
        metadata: TokenMetadata {
            issued_ip: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            device_id: Some("device123".to_string()),
            ..TokenMetadata::default()
        },
    };

    group.bench_function("token_serialize", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(&token).unwrap());
        });
    });

    let serialized = serde_json::to_string(&token).unwrap();
    group.bench_function("token_deserialize", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<AuthToken>(&serialized).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_operations,
    bench_session_operations,
    bench_concurrent_operations,
    bench_framework_init,
    bench_serialization
);
criterion_main!(benches);
