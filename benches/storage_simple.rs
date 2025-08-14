use auth_framework::storage::core::AuthStorage;
use auth_framework::storage::dashmap_memory::DashMapMemoryStorage;
use auth_framework::test_infrastructure::TestEnvironmentGuard;
use auth_framework::tokens::{AuthToken, TokenMetadata};
use criterion::{Criterion, criterion_group, criterion_main};
use std::sync::Arc;

/// Create a test token with proper structure
fn create_test_token(token_id: &str, user_id: &str, access_token: &str) -> AuthToken {
    AuthToken {
        token_id: token_id.to_string(),
        user_id: user_id.to_string(),
        access_token: access_token.to_string(),
        token_type: Some("bearer".to_string()),
        subject: Some(user_id.to_string()),
        issuer: Some("test-issuer".to_string()),
        refresh_token: None,
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        scopes: vec!["read".to_string(), "write".to_string()],
        auth_method: "password".to_string(),
        client_id: Some("test-client".to_string()),
        user_profile: None,
        metadata: TokenMetadata::default(),
    }
}

fn bench_token_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("dashmap_token_store_retrieve", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _env = TestEnvironmentGuard::new().with_jwt_secret("bench-token-ops");
                let storage = Arc::new(DashMapMemoryStorage::new());

                let token = create_test_token("bench-token-1", "user-1", "access-1");
                storage.store_token(&token).await.unwrap();
                let _retrieved = storage.get_token(&token.token_id).await.unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_token_operations);
criterion_main!(benches);
