//! QuickStart must not hand back an in-memory framework when a persistent backend was asked for.
#![cfg(not(feature = "redis-storage"))]

use auth_framework::prelude::*;

const SECRET: &str = "quickstart-fallback-test-secret-32-chars!!";

#[tokio::test]
async fn requesting_redis_without_the_feature_is_an_error() {
    let built = AuthFramework::quick_start()
        .jwt_auth(SECRET)
        .with_redis("redis://127.0.0.1:1")
        .build()
        .await;
    assert!(
        built.is_err(),
        "redis was requested but the redis-storage feature is off: expected an error, got a framework (in-memory fallback)"
    );
}

#[tokio::test]
async fn memory_storage_still_builds() {
    let built = AuthFramework::quick_start()
        .jwt_auth(SECRET)
        .with_memory_storage()
        .build()
        .await;
    assert!(built.is_ok(), "{:?}", built.err());
}
