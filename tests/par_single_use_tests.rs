//! A pushed authorization request's `request_uri` is single use (RFC 9126): of any number of
//! simultaneous redemptions exactly one succeeds. It used to be a read followed by a delete, so
//! several callers could redeem the same request_uri at once.

use auth_framework::server::oauth::par::{PARManager, PushedAuthorizationRequest};
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::collections::HashMap;
use std::sync::Arc;

fn request() -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id: "c".into(),
        response_type: "code".into(),
        redirect_uri: "https://example.com/cb".into(),
        scope: Some("openid".into()),
        state: None,
        code_challenge: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()),
        code_challenge_method: Some("S256".into()),
        additional_params: HashMap::new(),
    }
}

async fn hammer(storage: Arc<dyn AuthStorage>) -> (usize, usize) {
    let mgr = Arc::new(PARManager::new(storage));
    let rounds = 100;
    let mut worst = 0;
    let mut exactly_one = 0;
    for _ in 0..rounds {
        let uri = mgr.store_request(request()).await.unwrap().request_uri;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let m = mgr.clone();
            let u = uri.clone();
            tasks.push(tokio::spawn(
                async move { m.consume_request(&u).await.is_ok() },
            ));
        }
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap() {
                ok += 1;
            }
        }
        worst = worst.max(ok);
        if ok == 1 {
            exactly_one += 1;
        }
    }
    (worst, exactly_one)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_redemptions_of_a_request_uri_yield_exactly_one_winner() {
    let (worst, exactly_one) = hammer(Arc::new(MemoryStorage::new())).await;
    assert_eq!(
        worst, 1,
        "up to {worst} callers redeemed one single-use request_uri at once"
    );
    assert_eq!(exactly_one, 100);
}

#[tokio::test]
async fn a_redeemed_request_uri_stays_spent() {
    let mgr = PARManager::new(Arc::new(MemoryStorage::new()));
    let uri = mgr.store_request(request()).await.unwrap().request_uri;
    assert!(mgr.consume_request(&uri).await.is_ok());
    assert!(mgr.consume_request(&uri).await.is_err());
    assert!(mgr.consume_request(&uri).await.is_err());
}

#[tokio::test]
async fn an_unknown_request_uri_is_refused_and_a_fresh_one_still_works() {
    let mgr = PARManager::new(Arc::new(MemoryStorage::new()));
    assert!(
        mgr.consume_request("urn:ietf:params:oauth:request_uri:nope")
            .await
            .is_err()
    );
    let uri = mgr.store_request(request()).await.unwrap().request_uri;
    assert!(mgr.consume_request(&uri).await.is_ok());
}
