//! WS-Trust tokens kept in the `AuthStorage` KV layer (ROADMAP A3): a restarted or second STS
//! instance sees the tokens another one issued, cancelled or renewed.

use auth_framework::protocols::ws_trust::{
    AuthenticationContext, RequestSecurityToken, RequestSecurityTokenResponse,
    SecurityTokenService, StsConfig,
};
use auth_framework::storage::{AuthStorage, MemoryStorage};
use std::collections::HashMap;
use std::sync::Arc;

const NS: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";

fn sts(storage: &Arc<MemoryStorage>) -> SecurityTokenService {
    let storage: Arc<dyn AuthStorage> = storage.clone();
    SecurityTokenService::new(StsConfig::default()).with_storage(storage)
}

fn request(kind: &str, existing: Option<&str>) -> RequestSecurityToken {
    RequestSecurityToken {
        request_type: format!("{NS}{kind}"),
        token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
        applies_to: Some("https://rp.example.com".to_string()),
        lifetime: None,
        key_type: None,
        key_size: None,
        existing_token: existing.map(str::to_string),
        auth_context: (kind == "Issue").then(|| AuthenticationContext {
            username: "alice".to_string(),
            auth_method: "password".to_string(),
            claims: HashMap::new(),
        }),
    }
}

async fn issue(sts: &mut SecurityTokenService) -> String {
    let response = sts
        .process_request_stored(request("Issue", None))
        .await
        .unwrap();
    response
        .requested_unattached_reference
        .expect("the response names the token id")
}

async fn status(sts: &mut SecurityTokenService, id: &str) -> Result<String, String> {
    sts.process_request_stored(request("Validate", Some(id)))
        .await
        .map(|r: RequestSecurityTokenResponse| r.requested_security_token)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_second_instance_validates_a_token_the_first_issued() {
    let storage = Arc::new(MemoryStorage::new());
    let id = issue(&mut sts(&storage)).await;

    // A fresh instance over the same storage stands for a restart or another node.
    assert_eq!(status(&mut sts(&storage), &id).await.unwrap(), "Valid");

    // Control: an instance over different storage has never seen it.
    let other = Arc::new(MemoryStorage::new());
    assert!(
        status(&mut sts(&other), &id)
            .await
            .unwrap_err()
            .contains("Token not found")
    );
}

#[tokio::test]
async fn the_token_is_stored_under_its_key_and_the_working_map_stays_empty() {
    let storage = Arc::new(MemoryStorage::new());
    let mut first = sts(&storage);
    let id = issue(&mut first).await;
    assert!(
        storage
            .get_kv(&format!("wstrust:token:{id}"))
            .await
            .unwrap()
            .is_some()
    );

    // The plain in-memory entry point does not see it: the store is the only copy.
    let err = first
        .process_request(request("Validate", Some(&id)))
        .map(|r| r.requested_security_token);
    assert!(
        err.is_err(),
        "the in-memory map must not keep the token: {err:?}"
    );
}

#[tokio::test]
async fn a_cancel_on_one_instance_ends_the_token_on_every_instance() {
    let storage = Arc::new(MemoryStorage::new());
    let mut a = sts(&storage);
    let id = issue(&mut a).await;
    assert_eq!(status(&mut sts(&storage), &id).await.unwrap(), "Valid");

    sts(&storage)
        .process_request_stored(request("Cancel", Some(&id)))
        .await
        .unwrap();

    assert!(
        status(&mut a, &id)
            .await
            .unwrap_err()
            .contains("Token not found")
    );
    assert!(
        status(&mut sts(&storage), &id)
            .await
            .unwrap_err()
            .contains("Token not found")
    );
    assert!(
        storage
            .get_kv(&format!("wstrust:token:{id}"))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_renewal_on_a_fresh_instance_issues_a_token_every_instance_can_validate() {
    let storage = Arc::new(MemoryStorage::new());
    let id = issue(&mut sts(&storage)).await;

    let renewed = sts(&storage)
        .process_request_stored(request("Renew", Some(&id)))
        .await
        .unwrap();
    let new_id = renewed
        .requested_unattached_reference
        .expect("the renewal names its token id");
    assert_ne!(new_id, id);

    assert_eq!(status(&mut sts(&storage), &new_id).await.unwrap(), "Valid");
    assert_eq!(status(&mut sts(&storage), &id).await.unwrap(), "Valid");
}

#[tokio::test]
async fn an_id_that_is_not_a_generated_token_id_never_reaches_the_store() {
    let storage = Arc::new(MemoryStorage::new());
    // A record planted where a crafted id would land if the id were used as a key part.
    storage
        .store_kv("wstrust:token:a:b", b"{}", None)
        .await
        .unwrap();

    for crafted in ["a:b", "../x", &"x".repeat(300)] {
        let message = status(&mut sts(&storage), crafted).await.unwrap_err();
        assert!(
            message.contains("Token not found"),
            "{crafted:.20}: {message}"
        );
    }
}

#[tokio::test]
async fn a_token_that_cannot_be_stored_is_not_handed_out() {
    let storage = Arc::new(MemoryStorage::new());
    let config = StsConfig {
        default_token_lifetime: chrono::Duration::zero(),
        ..StsConfig::default()
    };
    let dyn_storage: Arc<dyn AuthStorage> = storage.clone();
    let mut short = SecurityTokenService::new(config).with_storage(dyn_storage);

    let err = short
        .process_request_stored(request("Issue", None))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("already ended"), "{err}");
    assert!(
        storage
            .list_kv_keys("wstrust:token:")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn without_a_storage_the_stored_entry_point_behaves_as_before() {
    let mut plain = SecurityTokenService::new(StsConfig::default());
    let id = issue(&mut plain).await;
    assert_eq!(status(&mut plain, &id).await.unwrap(), "Valid");
    // Control: the in-memory path sees the same token.
    assert!(
        plain
            .process_request(request("Validate", Some(&id)))
            .is_ok()
    );
}

#[tokio::test]
async fn a_renewal_presenting_a_jwt_finds_the_stored_token_by_its_jti() {
    use base64::Engine as _;
    let storage = Arc::new(MemoryStorage::new());
    let id = issue(&mut sts(&storage)).await;

    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    let jwt = format!("{}.{}.sig", b64("{}"), b64(&format!(r#"{{"jti":"{id}"}}"#)));
    let renewed = sts(&storage)
        .process_request_stored(request("Renew", Some(&jwt)))
        .await
        .unwrap();
    assert!(renewed.requested_unattached_reference.is_some());

    // Control: the same JWT naming a token that was never stored is not found.
    let ghost = format!("{}.{}.sig", b64("{}"), b64(r#"{"jti":"token-ghost"}"#));
    let err = sts(&storage)
        .process_request_stored(request("Renew", Some(&ghost)))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Token not found"), "{err}");
}
