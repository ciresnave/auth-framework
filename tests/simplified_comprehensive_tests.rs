//! Simplified comprehensive tests for auth_framework
//!
//! This test suite covers core functionality of the auth framework:
//! - Authentication methods (JWT)
//! - Storage backends (Memory)
//! - Session management
//! - Token lifecycle
//! - Error handling
//! - Edge cases

use auth_framework::{
    AuthConfig, AuthFramework, AuthToken,
    methods::{AuthMethodEnum, JwtMethod},
    providers::UserProfile,
    storage::{AuthStorage, MemoryStorage, SessionData},
    tokens::TokenMetadata,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

mod test_helpers {
    use super::*;

    pub fn create_test_user() -> UserProfile {
        UserProfile {
            id: Some("test_user_123".to_string()),
            provider: Some("test_provider".to_string()),
            username: Some("test_user".to_string()),
            name: Some("Test User".to_string()),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            picture: Some("https://example.com/avatar.jpg".to_string()),
            locale: Some("en-US".to_string()),
            additional_data: {
                let mut data = HashMap::new();
                data.insert(
                    "role".to_string(),
                    serde_json::Value::String("user".to_string()),
                );
                data.insert(
                    "department".to_string(),
                    serde_json::Value::String("engineering".to_string()),
                );
                data
            },
        }
    }

    pub fn create_test_token(user_id: &str) -> AuthToken {
        let now = Utc::now();

        AuthToken {
            token_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            access_token: format!("access_token_{}", Uuid::new_v4()),
            token_type: Some("Bearer".to_string()),
            subject: Some(user_id.to_string()),
            issuer: Some("test-issuer".to_string()),
            refresh_token: Some(format!("refresh_token_{}", Uuid::new_v4())),
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "jwt".to_string(),
            client_id: Some("test-client".to_string()),
            user_profile: Some(create_test_user()),
            permissions: vec!["read:data".to_string(), "write:data".to_string()],
            roles: vec!["user".to_string()],
            metadata: TokenMetadata {
                issued_ip: Some("192.168.1.100".to_string()),
                user_agent: Some("Mozilla/5.0 Test Browser".to_string()),
                device_id: Some("test-device-123".to_string()),
                session_id: Some(Uuid::new_v4().to_string()),
                revoked: false,
                revoked_at: None,
                revoked_reason: None,
                last_used: Some(now),
                use_count: 0,
                custom: {
                    let mut custom = HashMap::new();
                    custom.insert(
                        "location".to_string(),
                        serde_json::Value::String("test-location".to_string()),
                    );
                    custom
                },
            },
        }
    }

    pub fn create_test_session(user_id: &str) -> SessionData {
        let now = Utc::now();

        SessionData {
            session_id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(2),
            last_activity: now,
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0 Test Browser".to_string()),
            data: {
                let mut data = HashMap::new();
                data.insert(
                    "preference".to_string(),
                    serde_json::Value::String("dark_mode".to_string()),
                );
                data.insert(
                    "language".to_string(),
                    serde_json::Value::String("en".to_string()),
                );
                data
            },
        }
    }
}

#[cfg(test)]
mod auth_framework_tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_framework_initialization() {
        let config = AuthConfig::new()
            .secret("test-secret-key-for-initialization-test-12345")
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));

        let mut auth = AuthFramework::new(config);

        // Should initialize without errors
        assert!(auth.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_jwt_method_registration() {
        let config = AuthConfig::new().secret("test-secret-key-for-jwt-method-test-12345");
        let mut auth = AuthFramework::new(config);

        let jwt_method = JwtMethod::new()
            .secret_key("test-secret-key-12345")
            .issuer("test-issuer");

        auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
        assert!(auth.initialize().await.is_ok());
    }
}

#[cfg(test)]
mod memory_storage_tests {
    use super::*;
    use test_helpers::*;

    #[tokio::test]
    async fn test_token_storage_and_retrieval() {
        let storage = Arc::new(MemoryStorage::new());
        let token = create_test_token("user123");
        let token_id = token.token_id.clone();

        // Store token
        assert!(storage.store_token(&token).await.is_ok());

        // Retrieve token
        let retrieved = storage
            .get_token(&token_id)
            .await
            .expect("Failed to retrieve token from storage");
        assert!(retrieved.is_some(), "Token should exist in storage");
        let retrieved_token = retrieved.expect("Token should be present");
        assert_eq!(retrieved_token.token_id, token_id);
        assert_eq!(retrieved_token.user_id, "user123");
    }

    #[tokio::test]
    async fn test_token_deletion() {
        let storage = Arc::new(MemoryStorage::new());
        let token = create_test_token("user123");
        let token_id = token.token_id.clone();

        // Store and then delete
        assert!(storage.store_token(&token).await.is_ok());
        assert!(storage.delete_token(&token_id).await.is_ok());

        // Should not be retrievable after deletion
        let retrieved = storage
            .get_token(&token_id)
            .await
            .expect("Failed to query storage for deleted token");
        assert!(retrieved.is_none(), "Token should be deleted from storage");
    }

    #[tokio::test]
    async fn test_list_user_tokens() {
        let storage = Arc::new(MemoryStorage::new());
        let user_id = "user123";

        // Create multiple tokens for the same user
        let token1 = create_test_token(user_id);
        let token2 = create_test_token(user_id);
        let token3 = create_test_token("other_user");

        assert!(storage.store_token(&token1).await.is_ok());
        assert!(storage.store_token(&token2).await.is_ok());
        assert!(storage.store_token(&token3).await.is_ok());

        // Should return only tokens for the specified user
        let user_tokens = storage
            .list_user_tokens(user_id)
            .await
            .expect("Failed to list user tokens");
        assert_eq!(
            user_tokens.len(),
            2,
            "Should find exactly 2 tokens for the user"
        );

        for token in user_tokens {
            assert_eq!(token.user_id, user_id);
        }
    }

    #[tokio::test]
    async fn test_session_storage_and_retrieval() {
        let storage = Arc::new(MemoryStorage::new());
        let session = create_test_session("user123");
        let session_id = session.session_id.clone();

        // Store session
        assert!(storage.store_session(&session_id, &session).await.is_ok());

        // Retrieve session
        let retrieved = storage.get_session(&session_id).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved_session = retrieved.unwrap();
        assert_eq!(retrieved_session.session_id, session_id);
        assert_eq!(retrieved_session.user_id, "user123");
    }

    #[tokio::test]
    async fn test_session_deletion() {
        let storage = Arc::new(MemoryStorage::new());
        let session = create_test_session("user123");
        let session_id = session.session_id.clone();

        // Store and then delete
        assert!(storage.store_session(&session_id, &session).await.is_ok());
        assert!(storage.delete_session(&session_id).await.is_ok());

        // Should not be retrievable after deletion
        let retrieved = storage.get_session(&session_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_key_value_storage() {
        let storage = Arc::new(MemoryStorage::new());
        let key = "test_key";
        let data = b"test_data_12345".to_vec();

        // Store data
        assert!(storage.store_kv(key, &data, None).await.is_ok());

        // Retrieve data
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        // Delete data
        assert!(storage.delete_kv(key).await.is_ok());

        // Should not be retrievable after deletion
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_none());
    }
}

#[cfg(test)]
mod token_tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn test_token_creation() {
        let token = create_test_token("user123");

        assert_eq!(token.user_id, "user123");
        assert!(token.access_token.starts_with("access_token_"));
        assert!(token.refresh_token.is_some());
        assert_eq!(token.token_type.as_ref().unwrap(), "Bearer");
        assert_eq!(token.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_token_metadata() {
        let token = create_test_token("user123");
        let metadata = &token.metadata;

        assert!(!metadata.revoked);
        assert_eq!(metadata.use_count, 0);
        assert!(metadata.issued_ip.is_some());
        assert!(metadata.user_agent.is_some());
        assert!(metadata.device_id.is_some());
        assert!(metadata.custom.contains_key("location"));
    }

    #[test]
    fn test_token_expiration() {
        let mut token = create_test_token("user123");
        let past_time = Utc::now() - chrono::Duration::hours(2);
        token.expires_at = past_time;

        // Token should be considered expired
        assert!(token.expires_at < Utc::now());
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn test_session_creation() {
        let session = create_test_session("user123");

        assert_eq!(session.user_id, "user123");
        assert!(session.ip_address.is_some());
        assert!(session.user_agent.is_some());
        assert!(session.created_at <= Utc::now());
        assert!(session.expires_at > Utc::now());
    }

    #[test]
    fn test_session_data() {
        let session = create_test_session("user123");

        assert!(session.data.contains_key("preference"));
        assert!(session.data.contains_key("language"));
        assert_eq!(
            session.data.get("preference").unwrap(),
            &serde_json::Value::String("dark_mode".to_string())
        );
    }
}

#[cfg(test)]
mod user_profile_tests {
    use super::*;
    use test_helpers::*;

    #[test]
    fn test_user_profile_creation() {
        let user = create_test_user();

        assert_eq!(user.id.as_ref().unwrap(), "test_user_123");
        assert_eq!(user.username.as_ref().unwrap(), "test_user");
        assert_eq!(user.email.as_ref().unwrap(), "test@example.com");
        assert!(user.email_verified.unwrap());
    }

    #[test]
    fn test_user_profile_additional_data() {
        let user = create_test_user();

        assert!(user.additional_data.contains_key("role"));
        assert!(user.additional_data.contains_key("department"));
        assert_eq!(
            user.additional_data.get("role").unwrap(),
            &serde_json::Value::String("user".to_string())
        );
        assert_eq!(
            user.additional_data.get("department").unwrap(),
            &serde_json::Value::String("engineering".to_string())
        );
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_nonexistent_token_retrieval() {
        let storage = Arc::new(MemoryStorage::new());
        let fake_token_id = "nonexistent_token_id";

        let result = storage.get_token(fake_token_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_nonexistent_session_retrieval() {
        let storage = Arc::new(MemoryStorage::new());
        let fake_session_id = "nonexistent_session_id";

        let result = storage.get_session(fake_session_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_token() {
        let storage = Arc::new(MemoryStorage::new());
        let fake_token_id = "nonexistent_token_id";

        // Should not error when deleting nonexistent token
        assert!(storage.delete_token(fake_token_id).await.is_ok());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_session() {
        let storage = Arc::new(MemoryStorage::new());
        let fake_session_id = "nonexistent_session_id";

        // Should not error when deleting nonexistent session
        assert!(storage.delete_session(fake_session_id).await.is_ok());
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;
    use test_helpers::*;

    #[tokio::test]
    async fn test_empty_user_id_tokens() {
        let storage = Arc::new(MemoryStorage::new());

        let tokens = storage.list_user_tokens("").await.unwrap();
        assert_eq!(tokens.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_token_operations() {
        let storage = Arc::new(MemoryStorage::new());
        let user_id = "concurrent_user";

        // Create multiple tokens concurrently
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let storage = storage.clone();
                let user_id = format!("{}_{}", user_id, i);
                tokio::spawn(async move {
                    let token = create_test_token(&user_id);
                    storage.store_token(&token).await
                })
            })
            .collect();

        // Wait for all operations to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_token_with_empty_scopes() {
        let storage = Arc::new(MemoryStorage::new());
        let mut token = create_test_token("user123");
        token.scopes = vec![]; // Empty scopes

        assert!(storage.store_token(&token).await.is_ok());

        let retrieved = storage.get_token(&token.token_id).await.unwrap().unwrap();
        assert!(retrieved.scopes.is_empty());
    }

    #[tokio::test]
    async fn test_token_with_no_user_profile() {
        let storage = Arc::new(MemoryStorage::new());
        let mut token = create_test_token("user123");
        token.user_profile = None; // No user profile

        assert!(storage.store_token(&token).await.is_ok());

        let retrieved = storage.get_token(&token.token_id).await.unwrap().unwrap();
        assert!(retrieved.user_profile.is_none());
    }

    #[test]
    fn test_user_profile_with_minimal_data() {
        let user = UserProfile {
            id: Some("minimal_user".to_string()),
            provider: None,
            username: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            locale: None,
            additional_data: HashMap::new(),
        };

        assert_eq!(user.id.as_ref().unwrap(), "minimal_user");
        assert!(user.provider.is_none());
        assert!(user.additional_data.is_empty());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use test_helpers::*;

    #[tokio::test]
    async fn test_full_auth_workflow() {
        // Initialize auth framework
        let config = AuthConfig::new()
            .secret("test-secret-key-for-full-auth-workflow-test-12345")
            .token_lifetime(Duration::from_secs(3600))
            .refresh_token_lifetime(Duration::from_secs(86400));

        let mut auth = AuthFramework::new(config);

        let jwt_method = JwtMethod::new()
            .secret_key("integration-test-secret")
            .issuer("integration-test");

        auth.register_method("jwt", AuthMethodEnum::Jwt(jwt_method));
        assert!(auth.initialize().await.is_ok());

        // Create storage and test full workflow
        let storage = Arc::new(MemoryStorage::new());
        let user = create_test_user();
        let token = create_test_token(user.id.as_ref().unwrap());
        let session = create_test_session(user.id.as_ref().unwrap());

        // Store token and session
        assert!(storage.store_token(&token).await.is_ok());
        assert!(
            storage
                .store_session(&session.session_id, &session)
                .await
                .is_ok()
        );

        // Verify everything is stored
        let retrieved_token = storage.get_token(&token.token_id).await.unwrap();
        assert!(retrieved_token.is_some());

        let retrieved_session = storage.get_session(&session.session_id).await.unwrap();
        assert!(retrieved_session.is_some());

        // Clean up
        assert!(storage.delete_token(&token.token_id).await.is_ok());
        assert!(storage.delete_session(&session.session_id).await.is_ok());
    }

    #[tokio::test]
    async fn test_token_access_by_access_token() {
        let storage = Arc::new(MemoryStorage::new());
        let token = create_test_token("user123");
        let access_token = token.access_token.clone();

        // Store token
        assert!(storage.store_token(&token).await.is_ok());

        // Retrieve by access token
        let retrieved = storage
            .get_token_by_access_token(&access_token)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved_token = retrieved.unwrap();
        assert_eq!(retrieved_token.access_token, access_token);
        assert_eq!(retrieved_token.user_id, "user123");
    }

    #[tokio::test]
    async fn test_bulk_token_operations() {
        let storage = Arc::new(MemoryStorage::new());
        let tokens = vec![
            create_test_token("user1"),
            create_test_token("user2"),
            create_test_token("user3"),
        ];
        let token_ids: Vec<String> = tokens.iter().map(|t| t.token_id.clone()).collect();

        // Bulk store
        assert!(storage.store_tokens_bulk(&tokens).await.is_ok());

        // Verify all tokens are stored
        for token_id in &token_ids {
            let retrieved = storage.get_token(token_id).await.unwrap();
            assert!(retrieved.is_some());
        }

        // Bulk delete
        assert!(storage.delete_tokens_bulk(&token_ids).await.is_ok());

        // Verify all tokens are deleted
        for token_id in &token_ids {
            let retrieved = storage.get_token(token_id).await.unwrap();
            assert!(retrieved.is_none());
        }
    }

    #[tokio::test]
    async fn test_user_sessions_listing() {
        let storage = Arc::new(MemoryStorage::new());
        let user_id = "user123";

        // Create multiple sessions for the same user
        let session1 = create_test_session(user_id);
        let session2 = create_test_session(user_id);
        let session3 = create_test_session("other_user");

        assert!(
            storage
                .store_session(&session1.session_id, &session1)
                .await
                .is_ok()
        );
        assert!(
            storage
                .store_session(&session2.session_id, &session2)
                .await
                .is_ok()
        );
        assert!(
            storage
                .store_session(&session3.session_id, &session3)
                .await
                .is_ok()
        );

        // Should return only sessions for the specified user
        let user_sessions = storage.list_user_sessions(user_id).await.unwrap();
        assert_eq!(user_sessions.len(), 2);

        for session in user_sessions {
            assert_eq!(session.user_id, user_id);
        }
    }
}
