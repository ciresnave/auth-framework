//! Pushed Authorization Requests (PAR) Implementation - RFC 9126
//!
//! This module implements RFC 9126 - OAuth 2.0 Pushed Authorization Requests
/// which enhances security by allowing clients to push authorization request
/// parameters directly to the authorization server.
use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// PAR request containing authorization parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest {
    /// Client identifier
    pub client_id: String,

    /// Response type (e.g., "code")
    pub response_type: String,

    /// Redirect URI
    pub redirect_uri: String,

    /// Requested scopes
    pub scope: Option<String>,

    /// State parameter
    pub state: Option<String>,

    /// PKCE code challenge
    pub code_challenge: Option<String>,

    /// PKCE code challenge method
    pub code_challenge_method: Option<String>,

    /// Additional parameters
    #[serde(flatten)]
    pub additional_params: HashMap<String, String>,
}

/// PAR response containing request URI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationResponse {
    /// Request URI to be used in subsequent authorization request
    pub request_uri: String,

    /// Expiration time in seconds
    pub expires_in: u64,
}

/// Stored PAR request with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPushedRequest {
    /// Original request parameters
    pub request: PushedAuthorizationRequest,

    /// When the request was created
    pub created_at: SystemTime,

    /// When the request expires
    pub expires_at: SystemTime,

    /// Whether the request has been used
    pub used: bool,
}

/// PAR request manager with persistent storage
use std::fmt;

#[derive(Clone)]
pub struct PARManager {
    /// Persistent storage backend
    storage: Arc<dyn AuthStorage>,

    /// Memory cache for fast access
    requests: Arc<tokio::sync::RwLock<HashMap<String, StoredPushedRequest>>>,

    /// Default expiration time for PAR requests
    default_expiration: Duration,
}

impl fmt::Debug for PARManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PARManager")
            .field("storage", &"<dyn AuthStorage>")
            .field("default_expiration", &self.default_expiration)
            .finish()
    }
}

impl PARManager {
    /// Create a new PAR manager with storage backend
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            storage,
            requests: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            default_expiration: Duration::from_secs(90), // RFC 9126 recommendation
        }
    }

    /// Create a new PAR manager with custom expiration
    pub fn with_expiration(storage: Arc<dyn AuthStorage>, expiration: Duration) -> Self {
        Self {
            storage,
            requests: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            default_expiration: expiration,
        }
    }

    /// Store a pushed authorization request
    pub async fn store_request(
        &self,
        request: PushedAuthorizationRequest,
    ) -> Result<PushedAuthorizationResponse> {
        // Validate the request
        self.validate_request(&request)?;

        // Generate request URI
        let request_id = Uuid::new_v4().to_string();
        let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", request_id);

        // Calculate expiration
        let now = SystemTime::now();
        let expires_at = now + self.default_expiration;

        // Store the request in persistent storage with TTL
        let stored_request = StoredPushedRequest {
            request: request.clone(),
            created_at: now,
            expires_at,
            used: false,
        };

        // Store in persistent backend with TTL
        let storage_key = format!("par:{}", request_uri);
        let serialized = serde_json::to_string(&stored_request)
            .map_err(|e| AuthError::internal(format!("Failed to serialize PAR request: {}", e)))?;

        self.storage
            .store_kv(
                &storage_key,
                &serialized.into_bytes(),
                Some(self.default_expiration),
            )
            .await
            .map_err(|e| AuthError::internal(format!("Failed to store PAR request: {}", e)))?;

        // Also cache in memory for fast access
        let mut requests = self.requests.write().await;
        requests.insert(request_uri.clone(), stored_request);

        // Clean up expired requests from memory cache
        self.cleanup_expired_requests(&mut requests, now);

        Ok(PushedAuthorizationResponse {
            request_uri,
            expires_in: self.default_expiration.as_secs(),
        })
    }

    /// Retrieve and consume a pushed authorization request
    pub async fn consume_request(&self, request_uri: &str) -> Result<PushedAuthorizationRequest> {
        let storage_key = format!("par:{}", request_uri);

        // Try to load from persistent storage first
        let stored_request = if let Some(data) = self.storage.get_kv(&storage_key).await? {
            let serialized = String::from_utf8(data)
                .map_err(|_| AuthError::internal("Invalid UTF-8 in stored PAR data"))?;

            serde_json::from_str::<StoredPushedRequest>(&serialized).map_err(|e| {
                AuthError::internal(format!("Failed to deserialize PAR request: {}", e))
            })?
        } else {
            // Fallback to memory cache (for backward compatibility during transition)
            let requests = self.requests.read().await;
            requests
                .get(request_uri)
                .cloned()
                .ok_or_else(|| AuthError::auth_method("par", "Invalid request_uri"))?
        };

        // Check if expired
        let now = SystemTime::now();
        if now > stored_request.expires_at {
            // Clean up from both storage and cache
            let _ = self.storage.delete_kv(&storage_key).await;
            let mut requests = self.requests.write().await;
            requests.remove(request_uri);
            return Err(AuthError::auth_method("par", "Request URI expired"));
        }

        // Check if already used
        if stored_request.used {
            return Err(AuthError::auth_method("par", "Request URI already used"));
        }

        // Mark as consumed by removing from storage (single use)
        self.storage
            .delete_kv(&storage_key)
            .await
            .map_err(|e| AuthError::internal(format!("Failed to consume PAR request: {}", e)))?;

        // Also remove from memory cache
        let mut requests = self.requests.write().await;
        requests.remove(request_uri);

        Ok(stored_request.request)
    }

    /// Validate a PAR request
    fn validate_request(&self, request: &PushedAuthorizationRequest) -> Result<()> {
        // Validate required parameters
        if request.client_id.is_empty() {
            return Err(AuthError::auth_method("par", "Missing client_id"));
        }

        if request.response_type.is_empty() {
            return Err(AuthError::auth_method("par", "Missing response_type"));
        }

        if request.redirect_uri.is_empty() {
            return Err(AuthError::auth_method("par", "Missing redirect_uri"));
        }

        // Validate redirect URI format
        if url::Url::parse(&request.redirect_uri).is_err() {
            return Err(AuthError::auth_method("par", "Invalid redirect_uri format"));
        }

        // Validate PKCE parameters if present
        if let (Some(challenge), Some(method)) =
            (&request.code_challenge, &request.code_challenge_method)
        {
            if method != "S256" && method != "plain" {
                return Err(AuthError::auth_method(
                    "par",
                    "Invalid code_challenge_method",
                ));
            }

            if challenge.is_empty() {
                return Err(AuthError::auth_method("par", "Empty code_challenge"));
            }
        }

        Ok(())
    }

    /// Clean up expired requests
    fn cleanup_expired_requests(
        &self,
        requests: &mut HashMap<String, StoredPushedRequest>,
        now: SystemTime,
    ) {
        requests.retain(|_, stored_request| now <= stored_request.expires_at);
    }

    /// Get statistics about stored requests
    pub async fn get_statistics(&self) -> PARStatistics {
        let requests = self.requests.read().await;
        let now = SystemTime::now();

        let total_count = requests.len();
        let expired_count = requests.values().filter(|req| now > req.expires_at).count();
        let used_count = requests.values().filter(|req| req.used).count();

        PARStatistics {
            total_requests: total_count,
            expired_requests: expired_count,
            used_requests: used_count,
            active_requests: total_count - expired_count - used_count,
        }
    }
}

/// PAR statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PARStatistics {
    /// Total number of stored requests
    pub total_requests: usize,

    /// Number of expired requests
    pub expired_requests: usize,

    /// Number of used requests
    pub used_requests: usize,

    /// Number of active (valid, unused) requests
    pub active_requests: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    fn create_test_request() -> PushedAuthorizationRequest {
        PushedAuthorizationRequest {
            client_id: "test_client".to_string(),
            response_type: "code".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid profile".to_string()),
            state: Some("test_state".to_string()),
            code_challenge: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
            code_challenge_method: Some("S256".to_string()),
            additional_params: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_store_and_consume_request() {
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let par_manager = PARManager::new(storage);
        let request = create_test_request();

        // Store the request
        let response = par_manager.store_request(request.clone()).await.unwrap();
        assert!(
            response
                .request_uri
                .starts_with("urn:ietf:params:oauth:request_uri:")
        );
        assert_eq!(response.expires_in, 90);

        // Consume the request
        let consumed_request = par_manager
            .consume_request(&response.request_uri)
            .await
            .unwrap();
        assert_eq!(consumed_request.client_id, request.client_id);
        assert_eq!(consumed_request.response_type, request.response_type);

        // Try to consume again (should fail)
        let result = par_manager.consume_request(&response.request_uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_expiration() {
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let par_manager = PARManager::with_expiration(storage, Duration::from_millis(50));
        let request = create_test_request();

        // Store the request
        let response = par_manager.store_request(request).await.unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(100)).await;

        // Try to consume (should fail due to expiration)
        let result = par_manager.consume_request(&response.request_uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_request_validation() {
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let par_manager = PARManager::new(storage);

        // Test missing client_id
        let mut request = create_test_request();
        request.client_id = "".to_string();
        let result = par_manager.store_request(request).await;
        assert!(result.is_err());

        // Test invalid redirect_uri
        let mut request = create_test_request();
        request.redirect_uri = "invalid-uri".to_string();
        let result = par_manager.store_request(request).await;
        assert!(result.is_err());

        // Test invalid PKCE method
        let mut request = create_test_request();
        request.code_challenge_method = Some("invalid".to_string());
        let result = par_manager.store_request(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_statistics() {
        use crate::storage::MemoryStorage;
        use std::sync::Arc;

        let storage = Arc::new(MemoryStorage::new());
        let par_manager = PARManager::new(storage);
        let request = create_test_request();

        // Initial statistics
        let stats = par_manager.get_statistics().await;
        assert_eq!(stats.total_requests, 0);

        // Store a request
        let response = par_manager.store_request(request).await.unwrap();
        let stats = par_manager.get_statistics().await;
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.active_requests, 1);

        // Consume the request
        par_manager
            .consume_request(&response.request_uri)
            .await
            .unwrap();
        let stats = par_manager.get_statistics().await;
        assert_eq!(stats.total_requests, 0); // Removed after consumption
    }
}


