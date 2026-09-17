//! Device Authorization Grant Implementation - RFC 8628
//!
//! This module implements RFC 8628 - OAuth 2.0 Device Authorization Grant
//! which allows devices with limited input capability (smart TVs, printers, etc.)
//! to obtain user authorization.

use crate::errors::{AuthError, Result};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Device authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Client identifier
    pub client_id: String,

    /// Requested scopes
    pub scope: Option<String>,
}

/// Device authorization response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// Device verification code (for storage)
    pub device_code: String,

    /// User-friendly code to enter
    pub user_code: String,

    /// URL where user should authorize
    pub verification_uri: String,

    /// Complete verification URL with user_code (optional)
    pub verification_uri_complete: Option<String>,

    /// Polling interval in seconds
    pub interval: u64,

    /// Device code expires in seconds
    pub expires_in: u64,
}

/// Token request for device code grant
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceTokenRequest {
    /// Grant type (must be "urn:ietf:params:oauth:grant-type:device_code")
    pub grant_type: String,

    /// Device code received from device authorization
    pub device_code: String,

    /// Client identifier
    pub client_id: String,
}

/// Stored device authorization data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDeviceAuthorization {
    /// Device code
    pub device_code: String,

    /// User code
    pub user_code: String,

    /// Client ID
    pub client_id: String,

    /// Requested scopes
    pub scope: Option<String>,

    /// Authorization status
    pub status: DeviceAuthorizationStatus,

    /// User ID (once authorized)
    pub user_id: Option<String>,

    /// When the request was created
    pub created_at: SystemTime,

    /// When the request expires
    pub expires_at: SystemTime,

    /// Last poll time (for slow_down error)
    pub last_poll: Option<SystemTime>,

    /// Number of times the client has been told to slow down (RFC 8628 §3.5).
    /// Each slow_down increases the required interval by 5 seconds.
    #[serde(default)]
    pub slow_down_count: u32,
}

/// Device authorization status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DeviceAuthorizationStatus {
    /// Awaiting user authorization
    Pending,
    /// User has authorized
    Authorized,
    /// User has denied
    Denied,
    /// Authorization expired
    Expired,
}

/// Device authorization manager with persistent storage
use std::fmt;

#[derive(Clone)]
pub struct DeviceAuthManager {
    /// Persistent storage backend
    storage: Arc<dyn AuthStorage>,

    /// Memory cache for fast access
    authorizations: Arc<tokio::sync::RwLock<HashMap<String, StoredDeviceAuthorization>>>,

    /// Default expiration time for device codes
    default_expiration: Duration,

    /// Minimum polling interval
    min_interval: Duration,

    /// Base verification URI
    verification_uri: String,
}

impl fmt::Debug for DeviceAuthManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthManager")
            .field("storage", &"<dyn AuthStorage>")
            .field("default_expiration", &self.default_expiration)
            .field("min_interval", &self.min_interval)
            .field("verification_uri", &self.verification_uri)
            .finish()
    }
}

impl DeviceAuthManager {
    /// Create a new device authorization manager
    pub fn new(storage: Arc<dyn AuthStorage>, verification_uri: String) -> Self {
        Self {
            storage,
            authorizations: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            default_expiration: Duration::from_secs(600), // 10 minutes (RFC 8628 recommendation)
            min_interval: Duration::from_secs(5),         // 5 seconds minimum
            verification_uri,
        }
    }

    /// Create a new device authorization manager with custom settings
    pub fn with_settings(
        storage: Arc<dyn AuthStorage>,
        verification_uri: String,
        expiration: Duration,
        min_interval: Duration,
    ) -> Self {
        Self {
            storage,
            authorizations: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            default_expiration: expiration,
            min_interval,
            verification_uri,
        }
    }

    /// Set the default expiration time for device codes (chainable).
    ///
    /// Default: 600 seconds (10 minutes, per RFC 8628 recommendation).
    pub fn expiration(mut self, expiration: Duration) -> Self {
        self.default_expiration = expiration;
        self
    }

    /// Set the minimum polling interval (chainable).
    ///
    /// Default: 5 seconds.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }

    /// Initiate device authorization flow
    pub async fn create_authorization(
        &self,
        request: DeviceAuthorizationRequest,
    ) -> Result<DeviceAuthorizationResponse> {
        // Validate the request
        self.validate_request(&request)?;

        // Generate device code and user code
        let device_code = format!("dc_{}", Uuid::new_v4().simple());
        let user_code = self.generate_user_code();

        // Calculate expiration
        let now = SystemTime::now();
        let expires_at = now + self.default_expiration;

        // Create stored authorization
        let stored = StoredDeviceAuthorization {
            device_code: device_code.clone(),
            user_code: user_code.clone(),
            client_id: request.client_id.clone(),
            scope: request.scope.clone(),
            status: DeviceAuthorizationStatus::Pending,
            user_id: None,
            created_at: now,
            expires_at,
            last_poll: None,
            slow_down_count: 0,
        };

        // Store in persistent backend with TTL
        let device_key = format!("device_code:{}", device_code);
        let user_key = format!("user_code:{}", user_code);

        let serialized = serde_json::to_string(&stored)
            .map_err(|e| AuthError::internal(format!("Failed to serialize device auth: {}", e)))?;

        self.storage
            .store_kv(
                &device_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await
            .map_err(|e| {
                AuthError::internal(format!("Failed to store device authorization: {}", e))
            })?;

        // Also store under user_code for verification page
        self.storage
            .store_kv(
                &user_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await
            .map_err(|e| {
                AuthError::internal(format!("Failed to store user code mapping: {}", e))
            })?;

        // Cache in memory
        let mut authorizations = self.authorizations.write().await;
        authorizations.insert(device_code.clone(), stored);

        // Cleanup expired entries
        self.cleanup_expired(&mut authorizations, now);

        // Create response
        let verification_uri_complete =
            format!("{}?user_code={}", self.verification_uri, user_code);

        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri: self.verification_uri.clone(),
            verification_uri_complete: Some(verification_uri_complete),
            interval: self.min_interval.as_secs(),
            expires_in: self.default_expiration.as_secs(),
        })
    }

    /// Poll for authorization status (used during token endpoint polling)
    pub async fn poll_authorization(&self, device_code: &str) -> Result<StoredDeviceAuthorization> {
        let device_key = format!("device_code:{}", device_code);

        // Try to load from persistent storage first
        let mut stored = if let Some(data) = self.storage.get_kv(&device_key).await? {
            let serialized = String::from_utf8(data)
                .map_err(|_| AuthError::internal("Invalid UTF-8 in stored device auth data"))?;

            serde_json::from_str::<StoredDeviceAuthorization>(&serialized).map_err(|e| {
                AuthError::internal(format!("Failed to deserialize device auth: {}", e))
            })?
        } else {
            // Fallback to memory cache
            let authorizations = self.authorizations.read().await;
            authorizations
                .get(device_code)
                .cloned()
                .ok_or_else(|| AuthError::auth_method("device_auth", "Invalid device_code"))?
        };

        // Check expiration
        let now = SystemTime::now();
        if now > stored.expires_at {
            stored.status = DeviceAuthorizationStatus::Expired;
            return Err(AuthError::auth_method("device_auth", "Device code expired"));
        }

        // Check for slow_down (polling too frequently) — RFC 8628 §3.5
        // The required interval increases by 5 seconds each time the client
        // polls too fast, implementing exponential backoff.
        let effective_interval =
            self.min_interval + Duration::from_secs(5 * u64::from(stored.slow_down_count));
        if let Some(last_poll) = stored.last_poll {
            let elapsed = now.duration_since(last_poll).unwrap_or(Duration::ZERO);
            if elapsed < effective_interval {
                stored.slow_down_count += 1;
                // Persist the updated slow_down_count
                stored.last_poll = Some(now);
                let serialized = serde_json::to_string(&stored).map_err(|e| {
                    AuthError::internal(format!("Failed to serialize device auth: {}", e))
                })?;
                self.storage
                    .store_kv(
                        &device_key,
                        serialized.as_bytes(),
                        Some(self.default_expiration),
                    )
                    .await
                    .ok();
                let mut authorizations = self.authorizations.write().await;
                authorizations.insert(device_code.to_string(), stored);
                return Err(AuthError::auth_method("device_auth", "slow_down"));
            }
        }

        // Update last poll time
        stored.last_poll = Some(now);

        // Persist updated state
        let serialized = serde_json::to_string(&stored)
            .map_err(|e| AuthError::internal(format!("Failed to serialize device auth: {}", e)))?;

        self.storage
            .store_kv(
                &device_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await
            .ok(); // Ignore errors for poll time update

        // Update memory cache
        let mut authorizations = self.authorizations.write().await;
        authorizations.insert(device_code.to_string(), stored.clone());

        // Return current status
        match stored.status {
            DeviceAuthorizationStatus::Pending => Err(AuthError::auth_method(
                "device_auth",
                "authorization_pending",
            )),
            DeviceAuthorizationStatus::Authorized => Ok(stored),
            DeviceAuthorizationStatus::Denied => {
                Err(AuthError::auth_method("device_auth", "access_denied"))
            }
            DeviceAuthorizationStatus::Expired => {
                Err(AuthError::auth_method("device_auth", "expired_token"))
            }
        }
    }

    /// Authorize a device (called when user approves on verification page)
    pub async fn authorize_device(&self, user_code: &str, user_id: &str) -> Result<()> {
        let user_key = format!("user_code:{}", user_code);

        // Load from storage
        let mut stored = if let Some(data) = self.storage.get_kv(&user_key).await? {
            let serialized = String::from_utf8(data)
                .map_err(|_| AuthError::internal("Invalid UTF-8 in stored device auth data"))?;

            serde_json::from_str::<StoredDeviceAuthorization>(&serialized).map_err(|e| {
                AuthError::internal(format!("Failed to deserialize device auth: {}", e))
            })?
        } else {
            return Err(AuthError::auth_method("device_auth", "Invalid user_code"));
        };

        // Check if expired
        let now = SystemTime::now();
        if now > stored.expires_at {
            return Err(AuthError::auth_method("device_auth", "Device code expired"));
        }

        // Update status
        stored.status = DeviceAuthorizationStatus::Authorized;
        stored.user_id = Some(user_id.to_string());

        // Persist updated state
        let serialized = serde_json::to_string(&stored)
            .map_err(|e| AuthError::internal(format!("Failed to serialize device auth: {}", e)))?;

        let device_key = format!("device_code:{}", stored.device_code);

        self.storage
            .store_kv(
                &device_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await?;

        self.storage
            .store_kv(
                &user_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await?;

        // Update memory cache
        let mut authorizations = self.authorizations.write().await;
        authorizations.insert(stored.device_code.clone(), stored);

        Ok(())
    }

    /// Deny a device authorization
    pub async fn deny_device(&self, user_code: &str) -> Result<()> {
        let user_key = format!("user_code:{}", user_code);

        // Load from storage
        let mut stored = if let Some(data) = self.storage.get_kv(&user_key).await? {
            let serialized = String::from_utf8(data)
                .map_err(|_| AuthError::internal("Invalid UTF-8 in stored device auth data"))?;

            serde_json::from_str::<StoredDeviceAuthorization>(&serialized).map_err(|e| {
                AuthError::internal(format!("Failed to deserialize device auth: {}", e))
            })?
        } else {
            return Err(AuthError::auth_method("device_auth", "Invalid user_code"));
        };

        // Update status
        stored.status = DeviceAuthorizationStatus::Denied;

        // Persist updated state
        let serialized = serde_json::to_string(&stored)
            .map_err(|e| AuthError::internal(format!("Failed to serialize device auth: {}", e)))?;

        let device_key = format!("device_code:{}", stored.device_code);

        self.storage
            .store_kv(
                &device_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await?;

        self.storage
            .store_kv(
                &user_key,
                serialized.as_bytes(),
                Some(self.default_expiration),
            )
            .await?;

        // Update memory cache
        let mut authorizations = self.authorizations.write().await;
        authorizations.insert(stored.device_code.clone(), stored);

        Ok(())
    }

    /// Get device authorization by user code (for verification page)
    pub async fn get_by_user_code(&self, user_code: &str) -> Result<StoredDeviceAuthorization> {
        let user_key = format!("user_code:{}", user_code);

        if let Some(data) = self.storage.get_kv(&user_key).await? {
            let serialized = String::from_utf8(data)
                .map_err(|_| AuthError::internal("Invalid UTF-8 in stored device auth data"))?;

            let stored: StoredDeviceAuthorization =
                serde_json::from_str(&serialized).map_err(|e| {
                    AuthError::internal(format!("Failed to deserialize device auth: {}", e))
                })?;

            // Check expiration
            let now = SystemTime::now();
            if now > stored.expires_at {
                return Err(AuthError::auth_method("device_auth", "User code expired"));
            }

            Ok(stored)
        } else {
            Err(AuthError::auth_method("device_auth", "Invalid user_code"))
        }
    }

    /// Validate device authorization request
    fn validate_request(&self, request: &DeviceAuthorizationRequest) -> Result<()> {
        if request.client_id.is_empty() {
            return Err(AuthError::auth_method("device_auth", "Missing client_id"));
        }

        // In production, validate client_id against registered clients

        Ok(())
    }

    /// Generate a user-friendly code (uppercase, no ambiguous characters)
    fn generate_user_code(&self) -> String {
        use rand::RngExt;
        const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No ambiguous: 0,O,I,1
        let mut rng = rand::rng();

        // Generate 9-character code with dash for readability: XXXX-XXXX
        let code: String = (0..9)
            .map(|i| {
                if i == 4 {
                    '-'
                } else {
                    let idx = rng.random_range(0..CHARS.len());
                    CHARS[idx] as char
                }
            })
            .collect();

        code
    }

    /// Clean up expired entries from memory cache
    fn cleanup_expired(
        &self,
        authorizations: &mut HashMap<String, StoredDeviceAuthorization>,
        now: SystemTime,
    ) {
        authorizations.retain(|_, auth| now <= auth.expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use tokio::time::sleep;

    fn create_test_manager() -> DeviceAuthManager {
        let storage = Arc::new(MemoryStorage::new());
        DeviceAuthManager::new(storage, "https://example.com/device".to_string())
    }

    #[tokio::test]
    async fn test_create_authorization() {
        let manager = create_test_manager();

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: Some("openid profile".to_string()),
        };

        let response = manager.create_authorization(request).await.unwrap();

        assert!(response.device_code.starts_with("dc_"));
        assert_eq!(response.user_code.len(), 9); // XXXX-XXXX
        assert!(response.user_code.contains('-'));
        assert_eq!(response.verification_uri, "https://example.com/device");
        assert!(response.verification_uri_complete.is_some());
        assert_eq!(response.interval, 5);
        assert_eq!(response.expires_in, 600);
    }

    #[tokio::test]
    async fn test_poll_pending() {
        let manager = create_test_manager();

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = manager.create_authorization(request).await.unwrap();

        // Poll should return authorization_pending
        let result = manager.poll_authorization(&response.device_code).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("authorization_pending"));
    }

    #[tokio::test]
    async fn test_authorize_and_poll() {
        let manager = create_test_manager();

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: Some("openid".to_string()),
        };

        let response = manager.create_authorization(request).await.unwrap();

        // Authorize the device
        manager
            .authorize_device(&response.user_code, "user_123")
            .await
            .unwrap();

        // Poll should now succeed
        let stored = manager
            .poll_authorization(&response.device_code)
            .await
            .unwrap();
        assert_eq!(stored.status, DeviceAuthorizationStatus::Authorized);
        assert_eq!(stored.user_id, Some("user_123".to_string()));
    }

    #[tokio::test]
    async fn test_deny_device() {
        let manager = create_test_manager();

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = manager.create_authorization(request).await.unwrap();

        // Deny the device
        manager.deny_device(&response.user_code).await.unwrap();

        // Poll should return access_denied
        let result = manager.poll_authorization(&response.device_code).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("access_denied"));
    }

    #[tokio::test]
    async fn test_slow_down() {
        let manager = create_test_manager();

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = manager.create_authorization(request).await.unwrap();

        // First poll
        let _ = manager.poll_authorization(&response.device_code).await;

        // Immediate second poll should return slow_down
        let result = manager.poll_authorization(&response.device_code).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("slow_down"));
    }

    #[tokio::test]
    async fn test_expiration() {
        let storage = Arc::new(MemoryStorage::new());
        // Create manager with very short expiration
        let manager = DeviceAuthManager::with_settings(
            storage,
            "https://example.com/device".to_string(),
            Duration::from_millis(100),
            Duration::from_secs(1),
        );

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = manager.create_authorization(request).await.unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(150)).await;

        // Poll should return expired
        let result = manager.poll_authorization(&response.device_code).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_chainable_expiration_and_interval() {
        let storage = Arc::new(MemoryStorage::new());
        let manager = DeviceAuthManager::new(storage, "https://example.com/device".to_string())
            .expiration(Duration::from_secs(300))
            .interval(Duration::from_secs(10));

        let request = DeviceAuthorizationRequest {
            client_id: "test_client".to_string(),
            scope: None,
        };

        let response = manager.create_authorization(request).await.unwrap();
        assert_eq!(response.expires_in, 300);
        assert_eq!(response.interval, 10);
    }
}
