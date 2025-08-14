use crate::audit::{
    ActorInfo, AuditEvent, AuditEventType, EventOutcome, RequestMetadata, ResourceInfo, RiskLevel,
};
/// DashMap-based storage implementation with deadlock-safe patterns
///
/// This implementation replaces RwLock<HashMap> with DashMap to provide:
/// - Lock-free concurrent access
/// - Deadlock-free operations
/// - Better performance under high concurrency
///
/// Key safety principles:
/// 1. Never hold multiple DashMap references simultaneously
/// 2. Always extract values immediately rather than holding references
/// 3. Use atomic operations for cross-map updates
/// 4. Scope all operations to prevent reference leaks
use crate::errors::Result;
use crate::storage::core::{AuthStorage, SessionData};
use crate::tokens::AuthToken;
use async_trait::async_trait;
use dashmap::DashMap;
use std::time::Duration;

/// Wrapper for tokens with expiration tracking
#[derive(Debug, Clone)]
struct TimestampedToken {
    token: AuthToken,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Wrapper for sessions with expiration tracking
#[derive(Debug, Clone)]
struct TimestampedSession {
    session: SessionData,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Wrapper for KV values with expiration
#[derive(Debug, Clone)]
struct TimestampedValue {
    data: Vec<u8>,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TimestampedToken {
    fn new(token: AuthToken, ttl: Option<Duration>) -> Self {
        let now = chrono::Utc::now();
        let expires_at = ttl.map(|d| now + chrono::Duration::from_std(d).unwrap());

        Self {
            token,
            created_at: now,
            expires_at,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| chrono::Utc::now() > exp)
            .unwrap_or(false)
    }
}

impl TimestampedSession {
    fn new(session: SessionData) -> Self {
        Self {
            session,
            created_at: chrono::Utc::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.session.is_expired()
    }
}

impl TimestampedValue {
    fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        let now = chrono::Utc::now();
        let expires_at = ttl.map(|d| now + chrono::Duration::from_std(d).unwrap());

        Self {
            data,
            created_at: now,
            expires_at,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| chrono::Utc::now() > exp)
            .unwrap_or(false)
    }
}

/// DashMap-based storage with deadlock-safe patterns
#[derive(Debug, Clone)]
pub struct DashMapMemoryStorage {
    // Core storage maps
    tokens: DashMap<String, TimestampedToken>,
    sessions: DashMap<String, TimestampedSession>,
    kv_store: DashMap<String, TimestampedValue>,

    // Index maps for efficient lookups
    access_token_to_id: DashMap<String, String>,
    user_to_tokens: DashMap<String, Vec<String>>,
    user_to_sessions: DashMap<String, Vec<String>>,

    // Configuration
    default_ttl: Option<Duration>,
}

impl Default for DashMapMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl DashMapMemoryStorage {
    /// Create a new DashMap-based storage
    pub fn new() -> Self {
        Self {
            tokens: DashMap::new(),
            sessions: DashMap::new(),
            kv_store: DashMap::new(),
            access_token_to_id: DashMap::new(),
            user_to_tokens: DashMap::new(),
            user_to_sessions: DashMap::new(),
            default_ttl: None,
        }
    }

    /// Create storage with default TTL for all stored items
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            tokens: DashMap::new(),
            sessions: DashMap::new(),
            kv_store: DashMap::new(),
            access_token_to_id: DashMap::new(),
            user_to_tokens: DashMap::new(),
            user_to_sessions: DashMap::new(),
            default_ttl: Some(ttl),
        }
    }

    /// Generate audit event for storage operations
    fn create_audit_event(
        &self,
        event_type: AuditEventType,
        user_id: &str,
        resource_id: &str,
        resource_type: &str,
        outcome: EventOutcome,
        details_str: Option<&str>,
    ) -> AuditEvent {
        let mut details = std::collections::HashMap::new();
        if let Some(detail) = details_str {
            details.insert("operation_details".to_string(), detail.to_string());
        }
        details.insert("resource_type".to_string(), resource_type.to_string());
        details.insert("resource_id".to_string(), resource_id.to_string());

        AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.clone(),
            timestamp: std::time::SystemTime::now(),
            user_id: Some(user_id.to_string()),
            session_id: None,
            outcome,
            risk_level: match &event_type {
                AuditEventType::TokenRevoked | AuditEventType::TokenExpired => RiskLevel::Medium,
                AuditEventType::SuspiciousActivity => RiskLevel::High,
                _ => RiskLevel::Low,
            },
            description: format!(
                "{:?} operation on {} {}",
                event_type, resource_type, resource_id
            ),
            details,
            request_metadata: RequestMetadata {
                ip_address: None,
                user_agent: None,
                request_id: None,
                endpoint: Some("storage".to_string()),
                http_method: None,
                geolocation: None,
                device_info: None,
            },
            resource: Some(ResourceInfo {
                resource_type: resource_type.to_string(),
                resource_id: resource_id.to_string(),
                resource_name: None,
                attributes: std::collections::HashMap::new(),
            }),
            actor: ActorInfo {
                actor_type: "storage_system".to_string(),
                actor_id: user_id.to_string(),
                actor_name: Some(user_id.to_string()),
                roles: vec!["storage_user".to_string()],
            },
            correlation_id: None,
        }
    }

    /// Log storage operation with lifecycle information
    async fn log_storage_operation(
        &self,
        event_type: AuditEventType,
        user_id: &str,
        resource_id: &str,
        resource_type: &str,
        created_at: Option<chrono::DateTime<chrono::Utc>>,
        outcome: EventOutcome,
    ) {
        let details = if let Some(created) = created_at {
            let age = chrono::Utc::now().signed_duration_since(created);
            format!(
                "{:?} operation on {} {} (age: {} seconds)",
                event_type,
                resource_type,
                resource_id,
                age.num_seconds()
            )
        } else {
            format!(
                "{:?} operation on {} {}",
                event_type, resource_type, resource_id
            )
        };

        let audit_event = self.create_audit_event(
            event_type,
            user_id,
            resource_id,
            resource_type,
            outcome,
            Some(&details),
        );

        // Log the audit event - in production this would go to the audit logger
        log::info!(
            "STORAGE AUDIT: {}",
            serde_json::to_string(&audit_event).unwrap_or_default()
        );
    }

    /// Get storage statistics for audit reporting
    pub fn get_storage_statistics(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut stats = std::collections::HashMap::new();
        stats.insert(
            "total_tokens".to_string(),
            serde_json::Value::from(self.tokens.len()),
        );
        stats.insert(
            "total_sessions".to_string(),
            serde_json::Value::from(self.sessions.len()),
        );
        stats.insert(
            "total_kv_pairs".to_string(),
            serde_json::Value::from(self.kv_store.len()),
        );
        stats.insert(
            "total_users_with_tokens".to_string(),
            serde_json::Value::from(self.user_to_tokens.len()),
        );
        stats.insert(
            "total_users_with_sessions".to_string(),
            serde_json::Value::from(self.user_to_sessions.len()),
        );
        stats.insert(
            "timestamp".to_string(),
            serde_json::Value::from(chrono::Utc::now().to_rfc3339()),
        );
        stats
    }

    /// Audit tokens by age - find old tokens for security review
    pub fn audit_token_ages(&self) -> Vec<(String, String, i64)> {
        let mut aged_tokens = Vec::new();
        let now = chrono::Utc::now();

        for entry in self.tokens.iter() {
            let age_seconds = now.signed_duration_since(entry.created_at).num_seconds();
            aged_tokens.push((
                entry.key().clone(),
                entry.token.user_id.clone(),
                age_seconds,
            ));
        }

        aged_tokens.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by age descending
        aged_tokens
    }

    /// Audit sessions by age - find old sessions for security review
    pub fn audit_session_ages(&self) -> Vec<(String, String, i64)> {
        let mut aged_sessions = Vec::new();
        let now = chrono::Utc::now();

        for entry in self.sessions.iter() {
            let age_seconds = now.signed_duration_since(entry.created_at).num_seconds();
            aged_sessions.push((
                entry.key().clone(),
                entry.session.user_id.clone(),
                age_seconds,
            ));
        }

        aged_sessions.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by age descending
        aged_sessions
    }

    /// Generate comprehensive audit report
    pub fn generate_audit_report(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut report = self.get_storage_statistics();

        let token_ages = self.audit_token_ages();
        let session_ages = self.audit_session_ages();

        // Add age analysis
        if !token_ages.is_empty() {
            report.insert(
                "oldest_token_age_seconds".to_string(),
                serde_json::Value::from(token_ages[0].2),
            );
            report.insert(
                "tokens_older_than_24h".to_string(),
                serde_json::Value::from(
                    token_ages.iter().filter(|(_, _, age)| *age > 86400).count(),
                ),
            );
        }

        if !session_ages.is_empty() {
            report.insert(
                "oldest_session_age_seconds".to_string(),
                serde_json::Value::from(session_ages[0].2),
            );
            report.insert(
                "sessions_older_than_24h".to_string(),
                serde_json::Value::from(
                    session_ages
                        .iter()
                        .filter(|(_, _, age)| *age > 86400)
                        .count(),
                ),
            );
        }

        report
    }

    /// DEADLOCK-SAFE: Add token to user index
    /// Uses atomic operations to prevent cross-map deadlocks
    fn add_token_to_user_index(&self, user_id: &str, token_id: &str) {
        // SAFE: Scoped operation that doesn't hold references across map operations
        self.user_to_tokens
            .entry(user_id.to_string())
            .and_modify(|tokens| tokens.push(token_id.to_string()))
            .or_insert_with(|| vec![token_id.to_string()]);
    }

    /// DEADLOCK-SAFE: Remove token from user index
    fn remove_token_from_user_index(&self, user_id: &str, token_id: &str) {
        // SAFE: Scoped operation with immediate value extraction
        if let Some(mut entry) = self.user_to_tokens.get_mut(user_id) {
            entry.retain(|id| id != token_id);
            if entry.is_empty() {
                drop(entry); // Release the entry before removal
                self.user_to_tokens.remove(user_id);
            }
        }
    }

    /// DEADLOCK-SAFE: Add session to user index
    fn add_session_to_user_index(&self, user_id: &str, session_id: &str) {
        self.user_to_sessions
            .entry(user_id.to_string())
            .and_modify(|sessions| sessions.push(session_id.to_string()))
            .or_insert_with(|| vec![session_id.to_string()]);
    }

    /// DEADLOCK-SAFE: Remove session from user index
    fn remove_session_from_user_index(&self, user_id: &str, session_id: &str) {
        if let Some(mut entry) = self.user_to_sessions.get_mut(user_id) {
            entry.retain(|id| id != session_id);
            if entry.is_empty() {
                drop(entry);
                self.user_to_sessions.remove(user_id);
            }
        }
    }
}

#[async_trait]
impl AuthStorage for DashMapMemoryStorage {
    async fn store_token(&self, token: &AuthToken) -> Result<()> {
        let timestamped = TimestampedToken::new(token.clone(), self.default_ttl);
        let created_at = timestamped.created_at;

        // SAFE: Store in primary map first
        self.tokens.insert(token.token_id.clone(), timestamped);

        // SAFE: Update access token index (no cross-map references)
        self.access_token_to_id
            .insert(token.access_token.clone(), token.token_id.clone());

        // SAFE: Update user index (atomic operation)
        self.add_token_to_user_index(&token.user_id, &token.token_id);

        // Log storage operation with creation timestamp
        self.log_storage_operation(
            AuditEventType::LoginSuccess, // Token storage represents successful authentication
            &token.user_id,
            &token.token_id,
            "token",
            Some(created_at),
            EventOutcome::Success,
        )
        .await;

        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<AuthToken>> {
        // SAFE: Immediate value extraction, no reference holding
        if let Some(timestamped) = self.tokens.get(token_id) {
            let created_at = timestamped.created_at;
            let user_id = timestamped.token.user_id.clone();

            if timestamped.is_expired() {
                drop(timestamped); // Release reference
                self.tokens.remove(token_id); // Cleanup expired

                // Log expired token access attempt
                self.log_storage_operation(
                    AuditEventType::TokenExpired,
                    &user_id,
                    token_id,
                    "token",
                    Some(created_at),
                    EventOutcome::Failure,
                )
                .await;

                return Ok(None);
            }

            let token = timestamped.token.clone();
            drop(timestamped); // Release reference

            // Log successful token access
            self.log_storage_operation(
                AuditEventType::LoginSuccess, // Token access represents authentication validation
                &user_id,
                token_id,
                "token",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;

            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    async fn get_token_by_access_token(&self, access_token: &str) -> Result<Option<AuthToken>> {
        // SAFE: Two-step lookup with immediate value extraction
        if let Some(token_id_entry) = self.access_token_to_id.get(access_token) {
            let token_id = token_id_entry.clone(); // Extract value immediately
            drop(token_id_entry); // Release first map reference
            self.get_token(&token_id).await // Use extracted value
        } else {
            Ok(None)
        }
    }

    async fn update_token(&self, token: &AuthToken) -> Result<()> {
        // SAFE: Update is same as store for this implementation
        self.store_token(token).await
    }

    async fn delete_token(&self, token_id: &str) -> Result<()> {
        // SAFE: Extract token info before removal to avoid reference issues
        let token_info = if let Some(timestamped) = self.tokens.get(token_id) {
            Some((
                timestamped.token.user_id.clone(),
                timestamped.token.access_token.clone(),
                timestamped.created_at,
            ))
        } else {
            None
        };

        if let Some((user_id, access_token, created_at)) = token_info {
            // SAFE: All operations use extracted values, no cross-map references
            self.tokens.remove(token_id);
            self.access_token_to_id.remove(&access_token);
            self.remove_token_from_user_index(&user_id, token_id);

            // Log token deletion with creation timestamp for audit trail
            self.log_storage_operation(
                AuditEventType::TokenRevoked,
                &user_id,
                token_id,
                "token",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;
        }

        Ok(())
    }

    async fn list_user_tokens(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        // SAFE: Extract token IDs first, then lookup individually
        let token_ids = if let Some(ids) = self.user_to_tokens.get(user_id) {
            ids.clone() // Immediate extraction
        } else {
            return Ok(Vec::new());
        };

        let mut tokens = Vec::new();
        let mut expired_tokens = Vec::new();

        // SAFE: Iterate over extracted IDs, no cross-map reference holding
        for token_id in token_ids {
            if let Some(timestamped) = self.tokens.get(&token_id) {
                if timestamped.is_expired() {
                    expired_tokens.push(token_id);
                } else {
                    tokens.push(timestamped.token.clone());
                }
            } else {
                expired_tokens.push(token_id); // Token was removed elsewhere
            }
        }

        // SAFE: Cleanup expired tokens (uses extracted IDs)
        for token_id in expired_tokens {
            self.delete_token(&token_id).await?;
        }

        Ok(tokens)
    }

    async fn store_session(&self, session_id: &str, data: &SessionData) -> Result<()> {
        let timestamped = TimestampedSession::new(data.clone());
        let created_at = timestamped.created_at;

        // SAFE: Store in primary map first
        self.sessions.insert(session_id.to_string(), timestamped);

        // SAFE: Update user index (atomic operation)
        self.add_session_to_user_index(&data.user_id, session_id);

        // Log session storage with creation timestamp
        self.log_storage_operation(
            AuditEventType::LoginSuccess, // Session creation represents successful login
            &data.user_id,
            session_id,
            "session",
            Some(created_at),
            EventOutcome::Success,
        )
        .await;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        // SAFE: Immediate value extraction
        if let Some(timestamped) = self.sessions.get(session_id) {
            let created_at = timestamped.created_at;
            let user_id = timestamped.session.user_id.clone();

            if timestamped.is_expired() {
                drop(timestamped);
                self.sessions.remove(session_id);

                // Log expired session access
                self.log_storage_operation(
                    AuditEventType::TokenExpired, // Session expiration
                    &user_id,
                    session_id,
                    "session",
                    Some(created_at),
                    EventOutcome::Failure,
                )
                .await;

                return Ok(None);
            }

            let session = timestamped.session.clone();
            drop(timestamped);

            // Log successful session access
            self.log_storage_operation(
                AuditEventType::LoginSuccess, // Session access represents continued authentication
                &user_id,
                session_id,
                "session",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        // SAFE: Extract session info before removal
        let session_info = if let Some(timestamped) = self.sessions.get(session_id) {
            Some((timestamped.session.user_id.clone(), timestamped.created_at))
        } else {
            None
        };

        if let Some((user_id, created_at)) = session_info {
            self.sessions.remove(session_id);
            self.remove_session_from_user_index(&user_id, session_id);

            // Log session deletion with creation timestamp
            self.log_storage_operation(
                AuditEventType::Logout,
                &user_id,
                session_id,
                "session",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;
        }

        Ok(())
    }

    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        // SAFE: Extract session IDs first
        let session_ids = if let Some(ids) = self.user_to_sessions.get(user_id) {
            ids.clone()
        } else {
            return Ok(Vec::new());
        };

        let mut sessions = Vec::new();
        let mut expired_sessions = Vec::new();

        // SAFE: Iterate over extracted IDs
        for session_id in session_ids {
            if let Some(timestamped) = self.sessions.get(&session_id) {
                if timestamped.is_expired() {
                    expired_sessions.push(session_id);
                } else {
                    sessions.push(timestamped.session.clone());
                }
            } else {
                expired_sessions.push(session_id);
            }
        }

        // SAFE: Cleanup expired sessions
        for session_id in expired_sessions {
            self.delete_session(&session_id).await?;
        }

        Ok(sessions)
    }

    async fn store_kv(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let timestamped = TimestampedValue::new(value.to_vec(), ttl.or(self.default_ttl));
        let created_at = timestamped.created_at;

        self.kv_store.insert(key.to_string(), timestamped);

        // Log KV storage operation with creation timestamp
        self.log_storage_operation(
            AuditEventType::ConfigurationChanged, // KV operations represent configuration/data changes
            "system",                             // KV operations are typically system-level
            key,
            "kv_pair",
            Some(created_at),
            EventOutcome::Success,
        )
        .await;

        Ok(())
    }

    async fn get_kv(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // SAFE: Immediate value extraction
        if let Some(timestamped) = self.kv_store.get(key) {
            let created_at = timestamped.created_at;

            if timestamped.is_expired() {
                drop(timestamped);
                self.kv_store.remove(key);

                // Log expired KV access
                self.log_storage_operation(
                    AuditEventType::TokenExpired, // Data expiration
                    "system",
                    key,
                    "kv_pair",
                    Some(created_at),
                    EventOutcome::Failure,
                )
                .await;

                return Ok(None);
            }

            let data = timestamped.data.clone();
            drop(timestamped);

            // Log successful KV access
            self.log_storage_operation(
                AuditEventType::ConfigurationChanged, // KV access
                "system",
                key,
                "kv_pair",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;

            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn delete_kv(&self, key: &str) -> Result<()> {
        // SAFE: Extract creation timestamp before removal
        let created_at = if let Some(timestamped) = self.kv_store.get(key) {
            Some(timestamped.created_at)
        } else {
            None
        };

        self.kv_store.remove(key);

        if let Some(created_at) = created_at {
            // Log KV deletion with creation timestamp
            self.log_storage_operation(
                AuditEventType::ConfigurationChanged, // KV deletion
                "system",
                key,
                "kv_pair",
                Some(created_at),
                EventOutcome::Success,
            )
            .await;
        }

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // SAFE: Collect expired keys first, then remove them
        let mut expired_tokens = Vec::new();
        let mut expired_sessions = Vec::new();
        let mut expired_kvs = Vec::new();

        // SAFE: Scan for expired items (no cross-map operations)
        for entry in self.tokens.iter() {
            if entry.is_expired() {
                expired_tokens.push(entry.key().clone());
            }
        }

        for entry in self.sessions.iter() {
            if entry.is_expired() {
                expired_sessions.push(entry.key().clone());
            }
        }

        for entry in self.kv_store.iter() {
            if entry.is_expired() {
                expired_kvs.push(entry.key().clone());
            }
        }

        // SAFE: Remove expired items using extracted keys
        for token_id in expired_tokens {
            self.delete_token(&token_id).await?;
        }

        for session_id in expired_sessions {
            self.delete_session(&session_id).await?;
        }

        for key in expired_kvs {
            self.delete_kv(&key).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_infrastructure::TestEnvironmentGuard, tokens::TokenMetadata};
    use std::collections::HashMap;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn test_basic_token_operations() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-test");
        let storage = DashMapMemoryStorage::new();

        let token = AuthToken {
            token_id: "test-token".to_string(),
            user_id: "test-user".to_string(),
            access_token: "access-123".to_string(),
            token_type: Some("bearer".to_string()),
            subject: Some("test-user".to_string()),
            issuer: Some("test-issuer".to_string()),
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            scopes: vec!["read".to_string()],
            auth_method: "password".to_string(),
            client_id: Some("test-client".to_string()),
            user_profile: None,
            metadata: TokenMetadata::default(),
        };

        // Store token
        storage.store_token(&token).await.unwrap();

        // Get token by ID
        let retrieved = storage.get_token("test-token").await.unwrap().unwrap();
        assert_eq!(retrieved.user_id, "test-user");

        // Get token by access token
        let retrieved = storage
            .get_token_by_access_token("access-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.token_id, "test-token");

        // List user tokens
        let user_tokens = storage.list_user_tokens("test-user").await.unwrap();
        assert_eq!(user_tokens.len(), 1);

        // Delete token
        storage.delete_token("test-token").await.unwrap();
        let retrieved = storage.get_token("test-token").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_session_operations() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-session-test");
        let storage = DashMapMemoryStorage::new();

        let session = SessionData {
            session_id: "test-session".to_string(),
            user_id: "test-user".to_string(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            data: HashMap::new(),
        };

        // Store session
        storage
            .store_session("test-session", &session)
            .await
            .unwrap();

        // Get session
        let retrieved = storage.get_session("test-session").await.unwrap().unwrap();
        assert_eq!(retrieved.user_id, "test-user");

        // List user sessions
        let user_sessions = storage.list_user_sessions("test-user").await.unwrap();
        assert_eq!(user_sessions.len(), 1);

        // Delete session
        storage.delete_session("test-session").await.unwrap();
        let retrieved = storage.get_session("test-session").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_kv_operations() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-kv-test");
        let storage = DashMapMemoryStorage::new();

        let key = "test-key";
        let value = b"test-value";

        // Store KV
        storage
            .store_kv(key, value, Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        // Get KV
        let retrieved = storage.get_kv(key).await.unwrap().unwrap();
        assert_eq!(retrieved, value);

        // Delete KV
        storage.delete_kv(key).await.unwrap();
        let retrieved = storage.get_kv(key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_operations_no_deadlock() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-concurrent-test");
        let storage = std::sync::Arc::new(DashMapMemoryStorage::new());

        let mut join_set = JoinSet::new();

        // Spawn multiple tasks doing concurrent operations
        for i in 0..10 {
            let storage = storage.clone();
            join_set.spawn(async move {
                for j in 0..50 {
                    let token = AuthToken {
                        token_id: format!("token-{}-{}", i, j),
                        user_id: format!("user-{}", i % 3), // Multiple users per task
                        access_token: format!("access-{}-{}", i, j),
                        token_type: Some("bearer".to_string()),
                        subject: Some(format!("user-{}", i % 3)),
                        issuer: Some("test-issuer".to_string()),
                        refresh_token: None,
                        issued_at: chrono::Utc::now(),
                        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                        scopes: vec!["read".to_string()],
                        auth_method: "password".to_string(),
                        client_id: Some("test-client".to_string()),
                        user_profile: None,
                        metadata: TokenMetadata::default(),
                    };

                    // Store token
                    storage.store_token(&token).await.unwrap();

                    // Immediately list user tokens (tests cross-map operations)
                    let _user_tokens = storage.list_user_tokens(&token.user_id).await.unwrap();

                    // Get by access token
                    let _retrieved = storage
                        .get_token_by_access_token(&token.access_token)
                        .await
                        .unwrap();
                }
            });
        }

        // Wait for all tasks to complete (should not deadlock)
        while join_set.join_next().await.is_some() {}

        println!("✅ Concurrent operations test passed - no deadlocks detected!");
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-ttl-test");
        let storage = DashMapMemoryStorage::with_ttl(Duration::from_millis(100));

        // Store a KV that should expire
        storage
            .store_kv("expiring-key", b"expiring-value", None)
            .await
            .unwrap();

        // Should be available immediately
        let retrieved = storage.get_kv("expiring-key").await.unwrap();
        assert!(retrieved.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired and cleaned up
        let retrieved = storage.get_kv("expiring-key").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let _env = TestEnvironmentGuard::new().with_jwt_secret("dashmap-cleanup-test");
        let storage = DashMapMemoryStorage::with_ttl(Duration::from_millis(50));

        // Store multiple items that will expire
        for i in 0..10 {
            storage
                .store_kv(&format!("key-{}", i), b"value", None)
                .await
                .unwrap();
        }

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run cleanup
        storage.cleanup_expired().await.unwrap();

        // Verify all items are cleaned up
        for i in 0..10 {
            let retrieved = storage.get_kv(&format!("key-{}", i)).await.unwrap();
            assert!(retrieved.is_none());
        }
    }
}
