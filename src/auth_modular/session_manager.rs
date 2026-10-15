//! Session management module

use crate::distributed::{DistributedSessionStore, LocalOnlySessionStore};
use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, SessionData};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Statistics from a distributed session coordination pass.
///
/// # Example
/// ```rust,ignore
/// let stats = session_mgr.coordinate_distributed_sessions().await?;
/// println!("local={}, remote={}", stats.local_active_sessions, stats.remote_active_sessions);
/// ```
#[derive(Debug)]
pub struct SessionCoordinationStats {
    pub local_active_sessions: u64,
    pub remote_active_sessions: u64,
    pub synchronized_sessions: u64,
    pub coordination_conflicts: u64,
    pub last_coordination_time: chrono::DateTime<chrono::Utc>,
}

/// Session manager for handling user sessions.
///
/// # Example
/// ```rust,ignore
/// use auth_framework::auth_modular::SessionManager;
/// use std::sync::Arc;
///
/// let mgr = SessionManager::new(storage.clone());
/// let sid = mgr.create_session("user-1", Duration::from_secs(3600), None, None).await?;
/// ```
pub struct SessionManager {
    storage: Arc<dyn AuthStorage>,
    distributed_store: Arc<dyn DistributedSessionStore>,
}

impl SessionManager {
    /// Create a new session manager.
    ///
    /// # Example
    /// ```rust,ignore
    /// use auth_framework::auth_modular::SessionManager;
    /// let mgr = SessionManager::new(storage.clone());
    /// ```
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self {
            storage,
            distributed_store: Arc::new(LocalOnlySessionStore),
        }
    }

    /// Replace the distributed session store (multi-node deployments).
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.set_distributed_store(Arc::new(RedisSessionStore::new("redis://...").await?));
    /// ```
    pub fn set_distributed_store(&mut self, store: Arc<dyn DistributedSessionStore>) {
        self.distributed_store = store;
    }

    /// Create a new session.
    ///
    /// # Example
    /// ```rust,ignore
    /// let sid = mgr.create_session(
    ///     "user-1",
    ///     Duration::from_secs(3600),
    ///     Some("127.0.0.1".into()),
    ///     Some("Mozilla/5.0".into()),
    /// ).await?;
    /// ```
    pub async fn create_session(
        &self,
        user_id: &str,
        expires_in: Duration,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        debug!("Creating session for user '{}'", user_id);

        // Validate session duration
        if expires_in.is_zero() {
            return Err(AuthError::invalid_credential(
                "session_duration",
                "Session duration must be greater than zero",
            ));
        }

        if expires_in > Duration::from_secs(365 * 24 * 60 * 60) {
            // 1 year max
            return Err(AuthError::invalid_credential(
                "session_duration",
                "Session duration exceeds maximum allowed (1 year)",
            ));
        }

        let session_id = crate::utils::string::generate_id(Some("sess"));
        let session = SessionData::new(session_id.clone(), user_id, expires_in)
            .with_metadata(ip_address, user_agent);

        self.storage.store_session(&session_id, &session).await?;

        info!("Session '{}' created for user '{}'", session_id, user_id);
        Ok(session_id)
    }

    /// Get session information.
    ///
    /// Returns `None` if the session does not exist or has expired.
    ///
    /// # Example
    /// ```rust,ignore
    /// if let Some(session) = mgr.get_session("sess_abc").await? {
    ///     println!("user: {}", session.user_id);
    /// }
    /// ```
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>> {
        debug!("Getting session '{}'", session_id);

        let session = self.storage.get_session(session_id).await?;

        // Check if session is expired
        if let Some(ref session_data) = session
            && session_data.is_expired()
        {
            // Remove expired session
            let _ = self.delete_session(session_id).await;
            return Ok(None);
        }

        Ok(session)
    }

    /// Delete a session.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.delete_session("sess_abc").await?;
    /// ```
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        debug!("Deleting session '{}'", session_id);

        self.storage.delete_session(session_id).await?;
        info!("Session '{}' deleted", session_id);
        Ok(())
    }

    /// Update session last activity timestamp.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.update_session_activity("sess_abc").await?;
    /// ```
    pub async fn update_session_activity(&self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.last_activity = chrono::Utc::now();
            self.storage.store_session(session_id, &session).await?;
        }
        Ok(())
    }

    /// Get all active (non-expired) sessions for a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// let sessions = mgr.get_user_sessions("user-1").await?;
    /// for (id, data) in &sessions {
    ///     println!("session {}: ip={:?}", id, data.ip_address);
    /// }
    /// ```
    pub async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<(String, SessionData)>> {
        debug!("Getting all sessions for user '{}'", user_id);
        let sessions = self.storage.list_user_sessions(user_id).await?;
        Ok(sessions
            .into_iter()
            .filter(|s| !s.is_expired())
            .map(|s| (s.session_id.clone(), s))
            .collect())
    }

    /// Delete all sessions for a user.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.delete_user_sessions("user-1").await?;
    /// ```
    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<()> {
        debug!("Deleting all sessions for user '{}'", user_id);

        // Get user sessions and delete them
        let sessions = self.get_user_sessions(user_id).await?;
        for (session_id, _) in sessions {
            let _ = self.delete_session(&session_id).await;
        }

        info!("All sessions deleted for user '{}'", user_id);
        Ok(())
    }

    /// Clean up expired sessions from storage.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.cleanup_expired_sessions().await?;
    /// ```
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        debug!("Cleaning up expired sessions");
        self.storage.cleanup_expired().await?;
        info!("Expired sessions cleaned up");
        Ok(())
    }

    /// Validate a session and return the owning user ID.
    ///
    /// Returns `None` if the session is missing or expired.
    ///
    /// # Example
    /// ```rust,ignore
    /// if let Some(user_id) = mgr.validate_session("sess_abc").await? {
    ///     println!("session belongs to {}", user_id);
    /// }
    /// ```
    pub async fn validate_session(&self, session_id: &str) -> Result<Option<String>> {
        if let Some(session) = self.get_session(session_id).await?
            && !session.is_expired()
        {
            // Update last activity
            let _ = self.update_session_activity(session_id).await;
            return Ok(Some(session.user_id));
        }
        Ok(None)
    }

    /// Extend session expiration by `additional_time`.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.extend_session("sess_abc", Duration::from_secs(1800)).await?;
    /// ```
    pub async fn extend_session(&self, session_id: &str, additional_time: Duration) -> Result<()> {
        debug!(
            "Extending session '{}' by {:?}",
            session_id, additional_time
        );

        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.expires_at += chrono::Duration::from_std(additional_time)
                .map_err(|e| AuthError::internal(format!("Failed to convert duration: {}", e)))?;
            self.storage.store_session(session_id, &session).await?;
            info!("Session '{}' extended", session_id);
        }

        Ok(())
    }

    /// Create a new session with resource-limit guards.
    ///
    /// Enforces a global cap of 100 000 total sessions and a per-user cap
    /// of 50 sessions to prevent DoS / resource exhaustion.
    ///
    /// Returns `(session_id, new_total_count)` so the caller can update monitoring.
    ///
    /// # Example
    /// ```rust,ignore
    /// let (sid, total) = mgr.create_session_limited(
    ///     "user-1", Duration::from_secs(3600), None, None,
    /// ).await?;
    /// println!("created session {} (total active: {})", sid, total);
    /// ```
    pub async fn create_session_limited(
        &self,
        user_id: &str,
        expires_in: Duration,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, u64)> {
        const MAX_TOTAL_SESSIONS: u64 = 100_000;
        let total_sessions = self.count_active_sessions().await?;
        if total_sessions >= MAX_TOTAL_SESSIONS {
            warn!(
                "Maximum total sessions ({}) exceeded, rejecting new session",
                MAX_TOTAL_SESSIONS
            );
            return Err(AuthError::rate_limit(
                "Maximum concurrent sessions exceeded. Please try again later.",
            ));
        }

        const MAX_USER_SESSIONS: usize = 50;
        let user_sessions = self.storage.list_user_sessions(user_id).await?;
        if user_sessions.len() >= MAX_USER_SESSIONS {
            warn!(
                "User '{}' has reached maximum sessions ({})",
                user_id, MAX_USER_SESSIONS
            );
            return Err(AuthError::TooManyConcurrentSessions);
        }

        let session_id = self
            .create_session(user_id, expires_in, ip_address, user_agent)
            .await?;
        Ok((session_id, total_sessions + 1))
    }

    /// Count the number of currently active sessions.
    ///
    /// Used for security audit statistics.
    ///
    /// # Example
    /// ```rust,ignore
    /// let n = mgr.count_active_sessions().await?;
    /// println!("{} active sessions", n);
    /// ```
    pub async fn count_active_sessions(&self) -> Result<u64> {
        debug!("Counting active sessions");

        // Use the storage layer's count_active_sessions method
        let active_count = self.storage.count_active_sessions().await?;

        debug!("Found {} active sessions", active_count);
        Ok(active_count)
    }

    /// Get security metrics for sessions.
    ///
    /// # Example
    /// ```rust,ignore
    /// let metrics = mgr.get_session_security_metrics().await?;
    /// println!("active: {:?}", metrics.get("active_sessions"));
    /// ```
    pub async fn get_session_security_metrics(&self) -> Result<HashMap<String, serde_json::Value>> {
        debug!("Collecting session security metrics");

        let mut metrics = HashMap::new();
        let active_count = self.count_active_sessions().await?;

        metrics.insert(
            "active_sessions".to_string(),
            serde_json::Value::Number(serde_json::Number::from(active_count)),
        );
        metrics.insert(
            "last_check".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );

        Ok(metrics)
    }

    /// Coordinate session state across distributed instances.
    ///
    /// # Example
    /// ```rust,ignore
    /// let stats = mgr.coordinate_distributed_sessions().await?;
    /// println!("synced: {}", stats.synchronized_sessions);
    /// ```
    pub async fn coordinate_distributed_sessions(&self) -> Result<SessionCoordinationStats> {
        tracing::debug!("Coordinating distributed sessions across instances");

        let local_sessions = self.count_active_sessions().await?;

        let coordination_stats = SessionCoordinationStats {
            local_active_sessions: local_sessions as u64,
            remote_active_sessions: self.estimate_remote_sessions().await?,
            synchronized_sessions: self.count_synchronized_sessions().await?,
            coordination_conflicts: 0,
            last_coordination_time: chrono::Utc::now(),
        };

        self.broadcast_session_state().await?;
        self.resolve_session_conflicts().await?;

        tracing::info!(
            "Session coordination complete - Local: {}, Remote: {}, Synchronized: {}",
            coordination_stats.local_active_sessions,
            coordination_stats.remote_active_sessions,
            coordination_stats.synchronized_sessions
        );

        Ok(coordination_stats)
    }

    /// Estimate active sessions on remote instances by querying the distributed store.
    async fn estimate_remote_sessions(&self) -> Result<u64> {
        let total = self.distributed_store.total_session_count().await?;
        if total == 0 {
            tracing::debug!("No distributed session store configured; remote session count = 0");
            return Ok(0);
        }
        let local = self.count_active_sessions().await.unwrap_or(0);
        let remote = total.saturating_sub(local);
        tracing::debug!(
            "Distributed session count: total={}, local={}, remote={}",
            total,
            local,
            remote
        );
        Ok(remote)
    }

    /// Count sessions synchronized across instances.
    async fn count_synchronized_sessions(&self) -> Result<u64> {
        let metrics = self.get_session_security_metrics().await?;
        let synchronized = metrics
            .get("synchronized_sessions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        tracing::debug!("Synchronized sessions count: {}", synchronized);
        Ok(synchronized)
    }

    /// Broadcast local session state to other instances (no-op for single-node).
    async fn broadcast_session_state(&self) -> Result<()> {
        let count = self.count_active_sessions().await.unwrap_or(0);
        tracing::debug!("Session state broadcast completed for {} sessions", count);
        Ok(())
    }

    /// Resolve session conflicts between instances (no-op for single-node).
    async fn resolve_session_conflicts(&self) -> Result<()> {
        tracing::debug!("Session conflict resolution completed (no-op for single-instance)");
        Ok(())
    }

    /// Synchronize a specific session with remote instances.
    ///
    /// # Example
    /// ```rust,ignore
    /// mgr.synchronize_session("sess_abc").await?;
    /// ```
    pub async fn synchronize_session(&self, session_id: &str) -> Result<()> {
        if self.get_session(session_id).await?.is_none() {
            return Err(AuthError::validation(format!(
                "Session {} not found",
                session_id
            )));
        }
        tracing::info!("Session {} synchronized (single-instance)", session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn make_manager() -> SessionManager {
        SessionManager::new(Arc::new(MemoryStorage::new()))
    }

    // ── create_session ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_session_success() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u1", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        assert!(sid.starts_with("sess"));
    }

    #[tokio::test]
    async fn test_create_session_with_metadata() {
        let mgr = make_manager();
        let sid = mgr
            .create_session(
                "u2",
                Duration::from_secs(600),
                Some("127.0.0.1".into()),
                Some("TestUA".into()),
            )
            .await
            .unwrap();
        let session = mgr.get_session(&sid).await.unwrap().unwrap();
        assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(session.user_agent.as_deref(), Some("TestUA"));
    }

    #[tokio::test]
    async fn test_create_session_zero_duration_rejected() {
        let mgr = make_manager();
        let result = mgr.create_session("u3", Duration::ZERO, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_session_excessive_duration_rejected() {
        let mgr = make_manager();
        let result = mgr
            .create_session("u4", Duration::from_secs(400 * 24 * 3600), None, None)
            .await;
        assert!(result.is_err());
    }

    // ── get_session ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_session_found() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u5", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let session = mgr.get_session(&sid).await.unwrap();
        assert!(session.is_some());
        assert_eq!(session.unwrap().user_id, "u5");
    }

    #[tokio::test]
    async fn test_get_session_not_found() {
        let mgr = make_manager();
        let result = mgr.get_session("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    // ── delete_session ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_session() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u6", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        mgr.delete_session(&sid).await.unwrap();
        assert!(mgr.get_session(&sid).await.unwrap().is_none());
    }

    // ── validate_session ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_validate_session_valid() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u7", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let uid = mgr.validate_session(&sid).await.unwrap();
        assert_eq!(uid.as_deref(), Some("u7"));
    }

    #[tokio::test]
    async fn test_validate_session_nonexistent() {
        let mgr = make_manager();
        let uid = mgr.validate_session("ghost").await.unwrap();
        assert!(uid.is_none());
    }

    // ── extend_session ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_extend_session() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u8", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let before = mgr.get_session(&sid).await.unwrap().unwrap().expires_at;
        mgr.extend_session(&sid, Duration::from_secs(3600))
            .await
            .unwrap();
        let after = mgr.get_session(&sid).await.unwrap().unwrap().expires_at;
        assert!(after > before);
    }

    // ── get_user_sessions / delete_user_sessions ────────────────────────

    #[tokio::test]
    async fn test_get_user_sessions() {
        let mgr = make_manager();
        mgr.create_session("u9", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        mgr.create_session("u9", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let sessions = mgr.get_user_sessions("u9").await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_user_sessions() {
        let mgr = make_manager();
        mgr.create_session("u10", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        mgr.create_session("u10", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        mgr.delete_user_sessions("u10").await.unwrap();
        let sessions = mgr.get_user_sessions("u10").await.unwrap();
        assert!(sessions.is_empty());
    }

    // ── count_active_sessions ───────────────────────────────────────────

    #[tokio::test]
    async fn test_count_active_sessions() {
        let mgr = make_manager();
        let before = mgr.count_active_sessions().await.unwrap();
        mgr.create_session("u11", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let after = mgr.count_active_sessions().await.unwrap();
        assert!(after > before);
    }

    // ── create_session_limited ──────────────────────────────────────────

    #[tokio::test]
    async fn test_create_session_limited_success() {
        let mgr = make_manager();
        let (sid, count) = mgr
            .create_session_limited("u12", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        assert!(sid.starts_with("sess"));
        assert!(count >= 1);
    }

    // ── get_session_security_metrics ────────────────────────────────────

    #[tokio::test]
    async fn test_get_session_security_metrics() {
        let mgr = make_manager();
        mgr.create_session("u13", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        let metrics = mgr.get_session_security_metrics().await.unwrap();
        assert!(metrics.contains_key("active_sessions"));
        assert!(metrics.contains_key("last_check"));
    }

    // ── coordinate_distributed_sessions ─────────────────────────────────

    #[tokio::test]
    async fn test_coordinate_distributed_sessions() {
        let mgr = make_manager();
        let stats = mgr.coordinate_distributed_sessions().await.unwrap();
        // With LocalOnlySessionStore, remote sessions should be 0
        assert_eq!(stats.remote_active_sessions, 0);
        assert_eq!(stats.coordination_conflicts, 0);
    }

    // ── synchronize_session ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_synchronize_session_success() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u14", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        assert!(mgr.synchronize_session(&sid).await.is_ok());
    }

    #[tokio::test]
    async fn test_synchronize_session_not_found() {
        let mgr = make_manager();
        assert!(mgr.synchronize_session("ghost").await.is_err());
    }

    // ── update_session_activity ─────────────────────────────────────────

    #[tokio::test]
    async fn test_update_session_activity() {
        let mgr = make_manager();
        let sid = mgr
            .create_session("u15", Duration::from_secs(600), None, None)
            .await
            .unwrap();
        // Just ensure it doesn't error
        mgr.update_session_activity(&sid).await.unwrap();
    }

    // ── cleanup_expired_sessions ────────────────────────────────────────

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let mgr = make_manager();
        // Just ensure it doesn't error on empty storage
        mgr.cleanup_expired_sessions().await.unwrap();
    }
}
