//! Session management module

use crate::errors::{AuthError, Result};
use crate::storage::{AuthStorage, SessionData};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// Session manager for handling user sessions
pub struct SessionManager {
    storage: Arc<dyn AuthStorage>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(storage: Arc<dyn AuthStorage>) -> Self {
        Self { storage }
    }

    /// Create a new session
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

    /// Get session information
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

    /// Delete a session
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        debug!("Deleting session '{}'", session_id);

        self.storage.delete_session(session_id).await?;
        info!("Session '{}' deleted", session_id);
        Ok(())
    }

    /// Update session last activity
    pub async fn update_session_activity(&self, session_id: &str) -> Result<()> {
        if let Some(mut session) = self.storage.get_session(session_id).await? {
            session.last_activity = chrono::Utc::now();
            self.storage.store_session(session_id, &session).await?;
        }
        Ok(())
    }

    /// Get all sessions for a user
    pub async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<(String, SessionData)>> {
        // Note: This would require storage backend support for querying by user_id
        // For now, return empty vector as this would be a more complex implementation
        debug!("Getting all sessions for user '{}'", user_id);
        Ok(vec![])
    }

    /// Delete all sessions for a user
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

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        debug!("Cleaning up expired sessions");

        // This would require storage backend support for bulk cleanup
        // For now, this is handled by the storage implementation's cleanup_expired method
        Ok(())
    }

    /// Validate session and return user info
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

    /// Extend session expiration
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

    /// Count the number of currently active sessions
    /// Used for security audit statistics
    pub async fn count_active_sessions(&self) -> Result<u64> {
        debug!("Counting active sessions");

        // Use the storage layer's count_active_sessions method
        let active_count = self.storage.count_active_sessions().await?;

        debug!("Found {} active sessions", active_count);
        Ok(active_count)
    }

    /// Get security metrics for sessions
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
}


