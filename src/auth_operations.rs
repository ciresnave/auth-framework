//! Grouped operation facades over [`AuthFramework`].
//!
//! Each `*Operations` struct is a lightweight view (holds only a lifetime-bound
//! reference to the framework) that exposes a focused subset of the full API.
//! They are created by the corresponding accessor on `AuthFramework` (e.g. [`users()`]).
//!
//! # Request structs
//!
//! Several operations accept structured request types instead of long
//! parameter lists.  These types carry required parameters via a
//! constructor and optional parameters via builder methods:
//!
//! - [`SessionCreateRequest`] — session creation with optional IP / user-agent.
//! - [`AuditLogQuery`] — filtered audit log queries.
//! - [`UserListQuery`] — user listing with pagination and filtering.
//! - [`PermissionContext`] — context data for dynamic permission evaluation.
//! - [`DelegationRequest`] — permission delegation with required fields.
//! - [`ExecutionMode`] — `DryRun` vs `Execute` for maintenance operations.
//! - [`UserStatus`] — `Active` vs `Inactive` for user account state.
//! - [`SessionFilter`] — `ActiveOnly` vs `IncludeInactive` for session listing.
//!
//! [`users()`]: crate::auth::AuthFramework::users

use crate::audit::SecurityAuditStats;
use crate::auth::{AuthFramework, AuthStats, UserInfo};
use crate::errors::{AuthError, Result};
use crate::maintenance::{BackupReport, ResetReport, RestoreReport};
use crate::methods::MfaChallenge;
use crate::permissions::Role;
use crate::storage::SessionData;
use crate::tokens::AuthToken;
use std::sync::Arc;
use std::time::Duration;

/// Controls whether a maintenance operation (backup, restore, reset) actually
/// modifies state or merely previews what *would* happen.
///
/// Replaces bare `bool` parameters for better call-site readability.
///
/// # Example
///
/// ```rust,ignore
/// use auth_framework::auth_operations::ExecutionMode;
///
/// // Preview:
/// let preview = auth.maintenance().backup("backup.json", ExecutionMode::DryRun).await?;
/// // For real:
/// let report = auth.maintenance().backup("backup.json", ExecutionMode::Execute).await?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionMode {
    /// Report what the operation would do without making changes.
    DryRun,
    /// Actually perform the operation.
    Execute,
}

impl ExecutionMode {
    /// Returns `true` when this is a dry-run (preview) execution.
    pub fn is_dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

impl From<ExecutionMode> for bool {
    /// Converts to the legacy `dry_run: bool` parameter (`DryRun → true`).
    fn from(mode: ExecutionMode) -> bool {
        mode.is_dry_run()
    }
}

/// Whether a user account should be active (able to log in) or inactive
/// (locked out).
///
/// Replaces bare `bool` parameters for better call-site readability.
///
/// # Example
///
/// ```rust,ignore
/// use auth_framework::auth_operations::UserStatus;
///
/// // Deactivate a user:
/// auth.users().set_status(&user_id, UserStatus::Inactive).await?;
/// // Re-activate:
/// auth.users().set_status(&user_id, UserStatus::Active).await?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserStatus {
    /// Account is active and can authenticate.
    Active,
    /// Account is disabled and all login attempts will be rejected.
    Inactive,
}

impl UserStatus {
    /// Returns `true` when the user should be active.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl From<UserStatus> for bool {
    /// Converts to the legacy `active: bool` parameter (`Active → true`).
    fn from(status: UserStatus) -> bool {
        status.is_active()
    }
}

impl From<bool> for UserStatus {
    fn from(active: bool) -> Self {
        if active { Self::Active } else { Self::Inactive }
    }
}

/// Filter for session listing queries.
///
/// Replaces `include_inactive: bool` for self-documenting call sites.
///
/// # Example
///
/// ```rust,ignore
/// use auth_framework::auth_operations::SessionFilter;
///
/// let active = mgr.get_user_sessions(user_id, SessionFilter::ActiveOnly).await?;
/// let all    = mgr.get_user_sessions(user_id, SessionFilter::IncludeInactive).await?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionFilter {
    /// Return only active sessions.
    ActiveOnly,
    /// Return all sessions including expired/revoked ones.
    IncludeInactive,
}

impl SessionFilter {
    /// Returns `true` when inactive sessions should be included.
    pub fn include_inactive(self) -> bool {
        matches!(self, Self::IncludeInactive)
    }
}

impl From<SessionFilter> for bool {
    /// Converts to the legacy `include_inactive: bool` parameter.
    fn from(filter: SessionFilter) -> bool {
        filter.include_inactive()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Request / query structs
// ──────────────────────────────────────────────────────────────────────────────

/// Filtering criteria for [`AuditOperations::query_permission_logs`].
///
/// All fields are optional — an empty query returns unfiltered results.
///
/// # Example
///
/// ```rust,ignore
/// let query = AuditLogQuery::new()
///     .user("user_123")
///     .action("read")
///     .limit(50);
/// ```
#[derive(Debug, Clone, Default)]
pub struct AuditLogQuery {
    user_id: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    limit: Option<usize>,
}

impl AuditLogQuery {
    /// Create an empty query (matches everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by user ID.
    pub fn user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Filter by action (e.g. `"read"`, `"write"`).
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Filter by resource path.
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Limit the number of returned entries.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Returns the user-ID filter, if set.
    pub fn get_user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Returns the action filter, if set.
    pub fn get_action(&self) -> Option<&str> {
        self.action.as_deref()
    }

    /// Returns the resource filter, if set.
    pub fn get_resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// Returns the maximum number of entries to return, if set.
    pub fn get_limit(&self) -> Option<usize> {
        self.limit
    }
}

/// Query type for listing users with pagination and filtering.
///
/// Provides a fluent API for configuring user listing parameters.
///
/// # Example
///
/// ```rust
/// # use auth_framework::auth_operations::UserListQuery;
/// let query = UserListQuery::new()
///     .limit(50)
///     .active_only();
/// ```
#[derive(Debug, Clone, Default)]
pub struct UserListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    active_only: bool,
}

impl UserListQuery {
    /// Create an empty query (returns all users).
    pub fn new() -> Self {
        Self::default()
    }

    /// Limit the number of users returned.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Skip the first N users (for pagination).
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Only return active users (default: false).
    pub fn active_only(mut self) -> Self {
        self.active_only = true;
        self
    }

    /// Conditionally restrict the query to active users.
    pub fn active_only_if(mut self, active_only: bool) -> Self {
        self.active_only = active_only;
        self
    }

    /// Conditionally apply a limit when one is provided.
    pub fn limit_if_some(mut self, limit: Option<usize>) -> Self {
        if let Some(limit) = limit {
            self.limit = Some(limit);
        }
        self
    }

    /// Returns the maximum number of users to return, if set.
    pub fn get_limit(&self) -> Option<usize> {
        self.limit
    }

    /// Returns the pagination offset, if set.
    pub fn get_offset(&self) -> Option<usize> {
        self.offset
    }

    /// Returns `true` when only active users should be listed.
    pub fn get_active_only(&self) -> bool {
        self.active_only
    }
}

/// Context data for dynamic permission evaluation (ABAC).
///
/// Provides a structured way to pass environmental and contextual information
/// for attribute-based access control decisions.
///
/// # Example
///
/// ```rust
/// # use auth_framework::auth_operations::PermissionContext;
/// let context = PermissionContext::new()
///     .with_attribute("time_of_day", "business_hours")
///     .with_attribute("ip_location", "office")
///     .with_attribute("device_type", "trusted");
/// ```
#[derive(Debug, Clone, Default)]
pub struct PermissionContext {
    attributes: std::collections::HashMap<String, String>,
}

impl PermissionContext {
    /// Create an empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a context attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add multiple attributes from an iterator.
    pub fn with_attributes<I, K, V>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in attributes {
            self.attributes.insert(key.into(), value.into());
        }
        self
    }

    /// Get the underlying attributes map.
    pub fn into_attributes(self) -> std::collections::HashMap<String, String> {
        self.attributes
    }

    /// Get a reference to the attributes map.
    pub fn attributes(&self) -> &std::collections::HashMap<String, String> {
        &self.attributes
    }
}

/// Request type for [`AdminOperations::delegate`].
///
/// Bundles the four required delegation fields and the optional duration
/// into a single self-documenting value.
///
/// # Example
///
/// ```rust,ignore
/// let req = DelegationRequest::new("admin_1", "user_2", "write", "reports")
///     .duration(Duration::from_secs(3600));
/// ```
#[derive(Debug, Clone)]
pub struct DelegationRequest {
    delegator_id: String,
    delegatee_id: String,
    action: String,
    resource: String,
    duration: Duration,
}

impl DelegationRequest {
    /// Create a delegation request with required parameters.
    ///
    /// The default duration is 1 hour. Override with [`duration`](Self::duration).
    pub fn new(
        delegator_id: impl Into<String>,
        delegatee_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            delegator_id: delegator_id.into(),
            delegatee_id: delegatee_id.into(),
            action: action.into(),
            resource: resource.into(),
            duration: Duration::from_secs(3600),
        }
    }

    /// Set the delegation duration (replaces the default of 1 hour).
    pub fn duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Returns the ID of the user granting permissions.
    pub fn delegator_id(&self) -> &str {
        &self.delegator_id
    }

    /// Returns the ID of the user receiving permissions.
    pub fn delegatee_id(&self) -> &str {
        &self.delegatee_id
    }

    /// Returns the action being delegated (e.g. `"write"`).
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns the resource being delegated (e.g. `"reports"`).
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns how long the delegation is valid.
    pub fn get_duration(&self) -> Duration {
        self.duration
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// User operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused user-management operations exposed from [`AuthFramework::users`].
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::prelude::*;
/// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
/// // Register
/// let uid = auth.users().register("alice", "alice@example.com", "P@ssw0rd!").await?;
///
/// // Look up
/// let user = auth.users().get(&uid).await?;
/// assert_eq!(user.username, "alice");
///
/// // Update password
/// auth.users().update_password_by_id(&uid, "NewP@ss!").await?;
/// # Ok(())
/// # }
/// ```
pub struct UserOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl UserOperations<'_> {
    /// Register a new user and return the generated user ID.
    pub async fn register(&self, username: &str, email: &str, password: &str) -> Result<String> {
        self.framework
            .register_user(username, email, password)
            .await
    }

    /// List users from the canonical user index.
    ///
    /// **Prefer [`list_with_query`](Self::list_with_query)** which uses a
    /// [`UserListQuery`] builder for better readability at call sites.
    #[deprecated(
        since = "0.6.0",
        note = "use `list_with_query(UserListQuery::new().limit(n).active_only())` instead"
    )]
    pub async fn list(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        active_only: bool,
    ) -> Result<Vec<UserInfo>> {
        self.framework
            .list_users_with_query(
                UserListQuery::new()
                    .offset(offset.unwrap_or(0))
                    .active_only_if(active_only)
                    .limit_if_some(limit),
            )
            .await
    }

    /// List users using a [`UserListQuery`] for better readability.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// let active = auth.users()
    ///     .list_with_query(UserListQuery::new().limit(50).active_only())
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_with_query(&self, query: UserListQuery) -> Result<Vec<UserInfo>> {
        self.framework.list_users_with_query(query).await
    }

    /// Fetch a user record by canonical user ID.
    pub async fn get(&self, user_id: &str) -> Result<UserInfo> {
        self.framework.get_user_record(user_id).await
    }

    /// Check whether a username exists.
    pub async fn exists_by_username(&self, username: &str) -> Result<bool> {
        self.framework.username_exists(username).await
    }

    /// Check whether an email exists.
    pub async fn exists_by_email(&self, email: &str) -> Result<bool> {
        self.framework.email_exists(email).await
    }

    /// Fetch a user record by username.
    pub async fn get_by_username(
        &self,
        username: &str,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>> {
        self.framework.get_user_by_username(username).await
    }

    /// Fetch an application-level user profile.
    pub async fn profile(&self, user_id: &str) -> Result<crate::providers::ProviderProfile> {
        self.framework.get_user_profile(user_id).await
    }

    /// Update a user's password.
    pub async fn update_password(&self, username: &str, new_password: &str) -> Result<()> {
        self.framework
            .update_user_password(username, new_password)
            .await
    }

    /// Update a user's password by user ID.
    pub async fn update_password_by_id(&self, user_id: &str, new_password: &str) -> Result<()> {
        self.framework
            .update_user_password_by_id(user_id, new_password)
            .await
    }

    /// Update the roles assigned to a user.
    pub async fn update_roles(&self, user_id: &str, roles: &[String]) -> Result<()> {
        self.framework.update_user_roles(user_id, roles).await
    }

    /// Enable or disable a user.
    #[deprecated(since = "0.5.0", note = "use `set_status(id, UserStatus)` instead")]
    pub async fn set_active(&self, user_id: &str, active: bool) -> Result<()> {
        self.framework.set_user_active(user_id, active).await
    }

    /// Change whether a user account is active or inactive.
    ///
    /// Inactive users cannot authenticate until re-activated.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// auth.users().set_status(&user_id, UserStatus::Inactive).await?;
    /// ```
    pub async fn set_status(&self, user_id: &str, status: UserStatus) -> Result<()> {
        self.framework
            .set_user_active(user_id, status.is_active())
            .await
    }

    /// Update a user's email address.
    pub async fn update_email(&self, user_id: &str, email: &str) -> Result<()> {
        self.framework.update_user_email(user_id, email).await
    }

    /// Verify a user's password.
    pub async fn verify_password(&self, user_id: &str, password: &str) -> Result<bool> {
        self.framework.verify_user_password(user_id, password).await
    }

    /// Resolve a username from a user ID.
    pub async fn username(&self, user_id: &str) -> Result<String> {
        self.framework.get_username_by_id(user_id).await
    }

    /// Delete a user by username.
    pub async fn delete(&self, username: &str) -> Result<()> {
        self.framework.delete_user(username).await
    }

    /// Delete a user by user ID.
    pub async fn delete_by_id(&self, user_id: &str) -> Result<()> {
        self.framework.delete_user_by_id(user_id).await
    }

    /// Validate a username against the configured format rules.
    ///
    /// Returns `Ok(())` when the username is acceptable, or
    /// `Err(AuthError::Validation { .. })` describing the policy violation.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// auth.users().check_username("alice")?;
    /// // Returns Err explaining why the name is invalid:
    /// assert!(auth.users().check_username("").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_username(&self, username: &str) -> Result<()> {
        crate::utils::validation::validate_username(username)
    }

    /// Validate a password against the active security policy.
    ///
    /// Returns `Ok(())` when the password meets production strength
    /// requirements, or `Err(AuthError::Validation { .. })` with feedback.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// auth.users().check_password_strength("C0mpl3x!Pa$$word")?;
    /// assert!(auth.users().check_password_strength("weak").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_password_strength(&self, password: &str) -> Result<()> {
        let strength = crate::utils::password::check_password_strength(password);
        if crate::utils::password::meets_production_strength(strength.level) {
            Ok(())
        } else {
            Err(AuthError::validation(format!(
                "Password does not meet strength requirements: {}",
                strength.feedback.join(", ")
            )))
        }
    }

    /// Validate an email address against RFC 5322 format rules.
    ///
    /// Returns `Ok(())` when the email is acceptable, or
    /// `Err(AuthError::Validation { .. })` describing the issue.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// auth.users().check_email("alice@example.com")?;
    /// assert!(auth.users().check_email("not-an-email").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_email(&self, email: &str) -> Result<()> {
        crate::utils::validation::validate_email(email)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Session operations
// ──────────────────────────────────────────────────────────────────────────────

/// Request type for [`SessionOperations::create`].
///
/// Bundles the required session parameters (user ID, lifetime) with optional
/// context (IP address, user-agent) so callers never need to pass `None`
/// explicitly.
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::auth_operations::SessionCreateRequest;
/// # use std::time::Duration;
/// // Minimal — no optional fields:
/// let req = SessionCreateRequest::new("user-123", Duration::from_secs(3600));
///
/// // With optional context:
/// let req = SessionCreateRequest::new("user-123", Duration::from_secs(3600))
///     .ip_address("10.0.0.1")
///     .user_agent("Mozilla/5.0");
/// ```
#[derive(Debug, Clone)]
pub struct SessionCreateRequest {
    user_id: String,
    expires_in: Duration,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl SessionCreateRequest {
    /// Create a request with the required fields.
    pub fn new(user_id: impl Into<String>, expires_in: Duration) -> Self {
        Self {
            user_id: user_id.into(),
            expires_in,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Attach a client IP address for audit / geolocation.
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Attach a `User-Agent` string for device tracking.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Returns the user ID this session is being created for.
    pub fn get_user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns how long until the session expires.
    pub fn get_expires_in(&self) -> Duration {
        self.expires_in
    }

    /// Returns the client IP address, if attached.
    pub fn get_ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }

    /// Returns the `User-Agent` header value, if attached.
    pub fn get_user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

/// Focused session-management operations exposed from [`AuthFramework::sessions`].
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::prelude::*;
/// # use auth_framework::auth_operations::SessionCreateRequest;
/// # use std::time::Duration;
/// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
/// // Using the request struct (recommended):
/// let req = SessionCreateRequest::new("user-123", Duration::from_secs(3600))
///     .ip_address("10.0.0.1");
/// let sid = auth.sessions().create_session(req).await?;
///
/// // Positional shorthand still works:
/// let sid = auth.sessions().create("user-123", Duration::from_secs(3600), None, None).await?;
///
/// let session = auth.sessions().get(&sid).await?;
/// auth.sessions().delete(&sid).await?;
/// # Ok(())
/// # }
/// ```
pub struct SessionOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl SessionOperations<'_> {
    /// Create a new session from a [`SessionCreateRequest`].
    ///
    /// This is the preferred entry point — it avoids passing `None` for
    /// optional parameters and makes the call site self-documenting.
    pub async fn create_session(&self, req: SessionCreateRequest) -> Result<String> {
        self.framework
            .create_session(&req.user_id, req.expires_in, req.ip_address, req.user_agent)
            .await
    }

    /// Create a new session for a user (positional convenience).
    ///
    /// Prefer [`create_session`](Self::create_session) with a
    /// [`SessionCreateRequest`] when you need optional fields.
    pub async fn create(
        &self,
        user_id: &str,
        expires_in: Duration,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        self.framework
            .create_session(user_id, expires_in, ip_address, user_agent)
            .await
    }

    /// Fetch a session by ID.
    pub async fn get(&self, session_id: &str) -> Result<Option<SessionData>> {
        self.framework.get_session(session_id).await
    }

    /// Delete a session by ID.
    pub async fn delete(&self, session_id: &str) -> Result<()> {
        self.framework.delete_session(session_id).await
    }

    /// List all sessions owned by a user.
    pub async fn list_for_user(&self, user_id: &str) -> Result<Vec<SessionData>> {
        self.framework.storage().list_user_sessions(user_id).await
    }

    /// List sessions owned by a user, optionally filtering out expired ones.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # use auth_framework::auth_operations::SessionFilter;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// let active = auth.sessions()
    ///     .list_for_user_filtered("user-1", SessionFilter::ActiveOnly)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_for_user_filtered(
        &self,
        user_id: &str,
        filter: SessionFilter,
    ) -> Result<Vec<SessionData>> {
        let sessions = self.framework.storage().list_user_sessions(user_id).await?;
        if filter.include_inactive() {
            Ok(sessions)
        } else {
            Ok(sessions.into_iter().filter(|s| !s.is_expired()).collect())
        }
    }

    /// Remove expired sessions and tokens.
    pub async fn cleanup_expired(&self) -> Result<()> {
        self.framework.cleanup_expired_data().await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Token operations
// ──────────────────────────────────────────────────────────────────────────────

/// Builder for [`TokenOperations::create_token`].
///
/// Bundles the required token parameters (user ID, auth method) with optional
/// scopes and lifetime, keeping call sites readable.
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::prelude::*;
/// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
/// let token = auth.tokens().create_token(
///     TokenCreateRequest::new("user-123", "jwt")
///         .scope("read")
///         .scope("write")
///         .lifetime(std::time::Duration::from_secs(7200))
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct TokenCreateRequest {
    user_id: String,
    method: String,
    scopes: Vec<String>,
    lifetime: Option<Duration>,
}

impl TokenCreateRequest {
    /// Create a new token request for a user authenticated via `method`.
    pub fn new(user_id: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            method: method.into(),
            scopes: Vec::new(),
            lifetime: None,
        }
    }

    /// Add a single scope.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Add multiple scopes at once.
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Override the default token lifetime.
    pub fn lifetime(mut self, duration: Duration) -> Self {
        self.lifetime = Some(duration);
        self
    }
}

/// Focused token-management operations exposed from [`AuthFramework::tokens`].
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::prelude::*;
/// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
/// // Issue a JWT token
/// let token = auth.tokens().create("user-123", &["read"], "jwt", None).await?;
///
/// // Validate
/// assert!(auth.tokens().validate(&token).await?);
///
/// // Refresh
/// let new_token = auth.tokens().refresh(&token).await?;
///
/// // Revoke
/// auth.tokens().revoke(&new_token).await?;
/// # Ok(())
/// # }
/// ```
pub struct TokenOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl TokenOperations<'_> {
    /// Create a new authentication token for a user.
    ///
    /// `scopes` accepts any iterator of string-like values, so all of these
    /// work:
    ///
    /// ```rust,ignore
    /// // Vec<String>
    /// tokens.create("uid", vec!["read".into()], "jwt", None).await?;
    /// // Slice of &str
    /// tokens.create("uid", &["read", "write"], "jwt", None).await?;
    /// // Empty
    /// tokens.create("uid", std::iter::empty::<&str>(), "jwt", None).await?;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `user_id` — the user to issue a token for
    /// * `scopes` — permission scopes to embed in the token
    /// * `method_name` — the auth method that authenticated the user (e.g. `"jwt"`)
    /// * `lifetime` — custom lifetime, or `None` for the configured default
    pub async fn create<I, S>(
        &self,
        user_id: impl Into<String>,
        scopes: I,
        method_name: impl Into<String>,
        lifetime: Option<Duration>,
    ) -> Result<AuthToken>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let scopes: Vec<String> = scopes.into_iter().map(|s| s.as_ref().to_owned()).collect();
        self.framework
            .create_auth_token(user_id, scopes, method_name, lifetime)
            .await
    }

    /// Create a token from a [`TokenCreateRequest`].
    ///
    /// This is the preferred entry point — it replaces positional `Option`
    /// parameters with a self-documenting builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// let token = auth.tokens().create_token(
    ///     TokenCreateRequest::new("user-123", "jwt")
    ///         .scope("read")
    ///         .scope("write")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_token(&self, req: TokenCreateRequest) -> Result<AuthToken> {
        self.framework
            .create_auth_token(req.user_id, req.scopes, req.method, req.lifetime)
            .await
    }

    /// Validate an authentication token.
    pub async fn validate(&self, token: &AuthToken) -> Result<bool> {
        self.framework.validate_token(token).await
    }

    /// Refresh an authentication token.
    pub async fn refresh(&self, token: &AuthToken) -> Result<AuthToken> {
        self.framework.refresh_token(token).await
    }

    /// Revoke an authentication token.
    pub async fn revoke(&self, token: &AuthToken) -> Result<()> {
        self.framework.revoke_token(token).await
    }

    /// List all tokens belonging to a user.
    pub async fn list_for_user(&self, user_id: &str) -> Result<Vec<AuthToken>> {
        self.framework.list_user_tokens(user_id).await
    }

    /// Create an API key for a user.
    pub async fn create_api_key(
        &self,
        user_id: &str,
        expires_in: Option<Duration>,
    ) -> Result<String> {
        self.framework.create_api_key(user_id, expires_in).await
    }

    /// Validate an API key and return the associated user info.
    pub async fn validate_api_key(&self, api_key: &str) -> Result<UserInfo> {
        self.framework.validate_api_key(api_key).await
    }

    /// Revoke an API key.
    pub async fn revoke_api_key(&self, api_key: &str) -> Result<()> {
        self.framework.revoke_api_key(api_key).await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Authorization operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused authorization operations exposed via [`AuthFramework::authorization()`].
///
/// Provides role-based access control (RBAC), direct permission grants, and
/// effective-permission queries.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(auth: &auth_framework::AuthFramework) -> auth_framework::Result<()> {
/// use auth_framework::permissions::{Permission, Role};
/// use auth_framework::tokens::AuthToken;
///
/// let authz = auth.authorization();
/// let token = AuthToken::builder("token_123", "user_123", "access_token").build();
///
/// // Create a role and assign it to a user
/// let mut editor = Role::new("editor");
/// editor.add_permission(Permission::new("articles", "edit"));
/// authz.create_role(editor).await?;
/// authz.assign_role("user_123", "editor").await?;
///
/// // Check permission via token
/// let allowed = authz.check(&token, "edit", "articles").await?;
/// # Ok(())
/// # }
/// ```
pub struct AuthorizationOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl AuthorizationOperations<'_> {
    /// Check whether a token grants access to an action on a resource.
    pub async fn check(&self, token: &AuthToken, action: &str, resource: &str) -> Result<bool> {
        self.framework
            .check_permission(token, action, resource)
            .await
    }

    /// Grant a direct permission to a user.
    pub async fn grant(&self, user_id: &str, action: &str, resource: &str) -> Result<()> {
        self.framework
            .grant_permission(user_id, action, resource)
            .await
    }

    /// Revoke a direct permission from a user.
    pub async fn revoke(&self, user_id: &str, action: &str, resource: &str) -> Result<()> {
        self.framework
            .revoke_permission(user_id, action, resource)
            .await
    }

    /// Create a role.
    pub async fn create_role(&self, role: Role) -> Result<()> {
        self.framework.create_role(role).await
    }

    /// List all defined roles.
    pub async fn list_roles(&self) -> Vec<Role> {
        self.framework.list_roles().await
    }

    /// Fetch a role definition by name.
    pub async fn role(&self, role_name: &str) -> Result<Role> {
        self.framework.get_role(role_name).await
    }

    /// Add a permission to an existing role.
    pub async fn add_role_permission(
        &self,
        role_name: &str,
        permission: crate::permissions::Permission,
    ) -> Result<()> {
        self.framework
            .add_role_permission(role_name, permission)
            .await
    }

    /// Assign a role to a user.
    pub async fn assign_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        self.framework.assign_role(user_id, role_name).await
    }

    /// Remove a role from a user.
    pub async fn remove_role(&self, user_id: &str, role_name: &str) -> Result<()> {
        self.framework.remove_role(user_id, role_name).await
    }

    /// Check whether a user currently has a role.
    pub async fn has_role(&self, user_id: &str, role_name: &str) -> Result<bool> {
        self.framework.user_has_role(user_id, role_name).await
    }

    /// List effective permissions for a user.
    pub async fn effective_permissions(&self, user_id: &str) -> Result<crate::types::Permissions> {
        self.framework
            .get_effective_permissions(user_id)
            .await
            .map(crate::types::Permissions)
    }

    /// List the currently assigned runtime roles for a user.
    pub async fn roles_for_user(&self, user_id: &str) -> Result<crate::types::Roles> {
        self.framework
            .list_user_roles(user_id)
            .await
            .map(crate::types::Roles)
    }
}

/// Focused maintenance operations exposed via [`AuthFramework::maintenance()`].
///
/// Backup, restore, and reset authentication state in the configured storage
/// backend. All operations support an [`ExecutionMode`] parameter that
/// controls whether changes are applied or merely previewed.
///
/// # Example
///
/// ```rust,no_run
/// # use auth_framework::auth_operations::ExecutionMode;
/// # async fn example(auth: &auth_framework::AuthFramework) -> auth_framework::Result<()> {
/// let maint = auth.maintenance();
///
/// // Preview a backup without writing to disk
/// let preview = maint.backup("/tmp/auth_backup.json", ExecutionMode::DryRun).await?;
/// println!("Would export {} records", preview.manifest.user_count);
///
/// // Perform the real backup
/// let report = maint.backup("/tmp/auth_backup.json", ExecutionMode::Execute).await?;
/// # Ok(())
/// # }
/// ```
pub struct MaintenanceOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl MaintenanceOperations<'_> {
    /// Export a logical snapshot to disk.
    ///
    /// Uses [`ExecutionMode`] for clarity at call sites.
    pub async fn backup(&self, output_path: &str, mode: ExecutionMode) -> Result<BackupReport> {
        crate::maintenance::backup_to_file(self.framework, output_path, mode.is_dry_run()).await
    }

    /// Export a logical snapshot to disk (legacy API).
    ///
    /// Prefer [`backup`](Self::backup) with an [`ExecutionMode`] for
    /// self-documenting call sites.
    pub async fn backup_to_file(&self, output_path: &str, dry_run: bool) -> Result<BackupReport> {
        crate::maintenance::backup_to_file(self.framework, output_path, dry_run).await
    }

    /// Restore a logical snapshot from disk.
    ///
    /// Uses [`ExecutionMode`] for clarity at call sites.
    pub async fn restore(&self, backup_path: &str, mode: ExecutionMode) -> Result<RestoreReport> {
        crate::maintenance::restore_from_file(self.framework, backup_path, mode.is_dry_run()).await
    }

    /// Restore a logical snapshot from disk (legacy API).
    ///
    /// Prefer [`restore`](Self::restore) with an [`ExecutionMode`] for
    /// self-documenting call sites.
    pub async fn restore_from_file(
        &self,
        backup_path: &str,
        dry_run: bool,
    ) -> Result<RestoreReport> {
        crate::maintenance::restore_from_file(self.framework, backup_path, dry_run).await
    }

    /// Reset logical authentication state in the configured backend.
    ///
    /// Uses [`ExecutionMode`] for clarity at call sites.
    pub async fn reset_with_mode(&self, mode: ExecutionMode) -> Result<ResetReport> {
        crate::maintenance::reset_runtime_data(self.framework, mode.is_dry_run()).await
    }

    /// Reset logical authentication state in the configured backend (legacy API).
    ///
    /// Prefer [`reset_with_mode`](Self::reset_with_mode) with an
    /// [`ExecutionMode`] for self-documenting call sites.
    pub async fn reset(&self, dry_run: bool) -> Result<ResetReport> {
        crate::maintenance::reset_runtime_data(self.framework, dry_run).await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MFA operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused multi-factor authentication operations exposed via [`AuthFramework::mfa()`].
///
/// Covers TOTP, SMS, email challenges, backup codes, and MFA completion
/// flows.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(auth: &auth_framework::AuthFramework) -> auth_framework::Result<()> {
/// let mfa = auth.mfa();
///
/// // Set up TOTP for a user
/// let secret = mfa.generate_totp_secret("user_123").await?;
/// let qr_url = mfa.generate_totp_qr_url("user_123", "MyApp", &secret).await?;
///
/// // Verify a code supplied by the user
/// let valid = mfa.verify_totp("user_123", "123456").await?;
/// # Ok(())
/// # }
/// ```
pub struct MfaOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl MfaOperations<'_> {
    /// Complete a pending MFA challenge with the provided code.
    pub async fn complete(&self, challenge: MfaChallenge, code: &str) -> Result<AuthToken> {
        self.framework.complete_mfa(challenge, code).await
    }

    /// Complete a pending MFA challenge by its ID.
    pub async fn complete_by_id(&self, challenge_id: &str, code: &str) -> Result<AuthToken> {
        self.framework.complete_mfa_by_id(challenge_id, code).await
    }

    /// Initiate an SMS-based MFA challenge for a user.
    pub async fn initiate_sms(&self, user_id: &str) -> Result<String> {
        self.framework.initiate_sms_challenge(user_id).await
    }

    /// Verify an SMS challenge code.
    pub async fn verify_sms(&self, challenge_id: &str, code: &str) -> Result<bool> {
        self.framework.verify_sms_code(challenge_id, code).await
    }

    /// Initiate an email-based MFA challenge for a user.
    pub async fn initiate_email(&self, user_id: &str) -> Result<String> {
        self.framework.initiate_email_challenge(user_id).await
    }

    /// Register a phone number for SMS MFA.
    pub async fn register_phone(&self, user_id: &str, phone_number: &str) -> Result<()> {
        self.framework
            .register_phone_number(user_id, phone_number)
            .await
    }

    /// Register an email address for email MFA.
    pub async fn register_email(&self, user_id: &str, email: &str) -> Result<()> {
        self.framework.register_email(user_id, email).await
    }

    /// Generate a TOTP secret for a user.
    pub async fn generate_totp_secret(&self, user_id: &str) -> Result<String> {
        self.framework.generate_totp_secret(user_id).await
    }

    /// Generate a TOTP QR code provisioning URL.
    pub async fn generate_totp_qr_url(
        &self,
        user_id: &str,
        app_name: &str,
        secret: &str,
    ) -> Result<String> {
        self.framework
            .generate_totp_qr_code(user_id, app_name, secret)
            .await
    }

    /// Generate the current TOTP code for a secret.
    pub async fn generate_totp_code(&self, secret: &str) -> Result<String> {
        self.framework.generate_totp_code(secret).await
    }

    /// Verify a TOTP code for a user.
    pub async fn verify_totp(&self, user_id: &str, code: &str) -> Result<bool> {
        self.framework.verify_totp_code(user_id, code).await
    }

    /// Generate backup codes for a user.
    pub async fn generate_backup_codes(&self, user_id: &str, count: usize) -> Result<Vec<String>> {
        self.framework.generate_backup_codes(user_id, count).await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Monitoring operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused monitoring and health operations exposed via [`AuthFramework::monitoring()`].
///
/// Health-checks, performance and security metrics, Prometheus export, and
/// rate-limit inspection.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(auth: &auth_framework::AuthFramework) -> auth_framework::Result<()> {
/// let mon = auth.monitoring();
///
/// let health = mon.health_check().await?;
/// let stats  = mon.stats().await?;
/// let prom   = mon.prometheus_metrics().await;
/// # Ok(())
/// # }
/// ```
pub struct MonitoringOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl MonitoringOperations<'_> {
    /// Perform a comprehensive health check across all subsystems.
    ///
    /// Returns a map of subsystem name → health result (e.g. `"storage"`,
    /// `"token_manager"`, `"rate_limiter"`).
    pub async fn health_check(
        &self,
    ) -> Result<std::collections::HashMap<String, crate::monitoring::HealthCheckResult>> {
        self.framework.health_check().await
    }

    /// Get current performance metrics.
    ///
    /// Returns a map of metric name → counter value (e.g.
    /// `"auth_requests"`, `"auth_successes"`, `"auth_failures"`).
    pub async fn performance_metrics(&self) -> std::collections::HashMap<String, u64> {
        self.framework.get_performance_metrics().await
    }

    /// Get aggregated security metrics.
    ///
    /// Returns a map of metric name → counter value (e.g.
    /// `"brute_force_blocked"`, `"rate_limited_requests"`).
    pub async fn security_metrics(&self) -> Result<std::collections::HashMap<String, u64>> {
        self.framework.get_security_metrics().await
    }

    /// Export metrics in Prometheus text format.
    pub async fn prometheus_metrics(&self) -> String {
        self.framework.export_prometheus_metrics().await
    }

    /// Get authentication statistics.
    pub async fn stats(&self) -> Result<AuthStats> {
        self.framework.get_stats().await
    }

    /// Check whether an IP address is within the configured rate limit.
    pub async fn check_ip_rate_limit(&self, ip: &str) -> Result<bool> {
        self.framework.check_ip_rate_limit(ip).await
    }

    /// Access the underlying monitoring manager for advanced usage.
    pub fn manager(&self) -> Arc<crate::monitoring::MonitoringManager> {
        self.framework.monitoring_manager()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused audit log operations exposed via [`AuthFramework::audit()`].
///
/// Query permission audit logs, view permission metrics, and retrieve
/// comprehensive security audit statistics.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(auth: &auth_framework::AuthFramework) -> auth_framework::Result<()> {
/// let audit = auth.audit();
///
/// // Retrieve recent permission log entries for a specific user
/// let logs = audit.permission_logs(Some("user_123"), None, None, Some(50)).await?;
///
/// // Get security audit statistics
/// let stats = audit.security_stats().await?;
/// # Ok(())
/// # }
/// ```
pub struct AuditOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl AuditOperations<'_> {
    /// Query permission-related audit log entries using an [`AuditLogQuery`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let logs = auth.audit()
    ///     .query_permission_logs(
    ///         AuditLogQuery::new()
    ///             .user("user_123")
    ///             .action("read")
    ///             .limit(50)
    ///     )
    ///     .await?;
    /// ```
    pub async fn query_permission_logs(&self, query: AuditLogQuery) -> Result<Vec<String>> {
        self.framework
            .get_permission_audit_logs(
                query.user_id.as_deref(),
                query.action.as_deref(),
                query.resource.as_deref(),
                query.limit,
            )
            .await
    }

    /// Query permission-related audit log entries with optional filters.
    ///
    /// Prefer [`query_permission_logs`](Self::query_permission_logs) with an
    /// [`AuditLogQuery`] for better readability when using multiple filters.
    pub async fn permission_logs(
        &self,
        user_id: Option<&str>,
        action: Option<&str>,
        resource: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<String>> {
        self.framework
            .get_permission_audit_logs(user_id, action, resource, limit)
            .await
    }

    /// Get aggregated permission metrics (role counts, active sessions, checks per hour).
    pub async fn permission_metrics(&self) -> Result<std::collections::HashMap<String, u64>> {
        self.framework.get_permission_metrics().await
    }

    /// Get comprehensive security audit statistics.
    pub async fn security_stats(&self) -> Result<SecurityAuditStats> {
        self.framework.get_security_audit_stats().await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;

    async fn make_fw() -> AuthFramework {
        let config = AuthConfig::new().secret("test_ops_secret_key_32bytes_long!".to_string());
        let mut fw = AuthFramework::new(config);
        fw.initialize().await.unwrap();
        fw
    }

    // ── UserOperations ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_user_ops_register_and_get() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("ops_user1", "ops1@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let info = fw.users().get(&uid).await.unwrap();
        assert_eq!(info.username, "ops_user1");
    }

    #[tokio::test]
    async fn test_user_ops_list_empty() {
        let fw = make_fw().await;
        let list = fw
            .users()
            .list_with_query(UserListQuery::new().limit(10))
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_user_ops_exists_by_username() {
        let fw = make_fw().await;
        fw.users()
            .register("exists_u", "exists@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(fw.users().exists_by_username("exists_u").await.unwrap());
        assert!(!fw.users().exists_by_username("nope_u").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_ops_exists_by_email() {
        let fw = make_fw().await;
        fw.users()
            .register("email_u", "email_exists@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        assert!(
            fw.users()
                .exists_by_email("email_exists@test.com")
                .await
                .unwrap()
        );
        assert!(!fw.users().exists_by_email("no@test.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_ops_profile() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("profile_u", "prof@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let profile = fw.users().profile(&uid).await.unwrap();
        assert_eq!(profile.display_name().unwrap_or_default(), "profile_u");
    }

    #[tokio::test]
    async fn test_user_ops_update_password_and_verify() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("pw_user", "pw@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.users()
            .update_password("pw_user", "NewStr0ng!Pass")
            .await
            .unwrap();
        assert!(
            fw.users()
                .verify_password(&uid, "NewStr0ng!Pass")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_user_ops_update_email() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("email_upd_u", "old@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.users().update_email(&uid, "new@test.com").await.unwrap();
        assert!(fw.users().exists_by_email("new@test.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_ops_set_active() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("act_u", "act@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.users()
            .set_status(&uid, UserStatus::Inactive)
            .await
            .unwrap();
        let info = fw.users().get(&uid).await.unwrap();
        assert!(!info.active);
    }

    #[tokio::test]
    async fn test_user_ops_delete() {
        let fw = make_fw().await;
        fw.users()
            .register("del_u", "del@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.users().delete("del_u").await.unwrap();
        assert!(!fw.users().exists_by_username("del_u").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_ops_username() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("name_u", "name@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let name = fw.users().username(&uid).await.unwrap();
        assert_eq!(name, "name_u");
    }

    // ── SessionOperations ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_session_ops_create_get_delete() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("sess_u", "sess@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let sid = fw
            .sessions()
            .create(&uid, Duration::from_secs(3600), None, None)
            .await
            .unwrap();
        let sess = fw.sessions().get(&sid).await.unwrap();
        assert!(sess.is_some());
        fw.sessions().delete(&sid).await.unwrap();
        assert!(fw.sessions().get(&sid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_session_ops_list_for_user() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("sl_u", "sl@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.sessions()
            .create(&uid, Duration::from_secs(3600), None, None)
            .await
            .unwrap();
        let list = fw.sessions().list_for_user(&uid).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_session_ops_cleanup_expired() {
        let fw = make_fw().await;
        // Should not error even with no sessions
        fw.sessions().cleanup_expired().await.unwrap();
    }

    // ── TokenOperations ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_token_ops_create_validate_revoke() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("tok_u", "tok@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        // Create API key instead of auth token—no auth method registration needed
        let key = fw.tokens().create_api_key(&uid, None).await.unwrap();
        let info = fw.tokens().validate_api_key(&key).await.unwrap();
        assert!(!info.id.is_empty());
        fw.tokens().revoke_api_key(&key).await.unwrap();
    }

    #[tokio::test]
    async fn test_token_ops_api_key_lifecycle() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("apikey_u", "apikey@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let key = fw.tokens().create_api_key(&uid, None).await.unwrap();
        let info = fw.tokens().validate_api_key(&key).await.unwrap();
        // API key creates an internal user; just verify it resolves
        assert!(!info.id.is_empty());
        fw.tokens().revoke_api_key(&key).await.unwrap();
        assert!(fw.tokens().validate_api_key(&key).await.is_err());
    }

    // ── AuthorizationOperations ─────────────────────────────────────────

    #[tokio::test]
    async fn test_authz_ops_grant_and_check() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("authz_u", "authz@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.authorization()
            .grant(&uid, "read", "docs")
            .await
            .unwrap();
        // Verify via has_role / effective_permissions rather than via token (no auth method registered)
        let perms = fw
            .authorization()
            .effective_permissions(&uid)
            .await
            .unwrap();
        assert!(perms.iter().any(|p| p.contains("read")));
    }

    #[tokio::test]
    async fn test_authz_ops_role_lifecycle() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("role_u", "role@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.authorization().assign_role(&uid, "admin").await.unwrap();
        assert!(fw.authorization().has_role(&uid, "admin").await.unwrap());
        let roles = fw.authorization().roles_for_user(&uid).await.unwrap();
        assert!(roles.contains(&"admin".to_string()));
        fw.authorization().remove_role(&uid, "admin").await.unwrap();
        assert!(!fw.authorization().has_role(&uid, "admin").await.unwrap());
    }

    // ── MfaOperations ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_mfa_ops_totp_lifecycle() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("mfa_u", "mfa@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let secret = fw.mfa().generate_totp_secret(&uid).await.unwrap();
        assert!(!secret.is_empty());
        let code = fw.mfa().generate_totp_code(&secret).await.unwrap();
        assert_eq!(code.len(), 6);
        assert!(fw.mfa().verify_totp(&uid, &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_mfa_ops_backup_codes() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("bc_u", "bc@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let codes = fw.mfa().generate_backup_codes(&uid, 5).await.unwrap();
        assert_eq!(codes.len(), 5);
    }

    #[tokio::test]
    async fn test_mfa_ops_sms_lifecycle() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("smsop_u", "smsop@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.mfa().register_phone(&uid, "+12345678901").await.unwrap();
        let cid = fw.mfa().initiate_sms(&uid).await.unwrap();
        assert!(!cid.is_empty());
    }

    #[tokio::test]
    async fn test_mfa_ops_email_lifecycle() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("emop_u", "emop@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.mfa()
            .register_email(&uid, "emop@test.com")
            .await
            .unwrap();
        let cid = fw.mfa().initiate_email(&uid).await.unwrap();
        assert!(!cid.is_empty());
    }

    // ── MonitoringOperations ────────────────────────────────────────────

    #[tokio::test]
    async fn test_monitoring_ops_health_check() {
        let fw = make_fw().await;
        let health = fw.monitoring().health_check().await.unwrap();
        assert!(!health.is_empty());
    }

    #[tokio::test]
    async fn test_monitoring_ops_performance_metrics() {
        let fw = make_fw().await;
        let _metrics = fw.monitoring().performance_metrics().await;
    }

    #[tokio::test]
    async fn test_monitoring_ops_stats() {
        let fw = make_fw().await;
        let stats = fw.monitoring().stats().await.unwrap();
        assert_eq!(stats.active_sessions, 0);
    }

    #[tokio::test]
    async fn test_monitoring_ops_prometheus() {
        let fw = make_fw().await;
        let prom = fw.monitoring().prometheus_metrics().await;
        // Just verify it returns valid-looking metrics text
        assert!(!prom.is_empty());
    }

    // ── AdminOperations ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_admin_ops_role_inheritance() {
        let fw = make_fw().await;
        // Default roles include "admin" and "user" — use those
        fw.admin()
            .set_role_inheritance("user", "admin")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_admin_ops_abac_policy() {
        let fw = make_fw().await;
        fw.admin()
            .create_abac_policy("ip_allow", "IP allowlist policy")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_admin_ops_user_attributes() {
        let fw = make_fw().await;
        let uid = fw
            .users()
            .register("attr_u", "attr@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.admin()
            .map_user_attribute(&uid, "department", "engineering")
            .await
            .unwrap();
        let val = fw
            .admin()
            .get_user_attribute(&uid, "department")
            .await
            .unwrap();
        assert_eq!(val.as_deref(), Some("engineering"));
    }

    #[tokio::test]
    async fn test_admin_ops_delegation() {
        let fw = make_fw().await;
        let uid1 = fw
            .users()
            .register("del_from", "delf@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        let uid2 = fw
            .users()
            .register("del_to", "delt@test.com", "StrongP@ss1!")
            .await
            .unwrap();
        fw.authorization()
            .grant(&uid1, "write", "report")
            .await
            .unwrap();
        fw.admin()
            .delegate_permission(&uid1, &uid2, "write", "report", Duration::from_secs(3600))
            .await
            .unwrap();
    }

    // ── MaintenanceOperations ───────────────────────────────────────────

    #[tokio::test]
    async fn test_maintenance_ops_backup_dry_run() {
        let fw = make_fw().await;
        let report = fw
            .maintenance()
            .backup_to_file("test_backup.json", true)
            .await
            .unwrap();
        assert!(report.dry_run);
    }

    #[tokio::test]
    async fn test_maintenance_ops_reset_dry_run() {
        let fw = make_fw().await;
        let report = fw.maintenance().reset(true).await.unwrap();
        assert!(report.dry_run);
    }

    // ── AuditOperations ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_audit_ops_permission_logs() {
        let fw = make_fw().await;
        let logs = fw
            .audit()
            .permission_logs(None, None, None, Some(10))
            .await
            .unwrap();
        assert!(logs.is_empty()); // no activity yet
    }

    #[tokio::test]
    async fn test_audit_ops_permission_metrics() {
        let fw = make_fw().await;
        let metrics = fw.audit().permission_metrics().await.unwrap();
        assert!(!metrics.is_empty());
    }

    #[tokio::test]
    async fn test_audit_ops_security_stats() {
        let fw = make_fw().await;
        let stats = fw.audit().security_stats().await.unwrap();
        assert_eq!(stats.failed_logins_24h, 0);
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// Admin operations
// ──────────────────────────────────────────────────────────────────────────────

/// Focused advanced administration operations exposed from [`AuthFramework::admin`].
///
/// These operations go beyond the everyday [`AuthorizationOperations`] surface and cover
/// ABAC policy management, permission delegation, role inheritance, resource registration,
/// and attribute-based access control.
pub struct AdminOperations<'a> {
    pub(crate) framework: &'a AuthFramework,
}

impl AdminOperations<'_> {
    /// Define a parent–child role inheritance relationship.
    pub async fn set_role_inheritance(&self, child_role: &str, parent_role: &str) -> Result<()> {
        self.framework
            .set_role_inheritance(child_role, parent_role)
            .await
    }

    /// Create an ABAC policy.
    pub async fn create_abac_policy(&self, name: &str, description: &str) -> Result<()> {
        self.framework.create_abac_policy(name, description).await
    }

    /// Map a user attribute used in ABAC policy evaluation.
    pub async fn map_user_attribute(
        &self,
        user_id: &str,
        attribute: &str,
        value: &str,
    ) -> Result<()> {
        self.framework
            .map_user_attribute(user_id, attribute, value)
            .await
    }

    /// Set multiple user attributes in one call.
    ///
    /// This is a convenience wrapper around [`map_user_attribute`](Self::map_user_attribute)
    /// for setting several ABAC attributes at once.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::prelude::*;
    /// # async fn example(auth: &AuthFramework) -> Result<(), AuthError> {
    /// auth.admin().set_user_attributes("user-1", &[
    ///     ("department", "engineering"),
    ///     ("clearance", "top-secret"),
    ///     ("location", "us-west-2"),
    /// ]).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_user_attributes(
        &self,
        user_id: &str,
        attributes: &[(&str, &str)],
    ) -> Result<()> {
        for &(attribute, value) in attributes {
            self.framework
                .map_user_attribute(user_id, attribute, value)
                .await?;
        }
        Ok(())
    }

    /// Get a user attribute value.
    pub async fn get_user_attribute(
        &self,
        user_id: &str,
        attribute: &str,
    ) -> Result<Option<String>> {
        self.framework.get_user_attribute(user_id, attribute).await
    }

    /// Check a permission using dynamic ABAC context evaluation.
    ///
    /// Prefer [`check_dynamic_permission_with_context`](Self::check_dynamic_permission_with_context)
    /// with a [`PermissionContext`] for a more readable API.
    pub async fn check_dynamic_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        context: std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        self.framework
            .check_dynamic_permission(user_id, action, resource, context)
            .await
    }

    /// Check a permission using dynamic ABAC context evaluation with a
    /// [`PermissionContext`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use auth_framework::auth_operations::PermissionContext;
    ///
    /// let ctx = PermissionContext::new()
    ///     .with_attribute("ip_location", "office")
    ///     .with_attribute("device_type", "trusted");
    ///
    /// let allowed = auth.admin()
    ///     .check_dynamic_permission_with_context("user_123", "read", "docs", ctx)
    ///     .await?;
    /// ```
    pub async fn check_dynamic_permission_with_context(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        context: PermissionContext,
    ) -> Result<bool> {
        self.framework
            .check_dynamic_permission(user_id, action, resource, context.into_attributes())
            .await
    }

    /// Register a resource in the permission system.
    pub async fn create_resource(&self, resource: &str) -> Result<()> {
        self.framework.create_resource(resource).await
    }

    /// Delegate a permission from one user to another using a [`DelegationRequest`].
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// auth.admin()
    ///     .delegate(
    ///         DelegationRequest::new("admin_1", "user_2", "write", "reports")
    ///             .duration(Duration::from_secs(3600))
    ///     )
    ///     .await?;
    /// ```
    pub async fn delegate(&self, req: DelegationRequest) -> Result<()> {
        self.framework
            .delegate_permission(
                &req.delegator_id,
                &req.delegatee_id,
                &req.action,
                &req.resource,
                req.duration,
            )
            .await
    }

    /// Delegate a permission from one user to another for a limited duration.
    ///
    /// Prefer [`delegate`](Self::delegate) with a [`DelegationRequest`] for
    /// better readability.
    pub async fn delegate_permission(
        &self,
        delegator_id: &str,
        delegatee_id: &str,
        action: &str,
        resource: &str,
        duration: Duration,
    ) -> Result<()> {
        self.framework
            .delegate_permission(delegator_id, delegatee_id, action, resource, duration)
            .await
    }

    /// List currently active permission delegations for a user.
    pub async fn active_delegations(&self, user_id: &str) -> Result<Vec<String>> {
        self.framework.get_active_delegations(user_id).await
    }
}
