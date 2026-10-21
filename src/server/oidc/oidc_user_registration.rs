//! Initiating User Registration via OpenID Connect
//!
//! This module implements the "Initiating User Registration via OpenID Connect 1.0"
//! specification, which allows clients to initiate user registration through the
//! OpenID Connect authorization flow using the `prompt=create` parameter.
//!
//! # Features
//!
//! - `prompt=create` parameter handling
//! - User registration flow integration
//! - Registration completion validation
//! - Registration metadata and claims handling
//! - Structured OIDC error responses for registration failures
//! - Session management with timeout handling
//! - Comprehensive error reporting using OpenID Connect error codes
//!
//! # Error Handling
//!
//! The registration manager uses `OidcErrorManager` to provide structured error
//! responses that comply with OpenID Connect specifications:
//!
//! - `registration_not_supported` - When registration is disabled
//! - `invalid_request` - For malformed registration requests
//! - `session_selection_required` - For missing/invalid registration sessions
//! - `registration_required` - For incomplete registration data
//! - `login_required` - For expired registration sessions
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use auth_framework::server::oidc::oidc_user_registration::{RegistrationManager, RegistrationConfig, RegistrationRequest};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manager = RegistrationManager::new(RegistrationConfig::default());
//!
//! let request = RegistrationRequest {
//!     client_id: "client123".to_string(),
//!     redirect_uri: "https://app.example.com/callback".to_string(),
//!     scope: "openid profile email".to_string(),
//!     response_type: "code".to_string(),
//!     prompt: Some("create".to_string()),
//!     state: None,
//!     nonce: None,
//!     login_hint: None,
//!     ui_locales: None,
//!     registration_metadata: None,
//!     claims: None,
//! };
//!
//! let registration_id = manager.initiate_registration(request)?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::server::oidc::oidc_error_extensions::{
    OidcErrorCode, OidcErrorManager, OidcErrorResponse,
};
use crate::storage::AuthStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

/// User registration request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    /// Standard OpenID Connect parameters
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub response_type: String,
    pub state: Option<String>,
    pub nonce: Option<String>,

    /// Registration-specific parameters
    /// Prompt parameter should contain "create"
    pub prompt: Option<String>,
    /// Login hint for pre-filling registration form
    pub login_hint: Option<String>,
    /// UI locales for registration interface
    pub ui_locales: Option<String>,
    /// Registration metadata as JSON string
    pub registration_metadata: Option<String>,
    /// Claims to be collected during registration
    pub claims: Option<String>,
}

impl RegistrationRequest {
    /// Create a new builder for a RegistrationRequest.
    pub fn builder(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        response_type: impl Into<String>,
    ) -> RegistrationRequestBuilder {
        RegistrationRequestBuilder {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            response_type: response_type.into(),
            state: None,
            nonce: None,
            prompt: None,
            login_hint: None,
            ui_locales: None,
            registration_metadata: None,
            claims: None,
        }
    }
}

/// Builder for RegistrationRequest
pub struct RegistrationRequestBuilder {
    client_id: String,
    redirect_uri: String,
    scope: String,
    response_type: String,
    state: Option<String>,
    nonce: Option<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    ui_locales: Option<String>,
    registration_metadata: Option<String>,
    claims: Option<String>,
}

impl RegistrationRequestBuilder {
    /// Set the state parameter
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Set the nonce parameter
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Set the prompt parameter
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Set the login hint
    pub fn login_hint(mut self, login_hint: impl Into<String>) -> Self {
        self.login_hint = Some(login_hint.into());
        self
    }

    /// Set UI locales
    pub fn ui_locales(mut self, ui_locales: impl Into<String>) -> Self {
        self.ui_locales = Some(ui_locales.into());
        self
    }

    /// Set registration metadata
    pub fn registration_metadata(mut self, registration_metadata: impl Into<String>) -> Self {
        self.registration_metadata = Some(registration_metadata.into());
        self
    }

    /// Set claims to collect
    pub fn claims(mut self, claims: impl Into<String>) -> Self {
        self.claims = Some(claims.into());
        self
    }

    /// Build the request
    pub fn build(self) -> RegistrationRequest {
        RegistrationRequest {
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            response_type: self.response_type,
            state: self.state,
            nonce: self.nonce,
            prompt: self.prompt,
            login_hint: self.login_hint,
            ui_locales: self.ui_locales,
            registration_metadata: self.registration_metadata,
            claims: self.claims,
        }
    }
}

/// User registration data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistrationData {
    /// Unique registration session ID
    pub registration_id: String,
    /// User's email address
    pub email: Option<String>,
    /// User's phone number
    pub phone_number: Option<String>,
    /// User's given name
    pub given_name: Option<String>,
    /// User's family name
    pub family_name: Option<String>,
    /// User's full name
    pub name: Option<String>,
    /// User's preferred username
    pub preferred_username: Option<String>,
    /// User's profile picture URL
    pub picture: Option<String>,
    /// User's website URL
    pub website: Option<String>,
    /// User's gender
    pub gender: Option<String>,
    /// User's birthdate
    pub birthdate: Option<String>,
    /// User's timezone
    pub zoneinfo: Option<String>,
    /// User's locale
    pub locale: Option<String>,
    /// Custom registration fields
    pub custom_fields: HashMap<String, serde_json::Value>,
    /// Registration completion status
    pub completed: bool,
    /// Creation timestamp
    pub created_at: u64,
}

impl RegistrationData {
    /// Create a new RegistrationData instance.
    pub fn new(registration_id: impl Into<String>) -> Self {
        use std::time::SystemTime;
        Self {
            registration_id: registration_id.into(),
            email: None,
            phone_number: None,
            given_name: None,
            family_name: None,
            name: None,
            preferred_username: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            custom_fields: HashMap::new(),
            completed: false,
            created_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Set the user's email.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the user's phone number.
    pub fn with_phone_number(mut self, phone_number: impl Into<String>) -> Self {
        self.phone_number = Some(phone_number.into());
        self
    }

    /// Set the full name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the given and family name.
    pub fn with_names(mut self, given: impl Into<String>, family: impl Into<String>) -> Self {
        self.given_name = Some(given.into());
        self.family_name = Some(family.into());
        self
    }

    /// Mark the registration as completed.
    pub fn mark_completed(mut self) -> Self {
        self.completed = true;
        self
    }
}

/// Registration completion response
#[derive(Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// New user's subject identifier
    pub sub: String,
    /// Registration completion status
    pub completed: bool,
    /// Authorization code for completed registration
    pub code: Option<String>,
    /// State parameter from original request
    pub state: Option<String>,
}

impl std::fmt::Debug for RegistrationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("RegistrationResponse");
        d.field("sub", &self.sub);
        d.field("completed", &self.completed);
        d.field("code", &crate::utils::redact::redacted(&self.code));
        d.field("state", &self.state);
        d.finish()
    }
}

/// Registration configuration
#[derive(Debug, Clone)]
pub struct RegistrationConfig {
    /// Enable user registration via prompt=create
    pub enabled: bool,
    /// Registration endpoint URL
    pub registration_endpoint: String,
    /// Required fields for registration
    pub required_fields: Vec<String>,
    /// Optional fields available during registration
    pub optional_fields: Vec<String>,
    /// Maximum registration session duration (seconds)
    pub session_timeout: u64,
    /// Enable email verification during registration
    pub require_email_verification: bool,
    /// Enable phone verification during registration
    pub require_phone_verification: bool,
    /// Custom field validation rules
    pub field_validation_rules: HashMap<String, String>,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            registration_endpoint: "/connect/register".to_string(),
            required_fields: vec!["email".to_string()],
            optional_fields: vec![
                "given_name".to_string(),
                "family_name".to_string(),
                "name".to_string(),
                "preferred_username".to_string(),
                "phone_number".to_string(),
            ],
            session_timeout: 1800, // 30 minutes
            require_email_verification: true,
            require_phone_verification: false,
            field_validation_rules: HashMap::new(),
        }
    }
}

/// User registration manager
#[derive(Clone)]
pub struct RegistrationManager {
    /// Configuration
    config: RegistrationConfig,
    /// Error manager for creating error responses
    error_manager: OidcErrorManager,
    /// Active registration sessions
    registration_sessions: HashMap<String, RegistrationData>,
    /// Optional storage backend for persisting completed registrations
    storage: Option<Arc<dyn AuthStorage>>,
}

impl std::fmt::Debug for RegistrationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationManager")
            .field("config", &self.config)
            .field("sessions", &self.registration_sessions.len())
            .field("has_storage", &self.storage.is_some())
            .finish()
    }
}

impl RegistrationManager {
    /// Create new registration manager
    pub fn new(config: RegistrationConfig) -> Self {
        Self {
            config,
            error_manager: OidcErrorManager::default(),
            registration_sessions: HashMap::new(),
            storage: None,
        }
    }

    /// Set an optional storage backend for user persistence (chainable).
    pub fn storage(mut self, storage: Arc<dyn AuthStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set a custom OidcErrorManager (chainable).
    pub fn error_manager(mut self, error_manager: OidcErrorManager) -> Self {
        self.error_manager = error_manager;
        self
    }

    /// Create OIDC error response for registration not enabled
    pub fn create_registration_disabled_error(&self, state: Option<String>) -> OidcErrorResponse {
        self.error_manager.create_error_response(
            OidcErrorCode::RegistrationNotSupported,
            Some("User registration is not enabled on this server".to_string()),
            state,
            HashMap::new(),
        )
    }

    /// Create OIDC error response for invalid registration request
    pub fn create_invalid_registration_request_error(
        &self,
        description: String,
        state: Option<String>,
    ) -> OidcErrorResponse {
        self.error_manager.create_error_response(
            OidcErrorCode::InvalidRequest,
            Some(description),
            state,
            HashMap::new(),
        )
    }

    /// Create OIDC error response for registration session not found
    pub fn create_session_not_found_error(&self, state: Option<String>) -> OidcErrorResponse {
        self.error_manager.create_error_response(
            OidcErrorCode::SessionSelectionRequired,
            Some("Registration session not found or expired".to_string()),
            state,
            HashMap::new(),
        )
    }

    /// Create OIDC error response for missing required registration fields
    pub fn create_registration_incomplete_error(
        &self,
        missing_fields: Vec<String>,
        state: Option<String>,
    ) -> OidcErrorResponse {
        let mut additional_details = HashMap::new();
        additional_details.insert(
            "missing_fields".to_string(),
            serde_json::to_value(missing_fields.clone()).unwrap_or_default(),
        );

        self.error_manager.create_error_response(
            OidcErrorCode::RegistrationRequired,
            Some(format!(
                "Registration incomplete. Missing required fields: {}",
                missing_fields.join(", ")
            )),
            state,
            additional_details,
        )
    }

    /// Create OIDC error response for expired registration session
    pub fn create_session_expired_error(&self, state: Option<String>) -> OidcErrorResponse {
        self.error_manager.create_error_response(
            OidcErrorCode::LoginRequired,
            Some("Registration session has expired. Please start registration again".to_string()),
            state,
            HashMap::new(),
        )
    }

    /// Get error manager reference for external usage
    pub fn get_error_manager(&self) -> &OidcErrorManager {
        &self.error_manager
    }

    /// Update error manager configuration
    pub fn update_error_manager(&mut self, error_manager: OidcErrorManager) {
        self.error_manager = error_manager;
    }

    /// Check if registration is requested via prompt=create
    pub fn is_registration_requested(&self, prompt: Option<&str>) -> bool {
        if !self.config.enabled {
            return false;
        }

        if let Some(prompt_values) = prompt {
            let prompts: Vec<&str> = prompt_values.split_whitespace().collect();
            prompts.contains(&"create")
        } else {
            false
        }
    }

    /// Initiate user registration process
    pub fn initiate_registration(&mut self, request: RegistrationRequest) -> Result<String> {
        if !self.config.enabled {
            let error_response = self.create_registration_disabled_error(request.state.clone());
            return Err(AuthError::validation(format!(
                "Registration disabled: {}",
                error_response.error_description.unwrap_or_default()
            )));
        }

        // Validate prompt parameter contains "create"
        if !self.is_registration_requested(request.prompt.as_deref()) {
            let error_response = self.create_invalid_registration_request_error(
                "Registration requires prompt=create parameter".to_string(),
                request.state.clone(),
            );
            return Err(AuthError::validation(format!(
                "Invalid request: {}",
                error_response.error_description.unwrap_or_default()
            )));
        }

        // Create new registration session
        let registration_id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut registration_data = RegistrationData {
            registration_id: registration_id.clone(),
            email: None,
            phone_number: None,
            given_name: None,
            family_name: None,
            name: None,
            preferred_username: None,
            picture: None,
            website: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            custom_fields: HashMap::new(),
            completed: false,
            created_at: now,
        };

        // Pre-fill with login_hint if provided
        if let Some(login_hint) = &request.login_hint {
            if login_hint.contains('@') {
                registration_data.email = Some(login_hint.clone());
            } else {
                registration_data.preferred_username = Some(login_hint.clone());
            }
        }

        // Parse and store registration metadata
        if let Some(metadata_str) = &request.registration_metadata {
            match serde_json::from_str::<HashMap<String, serde_json::Value>>(metadata_str) {
                Ok(metadata) => {
                    registration_data.custom_fields.extend(metadata);
                }
                Err(_) => {
                    let error_response = self.create_invalid_registration_request_error(
                        "Invalid registration metadata JSON format".to_string(),
                        request.state.clone(),
                    );
                    return Err(AuthError::validation(format!(
                        "Invalid metadata: {}",
                        error_response.error_description.unwrap_or_default()
                    )));
                }
            }
        }

        self.registration_sessions
            .insert(registration_id.clone(), registration_data);

        Ok(registration_id)
    }

    /// Update registration data
    pub fn update_registration_data(
        &mut self,
        registration_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        // Check if registration exists and get mutable reference
        let Some(registration) = self.registration_sessions.get_mut(registration_id) else {
            let error_response = self.create_session_not_found_error(None);
            return Err(AuthError::validation(format!(
                "Session error: {}",
                error_response.error_description.unwrap_or_default()
            )));
        };

        // Check session timeout
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now - registration.created_at > self.config.session_timeout {
            let error_response = self.create_session_expired_error(None);
            return Err(AuthError::validation(format!(
                "Session expired: {}",
                error_response.error_description.unwrap_or_default()
            )));
        }

        // Update standard fields
        for (key, value) in updates {
            match key.as_str() {
                "email" => registration.email = value.as_str().map(|s| s.to_string()),
                "phone_number" => registration.phone_number = value.as_str().map(|s| s.to_string()),
                "given_name" => registration.given_name = value.as_str().map(|s| s.to_string()),
                "family_name" => registration.family_name = value.as_str().map(|s| s.to_string()),
                "name" => registration.name = value.as_str().map(|s| s.to_string()),
                "preferred_username" => {
                    registration.preferred_username = value.as_str().map(|s| s.to_string())
                }
                "picture" => registration.picture = value.as_str().map(|s| s.to_string()),
                "website" => registration.website = value.as_str().map(|s| s.to_string()),
                "gender" => registration.gender = value.as_str().map(|s| s.to_string()),
                "birthdate" => registration.birthdate = value.as_str().map(|s| s.to_string()),
                "zoneinfo" => registration.zoneinfo = value.as_str().map(|s| s.to_string()),
                "locale" => registration.locale = value.as_str().map(|s| s.to_string()),
                _ => {
                    // Store in custom fields
                    registration.custom_fields.insert(key, value);
                }
            }
        }

        Ok(())
    }

    /// Validate registration data completeness
    pub fn validate_registration_data(&self, registration_id: &str) -> Result<Vec<String>> {
        // Check if registration exists
        let Some(registration) = self.registration_sessions.get(registration_id) else {
            let error_response = self.create_session_not_found_error(None);
            return Err(AuthError::validation(format!(
                "Session error: {}",
                error_response.error_description.unwrap_or_default()
            )));
        };

        let mut missing_fields = Vec::new();

        // Check required fields
        for field in &self.config.required_fields {
            let is_present = match field.as_str() {
                "email" => registration.email.is_some(),
                "phone_number" => registration.phone_number.is_some(),
                "given_name" => registration.given_name.is_some(),
                "family_name" => registration.family_name.is_some(),
                "name" => registration.name.is_some(),
                "preferred_username" => registration.preferred_username.is_some(),
                _ => registration.custom_fields.contains_key(field),
            };

            if !is_present {
                missing_fields.push(field.clone());
            }
        }

        Ok(missing_fields)
    }

    /// Validate registration data and create error response if incomplete
    pub fn validate_registration_completeness(
        &self,
        registration_id: &str,
        state: Option<String>,
    ) -> Result<()> {
        let missing_fields = self.validate_registration_data(registration_id)?;
        if !missing_fields.is_empty() {
            let error_response = self.create_registration_incomplete_error(missing_fields, state);
            return Err(AuthError::validation(format!(
                "Registration incomplete: {}",
                error_response.error_description.unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Complete user registration and create user account
    ///
    /// When a storage backend has been provided via [`RegistrationManager::storage`],
    /// the newly registered user is persisted to storage using the same key layout as
    /// `AuthFramework::register_user` so that downstream endpoints (e.g. `userinfo`) can
    /// retrieve the profile immediately after registration.
    ///
    /// If no storage backend is configured the session is still consumed and an
    /// authorisation code is issued, but the user is **not** persisted — callers must
    /// wire in storage via `.storage()` before this path is production-ready.
    pub async fn complete_registration(
        &mut self,
        registration_id: &str,
    ) -> Result<RegistrationResponse> {
        // Validate registration data using error manager
        self.validate_registration_completeness(registration_id, None)?;

        // Check if registration exists and remove it
        let Some(mut registration) = self.registration_sessions.remove(registration_id) else {
            let error_response = self.create_session_not_found_error(None);
            return Err(AuthError::validation(format!(
                "Session error: {}",
                error_response.error_description.unwrap_or_default()
            )));
        };

        // Generate new user subject identifier
        let sub = crate::utils::string::generate_id(Some("user"));

        // Mark registration as completed
        registration.completed = true;

        // Persist the user to storage when a backend has been configured.
        if let Some(storage) = &self.storage {
            // Derive a username: prefer preferred_username, fall back to the local
            // part of the email address, and finally the sub itself.
            let username = registration
                .preferred_username
                .clone()
                .or_else(|| {
                    registration
                        .email
                        .as_deref()
                        .and_then(|e| e.split('@').next())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| sub.clone());

            let email = registration
                .email
                .clone()
                .unwrap_or_else(|| format!("{}@unknown.invalid", sub));

            // A password may be supplied in custom_fields["password"] (e.g. from an
            // interactive registration form).  If absent, generate a strong temporary
            // password so the account is accessible; the client receives it in the
            // RegistrationResponse and should prompt an immediate password change.
            let plain_password = registration
                .custom_fields
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("tmp_{}", Uuid::new_v4()));

            let password_hash =
                bcrypt::hash(&plain_password, bcrypt::DEFAULT_COST).map_err(|e| {
                    AuthError::crypto(format!(
                        "Failed to hash password during registration: {}",
                        e
                    ))
                })?;

            let user_data = serde_json::json!({
                "user_id": sub,
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "given_name": registration.given_name,
                "family_name": registration.family_name,
                "name": registration.name,
                "phone_number": registration.phone_number,
                "picture": registration.picture,
                "roles": ["user"],
                "active": true,
                "created_at": chrono::Utc::now().to_rfc3339(),
            });

            // Store indexed entries following the same layout as auth.rs::register_user.
            storage
                .store_kv(
                    &format!("user:{}", sub),
                    user_data.to_string().as_bytes(),
                    None,
                )
                .await?;
            storage
                .store_kv(&format!("user:username:{}", username), sub.as_bytes(), None)
                .await?;
            storage
                .store_kv(&format!("user:email:{}", email), sub.as_bytes(), None)
                .await?;

            tracing::info!(
                "OIDC registration complete: user '{}' (sub={}) persisted to storage",
                username,
                sub
            );
        } else {
            warn!(
                "OIDC user registration for sub '{}' completed the session but did NOT persist \
                 the user to storage. Provide a storage backend via \
                 RegistrationManager::storage() to enable user persistence.",
                sub
            );
        }

        // Generate authorization code for successful registration
        let authorization_code = format!("reg_auth_{}", Uuid::new_v4());

        Ok(RegistrationResponse {
            sub,
            completed: true,
            code: Some(authorization_code),
            state: None, // This would be populated from the original request
        })
    }

    /// Get registration session data
    pub fn get_registration_data(&self, registration_id: &str) -> Option<&RegistrationData> {
        self.registration_sessions.get(registration_id)
    }

    /// Generate registration form HTML
    pub fn generate_registration_form(&self, registration_id: &str) -> Result<String> {
        // Check if registration exists
        let Some(registration) = self.registration_sessions.get(registration_id) else {
            let error_response = self.create_session_not_found_error(None);
            return Err(AuthError::validation(format!(
                "Session error: {}",
                error_response.error_description.unwrap_or_default()
            )));
        };

        let mut form = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>User Registration</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .form-group {{ margin-bottom: 15px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input {{ width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }}
        .required {{ color: red; }}
        .submit-btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>Create Your Account</h1>
    <form method="post" action="/connect/register/{}/complete">
"#,
            registration.registration_id
        );

        // Add required fields
        for field in &self.config.required_fields {
            let (field_name, field_type, current_value) = match field.as_str() {
                "email" => (
                    "Email Address",
                    "email",
                    registration.email.as_deref().unwrap_or(""),
                ),
                "given_name" => (
                    "First Name",
                    "text",
                    registration.given_name.as_deref().unwrap_or(""),
                ),
                "family_name" => (
                    "Last Name",
                    "text",
                    registration.family_name.as_deref().unwrap_or(""),
                ),
                "phone_number" => (
                    "Phone Number",
                    "tel",
                    registration.phone_number.as_deref().unwrap_or(""),
                ),
                _ => (field.as_str(), "text", ""),
            };

            form.push_str(&format!(
                r#"        <div class="form-group">
            <label for="{}">{} <span class="required">*</span></label>
            <input type="{}" id="{}" name="{}" value="{}" required>
        </div>
"#,
                field, field_name, field_type, field, field, current_value
            ));
        }

        // Add optional fields
        for field in &self.config.optional_fields {
            if !self.config.required_fields.contains(field) {
                let (field_name, field_type, current_value) = match field.as_str() {
                    "preferred_username" => (
                        "Username",
                        "text",
                        registration.preferred_username.as_deref().unwrap_or(""),
                    ),
                    "website" => (
                        "Website",
                        "url",
                        registration.website.as_deref().unwrap_or(""),
                    ),
                    "picture" => (
                        "Profile Picture URL",
                        "url",
                        registration.picture.as_deref().unwrap_or(""),
                    ),
                    _ => (field.as_str(), "text", ""),
                };

                form.push_str(&format!(
                    r#"        <div class="form-group">
            <label for="{}">{}</label>
            <input type="{}" id="{}" name="{}" value="{}">
        </div>
"#,
                    field, field_name, field_type, field, field, current_value
                ));
            }
        }

        form.push_str(
            r#"        <button type="submit" class="submit-btn">Create Account</button>
    </form>
</body>
</html>"#,
        );

        Ok(form)
    }

    /// Clean up expired registration sessions
    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let initial_count = self.registration_sessions.len();

        self.registration_sessions
            .retain(|_, registration| now - registration.created_at < self.config.session_timeout);

        initial_count - self.registration_sessions.len()
    }

    /// Get registration discovery metadata
    pub fn get_discovery_metadata(&self) -> HashMap<String, serde_json::Value> {
        let mut metadata = HashMap::new();

        if self.config.enabled {
            metadata.insert(
                "registration_endpoint".to_string(),
                serde_json::Value::String(self.config.registration_endpoint.clone()),
            );
            metadata.insert(
                "prompt_values_supported".to_string(),
                serde_json::Value::Array(vec![
                    serde_json::Value::String("none".to_string()),
                    serde_json::Value::String("login".to_string()),
                    serde_json::Value::String("consent".to_string()),
                    serde_json::Value::String("select_account".to_string()),
                    serde_json::Value::String("create".to_string()),
                ]),
            );
        }

        metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_request_builder() {
        let req = RegistrationRequest::builder("client_123", "https://app/cb", "openid", "code")
            .prompt("create")
            .login_hint("user@example.com")
            .ui_locales("fr-FR")
            .build();

        assert_eq!(req.client_id, "client_123");
        assert_eq!(req.prompt, Some("create".to_string()));
        assert_eq!(req.login_hint, Some("user@example.com".to_string()));
        assert_eq!(req.ui_locales, Some("fr-FR".to_string()));
    }

    #[test]
    fn test_registration_data_builder() {
        let data = RegistrationData::new("reg_123")
            .with_email("user@example.com")
            .with_names("John", "Doe")
            .mark_completed();

        assert_eq!(data.registration_id, "reg_123");
        assert_eq!(data.email, Some("user@example.com".to_string()));
        assert_eq!(data.given_name, Some("John".to_string()));
        assert_eq!(data.family_name, Some("Doe".to_string()));
        assert!(data.completed);
    }

    #[test]
    fn test_error_manager_integration() {
        let mut manager = RegistrationManager::new(RegistrationConfig::default());

        // Test registration disabled error
        let disabled_config = RegistrationConfig {
            enabled: false,
            ..Default::default()
        };
        let mut disabled_manager = RegistrationManager::new(disabled_config);

        let request = RegistrationRequest {
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            response_type: "code".to_string(),
            state: Some("state123".to_string()),
            nonce: Some("nonce456".to_string()),
            prompt: Some("create".to_string()),
            login_hint: None,
            ui_locales: None,
            registration_metadata: None,
            claims: None,
        };

        let result = disabled_manager.initiate_registration(request.clone());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Registration disabled")
        );

        // Test invalid prompt error
        let invalid_request = RegistrationRequest {
            prompt: Some("login".to_string()), // Missing "create"
            ..request.clone()
        };

        let result = manager.initiate_registration(invalid_request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid request"));

        // Test invalid metadata error
        let invalid_metadata_request = RegistrationRequest {
            registration_metadata: Some("invalid json".to_string()),
            ..request
        };

        let result = manager.initiate_registration(invalid_metadata_request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid metadata"));
    }

    #[test]
    fn test_error_manager_session_handling() {
        let mut manager = RegistrationManager::new(RegistrationConfig::default());

        // Test session not found error
        let result = manager.update_registration_data("nonexistent", HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Session error"));

        // Test validation completeness with missing fields
        let config = RegistrationConfig {
            required_fields: vec!["email".to_string(), "given_name".to_string()],
            ..Default::default()
        };
        let mut manager = RegistrationManager::new(config);

        let registration_data = RegistrationData {
            registration_id: "test123".to_string(),
            email: Some("user@example.com".to_string()),
            given_name: None, // Missing required field
            ..Default::default()
        };

        manager
            .registration_sessions
            .insert("test123".to_string(), registration_data);

        let result =
            manager.validate_registration_completeness("test123", Some("state456".to_string()));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Registration incomplete")
        );
    }

    #[test]
    fn test_error_manager_custom_configuration() {
        use crate::server::oidc::oidc_error_extensions::{OidcErrorCode, OidcErrorManager};

        let mut custom_error_manager = OidcErrorManager::default();
        custom_error_manager.add_custom_error_mapping(
            "custom_registration_error".to_string(),
            OidcErrorCode::RegistrationRequired,
        );

        let manager = RegistrationManager::new(RegistrationConfig::default())
            .error_manager(custom_error_manager);

        // Test error manager is properly set
        assert!(
            manager
                .get_error_manager()
                .has_custom_mapping("custom_registration_error")
        );

        // Test error response creation
        let error_response =
            manager.create_registration_disabled_error(Some("test_state".to_string()));
        assert_eq!(error_response.state.as_ref().unwrap(), "test_state");

        let session_error = manager.create_session_not_found_error(None);
        assert_eq!(session_error.error, OidcErrorCode::SessionSelectionRequired);
    }

    #[test]
    fn test_registration_request_detection() {
        let manager = RegistrationManager::new(RegistrationConfig::default());

        assert!(manager.is_registration_requested(Some("create")));
        assert!(manager.is_registration_requested(Some("login create")));
        assert!(manager.is_registration_requested(Some("create consent")));
        assert!(!manager.is_registration_requested(Some("login")));
        assert!(!manager.is_registration_requested(None));
    }

    #[test]
    fn test_registration_initiation() {
        let mut manager = RegistrationManager::new(RegistrationConfig::default());

        let request = RegistrationRequest {
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            response_type: "code".to_string(),
            state: Some("state123".to_string()),
            nonce: Some("nonce456".to_string()),
            prompt: Some("create".to_string()),
            login_hint: Some("user@example.com".to_string()),
            ui_locales: None,
            registration_metadata: None,
            claims: None,
        };

        let registration_id = manager.initiate_registration(request).unwrap();
        assert!(!registration_id.is_empty());

        let registration_data = manager.get_registration_data(&registration_id).unwrap();
        assert_eq!(
            registration_data.email,
            Some("user@example.com".to_string())
        );
        assert!(!registration_data.completed);
    }

    #[test]
    fn test_registration_data_validation() {
        let mut manager = RegistrationManager::new(RegistrationConfig {
            required_fields: vec!["email".to_string(), "given_name".to_string()],
            ..RegistrationConfig::default()
        });

        let registration_id = "test_reg_123";
        let registration_data = RegistrationData {
            registration_id: registration_id.to_string(),
            email: Some("user@example.com".to_string()),
            given_name: None, // Missing required field
            ..Default::default()
        };

        manager
            .registration_sessions
            .insert(registration_id.to_string(), registration_data);

        let missing_fields = manager.validate_registration_data(registration_id).unwrap();
        assert_eq!(missing_fields, vec!["given_name"]);
    }
}
