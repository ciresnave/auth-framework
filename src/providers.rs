//! OAuth provider configurations and implementations.
impl Default for UserProfile {
    fn default() -> Self {
        Self::new()
    }
}
use crate::errors::{AuthError, Result};
use crate::tokens::AuthToken;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use url::Url;

/// Supported OAuth providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuthProvider {
    /// GitHub OAuth provider
    GitHub,

    /// Google OAuth provider
    Google,

    /// Microsoft OAuth provider
    Microsoft,

    /// Discord OAuth provider
    Discord,

    /// Twitter OAuth provider
    Twitter,

    /// Facebook OAuth provider
    Facebook,

    /// LinkedIn OAuth provider
    LinkedIn,

    /// GitLab OAuth provider
    GitLab,

    /// Generic OAuth provider with custom configuration
    Custom {
        name: String,
        config: Box<OAuthProviderConfig>,
    },
}

/// OAuth provider configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    /// Authorization endpoint URL
    pub authorization_url: String,

    /// Token endpoint URL
    pub token_url: String,

    /// Device authorization endpoint URL (for device flow)
    pub device_authorization_url: Option<String>,

    /// User info endpoint URL
    pub userinfo_url: Option<String>,

    /// Revocation endpoint URL
    pub revocation_url: Option<String>,

    /// Default scopes to request
    pub default_scopes: Vec<String>,

    /// Whether this provider supports PKCE
    pub supports_pkce: bool,

    /// Whether this provider supports refresh tokens
    pub supports_refresh: bool,

    /// Whether this provider supports device flow
    pub supports_device_flow: bool,

    /// Custom parameters to include in authorization requests
    pub additional_params: HashMap<String, String>,
}

/// Device flow authorization response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// Device code
    pub device_code: String,

    /// User code that the user should enter
    pub user_code: String,

    /// URL where the user should verify the device
    pub verification_uri: String,

    /// Complete verification URL (optional)
    pub verification_uri_complete: Option<String>,

    /// Interval in seconds between polling requests
    pub interval: u64,

    /// Device code expires in seconds
    pub expires_in: u64,
}

/// Standardized user profile across all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// Unique identifier from the provider
    pub id: Option<String>,

    /// Provider that authenticated this user
    pub provider: Option<String>,

    /// Username or login name
    pub username: Option<String>,

    /// Display name
    pub name: Option<String>,

    /// Email address
    pub email: Option<String>,

    /// Whether email is verified
    pub email_verified: Option<bool>,

    /// Profile picture URL
    pub picture: Option<String>,

    /// Locale/language preference
    pub locale: Option<String>,

    /// Provider-specific additional data
    pub additional_data: HashMap<String, serde_json::Value>,
}

#[cfg(feature = "postgres-storage")]
use sqlx::{Decode, Postgres, Type, postgres::PgValueRef};

#[cfg(feature = "postgres-storage")]
impl<'r> Decode<'r, Postgres> for UserProfile {
    fn decode(value: PgValueRef<'r>) -> std::result::Result<Self, sqlx::error::BoxDynError> {
        let json: serde_json::Value = <serde_json::Value as Decode<Postgres>>::decode(value)?;
        serde_json::from_value(json).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

#[cfg(feature = "postgres-storage")]
impl Type<Postgres> for UserProfile {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <serde_json::Value as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <serde_json::Value as Type<Postgres>>::compatible(ty)
    }
}

impl UserProfile {
    /// Create a new empty user profile
    pub fn new() -> Self {
        Self {
            id: None,
            provider: None,
            username: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            locale: None,
            additional_data: HashMap::new(),
        }
    }

    /// Set user ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set provider
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set username
    pub fn with_username(mut self, username: Option<impl Into<String>>) -> Self {
        self.username = username.map(Into::into);
        self
    }

    /// Set display name
    pub fn with_name(mut self, name: Option<impl Into<String>>) -> Self {
        self.name = name.map(Into::into);
        self
    }

    /// Set email
    pub fn with_email(mut self, email: Option<impl Into<String>>) -> Self {
        self.email = email.map(Into::into);
        self
    }

    /// Set email verification status
    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    /// Set profile picture URL
    pub fn with_picture(mut self, picture: Option<impl Into<String>>) -> Self {
        self.picture = picture.map(Into::into);
        self
    }

    /// Set locale
    pub fn with_locale(mut self, locale: Option<impl Into<String>>) -> Self {
        self.locale = locale.map(Into::into);
        self
    }

    /// Add additional provider-specific data
    pub fn with_additional_data(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.additional_data.insert(key.into(), value);
        self
    }

    /// Create a new user profile from an OAuth token response
    pub fn from_token_response(
        token: &OAuthTokenResponse,
        provider: &OAuthProvider,
    ) -> Option<Self> {
        // Extract user info from ID token if present in additional fields
        if let Some(id_token_value) = token.additional_fields.get("id_token")
            && let Some(id_token) = id_token_value.as_str()
            && let Ok(profile) = Self::from_id_token(id_token)
        {
            return Some(profile.with_provider(provider.to_string()));
        }
        None
    }

    /// Extract a user profile from an ID token (JWT)
    pub fn from_id_token(id_token: &str) -> Result<Self> {
        // Basic JWT parsing
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::validation("Invalid JWT format"));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let padding_len = payload.len() % 4;
        let padded_payload = if padding_len > 0 {
            format!("{}{}", payload, "=".repeat(4 - padding_len))
        } else {
            payload.to_string()
        };

        // Decode base64
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&padded_payload)
            .map_err(|e| AuthError::validation(format!("Failed to decode JWT: {}", e)))?;

        // Parse JSON
        let json: Value = serde_json::from_slice(&decoded)
            .map_err(|e| AuthError::validation(format!("Failed to parse JWT payload: {}", e)))?;

        // Extract common claims
        let mut profile = Self::new();

        // Try common ID fields
        if let Some(sub) = json.get("sub").and_then(|v| v.as_str()) {
            profile = profile.with_id(sub);
        } else if let Some(id) = json.get("id").and_then(|v| v.as_str()) {
            profile = profile.with_id(id);
        } else {
            return Err(AuthError::validation("JWT missing subject claim"));
        }

        // Extract other common fields
        if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
            profile = profile.with_name(Some(name));
        }

        if let Some(email) = json.get("email").and_then(|v| v.as_str()) {
            profile = profile.with_email(Some(email));
        }

        if let Some(verified) = json.get("email_verified").and_then(|v| v.as_bool()) {
            profile = profile.with_email_verified(verified);
        }

        if let Some(preferred_username) = json.get("preferred_username").and_then(|v| v.as_str()) {
            profile = profile.with_username(Some(preferred_username));
        }

        if let Some(picture) = json.get("picture").and_then(|v| v.as_str()) {
            profile = profile.with_picture(Some(picture));
        }

        if let Some(locale) = json.get("locale").and_then(|v| v.as_str()) {
            profile = profile.with_locale(Some(locale));
        }

        // Store the entire claims as additional data
        profile = profile.with_additional_data("id_token_claims", json);

        Ok(profile)
    }

    /// Create an AuthToken with this profile's information
    pub fn to_auth_token(&self, access_token: String) -> AuthToken {
        let user_id = self.id.as_deref().unwrap_or("unknown").to_string();
        let auth_method = self.provider.as_deref().unwrap_or("oauth").to_string();
        let expires_in = std::time::Duration::from_secs(3600); // 1 hour default

        let mut token = AuthToken::new(user_id.clone(), access_token, expires_in, auth_method);
        token.subject = self.id.clone();
        token.issuer = self.provider.clone();
        token.user_profile = Some(self.clone());
        token
    }

    /// Check if this profile has an ID
    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    /// Get display name or fall back to username
    pub fn display_name(&self) -> Option<&str> {
        self.name.as_deref().or(self.username.as_deref())
    }
}

/// OAuth token response from the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// Access token
    pub access_token: String,

    /// Token type (usually "Bearer")
    pub token_type: String,

    /// Token expiration in seconds
    pub expires_in: Option<u64>,

    /// Refresh token (if available)
    pub refresh_token: Option<String>,

    /// Granted scopes
    pub scope: Option<String>,

    /// Additional provider-specific fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// User information from OAuth provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Unique user ID from the provider
    pub id: String,

    /// Username
    pub username: Option<String>,

    /// Display name
    pub name: Option<String>,

    /// Email address
    pub email: Option<String>,

    /// Whether email is verified
    pub email_verified: Option<bool>,

    /// Profile picture URL
    pub picture: Option<String>,

    /// Locale/language preference
    pub locale: Option<String>,

    /// Additional provider-specific fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

impl OAuthProvider {
    /// Get the configuration for this provider.
    pub fn config(&self) -> OAuthProviderConfig {
        match self {
            Self::GitHub => OAuthProviderConfig {
                authorization_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                device_authorization_url: Some("https://github.com/login/device/code".to_string()),
                userinfo_url: Some("https://api.github.com/user".to_string()),
                revocation_url: None,
                default_scopes: vec!["user:email".to_string()],
                supports_pkce: true,
                supports_refresh: false,
                supports_device_flow: true,
                additional_params: HashMap::new(),
            },

            Self::Google => OAuthProviderConfig {
                authorization_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_url: "https://oauth2.googleapis.com/token".to_string(),
                device_authorization_url: Some(
                    "https://oauth2.googleapis.com/device/code".to_string(),
                ),
                userinfo_url: Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string()),
                revocation_url: Some("https://oauth2.googleapis.com/revoke".to_string()),
                default_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                supports_pkce: true,
                supports_refresh: true,
                supports_device_flow: true,
                additional_params: HashMap::new(),
            },

            Self::Microsoft => OAuthProviderConfig {
                authorization_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                    .to_string(),
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                device_authorization_url: Some(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string(),
                ),
                userinfo_url: Some("https://graph.microsoft.com/v1.0/me".to_string()),
                revocation_url: None,
                default_scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                supports_pkce: true,
                supports_refresh: true,
                supports_device_flow: true,
                additional_params: HashMap::new(),
            },

            Self::Discord => OAuthProviderConfig {
                authorization_url: "https://discord.com/api/oauth2/authorize".to_string(),
                token_url: "https://discord.com/api/oauth2/token".to_string(),
                device_authorization_url: None,
                userinfo_url: Some("https://discord.com/api/users/@me".to_string()),
                revocation_url: Some("https://discord.com/api/oauth2/token/revoke".to_string()),
                default_scopes: vec!["identify".to_string(), "email".to_string()],
                supports_pkce: false,
                supports_refresh: true,
                supports_device_flow: false,
                additional_params: HashMap::new(),
            },

            Self::Twitter => OAuthProviderConfig {
                authorization_url: "https://twitter.com/i/oauth2/authorize".to_string(),
                token_url: "https://api.twitter.com/2/oauth2/token".to_string(),
                device_authorization_url: None,
                userinfo_url: Some("https://api.twitter.com/2/users/me".to_string()),
                revocation_url: Some("https://api.twitter.com/2/oauth2/revoke".to_string()),
                default_scopes: vec!["tweet.read".to_string(), "users.read".to_string()],
                supports_pkce: true,
                supports_refresh: true,
                supports_device_flow: false,
                additional_params: HashMap::new(),
            },

            Self::Facebook => OAuthProviderConfig {
                authorization_url: "https://www.facebook.com/v18.0/dialog/oauth".to_string(),
                token_url: "https://graph.facebook.com/v18.0/oauth/access_token".to_string(),
                device_authorization_url: None,
                userinfo_url: Some("https://graph.facebook.com/me".to_string()),
                revocation_url: None,
                default_scopes: vec!["email".to_string(), "public_profile".to_string()],
                supports_pkce: false,
                supports_refresh: false,
                supports_device_flow: false,
                additional_params: HashMap::new(),
            },

            Self::LinkedIn => OAuthProviderConfig {
                authorization_url: "https://www.linkedin.com/oauth/v2/authorization".to_string(),
                token_url: "https://www.linkedin.com/oauth/v2/accessToken".to_string(),
                device_authorization_url: None,
                userinfo_url: Some("https://api.linkedin.com/v2/me".to_string()),
                revocation_url: None,
                default_scopes: vec!["r_liteprofile".to_string(), "r_emailaddress".to_string()],
                supports_pkce: false,
                supports_refresh: true,
                supports_device_flow: false,
                additional_params: HashMap::new(),
            },

            Self::GitLab => OAuthProviderConfig {
                authorization_url: "https://gitlab.com/oauth/authorize".to_string(),
                token_url: "https://gitlab.com/oauth/token".to_string(),
                device_authorization_url: None,
                userinfo_url: Some("https://gitlab.com/api/v4/user".to_string()),
                revocation_url: Some("https://gitlab.com/oauth/revoke".to_string()),
                default_scopes: vec!["read_user".to_string()],
                supports_pkce: true,
                supports_refresh: true,
                supports_device_flow: false,
                additional_params: HashMap::new(),
            },

            Self::Custom { config, .. } => *config.clone(),
        }
    }

    /// Get the provider name.
    pub fn name(&self) -> &str {
        match self {
            Self::GitHub => "github",
            Self::Google => "google",
            Self::Microsoft => "microsoft",
            Self::Discord => "discord",
            Self::Twitter => "twitter",
            Self::Facebook => "facebook",
            Self::LinkedIn => "linkedin",
            Self::GitLab => "gitlab",
            Self::Custom { name, .. } => name,
        }
    }

    /// Create a custom OAuth provider.
    pub fn custom(name: impl Into<String>, config: OAuthProviderConfig) -> Self {
        Self::Custom {
            name: name.into(),
            config: Box::new(config),
        }
    }

    /// Build authorization URL.
    pub fn build_authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        scopes: Option<&[String]>,
        code_challenge: Option<&str>,
    ) -> Result<String> {
        let config = self.config();
        let mut url = Url::parse(&config.authorization_url)
            .map_err(|e| AuthError::config(format!("Invalid authorization URL: {e}")))?;

        let scopes = scopes.unwrap_or(&config.default_scopes);

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", client_id);
            query.append_pair("redirect_uri", redirect_uri);
            query.append_pair("response_type", "code");
            query.append_pair("state", state);

            if !scopes.is_empty() {
                query.append_pair("scope", &scopes.join(" "));
            }

            // Add PKCE challenge if supported and provided (Clippy-compliant)
            if config.supports_pkce
                && let Some(challenge) = code_challenge
            {
                query.append_pair("code_challenge", challenge);
                query.append_pair("code_challenge_method", "S256");
            }

            // Add any additional parameters
            for (key, value) in &config.additional_params {
                query.append_pair(key, value);
            }
        }

        Ok(url.to_string())
    }

    /// Exchange authorization code for tokens.
    pub async fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        authorization_code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuthTokenResponse> {
        let config = self.config();
        let client = reqwest::Client::new();

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", authorization_code),
            ("redirect_uri", redirect_uri),
        ];

        // Add PKCE verifier if provided
        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier));
        }

        let response = client.post(&config.token_url).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("Token exchange failed: {error_text}"),
            ));
        }

        let token_response: OAuthTokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Refresh an access token.
    pub async fn refresh_token(
        &self,
        client_id: &str,
        client_secret: &str,
        refresh_token: &str,
    ) -> Result<OAuthTokenResponse> {
        let config = self.config();

        if !config.supports_refresh {
            return Err(AuthError::auth_method(
                self.name(),
                "Provider does not support token refresh".to_string(),
            ));
        }

        let client = reqwest::Client::new();

        let params = vec![
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
        ];

        let response = client.post(&config.token_url).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("Token refresh failed: {error_text}"),
            ));
        }

        let token_response: OAuthTokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Get user information using an access token.
    pub async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let config = self.config();

        let userinfo_url = config.userinfo_url.ok_or_else(|| {
            AuthError::auth_method(
                self.name(),
                "Provider does not support user info endpoint".to_string(),
            )
        })?;

        let client = reqwest::Client::new();
        let response = client
            .get(&userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("User info request failed: {error_text}"),
            ));
        }

        let user_data: serde_json::Value = response.json().await?;

        // Convert provider-specific user data to our standard format
        let user_info = self.parse_user_info(user_data)?;
        Ok(user_info)
    }

    /// Parse provider-specific user info into our standard format.
    fn parse_user_info(&self, data: serde_json::Value) -> Result<OAuthUserInfo> {
        let mut additional_fields = HashMap::new();

        let user_info = match self {
            Self::GitHub => {
                let id = data["id"]
                    .as_u64()
                    .ok_or_else(|| AuthError::auth_method(self.name(), "Missing user ID"))?
                    .to_string();

                OAuthUserInfo {
                    id,
                    username: data["login"].as_str().map(|s| s.to_string()),
                    email: data["email"].as_str().map(|s| s.to_string()),
                    name: data["name"].as_str().map(|s| s.to_string()),
                    picture: data["avatar_url"].as_str().map(|s| s.to_string()),
                    email_verified: None, // GitHub doesn't provide this directly
                    locale: None,
                    additional_fields,
                }
            }

            Self::Google => {
                let id = data["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::auth_method(self.name(), "Missing user ID"))?
                    .to_string();

                OAuthUserInfo {
                    id,
                    username: None, // Google doesn't provide username
                    email: data["email"].as_str().map(|s| s.to_string()),
                    name: data["name"].as_str().map(|s| s.to_string()),
                    picture: data["picture"].as_str().map(|s| s.to_string()),
                    email_verified: data["verified_email"].as_bool(),
                    locale: data["locale"].as_str().map(|s| s.to_string()),
                    additional_fields,
                }
            }

            // Add other provider-specific parsing...
            _ => {
                // Generic parsing for custom providers
                let id = data["id"]
                    .as_str()
                    .or_else(|| data["sub"].as_str())
                    .or_else(|| data["user_id"].as_str())
                    .ok_or_else(|| AuthError::auth_method(self.name(), "Missing user ID"))?
                    .to_string();

                // Copy all fields to additional_fields for custom providers
                if let serde_json::Value::Object(map) = data {
                    additional_fields = map.into_iter().collect();
                }

                OAuthUserInfo {
                    id,
                    username: additional_fields
                        .get("username")
                        .or_else(|| additional_fields.get("login"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    email: additional_fields
                        .get("email")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    name: additional_fields
                        .get("name")
                        .or_else(|| additional_fields.get("display_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    picture: additional_fields
                        .get("avatar_url")
                        .or_else(|| additional_fields.get("picture"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    email_verified: additional_fields
                        .get("email_verified")
                        .and_then(|v| v.as_bool()),
                    locale: additional_fields
                        .get("locale")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    additional_fields,
                }
            }
        };

        Ok(user_info)
    }

    /// Revoke a token if the provider supports it.
    pub async fn revoke_token(&self, access_token: &str) -> Result<()> {
        let config = self.config();

        let revocation_url = config.revocation_url.ok_or_else(|| {
            AuthError::auth_method(
                self.name(),
                "Provider does not support token revocation".to_string(),
            )
        })?;

        let client = reqwest::Client::new();
        let response = client
            .post(&revocation_url)
            .form(&[("token", access_token)])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("Token revocation failed: {error_text}"),
            ));
        }

        Ok(())
    }

    /// Perform device authorization flow.
    pub async fn device_authorization(
        &self,
        client_id: &str,
        scope: Option<&[String]>,
    ) -> Result<DeviceAuthorizationResponse> {
        let config = self.config();

        if !config.supports_device_flow {
            return Err(AuthError::auth_method(
                self.name(),
                "Provider does not support device authorization flow".to_string(),
            ));
        }

        let client = reqwest::Client::new();

        let scope_string = scope.unwrap_or(&config.default_scopes).join(" ");
        let params = vec![("client_id", client_id), ("scope", scope_string.as_str())];

        let response = client
            .post(config.device_authorization_url.as_deref().unwrap())
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("Device authorization request failed: {error_text}"),
            ));
        }

        let device_response: DeviceAuthorizationResponse = response.json().await?;
        Ok(device_response)
    }

    /// Poll for access token using device code.
    pub async fn poll_device_code(
        &self,
        client_id: &str,
        device_code: &str,
        _interval: Option<u64>,
    ) -> Result<OAuthTokenResponse> {
        let config = self.config();

        if !config.supports_device_flow {
            return Err(AuthError::auth_method(
                self.name(),
                "Provider does not support device authorization flow".to_string(),
            ));
        }

        let client = reqwest::Client::new();

        let params = vec![
            ("client_id", client_id),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ];

        let response = client.post(&config.token_url).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::auth_method(
                self.name(),
                format!("Token request failed: {error_text}"),
            ));
        }

        let token_response: OAuthTokenResponse = response.json().await?;
        Ok(token_response)
    }
}

/// Generate a random state parameter for OAuth flows.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate PKCE code verifier and challenge.
pub fn generate_pkce() -> (String, String) {
    use rand::RngCore;
    use ring::digest;

    // Generate code verifier (43-128 characters)
    let mut rng = rand::rng();
    let mut bytes = [0u8; 96]; // 96 bytes = 128 base64 characters
    rng.fill_bytes(&mut bytes);
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    // Generate code challenge (SHA256 hash of verifier, base64url encoded)
    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

    (code_verifier, code_challenge)
}

/// Automated token-to-profile conversion utilities
pub struct ProfileExtractor {
    client: Client,
}

impl ProfileExtractor {
    /// Create a new profile extractor
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Extract user profile from token automatically based on provider
    pub async fn extract_profile(
        &self,
        token: &AuthToken,
        provider: &OAuthProvider,
    ) -> Result<UserProfile> {
        match provider {
            OAuthProvider::GitHub => self.extract_github_profile(token).await,
            OAuthProvider::Google => self.extract_google_profile(token).await,
            OAuthProvider::Microsoft => self.extract_microsoft_profile(token).await,
            OAuthProvider::Discord => self.extract_discord_profile(token).await,
            OAuthProvider::GitLab => self.extract_gitlab_profile(token).await,
            OAuthProvider::Custom { name, config } => {
                self.extract_custom_profile(token, name, config).await
            }
            _ => Err(AuthError::UnsupportedProvider(format!(
                "Profile extraction not supported for {:?}",
                provider
            ))),
        }
    }

    /// Extract GitHub user profile
    async fn extract_github_profile(&self, token: &AuthToken) -> Result<UserProfile> {
        let response = self
            .client
            .get("https://api.github.com/user")
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;

        let mut profile = UserProfile::new();
        profile = profile.with_id(json["id"].as_u64().unwrap_or(0).to_string());
        profile = profile.with_provider("github".to_string());

        if let Some(login) = json["login"].as_str() {
            profile.username = Some(login.to_string());
        }

        if let Some(name) = json["name"].as_str() {
            profile.name = Some(name.to_string());
        }

        if let Some(email) = json["email"].as_str() {
            profile.email = Some(email.to_string());
        }

        if let Some(avatar_url) = json["avatar_url"].as_str() {
            profile.picture = Some(avatar_url.to_string());
        }

        // Store additional GitHub-specific data
        if let Some(company) = json["company"].as_str() {
            profile
                .additional_data
                .insert("company".to_string(), Value::String(company.to_string()));
        }

        if let Some(blog) = json["blog"].as_str() {
            profile
                .additional_data
                .insert("blog".to_string(), Value::String(blog.to_string()));
        }

        if let Some(bio) = json["bio"].as_str() {
            profile
                .additional_data
                .insert("bio".to_string(), Value::String(bio.to_string()));
        }

        Ok(profile)
    }

    /// Extract Google user profile
    async fn extract_google_profile(&self, token: &AuthToken) -> Result<UserProfile> {
        let response = self
            .client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;

        let mut profile = UserProfile::new();
        profile = profile.with_id(json["id"].as_str().unwrap_or("").to_string());
        profile = profile.with_provider("google".to_string());

        if let Some(name) = json["name"].as_str() {
            profile.name = Some(name.to_string());
        }

        if let Some(email) = json["email"].as_str() {
            profile.email = Some(email.to_string());
        }

        if let Some(verified) = json["verified_email"].as_bool() {
            profile.email_verified = Some(verified);
        }

        if let Some(picture) = json["picture"].as_str() {
            profile.picture = Some(picture.to_string());
        }

        if let Some(locale) = json["locale"].as_str() {
            profile.locale = Some(locale.to_string());
        }

        Ok(profile)
    }

    /// Extract Microsoft user profile
    async fn extract_microsoft_profile(&self, token: &AuthToken) -> Result<UserProfile> {
        let response = self
            .client
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;

        let mut profile = UserProfile::new();
        profile = profile.with_id(json["id"].as_str().unwrap_or("").to_string());
        profile = profile.with_provider("microsoft".to_string());

        if let Some(display_name) = json["displayName"].as_str() {
            profile.name = Some(display_name.to_string());
        }

        if let Some(user_principal_name) = json["userPrincipalName"].as_str() {
            profile.username = Some(user_principal_name.to_string());
        }

        if let Some(mail) = json["mail"].as_str() {
            profile.email = Some(mail.to_string());
        }

        if let Some(preferred_language) = json["preferredLanguage"].as_str() {
            profile.locale = Some(preferred_language.to_string());
        }

        // Store additional Microsoft-specific data
        if let Some(job_title) = json["jobTitle"].as_str() {
            profile
                .additional_data
                .insert("jobTitle".to_string(), Value::String(job_title.to_string()));
        }

        if let Some(office_location) = json["officeLocation"].as_str() {
            profile.additional_data.insert(
                "officeLocation".to_string(),
                Value::String(office_location.to_string()),
            );
        }

        Ok(profile)
    }

    /// Extract Discord user profile
    async fn extract_discord_profile(&self, token: &AuthToken) -> Result<UserProfile> {
        let response = self
            .client
            .get("https://discord.com/api/users/@me")
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;

        let mut profile = UserProfile::new();
        profile = profile.with_id(json["id"].as_str().unwrap_or("").to_string());
        profile = profile.with_provider("discord".to_string());

        if let Some(username) = json["username"].as_str() {
            profile.username = Some(username.to_string());
        }

        if let Some(discriminator) = json["discriminator"].as_str() {
            profile.name = Some(format!(
                "{}#{}",
                json["username"].as_str().unwrap_or(""),
                discriminator
            ));
        }

        if let Some(email) = json["email"].as_str() {
            profile.email = Some(email.to_string());
        }

        if let Some(verified) = json["verified"].as_bool() {
            profile.email_verified = Some(verified);
        }

        if let Some(avatar) = json["avatar"].as_str() {
            let user_id = json["id"].as_str().unwrap_or("");
            profile.picture = Some(format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                user_id, avatar
            ));
        }

        if let Some(locale) = json["locale"].as_str() {
            profile.locale = Some(locale.to_string());
        }

        Ok(profile)
    }

    /// Extract GitLab user profile
    async fn extract_gitlab_profile(&self, token: &AuthToken) -> Result<UserProfile> {
        let response = self
            .client
            .get("https://gitlab.com/api/v4/user")
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::NetworkError(e.to_string()))?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| AuthError::ParseError(e.to_string()))?;

        let mut profile = UserProfile::new();
        profile = profile.with_id(json["id"].as_u64().unwrap_or(0).to_string());
        profile = profile.with_provider("gitlab".to_string());

        if let Some(username) = json["username"].as_str() {
            profile.username = Some(username.to_string());
        }

        if let Some(name) = json["name"].as_str() {
            profile.name = Some(name.to_string());
        }

        if let Some(email) = json["email"].as_str() {
            profile.email = Some(email.to_string());
        }

        if let Some(avatar_url) = json["avatar_url"].as_str() {
            profile.picture = Some(avatar_url.to_string());
        }

        // Store additional GitLab-specific data
        if let Some(web_url) = json["web_url"].as_str() {
            profile
                .additional_data
                .insert("web_url".to_string(), Value::String(web_url.to_string()));
        }

        if let Some(bio) = json["bio"].as_str() {
            profile
                .additional_data
                .insert("bio".to_string(), Value::String(bio.to_string()));
        }

        Ok(profile)
    }

    /// Extract custom provider profile
    async fn extract_custom_profile(
        &self,
        token: &AuthToken,
        provider_name: &str,
        config: &OAuthProviderConfig,
    ) -> Result<UserProfile> {
        if let Some(user_info_url) = &config.userinfo_url {
            let response = self
                .client
                .get(user_info_url)
                .bearer_auth(&token.access_token)
                .send()
                .await
                .map_err(|e| AuthError::NetworkError(e.to_string()))?;

            let json: Value = response
                .json()
                .await
                .map_err(|e| AuthError::ParseError(e.to_string()))?;

            let mut profile = UserProfile::new();
            profile = profile.with_id(
                json["id"]
                    .as_str()
                    .or_else(|| json["sub"].as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            profile = profile.with_provider(provider_name.to_string());

            // Try common field names
            if let Some(username) = json["username"].as_str().or_else(|| json["login"].as_str()) {
                profile.username = Some(username.to_string());
            }

            if let Some(name) = json["name"]
                .as_str()
                .or_else(|| json["display_name"].as_str())
            {
                profile.name = Some(name.to_string());
            }

            if let Some(email) = json["email"].as_str() {
                profile.email = Some(email.to_string());
            }

            if let Some(verified) = json["email_verified"]
                .as_bool()
                .or_else(|| json["verified"].as_bool())
            {
                profile.email_verified = Some(verified);
            }

            if let Some(picture) = json["picture"]
                .as_str()
                .or_else(|| json["avatar_url"].as_str())
            {
                profile.picture = Some(picture.to_string());
            }

            if let Some(locale) = json["locale"].as_str().or_else(|| json["lang"].as_str()) {
                profile.locale = Some(locale.to_string());
            }

            // Store all additional data
            for (key, value) in json.as_object().unwrap_or(&serde_json::Map::new()) {
                if ![
                    "id",
                    "sub",
                    "username",
                    "login",
                    "name",
                    "display_name",
                    "email",
                    "email_verified",
                    "verified",
                    "picture",
                    "avatar_url",
                    "locale",
                    "lang",
                ]
                .contains(&key.as_str())
                {
                    profile.additional_data.insert(key.clone(), value.clone());
                }
            }

            Ok(profile)
        } else {
            Err(AuthError::ConfigurationError(
                "Custom provider requires user_info_url".to_string(),
            ))
        }
    }
}

impl Default for ProfileExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OAuthProvider::GitHub => write!(f, "github"),
            OAuthProvider::Google => write!(f, "google"),
            OAuthProvider::Microsoft => write!(f, "microsoft"),
            OAuthProvider::Discord => write!(f, "discord"),
            OAuthProvider::Twitter => write!(f, "twitter"),
            OAuthProvider::Facebook => write!(f, "facebook"),
            OAuthProvider::LinkedIn => write!(f, "linkedin"),
            OAuthProvider::GitLab => write!(f, "gitlab"),
            OAuthProvider::Custom { name, .. } => write!(f, "{}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config() {
        let github = OAuthProvider::GitHub;
        let config = github.config();

        assert_eq!(
            config.authorization_url,
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(
            config.token_url,
            "https://github.com/login/oauth/access_token"
        );
        assert!(config.supports_pkce);
    }

    #[test]
    fn test_authorization_url() {
        let github = OAuthProvider::GitHub;
        let url = github
            .build_authorization_url(
                "client123",
                "https://example.com/callback",
                "state123",
                None,
                Some("challenge123"),
            )
            .unwrap();

        assert!(url.contains("client_id=client123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("code_challenge=challenge123"));
    }

    #[test]
    fn test_generate_state() {
        let state1 = generate_state();
        let state2 = generate_state();

        assert_eq!(state1.len(), 43);
        assert_eq!(state2.len(), 43);
        assert_ne!(state1, state2);
    }

    #[test]
    fn test_generate_pkce() {
        let (verifier1, challenge1) = generate_pkce();
        let (verifier2, challenge2) = generate_pkce();

        assert_eq!(verifier1.len(), 128);
        assert_eq!(verifier2.len(), 128);
        assert_ne!(verifier1, verifier2);
        assert_ne!(challenge1, challenge2);
    }
}
