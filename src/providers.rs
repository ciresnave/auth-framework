//! OAuth provider configurations and implementations.

use base64::Engine;
use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    pub id: String,
    
    /// Provider that authenticated this user
    pub provider: String,
    
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

impl UserProfile {
    /// Create a new user profile
    pub fn new(id: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            provider: provider.into(),
            username: None,
            name: None,
            email: None,
            email_verified: None,
            picture: None,
            locale: None,
            additional_data: HashMap::new(),
        }
    }
    
    /// Set username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
    
    /// Set display name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    /// Set email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
    
    /// Set email verification status
    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }
    
    /// Set profile picture URL
    pub fn with_picture(mut self, picture: impl Into<String>) -> Self {
        self.picture = Some(picture.into());
        self
    }
    
    /// Set locale
    pub fn with_locale(mut self, locale: impl Into<String>) -> Self {
        self.locale = Some(locale.into());
        self
    }
    
    /// Add additional provider-specific data
    pub fn with_additional_data(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.additional_data.insert(key.into(), value);
        self
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
                device_authorization_url: Some("https://oauth2.googleapis.com/device/code".to_string()),
                userinfo_url: Some("https://www.googleapis.com/oauth2/v2/userinfo".to_string()),
                revocation_url: Some("https://oauth2.googleapis.com/revoke".to_string()),
                default_scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
                supports_pkce: true,
                supports_refresh: true,
                supports_device_flow: true,
                additional_params: HashMap::new(),
            },
            
            Self::Microsoft => OAuthProviderConfig {
                authorization_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
                token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                device_authorization_url: Some("https://login.microsoftonline.com/common/oauth2/v2.0/devicecode".to_string()),
                userinfo_url: Some("https://graph.microsoft.com/v1.0/me".to_string()),
                revocation_url: None,
                default_scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
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

            // Add PKCE challenge if supported and provided
            if config.supports_pkce {
                if let Some(challenge) = code_challenge {
                    query.append_pair("code_challenge", challenge);
                    query.append_pair("code_challenge_method", "S256");
                }
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

        let response = client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await?;

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

        let response = client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await?;

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
                let id = data["id"].as_u64()
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
                let id = data["id"].as_str()
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
                let id = data["id"].as_str()
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
                    username: additional_fields.get("username")
                        .or_else(|| additional_fields.get("login"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    email: additional_fields.get("email")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    name: additional_fields.get("name")
                        .or_else(|| additional_fields.get("display_name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    picture: additional_fields.get("avatar_url")
                        .or_else(|| additional_fields.get("picture"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    email_verified: additional_fields.get("email_verified")
                        .and_then(|v| v.as_bool()),
                    locale: additional_fields.get("locale")
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
        let params = vec![
            ("client_id", client_id),
            ("scope", scope_string.as_str()),
        ];

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

        let response = client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await?;

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
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}

/// Generate PKCE code verifier and challenge.
pub fn generate_pkce() -> (String, String) {
    use rand::Rng;
    use ring::digest;
    
    // Generate code verifier (43-128 characters)
    let mut rng = rand::thread_rng();
    let code_verifier: String = (0..128)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();

    // Generate code challenge (SHA256 hash of verifier, base64url encoded)
    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

    (code_verifier, code_challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config() {
        let github = OAuthProvider::GitHub;
        let config = github.config();
        
        assert_eq!(config.authorization_url, "https://github.com/login/oauth/authorize");
        assert_eq!(config.token_url, "https://github.com/login/oauth/access_token");
        assert!(config.supports_pkce);
    }

    #[test]
    fn test_authorization_url() {
        let github = OAuthProvider::GitHub;
        let url = github.build_authorization_url(
            "client123",
            "https://example.com/callback",
            "state123",
            None,
            Some("challenge123"),
        ).unwrap();

        assert!(url.contains("client_id=client123"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("code_challenge=challenge123"));
    }

    #[test]
    fn test_generate_state() {
        let state1 = generate_state();
        let state2 = generate_state();
        
        assert_eq!(state1.len(), 32);
        assert_eq!(state2.len(), 32);
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
