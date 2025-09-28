//! Credential types for various authentication methods.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents different types of credentials that can be used for authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Credential {
    /// Username and password credentials
    Password { username: String, password: String },

    /// OAuth authorization code flow
    OAuth {
        authorization_code: String,
        redirect_uri: Option<String>,
        code_verifier: Option<String>, // For PKCE
        state: Option<String>,
    },

    /// OAuth refresh token
    OAuthRefresh { refresh_token: String },

    /// API key authentication
    ApiKey { key: String },

    /// JSON Web Token
    Jwt { token: String },

    /// Bearer token (generic)
    Bearer { token: String },

    /// Basic authentication (username:password base64 encoded)
    Basic { credentials: String },

    /// Custom authentication with flexible key-value pairs
    Custom {
        method: String,
        data: HashMap<String, String>,
    },

    /// Multi-factor authentication token
    Mfa {
        primary_credential: Box<Credential>,
        mfa_code: String,
        challenge_id: String,
    },

    /// Certificate-based authentication
    Certificate {
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        passphrase: Option<String>,
    },

    /// SAML assertion with secure XML signature validation
    #[cfg(feature = "saml")]
    Saml { assertion: String },

    /// OpenID Connect ID token
    OpenIdConnect {
        id_token: String,
        access_token: Option<String>,
        refresh_token: Option<String>,
    },

    /// Device flow credentials (device code polling)
    DeviceCode {
        device_code: String,
        client_id: String,
        user_code: Option<String>,
        verification_uri: Option<String>,
        verification_uri_complete: Option<String>,
        expires_in: Option<u64>,
        interval: Option<u64>,
    },

    /// Enhanced device flow credentials with full OAuth device flow support
    EnhancedDeviceFlow {
        device_code: String,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: Option<String>,
        expires_in: u64,
        interval: u64,
        client_id: String,
        client_secret: Option<String>,
        scopes: Vec<String>,
    },

    /// WebAuthn/FIDO2 Passkey authentication using pure Rust implementation
    #[cfg(feature = "passkeys")]
    Passkey {
        credential_id: Vec<u8>,
        assertion_response: String, // JSON-serialized AuthenticatorAssertionResponse
    },
}

impl Credential {
    /// Create password credentials
    pub fn password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Password {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Create OAuth authorization code credentials
    pub fn oauth_code(authorization_code: impl Into<String>) -> Self {
        Self::OAuth {
            authorization_code: authorization_code.into(),
            redirect_uri: None,
            code_verifier: None,
            state: None,
        }
    }

    /// Create OAuth authorization code credentials with PKCE
    pub fn oauth_code_with_pkce(
        authorization_code: impl Into<String>,
        code_verifier: impl Into<String>,
    ) -> Self {
        Self::OAuth {
            authorization_code: authorization_code.into(),
            redirect_uri: None,
            code_verifier: Some(code_verifier.into()),
            state: None,
        }
    }

    /// Create OAuth refresh token credentials
    pub fn oauth_refresh(refresh_token: impl Into<String>) -> Self {
        Self::OAuthRefresh {
            refresh_token: refresh_token.into(),
        }
    }

    /// Create device code credentials for device flow
    pub fn device_code(device_code: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self::DeviceCode {
            device_code: device_code.into(),
            client_id: client_id.into(),
            user_code: None,
            verification_uri: None,
            verification_uri_complete: None,
            expires_in: None,
            interval: None,
        }
    }

    /// Create API key credentials
    pub fn api_key(key: impl Into<String>) -> Self {
        Self::ApiKey { key: key.into() }
    }

    /// Create JWT credentials
    pub fn jwt(token: impl Into<String>) -> Self {
        Self::Jwt {
            token: token.into(),
        }
    }

    /// Create bearer token credentials
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: token.into(),
        }
    }

    /// Create basic authentication credentials
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        let credentials = format!("{}:{}", username.into(), password.into());
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

        Self::Basic {
            credentials: encoded,
        }
    }

    /// Create custom credentials
    pub fn custom(method: impl Into<String>, data: HashMap<String, String>) -> Self {
        Self::Custom {
            method: method.into(),
            data,
        }
    }

    /// Create MFA credentials
    pub fn mfa(
        primary_credential: Credential,
        mfa_code: impl Into<String>,
        challenge_id: impl Into<String>,
    ) -> Self {
        Self::Mfa {
            primary_credential: Box::new(primary_credential),
            mfa_code: mfa_code.into(),
            challenge_id: challenge_id.into(),
        }
    }

    /// Create certificate credentials
    pub fn certificate(
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        passphrase: Option<String>,
    ) -> Self {
        Self::Certificate {
            certificate,
            private_key,
            passphrase,
        }
    }

    /// Create SAML assertion credentials - REMOVED for security
    ///
    /// Create OpenID Connect credentials
    pub fn openid_connect(id_token: impl Into<String>) -> Self {
        Self::OpenIdConnect {
            id_token: id_token.into(),
            access_token: None,
            refresh_token: None,
        }
    }

    /// Create passkey credentials (WebAuthn/FIDO2)
    #[cfg(feature = "passkeys")]
    pub fn passkey(credential_id: Vec<u8>, assertion_response: impl Into<String>) -> Self {
        Self::Passkey {
            credential_id,
            assertion_response: assertion_response.into(),
        }
    }

    /// Get the credential type as a string
    pub fn credential_type(&self) -> &str {
        match self {
            Self::Password { .. } => "password",
            Self::OAuth { .. } => "oauth",
            Self::OAuthRefresh { .. } => "oauth_refresh",
            Self::ApiKey { .. } => "api_key",
            Self::Jwt { .. } => "jwt",
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
            Self::Custom { method, .. } => method.as_str(),
            Self::Mfa { .. } => "mfa",
            Self::Certificate { .. } => "certificate",
            #[cfg(feature = "saml")]
            Self::Saml { .. } => "saml",
            Self::OpenIdConnect { .. } => "openid_connect",
            Self::DeviceCode { .. } => "device_code",
            Self::EnhancedDeviceFlow { .. } => "enhanced_device_flow",
            #[cfg(feature = "passkeys")]
            Self::Passkey { .. } => "passkey",
        }
    }

    /// Check if this credential supports refresh
    pub fn supports_refresh(&self) -> bool {
        matches!(
            self,
            Self::OAuth { .. } | Self::OAuthRefresh { .. } | Self::OpenIdConnect { .. }
        )
    }

    /// Extract refresh token if available
    pub fn refresh_token(&self) -> Option<&str> {
        match self {
            Self::OAuthRefresh { refresh_token } => Some(refresh_token),
            Self::OpenIdConnect { refresh_token, .. } => refresh_token.as_deref(),
            _ => None,
        }
    }

    /// Check if this credential is sensitive and should be masked in logs
    pub fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::Password { .. }
                | Self::ApiKey { .. }
                | Self::Jwt { .. }
                | Self::Bearer { .. }
                | Self::Basic { .. }
                | Self::Certificate { .. }
                | Self::Mfa { .. }
        )
    }

    /// Get a safe representation for logging (masks sensitive data)
    pub fn safe_display(&self) -> String {
        match self {
            Self::Password { username, .. } => {
                format!("Password(username: {username})")
            }
            Self::OAuth { .. } => "OAuth(authorization_code)".to_string(),
            Self::OAuthRefresh { .. } => "OAuthRefresh(refresh_token)".to_string(),
            Self::ApiKey { .. } => "ApiKey(****)".to_string(),
            Self::Jwt { .. } => "Jwt(****)".to_string(),
            Self::Bearer { .. } => "Bearer(****)".to_string(),
            Self::Basic { .. } => "Basic(****)".to_string(),
            Self::Custom { method, .. } => format!("Custom(method: {method})"),
            Self::Mfa { challenge_id, .. } => {
                format!("Mfa(challenge_id: {challenge_id})")
            }
            Self::Certificate { .. } => "Certificate(****)".to_string(),
            #[cfg(feature = "saml")]
            Self::Saml { .. } => "Saml(****)".to_string(),
            Self::OpenIdConnect { .. } => "OpenIdConnect(id_token)".to_string(),
            Self::DeviceCode { .. } => "DeviceCode(****)".to_string(),
            Self::EnhancedDeviceFlow { .. } => "EnhancedDeviceFlow(****)".to_string(),
            #[cfg(feature = "passkeys")]
            Self::Passkey { .. } => "Passkey(****)".to_string(),
        }
    }
}

/// Additional credential metadata that can be attached to any credential type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMetadata {
    /// Client identifier (for OAuth flows)
    pub client_id: Option<String>,

    /// Requested scopes
    pub scopes: Vec<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// IP address of the client
    pub client_ip: Option<String>,

    /// Additional custom metadata
    pub custom: HashMap<String, String>,
}

impl CredentialMetadata {
    /// Create new credential metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the client ID
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Add a scope
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Set multiple scopes
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set the user agent
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Set the client IP
    pub fn client_ip(mut self, client_ip: impl Into<String>) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }

    /// Add custom metadata
    pub fn custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

/// A complete authentication request with credentials and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// The credentials to authenticate with
    pub credential: Credential,

    /// Additional metadata
    pub metadata: CredentialMetadata,

    /// Timestamp of the request
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl AuthRequest {
    /// Create a new authentication request
    pub fn new(credential: Credential) -> Self {
        Self {
            credential,
            metadata: CredentialMetadata::default(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a new authentication request with metadata
    pub fn with_metadata(credential: Credential, metadata: CredentialMetadata) -> Self {
        Self {
            credential,
            metadata,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get a safe representation for logging
    pub fn safe_display(&self) -> String {
        format!(
            "AuthRequest(credential: {}, client_id: {:?}, timestamp: {})",
            self.credential.safe_display(),
            self.metadata.client_id,
            self.timestamp
        )
    }
}
