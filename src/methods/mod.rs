//! Authentication method implementations.

use crate::{
    authentication::credentials::{Credential, CredentialMetadata},
    errors::{AuthError, Result},
    tokens::AuthToken,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Import the specific auth method modules
pub mod client_cert;
pub mod enhanced_device;
pub mod hardware_token;
#[cfg(feature = "ldap-auth")]
pub mod ldap;
pub mod passkey;
#[cfg(feature = "saml")]
pub mod saml;

// Re-export types from submodules
pub use client_cert::ClientCertAuthMethod;
#[cfg(feature = "enhanced-device-flow")]
pub use enhanced_device::EnhancedDeviceFlowMethod;
pub use hardware_token::HardwareOtpToken;
#[cfg(feature = "ldap-auth")]
pub use ldap::{LdapAuthMethod, LdapConfig};
#[cfg(feature = "passkeys")]
pub use passkey::PasskeyAuthMethod;
#[cfg(feature = "saml")]
pub use saml::SamlAuthMethod;

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub enum MethodResult {
    /// Authentication was successful
    Success(Box<AuthToken>),

    /// Multi-factor authentication is required
    MfaRequired(Box<MfaChallenge>),

    /// Authentication failed
    Failure { reason: String },
}

/// Multi-factor authentication challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Unique challenge ID
    pub id: String,

    /// Type of MFA required
    pub mfa_type: MfaType,

    /// User ID this challenge is for
    pub user_id: String,

    /// When the challenge was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the challenge expires
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Number of verification attempts made
    pub attempts: u32,

    /// Maximum allowed attempts before the challenge is invalidated
    pub max_attempts: u32,

    /// Hash of the expected OTP code (for Sms/Email/Totp methods).
    /// `None` for methods that verify externally (Push, SecurityKey).
    pub code_hash: Option<String>,

    /// Optional message or instructions to show the user
    pub message: Option<String>,

    /// Additional challenge data (e.g. masked phone, masked email, session token)
    pub data: HashMap<String, serde_json::Value>,
}

/// Types of multi-factor authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaType {
    /// Time-based one-time password (TOTP)
    Totp,

    /// SMS verification code
    Sms { phone_number: String },

    /// Email verification code
    Email { email_address: String },

    /// Push notification
    Push { device_id: String },

    /// Hardware security key
    SecurityKey,

    /// Backup codes
    BackupCode,

    /// Cross-method challenge that requires satisfying multiple MFA methods simultaneously
    MultiMethod,
}

/// Trait for authentication methods.
pub trait AuthMethod: Send + Sync {
    type MethodResult: Send + Sync + 'static;
    type AuthToken: Send + Sync + 'static;

    /// Get the name of this authentication method.
    fn name(&self) -> &str;

    /// Authenticate using the provided credentials.
    fn authenticate(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> impl std::future::Future<Output = Result<Self::MethodResult>> + Send;

    /// Validate configuration for this method.
    fn validate_config(&self) -> Result<()>;

    /// Check if this method supports refresh tokens.
    fn supports_refresh(&self) -> bool {
        false
    }

    /// Refresh a token if supported.
    fn refresh_token(
        &self,
        _refresh_token: String,
    ) -> impl std::future::Future<Output = Result<AuthToken, AuthError>> + Send {
        async {
            Err(AuthError::auth_method(
                self.name(),
                "Token refresh not supported by this method".to_string(),
            ))
        }
    }
}

/// Basic user information. Alias for the canonical [`crate::auth::UserInfo`].
pub type UserInfo = crate::auth::UserInfo;

/// Enum wrapper for all supported authentication methods (for registry)
#[allow(clippy::large_enum_variant)]
pub enum AuthMethodEnum {
    Password(PasswordMethod),
    Jwt(JwtMethod),
    ApiKey(ApiKeyMethod),
    OAuth2(OAuth2Method),
    #[cfg(feature = "saml")]
    Saml(Box<SamlAuthMethod>),
    #[cfg(feature = "ldap-auth")]
    Ldap(LdapAuthMethod),
    HardwareOtpToken(HardwareOtpToken),
    ClientCert(ClientCertAuthMethod),
    OpenIdConnect(OpenIdConnectAuthMethod),
    AdvancedMfa(AdvancedMfaAuthMethod),
    #[cfg(feature = "enhanced-device-flow")]
    EnhancedDeviceFlow(Box<enhanced_device::EnhancedDeviceFlowMethod>),
    #[cfg(feature = "passkeys")]
    Passkey(PasskeyAuthMethod),
}

/// Simplified implementations - these would contain the full implementations
#[derive(Debug)]
pub struct PasswordMethod;

#[derive(Debug)]
pub struct JwtMethod;

#[derive(Debug)]
pub struct ApiKeyMethod;

#[derive(Debug)]
pub struct OAuth2Method;

#[derive(Debug)]
pub struct OpenIdConnectAuthMethod;

#[derive(Debug)]
pub struct AdvancedMfaAuthMethod;

// Add basic constructors for test compatibility
impl Default for PasswordMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordMethod {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JwtMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtMethod {
    pub fn new() -> Self {
        Self
    }

    pub fn secret_key(self, _secret: &str) -> Self {
        self
    }

    pub fn issuer(self, _issuer: &str) -> Self {
        self
    }

    pub fn audience(self, _audience: &str) -> Self {
        self
    }
}

impl Default for ApiKeyMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyMethod {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OAuth2Method {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuth2Method {
    pub fn new() -> Self {
        Self
    }
}

impl AuthMethod for AuthMethodEnum {
    type MethodResult = MethodResult;
    type AuthToken = AuthToken;

    fn name(&self) -> &str {
        match self {
            AuthMethodEnum::Password(_) => "password",
            AuthMethodEnum::Jwt(_) => "jwt",
            AuthMethodEnum::ApiKey(_) => "api_key",
            AuthMethodEnum::OAuth2(_) => "oauth2",
            #[cfg(feature = "saml")]
            AuthMethodEnum::Saml(_) => "saml",
            #[cfg(feature = "ldap-auth")]
            AuthMethodEnum::Ldap(_) => "ldap",
            AuthMethodEnum::HardwareOtpToken(_) => "hardware_token",
            AuthMethodEnum::ClientCert(_) => "client_cert",
            AuthMethodEnum::OpenIdConnect(_) => "openid_connect",
            AuthMethodEnum::AdvancedMfa(_) => "advanced_mfa",
            #[cfg(feature = "enhanced-device-flow")]
            AuthMethodEnum::EnhancedDeviceFlow(_) => "enhanced_device_flow",
            #[cfg(feature = "passkeys")]
            AuthMethodEnum::Passkey(_) => "passkey",
        }
    }

    async fn authenticate(
        &self,
        credential: Credential,
        metadata: CredentialMetadata,
    ) -> Result<Self::MethodResult> {
        let _ = &metadata;
        match self {
            #[cfg(feature = "saml")]
            AuthMethodEnum::Saml(m) => return m.authenticate(credential, metadata).await,
            #[cfg(feature = "passkeys")]
            AuthMethodEnum::Passkey(m) => return m.authenticate(credential, metadata).await,
            #[cfg(feature = "enhanced-device-flow")]
            AuthMethodEnum::EnhancedDeviceFlow(m) => {
                return m.authenticate(credential, metadata).await;
            }
            AuthMethodEnum::Password(_) => match credential {
                Credential::Password { username, password } => {
                    if username.is_empty() || password.is_empty() {
                        return Self::failure("Username or password cannot be empty");
                    }
                    Self::failure(
                        "Password authentication is handled by AuthFramework's built-in storage-backed password flow",
                    )
                }
                _ => Self::failure("Password authentication expects Credential::password"),
            },
            AuthMethodEnum::Jwt(_) => match credential {
                Credential::Jwt { token } | Credential::Bearer { token } => {
                    if token.is_empty() {
                        return Self::failure("JWT token cannot be empty");
                    }
                    Self::failure(
                        "JWT authentication must be performed through AuthFramework so the active TokenManager can validate the token signature",
                    )
                }
                _ => Self::failure(
                    "JWT authentication expects Credential::jwt or Credential::bearer",
                ),
            },
            AuthMethodEnum::ApiKey(_) => match credential {
                Credential::ApiKey { key } => {
                    if key.is_empty() {
                        return Self::failure("API key cannot be empty");
                    }
                    Self::failure(
                        "API key authentication must be performed through AuthFramework so the stored key can be resolved to a user and session token",
                    )
                }
                _ => Self::failure("API key authentication expects Credential::api_key"),
            },
            AuthMethodEnum::OAuth2(_) => match credential {
                Credential::OAuth {
                    authorization_code, ..
                } => {
                    if authorization_code.is_empty() {
                        return Self::failure("OAuth authorization code cannot be empty");
                    }
                    Self::failure(
                        "OAuth 2.0 authorization codes must be exchanged through an OAuth provider or server endpoint before authentication completes",
                    )
                }
                Credential::OAuthRefresh { refresh_token } => {
                    if refresh_token.is_empty() {
                        return Self::failure("OAuth refresh token cannot be empty");
                    }
                    Self::failure(
                        "OAuth 2.0 refresh tokens must be exchanged through an OAuth provider or server endpoint before authentication completes",
                    )
                }
                Credential::Jwt { token }
                | Credential::Bearer { token }
                | Credential::OpenIdConnect {
                    id_token: token, ..
                } => {
                    if token.is_empty() {
                        return Self::failure("OAuth token cannot be empty");
                    }
                    Self::failure(
                        "OAuth 2.0 token authentication must be performed through AuthFramework so token validation and auditing use the active framework state",
                    )
                }
                _ => Self::failure(
                    "OAuth2 authentication expects Credential::oauth_code, Credential::oauth_refresh, Credential::jwt, Credential::bearer, or Credential::openid_connect",
                ),
            },
            #[cfg(feature = "ldap-auth")]
            AuthMethodEnum::Ldap(_) => {
                return Self::failure(
                    "LDAP authentication requires a concrete LDAP integration and cannot use the generic AuthMethodEnum fallback",
                );
            }
            AuthMethodEnum::HardwareOtpToken(_) => Self::failure(
                "Hardware token authentication requires the concrete hardware token flow rather than the generic AuthMethodEnum fallback",
            ),
            AuthMethodEnum::ClientCert(_) => Self::failure(
                "Client certificate authentication requires the concrete client certificate flow rather than the generic AuthMethodEnum fallback",
            ),
            AuthMethodEnum::OpenIdConnect(_) => Self::failure(
                "OpenID Connect authentication should be performed through the OIDC provider or AuthFramework integrations",
            ),
            AuthMethodEnum::AdvancedMfa(_) => Self::failure(
                "Advanced MFA authentication requires the concrete MFA flow rather than the generic AuthMethodEnum fallback",
            ),
        }
    }

    fn validate_config(&self) -> Result<()> {
        match self {
            AuthMethodEnum::Password(_) => Ok(()),
            AuthMethodEnum::Jwt(_) => Ok(()),
            AuthMethodEnum::ApiKey(_) => Ok(()),
            AuthMethodEnum::OAuth2(_) => Ok(()),
            #[cfg(feature = "saml")]
            AuthMethodEnum::Saml(method) => method.validate_config(),
            #[cfg(feature = "ldap-auth")]
            AuthMethodEnum::Ldap(_) => Ok(()),
            AuthMethodEnum::HardwareOtpToken(method) => {
                if method.device_id.trim().is_empty() {
                    return Err(AuthError::config(
                        "Hardware token device_id cannot be empty",
                    ));
                }
                if method.token_type.trim().is_empty() {
                    return Err(AuthError::config(
                        "Hardware token token_type cannot be empty",
                    ));
                }
                Ok(())
            }
            AuthMethodEnum::ClientCert(_) => Ok(()),
            AuthMethodEnum::OpenIdConnect(_) => Ok(()),
            AuthMethodEnum::AdvancedMfa(_) => Ok(()),
            #[cfg(feature = "enhanced-device-flow")]
            AuthMethodEnum::EnhancedDeviceFlow(method) => method.validate_config(),
            #[cfg(feature = "passkeys")]
            AuthMethodEnum::Passkey(method) => method.validate_config(),
        }
    }

    fn supports_refresh(&self) -> bool {
        false
    }

    async fn refresh_token(&self, _refresh_token: String) -> Result<AuthToken, AuthError> {
        Err(AuthError::auth_method(
            self.name(),
            "Token refresh not supported by this method".to_string(),
        ))
    }
}

impl AuthMethodEnum {
    fn failure(reason: impl Into<String>) -> Result<MethodResult> {
        Ok(MethodResult::Failure {
            reason: reason.into(),
        })
    }
}

impl MfaChallenge {
    /// Create a new MFA challenge.
    pub fn new(
        mfa_type: MfaType,
        user_id: impl Into<String>,
        expires_in: std::time::Duration,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            mfa_type,
            user_id: user_id.into(),
            expires_at: chrono::Utc::now()
                + chrono::Duration::from_std(expires_in).unwrap_or(chrono::Duration::hours(1)),
            created_at: chrono::Utc::now(),
            attempts: 0,
            max_attempts: 3,
            code_hash: None,
            message: None,
            data: HashMap::new(),
        }
    }

    /// Get the challenge ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Check if the challenge has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}
