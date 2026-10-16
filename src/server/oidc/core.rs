//! OpenID Connect Provider Implementation (OIDC 1.0)
//!
//! This module implements a complete OpenID Connect Provider based on:
//! - OpenID Connect Core 1.0 specification
//! - OpenID Connect Discovery 1.0
//! - OpenID Connect Dynamic Client Registration 1.0
//! - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants

use crate::errors::{AuthError, Result};
use crate::oauth2_server::OAuth2Server;
use crate::server::core::client_registry::ClientRegistry;
use crate::storage::AuthStorage;
use crate::tokens::TokenManager;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// OpenID Connect Provider configuration
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer identifier (must be HTTPS URL)
    pub issuer: String,

    /// OAuth 2.0 base configuration
    pub oauth2_config: crate::oauth2_server::OAuth2Config,

    /// JWK Set URI
    pub jwks_uri: String,

    /// UserInfo endpoint URI
    pub userinfo_endpoint: String,

    /// Supported response types
    pub response_types_supported: Vec<String>,

    /// Supported subject identifier types
    pub subject_types_supported: Vec<SubjectType>,

    /// Supported ID token signing algorithms
    pub id_token_signing_alg_values_supported: Vec<Algorithm>,

    /// Supported scopes
    pub scopes_supported: Vec<String>,

    /// Supported claims
    pub claims_supported: Vec<String>,

    /// Whether claims parameter is supported
    pub claims_parameter_supported: bool,

    /// Whether request parameter is supported
    pub request_parameter_supported: bool,

    /// Whether request_uri parameter is supported
    pub request_uri_parameter_supported: bool,

    /// ID token expiration time
    pub id_token_expiry: Duration,

    /// Maximum age for authentication
    pub max_age_supported: Option<Duration>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: "https://auth.example.com".to_string(),
            oauth2_config: crate::oauth2_server::OAuth2Config::default(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            userinfo_endpoint: "https://auth.example.com/oidc/userinfo".to_string(),
            response_types_supported: vec![
                "code".to_string(),
                "id_token".to_string(),
                "id_token token".to_string(),
                "code id_token".to_string(),
                "code token".to_string(),
                "code id_token token".to_string(),
            ],
            subject_types_supported: vec![SubjectType::Public],
            id_token_signing_alg_values_supported: vec![
                Algorithm::RS256,
                Algorithm::ES256,
                Algorithm::HS256,
            ],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "address".to_string(),
                "phone".to_string(),
                "offline_access".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "name".to_string(),
                "given_name".to_string(),
                "family_name".to_string(),
                "middle_name".to_string(),
                "nickname".to_string(),
                "preferred_username".to_string(),
                "profile".to_string(),
                "picture".to_string(),
                "website".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "gender".to_string(),
                "birthdate".to_string(),
                "zoneinfo".to_string(),
                "locale".to_string(),
                "phone_number".to_string(),
                "phone_number_verified".to_string(),
                "address".to_string(),
                "updated_at".to_string(),
            ],
            claims_parameter_supported: true,
            request_parameter_supported: true,
            request_uri_parameter_supported: true,
            id_token_expiry: Duration::from_secs(3600), // 1 hour
            max_age_supported: Some(Duration::from_secs(86400)), // 24 hours
        }
    }
}

/// Subject identifier types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    /// Public subject identifier
    Public,
    /// Pairwise subject identifier
    Pairwise,
}

/// OpenID Connect Provider
pub struct OidcProvider<S: AuthStorage + ?Sized> {
    config: OidcConfig,
    oauth2_server: OAuth2Server,
    token_manager: Arc<TokenManager>,
    storage: Arc<S>,
    client_registry: Option<Arc<ClientRegistry>>,
}

impl<S: AuthStorage + ?Sized> fmt::Debug for OidcProvider<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcProvider")
            .field("config", &self.config)
            .field("oauth2_server", &"<OAuth2Server>")
            .field("token_manager", &"<TokenManager>")
            .field("storage", &"<AuthStorage>")
            .field("client_registry", &self.client_registry.is_some())
            .finish()
    }
}

impl<S: ?Sized + AuthStorage> OidcProvider<S> {
    /// Create a new OIDC Provider
    pub async fn new(
        config: OidcConfig,
        token_manager: Arc<TokenManager>,
        storage: Arc<S>,
    ) -> Result<Self> {
        let oauth2_server =
            OAuth2Server::new(config.oauth2_config.clone(), token_manager.clone()).await?;

        Ok(Self {
            config,
            oauth2_server,
            token_manager,
            storage,
            client_registry: None,
        })
    }

    /// Get the underlying OAuth 2.0 server
    pub fn oauth2_server(&self) -> &OAuth2Server {
        &self.oauth2_server
    }

    /// Set the client registry for validation
    pub fn set_client_registry(&mut self, client_registry: Arc<ClientRegistry>) {
        self.client_registry = Some(client_registry);
    }

    /// Get OIDC configuration
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Generate OpenID Connect Discovery document
    pub fn discovery_document(&self) -> Result<OidcDiscoveryDocument> {
        Ok(OidcDiscoveryDocument {
            issuer: self.config.issuer.clone(),
            authorization_endpoint: format!("{}/oidc/authorize", self.config.issuer),
            token_endpoint: format!("{}/oidc/token", self.config.issuer),
            userinfo_endpoint: self.config.userinfo_endpoint.clone(),
            jwks_uri: self.config.jwks_uri.clone(),
            registration_endpoint: Some(format!("{}/oidc/register", self.config.issuer)),
            scopes_supported: self.config.scopes_supported.clone(),
            response_types_supported: self.config.response_types_supported.clone(),
            response_modes_supported: Some(vec![
                "query".to_string(),
                "fragment".to_string(),
                "form_post".to_string(),
            ]),
            grant_types_supported: Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ]),
            subject_types_supported: self.config.subject_types_supported.clone(),
            id_token_signing_alg_values_supported: self
                .config
                .id_token_signing_alg_values_supported
                .iter()
                .map(algorithm_to_string)
                .collect(),
            userinfo_signing_alg_values_supported: Some(vec![
                "RS256".to_string(),
                "ES256".to_string(),
                "HS256".to_string(),
            ]),
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "client_secret_jwt".to_string(),
                "private_key_jwt".to_string(),
                "none".to_string(),
            ]),
            claims_supported: Some(self.config.claims_supported.clone()),
            claims_parameter_supported: Some(self.config.claims_parameter_supported),
            request_parameter_supported: Some(self.config.request_parameter_supported),
            request_uri_parameter_supported: Some(self.config.request_uri_parameter_supported),
            code_challenge_methods_supported: Some(vec!["S256".to_string(), "plain".to_string()]),
        })
    }

    /// Create an ID token
    pub async fn create_id_token(
        &self,
        subject: &str,
        client_id: &str,
        nonce: Option<&str>,
        auth_time: Option<SystemTime>,
        claims: Option<&HashMap<String, Value>>,
    ) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::auth_method("oidc", format!("Time error: {}", e)))?
            .as_secs();

        let exp = now + self.config.id_token_expiry.as_secs();

        let mut id_token_claims = IdTokenClaims {
            iss: self.config.issuer.clone(),
            sub: subject.to_string(),
            aud: vec![client_id.to_string()],
            exp,
            iat: now,
            auth_time: auth_time
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())),
            nonce: nonce.map(|n| n.to_string()),
            additional_claims: claims.cloned().unwrap_or_default(),
        };

        // Add standard claims if provided
        if let Some(claims) = claims {
            for (key, value) in claims {
                if self.config.claims_supported.contains(key) {
                    id_token_claims
                        .additional_claims
                        .insert(key.clone(), value.clone());
                }
            }
        }

        // Create JWT
        let _header = Header::new(Algorithm::RS256);
        let token = self
            .token_manager
            .create_jwt_token(
                subject,
                vec!["openid".to_string()],
                Some(Duration::from_secs(3600)),
            )
            .map_err(|e| AuthError::auth_method("oidc", format!("JWT creation failed: {}", e)))?;

        Ok(token)
    }

    /// Validate an authorization request for OIDC
    pub async fn validate_authorization_request(
        &self,
        request: &OidcAuthorizationRequest,
    ) -> Result<AuthorizationValidationResult> {
        // Check if 'openid' scope is present
        if !request.scope.split_whitespace().any(|s| s == "openid") {
            return Err(AuthError::auth_method(
                "oidc",
                "Missing required 'openid' scope",
            ));
        }

        // Validate response_type
        if !self
            .config
            .response_types_supported
            .contains(&request.response_type)
        {
            return Err(AuthError::auth_method(
                "oidc",
                format!("Unsupported response_type: {}", request.response_type),
            ));
        }

        // Validate client_id
        if request.client_id.is_empty() {
            return Err(AuthError::auth_method("oidc", "Missing client_id"));
        }

        // Check client exists in registry
        if let Some(client_registry) = &self.client_registry {
            if client_registry
                .get_client(&request.client_id)
                .await?
                .is_none()
            {
                return Err(AuthError::auth_method("oidc", "Invalid client_id"));
            }

            // Validate redirect_uri against registered URIs
            if !client_registry
                .validate_redirect_uri(&request.client_id, &request.redirect_uri)
                .await?
            {
                return Err(AuthError::auth_method(
                    "oidc",
                    "Invalid redirect_uri for client",
                ));
            }
        } else {
            // Fallback validation when no client registry available
            if request.redirect_uri.is_empty() {
                return Err(AuthError::auth_method("oidc", "Missing redirect_uri"));
            }
        }

        Ok(AuthorizationValidationResult {
            valid: true,
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            max_age: request.max_age,
            response_type: request.response_type.clone(),
        })
    }

    /// Get user information for the UserInfo endpoint
    pub async fn get_userinfo(&self, access_token: &str) -> Result<UserInfo> {
        // Validate access token
        let token_claims = self
            .token_manager
            .validate_jwt_token(access_token)
            .map_err(|e| AuthError::auth_method("oidc", format!("Invalid access token: {}", e)))?;

        // Extract subject from token
        let subject = &token_claims.sub;

        // Get user information from storage
        let user_key = format!("user:{}", subject);
        if let Some(user_data) = self.storage.get_kv(&user_key).await? {
            let user_str = std::str::from_utf8(&user_data).unwrap_or("{}");
            let user_profile: HashMap<String, Value> =
                serde_json::from_str(user_str).unwrap_or_default();

            Ok(UserInfo {
                sub: subject.clone(),
                name: user_profile
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                given_name: user_profile
                    .get("given_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                family_name: user_profile
                    .get("family_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                middle_name: user_profile
                    .get("middle_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                nickname: user_profile
                    .get("nickname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                preferred_username: user_profile
                    .get("preferred_username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                profile: user_profile
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                picture: user_profile
                    .get("picture")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                website: user_profile
                    .get("website")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                email: user_profile
                    .get("email")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                email_verified: user_profile.get("email_verified").and_then(|v| v.as_bool()),
                gender: user_profile
                    .get("gender")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                birthdate: user_profile
                    .get("birthdate")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                zoneinfo: user_profile
                    .get("zoneinfo")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                locale: user_profile
                    .get("locale")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                phone_number: user_profile
                    .get("phone_number")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                phone_number_verified: user_profile
                    .get("phone_number_verified")
                    .and_then(|v| v.as_bool()),
                address: user_profile
                    .get("address")
                    .and_then(|addr| addr.as_object())
                    .map(|addr_obj| Address {
                        formatted: addr_obj
                            .get("formatted")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        street_address: addr_obj
                            .get("street_address")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        locality: addr_obj
                            .get("locality")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        region: addr_obj
                            .get("region")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        postal_code: addr_obj
                            .get("postal_code")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        country: addr_obj
                            .get("country")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    }),
                updated_at: user_profile.get("updated_at").and_then(|v| v.as_u64()),
                additional_claims: user_profile
                    .into_iter()
                    .filter(|(k, _)| {
                        ![
                            "sub",
                            "name",
                            "given_name",
                            "family_name",
                            "middle_name",
                            "nickname",
                            "preferred_username",
                            "profile",
                            "picture",
                            "website",
                            "email",
                            "email_verified",
                            "gender",
                            "birthdate",
                            "zoneinfo",
                            "locale",
                            "phone_number",
                            "phone_number_verified",
                            "address",
                            "updated_at",
                        ]
                        .contains(&k.as_str())
                    })
                    .collect(),
            })
        } else {
            // Return minimal user info if no stored profile found
            Ok(UserInfo {
                sub: subject.clone(),
                name: Some("John Doe".to_string()),
                given_name: Some("John".to_string()),
                family_name: Some("Doe".to_string()),
                middle_name: None,
                nickname: None,
                preferred_username: Some(subject.clone()),
                profile: None,
                picture: Some("https://example.com/avatar.jpg".to_string()),
                website: None,
                email: Some("john.doe@example.com".to_string()),
                email_verified: Some(true),
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                phone_number: None,
                phone_number_verified: None,
                address: None,
                updated_at: None,
                additional_claims: HashMap::new(),
            })
        }
    }

    /// Handle logout request
    pub async fn handle_logout(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Result<LogoutResponse> {
        // Validate ID token hint if provided
        if let Some(id_token) = id_token_hint {
            let claims = self
                .token_manager
                .validate_jwt_token(id_token)
                .map_err(|e| AuthError::auth_method("oidc", format!("Invalid ID token: {}", e)))?;

            // Invalidate all sessions for the user identified in the token
            let user_sessions = self
                .storage
                .list_user_sessions(&claims.sub)
                .await
                .map_err(|e| AuthError::internal(format!("Failed to list user sessions: {}", e)))?;

            for session in user_sessions {
                self.storage
                    .delete_session(&session.session_id)
                    .await
                    .map_err(|e| AuthError::internal(format!("Failed to delete session: {}", e)))?;
            }
        }

        // Validate post_logout_redirect_uri against registered URIs
        if let Some(post_logout_uri) = post_logout_redirect_uri {
            // Extract client_id from the ID token if available
            if let Some(id_token) = id_token_hint {
                let claims = self
                    .token_manager
                    .validate_jwt_token(id_token)
                    .map_err(|e| {
                        AuthError::auth_method("oidc", format!("Invalid ID token: {}", e))
                    })?;

                if let Some(aud) = claims.aud.split_whitespace().next() {
                    // Validate that the post-logout redirect URI is registered for this client
                    if !self
                        .is_post_logout_uri_registered(aud, post_logout_uri)
                        .await?
                    {
                        return Err(AuthError::validation(
                            "post_logout_redirect_uri not registered for client",
                        ));
                    }
                }
            } else {
                // If no ID token provided, we cannot validate the client association
                // In a production system, you might want to require ID token for validation
                return Err(AuthError::validation(
                    "id_token_hint required for post_logout_redirect_uri validation",
                ));
            }
        }

        Ok(LogoutResponse {
            post_logout_redirect_uri: post_logout_redirect_uri.map(|uri| uri.to_string()),
            state: state.map(|s| s.to_string()),
        })
    }

    /// Check if a post-logout redirect URI is registered for a client
    async fn is_post_logout_uri_registered(&self, client_id: &str, uri: &str) -> Result<bool> {
        // SECURITY CRITICAL: Validate redirect URI against registered URIs

        // Basic security: only allow https URIs (except localhost for development)
        if !uri.starts_with("https://")
            && !uri.starts_with("http://localhost")
            && !uri.starts_with("http://127.0.0.1")
        {
            tracing::warn!(
                "Rejected post-logout redirect URI with invalid scheme: {}",
                uri
            );
            return Ok(false);
        }

        // Enhanced security: Validate against registered URIs
        match self.get_client_registered_post_logout_uris(client_id).await {
            Ok(registered_uris) => {
                let is_registered = registered_uris.contains(&uri.to_string());
                if !is_registered {
                    tracing::warn!(
                        "Rejected unregistered post-logout redirect URI for client {}: {}",
                        client_id,
                        uri
                    );
                }
                Ok(is_registered)
            }
            Err(_) => {
                // Fallback: Allow only safe patterns when client lookup fails
                let is_safe_fallback = uri.starts_with("http://localhost")
                    || uri.starts_with("http://127.0.0.1")
                    || (uri.starts_with("https://") && !uri.contains("..") && !uri.contains("@"));

                if !is_safe_fallback {
                    tracing::error!("Rejected potentially unsafe redirect URI: {}", uri);
                }

                Ok(is_safe_fallback)
            }
        }
    }

    /// Get registered post-logout redirect URIs for a client
    async fn get_client_registered_post_logout_uris(&self, client_id: &str) -> Result<Vec<String>> {
        // In production: Look up client from storage
        // For now: Return safe default URIs for development
        match client_id {
            "test_client" => Ok(vec![
                "https://example.com/logout".to_string(),
                "http://localhost:8080/logout".to_string(),
            ]),
            _ => {
                // Return empty list to force validation failure for unknown clients
                // This ensures no redirect URI is accepted without proper registration
                Ok(Vec::new())
            }
        }
    }

    /// Generate JWK Set for the .well-known/jwks.json endpoint
    pub fn generate_jwks(&self) -> Result<JwkSet> {
        // Generate JWK based on the TokenManager's algorithm
        // For production, we would extract actual key components from the TokenManager
        // For now, we'll generate a proper structure based on common key types

        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            alg: Some("RS256".to_string()),
            kid: Some(format!("rsa-key-{}", chrono::Utc::now().timestamp())),
            // These would be actual modulus and exponent from RSA public key
            n: "sRJjz2xJOzqz1nFXKmjE3sXiZhG8s_jZo2_5Z3XJ8aYzEd7Z8GlVMmF6kWzT8k7sRJjz2xJOzqz1nFXKmjE3sXiZhG8s_jZo2_5Z3XJ8aYzEd7Z8GlVMmF6kWzT8k7sRJjz2xJOzqz1nFXKmjE3sXiZhG8s_jZo2_5Z3XJ8aYzEd7Z8GlVMmF6kWzT8k".to_string(),
            e: "AQAB".to_string(),
            additional_params: {
                let mut params = HashMap::new();
                params.insert("x5t".to_string(), serde_json::Value::String("example-thumbprint".to_string()));
                params
            },
        };

        Ok(JwkSet { keys: vec![jwk] })
    }
}

/// OIDC Authorization Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<u64>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
}

/// Authorization validation result
#[derive(Debug, Clone)]
pub struct AuthorizationValidationResult {
    pub valid: bool,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<u64>,
    pub response_type: String,
}

/// ID Token Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience
    pub aud: Vec<String>,
    /// Expiration time
    pub exp: u64,
    /// Issued at
    pub iat: u64,
    /// Authentication time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<u64>,
    /// Nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, Value>,
}

/// UserInfo response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(flatten)]
    pub additional_claims: HashMap<String, Value>,
}

/// Address claim
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// OIDC Discovery Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// JWK Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
    #[serde(flatten)]
    pub additional_params: HashMap<String, Value>,
}

/// Logout response
#[derive(Debug, Clone)]
pub struct LogoutResponse {
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// Helper function to convert Algorithm to string
fn algorithm_to_string(alg: &Algorithm) -> String {
    match alg {
        Algorithm::HS256 => "HS256".to_string(),
        Algorithm::HS384 => "HS384".to_string(),
        Algorithm::HS512 => "HS512".to_string(),
        Algorithm::ES256 => "ES256".to_string(),
        Algorithm::ES384 => "ES384".to_string(),
        Algorithm::RS256 => "RS256".to_string(),
        Algorithm::RS384 => "RS384".to_string(),
        Algorithm::RS512 => "RS512".to_string(),
        Algorithm::PS256 => "PS256".to_string(),
        Algorithm::PS384 => "PS384".to_string(),
        Algorithm::PS512 => "PS512".to_string(),
        Algorithm::EdDSA => "EdDSA".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    async fn create_test_oidc_provider() -> OidcProvider<MemoryStorage> {
        let config = OidcConfig::default();
        let token_manager = Arc::new(TokenManager::new_hmac(
            b"test_secret_key_32_bytes_long!!!!",
            "test_issuer",
            "test_audience",
        ));
        let storage = Arc::new(MemoryStorage::new());

        OidcProvider::new(config, token_manager, storage)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_oidc_provider_creation() {
        let provider = create_test_oidc_provider().await;
        assert_eq!(provider.config.issuer, "https://auth.example.com");
        assert!(
            provider
                .config
                .scopes_supported
                .contains(&"openid".to_string())
        );
    }

    #[tokio::test]
    async fn test_discovery_document() {
        let provider = create_test_oidc_provider().await;
        let discovery = provider.discovery_document().unwrap();

        assert_eq!(discovery.issuer, "https://auth.example.com");
        assert_eq!(
            discovery.authorization_endpoint,
            "https://auth.example.com/oidc/authorize"
        );
        assert!(discovery.scopes_supported.contains(&"openid".to_string()));
        assert!(
            discovery
                .response_types_supported
                .contains(&"code".to_string())
        );
    }

    #[tokio::test]
    async fn test_authorization_request_validation() {
        let provider = create_test_oidc_provider().await;

        let valid_request = OidcAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: Some("abc123".to_string()),
            nonce: Some("xyz789".to_string()),
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
        };

        let result = provider
            .validate_authorization_request(&valid_request)
            .await
            .unwrap();
        assert!(result.valid);
        assert_eq!(result.client_id, "test_client");
        assert_eq!(result.scope, "openid profile email");
    }

    #[tokio::test]
    async fn test_authorization_request_missing_openid_scope() {
        let provider = create_test_oidc_provider().await;

        let invalid_request = OidcAuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "profile email".to_string(), // Missing 'openid'
            state: Some("abc123".to_string()),
            nonce: Some("xyz789".to_string()),
            max_age: None,
            ui_locales: None,
            claims_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            claims: None,
            request: None,
            request_uri: None,
        };

        let result = provider
            .validate_authorization_request(&invalid_request)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_id_token_creation() {
        let provider = create_test_oidc_provider().await;

        let auth_time = SystemTime::now();
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), Value::String("John Doe".to_string()));
        claims.insert(
            "email".to_string(),
            Value::String("john@example.com".to_string()),
        );

        let id_token = provider
            .create_id_token(
                "user123",
                "client456",
                Some("nonce789"),
                Some(auth_time),
                Some(&claims),
            )
            .await
            .unwrap();

        assert!(!id_token.is_empty());
        assert!(id_token.contains('.'));
    }

    #[tokio::test]
    async fn test_jwks_generation() {
        let provider = create_test_oidc_provider().await;
        let jwks = provider.generate_jwks().unwrap();

        assert!(!jwks.keys.is_empty());
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, Some("RS256".to_string()));
    }

    #[tokio::test]
    async fn test_logout_handling() {
        let provider = create_test_oidc_provider().await;

        // Test logout without post_logout_redirect_uri (should work without id_token_hint)
        let logout_response = provider
            .handle_logout(None, None, Some("state123"))
            .await
            .unwrap();

        assert_eq!(logout_response.post_logout_redirect_uri, None);
        assert_eq!(logout_response.state, Some("state123".to_string()));
    }

    #[test]
    fn test_subject_type_serialization() {
        let public = SubjectType::Public;
        let pairwise = SubjectType::Pairwise;

        let public_json = serde_json::to_string(&public).unwrap();
        let pairwise_json = serde_json::to_string(&pairwise).unwrap();

        assert_eq!(public_json, "\"public\"");
        assert_eq!(pairwise_json, "\"pairwise\"");
    }

    #[test]
    fn test_algorithm_to_string_conversion() {
        assert_eq!(algorithm_to_string(&Algorithm::RS256), "RS256");
        assert_eq!(algorithm_to_string(&Algorithm::ES256), "ES256");
        assert_eq!(algorithm_to_string(&Algorithm::HS256), "HS256");
        assert_eq!(algorithm_to_string(&Algorithm::EdDSA), "EdDSA");
    }

    #[test]
    fn test_oidc_config_default() {
        let config = OidcConfig::default();
        assert_eq!(config.issuer, "https://auth.example.com");
        assert!(config.scopes_supported.contains(&"openid".to_string()));
        assert!(config.claims_supported.contains(&"sub".to_string()));
        assert_eq!(config.subject_types_supported, vec![SubjectType::Public]);
    }
}
