//! OAuth 2.0 Token Introspection (RFC 7662)
//!
//! This module implements RFC 7662, which defines a method for a protected resource
//! to query an OAuth 2.0 authorization server to determine meta-information about
//! an OAuth 2.0 token.

use crate::errors::{AuthError, Result};
use crate::server::jwt::jwt_access_tokens::JwtAccessTokenValidator;
use crate::storage::AuthStorage;
use crate::tokens::{AuthToken, TokenManager};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Token introspection request (RFC 7662)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionRequest {
    /// The string value of the token
    pub token: String,

    /// Optional hint about the type of token being introspected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,

    /// Additional parameters for extension specifications
    #[serde(flatten)]
    pub additional_params: HashMap<String, String>,
}

/// Token introspection response (RFC 7662)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospectionResponse {
    /// Boolean indicator of whether the token is currently active
    pub active: bool,

    /// Space-separated list of scopes associated with the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Client identifier for the OAuth 2.0 client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Human-readable identifier for the resource owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Type of the token (e.g., "Bearer")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Integer timestamp of when the token expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Integer timestamp of when the token was issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Integer timestamp of when the token is not to be used before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Subject of the token (usually a machine-readable identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Intended audience for the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,

    /// Issuer of the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Unique identifier for the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Additional token attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

impl TokenIntrospectionResponse {
    /// Create an inactive token response
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            additional_attributes: HashMap::new(),
        }
    }

    /// Create an active token response from AuthToken
    pub fn from_auth_token(
        token: &AuthToken,
        client_id: Option<String>,
        issuer: Option<String>,
    ) -> Self {
        Self {
            active: !token.is_expired(),
            scope: if token.scopes.is_empty() {
                None
            } else {
                Some(token.scopes.join(" "))
            },
            client_id,
            username: Some(token.user_id.clone()),
            token_type: Some("Bearer".to_string()),
            exp: Some(token.expires_at.timestamp()),
            iat: Some(token.issued_at.timestamp()),
            nbf: Some(token.issued_at.timestamp()),
            sub: Some(token.user_id.clone()),
            aud: None, // Set based on configuration
            iss: issuer,
            jti: Some(token.token_id.clone()),
            additional_attributes: HashMap::new(),
        }
    }
}

/// Token introspection endpoint configuration
#[derive(Debug, Clone)]
pub struct TokenIntrospectionConfig {
    /// Whether introspection is enabled
    pub enabled: bool,

    /// Issuer identifier
    pub issuer: String,

    /// Whether to include detailed token information
    pub include_detailed_info: bool,

    /// Maximum number of introspection requests per client per minute
    pub rate_limit_per_minute: u32,

    /// Supported token types for introspection
    pub supported_token_types: Vec<String>,

    /// Whether to validate client credentials for introspection
    pub require_client_authentication: bool,
}

impl Default for TokenIntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            issuer: "https://auth.example.com".to_string(),
            include_detailed_info: true,
            rate_limit_per_minute: 100,
            supported_token_types: vec!["access_token".to_string(), "refresh_token".to_string()],
            require_client_authentication: true,
        }
    }
}

/// Token introspection client credentials
#[derive(Debug, Clone)]
pub struct IntrospectionClientCredentials {
    /// Client identifier
    pub client_id: String,

    /// Client secret (if required)
    pub client_secret: Option<String>,

    /// Client assertion for JWT authentication
    pub client_assertion: Option<String>,

    /// Client authentication method
    pub auth_method: ClientAuthMethod,
}

/// Client authentication methods for introspection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// HTTP Basic authentication with client_id and client_secret
    ClientSecretBasic,

    /// POST body authentication with client_id and client_secret
    ClientSecretPost,

    /// JWT-based client authentication
    ClientSecretJwt,

    /// Private key JWT authentication
    PrivateKeyJwt,

    /// No authentication (public clients)
    None,
}

/// Token introspection service
pub struct TokenIntrospectionService {
    /// Configuration
    config: TokenIntrospectionConfig,

    /// Storage backend
    storage: Arc<dyn AuthStorage>,

    /// Token manager for JWT validation
    token_manager: Arc<TokenManager>,

    /// JWT access token validator
    jwt_validator: Option<JwtAccessTokenValidator>,

    /// Rate limiting tracker
    rate_limiter: Arc<tokio::sync::RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl TokenIntrospectionService {
    /// Create a new token introspection service
    pub fn new(
        config: TokenIntrospectionConfig,
        storage: Arc<dyn AuthStorage>,
        token_manager: Arc<TokenManager>,
        jwt_validator: Option<JwtAccessTokenValidator>,
    ) -> Self {
        Self {
            config,
            storage,
            token_manager,
            jwt_validator,
            rate_limiter: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Handle token introspection request
    pub async fn introspect_token(
        &self,
        request: TokenIntrospectionRequest,
        client_credentials: Option<IntrospectionClientCredentials>,
    ) -> Result<TokenIntrospectionResponse> {
        // Check if introspection is enabled
        if !self.config.enabled {
            return Err(AuthError::access_denied("Token introspection is disabled"));
        }

        // Validate client credentials if required
        if self.config.require_client_authentication {
            let credentials = client_credentials.ok_or_else(|| {
                AuthError::access_denied("Client authentication required for token introspection")
            })?;

            self.validate_client_credentials(&credentials).await?;

            // Check rate limiting
            self.check_rate_limit(&credentials.client_id).await?;
        }

        // Determine token type and introspect accordingly
        let token_type = request.token_type_hint.as_deref().unwrap_or("access_token");

        match token_type {
            "access_token" => self.introspect_access_token(&request.token).await,
            "refresh_token" => self.introspect_refresh_token(&request.token).await,
            _ => self.introspect_unknown_token(&request.token).await,
        }
    }

    /// Introspect an access token
    async fn introspect_access_token(&self, token: &str) -> Result<TokenIntrospectionResponse> {
        // Try JWT access token first if validator is available
        if let Some(ref jwt_validator) = self.jwt_validator
            && let Ok(claims) = jwt_validator.validate_jwt_access_token(token)
        {
            return Ok(TokenIntrospectionResponse {
                active: true,
                scope: claims.scope,
                client_id: Some(claims.client_id),
                username: Some(claims.sub.clone()),
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                nbf: claims.nbf,
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
                additional_attributes: HashMap::new(),
            });
        }

        // Try opaque token lookup in storage
        match self.storage.get_token(token).await? {
            Some(auth_token) => {
                if auth_token.is_expired() {
                    Ok(TokenIntrospectionResponse::inactive())
                } else {
                    Ok(TokenIntrospectionResponse::from_auth_token(
                        &auth_token,
                        None, // Would need client ID from token metadata
                        Some(self.config.issuer.clone()),
                    ))
                }
            }
            None => Ok(TokenIntrospectionResponse::inactive()),
        }
    }

    /// Introspect a refresh token
    async fn introspect_refresh_token(&self, token: &str) -> Result<TokenIntrospectionResponse> {
        // Look up refresh token in storage
        // This would need to be implemented in the storage backend
        match self.storage.get_token(token).await? {
            Some(auth_token) => {
                if let Some(ref refresh_token) = auth_token.refresh_token {
                    if refresh_token == token && !auth_token.is_expired() {
                        let mut response = TokenIntrospectionResponse::from_auth_token(
                            &auth_token,
                            None,
                            Some(self.config.issuer.clone()),
                        );
                        response.token_type = Some("refresh_token".to_string());
                        Ok(response)
                    } else {
                        Ok(TokenIntrospectionResponse::inactive())
                    }
                } else {
                    Ok(TokenIntrospectionResponse::inactive())
                }
            }
            None => Ok(TokenIntrospectionResponse::inactive()),
        }
    }

    /// Introspect an unknown token type
    async fn introspect_unknown_token(&self, token: &str) -> Result<TokenIntrospectionResponse> {
        // Try as access token first, then refresh token
        let access_result = self.introspect_access_token(token).await?;
        if access_result.active {
            return Ok(access_result);
        }

        self.introspect_refresh_token(token).await
    }

    /// Validate client credentials for introspection
    async fn validate_client_credentials(
        &self,
        credentials: &IntrospectionClientCredentials,
    ) -> Result<()> {
        if credentials.client_id.is_empty() {
            return Err(AuthError::access_denied("Invalid client_id"));
        }

        match credentials.auth_method {
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                if let Some(client_secret) = &credentials.client_secret {
                    // Validate against client registry if available
                    let client_key = format!("oauth_client:{}", credentials.client_id);
                    if let Some(client_data) = self.storage.get_kv(&client_key).await? {
                        let client_str = std::str::from_utf8(&client_data).map_err(|e| {
                            AuthError::internal(format!("Invalid UTF-8 in client data: {}", e))
                        })?;
                        let client: serde_json::Value =
                            serde_json::from_str(client_str).map_err(|e| {
                                AuthError::internal(format!("Failed to deserialize client: {}", e))
                            })?;

                        if let Some(stored_secret) =
                            client.get("client_secret").and_then(|v| v.as_str())
                        {
                            if !crate::security::secure_utils::constant_time_compare(
                                client_secret.as_bytes(),
                                stored_secret.as_bytes(),
                            ) {
                                return Err(AuthError::access_denied("Invalid client secret"));
                            }
                        } else {
                            return Err(AuthError::access_denied("Client secret not found"));
                        }
                    } else {
                        return Err(AuthError::access_denied("Client not found"));
                    }
                } else {
                    return Err(AuthError::access_denied("Client secret required"));
                }
            }
            ClientAuthMethod::ClientSecretJwt | ClientAuthMethod::PrivateKeyJwt => {
                if let Some(client_assertion) = &credentials.client_assertion {
                    // Validate JWT assertion
                    if let Ok(claims) = self.token_manager.validate_jwt_token(client_assertion) {
                        if claims.sub != credentials.client_id {
                            return Err(AuthError::access_denied(
                                "JWT subject doesn't match client_id",
                            ));
                        }
                        if claims.aud.is_empty() || !claims.aud.contains(&self.config.issuer) {
                            return Err(AuthError::access_denied("Invalid JWT audience"));
                        }
                    } else {
                        return Err(AuthError::access_denied("Invalid JWT assertion"));
                    }
                } else {
                    return Err(AuthError::access_denied(
                        "Client assertion required for JWT auth",
                    ));
                }
            }
            ClientAuthMethod::None => {
                // Public client - no validation needed
            }
        }

        Ok(())
    }

    /// Check rate limiting for introspection requests
    async fn check_rate_limit(&self, client_id: &str) -> Result<()> {
        let mut rate_limiter = self.rate_limiter.write().await;
        let now = Utc::now();
        let one_minute_ago = now - chrono::Duration::minutes(1);

        // Clean up old entries and count recent requests
        let requests = rate_limiter
            .entry(client_id.to_string())
            .or_insert_with(Vec::new);
        requests.retain(|&timestamp| timestamp > one_minute_ago);

        if requests.len() >= self.config.rate_limit_per_minute as usize {
            return Err(AuthError::access_denied(
                "Rate limit exceeded for token introspection",
            ));
        }

        requests.push(now);
        Ok(())
    }

    /// Get introspection endpoint metadata
    pub fn get_metadata(&self) -> HashMap<String, serde_json::Value> {
        let mut metadata = HashMap::new();

        metadata.insert(
            "introspection_endpoint".to_string(),
            serde_json::Value::String(format!("{}/introspect", self.config.issuer)),
        );

        metadata.insert(
            "introspection_endpoint_auth_methods_supported".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("client_secret_basic".to_string()),
                serde_json::Value::String("client_secret_post".to_string()),
            ]),
        );

        metadata.insert(
            "token_introspection_supported".to_string(),
            serde_json::Value::Bool(self.config.enabled),
        );

        metadata
    }
}

/// HTTP handler for token introspection endpoint
pub struct TokenIntrospectionHandler {
    /// Introspection service
    service: Arc<TokenIntrospectionService>,
}

impl TokenIntrospectionHandler {
    /// Create a new introspection handler
    pub fn new(service: Arc<TokenIntrospectionService>) -> Self {
        Self { service }
    }

    /// Handle HTTP POST request to introspection endpoint
    pub async fn handle_introspection_request(
        &self,
        request_body: &str,
        authorization_header: Option<&str>,
    ) -> Result<String> {
        // Parse request body (application/x-www-form-urlencoded)
        let request = self.parse_introspection_request(request_body)?;

        // Extract client credentials from Authorization header or request body
        let client_credentials =
            self.extract_client_credentials(authorization_header, request_body)?;

        // Perform introspection
        let response = self
            .service
            .introspect_token(request, client_credentials)
            .await?;

        // Serialize response as JSON
        serde_json::to_string(&response).map_err(|e| {
            AuthError::internal(format!("Failed to serialize introspection response: {}", e))
        })
    }

    /// Parse introspection request from form data
    fn parse_introspection_request(&self, body: &str) -> Result<TokenIntrospectionRequest> {
        let mut token = None;
        let mut token_type_hint = None;
        let mut additional_params = HashMap::new();

        for pair in body.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = urlencoding::decode(key).map_err(|e| {
                    AuthError::validation(format!("Invalid URL encoding in key: {}", e))
                })?;
                let value = urlencoding::decode(value).map_err(|e| {
                    AuthError::validation(format!("Invalid URL encoding in value: {}", e))
                })?;

                match key.as_ref() {
                    "token" => token = Some(value.to_string()),
                    "token_type_hint" => token_type_hint = Some(value.to_string()),
                    _ => {
                        additional_params.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        let token =
            token.ok_or_else(|| AuthError::validation("Missing required parameter: token"))?;

        Ok(TokenIntrospectionRequest {
            token,
            token_type_hint,
            additional_params,
        })
    }

    /// Extract client credentials from Authorization header or request body
    fn extract_client_credentials(
        &self,
        authorization_header: Option<&str>,
        request_body: &str,
    ) -> Result<Option<IntrospectionClientCredentials>> {
        // Try Basic authentication first
        if let Some(auth_header) = authorization_header
            && let Some(encoded) = auth_header.strip_prefix("Basic ")
        {
            let decoded = general_purpose::STANDARD.decode(encoded).map_err(|e| {
                AuthError::validation(format!("Invalid Basic auth encoding: {}", e))
            })?;
            let credentials = String::from_utf8(decoded)
                .map_err(|e| AuthError::validation(format!("Invalid Basic auth UTF-8: {}", e)))?;

            if let Some((client_id, client_secret)) = credentials.split_once(':') {
                return Ok(Some(IntrospectionClientCredentials {
                    client_id: client_id.to_string(),
                    client_secret: Some(client_secret.to_string()),
                    client_assertion: None,
                    auth_method: ClientAuthMethod::ClientSecretBasic,
                }));
            }
        }

        // Try POST body credentials
        let mut client_id = None;
        let mut client_secret = None;

        for pair in request_body.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = urlencoding::decode(key).unwrap_or_default();
                let value = urlencoding::decode(value).unwrap_or_default();

                match key.as_ref() {
                    "client_id" => client_id = Some(value.to_string()),
                    "client_secret" => client_secret = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        if let Some(client_id) = client_id {
            return Ok(Some(IntrospectionClientCredentials {
                client_id,
                client_secret,
                client_assertion: None,
                auth_method: ClientAuthMethod::ClientSecretPost,
            }));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockStorage;
    use crate::tokens::TokenManager;
    use chrono::Duration;

    fn create_test_service() -> TokenIntrospectionService {
        let config = TokenIntrospectionConfig::default();
        let storage = Arc::new(MockStorage::new());
        let secret = b"test-secret-key-32-bytes-minimum!";
        let token_manager = Arc::new(TokenManager::new_hmac(
            secret,
            "test-issuer",
            "test-audience",
        ));

        TokenIntrospectionService::new(config, storage, token_manager, None)
    }

    #[tokio::test]
    async fn test_inactive_token_introspection() {
        let service = create_test_service();

        // Register a test client first
        let client_data = serde_json::json!({
            "client_id": "test-client",
            "client_secret": "test-secret"
        });
        service
            .storage
            .store_kv(
                "oauth_client:test-client",
                client_data.to_string().as_bytes(),
                None,
            )
            .await
            .unwrap();

        // Provide client credentials for introspection
        let client_credentials = IntrospectionClientCredentials {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_assertion: None,
            auth_method: ClientAuthMethod::ClientSecretBasic,
        };

        let request = TokenIntrospectionRequest {
            token: "invalid-token".to_string(),
            token_type_hint: Some("access_token".to_string()),
            additional_params: HashMap::new(),
        };

        let response = service
            .introspect_token(request, Some(client_credentials))
            .await
            .unwrap();
        assert!(!response.active);
    }

    #[tokio::test]
    async fn test_client_credentials_validation() {
        let service = create_test_service();

        // Register the test client in storage first
        let client_data = serde_json::json!({
            "client_id": "test-client",
            "client_secret": "test-secret"
        });
        service
            .storage
            .store_kv(
                "oauth_client:test-client",
                client_data.to_string().as_bytes(),
                None,
            )
            .await
            .unwrap();

        let valid_credentials = IntrospectionClientCredentials {
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            client_assertion: None,
            auth_method: ClientAuthMethod::ClientSecretBasic,
        };

        // Should not error with valid credentials
        assert!(
            service
                .validate_client_credentials(&valid_credentials)
                .await
                .is_ok()
        );

        let invalid_credentials = IntrospectionClientCredentials {
            client_id: "".to_string(),
            client_secret: None,
            client_assertion: None,
            auth_method: ClientAuthMethod::ClientSecretBasic,
        };

        // Should error with invalid credentials
        assert!(
            service
                .validate_client_credentials(&invalid_credentials)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let service = create_test_service();
        let client_id = "test-client";

        // Should allow requests under the limit
        for _ in 0..10 {
            assert!(service.check_rate_limit(client_id).await.is_ok());
        }

        // Should deny requests over the limit
        for _ in 0..service.config.rate_limit_per_minute {
            let _ = service.check_rate_limit(client_id).await;
        }

        // This should be rate limited
        assert!(service.check_rate_limit(client_id).await.is_err());
    }

    #[tokio::test]
    async fn test_token_introspection_response_creation() {
        let token = AuthToken {
            token_id: "test-token".to_string(),
            user_id: "test-user".to_string(),
            access_token: "test-access-token".to_string(),
            token_type: Some("Bearer".to_string()),
            subject: None,
            issuer: None,
            refresh_token: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            scopes: vec!["read".to_string(), "write".to_string()],
            auth_method: "test".to_string(),
            client_id: None,
            user_profile: None,
            permissions: vec!["read:data".to_string(), "write:data".to_string()],
            roles: vec!["user".to_string()],
            metadata: Default::default(),
        };

        let response = TokenIntrospectionResponse::from_auth_token(
            &token,
            Some("test-client".to_string()),
            Some("https://auth.example.com".to_string()),
        );

        assert!(response.active);
        assert_eq!(response.client_id.unwrap(), "test-client");
        assert_eq!(response.username.unwrap(), "test-user");
        assert_eq!(response.scope.unwrap(), "read write");
        assert_eq!(response.token_type.unwrap(), "Bearer");
        assert_eq!(response.iss.unwrap(), "https://auth.example.com");
    }

    #[test]
    fn test_introspection_handler_request_parsing() {
        let service = create_test_service();
        let handler = TokenIntrospectionHandler::new(Arc::new(service));

        let request_body = "token=test-token&token_type_hint=access_token";
        let request = handler.parse_introspection_request(request_body).unwrap();

        assert_eq!(request.token, "test-token");
        assert_eq!(request.token_type_hint.unwrap(), "access_token");
    }

    #[test]
    fn test_client_credentials_extraction() {
        let service = create_test_service();
        let handler = TokenIntrospectionHandler::new(Arc::new(service));

        // Test Basic authentication
        let auth_header = "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="; // test-client:test-secret
        let credentials = handler
            .extract_client_credentials(Some(auth_header), "")
            .unwrap()
            .unwrap();

        assert_eq!(credentials.client_id, "test-client");
        assert_eq!(credentials.client_secret.unwrap(), "test-secret");
        assert_eq!(credentials.auth_method, ClientAuthMethod::ClientSecretBasic);

        // Test POST body authentication
        let request_body = "token=test&client_id=test-client&client_secret=test-secret";
        let credentials = handler
            .extract_client_credentials(None, request_body)
            .unwrap()
            .unwrap();

        assert_eq!(credentials.client_id, "test-client");
        assert_eq!(credentials.client_secret.unwrap(), "test-secret");
        assert_eq!(credentials.auth_method, ClientAuthMethod::ClientSecretPost);
    }

    #[test]
    fn test_metadata_generation() {
        let service = create_test_service();
        let metadata = service.get_metadata();

        assert!(metadata.contains_key("introspection_endpoint"));
        assert!(metadata.contains_key("introspection_endpoint_auth_methods_supported"));
        assert!(metadata.contains_key("token_introspection_supported"));
    }
}
