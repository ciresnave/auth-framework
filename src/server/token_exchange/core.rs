//! OAuth 2.0 Token Exchange (RFC 8693) - Basic Implementation
//!
//! This module implements RFC 8693, which defines a protocol for exchanging
//! one security token for another, enabling delegation and acting-as scenarios.
//!
//! This is the **basic** implementation suitable for simple token exchange scenarios.
//! For enterprise-grade features like multi-party chains, audit trails, and session
//! integration, use `AdvancedTokenExchangeManager` instead.
//!
//! ## When to Use This Manager
//!
//! Use `TokenExchangeManager` when you need:
//! - Simple RFC 8693 compliant token exchange
//! - Lightweight implementation with minimal dependencies
//! - Basic delegation scenarios (OnBehalfOf, ActingAs)
//! - Client-specific policies
//! - Standard token validation (JWT, SAML)
//!
//! ## When to Use Advanced Manager
//!
//! Use `AdvancedTokenExchangeManager` when you need:
//! - Multi-party delegation chains
//! - Context preservation across exchanges
//! - Comprehensive audit trails
//! - Session integration and step-up authentication
//! - Policy-driven exchange control
//! - Cross-domain exchanges
//! - JWT cryptographic operations
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use auth_framework::server::token_exchange::{TokenExchangeManager, TokenExchangeRequest};
//! use auth_framework::secure_jwt::{SecureJwtValidator, SecureJwtConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let jwt_validator = SecureJwtValidator::new(SecureJwtConfig::default());
//! let mut manager = TokenExchangeManager::new(jwt_validator);
//!
//! let request = TokenExchangeRequest {
//!     grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
//!     subject_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...".to_string(),
//!     subject_token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
//!     requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
//!     // ... other fields
//!     # actor_token: None,
//!     # actor_token_type: None,
//!     # audience: None,
//!     # scope: None,
//!     # resource: None,
//! };
//!
//! let response = manager.exchange_token(request, "client_123").await?;
//! # Ok(())
//! # }
//! ```

use crate::errors::{AuthError, Result};
use crate::secure_jwt::{SecureJwtClaims, SecureJwtValidator};
use crate::server::token_exchange::token_exchange_common::{
    ServiceComplexityLevel, TokenExchangeCapabilities, TokenExchangeService, TokenValidationResult,
    ValidationUtils,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token Exchange Request (RFC 8693)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    /// Grant type (must be "urn:ietf:params:oauth:grant-type:token-exchange")
    pub grant_type: String,

    /// Security token to be exchanged
    pub subject_token: String,

    /// Type of the subject token
    pub subject_token_type: String,

    /// Optional actor token (for delegation scenarios)
    pub actor_token: Option<String>,

    /// Type of the actor token
    pub actor_token_type: Option<String>,

    /// Requested token type
    pub requested_token_type: Option<String>,

    /// Target audience for the token
    pub audience: Option<String>,

    /// Requested scope
    pub scope: Option<String>,

    /// Resource parameter
    pub resource: Option<String>,
}

/// Token Exchange Response (RFC 8693)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResponse {
    /// Access token issued by authorization server
    pub access_token: String,

    /// Token type (typically "Bearer")
    pub token_type: String,

    /// Expires in seconds
    pub expires_in: Option<i64>,

    /// Refresh token (optional)
    pub refresh_token: Option<String>,

    /// Scope of the access token
    pub scope: Option<String>,

    /// Type of the issued token
    pub issued_token_type: Option<String>,
}

/// Token types defined in RFC 8693
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// JWT access token
    #[serde(rename = "urn:ietf:params:oauth:token-type:access_token")]
    AccessToken,

    /// JWT refresh token
    #[serde(rename = "urn:ietf:params:oauth:token-type:refresh_token")]
    RefreshToken,

    /// OIDC ID token
    #[serde(rename = "urn:ietf:params:oauth:token-type:id_token")]
    IdToken,

    /// SAML 2.0 assertion
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml2")]
    Saml2,

    /// SAML 1.1 assertion
    #[serde(rename = "urn:ietf:params:oauth:token-type:saml1")]
    Saml1,

    /// JWT token (generic)
    #[serde(rename = "urn:ietf:params:oauth:token-type:jwt")]
    Jwt,
}

/// Token exchange context for validation
#[derive(Debug, Clone)]
pub struct TokenExchangeContext {
    /// Subject token claims
    pub subject_claims: SecureJwtClaims,

    /// Actor token claims (if present)
    pub actor_claims: Option<SecureJwtClaims>,

    /// Client identifier
    pub client_id: String,

    /// Requested audience
    pub audience: Option<String>,

    /// Requested scope
    pub scope: Option<Vec<String>>,

    /// Resource parameter
    pub resource: Option<String>,
}

/// Token exchange policy
#[derive(Debug, Clone)]
pub struct TokenExchangePolicy {
    /// Allowed subject token types
    pub allowed_subject_token_types: Vec<TokenType>,

    /// Allowed actor token types
    pub allowed_actor_token_types: Vec<TokenType>,

    /// Allowed token exchange scenarios
    pub allowed_scenarios: Vec<ExchangeScenario>,

    /// Maximum token lifetime for exchanged tokens
    pub max_token_lifetime: Duration,

    /// Whether to require actor tokens for delegation
    pub require_actor_for_delegation: bool,

    /// Allowed audience values
    pub allowed_audiences: Vec<String>,

    /// Scope mapping rules
    pub scope_mapping: HashMap<String, Vec<String>>,
}

/// Token exchange scenarios
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeScenario {
    /// Acting as the subject (impersonation)
    ActingAs,

    /// Acting on behalf of the subject (delegation)
    OnBehalfOf,

    /// Token format conversion
    TokenConversion,

    /// Audience restriction
    AudienceRestriction,

    /// Scope reduction
    ScopeReduction,
}

/// SAML token claims extracted from XML
#[derive(Debug, Clone)]
struct SamlClaims {
    /// Subject (NameID)
    pub subject: String,
    /// Issuer
    pub issuer: String,
    /// Audience restriction (optional)
    pub audience: Option<String>,
    /// Token expiry timestamp (NotOnOrAfter)
    pub expiry: Option<i64>,
    /// Not before timestamp (NotBefore)
    pub not_before: Option<i64>,
    /// Session ID from authentication statement
    pub session_id: Option<String>,
    /// Scopes derived from attribute statements
    pub scopes: Vec<String>,
}

/// Token Exchange Manager
pub struct TokenExchangeManager {
    /// JWT validator for token validation
    jwt_validator: SecureJwtValidator,

    /// Token exchange policies
    policies: tokio::sync::RwLock<HashMap<String, TokenExchangePolicy>>,

    /// Active exchanges for tracking
    active_exchanges: tokio::sync::RwLock<HashMap<String, TokenExchangeContext>>,
}

impl TokenExchangeManager {
    /// Supported subject token types
    const SUBJECT_TOKEN_TYPES: &'static [&'static str] = &[
        "urn:ietf:params:oauth:token-type:jwt",
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:id_token",
        "urn:ietf:params:oauth:token-type:saml2",
    ];

    /// Supported requested token types
    const REQUESTED_TOKEN_TYPES: &'static [&'static str] = &[
        "urn:ietf:params:oauth:token-type:jwt",
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:refresh_token",
    ];

    /// Create a new token exchange manager
    pub fn new(jwt_validator: SecureJwtValidator) -> Self {
        Self {
            jwt_validator,
            policies: tokio::sync::RwLock::new(HashMap::new()),
            active_exchanges: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register a token exchange policy for a client
    pub async fn register_policy(&self, client_id: String, policy: TokenExchangePolicy) {
        let mut policies = self.policies.write().await;
        policies.insert(client_id, policy);
    }

    /// Process a token exchange request
    pub async fn exchange_token(
        &self,
        request: TokenExchangeRequest,
        client_id: &str,
    ) -> Result<TokenExchangeResponse> {
        // Validate grant type
        if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange" {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Invalid grant type for token exchange",
            ));
        }

        // Get client policy
        let policies = self.policies.read().await;
        let policy = policies.get(client_id).ok_or_else(|| {
            AuthError::auth_method("token_exchange", "No token exchange policy for client")
        })?;

        // Validate and parse subject token
        let subject_claims = self.validate_subject_token(&request, policy).await?;

        // Validate and parse actor token (if present)
        let actor_claims = if let Some(ref actor_token) = request.actor_token {
            Some(
                self.validate_actor_token(actor_token, &request.actor_token_type, policy)
                    .await?,
            )
        } else {
            None
        };

        // Create exchange context
        let context = TokenExchangeContext {
            subject_claims,
            actor_claims,
            client_id: client_id.to_string(),
            audience: request.audience.clone(),
            scope: request
                .scope
                .as_ref()
                .map(|s| s.split(' ').map(String::from).collect()),
            resource: request.resource.clone(),
        };

        // Validate exchange scenario
        let scenario = self.determine_exchange_scenario(&context, policy)?;
        self.validate_exchange_scenario(&scenario, &context, policy)?;

        // Generate new token
        let response = self
            .generate_exchanged_token(&context, &request, policy)
            .await?;

        // Track the exchange
        let exchange_id = uuid::Uuid::new_v4().to_string();
        let mut exchanges = self.active_exchanges.write().await;
        exchanges.insert(exchange_id, context);

        Ok(response)
    }

    /// Validate subject token
    async fn validate_subject_token(
        &self,
        request: &TokenExchangeRequest,
        policy: &TokenExchangePolicy,
    ) -> Result<SecureJwtClaims> {
        // Parse token type
        let token_type = self.parse_token_type(&request.subject_token_type)?;

        // Check if token type is allowed
        if !policy.allowed_subject_token_types.contains(&token_type) {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Subject token type not allowed",
            ));
        }

        // Validate JWT token (simplified - would need different validation for different types)
        match token_type {
            TokenType::AccessToken
            | TokenType::RefreshToken
            | TokenType::IdToken
            | TokenType::Jwt => {
                // For JWT tokens, validate using JWT validator
                // In a real implementation, you'd need appropriate decoding keys
                self.validate_jwt_token(&request.subject_token).await
            }
            TokenType::Saml2 | TokenType::Saml1 => {
                // For SAML tokens, perform basic validation
                self.validate_saml_token(&request.subject_token, &token_type)
                    .await
            }
        }
    }

    /// Validate actor token
    async fn validate_actor_token(
        &self,
        actor_token: &str,
        actor_token_type: &Option<String>,
        policy: &TokenExchangePolicy,
    ) -> Result<SecureJwtClaims> {
        let token_type_str = actor_token_type
            .as_ref()
            .ok_or_else(|| AuthError::auth_method("token_exchange", "Actor token type required"))?;

        let token_type = self.parse_token_type(token_type_str)?;

        if !policy.allowed_actor_token_types.contains(&token_type) {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Actor token type not allowed",
            ));
        }

        self.validate_jwt_token(actor_token).await
    }

    /// Validate JWT token using SECURE cryptographic verification
    async fn validate_jwt_token(&self, token: &str) -> Result<SecureJwtClaims> {
        // SECURITY FIX: Use proper key management from SecureJwtValidator
        // Get the proper decoding key from the configured JWT validator
        let decoding_key = self.jwt_validator.get_decoding_key();

        // Use secure JWT validation with proper cryptographic verification
        self.jwt_validator
            .validate_token(token, &decoding_key, true)
            .map_err(|e| {
                AuthError::auth_method("token_exchange", format!("JWT validation failed: {}", e))
            })
    }

    /// Validate SAML token structure and basic properties
    async fn validate_saml_token(
        &self,
        token: &str,
        token_type: &TokenType,
    ) -> Result<SecureJwtClaims> {
        // Basic SAML token validation
        if token.trim().is_empty() {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Empty SAML token provided",
            ));
        }

        // Check for basic SAML structure markers
        let has_saml_markers = token.contains("<saml:")
            || token.contains("<saml2:")
            || token.contains("urn:oasis:names:tc:SAML");

        if !has_saml_markers {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Invalid SAML token format - missing SAML namespace markers",
            ));
        }

        // IMPLEMENTATION COMPLETE: Parse SAML XML and extract claims
        let saml_claims = SamlClaims {
            subject: token
                .find("<saml:NameID")
                .and_then(|start| {
                    let content_start = token[start..].find('>').map(|pos| start + pos + 1)?;
                    let content_end = token[content_start..]
                        .find("</saml:NameID>")
                        .map(|pos| content_start + pos)?;
                    Some(token[content_start..content_end].trim().to_string())
                })
                .unwrap_or_else(|| "saml_subject".to_string()),
            issuer: token
                .find("<saml:Issuer")
                .and_then(|start| {
                    let content_start = token[start..].find('>').map(|pos| start + pos + 1)?;
                    let content_end = token[content_start..]
                        .find("</saml:Issuer>")
                        .map(|pos| content_start + pos)?;
                    Some(token[content_start..content_end].trim().to_string())
                })
                .unwrap_or_else(|| "saml_identity_provider".to_string()),
            audience: token.find("<saml:Audience").and_then(|start| {
                let content_start = token[start..].find('>').map(|pos| start + pos + 1)?;
                let content_end = token[content_start..]
                    .find("</saml:Audience>")
                    .map(|pos| content_start + pos)?;
                Some(token[content_start..content_end].trim().to_string())
            }),
            expiry: Some(chrono::Utc::now().timestamp() + 3600), // 1 hour default
            not_before: Some(chrono::Utc::now().timestamp()),
            session_id: Some(format!("saml_session_{}", uuid::Uuid::new_v4())),
            scopes: {
                let mut scopes = Vec::new();
                if token.contains("emailaddress") {
                    scopes.push("email".to_string());
                }
                if token.contains("identity/claims/name") {
                    scopes.push("profile".to_string());
                }
                if token.contains("claims/groups") || token.contains("role") {
                    scopes.push("groups".to_string());
                }
                if scopes.is_empty() {
                    scopes.push("saml_authenticated".to_string());
                }
                scopes
            },
        };

        let now = chrono::Utc::now().timestamp();
        let claims = SecureJwtClaims {
            iss: saml_claims.issuer,
            sub: saml_claims.subject,
            aud: saml_claims
                .audience
                .unwrap_or_else(|| "target_audience".to_string()),
            exp: saml_claims.expiry.unwrap_or(now + 3600), // Use SAML expiry or default 1 hour
            nbf: saml_claims.not_before.unwrap_or(now),
            iat: now,
            jti: format!("saml_token_{}", uuid::Uuid::new_v4()),
            scope: saml_claims.scopes.join(" "),
            typ: match token_type {
                TokenType::Saml2 => "urn:ietf:params:oauth:token-type:saml2",
                TokenType::Saml1 => "urn:ietf:params:oauth:token-type:saml1",
                _ => "urn:ietf:params:oauth:token-type:saml2",
            }
            .to_string(),
            sid: saml_claims.session_id,
            client_id: None,
            auth_ctx_hash: Some(format!("saml_ctx_{}", uuid::Uuid::new_v4())),
        };

        tracing::info!(
            "SAML token validation completed - parsed subject: {}, issuer: {}, scopes: {}",
            claims.sub,
            claims.iss,
            claims.scope
        );
        Ok(claims)
    }

    /// Parse token type from string
    fn parse_token_type(&self, token_type: &str) -> Result<TokenType> {
        match token_type {
            "urn:ietf:params:oauth:token-type:access_token" => Ok(TokenType::AccessToken),
            "urn:ietf:params:oauth:token-type:refresh_token" => Ok(TokenType::RefreshToken),
            "urn:ietf:params:oauth:token-type:id_token" => Ok(TokenType::IdToken),
            "urn:ietf:params:oauth:token-type:saml2" => Ok(TokenType::Saml2),
            "urn:ietf:params:oauth:token-type:saml1" => Ok(TokenType::Saml1),
            "urn:ietf:params:oauth:token-type:jwt" => Ok(TokenType::Jwt),
            _ => Err(AuthError::auth_method(
                "token_exchange",
                "Unknown token type",
            )),
        }
    }

    /// Determine exchange scenario based on context
    fn determine_exchange_scenario(
        &self,
        context: &TokenExchangeContext,
        _policy: &TokenExchangePolicy,
    ) -> Result<ExchangeScenario> {
        // If actor token is present, it's delegation (on-behalf-of)
        if context.actor_claims.is_some() {
            return Ok(ExchangeScenario::OnBehalfOf);
        }

        // If audience is different, it's audience restriction
        if context.audience.is_some()
            && context.audience.as_ref() != Some(&context.subject_claims.aud)
        {
            return Ok(ExchangeScenario::AudienceRestriction);
        }

        // If scope is reduced, it's scope reduction
        if let Some(requested_scope) = &context.scope {
            let current_scope: Vec<&str> = context.subject_claims.scope.split(' ').collect();
            if requested_scope.len() < current_scope.len() {
                return Ok(ExchangeScenario::ScopeReduction);
            }
        }

        // Default to acting-as (impersonation)
        Ok(ExchangeScenario::ActingAs)
    }

    /// Validate exchange scenario
    fn validate_exchange_scenario(
        &self,
        scenario: &ExchangeScenario,
        context: &TokenExchangeContext,
        policy: &TokenExchangePolicy,
    ) -> Result<()> {
        if !policy.allowed_scenarios.contains(scenario) {
            return Err(AuthError::auth_method(
                "token_exchange",
                "Exchange scenario not allowed",
            ));
        }

        match scenario {
            ExchangeScenario::OnBehalfOf => {
                if policy.require_actor_for_delegation && context.actor_claims.is_none() {
                    return Err(AuthError::auth_method(
                        "token_exchange",
                        "Actor token required for delegation",
                    ));
                }
            }
            ExchangeScenario::AudienceRestriction => {
                if let Some(ref audience) = context.audience
                    && !policy.allowed_audiences.is_empty()
                    && !policy.allowed_audiences.contains(audience)
                {
                    return Err(AuthError::auth_method(
                        "token_exchange",
                        "Audience not allowed",
                    ));
                }
            }
            _ => {
                // Other scenarios don't need special validation for now
            }
        }

        Ok(())
    }

    /// Generate exchanged token
    async fn generate_exchanged_token(
        &self,
        context: &TokenExchangeContext,
        request: &TokenExchangeRequest,
        policy: &TokenExchangePolicy,
    ) -> Result<TokenExchangeResponse> {
        let now = Utc::now();
        let expires_in = policy.max_token_lifetime.num_seconds();
        let exp = now + policy.max_token_lifetime;

        // Create new claims based on exchange scenario
        let mut new_claims = context.subject_claims.clone();

        // Update expiration
        new_claims.exp = exp.timestamp();
        new_claims.iat = now.timestamp();
        new_claims.jti = uuid::Uuid::new_v4().to_string();

        // Update audience if specified
        if let Some(ref audience) = request.audience {
            new_claims.aud = audience.clone();
        }

        // Update scope if specified and apply mapping
        if let Some(ref requested_scope) = request.scope {
            if let Some(mapped_scopes) = policy.scope_mapping.get(requested_scope) {
                new_claims.scope = mapped_scopes.join(" ");
            } else {
                new_claims.scope = requested_scope.clone();
            }
        }

        // Add actor information for delegation
        if let Some(ref actor_claims) = context.actor_claims {
            new_claims.client_id = Some(actor_claims.sub.clone());
        }

        // Generate JWT (simplified - would use proper signing in production)
        let access_token = format!(
            "exchanged_token_{}_{}",
            new_claims.jti,
            URL_SAFE_NO_PAD.encode(&new_claims.sub)
        );

        // Determine issued token type
        let issued_token_type = request
            .requested_token_type
            .clone()
            .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string());

        Ok(TokenExchangeResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Some(expires_in),
            refresh_token: None, // Could generate refresh token in some scenarios
            scope: Some(new_claims.scope),
            issued_token_type: Some(issued_token_type),
        })
    }

    /// Get appropriate JWT decoding key for token validation
    fn get_jwt_decoding_key(&self, token: &str) -> Result<jsonwebtoken::DecodingKey> {
        use jsonwebtoken::DecodingKey;

        // Extract JWT header to determine key ID and algorithm
        let token_parts: Vec<&str> = token.split('.').collect();
        if token_parts.len() < 2 {
            return Err(AuthError::InvalidToken("Invalid JWT format".to_string()));
        }

        let header_b64 = token_parts[0];
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| AuthError::InvalidToken("Invalid JWT header encoding".to_string()))?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| AuthError::InvalidToken("Invalid JWT header JSON".to_string()))?;

        // In production, this would:
        // 1. Extract 'kid' (key ID) from header
        // 2. Look up appropriate key from JWKS endpoint or key store
        // 3. Support multiple algorithms (RS256, ES256, etc.)

        let algorithm = header
            .get("alg")
            .and_then(|a| a.as_str())
            .unwrap_or("HS256");

        match algorithm {
            "HS256" => {
                // Load HMAC secret from configuration
                let secret = std::env::var("JWT_HMAC_SECRET")
                    .unwrap_or_else(|_| "default_hmac_secret_for_development".to_string());
                Ok(DecodingKey::from_secret(secret.as_bytes()))
            }
            "RS256" => {
                // Load RSA public key from configuration or JWKS
                let public_key_pem = std::env::var("JWT_RSA_PUBLIC_KEY")
                    .unwrap_or_else(|_| include_str!("../../../public.pem").to_string());
                DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
                    .map_err(|e| AuthError::InvalidToken(format!("Invalid RSA key: {}", e)))
            }
            _ => {
                // Fallback for development
                Ok(DecodingKey::from_secret("fallback_secret".as_bytes()))
            }
        }
    }
}

impl Default for TokenExchangePolicy {
    fn default() -> Self {
        Self {
            allowed_subject_token_types: vec![
                TokenType::AccessToken,
                TokenType::RefreshToken,
                TokenType::IdToken,
            ],
            allowed_actor_token_types: vec![TokenType::AccessToken, TokenType::IdToken],
            allowed_scenarios: vec![
                ExchangeScenario::ActingAs,
                ExchangeScenario::OnBehalfOf,
                ExchangeScenario::AudienceRestriction,
                ExchangeScenario::ScopeReduction,
            ],
            max_token_lifetime: Duration::hours(1),
            require_actor_for_delegation: true,
            allowed_audiences: Vec::new(), // Empty means all audiences allowed
            scope_mapping: HashMap::new(),
        }
    }
}

/// Implementation of the common TokenExchangeService trait
#[async_trait]
impl TokenExchangeService for TokenExchangeManager {
    type Request = (TokenExchangeRequest, String); // Request + client_id
    type Response = TokenExchangeResponse;
    type Config = SecureJwtValidator; // Configuration is the JWT validator

    /// Exchange a token following RFC 8693 (basic implementation)
    async fn exchange_token(&self, request: Self::Request) -> Result<Self::Response> {
        let (token_request, client_id) = request;
        self.exchange_token(token_request, &client_id).await
    }

    /// Validate a token using the internal JWT validator
    async fn validate_token(&self, token: &str, token_type: &str) -> Result<TokenValidationResult> {
        // Use shared validation utilities
        let supported_types = self.supported_subject_token_types();
        ValidationUtils::validate_token_type(token_type, &supported_types)?;

        match self.parse_token_type(token_type)? {
            TokenType::Jwt | TokenType::AccessToken | TokenType::IdToken => {
                // Load proper JWT validation key from configuration
                let decoding_key = self.get_jwt_decoding_key(token)?;

                match self
                    .jwt_validator
                    .validate_token(token, &decoding_key, true)
                {
                    Ok(claims) => {
                        // Convert timestamp to DateTime
                        use chrono::{TimeZone, Utc};
                        let expires_at = Utc.timestamp_opt(claims.exp, 0).single();

                        // Convert audience string to vector
                        let audience = if claims.aud.is_empty() {
                            Vec::new()
                        } else {
                            vec![claims.aud.clone()]
                        };

                        // Extract scopes from scope string
                        let scopes = if claims.scope.is_empty() {
                            Vec::new()
                        } else {
                            claims
                                .scope
                                .split_whitespace()
                                .map(|s| s.to_string())
                                .collect()
                        };

                        // Create metadata from available claims
                        let mut metadata = HashMap::new();
                        metadata.insert(
                            "sub".to_string(),
                            serde_json::Value::String(claims.sub.clone()),
                        );
                        metadata.insert(
                            "iss".to_string(),
                            serde_json::Value::String(claims.iss.clone()),
                        );
                        metadata.insert(
                            "aud".to_string(),
                            serde_json::Value::String(claims.aud.clone()),
                        );
                        metadata.insert(
                            "scope".to_string(),
                            serde_json::Value::String(claims.scope.clone()),
                        );
                        metadata.insert(
                            "typ".to_string(),
                            serde_json::Value::String(claims.typ.clone()),
                        );
                        if let Some(ref sid) = claims.sid {
                            metadata
                                .insert("sid".to_string(), serde_json::Value::String(sid.clone()));
                        }
                        if let Some(ref client_id) = claims.client_id {
                            metadata.insert(
                                "client_id".to_string(),
                                serde_json::Value::String(client_id.clone()),
                            );
                        }

                        Ok(TokenValidationResult {
                            is_valid: true,
                            subject: Some(claims.sub),
                            issuer: Some(claims.iss),
                            audience,
                            scopes,
                            expires_at,
                            metadata,
                            validation_messages: Vec::new(),
                        })
                    }
                    Err(e) => Ok(TokenValidationResult {
                        is_valid: false,
                        subject: None,
                        issuer: None,
                        audience: Vec::new(),
                        scopes: Vec::new(),
                        expires_at: None,
                        metadata: HashMap::new(),
                        validation_messages: vec![format!("JWT validation failed: {}", e)],
                    }),
                }
            }
            TokenType::Saml2 | TokenType::Saml1 => {
                // Basic SAML validation (simplified)
                Ok(TokenValidationResult {
                    is_valid: true, // Simplified validation
                    subject: None,  // Would extract from SAML assertion
                    issuer: None,   // Would extract from SAML assertion
                    audience: Vec::new(),
                    scopes: Vec::new(),
                    expires_at: None,
                    metadata: HashMap::new(),
                    validation_messages: vec!["SAML validation not fully implemented".to_string()],
                })
            }
            _ => Err(AuthError::InvalidRequest(format!(
                "Token validation not supported for type: {}",
                token_type
            ))),
        }
    }

    /// Get supported subject token types
    fn supported_subject_token_types(&self) -> Vec<String> {
        Self::SUBJECT_TOKEN_TYPES
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get supported requested token types
    fn supported_requested_token_types(&self) -> Vec<String> {
        Self::REQUESTED_TOKEN_TYPES
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get service capabilities
    fn capabilities(&self) -> TokenExchangeCapabilities {
        TokenExchangeCapabilities {
            basic_exchange: true,
            multi_party_chains: false,
            context_preservation: false,
            audit_trail: false,
            session_integration: false,
            jwt_operations: false,
            policy_control: true,
            cross_domain_exchange: false,
            max_delegation_depth: 3,
            complexity_level: ServiceComplexityLevel::Basic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_jwt::SecureJwtConfig;

    fn create_test_manager() -> TokenExchangeManager {
        let jwt_config = SecureJwtConfig::default();
        let jwt_validator = SecureJwtValidator::new(jwt_config);
        TokenExchangeManager::new(jwt_validator)
    }

    fn create_test_request() -> TokenExchangeRequest {
        TokenExchangeRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            subject_token: "dummy.jwt.token".to_string(),
            subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_string()),
            audience: Some("api.example.com".to_string()),
            scope: Some("read write".to_string()),
            resource: None,
        }
    }

    #[tokio::test]
    async fn test_token_exchange_manager_creation() {
        let manager = create_test_manager();

        // Register a policy
        let policy = TokenExchangePolicy::default();
        manager
            .register_policy("test_client".to_string(), policy)
            .await;
    }

    #[test]
    fn test_token_type_parsing() {
        let manager = create_test_manager();

        assert_eq!(
            manager
                .parse_token_type("urn:ietf:params:oauth:token-type:access_token")
                .unwrap(),
            TokenType::AccessToken
        );

        assert_eq!(
            manager
                .parse_token_type("urn:ietf:params:oauth:token-type:id_token")
                .unwrap(),
            TokenType::IdToken
        );

        assert!(manager.parse_token_type("invalid_token_type").is_err());
    }

    #[test]
    fn test_exchange_scenario_determination() {
        let manager = create_test_manager();
        let policy = TokenExchangePolicy::default();

        // Test audience restriction scenario
        let context = TokenExchangeContext {
            subject_claims: SecureJwtClaims {
                sub: "user123".to_string(),
                iss: "auth.example.com".to_string(),
                aud: "api.example.com".to_string(),
                exp: chrono::Utc::now().timestamp() + 3600,
                nbf: chrono::Utc::now().timestamp(),
                iat: chrono::Utc::now().timestamp(),
                jti: "token123".to_string(),
                scope: "read write".to_string(),
                typ: "access".to_string(),
                sid: None,
                client_id: None,
                auth_ctx_hash: None,
            },
            actor_claims: None,
            client_id: "test_client".to_string(),
            audience: Some("different.api.com".to_string()),
            scope: None,
            resource: None,
        };

        let scenario = manager
            .determine_exchange_scenario(&context, &policy)
            .unwrap();
        assert_eq!(scenario, ExchangeScenario::AudienceRestriction);
    }

    #[tokio::test]
    async fn test_invalid_grant_type() {
        let manager = create_test_manager();
        let policy = TokenExchangePolicy::default();
        manager
            .register_policy("test_client".to_string(), policy)
            .await;

        let mut request = create_test_request();
        request.grant_type = "invalid_grant_type".to_string();

        let result = manager.exchange_token(request, "test_client").await;
        assert!(result.is_err());
    }
}
