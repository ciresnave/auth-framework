//! WS-Trust 1.3 Security Token Service (STS) Support
//!
//! This module provides WS-Trust 1.3 Security Token Service functionality for token exchange,
//! issuance, and validation scenarios.

use crate::errors::{AuthError, Result};
use crate::protocols::saml_assertions::SamlAssertionBuilder;
// SamlAssertion removed from import - not currently used but may be needed later
use crate::protocols::ws_security::{PasswordType, WsSecurityClient, WsSecurityConfig};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode as jwt_encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WS-Trust Security Token Service
///
/// **Note:** Issued tokens are stored in an in-memory `HashMap`. They will be
/// lost on restart and are not shared across STS instances. For production
/// multi-instance deployments, integrate with the `StorageBackend` KV store
/// for persistent/shared token state.
pub struct SecurityTokenService {
    /// STS configuration
    config: StsConfig,

    /// WS-Security client for generating secure headers
    ws_security: WsSecurityClient,

    /// Issued tokens cache
    issued_tokens: HashMap<String, IssuedToken>,
}

/// STS Configuration
#[derive(Debug, Clone)]
pub struct StsConfig {
    /// STS issuer identifier
    pub issuer: String,

    /// Default token lifetime
    pub default_token_lifetime: Duration,

    /// Maximum token lifetime
    pub max_token_lifetime: Duration,

    /// Supported token types
    pub supported_token_types: Vec<String>,

    /// STS endpoint URL
    pub endpoint_url: String,

    /// Whether to include proof tokens
    pub include_proof_tokens: bool,

    /// Trust relationships
    pub trust_relationships: Vec<TrustRelationship>,

    /// HMAC-HS256 signing secret used when issuing JWT tokens.
    ///
    /// **Must be set to a strong, randomly-generated value in production.**
    /// `StsConfig::default()` generates a cryptographically random secret
    /// automatically; override this field when you need a stable / shared
    /// signing key (e.g. for multi-node deployments that share the same
    /// validator).
    pub jwt_signing_secret: String,
}

/// Trust relationship with relying parties
#[derive(Debug, Clone)]
pub struct TrustRelationship {
    /// Relying party identifier
    pub rp_identifier: String,

    /// Certificate for encryption/signing
    pub certificate: Option<Vec<u8>>,

    /// Allowed token types
    pub allowed_token_types: Vec<String>,

    /// Maximum token lifetime for this RP
    pub max_token_lifetime: Option<Duration>,
}

/// Issued token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedToken {
    /// Token ID
    pub token_id: String,

    /// Token type
    pub token_type: String,

    /// Token content (SAML assertion, JWT, etc.)
    pub token_content: String,

    /// Issue time
    pub issued_at: DateTime<Utc>,

    /// Expiration time
    pub expires_at: DateTime<Utc>,

    /// Subject identifier
    pub subject: String,

    /// Audience/relying party
    pub audience: String,

    /// Proof token (if any)
    pub proof_token: Option<ProofToken>,
}

/// Proof token for holder-of-key scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofToken {
    /// Proof token type (symmetric key, certificate, etc.)
    pub token_type: String,

    /// Key material
    pub key_material: Vec<u8>,

    /// Key identifier
    pub key_identifier: String,
}

/// WS-Trust Request Security Token (RST)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityToken {
    /// Request type (Issue, Renew, Cancel, Validate)
    pub request_type: String,

    /// Token type being requested
    pub token_type: String,

    /// Applies to (target service/audience)
    pub applies_to: Option<String>,

    /// Lifetime requirements
    pub lifetime: Option<TokenLifetime>,

    /// Key type (Bearer, Symmetric, Asymmetric)
    pub key_type: Option<String>,

    /// Key size for symmetric keys
    pub key_size: Option<u32>,

    /// Existing token (for renew/validate operations)
    pub existing_token: Option<String>,

    /// Authentication context
    pub auth_context: Option<AuthenticationContext>,
}

/// Token lifetime specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLifetime {
    /// Created time
    pub created: DateTime<Utc>,

    /// Expires time
    pub expires: DateTime<Utc>,
}

/// Authentication context for token requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContext {
    /// Username
    pub username: String,

    /// Authentication method
    pub auth_method: String,

    /// Additional claims
    pub claims: HashMap<String, String>,
}

/// WS-Trust Request Security Token Response (RSTR)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSecurityTokenResponse {
    /// Request type being responded to
    pub request_type: String,

    /// Token type issued
    pub token_type: String,

    /// Lifetime of issued token
    pub lifetime: TokenLifetime,

    /// Applies to (target audience)
    pub applies_to: Option<String>,

    /// Requested security token
    pub requested_security_token: String,

    /// Requested proof token
    pub requested_proof_token: Option<ProofToken>,

    /// Token reference for future operations
    pub requested_attached_reference: Option<String>,

    /// Token reference for external use
    pub requested_unattached_reference: Option<String>,
}

impl SecurityTokenService {
    /// Create a new Security Token Service
    pub fn new(config: StsConfig) -> Self {
        let ws_security_config = WsSecurityConfig::default();
        let ws_security = WsSecurityClient::new(ws_security_config);

        Self {
            config,
            ws_security,
            issued_tokens: HashMap::new(),
        }
    }

    /// Process a WS-Trust Request Security Token
    pub fn process_request(
        &mut self,
        request: RequestSecurityToken,
    ) -> Result<RequestSecurityTokenResponse> {
        match request.request_type.as_str() {
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue" => self.issue_token(request),
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew" => self.renew_token(request),
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel" => self.cancel_token(request),
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate" => {
                self.validate_token(request)
            }
            _ => Err(AuthError::auth_method(
                "wstrust",
                "Unsupported request type",
            )),
        }
    }

    /// Issue a new security token
    fn issue_token(
        &mut self,
        request: RequestSecurityToken,
    ) -> Result<RequestSecurityTokenResponse> {
        // Validate authentication context
        let auth_context = request
            .auth_context
            .as_ref()
            .ok_or_else(|| AuthError::auth_method("wstrust", "Authentication context required"))?;

        // Determine token lifetime
        let now = Utc::now();
        let lifetime = if let Some(ref requested_lifetime) = request.lifetime {
            // Validate requested lifetime
            let max_expires = now + self.config.max_token_lifetime;
            let expires = if requested_lifetime.expires > max_expires {
                max_expires
            } else {
                requested_lifetime.expires
            };

            TokenLifetime {
                created: now,
                expires,
            }
        } else {
            TokenLifetime {
                created: now,
                expires: now + self.config.default_token_lifetime,
            }
        };

        // Generate token based on type
        let token_content = match request.token_type.as_str() {
            "urn:oasis:names:tc:SAML:2.0:assertion" => {
                self.issue_saml_token(auth_context, &request, &lifetime)?
            }
            "urn:ietf:params:oauth:token-type:jwt" => {
                self.issue_jwt_token(auth_context, &request, &lifetime)?
            }
            _ => {
                return Err(AuthError::auth_method("wstrust", "Unsupported token type"));
            }
        };

        // Generate proof token if required
        let proof_token = if self.config.include_proof_tokens
            && request.key_type.as_deref()
                == Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey")
        {
            Some(self.generate_proof_token()?)
        } else {
            None
        };

        // Store issued token
        let token_id = format!("token-{}", uuid::Uuid::new_v4());
        let issued_token = IssuedToken {
            token_id: token_id.clone(),
            token_type: request.token_type.clone(),
            token_content: token_content.clone(),
            issued_at: lifetime.created,
            expires_at: lifetime.expires,
            subject: auth_context.username.clone(),
            audience: request.applies_to.clone().unwrap_or_default(),
            proof_token: proof_token.clone(),
        };

        self.issued_tokens.insert(token_id.clone(), issued_token);

        Ok(RequestSecurityTokenResponse {
            request_type: request.request_type,
            token_type: request.token_type,
            lifetime,
            applies_to: request.applies_to,
            requested_security_token: token_content,
            requested_proof_token: proof_token,
            requested_attached_reference: Some(format!("#{}", token_id)),
            requested_unattached_reference: Some(token_id),
        })
    }

    /// Issue a SAML 2.0 assertion token
    fn issue_saml_token(
        &self,
        auth_context: &AuthenticationContext,
        request: &RequestSecurityToken,
        lifetime: &TokenLifetime,
    ) -> Result<String> {
        let mut assertion_builder = SamlAssertionBuilder::new(&self.config.issuer)
            .with_validity_period(lifetime.created, lifetime.expires)
            .with_attribute("username", &auth_context.username)
            .with_attribute("auth_method", &auth_context.auth_method);

        // Add audience if specified
        if let Some(ref audience) = request.applies_to {
            assertion_builder = assertion_builder.with_audience(audience);
        }

        // Add additional claims as attributes
        for (key, value) in &auth_context.claims {
            assertion_builder = assertion_builder.with_attribute(key, value);
        }

        let assertion = assertion_builder.build();
        assertion.to_xml()
    }

    /// Issue a JWT token signed with HMAC-HS256 using `StsConfig::jwt_signing_secret`.
    fn issue_jwt_token(
        &self,
        auth_context: &AuthenticationContext,
        request: &RequestSecurityToken,
        lifetime: &TokenLifetime,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct WsTrustClaims<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
            auth_method: &'a str,
            #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
            claims: &'a HashMap<String, String>,
        }

        let jwt_claims = WsTrustClaims {
            iss: &self.config.issuer,
            sub: &auth_context.username,
            aud: request.applies_to.as_deref().unwrap_or(""),
            iat: lifetime.created.timestamp(),
            exp: lifetime.expires.timestamp(),
            auth_method: &auth_context.auth_method,
            claims: &auth_context.claims,
        };

        let encoding_key = EncodingKey::from_secret(self.config.jwt_signing_secret.as_bytes());

        jwt_encode(&Header::new(Algorithm::HS256), &jwt_claims, &encoding_key)
            .map_err(|e| AuthError::internal(format!("WS-Trust JWT signing failed: {e}")))
    }

    /// Generate a proof token for holder-of-key scenarios
    fn generate_proof_token(&self) -> Result<ProofToken> {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut key_material = vec![0u8; 32]; // 256-bit symmetric key
        rng.fill_bytes(&mut key_material);

        Ok(ProofToken {
            token_type: "SymmetricKey".to_string(),
            key_material,
            key_identifier: format!("key-{}", uuid::Uuid::new_v4()),
        })
    }

    /// Renew an existing token
    fn renew_token(
        &mut self,
        request: RequestSecurityToken,
    ) -> Result<RequestSecurityTokenResponse> {
        let existing_token = request.existing_token.ok_or_else(|| {
            AuthError::auth_method("wstrust", "Existing token required for renewal")
        })?;

        // Find the token — try direct lookup first, then attempt JWT parsing
        // to extract claims from the existing token if it looks like a JWT.
        let mut renewal_claims = HashMap::new();
        let token_id = if existing_token.matches('.').count() == 2 {
            // Token looks like a JWT — extract claims from payload
            if let Some(payload_b64) = existing_token.split('.').nth(1) {
                if let Ok(payload_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload_b64)
                    .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_b64))
                {
                    if let Ok(claims) =
                        serde_json::from_slice::<HashMap<String, serde_json::Value>>(&payload_bytes)
                    {
                        for (k, v) in &claims {
                            if let Some(s) = v.as_str() {
                                renewal_claims.insert(k.clone(), s.to_string());
                            }
                        }
                        // Use "jti" or "sub" as token ID for lookup
                        claims
                            .get("jti")
                            .or_else(|| claims.get("sub"))
                            .and_then(|v| v.as_str())
                            .unwrap_or(&existing_token)
                            .to_string()
                    } else {
                        existing_token.clone()
                    }
                } else {
                    existing_token.clone()
                }
            } else {
                existing_token.clone()
            }
        } else {
            existing_token.clone()
        };

        let issued_token = self
            .issued_tokens
            .get(&token_id)
            .ok_or_else(|| AuthError::auth_method("wstrust", "Token not found"))?;

        // Check if token is still valid
        let now = Utc::now();
        if now >= issued_token.expires_at {
            return Err(AuthError::auth_method("wstrust", "Token has expired"));
        }

        // Create renewed token with new lifetime
        let new_lifetime = TokenLifetime {
            created: now,
            expires: now + self.config.default_token_lifetime,
        };

        // Issue new token (carry forward original claims where available)
        let auth_context = AuthenticationContext {
            username: issued_token.subject.clone(),
            auth_method: "token_renewal".to_string(),
            claims: if renewal_claims.is_empty() {
                HashMap::new()
            } else {
                renewal_claims
            },
        };

        let new_request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: issued_token.token_type.clone(),
            applies_to: Some(issued_token.audience.clone()),
            lifetime: Some(new_lifetime.clone()),
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        self.issue_token(new_request)
    }

    /// Cancel an existing token
    fn cancel_token(
        &mut self,
        request: RequestSecurityToken,
    ) -> Result<RequestSecurityTokenResponse> {
        let existing_token = request
            .existing_token
            .ok_or_else(|| AuthError::auth_method("wstrust", "Token required for cancellation"))?;

        // Remove token from cache
        self.issued_tokens.remove(&existing_token);

        Ok(RequestSecurityTokenResponse {
            request_type: request.request_type,
            token_type: "Cancelled".to_string(),
            lifetime: TokenLifetime {
                created: Utc::now(),
                expires: Utc::now(),
            },
            applies_to: None,
            requested_security_token: "Token cancelled".to_string(),
            requested_proof_token: None,
            requested_attached_reference: None,
            requested_unattached_reference: None,
        })
    }

    /// Validate an existing token
    fn validate_token(
        &self,
        request: RequestSecurityToken,
    ) -> Result<RequestSecurityTokenResponse> {
        let existing_token = request
            .existing_token
            .ok_or_else(|| AuthError::auth_method("wstrust", "Token required for validation"))?;

        // Find and validate token
        let token_id = existing_token;
        let issued_token = self
            .issued_tokens
            .get(&token_id)
            .ok_or_else(|| AuthError::auth_method("wstrust", "Token not found"))?;

        let now = Utc::now();
        let is_valid = now < issued_token.expires_at;

        let status = if is_valid { "Valid" } else { "Invalid" };

        Ok(RequestSecurityTokenResponse {
            request_type: request.request_type,
            token_type: "ValidationResponse".to_string(),
            lifetime: TokenLifetime {
                created: issued_token.issued_at,
                expires: issued_token.expires_at,
            },
            applies_to: Some(issued_token.audience.clone()),
            requested_security_token: status.to_string(),
            requested_proof_token: None,
            requested_attached_reference: None,
            requested_unattached_reference: None,
        })
    }

    /// Create a complete WS-Trust SOAP request
    pub fn create_rst_soap_request(
        &self,
        request: &RequestSecurityToken,
        username: &str,
        password: Option<&str>,
    ) -> Result<String> {
        let header = self.ws_security.create_username_token_header(
            username,
            password,
            PasswordType::PasswordText,
        )?;

        let security_header = self.ws_security.header_to_xml(&header)?;

        let soap_request = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
               xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
    <soap:Header>
        {}
    </soap:Header>
    <soap:Body>
        <wst:RequestSecurityToken>
            <wst:RequestType>{}</wst:RequestType>
            <wst:TokenType>{}</wst:TokenType>
            {}
            {}
            {}
        </wst:RequestSecurityToken>
    </soap:Body>
</soap:Envelope>"#,
            security_header,
            request.request_type,
            request.token_type,
            request.applies_to.as_ref().map(|a| format!("<wsp:AppliesTo><wsp:EndpointReference><wsp:Address>{}</wsp:Address></wsp:EndpointReference></wsp:AppliesTo>", a)).unwrap_or_default(),
            request.lifetime.as_ref().map(|l| format!("<wst:Lifetime><wsu:Created>{}</wsu:Created><wsu:Expires>{}</wsu:Expires></wst:Lifetime>",
                l.created.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                l.expires.format("%Y-%m-%dT%H:%M:%S%.3fZ"))).unwrap_or_default(),
            request.key_type.as_ref().map(|k| format!("<wst:KeyType>{}</wst:KeyType>", k)).unwrap_or_default()
        );

        Ok(soap_request)
    }
}

impl Default for StsConfig {
    fn default() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        // SAFETY: CSPRNG failure at initialization is terminal; the framework
        // cannot operate without entropy.
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .expect("AuthFramework fatal: system CSPRNG unavailable — the operating system cannot provide cryptographic randomness");
        let jwt_signing_secret = bytes.iter().fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });

        Self {
            issuer: "https://sts.example.com".to_string(),
            default_token_lifetime: Duration::hours(1),
            max_token_lifetime: Duration::hours(8),
            supported_token_types: vec![
                "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
                "urn:ietf:params:oauth:token-type:jwt".to_string(),
            ],
            endpoint_url: "https://sts.example.com/trust".to_string(),
            include_proof_tokens: false,
            trust_relationships: Vec::new(),
            jwt_signing_secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sts_issue_saml_token() {
        let config = StsConfig::default();
        let mut sts = SecurityTokenService::new(config);

        let auth_context = AuthenticationContext {
            username: "testuser".to_string(),
            auth_method: "password".to_string(),
            claims: {
                let mut claims = HashMap::new();
                claims.insert("role".to_string(), "admin".to_string());
                claims
            },
        };

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some("https://rp.example.com".to_string()),
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        let response = sts.process_request(request).unwrap();

        assert_eq!(response.token_type, "urn:oasis:names:tc:SAML:2.0:assertion");
        assert!(
            response
                .requested_security_token
                .contains("<saml:Assertion")
        );
        assert!(response.requested_security_token.contains("testuser"));
    }

    #[test]
    fn test_sts_issue_jwt_token() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode as jwt_decode};

        let config = StsConfig::default();
        let signing_secret = config.jwt_signing_secret.clone();
        let mut sts = SecurityTokenService::new(config);

        let auth_context = AuthenticationContext {
            username: "testuser".to_string(),
            auth_method: "certificate".to_string(),
            claims: HashMap::new(),
        };

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            applies_to: Some("https://api.example.com".to_string()),
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(auth_context),
        };

        let response = sts.process_request(request).unwrap();

        assert_eq!(response.token_type, "urn:ietf:params:oauth:token-type:jwt");

        // Verify the issued JWT has exactly 3 Base64URL parts.
        let parts: Vec<&str> = response.requested_security_token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // Verify the signature is valid by decoding with the same secret.
        let decoding_key = DecodingKey::from_secret(signing_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["https://api.example.com"]);
        let token_data = jwt_decode::<serde_json::Value>(
            &response.requested_security_token,
            &decoding_key,
            &validation,
        )
        .expect("Issued WS-Trust JWT must be verifiable with the config signing secret");
        assert_eq!(token_data.claims["sub"], "testuser");
        assert_eq!(token_data.claims["auth_method"], "certificate");
    }

    #[test]
    fn test_sts_soap_request_generation() {
        let config = StsConfig::default();
        let sts = SecurityTokenService::new(config);

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: Some("https://rp.example.com".to_string()),
            lifetime: None,
            key_type: Some("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer".to_string()),
            key_size: None,
            existing_token: None,
            auth_context: None,
        };

        let soap_request = sts
            .create_rst_soap_request(&request, "test_user", Some("test_pass"))
            .unwrap();

        assert!(soap_request.contains("<soap:Envelope"));
        assert!(soap_request.contains("<wsse:Security"));
        assert!(soap_request.contains("<wst:RequestSecurityToken"));
        assert!(soap_request.contains("https://rp.example.com"));
        assert!(soap_request.contains("</soap:Envelope>"));
    }

    #[test]
    fn test_unsupported_request_type() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://invalid/BadRequest".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: None,
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Unsupported request type"), "got: {msg}");
    }

    #[test]
    fn test_issue_missing_auth_context() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: None,
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Authentication context required"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_issue_unsupported_token_type() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:unknown:token:type".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(AuthenticationContext {
                username: "user".to_string(),
                auth_method: "password".to_string(),
                claims: HashMap::new(),
            }),
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Unsupported token type"), "got: {msg}");
    }

    #[test]
    fn test_lifetime_clamped_to_max() {
        let config = StsConfig {
            max_token_lifetime: Duration::hours(2),
            ..Default::default()
        };
        let mut sts = SecurityTokenService::new(config);

        let now = Utc::now();
        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            applies_to: Some("https://rp.example.com".to_string()),
            lifetime: Some(TokenLifetime {
                created: now,
                expires: now + Duration::hours(999), // way beyond max
            }),
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(AuthenticationContext {
                username: "user".to_string(),
                auth_method: "password".to_string(),
                claims: HashMap::new(),
            }),
        };

        let resp = sts.process_request(request).unwrap();
        // Expires must be clamped to ~2 h from now, not 999 h
        let delta = resp.lifetime.expires - now;
        assert!(
            delta <= Duration::hours(2) + Duration::seconds(5),
            "lifetime should be clamped to max_token_lifetime, got {delta}"
        );
    }

    #[test]
    fn test_cancel_nonexistent_token() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some("nonexistent-id".to_string()),
            auth_context: None,
        };

        // Cancel of a non-existent token should succeed silently (idempotent)
        let resp = sts.process_request(request).unwrap();
        assert_eq!(resp.requested_security_token, "Token cancelled");
    }

    #[test]
    fn test_cancel_missing_existing_token_field() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None, // missing
            auth_context: None,
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Token required for cancellation"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_validate_nonexistent_token() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some("does-not-exist".to_string()),
            auth_context: None,
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Token not found"), "got: {msg}");
    }

    #[test]
    fn test_renew_missing_existing_token() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None, // missing
            auth_context: None,
        };

        let err = sts.process_request(request).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Existing token required for renewal"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_issue_with_proof_token_symmetric_key() {
        let config = StsConfig {
            include_proof_tokens: true,
            ..Default::default()
        };
        let mut sts = SecurityTokenService::new(config);

        let request = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            applies_to: Some("https://rp.example.com".to_string()),
            lifetime: None,
            key_type: Some(
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey".to_string(),
            ),
            key_size: None,
            existing_token: None,
            auth_context: Some(AuthenticationContext {
                username: "keyuser".to_string(),
                auth_method: "certificate".to_string(),
                claims: HashMap::new(),
            }),
        };

        let resp = sts.process_request(request).unwrap();
        let proof = resp
            .requested_proof_token
            .expect("proof token should be present for symmetric key request");
        assert_eq!(proof.token_type, "SymmetricKey");
        assert_eq!(proof.key_material.len(), 32); // 256-bit key
        assert!(proof.key_identifier.starts_with("key-"));
    }

    #[test]
    fn test_issue_and_validate_roundtrip() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        // Issue
        let issue_req = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:ietf:params:oauth:token-type:jwt".to_string(),
            applies_to: Some("https://rp.example.com".to_string()),
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(AuthenticationContext {
                username: "roundtrip_user".to_string(),
                auth_method: "password".to_string(),
                claims: HashMap::new(),
            }),
        };

        let issue_resp = sts.process_request(issue_req).unwrap();
        let token_id = issue_resp
            .requested_unattached_reference
            .expect("token id should be returned");

        // Validate
        let validate_req = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_id),
            auth_context: None,
        };

        let validate_resp = sts.process_request(validate_req).unwrap();
        assert_eq!(validate_resp.requested_security_token, "Valid");
        assert_eq!(
            validate_resp.applies_to.as_deref(),
            Some("https://rp.example.com")
        );
    }

    #[test]
    fn test_issue_and_cancel_then_validate_fails() {
        let mut sts = SecurityTokenService::new(StsConfig::default());

        // Issue
        let issue_req = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue".to_string(),
            token_type: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: None,
            auth_context: Some(AuthenticationContext {
                username: "cancelme".to_string(),
                auth_method: "password".to_string(),
                claims: HashMap::new(),
            }),
        };

        let issue_resp = sts.process_request(issue_req).unwrap();
        let token_id = issue_resp
            .requested_unattached_reference
            .expect("should have token id");

        // Cancel
        let cancel_req = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_id.clone()),
            auth_context: None,
        };
        sts.process_request(cancel_req).unwrap();

        // Validate should now fail (token was removed)
        let validate_req = RequestSecurityToken {
            request_type: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate".to_string(),
            token_type: "".to_string(),
            applies_to: None,
            lifetime: None,
            key_type: None,
            key_size: None,
            existing_token: Some(token_id),
            auth_context: None,
        };

        let err = sts.process_request(validate_req).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Token not found"), "got: {msg}");
    }
}
