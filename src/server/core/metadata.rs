//! OAuth 2.0 Authorization Server Metadata (RFC 8414)
//!
//! This module implements RFC 8414, which defines a mechanism for clients
//! to obtain configuration details about an OAuth 2.0 authorization server.

use crate::errors::{AuthError, Result};
// use crate::server::oauth2::OAuth2Server;
// use crate::server::oauth21::OAuth21Server;
use crate::oauth2_server::OAuth2Server; // Use the new OAuth2Server
use serde::{Deserialize, Serialize};
// use std::collections::HashSet;

/// OAuth 2.0 Authorization Server Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier
    pub issuer: String,

    /// URL of the authorization server's authorization endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,

    /// URL of the authorization server's token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// URL of the authorization server's JWK Set document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// URL of the authorization server's registration endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// List of scope values supported by the authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// List of response type values supported by the authorization server
    pub response_types_supported: Vec<String>,

    /// List of response mode values supported by the authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,

    /// List of grant type values supported by the authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    /// List of client authentication methods supported by the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// List of client authentication methods supported by the revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// List of client authentication methods supported by the introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// List of PKCE code challenge methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// URL of the authorization server's revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// URL of the authorization server's introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// Boolean value indicating whether the authorization server provides the iss parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_response_iss_parameter_supported: Option<bool>,

    // RFC 9126 - Pushed Authorization Requests
    /// URL of the pushed authorization request endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<String>,

    /// Whether PAR is required for this authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,

    // RFC 8628 - Device Authorization Grant
    /// URL of the device authorization endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    // RFC 9449 - DPoP
    /// List of algorithms supported for DPoP proof JWTs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    // RFC 8705 - Mutual TLS
    /// URL of the authorization server's token endpoint for mutual TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,

    /// List of client certificate types supported for mutual TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    // OpenID Connect Discovery (if applicable)
    /// URL of the authorization server's UserInfo endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// List of subject identifier types supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_types_supported: Option<Vec<String>>,

    /// List of JWS signing algorithms supported for ID tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,

    /// List of JWE encryption algorithms supported for ID tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,

    /// List of JWE encryption methods supported for ID tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,

    /// List of claim names supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    /// Whether claims parameter is supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,

    /// Whether request parameter is supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,

    /// Whether request_uri parameter is supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,
}

/// Mutual TLS endpoint aliases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsEndpointAliases {
    /// Token endpoint for mutual TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// Revocation endpoint for mutual TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// Introspection endpoint for mutual TLS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
}

/// Authorization Server Metadata Builder
pub struct MetadataBuilder {
    metadata: AuthorizationServerMetadata,
}

impl MetadataBuilder {
    /// Create a new metadata builder
    pub fn new(issuer: String) -> Self {
        Self {
            metadata: AuthorizationServerMetadata {
                issuer,
                authorization_endpoint: None,
                token_endpoint: None,
                jwks_uri: None,
                registration_endpoint: None,
                scopes_supported: None,
                response_types_supported: vec!["code".to_string()],
                response_modes_supported: None,
                grant_types_supported: None,
                token_endpoint_auth_methods_supported: None,
                revocation_endpoint_auth_methods_supported: None,
                introspection_endpoint_auth_methods_supported: None,
                code_challenge_methods_supported: None,
                revocation_endpoint: None,
                introspection_endpoint: None,
                authorization_response_iss_parameter_supported: None,
                pushed_authorization_request_endpoint: None,
                require_pushed_authorization_requests: None,
                device_authorization_endpoint: None,
                dpop_signing_alg_values_supported: None,
                mtls_endpoint_aliases: None,
                tls_client_certificate_bound_access_tokens: None,
                userinfo_endpoint: None,
                subject_types_supported: None,
                id_token_signing_alg_values_supported: None,
                id_token_encryption_alg_values_supported: None,
                id_token_encryption_enc_values_supported: None,
                claims_supported: None,
                claims_parameter_supported: None,
                request_parameter_supported: None,
                request_uri_parameter_supported: None,
            },
        }
    }

    /// Set authorization endpoint
    pub fn authorization_endpoint(mut self, endpoint: String) -> Self {
        self.metadata.authorization_endpoint = Some(endpoint);
        self
    }

    /// Set token endpoint
    pub fn token_endpoint(mut self, endpoint: String) -> Self {
        self.metadata.token_endpoint = Some(endpoint);
        self
    }

    /// Set JWK Set URI
    pub fn jwks_uri(mut self, uri: String) -> Self {
        self.metadata.jwks_uri = Some(uri);
        self
    }

    /// Set supported scopes
    pub fn scopes_supported(mut self, scopes: Vec<String>) -> Self {
        self.metadata.scopes_supported = Some(scopes);
        self
    }

    /// Set supported response types
    pub fn response_types_supported(mut self, response_types: Vec<String>) -> Self {
        self.metadata.response_types_supported = response_types;
        self
    }

    /// Set supported grant types
    pub fn grant_types_supported(mut self, grant_types: Vec<String>) -> Self {
        self.metadata.grant_types_supported = Some(grant_types);
        self
    }

    /// Set supported token endpoint authentication methods
    pub fn token_endpoint_auth_methods_supported(mut self, methods: Vec<String>) -> Self {
        self.metadata.token_endpoint_auth_methods_supported = Some(methods);
        self
    }

    /// Set supported PKCE code challenge methods
    pub fn code_challenge_methods_supported(mut self, methods: Vec<String>) -> Self {
        self.metadata.code_challenge_methods_supported = Some(methods);
        self
    }

    /// Set revocation endpoint
    pub fn revocation_endpoint(mut self, endpoint: String) -> Self {
        self.metadata.revocation_endpoint = Some(endpoint);
        self
    }

    /// Set introspection endpoint
    pub fn introspection_endpoint(mut self, endpoint: String) -> Self {
        self.metadata.introspection_endpoint = Some(endpoint);
        self
    }

    /// Enable PAR (Pushed Authorization Requests)
    pub fn enable_par(mut self, endpoint: String, required: bool) -> Self {
        self.metadata.pushed_authorization_request_endpoint = Some(endpoint);
        self.metadata.require_pushed_authorization_requests = Some(required);
        self
    }

    /// Set device authorization endpoint
    pub fn device_authorization_endpoint(mut self, endpoint: String) -> Self {
        self.metadata.device_authorization_endpoint = Some(endpoint);
        self
    }

    /// Enable DPoP support
    pub fn enable_dpop(mut self, signing_algorithms: Vec<String>) -> Self {
        self.metadata.dpop_signing_alg_values_supported = Some(signing_algorithms);
        self
    }

    /// Enable Mutual TLS support
    pub fn enable_mtls(
        mut self,
        mtls_endpoints: MtlsEndpointAliases,
        certificate_bound_tokens: bool,
    ) -> Self {
        self.metadata.mtls_endpoint_aliases = Some(mtls_endpoints);
        self.metadata.tls_client_certificate_bound_access_tokens = Some(certificate_bound_tokens);
        self
    }

    /// Enable OpenID Connect support
    pub fn enable_openid_connect(
        mut self,
        userinfo_endpoint: String,
        subject_types: Vec<String>,
        id_token_signing_algs: Vec<String>,
    ) -> Self {
        self.metadata.userinfo_endpoint = Some(userinfo_endpoint);
        self.metadata.subject_types_supported = Some(subject_types);
        self.metadata.id_token_signing_alg_values_supported = Some(id_token_signing_algs);
        self
    }

    /// Build the metadata
    pub fn build(self) -> AuthorizationServerMetadata {
        self.metadata
    }
}

/// Authorization Server Metadata Provider
pub struct MetadataProvider {
    metadata: AuthorizationServerMetadata,
}

impl MetadataProvider {
    /// Create a new metadata provider
    pub fn new(metadata: AuthorizationServerMetadata) -> Self {
        Self { metadata }
    }

    /// Create metadata from OAuth 2.0 server configuration
    pub fn from_oauth2_server(_server: &OAuth2Server, base_url: &str) -> Result<Self> {
        let mut builder = MetadataBuilder::new(base_url.to_string())
            .authorization_endpoint(format!("{}/oauth2/authorize", base_url))
            .token_endpoint(format!("{}/oauth2/token", base_url))
            .jwks_uri(format!("{}/.well-known/jwks.json", base_url))
            .response_types_supported(vec!["code".to_string()])
            .grant_types_supported(vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ])
            .token_endpoint_auth_methods_supported(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ])
            .code_challenge_methods_supported(vec!["S256".to_string(), "plain".to_string()])
            .revocation_endpoint(format!("{}/oauth2/revoke", base_url))
            .introspection_endpoint(format!("{}/oauth2/introspect", base_url))
            .scopes_supported(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "address".to_string(),
                "phone".to_string(),
            ]);

        // Add device authorization if supported
        builder = builder
            .device_authorization_endpoint(format!("{}/oauth2/device_authorization", base_url));

        // Add PAR if supported
        builder = builder.enable_par(format!("{}/oauth2/par", base_url), false);

        // Add DPoP if supported
        builder = builder.enable_dpop(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "ES512".to_string(),
            "RS256".to_string(),
        ]);

        // Add Mutual TLS if supported
        let mtls_endpoints = MtlsEndpointAliases {
            token_endpoint: Some(format!("{}/oauth2/token", base_url)),
            revocation_endpoint: Some(format!("{}/oauth2/revoke", base_url)),
            introspection_endpoint: Some(format!("{}/oauth2/introspect", base_url)),
        };
        builder = builder.enable_mtls(mtls_endpoints, true);

        Ok(Self::new(builder.build()))
    }

    /// Create metadata from OAuth 2.1 server configuration
    pub fn from_oauth21_server(_server: &OAuth2Server, base_url: &str) -> Result<Self> {
        // OAuth 2.1 uses the same base server but with enhanced security
        let mut builder = MetadataBuilder::new(base_url.to_string())
            .authorization_endpoint(format!("{}/oauth2/authorize", base_url))
            .token_endpoint(format!("{}/oauth2/token", base_url))
            .jwks_uri(format!("{}/.well-known/jwks.json", base_url))
            .response_types_supported(vec!["code".to_string()]) // Only code in OAuth 2.1
            .grant_types_supported(vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ])
            .token_endpoint_auth_methods_supported(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "tls_client_auth".to_string(),
                "self_signed_tls_client_auth".to_string(),
            ])
            .code_challenge_methods_supported(vec!["S256".to_string()]) // Only S256 in OAuth 2.1
            .revocation_endpoint(format!("{}/oauth2/revoke", base_url))
            .introspection_endpoint(format!("{}/oauth2/introspect", base_url))
            .scopes_supported(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]);

        // PAR is recommended in OAuth 2.1
        builder = builder.enable_par(format!("{}/oauth2/par", base_url), true);

        // DPoP is recommended in OAuth 2.1
        builder = builder.enable_dpop(vec![
            "ES256".to_string(),
            "ES384".to_string(),
            "ES512".to_string(),
        ]);

        // Add Mutual TLS if supported
        let mtls_endpoints = MtlsEndpointAliases {
            token_endpoint: Some(format!("{}/oauth2/token", base_url)),
            revocation_endpoint: Some(format!("{}/oauth2/revoke", base_url)),
            introspection_endpoint: Some(format!("{}/oauth2/introspect", base_url)),
        };
        builder = builder.enable_mtls(mtls_endpoints, true);

        Ok(Self::new(builder.build()))
    }

    /// Get the authorization server metadata
    pub fn get_metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// Get metadata as JSON
    pub fn get_metadata_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.metadata).map_err(|e| {
            AuthError::auth_method("metadata", format!("Failed to serialize metadata: {}", e))
        })
    }

    /// Validate metadata completeness
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Required fields validation
        if self.metadata.issuer.is_empty() {
            errors.push("Issuer is required");
        }

        if self.metadata.response_types_supported.is_empty() {
            errors.push("At least one response type must be supported");
        }

        // Validate URLs
        let endpoints = [
            &self.metadata.authorization_endpoint,
            &self.metadata.token_endpoint,
            &self.metadata.jwks_uri,
            &self.metadata.revocation_endpoint,
            &self.metadata.introspection_endpoint,
        ];

        for endpoint in endpoints.iter().filter_map(|ep| ep.as_ref()) {
            if url::Url::parse(endpoint).is_err() {
                errors.push("Invalid endpoint URL format");
            }
        }

        // OAuth 2.1 specific validations
        if self
            .metadata
            .code_challenge_methods_supported
            .as_ref()
            .is_some_and(|methods| methods.len() == 1 && methods[0] == "S256")
        {
            // This looks like OAuth 2.1, validate accordingly
            if self.metadata.response_types_supported.len() != 1
                || self.metadata.response_types_supported[0] != "code"
            {
                errors.push("OAuth 2.1 must only support 'code' response type");
            }
        }

        if !errors.is_empty() {
            return Err(AuthError::auth_method("metadata", errors.join(", ")));
        }

        Ok(())
    }

    /// Update metadata field
    pub fn update_metadata<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut AuthorizationServerMetadata),
    {
        updater(&mut self.metadata);
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_builder() {
        let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
            .authorization_endpoint("https://auth.example.com/oauth2/authorize".to_string())
            .token_endpoint("https://auth.example.com/oauth2/token".to_string())
            .grant_types_supported(vec!["authorization_code".to_string()])
            .code_challenge_methods_supported(vec!["S256".to_string()])
            .build();

        assert_eq!(metadata.issuer, "https://auth.example.com");
        assert_eq!(
            metadata.authorization_endpoint,
            Some("https://auth.example.com/oauth2/authorize".to_string())
        );
        assert_eq!(
            metadata.grant_types_supported,
            Some(vec!["authorization_code".to_string()])
        );
    }

    #[test]
    fn test_metadata_provider() {
        let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
            .authorization_endpoint("https://auth.example.com/oauth2/authorize".to_string())
            .token_endpoint("https://auth.example.com/oauth2/token".to_string())
            .build();

        let provider = MetadataProvider::new(metadata);
        let json = provider.get_metadata_json().unwrap();

        assert!(json.contains("https://auth.example.com"));
        assert!(json.contains("authorization_endpoint"));
    }

    #[test]
    fn test_metadata_validation() {
        let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
            .authorization_endpoint("https://auth.example.com/oauth2/authorize".to_string())
            .token_endpoint("https://auth.example.com/oauth2/token".to_string())
            .build();

        let provider = MetadataProvider::new(metadata);
        provider.validate().unwrap();
    }

    #[test]
    fn test_oauth21_specific_metadata() {
        let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
            .response_types_supported(vec!["code".to_string()])
            .code_challenge_methods_supported(vec!["S256".to_string()])
            .enable_par("https://auth.example.com/oauth2/par".to_string(), true)
            .enable_dpop(vec!["ES256".to_string()])
            .build();

        let provider = MetadataProvider::new(metadata);
        provider.validate().unwrap();

        let metadata = provider.get_metadata();
        assert_eq!(metadata.require_pushed_authorization_requests, Some(true));
        assert!(metadata.dpop_signing_alg_values_supported.is_some());
    }

    #[test]
    fn test_mtls_metadata() {
        let mtls_endpoints = MtlsEndpointAliases {
            token_endpoint: Some("https://mtls.auth.example.com/oauth2/token".to_string()),
            revocation_endpoint: Some("https://mtls.auth.example.com/oauth2/revoke".to_string()),
            introspection_endpoint: Some(
                "https://mtls.auth.example.com/oauth2/introspect".to_string(),
            ),
        };

        let metadata = MetadataBuilder::new("https://auth.example.com".to_string())
            .enable_mtls(mtls_endpoints, true)
            .build();

        assert!(metadata.mtls_endpoint_aliases.is_some());
        assert_eq!(
            metadata.tls_client_certificate_bound_access_tokens,
            Some(true)
        );
    }
}
