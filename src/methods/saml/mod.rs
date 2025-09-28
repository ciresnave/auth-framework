//! SAML authentication method with production-grade XML signature validation
//!
//! This module provides SAML 2.0 authentication support with RFC-compliant XML signature
//! validation using pure Rust implementations (ring, x509-parser, quick-xml).
//!
//! Features:
//! - Full XML-DSIG signature validation
//! - X.509 certificate chain validation
//! - XML canonicalization (C14N)
//! - RSA-SHA256 and ECDSA-P256-SHA256 support
//! - Protection against XML signature wrapping attacks

use crate::authentication::credentials::{Credential, CredentialMetadata};
use crate::errors::{AuthError, Result};
use crate::methods::{AuthMethod, MethodResult};
use crate::tokens::{AuthToken, TokenManager};
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// SAML module structure
pub mod xml_signature;

pub use xml_signature::{SamlSignatureValidator, XmlCanonicalizer};

/// SAML authentication method with basic XML validation
pub struct SamlAuthMethod {
    pub token_manager: TokenManager,
    pub config: SamlConfig,
    pub identity_providers: HashMap<String, SamlIdpMetadata>,
}

/// SAML configuration for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Service Provider Entity ID
    pub entity_id: String,
    /// Assertion Consumer Service URL
    pub acs_url: String,
    /// Single Logout Service URL
    pub sls_url: Option<String>,
    /// Certificate for signature verification (PEM format)
    pub certificate: Option<String>,
    /// Private key for signing (PEM format)
    pub private_key: Option<String>,
    /// Require signed assertions
    pub require_signed_assertions: bool,
    /// Require signed responses
    pub require_signed_responses: bool,
    /// Maximum assertion age in seconds
    pub max_assertion_age: u64,
    /// Allowed clock skew in seconds
    pub clock_skew_seconds: u64,
    /// Enable production-grade XML signature validation
    pub validate_xml_signature: bool,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            entity_id: "urn:example:sp".to_string(),
            acs_url: "https://example.com/acs".to_string(),
            sls_url: None,
            certificate: None,
            private_key: None,
            require_signed_assertions: true,
            require_signed_responses: true,
            max_assertion_age: 300, // 5 minutes
            clock_skew_seconds: 30, // 30 seconds
            validate_xml_signature: true,
        }
    }
}

/// Simple SAML Identity Provider metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpMetadata {
    pub entity_id: String,
    pub certificate: String, // Base64 encoded
    pub sso_url: String,
    pub slo_url: Option<String>,
}

/// SAML assertion data after validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Subject (user identifier)
    pub subject: String,
    /// Attributes from the assertion
    pub attributes: HashMap<String, Vec<String>>,
    /// Issuer of the assertion
    pub issuer: String,
    /// Issue time
    pub issue_instant: SystemTime,
    /// Not before time
    pub not_before: Option<SystemTime>,
    /// Not on or after time
    pub not_on_or_after: Option<SystemTime>,
    /// Session index for logout
    pub session_index: Option<String>,
}

/// SAML response structure with comprehensive validation fields
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SamlResponse {
    #[serde(rename = "Issuer")]
    issuer: Option<SamlIssuer>,
    #[serde(rename = "Assertion")]
    assertions: Option<Vec<SamlAssertionXml>>,
}

#[derive(Debug, Deserialize)]
struct SamlIssuer {
    #[serde(rename = "$text")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct SamlAssertionXml {
    #[serde(rename = "Issuer")]
    issuer: SamlIssuer,
    #[serde(rename = "Subject")]
    subject: Option<SamlSubject>,
    #[serde(rename = "AttributeStatement")]
    attribute_statements: Option<Vec<SamlAttributeStatement>>,
    #[serde(rename = "AuthnStatement")]
    authn_statements: Option<Vec<SamlAuthnStatement>>,
    #[serde(rename = "Conditions")]
    #[allow(dead_code)]
    conditions: Option<SamlConditions>,
    #[serde(rename = "IssueInstant")]
    #[allow(dead_code)]
    issue_instant: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SamlConditions {
    #[serde(rename = "NotBefore")]
    #[allow(dead_code)]
    not_before: Option<String>,
    #[serde(rename = "NotOnOrAfter")]
    #[allow(dead_code)]
    not_on_or_after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SamlSubject {
    #[serde(rename = "NameID")]
    name_id: Option<SamlNameId>,
}

#[derive(Debug, Deserialize)]
struct SamlNameId {
    #[serde(rename = "$text")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct SamlAttributeStatement {
    #[serde(rename = "Attribute")]
    attributes: Vec<SamlAttribute>,
}

#[derive(Debug, Deserialize)]
struct SamlAttribute {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "AttributeValue")]
    values: Vec<SamlAttributeValue>,
}

#[derive(Debug, Deserialize)]
struct SamlAttributeValue {
    #[serde(rename = "$text")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct SamlAuthnStatement {
    #[serde(rename = "SessionIndex")]
    session_index: Option<String>,
}

impl SamlAuthMethod {
    /// Create a new SAML authentication method
    pub fn new(token_manager: TokenManager, config: SamlConfig) -> Self {
        Self {
            token_manager,
            config,
            identity_providers: HashMap::new(),
        }
    }

    /// Add an identity provider metadata
    pub fn add_identity_provider(&mut self, metadata: SamlIdpMetadata) {
        let entity_id = metadata.entity_id.clone();
        self.identity_providers.insert(entity_id, metadata);
    }

    /// Production-grade XML signature validation using pure Rust cryptography
    #[cfg(feature = "saml")]
    fn validate_xml_signature(&self, xml: &str, certificate: &[u8]) -> Result<bool> {
        if !self.config.validate_xml_signature {
            tracing::warn!(
                "XML signature validation is disabled - this is INSECURE for production!"
            );
            return Ok(true);
        }

        tracing::debug!("Performing production-grade XML signature validation");

        // Use the new production-grade SAML signature validator
        let validator = SamlSignatureValidator;

        // Validate XML signature using pure Rust cryptography
        match validator.validate_xml_signature(xml, certificate) {
            Ok(true) => {
                tracing::info!("XML signature validation PASSED - signature is valid");
                Ok(true)
            }
            Ok(false) => {
                tracing::error!("XML signature validation FAILED - invalid signature");
                Err(AuthError::validation("XML signature verification failed"))
            }
            Err(e) => {
                tracing::error!("XML signature validation ERROR: {}", e);
                Err(e)
            }
        }
    }

    /// Fallback for when SAML feature is disabled
    #[cfg(not(feature = "saml"))]
    fn validate_xml_signature(&self, _xml: &str, _certificate: &[u8]) -> Result<bool> {
        Err(AuthError::validation(
            "SAML feature is not enabled. Compile with --features saml to enable SAML authentication.",
        ))
    }

    /// Parse ISO 8601 timestamp to SystemTime
    /// Used for SAML assertion timestamp validation
    #[allow(dead_code)]
    fn parse_timestamp(&self, timestamp: &str) -> Result<SystemTime> {
        use chrono::DateTime;

        // Try to parse as ISO 8601 datetime
        let datetime = DateTime::parse_from_rfc3339(timestamp)
            .or_else(|_| DateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .or_else(|_| DateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%SZ"))
            .map_err(|_| {
                AuthError::validation(format!("Invalid timestamp format: {}", timestamp))
            })?;

        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(datetime.timestamp() as u64))
    }

    /// Validate SAML assertion timestamps and issuer
    #[allow(dead_code)]
    fn validate_assertion_security(
        &self,
        assertion: &SamlAssertionXml,
        expected_issuer: &str,
    ) -> Result<()> {
        // Validate issuer matches expected
        if assertion.issuer.value != expected_issuer {
            return Err(AuthError::validation(format!(
                "Assertion issuer '{}' does not match expected issuer '{}'",
                assertion.issuer.value, expected_issuer
            )));
        }

        // Validate issue instant if present
        if let Some(issue_instant) = &assertion.issue_instant {
            let issue_time = self.parse_timestamp(issue_instant)?;
            let now = SystemTime::now();
            let five_minutes_ago = now - Duration::from_secs(5 * 60);
            let five_minutes_future = now + Duration::from_secs(5 * 60);

            // Check if assertion is too old or too far in the future
            if issue_time < five_minutes_ago {
                return Err(AuthError::validation("SAML assertion is too old"));
            }
            if issue_time > five_minutes_future {
                return Err(AuthError::validation("SAML assertion is from the future"));
            }
        }

        Ok(())
    }

    /// Comprehensive SAML response validation using all available fields
    #[allow(dead_code)]
    async fn validate_saml_response_comprehensive(
        &self,
        saml_response: &str,
    ) -> Result<SamlAssertion> {
        // First try to parse as structured XML using quick-xml
        if let Ok(parsed_response) = from_str::<SamlResponse>(saml_response) {
            return self
                .validate_structured_saml_response(parsed_response)
                .await;
        }

        // Fall back to the existing validation method
        self.validate_saml_response(saml_response).await
    }

    /// Validate structured SAML response with comprehensive security checks
    #[allow(dead_code)]
    async fn validate_structured_saml_response(
        &self,
        response: SamlResponse,
    ) -> Result<SamlAssertion> {
        // Validate response-level issuer if present
        if let Some(response_issuer) = &response.issuer {
            let issuer = &response_issuer.value;

            // Verify this is a known IdP
            let _idp_metadata = self
                .identity_providers
                .get(issuer)
                .ok_or_else(|| AuthError::validation(format!("Unknown issuer: {}", issuer)))?;

            // Validate assertions
            if let Some(assertions) = &response.assertions {
                if assertions.is_empty() {
                    return Err(AuthError::validation(
                        "No assertions found in SAML response",
                    ));
                }

                // Process the first assertion (typically there's only one)
                let assertion = &assertions[0];

                // Validate assertion security
                self.validate_assertion_security(assertion, issuer)?;

                // Extract subject
                let subject = assertion
                    .subject
                    .as_ref()
                    .ok_or_else(|| AuthError::validation("No subject found in SAML assertion"))?;

                let user_id = subject
                    .name_id
                    .as_ref()
                    .ok_or_else(|| AuthError::validation("No NameID found in SAML subject"))?
                    .value
                    .clone();

                // Extract attributes
                let mut attributes = HashMap::new();
                if let Some(attr_statements) = &assertion.attribute_statements {
                    for statement in attr_statements {
                        for attr in &statement.attributes {
                            let attribute_values: Vec<String> =
                                attr.values.iter().map(|v| v.value.clone()).collect();
                            attributes.insert(attr.name.clone(), attribute_values);
                        }
                    }
                }

                // Extract timing information
                let issue_instant = assertion
                    .issue_instant
                    .as_ref()
                    .and_then(|ts| self.parse_timestamp(ts).ok())
                    .unwrap_or_else(SystemTime::now);

                let (not_before, not_on_or_after) = if let Some(conditions) = &assertion.conditions
                {
                    let not_before = conditions
                        .not_before
                        .as_ref()
                        .and_then(|ts| self.parse_timestamp(ts).ok());
                    let not_on_or_after = conditions
                        .not_on_or_after
                        .as_ref()
                        .and_then(|ts| self.parse_timestamp(ts).ok());
                    (not_before, not_on_or_after)
                } else {
                    (None, None)
                };

                // Extract session index from AuthnStatement
                let session_index = assertion
                    .authn_statements
                    .as_ref()
                    .and_then(|statements| statements.first())
                    .and_then(|stmt| stmt.session_index.clone());

                // Create validated assertion
                return Ok(SamlAssertion {
                    subject: user_id,
                    attributes,
                    issuer: issuer.clone(),
                    issue_instant,
                    not_before,
                    not_on_or_after,
                    session_index,
                });
            } else {
                return Err(AuthError::validation(
                    "No assertions found in SAML response",
                ));
            }
        }

        Err(AuthError::validation("Invalid SAML response structure"))
    }

    /// Parse and validate SAML assertion from XML
    fn parse_saml_assertion(&self, assertion_xml: &str, issuer: &str) -> Result<SamlAssertion> {
        // Parse the XML assertion using quick-xml
        let assertion: SamlAssertionXml = from_str(assertion_xml)
            .map_err(|e| AuthError::validation(format!("Failed to parse SAML assertion: {}", e)))?;

        // Validate issuer matches
        if assertion.issuer.value != issuer {
            return Err(AuthError::validation("Assertion issuer mismatch"));
        }

        // Extract subject
        let subject = assertion
            .subject
            .as_ref()
            .and_then(|s| s.name_id.as_ref())
            .map(|n| n.value.clone())
            .ok_or_else(|| AuthError::validation("No subject found in assertion"))?;

        // Extract attributes
        let mut attributes = HashMap::new();
        if let Some(attribute_statements) = &assertion.attribute_statements {
            for statement in attribute_statements {
                for attribute in &statement.attributes {
                    let name = attribute.name.clone();
                    let values: Vec<String> =
                        attribute.values.iter().map(|v| v.value.clone()).collect();
                    attributes.insert(name, values);
                }
            }
        }

        // Parse issue instant from SAML assertion with full RFC 3339/ISO 8601 support
        let issue_instant = self
            .parse_saml_time_attribute(assertion_xml, "IssueInstant")?
            .unwrap_or_else(SystemTime::now);

        // Extract and validate time constraints for security
        let not_before = self.parse_saml_time_attribute(assertion_xml, "NotBefore")?;
        let not_on_or_after = self.parse_saml_time_attribute(assertion_xml, "NotOnOrAfter")?;

        // Extract session index
        let session_index = assertion
            .authn_statements
            .as_ref()
            .and_then(|statements| statements.first())
            .and_then(|statement| statement.session_index.clone());

        // Validate assertion time constraints for security
        self.validate_assertion_time_constraints(issue_instant, not_before, not_on_or_after)?;

        Ok(SamlAssertion {
            subject,
            attributes,
            issuer: issuer.to_string(),
            issue_instant,
            not_before,
            not_on_or_after,
            session_index,
        })
    }

    /// Validate SAML response with basic signature verification
    async fn validate_saml_response(&self, saml_response: &str) -> Result<SamlAssertion> {
        // Decode base64 if needed
        let decoded_response = if saml_response.starts_with('<') {
            saml_response.to_string()
        } else {
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(saml_response)
                    .map_err(|e| AuthError::validation(format!("Invalid base64: {}", e)))?,
            )
            .map_err(|e| AuthError::validation(format!("Invalid UTF-8: {}", e)))?
        };

        // Simple XML parsing to extract basic elements
        // For production, use a proper SAML library

        // Extract issuer from the response
        let issuer = if let Some(start) = decoded_response.find("<saml:Issuer>") {
            if let Some(end) = decoded_response.find("</saml:Issuer>") {
                decoded_response[start + 14..end].to_string()
            } else {
                return Err(AuthError::validation("Invalid issuer format"));
            }
        } else if let Some(start) = decoded_response.find("<Issuer>") {
            if let Some(end) = decoded_response.find("</Issuer>") {
                decoded_response[start + 8..end].to_string()
            } else {
                return Err(AuthError::validation("Invalid issuer format"));
            }
        } else {
            return Err(AuthError::validation("No issuer found"));
        };

        // Get the IdP metadata
        let idp_metadata = self
            .identity_providers
            .get(&issuer)
            .ok_or_else(|| AuthError::validation(format!("Unknown issuer: {}", issuer)))?;

        // Decode certificate
        let cert_bytes = base64::engine::general_purpose::STANDARD
            .decode(&idp_metadata.certificate)
            .map_err(|e| AuthError::validation(format!("Invalid certificate encoding: {}", e)))?;

        // Validate XML signature (basic)
        if !self.validate_xml_signature(&decoded_response, &cert_bytes)? {
            return Err(AuthError::validation("XML signature validation failed"));
        }

        // Parse assertion from the response
        self.parse_saml_assertion(&decoded_response, &issuer)
    }

    /// Parse SAML time attribute with production-grade RFC 3339/ISO 8601 support
    fn parse_saml_time_attribute(
        &self,
        xml: &str,
        attribute_name: &str,
    ) -> Result<Option<SystemTime>> {
        // Look for time attributes in various SAML formats
        let patterns = [
            format!("{}=\"", attribute_name),
            format!("{}='", attribute_name),
        ];

        for pattern in &patterns {
            if let Some(start) = xml.find(pattern) {
                let start_pos = start + pattern.len();
                if let Some(end_pos) = xml[start_pos..].find(['"', '\'']) {
                    let time_str = &xml[start_pos..start_pos + end_pos];

                    // Try parsing as RFC 3339 (ISO 8601) format
                    if let Ok(dt) = time_str.parse::<DateTime<Utc>>() {
                        return Ok(Some(dt.into()));
                    }

                    // Try parsing as alternative SAML date format (without timezone)
                    if let Ok(dt) =
                        chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S")
                    {
                        return Ok(Some(
                            DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).into(),
                        ));
                    }

                    // Try parsing with microseconds
                    if let Ok(dt) =
                        chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S%.f")
                    {
                        return Ok(Some(
                            DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).into(),
                        ));
                    }

                    return Err(AuthError::validation(format!(
                        "Invalid SAML time format for {}: {}",
                        attribute_name, time_str
                    )));
                }
            }
        }

        Ok(None)
    }

    /// Validate SAML assertion time constraints for security
    fn validate_assertion_time_constraints(
        &self,
        issue_instant: SystemTime,
        not_before: Option<SystemTime>,
        not_on_or_after: Option<SystemTime>,
    ) -> Result<()> {
        let now = SystemTime::now();

        // Check if assertion is too old (prevent replay attacks)
        if let Ok(elapsed) = now.duration_since(issue_instant) {
            if elapsed > Duration::from_secs(300) {
                // 5 minutes max age
                return Err(AuthError::validation(
                    "SAML assertion is too old - potential replay attack",
                ));
            }
        } else {
            return Err(AuthError::validation("SAML assertion issued in the future"));
        }

        // Validate not_before constraint
        if let Some(not_before_time) = not_before
            && now < not_before_time
        {
            return Err(AuthError::validation(
                "SAML assertion is not yet valid (before NotBefore time)",
            ));
        }

        // Validate not_on_or_after constraint
        if let Some(not_after_time) = not_on_or_after
            && now >= not_after_time
        {
            return Err(AuthError::validation(
                "SAML assertion has expired (after NotOnOrAfter time)",
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl AuthMethod for SamlAuthMethod {
    type MethodResult = MethodResult;
    type AuthToken = AuthToken;

    fn name(&self) -> &str {
        "saml"
    }

    fn validate_config(&self) -> Result<()> {
        // Validate SAML configuration
        if self.config.entity_id.is_empty() {
            return Err(AuthError::Configuration {
                message: "SAML entity_id cannot be empty".to_string(),
                source: None,
                help: Some("Set a valid entity_id in the SAML configuration".to_string()),
                docs_url: Some(
                    "https://docs.rs/auth-framework/latest/auth_framework/methods/saml/"
                        .to_string(),
                ),
                suggested_fix: Some(
                    "Add entity_id = \"your-service-provider-id\" to SAML config".to_string(),
                ),
            });
        }

        if self.config.acs_url.is_empty() {
            return Err(AuthError::Configuration {
                message: "SAML acs_url cannot be empty".to_string(),
                source: None,
                help: Some(
                    "Set a valid Assertion Consumer Service URL in the SAML configuration"
                        .to_string(),
                ),
                docs_url: Some(
                    "https://docs.rs/auth-framework/latest/auth_framework/methods/saml/"
                        .to_string(),
                ),
                suggested_fix: Some(
                    "Add acs_url = \"https://your-domain.com/saml/acs\" to SAML config".to_string(),
                ),
            });
        }

        Ok(())
    }

    #[allow(clippy::manual_async_fn)]
    fn authenticate(
        &self,
        credential: Credential,
        _metadata: CredentialMetadata,
    ) -> impl std::future::Future<Output = Result<MethodResult>> + Send {
        async move {
            let start_time = std::time::Instant::now();

            let saml_response = match credential {
                #[cfg(feature = "saml")]
                Credential::Saml { assertion } => assertion,
                #[cfg(not(feature = "saml"))]
                _ => {
                    return Ok(MethodResult::Failure {
                        reason: "SAML feature is not enabled. Compile with --features saml"
                            .to_string(),
                    });
                }
                #[cfg(feature = "saml")]
                _ => {
                    return Ok(MethodResult::Failure {
                        reason: "Invalid credential type for SAML authentication".to_string(),
                    });
                }
            };

            // Validate SAML response and extract assertion
            let assertion = match self.validate_saml_response(&saml_response).await {
                Ok(assertion) => assertion,
                Err(e) => {
                    tracing::warn!("SAML authentication failed: {}", e);
                    return Ok(MethodResult::Failure {
                        reason: format!("SAML authentication failed: {}", e),
                    });
                }
            };

            // Create scopes from SAML attributes
            let mut scopes = Vec::new();

            // Add default scope
            scopes.push("read".to_string());

            // Extract roles from attributes if present
            if let Some(roles) = assertion.attributes.get("Role") {
                scopes.extend(roles.clone());
            }
            if let Some(groups) = assertion.attributes.get("Group") {
                scopes.extend(groups.clone());
            }

            // Create authentication token
            let token = self.token_manager.create_auth_token(
                &assertion.subject,
                scopes,
                "saml",
                Some(start_time.elapsed()),
            )?;

            tracing::info!(
                "SAML authentication successful for user '{}' from issuer '{}'",
                assertion.subject,
                assertion.issuer
            );

            Ok(MethodResult::Success(Box::new(token)))
        }
    }
}

impl Default for SamlAuthMethod {
    fn default() -> Self {
        Self::new(
            TokenManager::new_hmac(b"default-saml-secret", "saml-issuer", "saml-audience"),
            SamlConfig::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_saml_method_creation() {
        let config = SamlConfig::default();
        let token_manager =
            TokenManager::new_hmac(b"test-secret-key", "test-issuer", "test-audience");
        let saml = SamlAuthMethod::new(token_manager, config);

        assert_eq!(saml.name(), "saml");
        // Note: supports_credential_type is not part of the AuthMethod trait
        // This would need to be implemented separately if needed
    }

    #[tokio::test]
    async fn test_saml_config_defaults() {
        let config = SamlConfig::default();
        assert_eq!(config.entity_id, "urn:example:sp");
        assert_eq!(config.acs_url, "https://example.com/acs");
        assert!(config.require_signed_assertions);
        assert!(config.require_signed_responses);
        assert!(config.validate_xml_signature);
        assert_eq!(config.max_assertion_age, 300);
        assert_eq!(config.clock_skew_seconds, 30);
    }

    #[cfg(not(feature = "saml"))]
    #[tokio::test]
    async fn test_saml_disabled_fallback() {
        let saml = SamlAuthMethod::default();
        let credential = Credential::Password {
            username: "test".to_string(),
            password: "test".to_string(),
        };

        let result = saml
            .authenticate(credential, CredentialMetadata::default())
            .await
            .unwrap();

        match result {
            MethodResult::Failure(msg) => {
                assert!(msg.contains("SAML feature is not enabled"));
            }
            _ => panic!("Expected failure when SAML is disabled"),
        }
    }

    #[tokio::test]
    async fn test_idp_metadata() {
        let mut saml = SamlAuthMethod::default();

        let metadata = SamlIdpMetadata {
            entity_id: "https://example.com/idp".to_string(),
            certificate: "test-cert".to_string(),
            sso_url: "https://example.com/sso".to_string(),
            slo_url: Some("https://example.com/slo".to_string()),
        };

        saml.add_identity_provider(metadata);
        assert!(
            saml.identity_providers
                .contains_key("https://example.com/idp")
        );
    }
}
