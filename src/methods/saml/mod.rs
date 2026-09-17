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

/// SAML assertion data after validation — the parsed/authenticated result
/// returned by [`SamlAuthMethod`]. Distinct from [`crate::protocols::saml_assertions::SamlAssertion`],
/// which is the full SAML 2.0 domain object model used by WS-Security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedSamlAssertion {
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

/// SAML response structure with comprehensive validation fields (XML deserialization only)
#[derive(Debug, Deserialize)]
pub(super) struct SamlResponse {
    #[serde(rename = "Issuer")]
    pub issuer: Option<SamlIssuer>,
    #[serde(rename = "Assertion")]
    pub assertions: Option<Vec<SamlAssertionXml>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlIssuer {
    #[serde(rename = "$text")]
    pub(super) value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlAssertionXml {
    #[serde(rename = "Issuer")]
    pub issuer: SamlIssuer,
    #[serde(rename = "Subject")]
    pub subject: Option<SamlSubject>,
    #[serde(rename = "AttributeStatement")]
    pub attribute_statements: Option<Vec<SamlAttributeStatement>>,
    #[serde(rename = "AuthnStatement")]
    pub authn_statements: Option<Vec<SamlAuthnStatement>>,
    #[serde(rename = "Conditions")]
    pub conditions: Option<SamlConditions>,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlConditions {
    #[serde(rename = "NotBefore")]
    pub(super) not_before: Option<String>,
    #[serde(rename = "NotOnOrAfter")]
    pub(super) not_on_or_after: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlSubject {
    #[serde(rename = "NameID")]
    pub(super) name_id: Option<SamlNameId>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlNameId {
    #[serde(rename = "$text")]
    pub(super) value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlAttributeStatement {
    #[serde(rename = "Attribute")]
    pub(super) attributes: Vec<SamlAttribute>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlAttribute {
    #[serde(rename = "Name")]
    pub(super) name: String,
    #[serde(rename = "AttributeValue")]
    pub(super) values: Vec<SamlAttributeValue>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlAttributeValue {
    #[serde(rename = "$text")]
    pub(super) value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SamlAuthnStatement {
    #[serde(rename = "SessionIndex")]
    pub(super) session_index: Option<String>,
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
            tracing::error!(
                "XML signature validation is disabled; rejecting SAML assertion instead of failing open"
            );
            return Err(AuthError::validation(
                "XML signature validation cannot be disabled for SAML authentication",
            ));
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
    pub fn parse_timestamp(&self, timestamp: &str) -> Result<SystemTime> {
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
    pub(super) fn validate_assertion_security(
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
            self.validate_assertion_time_constraints(issue_time, None, None)?;
        }

        Ok(())
    }

    fn decode_saml_xml(&self, saml_response: &str) -> Result<String> {
        if saml_response.starts_with('<') {
            return Ok(saml_response.to_string());
        }

        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(saml_response)
                .map_err(|e| AuthError::validation(format!("Invalid base64: {}", e)))?,
        )
        .map_err(|e| AuthError::validation(format!("Invalid UTF-8: {}", e)))
    }

    fn lookup_idp_certificate(&self, issuer: &str) -> Result<Vec<u8>> {
        let idp_metadata = self
            .identity_providers
            .get(issuer)
            .ok_or_else(|| AuthError::validation(format!("Unknown issuer: {}", issuer)))?;

        base64::engine::general_purpose::STANDARD
            .decode(&idp_metadata.certificate)
            .map_err(|e| AuthError::validation(format!("Invalid certificate encoding: {}", e)))
    }

    /// Comprehensive SAML response validation using all available fields
    pub async fn validate_saml_response_comprehensive(
        &self,
        saml_response: &str,
    ) -> Result<ValidatedSamlAssertion> {
        let decoded_response = self.decode_saml_xml(saml_response)?;
        let parsed_response: SamlResponse = from_str(&decoded_response).map_err(|e| {
            AuthError::validation(format!("Failed to parse SAML response XML: {}", e))
        })?;

        let issuer = parsed_response
            .issuer
            .as_ref()
            .map(|issuer| issuer.value.as_str())
            .or_else(|| {
                parsed_response
                    .assertions
                    .as_ref()
                    .and_then(|assertions| assertions.first())
                    .map(|assertion| assertion.issuer.value.as_str())
            })
            .ok_or_else(|| AuthError::validation("No issuer found in SAML response"))?;

        let cert_bytes = self.lookup_idp_certificate(issuer)?;
        if !self.validate_xml_signature(&decoded_response, &cert_bytes)? {
            return Err(AuthError::validation("XML signature validation failed"));
        }

        self.validate_structured_saml_response(parsed_response)
            .await
    }

    /// Validate structured SAML response with comprehensive security checks
    pub(super) async fn validate_structured_saml_response(
        &self,
        response: SamlResponse,
    ) -> Result<ValidatedSamlAssertion> {
        let issuer = response
            .issuer
            .as_ref()
            .map(|response_issuer| response_issuer.value.clone())
            .or_else(|| {
                response
                    .assertions
                    .as_ref()
                    .and_then(|assertions| assertions.first())
                    .map(|assertion| assertion.issuer.value.clone())
            })
            .ok_or_else(|| AuthError::validation("No issuer found in SAML response"))?;

        let _idp_metadata = self
            .identity_providers
            .get(&issuer)
            .ok_or_else(|| AuthError::validation(format!("Unknown issuer: {}", issuer)))?;

        let assertions = response
            .assertions
            .as_ref()
            .ok_or_else(|| AuthError::validation("No assertions found in SAML response"))?;
        if assertions.is_empty() {
            return Err(AuthError::validation(
                "No assertions found in SAML response",
            ));
        }

        let assertion = &assertions[0];
        self.validate_assertion_security(assertion, &issuer)?;

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

        let issue_instant = assertion
            .issue_instant
            .as_ref()
            .map(|ts| self.parse_timestamp(ts))
            .transpose()?
            .unwrap_or_else(SystemTime::now);

        let (not_before, not_on_or_after) = if let Some(conditions) = &assertion.conditions {
            let not_before = conditions
                .not_before
                .as_ref()
                .map(|ts| self.parse_timestamp(ts))
                .transpose()?;
            let not_on_or_after = conditions
                .not_on_or_after
                .as_ref()
                .map(|ts| self.parse_timestamp(ts))
                .transpose()?;
            (not_before, not_on_or_after)
        } else {
            (None, None)
        };

        let session_index = assertion
            .authn_statements
            .as_ref()
            .and_then(|statements| statements.first())
            .and_then(|stmt| stmt.session_index.clone());

        self.validate_assertion_time_constraints(issue_instant, not_before, not_on_or_after)?;

        Ok(ValidatedSamlAssertion {
            subject: user_id,
            attributes,
            issuer,
            issue_instant,
            not_before,
            not_on_or_after,
            session_index,
        })
    }

    /// Validate SAML assertion time constraints for security
    fn validate_assertion_time_constraints(
        &self,
        issue_instant: SystemTime,
        not_before: Option<SystemTime>,
        not_on_or_after: Option<SystemTime>,
    ) -> Result<()> {
        let now = SystemTime::now();
        let skew = Duration::from_secs(self.config.clock_skew_seconds);
        let max_assertion_age = Duration::from_secs(self.config.max_assertion_age);

        // Check if assertion is too old (prevent replay attacks)
        if let Ok(elapsed) = now.duration_since(issue_instant) {
            if elapsed > max_assertion_age + skew {
                return Err(AuthError::validation(
                    "SAML assertion is too old - potential replay attack",
                ));
            }
        } else if issue_instant.duration_since(now).unwrap_or_default() > skew {
            return Err(AuthError::validation("SAML assertion issued in the future"));
        }

        // Validate not_before constraint
        if let Some(not_before_time) = not_before
            && not_before_time.duration_since(now).unwrap_or_default() > skew
        {
            return Err(AuthError::validation(
                "SAML assertion is not yet valid (before NotBefore time)",
            ));
        }

        // Validate not_on_or_after constraint
        if let Some(not_after_time) = not_on_or_after
            && now.duration_since(not_after_time).unwrap_or_default() >= skew
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

            // Validate SAML response and extract assertion using comprehensive validation
            let assertion = match self
                .validate_saml_response_comprehensive(&saml_response)
                .await
            {
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
    use chrono::Utc;

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

    #[test]
    fn test_saml_response_structure_internal() {
        // SamlResponse is an internal XML-deserialization type (pub(super))
        // accessible within this module and its tests
        let response_data = r#"
            <Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
                <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">example.com</Issuer>
            </Response>
        "#;

        let _test_response: Result<SamlResponse, _> = quick_xml::de::from_str(response_data);
    }

    #[test]
    fn test_saml_assertion_xml_structure_internal() {
        // SamlAssertionXml is an internal XML-deserialization type (pub(super))
        let xml_data = r#"
            <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
                <Issuer>example.com</Issuer>
            </Assertion>
        "#;

        let _test_assertion: Result<SamlAssertionXml, _> = quick_xml::de::from_str(xml_data);
    }

    #[test]
    fn test_saml_issuer_internal() {
        // SamlIssuer is internal to the SAML XML parsing pipeline
        let issuer = SamlIssuer {
            value: "https://idp.example.com".to_string(),
        };
        assert_eq!(issuer.value, "https://idp.example.com");
    }

    #[test]
    fn test_saml_attribute_statement_internal() {
        // SamlAttributeStatement and related types are internal XML-parsing types
        let attr_value = SamlAttributeValue {
            value: "developer".to_string(),
        };
        assert_eq!(attr_value.value, "developer");

        let attribute = SamlAttribute {
            name: "role".to_string(),
            values: vec![attr_value],
        };
        assert_eq!(attribute.name, "role");
        assert_eq!(attribute.values.len(), 1);

        let attr_stmt = SamlAttributeStatement {
            attributes: vec![attribute],
        };
        assert_eq!(attr_stmt.attributes.len(), 1);
    }

    #[test]
    fn test_saml_conditions_internal() {
        // SamlConditions is an internal XML-parsing type; the public SAML 2.0 domain
        // type is crate::protocols::saml_assertions::SamlConditions
        let conditions = SamlConditions {
            not_before: Some("2024-01-01T00:00:00Z".to_string()),
            not_on_or_after: Some("2024-12-31T23:59:59Z".to_string()),
        };
        assert!(conditions.not_before.is_some());
        assert!(conditions.not_on_or_after.is_some());
    }

    #[tokio::test]
    async fn test_validate_structured_saml_response_uses_assertion_issuer() {
        let token_manager =
            TokenManager::new_hmac(b"test-secret-key", "test-issuer", "test-audience");
        let mut saml = SamlAuthMethod::new(token_manager, SamlConfig::default());
        saml.add_identity_provider(SamlIdpMetadata {
            entity_id: "https://idp.example.com".to_string(),
            certificate: base64::engine::general_purpose::STANDARD.encode(b"test-cert"),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: None,
        });

        let response = SamlResponse {
            issuer: None,
            assertions: Some(vec![SamlAssertionXml {
                issuer: SamlIssuer {
                    value: "https://idp.example.com".to_string(),
                },
                subject: Some(SamlSubject {
                    name_id: Some(SamlNameId {
                        value: "user-123".to_string(),
                    }),
                }),
                attribute_statements: Some(vec![SamlAttributeStatement {
                    attributes: vec![SamlAttribute {
                        name: "Role".to_string(),
                        values: vec![SamlAttributeValue {
                            value: "admin".to_string(),
                        }],
                    }],
                }]),
                authn_statements: Some(vec![SamlAuthnStatement {
                    session_index: Some("session-1".to_string()),
                }]),
                conditions: Some(SamlConditions {
                    not_before: None,
                    not_on_or_after: None,
                }),
                issue_instant: Some(Utc::now().to_rfc3339()),
            }]),
        };

        let validated = saml
            .validate_structured_saml_response(response)
            .await
            .unwrap();

        assert_eq!(validated.subject, "user-123");
        assert_eq!(validated.issuer, "https://idp.example.com");
        assert_eq!(validated.attributes["Role"], vec!["admin".to_string()]);
        assert_eq!(validated.session_index.as_deref(), Some("session-1"));
    }

    #[cfg(feature = "saml")]
    #[test]
    fn test_validate_xml_signature_rejects_disabled_validation() {
        let token_manager =
            TokenManager::new_hmac(b"test-secret-key", "test-issuer", "test-audience");
        let saml = SamlAuthMethod::new(
            token_manager,
            SamlConfig {
                validate_xml_signature: false,
                ..SamlConfig::default()
            },
        );

        let result = saml.validate_xml_signature("<Response />", b"certificate-bytes");

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot be disabled")
        );
    }
}
