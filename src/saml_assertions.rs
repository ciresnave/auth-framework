//! SAML 2.0 Assertion Support for WS-Security
//!
//! This module provides SAML 2.0 assertion generation and validation for WS-Security scenarios.

use crate::errors::{AuthError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
// HashMap removed - not currently used but may be needed later
// use std::collections::HashMap;

/// SAML 2.0 Assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Assertion ID
    pub id: String,

    /// Issuer of the assertion
    pub issuer: String,

    /// Issue instant
    pub issue_instant: DateTime<Utc>,

    /// Version (always "2.0" for SAML 2.0)
    pub version: String,

    /// Subject information
    pub subject: Option<SamlSubject>,

    /// Conditions (validity constraints)
    pub conditions: Option<SamlConditions>,

    /// Attribute statements
    pub attribute_statements: Vec<SamlAttributeStatement>,

    /// Authentication statements
    pub authn_statements: Vec<SamlAuthnStatement>,

    /// Authorization decision statements
    pub authz_decision_statements: Vec<SamlAuthzDecisionStatement>,
}

/// SAML Subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    /// Name identifier
    pub name_id: Option<SamlNameId>,

    /// Subject confirmations
    pub subject_confirmations: Vec<SamlSubjectConfirmation>,
}

/// SAML Name Identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlNameId {
    /// Value of the name identifier
    pub value: String,

    /// Format of the name identifier
    pub format: Option<String>,

    /// Name qualifier
    pub name_qualifier: Option<String>,

    /// SP name qualifier
    pub sp_name_qualifier: Option<String>,
}

/// SAML Subject Confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmation {
    /// Method (bearer, holder-of-key, etc.)
    pub method: String,

    /// Subject confirmation data
    pub subject_confirmation_data: Option<SamlSubjectConfirmationData>,
}

/// SAML Subject Confirmation Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmationData {
    /// Not before timestamp
    pub not_before: Option<DateTime<Utc>>,

    /// Not on or after timestamp
    pub not_on_or_after: Option<DateTime<Utc>>,

    /// Recipient URL
    pub recipient: Option<String>,

    /// In response to (for response assertions)
    pub in_response_to: Option<String>,

    /// Address restriction
    pub address: Option<String>,
}

/// SAML Conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    /// Not before timestamp
    pub not_before: Option<DateTime<Utc>>,

    /// Not on or after timestamp
    pub not_on_or_after: Option<DateTime<Utc>>,

    /// Audience restrictions
    pub audience_restrictions: Vec<SamlAudienceRestriction>,

    /// One time use
    pub one_time_use: bool,

    /// Proxy restrictions
    pub proxy_restriction: Option<SamlProxyRestriction>,
}

/// SAML Audience Restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAudienceRestriction {
    /// Audience URIs
    pub audiences: Vec<String>,
}

/// SAML Proxy Restriction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlProxyRestriction {
    /// Count limit
    pub count: Option<u32>,

    /// Allowed audiences
    pub audiences: Vec<String>,
}

/// SAML Attribute Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    /// Attributes
    pub attributes: Vec<SamlAttribute>,

    /// Encrypted attributes
    pub encrypted_attributes: Vec<String>, // Would be proper encrypted elements in production
}

/// SAML Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttribute {
    /// Attribute name
    pub name: String,

    /// Name format
    pub name_format: Option<String>,

    /// Friendly name
    pub friendly_name: Option<String>,

    /// Attribute values
    pub values: Vec<SamlAttributeValue>,
}

/// SAML Attribute Value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeValue {
    /// Value content
    pub value: String,

    /// Type information
    pub type_info: Option<String>,
}

/// SAML Authentication Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnStatement {
    /// Authentication instant
    pub authn_instant: DateTime<Utc>,

    /// Session index
    pub session_index: Option<String>,

    /// Session not on or after
    pub session_not_on_or_after: Option<DateTime<Utc>>,

    /// Authentication context
    pub authn_context: SamlAuthnContext,

    /// Subject locality
    pub subject_locality: Option<SamlSubjectLocality>,
}

/// SAML Authentication Context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnContext {
    /// Authentication context class reference
    pub authn_context_class_ref: Option<String>,

    /// Authentication context declaration
    pub authn_context_decl: Option<String>,

    /// Authentication context declaration reference
    pub authn_context_decl_ref: Option<String>,

    /// Authenticating authorities
    pub authenticating_authorities: Vec<String>,
}

/// SAML Subject Locality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectLocality {
    /// IP address
    pub address: Option<String>,

    /// DNS name
    pub dns_name: Option<String>,
}

/// SAML Authorization Decision Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthzDecisionStatement {
    /// Resource being accessed
    pub resource: String,

    /// Decision (Permit, Deny, Indeterminate)
    pub decision: SamlDecision,

    /// Actions being performed
    pub actions: Vec<SamlAction>,

    /// Evidence supporting the decision
    pub evidence: Option<SamlEvidence>,
}

/// SAML Decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SamlDecision {
    /// Access permitted
    Permit,

    /// Access denied
    Deny,

    /// Decision cannot be made
    Indeterminate,
}

/// SAML Action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAction {
    /// Action value
    pub value: String,

    /// Action namespace
    pub namespace: Option<String>,
}

/// SAML Evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlEvidence {
    /// Supporting assertions
    pub assertions: Vec<String>, // References to other assertions

    /// Assertion ID references
    pub assertion_id_refs: Vec<String>,

    /// Assertion URI references
    pub assertion_uri_refs: Vec<String>,
}

/// SAML Assertion Builder
pub struct SamlAssertionBuilder {
    /// Current assertion being built
    assertion: SamlAssertion,
}

/// SAML Assertion Validator
pub struct SamlAssertionValidator {
    /// Allowed clock skew
    clock_skew: Duration,

    /// Trusted issuers
    trusted_issuers: Vec<String>,

    /// Expected audiences
    expected_audiences: Vec<String>,
}

impl SamlAssertionBuilder {
    /// Create a new SAML assertion builder
    pub fn new(issuer: &str) -> Self {
        let assertion = SamlAssertion {
            id: format!("_{}", uuid::Uuid::new_v4()),
            issuer: issuer.to_string(),
            issue_instant: Utc::now(),
            version: "2.0".to_string(),
            subject: None,
            conditions: None,
            attribute_statements: Vec::new(),
            authn_statements: Vec::new(),
            authz_decision_statements: Vec::new(),
        };

        Self { assertion }
    }

    /// Set the subject
    pub fn with_subject(mut self, subject: SamlSubject) -> Self {
        self.assertion.subject = Some(subject);
        self
    }

    /// Set conditions
    pub fn with_conditions(mut self, conditions: SamlConditions) -> Self {
        self.assertion.conditions = Some(conditions);
        self
    }

    /// Add an attribute statement
    pub fn with_attribute_statement(mut self, statement: SamlAttributeStatement) -> Self {
        self.assertion.attribute_statements.push(statement);
        self
    }

    /// Add an authentication statement
    pub fn with_authn_statement(mut self, statement: SamlAuthnStatement) -> Self {
        self.assertion.authn_statements.push(statement);
        self
    }

    /// Add an authorization decision statement
    pub fn with_authz_decision_statement(mut self, statement: SamlAuthzDecisionStatement) -> Self {
        self.assertion.authz_decision_statements.push(statement);
        self
    }

    /// Add a simple attribute
    pub fn with_attribute(mut self, name: &str, value: &str) -> Self {
        let attribute = SamlAttribute {
            name: name.to_string(),
            name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
            friendly_name: None,
            values: vec![SamlAttributeValue {
                value: value.to_string(),
                type_info: None,
            }],
        };

        // Find or create attribute statement
        if self.assertion.attribute_statements.is_empty() {
            self.assertion
                .attribute_statements
                .push(SamlAttributeStatement {
                    attributes: vec![attribute],
                    encrypted_attributes: Vec::new(),
                });
        } else {
            self.assertion.attribute_statements[0]
                .attributes
                .push(attribute);
        }

        self
    }

    /// Set validity period
    pub fn with_validity_period(
        mut self,
        not_before: DateTime<Utc>,
        not_on_or_after: DateTime<Utc>,
    ) -> Self {
        if let Some(ref mut conditions) = self.assertion.conditions {
            // Update existing conditions
            conditions.not_before = Some(not_before);
            conditions.not_on_or_after = Some(not_on_or_after);
        } else {
            // Create new conditions
            let conditions = SamlConditions {
                not_before: Some(not_before),
                not_on_or_after: Some(not_on_or_after),
                audience_restrictions: Vec::new(),
                one_time_use: false,
                proxy_restriction: None,
            };
            self.assertion.conditions = Some(conditions);
        }
        self
    }

    /// Add audience restriction
    pub fn with_audience(mut self, audience: &str) -> Self {
        if let Some(ref mut conditions) = self.assertion.conditions {
            if conditions.audience_restrictions.is_empty() {
                conditions
                    .audience_restrictions
                    .push(SamlAudienceRestriction {
                        audiences: vec![audience.to_string()],
                    });
            } else {
                conditions.audience_restrictions[0]
                    .audiences
                    .push(audience.to_string());
            }
        } else {
            let conditions = SamlConditions {
                not_before: None,
                not_on_or_after: None,
                audience_restrictions: vec![SamlAudienceRestriction {
                    audiences: vec![audience.to_string()],
                }],
                one_time_use: false,
                proxy_restriction: None,
            };
            self.assertion.conditions = Some(conditions);
        }

        self
    }

    /// Build the assertion
    pub fn build(self) -> SamlAssertion {
        self.assertion
    }

    /// Build and convert to XML
    pub fn build_xml(self) -> Result<String> {
        let assertion = self.assertion;
        assertion.to_xml()
    }
}

impl SamlAssertionValidator {
    /// Create a new SAML assertion validator
    pub fn new() -> Self {
        Self {
            clock_skew: Duration::minutes(5),
            trusted_issuers: Vec::new(),
            expected_audiences: Vec::new(),
        }
    }

    /// Set clock skew tolerance
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Add trusted issuer
    pub fn with_trusted_issuer(mut self, issuer: &str) -> Self {
        self.trusted_issuers.push(issuer.to_string());
        self
    }

    /// Add expected audience
    pub fn with_expected_audience(mut self, audience: &str) -> Self {
        self.expected_audiences.push(audience.to_string());
        self
    }

    /// Validate a SAML assertion
    pub fn validate(&self, assertion: &SamlAssertion) -> Result<()> {
        // Check issuer
        if !self.trusted_issuers.is_empty() && !self.trusted_issuers.contains(&assertion.issuer) {
            return Err(AuthError::auth_method("saml", "Untrusted issuer"));
        }

        // Check time validity
        self.validate_timing(assertion)?;

        // Check audience restrictions
        self.validate_audience(assertion)?;

        // Check subject confirmation (if present)
        if let Some(ref subject) = assertion.subject {
            self.validate_subject_confirmation(subject)?;
        }

        Ok(())
    }

    /// Validate timing constraints
    fn validate_timing(&self, assertion: &SamlAssertion) -> Result<()> {
        let now = Utc::now();

        // Check issue instant (shouldn't be too far in the future)
        if assertion.issue_instant > now + self.clock_skew {
            return Err(AuthError::auth_method(
                "saml",
                "Assertion issued in the future",
            ));
        }

        // Check conditions timing
        if let Some(ref conditions) = assertion.conditions {
            if let Some(not_before) = conditions.not_before
                && now < not_before - self.clock_skew
            {
                return Err(AuthError::auth_method("saml", "Assertion not yet valid"));
            }

            if let Some(not_on_or_after) = conditions.not_on_or_after
                && now >= not_on_or_after + self.clock_skew
            {
                return Err(AuthError::auth_method("saml", "Assertion has expired"));
            }
        }

        Ok(())
    }

    /// Validate audience restrictions
    fn validate_audience(&self, assertion: &SamlAssertion) -> Result<()> {
        if self.expected_audiences.is_empty() {
            return Ok(());
        }

        if let Some(ref conditions) = assertion.conditions {
            for restriction in &conditions.audience_restrictions {
                for audience in &restriction.audiences {
                    if self.expected_audiences.contains(audience) {
                        return Ok(());
                    }
                }
            }

            if !conditions.audience_restrictions.is_empty() {
                return Err(AuthError::auth_method("saml", "No matching audience found"));
            }
        }

        Ok(())
    }

    /// Validate subject confirmation
    fn validate_subject_confirmation(&self, _subject: &SamlSubject) -> Result<()> {
        // Simplified validation - would check bearer tokens, holder-of-key, etc.
        Ok(())
    }
}

impl SamlAssertion {
    /// Convert assertion to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str(&format!(
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" IssueInstant="{}" Version="{}">"#,
            self.id,
            self.issue_instant.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            self.version
        ));

        // Issuer
        xml.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", self.issuer));

        // Subject
        if let Some(ref subject) = self.subject {
            xml.push_str(&subject.to_xml()?);
        }

        // Conditions
        if let Some(ref conditions) = self.conditions {
            xml.push_str(&conditions.to_xml()?);
        }

        // Attribute statements
        for statement in &self.attribute_statements {
            xml.push_str(&statement.to_xml()?);
        }

        // Authentication statements
        for statement in &self.authn_statements {
            xml.push_str(&statement.to_xml()?);
        }

        // Authorization decision statements
        for statement in &self.authz_decision_statements {
            xml.push_str(&statement.to_xml()?);
        }

        xml.push_str("</saml:Assertion>");

        Ok(xml)
    }
}

impl SamlSubject {
    /// Convert subject to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:Subject>");

        if let Some(ref name_id) = self.name_id {
            xml.push_str(&name_id.to_xml()?);
        }

        for confirmation in &self.subject_confirmations {
            xml.push_str(&confirmation.to_xml()?);
        }

        xml.push_str("</saml:Subject>");

        Ok(xml)
    }
}

impl SamlNameId {
    /// Convert name ID to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:NameID");

        if let Some(ref format) = self.format {
            xml.push_str(&format!(" Format=\"{}\"", format));
        }

        if let Some(ref name_qualifier) = self.name_qualifier {
            xml.push_str(&format!(" NameQualifier=\"{}\"", name_qualifier));
        }

        if let Some(ref sp_name_qualifier) = self.sp_name_qualifier {
            xml.push_str(&format!(" SPNameQualifier=\"{}\"", sp_name_qualifier));
        }

        xml.push_str(&format!(">{}</saml:NameID>", self.value));

        Ok(xml)
    }
}

impl SamlSubjectConfirmation {
    /// Convert subject confirmation to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str(&format!(
            "<saml:SubjectConfirmation Method=\"{}\">",
            self.method
        ));

        if let Some(ref data) = self.subject_confirmation_data {
            xml.push_str(&data.to_xml()?);
        }

        xml.push_str("</saml:SubjectConfirmation>");

        Ok(xml)
    }
}

impl SamlSubjectConfirmationData {
    /// Convert subject confirmation data to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:SubjectConfirmationData");

        if let Some(not_before) = self.not_before {
            xml.push_str(&format!(
                " NotBefore=\"{}\"",
                not_before.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        if let Some(not_on_or_after) = self.not_on_or_after {
            xml.push_str(&format!(
                " NotOnOrAfter=\"{}\"",
                not_on_or_after.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        if let Some(ref recipient) = self.recipient {
            xml.push_str(&format!(" Recipient=\"{}\"", recipient));
        }

        if let Some(ref in_response_to) = self.in_response_to {
            xml.push_str(&format!(" InResponseTo=\"{}\"", in_response_to));
        }

        if let Some(ref address) = self.address {
            xml.push_str(&format!(" Address=\"{}\"", address));
        }

        xml.push_str("/>");

        Ok(xml)
    }
}

impl SamlConditions {
    /// Convert conditions to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:Conditions");

        if let Some(not_before) = self.not_before {
            xml.push_str(&format!(
                " NotBefore=\"{}\"",
                not_before.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        if let Some(not_on_or_after) = self.not_on_or_after {
            xml.push_str(&format!(
                " NotOnOrAfter=\"{}\"",
                not_on_or_after.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        xml.push('>');

        for restriction in &self.audience_restrictions {
            xml.push_str(&restriction.to_xml()?);
        }

        if self.one_time_use {
            xml.push_str("<saml:OneTimeUse/>");
        }

        if let Some(ref proxy_restriction) = self.proxy_restriction {
            xml.push_str(&proxy_restriction.to_xml()?);
        }

        xml.push_str("</saml:Conditions>");

        Ok(xml)
    }
}

impl SamlAudienceRestriction {
    /// Convert audience restriction to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:AudienceRestriction>");

        for audience in &self.audiences {
            xml.push_str(&format!("<saml:Audience>{}</saml:Audience>", audience));
        }

        xml.push_str("</saml:AudienceRestriction>");

        Ok(xml)
    }
}

impl SamlProxyRestriction {
    /// Convert proxy restriction to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:ProxyRestriction");

        if let Some(count) = self.count {
            xml.push_str(&format!(" Count=\"{}\"", count));
        }

        xml.push('>');

        for audience in &self.audiences {
            xml.push_str(&format!("<saml:Audience>{}</saml:Audience>", audience));
        }

        xml.push_str("</saml:ProxyRestriction>");

        Ok(xml)
    }
}

impl SamlAttributeStatement {
    /// Convert attribute statement to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:AttributeStatement>");

        for attribute in &self.attributes {
            xml.push_str(&attribute.to_xml()?);
        }

        // Encrypted attributes would be handled here
        for encrypted_attr in &self.encrypted_attributes {
            xml.push_str(encrypted_attr);
        }

        xml.push_str("</saml:AttributeStatement>");

        Ok(xml)
    }
}

impl SamlAttribute {
    /// Convert attribute to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str(&format!("<saml:Attribute Name=\"{}\">", self.name));

        if let Some(ref name_format) = self.name_format {
            xml = xml.replace(">", &format!(" NameFormat=\"{}\">", name_format));
        }

        if let Some(ref friendly_name) = self.friendly_name {
            xml = xml.replace(">", &format!(" FriendlyName=\"{}\">", friendly_name));
        }

        for value in &self.values {
            xml.push_str(&value.to_xml()?);
        }

        xml.push_str("</saml:Attribute>");

        Ok(xml)
    }
}

impl SamlAttributeValue {
    /// Convert attribute value to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:AttributeValue");

        if let Some(ref type_info) = self.type_info {
            xml.push_str(&format!(" xsi:type=\"{}\"", type_info));
        }

        xml.push_str(&format!(">{}</saml:AttributeValue>", self.value));

        Ok(xml)
    }
}

impl SamlAuthnStatement {
    /// Convert authentication statement to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str(&format!(
            "<saml:AuthnStatement AuthnInstant=\"{}\"",
            self.authn_instant.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        ));

        if let Some(ref session_index) = self.session_index {
            xml.push_str(&format!(" SessionIndex=\"{}\"", session_index));
        }

        if let Some(session_not_on_or_after) = self.session_not_on_or_after {
            xml.push_str(&format!(
                " SessionNotOnOrAfter=\"{}\"",
                session_not_on_or_after.format("%Y-%m-%dT%H:%M:%S%.3fZ")
            ));
        }

        xml.push('>');

        if let Some(ref locality) = self.subject_locality {
            xml.push_str(&locality.to_xml()?);
        }

        xml.push_str(&self.authn_context.to_xml()?);

        xml.push_str("</saml:AuthnStatement>");

        Ok(xml)
    }
}

impl SamlAuthnContext {
    /// Convert authentication context to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:AuthnContext>");

        if let Some(ref class_ref) = self.authn_context_class_ref {
            xml.push_str(&format!(
                "<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>",
                class_ref
            ));
        }

        if let Some(ref decl) = self.authn_context_decl {
            xml.push_str(&format!(
                "<saml:AuthnContextDecl>{}</saml:AuthnContextDecl>",
                decl
            ));
        }

        if let Some(ref decl_ref) = self.authn_context_decl_ref {
            xml.push_str(&format!(
                "<saml:AuthnContextDeclRef>{}</saml:AuthnContextDeclRef>",
                decl_ref
            ));
        }

        for authority in &self.authenticating_authorities {
            xml.push_str(&format!(
                "<saml:AuthenticatingAuthority>{}</saml:AuthenticatingAuthority>",
                authority
            ));
        }

        xml.push_str("</saml:AuthnContext>");

        Ok(xml)
    }
}

impl SamlSubjectLocality {
    /// Convert subject locality to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:SubjectLocality");

        if let Some(ref address) = self.address {
            xml.push_str(&format!(" Address=\"{}\"", address));
        }

        if let Some(ref dns_name) = self.dns_name {
            xml.push_str(&format!(" DNSName=\"{}\"", dns_name));
        }

        xml.push_str("/>");

        Ok(xml)
    }
}

impl SamlAuthzDecisionStatement {
    /// Convert authorization decision statement to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        let decision_str = match self.decision {
            SamlDecision::Permit => "Permit",
            SamlDecision::Deny => "Deny",
            SamlDecision::Indeterminate => "Indeterminate",
        };

        xml.push_str(&format!(
            "<saml:AuthzDecisionStatement Decision=\"{}\" Resource=\"{}\">",
            decision_str, self.resource
        ));

        for action in &self.actions {
            xml.push_str(&action.to_xml()?);
        }

        if let Some(ref evidence) = self.evidence {
            xml.push_str(&evidence.to_xml()?);
        }

        xml.push_str("</saml:AuthzDecisionStatement>");

        Ok(xml)
    }
}

impl SamlAction {
    /// Convert action to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:Action");

        if let Some(ref namespace) = self.namespace {
            xml.push_str(&format!(" Namespace=\"{}\"", namespace));
        }

        xml.push_str(&format!(">{}</saml:Action>", self.value));

        Ok(xml)
    }
}

impl SamlEvidence {
    /// Convert evidence to XML
    pub fn to_xml(&self) -> Result<String> {
        let mut xml = String::new();

        xml.push_str("<saml:Evidence>");

        for assertion in &self.assertions {
            xml.push_str(assertion);
        }

        for id_ref in &self.assertion_id_refs {
            xml.push_str(&format!(
                "<saml:AssertionIDRef>{}</saml:AssertionIDRef>",
                id_ref
            ));
        }

        for uri_ref in &self.assertion_uri_refs {
            xml.push_str(&format!(
                "<saml:AssertionURIRef>{}</saml:AssertionURIRef>",
                uri_ref
            ));
        }

        xml.push_str("</saml:Evidence>");

        Ok(xml)
    }
}

impl Default for SamlAssertionValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_saml_assertion_builder() {
        let assertion = SamlAssertionBuilder::new("https://idp.example.com")
            .with_attribute("username", "testuser")
            .with_attribute("email", "test@example.com")
            .with_audience("https://sp.example.com")
            .build();

        assert_eq!(assertion.issuer, "https://idp.example.com");
        assert_eq!(assertion.version, "2.0");
        assert!(!assertion.attribute_statements.is_empty());
        assert!(assertion.conditions.is_some());
    }

    #[test]
    fn test_saml_assertion_xml() {
        let assertion = SamlAssertionBuilder::new("https://idp.example.com")
            .with_attribute("username", "testuser")
            .build();

        let xml = assertion.to_xml().unwrap();
        assert!(xml.contains("<saml:Assertion"));
        assert!(xml.contains("https://idp.example.com"));
        assert!(xml.contains("testuser"));
        assert!(xml.contains("</saml:Assertion>"));
    }

    #[test]
    fn test_saml_assertion_validation() {
        let validator = SamlAssertionValidator::new()
            .with_trusted_issuer("https://idp.example.com")
            .with_expected_audience("https://sp.example.com");

        let assertion = SamlAssertionBuilder::new("https://idp.example.com")
            .with_audience("https://sp.example.com")
            .with_validity_period(
                Utc::now() - Duration::minutes(1),
                Utc::now() + Duration::hours(1),
            )
            .build();

        assert!(validator.validate(&assertion).is_ok());
    }

    #[test]
    fn test_expired_assertion_validation() {
        let validator = SamlAssertionValidator::new();

        let assertion = SamlAssertionBuilder::new("https://idp.example.com")
            .with_validity_period(
                Utc::now() - Duration::hours(2),
                Utc::now() - Duration::hours(1),
            )
            .build();

        assert!(validator.validate(&assertion).is_err());
    }
}
