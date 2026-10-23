//! WS-Federation Passive Requestor Profile
//!
//! Implements the WS-Federation 1.2 passive requestor profile for browser-based
//! SSO. WS-Federation is commonly used with Active Directory Federation Services
//! (ADFS) and Azure AD in legacy enterprise environments.
//!
//! # Protocol Flow (Passive Requestor)
//!
//! 1. Application redirects the user to the STS sign-in URL with `wa=wsignin1.0`
//! 2. STS authenticates the user and posts a security token (SAML assertion)
//!    back to the application's reply URL (`wtrealm`)
//! 3. Application validates the security token and establishes a session
//! 4. Logout: redirect to STS with `wa=wsignout1.0`
//!
//! # Security Considerations
//!
//! - Federation metadata should be fetched over HTTPS and cached
//! - Security tokens (SAML assertions) are only accepted when their signature
//!   verifies under a signing certificate (or thumbprint) you configured; with
//!   none configured the client cannot be built
//! - Replay protection via `wctx` state parameter

use crate::errors::{AuthError, Result};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed assertion fields: `(subject, issuer, audience, not_before, not_on_or_after, claims)`.
#[cfg(any(feature = "saml", test))]
type ParsedAssertion = (
    String,
    String,
    String,
    u64,
    u64,
    HashMap<String, Vec<String>>,
);

// ─── WS-Federation Constants ─────────────────────────────────────────────────

/// WS-Federation action values.
pub mod action {
    /// Sign-in action.
    pub const SIGN_IN: &str = "wsignin1.0";
    /// Sign-out action.
    pub const SIGN_OUT: &str = "wsignout1.0";
    /// Sign-out cleanup action.
    pub const SIGN_OUT_CLEANUP: &str = "wsignoutcleanup1.0";
    /// Attribute request action.
    pub const ATTRIBUTE: &str = "wattr1.0";
}

/// WS-Federation XML namespace URIs.
pub mod ns {
    pub const WS_FED: &str = "http://docs.oasis-open.org/wsfed/federation/200706";
    pub const WS_TRUST: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    pub const WS_ADDRESSING: &str = "http://www.w3.org/2005/08/addressing";
    pub const SAML_11_ASSERTION: &str = "urn:oasis:names:tc:SAML:1.0:assertion";
    pub const SAML_20_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
}

// ─── Configuration ───────────────────────────────────────────────────────────

/// WS-Federation Relying Party (RP) configuration.
#[derive(Debug, Clone)]
pub struct WsFederationConfig {
    /// STS (Security Token Service) sign-in URL.
    pub sts_url: String,

    /// This relying party's realm (wtrealm / appliesTo).
    pub realm: String,

    /// Reply URL where the STS posts the token back (wreply).
    pub reply_url: String,

    /// Federation metadata URL for dynamic trust configuration.
    pub metadata_url: Option<String>,

    /// Trusted issuer identifiers.
    pub trusted_issuers: Vec<String>,

    /// Trusted signing certificate fingerprints (SHA-256 hex). A token is accepted if it is signed
    /// under a certificate it carries whose thumbprint is listed here.
    pub trusted_cert_thumbprints: Vec<String>,

    /// Signing certificates to trust, as `(issuer, certificate)` with the certificate a PEM block or
    /// bare base64 DER (for example from the federation metadata, checked out of band). A token is
    /// accepted if its issuer is listed and it is signed under that issuer's certificate.
    ///
    /// At least one certificate or thumbprint must be configured: a token is only accepted when its
    /// signature verifies under a key configured here, never under a key the token supplies itself.
    pub trusted_signing_certificates: Vec<(String, String)>,

    /// Maximum allowed clock skew for token validation (seconds).
    pub max_clock_skew_secs: u64,

    /// Whether to require encrypted tokens.
    pub require_encrypted_tokens: bool,

    /// HTTP request timeout.
    pub timeout_secs: u64,

    /// Custom home realm for IdP discovery (whr parameter).
    pub home_realm: Option<String>,
}

impl Default for WsFederationConfig {
    fn default() -> Self {
        Self {
            sts_url: String::new(),
            realm: String::new(),
            reply_url: String::new(),
            metadata_url: None,
            trusted_issuers: Vec::new(),
            trusted_cert_thumbprints: Vec::new(),
            trusted_signing_certificates: Vec::new(),
            max_clock_skew_secs: 300,
            require_encrypted_tokens: false,
            timeout_secs: 10,
            home_realm: None,
        }
    }
}

// ─── Data Types ──────────────────────────────────────────────────────────────

/// Parsed WS-Federation sign-in response.
#[derive(Clone, Serialize, Deserialize)]
pub struct WsFedSignInResponse {
    /// The action (`wa` parameter) — should be `wsignin1.0`.
    pub action: String,

    /// The `wresult` — contains the `<RequestSecurityTokenResponse>`.
    pub result_xml: String,

    /// The `wctx` context/state parameter echoed back from the STS.
    pub context: Option<String>,
}

impl std::fmt::Debug for WsFedSignInResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("WsFedSignInResponse");
        d.field("action", &self.action);
        d.field(
            "result_xml",
            &crate::utils::redact::redacted(&self.result_xml),
        );
        d.field("context", &self.context);
        d.finish()
    }
}

/// Validated security token extracted from a WS-Federation response.
#[derive(Clone, Serialize, Deserialize)]
pub struct WsFedSecurityToken {
    /// Token type (SAML 1.1 or SAML 2.0).
    pub token_type: WsFedTokenType,

    /// Authenticated subject / name identifier.
    pub subject: String,

    /// Token issuer.
    pub issuer: String,

    /// Token audience (appliesTo / realm).
    pub audience: String,

    /// When the token was issued.
    pub issued_at: u64,

    /// When the token expires.
    pub expires_at: u64,

    /// Claims / attributes from the token.
    pub claims: HashMap<String, Vec<String>>,

    /// Raw assertion XML (for downstream processing).
    pub raw_assertion: String,
}

impl std::fmt::Debug for WsFedSecurityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("WsFedSecurityToken");
        d.field("token_type", &self.token_type);
        d.field("subject", &self.subject);
        d.field("issuer", &self.issuer);
        d.field("audience", &self.audience);
        d.field("issued_at", &self.issued_at);
        d.field("expires_at", &self.expires_at);
        d.field("claims", &self.claims);
        d.field(
            "raw_assertion",
            &crate::utils::redact::redacted(&self.raw_assertion),
        );
        d.finish()
    }
}

/// Security token type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WsFedTokenType {
    /// SAML 1.1 assertion.
    Saml11,
    /// SAML 2.0 assertion.
    Saml20,
    /// JWT (non-standard but used by Azure AD).
    Jwt,
}

/// Federation metadata for an STS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMetadata {
    /// STS entity ID.
    pub entity_id: String,

    /// Passive requestor endpoint URL.
    pub passive_endpoint: Option<String>,

    /// Signing certificate(s) as Base64-encoded DER.
    pub signing_certificates: Vec<String>,

    /// Token types offered.
    pub token_types_offered: Vec<String>,

    /// Claim types offered.
    pub claim_types_offered: Vec<ClaimTypeOffered>,
}

/// Claim type advertised in federation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTypeOffered {
    pub uri: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

// ─── Client ──────────────────────────────────────────────────────────────────

/// WS-Federation Relying Party client.
#[derive(Debug)]
pub struct WsFederationClient {
    config: WsFederationConfig,
    http: reqwest::Client,
}

impl WsFederationClient {
    /// Create a new WS-Federation client.
    pub fn new(config: WsFederationConfig) -> Result<Self> {
        if config.sts_url.is_empty() {
            return Err(AuthError::config("WS-Federation STS URL must be set"));
        }
        if !config.sts_url.starts_with("https://") {
            return Err(AuthError::config("WS-Federation STS URL must use HTTPS"));
        }
        if config.realm.is_empty() {
            return Err(AuthError::config("WS-Federation realm must be set"));
        }
        if config.trusted_signing_certificates.is_empty()
            && config.trusted_cert_thumbprints.is_empty()
        {
            return Err(AuthError::config(
                "WS-Federation needs a trusted signing certificate or thumbprint: sign-in tokens are only accepted when signed under a configured key",
            ));
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| AuthError::internal(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self { config, http })
    }

    /// Generate the WS-Federation sign-in redirect URL.
    ///
    /// Returns `(url, wctx)` where `wctx` is a random state value for
    /// CSRF protection.
    pub fn sign_in_url(&self) -> Result<(String, String)> {
        let rng = ring::rand::SystemRandom::new();
        let mut ctx_bytes = [0u8; 16];
        rng.fill(&mut ctx_bytes)
            .map_err(|_| AuthError::crypto("Failed to generate wctx nonce"))?;
        let wctx = hex::encode(ctx_bytes);

        let mut url = format!(
            "{}?wa={}&wtrealm={}&wreply={}&wctx={}",
            self.config.sts_url,
            urlencoding::encode(action::SIGN_IN),
            urlencoding::encode(&self.config.realm),
            urlencoding::encode(&self.config.reply_url),
            urlencoding::encode(&wctx),
        );

        if let Some(ref whr) = self.config.home_realm {
            url.push_str(&format!("&whr={}", urlencoding::encode(whr)));
        }

        Ok((url, wctx))
    }

    /// Generate the WS-Federation sign-out URL.
    pub fn sign_out_url(&self) -> String {
        format!(
            "{}?wa={}&wtrealm={}",
            self.config.sts_url,
            urlencoding::encode(action::SIGN_OUT),
            urlencoding::encode(&self.config.realm),
        )
    }

    /// Process a WS-Federation sign-in response (POST from STS).
    ///
    /// The parameters are extracted from the form POST body:
    /// - `wa`: action (should be `wsignin1.0`)
    /// - `wresult`: the `<RequestSecurityTokenResponse>` XML
    /// - `wctx`: echoed state parameter
    pub fn process_sign_in_response(
        &self,
        wa: &str,
        wresult: &str,
        wctx: Option<&str>,
        expected_wctx: &str,
    ) -> Result<WsFedSecurityToken> {
        // Validate action
        if wa != action::SIGN_IN {
            return Err(AuthError::validation(format!(
                "Unexpected WS-Fed action: {wa}"
            )));
        }

        // Validate wctx for CSRF protection
        if let Some(ctx) = wctx {
            if !constant_time_eq(ctx.as_bytes(), expected_wctx.as_bytes()) {
                return Err(AuthError::validation("WS-Federation wctx mismatch (CSRF)"));
            }
        } else {
            return Err(AuthError::validation("Missing wctx parameter"));
        }

        // Verify the signature under a configured key and read the assertion it covers
        let token = self.verify_and_parse(wresult)?;

        // Validate token
        self.validate_token(&token)?;

        Ok(token)
    }

    /// Fetch and parse federation metadata from the metadata URL.
    pub async fn fetch_metadata(&self) -> Result<FederationMetadata> {
        let url = self
            .config
            .metadata_url
            .as_deref()
            .ok_or_else(|| AuthError::config("Federation metadata URL not configured"))?;

        let resp =
            self.http.get(url).send().await.map_err(|e| {
                AuthError::internal(format!("Federation metadata fetch failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(AuthError::internal(format!(
                "Federation metadata HTTP error: {status}"
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AuthError::internal(format!("Federation metadata read failed: {e}")))?;

        parse_federation_metadata(&body)
    }

    /// Verify a RequestSecurityTokenResponse (RSTR) and read the security token out of it.
    ///
    /// The assertion must be signed under a key configured in `trusted_signing_certificates` (for
    /// its issuer) or identified by `trusted_cert_thumbprints`; only the assertion that signature
    /// covers is read. JWT tokens are not accepted: their signature is not verified here.
    #[cfg(feature = "saml")]
    fn verify_and_parse(&self, rstr_xml: &str) -> Result<WsFedSecurityToken> {
        use crate::methods::saml::{
            SamlTrustAnchors, anchors_for_thumbprints, verify_signed_assertion,
        };

        let mut anchors = SamlTrustAnchors::new();
        for (issuer, certificate) in &self.config.trusted_signing_certificates {
            anchors.trust_pem(issuer.clone(), certificate)?;
        }
        anchors.extend(anchors_for_thumbprints(
            rstr_xml,
            &self.config.trusted_issuers,
            &self.config.trusted_cert_thumbprints,
        )?);

        let verified = verify_signed_assertion(rstr_xml, &anchors)?;
        let raw_assertion = verified.assertion_xml;

        // SAML 1.1 assertions carry `MajorVersion` and `AssertionID` on the element itself.
        let opening = raw_assertion.split('>').next().unwrap_or_default();
        let token_type = if opening.contains("AssertionID=") || opening.contains("MajorVersion=") {
            WsFedTokenType::Saml11
        } else {
            WsFedTokenType::Saml20
        };
        let (subject, _claimed_issuer, audience, issued_at, expires_at, claims) = match token_type {
            WsFedTokenType::Saml11 => parse_saml11_assertion(&raw_assertion)?,
            _ => parse_saml20_assertion(&raw_assertion)?,
        };

        Ok(WsFedSecurityToken {
            token_type,
            subject,
            // The issuer the signature was verified for, not whatever text the assertion repeats.
            issuer: verified.issuer,
            audience,
            issued_at,
            expires_at,
            claims,
            raw_assertion,
        })
    }

    /// Without the `saml` feature there is no signature verification, so nothing is accepted.
    #[cfg(not(feature = "saml"))]
    fn verify_and_parse(&self, _rstr_xml: &str) -> Result<WsFedSecurityToken> {
        Err(AuthError::config(
            "WS-Federation sign-in tokens can only be accepted when their signature is verified: build with the `saml` feature",
        ))
    }

    /// Validate a security token against the configuration.
    fn validate_token(&self, token: &WsFedSecurityToken) -> Result<()> {
        // Check issuer trust
        if !self.config.trusted_issuers.is_empty()
            && !self.config.trusted_issuers.contains(&token.issuer)
        {
            return Err(AuthError::validation(format!(
                "Token issuer '{}' is not trusted",
                token.issuer
            )));
        }

        // Check audience
        if !token.audience.is_empty() && token.audience != self.config.realm {
            return Err(AuthError::validation(format!(
                "Token audience '{}' does not match realm '{}'",
                token.audience, self.config.realm
            )));
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::internal(format!("Clock error: {e}")))?
            .as_secs();

        let skew = self.config.max_clock_skew_secs;
        if token.expires_at.saturating_add(skew) < now {
            return Err(AuthError::validation("Security token has expired"));
        }

        if token.issued_at > now.saturating_add(skew) {
            return Err(AuthError::validation("Security token issued in the future"));
        }

        Ok(())
    }
}

// ─── XML Parsing Helpers ─────────────────────────────────────────────────────

/// Parse a SAML 2.0 assertion.
#[cfg(any(feature = "saml", test))]
fn parse_saml20_assertion(xml: &str) -> Result<ParsedAssertion> {
    let subject = extract_xml_text(xml, "NameID")
        .or_else(|| extract_xml_text(xml, "saml:NameID"))
        .unwrap_or_default();

    let issuer = extract_xml_text(xml, "Issuer")
        .or_else(|| extract_xml_text(xml, "saml:Issuer"))
        .unwrap_or_default();

    let audience = extract_xml_text(xml, "Audience")
        .or_else(|| extract_xml_text(xml, "saml:Audience"))
        .unwrap_or_default();

    let not_before = extract_xml_attr_val(xml, "Conditions", "NotBefore")
        .or_else(|| extract_xml_attr_val(xml, "saml:Conditions", "NotBefore"))
        .and_then(|s| parse_iso_timestamp(&s))
        .unwrap_or(0);

    let not_on_or_after = extract_xml_attr_val(xml, "Conditions", "NotOnOrAfter")
        .or_else(|| extract_xml_attr_val(xml, "saml:Conditions", "NotOnOrAfter"))
        .and_then(|s| parse_iso_timestamp(&s))
        .unwrap_or(u64::MAX);

    let claims = extract_saml_attributes(xml);

    Ok((
        subject,
        issuer,
        audience,
        not_before,
        not_on_or_after,
        claims,
    ))
}

/// Parse a SAML 1.1 assertion.
#[cfg(feature = "saml")]
fn parse_saml11_assertion(xml: &str) -> Result<ParsedAssertion> {
    let subject = extract_xml_text(xml, "NameIdentifier")
        .or_else(|| extract_xml_text(xml, "saml:NameIdentifier"))
        .unwrap_or_default();

    let issuer = extract_xml_attr_val(xml, "Assertion", "Issuer")
        .or_else(|| extract_xml_attr_val(xml, "saml:Assertion", "Issuer"))
        .unwrap_or_default();

    let audience = extract_xml_text(xml, "Audience")
        .or_else(|| extract_xml_text(xml, "saml:Audience"))
        .unwrap_or_default();

    let not_before = extract_xml_attr_val(xml, "Conditions", "NotBefore")
        .or_else(|| extract_xml_attr_val(xml, "saml:Conditions", "NotBefore"))
        .and_then(|s| parse_iso_timestamp(&s))
        .unwrap_or(0);

    let not_on_or_after = extract_xml_attr_val(xml, "Conditions", "NotOnOrAfter")
        .or_else(|| extract_xml_attr_val(xml, "saml:Conditions", "NotOnOrAfter"))
        .and_then(|s| parse_iso_timestamp(&s))
        .unwrap_or(u64::MAX);

    let claims = extract_saml_attributes(xml);

    Ok((
        subject,
        issuer,
        audience,
        not_before,
        not_on_or_after,
        claims,
    ))
}

/// Extract text content from an XML element.
fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut search_from = 0;
    loop {
        let start = xml[search_from..].find(&open).map(|i| search_from + i)?;
        // Ensure we matched the exact tag, not a prefix (e.g. "Audience" vs "AudienceRestriction")
        let after_name = start + open.len();
        if after_name < xml.len() {
            let next_char = xml.as_bytes()[after_name];
            if next_char != b'>' && next_char != b' ' && next_char != b'/' {
                search_from = after_name;
                continue;
            }
        }
        let after_tag = xml[after_name..].find('>')?;
        let content_start = after_name + after_tag + 1;
        let content_end = xml[content_start..].find(&close)?;
        return Some(
            xml[content_start..content_start + content_end]
                .trim()
                .to_string(),
        );
    }
}

/// Extract an attribute value from an XML element.
fn extract_xml_attr_val(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let tag_end = xml[start..].find('>')?;
    let tag_content = &xml[start..start + tag_end];
    let attr_search = format!("{attr}=\"");
    let attr_start = tag_content.find(&attr_search)?;
    let val_start = attr_start + attr_search.len();
    let val_end = tag_content[val_start..].find('"')?;
    Some(tag_content[val_start..val_start + val_end].to_string())
}

/// Extract SAML attribute statements.
#[cfg(any(feature = "saml", test))]
fn extract_saml_attributes(xml: &str) -> HashMap<String, Vec<String>> {
    let mut attrs = HashMap::new();

    // Find all <Attribute Name="..."> elements
    let mut search_pos = 0;
    while let Some(attr_pos) = xml[search_pos..].find("<Attribute ") {
        let abs_pos = search_pos + attr_pos;
        let tag_end = match xml[abs_pos..].find('>') {
            Some(p) => abs_pos + p,
            None => break,
        };

        // Extract attribute name
        let tag_content = &xml[abs_pos..tag_end];
        let name = if let Some(n) = extract_inline_attr(tag_content, "Name") {
            n
        } else {
            search_pos = tag_end + 1;
            continue;
        };

        // Find the closing </Attribute> or </saml:Attribute>
        let close_tag = "</Attribute>";
        let alt_close = "</saml:Attribute>".to_string();
        let end_pos = xml[tag_end..]
            .find(close_tag)
            .or_else(|| xml[tag_end..].find(&alt_close))
            .map(|p| tag_end + p)
            .unwrap_or(xml.len());

        // Extract <AttributeValue> elements within this attribute
        let attr_block = &xml[tag_end + 1..end_pos];
        let values = extract_attribute_values(attr_block);

        if !values.is_empty() {
            attrs.entry(name).or_insert_with(Vec::new).extend(values);
        }

        search_pos = end_pos;
    }

    attrs
}

/// Extract the value of an inline XML attribute.
fn extract_inline_attr(tag: &str, attr: &str) -> Option<String> {
    let search = format!("{attr}=\"");
    let start = tag.find(&search)?;
    let val_start = start + search.len();
    let val_end = tag[val_start..].find('"')?;
    Some(tag[val_start..val_start + val_end].to_string())
}

/// Extract <AttributeValue> elements from an attribute block.
#[cfg(any(feature = "saml", test))]
fn extract_attribute_values(block: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut pos = 0;

    let open_tags = ["<AttributeValue", "<saml:AttributeValue"];
    let close_tags = ["</AttributeValue>", "</saml:AttributeValue>"];

    while pos < block.len() {
        let mut found = false;
        for (open, close) in open_tags.iter().zip(close_tags.iter()) {
            if let Some(start) = block[pos..].find(open) {
                let abs_start = pos + start;
                if let Some(tag_end) = block[abs_start..].find('>') {
                    let content_start = abs_start + tag_end + 1;
                    if let Some(close_pos) = block[content_start..].find(close) {
                        let val = block[content_start..content_start + close_pos].trim();
                        if !val.is_empty() {
                            values.push(val.to_string());
                        }
                        pos = content_start + close_pos + close.len();
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            break;
        }
    }

    values
}

/// Parse an ISO 8601 timestamp to Unix epoch seconds.
#[cfg(any(feature = "saml", test))]
fn parse_iso_timestamp(s: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp() as u64)
}

/// Parse federation metadata XML.
fn parse_federation_metadata(xml: &str) -> Result<FederationMetadata> {
    let entity_id = extract_xml_attr_val(xml, "EntityDescriptor", "entityID").unwrap_or_default();

    // Extract passive endpoint
    let passive_endpoint = extract_xml_attr_val(xml, "PassiveRequestorEndpoint", "Location")
        .or_else(|| {
            // Also look in Address element
            extract_xml_text(xml, "Address").or_else(|| extract_xml_text(xml, "wsa:Address"))
        });

    // Extract signing certificates
    let signing_certificates = extract_all_x509_certs(xml);

    // Extract token types offered
    let token_types = extract_xml_list_by_tag(xml, "TokenType");

    // Extract claim types
    let claim_types = extract_claim_types(xml);

    Ok(FederationMetadata {
        entity_id,
        passive_endpoint,
        signing_certificates,
        token_types_offered: token_types,
        claim_types_offered: claim_types,
    })
}

/// Extract all X509Certificate values from metadata.
fn extract_all_x509_certs(xml: &str) -> Vec<String> {
    let mut certs = Vec::new();
    let tag = "X509Certificate";
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut pos = 0;

    while let Some(start) = xml[pos..].find(&open) {
        let content_start = pos + start + open.len();
        if let Some(end) = xml[content_start..].find(&close) {
            let cert = xml[content_start..content_start + end]
                .trim()
                .replace(['\n', '\r', ' '], "");
            if !cert.is_empty() {
                certs.push(cert);
            }
            pos = content_start + end + close.len();
        } else {
            break;
        }
    }

    certs
}

/// Extract token type values.
fn extract_xml_list_by_tag(xml: &str, tag: &str) -> Vec<String> {
    let mut values = Vec::new();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut pos = 0;

    while let Some(start) = xml[pos..].find(&open) {
        let abs = pos + start;
        if let Some(tag_end) = xml[abs..].find('>') {
            let content_start = abs + tag_end + 1;
            if let Some(close_pos) = xml[content_start..].find(&close) {
                let val = xml[content_start..content_start + close_pos].trim();
                if !val.is_empty() {
                    values.push(val.to_string());
                }
                pos = content_start + close_pos + close.len();
            } else {
                break;
            }
        } else {
            break;
        }
    }

    values
}

/// Extract claim types offered from metadata.
fn extract_claim_types(xml: &str) -> Vec<ClaimTypeOffered> {
    let mut claims = Vec::new();
    let mut pos = 0;

    while let Some(start) = xml[pos..].find("<ClaimType ") {
        let abs = pos + start;
        let tag_end = match xml[abs..].find('>') {
            Some(p) => abs + p,
            None => break,
        };
        let tag = &xml[abs..tag_end];

        let uri = extract_inline_attr(tag, "Uri").unwrap_or_default();

        let close = "</ClaimType>";
        let block_end = xml[tag_end..]
            .find(close)
            .map(|p| tag_end + p + close.len())
            .unwrap_or(xml.len());

        let block = &xml[tag_end + 1..block_end.saturating_sub(close.len())];

        let display_name = extract_xml_text(block, "DisplayName");
        let description = extract_xml_text(block, "Description");

        claims.push(ClaimTypeOffered {
            uri,
            display_name,
            description,
        });

        pos = block_end;
    }

    claims
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = WsFederationConfig::default();
        assert_eq!(config.max_clock_skew_secs, 300);
        assert!(!config.require_encrypted_tokens);
    }

    #[test]
    fn test_client_requires_https() {
        let config = WsFederationConfig {
            sts_url: "http://adfs.example.com/adfs/ls".into(),
            realm: "https://app.example.com".into(),
            ..Default::default()
        };
        let err = WsFederationClient::new(config).unwrap_err();
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_client_requires_realm() {
        let config = WsFederationConfig {
            sts_url: "https://adfs.example.com/adfs/ls".into(),
            ..Default::default()
        };
        let err = WsFederationClient::new(config).unwrap_err();
        assert!(err.to_string().contains("realm"));
    }

    #[test]
    fn test_sign_in_url() {
        let config = WsFederationConfig {
            sts_url: "https://adfs.example.com/adfs/ls".into(),
            realm: "https://app.example.com".into(),
            reply_url: "https://app.example.com/auth/wsfed".into(),
            trusted_cert_thumbprints: vec!["ab".repeat(32)],
            ..Default::default()
        };
        let client = WsFederationClient::new(config).unwrap();
        let (url, wctx) = client.sign_in_url().unwrap();
        assert!(url.contains("wa=wsignin1.0"));
        assert!(url.contains("wtrealm="));
        assert!(url.contains("wreply="));
        assert!(url.contains(&wctx));
    }

    #[test]
    fn test_sign_out_url() {
        let config = WsFederationConfig {
            sts_url: "https://adfs.example.com/adfs/ls".into(),
            realm: "https://app.example.com".into(),
            reply_url: "https://app.example.com/auth/wsfed".into(),
            trusted_cert_thumbprints: vec!["ab".repeat(32)],
            ..Default::default()
        };
        let client = WsFederationClient::new(config).unwrap();
        let url = client.sign_out_url();
        assert!(url.contains("wa=wsignout1.0"));
    }

    #[test]
    fn test_parse_saml20_assertion() {
        let xml = r#"
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <saml:Subject>
                <saml:NameID>jdoe@example.com</saml:NameID>
            </saml:Subject>
            <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2034-01-01T00:00:00Z">
                <saml:AudienceRestriction>
                    <saml:Audience>https://app.example.com</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AttributeStatement>
                <Attribute Name="email">
                    <AttributeValue>jdoe@example.com</AttributeValue>
                </Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
        "#;

        let (subject, issuer, audience, _issued, _expires, claims) =
            parse_saml20_assertion(xml).unwrap();

        assert_eq!(subject, "jdoe@example.com");
        assert_eq!(issuer, "https://idp.example.com");
        assert_eq!(audience, "https://app.example.com");
        assert!(claims.contains_key("email"));
    }

    #[test]
    fn test_action_constants() {
        assert_eq!(action::SIGN_IN, "wsignin1.0");
        assert_eq!(action::SIGN_OUT, "wsignout1.0");
    }
}
