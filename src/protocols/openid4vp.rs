//! OpenID for Verifiable Presentations (OpenID4VP) and Credential Issuance.
//!
//! Provides the infrastructure for issuing, storing, and presenting
//! Verifiable Credentials using the W3C data model and the OpenID protocol suite.
//!
//! **Experimental**: Core data types and request/response structures are defined.
//! DID resolution supports `did:key:` (Ed25519, P-256) and `did:web:` methods.
//! JWS proof verification is implemented for EdDSA and ES256 algorithms.

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenId4vpConfig {
    pub enabled: bool,
    pub issuer_did: String,
    pub presentation_endpoint: String,
}

impl Default for OpenId4vpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer_did: "did:web:example.com".to_string(),
            presentation_endpoint: "/api/oid4vp/present".to_string(),
        }
    }
}

// ── DID Document types ──────────────────────────────────────────────

/// Minimal DID Document following the W3C DID Core specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<serde_json::Value>,
    #[serde(default, rename = "assertionMethod")]
    pub assertion_method: Vec<serde_json::Value>,
}

/// A verification method within a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

// ── Presentation Definition (DIF Presentation Exchange) ─────────────

/// A Presentation Definition per DIF Presentation Exchange v2.
///
/// Describes what kinds of credential(s) a verifier requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    /// Unique identifier for this definition.
    pub id: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable purpose statement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Input descriptors — each describes one required credential.
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes a single credential input requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    /// Unique identifier for this descriptor.
    pub id: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Purpose of this credential requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Constraints on the credential.
    pub constraints: InputConstraints,
}

/// Constraint filters on a credential's JSON structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConstraints {
    /// JSONPath field filters.
    pub fields: Vec<FieldConstraint>,
    /// If `required`, the field set in `fields` must all be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<String>,
}

/// A single field filter (JSONPath + optional JSON Schema filter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraint {
    /// JSONPath expressions to the target field(s).
    pub path: Vec<String>,
    /// Optional JSON-Schema filter on the field value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    /// Whether this field is optional.
    #[serde(default)]
    pub optional: bool,
}

// ── Presentation Submission ─────────────────────────────────────────

/// A Presentation Submission per DIF Presentation Exchange v2.
///
/// Accompanies a `vp_token` in the authorization response, mapping
/// each Input Descriptor to the credential that fulfills it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    /// Unique identifier for this submission.
    pub id: String,
    /// The `id` of the Presentation Definition this submission fulfills.
    pub definition_id: String,
    /// Descriptor maps connecting descriptors to credentials.
    pub descriptor_map: Vec<DescriptorMap>,
}

/// Maps an Input Descriptor to a credential location in the VP Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMap {
    /// The `id` of the matched Input Descriptor.
    pub id: String,
    /// Credential format (e.g. "jwt_vp", "ldp_vp").
    pub format: String,
    /// JSONPath to the credential in the VP Token.
    pub path: String,
    /// Nested path for credentials inside a VP envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMap>>,
}

/// Validate that a Presentation Submission matches a Presentation Definition.
///
/// Checks that every required Input Descriptor is covered by a descriptor map entry.
pub fn validate_submission(
    definition: &PresentationDefinition,
    submission: &PresentationSubmission,
) -> Result<()> {
    if submission.definition_id != definition.id {
        return Err(AuthError::validation(
            "Presentation Submission definition_id does not match Presentation Definition id",
        ));
    }

    for descriptor in &definition.input_descriptors {
        let matched = submission
            .descriptor_map
            .iter()
            .any(|dm| dm.id == descriptor.id);
        if !matched {
            return Err(AuthError::validation(format!(
                "Input Descriptor '{}' not satisfied by Presentation Submission",
                descriptor.id
            )));
        }
    }

    Ok(())
}

/// Build a minimal Presentation Definition requiring a single credential type.
pub fn simple_presentation_definition(id: &str, credential_type: &str) -> PresentationDefinition {
    PresentationDefinition {
        id: id.to_string(),
        name: Some(format!("Request for {credential_type}")),
        purpose: None,
        input_descriptors: vec![InputDescriptor {
            id: format!("{id}_input"),
            name: Some(credential_type.to_string()),
            purpose: None,
            constraints: InputConstraints {
                fields: vec![FieldConstraint {
                    path: vec!["$.type".to_string()],
                    filter: Some(serde_json::json!({
                        "type": "array",
                        "contains": { "const": credential_type }
                    })),
                    optional: false,
                }],
                limit_disclosure: None,
            },
        }],
    }
}

// ── DID Resolution ──────────────────────────────────────────────────

/// Resolve a DID to its DID Document.
///
/// Supports:
/// - `did:key:` — self-contained Ed25519 and P-256 keys
/// - `did:web:` — HTTPS-based resolution
pub async fn resolve_did(did: &str) -> Result<DidDocument> {
    if did.starts_with("did:key:") {
        resolve_did_key(did)
    } else if did.starts_with("did:web:") {
        resolve_did_web(did).await
    } else {
        Err(AuthError::invalid_credential(
            "openid4vp",
            format!("Unsupported DID method: {did}"),
        ))
    }
}

/// Resolve a `did:key:` using multicodec prefixes.
///
/// Supported key types:
/// - Ed25519 (multicodec 0xed, 32-byte key)
/// - P-256 / secp256r1 (multicodec 0x1200, 33-byte compressed key)
fn resolve_did_key(did: &str) -> Result<DidDocument> {
    let key_part = did
        .strip_prefix("did:key:")
        .ok_or_else(|| AuthError::invalid_credential("openid4vp", "Invalid did:key format"))?;

    // Multibase base58btc prefix is 'z'
    if !key_part.starts_with('z') {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            "did:key must use base58btc encoding (prefix 'z')",
        ));
    }

    let decoded = bs58::decode(&key_part[1..]).into_vec().map_err(|e| {
        AuthError::invalid_credential("openid4vp", format!("Base58 decode failed: {e}"))
    })?;

    if decoded.len() < 2 {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            "did:key decoded value too short",
        ));
    }

    // Parse multicodec varint prefix
    let (key_type, public_key_bytes) = if decoded[0] == 0xed && decoded[1] == 0x01 {
        // Ed25519: prefix 0xed01, 32-byte key
        if decoded.len() != 34 {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                format!(
                    "Ed25519 key must be 34 bytes (prefix+key), got {}",
                    decoded.len()
                ),
            ));
        }
        ("Ed25519VerificationKey2020", &decoded[2..])
    } else if decoded[0] == 0x80 && decoded.len() > 2 && decoded[1] == 0x24 {
        // P-256: varint 0x1200 encodes as [0x80, 0x24], 33-byte compressed key
        if decoded.len() != 35 {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                format!(
                    "P-256 key must be 35 bytes (prefix+key), got {}",
                    decoded.len()
                ),
            ));
        }
        ("EcdsaSecp256r1VerificationKey2019", &decoded[2..])
    } else {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            format!(
                "Unsupported multicodec prefix: 0x{:02x}{:02x}",
                decoded[0],
                decoded.get(1).copied().unwrap_or(0)
            ),
        ));
    };

    let multibase_key = format!("z{}", bs58::encode(public_key_bytes).into_string());
    let vm_id = format!("{did}#{key_part}");

    Ok(DidDocument {
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: vm_id,
            method_type: key_type.to_string(),
            controller: did.to_string(),
            public_key_jwk: None,
            public_key_multibase: Some(multibase_key),
        }],
        authentication: vec![serde_json::json!(format!("{did}#{key_part}"))],
        assertion_method: vec![serde_json::json!(format!("{did}#{key_part}"))],
    })
}

/// Resolve a `did:web:` by fetching the DID document over HTTPS.
///
/// `did:web:example.com` → `https://example.com/.well-known/did.json`
/// `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
async fn resolve_did_web(did: &str) -> Result<DidDocument> {
    let domain_path = did
        .strip_prefix("did:web:")
        .ok_or_else(|| AuthError::invalid_credential("openid4vp", "Invalid did:web format"))?;

    let parts: Vec<&str> = domain_path.split(':').collect();
    if parts.is_empty() {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            "did:web missing domain",
        ));
    }

    // Percent-decode the domain
    let domain = percent_decode(parts[0]);
    let url = if parts.len() == 1 {
        format!("https://{domain}/.well-known/did.json")
    } else {
        let path = parts[1..].join("/");
        format!("https://{domain}/{path}/did.json")
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| {
            AuthError::invalid_credential("openid4vp", format!("HTTP client error: {e}"))
        })?;

    let resp = client.get(&url).send().await.map_err(|e| {
        AuthError::invalid_credential("openid4vp", format!("Failed to fetch DID document: {e}"))
    })?;

    if !resp.status().is_success() {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            format!("DID document fetch returned HTTP {}", resp.status()),
        ));
    }

    let doc: DidDocument = resp.json().await.map_err(|e| {
        AuthError::invalid_credential("openid4vp", format!("Invalid DID document JSON: {e}"))
    })?;

    // Verify the document ID matches the DID
    if doc.id != did {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            format!(
                "DID document id '{}' does not match requested DID '{did}'",
                doc.id
            ),
        ));
    }

    Ok(doc)
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }
    result
}

// ── JWS Verification ────────────────────────────────────────────────

/// Extract the public key bytes from a verification method.
fn extract_public_key(vm: &VerificationMethod) -> Result<Vec<u8>> {
    if let Some(multibase) = &vm.public_key_multibase {
        if let Some(data) = multibase.strip_prefix('z') {
            return bs58::decode(data).into_vec().map_err(|e| {
                AuthError::invalid_credential("openid4vp", format!("Multibase decode failed: {e}"))
            });
        }
        return Err(AuthError::invalid_credential(
            "openid4vp",
            "Only base58btc (prefix 'z') multibase encoding is supported",
        ));
    }

    if let Some(jwk) = &vm.public_key_jwk {
        // For JWK, extract the raw key bytes based on key type
        if let Some(crv) = jwk.get("crv").and_then(|v| v.as_str()) {
            match crv {
                "Ed25519" => {
                    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                        AuthError::invalid_credential("openid4vp", "Ed25519 JWK missing 'x'")
                    })?;
                    return base64_url_decode(x);
                }
                "P-256" => {
                    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| {
                        AuthError::invalid_credential("openid4vp", "P-256 JWK missing 'x'")
                    })?;
                    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| {
                        AuthError::invalid_credential("openid4vp", "P-256 JWK missing 'y'")
                    })?;
                    let x_bytes = base64_url_decode(x)?;
                    let y_bytes = base64_url_decode(y)?;
                    // Uncompressed point: 0x04 || x || y
                    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                    point.push(0x04);
                    point.extend_from_slice(&x_bytes);
                    point.extend_from_slice(&y_bytes);
                    return Ok(point);
                }
                _ => {
                    return Err(AuthError::invalid_credential(
                        "openid4vp",
                        format!("Unsupported JWK curve: {crv}"),
                    ));
                }
            }
        }
    }

    Err(AuthError::invalid_credential(
        "openid4vp",
        "Verification method has no extractable public key",
    ))
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| {
            AuthError::invalid_credential("openid4vp", format!("Base64url decode error: {e}"))
        })
}

/// Verify a JWS compact serialization signature against a resolved public key.
///
/// Supports EdDSA (Ed25519) and ES256 (P-256) algorithms.
fn verify_jws(jws: &str, public_key_bytes: &[u8], key_type: &str) -> Result<bool> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::invalid_credential(
            "openid4vp",
            "JWS must have exactly 3 parts (header.payload.signature)",
        ));
    }

    let header_json = base64_url_decode(parts[0])?;
    let header: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&header_json).map_err(|e| {
            AuthError::invalid_credential("openid4vp", format!("Invalid JWS header: {e}"))
        })?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("none");

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = base64_url_decode(parts[2])?;

    match alg {
        "EdDSA" => {
            if !key_type.contains("Ed25519") {
                return Err(AuthError::invalid_credential(
                    "openid4vp",
                    "EdDSA algorithm requires Ed25519 key",
                ));
            }
            let peer_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                public_key_bytes,
            );
            peer_key
                .verify(signing_input.as_bytes(), &signature)
                .map_err(|_| {
                    AuthError::invalid_credential(
                        "openid4vp",
                        "EdDSA signature verification failed",
                    )
                })?;
            Ok(true)
        }
        "ES256" => {
            if !key_type.contains("256") && !key_type.contains("P-256") {
                return Err(AuthError::invalid_credential(
                    "openid4vp",
                    "ES256 algorithm requires P-256 key",
                ));
            }
            let peer_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                public_key_bytes,
            );
            peer_key
                .verify(signing_input.as_bytes(), &signature)
                .map_err(|_| {
                    AuthError::invalid_credential(
                        "openid4vp",
                        "ES256 signature verification failed",
                    )
                })?;
            Ok(true)
        }
        _ => Err(AuthError::invalid_credential(
            "openid4vp",
            format!("Unsupported JWS algorithm: {alg}"),
        )),
    }
}

// ── OpenID4VP Service ───────────────────────────────────────────────

pub struct OpenId4vpService {
    config: OpenId4vpConfig,
}

impl OpenId4vpService {
    pub fn new(config: OpenId4vpConfig) -> Self {
        Self { config }
    }

    /// Verifies an incoming Presentation Exchange request containing a W3C Verifiable Presentation.
    pub async fn verify_presentation(&self, vp: &serde_json::Value) -> Result<bool> {
        if !self.config.enabled {
            return Err(AuthError::config(
                "OpenID4VP protocol is currently disabled",
            ));
        }

        // 1. Check for valid VP structure according to W3C Verifiable Credentials Data Model v1.1
        let _is_vp = vp.get("verifiablePresentation").is_some() || vp.get("vp").is_some();
        let presentation = vp.get("verifiablePresentation").or_else(|| vp.get("vp"));

        let presentation_obj = match presentation {
            Some(obj) => obj,
            None => {
                if vp.get("@context").is_some() && vp.get("type").is_some() {
                    vp // Is likely already the root VP object
                } else {
                    return Err(AuthError::invalid_credential(
                        "openid4vp",
                        "Missing verifiable presentation wrapper",
                    ));
                }
            }
        };

        // 2. Validate @context
        let context = presentation_obj
            .get("@context")
            .and_then(|c| c.as_array())
            .ok_or_else(|| {
                AuthError::invalid_credential("openid4vp", "Missing or invalid @context in VP")
            })?;

        let has_w3c_context = context
            .iter()
            .any(|c| c.as_str() == Some("https://www.w3.org/2018/credentials/v1"));
        if !has_w3c_context {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "VP missing W3C credentials context",
            ));
        }

        // 3. Validate type
        let vp_type = presentation_obj
            .get("type")
            .and_then(|t| t.as_array())
            .ok_or_else(|| {
                AuthError::invalid_credential("openid4vp", "Missing or invalid type in VP")
            })?;

        if !vp_type
            .iter()
            .any(|t| t.as_str() == Some("VerifiablePresentation"))
        {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Object is not a VerifiablePresentation",
            ));
        }

        // 4. Check for verifiableCredentials array
        let credentials = presentation_obj
            .get("verifiableCredential")
            .and_then(|c| c.as_array())
            .ok_or_else(|| {
                AuthError::invalid_credential(
                    "openid4vp",
                    "No credentials included in presentation",
                )
            })?;

        if credentials.is_empty() {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Empty verifiableCredential array",
            ));
        }

        // 5. Proof / Signature Verification
        // Resolve the DID and verify the JWS signature against the public key
        let proof = presentation_obj.get("proof").ok_or_else(|| {
            AuthError::invalid_credential(
                "openid4vp",
                "Missing proof object in Verifiable Presentation",
            )
        })?;

        if proof.get("type").is_none() {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Proof missing 'type' field",
            ));
        }

        let jws = proof.get("jws").and_then(|v| v.as_str());
        let proof_value = proof.get("proofValue").and_then(|v| v.as_str());

        if jws.is_none() && proof_value.is_none() {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Proof missing both 'jws' and 'proofValue' — at least one is required",
            ));
        }

        // Validate challenge/nonce if present (recommended by OpenID4VP spec)
        if let Some(challenge) = proof.get("challenge")
            && challenge.as_str().unwrap_or("").is_empty()
        {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Proof challenge must not be empty",
            ));
        }

        // Validate domain binding if present
        if let Some(domain) = proof.get("domain")
            && domain.as_str().unwrap_or("").is_empty()
        {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Proof domain must not be empty",
            ));
        }

        // Resolve the DID to get the public key for signature verification
        let verification_method_id = proof.get("verificationMethod").and_then(|v| v.as_str());

        // Extract the DID from the verification method or the VP holder
        let did = if let Some(vm_id) = verification_method_id {
            // verificationMethod is typically "did:key:z...#z..."
            vm_id.split('#').next().unwrap_or(vm_id).to_string()
        } else if let Some(holder) = presentation_obj.get("holder").and_then(|h| h.as_str()) {
            holder.to_string()
        } else {
            return Err(AuthError::invalid_credential(
                "openid4vp",
                "Cannot determine DID: no verificationMethod or holder in proof",
            ));
        };

        // Resolve DID and verify JWS
        if let Some(jws_value) = jws {
            let did_doc = resolve_did(&did).await?;

            if did_doc.verification_method.is_empty() {
                return Err(AuthError::invalid_credential(
                    "openid4vp",
                    "Resolved DID document has no verification methods",
                ));
            }

            // Use the first matching verification method, or the first one
            let vm = if let Some(vm_id) = verification_method_id {
                did_doc
                    .verification_method
                    .iter()
                    .find(|vm| vm.id == vm_id)
                    .or_else(|| did_doc.verification_method.first())
            } else {
                did_doc.verification_method.first()
            }
            .ok_or_else(|| {
                AuthError::invalid_credential(
                    "openid4vp",
                    "No matching verification method in DID document",
                )
            })?;

            let public_key = extract_public_key(vm)?;
            verify_jws(jws_value, &public_key, &vm.method_type)?;
        }

        // 6. Validate individual credentials
        for credential in credentials {
            // Each credential should have an issuer
            if credential.get("issuer").is_none() {
                return Err(AuthError::invalid_credential(
                    "openid4vp",
                    "Credential missing 'issuer' field",
                ));
            }

            // Each credential should have a credentialSubject
            if credential.get("credentialSubject").is_none() {
                return Err(AuthError::invalid_credential(
                    "openid4vp",
                    "Credential missing 'credentialSubject' field",
                ));
            }
        }

        tracing::info!(
            "OpenID4VP: Verifiable Presentation validated — structural checks and \
             {} verification passed",
            if jws.is_some() {
                "JWS signature"
            } else {
                "proof structure"
            }
        );

        Ok(true)
    }

    /// Create an authorization request for a Verifiable Presentation (OpenID4VP §5)
    pub fn create_presentation_request(
        &self,
        nonce: &str,
        presentation_definition: serde_json::Value,
    ) -> Result<serde_json::Value> {
        if !self.config.enabled {
            return Err(AuthError::config(
                "OpenID4VP protocol is currently disabled",
            ));
        }

        if nonce.is_empty() {
            return Err(AuthError::validation("nonce must not be empty"));
        }

        Ok(serde_json::json!({
            "response_type": "vp_token",
            "client_id": self.config.issuer_did,
            "nonce": nonce,
            "presentation_definition": presentation_definition,
            "response_mode": "direct_post",
            "response_uri": self.config.presentation_endpoint,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> OpenId4vpConfig {
        OpenId4vpConfig {
            enabled: true,
            ..Default::default()
        }
    }

    // ── DID Resolution ──────────────────────────────────────────

    #[test]
    fn test_resolve_did_key_ed25519() {
        // Known Ed25519 did:key (multicodec 0xed01 + 32 zero bytes)
        let mut key_bytes = vec![0xed, 0x01];
        key_bytes.extend_from_slice(&[0u8; 32]);
        let encoded = format!("z{}", bs58::encode(&key_bytes).into_string());
        let did = format!("did:key:{encoded}");

        let doc = resolve_did_key(&did).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].method_type,
            "Ed25519VerificationKey2020"
        );
        assert!(doc.verification_method[0].public_key_multibase.is_some());
    }

    #[test]
    fn test_resolve_did_key_p256() {
        // P-256 compressed point (0x02 prefix + 32 bytes)
        let mut key_bytes = vec![0x80, 0x24]; // varint encoding of 0x1200
        let mut compressed_point = vec![0x02]; // compressed point prefix
        compressed_point.extend_from_slice(&[0xAA; 32]);
        key_bytes.extend_from_slice(&compressed_point);
        let encoded = format!("z{}", bs58::encode(&key_bytes).into_string());
        let did = format!("did:key:{encoded}");

        let doc = resolve_did_key(&did).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].method_type,
            "EcdsaSecp256r1VerificationKey2019"
        );
    }

    #[test]
    fn test_resolve_did_key_unsupported_prefix() {
        let key_bytes = vec![0xFF, 0xFF, 0x00, 0x01];
        let encoded = format!("z{}", bs58::encode(&key_bytes).into_string());
        let did = format!("did:key:{encoded}");

        let err = resolve_did_key(&did);
        assert!(err.is_err());
    }

    #[test]
    fn test_resolve_did_key_invalid_multibase() {
        let did = "did:key:m123456"; // 'm' is not base58btc
        let err = resolve_did_key(did);
        assert!(err.is_err());
    }

    #[test]
    fn test_resolve_did_key_short_value() {
        let encoded = format!("z{}", bs58::encode(&[0xed]).into_string());
        let did = format!("did:key:{encoded}");
        let err = resolve_did_key(&did);
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_resolve_did_unsupported_method() {
        let err = resolve_did("did:example:12345").await;
        assert!(err.is_err());
    }

    // ── Key Extraction ──────────────────────────────────────────

    #[test]
    fn test_extract_public_key_multibase() {
        let vm = VerificationMethod {
            id: "did:key:z...#z...".to_string(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            controller: "did:key:z...".to_string(),
            public_key_jwk: None,
            public_key_multibase: Some(format!("z{}", bs58::encode(&[0u8; 32]).into_string())),
        };
        let key = extract_public_key(&vm).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_extract_public_key_jwk_ed25519() {
        use base64::Engine;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0xAB; 32]);
        let vm = VerificationMethod {
            id: "key1".to_string(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            controller: "did:key:z...".to_string(),
            public_key_jwk: Some(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
            })),
            public_key_multibase: None,
        };
        let key = extract_public_key(&vm).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_extract_public_key_jwk_p256() {
        use base64::Engine;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0x01; 32]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0x02; 32]);
        let vm = VerificationMethod {
            id: "key1".to_string(),
            method_type: "EcdsaSecp256r1VerificationKey2019".to_string(),
            controller: "did:key:z...".to_string(),
            public_key_jwk: Some(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
            })),
            public_key_multibase: None,
        };
        let key = extract_public_key(&vm).unwrap();
        // Uncompressed point: 0x04 || x(32) || y(32) = 65 bytes
        assert_eq!(key.len(), 65);
        assert_eq!(key[0], 0x04);
    }

    #[test]
    fn test_extract_public_key_no_key_data() {
        let vm = VerificationMethod {
            id: "key1".to_string(),
            method_type: "SomeType".to_string(),
            controller: "did:key:z...".to_string(),
            public_key_jwk: None,
            public_key_multibase: None,
        };
        assert!(extract_public_key(&vm).is_err());
    }

    // ── JWS Verification ────────────────────────────────────────

    #[test]
    fn test_verify_jws_invalid_parts() {
        let err = verify_jws("only.two", &[0; 32], "Ed25519");
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_jws_unsupported_algorithm() {
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256"}"#.as_bytes());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"test");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jws = format!("{header}.{payload}.{sig}");
        let err = verify_jws(&jws, &[0; 32], "Ed25519");
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_jws_ed25519_with_real_signing() {
        use base64::Engine;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        // Generate an Ed25519 key pair
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();

        // Create JWS components
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA"}"#.as_bytes());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"test payload");
        let signing_input = format!("{header}.{payload}");
        let signature = key_pair.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref());

        let jws = format!("{signing_input}.{sig_b64}");
        let result = verify_jws(&jws, &public_key, "Ed25519VerificationKey2020").unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_jws_ed25519_bad_signature() {
        use base64::Engine;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA"}"#.as_bytes());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"test");
        let bad_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0u8; 64]);

        let jws = format!("{header}.{payload}.{bad_sig}");
        let err = verify_jws(&jws, &public_key, "Ed25519VerificationKey2020");
        assert!(err.is_err());
    }

    // ── Service Tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_verify_disabled() {
        let svc = OpenId4vpService::new(OpenId4vpConfig::default());
        let vp = serde_json::json!({"test": true});
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_missing_vp_wrapper() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({"not_a_vp": true});
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_missing_context() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({
            "type": ["VerifiablePresentation"],
        });
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_wrong_type() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["SomethingElse"],
        });
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_empty_credentials() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [],
        });
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_missing_proof() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [{
                "issuer": "did:example:123",
                "credentialSubject": {"id": "did:example:456"},
            }],
        });
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_proof_missing_jws_and_proof_value() {
        let svc = OpenId4vpService::new(enabled_config());
        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [{
                "issuer": "did:example:123",
                "credentialSubject": {"id": "did:example:456"},
            }],
            "proof": {
                "type": "Ed25519Signature2020",
            },
        });
        let err = svc.verify_presentation(&vp).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_verify_full_vp_with_ed25519_proof() {
        use base64::Engine;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let svc = OpenId4vpService::new(enabled_config());

        // Generate key pair
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key().as_ref();

        // Build did:key from Ed25519 public key
        let mut mc_bytes = vec![0xed, 0x01];
        mc_bytes.extend_from_slice(public_key);
        let did_key_fragment = format!("z{}", bs58::encode(&mc_bytes).into_string());
        let did = format!("did:key:{did_key_fragment}");

        // Create JWS
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA"}"#.as_bytes());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{header}.{payload}");
        let signature = key_pair.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref());
        let jws = format!("{signing_input}.{sig_b64}");

        let vm_id = format!("{did}#{did_key_fragment}");

        let vp = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": did,
            "verifiableCredential": [{
                "issuer": "did:example:issuer",
                "credentialSubject": {"id": "did:example:subject"},
            }],
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": vm_id,
                "jws": jws,
                "challenge": "abc123",
            },
        });

        let result = svc.verify_presentation(&vp).await.unwrap();
        assert!(result);
    }

    #[test]
    fn test_create_presentation_request() {
        let svc = OpenId4vpService::new(enabled_config());
        let req = svc
            .create_presentation_request("nonce123", serde_json::json!({"input_descriptors": []}))
            .unwrap();
        assert_eq!(req["response_type"], "vp_token");
        assert_eq!(req["nonce"], "nonce123");
    }

    #[test]
    fn test_create_presentation_request_empty_nonce() {
        let svc = OpenId4vpService::new(enabled_config());
        let err = svc.create_presentation_request("", serde_json::json!({}));
        assert!(err.is_err());
    }

    #[test]
    fn test_create_presentation_request_disabled() {
        let svc = OpenId4vpService::new(OpenId4vpConfig::default());
        let err = svc.create_presentation_request("nonce", serde_json::json!({}));
        assert!(err.is_err());
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("no-encoding"), "no-encoding");
        assert_eq!(percent_decode("%41%42"), "AB");
    }

    // ── DID Document serialization ──────────────────────────────

    #[test]
    fn test_did_document_roundtrip() {
        let doc = DidDocument {
            id: "did:key:z123".to_string(),
            verification_method: vec![VerificationMethod {
                id: "did:key:z123#z123".to_string(),
                method_type: "Ed25519VerificationKey2020".to_string(),
                controller: "did:key:z123".to_string(),
                public_key_jwk: None,
                public_key_multibase: Some("z123".to_string()),
            }],
            authentication: vec![serde_json::json!("did:key:z123#z123")],
            assertion_method: vec![],
        };

        let json = serde_json::to_string(&doc).unwrap();
        let deserialized: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, doc.id);
        assert_eq!(deserialized.verification_method.len(), 1);
    }
}
