use crate::api::{ApiResponse, ApiState};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Escape a string for safe inclusion in XML attribute values and text content.
/// Prevents XML injection by escaping the five predefined XML entities.
fn xml_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(ch),
        }
    }
    output
}

#[cfg(feature = "saml")]
use bergshamra::{DsigContext, Key, KeyData, KeysManager, VerifyResult, verify};
#[cfg(feature = "saml")]
use quick_xml::Reader;
#[cfg(feature = "saml")]
use quick_xml::events::Event;
#[cfg(feature = "saml")]
use quick_xml::name::QName;

/// Extract the local name (without namespace prefix) from a `QName`, taking
/// ownership to avoid temporary-lifetime issues from method chaining.
#[cfg(feature = "saml")]
fn xml_local<'a>(name: QName<'a>) -> &'a [u8] {
    let full = name.0;
    match full.iter().position(|&b| b == b':') {
        Some(pos) => &full[pos + 1..],
        None => full,
    }
}

/// SAML SSO initiation request
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlSsoRequest {
    pub idp_entity_id: String,
    pub relay_state: Option<String>,
    pub force_authn: Option<bool>,
    pub is_passive: Option<bool>,
}

/// SAML SSO response containing redirect URL
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlSsoResponse {
    pub redirect_url: String,
    pub saml_request: String,
    pub relay_state: Option<String>,
}

/// SAML ACS (Assertion Consumer Service) request
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlAcsRequest {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
    #[serde(rename = "SigAlg")]
    pub sig_alg: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<String>,
}

/// SAML metadata configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlMetadataResponse {
    pub entity_id: String,
    pub acs_url: String,
    pub sls_url: Option<String>,
    pub certificate: Option<String>,
    pub name_id_format: String,
}

#[derive(Debug, Deserialize)]
struct SamlSpConfig {
    entity_id: String,
    acs_url: String,
    #[serde(default)]
    slo_url: Option<String>,
}

impl SamlSpConfig {
    fn validate(self) -> Result<Self, String> {
        if self.entity_id.trim().is_empty() {
            return Err("missing entity_id".to_string());
        }
        if self.acs_url.trim().is_empty() {
            return Err("missing acs_url".to_string());
        }
        Ok(self)
    }

    fn slo_url(&self) -> Result<&str, String> {
        self.slo_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "missing slo_url".to_string())
    }
}

async fn load_saml_sp_config(state: &ApiState) -> Result<SamlSpConfig, String> {
    let data = state
        .auth_framework
        .storage()
        .get_kv("saml_sp:config")
        .await
        .map_err(|_| "failed to load saml_sp:config".to_string())?
        .ok_or_else(|| "missing saml_sp:config".to_string())?;

    serde_json::from_slice::<SamlSpConfig>(&data)
        .map_err(|_| "invalid saml_sp:config JSON".to_string())?
        .validate()
}

/// SAML logout request
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlLogoutRequest {
    pub name_id: String,
    pub session_index: Option<String>,
    pub idp_entity_id: String,
}

/// SAML logout response
#[derive(Debug, Serialize, Deserialize)]
pub struct SamlLogoutResponse {
    pub redirect_url: String,
    pub status: String,
}

/// Get SAML metadata for this SP (Service Provider).
/// SP configuration (entity_id, acs_url, slo_url) is read from storage key `saml_sp:config`.
/// Store a JSON object with those fields to customise the metadata for your deployment.
pub async fn get_saml_metadata(State(state): State<ApiState>) -> impl IntoResponse {
    let sp_config = match load_saml_sp_config(&state).await {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "SAML metadata requested without valid SP configuration");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("SAML service provider configuration is missing or incomplete".to_string()),
            )
                .into_response();
        }
    };
    let slo_url = match sp_config.slo_url() {
        Ok(url) => url,
        Err(error) => {
            tracing::error!(error = %error, "SAML metadata requested without SLO URL configured");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("SAML service provider configuration is missing or incomplete".to_string()),
            )
                .into_response();
        }
    };

    let metadata_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="{acs_url}"
                                index="0" />
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                               Location="{slo_url}" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#,
        entity_id = xml_escape(&sp_config.entity_id),
        acs_url = xml_escape(&sp_config.acs_url),
        slo_url = xml_escape(slo_url),
    );

    // Return SAML metadata with correct Content-Type per SAML metadata spec
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/samlmetadata+xml",
        )],
        metadata_xml,
    )
        .into_response()
}

/// Initiate SAML SSO flow.
/// The IdP must be pre-registered in storage under the key `saml_idp:{idp_entity_id}`
/// as a JSON object with at least a `sso_url` field.  SP configuration is read from
/// `saml_sp:config` (fields: `entity_id`, `acs_url`).
pub async fn initiate_saml_sso(
    State(state): State<ApiState>,
    Json(request): Json<SamlSsoRequest>,
) -> Json<ApiResponse<SamlSsoResponse>> {
    // Look up IdP SSO URL from storage — reject unknown IdPs rather than
    // redirecting to a hardcoded placeholder.
    let idp_key = format!("saml_idp:{}", request.idp_entity_id);
    let idp_sso_url = match state.auth_framework.storage().get_kv(&idp_key).await {
        Ok(Some(data)) => {
            let cfg: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
            match cfg["sso_url"].as_str() {
                Some(url) => url.to_string(),
                None => {
                    return Json(ApiResponse::error_typed(
                        "SAML_CONFIG_ERROR",
                        "IdP config is missing required sso_url field",
                    ));
                }
            }
        }
        Ok(None) => {
            tracing::warn!(idp = %request.idp_entity_id, "SAML SSO: unknown IdP entity ID");
            return Json(ApiResponse::error_typed(
                "SAML_UNKNOWN_IDP",
                format!("IdP not configured: {}", request.idp_entity_id),
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "SAML SSO: storage error looking up IdP");
            return Json(ApiResponse::error_typed(
                "server_error",
                "Failed to look up IdP configuration",
            ));
        }
    };

    let sp_config = match load_saml_sp_config(&state).await {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "SAML SSO requested without valid SP configuration");
            return Json(ApiResponse::error_typed(
                "SAML_CONFIG_ERROR",
                "Service Provider configuration is missing required entity_id and acs_url values",
            ));
        }
    };

    // Generate SAML AuthnRequest
    let request_id = format!("saml_{}", uuid::Uuid::new_v4());
    let issue_instant = chrono::Utc::now().to_rfc3339();

    let saml_request = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="{request_id}"
                           Version="2.0"
                           IssueInstant="{issue_instant}"
                           Destination="{idp_sso_url}"
                           {force_authn}
                           {is_passive}
                           AssertionConsumerServiceURL="{sp_acs_url}">
  <saml:Issuer>{sp_entity_id}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                      AllowCreate="true" />
</samlp:AuthnRequest>"#,
        force_authn = request
            .force_authn
            .map_or(String::new(), |fa| format!(r#"ForceAuthn="{}""#, fa)),
        is_passive = request
            .is_passive
            .map_or(String::new(), |ip| format!(r#"IsPassive="{}""#, ip)),
        sp_entity_id = xml_escape(&sp_config.entity_id),
        sp_acs_url = xml_escape(&sp_config.acs_url),
        idp_sso_url = xml_escape(&idp_sso_url),
    );

    // Encode SAML request
    let encoded_request = base64::engine::general_purpose::STANDARD.encode(&saml_request);

    // Build redirect URL
    let mut redirect_url = format!(
        "{}?SAMLRequest={}",
        idp_sso_url,
        urlencoding::encode(&encoded_request)
    );

    if let Some(relay_state) = &request.relay_state {
        redirect_url.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
    }

    // Persist the AuthnRequest so the ACS handler can validate InResponseTo.
    let request_key = format!("saml_request:{}", request_id);
    let request_data = serde_json::json!({
        "request_id": request_id,
        "idp_entity_id": request.idp_entity_id,
        "relay_state": request.relay_state,
        "issued_at": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &request_key,
            request_data.as_bytes(),
            Some(std::time::Duration::from_secs(600)),
        )
        .await
    {
        tracing::warn!(error = %e, "SAML SSO: failed to persist AuthnRequest — InResponseTo validation will be skipped");
    }

    Json(ApiResponse::success(SamlSsoResponse {
        redirect_url,
        saml_request: encoded_request,
        relay_state: request.relay_state,
    }))
}

/// Handle SAML ACS (Assertion Consumer Service) - where IdP sends response
#[allow(unreachable_code, unused_variables)]
pub async fn handle_saml_acs(
    State(state): State<ApiState>,
    axum::Form(form_data): axum::Form<SamlAcsRequest>,
) -> Json<ApiResponse<serde_json::Value>> {
    // Decode SAML response
    let saml_response_xml =
        match base64::engine::general_purpose::STANDARD.decode(&form_data.saml_response) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(xml) => xml,
                Err(e) => {
                    tracing::warn!(error = %e, "SAML ACS: invalid UTF-8 in decoded response");
                    return Json(ApiResponse::validation_error_typed(
                        "Invalid SAML response encoding",
                    ));
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "SAML ACS: base64 decode failed");
                return Json(ApiResponse::validation_error_typed(
                    "Invalid SAML response encoding",
                ));
            }
        };

    // --- XML Digital Signature Validation ---
    #[cfg(feature = "saml")]
    {
        match validate_saml_signature(&state, &saml_response_xml).await {
            Ok(()) => {
                tracing::info!("SAML ACS: XML signature validated successfully");
            }
            Err(e) => {
                tracing::error!(error = %e, "SAML ACS: XML signature validation failed");
                return Json(ApiResponse::error_typed(
                    "SAML_SIGNATURE_INVALID",
                    format!("SAML response signature validation failed: {}", e),
                ));
            }
        }
    }
    #[cfg(not(feature = "saml"))]
    {
        tracing::error!(
            "SAML ACS: XML signature validation is not available — \
             the 'saml' feature is required for secure SAML processing"
        );
        return Json(ApiResponse::error_typed(
            "SAML_SIGNATURE_UNAVAILABLE",
            "SAML signature validation is not available; the server must be compiled with the 'saml' feature",
        ));
    }

    if !saml_response_xml.contains("<saml:Assertion")
        && !saml_response_xml.contains("<saml2:Assertion")
        && !saml_response_xml.contains("<Assertion")
    {
        return Json(ApiResponse::validation_error_typed(
            "No SAML assertion found",
        ));
    }

    // Validate InResponseTo: the SAML response must reference an AuthnRequest that
    // we actually issued.  This prevents unsolicited response injection attacks.
    if let Some(irt) = extract_in_response_to(&saml_response_xml) {
        let request_key = format!("saml_request:{}", irt);
        match state.auth_framework.storage().get_kv(&request_key).await {
            Ok(Some(_)) => {
                // Valid outstanding request — consume it so it cannot be replayed.
                let _ = state.auth_framework.storage().delete_kv(&request_key).await;
            }
            _ => {
                tracing::warn!(in_response_to = %irt, "SAML ACS: InResponseTo references unknown or expired request");
                return Json(ApiResponse::error_typed(
                    "SAML_INVALID_RESPONSE",
                    "SAML response references an unknown or expired authentication request",
                ));
            }
        }
    } else {
        // Unsolicited SAML responses (no InResponseTo) are a common attack vector.
        tracing::warn!(
            "SAML ACS: response has no InResponseTo attribute — rejecting unsolicited response"
        );
        return Json(ApiResponse::error_typed(
            "SAML_UNSOLICITED_RESPONSE",
            "Unsolicited SAML responses are not accepted; initiate SSO via /api/v1/saml/sso first",
        ));
    }

    // --- SAML Assertion Conditions Validation ---
    // Validate NotBefore, NotOnOrAfter, and AudienceRestriction per SAML Core 2.5.1.
    #[cfg(feature = "saml")]
    {
        let sp_entity_id = match load_saml_sp_config(&state).await {
            Ok(config) => config.entity_id,
            Err(error) => {
                tracing::error!(error = %error, "SAML ACS requested without valid SP configuration");
                return Json(ApiResponse::error_typed(
                    "SAML_CONFIG_ERROR",
                    "Service Provider configuration is missing required entity_id and acs_url values",
                ));
            }
        };

        if let Err(e) = validate_saml_conditions(&saml_response_xml, &sp_entity_id) {
            tracing::warn!(error = %e, "SAML ACS: assertion conditions validation failed");
            return Json(ApiResponse::error_typed("SAML_CONDITIONS_INVALID", e));
        }
    }

    // Extract user information from assertion
    let username = match extract_username_from_saml(&saml_response_xml) {
        Ok(user) => user,
        Err(e) => return Json(ApiResponse::error_typed("SAML_PARSE_ERROR", e)),
    };

    let attributes = match extract_attributes_from_saml(&saml_response_xml) {
        Ok(attrs) => attrs,
        Err(e) => return Json(ApiResponse::error_typed("SAML_PARSE_ERROR", e)),
    };

    // Issue a proper JWT/auth token using the framework's token infrastructure.
    let scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
    ];
    let token = match state
        .auth_framework
        .token_manager()
        .create_auth_token(&username, scopes, "saml", None)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(user = %username, error = %e, "SAML ACS: failed to create auth token");
            return Json(ApiResponse::error_typed(
                "server_error",
                "Failed to create authentication token",
            ));
        }
    };

    let token_data = serde_json::json!({
        "access_token": token.access_token,
        "token_type": "Bearer",
        "expires_in": (token.expires_at - token.issued_at).num_seconds().max(0) as u64,
        "refresh_token": token.refresh_token,
        "user_id": username,
        "authentication_method": "saml",
        "attributes": attributes,
        "relay_state": form_data.relay_state
    });

    tracing::info!(user = %username, "SAML authentication successful");
    Json(ApiResponse::success_with_message(
        token_data,
        "SAML authentication successful",
    ))
}

/// Initiate SAML Single Logout (SLO).
/// The IdP must be pre-registered in storage under `saml_idp:{idp_entity_id}` with a `slo_url` field.
pub async fn initiate_saml_slo(
    State(state): State<ApiState>,
    Json(request): Json<SamlLogoutRequest>,
) -> Json<ApiResponse<SamlLogoutResponse>> {
    // Look up IdP SLO URL from storage.
    let idp_key = format!("saml_idp:{}", request.idp_entity_id);
    let idp_slo_url = match state.auth_framework.storage().get_kv(&idp_key).await {
        Ok(Some(data)) => {
            let cfg: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
            match cfg["slo_url"].as_str() {
                Some(url) => url.to_string(),
                None => {
                    return Json(ApiResponse::error_typed(
                        "SAML_CONFIG_ERROR",
                        "IdP config is missing required slo_url field",
                    ));
                }
            }
        }
        Ok(None) => {
            tracing::warn!(idp = %request.idp_entity_id, "SAML SLO: unknown IdP entity ID");
            return Json(ApiResponse::error_typed(
                "SAML_UNKNOWN_IDP",
                format!("IdP not configured: {}", request.idp_entity_id),
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "SAML SLO: storage error looking up IdP");
            return Json(ApiResponse::error_typed(
                "server_error",
                "Failed to look up IdP configuration",
            ));
        }
    };

    let sp_config = match load_saml_sp_config(&state).await {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "SAML SLO requested without valid SP configuration");
            return Json(ApiResponse::error_typed(
                "SAML_CONFIG_ERROR",
                "Service Provider configuration is missing required entity_id and acs_url values",
            ));
        }
    };

    let logout_id = format!("logout_{}", uuid::Uuid::new_v4());
    let issue_instant = chrono::Utc::now().to_rfc3339();

    // Build SAML LogoutRequest
    let saml_logout_request = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="{logout_id}"
                            Version="2.0"
                            IssueInstant="{issue_instant}"
                            Destination="{idp_slo_url}">
    <saml:Issuer>{sp_entity_id}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
  {session_index}
</samlp:LogoutRequest>"#,
        name_id = xml_escape(&request.name_id),
        session_index = request.session_index.map_or(String::new(), |si| format!(
            r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#,
            xml_escape(&si)
        )),
        sp_entity_id = xml_escape(&sp_config.entity_id),
        idp_slo_url = xml_escape(&idp_slo_url),
    );

    let encoded_request = base64::engine::general_purpose::STANDARD.encode(&saml_logout_request);
    let redirect_url = format!(
        "{}?SAMLRequest={}",
        idp_slo_url,
        urlencoding::encode(&encoded_request)
    );

    Json(ApiResponse::success_with_message(
        SamlLogoutResponse {
            redirect_url,
            status: "logout_initiated".to_string(),
        },
        "SAML logout initiated",
    ))
}

/// Handle SAML SLO response from IdP
pub async fn handle_saml_slo_response(
    State(_state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<ApiResponse<()>> {
    #[cfg(not(feature = "saml"))]
    {
        let _ = params;
        Json(ApiResponse::error_typed(
            "SAML_SIGNATURE_UNAVAILABLE",
            "SAML logout response validation is not available; the server must be compiled with the 'saml' feature",
        ))
    }

    #[cfg(feature = "saml")]
    {
        let saml_response = match params.get("SAMLResponse") {
            Some(response) => response,
            None => {
                return Json(ApiResponse::validation_error(
                    "Missing SAMLResponse parameter",
                ));
            }
        };

        // Decode and validate SLO response.
        let response_xml = match base64::engine::general_purpose::STANDARD.decode(saml_response) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(xml) => xml,
                Err(e) => {
                    return Json(ApiResponse::validation_error(format!(
                        "Invalid SLO response UTF-8: {}",
                        e
                    )));
                }
            },
            Err(e) => {
                return Json(ApiResponse::validation_error(format!(
                    "Invalid SLO response encoding: {}",
                    e
                )));
            }
        };

        let slo_success = xml_extract_status_code(&response_xml)
            .map(|code| code == "urn:oasis:names:tc:SAML:2.0:status:Success")
            .unwrap_or(false);

        if slo_success {
            // Invalidate the user's session associated with this SAML exchange.
            // The SAML response should carry the NameID that maps to our user.
            if let Some(name_id) = xml_extract_name_id(&response_xml) {
                // Look up user by email (NameID) and invalidate their sessions.
                if let Ok(Some(uid_bytes)) = _state
                    .auth_framework
                    .storage()
                    .get_kv(&format!("user:email:{}", name_id))
                    .await
                {
                    let user_id = String::from_utf8_lossy(&uid_bytes).to_string();
                    let session_key = format!("sessions:user:{}", user_id);
                    let _ = _state
                        .auth_framework
                        .storage()
                        .delete_kv(&session_key)
                        .await;
                    tracing::info!(user_id = %user_id, "SAML SLO: invalidated sessions");
                }
            }

            // Handle RelayState redirect if provided
            if let Some(relay_state) = params.get("RelayState") {
                if !relay_state.is_empty() {
                    tracing::debug!(relay_state = %relay_state, "SAML SLO: RelayState provided");
                }
            }

            Json(ApiResponse::<()>::ok_with_message(
                "SAML logout completed successfully",
            ))
        } else {
            Json(ApiResponse::error(
                "SAML_LOGOUT_FAILED",
                "SAML logout failed",
            ))
        }
    }
}

/// Create SAML assertion (for Identity Provider functionality)
pub async fn create_saml_assertion(
    State(state): State<ApiState>,
    Json(request): Json<serde_json::Value>,
) -> Json<ApiResponse<String>> {
    let username = match request["username"].as_str() {
        Some(user) => user,
        None => return Json(ApiResponse::validation_error_typed("Username required")),
    };

    let audience = match request["audience"].as_str() {
        Some(aud) => aud,
        None => return Json(ApiResponse::validation_error_typed("Audience required")),
    };

    let sp_config = match load_saml_sp_config(&state).await {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(error = %error, "SAML assertion requested without valid SP configuration");
            return Json(ApiResponse::error_typed(
                "SAML_CONFIG_ERROR",
                "Service Provider configuration is missing required entity_id and acs_url values",
            ));
        }
    };

    let name_id = match request["email"].as_str().map(str::trim) {
        Some(email) if !email.is_empty() => email.to_string(),
        _ if username.contains('@') => username.to_string(),
        _ => {
            return Json(ApiResponse::validation_error_typed(
                "Email required when username is not an email address",
            ));
        }
    };

    // Create SAML assertion with Response wrapper.
    // Note: In production, this assertion should be signed with an XML-DSig
    // private key. Without signing, relying parties that enforce signature
    // verification will reject the assertion.
    let assertion_id = uuid::Uuid::new_v4();
    let response_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let not_before = (now - chrono::Duration::minutes(1)).to_rfc3339();
    let not_after = (now + chrono::Duration::hours(1)).to_rfc3339();
    let now_str = now.to_rfc3339();
    // Issuer is our own entity (acting as IdP), not the SP
    let issuer = xml_escape(&sp_config.entity_id);
    let audience_escaped = xml_escape(audience);
    let name_id_escaped = xml_escape(&name_id);
    let username_escaped = xml_escape(username);

    let assertion_xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                         xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                         ID="response_{response_id}"
                         IssueInstant="{now_str}"
                         Destination="{audience_escaped}"
                         Version="2.0">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="assertion_{assertion_id}"
                  IssueInstant="{now_str}"
                  Version="2.0">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id_escaped}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_after}" Recipient="{audience_escaped}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience_escaped}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{now_str}" SessionIndex="session_{assertion_id}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="username">
        <saml:AttributeValue>{username_escaped}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{name_id_escaped}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#,
    );

    Json(ApiResponse::success_with_message(
        assertion_xml,
        "SAML assertion created",
    ))
}

/// List configured SAML Identity Providers.
/// IdPs are indexed in storage under the key `saml_idps:index` (JSON array of entity ID strings).
/// Each IdP's configuration is stored under `saml_idp:{entity_id}`.
pub async fn list_saml_idps(
    State(state): State<ApiState>,
) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    // Load the IdP index from storage.
    let entity_ids: Vec<String> = match state
        .auth_framework
        .storage()
        .get_kv("saml_idps:index")
        .await
    {
        Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
        Ok(None) => vec![],
        Err(e) => {
            tracing::error!(error = %e, "Failed to load SAML IdP index");
            return Json(ApiResponse::error_typed(
                "server_error",
                "Failed to load IdP list",
            ));
        }
    };

    // Fetch each IdP's config.
    let mut idps = Vec::with_capacity(entity_ids.len());
    for entity_id in &entity_ids {
        let key = format!("saml_idp:{}", entity_id);
        if let Ok(Some(data)) = state.auth_framework.storage().get_kv(&key).await
            && let Ok(cfg) = serde_json::from_slice::<serde_json::Value>(&data)
        {
            idps.push(cfg);
        }
    }

    Json(ApiResponse::success_with_message(
        idps,
        "SAML IdPs retrieved",
    ))
}

/// Validate the XML-DSig signature on a SAML response using the IdP's trusted signing key.
///
/// The IdP's signing certificate (PEM-encoded X.509) must be stored under
/// `saml_idp:{entity_id}` in the `signing_cert` field.  The IdP entity ID is
/// extracted from the `<saml:Issuer>` element inside the SAML response.
///
/// Uses bergshamra with SAML-hardened settings:
/// - `trusted_keys_only = true` — ignores attacker-embedded inline KeyInfo
/// - `strict_verification = true` — XSW attack protection
/// - `verify_keys = true` — validates key certificates
#[cfg(feature = "saml")]
async fn validate_saml_signature(state: &ApiState, saml_xml: &str) -> Result<(), String> {
    // Extract the IdP entity ID (Issuer) from the response so we can look up
    // the correct signing key.
    let issuer = extract_issuer(saml_xml)
        .ok_or_else(|| "SAML response does not contain an Issuer element".to_string())?;

    // Load the IdP's signing certificate from storage.
    let idp_key = format!("saml_idp:{}", issuer);
    let idp_cfg_data = state
        .auth_framework
        .storage()
        .get_kv(&idp_key)
        .await
        .map_err(|e| format!("Storage error loading IdP config: {}", e))?
        .ok_or_else(|| format!("IdP not configured: {}", issuer))?;

    let idp_cfg: serde_json::Value = serde_json::from_slice(&idp_cfg_data)
        .map_err(|e| format!("Invalid IdP config JSON: {}", e))?;

    let signing_cert_pem = idp_cfg["signing_cert"]
        .as_str()
        .ok_or_else(|| format!("IdP '{}' has no signing_cert configured", issuer))?;

    // Parse PEM certificate to DER bytes.
    let der_bytes = pem_to_der(signing_cert_pem)?;

    // Build the KeysManager with the trusted IdP key.
    let mut keys_manager = KeysManager::new();

    // Parse the X.509 certificate to extract the public key, then build a
    // bergshamra Key from it.  Most SAML IdPs use RSA; we also support ECDSA.
    let key = key_from_x509_der(&der_bytes)?;
    keys_manager.add_key(key);

    // Also register the cert as a trusted certificate for chain validation.
    keys_manager.add_trusted_cert(der_bytes);

    // SAML-hardened DsigContext configuration:
    // - trusted_keys_only: only use our pre-loaded IdP key, ignore inline KeyInfo
    // - strict_verification: reject XSW (XML Signature Wrapping) attacks
    // - verify_keys: validate certificates on the keys
    let ctx = DsigContext::new(keys_manager)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_verify_keys(true);

    // Verify the XML signature.
    let result =
        verify(&ctx, saml_xml).map_err(|e| format!("XML-DSig verification error: {}", e))?;

    match result {
        VerifyResult::Valid { references, .. } => {
            // Ensure the signature actually covers content (not an empty reference set).
            if references.is_empty() {
                return Err("Signature is valid but covers no references".to_string());
            }
            Ok(())
        }
        VerifyResult::Invalid { reason } => Err(format!("Signature invalid: {}", reason)),
    }
}

/// Decode a PEM-encoded certificate to raw DER bytes.
#[cfg(feature = "saml")]
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    // Strip PEM headers/footers and whitespace, then base64-decode.
    let b64: String = pem
        .lines()
        .filter(|line| {
            !line.starts_with("-----BEGIN") && !line.starts_with("-----END") && !line.is_empty()
        })
        .collect::<Vec<&str>>()
        .join("");

    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("Failed to base64-decode PEM certificate: {}", e))
}

/// Extract a bergshamra `Key` from a DER-encoded X.509 certificate.
///
/// Supports RSA and ECDSA (P-256/P-384) public keys — the algorithms used by
/// the vast majority of SAML Identity Providers.
#[cfg(feature = "saml")]
fn key_from_x509_der(der: &[u8]) -> Result<Key, String> {
    use rsa::pkcs8::DecodePublicKey;
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| format!("Failed to parse X.509 certificate: {}", e))?;

    let spki = cert.public_key();
    let spki_der = spki.raw;

    // Try RSA first (by far the most common in SAML).
    if let Ok(rsa_pub) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::Rsa {
                public: rsa_pub,
                private: None,
            },
            bergshamra::KeyUsage::Verify,
        ));
    }

    // ECDSA P-256.
    if let Ok(ec_key) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP256 {
                public: ec_key,
                private: None,
            },
            bergshamra::KeyUsage::Verify,
        ));
    }

    // ECDSA P-384.
    if let Ok(ec_key) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
        return Ok(Key::new(
            KeyData::EcP384 {
                public: ec_key,
                private: None,
            },
            bergshamra::KeyUsage::Verify,
        ));
    }

    Err(format!(
        "Unsupported IdP signing key algorithm (OID: {}). RSA, P-256, and P-384 are supported.",
        cert.public_key().algorithm.oid()
    ))
}

/// Extract the `<saml:Issuer>` or `<saml2:Issuer>` value from the top-level
/// `<samlp:Response>` element using proper XML parsing.
#[cfg(feature = "saml")]
fn extract_issuer(saml_xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(saml_xml);
    let mut in_response = false;
    let mut in_issuer = false;
    let mut depth: u32 = 0;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = xml_local(e.name());
                if local == b"Response" && !in_response {
                    in_response = true;
                    depth = 1;
                } else if in_response {
                    depth += 1;
                    // Issuer must be a direct child of Response (depth == 2).
                    if local == b"Issuer" && depth == 2 {
                        in_issuer = true;
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = xml_local(e.name());
                if in_issuer && local == b"Issuer" {
                    in_issuer = false;
                }
                if in_response {
                    depth -= 1;
                    if depth == 0 {
                        break; // Exited the Response element.
                    }
                }
            }
            Ok(Event::Text(t)) if in_issuer => {
                if let Ok(text) = t.decode() {
                    let s = text.trim();
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Extract the `InResponseTo` attribute from the top-level `<samlp:Response>` element
/// using proper XML parsing.
#[cfg(feature = "saml")]
fn extract_in_response_to(saml_xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(saml_xml);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if xml_local(e.name()) == b"Response" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"InResponseTo" {
                            return String::from_utf8(attr.value.to_vec()).ok();
                        }
                    }
                    return None; // Found Response but no InResponseTo.
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Fallback InResponseTo extractor used when `saml` feature is disabled.
#[cfg(not(feature = "saml"))]
fn extract_in_response_to(saml_xml: &str) -> Option<String> {
    // Minimal string-based fallback — only used in the non-saml path which now
    // hard-fails before reaching username extraction, so this is defence-in-depth.
    let response_tag_start = saml_xml.find("<samlp:Response")?;
    let tag_end = saml_xml[response_tag_start..].find('>')?;
    let tag = &saml_xml[response_tag_start..response_tag_start + tag_end];
    let attr_start = tag.find("InResponseTo=\"")?;
    let value_start = attr_start + "InResponseTo=\"".len();
    let value_end = tag[value_start..].find('"')?;
    Some(tag[value_start..value_start + value_end].to_string())
}

/// Extract the username from the `<saml:NameID>` element inside the first
/// `<saml:Assertion>` using proper XML parsing.
#[cfg(feature = "saml")]
fn extract_username_from_saml(saml_xml: &str) -> Result<String, String> {
    let mut reader = Reader::from_str(saml_xml);
    let mut in_assertion = false;
    let mut in_name_id = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = xml_local(e.name());
                if local == b"Assertion" {
                    in_assertion = true;
                } else if in_assertion && local == b"NameID" {
                    in_name_id = true;
                }
            }
            Ok(Event::End(e)) => {
                let local = xml_local(e.name());
                if in_name_id && local == b"NameID" {
                    in_name_id = false;
                }
                if local == b"Assertion" {
                    break; // Only look in the first Assertion.
                }
            }
            Ok(Event::Text(t)) if in_name_id => {
                if let Ok(text) = t.decode() {
                    let s = text.trim();
                    if !s.is_empty() {
                        return Ok(s.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error extracting NameID: {}", e)),
            _ => {}
        }
    }

    Err("Could not extract username from SAML assertion".to_string())
}

/// Fallback username extractor used when `saml` feature is disabled.
#[cfg(not(feature = "saml"))]
fn extract_username_from_saml(_saml_xml: &str) -> Result<String, String> {
    // The non-saml path now hard-fails before reaching this point.
    Err("SAML parsing requires the 'saml' feature".to_string())
}

/// Extract SAML attributes from `<saml:AttributeStatement>` using proper XML parsing.
#[cfg(feature = "saml")]
fn extract_attributes_from_saml(saml_xml: &str) -> Result<HashMap<String, Vec<String>>, String> {
    let mut attributes = HashMap::new();
    attributes.insert("source".to_string(), vec!["saml".to_string()]);
    attributes.insert("auth_method".to_string(), vec!["saml_sso".to_string()]);

    let mut reader = Reader::from_str(saml_xml);
    let mut in_attr_statement = false;
    let mut in_attribute = false;
    let mut in_attr_value = false;
    let mut current_attr_name: Option<String> = None;
    let mut current_values: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = xml_local(e.name());
                if local == b"AttributeStatement" {
                    in_attr_statement = true;
                } else if in_attr_statement && local == b"Attribute" {
                    in_attribute = true;
                    current_values.clear();
                    current_attr_name = None;
                    for attr in e.attributes().flatten() {
                        if xml_local(attr.key) == b"Name" {
                            current_attr_name = String::from_utf8(attr.value.to_vec()).ok();
                        }
                    }
                } else if in_attribute && local == b"AttributeValue" {
                    in_attr_value = true;
                }
            }
            Ok(Event::End(e)) => {
                let local = xml_local(e.name());
                if local == b"AttributeValue" {
                    in_attr_value = false;
                } else if local == b"Attribute" && in_attribute {
                    if let Some(name) = current_attr_name.take()
                        && !current_values.is_empty()
                    {
                        attributes.insert(name, std::mem::take(&mut current_values));
                    }
                    in_attribute = false;
                } else if local == b"AttributeStatement" {
                    in_attr_statement = false;
                }
            }
            Ok(Event::Text(t)) if in_attr_value => {
                if let Ok(text) = t.decode() {
                    let s = text.trim();
                    if !s.is_empty() {
                        current_values.push(s.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    Ok(attributes)
}

/// Fallback attribute extractor used when `saml` feature is disabled.
#[cfg(not(feature = "saml"))]
fn extract_attributes_from_saml(_saml_xml: &str) -> Result<HashMap<String, Vec<String>>, String> {
    Err("SAML parsing requires the 'saml' feature".to_string())
}

/// Validate the SAML assertion's `<saml:Conditions>` element.
///
/// Checks:
/// - `NotBefore` / `NotOnOrAfter` against the current time (with 60-second clock skew allowance)
/// - `AudienceRestriction` contains the SP's entity ID
#[cfg(feature = "saml")]
fn validate_saml_conditions(saml_xml: &str, sp_entity_id: &str) -> Result<(), String> {
    let mut reader = Reader::from_str(saml_xml);
    let mut in_assertion = false;
    let mut in_conditions = false;
    let mut in_audience_restriction = false;
    let mut in_audience = false;
    let mut found_conditions = false;
    let mut not_before: Option<String> = None;
    let mut not_on_or_after: Option<String> = None;
    let mut audiences: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = xml_local(e.name());
                if local == b"Assertion" {
                    in_assertion = true;
                } else if in_assertion && local == b"Conditions" {
                    in_conditions = true;
                    found_conditions = true;
                    for attr in e.attributes().flatten() {
                        let key = attr.key.as_ref();
                        if key == b"NotBefore" {
                            not_before = String::from_utf8(attr.value.to_vec()).ok();
                        } else if key == b"NotOnOrAfter" {
                            not_on_or_after = String::from_utf8(attr.value.to_vec()).ok();
                        }
                    }
                } else if in_conditions && local == b"AudienceRestriction" {
                    in_audience_restriction = true;
                } else if in_audience_restriction && local == b"Audience" {
                    in_audience = true;
                }
            }
            Ok(Event::End(e)) => {
                let local = xml_local(e.name());
                if local == b"Audience" {
                    in_audience = false;
                } else if local == b"AudienceRestriction" {
                    in_audience_restriction = false;
                } else if local == b"Conditions" {
                    break; // Only process the first Conditions element.
                } else if local == b"Assertion" {
                    break;
                }
            }
            Ok(Event::Text(t)) if in_audience => {
                if let Ok(text) = t.decode() {
                    let s = text.trim();
                    if !s.is_empty() {
                        audiences.push(s.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error in Conditions: {}", e)),
            _ => {}
        }
    }

    if !found_conditions {
        return Err("Assertion does not contain a Conditions element".to_string());
    }

    // 60-second clock skew allowance per SAML implementation best practice.
    let skew = chrono::Duration::seconds(60);
    let now = chrono::Utc::now();

    if let Some(nb) = not_before {
        let ts = chrono::DateTime::parse_from_rfc3339(&nb)
            .or_else(|_| chrono::DateTime::parse_from_str(&nb, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .map_err(|e| format!("Invalid NotBefore timestamp '{}': {}", nb, e))?;
        if now < ts.with_timezone(&chrono::Utc) - skew {
            return Err(format!("Assertion is not yet valid (NotBefore: {})", nb));
        }
    }

    if let Some(noa) = not_on_or_after {
        let ts = chrono::DateTime::parse_from_rfc3339(&noa)
            .or_else(|_| chrono::DateTime::parse_from_str(&noa, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .map_err(|e| format!("Invalid NotOnOrAfter timestamp '{}': {}", noa, e))?;
        if now >= ts.with_timezone(&chrono::Utc) + skew {
            return Err(format!("Assertion has expired (NotOnOrAfter: {})", noa));
        }
    }

    // Audience restriction: at least one <Audience> must match the SP's entity ID.
    if !audiences.is_empty() && !audiences.iter().any(|a| a == sp_entity_id) {
        return Err(format!(
            "Assertion audience restriction does not include this SP (expected '{}', got {:?})",
            sp_entity_id, audiences
        ));
    }

    Ok(())
}

/// Extract the `StatusCode@Value` from the first `<samlp:Status>` element
/// using proper XML parsing (used for SLO response validation).
#[cfg(feature = "saml")]
fn xml_extract_status_code(saml_xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(saml_xml);
    let mut in_status = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local = xml_local(e.name());
                if local == b"Status" {
                    in_status = true;
                } else if in_status && local == b"StatusCode" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Value" {
                            return String::from_utf8(attr.value.to_vec()).ok();
                        }
                    }
                    return None; // StatusCode without Value attribute.
                }
            }
            Ok(Event::End(e)) => {
                if xml_local(e.name()) == b"Status" {
                    return None; // Status element ended without StatusCode.
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Extract the NameID text from the first `<saml:NameID>` element.
#[cfg(feature = "saml")]
fn xml_extract_name_id(saml_xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(saml_xml);
    let mut in_name_id = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if xml_local(e.name()) == b"NameID" {
                    in_name_id = true;
                }
            }
            Ok(Event::Text(e)) if in_name_id => {
                if let Ok(text) = e.decode() {
                    let s = text.trim();
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
            Ok(Event::End(e)) if in_name_id && xml_local(e.name()) == b"NameID" => {
                return None; // Empty NameID
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
#[cfg(feature = "saml")]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_extract_issuer() {
        // extract_issuer looks for an <Issuer> that is a direct child of a <Response> element.
        let xml = r#"<samlp:Response><saml:Issuer>https://idp.example.com</saml:Issuer></samlp:Response>"#;
        assert_eq!(extract_issuer(xml).unwrap(), "https://idp.example.com");
    }

    #[test]
    fn test_extract_username() {
        // extract_username_from_saml looks for a <NameID> inside an <Assertion> element.
        let xml = r#"<saml:Assertion><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>"#;
        assert_eq!(extract_username_from_saml(xml).unwrap(), "user@example.com");
    }

    #[test]
    fn test_validate_conditions_time() {
        // validate_saml_conditions looks for <Conditions> inside an <Assertion> element.
        let now = Utc::now();
        let past = now - Duration::minutes(10);
        let future = now + Duration::minutes(10);
        let xml = format!(
            r#"<saml:Assertion><saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>test-aud</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#,
            past.to_rfc3339(),
            future.to_rfc3339()
        );
        assert!(validate_saml_conditions(&xml, "test-aud").is_ok());

        let wrong_aud = format!(
            r#"<saml:Assertion><saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>wrong-aud</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#,
            past.to_rfc3339(),
            future.to_rfc3339()
        );
        assert!(validate_saml_conditions(&wrong_aud, "test-aud").is_err());
    }

    #[test]
    fn test_extract_status() {
        let xml = r#"<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#;
        assert_eq!(
            xml_extract_status_code(xml).unwrap(),
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
    }
}
