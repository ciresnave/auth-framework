//! OAuth 2.0 Advanced Features API Endpoints
//!
//! This module implements OAuth 2.0 advanced features:
//! - RFC 7662: Token Introspection
//! - RFC 9126: Pushed Authorization Requests  
//! - RFC 8628: Device Authorization Grant
//! - OpenID Connect CIBA (Client Initiated Backchannel Authentication)

use crate::api::ApiState;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use std::collections::HashMap;
use tracing::{debug, error};
use url::Url;
use uuid::Uuid;

/// Token introspection request (RFC 7662)
#[derive(Deserialize)]
pub struct IntrospectRequest {
    /// The token to introspect
    pub token: String,

    /// Optional hint about the token type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<String>,

    /// Client ID (if using POST body authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Client secret (if using POST body authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl std::fmt::Debug for IntrospectRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("IntrospectRequest");
        d.field("token", &crate::utils::redact::redacted(&self.token));
        d.field("token_type_hint", &self.token_type_hint);
        d.field("client_id", &self.client_id);
        d.field(
            "client_secret",
            &crate::utils::redact::redacted(&self.client_secret),
        );
        d.finish()
    }
}

/// Token introspection response (RFC 7662)
#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    /// Indicates if the token is currently active
    pub active: bool,

    /// The subject of the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// The client_id associated with the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// The scopes associated with the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Token expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Token issued at timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Not before timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issuer of the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience of the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<JsonValue>,

    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Token type (e.g., "Bearer")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Username associated with the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Pushed Authorization Request parameters (RFC 9126)
///
/// Required fields are non-optional so Axum Form validation returns 422
/// automatically when they are missing from the request body.
#[derive(Debug, Deserialize)]
pub struct PARRequest {
    /// Required: OAuth 2.0 response type (e.g., "code")
    pub response_type: String,

    /// Required: The client identifier
    pub client_id: String,

    /// Required: Redirection URI for the authorization response
    pub redirect_uri: String,

    /// Optional: Requested scope(s)
    pub scope: Option<String>,

    /// Optional: Opaque state value for the client
    pub state: Option<String>,

    /// Optional: Nonce for OIDC requests
    pub nonce: Option<String>,

    /// Optional: PKCE code challenge
    pub code_challenge: Option<String>,

    /// Optional: PKCE code challenge method (e.g., "S256")
    pub code_challenge_method: Option<String>,
}

/// Pushed Authorization Request response (RFC 9126)
#[derive(Serialize)]
pub struct PARResponse {
    /// The request URI for the authorization request
    pub request_uri: String,

    /// Expiration time in seconds
    pub expires_in: u64,
}

impl std::fmt::Debug for PARResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("PARResponse");
        d.field(
            "request_uri",
            &crate::utils::redact::redacted(&self.request_uri),
        );
        d.field("expires_in", &self.expires_in);
        d.finish()
    }
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// Verify OAuth2 client credentials against the registered client record in storage.
///
/// Returns `Ok(true)` if the credentials are valid, `Ok(false)` if the client_id
/// is unknown or the secret does not match, and `Err(...)` on storage failures.
/// The function uses constant-time comparison to prevent timing oracle attacks on
/// the client_secret.
async fn verify_client_credentials(
    state: &State<ApiState>,
    client_id: &str,
    client_secret: &str,
) -> Result<bool, (StatusCode, Json<JsonValue>)> {
    let client_key = format!("oauth2_client:{}", client_id);
    let client_data = match state.auth_framework.storage().get_kv(&client_key).await {
        Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(v) => v,
            Err(_) => {
                error!(
                    "Introspect: failed to deserialize client record for {}",
                    client_id
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Internal server error"
                    })),
                ));
            }
        },
        Ok(None) => {
            // Unknown client — return false (don't reveal whether the client exists)
            return Ok(false);
        }
        Err(e) => {
            error!(
                "Introspect: storage error looking up client {}: {}",
                client_id, e
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Internal server error"
                })),
            ));
        }
    };

    if super::client_secret::is_confidential(&client_data) {
        // A hashed secret is verified against its hash; a legacy plain one is compared in
        // constant time and then replaced by its hash.
        return Ok(super::client_secret::authenticate(
            state.auth_framework.storage().as_ref(),
            client_id,
            &client_data,
            client_secret,
        )
        .await);
    }
    // A record without a secret accepts the empty secret (unchanged here; see issue #90).
    Ok(crate::security::timing_protection::constant_time_string_compare(client_secret, ""))
}

/// Token introspection endpoint (RFC 7662)
///
/// Allows authorized clients to determine the active state and meta-information
/// about a given token.
///
/// Authentication is required via either:
/// - HTTP Basic Auth header (`Authorization: Basic <base64(client_id:client_secret)>`)
/// - POST body parameters (`client_id` + `client_secret`)
///
/// Bearer token authentication is explicitly rejected per RFC 7662 §2.1.
pub async fn introspect_token(
    state: State<ApiState>,
    headers: HeaderMap,
    form: Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, (StatusCode, Json<JsonValue>)> {
    debug!("Processing token introspection request");

    // --- Authentication enforcement (RFC 7662 §2.1) ---
    let auth_header = headers.get(axum::http::header::AUTHORIZATION);

    let authenticated = match auth_header {
        Some(value) => {
            let value_str = value.to_str().unwrap_or("");
            if value_str.starts_with("Bearer ") {
                // Bearer tokens are not a valid authentication method for introspection
                debug!("Introspect rejected: Bearer auth is not allowed");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Bearer token authentication is not supported for token introspection"
                    })),
                ));
            } else if let Some(encoded) = value_str.strip_prefix("Basic ") {
                // Decode Basic auth credentials and verify against registered client.
                match general_purpose::STANDARD.decode(encoded) {
                    Ok(decoded_bytes) => {
                        let decoded = String::from_utf8_lossy(&decoded_bytes);
                        let mut parts = decoded.splitn(2, ':');
                        let basic_client_id = parts.next().unwrap_or("").to_string();
                        let basic_client_secret = parts.next().unwrap_or("").to_string();
                        verify_client_credentials(&state, &basic_client_id, &basic_client_secret)
                            .await?
                    }
                    Err(_) => {
                        debug!("Introspect rejected: invalid Basic auth encoding");
                        return Err((
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "invalid_client",
                                "error_description": "Invalid Basic authentication encoding"
                            })),
                        ));
                    }
                }
            } else {
                // Unrecognised auth scheme
                debug!("Introspect rejected: unknown auth scheme");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "invalid_client",
                        "error_description": "Unsupported authentication scheme"
                    })),
                ));
            }
        }
        None => {
            // No Authorization header — verify using POST body client_id + client_secret.
            match (&form.client_id, &form.client_secret) {
                (Some(id), Some(secret)) => verify_client_credentials(&state, id, secret).await?,
                _ => {
                    debug!("Introspect rejected: missing client credentials");
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({
                            "error": "invalid_client",
                            "error_description": "client_id and client_secret are required"
                        })),
                    ));
                }
            }
        }
    };

    if !authenticated {
        debug!("Introspect rejected: invalid client credentials");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "Client authentication failed"
            })),
        ));
    }

    // --- Token validation ---
    let token_manager = state.auth_framework.token_manager();

    match token_manager.validate_jwt_token(&form.token) {
        Ok(claims) => {
            // Cross-check the revocation list before reporting the token as active.
            // Tokens revoked via POST /oauth/revoke or POST /auth/logout are stored
            // under revoked_token:{jti}; return active=false without revealing why.
            let revocation_key = format!("revoked_token:{}", claims.jti);
            if let Ok(Some(_)) = state.auth_framework.storage().get_kv(&revocation_key).await {
                debug!(
                    "Token introspection: token has been revoked (jti: {})",
                    claims.jti
                );
                return Ok(Json(IntrospectResponse {
                    active: false,
                    sub: None,
                    client_id: None,
                    scope: None,
                    exp: None,
                    iat: None,
                    nbf: None,
                    iss: None,
                    aud: None,
                    jti: None,
                    token_type: None,
                    username: None,
                }));
            }

            debug_assert!(!claims.sub.is_empty(), "Token subject should not be empty");
            Ok(Json(IntrospectResponse {
                active: true,
                sub: Some(claims.sub.clone()),
                client_id: claims.client_id.clone(),
                scope: Some(claims.scope.clone()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                nbf: Some(claims.nbf),
                iss: Some(claims.iss.clone()),
                aud: Some(JsonValue::String(claims.aud.clone())),
                jti: Some(claims.jti.clone()),
                token_type: Some("Bearer".to_string()),
                username: Some(claims.sub),
            }))
        }
        Err(_e) => {
            debug!("Token introspection: token is inactive");
            // Return inactive token (per RFC 7662, don't reveal why it's invalid)
            Ok(Json(IntrospectResponse {
                active: false,
                sub: None,
                client_id: None,
                scope: None,
                exp: None,
                iat: None,
                nbf: None,
                iss: None,
                aud: None,
                jti: None,
                token_type: None,
                username: None,
            }))
        }
    }
}

/// Pushed Authorization Request endpoint (RFC 9126)
///
/// Clients push authorization request parameters to the server and receive a
/// `request_uri` they can use at the authorization endpoint. The URI is unique
/// per request and expires after 90 seconds (RFC 9126 §2.2).
///
/// Required form fields: `response_type`, `client_id`, `redirect_uri`
/// Missing required fields are automatically rejected with 422 by Axum.
pub async fn pushed_authorization_request(
    State(state): State<ApiState>,
    Form(req): Form<PARRequest>,
) -> (StatusCode, Json<PARResponse>) {
    debug!("Processing PAR request for client_id={}", req.client_id);

    // Validate redirect_uri is a well-formed URL before accepting it
    if Url::parse(&req.redirect_uri).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PARResponse {
                request_uri: String::new(),
                expires_in: 0,
            }),
        );
    }

    // Generate a unique request URI per RFC 9126 §2.2
    let request_id = Uuid::new_v4().to_string();
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", request_id);

    // Persist the authorization request parameters so the /authorize endpoint
    // can retrieve them when presented with this request_uri (RFC 9126 §4).
    let par_data = json!({
        "response_type": req.response_type,
        "client_id": req.client_id,
        "redirect_uri": req.redirect_uri,
        "scope": req.scope,
        "state": req.state,
        "nonce": req.nonce,
        "code_challenge": req.code_challenge,
        "code_challenge_method": req.code_challenge_method,
    });
    let storage_key = format!("par_request:{}", request_id);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &storage_key,
            par_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(90)),
        )
        .await
    {
        error!("Failed to store PAR request: {}", e);
        // The request_uri would be unresolvable; returning a 201 with a URI
        // that will never resolve is worse than surfacing the error early.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PARResponse {
                request_uri: String::new(),
                expires_in: 0,
            }),
        );
    }

    (
        StatusCode::CREATED,
        Json(PARResponse {
            request_uri,
            expires_in: 90,
        }),
    )
}

/// Device Authorization endpoint (RFC 8628 §3.1)
///
/// Initiates a device-authorization flow for input-constrained devices.
/// Returns a `device_code`, human-friendly `user_code`, `verification_uri`,
/// `expires_in`, and a polling `interval`.
pub async fn device_authorization(
    State(state): State<ApiState>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<JsonValue>, (StatusCode, Json<JsonValue>)> {
    // RFC 8628 §3.1 – client_id is required
    if form.get("client_id").map(|s| s.is_empty()).unwrap_or(true) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "client_id is required"
            })),
        ));
    }

    // Generate a high-entropy device_code and a human-friendly user_code.
    let device_code = format!("dc_{}", Uuid::new_v4().simple());
    let user_code = generate_user_code();
    let verification_uri = "/device";
    let expires_in: u64 = 600; // RFC 8628 recommends ≥600 s

    // Persist the device authorization request so the token endpoint can poll.
    let device_data = json!({
        "client_id": form.get("client_id").cloned().unwrap_or_default(),
        "scope":     form.get("scope").cloned().unwrap_or_default(),
        "user_code": user_code,
        "authorized": false
    });
    state
        .auth_framework
        .storage()
        .store_kv(
            &format!("device:{}", device_code),
            device_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(expires_in)),
        )
        .await
        .map_err(|e| {
            error!("Failed to store device authorization request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to initiate device authorization flow"
                })),
            )
        })?;

    debug!(
        "Device authorization initiated for client_id={}",
        form.get("client_id")
            .map(String::as_str)
            .unwrap_or_default()
    );

    Ok(Json(json!({
        "device_code":              device_code,
        "user_code":               user_code,
        "verification_uri":        verification_uri,
        "verification_uri_complete": format!("{}?user_code={}", verification_uri, user_code),
        "expires_in":              expires_in,
        "interval":                5
    })))
}

/// CIBA (Client Initiated Backchannel Authentication) endpoint (OpenID Connect CIBA Core §7.1)
///
/// Initiates a backchannel authentication request.  Exactly one of
/// `login_hint`, `login_hint_token`, or `id_token_hint` must be present.
/// Returns an `auth_req_id` that the client polls at the token endpoint.
pub async fn ciba_backchannel_auth(
    State(state): State<ApiState>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<JsonValue>, (StatusCode, Json<JsonValue>)> {
    // CIBA Core §7.1 – exactly one user-identification hint is required.
    let login_hint = form
        .get("login_hint")
        .or_else(|| form.get("login_hint_token"))
        .or_else(|| form.get("id_token_hint"))
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description":
                        "One of login_hint, login_hint_token, or id_token_hint is required"
                })),
            )
        })?;

    let auth_req_id = Uuid::new_v4().to_string();
    let expires_in: u64 = 120; // 2-minute window for the authenticating device

    // Persist the CIBA request so the token-endpoint poll can resolve it.
    let ciba_data = json!({
        "login_hint":      login_hint,
        "client_id":       form.get("client_id").cloned().unwrap_or_default(),
        "scope":           form.get("scope").cloned().unwrap_or_default(),
        "binding_message": form.get("binding_message").cloned(),
        "status":          "pending"
    });
    state
        .auth_framework
        .storage()
        .store_kv(
            &format!("ciba:{}", auth_req_id),
            ciba_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(expires_in)),
        )
        .await
        .map_err(|e| {
            error!("Failed to store CIBA request: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to initiate backchannel authentication"
                })),
            )
        })?;

    debug!(
        "CIBA request created: auth_req_id={}",
        crate::utils::redact::fingerprint(&auth_req_id)
    );

    Ok(Json(json!({
        "auth_req_id": auth_req_id,
        "expires_in":  expires_in,
        "interval":    5
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate an 8-character, human-friendly user code (RFC 8628 §6.1 charset).
/// Uses only unambiguous uppercase letters and digits (no O/0, I/1).
fn generate_user_code() -> String {
    use rand::RngExt;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}
