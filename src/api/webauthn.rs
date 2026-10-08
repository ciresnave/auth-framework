use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use axum::{extract::State, http::HeaderMap, response::Json};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// WebAuthn Relying Party configuration.
///
/// Collects the RP identity, default timeouts, and attestation preference
/// in a single struct so that individual handlers don't need to scatter
/// `std::env::var` calls.
///
/// # Example
/// ```rust
/// use auth_framework::api::webauthn::WebAuthnConfig;
///
/// // Minimal — defaults to "localhost" / "AuthFramework" / "none"
/// let cfg = WebAuthnConfig::default();
/// assert_eq!(cfg.rp_id, "localhost");
///
/// // Typical production use
/// let cfg = WebAuthnConfig::new("auth.example.com", "My Service")
///     .attestation("none")
///     .timeout(120_000);
/// assert_eq!(cfg.rp_id, "auth.example.com");
/// assert_eq!(cfg.attestation, "none");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party identifier (usually the domain name).
    pub rp_id: String,
    /// Human-readable Relying Party name.
    pub rp_name: String,
    /// Attestation conveyance preference. This server does not verify
    /// attestation statements, so only `"none"` is accepted by the
    /// registration endpoints; any other value makes them refuse rather
    /// than request an attestation that would then be ignored.
    pub attestation: String,
    /// Timeout for ceremonies in milliseconds (default: 60 000).
    pub timeout_ms: u64,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "AuthFramework".to_string(),
            attestation: "none".to_string(),
            timeout_ms: 60_000,
        }
    }
}

impl WebAuthnConfig {
    /// Create a config with the given RP id and name.
    pub fn new(rp_id: impl Into<String>, rp_name: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            ..Self::default()
        }
    }

    /// Build a config from environment variables.
    ///
    /// | Variable | Default |
    /// |----------|---------|
    /// | `WEBAUTHN_RP_ID` | `"localhost"` |
    /// | `WEBAUTHN_RP_NAME` | `"AuthFramework"` |
    /// | `WEBAUTHN_ATTESTATION` | `"none"` |
    /// | `WEBAUTHN_TIMEOUT_MS` | `60000` |
    pub fn from_env() -> Self {
        Self {
            rp_id: std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_name: std::env::var("WEBAUTHN_RP_NAME")
                .unwrap_or_else(|_| "AuthFramework".to_string()),
            attestation: std::env::var("WEBAUTHN_ATTESTATION")
                .unwrap_or_else(|_| "none".to_string()),
            timeout_ms: std::env::var("WEBAUTHN_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60_000),
        }
    }

    /// Set the attestation conveyance preference.
    pub fn attestation(mut self, attestation: impl Into<String>) -> Self {
        self.attestation = attestation.into();
        self
    }

    /// Set the ceremony timeout in milliseconds.
    pub fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

/// Whether this server can honour an attestation conveyance preference.
///
/// The server does not verify attestation statements, so it only accepts
/// `"none"`: asking an authenticator for an attestation it then ignores
/// would look like provenance checking while providing none.
pub(crate) fn attestation_supported(preference: &str) -> bool {
    preference == "none"
}

/// Request to initiate WebAuthn registration
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationInitRequest {
    pub username: String,
    pub display_name: Option<String>,
    pub authenticator_attachment: Option<String>, // "platform" or "cross-platform"
    pub user_verification: Option<String>,        // "required", "preferred", "discouraged"
}

/// WebAuthn registration challenge response
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResponse {
    pub challenge: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pubkey_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: String,
    pub session_id: String,
}

/// Complete WebAuthn registration
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRegistrationCompleteRequest {
    pub session_id: String,
    pub credential_id: String,
    pub credential_public_key: String,
    pub attestation_object: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// WebAuthn authentication initiation request
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationRequest {
    pub username: Option<String>,
    pub user_verification: Option<String>,
}

/// WebAuthn authentication challenge response
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationResponse {
    pub challenge: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub timeout: Option<u64>,
    pub user_verification: String,
    pub session_id: String,
}

/// Complete WebAuthn authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationCompleteRequest {
    pub session_id: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// Supporting structures
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_field: String,
    pub alg: i32,
}

impl PublicKeyCredentialParameters {
    /// ES256 (ECDSA P-256) — COSE algorithm −7.
    pub fn es256() -> Self {
        Self {
            type_field: "public-key".to_string(),
            alg: -7,
        }
    }

    /// RS256 (RSASSA-PKCS1-v1_5 with SHA-256) — COSE algorithm −257.
    pub fn rs256() -> Self {
        Self {
            type_field: "public-key".to_string(),
            alg: -257,
        }
    }

    /// Default WebAuthn parameter set: ES256 + RS256.
    pub fn defaults() -> Vec<Self> {
        vec![Self::es256(), Self::rs256()]
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_field: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: Option<bool>,
    pub user_verification: String,
}

type SharedStorage = std::sync::Arc<dyn crate::storage::AuthStorage>;

/// Resolve a username to its account id via the `user:username:{name}`
/// index every registration path maintains.
async fn resolve_user_id(storage: &SharedStorage, username: &str) -> Option<String> {
    let bytes = storage
        .get_kv(&format!("user:username:{username}"))
        .await
        .ok()
        .flatten()?;
    String::from_utf8(bytes).ok().filter(|id| !id.is_empty())
}

/// `true` when `user:{id}` exists, parses, and is not deactivated.
async fn account_is_active(storage: &SharedStorage, user_id: &str) -> bool {
    match storage.get_kv(&format!("user:{user_id}")).await {
        Ok(Some(bytes)) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map(|record| record["active"].as_bool() != Some(false))
            .unwrap_or(false),
        _ => false,
    }
}

/// Authenticate the caller from the `Authorization: Bearer` header.
///
/// Returns the `(code, message)` of the error response on failure.
async fn require_caller(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<crate::tokens::AuthToken, (&'static str, &'static str)> {
    let token = extract_bearer_token(headers).ok_or(("UNAUTHORIZED", "Authentication required"))?;
    validate_api_token(&state.auth_framework, &token)
        .await
        .map_err(|_| ("UNAUTHORIZED", "Invalid or expired token"))
}

/// A caller may manage an account's passkeys if it is that account, or an admin.
fn may_manage(caller: &crate::tokens::AuthToken, target_user_id: &str) -> bool {
    caller.user_id == target_user_id || caller.roles.contains("admin")
}

/// Credentials are stored per ACCOUNT ID, never per caller-supplied name.
fn credential_key(user_id: &str, credential_id: &str) -> String {
    format!("webauthn_credential:{user_id}:{credential_id}")
}

fn credential_index_key(user_id: &str) -> String {
    format!("webauthn_creds_index:{user_id}")
}

/// Check the client-data `origin` against the relying-party id. A missing
/// origin is a refusal: the origin binding is what ties the ceremony to
/// this site, so it cannot be optional.
fn check_origin(client_data: &serde_json::Value, expected_rp_id: &str) -> Result<(), &'static str> {
    const MISMATCH: &str = "Origin mismatch: does not match relying party ID";
    let origin = client_data
        .get("origin")
        .and_then(|o| o.as_str())
        .ok_or("Missing origin in client data")?;
    match url::Url::parse(origin) {
        Ok(origin_url) if origin_url.host_str() == Some(expected_rp_id) => Ok(()),
        Ok(_) => Err(MISMATCH),
        Err(_) if origin == expected_rp_id => Ok(()),
        Err(_) => Err(MISMATCH),
    }
}

/// Initiate WebAuthn registration process.
///
/// Requires a bearer token. The caller must be the account named by
/// `username`, or an admin: registering a credential gives the holder of
/// its private key the ability to sign in as the account.
pub async fn webauthn_registration_init(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WebAuthnRegistrationInitRequest>,
) -> Json<ApiResponse<WebAuthnRegistrationResponse>> {
    let caller = match require_caller(&state, &headers).await {
        Ok(caller) => caller,
        Err((code, message)) => return Json(ApiResponse::error_typed(code, message)),
    };

    // Validate username format before processing
    if let Err(e) = crate::utils::validation::validate_username(&request.username) {
        return Json(ApiResponse::error_typed("VALIDATION_ERROR", format!("{e}")));
    }

    let webauthn_cfg = WebAuthnConfig::from_env();
    if !attestation_supported(&webauthn_cfg.attestation) {
        return Json(ApiResponse::error_typed(
            "ATTESTATION_UNSUPPORTED",
            "This server cannot verify attestation statements; set WEBAUTHN_ATTESTATION=none",
        ));
    }

    // Same answer whether the account is missing or belongs to someone
    // else, so this cannot be used to probe which usernames exist.
    let storage = state.auth_framework.storage();
    let target_user_id = match resolve_user_id(&storage, &request.username).await {
        Some(id) if may_manage(&caller, &id) && account_is_active(&storage, &id).await => id,
        _ => {
            return Json(ApiResponse::error_typed(
                "FORBIDDEN",
                "You can only register credentials for your own account",
            ));
        }
    };

    // Generate a secure challenge
    let mut challenge_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // The WebAuthn user handle is the opaque account id, not the username.
    let user_handle =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(target_user_id.as_bytes());

    // Create session ID for tracking this registration
    let session_id = format!("webauthn_{}", uuid::Uuid::new_v4());

    let response = WebAuthnRegistrationResponse {
        challenge: challenge.clone(),
        rp: PublicKeyCredentialRpEntity {
            id: webauthn_cfg.rp_id,
            name: webauthn_cfg.rp_name,
        },
        user: PublicKeyCredentialUserEntity {
            id: user_handle,
            name: request.username.clone(),
            display_name: request.display_name.unwrap_or(request.username.clone()),
        },
        pubkey_cred_params: PublicKeyCredentialParameters::defaults(),
        timeout: Some(webauthn_cfg.timeout_ms),
        exclude_credentials: None,
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: request.authenticator_attachment,
            require_resident_key: Some(false),
            user_verification: request.user_verification.unwrap_or("preferred".to_string()),
        }),
        // The server does not verify attestation statements, so it only
        // ever asks for "none" (see `attestation_supported`).
        attestation: webauthn_cfg.attestation,
        session_id: session_id.clone(),
    };

    // Store the challenge, the target account and the authenticated
    // caller with a 5-minute TTL. The caller is bound so the session id
    // alone is not a capability.
    let session_key = format!("webauthn_reg_session:{}", session_id);
    let session_data = serde_json::json!({
        "challenge": challenge,
        "user_id": target_user_id,
        "caller_id": caller.user_id,
        "timestamp": chrono::Utc::now().timestamp()
    });
    if let Err(e) = storage
        .store_kv(
            &session_key,
            session_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(300)),
        )
        .await
    {
        tracing::error!("Failed to store WebAuthn registration session: {}", e);
        return Json(ApiResponse::error_typed(
            "INTERNAL_ERROR",
            "Failed to start registration",
        ));
    }

    Json(ApiResponse::success_with_message(
        response,
        "WebAuthn registration challenge generated",
    ))
}

/// Complete WebAuthn registration process.
///
/// Requires the same bearer token that started the ceremony. The server
/// does not verify attestation statements (see [`attestation_supported`]):
/// the credential is trusted because an authenticated session for the
/// account registered it, not because of what the authenticator claims.
pub async fn webauthn_registration_complete(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WebAuthnRegistrationCompleteRequest>,
) -> Json<ApiResponse<()>> {
    let caller = match require_caller(&state, &headers).await {
        Ok(caller) => caller,
        Err((code, message)) => return Json(ApiResponse::error_typed(code, message)),
    };

    // Retrieve the stored session to validate the challenge
    let session_key = format!("webauthn_reg_session:{}", request.session_id);
    let storage = state.auth_framework.storage();

    let (user_id, session_caller, stored_challenge) = match storage.get_kv(&session_key).await {
        Ok(Some(data)) => {
            let session: serde_json::Value =
                serde_json::from_slice(&data).unwrap_or(serde_json::Value::Null);
            let field = |name: &str| {
                session
                    .get(name)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            (field("user_id"), field("caller_id"), field("challenge"))
        }
        _ => {
            return Json(ApiResponse::validation_error(
                "Session not found or expired",
            ));
        }
    };
    if user_id.is_empty() || stored_challenge.is_empty() {
        return Json(ApiResponse::validation_error(
            "Session not found or expired",
        ));
    }

    // Only the caller that started the ceremony may finish it. Checked
    // before the session is consumed so a stranger cannot burn it.
    if session_caller != caller.user_id {
        return Json(ApiResponse::error_typed(
            "FORBIDDEN",
            "This registration session belongs to another account",
        ));
    }

    // Delete session immediately to prevent replay attacks
    if let Err(e) = storage.delete_kv(&session_key).await {
        tracing::warn!("Failed to delete WebAuthn registration session: {}", e);
    }

    // The account may have been deactivated since the ceremony began.
    if !account_is_active(&storage, &user_id).await {
        return Json(ApiResponse::error_typed(
            "FORBIDDEN",
            "You can only register credentials for your own account",
        ));
    }

    // Basic validation of credential data
    if request.credential_id.is_empty() || request.attestation_object.is_empty() {
        return Json(ApiResponse::validation_error("Invalid credential data"));
    }
    let key_ok = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.credential_public_key)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD.decode(&request.credential_public_key)
        })
        .map(|key| !key.is_empty() && key.len() <= 1024)
        .unwrap_or(false);
    if !key_ok {
        return Json(ApiResponse::validation_error(
            "Invalid credential public key",
        ));
    }

    // Verify client_data_json: challenge, origin, and type
    let client_data_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.client_data_json)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&request.client_data_json))
    {
        Ok(b) => b,
        Err(_) => {
            return Json(ApiResponse::validation_error(
                "Invalid client_data_json encoding",
            ));
        }
    };

    let client_data: serde_json::Value = match serde_json::from_slice(&client_data_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Json(ApiResponse::validation_error(
                "Invalid client_data_json format",
            ));
        }
    };

    // Verify type is "webauthn.create"
    if client_data.get("type").and_then(|t| t.as_str()) != Some("webauthn.create") {
        return Json(ApiResponse::validation_error(
            "Invalid ceremony type: expected webauthn.create",
        ));
    }

    // Verify challenge matches the one we stored
    if let Some(received_challenge) = client_data.get("challenge").and_then(|c| c.as_str()) {
        if received_challenge != stored_challenge {
            return Json(ApiResponse::validation_error(
                "Challenge mismatch: possible replay attack",
            ));
        }
    } else {
        return Json(ApiResponse::validation_error(
            "Missing challenge in client data",
        ));
    }

    // Verify origin matches the configured RP ID (a missing origin is refused)
    if let Err(message) = check_origin(&client_data, &WebAuthnConfig::from_env().rp_id) {
        return Json(ApiResponse::validation_error(message));
    }

    // Store the registered credential (including initial signature counter)
    let credential_key = credential_key(&user_id, &request.credential_id);
    let credential_data = serde_json::json!({
        "credential_id": request.credential_id,
        "credential_public_key": request.credential_public_key,
        "user_id": user_id,
        "registered_at": chrono::Utc::now().timestamp(),
        "sign_count": 0u64
    });
    if let Err(e) = storage
        .store_kv(
            &credential_key,
            credential_data.to_string().as_bytes(),
            None,
        )
        .await
    {
        tracing::error!("Failed to store WebAuthn credential: {}", e);
        return Json(ApiResponse::error_typed(
            "INTERNAL_ERROR",
            "Failed to store credential",
        ));
    }

    // Update the user's credential index so authentication can enumerate them
    let index_key = credential_index_key(&user_id);
    let mut existing_ids: Vec<String> = match storage.get_kv(&index_key).await {
        Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
        _ => Vec::new(),
    };
    if !existing_ids.contains(&request.credential_id) {
        existing_ids.push(request.credential_id.clone());
        if let Err(e) = storage
            .store_kv(
                &index_key,
                serde_json::to_string(&existing_ids)
                    .unwrap_or_default()
                    .as_bytes(),
                None,
            )
            .await
        {
            tracing::error!("Failed to update WebAuthn credential index: {}", e);
            return Json(ApiResponse::error_typed(
                "INTERNAL_ERROR",
                "Failed to store credential",
            ));
        }
    }

    Json(ApiResponse::<()>::ok_with_message(
        "WebAuthn credential registered successfully",
    ))
}

/// Initiate WebAuthn authentication process
pub async fn webauthn_authentication_init(
    State(state): State<ApiState>,
    Json(request): Json<WebAuthnAuthenticationRequest>,
) -> Json<ApiResponse<WebAuthnAuthenticationResponse>> {
    let mut challenge_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    let session_id = format!("webauthn_auth_{}", uuid::Uuid::new_v4());
    let storage = state.auth_framework.storage();

    // Retrieve the account's registered credentials from storage. An
    // unknown username yields an empty list, exactly like an account with
    // no credentials, so this does not reveal which usernames exist.
    let username = request.username.as_deref().unwrap_or("");
    let account_id = if username.is_empty() {
        None
    } else {
        resolve_user_id(&storage, username).await
    };
    let allow_credentials = if let Some(account_id) = account_id.as_deref() {
        // Look up registered credential IDs via the account's credential index
        let index_key = credential_index_key(account_id);
        match storage.get_kv(&index_key).await {
            Ok(Some(data)) => {
                if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&data) {
                    ids.into_iter()
                        .map(|id| PublicKeyCredentialDescriptor {
                            type_field: "public-key".to_string(),
                            id,
                            transports: Some(vec!["internal".to_string(), "usb".to_string()]),
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // Store auth session with challenge
    let session_key = format!("webauthn_auth_session:{}", session_id);
    let session_data = serde_json::json!({
        "challenge": challenge,
        "username": request.username,
        "timestamp": chrono::Utc::now().timestamp()
    });
    let _ = storage
        .store_kv(
            &session_key,
            session_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(300)), // 5-minute session
        )
        .await;

    let response = WebAuthnAuthenticationResponse {
        challenge,
        allow_credentials,
        timeout: Some(60000),
        user_verification: request.user_verification.unwrap_or("preferred".to_string()),
        session_id,
    };

    Json(ApiResponse::success_with_message(
        response,
        "WebAuthn authentication challenge generated",
    ))
}

/// Complete WebAuthn authentication process
pub async fn webauthn_authentication_complete(
    State(state): State<ApiState>,
    Json(request): Json<WebAuthnAuthenticationCompleteRequest>,
) -> Json<ApiResponse<serde_json::Value>> {
    let storage = state.auth_framework.storage();
    let session_key = format!("webauthn_auth_session:{}", request.session_id);

    // Retrieve and validate the stored session
    let (username, stored_challenge) = match storage.get_kv(&session_key).await {
        Ok(Some(data)) => {
            let session: serde_json::Value =
                serde_json::from_slice(&data).unwrap_or(serde_json::Value::Null);
            let uname = session
                .get("username")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let challenge = session
                .get("challenge")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            (uname, challenge)
        }
        _ => {
            return Json(ApiResponse::validation_error_typed(
                "Authentication session not found or expired",
            ));
        }
    };

    // Delete session immediately to prevent replay attacks
    if let Err(e) = storage.delete_kv(&session_key).await {
        tracing::warn!("Failed to delete WebAuthn authentication session: {}", e);
    }

    // Verify client_data_json: challenge, origin, and type
    let client_data_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.client_data_json)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&request.client_data_json))
    {
        Ok(b) => b,
        Err(_) => {
            return Json(ApiResponse::validation_error_typed(
                "Invalid client_data_json encoding",
            ));
        }
    };

    let client_data: serde_json::Value = match serde_json::from_slice(&client_data_bytes) {
        Ok(v) => v,
        Err(_) => {
            return Json(ApiResponse::validation_error_typed(
                "Invalid client_data_json format",
            ));
        }
    };

    // Verify type is "webauthn.get"
    if client_data.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Json(ApiResponse::validation_error_typed(
            "Invalid ceremony type: expected webauthn.get",
        ));
    }

    // Verify challenge matches the one we stored
    if let Some(received_challenge) = client_data.get("challenge").and_then(|c| c.as_str()) {
        if received_challenge != stored_challenge {
            return Json(ApiResponse::validation_error_typed(
                "Challenge mismatch: possible replay attack",
            ));
        }
    } else {
        return Json(ApiResponse::validation_error_typed(
            "Missing challenge in client data",
        ));
    }

    // Verify origin matches the configured RP ID (a missing origin is refused)
    if let Err(message) = check_origin(&client_data, &WebAuthnConfig::from_env().rp_id) {
        return Json(ApiResponse::validation_error_typed(message));
    }

    // Resolve the session's username to the REAL account, which must exist
    // and be active, before anything is looked up or minted. This failure
    // and "no such credential" below get the same answer, so the response
    // cannot be used to probe which usernames exist.
    let user_id = match resolve_user_id(&storage, &username).await {
        Some(id) if account_is_active(&storage, &id).await => id,
        _ => {
            return Json(ApiResponse::validation_error_typed("Authentication failed"));
        }
    };

    // Retrieve stored credential to verify it exists and check signature counter
    let credential_key = credential_key(&user_id, &request.credential_id);
    let stored_credential = match storage.get_kv(&credential_key).await {
        Ok(Some(data)) => {
            serde_json::from_slice::<serde_json::Value>(&data).unwrap_or(serde_json::Value::Null)
        }
        _ => {
            return Json(ApiResponse::validation_error_typed("Authentication failed"));
        }
    };

    // Check and update signature counter to detect cloned authenticators
    let stored_count = stored_credential
        .get("sign_count")
        .and_then(|c| c.as_u64())
        .unwrap_or(0);
    // Extract sign_count from authenticator_data (bytes 33-36 are the counter, big-endian)
    let new_count = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.authenticator_data)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&request.authenticator_data))
        .ok()
        .filter(|d| d.len() >= 37)
        .map(|d| u32::from_be_bytes([d[33], d[34], d[35], d[36]]) as u64)
        .unwrap_or(0);
    if new_count > 0 && new_count <= stored_count {
        tracing::warn!(
            "WebAuthn signature counter regression for user {}: stored={}, received={}. Possible cloned authenticator.",
            username,
            stored_count,
            new_count
        );
        return Json(ApiResponse::validation_error_typed(
            "Signature counter regression detected: possible cloned authenticator",
        ));
    }

    // ---- Cryptographic signature verification (WebAuthn §7.2 step 19-20) ----
    // 1. Decode the authenticator data and the raw client data JSON bytes
    let auth_data_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.authenticator_data)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&request.authenticator_data))
    {
        Ok(b) => b,
        Err(_) => {
            return Json(ApiResponse::validation_error_typed(
                "Invalid authenticator_data encoding",
            ));
        }
    };

    // 2. Compute SHA-256 hash of the raw client_data_json bytes
    let client_data_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&client_data_bytes);
        hasher.finalize()
    };

    // 3. Build the signed message: authenticatorData || SHA-256(clientDataJSON)
    let mut signed_message = auth_data_bytes.clone();
    signed_message.extend_from_slice(&client_data_hash);

    // 4. Decode the signature
    let signature_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&request.signature)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&request.signature))
    {
        Ok(b) => b,
        Err(_) => {
            return Json(ApiResponse::validation_error_typed(
                "Invalid signature encoding",
            ));
        }
    };

    // 5. Retrieve the stored public key and verify the signature
    let credential_pub_key = stored_credential
        .get("credential_public_key")
        .and_then(|k| k.as_str())
        .unwrap_or("");

    if credential_pub_key.is_empty() {
        return Json(ApiResponse::validation_error_typed(
            "No public key stored for this credential",
        ));
    }

    // Decode the stored public key (base64url or standard base64)
    let pub_key_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_pub_key)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(credential_pub_key))
    {
        Ok(b) => b,
        Err(_) => {
            return Json(ApiResponse::validation_error_typed(
                "Failed to decode stored public key",
            ));
        }
    };

    // Try ES256 (ECDSA P-256) first, then RS256 (RSA PKCS#1 v1.5 with SHA-256)
    let sig_valid = {
        // Attempt ES256 verification (COSE algorithm -7)
        let es256_result = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &pub_key_bytes,
        )
        .verify(&signed_message, &signature_bytes);

        if es256_result.is_ok() {
            true
        } else {
            // Attempt RS256 verification (COSE algorithm -257)
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                &pub_key_bytes,
            )
            .verify(&signed_message, &signature_bytes)
            .is_ok()
        }
    };

    if !sig_valid {
        tracing::warn!(
            "WebAuthn signature verification failed for user {} credential {}",
            username,
            request.credential_id
        );
        return Json(ApiResponse::validation_error_typed(
            "Signature verification failed: authentication assertion is not valid",
        ));
    }

    // Update the stored counter
    let mut updated_cred = stored_credential.clone();
    if let Some(obj) = updated_cred.as_object_mut() {
        obj.insert("sign_count".to_string(), serde_json::json!(new_count));
    }
    if let Err(e) = storage
        .store_kv(
            &credential_key,
            serde_json::to_string(&updated_cred)
                .unwrap_or_default()
                .as_bytes(),
            None,
        )
        .await
    {
        tracing::warn!(
            "Failed to update WebAuthn credential counter for {}: {}",
            username,
            e
        );
    }

    // Generate authentication token for the verified user
    let token_lifetime = state.auth_framework.config().token_lifetime;
    let token = match state.auth_framework.token_manager().create_jwt_token(
        &user_id,
        vec![],
        Some(token_lifetime),
    ) {
        Ok(t) => t,
        Err(e) => {
            return Json(ApiResponse::validation_error_typed(format!(
                "Token generation failed: {}",
                e
            )));
        }
    };

    let auth_response = serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": token_lifetime.as_secs(),
        "user_id": user_id,
        "authentication_method": "webauthn"
    });

    Json(ApiResponse::success_with_message(
        auth_response,
        "WebAuthn authentication successful",
    ))
}

/// List an account's registered WebAuthn credentials. `username` names the
/// account; the caller must be that account or an admin.
pub async fn list_webauthn_credentials(
    State(state): State<ApiState>,
    headers: HeaderMap,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    let caller = match require_caller(&state, &headers).await {
        Ok(caller) => caller,
        Err((code, message)) => return Json(ApiResponse::error_typed(code, message)),
    };

    let storage = state.auth_framework.storage();
    let user_id = match resolve_user_id(&storage, &username).await {
        Some(id) if may_manage(&caller, &id) => id,
        // An admin may ask about a name that does not exist: empty, not an error.
        None if caller.roles.contains("admin") => {
            return Json(ApiResponse::success_with_message(
                Vec::new(),
                format!("WebAuthn credentials retrieved for user: {}", username),
            ));
        }
        _ => {
            return Json(ApiResponse::error_typed(
                "FORBIDDEN",
                "You can only view your own credentials",
            ));
        }
    };

    let credentials = match storage.get_kv(&credential_index_key(&user_id)).await {
        Ok(Some(data)) => {
            if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&data) {
                let mut creds = Vec::new();
                for id in ids {
                    if let Ok(Some(cred_data)) =
                        storage.get_kv(&credential_key(&user_id, &id)).await
                        && let Ok(cred) = serde_json::from_slice::<serde_json::Value>(&cred_data)
                    {
                        creds.push(cred);
                    }
                }
                creds
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };

    Json(ApiResponse::success_with_message(
        credentials,
        format!("WebAuthn credentials retrieved for user: {}", username),
    ))
}

/// Delete a WebAuthn credential. `username` names the account; the caller
/// must be that account or an admin.
pub async fn delete_webauthn_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    axum::extract::Path((username, credential_id)): axum::extract::Path<(String, String)>,
) -> Json<ApiResponse<()>> {
    let caller = match require_caller(&state, &headers).await {
        Ok(caller) => caller,
        Err((code, message)) => return Json(ApiResponse::error(code, message)),
    };

    let storage = state.auth_framework.storage();
    let user_id = match resolve_user_id(&storage, &username).await {
        Some(id) if may_manage(&caller, &id) => id,
        _ => {
            return Json(ApiResponse::error(
                "FORBIDDEN",
                "You can only delete your own credentials",
            ));
        }
    };
    let credential_key = credential_key(&user_id, &credential_id);

    // Check credential exists before deleting
    match storage.get_kv(&credential_key).await {
        Ok(Some(_)) => {
            if let Err(e) = storage.delete_kv(&credential_key).await {
                tracing::warn!(
                    "Failed to delete WebAuthn credential {}: {}",
                    credential_id,
                    e
                );
            }

            // Update the credentials index
            let index_key = credential_index_key(&user_id);
            if let Ok(Some(idx_data)) = storage.get_kv(&index_key).await
                && let Ok(mut ids) = serde_json::from_slice::<Vec<String>>(&idx_data)
            {
                ids.retain(|id| id != &credential_id);
                if let Err(e) = storage
                    .store_kv(
                        &index_key,
                        serde_json::to_string(&ids).unwrap_or_default().as_bytes(),
                        None,
                    )
                    .await
                {
                    tracing::warn!(
                        "Failed to update WebAuthn credentials index for {}: {}",
                        username,
                        e
                    );
                }
            }

            Json(ApiResponse::<()>::ok_with_message(
                "WebAuthn credential deleted successfully",
            ))
        }
        _ => Json(ApiResponse::validation_error("Credential not found")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_config_default() {
        let cfg = WebAuthnConfig::default();
        assert_eq!(cfg.rp_id, "localhost");
        assert_eq!(cfg.rp_name, "AuthFramework");
        assert_eq!(cfg.attestation, "none");
        assert_eq!(cfg.timeout_ms, 60_000);
    }

    #[test]
    fn check_origin_accepts_only_the_relying_party_host() {
        let ok = |origin: &str| {
            check_origin(&serde_json::json!({ "origin": origin }), "localhost").is_ok()
        };
        assert!(ok("https://localhost"));
        assert!(ok("https://localhost:8443"));
        assert!(ok("localhost"), "non-URL equal to the rp id");
        for hostile in [
            "https://localhost.evil.com",
            "https://evil.com",
            "https://localhost@evil.com",
            "https://evil.com/localhost",
            "https://notlocalhost",
            "",
        ] {
            assert!(!ok(hostile), "{hostile:?} must be refused");
        }
        assert!(check_origin(&serde_json::json!({}), "localhost").is_err());
        assert!(check_origin(&serde_json::json!({ "origin": 5 }), "localhost").is_err());
    }

    #[test]
    fn test_only_attestation_none_is_supported() {
        assert!(attestation_supported("none"));
        for unsupported in ["direct", "indirect", "enterprise", ""] {
            assert!(!attestation_supported(unsupported), "{unsupported}");
        }
    }

    #[test]
    fn test_webauthn_config_new_and_chain() {
        let cfg = WebAuthnConfig::new("auth.example.com", "My Service")
            .attestation("none")
            .timeout(120_000);
        assert_eq!(cfg.rp_id, "auth.example.com");
        assert_eq!(cfg.rp_name, "My Service");
        assert_eq!(cfg.attestation, "none");
        assert_eq!(cfg.timeout_ms, 120_000);
    }

    #[test]
    fn test_pubkey_cred_params_presets() {
        let es = PublicKeyCredentialParameters::es256();
        assert_eq!(es.alg, -7);
        assert_eq!(es.type_field, "public-key");

        let rs = PublicKeyCredentialParameters::rs256();
        assert_eq!(rs.alg, -257);
        assert_eq!(rs.type_field, "public-key");
    }

    #[test]
    fn test_pubkey_cred_params_defaults_contains_both() {
        let params = PublicKeyCredentialParameters::defaults();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].alg, -7);
        assert_eq!(params[1].alg, -257);
    }
}
