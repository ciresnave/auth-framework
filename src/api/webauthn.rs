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
/// // Minimal — defaults to "localhost" / "AuthFramework" / "direct"
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
    /// Attestation conveyance preference (`"direct"`, `"indirect"`, `"none"`).
    pub attestation: String,
    /// Timeout for ceremonies in milliseconds (default: 60 000).
    pub timeout_ms: u64,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "AuthFramework".to_string(),
            attestation: "direct".to_string(),
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
    /// | `WEBAUTHN_ATTESTATION` | `"direct"` |
    /// | `WEBAUTHN_TIMEOUT_MS` | `60000` |
    pub fn from_env() -> Self {
        Self {
            rp_id: std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_name: std::env::var("WEBAUTHN_RP_NAME")
                .unwrap_or_else(|_| "AuthFramework".to_string()),
            attestation: std::env::var("WEBAUTHN_ATTESTATION")
                .unwrap_or_else(|_| "direct".to_string()),
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

/// Initiate WebAuthn registration process
pub async fn webauthn_registration_init(
    State(state): State<ApiState>,
    Json(request): Json<WebAuthnRegistrationInitRequest>,
) -> Json<ApiResponse<WebAuthnRegistrationResponse>> {
    // Validate username format before processing
    if let Err(e) = crate::utils::validation::validate_username(&request.username) {
        return Json(ApiResponse::error_typed("VALIDATION_ERROR", format!("{e}")));
    }

    // Generate a secure challenge
    let mut challenge_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Generate user ID (base64url-encoded username as per WebAuthn spec)
    let user_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.username.as_bytes());

    // Create session ID for tracking this registration
    let session_id = format!("webauthn_{}", uuid::Uuid::new_v4());

    let webauthn_cfg = WebAuthnConfig::from_env();

    let response = WebAuthnRegistrationResponse {
        challenge: challenge.clone(),
        rp: PublicKeyCredentialRpEntity {
            id: webauthn_cfg.rp_id,
            name: webauthn_cfg.rp_name,
        },
        user: PublicKeyCredentialUserEntity {
            id: user_id,
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
        // "direct" requests the authenticator to include attestation data,
        // enabling the server to verify the authenticator's identity and provenance.
        // Use "none" only if you explicitly do not need device attestation verification.
        attestation: webauthn_cfg.attestation,
        session_id: session_id.clone(),
    };

    // Store the challenge and session info with a 5-minute TTL
    let session_key = format!("webauthn_reg_session:{}", session_id);
    let session_data = serde_json::json!({
        "challenge": challenge,
        "username": request.username,
        "timestamp": chrono::Utc::now().timestamp()
    });
    let _ = state
        .auth_framework
        .storage()
        .store_kv(
            &session_key,
            session_data.to_string().as_bytes(),
            Some(std::time::Duration::from_secs(300)),
        )
        .await;

    Json(ApiResponse::success_with_message(
        response,
        "WebAuthn registration challenge generated",
    ))
}

/// Complete WebAuthn registration process
pub async fn webauthn_registration_complete(
    State(state): State<ApiState>,
    Json(request): Json<WebAuthnRegistrationCompleteRequest>,
) -> Json<ApiResponse<()>> {
    // Retrieve the stored session to validate the challenge
    let session_key = format!("webauthn_reg_session:{}", request.session_id);
    let storage = state.auth_framework.storage();

    let (username, stored_challenge) = match storage.get_kv(&session_key).await {
        Ok(Some(data)) => {
            let session: serde_json::Value =
                serde_json::from_slice(&data).unwrap_or(serde_json::Value::Null);
            let uname = session
                .get("username")
                .and_then(|u| u.as_str())
                .unwrap_or("unknown")
                .to_string();
            let challenge = session
                .get("challenge")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            (uname, challenge)
        }
        _ => {
            return Json(ApiResponse::validation_error(
                "Session not found or expired",
            ));
        }
    };

    // Delete session immediately to prevent replay attacks
    if let Err(e) = storage.delete_kv(&session_key).await {
        tracing::warn!("Failed to delete WebAuthn registration session: {}", e);
    }

    // Basic validation of credential data
    if request.credential_id.is_empty() || request.attestation_object.is_empty() {
        return Json(ApiResponse::validation_error("Invalid credential data"));
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

    // Verify origin matches the configured RP ID
    let expected_rp_id = WebAuthnConfig::from_env().rp_id;
    if let Some(origin) = client_data.get("origin").and_then(|o| o.as_str()) {
        // Origin should contain the RP ID as its hostname
        if let Ok(origin_url) = url::Url::parse(origin) {
            if origin_url.host_str() != Some(&expected_rp_id) {
                return Json(ApiResponse::validation_error(
                    "Origin mismatch: does not match relying party ID",
                ));
            }
        } else if origin != expected_rp_id {
            return Json(ApiResponse::validation_error(
                "Origin mismatch: does not match relying party ID",
            ));
        }
    }

    // Store the registered credential (including initial signature counter)
    let credential_key = format!("webauthn_credential:{}:{}", username, request.credential_id);
    let credential_data = serde_json::json!({
        "credential_id": request.credential_id,
        "credential_public_key": request.credential_public_key,
        "username": username,
        "registered_at": chrono::Utc::now().timestamp(),
        "sign_count": 0u64
    });
    let _ = storage
        .store_kv(
            &credential_key,
            credential_data.to_string().as_bytes(),
            None,
        )
        .await;

    // Update the user's credential index so authentication can enumerate them
    let index_key = format!("webauthn_creds_index:{}", username);
    let mut existing_ids: Vec<String> = match storage.get_kv(&index_key).await {
        Ok(Some(data)) => serde_json::from_slice(&data).unwrap_or_default(),
        _ => Vec::new(),
    };
    if !existing_ids.contains(&request.credential_id) {
        existing_ids.push(request.credential_id.clone());
        let _ = storage
            .store_kv(
                &index_key,
                serde_json::to_string(&existing_ids)
                    .unwrap_or_default()
                    .as_bytes(),
                None,
            )
            .await;
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

    // Retrieve user's registered credentials from storage
    let username = request.username.as_deref().unwrap_or("");
    let allow_credentials = if !username.is_empty() {
        // Look up registered credential IDs via the user's credential index
        let index_key = format!("webauthn_creds_index:{}", username);
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
                .unwrap_or("webauthn_user")
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

    // Verify origin matches the configured RP ID
    let expected_rp_id = WebAuthnConfig::from_env().rp_id;
    if let Some(origin) = client_data.get("origin").and_then(|o| o.as_str()) {
        if let Ok(origin_url) = url::Url::parse(origin) {
            if origin_url.host_str() != Some(&expected_rp_id) {
                return Json(ApiResponse::validation_error_typed(
                    "Origin mismatch: does not match relying party ID",
                ));
            }
        } else if origin != expected_rp_id {
            return Json(ApiResponse::validation_error_typed(
                "Origin mismatch: does not match relying party ID",
            ));
        }
    }

    // Retrieve stored credential to verify it exists and check signature counter
    let credential_key = format!("webauthn_credential:{}:{}", username, request.credential_id);
    let stored_credential = match storage.get_kv(&credential_key).await {
        Ok(Some(data)) => {
            serde_json::from_slice::<serde_json::Value>(&data).unwrap_or(serde_json::Value::Null)
        }
        _ => {
            return Json(ApiResponse::validation_error_typed(
                "Credential not found for this user",
            ));
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
        &username,
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
        "user_id": username,
        "authentication_method": "webauthn"
    });

    Json(ApiResponse::success_with_message(
        auth_response,
        "WebAuthn authentication successful",
    ))
}

/// List user's registered WebAuthn credentials (requires authentication; user can only list own credentials)
pub async fn list_webauthn_credentials(
    State(state): State<ApiState>,
    headers: HeaderMap,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Json<ApiResponse<Vec<serde_json::Value>>> {
    // Require authentication
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return Json(ApiResponse::error_typed(
                "UNAUTHORIZED",
                "Authentication required",
            ));
        }
    };
    let auth_token = match validate_api_token(&state.auth_framework, &token).await {
        Ok(t) => t,
        Err(_) => {
            return Json(ApiResponse::error_typed(
                "UNAUTHORIZED",
                "Invalid or expired token",
            ));
        }
    };

    // Authorize: user can only list their own credentials (admins can list any)
    if auth_token.user_id != username && !auth_token.roles.contains(&"admin".to_string()) {
        return Json(ApiResponse::error_typed(
            "FORBIDDEN",
            "You can only view your own credentials",
        ));
    }

    let storage = state.auth_framework.storage();
    let index_key = format!("webauthn_creds_index:{}", username);

    let credentials = match storage.get_kv(&index_key).await {
        Ok(Some(data)) => {
            if let Ok(ids) = serde_json::from_slice::<Vec<String>>(&data) {
                let mut creds = Vec::new();
                for id in ids {
                    let cred_key = format!("webauthn_credential:{}:{}", username, id);
                    if let Ok(Some(cred_data)) = storage.get_kv(&cred_key).await
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

/// Delete a WebAuthn credential (requires authentication; user can only delete own credentials)
pub async fn delete_webauthn_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    axum::extract::Path((username, credential_id)): axum::extract::Path<(String, String)>,
) -> Json<ApiResponse<()>> {
    // Require authentication
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return Json(ApiResponse::error(
                "UNAUTHORIZED",
                "Authentication required",
            ));
        }
    };
    let auth_token = match validate_api_token(&state.auth_framework, &token).await {
        Ok(t) => t,
        Err(_) => {
            return Json(ApiResponse::error(
                "UNAUTHORIZED",
                "Invalid or expired token",
            ));
        }
    };

    // Authorize: user can only delete their own credentials (admins can delete any)
    if auth_token.user_id != username && !auth_token.roles.contains(&"admin".to_string()) {
        return Json(ApiResponse::error(
            "FORBIDDEN",
            "You can only delete your own credentials",
        ));
    }

    let storage = state.auth_framework.storage();
    let credential_key = format!("webauthn_credential:{}:{}", username, credential_id);

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
            let index_key = format!("webauthn_creds_index:{}", username);
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
        assert_eq!(cfg.attestation, "direct");
        assert_eq!(cfg.timeout_ms, 60_000);
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
