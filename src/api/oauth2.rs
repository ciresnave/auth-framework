//! OAuth 2.0 API Endpoints
//!
//! Handles OAuth 2.0 authorization code flow (RFC 6749), token exchange,
//! token revocation (RFC 7009), and client metadata retrieval.

use crate::api::{ApiResponse, ApiState, extract_bearer_token, validate_api_token};
use crate::oauth2_server::AuthorizationRequest;
// Re-export canonical types for consumers that imported them from api::oauth2
pub use crate::oauth2_server::{
    AuthorizationRequest as AuthorizeRequest, TokenRequest, TokenResponse,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

/// Compare two redirect URIs using parsed URL normalization (RFC 6749 §3.1.2.3).
///
/// Normalization handles scheme/host case, default-port elision, and path
/// normalization so that trivial textual differences don't cause mismatches.
fn redirect_uri_matches(candidate: &str, registered: &str) -> bool {
    match (Url::parse(candidate), Url::parse(registered)) {
        (Ok(a), Ok(b)) => {
            // RFC 6749 §3.1.2: redirect URIs MUST NOT contain a fragment component.
            if a.fragment().is_some() || b.fragment().is_some() {
                return false;
            }

            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
                && a.path() == b.path()
                && a.query() == b.query()
        }
        // If either side isn't a valid URL, fall back to exact string match
        // so we don't silently accept garbage.
        _ => candidate == registered,
    }
}

/// OAuth error response per [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
///
/// Use the constructor + chaining helpers to avoid specifying all four fields
/// every time:
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::OAuthError;
///
/// let err = OAuthError::new("invalid_request")
///     .description("missing redirect_uri")
///     .state("abc");
/// assert_eq!(err.error, "invalid_request");
/// assert_eq!(err.error_description.as_deref(), Some("missing redirect_uri"));
/// ```
#[derive(Debug, Serialize)]
pub struct OAuthError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl OAuthError {
    /// Create a new error with the given error code (e.g. `"invalid_request"`).
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            error_description: None,
            error_uri: None,
            state: None,
        }
    }

    /// Set the human-readable error description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.error_description = Some(desc.into());
        self
    }

    /// Set the `state` parameter (echoed back from the authorization request).
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Set the `state` parameter from an `Option`.
    pub fn maybe_state(mut self, state: Option<String>) -> Self {
        self.state = state;
        self
    }

    /// Set the error URI pointing to a page with more information.
    pub fn error_uri(mut self, uri: impl Into<String>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }
}

/// Registered OAuth 2.0 client metadata.
///
/// Stored in KV at `oauth2_client:{client_id}` and returned by
/// [`get_client_info`].
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::ClientInfo;
///
/// let info = ClientInfo {
///     client_id: "abc".into(),
///     name: "My App".into(),
///     description: "A demo app".into(),
///     redirect_uris: vec!["https://example.com/cb".into()],
///     scopes: vec!["openid".into()],
/// };
/// assert_eq!(info.client_id, "abc");
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub name: String,
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

/// OAuth 2.0 token revocation request per [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009).
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::RevokeRequest;
///
/// let req: RevokeRequest = serde_json::from_str(r#"{"token":"abc"}"#).unwrap();
/// assert_eq!(req.token, "abc");
/// assert!(req.token_type_hint.is_none());
/// ```
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>, // "access_token" or "refresh_token"
}

/// OpenID Connect UserInfo response.
///
/// Contains claims about the authenticated user, filtered by the scopes
/// granted to the access token.
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::UserInfoResponse;
///
/// let info = UserInfoResponse {
///     sub: "user-1".into(),
///     name: Some("Alice".into()),
///     email: None,
///     picture: None,
///     updated_at: None,
/// };
/// assert_eq!(info.sub, "user-1");
/// ```
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

/// GET /oauth/authorize
/// OAuth 2.0 authorization endpoint — validates the client and redirect_uri, generates
/// an authorization code, and redirects the user-agent back to the client (RFC 6749 §4.1.2).
///
/// SECURITY: The caller must supply their access token as `Authorization: Bearer <token>`.
/// The authenticated user's identity is recorded in the authorization code so it can be
/// used when the client exchanges the code for tokens.  Issuing codes without a verified
/// user identity would allow any party that knows a valid client_id to obtain tokens.
pub async fn authorize(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizationRequest>,
) -> impl IntoResponse {
    if params.response_type != "code" {
        let error = OAuthError::new("unsupported_response_type")
            .description("Only 'code' response type is supported")
            .maybe_state(params.state);
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    if params.client_id.is_empty() {
        let error = OAuthError::new("invalid_request")
            .description("client_id is required")
            .maybe_state(params.state);
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    if params.redirect_uri.is_empty() {
        let error = OAuthError::new("invalid_request")
            .description("redirect_uri is required")
            .maybe_state(params.state);
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    // SECURITY: Require the resource owner to be authenticated before issuing codes.
    // The user must supply their Bearer access token.  Without this check, any caller
    // that knows a registered client_id could obtain a code and exchange it for tokens.
    let user_id = {
        let token_str = match extract_bearer_token(&headers) {
            Some(t) => t,
            None => {
                let error = OAuthError::new("unauthorized_client")
                    .description(
                        "User authentication required: supply your access token as \
                         'Authorization: Bearer <token>'",
                    )
                    .maybe_state(params.state);
                return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
            }
        };
        match validate_api_token(&state.auth_framework, &token_str).await {
            Ok(auth_token) => auth_token.user_id,
            Err(_) => {
                let error = OAuthError::new("unauthorized_client")
                    .description("Invalid or expired user access token")
                    .maybe_state(params.state);
                return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
            }
        }
    };

    // SECURITY: Validate client_id and verify the redirect_uri is pre-registered.
    // Redirecting to an unregistered URI would let an attacker steal the authorization code.
    let client_key = format!("oauth2_client:{}", params.client_id);
    match state.auth_framework.storage().get_kv(&client_key).await {
        Ok(Some(data)) => {
            let client_data: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
            let registered_uris: Vec<String> = client_data["redirect_uris"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            if !registered_uris
                .iter()
                .any(|r| redirect_uri_matches(&params.redirect_uri, r))
            {
                tracing::warn!(
                    client_id = %params.client_id,
                    redirect_uri = %params.redirect_uri,
                    "OAuth authorize: redirect_uri not registered for client"
                );
                let error = OAuthError::new("invalid_request")
                    .description("redirect_uri is not registered for this client")
                    .maybe_state(params.state);
                return (StatusCode::BAD_REQUEST, Json(error)).into_response();
            }

            // S8: Public clients (no client_secret) MUST provide a PKCE code_challenge.
            let is_public_client = client_data
                .get("client_secret")
                .and_then(|v| v.as_str())
                .map_or(true, |s| s.is_empty());
            if is_public_client && params.code_challenge.is_none() {
                let error = OAuthError::new("invalid_request")
                    .description("Public clients must use PKCE: code_challenge is required")
                    .maybe_state(params.state);
                return (StatusCode::BAD_REQUEST, Json(error)).into_response();
            }
        }
        Ok(None) => {
            tracing::warn!(client_id = %params.client_id, "OAuth authorize: unknown client_id");
            let error = OAuthError::new("invalid_client")
                .description("Unknown client_id")
                .maybe_state(params.state);
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
        Err(e) => {
            tracing::error!(
                client_id = %params.client_id,
                error = %e,
                "OAuth authorize: storage error looking up client"
            );
            let error = OAuthError::new("server_error")
                .description("Authorization server error")
                .maybe_state(params.state);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    }

    let auth_code = format!("ac_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

    // RFC 8707: Validate resource indicators if present.
    if let Some(ref resources) = params.resource {
        if let Err(e) =
            crate::server::oauth::resource_indicators::validate_resource_indicators(resources)
        {
            let error = OAuthError::new("invalid_target")
                .description(e.to_string())
                .maybe_state(params.state);
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    }

    let code_data = serde_json::json!({
        "client_id": params.client_id,
        "redirect_uri": params.redirect_uri,
        "scope": params.scope.clone().unwrap_or_else(|| "openid profile email".to_string()),
        "state": params.state.clone(),
        "code_challenge": params.code_challenge,
        "code_challenge_method": params.code_challenge_method,
        "user_id": user_id,
        "resource": params.resource,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
        "used": false,
    });

    let storage_key = format!("oauth2_code:{}", auth_code);
    let code_data_str = match serde_json::to_string(&code_data) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize OAuth authorization code data: {:?}", e);
            let error =
                OAuthError::new("server_error").description("Authorization server internal error");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    };

    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &storage_key,
            code_data_str.as_bytes(),
            Some(std::time::Duration::from_secs(600)),
        )
        .await
    {
        tracing::error!("Failed to store OAuth authorization code: {:?}", e);
        let error = OAuthError::new("server_error")
            .description("Authorization server error")
            .maybe_state(params.state);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
    }

    // SECURITY: URL-encode the state value to prevent parameter injection.
    // A raw state like "&extra=injected" would append unintended query parameters.
    let encoded_state: Option<String> = params.state.as_deref().map(|st| {
        st.bytes()
            .flat_map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    vec![b as char]
                } else {
                    format!("%{:02X}", b).chars().collect()
                }
            })
            .collect()
    });

    let mut redirect_url = params.redirect_uri;
    redirect_url.push_str(&format!("?code={}", auth_code));
    if let Some(ref st) = encoded_state {
        redirect_url.push_str(&format!("&state={}", st));
    }

    tracing::info!(
        client_id = %params.client_id,
        user_id = %user_id,
        "OAuth authorization code issued"
    );
    Redirect::to(&redirect_url).into_response()
}

/// POST /oauth/token — exchange an authorization code or refresh token for
/// an access token (RFC 6749 §4.1.3, §6).
///
/// Supported grant types:
/// - `authorization_code` — requires `code`, `client_id`, and optionally `code_verifier`
/// - `refresh_token` — requires `refresh_token`
///
/// # Example
/// ```rust,ignore
/// // POST /oauth/token {"grant_type":"authorization_code","code":"ac_...","client_id":"..."}
/// let response = token(State(api_state), Json(token_request)).await;
/// assert!(response.success);
/// ```
pub async fn token(
    State(state): State<ApiState>,
    Json(req): Json<TokenRequest>,
) -> ApiResponse<TokenResponse> {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_grant(state, req).await,
        "refresh_token" => handle_refresh_token_grant(state, req).await,
        _ => ApiResponse::error_typed(
            "unsupported_grant_type",
            "Supported grant types: authorization_code, refresh_token",
        ),
    }
}

async fn handle_authorization_code_grant(
    state: ApiState,
    req: TokenRequest,
) -> ApiResponse<TokenResponse> {
    let code = match req.code {
        Some(c) => c,
        None => {
            return ApiResponse::validation_error_typed(
                "code is required for authorization_code grant",
            );
        }
    };

    let client_id = match req.client_id {
        Some(c) => c,
        None => return ApiResponse::validation_error_typed("client_id is required"),
    };

    // Defense-in-depth: Use a consumed marker to mitigate the non-atomic get+delete
    // race condition (TOCTOU). If a concurrent request already marked the code as
    // consumed, reject this request immediately.
    let consumed_key = format!("oauth2_code_consumed:{}", code);
    if let Ok(Some(_)) = state.auth_framework.storage().get_kv(&consumed_key).await {
        return ApiResponse::error_typed("invalid_grant", "Authorization code already used");
    }
    // Mark code as consumed BEFORE reading it, narrowing the race window.
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &consumed_key,
            b"1",
            Some(std::time::Duration::from_secs(600)),
        )
        .await
    {
        tracing::warn!("Failed to store code consumed marker: {:?}", e);
    }

    let storage_key = format!("oauth2_code:{}", code);
    let code_data = match state.auth_framework.storage().get_kv(&storage_key).await {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(json) => json,
            Err(e) => {
                tracing::error!("Failed to parse stored authorization code data: {:?}", e);
                return ApiResponse::error_typed("invalid_grant", "Invalid authorization code");
            }
        },
        Ok(None) => {
            return ApiResponse::error_typed(
                "invalid_grant",
                "Authorization code not found or expired",
            );
        }
        Err(e) => {
            tracing::error!("Failed to retrieve authorization code: {:?}", e);
            return ApiResponse::error_typed(
                "server_error",
                "Failed to validate authorization code",
            );
        }
    };

    // Immediately delete the code to prevent reuse (single-use enforcement).
    if let Err(e) = state.auth_framework.storage().delete_kv(&storage_key).await {
        tracing::error!("Failed to delete authorization code from storage: {:?}", e);
        return ApiResponse::error_typed("server_error", "Failed to process authorization code");
    }

    // Validate client_id matches
    if code_data["client_id"].as_str() != Some(&client_id) {
        return ApiResponse::error_typed("invalid_grant", "client_id mismatch");
    }

    // Validate redirect_uri if provided
    if let Some(redirect_uri) = &req.redirect_uri {
        let stored_uri = code_data["redirect_uri"].as_str().unwrap_or_default();
        if !redirect_uri_matches(redirect_uri, stored_uri) {
            return ApiResponse::error_typed("invalid_grant", "redirect_uri mismatch");
        }
    }

    // Check if PKCE was used in authorization - if so, code_verifier is required
    let stored_challenge = code_data["code_challenge"].as_str();
    let challenge_method = code_data["code_challenge_method"]
        .as_str()
        .unwrap_or("plain");

    if let Some(stored) = stored_challenge {
        // PKCE was used in authorization, so code_verifier is required
        let code_verifier = match &req.code_verifier {
            Some(verifier) => verifier,
            None => {
                return ApiResponse::error_typed(
                    "invalid_request",
                    "code_verifier is required when PKCE challenge was provided",
                );
            }
        };

        let computed_challenge = match challenge_method {
            "S256" => {
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(hasher.finalize())
            }
            "plain" => code_verifier.clone(),
            _ => {
                return ApiResponse::error_typed(
                    "invalid_request",
                    "Unsupported code_challenge_method",
                );
            }
        };

        if computed_challenge != stored {
            return ApiResponse::error_typed("invalid_grant", "PKCE verification failed");
        }
    } else if req.code_verifier.is_some() {
        // code_verifier provided but no challenge was used - this is suspicious
        return ApiResponse::error_typed(
            "invalid_request",
            "code_verifier provided but no PKCE challenge was used in authorization",
        );
    } else if req.client_secret.is_none() {
        // S8: Public clients (no client_secret) MUST use PKCE.
        // If no code_challenge was stored and no client_secret is provided,
        // the request is from an unauthenticated public client without PKCE.
        return ApiResponse::error_typed(
            "invalid_request",
            "Public clients must use PKCE: provide code_challenge in authorization and code_verifier in token request",
        );
    }

    // Code was already atomically deleted above (delete-first approach).
    // No need to mark as used — the code is permanently consumed.

    // RFC 8707: Validate resource indicators on the token request.
    let authz_resources: Vec<String> = code_data["resource"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if let Some(ref token_resources) = req.resource {
        if let Err(e) =
            crate::server::oauth::resource_indicators::validate_resource_indicators(token_resources)
        {
            return ApiResponse::error_typed("invalid_target", &e.to_string());
        }
        if let Err(e) = crate::server::oauth::resource_indicators::validate_token_resource_subset(
            token_resources,
            &authz_resources,
        ) {
            return ApiResponse::error_typed("invalid_target", &e.to_string());
        }
    }

    // Create access and refresh tokens
    let scope = code_data["scope"]
        .as_str()
        .unwrap_or("openid profile email");
    let scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();

    // Use the user_id that was recorded in the authorization code when the resource owner
    // authenticated via the /oauth/authorize endpoint.  This ensures tokens are bound to the
    // actual user rather than a fabricated identifier derived from the client_id.
    let user_id = match code_data["user_id"].as_str() {
        Some(uid) if !uid.is_empty() => uid.to_string(),
        _ => {
            tracing::error!("Authorization code missing user_id field");
            return ApiResponse::error_typed("server_error", "Malformed authorization code");
        }
    };

    let token = match state.auth_framework.token_manager().create_auth_token(
        &user_id,
        scopes.clone(),
        "oauth2",
        None,
    ) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to create access token: {:?}", e);
            return ApiResponse::error_typed("server_error", "Failed to create access token");
        }
    };

    // Persist a storage-backed refresh token so the refresh grant can validate and rotate it.
    let refresh_token_value = uuid::Uuid::new_v4().to_string().replace("-", "");
    let refresh_data = serde_json::json!({
        "user_id": user_id,
        "client_id": client_id,
        "scopes": scope,
    });
    let refresh_key = format!("oauth2_refresh_token:{}", refresh_token_value);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &refresh_key,
            serde_json::to_string(&refresh_data)
                .unwrap_or_default()
                .as_bytes(),
            Some(std::time::Duration::from_secs(30 * 24 * 3600)),
        )
        .await
    {
        tracing::warn!("Failed to store refresh token: {:?}", e);
    }

    let expires_in = (token.expires_at - token.issued_at).num_seconds().max(0) as u64;
    let response = TokenResponse {
        access_token: token.access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: Some(refresh_token_value),
        scope: Some(scope.to_string()),
        id_token: None,
    };

    tracing::info!("OAuth2 tokens issued for client: {}", client_id);
    ApiResponse::success(response)
}

async fn handle_refresh_token_grant(
    state: ApiState,
    req: TokenRequest,
) -> ApiResponse<TokenResponse> {
    let refresh_token_str = match req.refresh_token {
        Some(t) => t,
        None => return ApiResponse::validation_error_typed("refresh_token is required"),
    };

    // Defense-in-depth: Use a consumed marker to mitigate the non-atomic get+delete
    // race condition. If a concurrent request already consumed this refresh token, reject.
    let consumed_key = format!("oauth2_refresh_consumed:{}", refresh_token_str);
    if let Ok(Some(_)) = state.auth_framework.storage().get_kv(&consumed_key).await {
        return ApiResponse::error_typed("invalid_grant", "Refresh token already consumed");
    }
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &consumed_key,
            b"1",
            Some(std::time::Duration::from_secs(600)),
        )
        .await
    {
        tracing::warn!("Failed to store refresh consumed marker: {:?}", e);
    }

    // Validate the refresh token against persistent storage.
    let refresh_key = format!("oauth2_refresh_token:{}", refresh_token_str);
    let stored = match state.auth_framework.storage().get_kv(&refresh_key).await {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(v) => v,
            Err(_) => return ApiResponse::error_typed("invalid_grant", "Invalid refresh token"),
        },
        Ok(None) => {
            return ApiResponse::error_typed("invalid_grant", "Refresh token not found or expired");
        }
        Err(e) => {
            tracing::error!("Failed to retrieve refresh token: {:?}", e);
            return ApiResponse::error_typed("server_error", "Failed to validate refresh token");
        }
    };

    let user_id = match stored["user_id"].as_str() {
        Some(u) => u.to_string(),
        None => return ApiResponse::error_typed("invalid_grant", "Malformed refresh token data"),
    };
    let scope = stored["scopes"]
        .as_str()
        .unwrap_or("openid profile email")
        .to_string();
    let scopes: Vec<String> = scope.split_whitespace().map(|s| s.to_string()).collect();

    let token = match state
        .auth_framework
        .token_manager()
        .create_auth_token(&user_id, scopes, "oauth2", None)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to create access token on refresh: {:?}", e);
            return ApiResponse::error_typed("server_error", "Failed to issue access token");
        }
    };

    // Issue a new refresh token (rotation).
    // Store the new token BEFORE deleting the old one to avoid data loss on failure.
    let new_refresh_token = uuid::Uuid::new_v4().to_string().replace("-", "");
    let new_refresh_data = serde_json::json!({ "user_id": user_id, "scopes": scope });
    let new_refresh_key = format!("oauth2_refresh_token:{}", new_refresh_token);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &new_refresh_key,
            serde_json::to_string(&new_refresh_data)
                .unwrap_or_default()
                .as_bytes(),
            Some(std::time::Duration::from_secs(30 * 24 * 3600)),
        )
        .await
    {
        tracing::error!("Failed to store new refresh token: {:?}", e);
        return ApiResponse::error_typed("server_error", "Failed to issue refresh token");
    }

    // Now that the new token is safely stored, delete the old one (single-use enforcement).
    if let Err(e) = state.auth_framework.storage().delete_kv(&refresh_key).await {
        tracing::warn!(
            "Failed to delete old refresh token during rotation: {:?}",
            e
        );
    }

    let expires_in = (token.expires_at - token.issued_at).num_seconds().max(0) as u64;
    let response = TokenResponse {
        access_token: token.access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: Some(new_refresh_token),
        scope: Some(scope),
        id_token: None,
    };

    tracing::info!("OAuth2 token refreshed for user: {}", user_id);
    ApiResponse::success(response)
}

/// POST /api/v1/oauth/revoke — revoke an access or refresh token.
///
/// Stores a revocation marker in KV (`oauth2_revoked_token:{token}`) and,
/// for JWT tokens, also stores a JTI-based marker (`revoked_token:{jti}`)
/// so that all authenticated endpoints reject the token immediately.
///
/// # Example
/// ```rust,ignore
/// let resp = revoke(State(state), Json(RevokeRequest {
///     token: "access_token_value".into(),
///     token_type_hint: Some("access_token".into()),
/// })).await;
/// assert!(resp.success);
/// ```
pub async fn revoke(
    State(state): State<ApiState>,
    Json(req): Json<RevokeRequest>,
) -> ApiResponse<serde_json::Value> {
    // Store the revoked token in a blacklist for immediate invalidation.
    // Key by the raw token value so the userinfo endpoint can check it too.
    let revoked_token_key = format!("oauth2_revoked_token:{}", req.token);
    let revoked_data = serde_json::json!({
        "token": req.token,
        "revoked_at": chrono::Utc::now().to_rfc3339(),
        "token_type_hint": req.token_type_hint
    });

    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(
            &revoked_token_key,
            serde_json::to_string(&revoked_data)
                .unwrap_or_default()
                .as_bytes(),
            Some(std::time::Duration::from_secs(86400 * 7)),
        )
        .await
    {
        tracing::error!("Failed to store revoked token: {:?}", e);
        return ApiResponse::error_typed("server_error", "Failed to revoke token");
    }

    // If the token is a JWT, also store revoked_token:{jti} so the authentication
    // middleware (validate_api_token in api/mod.rs) blocks it on all protected
    // endpoints. Without this step, the revocation would only be visible to the
    // userinfo endpoint, leaving all other authenticated routes unprotected.
    if let Ok(claims) = state
        .auth_framework
        .token_manager()
        .validate_jwt_token(&req.token)
    {
        let now = chrono::Utc::now().timestamp();
        let remaining_secs = (claims.exp - now + 60).max(60) as u64;
        let jti_key = format!("revoked_token:{}", claims.jti);
        if let Err(e) = state
            .auth_framework
            .storage()
            .store_kv(
                &jti_key,
                b"1",
                Some(std::time::Duration::from_secs(remaining_secs)),
            )
            .await
        {
            tracing::warn!("Failed to store JWT JTI revocation entry: {:?}", e);
        } else {
            tracing::info!("JWT token revoked via jti: {}", claims.jti);
        }
    }

    tracing::info!(
        "OAuth2 token revoked: {}",
        &req.token[..10.min(req.token.len())]
    );

    ApiResponse::success(serde_json::json!({
        "message": "Token revoked successfully"
    }))
}

/// GET /api/v1/oauth/userinfo — return claims about the authenticated user.
///
/// The caller must supply a valid Bearer access token. If the token has been
/// revoked, an `invalid_token` error is returned. Email is included only
/// when the `email` scope is present in the token.
///
/// # Example
/// ```rust,ignore
/// // GET /api/v1/oauth/userinfo  Authorization: Bearer <token>
/// let resp = userinfo(State(state), headers).await;
/// assert_eq!(resp.data.unwrap().sub, "user-1");
/// ```
pub async fn userinfo(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> ApiResponse<UserInfoResponse> {
    // Extract and validate access token
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return ApiResponse::error_typed("invalid_token", "Authorization header required");
        }
    };

    // Check if token is revoked first
    let revoked_token_key = format!("oauth2_revoked_token:{}", token);
    if let Ok(Some(_)) = state
        .auth_framework
        .storage()
        .get_kv(&revoked_token_key)
        .await
    {
        return ApiResponse::error_typed("invalid_token", "Token has been revoked");
    }

    // Validate the access token
    let claims = match state
        .auth_framework
        .token_manager()
        .validate_jwt_token(&token)
    {
        Ok(c) => c,
        Err(_) => {
            return ApiResponse::error_typed("invalid_token", "Access token is invalid");
        }
    };

    // Get user profile
    let user_profile = match state.auth_framework.get_user_profile(&claims.sub).await {
        Ok(profile) => profile,
        Err(e) => {
            tracing::error!("Failed to get user profile: {:?}", e);
            return ApiResponse::error_typed("server_error", "Failed to retrieve user information");
        }
    };

    let userinfo = UserInfoResponse {
        sub: claims.sub.clone(),
        name: user_profile.username.clone(),
        // Only include email if the token's scopes include "email"
        email: if claims.scope.split_whitespace().any(|s| s == "email") {
            user_profile.email.clone()
        } else {
            None
        },
        picture: user_profile.picture.clone(),
        updated_at: Some(chrono::Utc::now().timestamp()),
    };

    tracing::info!("OAuth2 UserInfo requested for user: {}", claims.sub);
    ApiResponse::success(userinfo)
}

/// GET /oauth/clients/{client_id} — return the stored metadata for a
/// registered OAuth 2.0 client.
///
/// # Example
/// ```rust,ignore
/// let resp = get_client_info(State(state), Path("my-client-id".into())).await;
/// ```
pub async fn get_client_info(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
) -> impl IntoResponse {
    let client_key = format!("oauth2_client:{}", client_id);
    match state.auth_framework.storage().get_kv(&client_key).await {
        Ok(Some(data)) => match serde_json::from_slice::<ClientInfo>(&data) {
            Ok(client) => (
                StatusCode::OK,
                Json(serde_json::json!({ "success": true, "data": client })),
            )
                .into_response(),
            Err(e) => {
                tracing::error!(client_id = %client_id, error = %e, "Failed to deserialize client record");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": "server_error",
                        "message": "Failed to read client record"
                    })),
                )
                    .into_response()
            }
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": "invalid_client",
                "message": "Unknown client_id"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(client_id = %client_id, error = %e, "Storage error looking up client");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "server_error",
                    "message": "Authorization server error"
                })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// OpenID Connect Discovery (RFC 8414 / OpenID Connect Discovery 1.0)
// ---------------------------------------------------------------------------

/// OpenID Connect Discovery endpoint (RFC 8414 / OpenID Connect Discovery 1.0).
///
/// Returns server authorization metadata so clients can auto-configure
/// (issuer, endpoints, supported grants, signing algorithms, etc.).
///
/// # Example
/// ```rust,ignore
/// // GET /.well-known/openid-configuration
/// let (status, Json(config)) = openid_configuration(State(state)).await;
/// assert_eq!(status, StatusCode::OK);
/// ```
pub async fn openid_configuration(State(state): State<ApiState>) -> impl IntoResponse {
    let issuer = {
        let configured = state.auth_framework.config().issuer.clone();
        if configured.is_empty() {
            "https://auth.example.com".to_string()
        } else {
            configured
        }
    };

    let config = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/api/v1/oauth/authorize", issuer),
        "token_endpoint": format!("{}/api/v1/oauth/token", issuer),
        "userinfo_endpoint": format!("{}/api/v1/oauth/userinfo", issuer),
        "revocation_endpoint": format!("{}/api/v1/oauth/revoke", issuer),
        "introspection_endpoint": format!("{}/api/v1/oauth/introspect", issuer),
        "jwks_uri": format!("{}/api/v1/.well-known/jwks.json", issuer),
        "end_session_endpoint": format!("{}/api/v1/oauth/end_session", issuer),
        "pushed_authorization_request_endpoint": format!("{}/api/v1/oauth/par", issuer),
        "registration_endpoint": format!("{}/api/v1/oauth/register", issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"]
    });

    (StatusCode::OK, Json(config))
}

// ---------------------------------------------------------------------------
// JWKS endpoint (RFC 7517)
// ---------------------------------------------------------------------------

/// JSON Web Key Set (JWKS) endpoint ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)).
///
/// Returns the public keys used to verify tokens. Currently returns an
/// empty key set because HS256 (symmetric) signing is used; clients
/// should use the introspection endpoint for token validation.
///
/// # Example
/// ```rust,ignore
/// // GET /.well-known/jwks.json
/// let (status, Json(jwks)) = jwks(State(state)).await;
/// assert!(jwks["keys"].as_array().unwrap().is_empty());
/// ```
pub async fn jwks(State(_state): State<ApiState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "keys": [] })))
}

// ---------------------------------------------------------------------------
// OIDC RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0)
// ---------------------------------------------------------------------------

/// Request parameters for OpenID Connect RP-Initiated Logout.
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::EndSessionRequest;
///
/// let req: EndSessionRequest = serde_json::from_str(
///     r#"{"id_token_hint":"eyJ...","state":"xyz"}"#
/// ).unwrap();
/// assert!(req.post_logout_redirect_uri.is_none());
/// ```
#[derive(Debug, Deserialize)]
pub struct EndSessionRequest {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// OIDC RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0).
///
/// Revokes the token from `id_token_hint` (if valid) and, when a
/// registered `post_logout_redirect_uri` is provided, redirects the
/// user-agent there.
///
/// # Example
/// ```rust,ignore
/// // GET /oauth/end_session?id_token_hint=eyJ...&state=xyz
/// let resp = end_session(State(state), Query(params)).await;
/// ```
pub async fn end_session(
    State(state): State<ApiState>,
    Query(params): Query<EndSessionRequest>,
) -> impl IntoResponse {
    // If an id_token_hint is provided, revoke it
    if let Some(ref token) = params.id_token_hint {
        if let Ok(claims) = state
            .auth_framework
            .token_manager()
            .validate_jwt_token(token)
        {
            let revoked_key = format!("oauth2_revoked_token:{}", token);
            if let Err(e) = state
                .auth_framework
                .storage()
                .store_kv(
                    &revoked_key,
                    b"revoked",
                    Some(std::time::Duration::from_secs(86400 * 7)),
                )
                .await
            {
                tracing::warn!("Failed to revoke token during OIDC end_session: {}", e);
            }
            tracing::info!("OIDC end_session: revoked token for user {}", claims.sub);
        }
    }

    // Redirect to post_logout_redirect_uri only if it matches a registered URI for the
    // client identified by id_token_hint.  Without this check an attacker could craft a
    // link that redirects users to an arbitrary URL (open redirect / phishing).
    if let Some(ref redirect_uri) = params.post_logout_redirect_uri {
        // Look up the client's registered redirect URIs via the id_token_hint's `azp` or `aud` claim.
        let allowed = if let Some(ref token) = params.id_token_hint {
            // Try to extract client_id from the token (azp > aud)
            let client_id = state
                .auth_framework
                .token_manager()
                .validate_jwt_token(token)
                .ok()
                .and_then(|claims| {
                    // client_id claim identifies the OAuth client
                    if let Some(ref cid) = claims.client_id {
                        if !cid.is_empty() {
                            return Some(cid.clone());
                        }
                    }
                    // Fallback: aud may contain the client_id
                    if !claims.aud.is_empty() {
                        Some(claims.aud.clone())
                    } else {
                        None
                    }
                });
            if let Some(cid) = client_id {
                let client_key = format!("oauth2_client:{}", cid);
                match state.auth_framework.storage().get_kv(&client_key).await {
                    Ok(Some(data)) => {
                        let client: serde_json::Value =
                            serde_json::from_slice(&data).unwrap_or_default();
                        let uris: Vec<String> = client["redirect_uris"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        uris.iter().any(|r| redirect_uri_matches(redirect_uri, r))
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        };

        if allowed {
            if let Ok(mut parsed) = Url::parse(redirect_uri) {
                if let Some(ref st) = params.state {
                    parsed.query_pairs_mut().append_pair("state", st);
                }
                return Redirect::to(parsed.as_str()).into_response();
            }
        } else {
            tracing::warn!(
                "end_session: post_logout_redirect_uri rejected — not registered for the client"
            );
        }
    }

    // No redirect — return a simple JSON acknowledgement
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "logged_out" })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Dynamic client registration request per [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591).
///
/// # Example
/// ```rust
/// use auth_framework::api::oauth2::ClientRegistrationRequest;
///
/// let req: ClientRegistrationRequest = serde_json::from_str(
///     r#"{"redirect_uris":["https://example.com/cb"]}"#
/// ).unwrap();
/// assert_eq!(req.redirect_uris.len(), 1);
/// ```
#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// POST /oauth/register — dynamically register a new OAuth 2.0 client
/// ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)).
///
/// Requires a valid Bearer token with `admin` role, or an Initial Access
/// Token stored in KV at `oauth2_initial_access_token`. Unauthenticated
/// callers are rejected to prevent resource exhaustion.
///
/// # Example
/// ```rust,ignore
/// let resp = register_client(
///     State(state),
///     headers,   // with Authorization: Bearer <admin-token>
///     Json(ClientRegistrationRequest {
///         redirect_uris: vec!["https://example.com/cb".into()],
///         client_name: Some("My App".into()),
///         ..Default::default()
///     }),
/// ).await;
/// ```
pub async fn register_client(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<ClientRegistrationRequest>,
) -> impl IntoResponse {
    // RFC 7591 §1.2: require authentication via Bearer token
    let token_str = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "A valid Bearer token is required for dynamic client registration"
                })),
            )
                .into_response();
        }
    };

    // Option 1: check if this is the pre-configured Initial Access Token
    let is_initial_access_token = match state
        .auth_framework
        .storage()
        .get_kv("oauth2_initial_access_token")
        .await
    {
        Ok(Some(stored)) => {
            let stored_str = String::from_utf8_lossy(&stored);
            subtle::ConstantTimeEq::ct_eq(token_str.as_bytes(), stored_str.trim().as_bytes()).into()
        }
        _ => false,
    };

    // Option 2: validate as a normal JWT and check for admin role
    let is_admin = if !is_initial_access_token {
        match validate_api_token(&state.auth_framework, &token_str).await {
            Ok(auth_token) => auth_token.roles.contains(&"admin".to_string()),
            Err(_) => false,
        }
    } else {
        false
    };

    if !is_initial_access_token && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "insufficient_scope",
                "error_description": "Dynamic client registration requires admin privileges or a valid Initial Access Token"
            })),
        )
            .into_response();
    }
    // Validate all redirect_uris are well-formed URLs with safe schemes
    for uri in &req.redirect_uris {
        match Url::parse(uri) {
            Ok(parsed) => {
                match parsed.scheme() {
                    "https" => {}
                    "http" => {
                        // Allow plain HTTP only for loopback addresses (development)
                        if !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": "invalid_redirect_uri",
                                    "error_description": format!("Non-loopback HTTP redirect_uri not allowed: {}", uri)
                                })),
                            )
                                .into_response();
                        }
                    }
                    scheme => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": "invalid_redirect_uri",
                                "error_description": format!("Disallowed URI scheme '{}' in redirect_uri: {}", scheme, uri)
                            })),
                        )
                            .into_response();
                    }
                }
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_redirect_uri",
                        "error_description": format!("Invalid redirect_uri: {}", uri)
                    })),
                )
                    .into_response();
            }
        }
    }

    if req.redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client_metadata",
                "error_description": "At least one redirect_uri is required"
            })),
        )
            .into_response();
    }

    let client_id = Uuid::new_v4().to_string();
    let client_secret = Uuid::new_v4().to_string();

    let client_data = serde_json::json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": req.client_name,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": req.token_endpoint_auth_method.as_deref().unwrap_or("client_secret_basic"),
        "grant_types": req.grant_types.as_deref().unwrap_or(&["authorization_code".to_string()]),
        "response_types": req.response_types.as_deref().unwrap_or(&["code".to_string()]),
        "scope": req.scope.as_deref().unwrap_or("openid"),
    });

    let key = format!("oauth2_client:{}", client_id);
    if let Err(e) = state
        .auth_framework
        .storage()
        .store_kv(&key, client_data.to_string().as_bytes(), None)
        .await
    {
        tracing::error!("Failed to store client registration: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to register client"
            })),
        )
            .into_response();
    }

    tracing::info!("Dynamic client registered: client_id={}", client_id);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": req.client_name,
            "redirect_uris": req.redirect_uris,
            "token_endpoint_auth_method": req.token_endpoint_auth_method.as_deref().unwrap_or("client_secret_basic"),
            "grant_types": req.grant_types.as_deref().unwrap_or(&["authorization_code".to_string()]),
            "response_types": req.response_types.as_deref().unwrap_or(&["code".to_string()]),
            "scope": req.scope.as_deref().unwrap_or("openid"),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /users/me — alias for the authenticated user's profile
// ---------------------------------------------------------------------------

/// GET /users/me — returns the authenticated user's profile.
///
/// Convenience alias that delegates to [`userinfo`].
///
/// # Example
/// ```rust,ignore
/// // GET /users/me  Authorization: Bearer <token>
/// let resp = users_me(state, headers).await;
/// ```
pub async fn users_me(state: State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    // Delegate to the existing userinfo handler
    userinfo(state, headers).await
}
