//! OAuth 2.0 API Endpoints
//!
//! **These endpoints are not implemented on this release line.** Earlier releases answered them with
//! placeholder data (an introspection said `active: true` for any string, the token endpoint issued
//! made-up tokens without checking the client, the authorization endpoint redirected with a made-up
//! code). Every handler here now answers `501 Not Implemented` whatever the request says, so
//! nothing that depends on them can be told that something is valid when it was never checked.
//! The working OAuth 2.0 server is `server::oauth` (library API), and the 0.5 and 0.6 lines
//! implement these endpoints in `api::oauth2`.

use crate::api::{ApiResponse, ApiState};
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// OAuth authorization request parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// OAuth token request
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
}

/// OAuth token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// OAuth error response
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

/// Client information
#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub name: String,
    pub description: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
}

const NOT_IMPLEMENTED_DESCRIPTION: &str =
    "this OAuth endpoint is not implemented in this release line";

fn not_implemented_response() -> Response {
    let error = OAuthError {
        error: "not_implemented".to_string(),
        error_description: Some(NOT_IMPLEMENTED_DESCRIPTION.to_string()),
        error_uri: None,
        state: None,
    };
    (StatusCode::NOT_IMPLEMENTED, Json(error)).into_response()
}

fn not_implemented<T: Serialize>() -> ApiResponse<T> {
    ApiResponse::<T>::error_typed("NOT_IMPLEMENTED", NOT_IMPLEMENTED_DESCRIPTION)
}

/// GET /oauth/authorize
/// Not implemented: answers `501` and never redirects.
pub async fn authorize(
    State(_state): State<ApiState>,
    Query(_params): Query<AuthorizeRequest>,
) -> impl IntoResponse {
    not_implemented_response()
}

/// POST /oauth/token
/// Not implemented: answers `501` for every grant type and issues nothing.
pub async fn token(
    State(_state): State<ApiState>,
    _headers: HeaderMap,
    Json(_req): Json<TokenRequest>,
) -> ApiResponse<TokenResponse> {
    not_implemented()
}

/// POST /oauth/revoke
/// Token revocation endpoint
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// Not implemented: answers `501`; nothing is revoked.
pub async fn revoke_token(
    State(_state): State<ApiState>,
    Json(_req): Json<RevokeRequest>,
) -> ApiResponse<()> {
    not_implemented()
}

/// POST /oauth/introspect
/// Token introspection endpoint (RFC 7662)
#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

/// Not implemented: answers `501`; never reports a token as active.
pub async fn introspect_token(
    State(_state): State<ApiState>,
    Json(_req): Json<IntrospectRequest>,
) -> ApiResponse<IntrospectResponse> {
    not_implemented()
}

/// GET /oauth/clients/{client_id}
/// Not implemented: answers `501`; no client information is made up.
pub async fn get_client_info(
    State(_state): State<ApiState>,
    axum::extract::Path(_client_id): axum::extract::Path<String>,
) -> ApiResponse<ClientInfo> {
    not_implemented()
}
