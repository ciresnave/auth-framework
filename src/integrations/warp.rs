/// Advanced middleware hooks for request/response interception and error mapping.
///
/// # Example
/// ```rust,ignore
/// struct MyHooks;
/// impl AdvancedMiddlewareHooks for MyHooks {}
/// ```
pub trait AdvancedMiddlewareHooks {
    fn on_request(&self, _req: &warp::http::Request<warp::hyper::body::Incoming>) {}
    fn on_response(&self, _res: &warp::http::Response<warp::hyper::body::Incoming>) {}
    fn on_error(&self, _err: &AuthError) {}
}
/// Warp integration for auth-framework.
///
/// This module provides filters and utilities for seamless
/// integration with Warp web applications.
use crate::authorization::{AccessContext, AuthorizationStorage};

use crate::{
    AuthError, AuthFramework, Result,
    authorization::{AbacPermission, AuthorizationEngine},
    tokens::AuthToken,
};
use chrono::TimeZone as _;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// Custom rejection type for authentication errors.
///
/// # Example
/// ```rust,ignore
/// let rejection = AuthRejection { error: AuthError::Token(TokenError::Missing) };
/// ```
#[derive(Debug)]
pub struct AuthRejection {
    pub error: AuthError,
}

impl warp::reject::Reject for AuthRejection {}

/// Warp filter for extracting and validating JWT tokens.
///
/// # Example
/// ```rust,ignore
/// let route = warp::path("api").and(with_auth(fw.clone())).map(|token: AuthToken| { /* ... */ });
/// ```
pub fn with_auth(
    auth_framework: Arc<AuthFramework>,
) -> impl Filter<Extract = (AuthToken,), Error = Rejection> + Clone {
    warp::header::<String>("authorization").and_then(move |auth_header: String| {
        let auth_framework = auth_framework.clone();
        async move {
            // Extract the raw bearer token
            let token_str = extract_token_from_header(&auth_header)
                .map_err(|e| warp::reject::custom(AuthRejection { error: e }))?;

            // Validate using the framework's TokenManager (full HMAC/RSA signature verification)
            let claims = auth_framework
                .token_manager()
                .validate_jwt_token(&token_str)
                .map_err(|e| warp::reject::custom(AuthRejection { error: e }))?;

            // Convert the validated JwtClaims into an AuthToken
            let exp_ts = chrono::Utc
                .timestamp_opt(claims.exp, 0)
                .single()
                .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(3600));
            let iat_ts = chrono::Utc
                .timestamp_opt(claims.iat, 0)
                .single()
                .unwrap_or_else(chrono::Utc::now);
            let scopes = claims
                .scope
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            let token = AuthToken {
                token_id: claims.jti.clone(),
                user_id: claims.sub.clone(),
                access_token: token_str,
                refresh_token: None,
                token_type: Some("Bearer".to_string()),
                expires_at: exp_ts,
                scopes,
                issued_at: iat_ts,
                auth_method: "jwt".to_string(),
                client_id: claims.client_id,
                user_profile: None,
                permissions: claims.permissions.unwrap_or_default().into(),
                roles: claims.roles.unwrap_or_default().into(),
                metadata: crate::tokens::TokenMetadata::default(),
                subject: Some(claims.sub),
                issuer: Some(claims.iss),
            };

            Ok::<AuthToken, warp::Rejection>(token)
        }
    })
}

/// Warp filter for checking permissions.
///
/// # Example
/// ```rust,ignore
/// let route = warp::path("admin").and(with_permission(perm, engine.clone())).map(|()| "ok");
/// ```
pub fn with_permission<S>(
    permission: AbacPermission,
    authorization: Arc<AuthorizationEngine<S>>,
) -> impl Filter<Extract = ((),), Error = Rejection> + Clone
where
    S: AuthorizationStorage + Send + Sync + 'static,
{
    with_auth_token().and_then(move |token: AuthToken| {
        let permission = permission.clone();
        let authorization = authorization.clone();

        async move {
            // Check if user has the required permission
            match authorization
                .check_permission(
                    &token.user_id,
                    &permission,
                    &AccessContext::new(token.user_id.clone()),
                )
                .await
            {
                Ok(result) if result.granted => Ok::<(), _>(()),
                Ok(_) => Err(warp::reject::custom(AuthRejection {
                    error: AuthError::Permission(crate::errors::PermissionError::Denied {
                        action: permission.action.clone(),
                        resource: permission.resource.clone(),
                        message: "Insufficient permissions".to_string(),
                    }),
                })),
                Err(e) => Err(warp::reject::custom(AuthRejection { error: e })),
            }
        }
    })
}

/// Helper filter to extract auth token without framework dependency.
///
/// # Example
/// ```rust,ignore
/// let route = warp::path("me").and(with_auth_token()).map(|t: AuthToken| t.user_id);
/// ```
pub fn with_auth_token() -> impl Filter<Extract = (AuthToken,), Error = Rejection> + Clone {
    warp::header::<String>("authorization").and_then(|auth_header: String| async move {
        extract_token_from_header(&auth_header)
            .and_then(|token_str| validate_token_secure(&token_str))
            .map_err(|e| warp::reject::custom(AuthRejection { error: e }))
    })
}

/// Filter for optional authentication (doesn't reject if no token).
///
/// # Example
/// ```rust,ignore
/// let route = warp::path("public").and(with_optional_auth()).map(|t: Option<AuthToken>| { /* ... */ });
/// ```
pub fn with_optional_auth() -> impl Filter<Extract = (Option<AuthToken>,), Error = Rejection> + Clone
{
    warp::header::optional::<String>("authorization").and_then(
        |auth_header: Option<String>| async move {
            match auth_header {
                Some(header) => {
                    match extract_token_from_header(&header)
                        .and_then(|token_str| validate_token_secure(&token_str))
                    {
                        Ok(token) => Ok::<_, warp::Rejection>(Some(token)),
                        Err(_) => Ok::<_, warp::Rejection>(None), // Invalid token is treated as no token
                    }
                }
                None => Ok::<_, warp::Rejection>(None),
            }
        },
    )
}

/// Filter for role-based access.
///
/// # Example
/// ```rust,ignore
/// let route = warp::path("admin").and(with_role("admin", engine.clone())).map(|()| "ok");
/// ```
pub fn with_role<S>(
    required_role: &str,
    authorization: Arc<AuthorizationEngine<S>>,
) -> impl Filter<Extract = ((),), Error = Rejection> + Clone
where
    S: AuthorizationStorage + Send + Sync + 'static,
{
    let required_role = required_role.to_string();

    with_auth_token().and_then({
        let required_role = required_role.clone();
        let authorization = authorization.clone();
        move |_token: AuthToken| {
            let required_role = required_role.clone();
            let authorization = authorization.clone();
            async move {
                // Implement real role checking using AuthorizationEngine
                let user_id = _token.user_id.clone();
                let has_role = authorization
                    .has_any_role(&user_id, std::slice::from_ref(&required_role))
                    .await
                    .unwrap_or(false);
                if has_role {
                    Ok::<(), _>(())
                } else {
                    Err(warp::reject::custom(AuthRejection {
                        error: AuthError::Permission(crate::errors::PermissionError::Denied {
                            action: "role_check".to_string(),
                            resource: required_role.clone(),
                            message: "Insufficient role".to_string(),
                        }),
                    }))
                }
            }
        }
    })
}

/// CORS filter for authentication endpoints.
///
/// Applies the centralized `CorsConfig` from the framework configuration.
/// If no config is supplied, uses the framework defaults (CORS disabled \u2014
/// returns a restrictive builder that rejects all cross-origin requests).
///
/// # Example
/// ```rust,ignore
/// let cors = cors_from_config(&my_cors_config);
/// ```
pub fn cors_from_config(config: &crate::config::CorsConfig) -> warp::cors::Builder {
    let mut cors = warp::cors();
    if config.enabled {
        for origin in &config.allowed_origins {
            cors = cors.allow_origin(origin.as_str());
        }
    }
    let headers: Vec<&str> = config.allowed_headers.iter().map(|h| h.as_str()).collect();
    let methods: Vec<&str> = config.allowed_methods.iter().map(|m| m.as_str()).collect();
    cors.allow_headers(headers)
        .allow_methods(methods)
        .max_age(std::time::Duration::from_secs(config.max_age_secs as u64))
}

/// CORS filter using default configuration.
///
/// **Deprecated**: prefer `cors_from_config()` with an explicit `CorsConfig` to
/// ensure the same policy is applied consistently across all integrations.
///
/// # Example
/// ```rust,ignore
/// #[allow(deprecated)]
/// let cors = cors();
/// ```
#[deprecated(
    since = "0.5.0",
    note = "Use cors_from_config() with a CorsConfig instead"
)]
pub fn cors() -> warp::cors::Builder {
    cors_from_config(&crate::config::CorsConfig::default())
}

/// Error handling for authentication rejections.
///
/// # Example
/// ```rust,ignore
/// let routes = api.recover(handle_rejection);
/// ```
pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Rejection> {
    if let Some(auth_rejection) = err.find::<AuthRejection>() {
        let code = match &auth_rejection.error {
            AuthError::Token(_) => warp::http::StatusCode::UNAUTHORIZED,
            AuthError::Permission(_) => warp::http::StatusCode::FORBIDDEN,
            _ => warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        };

        let message = match &auth_rejection.error {
            AuthError::Token(token_err) => match token_err {
                crate::errors::TokenError::Missing => "Missing authentication token",
                crate::errors::TokenError::Invalid { .. } => "Invalid authentication token",
                crate::errors::TokenError::Expired => "Authentication token expired",
                _ => "Authentication failed",
            },
            AuthError::Permission(_) => "Insufficient permissions",
            _ => "Internal server error",
        };

        let json = warp::reply::json(&serde_json::json!({
            "error": message,
            "code": code.as_u16()
        }));

        Ok(warp::reply::with_status(json, code))
    } else {
        Err(err)
    }
}

/// Helper function to extract token from Authorization header
fn extract_token_from_header(auth_header: &str) -> Result<String> {
    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Authorization header must use Bearer scheme".to_string(),
        }));
    }

    Ok(auth_header[7..].to_string())
}

/// Structural and claims validation for contexts where no signing key is available.
///
/// **This function does NOT verify the JWT cryptographic signature.** It validates:
/// - JWT base64url structure (three parts)
/// - Required claims (`sub`, `exp`)
/// - Token expiration
///
/// For full signature verification, use [`with_auth`] which delegates to the
/// framework's [`TokenManager::validate_jwt_token`].
fn validate_token_secure(token_str: &str) -> Result<AuthToken> {
    // Basic format validation
    if token_str.len() < 10 {
        return Err(AuthError::auth_method(
            "warp_integration",
            "Token too short",
        ));
    }

    // Check for JWT structure (header.payload.signature)
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::auth_method(
            "warp_integration",
            "Invalid JWT format - must have 3 parts",
        ));
    }

    // Validate base64url encoding of parts
    use base64::Engine;
    for (i, part) in parts.iter().enumerate() {
        if base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .is_err()
        {
            return Err(AuthError::auth_method(
                "warp_integration",
                format!("Invalid base64url encoding in part {}", i + 1),
            ));
        }
    }

    // Decode and validate the payload structure — signature is not verified here.
    // Use `with_auth()` for full cryptographic validation.
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::auth_method("warp_integration", "Failed to decode payload"))?;

    let payload_str = String::from_utf8(payload_json)
        .map_err(|_| AuthError::auth_method("warp_integration", "Invalid UTF-8 in payload"))?;

    let payload: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|_| AuthError::auth_method("warp_integration", "Invalid JSON in payload"))?;

    // Validate required JWT claims
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::auth_method("warp_integration", "Missing 'sub' claim"))?;

    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        AuthError::auth_method("warp_integration", "Missing or invalid 'exp' claim")
    })?;

    // Check token expiration
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err(AuthError::auth_method(
            "warp_integration",
            "Token has expired",
        ));
    }

    // Extract optional claims
    let scopes: crate::types::Scopes = payload
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let iat = payload.get("iat").and_then(|v| v.as_i64()).unwrap_or(now);

    // Create validated token
    Ok(AuthToken {
        token_id: uuid::Uuid::new_v4().to_string(),
        user_id: sub.to_string(),
        access_token: token_str.to_string(),
        refresh_token: None,
        token_type: Some("Bearer".to_string()),
        expires_at: chrono::Utc
            .timestamp_opt(exp, 0)
            .single()
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::seconds(3600)),
        scopes,
        issued_at: chrono::Utc
            .timestamp_opt(iat, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now),
        auth_method: "jwt".to_string(),
        client_id: payload
            .get("client_id")
            .or_else(|| payload.get("azp"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        user_profile: None,
        permissions: payload
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into(),
        roles: payload
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into(),
        metadata: crate::tokens::TokenMetadata::default(),
        subject: Some(sub.to_string()),
        issuer: payload
            .get("iss")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Configuration for Warp integration.
///
/// # Example
/// ```rust,ignore
/// let cfg = WarpConfig::new(fw.clone()).with_authorization(engine);
/// ```
pub struct WarpConfig<S: AuthorizationStorage + Send + Sync + 'static> {
    pub auth_framework: Arc<AuthFramework>,
    pub authorization_engine: Option<Arc<AuthorizationEngine<S>>>,
}

impl<S: AuthorizationStorage + Send + Sync + 'static> WarpConfig<S> {
    /// Create a new Warp config.
    ///
    /// # Example
    /// ```rust,ignore
    /// let cfg = WarpConfig::new(fw.clone());
    /// ```
    pub fn new(auth_framework: Arc<AuthFramework>) -> Self {
        Self {
            auth_framework,
            authorization_engine: None,
        }
    }

    /// Add an authorization engine.
    ///
    /// # Example
    /// ```rust,ignore
    /// let cfg = cfg.with_authorization(engine);
    /// ```
    pub fn with_authorization(mut self, engine: Arc<AuthorizationEngine<S>>) -> Self {
        self.authorization_engine = Some(engine);
        self
    }

    /// Create auth filter with this configuration.
    ///
    /// # Example
    /// ```rust,ignore
    /// let filter = cfg.auth_filter();
    /// ```
    pub fn auth_filter(&self) -> impl Filter<Extract = (AuthToken,), Error = Rejection> + Clone {
        with_auth(self.auth_framework.clone())
    }
}

/// Helper macros for common authentication patterns
#[macro_export]
macro_rules! protected_route {
    ($path:expr, $handler:expr) => {
        warp::path($path)
            .and($crate::integrations::warp::with_auth_token())
            .and_then($handler)
    };
}

#[macro_export]
macro_rules! admin_route {
    ($path:expr, $handler:expr, $authorization:expr) => {
        warp::path($path)
            .and($crate::integrations::warp::with_role(
                "admin",
                $authorization,
            ))
            .and_then($handler)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test;

    async fn test_handler(token: AuthToken) -> std::result::Result<impl Reply, warp::Rejection> {
        Ok(warp::reply::json(&serde_json::json!({
            "message": format!("Hello, {}!", token.user_id)
        })))
    }

    #[tokio::test]
    async fn test_auth_filter() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use serde_json::json;

        // Create a proper JWT token for testing
        let header = Header::new(Algorithm::HS256);
        let claims = json!({
            "sub": "test_user",
            "exp": chrono::Utc::now().timestamp() + 3600, // 1 hour from now
            "iat": chrono::Utc::now().timestamp(),
            "scope": "read write"
        });
        let secret = b"test_secret_key_32_bytes_minimum!";
        let token = encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap();

        let filter = warp::path("test")
            .and(with_auth_token())
            .and_then(test_handler);

        // Test with valid token
        let resp = test::request()
            .path("/test")
            .header("authorization", &format!("Bearer {}", token))
            .reply(&filter)
            .await;

        assert_eq!(resp.status(), 200);

        // Test with invalid token
        let resp = test::request()
            .path("/test")
            .header("authorization", "Bearer invalid_token")
            .reply(&filter)
            .await;

        assert_eq!(resp.status(), 500); // Should be handled by rejection handler
    }

    #[tokio::test]
    async fn test_optional_auth() {
        let filter = warp::path("test").and(with_optional_auth()).and_then(
            |token: Option<AuthToken>| async move {
                let message = match token {
                    Some(t) => format!("Hello, {}!", t.user_id),
                    None => "Hello, anonymous!".to_string(),
                };
                Ok::<_, Rejection>(warp::reply::json(&serde_json::json!({
                    "message": message
                })))
            },
        );

        // Test with token
        let resp = test::request()
            .path("/test")
            .header("authorization", "Bearer valid_token_123")
            .reply(&filter)
            .await;

        assert_eq!(resp.status(), 200);

        // Test without token
        let resp = test::request().path("/test").reply(&filter).await;

        assert_eq!(resp.status(), 200);
    }

    // --- Edge-case tests for extract_token_from_header ---

    #[test]
    fn test_extract_token_rejects_basic_scheme() {
        let result = extract_token_from_header("Basic abc123");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Bearer"), "Error should mention Bearer: {msg}");
    }

    #[test]
    fn test_extract_token_rejects_missing_scheme() {
        let result = extract_token_from_header("some-token-without-scheme");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_token_empty_after_bearer() {
        let result = extract_token_from_header("Bearer ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_extract_token_preserves_double_space() {
        let result = extract_token_from_header("Bearer  token");
        assert!(result.is_ok());
        // After "Bearer " (7 chars), the remaining is " token" (leading space)
        assert_eq!(result.unwrap(), " token");
    }

    #[test]
    fn test_extract_token_case_sensitive_bearer() {
        let result = extract_token_from_header("bearer abc123");
        assert!(result.is_err(), "Bearer scheme should be case-sensitive");
    }

    // --- Edge-case tests for validate_token_secure ---

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_token_secure("abc");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too short"), "Expected 'too short': {msg}");
    }

    #[test]
    fn test_validate_token_wrong_part_count_two() {
        let result = validate_token_secure("header.payload");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("3 parts"), "Expected '3 parts': {msg}");
    }

    #[test]
    fn test_validate_token_wrong_part_count_four() {
        let result = validate_token_secure("a.b.c.d.e.f.g.h.i.j");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("3 parts"), "Expected '3 parts': {msg}");
    }

    #[test]
    fn test_validate_token_invalid_base64_header() {
        // "!!!" is invalid base64url; pad the other parts with valid base64
        let result = validate_token_secure("!!!invalid.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("base64url") && msg.contains("part 1"),
            "Expected base64 error for part 1: {msg}"
        );
    }

    #[test]
    fn test_validate_token_non_json_payload() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-json");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Invalid JSON"), "Expected JSON error: {msg}");
    }

    #[test]
    fn test_validate_token_missing_sub_claim() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"exp\":{}}}", chrono::Utc::now().timestamp() + 3600).as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("sub"), "Expected missing sub: {msg}");
    }

    #[test]
    fn test_validate_token_missing_exp_claim() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"sub\":\"user1\"}");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exp"), "Expected missing exp: {msg}");
    }

    #[test]
    fn test_validate_token_expired() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let past = chrono::Utc::now().timestamp() - 3600;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"sub\":\"user1\",\"exp\":{past}}}").as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("expired"), "Expected expired: {msg}");
    }

    #[test]
    fn test_validate_token_exp_as_string() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"sub\":\"user1\",\"exp\":\"not-a-number\"}");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exp"), "Expected exp error: {msg}");
    }

    #[test]
    fn test_validate_token_valid_with_optional_claims() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let exp = chrono::Utc::now().timestamp() + 3600;
        let payload_json = serde_json::json!({
            "sub": "user1",
            "exp": exp,
            "iat": chrono::Utc::now().timestamp(),
            "scope": "read write admin",
            "client_id": "my-client",
            "iss": "my-issuer",
            "permissions": ["perm1", "perm2"],
            "roles": ["admin", "user"]
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(payload_json.to_string().as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(
            result.is_ok(),
            "Valid token should parse: {:?}",
            result.err()
        );
        let token = result.unwrap();
        assert_eq!(token.user_id, "user1");
        assert_eq!(token.client_id.as_deref(), Some("my-client"));
        assert_eq!(token.issuer.as_deref(), Some("my-issuer"));
        assert!(token.has_scope("read"));
        assert!(token.has_scope("admin"));
    }

    #[test]
    fn test_validate_token_valid_without_optional_claims() {
        use base64::Engine;
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        let exp = chrono::Utc::now().timestamp() + 3600;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{{\"sub\":\"user1\",\"exp\":{exp}}}").as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
        let jwt = format!("{header}.{payload}.{sig}");
        let result = validate_token_secure(&jwt);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.user_id, "user1");
        assert!(token.client_id.is_none());
        assert!(token.issuer.is_none());
    }

    // --- Edge-case tests for handle_rejection ---

    #[tokio::test]
    async fn test_rejection_token_missing() {
        let rejection = warp::reject::custom(AuthRejection {
            error: AuthError::Token(crate::errors::TokenError::Missing),
        });
        let result = handle_rejection(rejection).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_response();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_rejection_token_expired() {
        let rejection = warp::reject::custom(AuthRejection {
            error: AuthError::Token(crate::errors::TokenError::Expired),
        });
        let result = handle_rejection(rejection).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_response();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_rejection_permission_denied() {
        let rejection = warp::reject::custom(AuthRejection {
            error: AuthError::Permission(crate::errors::PermissionError::Denied {
                action: "delete".to_string(),
                resource: "users".to_string(),
                message: "Forbidden".to_string(),
            }),
        });
        let result = handle_rejection(rejection).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_response();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn test_rejection_internal_error() {
        let rejection = warp::reject::custom(AuthRejection {
            error: AuthError::internal("something broke"),
        });
        let result = handle_rejection(rejection).await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_response();
        assert_eq!(resp.status(), 500);
    }

    #[tokio::test]
    async fn test_rejection_non_auth_passes_through() {
        let rejection = warp::reject::not_found();
        let result = handle_rejection(rejection).await;
        assert!(result.is_err(), "Non-auth rejections should pass through");
    }

    // --- Edge-case tests for cors_from_config ---

    #[test]
    fn test_cors_disabled() {
        let cfg = crate::config::CorsConfig::default();
        assert!(!cfg.enabled);
        // Should build without error even with CORS disabled
        let _ = cors_from_config(&cfg);
    }

    #[test]
    fn test_cors_with_multiple_origins() {
        let cfg = crate::config::CorsConfig::for_origins([
            "https://app1.example.com",
            "https://app2.example.com",
        ]);
        assert!(cfg.enabled);
        let _ = cors_from_config(&cfg);
    }
}
