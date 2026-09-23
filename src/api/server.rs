//! REST API Server Implementation
//!
//! Main server that hosts all API endpoints

use crate::AuthFramework;
#[cfg(feature = "saml")]
use crate::api::saml;
use crate::api::{
    ApiState, admin, advanced_protocols, auth, email_verification, health, mfa, middleware,
    oauth_advanced, oauth2, openapi, users, webauthn,
};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::Method,
    middleware as axum_middleware,
    routing::{delete, get, post, put},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

/// REST API server configuration.
///
/// Use [`ApiServerConfig::builder()`] for ergonomic construction:
///
/// ```rust,ignore
/// let config = ApiServerConfig::builder()
///     .host("0.0.0.0")
///     .port(3000)
///     .enable_cors(true)
///     .allow_origin("https://example.com")
///     .build();
/// ```
///
/// Default values bind to `127.0.0.1:8080` with tracing enabled, CORS disabled,
/// and a 1 MB maximum request body.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// Address to bind the server to (default: `"127.0.0.1"`).
    pub host: String,
    /// TCP port to listen on (default: `8080`).
    pub port: u16,
    /// Centralized CORS configuration. Enable and set `allowed_origins` to
    /// permit cross-origin requests. Origins are validated strictly — wildcard
    /// (`"*"`) is never accepted.
    pub cors: crate::config::CorsConfig,
    /// Maximum allowed request body size in bytes (default: 1 MB).
    pub max_body_size: usize,
    /// Whether to attach a `tower_http::TraceLayer` for structured request/response logging.
    pub enable_tracing: bool,
}

impl ApiServerConfig {
    /// Convenience: is CORS enabled?
    pub fn enable_cors(&self) -> bool {
        self.cors.enabled
    }
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            cors: crate::config::CorsConfig::default(), // disabled by default
            max_body_size: 1024 * 1024,                 // 1MB
            enable_tracing: true,
        }
    }
}

/// REST API Server
impl ApiServerConfig {
    /// Create a new builder for `ApiServerConfig`
    pub fn builder() -> ApiServerConfigBuilder {
        ApiServerConfigBuilder::default()
    }
}

/// Fluent builder for [`ApiServerConfig`].
///
/// Obtain via [`ApiServerConfig::builder()`].  All fields start with the same
/// defaults as `ApiServerConfig::default()`.
#[derive(Default)]
pub struct ApiServerConfigBuilder {
    config: ApiServerConfig,
}

impl ApiServerConfigBuilder {
    /// Set the address to bind to (e.g. `"0.0.0.0"`).
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }

    /// Set the TCP port (e.g. `3000`).
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Enable or disable CORS (default: disabled).
    pub fn enable_cors(mut self, enable: bool) -> Self {
        self.config.cors.enabled = enable;
        self
    }

    /// Append a single allowed origin for CORS (e.g. `"https://example.com"`).
    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.config.cors.allowed_origins.push(origin.into());
        self
    }

    /// Replace the allowed origins list for CORS.
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.config.cors.allowed_origins = origins;
        self
    }

    /// Set the maximum request body size in bytes (default: 1 MB).
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.config.max_body_size = size;
        self
    }

    /// Enable or disable structured request/response tracing (default: enabled).
    pub fn enable_tracing(mut self, enable: bool) -> Self {
        self.config.enable_tracing = enable;
        self
    }

    /// Consume the builder and return the finished [`ApiServerConfig`].
    pub fn build(self) -> ApiServerConfig {
        self.config
    }
}

/// The REST API server that hosts all authentication, user-management,
/// and health-check endpoints.
///
/// # Example
///
/// ```rust,ignore
/// let server = ApiServer::with_config(auth.clone(), config);
/// server.start().await?;
/// ```
pub struct ApiServer {
    config: ApiServerConfig,
    auth_framework: Arc<AuthFramework>,
}

impl ApiServer {
    /// Create a server with the default [`ApiServerConfig`].
    pub fn new(auth_framework: Arc<AuthFramework>) -> Self {
        Self {
            config: ApiServerConfig::default(),
            auth_framework,
        }
    }

    /// Create a server with a custom [`ApiServerConfig`].
    pub fn with_config(auth_framework: Arc<AuthFramework>, config: ApiServerConfig) -> Self {
        Self {
            config,
            auth_framework,
        }
    }

    /// Assemble the Axum [`Router`] with all route groups and middleware.
    pub async fn build_router(&self) -> crate::errors::Result<Router> {
        let state = ApiState::new(self.auth_framework.clone()).await?;

        // Create nested router for API v1
        let api_v1 = Router::new()
            // Health and monitoring endpoints (public)
            .route("/health", get(health::health_check))
            .route("/health/detailed", get(health::detailed_health_check))
            .route("/metrics", get(health::metrics))
            .route("/readiness", get(health::readiness_check))
            .route("/liveness", get(health::liveness_check))
            // Authentication endpoints (public)
            .route("/auth/login", post(auth::login))
            .route("/auth/register", post(auth::register))
            .route("/auth/refresh", post(auth::refresh_token))
            .route("/auth/logout", post(auth::logout))
            .route("/auth/validate", get(auth::validate_token))
            .route("/auth/providers", get(auth::list_providers))
            .route("/api-keys", post(auth::create_api_key))
            // Email verification endpoints
            .route(
                "/auth/verify-email/send",
                post(email_verification::send_verification),
            )
            .route("/auth/verify-email", post(email_verification::verify_email))
            .route(
                "/auth/resend-verification",
                post(email_verification::resend_verification),
            )
            // OAuth 2.0 endpoints
            .route("/oauth/authorize", get(oauth2::authorize))
            .route("/oauth/token", post(oauth2::token))
            .route("/oauth/revoke", post(oauth2::revoke))
            // RFC 7662: Token Introspection (form-encoded, client auth required)
            .route("/oauth/introspect", post(oauth_advanced::introspect_token))
            // RFC 9126: Pushed Authorization Requests
            .route(
                "/oauth/par",
                post(oauth_advanced::pushed_authorization_request),
            )
            .route("/oauth/clients/{client_id}", get(oauth2::get_client_info))
            // RFC 8628: Device Authorization Grant
            .route("/oauth/device", post(oauth_advanced::device_authorization))
            // OpenID Connect CIBA (Client Initiated Backchannel Auth)
            .route("/oauth/ciba", post(oauth_advanced::ciba_backchannel_auth))
            // OIDC UserInfo endpoint
            .route("/oauth/userinfo", get(oauth2::userinfo))
            // OIDC RP-Initiated Logout
            .route("/oauth/end_session", get(oauth2::end_session))
            // RFC 7591: Dynamic Client Registration
            .route("/oauth/register", post(oauth2::register_client))
            // OpenID Connect Discovery
            .route(
                "/.well-known/openid-configuration",
                get(oauth2::openid_configuration),
            )
            // JWKS endpoint
            .route("/.well-known/jwks.json", get(oauth2::jwks))
            // User management endpoints (authenticated)
            .route("/users/me", get(oauth2::users_me))
            .route("/users/profile", get(users::get_profile))
            .route("/users/profile", put(users::update_profile))
            .route("/users/change-password", post(users::change_password))
            .route("/users/sessions", get(users::get_sessions))
            .route(
                "/users/sessions/{session_id}",
                delete(users::revoke_session),
            )
            .route("/users/{user_id}/profile", get(users::get_user_profile))
            // Multi-factor authentication endpoints (authenticated)
            .route("/mfa/setup", post(mfa::setup_mfa))
            .route("/mfa/verify", post(mfa::verify_mfa))
            .route("/mfa/disable", post(mfa::disable_mfa))
            .route("/mfa/status", get(mfa::get_mfa_status))
            .route(
                "/mfa/regenerate-backup-codes",
                post(mfa::regenerate_backup_codes),
            )
            .route("/mfa/verify-backup-code", post(mfa::verify_backup_code))
            // Administrative endpoints (admin only)
            .route("/admin/users", get(admin::list_users))
            .route("/admin/users", post(admin::create_user))
            .route(
                "/admin/users/{user_id}/roles",
                put(admin::update_user_roles),
            )
            .route("/admin/users/{user_id}", delete(admin::delete_user))
            .route("/admin/users/{user_id}/activate", put(admin::activate_user))
            .route("/admin/stats", get(admin::get_system_stats))
            .route("/admin/audit-logs", get(admin::get_audit_logs))
            .route("/admin/audit-logs/stats", get(admin::get_audit_log_stats))
            .route(
                "/admin/config",
                get(admin::get_config).put(admin::update_config),
            )
            // WebAuthn endpoints
            .route(
                "/webauthn/registration/init",
                post(webauthn::webauthn_registration_init),
            )
            .route(
                "/webauthn/registration/complete",
                post(webauthn::webauthn_registration_complete),
            )
            .route(
                "/webauthn/authentication/init",
                post(webauthn::webauthn_authentication_init),
            )
            .route(
                "/webauthn/authentication/complete",
                post(webauthn::webauthn_authentication_complete),
            )
            .route(
                "/webauthn/credentials/{username}",
                get(webauthn::list_webauthn_credentials),
            )
            .route(
                "/webauthn/credentials/{username}/{credential_id}",
                delete(webauthn::delete_webauthn_credential),
            );

        // Build the router with conditional SAML routes
        let api_v1 = {
            let router = api_v1;

            #[cfg(feature = "saml")]
            {
                router
                    .route("/saml/metadata", get(saml::get_saml_metadata))
                    .route("/saml/sso", post(saml::initiate_saml_sso))
                    .route("/saml/acs", post(saml::handle_saml_acs))
                    .route("/saml/slo", post(saml::initiate_saml_slo))
                    .route("/saml/slo/response", get(saml::handle_saml_slo_response))
                    .route("/saml/assertion", post(saml::create_saml_assertion))
                    .route("/saml/idps", get(saml::list_saml_idps))
            }

            #[cfg(not(feature = "saml"))]
            {
                router
            }
        };

        // Create the main router with all routes
        let router = Router::new()
            .route("/api/openapi.json", get(openapi::serve_openapi_json))
            .route("/docs", get(openapi::serve_swagger_ui))
            .nest("/api/v1", api_v1)
            .merge(advanced_protocols::router())
            .with_state(state.clone());

        // Add middleware layers
        let middleware_stack = ServiceBuilder::new()
            .layer(axum_middleware::from_fn(middleware::timeout_middleware))
            .layer(axum_middleware::from_fn(
                middleware::security_headers_middleware,
            ))
            .layer(axum_middleware::from_fn({
                let state = state.clone();
                move |request, next| {
                    let state = state.clone();
                    async move {
                        middleware::rate_limit_middleware_with_state(state, request, next).await
                    }
                }
            }))
            .layer(axum_middleware::from_fn(middleware::logging_middleware));

        let router = if self.config.cors.enabled {
            if self.config.cors.allowed_origins.is_empty() {
                tracing::warn!(
                    "SECURITY/CORS: CORS is enabled but allowed_origins is empty. All cross-origin requests will be rejected! Disable CORS or add allowed origins."
                );
            }

            let header_origins: Vec<axum::http::HeaderValue> = self
                .config
                .cors
                .allowed_origins
                .iter()
                .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
                .collect();

            if header_origins.is_empty() && !self.config.cors.allowed_origins.is_empty() {
                tracing::warn!(
                    "CORS: none of the configured allowed_origins could be parsed as valid HTTP \
                     header values; cross-origin requests will be rejected"
                );
            }

            let allow_origin = tower_http::cors::AllowOrigin::list(header_origins);

            let allowed_methods: Vec<Method> = self
                .config
                .cors
                .allowed_methods
                .iter()
                .filter_map(|m| m.parse::<Method>().ok())
                .collect();

            let allowed_headers: Vec<axum::http::HeaderName> = self
                .config
                .cors
                .allowed_headers
                .iter()
                .filter_map(|h| h.parse::<axum::http::HeaderName>().ok())
                .collect();

            router.layer(
                CorsLayer::new()
                    .allow_origin(allow_origin)
                    .allow_methods(allowed_methods)
                    .allow_headers(allowed_headers)
                    .max_age(std::time::Duration::from_secs(
                        self.config.cors.max_age_secs as u64,
                    )),
            )
        } else {
            router
        };

        let router = if self.config.enable_tracing {
            router.layer(TraceLayer::new_for_http())
        } else {
            router
        };

        Ok(router
            .layer(middleware_stack)
            .layer(DefaultBodyLimit::max(self.config.max_body_size)))
    }

    /// Start the API server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.build_router().await?;

        let addr = SocketAddr::new(self.config.host.parse()?, self.config.port);

        info!("🚀 AuthFramework API server starting on http://{}", addr);
        info!("📖 API documentation available at http://{}/docs", addr);
        info!(
            "📘 OpenAPI JSON available at http://{}/api/openapi.json",
            addr
        );
        info!("🏥 Health check available at http://{}/health", addr);
        info!("📊 Metrics available at http://{}/metrics", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Get server configuration
    pub fn config(&self) -> &ApiServerConfig {
        &self.config
    }

    /// Get server address
    pub fn address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }
}

/// Create a basic API server with default configuration
pub async fn create_api_server(auth_framework: Arc<AuthFramework>) -> ApiServer {
    ApiServer::new(auth_framework)
}

/// Create an API server with custom host and port
pub async fn create_api_server_with_address(
    auth_framework: Arc<AuthFramework>,
    host: impl Into<String>,
    port: u16,
) -> ApiServer {
    let config = ApiServerConfig {
        host: host.into(),
        port,
        ..Default::default()
    };
    ApiServer::with_config(auth_framework, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::InMemoryStorage;
    use crate::{AuthConfig, AuthFramework};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn create_test_api_server() -> ApiServer {
        let _storage = Arc::new(InMemoryStorage::new());
        let config = AuthConfig::default();
        let auth_framework = Arc::new(AuthFramework::new(config));
        ApiServer::new(auth_framework)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_required_endpoints() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/users/profile")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Protected endpoint should reject request without auth
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_cors_headers() {
        let config = AuthConfig::default();
        let auth_framework = Arc::new(AuthFramework::new(config));
        let api_config = ApiServerConfig {
            cors: crate::config::CorsConfig {
                enabled: true,
                allowed_origins: vec!["http://localhost:3000".to_string()],
                ..crate::config::CorsConfig::default()
            },
            ..ApiServerConfig::default()
        };
        let api_server = ApiServer::with_config(auth_framework, api_config);
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/health")
            .method("GET")
            .header("Origin", "http://localhost:3000")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Check CORS headers are present when a matching Origin is sent
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[tokio::test]
    async fn test_readiness_endpoint() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/readiness")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Should be OK or SERVICE_UNAVAILABLE, not a 404
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn test_liveness_endpoint() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/liveness")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/metrics")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_nonexistent_route_returns_404() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/this-does-not-exist")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_login_with_empty_body() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // Should return an error (400 or 422), not 200
        assert_ne!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_register_endpoint_accessible() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let body = serde_json::json!({
            "username": "newuser",
            "password": "StrongP@ssw0rd123!",
            "email": "test@example.com"
        });

        let request = Request::builder()
            .uri("/api/v1/auth/register")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // It should process the request (not 404 or 405)
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
        assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_server_config_defaults() {
        let config = ApiServerConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
        assert!(!config.enable_cors());
    }

    #[tokio::test]
    async fn test_server_address() {
        let api_server = create_test_api_server().await;
        assert_eq!(api_server.address(), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_create_api_server_with_address() {
        let config = AuthConfig::default();
        let auth_framework = Arc::new(AuthFramework::new(config));
        let api_server = create_api_server_with_address(auth_framework, "0.0.0.0", 8080).await;
        assert_eq!(api_server.address(), "0.0.0.0:8080");
    }

    #[tokio::test]
    async fn test_admin_endpoints_require_auth() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/admin/users")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        let api_server = create_test_api_server().await;
        let router = api_server.build_router().await.unwrap();

        let request = Request::builder()
            .uri("/api/v1/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
            Some("DENY")
        );
    }
}
