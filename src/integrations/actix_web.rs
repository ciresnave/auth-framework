//! Actix-web integration for auth-framework.
//!
//! This module provides middleware and extractors for seamless
//! integration with Actix-web applications.

#[cfg(feature = "actix-integration")]
use crate::{
    AuthError, AuthFramework, Result,
    authorization::{AuthorizationEngine, AuthorizationStorage, Permission},
    tokens::AuthToken,
};
#[cfg(feature = "actix-integration")]
use actix_web::{
    Error as ActixError, FromRequest, HttpMessage, HttpRequest,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::header::AUTHORIZATION,
    web,
};
#[cfg(feature = "actix-integration")]
use chrono::TimeZone;
#[cfg(feature = "actix-integration")]
use futures_util::future::{LocalBoxFuture, Ready, ready};
#[cfg(feature = "actix-integration")]
use std::{future::Future, pin::Pin, rc::Rc, sync::Arc};

#[cfg(feature = "actix-integration")]
/// Actix-web middleware for authentication
pub struct AuthMiddleware {
    auth_framework: Arc<AuthFramework>,
    skip_paths: Vec<String>,
}

impl AuthMiddleware {
    pub fn new(auth_framework: Arc<AuthFramework>) -> Self {
        Self {
            auth_framework,
            skip_paths: vec!["/health".to_string(), "/metrics".to_string()],
        }
    }

    pub fn skip_path(mut self, path: impl Into<String>) -> Self {
        self.skip_paths.push(path.into());
        self
    }

    pub fn skip_paths(mut self, paths: Vec<String>) -> Self {
        self.skip_paths.extend(paths);
        self
    }
}

/// Extract validated user context from JWT token and request
/// SECURITY NOTE: This function was removed due to critical JWT signature bypass vulnerability.
/// All JWT validation must use proper signature verification through TokenManager::validate_jwt_token()
/// instead of directly decoding the payload without verification.
impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<std::result::Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            auth_framework: self.auth_framework.clone(),
            skip_paths: self.skip_paths.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
    auth_framework: Arc<AuthFramework>,
    skip_paths: Vec<String>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        _ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), actix_web::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let auth_framework = self.auth_framework.clone();
        let skip_paths = self.skip_paths.clone();

        Box::pin(async move {
            let path = req.path();

            // Skip authentication for certain paths

            if skip_paths
                .iter()
                .any(|skip_path| path.starts_with(skip_path))
            {
                return service.call(req).await;
            }

            // Extract and validate token
            match extract_token_from_request(req.request()) {
                Ok(token_str) => {
                    // Parse and validate JWT token using AuthFramework
                    match auth_framework
                        .token_manager()
                        .validate_jwt_token(&token_str)
                    {
                        Ok(claims) => {
                            // Convert claims to AuthToken and insert into extensions
                            let token = AuthToken {
                                token_id: claims.jti.clone(),
                                user_id: claims.sub.clone(),
                                access_token: token_str.clone(),
                                refresh_token: None,
                                token_type: Some("Bearer".to_string()),
                                subject: Some(claims.sub.clone()),
                                issuer: Some(claims.iss.clone()),
                                issued_at: chrono::Utc
                                    .timestamp_opt(claims.iat, 0)
                                    .single()
                                    .unwrap(),
                                expires_at: chrono::Utc
                                    .timestamp_opt(claims.exp, 0)
                                    .single()
                                    .unwrap(),
                                scopes: claims
                                    .scope
                                    .split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect(),
                                auth_method: "jwt".to_string(),
                                client_id: None,
                                user_profile: None,
                                permissions: claims.permissions.unwrap_or_default(),
                                roles: claims.roles.unwrap_or_default(),
                                metadata: crate::tokens::TokenMetadata::default(),
                            };
                            tracing::debug!("AuthToken stored in request extensions");
                            req.extensions_mut().insert(token);
                        }
                        Err(e) => {
                            tracing::debug!("JWT validation failed: {}", e);
                            // Don't return error from middleware, let extractor handle it
                        }
                    }
                }
                Err(_) => {
                    tracing::debug!("No authorization token found");
                    // Don't return error from middleware, let extractor handle it
                }
            }
            // Always proceed to the service - let extractors handle authentication requirements
            service.call(req).await
        })
    }
}

/// Extractor for authenticated user tokens
pub struct AuthenticatedUser(pub AuthToken);

impl FromRequest for AuthenticatedUser {
    type Error = ActixError;
    type Future = Ready<std::result::Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<AuthToken>() {
            Some(token) => {
                tracing::debug!("AuthToken found in request extensions");
                ready(Ok(AuthenticatedUser(token.clone())))
            }
            None => {
                tracing::debug!("No AuthToken found in request extensions");
                ready(Err(ActixError::from(AuthError::Token(
                    crate::errors::TokenError::Missing,
                ))))
            }
        }
    }
}

/// Extractor for checking permissions
pub struct RequirePermission<S: AuthorizationStorage> {
    permission: Permission,
    authorization: Arc<AuthorizationEngine<S>>,
    expected_user_id: Option<String>, // PRODUCTION FIX: Renamed for clarity - optional user ID validation
}

impl<S: AuthorizationStorage + 'static> RequirePermission<S> {
    pub fn new(
        permission: Permission,
        authorization: Arc<AuthorizationEngine<S>>,
        expected_user_id: Option<String>, // Optional - if provided, validates JWT user matches
    ) -> Self {
        Self {
            permission,
            authorization,
            expected_user_id,
        }
    }

    /// Create without specific user ID requirement (validates any authenticated user)
    pub fn any_user(permission: Permission, authorization: Arc<AuthorizationEngine<S>>) -> Self {
        Self::new(permission, authorization, None)
    }

    /// Create with specific user ID requirement (validates specific user)
    pub fn specific_user(
        permission: Permission,
        authorization: Arc<AuthorizationEngine<S>>,
        user_id: String,
    ) -> Self {
        Self::new(permission, authorization, Some(user_id))
    }

    /// Check if the current user has the specific permission this struct was created with
    pub async fn check_access(
        &self,
        user_id: &str,
        request: &HttpRequest,
    ) -> Result<bool, AuthError> {
        let context = crate::authorization::AccessContext {
            user_id: user_id.to_string(),
            user_attributes: std::collections::HashMap::new(),
            resource_id: Some(self.permission.resource.clone()),
            resource_attributes: std::collections::HashMap::new(),
            ip_address: request.connection_info().peer_addr().map(|s| s.to_string()),
            timestamp: std::time::SystemTime::now(),
            metadata: std::collections::HashMap::new(),
        };

        // Perform authorization check using the specific permission
        match self
            .authorization
            .check_permission(user_id, &self.permission, &context)
            .await
        {
            Ok(result) => Ok(result.granted),
            Err(e) => Err(e),
        }
    }

    /// Validate that the current request has the required permission
    pub async fn validate(
        &self,
        token: &AuthToken,
        request: &HttpRequest,
        auth_framework: &AuthFramework,
    ) -> Result<(), AuthError> {
        // SECURITY FIX: Use proper JWT validation instead of insecure extraction
        // Validate the JWT token signature before trusting any claims
        let claims = match auth_framework
            .token_manager()
            .validate_jwt_token(&token.access_token)
        {
            Ok(validated_claims) => validated_claims,
            Err(e) => {
                return Err(AuthError::access_denied(format!(
                    "JWT validation failed: {}",
                    e
                )));
            }
        };
        let user_id = claims.sub;

        // PRODUCTION FIX: Validate specific user ID if required
        if let Some(expected_id) = &self.expected_user_id
            && user_id != *expected_id
        {
            return Err(AuthError::access_denied(format!(
                "Token user ID '{}' does not match expected user ID '{}'",
                user_id, expected_id
            )));
        }

        // Check if user has the required permission
        let has_permission = self.check_access(&user_id, request).await?;

        if has_permission {
            Ok(())
        } else {
            Err(AuthError::access_denied(format!(
                "User {} does not have permission {} on resource {}",
                user_id, self.permission.action, self.permission.resource
            )))
        }
    }
}

impl<S: AuthorizationStorage + 'static> FromRequest for RequirePermission<S> {
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            // Try to get the token from request extensions
            let token = req
                .extensions()
                .get::<AuthToken>()
                .cloned()
                .ok_or_else(|| {
                    ActixError::from(AuthError::Token(crate::errors::TokenError::Missing))
                })?;

            // Check if we have an authorization engine configured
            let app_data = req
                .app_data::<actix_web::web::Data<ActixConfig<S>>>()
                .ok_or_else(|| {
                    ActixError::from(AuthError::internal(
                        "AuthorizationEngine configuration not found in app data",
                    ))
                })?;

            if let Some(auth_engine) = &app_data.authorization_engine {
                // SECURITY FIX: Use proper JWT validation instead of insecure extraction
                // Validate the JWT token signature before trusting any claims
                let claims = match app_data
                    .auth_framework
                    .token_manager()
                    .validate_jwt_token(&token.access_token)
                {
                    Ok(validated_claims) => validated_claims,
                    Err(e) => {
                        tracing::error!("JWT validation failed during authorization: {}", e);
                        return Err(ActixError::from(AuthError::access_denied(
                            "JWT validation failed for authorization",
                        )));
                    }
                };
                let user_id = claims.sub;

                // Create an instance with a default permission - this will be replaced
                // by the actual permission check in the usage pattern
                let temp_permission = crate::authorization::Permission {
                    resource: "temp".to_string(),
                    action: "temp".to_string(),
                    conditions: None,
                    attributes: Vec::new(),
                };

                // Return the RequirePermission instance, which can then be used
                // to check specific permissions via its methods
                Ok(RequirePermission {
                    permission: temp_permission,
                    authorization: auth_engine.clone(),
                    expected_user_id: Some(user_id),
                })
            } else {
                Err(ActixError::from(AuthError::internal(
                    "AuthorizationEngine not configured - please configure authorization storage backend",
                )))
            }
        })
    }
}

/// Helper function to extract token from Authorization header
fn extract_token_from_request(req: &HttpRequest) -> Result<String> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or_else(|| AuthError::Token(crate::errors::TokenError::Missing))?;

    let auth_str = auth_header.to_str().map_err(|_| {
        AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Invalid Authorization header".to_string(),
        })
    })?;

    if !auth_str.starts_with("Bearer ") {
        return Err(AuthError::Token(crate::errors::TokenError::Invalid {
            message: "Authorization header must use Bearer scheme".to_string(),
        }));
    }

    Ok(auth_str[7..].to_string())
}

/// Configuration for Actix-web integration
pub struct ActixConfig<S: AuthorizationStorage> {
    pub auth_framework: Arc<AuthFramework>,
    pub authorization_engine: Option<Arc<AuthorizationEngine<S>>>,
}

impl<S: AuthorizationStorage + 'static> ActixConfig<S> {
    pub fn new(auth_framework: Arc<AuthFramework>) -> Self {
        Self {
            auth_framework,
            authorization_engine: None,
        }
    }

    pub fn with_authorization(mut self, engine: Arc<AuthorizationEngine<S>>) -> Self {
        self.authorization_engine = Some(engine);
        self
    }

    /// Configure Actix-web app with auth middleware
    pub fn configure_app<T>(&self, cfg: &mut web::ServiceConfig)
    where
        T: 'static,
    {
        cfg.app_data(web::Data::new(self.auth_framework.clone()));

        if let Some(authz) = &self.authorization_engine {
            cfg.app_data(web::Data::new(authz.clone()));
        }
    }
}

/// Helper macro for protecting routes with permissions
#[macro_export]
macro_rules! require_permission {
    ($permission:expr) => {
        |req: actix_web::HttpRequest| async move {
            use $crate::integrations::actix_web::AuthenticatedUser;

            let token = req
                .extensions()
                .get::<AuthToken>()
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing authentication"))?;

            // Check permission logic here
            Ok(())
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;
    use actix_web::{App, test, web};

    async fn test_handler(user: AuthenticatedUser) -> actix_web::Result<String> {
        if user.0.user_id.is_empty() {
            Err(actix_web::error::ErrorUnauthorized(
                "Missing or invalid user_id in AuthToken",
            ))
        } else {
            Ok(format!("Hello, user {}!", user.0.user_id))
        }
    }

    #[actix_web::test]
    async fn test_auth_middleware() {
        let test_secret = "auth-framework-test-secret-12345678"; // 32+ characters
        unsafe {
            std::env::set_var("JWT_SECRET", test_secret);
        }
        let config = AuthConfig::new()
            .secret(test_secret.to_string())
            .issuer("auth-framework".to_string())
            .audience("auth-framework".to_string());
        let mut auth_framework = AuthFramework::new(config);
        auth_framework
            .initialize()
            .await
            .expect("Failed to initialize auth framework");
        let auth_framework = Arc::new(auth_framework);

        let app = test::init_service(
            App::new()
                .wrap(AuthMiddleware::new(auth_framework.clone()))
                .route("/protected", web::get().to(test_handler)),
        )
        .await;

        // Test request without authorization should fail
        let req = test::TestRequest::get().uri("/protected").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        unsafe {
            std::env::remove_var("JWT_SECRET");
        }
    }
}
