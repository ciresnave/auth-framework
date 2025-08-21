# Integration Patterns and Best Practices

## Introduction

This guide provides proven integration patterns, best practices, and architectural recommendations for implementing AuthFramework in production environments. These patterns have been battle-tested across various deployment scenarios and provide secure, scalable, and maintainable authentication solutions.

## Table of Contents

1. [Core Integration Patterns](#core-integration-patterns)
2. [Authentication Flow Patterns](#authentication-flow-patterns)
3. [Session Management Patterns](#session-management-patterns)
4. [Multi-Service Architecture](#multi-service-architecture)
5. [Security Patterns](#security-patterns)
6. [Error Handling Patterns](#error-handling-patterns)
7. [Testing Patterns](#testing-patterns)
8. [Performance Patterns](#performance-patterns)
9. [Monitoring and Observability](#monitoring-and-observability)
10. [Production Deployment Patterns](#production-deployment-patterns)

## Core Integration Patterns

### 1. Middleware Integration Pattern

**Use Case**: Integrate AuthFramework as middleware in web frameworks.

**Implementation**:

```rust
// Axum Integration
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use auth_framework::{AuthClient, TokenValidationResult};

pub async fn auth_middleware<B>(
    State(auth_client): State<AuthClient>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let token = extract_bearer_token(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    match auth_client.validate_token(&token).await {
        Ok(TokenValidationResult::Valid { user_info, .. }) => {
            request.extensions_mut().insert(user_info);
            Ok(next.run(request).await)
        }
        Ok(TokenValidationResult::Invalid { reason }) => {
            tracing::warn!("Token validation failed: {}", reason);
            Err(StatusCode::UNAUTHORIZED)
        }
        Err(e) => {
            tracing::error!("Auth service error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn extract_bearer_token<B>(request: &Request<B>) -> Option<String> {
    request
        .headers()
        .get("authorization")?
        .to_str().ok()?
        .strip_prefix("Bearer ")
        .map(String::from)
}
```

**Best Practices**:

- Always validate tokens on protected routes
- Cache validation results for performance
- Log authentication failures for security monitoring
- Handle auth service unavailability gracefully

### 2. Service Layer Integration Pattern

**Use Case**: Integrate authentication logic into service layer for business logic separation.

**Implementation**:

```rust
use auth_framework::{AuthClient, UserPermissions};
use async_trait::async_trait;

#[async_trait]
pub trait UserService {
    async fn get_user_profile(&self, user_id: &str, requester: &UserContext) -> Result<UserProfile, ServiceError>;
    async fn update_user_profile(&self, user_id: &str, profile: UpdateUserProfile, requester: &UserContext) -> Result<(), ServiceError>;
}

pub struct UserServiceImpl {
    auth_client: AuthClient,
    user_repository: Box<dyn UserRepository>,
}

#[async_trait]
impl UserService for UserServiceImpl {
    async fn get_user_profile(&self, user_id: &str, requester: &UserContext) -> Result<UserProfile, ServiceError> {
        // Check permissions
        let permissions = self.auth_client
            .get_user_permissions(&requester.user_id)
            .await
            .map_err(ServiceError::AuthError)?;

        if !permissions.can_read_user_profile(user_id) {
            return Err(ServiceError::Forbidden);
        }

        // Fetch user profile
        self.user_repository
            .get_profile(user_id)
            .await
            .map_err(ServiceError::DatabaseError)
    }

    async fn update_user_profile(&self, user_id: &str, profile: UpdateUserProfile, requester: &UserContext) -> Result<(), ServiceError> {
        // Check permissions
        let permissions = self.auth_client
            .get_user_permissions(&requester.user_id)
            .await
            .map_err(ServiceError::AuthError)?;

        if !permissions.can_update_user_profile(user_id) {
            return Err(ServiceError::Forbidden);
        }

        // Update profile
        self.user_repository
            .update_profile(user_id, profile)
            .await
            .map_err(ServiceError::DatabaseError)
    }
}
```

### 3. Client Library Pattern

**Use Case**: Create reusable client libraries for different programming languages.

**Rust Client Example**:

```rust
use auth_framework::AuthClient;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuthService {
    client: AuthClient,
    base_url: String,
}

impl AuthService {
    pub fn new(base_url: String, api_key: String) -> Self {
        let client = AuthClient::builder()
            .base_url(&base_url)
            .api_key(&api_key)
            .timeout(Duration::from_secs(30))
            .retry_policy(RetryPolicy::exponential_backoff())
            .build();

        Self { client, base_url }
    }

    pub async fn authenticate(&self, credentials: LoginRequest) -> Result<AuthResponse, AuthError> {
        self.client
            .post("/auth/login")
            .json(&credentials)
            .send()
            .await?
            .json::<AuthResponse>()
            .await
            .map_err(AuthError::from)
    }

    pub async fn validate_token(&self, token: &str) -> Result<TokenInfo, AuthError> {
        self.client
            .get("/auth/validate")
            .bearer_auth(token)
            .send()
            .await?
            .json::<TokenInfo>()
            .await
            .map_err(AuthError::from)
    }
}
```

## Authentication Flow Patterns

### 1. Standard Web Application Flow

**Use Case**: Traditional web applications with session-based authentication.

```rust
use auth_framework::{AuthClient, SessionManager};

pub async fn login_flow(
    auth_client: &AuthClient,
    session_manager: &SessionManager,
    credentials: LoginRequest,
) -> Result<SessionToken, AuthError> {
    // 1. Authenticate user
    let auth_result = auth_client
        .authenticate(credentials)
        .await?;

    // 2. Create session
    let session = session_manager
        .create_session(CreateSessionRequest {
            user_id: auth_result.user_id,
            permissions: auth_result.permissions,
            expires_in: Duration::from_hours(24),
            remember_me: credentials.remember_me,
        })
        .await?;

    // 3. Return session token
    Ok(session.token)
}

pub async fn protected_route_handler(
    session_manager: &SessionManager,
    session_token: String,
) -> Result<UserContext, AuthError> {
    // Validate session
    let session = session_manager
        .validate_session(&session_token)
        .await?;

    // Check if session is still valid
    if session.is_expired() {
        return Err(AuthError::SessionExpired);
    }

    // Update last activity
    session_manager
        .update_activity(&session_token)
        .await?;

    Ok(UserContext {
        user_id: session.user_id,
        permissions: session.permissions,
        session_id: session.id,
    })
}
```

### 2. Single Page Application (SPA) Flow

**Use Case**: JavaScript applications using JWT tokens.

```rust
use auth_framework::{AuthClient, JwtManager};

pub async fn spa_login_flow(
    auth_client: &AuthClient,
    jwt_manager: &JwtManager,
    credentials: LoginRequest,
) -> Result<TokenPair, AuthError> {
    // 1. Authenticate user
    let auth_result = auth_client
        .authenticate(credentials)
        .await?;

    // 2. Generate token pair
    let tokens = jwt_manager
        .generate_token_pair(TokenClaims {
            user_id: auth_result.user_id,
            permissions: auth_result.permissions,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15), // Short-lived access token
        })
        .await?;

    Ok(tokens)
}

pub async fn token_refresh_flow(
    jwt_manager: &JwtManager,
    refresh_token: String,
) -> Result<TokenPair, AuthError> {
    // 1. Validate refresh token
    let claims = jwt_manager
        .validate_refresh_token(&refresh_token)
        .await?;

    // 2. Check if user is still active
    // (Implementation depends on your user management system)

    // 3. Generate new token pair
    let new_tokens = jwt_manager
        .generate_token_pair(TokenClaims {
            user_id: claims.user_id,
            permissions: claims.permissions,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
        })
        .await?;

    // 4. Invalidate old refresh token
    jwt_manager
        .revoke_refresh_token(&refresh_token)
        .await?;

    Ok(new_tokens)
}
```

### 3. Mobile Application Flow

**Use Case**: Mobile applications with secure token storage.

```rust
use auth_framework::{AuthClient, DeviceManager};

pub async fn mobile_login_flow(
    auth_client: &AuthClient,
    device_manager: &DeviceManager,
    credentials: MobileLoginRequest,
) -> Result<MobileAuthResponse, AuthError> {
    // 1. Register/identify device
    let device_info = device_manager
        .register_device(DeviceRegistration {
            device_id: credentials.device_id,
            device_type: credentials.device_type,
            app_version: credentials.app_version,
            os_version: credentials.os_version,
        })
        .await?;

    // 2. Authenticate user
    let auth_result = auth_client
        .authenticate_with_device(credentials.into(), device_info)
        .await?;

    // 3. Generate long-lived tokens for mobile
    let tokens = auth_client
        .generate_mobile_tokens(MobileTokenRequest {
            user_id: auth_result.user_id,
            device_id: device_info.id,
            permissions: auth_result.permissions,
            // Longer expiration for mobile apps
            access_token_ttl: Duration::from_hours(1),
            refresh_token_ttl: Duration::from_days(30),
        })
        .await?;

    Ok(MobileAuthResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user_info: auth_result.user_info,
        device_id: device_info.id,
    })
}
```

## Session Management Patterns

### 1. Distributed Session Pattern

**Use Case**: Multi-server deployments requiring shared session state.

```rust
use auth_framework::{SessionManager, RedisSessionStore};

pub async fn setup_distributed_sessions() -> Result<SessionManager, SetupError> {
    // Configure Redis session store
    let session_store = RedisSessionStore::builder()
        .cluster_urls(vec![
            "redis://redis-1:6379",
            "redis://redis-2:6379",
            "redis://redis-3:6379",
        ])
        .password(std::env::var("REDIS_PASSWORD")?)
        .pool_size(20)
        .timeout(Duration::from_secs(5))
        .build()
        .await?;

    // Configure session manager
    let session_manager = SessionManager::builder()
        .store(session_store)
        .default_ttl(Duration::from_hours(24))
        .cleanup_interval(Duration::from_minutes(30))
        .secure_cookies(true)
        .same_site_policy(SameSite::Strict)
        .build();

    Ok(session_manager)
}

pub async fn session_middleware<B>(
    State(session_manager): State<SessionManager>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // Extract session token from cookie or header
    let session_token = extract_session_token(&request);

    if let Some(token) = session_token {
        match session_manager.get_session(&token).await {
            Ok(Some(session)) => {
                request.extensions_mut().insert(session);
            }
            Ok(None) => {
                // Session not found - expired or invalid
                tracing::debug!("Session not found: {}", token);
            }
            Err(e) => {
                tracing::error!("Session lookup error: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    Ok(next.run(request).await)
}
```

### 2. Stateless JWT Pattern

**Use Case**: Stateless authentication for microservices.

```rust
use auth_framework::{JwtValidator, JwtClaims};

pub async fn jwt_validation_middleware<B>(
    State(jwt_validator): State<JwtValidator>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let token = extract_bearer_token(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    match jwt_validator.validate(&token).await {
        Ok(claims) => {
            // Check token expiration
            if claims.is_expired() {
                return Err(StatusCode::UNAUTHORIZED);
            }

            // Check required permissions for this endpoint
            let required_permissions = get_required_permissions(&request);
            if !claims.has_permissions(&required_permissions) {
                return Err(StatusCode::FORBIDDEN);
            }

            request.extensions_mut().insert(claims);
            Ok(next.run(request).await)
        }
        Err(e) => {
            tracing::warn!("JWT validation failed: {}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn get_required_permissions<B>(request: &Request<B>) -> Vec<Permission> {
    // Extract required permissions based on route
    match request.uri().path() {
        path if path.starts_with("/admin") => vec![Permission::Admin],
        path if path.starts_with("/api/users") => {
            match request.method() {
                &Method::GET => vec![Permission::ReadUsers],
                &Method::POST | &Method::PUT => vec![Permission::WriteUsers],
                &Method::DELETE => vec![Permission::DeleteUsers],
                _ => vec![],
            }
        }
        _ => vec![],
    }
}
```

## Multi-Service Architecture

### 1. API Gateway Pattern

**Use Case**: Centralized authentication for microservices architecture.

```rust
use auth_framework::{AuthClient, GatewayConfig};

pub struct ApiGateway {
    auth_client: AuthClient,
    service_registry: ServiceRegistry,
    rate_limiter: RateLimiter,
}

impl ApiGateway {
    pub async fn handle_request(&self, mut request: Request) -> Result<Response, GatewayError> {
        // 1. Rate limiting
        self.rate_limiter
            .check_rate_limit(&request)
            .await?;

        // 2. Authentication
        let user_context = self.authenticate_request(&request).await?;

        // 3. Authorization
        self.authorize_request(&request, &user_context).await?;

        // 4. Service routing
        let service = self.service_registry
            .find_service(&request.uri().path())?;

        // 5. Add user context to request
        request.headers_mut().insert(
            "X-User-ID",
            HeaderValue::from_str(&user_context.user_id)?,
        );
        request.headers_mut().insert(
            "X-User-Permissions",
            HeaderValue::from_str(&serde_json::to_string(&user_context.permissions)?)?,
        );

        // 6. Forward request
        let response = service.forward_request(request).await?;

        Ok(response)
    }

    async fn authenticate_request(&self, request: &Request) -> Result<UserContext, GatewayError> {
        let token = extract_bearer_token(request)
            .ok_or(GatewayError::Unauthorized)?;

        let validation_result = self.auth_client
            .validate_token(&token)
            .await
            .map_err(GatewayError::AuthServiceError)?;

        match validation_result {
            TokenValidationResult::Valid { user_info, permissions } => {
                Ok(UserContext {
                    user_id: user_info.id,
                    permissions,
                })
            }
            TokenValidationResult::Invalid { reason } => {
                Err(GatewayError::InvalidToken(reason))
            }
        }
    }
}
```

### 2. Service-to-Service Authentication

**Use Case**: Secure communication between microservices.

```rust
use auth_framework::{ServiceAuthClient, ServiceCredentials};

pub struct ServiceClient {
    auth_client: ServiceAuthClient,
    http_client: reqwest::Client,
    service_credentials: ServiceCredentials,
}

impl ServiceClient {
    pub async fn call_service<T, R>(&self, endpoint: &str, request: T) -> Result<R, ServiceError>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        // 1. Get service-to-service token
        let service_token = self.auth_client
            .get_service_token(&self.service_credentials)
            .await?;

        // 2. Make authenticated request
        let response = self.http_client
            .post(endpoint)
            .bearer_auth(service_token.access_token)
            .header("X-Service-ID", &self.service_credentials.service_id)
            .json(&request)
            .send()
            .await?;

        // 3. Handle response
        if response.status().is_success() {
            let result = response.json::<R>().await?;
            Ok(result)
        } else {
            let error = response.json::<ServiceErrorResponse>().await?;
            Err(ServiceError::RemoteServiceError(error))
        }
    }
}

// Service token validation middleware for receiving services
pub async fn service_auth_middleware<B>(
    State(service_auth): State<ServiceAuthValidator>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let token = extract_bearer_token(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let service_id = request
        .headers()
        .get("X-Service-ID")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    match service_auth.validate_service_token(&token, service_id).await {
        Ok(service_context) => {
            request.extensions_mut().insert(service_context);
            Ok(next.run(request).await)
        }
        Err(e) => {
            tracing::warn!("Service authentication failed: {}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
```

## Security Patterns

### 1. Defense in Depth Pattern

**Use Case**: Multiple layers of security validation.

```rust
use auth_framework::{SecurityValidator, ThreatDetection};

pub struct SecurityMiddleware {
    auth_validator: AuthValidator,
    threat_detector: ThreatDetection,
    rate_limiter: RateLimiter,
    request_validator: RequestValidator,
}

impl SecurityMiddleware {
    pub async fn validate_request<B>(&self, request: &Request<B>) -> Result<SecurityContext, SecurityError> {
        // Layer 1: Request validation
        self.request_validator
            .validate_request(request)
            .await?;

        // Layer 2: Rate limiting
        self.rate_limiter
            .check_limits(request)
            .await?;

        // Layer 3: Threat detection
        let threat_score = self.threat_detector
            .analyze_request(request)
            .await?;

        if threat_score > THREAT_THRESHOLD {
            return Err(SecurityError::SuspiciousActivity);
        }

        // Layer 4: Authentication
        let auth_context = self.auth_validator
            .validate_authentication(request)
            .await?;

        // Layer 5: Authorization
        self.validate_permissions(request, &auth_context)
            .await?;

        Ok(SecurityContext {
            auth_context,
            threat_score,
            validated_at: Utc::now(),
        })
    }

    async fn validate_permissions<B>(
        &self,
        request: &Request<B>,
        auth_context: &AuthContext,
    ) -> Result<(), SecurityError> {
        let required_permissions = extract_required_permissions(request);

        for permission in required_permissions {
            if !auth_context.has_permission(&permission) {
                tracing::warn!(
                    "Permission denied: user {} lacks {} for {}",
                    auth_context.user_id,
                    permission,
                    request.uri().path()
                );
                return Err(SecurityError::InsufficientPermissions);
            }
        }

        Ok(())
    }
}
```

### 2. Secure Token Storage Pattern

**Use Case**: Secure storage and rotation of authentication tokens.

```rust
use auth_framework::{TokenStore, EncryptionKey, TokenRotationPolicy};

pub struct SecureTokenManager {
    token_store: TokenStore,
    encryption_key: EncryptionKey,
    rotation_policy: TokenRotationPolicy,
}

impl SecureTokenManager {
    pub async fn store_token(&self, user_id: &str, token: AuthToken) -> Result<TokenHandle, TokenError> {
        // 1. Encrypt token
        let encrypted_token = self.encryption_key
            .encrypt(&token.serialize()?)?;

        // 2. Store with metadata
        let handle = self.token_store
            .store(StoredToken {
                user_id: user_id.to_string(),
                encrypted_data: encrypted_token,
                created_at: Utc::now(),
                expires_at: token.expires_at,
                token_type: token.token_type,
            })
            .await?;

        // 3. Schedule rotation if needed
        if self.rotation_policy.should_schedule_rotation(&token) {
            self.schedule_token_rotation(&handle).await?;
        }

        Ok(handle)
    }

    pub async fn retrieve_token(&self, handle: &TokenHandle) -> Result<AuthToken, TokenError> {
        // 1. Retrieve from store
        let stored_token = self.token_store
            .retrieve(handle)
            .await?
            .ok_or(TokenError::NotFound)?;

        // 2. Check expiration
        if stored_token.is_expired() {
            self.token_store.delete(handle).await?;
            return Err(TokenError::Expired);
        }

        // 3. Decrypt
        let decrypted_data = self.encryption_key
            .decrypt(&stored_token.encrypted_data)?;

        // 4. Deserialize
        let token = AuthToken::deserialize(&decrypted_data)?;

        Ok(token)
    }

    async fn schedule_token_rotation(&self, handle: &TokenHandle) -> Result<(), TokenError> {
        let rotation_time = self.rotation_policy.calculate_rotation_time();

        // Schedule background task for token rotation
        tokio::spawn({
            let handle = handle.clone();
            let token_manager = self.clone();

            async move {
                tokio::time::sleep_until(rotation_time).await;

                if let Err(e) = token_manager.rotate_token(&handle).await {
                    tracing::error!("Token rotation failed: {}", e);
                }
            }
        });

        Ok(())
    }
}
```

## Error Handling Patterns

### 1. Structured Error Response Pattern

**Use Case**: Consistent error handling and response format.

```rust
use auth_framework::{AuthError, ErrorCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorInfo,
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub retry_after: Option<u64>,
}

pub async fn error_handler(err: AuthError) -> impl IntoResponse {
    let (status, error_info) = match err {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            ErrorInfo {
                code: ErrorCode::InvalidCredentials,
                message: "Invalid username or password".to_string(),
                details: None,
                retry_after: None,
            },
        ),
        AuthError::TokenExpired => (
            StatusCode::UNAUTHORIZED,
            ErrorInfo {
                code: ErrorCode::TokenExpired,
                message: "Access token has expired".to_string(),
                details: Some(json!({
                    "suggestion": "Use refresh token to obtain a new access token"
                })),
                retry_after: None,
            },
        ),
        AuthError::RateLimitExceeded { retry_after } => (
            StatusCode::TOO_MANY_REQUESTS,
            ErrorInfo {
                code: ErrorCode::RateLimitExceeded,
                message: "Rate limit exceeded".to_string(),
                details: Some(json!({
                    "suggestion": "Reduce request frequency"
                })),
                retry_after: Some(retry_after.as_secs()),
            },
        ),
        AuthError::InternalError(e) => {
            tracing::error!("Internal auth error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorInfo {
                    code: ErrorCode::InternalError,
                    message: "An internal error occurred".to_string(),
                    details: None,
                    retry_after: Some(5), // Suggest retry after 5 seconds
                },
            )
        }
    };

    let error_response = ErrorResponse {
        error: error_info,
        request_id: generate_request_id(),
        timestamp: Utc::now(),
    };

    (status, Json(error_response))
}
```

### 2. Circuit Breaker Pattern

**Use Case**: Protect against cascading failures when auth service is down.

```rust
use auth_framework::{AuthClient, CircuitBreaker, CircuitState};

pub struct ResilientAuthClient {
    inner: AuthClient,
    circuit_breaker: CircuitBreaker,
    fallback_validator: Option<LocalTokenValidator>,
}

impl ResilientAuthClient {
    pub async fn validate_token(&self, token: &str) -> Result<TokenValidationResult, AuthError> {
        match self.circuit_breaker.state() {
            CircuitState::Closed => {
                // Normal operation
                match self.inner.validate_token(token).await {
                    Ok(result) => {
                        self.circuit_breaker.record_success();
                        Ok(result)
                    }
                    Err(e) if e.is_retriable() => {
                        self.circuit_breaker.record_failure();
                        Err(e)
                    }
                    Err(e) => Err(e),
                }
            }
            CircuitState::Open => {
                // Circuit is open - use fallback
                if let Some(fallback) = &self.fallback_validator {
                    tracing::warn!("Using fallback token validation - auth service unavailable");
                    fallback.validate_token_offline(token).await
                } else {
                    Err(AuthError::ServiceUnavailable)
                }
            }
            CircuitState::HalfOpen => {
                // Test if service is back
                match self.inner.validate_token(token).await {
                    Ok(result) => {
                        self.circuit_breaker.record_success();
                        tracing::info!("Auth service recovered - circuit breaker closed");
                        Ok(result)
                    }
                    Err(e) => {
                        self.circuit_breaker.record_failure();

                        // Fall back if available
                        if let Some(fallback) = &self.fallback_validator {
                            fallback.validate_token_offline(token).await
                        } else {
                            Err(e)
                        }
                    }
                }
            }
        }
    }
}
```

## Testing Patterns

### 1. Integration Testing Pattern

**Use Case**: Test authentication flows end-to-end.

```rust
use auth_framework::{AuthClient, TestAuthServer};
use tokio_test;

#[tokio::test]
async fn test_complete_authentication_flow() {
    // Setup test auth server
    let test_server = TestAuthServer::start().await;
    let auth_client = AuthClient::new(test_server.url());

    // Test user registration
    let user_request = CreateUserRequest {
        username: "testuser@example.com".to_string(),
        password: "secure_password123".to_string(),
        profile: UserProfile {
            first_name: "Test".to_string(),
            last_name: "User".to_string(),
        },
    };

    let user = auth_client
        .create_user(user_request)
        .await
        .expect("User creation should succeed");

    // Test login
    let login_request = LoginRequest {
        username: "testuser@example.com".to_string(),
        password: "secure_password123".to_string(),
        remember_me: false,
    };

    let auth_response = auth_client
        .login(login_request)
        .await
        .expect("Login should succeed");

    assert!(!auth_response.access_token.is_empty());
    assert!(!auth_response.refresh_token.is_empty());

    // Test token validation
    let validation_result = auth_client
        .validate_token(&auth_response.access_token)
        .await
        .expect("Token validation should succeed");

    match validation_result {
        TokenValidationResult::Valid { user_info, .. } => {
            assert_eq!(user_info.id, user.id);
            assert_eq!(user_info.username, "testuser@example.com");
        }
        TokenValidationResult::Invalid { .. } => {
            panic!("Token should be valid");
        }
    }

    // Test token refresh
    let refresh_result = auth_client
        .refresh_token(&auth_response.refresh_token)
        .await
        .expect("Token refresh should succeed");

    assert!(!refresh_result.access_token.is_empty());

    // Test logout
    auth_client
        .logout(&auth_response.access_token)
        .await
        .expect("Logout should succeed");

    // Verify token is invalidated
    let validation_after_logout = auth_client
        .validate_token(&auth_response.access_token)
        .await
        .expect("Validation request should succeed");

    match validation_after_logout {
        TokenValidationResult::Invalid { .. } => {
            // Expected - token should be invalid after logout
        }
        TokenValidationResult::Valid { .. } => {
            panic!("Token should be invalid after logout");
        }
    }
}
```

### 2. Mock Testing Pattern

**Use Case**: Unit testing with mocked auth dependencies.

```rust
use auth_framework::{AuthClient, MockAuthClient};
use mockall::predicate::*;

#[tokio::test]
async fn test_user_service_with_auth() {
    // Setup mock auth client
    let mut mock_auth = MockAuthClient::new();

    mock_auth
        .expect_get_user_permissions()
        .with(eq("user123"))
        .returning(|_| {
            Ok(UserPermissions {
                permissions: vec![Permission::ReadUsers],
            })
        });

    // Setup service with mock
    let user_service = UserServiceImpl::new(
        Arc::new(mock_auth),
        Arc::new(MockUserRepository::new()),
    );

    // Test service method
    let user_context = UserContext {
        user_id: "user123".to_string(),
        permissions: vec![],
    };

    let result = user_service
        .get_user_profile("user456", &user_context)
        .await;

    assert!(result.is_ok());
}
```

## Performance Patterns

### 1. Connection Pooling Pattern

**Use Case**: Optimize database connections for auth operations.

```rust
use auth_framework::{AuthClient, ConnectionPool};
use sqlx::PgPool;

pub struct OptimizedAuthService {
    db_pool: PgPool,
    redis_pool: RedisPool,
    auth_client: AuthClient,
}

impl OptimizedAuthService {
    pub async fn new() -> Result<Self, SetupError> {
        // Database connection pool
        let db_pool = PgPool::connect_with(
            PgConnectOptions::new()
                .host("localhost")
                .port(5432)
                .database("auth_db")
                .username("auth_user")
                .password(&std::env::var("DB_PASSWORD")?)
                .options([
                    ("application_name", "auth_framework"),
                    ("statement_timeout", "30s"),
                ])
        )
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .build()
        .await?;

        // Redis connection pool
        let redis_pool = RedisPool::builder()
            .max_size(15)
            .min_idle(Some(5))
            .connection_timeout(Duration::from_secs(10))
            .idle_timeout(Some(Duration::from_secs(300)))
            .build("redis://localhost:6379")?;

        // Auth client with HTTP connection pool
        let auth_client = AuthClient::builder()
            .base_url("https://auth.internal")
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .timeout(Duration::from_secs(30))
            .build();

        Ok(Self {
            db_pool,
            redis_pool,
            auth_client,
        })
    }

    pub async fn validate_token_with_cache(&self, token: &str) -> Result<TokenValidationResult, AuthError> {
        // Try cache first
        let cache_key = format!("token_validation:{}", blake3::hash(token.as_bytes()));

        if let Ok(Some(cached_result)) = self.get_from_cache(&cache_key).await {
            return Ok(cached_result);
        }

        // Validate with auth service
        let result = self.auth_client
            .validate_token(token)
            .await?;

        // Cache the result
        if matches!(result, TokenValidationResult::Valid { .. }) {
            self.cache_result(&cache_key, &result, Duration::from_secs(300)).await?;
        }

        Ok(result)
    }
}
```

### 2. Caching Pattern

**Use Case**: Cache authentication results for improved performance.

```rust
use auth_framework::{CacheManager, CachePolicy};

pub struct CachedAuthValidator {
    auth_client: AuthClient,
    cache_manager: CacheManager,
    cache_policy: CachePolicy,
}

impl CachedAuthValidator {
    pub async fn validate_token(&self, token: &str) -> Result<TokenValidationResult, AuthError> {
        let cache_key = self.generate_cache_key(token);

        // Check cache first
        if let Some(cached_result) = self.cache_manager.get(&cache_key).await? {
            // Verify cached result is still valid
            if self.is_cache_valid(&cached_result) {
                return Ok(cached_result);
            } else {
                // Remove expired cache entry
                self.cache_manager.remove(&cache_key).await?;
            }
        }

        // Validate with auth service
        let result = self.auth_client.validate_token(token).await?;

        // Cache successful validations
        if let TokenValidationResult::Valid { .. } = &result {
            let ttl = self.cache_policy.calculate_ttl(&result);
            self.cache_manager
                .set(&cache_key, &result, ttl)
                .await?;
        }

        Ok(result)
    }

    fn generate_cache_key(&self, token: &str) -> String {
        // Use hash to avoid storing actual token in cache key
        format!("auth:token:{}", blake3::hash(token.as_bytes()))
    }

    fn is_cache_valid(&self, cached_result: &CachedTokenValidation) -> bool {
        // Check if cached result is still within validity window
        Utc::now() < cached_result.valid_until
    }
}
```

## Monitoring and Observability

### 1. Comprehensive Logging Pattern

**Use Case**: Structured logging for authentication events.

```rust
use auth_framework::{AuthEvent, AuditLogger};
use tracing::{info, warn, error, instrument};

#[derive(Debug)]
pub struct AuthenticationLogger {
    audit_logger: AuditLogger,
}

impl AuthenticationLogger {
    #[instrument(skip(self, credentials), fields(username = %credentials.username))]
    pub async fn log_login_attempt(&self, credentials: &LoginRequest, result: &Result<AuthResponse, AuthError>) {
        match result {
            Ok(auth_response) => {
                info!(
                    user_id = %auth_response.user_id,
                    session_id = %auth_response.session_id,
                    "User login successful"
                );

                // Audit log
                self.audit_logger.log_event(AuthEvent::LoginSuccess {
                    user_id: auth_response.user_id.clone(),
                    session_id: auth_response.session_id.clone(),
                    ip_address: credentials.ip_address.clone(),
                    user_agent: credentials.user_agent.clone(),
                    timestamp: Utc::now(),
                }).await;
            }
            Err(AuthError::InvalidCredentials) => {
                warn!(
                    username = %credentials.username,
                    ip_address = %credentials.ip_address,
                    "Login attempt with invalid credentials"
                );

                // Audit log
                self.audit_logger.log_event(AuthEvent::LoginFailure {
                    username: credentials.username.clone(),
                    reason: "invalid_credentials".to_string(),
                    ip_address: credentials.ip_address.clone(),
                    user_agent: credentials.user_agent.clone(),
                    timestamp: Utc::now(),
                }).await;
            }
            Err(e) => {
                error!(
                    username = %credentials.username,
                    error = %e,
                    "Login attempt failed due to system error"
                );

                // Audit log
                self.audit_logger.log_event(AuthEvent::LoginError {
                    username: credentials.username.clone(),
                    error: e.to_string(),
                    ip_address: credentials.ip_address.clone(),
                    timestamp: Utc::now(),
                }).await;
            }
        }
    }

    #[instrument(skip(self), fields(token_id = %token_info.token_id))]
    pub async fn log_token_validation(&self, token_info: &TokenInfo, result: &TokenValidationResult) {
        match result {
            TokenValidationResult::Valid { user_info, .. } => {
                info!(
                    user_id = %user_info.id,
                    token_id = %token_info.token_id,
                    "Token validation successful"
                );
            }
            TokenValidationResult::Invalid { reason } => {
                warn!(
                    token_id = %token_info.token_id,
                    reason = %reason,
                    "Token validation failed"
                );

                // Audit log for security monitoring
                self.audit_logger.log_event(AuthEvent::InvalidTokenAttempt {
                    token_id: token_info.token_id.clone(),
                    reason: reason.clone(),
                    ip_address: token_info.source_ip.clone(),
                    timestamp: Utc::now(),
                }).await;
            }
        }
    }
}
```

### 2. Metrics Collection Pattern

**Use Case**: Collect authentication metrics for monitoring.

```rust
use auth_framework::{MetricsCollector, AuthMetrics};
use prometheus::{Counter, Histogram, Gauge};

pub struct AuthMetricsCollector {
    login_attempts_total: Counter,
    login_duration: Histogram,
    active_sessions: Gauge,
    token_validations_total: Counter,
    auth_errors_total: Counter,
}

impl AuthMetricsCollector {
    pub fn new() -> Self {
        Self {
            login_attempts_total: Counter::new(
                "auth_login_attempts_total",
                "Total number of login attempts"
            ).unwrap(),
            login_duration: Histogram::new(
                "auth_login_duration_seconds",
                "Duration of login operations"
            ).unwrap(),
            active_sessions: Gauge::new(
                "auth_active_sessions",
                "Number of active user sessions"
            ).unwrap(),
            token_validations_total: Counter::new(
                "auth_token_validations_total",
                "Total number of token validations"
            ).unwrap(),
            auth_errors_total: Counter::new(
                "auth_errors_total",
                "Total number of authentication errors"
            ).unwrap(),
        }
    }

    pub fn record_login_attempt(&self, success: bool) {
        self.login_attempts_total
            .with_label_values(&[if success { "success" } else { "failure" }])
            .inc();
    }

    pub fn record_login_duration(&self, duration: Duration) {
        self.login_duration.observe(duration.as_secs_f64());
    }

    pub fn update_active_sessions(&self, count: i64) {
        self.active_sessions.set(count as f64);
    }

    pub fn record_token_validation(&self, result: &TokenValidationResult) {
        let status = match result {
            TokenValidationResult::Valid { .. } => "valid",
            TokenValidationResult::Invalid { .. } => "invalid",
        };

        self.token_validations_total
            .with_label_values(&[status])
            .inc();
    }

    pub fn record_auth_error(&self, error_type: &str) {
        self.auth_errors_total
            .with_label_values(&[error_type])
            .inc();
    }
}

// Middleware to collect metrics
pub async fn metrics_middleware<B>(
    State(metrics): State<AuthMetricsCollector>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let start_time = Instant::now();

    let response = next.run(request).await;

    let duration = start_time.elapsed();
    let status = response.status();

    // Record metrics based on response
    if status.is_success() {
        metrics.record_login_duration(duration);
    } else {
        metrics.record_auth_error(&status.as_u16().to_string());
    }

    Ok(response)
}
```

## Production Deployment Patterns

### 1. Blue-Green Deployment Pattern

**Use Case**: Zero-downtime deployment of auth service updates.

```rust
use auth_framework::{DeploymentManager, HealthChecker};

pub struct BlueGreenDeployment {
    blue_cluster: ClusterConfig,
    green_cluster: ClusterConfig,
    load_balancer: LoadBalancer,
    health_checker: HealthChecker,
}

impl BlueGreenDeployment {
    pub async fn deploy_new_version(&self, new_version: &str) -> Result<(), DeploymentError> {
        // 1. Determine current active cluster
        let (active_cluster, inactive_cluster) = self.get_cluster_states().await?;

        info!("Starting blue-green deployment of version {}", new_version);
        info!("Active cluster: {}, Inactive cluster: {}", active_cluster.name, inactive_cluster.name);

        // 2. Deploy to inactive cluster
        self.deploy_to_cluster(&inactive_cluster, new_version).await?;

        // 3. Wait for deployment to be ready
        self.wait_for_cluster_ready(&inactive_cluster).await?;

        // 4. Run health checks
        self.run_comprehensive_health_checks(&inactive_cluster).await?;

        // 5. Run smoke tests
        self.run_smoke_tests(&inactive_cluster).await?;

        // 6. Switch traffic gradually
        self.gradual_traffic_switch(&active_cluster, &inactive_cluster).await?;

        // 7. Monitor for issues
        self.monitor_deployment_health(Duration::from_minutes(10)).await?;

        // 8. Complete switch or rollback
        if self.deployment_successful().await? {
            self.complete_traffic_switch(&inactive_cluster).await?;
            info!("Blue-green deployment completed successfully");
        } else {
            self.rollback_deployment(&active_cluster).await?;
            return Err(DeploymentError::HealthCheckFailed);
        }

        Ok(())
    }

    async fn gradual_traffic_switch(
        &self,
        from_cluster: &ClusterConfig,
        to_cluster: &ClusterConfig,
    ) -> Result<(), DeploymentError> {
        let traffic_steps = vec![5, 10, 25, 50, 75, 90];

        for percentage in traffic_steps {
            info!("Switching {}% traffic to new cluster", percentage);

            self.load_balancer
                .update_traffic_distribution(vec![
                    (from_cluster.endpoint.clone(), 100 - percentage),
                    (to_cluster.endpoint.clone(), percentage),
                ])
                .await?;

            // Wait and monitor
            tokio::time::sleep(Duration::from_minutes(2)).await;

            // Check health metrics
            if !self.check_deployment_metrics(percentage).await? {
                return Err(DeploymentError::TrafficSwitchFailed);
            }
        }

        Ok(())
    }

    async fn run_smoke_tests(&self, cluster: &ClusterConfig) -> Result<(), DeploymentError> {
        let test_client = AuthClient::new(&cluster.endpoint);

        // Test 1: Health endpoint
        test_client.health_check().await?;

        // Test 2: Authentication flow
        let test_credentials = self.get_test_credentials();
        let auth_response = test_client.login(test_credentials).await?;

        // Test 3: Token validation
        test_client.validate_token(&auth_response.access_token).await?;

        // Test 4: User management
        let user_info = test_client.get_user_info(&auth_response.access_token).await?;
        assert!(!user_info.id.is_empty());

        info!("Smoke tests passed for cluster {}", cluster.name);
        Ok(())
    }
}
```

### 2. Auto-Scaling Pattern

**Use Case**: Automatically scale auth service based on load.

```rust
use auth_framework::{AutoScaler, MetricsProvider, ScalingPolicy};

pub struct AuthServiceAutoScaler {
    metrics_provider: MetricsProvider,
    scaling_policy: ScalingPolicy,
    cluster_manager: ClusterManager,
}

impl AuthServiceAutoScaler {
    pub async fn monitor_and_scale(&self) -> Result<(), AutoScalerError> {
        loop {
            // Collect current metrics
            let metrics = self.metrics_provider.get_current_metrics().await?;

            // Determine scaling action
            let scaling_decision = self.scaling_policy.evaluate(&metrics);

            match scaling_decision {
                ScalingDecision::ScaleUp { instances } => {
                    info!("Scaling up by {} instances due to high load", instances);
                    self.scale_up(instances).await?;
                }
                ScalingDecision::ScaleDown { instances } => {
                    info!("Scaling down by {} instances due to low load", instances);
                    self.scale_down(instances).await?;
                }
                ScalingDecision::NoAction => {
                    // No scaling needed
                }
            }

            // Wait before next evaluation
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn scale_up(&self, instances: u32) -> Result<(), AutoScalerError> {
        for i in 0..instances {
            // Launch new instance
            let instance = self.cluster_manager
                .launch_instance(InstanceConfig {
                    instance_type: "auth-service".to_string(),
                    image: self.get_current_image_version(),
                    resources: ResourceLimits {
                        cpu: "1000m".to_string(),
                        memory: "2Gi".to_string(),
                    },
                })
                .await?;

            // Wait for instance to be ready
            self.wait_for_instance_ready(&instance).await?;

            // Add to load balancer
            self.cluster_manager
                .add_to_load_balancer(&instance)
                .await?;

            info!("Successfully scaled up instance {}/{}", i + 1, instances);
        }

        Ok(())
    }

    async fn scale_down(&self, instances: u32) -> Result<(), AutoScalerError> {
        // Get instances sorted by age (remove oldest first)
        let candidates = self.cluster_manager
            .get_scalable_instances()
            .await?;

        let to_remove = candidates.into_iter()
            .take(instances as usize)
            .collect::<Vec<_>>();

        for instance in to_remove {
            // Remove from load balancer first
            self.cluster_manager
                .remove_from_load_balancer(&instance)
                .await?;

            // Wait for connections to drain
            self.wait_for_connection_drain(&instance).await?;

            // Terminate instance
            self.cluster_manager
                .terminate_instance(&instance)
                .await?;

            info!("Successfully scaled down instance {}", instance.id);
        }

        Ok(())
    }
}
```

## Conclusion

These integration patterns provide proven approaches for implementing AuthFramework in production environments. Each pattern addresses specific challenges and provides battle-tested solutions for common authentication and authorization scenarios.

### Key Takeaways

1. **Security First**: Always implement multiple layers of security validation
2. **Performance Optimization**: Use caching, connection pooling, and efficient data structures
3. **Resilience**: Implement circuit breakers, retries, and graceful degradation
4. **Observability**: Comprehensive logging, metrics, and monitoring
5. **Testing**: Thorough testing patterns for reliable deployments
6. **Scalability**: Design for horizontal scaling and high availability

### Best Practices Summary

- **Always validate inputs** at every layer
- **Use structured error handling** for consistent API responses
- **Implement comprehensive logging** for security and debugging
- **Cache authentication results** appropriately
- **Design for failure** with circuit breakers and fallbacks
- **Monitor everything** with metrics and alerts
- **Test thoroughly** with integration and load tests
- **Deploy safely** with blue-green or canary deployments

These patterns ensure that AuthFramework integrations are secure, performant, and production-ready.

---

*AuthFramework v0.4.0 - Integration Patterns and Best Practices Guide*
