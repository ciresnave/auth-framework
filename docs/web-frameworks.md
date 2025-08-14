# Web Framework Integration Guide

This guide covers how to integrate auth-framework with popular Rust web frameworks.

## Actix-web Integration

Actix-web is a powerful, pragmatic, and extremely fast web framework for Rust.

### Setup

Add the actix-web feature to your `Cargo.toml`:

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["actix-web"] }
actix-web = "4.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Configuration

```rust
use actix_web::{web, App, HttpServer, Result, HttpResponse};
use auth_framework::{
    AuthFramework, InMemoryStorage,
    config::AuthConfig,
    integrations::actix_web::{AuthMiddleware, AuthenticatedUser, RequirePermission},
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize storage
    let storage = InMemoryStorage::new();
    
    // Create auth configuration
    let config = AuthConfig::builder()
        .jwt_secret("your-secret-key-here".to_string())
        .token_expiry(chrono::Duration::hours(24))
        .build();
    
    // Create auth framework instance
    let auth = AuthFramework::new(storage, config).await.unwrap();
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .wrap(AuthMiddleware::new())
            // Public routes
            .route("/login", web::post().to(login_handler))
            .route("/register", web::post().to(register_handler))
            // Protected routes
            .service(
                web::scope("/api")
                    .route("/profile", web::get().to(get_profile))
                    .route("/admin", web::get().to(admin_only))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Authentication Handlers

```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

async fn login_handler(
    auth: web::Data<AuthFramework<InMemoryStorage>>,
    req: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    match auth.authenticate(&req.username, &req.password).await {
        Ok(token) => {
            let response = LoginResponse {
                access_token: token.access_token,
                refresh_token: token.refresh_token.unwrap_or_default(),
                expires_in: token.expires_at.timestamp(),
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(_) => Ok(HttpResponse::Unauthorized().json("Invalid credentials")),
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    email: String,
}

async fn register_handler(
    auth: web::Data<AuthFramework<InMemoryStorage>>,
    req: web::Json<RegisterRequest>,
) -> Result<HttpResponse> {
    match auth.register_user(&req.username, &req.password).await {
        Ok(credentials) => Ok(HttpResponse::Created().json("User created successfully")),
        Err(e) => Ok(HttpResponse::BadRequest().json(format!("Registration failed: {}", e))),
    }
}
```

### Protected Route Handlers

```rust
// Simple authenticated route
async fn get_profile(user: AuthenticatedUser) -> Result<HttpResponse> {
    let profile = serde_json::json!({
        "user_id": user.user_id,
        "permissions": user.permissions,
        "roles": user.roles,
    });
    Ok(HttpResponse::Ok().json(profile))
}

// Admin-only route using permission guard
async fn admin_only(
    user: AuthenticatedUser,
    _admin: RequirePermission<"admin">,
) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(format!("Welcome, admin {}!", user.user_id)))
}

// Role-based route
async fn moderator_panel(
    user: AuthenticatedUser,
    _mod: RequireRole<"moderator">,
) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json("Moderator panel"))
}
```

### Custom Middleware Configuration

```rust
use auth_framework::integrations::actix_web::{AuthMiddleware, AuthConfig as ActixAuthConfig};

// Custom auth middleware configuration
let auth_config = ActixAuthConfig::builder()
    .skip_paths(vec!["/health", "/metrics", "/static"])
    .require_auth_header(true)
    .custom_header_name("X-Auth-Token")
    .build();

let auth_middleware = AuthMiddleware::with_config(auth_config);

App::new()
    .wrap(auth_middleware)
    // ... routes
```

### Error Handling

```rust
use actix_web::{middleware::ErrorHandlers, http::StatusCode};
use auth_framework::integrations::actix_web::AuthError;

fn create_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .wrap(
            ErrorHandlers::new()
                .handler(StatusCode::UNAUTHORIZED, handle_auth_error)
                .handler(StatusCode::FORBIDDEN, handle_forbidden_error)
        )
        // ... rest of app
}

fn handle_auth_error<B>(res: actix_web::dev::ServiceResponse<B>) -> actix_web::Result<ErrorHandlerResponse<B>> {
    let response = HttpResponse::Unauthorized()
        .json(serde_json::json!({"error": "Authentication required"}));
    Ok(ErrorHandlerResponse::Response(res.into_response(response.into_body())))
}
```

## Warp Integration

Warp is a super-easy, composable, web server framework for building HTTP APIs.

### Setup

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["warp"] }
warp = "0.3"
tokio = { version = "1.0", features = ["full"] }
```

### Basic Configuration

```rust
use warp::Filter;
use auth_framework::{
    AuthFramework, InMemoryStorage,
    config::AuthConfig,
    integrations::warp::{with_auth, require_permission, require_role},
};

#[tokio::main]
async fn main() {
    // Initialize auth framework
    let storage = InMemoryStorage::new();
    let config = AuthConfig::default();
    let auth = AuthFramework::new(storage, config).await.unwrap();
    
    // Create auth filter
    let auth_filter = with_auth(auth.clone());
    
    // Public routes
    let login = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth.clone()))
        .and_then(login_handler);
    
    let register = warp::path("register")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth.clone()))
        .and_then(register_handler);
    
    // Protected routes
    let profile = warp::path("profile")
        .and(warp::get())
        .and(auth_filter.clone())
        .map(|user: AuthenticatedUser| {
            warp::reply::json(&serde_json::json!({
                "user_id": user.user_id,
                "permissions": user.permissions,
            }))
        });
    
    let admin = warp::path("admin")
        .and(warp::get())
        .and(auth_filter.clone())
        .and(require_permission("admin"))
        .map(|user: AuthenticatedUser| {
            format!("Welcome, admin {}!", user.user_id)
        });
    
    let moderator = warp::path("moderator")
        .and(warp::get())
        .and(auth_filter)
        .and(require_role("moderator"))
        .map(|user: AuthenticatedUser| {
            "Moderator panel"
        });
    
    let routes = login
        .or(register)
        .or(profile)
        .or(admin)
        .or(moderator)
        .with(warp::cors().allow_any_origin())
        .recover(handle_rejection);
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
```

### Request Handlers

```rust
async fn login_handler(
    req: LoginRequest,
    auth: AuthFramework<InMemoryStorage>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match auth.authenticate(&req.username, &req.password).await {
        Ok(token) => {
            let response = LoginResponse {
                access_token: token.access_token,
                refresh_token: token.refresh_token.unwrap_or_default(),
                expires_in: token.expires_at.timestamp(),
            };
            Ok(warp::reply::json(&response))
        }
        Err(_) => Err(warp::reject::custom(AuthenticationError)),
    }
}

// Custom rejection types
#[derive(Debug)]
struct AuthenticationError;
impl warp::reject::Reject for AuthenticationError {}

async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    if err.is_not_found() {
        Ok(warp::reply::with_status("Not Found", warp::http::StatusCode::NOT_FOUND))
    } else if let Some(_) = err.find::<AuthenticationError>() {
        Ok(warp::reply::with_status("Unauthorized", warp::http::StatusCode::UNAUTHORIZED))
    } else {
        Ok(warp::reply::with_status("Internal Server Error", warp::http::StatusCode::INTERNAL_SERVER_ERROR))
    }
}
```

## Rocket Integration

Rocket is a web framework for Rust that makes it simple to write fast, secure web applications.

### Setup

```toml
[dependencies]
auth-framework = { version = "0.1.0", features = ["rocket"] }
rocket = { version = "0.5", features = ["json"] }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Configuration

```rust
use rocket::{get, post, launch, routes, serde::json::Json, State};
use auth_framework::{
    AuthFramework, InMemoryStorage,
    config::AuthConfig,
    integrations::rocket::{AuthenticatedUser, RequirePermission, RequireRole, AuthFairing},
};

#[post("/login", data = "<req>")]
async fn login(
    req: Json<LoginRequest>,
    auth: &State<AuthFramework<InMemoryStorage>>,
) -> Result<Json<LoginResponse>, rocket::http::Status> {
    match auth.authenticate(&req.username, &req.password).await {
        Ok(token) => {
            let response = LoginResponse {
                access_token: token.access_token,
                refresh_token: token.refresh_token.unwrap_or_default(),
                expires_in: token.expires_at.timestamp(),
            };
            Ok(Json(response))
        }
        Err(_) => Err(rocket::http::Status::Unauthorized),
    }
}

#[get("/profile")]
fn get_profile(user: AuthenticatedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.user_id,
        "permissions": user.permissions,
        "roles": user.roles,
    }))
}

#[get("/admin")]
fn admin_only(_user: AuthenticatedUser, _admin: RequirePermission<"admin">) -> &'static str {
    "Admin panel"
}

#[get("/moderator")]
fn moderator_only(_user: AuthenticatedUser, _mod: RequireRole<"moderator">) -> &'static str {
    "Moderator panel"
}

#[launch]
async fn rocket() -> _ {
    let storage = InMemoryStorage::new();
    let config = AuthConfig::default();
    let auth = AuthFramework::new(storage, config).await.unwrap();
    
    rocket::build()
        .manage(auth)
        .attach(AuthFairing::default())
        .mount("/", routes![login, get_profile, admin_only, moderator_only])
}
```

### Custom Request Guards

```rust
use rocket::{Request, request::{self, FromRequest}};

// Custom request guard for specific permission levels
pub struct RequireAdminOrModerator;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequireAdminOrModerator {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let user = match AuthenticatedUser::from_request(req).await {
            request::Outcome::Success(user) => user,
            request::Outcome::Failure((status, _)) => return request::Outcome::Failure((status, ())),
            request::Outcome::Forward(_) => return request::Outcome::Forward(()),
        };

        if user.has_permission("admin") || user.has_role("moderator") {
            request::Outcome::Success(RequireAdminOrModerator)
        } else {
            request::Outcome::Failure((rocket::http::Status::Forbidden, ()))
        }
    }
}

#[get("/admin-or-mod")]
fn admin_or_mod_handler(
    _user: AuthenticatedUser,
    _guard: RequireAdminOrModerator,
) -> &'static str {
    "Admin or Moderator access"
}
```

## Common Patterns

### CORS Configuration

```rust
// Actix-web CORS
use actix_cors::Cors;

App::new()
    .wrap(
        Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .max_age(3600)
    )

// Warp CORS
let cors = warp::cors()
    .allow_origin("http://localhost:3000")
    .allow_headers(vec!["authorization", "content-type"])
    .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]);

routes.with(cors)

// Rocket CORS (using rocket_cors crate)
use rocket_cors::{AllowedOrigins, CorsOptions};

let cors = CorsOptions::default()
    .allowed_origins(AllowedOrigins::some_exact(&["http://localhost:3000"]))
    .allowed_methods(vec![Method::Get, Method::Post, Method::Put, Method::Delete].into_iter().map(From::from).collect())
    .allow_credentials(true);

rocket::build().attach(cors.to_cors().unwrap())
```

### Rate Limiting

```rust
// Custom rate limiting middleware for Actix-web
use actix_web::dev::{ServiceRequest, ServiceResponse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    fn is_allowed(&self, client_ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let client_requests = requests.entry(client_ip.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests
        client_requests.retain(|&time| now.duration_since(time) < self.window);
        
        if client_requests.len() < self.max_requests {
            client_requests.push(now);
            true
        } else {
            false
        }
    }
}
```

### Session Management

```rust
// Session-based authentication alongside JWT
use auth_framework::storage::SessionData;

async fn create_session_handler(
    auth: web::Data<AuthFramework<InMemoryStorage>>,
    user: AuthenticatedUser,
) -> Result<HttpResponse> {
    let session_data = SessionData {
        user_id: user.user_id.clone(),
        data: serde_json::json!({"last_login": chrono::Utc::now()}),
        created_at: chrono::Utc::now(),
        last_accessed: chrono::Utc::now(),
    };
    
    let session_id = uuid::Uuid::new_v4().to_string();
    auth.storage.store_session(&session_id, &session_data).await.unwrap();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({"session_id": session_id})))
}
```

### Custom Claims

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
    exp: i64,
    permissions: Vec<String>,
    roles: Vec<String>,
    custom_field: String,
}

// Use custom claims in your handlers
async fn custom_protected_handler(
    req: HttpRequest,
    auth: web::Data<AuthFramework<InMemoryStorage>>,
) -> Result<HttpResponse> {
    let token = extract_token_from_request(&req)?;
    let claims: CustomClaims = auth.verify_custom_token(&token).await?;
    
    if claims.custom_field == "special_value" {
        Ok(HttpResponse::Ok().json("Special access granted"))
    } else {
        Ok(HttpResponse::Forbidden().json("Special access required"))
    }
}
```

## Testing Web Framework Integrations

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    
    #[actix_web::test]
    async fn test_protected_route() {
        let storage = InMemoryStorage::new();
        let config = AuthConfig::default();
        let auth = AuthFramework::new(storage, config).await.unwrap();
        
        // Create test user
        auth.register_user("testuser", "password").await.unwrap();
        let token = auth.authenticate("testuser", "password").await.unwrap();
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth))
                .wrap(AuthMiddleware::new())
                .route("/protected", web::get().to(get_profile))
        ).await;
        
        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", token.access_token)))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
```

This guide covers the essential patterns for integrating auth-framework with popular Rust web frameworks. Each framework has its own idioms and patterns, but the auth-framework provides consistent interfaces that work naturally with each one.
