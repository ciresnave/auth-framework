// SPDX-License-Identifier: MIT OR Apache-2.0
//! Axum Web Server with AuthFramework Integration
//!
//! Demonstrates the first-class Axum integration included in the default
//! `auth-framework` build.  Key patterns shown:
//!
//! - `AuthenticatedUser` extractor — validates the `Authorization: Bearer`
//!   header automatically; use it as a handler parameter and it just works.
//! - Grouped accessor pattern (`auth.users()`, `auth.tokens()`,
//!   `auth.authorization()`) for all framework operations.
//! - Shared `Arc<AuthFramework>` state via `axum::extract::State`.
//!
//! Run with in-memory storage (development):
//! ```bash
//! JWT_SECRET="replace-with-a-32-char-random-secret!!" \
//!   cargo run --example axum_integration
//! ```
//!
//! Run with PostgreSQL (production-like):
//! ```bash
//! JWT_SECRET="replace-with-a-32-char-random-secret!!" \
//! DATABASE_URL="postgres://user:pass@localhost/authdb" \
//!   cargo run --example axum_integration
//! ```
//!
//! Then try:
//! ```bash
//! # Register
//! curl -s -X POST http://127.0.0.1:3000/register \
//!      -H "Content-Type: application/json" \
//!      -d '{"username":"alice","email":"alice@example.com","password":"s3cr3t!"}'
//!
//! # Login
//! TOKEN=$(curl -s -X POST http://127.0.0.1:3000/login \
//!      -H "Content-Type: application/json" \
//!      -d '{"username":"alice","password":"s3cr3t!"}' | jq -r .access_token)
//!
//! # Access protected route
//! curl -s http://127.0.0.1:3000/profile -H "Authorization: Bearer $TOKEN"
//! ```

use auth_framework::{integrations::axum::AuthenticatedUser, prelude::*};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

type AppState = Arc<AuthFramework>;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    user_id: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("auth_framework=info,axum_integration=debug")
        .init();

    let config = AuthConfig::new()
        .token_lifetime(std::time::Duration::from_secs(3_600))
        .secret(
            std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "replace-with-a-32-char-random-secret!!".to_string()),
        );

    // Use PostgreSQL when DATABASE_URL is provided, otherwise fall back to
    // in-memory storage for local development and testing.
    let config = if let Ok(db_url) = std::env::var("DATABASE_URL") {
        println!("Using PostgreSQL storage: {db_url}");
        config.storage(StorageConfig::Postgres {
            connection_string: db_url,
            table_prefix: "auth_".to_string(),
        })
    } else {
        println!("DATABASE_URL not set — using in-memory storage (development only)");
        config
    };

    let mut framework = AuthFramework::new(config);
    framework.initialize().await?;

    let state: AppState = Arc::new(framework);

    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        // All routes below require a valid Bearer token
        .route("/profile", get(profile_handler))
        .route("/admin", get(admin_handler))
        .route("/logout", post(logout_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Register a new user.
async fn register_handler(
    State(auth): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    match auth
        .users()
        .register(&req.username, &req.email, &req.password)
        .await
    {
        Ok(user_id) => (StatusCode::CREATED, Json(json!({ "user_id": user_id }))).into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Authenticate and return a JWT.
async fn login_handler(
    State(auth): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Verify password against stored credentials.
    let user_id = match auth.users().get_by_username(&req.username).await {
        Ok(u) => u
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid credentials" })),
            )
                .into_response();
        }
    };

    let password_ok = auth
        .users()
        .verify_password(&user_id, &req.password)
        .await
        .unwrap_or(false);

    if !password_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid credentials" })),
        )
            .into_response();
    }

    match auth
        .tokens()
        .create(&user_id, &["read", "write"], "jwt", None)
        .await
    {
        Ok(token) => {
            let expires_in = token
                .expires_at
                .signed_duration_since(token.issued_at)
                .num_seconds()
                .unsigned_abs();
            (
                StatusCode::OK,
                Json(LoginResponse {
                    access_token: token.access_token,
                    token_type: "Bearer",
                    expires_in,
                    user_id: token.user_id,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Return the authenticated user's profile.
/// `AuthenticatedUser` validates the Bearer token automatically.
async fn profile_handler(user: AuthenticatedUser) -> impl IntoResponse {
    Json(json!({
        "user_id":     user.user_id,
        "roles":       user.roles,
        "permissions": user.permissions,
    }))
}

/// Admin-only endpoint: checks for the "admin" role in the verified token.
async fn admin_handler(State(auth): State<AppState>, user: AuthenticatedUser) -> impl IntoResponse {
    if !user.roles.contains(&"admin".to_string()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "admin role required" })),
        )
            .into_response();
    }

    match auth.monitoring().health_check().await {
        Ok(components) => {
            let all_healthy = components
                .values()
                .all(|c| matches!(c.status, HealthStatus::Healthy));
            let summary: std::collections::HashMap<_, _> = components
                .iter()
                .map(|(k, v)| (k.as_str(), v.message.as_str()))
                .collect();
            Json(json!({ "healthy": all_healthy, "components": summary })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Revoke the current token (logout).
async fn logout_handler(
    State(auth): State<AppState>,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    match auth.tokens().revoke(&user.token).await {
        Ok(()) => Json(json!({ "message": "logged out" })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
