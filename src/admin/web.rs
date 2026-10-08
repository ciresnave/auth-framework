//! Web GUI Interface for Auth Framework Administration

#[cfg(feature = "web-gui")]
use crate::admin::{AppState, HealthStatus};
#[cfg(feature = "web-gui")]
use crate::config::RuntimeConfig;
#[cfg(feature = "web-gui")]
use crate::errors::AuthError;
#[cfg(feature = "web-gui")]
use crate::errors::Result;
#[cfg(feature = "web-gui")]
use askama::Template;
#[cfg(feature = "web-gui")]
use axum::{
    Extension, Form, Router,
    extract::{Query, Request, State},
    http,
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
#[cfg(feature = "web-gui")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "web-gui")]
use std::collections::HashMap;
#[cfg(feature = "web-gui")]
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
#[cfg(feature = "web-gui")]
use zeroize::Zeroizing;

#[cfg(feature = "web-gui")]
const ADMIN_SESSION_TTL_SECONDS: i64 = 30 * 60;
/// Absolute maximum session lifetime (8 hours). Even with continuous sliding
/// window renewals the session is forced to expire after this duration.
#[cfg(feature = "web-gui")]
const ADMIN_SESSION_MAX_LIFETIME_SECONDS: i64 = 8 * 60 * 60;
#[cfg(feature = "web-gui")]
const ADMIN_LOGIN_WINDOW_MINUTES: i64 = 15;
#[cfg(feature = "web-gui")]
const ADMIN_MAX_FAILED_ATTEMPTS: u32 = 5;
#[cfg(feature = "web-gui")]
const ADMIN_LOCKOUT_MINUTES: i64 = 15;

/// Minimal HTML entity escaping to prevent XSS in dynamic HTML responses.
#[cfg(feature = "web-gui")]
fn escape_html(s: &str) -> String {
    html_escape::encode_quoted_attribute(s).to_string()
}

#[cfg(feature = "web-gui")]
pub async fn run_web_gui(
    state: AppState,
    host: &str,
    port: u16,
    daemon: bool,
    enable_auth: bool,
) -> Result<()> {
    tracing::info!("Starting Web GUI on {}:{}", host, port);

    // Warn at startup if admin credentials are not fully configured.
    if std::env::var("ADMIN_GUI_USERNAME").map_or(true, |v| v.is_empty())
        || std::env::var("ADMIN_GUI_PASSWORD").map_or(true, |v| v.is_empty())
    {
        tracing::warn!(
            "Admin GUI credentials are not fully configured. \
             Set both ADMIN_GUI_USERNAME and ADMIN_GUI_PASSWORD environment variables \
             to enable admin login."
        );
    }

    let app = create_web_app(state, host, port, enable_auth).await?;

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;

    if daemon {
        tracing::warn!(
            "The --daemon flag is a no-op. Use OS-level daemonization (systemd, \
             Windows Services, launchd) to run the admin GUI as a background service."
        );
    }

    tracing::info!(
        host = %host,
        port = port,
        "Admin Web GUI started (dashboard: /, config: /config, users: /users, security: /security)"
    );

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(feature = "web-gui")]
async fn create_web_app(
    state: AppState,
    host: &str,
    port: u16,
    enable_auth: bool,
) -> Result<Router, Box<dyn std::error::Error>> {
    // Public routes — no session required.
    let public_routes = Router::new()
        .route("/login", get(login_handler))
        .route("/login", post(login_post_handler))
        .route("/logout", get(logout_handler))
        .nest_service("/static", ServeDir::new("static"));

    // Protected routes — session cookie validated by `require_admin_session`.
    let protected_routes = Router::new()
        .route("/", get(dashboard_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/config", get(config_handler))
        .route("/config/edit", post(config_edit_handler))
        .route("/users", get(users_handler))
        .route("/users/create", post(create_user_handler))
        .route("/users/delete", post(delete_user_handler))
        .route("/security", get(security_handler))
        .route("/servers", get(servers_handler))
        .route("/logs", get(logs_handler))
        .route("/api/status", get(api_status_handler))
        .route("/api/config", get(api_config_handler))
        .route("/api/config", post(api_config_update_handler))
        .route("/api/users", get(api_users_handler))
        .route("/api/security", get(api_security_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_session,
        ));

    // Admin GUI should only be accessed from the same origin it is bound to.
    // Construct the exact allowed origin from the bind address rather than
    // using AllowOrigin::any(), so cross-origin requests from other hosts are
    // rejected by the browser.
    let scheme = if current_runtime_config(&state).await.secure_cookies {
        "https"
    } else {
        "http"
    };
    let gui_origin = http::HeaderValue::from_str(&format!("{scheme}://{host}:{port}"))
        .unwrap_or_else(|error| {
            tracing::warn!(
                %host,
                port,
                %scheme,
                %error,
                "Admin GUI origin was invalid; falling back to http://localhost"
            );
            http::HeaderValue::from_static("http://localhost")
        });
    let cors = CorsLayer::new()
        .allow_origin(gui_origin)
        .allow_methods([http::Method::GET, http::Method::POST])
        .allow_headers([http::header::CONTENT_TYPE]);

    let app = public_routes
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    if !enable_auth {
        tracing::warn!(
            "enable_auth=false is set but has no effect; \
             the admin GUI always enforces session authentication."
        );
    }

    Ok(app)
}

/// Generate a cryptographically random admin GUI session token (64 hex chars = 32 bytes entropy).
#[cfg(feature = "web-gui")]
fn generate_session_token() -> std::result::Result<String, &'static str> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| "System CSPRNG unavailable; cannot generate admin session token")?;
    Ok(bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    }))
}

#[cfg(feature = "web-gui")]
fn extract_session_token(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find(|c| c.trim().starts_with("auth_session="))
                .map(|c| c.trim()["auth_session=".len()..].to_string())
        })
}

#[cfg(feature = "web-gui")]
fn admin_session_cookie(token: &str, secure: bool) -> String {
    if secure {
        format!(
            "auth_session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            token, ADMIN_SESSION_TTL_SECONDS
        )
    } else {
        format!(
            "auth_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
            token, ADMIN_SESSION_TTL_SECONDS
        )
    }
}

#[cfg(feature = "web-gui")]
fn clear_admin_session_cookie(secure: bool) -> String {
    if secure {
        "auth_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
    } else {
        "auth_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
    }
}

#[cfg(feature = "web-gui")]
fn is_admin_login_locked(state: &AppState, username: &str) -> bool {
    let now = chrono::Utc::now();
    let Ok(mut attempts) = state.admin_login_attempts.lock() else {
        return false;
    };

    attempts.retain(|_, record| {
        record
            .locked_until
            .is_some_and(|locked_until| locked_until > now)
            || record.last_failed_at > now - chrono::Duration::minutes(ADMIN_LOGIN_WINDOW_MINUTES)
    });

    attempts
        .get(username)
        .and_then(|record| record.locked_until)
        .is_some_and(|locked_until| locked_until > now)
}

#[cfg(feature = "web-gui")]
fn record_failed_admin_login(state: &AppState, username: &str) {
    let now = chrono::Utc::now();
    let Ok(mut attempts) = state.admin_login_attempts.lock() else {
        return;
    };

    let record = attempts.entry(username.to_string()).or_insert_with(|| {
        crate::admin::AdminLoginAttemptRecord {
            failed_attempts: 0,
            first_failed_at: now,
            last_failed_at: now,
            locked_until: None,
        }
    });

    if record.last_failed_at <= now - chrono::Duration::minutes(ADMIN_LOGIN_WINDOW_MINUTES) {
        record.failed_attempts = 0;
        record.first_failed_at = now;
        record.locked_until = None;
    }

    record.failed_attempts += 1;
    record.last_failed_at = now;
    if record.failed_attempts >= ADMIN_MAX_FAILED_ATTEMPTS {
        record.locked_until = Some(now + chrono::Duration::minutes(ADMIN_LOCKOUT_MINUTES));
    }
}

#[cfg(feature = "web-gui")]
fn clear_failed_admin_logins(state: &AppState, username: &str) {
    if let Ok(mut attempts) = state.admin_login_attempts.lock() {
        attempts.remove(username);
    }
}

/// CSRF token extracted from the authenticated session and injected into
/// request extensions by [`require_admin_session`].
#[cfg(feature = "web-gui")]
#[derive(Clone, Debug)]
struct CsrfToken(String);

/// Axum middleware that enforces admin GUI session authentication.
///
/// Reads the `auth_session` cookie and verifies it against the in-memory
/// `AppState::admin_sessions` set.  Requests without a valid session token
/// are redirected to `/login`.
///
/// On success the session's CSRF token is injected into request extensions
/// so downstream handlers can include it in forms and validate it on POST.
#[cfg(feature = "web-gui")]
async fn require_admin_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let now = chrono::Utc::now();
    let session_csrf = extract_session_token(request.headers())
        .and_then(|token| {
            state
                .admin_sessions
                .lock()
                .ok()
                .and_then(|mut sessions| {
                    sessions.retain(|_, session| session.expires_at > now);
                    sessions.get_mut(&token).and_then(|session| {
                        // Enforce absolute maximum lifetime regardless of activity
                        let age = now - session.created_at;
                        if age.num_seconds() > ADMIN_SESSION_MAX_LIFETIME_SECONDS {
                            tracing::info!(
                                "Admin session for '{}' exceeded absolute max lifetime ({} hours); forcing re-login",
                                session.username,
                                ADMIN_SESSION_MAX_LIFETIME_SECONDS / 3600
                            );
                            return None;
                        }
                        session.last_activity = now;
                        session.expires_at =
                            now + chrono::Duration::seconds(ADMIN_SESSION_TTL_SECONDS);
                        Some(session.csrf_token.clone())
                    })
                })
        });

    match session_csrf {
        Some(csrf) => {
            // CSRF validation for state-changing methods — always enforced.
            if matches!(
                request.method(),
                &http::Method::POST
                    | &http::Method::PUT
                    | &http::Method::DELETE
                    | &http::Method::PATCH
            ) {
                let submitted = extract_csrf_token_from_request(&request);
                if submitted.as_deref() != Some(&csrf) {
                    tracing::warn!(
                        "CSRF token mismatch on {} {}",
                        request.method(),
                        request.uri()
                    );
                    return (
                        axum::http::StatusCode::FORBIDDEN,
                        "CSRF token missing or invalid",
                    )
                        .into_response();
                }
            }

            request.extensions_mut().insert(CsrfToken(csrf));
            next.run(request).await
        }
        None => Redirect::to("/login").into_response(),
    }
}

/// Extract the submitted CSRF token from either the `X-CSRF-Token` header
/// (for API / JS callers) or a `csrf_token` field in the form body.
///
/// SECURITY: CSRF tokens are no longer accepted from URL query parameters
/// because query strings are exposed in Referer headers, browser history,
/// and proxy access logs.
#[cfg(feature = "web-gui")]
fn extract_csrf_token_from_request(request: &Request) -> Option<String> {
    // 1. X-CSRF-Token header (preferred for API calls).
    if let Some(val) = request.headers().get("X-CSRF-Token") {
        if let Ok(s) = val.to_str() {
            return Some(s.to_string());
        }
    }

    // 2. CSRF tokens are NOT extracted from query strings.
    //    Forms must submit the token via the X-CSRF-Token header.
    None
}

// Templates
#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_dashboard.html")]
struct DashboardTemplate {
    server_running: bool,
    user_count: usize,
    active_sessions: u64,
    recent_events: Vec<String>,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_config.html")]
struct ConfigTemplate {
    items: Vec<ConfigItem>,
    live_updates_enabled: bool,
    csrf_token: String,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_users.html")]
struct UsersTemplate {
    user_count: usize,
    users: Vec<User>,
    csrf_token: String,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_security.html")]
struct SecurityTemplate {
    events: Vec<SecurityEvent>,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_servers.html")]
struct ServersTemplate {
    status: ServerStatus,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_logs.html")]
struct LogsTemplate {
    entries: Vec<LogEntry>,
}

#[cfg(feature = "web-gui")]
#[derive(Template)]
#[template(path = "simple_login.html")]
struct LoginTemplate {
    error_message: Option<String>,
}

// Data structures
#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigItem {
    pub key: String,
    pub value: String,
    pub description: String,
    pub editable: bool,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub active: bool,
    pub created: String,
    pub last_login: Option<String>,
    pub roles: Vec<String>,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub user: Option<String>,
    pub ip_address: Option<String>,
    pub details: String,
    pub severity: String,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub web_server_running: bool,
    pub web_server_port: Option<u16>,
    pub health: String,
    pub uptime: String,
    pub active_sessions: u64,
    pub last_config_update: Option<String>,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub network_in: String,
    pub network_out: String,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    pub timestamp: String,
    pub level: String,
    pub component: String,
    pub message: String,
}

#[cfg(feature = "web-gui")]
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: Zeroizing<String>,
}

#[cfg(feature = "web-gui")]
#[derive(Deserialize)]
#[allow(dead_code)] // Fields are read by axum's Form extractor via serde deserialization.
struct ConfigEditForm {
    key: String,
    value: String,
}

#[cfg(feature = "web-gui")]
#[derive(Deserialize)]
#[allow(dead_code)] // Fields are read by axum's Form extractor via serde deserialization.
struct CreateUserForm {
    email: String,
    password: Zeroizing<String>,
    admin: Option<bool>,
}

#[cfg(feature = "web-gui")]
#[derive(Deserialize)]
#[allow(dead_code)]
struct DeleteUserForm {
    user_id: String,
}

#[cfg(feature = "web-gui")]
#[derive(Debug, Default, Deserialize)]
struct RuntimeConfigUpdate {
    token_lifetime_secs: Option<u64>,
    refresh_token_lifetime_secs: Option<u64>,
    enable_multi_factor: Option<bool>,
    rate_limiting_enabled: Option<bool>,
    rate_limit_max_requests: Option<u32>,
    rate_limit_window_secs: Option<u64>,
    rate_limit_burst: Option<u32>,
    min_password_length: Option<usize>,
    require_password_complexity: Option<bool>,
    secure_cookies: Option<bool>,
    csrf_protection: Option<bool>,
    session_timeout_secs: Option<u64>,
    audit_enabled: Option<bool>,
    audit_log_success: Option<bool>,
    audit_log_failures: Option<bool>,
    audit_log_permissions: Option<bool>,
    audit_log_tokens: Option<bool>,
}

#[cfg(feature = "web-gui")]
async fn current_runtime_config(state: &AppState) -> RuntimeConfig {
    if let Some(ref af) = state.auth_framework {
        af.runtime_config().await
    } else {
        let config = state.config.read().await;
        RuntimeConfig::from_auth_config(&config.auth)
    }
}

#[cfg(feature = "web-gui")]
fn config_items_from_runtime_config(config: &RuntimeConfig) -> Vec<ConfigItem> {
    vec![
        ConfigItem {
            key: "token_lifetime_secs".to_string(),
            value: config.token_lifetime_secs.to_string(),
            description: "Access token lifetime in seconds".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "refresh_token_lifetime_secs".to_string(),
            value: config.refresh_token_lifetime_secs.to_string(),
            description: "Refresh token lifetime in seconds".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "enable_multi_factor".to_string(),
            value: config.enable_multi_factor.to_string(),
            description: "Enable or disable MFA globally".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "rate_limiting_enabled".to_string(),
            value: config.rate_limiting_enabled.to_string(),
            description: "Enable request rate limiting".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "rate_limit_max_requests".to_string(),
            value: config.rate_limit_max_requests.to_string(),
            description: "Maximum requests allowed per rate-limit window".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "rate_limit_window_secs".to_string(),
            value: config.rate_limit_window_secs.to_string(),
            description: "Rate-limit window in seconds".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "rate_limit_burst".to_string(),
            value: config.rate_limit_burst.to_string(),
            description: "Rate-limit burst allowance".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "min_password_length".to_string(),
            value: config.min_password_length.to_string(),
            description: "Minimum allowed password length".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "require_password_complexity".to_string(),
            value: config.require_password_complexity.to_string(),
            description: "Require mixed-case, numeric, and symbolic passwords".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "secure_cookies".to_string(),
            value: config.secure_cookies.to_string(),
            description: "Set the Secure flag on session cookies".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "csrf_protection".to_string(),
            value: config.csrf_protection.to_string(),
            description: "Enable CSRF protection".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "session_timeout_secs".to_string(),
            value: config.session_timeout_secs.to_string(),
            description: "Session timeout in seconds".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "audit_enabled".to_string(),
            value: config.audit_enabled.to_string(),
            description: "Enable audit logging".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "audit_log_success".to_string(),
            value: config.audit_log_success.to_string(),
            description: "Record successful authentication events".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "audit_log_failures".to_string(),
            value: config.audit_log_failures.to_string(),
            description: "Record failed authentication events".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "audit_log_permissions".to_string(),
            value: config.audit_log_permissions.to_string(),
            description: "Record authorization checks".to_string(),
            editable: true,
        },
        ConfigItem {
            key: "audit_log_tokens".to_string(),
            value: config.audit_log_tokens.to_string(),
            description: "Record token issuance and revocation events".to_string(),
            editable: true,
        },
    ]
}

#[cfg(feature = "web-gui")]
fn parse_bool_config_value(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(AuthError::config(format!(
            "Expected a boolean value for configuration update, got '{}'",
            value
        ))),
    }
}

#[cfg(feature = "web-gui")]
fn apply_form_config_value(config: &mut RuntimeConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "token_lifetime_secs" => {
            config.token_lifetime_secs = value
                .parse()
                .map_err(|_| AuthError::config("token_lifetime_secs must be an unsigned integer"))?
        }
        "refresh_token_lifetime_secs" => {
            config.refresh_token_lifetime_secs = value.parse().map_err(|_| {
                AuthError::config("refresh_token_lifetime_secs must be an unsigned integer")
            })?
        }
        "enable_multi_factor" => config.enable_multi_factor = parse_bool_config_value(value)?,
        "rate_limiting_enabled" => config.rate_limiting_enabled = parse_bool_config_value(value)?,
        "rate_limit_max_requests" => {
            config.rate_limit_max_requests = value.parse().map_err(|_| {
                AuthError::config("rate_limit_max_requests must be an unsigned integer")
            })?
        }
        "rate_limit_window_secs" => {
            config.rate_limit_window_secs = value.parse().map_err(|_| {
                AuthError::config("rate_limit_window_secs must be an unsigned integer")
            })?
        }
        "rate_limit_burst" => {
            config.rate_limit_burst = value
                .parse()
                .map_err(|_| AuthError::config("rate_limit_burst must be an unsigned integer"))?
        }
        "min_password_length" => {
            config.min_password_length = value
                .parse()
                .map_err(|_| AuthError::config("min_password_length must be an unsigned integer"))?
        }
        "require_password_complexity" => {
            config.require_password_complexity = parse_bool_config_value(value)?
        }
        "secure_cookies" => config.secure_cookies = parse_bool_config_value(value)?,
        "csrf_protection" => {
            // SECURITY: CSRF protection cannot be disabled at runtime.
            // Allowing runtime toggling would let an attacker who gains
            // config-write access silently disable CSRF for all users.
            if !parse_bool_config_value(value)? {
                return Err(AuthError::config(
                    "CSRF protection cannot be disabled at runtime for security reasons",
                ));
            }
        }
        "session_timeout_secs" => {
            config.session_timeout_secs = value.parse().map_err(|_| {
                AuthError::config("session_timeout_secs must be an unsigned integer")
            })?
        }
        "audit_enabled" => config.audit_enabled = parse_bool_config_value(value)?,
        "audit_log_success" => config.audit_log_success = parse_bool_config_value(value)?,
        "audit_log_failures" => config.audit_log_failures = parse_bool_config_value(value)?,
        "audit_log_permissions" => config.audit_log_permissions = parse_bool_config_value(value)?,
        "audit_log_tokens" => config.audit_log_tokens = parse_bool_config_value(value)?,
        _ => {
            return Err(AuthError::config(format!(
                "Unsupported runtime configuration key '{}'",
                key
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "web-gui")]
async fn apply_runtime_config_update(
    state: &AppState,
    update: RuntimeConfigUpdate,
) -> Result<RuntimeConfig> {
    let mut current = current_runtime_config(state).await;

    if let Some(value) = update.token_lifetime_secs {
        current.token_lifetime_secs = value;
    }
    if let Some(value) = update.refresh_token_lifetime_secs {
        current.refresh_token_lifetime_secs = value;
    }
    if let Some(value) = update.enable_multi_factor {
        current.enable_multi_factor = value;
    }
    if let Some(value) = update.rate_limiting_enabled {
        current.rate_limiting_enabled = value;
    }
    if let Some(value) = update.rate_limit_max_requests {
        current.rate_limit_max_requests = value;
    }
    if let Some(value) = update.rate_limit_window_secs {
        current.rate_limit_window_secs = value;
    }
    if let Some(value) = update.rate_limit_burst {
        current.rate_limit_burst = value;
    }
    if let Some(value) = update.min_password_length {
        current.min_password_length = value;
    }
    if let Some(value) = update.require_password_complexity {
        current.require_password_complexity = value;
    }
    if let Some(value) = update.secure_cookies {
        if !value && current.secure_cookies {
            tracing::warn!(
                "SECURITY: secure_cookies is being changed from true to false at runtime. \
                 Session cookies will no longer require HTTPS, increasing exposure to \
                 session hijacking via network sniffing."
            );
        }
        current.secure_cookies = value;
    }
    if let Some(value) = update.csrf_protection {
        // SECURITY: CSRF protection cannot be disabled at runtime.
        if !value {
            return Err(AuthError::config(
                "CSRF protection cannot be disabled at runtime for security reasons",
            ));
        }
    }
    if let Some(value) = update.session_timeout_secs {
        current.session_timeout_secs = value;
    }
    if let Some(value) = update.audit_enabled {
        current.audit_enabled = value;
    }
    if let Some(value) = update.audit_log_success {
        current.audit_log_success = value;
    }
    if let Some(value) = update.audit_log_failures {
        current.audit_log_failures = value;
    }
    if let Some(value) = update.audit_log_permissions {
        current.audit_log_permissions = value;
    }
    if let Some(value) = update.audit_log_tokens {
        current.audit_log_tokens = value;
    }

    let Some(ref af) = state.auth_framework else {
        return Err(AuthError::config(
            "Live runtime configuration updates require an attached AuthFramework instance",
        ));
    };

    let updated = af.update_runtime_config(current).await?;
    let mut status = state.server_status.write().await;
    status.last_config_update = Some(chrono::Utc::now());
    Ok(updated)
}

#[cfg(feature = "web-gui")]
async fn load_user_count(state: &AppState) -> usize {
    if let Some(ref af) = state.auth_framework {
        match af.storage().get_kv("users:index").await {
            Ok(Some(bytes)) => serde_json::from_slice::<Vec<String>>(&bytes)
                .map(|user_ids| user_ids.len())
                .unwrap_or(0),
            _ => 0,
        }
    } else {
        let status = state.server_status.read().await;
        status.active_sessions as usize
    }
}

#[cfg(feature = "web-gui")]
async fn load_active_session_count(state: &AppState) -> u64 {
    if let Some(ref af) = state.auth_framework {
        af.storage()
            .count_active_sessions()
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to query active sessions from storage");
                0
            })
    } else {
        let status = state.server_status.read().await;
        status.active_sessions as u64
    }
}

#[cfg(feature = "web-gui")]
fn security_event_from_log_line(index: usize, log_line: String) -> SecurityEvent {
    let (timestamp, rest) = log_line
        .strip_prefix('[')
        .and_then(|value| value.split_once("] "))
        .unwrap_or(("", log_line.as_str()));
    let event_type = rest.split_whitespace().next().unwrap_or("Unknown");
    let user = rest
        .split("user=")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.to_string());

    SecurityEvent {
        id: format!("evt_{}", index + 1),
        timestamp: timestamp.to_string(),
        event_type: event_type.to_string(),
        user,
        ip_address: None,
        details: rest.to_string(),
        severity: if rest.contains("Denied") || rest.contains("Failure") {
            "warning".to_string()
        } else {
            "info".to_string()
        },
    }
}

#[cfg(feature = "web-gui")]
async fn load_security_events(state: &AppState, limit: usize) -> Vec<SecurityEvent> {
    if let Some(ref af) = state.auth_framework
        && let Ok(logs) = af
            .get_permission_audit_logs(None, None, None, Some(limit))
            .await
    {
        return logs
            .into_iter()
            .enumerate()
            .map(|(index, log_line)| security_event_from_log_line(index, log_line))
            .collect();
    }

    Vec::new()
}

#[cfg(feature = "web-gui")]
async fn load_users(state: &AppState) -> Vec<User> {
    let Some(ref af) = state.auth_framework else {
        return Vec::new();
    };

    let storage = af.storage();
    let user_ids: Vec<String> = match storage.get_kv("users:index").await {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => vec![],
    };

    let mut result = Vec::with_capacity(user_ids.len());
    for user_id in &user_ids {
        let key = format!("user:{}", user_id);
        if let Ok(Some(bytes)) = storage.get_kv(&key).await
            && let Ok(data) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            let username = data["username"].as_str().unwrap_or("").to_string();
            let email = data["email"].as_str().unwrap_or("").to_string();
            let active = data["active"].as_bool().unwrap_or(true);
            let created = data["created_at"].as_str().unwrap_or("").to_string();
            let last_login = data["last_login"].as_str().map(|value| value.to_string());
            let roles: Vec<String> = data["roles"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|value| value.as_str().map(|item| item.to_string()))
                        .collect()
                })
                .unwrap_or_else(|| vec!["user".to_string()]);
            result.push(User {
                id: user_id.clone(),
                username,
                email,
                active,
                created,
                last_login,
                roles: roles,
            });
        }
    }

    result
}

#[cfg(feature = "web-gui")]
async fn load_log_entries(state: &AppState, limit: usize) -> Vec<LogEntry> {
    load_security_events(state, limit)
        .await
        .into_iter()
        .enumerate()
        .map(|(index, event)| LogEntry {
            id: format!("log_{}", index + 1),
            timestamp: event.timestamp,
            level: if event.severity == "warning" {
                "WARN".to_string()
            } else {
                "INFO".to_string()
            },
            component: "audit".to_string(),
            message: event.details,
        })
        .collect()
}

#[cfg(feature = "web-gui")]
async fn load_server_status_view(state: &AppState) -> ServerStatus {
    let server_status = state.server_status.read().await.clone();
    let uptime = crate::admin::format_uptime_since(server_status.started_at, chrono::Utc::now());
    let active_sessions = load_active_session_count(state).await;
    let health = match state.get_health_status().await {
        HealthStatus::Healthy => "healthy".to_string(),
        HealthStatus::Warning(message) => format!("warning: {}", message),
        HealthStatus::Critical(message) => format!("critical: {}", message),
    };

    ServerStatus {
        web_server_running: matches!(
            server_status.web_server_state,
            crate::admin::ServerRunState::Running
        ),
        web_server_port: server_status.web_server_port,
        health,
        uptime,
        active_sessions,
        last_config_update: server_status
            .last_config_update
            .map(|value| value.to_rfc3339()),
    }
}

#[cfg(feature = "web-gui")]
fn login_error_message(error_code: Option<&String>) -> Option<String> {
    match error_code.map(String::as_str) {
        Some("invalid_credentials") => Some("Invalid admin credentials".to_string()),
        Some("not_configured") => {
            Some("Admin credentials are not configured. Set both ADMIN_GUI_USERNAME and ADMIN_GUI_PASSWORD environment variables.".to_string())
        }
        _ => None,
    }
}

// Handlers
#[cfg(feature = "web-gui")]
async fn dashboard_handler(State(state): State<AppState>) -> impl IntoResponse {
    let server_status = state.server_status.read().await.clone();
    let template = DashboardTemplate {
        server_running: matches!(
            server_status.web_server_state,
            crate::admin::ServerRunState::Running
        ),
        user_count: load_user_count(&state).await,
        active_sessions: load_active_session_count(&state).await,
        recent_events: load_security_events(&state, 5)
            .await
            .into_iter()
            .map(|event| event.details)
            .collect(),
    };
    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("dashboard template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn config_handler(
    State(state): State<AppState>,
    Extension(csrf): Extension<CsrfToken>,
) -> impl IntoResponse {
    let runtime_config = current_runtime_config(&state).await;
    let template = ConfigTemplate {
        items: config_items_from_runtime_config(&runtime_config),
        live_updates_enabled: state.auth_framework.is_some(),
        csrf_token: csrf.0,
    };
    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("config template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn config_edit_handler(
    State(state): State<AppState>,
    Form(form): Form<ConfigEditForm>,
) -> impl IntoResponse {
    use axum::http::StatusCode;

    tracing::info!(key = %form.key, "Applying admin GUI runtime configuration edit");

    let mut update = RuntimeConfigUpdate::default();
    match form.key.as_str() {
        "token_lifetime_secs"
        | "refresh_token_lifetime_secs"
        | "enable_multi_factor"
        | "rate_limiting_enabled"
        | "rate_limit_max_requests"
        | "rate_limit_window_secs"
        | "rate_limit_burst"
        | "min_password_length"
        | "require_password_complexity"
        | "secure_cookies"
        | "csrf_protection"
        | "session_timeout_secs"
        | "audit_enabled"
        | "audit_log_success"
        | "audit_log_failures"
        | "audit_log_permissions"
        | "audit_log_tokens" => {
            let mut current = current_runtime_config(&state).await;
            match apply_form_config_value(&mut current, &form.key, &form.value) {
                Ok(()) => {
                    update.token_lifetime_secs = Some(current.token_lifetime_secs);
                    update.refresh_token_lifetime_secs = Some(current.refresh_token_lifetime_secs);
                    update.enable_multi_factor = Some(current.enable_multi_factor);
                    update.rate_limiting_enabled = Some(current.rate_limiting_enabled);
                    update.rate_limit_max_requests = Some(current.rate_limit_max_requests);
                    update.rate_limit_window_secs = Some(current.rate_limit_window_secs);
                    update.rate_limit_burst = Some(current.rate_limit_burst);
                    update.min_password_length = Some(current.min_password_length);
                    update.require_password_complexity = Some(current.require_password_complexity);
                    update.secure_cookies = Some(current.secure_cookies);
                    update.csrf_protection = Some(current.csrf_protection);
                    update.session_timeout_secs = Some(current.session_timeout_secs);
                    update.audit_enabled = Some(current.audit_enabled);
                    update.audit_log_success = Some(current.audit_log_success);
                    update.audit_log_failures = Some(current.audit_log_failures);
                    update.audit_log_permissions = Some(current.audit_log_permissions);
                    update.audit_log_tokens = Some(current.audit_log_tokens);
                }
                Err(error) => {
                    let safe_error = escape_html(&error.to_string());
                    return (
                        StatusCode::BAD_REQUEST,
                        Html(format!(
                            "<html><body>\
                             <h2>Configuration Update Failed</h2>\
                             <p>{safe_error}</p>\
                             <a href='/config'>&#8592; Back to Config</a>\
                             </body></html>"
                        )),
                    );
                }
            }
        }
        _ => {
            let safe_key = escape_html(&form.key);
            return (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<html><body>\
                     <h2>Configuration Update Failed</h2>\
                     <p>Unsupported runtime configuration key: <strong>{safe_key}</strong></p>\
                     <a href='/config'>&#8592; Back to Config</a>\
                     </body></html>"
                )),
            );
        }
    }

    match apply_runtime_config_update(&state, update).await {
        Ok(_) => (
            StatusCode::OK,
            Html(format!(
                "<html><body>\
                 <h2>Configuration Updated</h2>\
                 <p>Applied live runtime update for <strong>{}</strong>.</p>\
                 <a href='/config'>&#8592; Back to Config</a>\
                 </body></html>",
                escape_html(&form.key)
            )),
        ),
        Err(error) => {
            let safe_error = escape_html(&error.to_string());
            (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<html><body>\
                     <h2>Configuration Update Failed</h2>\
                     <p>{safe_error}</p>\
                     <a href='/config'>&#8592; Back to Config</a>\
                     </body></html>"
                )),
            )
        }
    }
}

#[cfg(feature = "web-gui")]
async fn users_handler(
    State(state): State<AppState>,
    Extension(csrf): Extension<CsrfToken>,
) -> impl IntoResponse {
    let users = load_users(&state).await;
    let user_count = users.len();

    let template = UsersTemplate {
        user_count,
        users,
        csrf_token: csrf.0,
    };

    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("users template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn create_user_handler(
    State(state): State<AppState>,
    Form(form): Form<CreateUserForm>,
) -> impl IntoResponse {
    use axum::http::StatusCode;

    let Some(ref af) = state.auth_framework else {
        tracing::warn!(
            email = %form.email,
            "User creation attempted but no AuthFramework instance is wired into AppState."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html(
                "<html><body>\
                 <h2>User Creation Unavailable</h2>\
                 <p>The admin GUI does not have access to the auth storage backend. \
                 Please use the CLI (<code>auth-framework users add</code>) \
                 or the REST API to manage users.</p>\
                 <a href='/users'>&#8592; Back to Users</a>\
                 </body></html>"
                    .to_string(),
            ),
        );
    };

    // Generate a username from the email local part.
    let username = form.email.split('@').next().unwrap_or("user");

    match af
        .register_user(username, &form.email, &form.password)
        .await
    {
        Ok(user_id) => {
            if form.admin.unwrap_or(false)
                && let Err(error) = af
                    .update_user_roles(&user_id, &["user".to_string(), "admin".to_string()])
                    .await
            {
                tracing::error!(user_id = %user_id, error = %error, "Failed to assign admin role to user created via admin GUI");
                let safe_error = escape_html(&error.to_string());
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!(
                        "<html><body>\
                         <h2>User Created With Errors</h2>\
                         <p>The user account was created, but the admin role assignment failed: {safe_error}</p>\
                         <a href='/users'>&#8592; Back to Users</a>\
                         </body></html>"
                    )),
                );
            }

            tracing::info!(user_id = %user_id, email = %form.email, "User created via admin GUI");
            // Escape dynamic values to prevent XSS in the HTML response.
            let safe_email = escape_html(&form.email);
            let safe_id = escape_html(&user_id);
            (
                StatusCode::OK,
                Html(format!(
                    "<html><body>\
                     <h2>User Created</h2>\
                     <p>User <strong>{safe_email}</strong> has been created successfully (ID: {safe_id}).</p>\
                     <a href='/users'>&#8592; Back to Users</a>\
                     </body></html>",
                )),
            )
        }
        Err(e) => {
            tracing::error!(email = %form.email, error = %e, "Failed to create user via admin GUI");
            let safe_err = escape_html(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<html><body>\
                     <h2>User Creation Failed</h2>\
                     <p>Error: {safe_err}</p>\
                     <a href='/users'>&#8592; Back to Users</a>\
                     </body></html>",
                )),
            )
        }
    }
}

#[cfg(feature = "web-gui")]
async fn delete_user_handler(
    State(state): State<AppState>,
    Form(form): Form<DeleteUserForm>,
) -> impl IntoResponse {
    use axum::http::StatusCode;

    let Some(ref af) = state.auth_framework else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html(
                "<html><body>\
                 <h2>User Deletion Unavailable</h2>\
                 <p>The admin GUI does not have access to the auth storage backend.</p>\
                 <a href='/users'>&#8592; Back to Users</a>\
                 </body></html>"
                    .to_string(),
            ),
        );
    };

    let safe_id = escape_html(&form.user_id);

    match af.delete_user_by_id(&form.user_id).await {
        Ok(()) => {
            tracing::info!(user_id = %form.user_id, "User deleted via admin GUI");
            (
                StatusCode::OK,
                Html(format!(
                    "<html><body>\
                     <h2>User Deleted</h2>\
                     <p>User <strong>{safe_id}</strong> has been deleted.</p>\
                     <a href='/users'>&#8592; Back to Users</a>\
                     </body></html>",
                )),
            )
        }
        Err(e) => {
            tracing::error!(user_id = %form.user_id, error = %e, "Failed to delete user via admin GUI");
            let safe_err = escape_html(&e.to_string());
            (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<html><body>\
                     <h2>User Deletion Failed</h2>\
                     <p>Error: {safe_err}</p>\
                     <a href='/users'>&#8592; Back to Users</a>\
                     </body></html>",
                )),
            )
        }
    }
}

#[cfg(feature = "web-gui")]
async fn security_handler(State(state): State<AppState>) -> impl IntoResponse {
    let template = SecurityTemplate {
        events: load_security_events(&state, 20).await,
    };

    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("security template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn servers_handler(State(state): State<AppState>) -> impl IntoResponse {
    let template = ServersTemplate {
        status: load_server_status_view(&state).await,
    };

    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("servers template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn logs_handler(State(state): State<AppState>) -> impl IntoResponse {
    let template = LogsTemplate {
        entries: load_log_entries(&state, 20).await,
    };

    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("logs template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn login_handler(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let template = LoginTemplate {
        error_message: login_error_message(params.get("error")),
    };

    Html(template.render().unwrap_or_else(|e| {
        tracing::error!("login template rendering failed: {e}");
        "<html><body><h1>Internal Server Error</h1></body></html>".to_string()
    }))
}

#[cfg(feature = "web-gui")]
async fn login_post_handler(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if is_admin_login_locked(&state, &form.username) {
        tracing::warn!(username = %form.username, "Admin GUI login rejected due to lockout");
        return Redirect::to("/login?error=invalid_credentials").into_response();
    }

    // Credentials are read from environment variables — no secret is hardcoded.
    // Both ADMIN_GUI_USERNAME and ADMIN_GUI_PASSWORD must be set explicitly;
    // there are no default credentials.
    let expected_username = match std::env::var("ADMIN_GUI_USERNAME") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            tracing::error!(
                "ADMIN_GUI_USERNAME environment variable is not set; \
                 admin GUI login is disabled until both ADMIN_GUI_USERNAME and \
                 ADMIN_GUI_PASSWORD are configured."
            );
            return Redirect::to("/login?error=not_configured").into_response();
        }
    };
    let expected_password = match std::env::var("ADMIN_GUI_PASSWORD") {
        Ok(pw) if !pw.is_empty() => pw,
        _ => {
            tracing::error!(
                "ADMIN_GUI_PASSWORD environment variable is not set; \
                 admin GUI login is disabled until both ADMIN_GUI_USERNAME and \
                 ADMIN_GUI_PASSWORD are configured."
            );
            return Redirect::to("/login?error=not_configured").into_response();
        }
    };
    // SECURITY: Use constant-time comparison to prevent timing oracle attacks.
    // Plain `==` on strings short-circuits on the first differing byte, allowing
    // statistical timing analysis to recover credentials byte-by-byte.
    let username_ok = crate::security::timing_protection::constant_time_string_compare(
        &form.username,
        &expected_username,
    );
    let password_ok = crate::security::timing_protection::constant_time_string_compare(
        &form.password,
        &expected_password,
    );
    if username_ok && password_ok {
        clear_failed_admin_logins(&state, &form.username);

        // Generate a fresh cryptographically random session token and store it
        // in the shared session map so `require_admin_session` can validate it.
        let (token, csrf_token) = match (generate_session_token(), generate_session_token()) {
            (Ok(t), Ok(c)) => (t, c),
            _ => {
                tracing::error!("System CSPRNG failure — cannot create admin session");
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error: token generation failed",
                )
                    .into_response();
            }
        };

        // Session fixation defence: invalidate all previous sessions for this
        // user so that any pre-authentication token (e.g. obtained via XSS or
        // network sniffing) cannot be reused after a successful login.
        if let Ok(mut sessions) = state.admin_sessions.lock() {
            sessions.retain(|_, s| s.username != form.username);

            let now = chrono::Utc::now();
            sessions.insert(
                token.clone(),
                crate::admin::AdminSessionRecord {
                    username: form.username.clone(),
                    created_at: now,
                    expires_at: now + chrono::Duration::seconds(ADMIN_SESSION_TTL_SECONDS),
                    last_activity: now,
                    csrf_token,
                },
            );
        }
        let secure = current_runtime_config(&state).await.secure_cookies;
        let mut response = Redirect::to("/dashboard").into_response();
        if let Ok(v) = admin_session_cookie(&token, secure).parse() {
            response.headers_mut().insert(http::header::SET_COOKIE, v);
        }
        response
    } else {
        record_failed_admin_login(&state, &form.username);
        tracing::warn!(username = %form.username, "Admin GUI login failed");
        Redirect::to("/login?error=invalid_credentials").into_response()
    }
}

#[cfg(feature = "web-gui")]
async fn logout_handler(State(state): State<AppState>, request: Request) -> impl IntoResponse {
    // Remove the session token from the server-side set so it cannot be reused.
    if let Some(token) = extract_session_token(request.headers())
        && let Ok(mut sessions) = state.admin_sessions.lock()
    {
        sessions.remove(&token);
    }
    let secure = current_runtime_config(&state).await.secure_cookies;
    let mut response = Redirect::to("/login").into_response();
    if let Ok(v) = clear_admin_session_cookie(secure).parse() {
        response.headers_mut().insert(http::header::SET_COOKIE, v);
    }
    response
}

// API Handlers
#[cfg(feature = "web-gui")]
async fn api_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let server_status = state.server_status.read().await;
    let health = state.get_health_status().await;
    let uptime = crate::admin::format_uptime_since(server_status.started_at, chrono::Utc::now());
    let active_sessions = load_active_session_count(&state).await;

    let status = serde_json::json!({
        "web_server_running": matches!(server_status.web_server_state, crate::admin::ServerRunState::Running),
        "web_server_port": server_status.web_server_port,
        "health": match health {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Warning(_) => "warning",
            HealthStatus::Critical(_) => "critical",
        },
        "active_sessions": active_sessions,
        "uptime": uptime
    });

    axum::Json(status)
}

#[cfg(feature = "web-gui")]
async fn api_config_handler(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(current_runtime_config(&state).await)
}

#[cfg(feature = "web-gui")]
async fn api_config_update_handler(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    use axum::http::StatusCode;

    let payload_keys: Vec<String> = payload
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    tracing::info!(keys = ?payload_keys, "API config request via admin GUI");

    if payload.as_object().is_some_and(|object| !object.is_empty()) {
        let update: RuntimeConfigUpdate = match serde_json::from_value(payload) {
            Ok(update) => update,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({
                        "success": false,
                        "error": format!("Invalid runtime config update payload: {}", error),
                        "applied": false,
                    })),
                )
                    .into_response();
            }
        };

        return match apply_runtime_config_update(&state, update).await {
            Ok(updated) => (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "success": true,
                    "message": "Runtime configuration updated",
                    "applied": true,
                    "config": updated,
                })),
            )
                .into_response(),
            Err(error) => (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": error.to_string(),
                    "applied": false,
                })),
            )
                .into_response(),
        };
    }

    if let Err(e) = state.reload_config().await {
        tracing::error!("Failed to reload config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to reload config: {}", e),
                "applied": false,
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "success": true,
            "message": "Configuration reloaded from the existing config sources",
            "applied": false,
        })),
    )
        .into_response()
}

#[cfg(feature = "web-gui")]
async fn api_users_handler(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(load_users(&state).await)
}

#[cfg(feature = "web-gui")]
async fn api_security_handler(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(load_security_events(&state, 50).await)
}

#[cfg(all(test, feature = "web-gui"))]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use std::sync::{Arc, Mutex, OnceLock};
    use tower::ServiceExt;

    fn login_env_guard() -> &'static Mutex<()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD.get_or_init(|| Mutex::new(()))
    }

    async fn create_test_state(with_framework: bool) -> AppState {
        let state = AppState::new(crate::config::AuthFrameworkSettings::default()).unwrap();

        let state = if with_framework {
            let mut framework = crate::AuthFramework::new(crate::config::AuthConfig::default());
            framework.initialize().await.unwrap();
            state.with_auth_framework(Arc::new(framework))
        } else {
            state
        };

        state
            .update_server_status(crate::admin::ServerRunState::Running, Some(3000))
            .await;
        state
    }

    fn insert_admin_session(state: &AppState) -> String {
        let token = "test-admin-session".to_string();
        let now = chrono::Utc::now();
        state.admin_sessions.lock().unwrap().insert(
            token.clone(),
            crate::admin::AdminSessionRecord {
                username: "admin".to_string(),
                created_at: now,
                expires_at: now + chrono::Duration::minutes(30),
                last_activity: now,
                csrf_token: "test-csrf-token".to_string(),
            },
        );
        token
    }

    async fn response_body_string(response: axum::response::Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn test_escape_html_special_chars() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
    }

    #[test]
    fn test_escape_html_empty_string() {
        assert_eq!(escape_html(""), "");
    }

    #[test]
    fn test_escape_html_no_special_chars() {
        assert_eq!(escape_html("hello world"), "hello world");
    }

    #[test]
    fn test_escape_html_xss_payload() {
        let input = "<img src=x onerror='alert(1)'>";
        let escaped = escape_html(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('\''));
    }

    #[tokio::test]
    async fn test_login_success_sets_admin_cookie() {
        let _guard = login_env_guard().lock().unwrap();
        // SAFETY: `_guard` holds `login_env_guard()`'s lock for this test's
        // duration, serializing these env-var mutations against every other
        // test that touches ADMIN_GUI_USERNAME/ADMIN_GUI_PASSWORD.
        unsafe {
            std::env::set_var("ADMIN_GUI_USERNAME", "admin-user");
            std::env::set_var("ADMIN_GUI_PASSWORD", "super-secret-password");
        }

        let state = create_test_state(false).await;
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(
                        "username=admin-user&password=super-secret-password",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response.headers().get(http::header::SET_COOKIE).unwrap();
        assert!(cookie.to_str().unwrap().contains("auth_session="));
    }

    #[tokio::test]
    async fn test_protected_routes_require_admin_session() {
        let state = create_test_state(false).await;
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "/login"
        );
    }

    #[tokio::test]
    async fn test_protected_html_routes_render_with_live_data() {
        let state = create_test_state(true).await;
        if let Some(ref af) = state.auth_framework {
            let _ = af
                .register_user("alice", "alice@example.com", "Password123!")
                .await
                .unwrap();
        }
        let session_token = insert_admin_session(&state);
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        for path in [
            "/",
            "/dashboard",
            "/config",
            "/users",
            "/security",
            "/servers",
            "/logs",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(
                            http::header::COOKIE,
                            format!("auth_session={session_token}"),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "route {path} failed");
        }
    }

    #[tokio::test]
    async fn test_dashboard_uses_real_user_count() {
        let state = create_test_state(true).await;
        if let Some(ref af) = state.auth_framework {
            af.register_user("alice", "alice@example.com", "Password123!")
                .await
                .unwrap();
        }
        let session_token = insert_admin_session(&state);
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .header(
                        http::header::COOKIE,
                        format!("auth_session={session_token}"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response_body_string(response).await;
        assert!(
            body.contains(">1<"),
            "dashboard should show user count of 1"
        );
        assert!(body.contains("Total Users"));
    }

    #[tokio::test]
    async fn test_config_edit_updates_runtime_config() {
        let state = create_test_state(true).await;
        let session_token = insert_admin_session(&state);
        let framework = state.auth_framework.as_ref().unwrap().clone();
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/config/edit")
                    .header(
                        http::header::COOKIE,
                        format!("auth_session={session_token}"),
                    )
                    .header("X-CSRF-Token", "test-csrf-token")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from("key=min_password_length&value=16"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(framework.runtime_config().await.min_password_length, 16);
    }

    #[tokio::test]
    async fn test_create_user_route_can_assign_admin_role() {
        let state = create_test_state(true).await;
        let session_token = insert_admin_session(&state);
        let framework = state.auth_framework.as_ref().unwrap().clone();
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/users/create")
                    .header(
                        http::header::COOKIE,
                        format!("auth_session={session_token}"),
                    )
                    .header("X-CSRF-Token", "test-csrf-token")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(
                        "email=bob%40example.com&password=Password123!&admin=true",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let verification_state = AppState::new(crate::config::AuthFrameworkSettings::default())
            .unwrap()
            .with_auth_framework(framework.clone());
        let users = load_users(&verification_state).await;
        assert!(users.iter().any(|user| {
            user.email == "bob@example.com" && user.roles.iter().any(|role| role == "admin")
        }));
    }

    #[tokio::test]
    async fn test_admin_api_routes_return_real_data() {
        let state = create_test_state(true).await;
        if let Some(ref af) = state.auth_framework {
            af.register_user("carol", "carol@example.com", "Password123!")
                .await
                .unwrap();
        }
        let session_token = insert_admin_session(&state);
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        for path in ["/api/status", "/api/config", "/api/users", "/api/security"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(
                            http::header::COOKIE,
                            format!("auth_session={session_token}"),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK, "route {path} failed");
        }
    }

    #[tokio::test]
    async fn test_api_config_update_applies_runtime_changes() {
        let state = create_test_state(true).await;
        let session_token = insert_admin_session(&state);
        let framework = state.auth_framework.as_ref().unwrap().clone();
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/config")
                    .header(
                        http::header::COOKIE,
                        format!("auth_session={session_token}"),
                    )
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header("X-CSRF-Token", "test-csrf-token")
                    .body(Body::from(r#"{"min_password_length":18}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(framework.runtime_config().await.min_password_length, 18);
    }

    #[tokio::test]
    async fn test_logout_clears_cookie() {
        let state = create_test_state(false).await;
        let session_token = insert_admin_session(&state);
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/logout")
                    .header(
                        http::header::COOKIE,
                        format!("auth_session={session_token}"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response
                .headers()
                .get(http::header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
    }

    #[tokio::test]
    async fn test_admin_session_absolute_expiry_blocks_old_sessions() {
        let state = create_test_state(false).await;
        // Insert a session that was created well beyond the absolute max lifetime
        let token = "old-session".to_string();
        let now = chrono::Utc::now();
        state.admin_sessions.lock().unwrap().insert(
            token.clone(),
            crate::admin::AdminSessionRecord {
                username: "admin".to_string(),
                // Created 9 hours ago — exceeds the 8-hour absolute max
                created_at: now - chrono::Duration::hours(9),
                expires_at: now + chrono::Duration::minutes(30),
                last_activity: now - chrono::Duration::seconds(5),
                csrf_token: "csrf".to_string(),
            },
        );

        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .header(http::header::COOKIE, format!("auth_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should redirect to /login because the absolute lifetime is exceeded
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "/login"
        );
    }

    #[tokio::test]
    async fn test_admin_session_within_lifetime_allowed() {
        let state = create_test_state(false).await;
        let token = "fresh-session".to_string();
        let now = chrono::Utc::now();
        state.admin_sessions.lock().unwrap().insert(
            token.clone(),
            crate::admin::AdminSessionRecord {
                username: "admin".to_string(),
                // Created 1 hour ago — well within the 8-hour limit
                created_at: now - chrono::Duration::hours(1),
                expires_at: now + chrono::Duration::minutes(30),
                last_activity: now - chrono::Duration::seconds(5),
                csrf_token: "csrf".to_string(),
            },
        );

        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .header(http::header::COOKIE, format!("auth_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be allowed (200 OK, not a redirect)
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ---- Rendered-output golden test for the admin web GUI templates ----
    //
    // `test_protected_html_routes_render_with_live_data` only asserts HTTP 200, and the
    // handlers answer 200 with an "Internal Server Error" body when an askama template
    // fails to render, so nothing else here pins the rendered HTML. This test renders every
    // page through the real router and compares it with a stored golden file.
    //
    // Regenerate after an intentional template change (review the diff before committing):
    //   ADMIN_GOLDEN_UPDATE=1 cargo test --lib --features web-gui admin::web::tests::admin_pages_match_golden
    // Golden files are written by this test, never hand-edited.

    fn golden_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/admin_pages")
    }

    /// Make a rendered page comparable across runs and platforms: line endings (template
    /// files are checked out CRLF on Windows), the users page's created-at timestamp, the
    /// random user id, and the servers page's uptime (wall-clock dependent).
    fn normalise_admin_html(html: &str) -> String {
        let html = html.replace("\r\n", "\n");
        let timestamp =
            regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)").unwrap();
        let html = timestamp.replace_all(&html, "<TIMESTAMP>");
        let user_id = regex::Regex::new(r"user_[A-Za-z0-9]{16}").unwrap();
        let html = user_id.replace_all(&html, "<USER_ID>");
        let uptime = regex::Regex::new(
            r#"(<div class="stat-value">)[^<]*(</div>\s*<div class="stat-label">Uptime)"#,
        )
        .unwrap();
        uptime.replace_all(&html, "${1}<UPTIME>${2}").into_owned()
    }

    #[test]
    fn normalise_admin_html_masks_only_the_volatile_parts() {
        // Control for the normaliser itself: it must mask exactly these and nothing else.
        let raw = "<td>2026-10-04T05:46:03.062014900+00:00</td>\r\n\
                   <input name=\"user_id\" value=\"user_y8cPBJ443aQBIVP5\">\r\n\
                   <div class=\"stat-value\">3h 2m</div>\r\n\
                   <div class=\"stat-label\">Uptime</div>\r\n\
                   <div class=\"stat-value\">0</div>\r\n\
                   <div class=\"stat-label\">Sessions</div>\r\n\
                   <p>user_id label stays, 2026 stays</p>";
        let expected = "<td><TIMESTAMP></td>\n\
                        <input name=\"user_id\" value=\"<USER_ID>\">\n\
                        <div class=\"stat-value\"><UPTIME></div>\n\
                        <div class=\"stat-label\">Uptime</div>\n\
                        <div class=\"stat-value\">0</div>\n\
                        <div class=\"stat-label\">Sessions</div>\n\
                        <p>user_id label stays, 2026 stays</p>";
        assert_eq!(normalise_admin_html(raw), expected);
    }

    #[tokio::test]
    async fn admin_pages_match_golden() {
        let state = create_test_state(true).await;
        let af = state.auth_framework.clone().expect("framework attached");
        af.register_user("alice", "alice@example.com", "Password123!")
            .await
            .unwrap();
        let session_token = insert_admin_session(&state);
        let app = create_web_app(state, "127.0.0.1", 9090, true)
            .await
            .unwrap();

        let update = std::env::var("ADMIN_GOLDEN_UPDATE").is_ok_and(|v| v == "1");
        let pages = [
            ("dashboard", "/"),
            ("config", "/config"),
            ("users", "/users"),
            ("security", "/security"),
            ("servers", "/servers"),
            ("logs", "/logs"),
            ("login", "/login"),
        ];
        for (name, path) in pages {
            let mut request = Request::builder().uri(path);
            if name != "login" {
                request = request.header(
                    http::header::COOKIE,
                    format!("auth_session={session_token}"),
                );
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {path} failed");
            let body = normalise_admin_html(&response_body_string(response).await);

            // The handlers return this fallback body (with status 200) when a template
            // fails to render.
            assert!(
                !body.contains("Internal Server Error"),
                "{name}: template render failed"
            );
            if name == "users" {
                // Control: the page really lists live data, so a golden of an empty or
                // wrong page cannot pass.
                assert!(
                    body.contains("alice"),
                    "users page does not list the registered user"
                );
            }

            let golden = golden_dir().join(format!("{name}.html"));
            if update {
                std::fs::create_dir_all(golden_dir()).unwrap();
                std::fs::write(&golden, &body).unwrap();
                continue;
            }
            let expected = std::fs::read_to_string(&golden)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: {e}; regenerate with ADMIN_GOLDEN_UPDATE=1",
                        golden.display()
                    )
                })
                .replace("\r\n", "\n");
            assert_eq!(
                body,
                expected,
                "{name} page differs from {}; if intentional, regenerate with ADMIN_GOLDEN_UPDATE=1",
                golden.display()
            );
        }
    }
}
