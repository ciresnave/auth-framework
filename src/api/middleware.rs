//! API Middleware
//!
//! Authentication, authorization, rate limiting, and other middleware

use crate::api::{ApiResponse, ApiState};
use crate::distributed::rate_limiting::RateLimitResult;
use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Sanitize a header value for safe inclusion in log output.
/// Strips control characters (except space) and truncates to 200 chars
/// to prevent log injection and log flooding.
fn sanitize_header_for_log(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(200)
        .collect()
}

/// The address to rate-limit a request under.
///
/// A peer that is not a trusted proxy IS the client: its headers are ignored. A trusted
/// proxy is believed: the client is the rightmost `X-Forwarded-For` entry that is not itself
/// a trusted proxy (the entries to its left were supplied by the client and are ignored),
/// else the proxy's own address (`X-Real-IP` is not consulted: many proxies pass a
/// client-supplied copy through). Every trusted proxy must APPEND to `X-Forwarded-For`
/// rather than pass it through. Anything unparsable falls back to the peer.
pub(crate) fn forwarded_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted_proxies.iter().any(|t| t.to_canonical() == *ip);
    if !is_trusted(&peer) {
        return peer;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    for entry in entries.iter().rev() {
        match parse_forwarded_addr(entry) {
            Some(ip) if is_trusted(&ip) => continue,
            Some(ip) => return ip,
            None => return peer,
        }
    }
    peer
}

/// The rate-limit bucket for an address. IPv6 clients are bucketed by their /64 (the size of
/// a single end-user allocation), so one client cannot mint a bucket per address.
fn rate_limit_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let prefix = std::net::Ipv6Addr::from([
                o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            format!("{prefix}/64")
        }
    }
}

/// Parse one `X-Forwarded-For` entry: a bare address, `addr:port`, or `[v6]` / `[v6]:port`.
fn parse_forwarded_addr(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip.to_canonical());
    }
    if let Ok(sock) = entry.parse::<SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
        .map(|ip| ip.to_canonical())
}

/// Rate limiting middleware backed by [`crate::distributed::rate_limiting::DistributedRateLimiter`].
///
/// Uses the connection's peer address (see [`forwarded_client_ip`]) as the rate-limiting key.  Returns **429 Too Many Requests** when the limit
/// is exceeded and adds standard `X-RateLimit-*` response headers on every response.
// Boxing the Err variant would require `Box<Response>` to implement Axum's
// `IntoResponse`, which it does not by default; both arms are already the
// same `Response` type this middleware pattern requires.
#[allow(clippy::result_large_err)]
pub async fn rate_limit_middleware_with_state(
    state: ApiState,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // The client is identified by the connection's peer address. `X-Forwarded-For` is
    // client-controlled, so it is believed only when the peer is a configured trusted proxy.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let client_key = match peer {
        Some(peer) => rate_limit_key(forwarded_client_ip(
            peer,
            request.headers(),
            &state.trusted_proxies,
        )),
        None => {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "Rate limiter: requests carry no peer address, so all of them share one \
                     bucket. Serve the router with \
                     `into_make_service_with_connect_info::<SocketAddr>()`."
                );
            }
            "unidentified".to_string()
        }
    };

    match state.rate_limiter.check_rate_limit(&client_key).await {
        Ok(RateLimitResult::Allowed {
            remaining,
            reset_at,
        }) => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            let reset_secs = reset_at
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO)
                .as_secs();
            if let Ok(v) = remaining.to_string().parse() {
                headers.insert("X-RateLimit-Remaining", v);
            }
            if let Ok(v) = reset_secs.to_string().parse() {
                headers.insert("X-RateLimit-Reset", v);
            }
            Ok(response)
        }
        Ok(RateLimitResult::Denied { retry_after, .. }) => {
            tracing::warn!(client = %client_key, "Rate limit exceeded");
            let mut response = ApiResponse::<()>::error(
                "RATE_LIMIT_EXCEEDED",
                "Too many requests — please retry after the indicated delay",
            )
            .into_response();
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            let headers = response.headers_mut();
            if let Ok(v) = retry_after.as_secs().to_string().parse() {
                headers.insert("Retry-After", v);
            }
            Err(response)
        }
        Ok(RateLimitResult::Blocked { unblock_at, reason }) => {
            tracing::warn!(client = %client_key, reason = %reason, "Client is blocked");
            let mut response = ApiResponse::<()>::error(
                "CLIENT_BLOCKED",
                "Access temporarily blocked due to repeated rate limit violations",
            )
            .into_response();
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            let unblock_secs = unblock_at
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO)
                .as_secs();
            if let Ok(v) = unblock_secs.to_string().parse() {
                let headers = response.headers_mut();
                headers.insert("Retry-After", v);
            }
            Err(response)
        }
        Err(e) => {
            tracing::error!(error = %e, "Rate limiter error — rejecting request");
            let mut response = ApiResponse::<()>::error(
                "RATE_LIMIT_UNAVAILABLE",
                "Rate limiting is temporarily unavailable; request rejected to protect the service",
            )
            .into_response();
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            Err(response)
        }
    }
}

// cors_middleware was removed: it set `Access-Control-Allow-Origin: *` which is
// inappropriate for an authentication service.  Use tower-http's `CorsLayer`
// with a configured `AllowOrigin` list instead.

/// Log every incoming HTTP request with method, URI, client IP, and user-agent.
///
/// Elapsed time is logged on the response path.
///
/// # Example
/// ```rust,ignore
/// let app = Router::new()
///     .layer(axum::middleware::from_fn(logging_middleware));
/// ```
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    // Extract user agent and IP for logging, sanitized to prevent log injection
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let user_agent = sanitize_header_for_log(user_agent);

    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let forwarded_for = sanitize_header_for_log(forwarded_for);

    tracing::info!(
        "Request started: {} {} from {} ({})",
        method,
        uri,
        forwarded_for,
        user_agent
    );

    let response = next.run(request).await;
    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        "Request completed: {} {} {} in {:?}",
        method,
        uri,
        status,
        duration
    );

    response
}

/// Security headers middleware
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    let mut response = response;
    let headers = response.headers_mut();

    // Security headers — all values are well-known static strings so from_static is safe.
    headers.insert(
        "X-Content-Type-Options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "X-Frame-Options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-XSS-Protection",
        axum::http::HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Strict-Transport-Security",
        axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Referrer-Policy",
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "Permissions-Policy",
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        "Content-Security-Policy",
        axum::http::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );

    response
}

/// Request timeout middleware
// See the allow rationale on `rate_limit_middleware_with_state` above.
#[allow(clippy::result_large_err)]
pub async fn timeout_middleware(request: Request, next: Next) -> Result<Response, Response> {
    // Set a 30-second timeout for all requests
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => {
            let error_response =
                ApiResponse::<()>::error("REQUEST_TIMEOUT", "Request timed out after 30 seconds");
            Err(error_response.into_response())
        }
    }
}

/// Check whether `auth_token` carries the given permission.
///
/// Supports exact matches, a wildcard `"*"`, and prefix wildcards such as
/// `"read:*"` (matches `"read:users"`, `"read:settings"`, etc.).
///
/// # Example
/// ```rust,ignore
/// if check_permission(&token, "users:write") {
///     // allow the operation
/// }
/// ```
pub fn check_permission(auth_token: &crate::tokens::AuthToken, required_permission: &str) -> bool {
    auth_token.permissions.iter().any(|perm| {
        perm == required_permission
            || perm == "*"
            || (perm.ends_with("*") && required_permission.starts_with(&perm[..perm.len() - 1]))
    })
}

/// Check whether `auth_token` carries the given role.
///
/// The `"admin"` role implicitly matches every role.
///
/// # Example
/// ```rust,ignore
/// if check_role(&token, "moderator") {
///     // allow moderation actions
/// }
/// ```
pub fn check_role(auth_token: &crate::tokens::AuthToken, required_role: &str) -> bool {
    auth_token.roles.contains(required_role) || auth_token.roles.contains("admin") // Admin has all roles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{AuthToken, TokenMetadata};

    fn make_token(permissions: Vec<&str>, roles: Vec<&str>) -> AuthToken {
        AuthToken {
            token_id: "tid".into(),
            user_id: "uid".into(),
            access_token: "at".into(),
            token_type: Some("Bearer".into()),
            subject: Some("uid".into()),
            issuer: Some("iss".into()),
            refresh_token: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            scopes: vec![].into(),
            auth_method: "jwt".into(),
            client_id: None,
            user_profile: None,
            permissions: permissions
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
                .into(),
            roles: roles
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
                .into(),
            metadata: TokenMetadata::default(),
        }
    }

    // ── check_permission ────────────────────────────────────────────────

    #[test]
    fn test_check_permission_exact_match() {
        let token = make_token(vec!["users:read"], vec![]);
        assert!(check_permission(&token, "users:read"));
    }

    #[test]
    fn test_check_permission_no_match() {
        let token = make_token(vec!["users:read"], vec![]);
        assert!(!check_permission(&token, "users:write"));
    }

    #[test]
    fn test_check_permission_wildcard_all() {
        let token = make_token(vec!["*"], vec![]);
        assert!(check_permission(&token, "anything:at:all"));
    }

    #[test]
    fn test_check_permission_wildcard_prefix() {
        let token = make_token(vec!["users:*"], vec![]);
        assert!(check_permission(&token, "users:read"));
        assert!(check_permission(&token, "users:write"));
        assert!(!check_permission(&token, "admin:read"));
    }

    #[test]
    fn test_check_permission_empty() {
        let token = make_token(vec![], vec![]);
        assert!(!check_permission(&token, "anything"));
    }

    // ── check_role ──────────────────────────────────────────────────────

    #[test]
    fn test_check_role_exact_match() {
        let token = make_token(vec![], vec!["editor"]);
        assert!(check_role(&token, "editor"));
    }

    #[test]
    fn test_check_role_no_match() {
        let token = make_token(vec![], vec!["editor"]);
        assert!(!check_role(&token, "moderator"));
    }

    #[test]
    fn test_check_role_admin_has_all_roles() {
        let token = make_token(vec![], vec!["admin"]);
        assert!(check_role(&token, "anything"));
        assert!(check_role(&token, "editor"));
    }

    #[test]
    fn test_check_role_empty() {
        let token = make_token(vec![], vec![]);
        assert!(!check_role(&token, "user"));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_slash_64() {
        assert_eq!(rate_limit_key(ip("203.0.113.7")), "203.0.113.7");
        let a = rate_limit_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        let b = rate_limit_key(ip("2001:db8:1:2::1"));
        let c = rate_limit_key(ip("2001:db8:1:3::1"));
        assert_eq!(a, b, "same /64");
        assert_ne!(a, c, "different /64");
    }

    #[test]
    fn forwarded_for_is_ignored_unless_the_peer_is_trusted() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "5.6.7.8")]);
        assert_eq!(forwarded_client_ip(ip("9.9.9.9"), &h, &[]), ip("9.9.9.9"));
        assert_eq!(
            forwarded_client_ip(ip("9.9.9.9"), &h, &[ip("10.0.0.1")]),
            ip("9.9.9.9")
        );
    }

    #[test]
    fn a_trusted_proxy_is_believed_from_the_right() {
        let proxies = [ip("10.0.0.1"), ip("10.0.0.2")];
        // client-supplied "6.6.6.6", then what the proxies appended
        let h = headers(&[("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.0.0.2")]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
            ip("203.0.113.7")
        );
        // several header lines are one list
        let h = headers(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
            ip("203.0.113.7")
        );
        // an IPv4-mapped IPv6 peer is the same proxy
        assert_eq!(
            forwarded_client_ip(ip("::ffff:10.0.0.1"), &h, &proxies),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn unusable_forwarding_headers_fall_back_to_the_proxy_or_real_ip() {
        let proxies = [ip("10.0.0.1")];
        let h = headers(&[("x-forwarded-for", "203.0.113.7, garbage")]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
            ip("10.0.0.1")
        );
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &headers(&[]), &proxies),
            ip("10.0.0.1")
        );
        // X-Real-IP is never consulted, with or without X-Forwarded-For
        let h = headers(&[("x-real-ip", "198.51.100.4")]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
            ip("10.0.0.1")
        );
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "198.51.100.4"),
        ]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
            ip("203.0.113.7")
        );
        // a chain made only of trusted proxies identifies the last proxy
        let h = headers(&[("x-forwarded-for", "10.0.0.2, 10.0.0.1")]);
        assert_eq!(
            forwarded_client_ip(ip("10.0.0.1"), &h, &[ip("10.0.0.1"), ip("10.0.0.2")]),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn forwarded_entries_with_ports_and_brackets_are_understood() {
        let proxies = [ip("10.0.0.1")];
        for (entry, want) in [
            ("203.0.113.7:51234", "203.0.113.7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("[2001:db8::7]:443", "2001:db8::7"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
        ] {
            let h = headers(&[("x-forwarded-for", entry)]);
            assert_eq!(
                forwarded_client_ip(ip("10.0.0.1"), &h, &proxies),
                ip(want),
                "{entry}"
            );
        }
    }
}
