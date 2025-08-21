//! Request Validation Middleware
//!
//! Provides comprehensive request validation and sanitization

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

/// Security headers to validate
const REQUIRED_SECURITY_HEADERS: &[&str] = &["user-agent", "accept"];

const SUSPICIOUS_PATTERNS: &[&str] = &[
    "<script",
    "javascript:",
    "onload=",
    "onerror=",
    "eval(",
    "alert(",
];

/// Request validation middleware
pub async fn validate_request_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();

    // Validate security headers
    validate_security_headers(headers)?;

    // Validate request size
    if let Some(content_length) = headers.get("content-length")
        && let Ok(length_str) = content_length.to_str()
        && let Ok(length) = length_str.parse::<usize>()
        && length > 10_000_000
    {
        // 10MB limit
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Check for suspicious patterns in headers
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str()
            && contains_suspicious_content(value_str)
        {
            tracing::warn!(
                "Suspicious content detected in header {}: {}",
                name,
                value_str
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    Ok(next.run(request).await)
}

/// Validate required security headers
fn validate_security_headers(headers: &HeaderMap) -> Result<(), StatusCode> {
    let missing_headers: Vec<&str> = REQUIRED_SECURITY_HEADERS
        .iter()
        .filter(|&&header| !headers.contains_key(header))
        .copied()
        .collect();

    if !missing_headers.is_empty() {
        tracing::warn!("Missing required headers: {:?}", missing_headers);
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(())
}

/// Check for suspicious content patterns
fn contains_suspicious_content(content: &str) -> bool {
    let content_lower = content.to_lowercase();
    SUSPICIOUS_PATTERNS
        .iter()
        .any(|&pattern| content_lower.contains(pattern))
}

/// Rate limiting by IP
pub struct IpRateLimiter {
    requests: std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
    max_requests: u32,
    window_duration: std::time::Duration,
}

impl IpRateLimiter {
    pub fn new(max_requests: u32, window_minutes: u64) -> Self {
        Self {
            requests: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_requests,
            window_duration: std::time::Duration::from_secs(window_minutes * 60),
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> Result<(), StatusCode> {
        let mut requests = self.requests.lock().unwrap();
        let now = std::time::Instant::now();

        // Clean expired entries
        requests.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.window_duration);

        // Check current IP
        match requests.get_mut(ip) {
            Some((count, timestamp)) => {
                if now.duration_since(*timestamp) < self.window_duration {
                    if *count >= self.max_requests {
                        return Err(StatusCode::TOO_MANY_REQUESTS);
                    }
                    *count += 1;
                } else {
                    *count = 1;
                    *timestamp = now;
                }
            }
            None => {
                requests.insert(ip.to_string(), (1, now));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_content_detection() {
        assert!(contains_suspicious_content("<script>alert('xss')</script>"));
        assert!(contains_suspicious_content("javascript:void(0)"));
        assert!(contains_suspicious_content("onload=malicious()"));
        assert!(!contains_suspicious_content("normal content"));
        assert!(!contains_suspicious_content("user@example.com"));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = IpRateLimiter::new(5, 1);

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("192.168.1.1").is_ok());
        }

        // Should block 6th request
        assert!(limiter.check_rate_limit("192.168.1.1").is_err());
    }
}


