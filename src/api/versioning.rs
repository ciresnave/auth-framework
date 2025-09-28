//! API Versioning Support
//!
//! Provides version negotiation and backwards compatibility

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

/// API version information
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ApiVersion {
    #[default]
    V1,
    V2,
}

impl ApiVersion {
    /// Parse version from Accept header or path
    pub fn from_header(headers: &HeaderMap) -> Option<Self> {
        if let Some(accept) = headers.get("accept")
            && let Ok(accept_str) = accept.to_str()
        {
            if accept_str.contains("application/vnd.authframework.v2+json") {
                return Some(ApiVersion::V2);
            } else if accept_str.contains("application/vnd.authframework.v1+json") {
                return Some(ApiVersion::V1);
            }
        }
        None
    }

    /// Convert to header value
    pub fn to_header_value(&self) -> &'static str {
        match self {
            ApiVersion::V1 => "application/vnd.authframework.v1+json",
            ApiVersion::V2 => "application/vnd.authframework.v2+json",
        }
    }
}

/// Middleware to handle API versioning
pub async fn version_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = request.headers();
    let version = ApiVersion::from_header(headers).unwrap_or_default();

    // Store version in request extensions for handlers to use
    let mut request = request;
    request.extensions_mut().insert(version);

    let mut response = next.run(request).await;

    // Add version info to response headers
    let default_version = ApiVersion::default();
    let version = response
        .extensions()
        .get::<ApiVersion>()
        .unwrap_or(&default_version)
        .to_header_value();

    response
        .headers_mut()
        .insert("api-version", version.parse().unwrap());

    Ok(response)
}

/// Extract API version from request
pub fn get_api_version(request: &Request) -> ApiVersion {
    request
        .extensions()
        .get::<ApiVersion>()
        .cloned()
        .unwrap_or_default()
}
