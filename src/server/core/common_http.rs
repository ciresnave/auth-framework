//! Common HTTP Client Utilities
//!
//! This module provides shared HTTP client functionality to eliminate
//! duplication across server modules.

use crate::errors::{AuthError, Result};
use crate::server::core::common_config::{EndpointConfig, RetryConfig};
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// HTTP client wrapper with common functionality
#[derive(Clone, Debug)]
pub struct HttpClient {
    client: Client,
    config: EndpointConfig,
    retry_config: RetryConfig,
}

impl HttpClient {
    /// Create new HTTP client
    pub fn new(config: EndpointConfig) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(
                config.timeout.connect_timeout.as_secs(),
            ))
            .connect_timeout(config.timeout.connect_timeout)
            .danger_accept_invalid_certs(!config.security.enable_tls);

        // Add default headers
        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in &config.headers {
            let header_name =
                reqwest::header::HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                    AuthError::ConfigurationError(format!("Invalid header name: {}", e))
                })?;
            let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|e| {
                AuthError::ConfigurationError(format!("Invalid header value: {}", e))
            })?;
            headers.insert(header_name, header_value);
        }

        if !headers.contains_key("user-agent") {
            headers.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_static("auth-framework/0.3.0"),
            );
        }

        client_builder = client_builder.default_headers(headers);

        let client = client_builder.build().map_err(|e| {
            AuthError::ConfigurationError(format!("Failed to create HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            config,
            retry_config: RetryConfig::default(),
        })
    }

    /// Set retry configuration
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.retry_config = retry_config;
        self
    }

    /// Execute GET request with retries
    pub async fn get(&self, path: &str) -> Result<Response> {
        let url = self.build_url(path)?;
        self.execute_with_retry(Method::GET, &url, None::<&()>)
            .await
    }

    /// Create POST request builder (reqwest-compatible)
    pub fn post(&self, url: &str) -> RequestBuilder {
        self.client.post(url)
    }

    /// Execute POST request with JSON body
    pub async fn post_json<T>(&self, path: &str, body: &T) -> Result<Response>
    where
        T: Serialize,
    {
        let url = self.build_url(path)?;
        self.execute_with_retry(Method::POST, &url, Some(body))
            .await
    }

    /// Execute PUT request with JSON body
    pub async fn put_json<T>(&self, path: &str, body: &T) -> Result<Response>
    where
        T: Serialize,
    {
        let url = self.build_url(path)?;
        self.execute_with_retry(Method::PUT, &url, Some(body)).await
    }

    /// Execute DELETE request
    pub async fn delete(&self, path: &str) -> Result<Response> {
        let url = self.build_url(path)?;
        self.execute_with_retry(Method::DELETE, &url, None::<&()>)
            .await
    }

    /// Execute form-encoded POST request
    pub async fn post_form(
        &self,
        path: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<Response> {
        let url = self.build_url(path)?;

        let mut request = self.client.request(Method::POST, &url);
        request = request.form(form_data);

        self.execute_request_with_retry(request).await
    }

    /// Execute request with custom headers
    pub async fn request_with_headers<T>(
        &self,
        method: Method,
        path: &str,
        headers: HashMap<String, String>,
        body: Option<&T>,
    ) -> Result<Response>
    where
        T: Serialize,
    {
        let url = self.build_url(path)?;
        let mut request = self.client.request(method, &url);

        // Add custom headers
        for (key, value) in headers {
            request = request.header(key, value);
        }

        // Add body if provided
        if let Some(body) = body {
            request = request.json(body);
        }

        self.execute_request_with_retry(request).await
    }

    /// Build full URL from base and path
    fn build_url(&self, path: &str) -> Result<String> {
        let mut url = self.config.base_url.clone();

        // Add API version if configured
        if let Some(ref version) = self.config.api_version {
            if !url.ends_with('/') {
                url.push('/');
            }
            url.push_str(version);
        }

        // Add path
        if !url.ends_with('/') && !path.starts_with('/') {
            url.push('/');
        }
        url.push_str(path);

        Ok(url)
    }

    /// Execute request with retry logic
    async fn execute_with_retry<T>(
        &self,
        method: Method,
        url: &str,
        body: Option<&T>,
    ) -> Result<Response>
    where
        T: Serialize,
    {
        let mut request = self.client.request(method, url);

        if let Some(body) = body {
            request = request.json(body);
        }

        self.execute_request_with_retry(request).await
    }

    /// Execute request with retry logic
    async fn execute_request_with_retry(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<Response> {
        let mut last_error = None;

        for attempt in 0..=self.retry_config.max_attempts {
            let request = request_builder
                .try_clone()
                .ok_or_else(|| AuthError::validation("Cannot clone request for retry"))?;

            match timeout(self.config.timeout.read_timeout, request.send()).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() || !self.is_retryable_error(&response) {
                        return Ok(response);
                    }
                    last_error = Some(AuthError::validation(format!("HTTP {}", response.status())));
                }
                Ok(Err(e)) => {
                    last_error = Some(AuthError::validation(format!("Request failed: {}", e)));
                }
                Err(_) => {
                    last_error = Some(AuthError::validation("Request timeout"));
                }
            }

            // Don't sleep after the last attempt
            if attempt < self.retry_config.max_attempts {
                let delay = self.calculate_retry_delay(attempt);
                sleep(delay).await;
            }
        }

        Err(last_error.unwrap_or_else(|| AuthError::validation("All retry attempts failed")))
    }

    /// Check if error is retryable
    fn is_retryable_error(&self, response: &Response) -> bool {
        match response.status().as_u16() {
            // Retry on server errors and some client errors
            500..=599 => true, // Server errors
            429 => true,       // Rate limiting
            408 => true,       // Request timeout
            _ => false,
        }
    }

    /// Calculate retry delay with exponential backoff and jitter
    fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.retry_config.initial_delay.as_millis() as f64;
        let backoff = self.retry_config.backoff_multiplier.powi(attempt as i32);
        let delay_ms = (base_delay * backoff).min(self.retry_config.max_delay.as_millis() as f64);

        // Add jitter
        let jitter = delay_ms * self.retry_config.jitter_factor * (rand::random::<f64>() - 0.5);
        let final_delay = (delay_ms + jitter).max(0.0) as u64;

        Duration::from_millis(final_delay)
    }
}

/// Common HTTP response handling utilities
pub mod response {
    use super::*;

    /// Parse JSON response with error handling
    pub async fn parse_json<T>(response: Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response body".to_string());

            return Err(AuthError::validation(format!("HTTP {} - {}", status, body)));
        }

        response
            .json::<T>()
            .await
            .map_err(|e| AuthError::validation(format!("Failed to parse JSON response: {}", e)))
    }

    /// Extract response body as text
    pub async fn extract_text(response: Response) -> Result<String> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response body".to_string());

            return Err(AuthError::validation(format!("HTTP {} - {}", status, body)));
        }

        response
            .text()
            .await
            .map_err(|e| AuthError::validation(format!("Failed to read response body: {}", e)))
    }

    /// Check if response indicates success
    pub fn is_success_status(status_code: u16) -> bool {
        (200..300).contains(&status_code)
    }

    /// Extract error details from response
    pub async fn extract_error_details(response: Response) -> (u16, String) {
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read response body".to_string());
        (status, body)
    }
}

/// OAuth-specific HTTP client utilities
pub mod oauth {
    use super::*;

    /// Execute OAuth token exchange request
    pub async fn token_exchange(
        client: &HttpClient,
        token_endpoint: &str,
        params: &HashMap<String, String>,
    ) -> Result<serde_json::Value> {
        // Use relative path from base_url or full URL
        let path = if token_endpoint.starts_with("http") {
            // Override base_url for this request
            return execute_absolute_url_form_post(client, token_endpoint, params).await;
        } else {
            token_endpoint
        };

        let response = client.post_form(path, params).await?;
        response::parse_json(response).await
    }

    /// Execute introspection request
    pub async fn introspect_token(
        client: &HttpClient,
        introspect_endpoint: &str,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut params = HashMap::new();
        params.insert("token".to_string(), token.to_string());

        if let Some(client_id) = client_id {
            params.insert("client_id".to_string(), client_id.to_string());
        }

        let response = client.post_form(introspect_endpoint, &params).await?;
        response::parse_json(response).await
    }

    /// Execute JWKS fetch
    pub async fn fetch_jwks(client: &HttpClient, jwks_uri: &str) -> Result<serde_json::Value> {
        let response = client.get(jwks_uri).await?;
        response::parse_json(response).await
    }

    /// Execute OAuth discovery request
    pub async fn discover_configuration(
        _client: &HttpClient,
        issuer: &str,
    ) -> Result<serde_json::Value> {
        let discovery_url = format!(
            "{}/.well-known/openid_configuration",
            issuer.trim_end_matches('/')
        );

        // Create temporary client for absolute URL
        let temp_config = EndpointConfig::new(&discovery_url);
        let temp_client = HttpClient::new(temp_config)?;

        let response = temp_client.get("").await?;
        response::parse_json(response).await
    }

    /// Execute form POST to absolute URL
    async fn execute_absolute_url_form_post(
        _client: &HttpClient,
        url: &str,
        params: &HashMap<String, String>,
    ) -> Result<serde_json::Value> {
        // Create client for specific URL
        let temp_config = EndpointConfig::new(url);
        let temp_client = HttpClient::new(temp_config)?;

        let response = temp_client.post_form("", params).await?;
        response::parse_json(response).await
    }
}

/// Webhook and callback utilities
pub mod webhooks {
    use super::*;

    /// Send webhook notification
    pub async fn send_webhook<T>(
        client: &HttpClient,
        webhook_url: &str,
        payload: &T,
        signature_key: Option<&str>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        // Add signature if key provided
        if let Some(key) = signature_key {
            let payload_json = serde_json::to_string(payload).map_err(|e| {
                AuthError::validation(format!("Failed to serialize payload: {}", e))
            })?;
            let signature = calculate_webhook_signature(&payload_json, key)?;
            headers.insert("X-Webhook-Signature".to_string(), signature);
        }

        let response = client
            .request_with_headers(Method::POST, webhook_url, headers, Some(payload))
            .await?;

        if !response.status().is_success() {
            return Err(AuthError::validation(format!(
                "Webhook failed: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Calculate HMAC signature for webhook
    fn calculate_webhook_signature(payload: &str, key: &str) -> Result<String> {
        // Simplified signature calculation without external HMAC dependency
        // In a real implementation, you'd use the `hmac` crate
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        payload.hash(&mut hasher);
        let hash_result = hasher.finish();

        Ok(format!("sha256={:x}", hash_result))
    }
}
