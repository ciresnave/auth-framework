//! Open Policy Agent (OPA) integration for externalized authorization.
//!
//! Delegates fine-grained policy evaluation to an OPA server using its
//! REST API, enabling dynamic, data-driven authorization decisions
//! expressed in Rego.
//!
//! # Architecture
//!
//! ```text
//! Application ──► OpaClient ──► POST /v1/data/{path} ──► OPA Server
//!                                                         │
//!                                                     Rego policies
//!                                                         │
//!                                                  ◄── Decision ──►
//! ```
//!
//! # References
//!
//! - [OPA REST API](https://www.openpolicyagent.org/docs/latest/rest-api/)
//! - [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;

// ── Configuration ───────────────────────────────────────────────────

/// OPA client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaConfig {
    /// Base URL of the OPA server (e.g., `http://localhost:8181`).
    pub base_url: String,
    /// Default policy path for queries (e.g., `authz/allow`).
    pub default_policy_path: String,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
    /// Optional bearer token for authenticating with OPA.
    pub auth_token: Option<String>,
    /// Whether to cache policy decisions.
    pub enable_cache: bool,
    /// Cache TTL in seconds (0 = no expiry).
    pub cache_ttl_secs: u64,
}

impl Default for OpaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8181".to_string(),
            default_policy_path: "authz/allow".to_string(),
            timeout_secs: 5,
            auth_token: None,
            enable_cache: false,
            cache_ttl_secs: 60,
        }
    }
}

// ── OPA request / response ──────────────────────────────────────────

/// Input payload sent to OPA for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaInput {
    /// The input object passed to the Rego policy.
    pub input: serde_json::Value,
}

/// Response from an OPA policy query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaResponse {
    /// The policy decision result.
    #[serde(default)]
    pub result: serde_json::Value,
    /// Decision ID for audit logging.
    #[serde(default)]
    pub decision_id: Option<String>,
}

impl OpaResponse {
    /// Check if the result is a simple boolean `true`.
    pub fn is_allowed(&self) -> bool {
        self.result.as_bool().unwrap_or(false)
    }

    /// Extract a boolean from a nested path in the result.
    pub fn get_bool(&self, path: &str) -> Option<bool> {
        let mut current = &self.result;
        for segment in path.split('.') {
            current = current.get(segment)?;
        }
        current.as_bool()
    }

    /// Extract a string from a nested path in the result.
    pub fn get_str(&self, path: &str) -> Option<&str> {
        let mut current = &self.result;
        for segment in path.split('.') {
            current = current.get(segment)?;
        }
        current.as_str()
    }
}

// ── Cache entry ─────────────────────────────────────────────────────

struct CacheEntry {
    response: OpaResponse,
    expires_at: u64,
}

// ── OPA Client ──────────────────────────────────────────────────────

/// Client for evaluating authorization decisions against an OPA server.
pub struct OpaClient {
    config: OpaConfig,
    base_url: Url,
    http: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl OpaClient {
    /// Create a new OPA client.
    pub fn new(config: OpaConfig) -> Result<Self> {
        let base_url = normalize_opa_base_url(&config.base_url)?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| AuthError::internal(format!("HTTP client init failed: {e}")))?;

        Ok(Self {
            config,
            base_url,
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Evaluate a policy at the given path with the provided input.
    ///
    /// # Arguments
    ///
    /// * `policy_path` — The Rego package/rule path (e.g., `authz/allow`)
    /// * `input` — Arbitrary JSON input for the policy
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use auth_framework::protocols::opa::*;
    /// # async fn example() -> auth_framework::errors::Result<()> {
    /// let client = OpaClient::new(OpaConfig::default())?;
    /// let input = serde_json::json!({
    ///     "user": "alice",
    ///     "action": "read",
    ///     "resource": "/documents/secret"
    /// });
    /// let response = client.query("authz/allow", input).await?;
    /// if response.is_allowed() {
    ///     println!("Access granted");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, policy_path: &str, input: serde_json::Value) -> Result<OpaResponse> {
        // Check cache first
        if self.config.enable_cache {
            let cache_key = format!("{}:{}", policy_path, input);
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&cache_key) {
                let now = now_secs();
                if self.config.cache_ttl_secs == 0 || entry.expires_at > now {
                    return Ok(entry.response.clone());
                }
            }
            drop(cache);
        }

        let url = self.build_api_url("v1/data", policy_path)?;
        let payload = OpaInput {
            input: input.clone(),
        };

        let mut request = self.http.post(url).json(&payload);
        if let Some(ref token) = self.config.auth_token {
            request = request.bearer_auth(token);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OPA request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = read_error_body(resp).await;
            return Err(AuthError::internal(format!(
                "OPA returned HTTP {status}: {body}"
            )));
        }

        let opa_response: OpaResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::internal(format!("Invalid OPA response: {e}")))?;

        // Update cache
        if self.config.enable_cache {
            let cache_key = format!("{}:{}", policy_path, input);
            let entry = CacheEntry {
                response: opa_response.clone(),
                expires_at: now_secs() + self.config.cache_ttl_secs,
            };
            self.cache.write().await.insert(cache_key, entry);
        }

        Ok(opa_response)
    }

    /// Evaluate the default policy path.
    pub async fn evaluate(&self, input: serde_json::Value) -> Result<OpaResponse> {
        self.query(&self.config.default_policy_path, input).await
    }

    /// Convenience: check if the default policy allows the given input.
    pub async fn is_allowed(&self, input: serde_json::Value) -> Result<bool> {
        let resp = self.evaluate(input).await?;
        Ok(resp.is_allowed())
    }

    /// Check OPA server health.
    pub async fn health_check(&self) -> Result<bool> {
        let url = self.build_static_url("health")?;
        let mut request = self.http.get(url);
        if let Some(ref token) = self.config.auth_token {
            request = request.bearer_auth(token);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OPA health check failed: {e}")))?;
        Ok(resp.status().is_success())
    }

    /// Upload a Rego policy to OPA.
    pub async fn put_policy(&self, policy_id: &str, rego: &str) -> Result<()> {
        let url = self.build_api_url("v1/policies", policy_id)?;
        let mut request = self
            .http
            .put(url)
            .header("Content-Type", "text/plain")
            .body(rego.to_string());
        if let Some(ref token) = self.config.auth_token {
            request = request.bearer_auth(token);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OPA policy upload failed: {e}")))?;

        if !resp.status().is_success() {
            let body = read_error_body(resp).await;
            return Err(AuthError::internal(format!(
                "OPA policy upload returned error: {body}"
            )));
        }
        Ok(())
    }

    /// Delete a policy from OPA.
    pub async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let url = self.build_api_url("v1/policies", policy_id)?;
        let mut request = self.http.delete(url);
        if let Some(ref token) = self.config.auth_token {
            request = request.bearer_auth(token);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OPA policy delete failed: {e}")))?;

        if !resp.status().is_success() {
            let body = read_error_body(resp).await;
            return Err(AuthError::internal(format!(
                "OPA policy delete returned error: {body}"
            )));
        }
        Ok(())
    }

    /// Upload data to OPA's data store.
    pub async fn put_data(&self, data_path: &str, data: serde_json::Value) -> Result<()> {
        let url = self.build_api_url("v1/data", data_path)?;
        let mut request = self.http.put(url).json(&data);
        if let Some(ref token) = self.config.auth_token {
            request = request.bearer_auth(token);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OPA data upload failed: {e}")))?;

        if !resp.status().is_success() {
            let body = read_error_body(resp).await;
            return Err(AuthError::internal(format!(
                "OPA data upload error: {body}"
            )));
        }
        Ok(())
    }

    fn build_static_url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| AuthError::internal(format!("Failed to build OPA URL: {e}")))
    }

    fn build_api_url(&self, prefix: &str, path: &str) -> Result<Url> {
        let sanitized_path = sanitize_opa_path(path)?;
        let joined = if sanitized_path.is_empty() {
            prefix.to_string()
        } else {
            format!("{}/{}", prefix.trim_end_matches('/'), sanitized_path)
        };
        self.build_static_url(&joined)
    }

    /// Clear the response cache.
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Get the number of cached entries.
    pub async fn cache_size(&self) -> usize {
        self.cache.read().await.len()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_opa_base_url(base_url: &str) -> Result<Url> {
    if base_url.is_empty() {
        return Err(AuthError::validation("OPA base URL cannot be empty"));
    }

    let mut parsed = Url::parse(base_url)
        .map_err(|e| AuthError::validation(format!("Invalid OPA base URL: {e}")))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AuthError::validation("OPA base URL must use http or https"));
    }

    if parsed.host_str().is_none() {
        return Err(AuthError::validation("OPA base URL must include a host"));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AuthError::validation(
            "OPA base URL must not embed credentials",
        ));
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(AuthError::validation(
            "OPA base URL must not include query parameters or fragments",
        ));
    }

    if !parsed.path().ends_with('/') {
        let new_path = format!("{}/", parsed.path().trim_end_matches('/'));
        parsed.set_path(&new_path);
    }

    Ok(parsed)
}

fn sanitize_opa_path(path: &str) -> Result<String> {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    if segments.is_empty() {
        return Err(AuthError::validation("OPA path cannot be empty"));
    }

    for segment in &segments {
        if matches!(*segment, "." | "..")
            || segment.contains('\\')
            || segment.contains('?')
            || segment.contains('#')
        {
            return Err(AuthError::validation("OPA path contains invalid segments"));
        }
    }

    Ok(segments.join("/"))
}

async fn read_error_body(response: reqwest::Response) -> String {
    match response.text().await {
        Ok(body) if !body.is_empty() => body,
        Ok(_) => "<empty response body>".to_string(),
        Err(error) => format!("<failed to read response body: {error}>"),
    }
}

// ── Rego-style local evaluator (for embedded policies) ──────────────

/// A lightweight local policy evaluator for simple attribute-based checks.
///
/// Useful when a full OPA server is not deployed. Supports rule evaluation
/// against a set of named attributes.
pub struct LocalPolicyEvaluator {
    rules: Vec<PolicyRule>,
}

/// A policy rule consisting of conditions that must all be true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name.
    pub name: String,
    /// Conditions that must ALL be satisfied.
    pub conditions: Vec<PolicyCondition>,
    /// Effect when all conditions are met.
    pub effect: PolicyEffect,
}

/// A single condition in a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Attribute path (dot-separated, e.g. "user.role").
    pub attribute: String,
    /// Comparison operator.
    pub operator: ConditionOperator,
    /// Expected value.
    pub value: serde_json::Value,
}

/// Comparison operators for policy conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    In,
    Exists,
}

/// Policy decision effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl LocalPolicyEvaluator {
    /// Create a new evaluator with no rules (default-deny).
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a policy rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate an input against all rules.
    ///
    /// Returns `Allow` if at least one Allow rule matches and no Deny rule matches.
    /// Returns `Deny` if no rules match or a Deny rule fires.
    pub fn evaluate(&self, input: &serde_json::Value) -> PolicyEffect {
        let mut any_allow = false;

        for rule in &self.rules {
            if self.evaluate_rule(rule, input) {
                match rule.effect {
                    PolicyEffect::Deny => return PolicyEffect::Deny,
                    PolicyEffect::Allow => any_allow = true,
                }
            }
        }

        if any_allow {
            PolicyEffect::Allow
        } else {
            PolicyEffect::Deny
        }
    }

    fn evaluate_rule(&self, rule: &PolicyRule, input: &serde_json::Value) -> bool {
        rule.conditions
            .iter()
            .all(|cond| self.evaluate_condition(cond, input))
    }

    fn evaluate_condition(&self, cond: &PolicyCondition, input: &serde_json::Value) -> bool {
        let actual = resolve_path(input, &cond.attribute);

        match cond.operator {
            ConditionOperator::Equals => match actual {
                Some(v) => *v == cond.value,
                None => false,
            },
            ConditionOperator::NotEquals => match actual {
                Some(v) => *v != cond.value,
                None => true,
            },
            ConditionOperator::Contains => match actual {
                Some(v) => {
                    if let (Some(arr), Some(needle)) = (v.as_array(), cond.value.as_str()) {
                        arr.iter().any(|e| e.as_str() == Some(needle))
                    } else if let (Some(s), Some(needle)) = (v.as_str(), cond.value.as_str()) {
                        s.contains(needle)
                    } else {
                        false
                    }
                }
                None => false,
            },
            ConditionOperator::In => match actual {
                Some(v) => {
                    if let Some(arr) = cond.value.as_array() {
                        arr.contains(v)
                    } else {
                        false
                    }
                }
                None => false,
            },
            ConditionOperator::Exists => actual.is_some(),
        }
    }
}

impl Default for LocalPolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a dot-separated path in a JSON value.
fn resolve_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── OPA config ──────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = OpaConfig::default();
        assert_eq!(cfg.base_url, "http://localhost:8181");
        assert_eq!(cfg.default_policy_path, "authz/allow");
        assert_eq!(cfg.timeout_secs, 5);
        assert!(cfg.auth_token.is_none());
        assert!(!cfg.enable_cache);
    }

    // ── OpaResponse ─────────────────────────────────────────────

    #[test]
    fn test_response_is_allowed_true() {
        let resp = OpaResponse {
            result: serde_json::json!(true),
            decision_id: None,
        };
        assert!(resp.is_allowed());
    }

    #[test]
    fn test_response_is_allowed_false() {
        let resp = OpaResponse {
            result: serde_json::json!(false),
            decision_id: None,
        };
        assert!(!resp.is_allowed());
    }

    #[test]
    fn test_response_is_allowed_non_bool() {
        let resp = OpaResponse {
            result: serde_json::json!({"allow": true}),
            decision_id: None,
        };
        assert!(!resp.is_allowed());
    }

    #[test]
    fn test_response_get_bool() {
        let resp = OpaResponse {
            result: serde_json::json!({"authz": {"allow": true, "admin": false}}),
            decision_id: Some("dec-1".to_string()),
        };
        assert_eq!(resp.get_bool("authz.allow"), Some(true));
        assert_eq!(resp.get_bool("authz.admin"), Some(false));
        assert_eq!(resp.get_bool("authz.missing"), None);
    }

    #[test]
    fn test_response_get_str() {
        let resp = OpaResponse {
            result: serde_json::json!({"reason": "policy XYZ"}),
            decision_id: None,
        };
        assert_eq!(resp.get_str("reason"), Some("policy XYZ"));
    }

    // ── OPA Client creation ─────────────────────────────────────

    #[test]
    fn test_client_creation_valid() {
        let client = OpaClient::new(OpaConfig::default());
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_creation_empty_url() {
        let cfg = OpaConfig {
            base_url: String::new(),
            ..Default::default()
        };
        assert!(OpaClient::new(cfg).is_err());
    }

    #[test]
    fn test_client_creation_rejects_embedded_credentials() {
        let cfg = OpaConfig {
            base_url: "https://user:pass@opa.example.com".to_string(),
            ..Default::default()
        };
        assert!(OpaClient::new(cfg).is_err());
    }

    #[test]
    fn test_client_creation_rejects_query_string_base_url() {
        let cfg = OpaConfig {
            base_url: "https://opa.example.com?target=internal".to_string(),
            ..Default::default()
        };
        assert!(OpaClient::new(cfg).is_err());
    }

    #[test]
    fn test_sanitize_opa_path_rejects_traversal() {
        assert!(sanitize_opa_path("../system/main").is_err());
        assert!(sanitize_opa_path("authz/../../admin").is_err());
    }

    // ── Local Policy Evaluator ──────────────────────────────────

    #[test]
    fn test_local_evaluator_default_deny() {
        let eval = LocalPolicyEvaluator::new();
        let input = serde_json::json!({"user": "alice"});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_allow_rule() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "allow admins".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.role".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("admin"),
            }],
            effect: PolicyEffect::Allow,
        });

        let input = serde_json::json!({"user": {"role": "admin"}});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        let input2 = serde_json::json!({"user": {"role": "viewer"}});
        assert_eq!(eval.evaluate(&input2), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_deny_overrides_allow() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "allow all".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.active".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!(true),
            }],
            effect: PolicyEffect::Allow,
        });
        eval.add_rule(PolicyRule {
            name: "deny blocked".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.blocked".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!(true),
            }],
            effect: PolicyEffect::Deny,
        });

        let input = serde_json::json!({"user": {"active": true, "blocked": true}});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_contains_operator() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "role check".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.roles".to_string(),
                operator: ConditionOperator::Contains,
                value: serde_json::json!("editor"),
            }],
            effect: PolicyEffect::Allow,
        });

        let input = serde_json::json!({"user": {"roles": ["viewer", "editor"]}});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        let input2 = serde_json::json!({"user": {"roles": ["viewer"]}});
        assert_eq!(eval.evaluate(&input2), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_in_operator() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "allowed actions".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "action".to_string(),
                operator: ConditionOperator::In,
                value: serde_json::json!(["read", "list"]),
            }],
            effect: PolicyEffect::Allow,
        });

        let input = serde_json::json!({"action": "read"});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        let input2 = serde_json::json!({"action": "delete"});
        assert_eq!(eval.evaluate(&input2), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_exists_operator() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "has token".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "auth.token".to_string(),
                operator: ConditionOperator::Exists,
                value: serde_json::json!(null),
            }],
            effect: PolicyEffect::Allow,
        });

        let input = serde_json::json!({"auth": {"token": "abc"}});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        let input2 = serde_json::json!({"auth": {}});
        assert_eq!(eval.evaluate(&input2), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_not_equals() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "not guest".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.role".to_string(),
                operator: ConditionOperator::NotEquals,
                value: serde_json::json!("guest"),
            }],
            effect: PolicyEffect::Allow,
        });

        let input = serde_json::json!({"user": {"role": "admin"}});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        let guest = serde_json::json!({"user": {"role": "guest"}});
        assert_eq!(eval.evaluate(&guest), PolicyEffect::Deny);
    }

    #[test]
    fn test_local_evaluator_multiple_conditions() {
        let mut eval = LocalPolicyEvaluator::new();
        eval.add_rule(PolicyRule {
            name: "admin write".to_string(),
            conditions: vec![
                PolicyCondition {
                    attribute: "user.role".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("admin"),
                },
                PolicyCondition {
                    attribute: "action".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("write"),
                },
            ],
            effect: PolicyEffect::Allow,
        });

        // Both conditions met
        let input = serde_json::json!({"user": {"role": "admin"}, "action": "write"});
        assert_eq!(eval.evaluate(&input), PolicyEffect::Allow);

        // Only one condition met
        let input2 = serde_json::json!({"user": {"role": "admin"}, "action": "read"});
        assert_eq!(eval.evaluate(&input2), PolicyEffect::Deny);
    }

    #[test]
    fn test_resolve_path() {
        let v = serde_json::json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_path(&v, "a.b.c"), Some(&serde_json::json!(42)));
        assert_eq!(resolve_path(&v, "a.b"), Some(&serde_json::json!({"c": 42})));
        assert_eq!(resolve_path(&v, "x.y"), None);
    }

    #[test]
    fn test_policy_rule_serialization() {
        let rule = PolicyRule {
            name: "test".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "user.role".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("admin"),
            }],
            effect: PolicyEffect::Allow,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: PolicyRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.effect, PolicyEffect::Allow);
    }

    #[test]
    fn test_opa_input_serialization() {
        let input = OpaInput {
            input: serde_json::json!({"user": "alice"}),
        };
        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["input"]["user"], "alice");
    }
}
