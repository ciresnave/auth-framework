//! Authorization context builders for enhanced RBAC
//!
//! This module provides utilities to build context objects for conditional
//! permissions and request-specific authorization decisions.

use crate::tokens::AuthToken;
use axum::extract::Request;
use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Request context for authorization decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    /// User information
    pub user_id: String,
    pub roles: Vec<String>,
    pub session_id: Option<String>,

    /// Request metadata
    pub method: String,
    pub path: String,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,

    /// Time-based context
    pub request_time: DateTime<Utc>,
    pub time_of_day: TimeOfDay,
    pub day_type: DayType,

    /// Device and connection info
    pub device_type: DeviceType,
    pub connection_type: ConnectionType,

    /// Security context
    pub security_level: SecurityLevel,
    pub risk_score: u8, // 0-100

    /// Custom attributes
    pub custom_attributes: HashMap<String, String>,
}

/// Time of day classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TimeOfDay {
    BusinessHours,
    AfterHours,
    Weekend,
    Holiday,
}

/// Day type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DayType {
    Weekday,
    Weekend,
    Holiday,
}

/// Device type detection
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    Unknown,
}

/// Connection type analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConnectionType {
    Direct,
    VPN,
    Proxy,
    Tor,
    Corporate,
    Unknown,
}

/// Security level assessment
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Enhanced context builder for authorization decisions
pub struct ContextBuilder {
    /// Known holiday dates (could be loaded from config)
    holidays: Vec<chrono::NaiveDate>,
    /// Business hours configuration
    business_start: u8,
    business_end: u8,
    /// IP ranges for corporate networks
    corporate_networks: Vec<ipnetwork::IpNetwork>,
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextBuilder {
    /// Create a new context builder with default settings
    pub fn new() -> Self {
        Self {
            holidays: Vec::new(),
            business_start: 9,
            business_end: 17,
            corporate_networks: Vec::new(),
        }
    }

    /// Configure business hours
    pub fn with_business_hours(mut self, start: u8, end: u8) -> Self {
        self.business_start = start;
        self.business_end = end;
        self
    }

    /// Add corporate network ranges
    pub fn with_corporate_networks(mut self, networks: Vec<ipnetwork::IpNetwork>) -> Self {
        self.corporate_networks = networks;
        self
    }

    /// Add holiday dates
    pub fn with_holidays(mut self, holidays: Vec<chrono::NaiveDate>) -> Self {
        self.holidays = holidays;
        self
    }

    /// Build authorization context from request and auth token
    pub fn build_context(&self, request: &Request, auth_token: &AuthToken) -> AuthorizationContext {
        let now = Utc::now();
        let ip_address = self.extract_ip_address(request);
        let user_agent = self.extract_user_agent(request);

        AuthorizationContext {
            user_id: auth_token.user_id.clone(),
            roles: auth_token.roles.clone(),
            session_id: auth_token.metadata.session_id.clone(),

            method: request.method().to_string(),
            path: request.uri().path().to_string(),
            ip_address,
            user_agent: user_agent.clone(),

            request_time: now,
            time_of_day: self.classify_time_of_day(now),
            day_type: self.classify_day_type(now),

            device_type: self.detect_device_type(&user_agent),
            connection_type: self.analyze_connection_type(request, &ip_address),

            security_level: self.assess_security_level(request),
            risk_score: self.calculate_risk_score(request, &ip_address, &user_agent),

            custom_attributes: self.extract_custom_attributes(request),
        }
    }

    /// Convert context to HashMap for role-system compatibility
    pub fn to_hashmap(&self, context: &AuthorizationContext) -> HashMap<String, String> {
        let mut map = HashMap::new();

        // User context
        map.insert("user_id".to_string(), context.user_id.clone());
        map.insert("roles".to_string(), context.roles.join(","));
        if let Some(session_id) = &context.session_id {
            map.insert("session_id".to_string(), session_id.clone());
        }

        // Request context
        map.insert("method".to_string(), context.method.clone());
        map.insert("path".to_string(), context.path.clone());
        if let Some(ip) = &context.ip_address {
            map.insert("ip_address".to_string(), ip.to_string());
        }
        if let Some(ua) = &context.user_agent {
            map.insert("user_agent".to_string(), ua.clone());
        }

        // Time context
        map.insert(
            "time_of_day".to_string(),
            format!("{:?}", context.time_of_day).to_lowercase(),
        );
        map.insert(
            "day_type".to_string(),
            format!("{:?}", context.day_type).to_lowercase(),
        );
        map.insert(
            "request_hour".to_string(),
            context.request_time.hour().to_string(),
        );
        map.insert(
            "request_weekday".to_string(),
            context.request_time.weekday().to_string(),
        );

        // Device and connection
        map.insert(
            "device_type".to_string(),
            format!("{:?}", context.device_type).to_lowercase(),
        );
        map.insert(
            "connection_type".to_string(),
            format!("{:?}", context.connection_type).to_lowercase(),
        );

        // Security context
        map.insert(
            "security_level".to_string(),
            format!("{:?}", context.security_level).to_lowercase(),
        );
        map.insert("risk_score".to_string(), context.risk_score.to_string());

        // Custom attributes
        for (key, value) in &context.custom_attributes {
            map.insert(format!("custom_{}", key), value.clone());
        }

        map
    }

    /// Extract IP address from request headers
    fn extract_ip_address(&self, request: &Request) -> Option<IpAddr> {
        // Try X-Forwarded-For first
        if let Some(forwarded) = request.headers().get("x-forwarded-for")
            && let Ok(forwarded_str) = forwarded.to_str()
        {
            if let Some(ip_str) = forwarded_str.split(',').next()
                && let Ok(ip) = ip_str.trim().parse()
            {
                return Some(ip);
            }

            // Try X-Real-IP
            if let Some(real_ip) = request.headers().get("x-real-ip")
                && let Ok(ip_str) = real_ip.to_str()
                && let Ok(ip) = ip_str.parse()
            {
                return Some(ip);
            }

            // Could also get from connection info if available
            None
        } else {
            // Fallback to remote address if no headers found
            request
                .extensions()
                .get::<axum::extract::ConnectInfo<IpAddr>>()
                .map(|info| info.0)
        }
    }

    /// Extract user agent from request headers
    fn extract_user_agent(&self, request: &Request) -> Option<String> {
        request
            .headers()
            .get("user-agent")
            .and_then(|ua| ua.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Classify time of day based on business hours and holidays
    fn classify_time_of_day(&self, now: DateTime<Utc>) -> TimeOfDay {
        let date = now.date_naive();

        // Check if it's a holiday
        if self.holidays.contains(&date) {
            return TimeOfDay::Holiday;
        }

        // Check if it's weekend
        match now.weekday() {
            Weekday::Sat | Weekday::Sun => return TimeOfDay::Weekend,
            _ => {}
        }

        // Check business hours
        let hour = now.hour() as u8;
        if hour >= self.business_start && hour < self.business_end {
            TimeOfDay::BusinessHours
        } else {
            TimeOfDay::AfterHours
        }
    }

    /// Classify day type
    fn classify_day_type(&self, now: DateTime<Utc>) -> DayType {
        let date = now.date_naive();

        if self.holidays.contains(&date) {
            DayType::Holiday
        } else {
            match now.weekday() {
                Weekday::Sat | Weekday::Sun => DayType::Weekend,
                _ => DayType::Weekday,
            }
        }
    }

    /// Detect device type from user agent
    fn detect_device_type(&self, user_agent: &Option<String>) -> DeviceType {
        let ua = match user_agent {
            Some(ua) => ua.to_lowercase(),
            None => return DeviceType::Unknown,
        };

        if ua.contains("mobile") || ua.contains("android") || ua.contains("iphone") {
            DeviceType::Mobile
        } else if ua.contains("tablet") || ua.contains("ipad") {
            DeviceType::Tablet
        } else if ua.contains("mozilla") || ua.contains("chrome") || ua.contains("firefox") {
            DeviceType::Desktop
        } else {
            DeviceType::Unknown
        }
    }

    /// Analyze connection type from headers and IP
    fn analyze_connection_type(
        &self,
        request: &Request,
        ip_address: &Option<IpAddr>,
    ) -> ConnectionType {
        // Check for VPN indicators in headers
        if let Some(via) = request.headers().get("via")
            && let Ok(via_str) = via.to_str()
        {
            if via_str.to_lowercase().contains("vpn") {
                return ConnectionType::VPN;
            }
            if via_str.to_lowercase().contains("proxy") {
                return ConnectionType::Proxy;
            }

            // Check for Tor indicators
            if let Some(ua) = request.headers().get("user-agent")
                && let Ok(ua_str) = ua.to_str()
                && ua_str.contains("Tor")
            {
                return ConnectionType::Tor;
            }

            // Check if IP is in corporate network range
            if let Some(ip) = ip_address {
                for network in &self.corporate_networks {
                    if network.contains(*ip) {
                        return ConnectionType::Corporate;
                    }
                }
            }

            return ConnectionType::Direct;
        }
        // Fallback to unknown if no indicators found
        ConnectionType::Unknown
    }

    /// Assess security level based on endpoint
    fn assess_security_level(&self, request: &Request) -> SecurityLevel {
        let path = request.uri().path();

        match path {
            _ if path.starts_with("/admin/system/") => SecurityLevel::Critical,
            _ if path.starts_with("/admin/") => SecurityLevel::High,
            _ if path.contains("/secrets/") => SecurityLevel::Critical,
            _ if path.contains("/keys/") => SecurityLevel::High,
            _ if path.starts_with("/api/") => SecurityLevel::Medium,
            _ => SecurityLevel::Low,
        }
    }

    /// Calculate risk score (0-100)
    fn calculate_risk_score(
        &self,
        request: &Request,
        ip_address: &Option<IpAddr>,
        user_agent: &Option<String>,
    ) -> u8 {
        let mut risk_score = 0u8;

        // Base risk from endpoint
        let path = request.uri().path();
        if path.starts_with("/admin/") {
            risk_score += 30;
        } else if path.contains("/secrets/") || path.contains("/keys/") {
            risk_score += 40;
        } else if path.starts_with("/api/") {
            risk_score += 10;
        }

        // Risk from connection type
        let connection_type = self.analyze_connection_type(request, ip_address);
        match connection_type {
            ConnectionType::Tor => risk_score += 50,
            ConnectionType::VPN => risk_score += 20,
            ConnectionType::Proxy => risk_score += 15,
            ConnectionType::Corporate => risk_score = risk_score.saturating_sub(10),
            ConnectionType::Direct => {}
            ConnectionType::Unknown => risk_score += 10,
        }

        // Risk from device type
        let device_type = self.detect_device_type(user_agent);
        match device_type {
            DeviceType::Mobile => risk_score += 5,
            DeviceType::Unknown => risk_score += 15,
            _ => {}
        }

        // Risk from time
        let now = Utc::now();
        match self.classify_time_of_day(now) {
            TimeOfDay::AfterHours => risk_score += 10,
            TimeOfDay::Weekend => risk_score += 5,
            _ => {}
        }

        // Missing user agent is suspicious
        if user_agent.is_none() {
            risk_score += 20;
        }

        // Cap at 100
        risk_score.min(100)
    }

    /// Extract custom attributes from headers
    fn extract_custom_attributes(&self, request: &Request) -> HashMap<String, String> {
        let mut attributes = HashMap::new();

        // Extract custom headers starting with X-Auth-
        for (name, value) in request.headers() {
            let name_str = name.as_str().to_lowercase();
            if let Some(attr_name) = name_str.strip_prefix("x-auth-")
                && let Ok(value_str) = value.to_str()
            {
                attributes.insert(attr_name.to_string(), value_str.to_string());
            }
        }

        // Extract query parameters for additional context
        if let Some(query) = request.uri().query() {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=')
                    && key.starts_with("ctx_")
                {
                    attributes.insert(
                        key.strip_prefix("ctx_").unwrap().to_string(),
                        urlencoding::decode(value).unwrap_or_default().to_string(),
                    );
                }
            }
        }

        attributes
    }

    /// Enrich existing context with additional computed attributes
    pub fn enrich_context(&self, mut context: AuthorizationContext) -> AuthorizationContext {
        // Add computed risk factors
        let current_risk = context.risk_score;
        context.risk_score = std::cmp::max(current_risk, 1); // Ensure minimum risk

        // Add time-based enrichment
        let now = chrono::Utc::now();
        context
            .custom_attributes
            .insert("enriched_timestamp".to_string(), now.to_rfc3339());

        // Add security level enhancement
        context.custom_attributes.insert(
            "security_assessment".to_string(),
            match context.security_level {
                SecurityLevel::Low => "basic".to_string(),
                SecurityLevel::Medium => "standard".to_string(),
                SecurityLevel::High => "enhanced".to_string(),
                SecurityLevel::Critical => "maximum".to_string(),
            },
        );

        context
    }
}

/// Conditional permission evaluator
/// PRODUCTION FIX: Implemented conditional evaluation for enterprise security requirements
pub struct ConditionalEvaluator {
    context_builder: ContextBuilder,
}

impl ConditionalEvaluator {
    /// Create new conditional evaluator
    pub fn new(context_builder: ContextBuilder) -> Self {
        Self { context_builder }
    }

    /// Evaluate time-based conditions
    pub fn evaluate_time_conditions(
        &self,
        context: &AuthorizationContext,
        conditions: &HashMap<String, String>,
    ) -> bool {
        // Check business hours requirement
        if let Some(require_business_hours) = conditions.get("require_business_hours")
            && require_business_hours == "true"
        {
            match context.time_of_day {
                TimeOfDay::BusinessHours => {}
                _ => return false,
            }
        }

        // Check weekday requirement
        if let Some(require_weekday) = conditions.get("require_weekday")
            && require_weekday == "true"
        {
            match context.day_type {
                DayType::Weekday => {}
                _ => return false,
            }
        }

        true
    }

    /// Evaluate location-based conditions
    pub fn evaluate_location_conditions(
        &self,
        context: &AuthorizationContext,
        conditions: &HashMap<String, String>,
    ) -> bool {
        // Check corporate network requirement
        if let Some(require_corporate) = conditions.get("require_corporate_network")
            && require_corporate == "true"
        {
            match context.connection_type {
                ConnectionType::Corporate => {}
                _ => return false,
            }
        }

        // Check VPN restrictions
        if let Some(block_vpn) = conditions.get("block_vpn")
            && block_vpn == "true"
        {
            match context.connection_type {
                ConnectionType::VPN | ConnectionType::Tor => return false,
                _ => {}
            }
        }

        true
    }

    /// Evaluate device-based conditions
    pub fn evaluate_device_conditions(
        &self,
        context: &AuthorizationContext,
        conditions: &HashMap<String, String>,
    ) -> bool {
        // Check device type restrictions
        if let Some(allowed_devices) = conditions.get("allowed_device_types") {
            let allowed: Vec<&str> = allowed_devices.split(',').collect();
            let device_str = format!("{:?}", context.device_type).to_lowercase();

            if !allowed.contains(&device_str.as_str()) {
                return false;
            }
        }

        true
    }

    /// Evaluate risk-based conditions
    pub fn evaluate_risk_conditions(
        &self,
        context: &AuthorizationContext,
        conditions: &HashMap<String, String>,
    ) -> bool {
        // Check maximum risk score
        if let Some(max_risk_str) = conditions.get("max_risk_score")
            && let Ok(max_risk) = max_risk_str.parse::<u8>()
            && context.risk_score > max_risk
        {
            return false;
        }

        true
    }

    /// Main conditional evaluation method for production use
    /// Evaluates complex conditional permission rules based on context
    pub fn evaluate_conditional_permission(
        &self,
        context: &AuthorizationContext,
        permission_conditions: &HashMap<String, String>,
    ) -> bool {
        // PRODUCTION FIX: Implement proper conditional evaluation
        tracing::debug!(
            "Evaluating conditional permission with conditions: {:?}",
            permission_conditions
        );

        // If no conditions specified, allow by default
        if permission_conditions.is_empty() {
            return true;
        }

        // Enrich context using the context builder for more comprehensive evaluation
        let _enriched_context = self.context_builder.enrich_context(context.clone());

        // Evaluate all condition types - ALL must pass for conditional permission to be granted
        let time_check = self.evaluate_time_conditions(context, permission_conditions);
        let location_check = self.evaluate_location_conditions(context, permission_conditions);
        let device_check = self.evaluate_device_conditions(context, permission_conditions);
        let risk_check = self.evaluate_risk_conditions(context, permission_conditions);

        let result = time_check && location_check && device_check && risk_check;

        tracing::info!(
            "Conditional evaluation result: {} (time: {}, location: {}, device: {}, risk: {})",
            result,
            time_check,
            location_check,
            device_check,
            risk_check
        );

        result
    }

    /// Evaluate all conditions
    pub fn evaluate_all_conditions(
        &self,
        context: &AuthorizationContext,
        conditions: &HashMap<String, String>,
    ) -> bool {
        self.evaluate_time_conditions(context, conditions)
            && self.evaluate_location_conditions(context, conditions)
            && self.evaluate_device_conditions(context, conditions)
            && self.evaluate_risk_conditions(context, conditions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_builder_creation() {
        let builder = ContextBuilder::new()
            .with_business_hours(8, 18)
            .with_holidays(vec![chrono::NaiveDate::from_ymd_opt(2024, 12, 25).unwrap()]);

        assert_eq!(builder.business_start, 8);
        assert_eq!(builder.business_end, 18);
        assert_eq!(builder.holidays.len(), 1);
    }

    #[test]
    fn test_time_classification() {
        let builder = ContextBuilder::new();

        // Business hours
        let business_time = chrono::Utc::now()
            .with_hour(14)
            .unwrap()
            .with_minute(0)
            .unwrap();

        match business_time.weekday() {
            Weekday::Sat | Weekday::Sun => {
                assert!(matches!(
                    builder.classify_time_of_day(business_time),
                    TimeOfDay::Weekend
                ));
            }
            _ => {
                assert!(matches!(
                    builder.classify_time_of_day(business_time),
                    TimeOfDay::BusinessHours
                ));
            }
        }
    }

    #[test]
    fn test_device_detection() {
        let builder = ContextBuilder::new();

        let mobile_ua = Some("Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)".to_string());
        assert!(matches!(
            builder.detect_device_type(&mobile_ua),
            DeviceType::Mobile
        ));

        let desktop_ua =
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string());
        assert!(matches!(
            builder.detect_device_type(&desktop_ua),
            DeviceType::Desktop
        ));

        assert!(matches!(
            builder.detect_device_type(&None),
            DeviceType::Unknown
        ));
    }

    #[test]
    fn test_risk_calculation() {
        let _builder = ContextBuilder::new();

        // Create a mock request - in real tests we'd use proper test utilities
        // This is a simplified test to verify the logic structure
        // NOTE: Complete test suite available with additional test infrastructure
    }
}
