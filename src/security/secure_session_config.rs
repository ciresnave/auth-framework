//! Enhanced Session Security Configuration
//!
//! This module provides configurable session security policies to prevent
//! session hijacking and implement defense-in-depth strategies.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// Security configuration for session management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecurityConfig {
    /// Whether to enforce strict IP consistency for sessions
    pub enforce_ip_consistency: bool,

    /// Allow IP changes within the same subnet/range
    pub allow_ip_range_changes: bool,

    /// Maximum allowed User-Agent deviation (0.0 = exact match, 1.0 = any)
    pub max_user_agent_deviation: f32,

    /// Whether to automatically rotate session IDs on security events
    pub auto_rotate_on_suspicious_activity: bool,

    /// Maximum session lifetime before forced re-authentication
    pub max_session_lifetime_hours: u64,

    /// Require periodic session validation
    pub require_periodic_validation: bool,

    /// Period between validation checks (in minutes)
    pub validation_period_minutes: u64,

    /// Enable device fingerprinting for additional security
    pub enable_device_fingerprinting: bool,

    /// Maximum number of concurrent sessions per user
    pub max_concurrent_sessions: Option<usize>,

    /// Geographic location validation
    pub enable_geo_validation: bool,

    /// Maximum allowed distance for geographic changes (in km)
    pub max_geo_distance_km: Option<f64>,
}

impl Default for SessionSecurityConfig {
    fn default() -> Self {
        Self {
            enforce_ip_consistency: false, // Default to warn-only for compatibility
            allow_ip_range_changes: true,
            max_user_agent_deviation: 0.1, // Allow minor browser updates
            auto_rotate_on_suspicious_activity: true,
            max_session_lifetime_hours: 24,
            require_periodic_validation: true,
            validation_period_minutes: 30,
            enable_device_fingerprinting: false, // Privacy consideration
            max_concurrent_sessions: Some(5),
            enable_geo_validation: false, // May require external service
            max_geo_distance_km: Some(1000.0), // 1000km threshold
        }
    }
}

impl SessionSecurityConfig {
    /// Create a strict security configuration for high-security environments
    pub fn strict() -> Self {
        Self {
            enforce_ip_consistency: true,
            allow_ip_range_changes: false,
            max_user_agent_deviation: 0.05, // Very strict UA validation
            auto_rotate_on_suspicious_activity: true,
            max_session_lifetime_hours: 8, // 8-hour workday
            require_periodic_validation: true,
            validation_period_minutes: 15, // More frequent validation
            enable_device_fingerprinting: true,
            max_concurrent_sessions: Some(2), // Limit concurrent sessions
            enable_geo_validation: true,
            max_geo_distance_km: Some(100.0), // 100km threshold
        }
    }

    /// Create a lenient configuration for development/testing
    pub fn lenient() -> Self {
        Self {
            enforce_ip_consistency: false,
            allow_ip_range_changes: true,
            max_user_agent_deviation: 0.5, // Allow significant UA changes
            auto_rotate_on_suspicious_activity: false,
            max_session_lifetime_hours: 72, // 3 days
            require_periodic_validation: false,
            validation_period_minutes: 120, // 2 hours
            enable_device_fingerprinting: false,
            max_concurrent_sessions: Some(10),
            enable_geo_validation: false,
            max_geo_distance_km: None, // No geo restrictions
        }
    }

    /// Create a balanced configuration for production use
    pub fn balanced() -> Self {
        Self::default()
    }
}

/// Security validation result for session checks
#[derive(Debug, Clone, PartialEq)]
pub enum SessionValidationResult {
    /// Session is valid and secure
    Valid,
    /// Session is valid but has security warnings
    ValidWithWarnings(Vec<SecurityWarning>),
    /// Session is suspicious and should be investigated
    Suspicious(Vec<SecurityThreat>),
    /// Session is compromised and should be terminated
    Compromised(Vec<SecurityThreat>),
}

/// Security warning indicators
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityWarning {
    /// IP address changed but within allowed parameters
    IPAddressChanged {
        original: String,
        current: String,
        subnet_match: bool,
    },
    /// User agent changed slightly
    UserAgentChanged {
        original: String,
        current: String,
        similarity: f32,
    },
    /// Session is approaching maximum lifetime
    SessionNearExpiry { hours_remaining: u64 },
    /// Unusual activity pattern detected
    UnusualActivity { description: String },
}

/// Security threat indicators
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityThreat {
    /// IP address changed beyond allowed parameters
    IPAddressCompromised {
        original: String,
        current: String,
        distance_km: Option<f64>,
    },
    /// User agent changed significantly
    UserAgentCompromised {
        original: String,
        current: String,
        similarity: f32,
    },
    /// Session exceeded maximum lifetime
    SessionExpired { hours_exceeded: u64 },
    /// Device fingerprint mismatch
    DeviceFingerprintMismatch { original: String, current: String },
    /// Geographic location impossible
    ImpossibleGeography {
        original_location: Option<String>,
        current_location: Option<String>,
        distance_km: f64,
        time_seconds: u64,
    },
    /// Too many concurrent sessions
    ConcurrentSessionLimitExceeded {
        current_count: usize,
        max_allowed: usize,
    },
}

/// IP address utilities for session security
pub struct IPSecurityUtils;

impl IPSecurityUtils {
    /// Check if two IP addresses are in the same subnet
    pub fn same_subnet(ip1: &str, ip2: &str, prefix_len: u8) -> bool {
        let Ok(addr1) = IpAddr::from_str(ip1) else {
            return false;
        };
        let Ok(addr2) = IpAddr::from_str(ip2) else {
            return false;
        };

        match (addr1, addr2) {
            (IpAddr::V4(a1), IpAddr::V4(a2)) => Self::same_ipv4_subnet(a1, a2, prefix_len),
            (IpAddr::V6(a1), IpAddr::V6(a2)) => Self::same_ipv6_subnet(a1, a2, prefix_len),
            _ => false, // Different IP versions
        }
    }

    fn same_ipv4_subnet(ip1: std::net::Ipv4Addr, ip2: std::net::Ipv4Addr, prefix_len: u8) -> bool {
        if prefix_len > 32 {
            return false;
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };

        let ip1_int = u32::from(ip1);
        let ip2_int = u32::from(ip2);

        (ip1_int & mask) == (ip2_int & mask)
    }

    fn same_ipv6_subnet(ip1: std::net::Ipv6Addr, ip2: std::net::Ipv6Addr, prefix_len: u8) -> bool {
        if prefix_len > 128 {
            return false;
        }

        let ip1_bytes = ip1.octets();
        let ip2_bytes = ip2.octets();

        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        // Check full bytes
        if ip1_bytes[..full_bytes] != ip2_bytes[..full_bytes] {
            return false;
        }

        // Check remaining bits if any
        if remaining_bits > 0 && full_bytes < 16 {
            let mask = !((1u8 << (8 - remaining_bits)) - 1);
            if (ip1_bytes[full_bytes] & mask) != (ip2_bytes[full_bytes] & mask) {
                return false;
            }
        }

        true
    }

    /// Estimate geographic distance between IP addresses
    /// Uses simplified geolocation based on IP prefix patterns
    pub fn estimate_distance_km(ip1: &str, ip2: &str) -> Option<f64> {
        // Extract country/region indicators from IP patterns
        let location1 = Self::estimate_ip_location(ip1)?;
        let location2 = Self::estimate_ip_location(ip2)?;

        // Calculate approximate distance using haversine formula
        Some(Self::calculate_haversine_distance(location1, location2))
    }

    /// Estimate approximate location from IP address patterns
    fn estimate_ip_location(ip: &str) -> Option<(f64, f64)> {
        // Basic geolocation based on IP ranges (simplified)
        if ip.starts_with("192.168.") || ip.starts_with("10.") || ip.starts_with("172.") {
            // Private/local networks - assume same location
            Some((0.0, 0.0))
        } else if ip.starts_with("8.8.") || ip.starts_with("1.1.") {
            // Public DNS servers - US approximate
            Some((39.0458, -76.6413)) // US East Coast
        } else {
            // Real MaxMind GeoIP2 integration for accurate geolocation
            Self::lookup_maxmind_coordinates(ip).or_else(|| {
                // Default fallback coordinates (NYC)
                Some((40.7128, -74.0060))
            })
        }
    }

    /// Calculate distance between two coordinates using haversine formula
    fn calculate_haversine_distance(coord1: (f64, f64), coord2: (f64, f64)) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let (lat1, lon1) = coord1;
        let (lat2, lon2) = coord2;

        let lat1_rad = lat1.to_radians();
        let lat2_rad = lat2.to_radians();
        let delta_lat = (lat2 - lat1).to_radians();
        let delta_lon = (lon2 - lon1).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();

        EARTH_RADIUS_KM * c
    }

    /// Lookup IP coordinates using MaxMind GeoIP2 database
    fn lookup_maxmind_coordinates(ip: &str) -> Option<(f64, f64)> {
        use std::net::IpAddr;
        use std::path::Path;
        use std::str::FromStr;

        // Path to MaxMind GeoLite2-City.mmdb (configurable via environment)
        let db_path =
            std::env::var("MAXMIND_DB_PATH").unwrap_or_else(|_| "GeoLite2-City.mmdb".to_string());

        if !Path::new(&db_path).exists() {
            log::debug!(
                "MaxMind database not found at {}, using fallback geolocation",
                db_path
            );
            return None;
        }

        // Parse IP address
        let ip_addr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        match maxminddb::Reader::open_readfile(&db_path) {
            Ok(reader) => match reader.lookup::<maxminddb::geoip2::City>(ip_addr) {
                Ok(city) => {
                    if let Some(location) = city.location
                        && let (Some(lat), Some(lon)) = (location.latitude, location.longitude) {
                            log::debug!("MaxMind lookup for {}: lat={}, lon={}", ip, lat, lon);
                            return Some((lat, lon));
                        }
                    log::debug!("MaxMind lookup for {} returned no coordinates", ip);
                    None
                }
                Err(e) => {
                    log::debug!("MaxMind lookup failed for {}: {}", ip, e);
                    None
                }
            },
            Err(e) => {
                log::warn!("Failed to open MaxMind database: {}", e);
                None
            }
        }
    }
}

/// User-Agent similarity calculation utilities
pub struct UserAgentUtils;

impl UserAgentUtils {
    /// Calculate similarity between two user agent strings
    /// Returns value between 0.0 (completely different) and 1.0 (identical)
    pub fn calculate_similarity(ua1: &str, ua2: &str) -> f32 {
        if ua1 == ua2 {
            return 1.0;
        }

        // Use character-level similarity for better results
        let len1 = ua1.len();
        let len2 = ua2.len();

        if len1 == 0 && len2 == 0 {
            return 1.0;
        }
        if len1 == 0 || len2 == 0 {
            return 0.0;
        }

        // Simple Levenshtein distance calculation
        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

        for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
            row[0] = i;
        }
        for j in 0..=len2 {
            matrix[0][j] = j;
        }
        let ua1_chars: Vec<char> = ua1.chars().collect();
        let ua2_chars: Vec<char> = ua2.chars().collect();

        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if ua1_chars[i - 1] == ua2_chars[j - 1] {
                    0
                } else {
                    1
                };
                matrix[i][j] = (matrix[i - 1][j] + 1)
                    .min(matrix[i][j - 1] + 1)
                    .min(matrix[i - 1][j - 1] + cost);
            }
        }

        let distance = matrix[len1][len2];
        let max_len = len1.max(len2);

        1.0 - (distance as f32 / max_len as f32)
    }

    /// Check if user agent change is suspicious
    pub fn is_suspicious_change(original: &str, current: &str, threshold: f32) -> bool {
        let similarity = Self::calculate_similarity(original, current);
        similarity < threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_security_config_presets() {
        let strict = SessionSecurityConfig::strict();
        assert!(strict.enforce_ip_consistency);
        assert_eq!(strict.max_session_lifetime_hours, 8);

        let lenient = SessionSecurityConfig::lenient();
        assert!(!lenient.enforce_ip_consistency);
        assert_eq!(lenient.max_session_lifetime_hours, 72);

        let balanced = SessionSecurityConfig::balanced();
        assert!(!balanced.enforce_ip_consistency);
        assert!(balanced.auto_rotate_on_suspicious_activity);
    }

    #[test]
    fn test_ip_subnet_checking() {
        // IPv4 subnet tests
        assert!(IPSecurityUtils::same_subnet(
            "192.168.1.1",
            "192.168.1.2",
            24
        ));
        assert!(!IPSecurityUtils::same_subnet(
            "192.168.1.1",
            "192.168.2.1",
            24
        ));
        assert!(IPSecurityUtils::same_subnet("10.0.0.1", "10.0.0.255", 24));

        // IPv6 subnet tests
        assert!(IPSecurityUtils::same_subnet(
            "2001:db8::1",
            "2001:db8::2",
            64
        ));
        assert!(!IPSecurityUtils::same_subnet(
            "2001:db8::1",
            "2001:db9::1",
            64
        ));
    }

    #[test]
    fn test_user_agent_similarity() {
        let ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.37";
        let ua3 = "Chrome/91.0.4472.124 Safari/537.36";

        // Very similar user agents
        let similarity1 = UserAgentUtils::calculate_similarity(ua1, ua2);
        assert!(similarity1 > 0.8);

        // Different user agents
        let similarity2 = UserAgentUtils::calculate_similarity(ua1, ua3);
        assert!(similarity2 < 0.5);

        // Identical user agents
        let similarity3 = UserAgentUtils::calculate_similarity(ua1, ua1);
        assert_eq!(similarity3, 1.0);
    }

    #[test]
    fn test_suspicious_user_agent_detection() {
        let original = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let minor_change = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.37";
        let major_change = "curl/7.68.0";

        assert!(!UserAgentUtils::is_suspicious_change(
            original,
            minor_change,
            0.8
        ));
        assert!(UserAgentUtils::is_suspicious_change(
            original,
            major_change,
            0.8
        ));
    }

    #[test]
    fn test_security_validation_result_enum() {
        let valid = SessionValidationResult::Valid;
        let suspicious =
            SessionValidationResult::Suspicious(vec![SecurityThreat::IPAddressCompromised {
                original: "192.168.1.1".to_string(),
                current: "10.0.0.1".to_string(),
                distance_km: Some(100.0),
            }]);

        match valid {
            SessionValidationResult::Valid => {
                // Test passed - validation correctly identified as valid
            }
            _ => panic!("Expected valid session validation"),
        }

        match suspicious {
            SessionValidationResult::Suspicious(threats) => {
                assert_eq!(threats.len(), 1);
            }
            _ => panic!("Expected suspicious session validation"),
        }
    }
}


