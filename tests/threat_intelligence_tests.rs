//! Tests for the threat intelligence feed manager.
//!
//! These tests exercise configuration, IP checking, and feed status
//! without making real network requests.

use auth_framework::threat_intelligence::{
    FeedConfig, FeedFormat, FeedType, ThreatFeedManager, ThreatIntelConfig,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tempfile::TempDir;

/// Helper: create a minimal config pointing at a temp directory.
fn test_config(temp_dir: &TempDir) -> ThreatIntelConfig {
    ThreatIntelConfig {
        auto_update_enabled: false,
        update_interval_seconds: 3600,
        feeds_directory: temp_dir.path().to_path_buf(),
        feeds: HashMap::new(),
        download_timeout_seconds: 5,
    }
}

/// Helper: insert a plain-text feed backed by actual file content.
fn add_feed_file(config: &mut ThreatIntelConfig, name: &str, feed_type: FeedType, content: &str) {
    let filename = format!("{name}.txt");
    let path = config.feeds_directory.join(&filename);
    std::fs::write(&path, content).unwrap();

    config.feeds.insert(
        name.to_string(),
        FeedConfig {
            enabled: true,
            feed_type,
            url: String::new(),
            api_key: None,
            headers: HashMap::new(),
            filename,
            format: FeedFormat::PlainText,
            custom_interval_seconds: None,
        },
    );
}

// ─── Default config ──────────────────────────────────────────────────

#[test]
fn default_config_has_expected_feeds() {
    let config = ThreatIntelConfig::default();

    assert!(!config.auto_update_enabled, "auto_update off by default");
    assert_eq!(config.update_interval_seconds, 3600);
    assert!(config.feeds.contains_key("tor_exits"));
    assert!(config.feeds.contains_key("spamhaus_drop"));
    assert!(config.feeds.contains_key("emergingthreats_compromised"));

    // All default feeds are disabled
    for feed in config.feeds.values() {
        assert!(!feed.enabled);
    }
}

#[test]
fn default_config_feed_types() {
    let config = ThreatIntelConfig::default();

    assert!(matches!(
        config.feeds["tor_exits"].feed_type,
        FeedType::TorExitNodes
    ));
    assert!(matches!(
        config.feeds["spamhaus_drop"].feed_type,
        FeedType::MaliciousIPs
    ));
}

// ─── Manager construction ────────────────────────────────────────────

#[test]
fn manager_new_creates_feeds_directory() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.feeds_directory = temp.path().join("nested").join("feeds");

    let manager = ThreatFeedManager::new(config);
    assert!(manager.is_ok());
    assert!(temp.path().join("nested").join("feeds").is_dir());
}

#[tokio::test]
async fn manager_new_async_creates_feeds_directory() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.feeds_directory = temp.path().join("async_feeds");

    let manager = ThreatFeedManager::new_async(config).await;
    assert!(manager.is_ok());
    assert!(temp.path().join("async_feeds").is_dir());
}

// ─── IP matching: exact ──────────────────────────────────────────────

#[test]
fn is_malicious_ip_exact_match() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(
        &mut config,
        "bad_ips",
        FeedType::MaliciousIPs,
        "# comment\n192.168.1.100\n10.0.0.1\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    let hit: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
    let miss: IpAddr = Ipv4Addr::new(192, 168, 1, 101).into();

    assert!(mgr.is_malicious_ip(&hit));
    assert!(!mgr.is_malicious_ip(&miss));
}

#[test]
fn is_malicious_ip_ignores_comments_and_blanks() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(
        &mut config,
        "bad",
        FeedType::MaliciousIPs,
        "# header\n\n  \n10.0.0.5\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
}

// ─── IP matching: CIDR ───────────────────────────────────────────────

#[test]
fn is_malicious_ip_cidr_v4() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(&mut config, "cidr", FeedType::MaliciousIPs, "10.0.0.0/24\n");

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))));
    assert!(!mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))));
}

#[test]
fn is_malicious_ip_cidr_v6() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(&mut config, "cidr6", FeedType::MaliciousIPs, "fd00::/120\n");

    let mgr = ThreatFeedManager::new(config).unwrap();
    let inside: IpAddr = "fd00::1".parse().unwrap();
    let outside: IpAddr = "fd00::1:1".parse().unwrap();
    assert!(mgr.is_malicious_ip(&inside));
    assert!(!mgr.is_malicious_ip(&outside));
}

// ─── Tor exit node detection ─────────────────────────────────────────

#[test]
fn is_tor_exit_detects_listed_ip() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(
        &mut config,
        "tor",
        FeedType::TorExitNodes,
        "198.51.100.7\n203.0.113.42\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(mgr.is_tor_exit(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
    assert!(!mgr.is_tor_exit(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8))));
}

#[test]
fn is_tor_exit_skips_feeds_of_wrong_type() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    // The IP is in a MaliciousIPs feed, not TorExitNodes.
    add_feed_file(
        &mut config,
        "bad_ips",
        FeedType::MaliciousIPs,
        "198.51.100.7\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(!mgr.is_tor_exit(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))));
}

// ─── VPN / Proxy detection ──────────────────────────────────────────

#[test]
fn is_proxy_vpn_detects_listed_ip() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(&mut config, "vpn", FeedType::VpnProxy, "172.16.0.0/12\n");

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(mgr.is_proxy_vpn(&IpAddr::V4(Ipv4Addr::new(172, 20, 5, 1))));
    assert!(!mgr.is_proxy_vpn(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

// ─── Disabled feeds are skipped ──────────────────────────────────────

#[test]
fn disabled_feed_is_not_checked() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(
        &mut config,
        "disabled",
        FeedType::MaliciousIPs,
        "192.0.2.1\n",
    );
    config.feeds.get_mut("disabled").unwrap().enabled = false;

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(!mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
}

// ─── Missing feed file returns false ─────────────────────────────────

#[test]
fn missing_feed_file_returns_false() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    config.feeds.insert(
        "ghost".to_string(),
        FeedConfig {
            enabled: true,
            feed_type: FeedType::MaliciousIPs,
            url: String::new(),
            api_key: None,
            headers: HashMap::new(),
            filename: "does-not-exist.txt".to_string(),
            format: FeedFormat::PlainText,
            custom_interval_seconds: None,
        },
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(!mgr.is_malicious_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
}

// ─── Feed status ─────────────────────────────────────────────────────

#[tokio::test]
async fn feed_status_reports_disabled_and_active() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);

    // One disabled feed
    config.feeds.insert(
        "off".to_string(),
        FeedConfig {
            enabled: false,
            feed_type: FeedType::MaliciousIPs,
            url: String::new(),
            api_key: None,
            headers: HashMap::new(),
            filename: "off.txt".to_string(),
            format: FeedFormat::PlainText,
            custom_interval_seconds: None,
        },
    );

    // One active feed with a file on disk
    add_feed_file(
        &mut config,
        "active_feed",
        FeedType::TorExitNodes,
        "10.0.0.1\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    let statuses = mgr.get_feed_status().await;

    assert!(matches!(
        statuses.get("off"),
        Some(auth_framework::threat_intelligence::FeedStatus::Disabled)
    ));
    assert!(matches!(
        statuses.get("active_feed"),
        Some(auth_framework::threat_intelligence::FeedStatus::Active { .. })
    ));
}

#[tokio::test]
async fn feed_status_reports_not_downloaded() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);

    config.feeds.insert(
        "pending".to_string(),
        FeedConfig {
            enabled: true,
            feed_type: FeedType::MaliciousIPs,
            url: String::new(),
            api_key: None,
            headers: HashMap::new(),
            filename: "not-there.txt".to_string(),
            format: FeedFormat::PlainText,
            custom_interval_seconds: None,
        },
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    let statuses = mgr.get_feed_status().await;

    assert!(matches!(
        statuses.get("pending"),
        Some(auth_framework::threat_intelligence::FeedStatus::NotDownloaded)
    ));
}

// ─── IPv6 exact match ────────────────────────────────────────────────

#[test]
fn ipv6_exact_match() {
    let temp = TempDir::new().unwrap();
    let mut config = test_config(&temp);
    add_feed_file(
        &mut config,
        "v6",
        FeedType::MaliciousIPs,
        "2001:db8::dead:beef\n",
    );

    let mgr = ThreatFeedManager::new(config).unwrap();
    let hit: IpAddr = "2001:db8::dead:beef".parse().unwrap();
    let miss: IpAddr = "2001:db8::dead:beee".parse().unwrap();
    assert!(mgr.is_malicious_ip(&hit));
    assert!(!mgr.is_malicious_ip(&miss));
}

// ─── Start_automated_updates when disabled ───────────────────────────

#[test]
fn start_automated_updates_noop_when_disabled() {
    let temp = TempDir::new().unwrap();
    let config = test_config(&temp);
    let mgr = ThreatFeedManager::new(config).unwrap();
    assert!(mgr.start_automated_updates().is_ok());
}
