//! YAML support (serde-saphyr): configuration files in YAML load and save, and a malformed file
//! is reported as an error, not accepted.

use auth_framework::deployment::config::{AppConfig, ConfigManager};

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn a_yaml_config_round_trips_through_the_config_manager() {
    let dir = dir();
    let defaults = AppConfig::default();
    let source = dir.path().join("in.yaml");
    std::fs::write(&source, serde_saphyr::to_string(&defaults).unwrap()).unwrap();

    let mut manager = ConfigManager::new();
    manager.load_from_file(&source).expect("YAML config loads");
    assert_eq!(
        serde_json::to_value(manager.get_config()).unwrap(),
        serde_json::to_value(&defaults).unwrap()
    );

    // The manager now holds the YAML format: saving writes YAML that reads back identically.
    let saved = dir.path().join("out.yaml");
    manager.save_to_file(&saved).unwrap();
    let mut again = ConfigManager::new();
    again.load_from_file(&saved).unwrap();
    assert_eq!(
        serde_json::to_value(again.get_config()).unwrap(),
        serde_json::to_value(&defaults).unwrap()
    );
}

#[test]
fn a_malformed_yaml_config_is_refused() {
    let dir = dir();
    let path = dir.path().join("bad.yaml");
    std::fs::write(&path, "server: [unterminated\n  port: : :\n").unwrap();
    let mut manager = ConfigManager::new();
    assert!(manager.load_from_file(&path).is_err());
}
