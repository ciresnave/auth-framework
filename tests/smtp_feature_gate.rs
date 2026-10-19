//! SMTP delivery (the `lettre` dependency) is opt-in through the `smtp` feature, so a consumer that
//! only needs TOTP or tokens does not compile an SMTP stack.

#[test]
fn lettre_is_optional_and_not_in_default_features() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    let manifest: toml::Value = toml::from_str(&text).expect("parse Cargo.toml");
    let deps = &manifest["dependencies"];

    // Control: a dependency known to be optional reads as optional, so the check below can say "true".
    assert_eq!(deps["ldap3"]["optional"].as_bool(), Some(true));
    assert_eq!(
        deps["lettre"]["optional"].as_bool(),
        Some(true),
        "lettre must be an optional dependency"
    );

    let features = &manifest["features"];
    let smtp: Vec<&str> = features["smtp"]
        .as_array()
        .expect("an `smtp` feature exists")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        smtp.contains(&"dep:lettre"),
        "smtp enables lettre: {smtp:?}"
    );

    // Nothing reachable from `default` may switch it on.
    let mut stack: Vec<String> = features["default"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let mut seen = std::collections::HashSet::new();
    while let Some(f) = stack.pop() {
        if !seen.insert(f.clone()) {
            continue;
        }
        assert_ne!(f, "smtp", "a default feature enables `smtp`");
        assert_ne!(f, "dep:lettre", "a default feature enables lettre");
        if let Some(sub) = features.get(&f).and_then(|v| v.as_array()) {
            stack.extend(sub.iter().filter_map(|v| v.as_str()).map(String::from));
        }
    }
    assert!(
        seen.contains("enhanced-rbac"),
        "walked the default set: {seen:?}"
    );
}

#[cfg(not(feature = "smtp"))]
mod without_the_feature {
    use auth_framework::auth_modular::mfa::EmailManager;
    use auth_framework::auth_modular::mfa::email::{
        EmailProvider, EmailProviderConfig, ProviderConfig,
    };
    use auth_framework::prelude::{AuthStorage, MemoryStorage};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    async fn manager(config: EmailProviderConfig) -> EmailManager {
        let storage = Arc::new(MemoryStorage::new());
        storage
            .store_kv("user:u1:email", b"u1@example.com", None)
            .await
            .unwrap();
        EmailManager::new_with_config(storage, config)
    }

    #[tokio::test]
    async fn smtp_provider_says_the_feature_is_missing() {
        let m = manager(EmailProviderConfig {
            provider: EmailProvider::Smtp,
            from_email: "a@example.com".into(),
            from_name: None,
            provider_config: ProviderConfig::Smtp {
                host: "127.0.0.1".into(),
                port: 1,
                username: "u".into(),
                password: Zeroizing::new("p".into()),
                use_tls: false,
            },
        })
        .await;
        let err = m
            .send_code("u1", "123456")
            .await
            .expect_err("no SMTP stack");
        assert!(err.to_string().contains("`smtp` feature"), "{err}");
    }

    /// Control: the same user and address work with a provider that needs no feature.
    #[tokio::test]
    async fn development_provider_still_sends() {
        let m = manager(EmailProviderConfig::default()).await;
        m.send_code("u1", "123456").await.expect("development send");
    }
}
