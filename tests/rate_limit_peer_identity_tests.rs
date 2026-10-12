//! The request rate limiter identifies a client by the connection's peer address, and
//! trusts `X-Forwarded-For` only when the peer is a configured trusted proxy.

#[cfg(all(test, feature = "api-server"))]
mod rate_limit_peer_identity_tests {
    use auth_framework::api::{ApiServer, server::ApiServerConfig};
    use auth_framework::{AuthConfig, AuthFramework};
    use axum::Router;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn config() -> ApiServerConfig {
        ApiServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            cors: auth_framework::CorsConfig {
                enabled: true,
                allowed_origins: vec!["http://localhost:3000".to_string()],
                ..auth_framework::CorsConfig::default()
            },
            max_body_size: 1024 * 1024,
            enable_tracing: false,
        }
    }

    async fn router(trusted: Vec<IpAddr>) -> Router {
        let cfg = AuthConfig::new()
            .secret("test_rate_limit_secret_key_that_is_long_enough_for_jwt".to_string());
        let mut f = AuthFramework::new(cfg);
        f.initialize().await.unwrap();
        ApiServer::with_config(Arc::new(f), config())
            .with_trusted_proxies(trusted)
            .build_router()
            .await
            .unwrap()
    }

    /// POST /auth/login from `peer`, optionally with an X-Forwarded-For header; returns the status.
    async fn hit(app: &Router, peer: &str, xff: Option<&str>) -> u16 {
        let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json");
        if let Some(xff) = xff {
            req = req.header("x-forwarded-for", xff);
        }
        let mut req = req
            .body(Body::from(r#"{"username":"nobody","password":"x"}"#))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        app.clone().oneshot(req).await.unwrap().status().as_u16()
    }

    async fn limited(app: &Router, peer: &str, xff: impl Fn(u32) -> Option<String>, n: u32) -> u32 {
        let mut limited = 0;
        for i in 0..n {
            if hit(app, peer, xff(i).as_deref()).await == 429 {
                limited += 1;
            }
        }
        limited
    }

    #[tokio::test]
    async fn rotating_forwarded_for_from_an_untrusted_peer_is_still_limited() {
        let app = router(vec![]).await;
        let limited = limited(
            &app,
            "198.51.100.9",
            |i| Some(format!("10.9.{}.{}", i / 250, i % 250 + 1)),
            400,
        )
        .await;
        assert!(
            limited >= 250,
            "only {limited}/400 were limited: the header chose the bucket"
        );
    }

    #[tokio::test]
    async fn each_peer_has_its_own_bucket() {
        let app = router(vec![]).await;
        assert!(limited(&app, "198.51.100.9", |_| None, 200).await > 0);
        assert_eq!(
            hit(&app, "198.51.100.9", None).await,
            429,
            "exhausted peer stays limited"
        );
        assert_ne!(
            hit(&app, "198.51.100.10", None).await,
            429,
            "a different peer must not share the exhausted peer's bucket"
        );
    }

    #[tokio::test]
    async fn behind_a_trusted_proxy_clients_are_told_apart_by_forwarded_for() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let app = router(vec![proxy]).await;

        // The proxy appends the real client address; whatever the client put before it is ignored.
        let x = limited(
            &app,
            "10.0.0.1",
            |i| Some(format!("9.9.{}.{}, 203.0.113.7", i / 250, i % 250 + 1)),
            200,
        )
        .await;
        assert!(
            x > 0,
            "client X must be limited despite rotating the spoofable left entries"
        );

        // Another client behind the same proxy is unaffected.
        assert_ne!(hit(&app, "10.0.0.1", Some("203.0.113.8")).await, 429);
    }

    #[tokio::test]
    async fn an_unparsable_forwarded_for_from_a_trusted_proxy_falls_back_to_the_proxy() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let app = router(vec![proxy]).await;
        let n = limited(&app, "10.0.0.1", |i| Some(format!("not-an-ip-{i}")), 200).await;
        assert!(n > 0, "garbage headers must not create fresh buckets");
    }
}
