//! The client address that authorization policies see is the connection's peer address;
//! forwarding headers are believed only from configured trusted proxies.

#[cfg(all(test, feature = "enhanced-rbac"))]
mod abac_client_ip_tests {
    use auth_framework::authorization_enhanced::ContextBuilder;
    use auth_framework::tokens::AuthToken;
    use axum::extract::{ConnectInfo, Request};
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    fn request(peer: Option<&str>, headers: &[(&str, &str)]) -> Request {
        let mut b = axum::http::Request::builder().uri("/api/things");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(axum::body::Body::empty()).unwrap();
        if let Some(peer) = peer {
            let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        req
    }

    fn ip_seen(builder: &ContextBuilder, req: &Request) -> Option<IpAddr> {
        let token = AuthToken::new("user_1", "tok", Duration::from_secs(60), "test");
        builder.build_context(req, &token).ip_address
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forwarding_headers_from_an_untrusted_peer_do_not_change_the_address() {
        let req = request(
            Some("198.51.100.9"),
            &[
                ("x-forwarded-for", "10.0.0.5"),
                ("x-real-ip", "192.168.1.1"),
            ],
        );
        assert_eq!(
            ip_seen(&ContextBuilder::new(), &req),
            Some(ip("198.51.100.9"))
        );
    }

    #[test]
    fn a_trusted_proxy_is_believed_from_the_right() {
        let builder = ContextBuilder::new().with_trusted_proxies(vec![ip("10.0.0.1")]);
        let req = request(
            Some("10.0.0.1"),
            &[("x-forwarded-for", "10.9.9.9, 203.0.113.7")],
        );
        assert_eq!(ip_seen(&builder, &req), Some(ip("203.0.113.7")));
        // ... and headers from anyone else still count for nothing
        let req = request(Some("10.0.0.2"), &[("x-forwarded-for", "203.0.113.7")]);
        assert_eq!(ip_seen(&builder, &req), Some(ip("10.0.0.2")));
    }

    #[test]
    fn without_a_peer_address_there_is_no_client_address() {
        let req = request(None, &[("x-forwarded-for", "10.0.0.5")]);
        assert_eq!(ip_seen(&ContextBuilder::new(), &req), None);
    }
}
