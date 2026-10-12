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
    fn an_ipv4_mapped_peer_and_forwarded_entry_are_canonical() {
        let builder = ContextBuilder::new().with_trusted_proxies(vec![ip("10.0.0.1")]);
        let req = request(Some("198.51.100.9"), &[]);
        assert_eq!(ip_seen(&builder, &req), Some(ip("198.51.100.9")));
        let mut mapped = request(None, &[("x-forwarded-for", "::ffff:203.0.113.7")]);
        let peer: SocketAddr = "[::ffff:10.0.0.1]:40000".parse().unwrap();
        mapped.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(ip_seen(&builder, &mapped), Some(ip("203.0.113.7")));
    }

    #[test]
    fn a_trusted_proxy_that_forwards_nothing_usable_is_reported_as_the_client() {
        let builder = ContextBuilder::new().with_trusted_proxies(vec![ip("10.0.0.1")]);
        for xff in [None, Some("unknown"), Some("not an address"), Some("")] {
            let headers: Vec<(&str, &str)> =
                xff.map(|v| ("x-forwarded-for", v)).into_iter().collect();
            let req = request(Some("10.0.0.1"), &headers);
            assert_eq!(ip_seen(&builder, &req), Some(ip("10.0.0.1")), "xff {xff:?}");
        }
    }

    #[test]
    fn several_forwarded_for_lines_are_read_in_order_and_an_unreadable_one_fails_closed() {
        let builder = ContextBuilder::new().with_trusted_proxies(vec![ip("10.0.0.1")]);
        let mut req = request(
            Some("10.0.0.1"),
            &[
                ("x-forwarded-for", "6.6.6.6"),
                ("x-forwarded-for", "203.0.113.7"),
            ],
        );
        assert_eq!(ip_seen(&builder, &req), Some(ip("203.0.113.7")));

        // a line that is not text: nothing is believed, the proxy stays the client
        req.headers_mut().append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(ip_seen(&builder, &req), Some(ip("10.0.0.1")));
    }

    #[test]
    fn without_a_peer_address_there_is_no_client_address() {
        let req = request(None, &[("x-forwarded-for", "10.0.0.5")]);
        assert_eq!(ip_seen(&ContextBuilder::new(), &req), None);
    }

    // ---- connection type: derived from the peer address, not from what the client says ----

    fn connection(
        builder: &ContextBuilder,
        req: &Request,
    ) -> auth_framework::authorization_enhanced::ConnectionType {
        let token = AuthToken::new("user_1", "tok", Duration::from_secs(60), "test");
        builder.build_context(req, &token).connection_type
    }

    fn corporate() -> ContextBuilder {
        ContextBuilder::new().with_corporate_networks(vec!["10.0.0.0/8".parse().unwrap()])
    }

    #[test]
    fn a_corporate_peer_is_corporate_with_or_without_a_via_header() {
        use auth_framework::authorization_enhanced::ConnectionType;
        let b = corporate();
        assert!(matches!(
            connection(&b, &request(Some("10.1.2.3"), &[])),
            ConnectionType::Corporate
        ));
        assert!(matches!(
            connection(&b, &request(Some("10.1.2.3"), &[("via", "1.1 whatever")])),
            ConnectionType::Corporate
        ));
    }

    #[test]
    fn claiming_a_via_header_does_not_lower_the_risk_of_an_outside_peer() {
        use auth_framework::authorization_enhanced::ConnectionType;
        let b = corporate();
        let outside = request(Some("198.51.100.9"), &[]);
        let with_via = request(Some("198.51.100.9"), &[("via", "1.1 whatever")]);
        assert!(matches!(connection(&b, &outside), ConnectionType::Direct));
        assert!(
            matches!(connection(&b, &with_via), ConnectionType::Direct),
            "the header must change nothing"
        );
        // no peer address at all: nothing is known
        assert!(matches!(
            connection(&b, &request(None, &[("via", "1.1 x")])),
            ConnectionType::Unknown
        ));
        assert!(matches!(
            connection(&b, &request(None, &[])),
            ConnectionType::Unknown
        ));
    }

    #[test]
    fn the_tor_check_does_not_depend_on_a_via_header() {
        use auth_framework::authorization_enhanced::ConnectionType;
        let b = corporate();
        let req = request(
            Some("198.51.100.9"),
            &[("user-agent", "Mozilla/5.0 Tor Browser")],
        );
        assert!(matches!(connection(&b, &req), ConnectionType::Tor));
    }
}
