// SPDX-License-Identifier: MIT OR Apache-2.0
//! actix-web routes for the GNAP RS-facing API (RFC 9767 section 3): the discovery document,
//! token introspection and resource set registration. All routing, status codes and headers come
//! from [`GnapRsHttp`]; this module only moves a request in and a response out.
//!
//! A body over the payload limit this module configures (one byte past
//! [`MAX_BODY_BYTES`]) is refused by actix itself with 413 before it reaches the handler.
//!
//! ```rust,ignore
//! let http = Arc::new(GnapRsHttp::new(Arc::new(api)));
//! App::new().configure(|cfg| gnap_configure(cfg, http.clone()));
//! ```

use crate::protocols::gnap_as_http::GnapAsHttp;
use crate::protocols::gnap_http::{GnapHttpRequest, GnapHttpResponse, GnapRsHttp, MAX_BODY_BYTES};
use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web};
use std::sync::Arc;

/// Register the discovery and introspection routes, and the registration route when `http`
/// offers registration, at the paths `http` reports.
pub fn gnap_configure(cfg: &mut web::ServiceConfig, http: Arc<GnapRsHttp>) {
    let (discovery, introspection) = {
        let (d, i) = http.paths();
        (d.to_string(), i.to_string())
    };
    let registration = http.registration_path().map(str::to_string);
    cfg.app_data(web::Data::from(http))
        .app_data(web::PayloadConfig::new(MAX_BODY_BYTES + 1))
        .service(web::resource(discovery).route(web::route().to(serve)))
        .service(web::resource(introspection).route(web::route().to(serve)));
    if let Some(path) = registration {
        cfg.service(web::resource(path).route(web::route().to(serve)));
    }
}

async fn serve(req: HttpRequest, body: web::Bytes, http: web::Data<GnapRsHttp>) -> HttpResponse {
    respond(http.handle(&read_request(&req, &body)).await)
}

/// Register the authorization-server routes: the grant endpoint (`POST` a transaction, `OPTIONS`
/// discovery) and the token management endpoint, at the paths `http` reports.
pub fn gnap_as_configure(cfg: &mut web::ServiceConfig, http: Arc<GnapAsHttp>) {
    let (grant, manage) = {
        let (g, m) = http.paths();
        (g.to_string(), m.to_string())
    };
    let http_continue = http.continue_route();
    cfg.app_data(web::Data::from(http))
        .app_data(web::PayloadConfig::new(MAX_BODY_BYTES + 1))
        .service(web::resource(grant).route(web::route().to(serve_as)))
        .service(web::resource(manage).route(web::route().to(serve_as)))
        .service(web::resource(http_continue).route(web::route().to(serve_as)));
}

async fn serve_as(req: HttpRequest, body: web::Bytes, http: web::Data<GnapAsHttp>) -> HttpResponse {
    respond(http.handle(&read_request(&req, &body)).await)
}

fn read_request(req: &HttpRequest, body: &web::Bytes) -> GnapHttpRequest {
    let headers = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    GnapHttpRequest {
        method: req.method().to_string(),
        uri: req.uri().to_string(),
        headers,
        body: body.to_vec(),
    }
}

fn respond(r: GnapHttpResponse) -> HttpResponse {
    let mut builder = HttpResponse::build(
        StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );
    for (k, v) in &r.headers {
        builder.insert_header((k.as_str(), v.as_str()));
    }
    builder.body(r.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::gnap_http::tests::{handler, handler_with_registry};
    use actix_web::{App, test};

    const GOOD: &str = r#"{"access_token":"tok-1","resource_server":"rs-1"}"#;

    macro_rules! app {
        () => {{
            let http = Arc::new(handler());
            test::init_service(App::new().configure(move |cfg| gnap_configure(cfg, http.clone())))
                .await
        }};
    }

    #[actix_web::test]
    async fn discovery_is_served() {
        let app = app!();
        let req = test::TestRequest::get()
            .uri("/.well-known/gnap-as-rs")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(doc["grant_request_endpoint"], "https://as.example.test/tx");
    }

    #[actix_web::test]
    async fn introspection_answers_through_the_app() {
        let app = app!();
        let req = test::TestRequest::post()
            .uri("/gnap/introspect")
            .insert_header(("X-Test-Rs", "rs-1"))
            .set_payload(GOOD)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["active"], true);
    }

    #[actix_web::test]
    async fn headers_reach_the_authenticator() {
        let app = app!();
        let req = test::TestRequest::post()
            .uri("/gnap/introspect")
            .set_payload(GOOD)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"]["code"], "invalid_resource_server");
    }

    #[actix_web::test]
    async fn the_wrong_method_is_405() {
        let app = app!();
        let req = test::TestRequest::get()
            .uri("/gnap/introspect")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[actix_web::test]
    async fn registration_is_routed_only_when_offered() {
        let http = Arc::new(handler_with_registry());
        let app =
            test::init_service(App::new().configure(move |cfg| gnap_configure(cfg, http.clone())))
                .await;
        let req = test::TestRequest::post()
            .uri("/gnap/resource")
            .insert_header(("X-Test-Rs", "rs-1"))
            .set_payload(r#"{"access":["dolphin-metadata"],"resource_server":"rs-1"}"#)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");

        let app = app!();
        let req = test::TestRequest::post()
            .uri("/gnap/resource")
            .insert_header(("X-Test-Rs", "rs-1"))
            .set_payload(GOOD)
            .to_request();
        assert_eq!(
            test::call_service(&app, req).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[actix_web::test]
    async fn an_unregistered_path_is_not_ours() {
        let app = app!();
        let req = test::TestRequest::post()
            .uri("/elsewhere")
            .set_payload(GOOD)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn the_as_app_answers_discovery_and_refuses_wrong_methods() {
        let http = Arc::new(crate::protocols::gnap_as_http::tests::handler());
        let app = test::init_service(
            App::new().configure(move |cfg| gnap_as_configure(cfg, http.clone())),
        )
        .await;
        let req = test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/api/gnap/tx")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(doc["key_proofs_supported"], serde_json::json!(["dpop"]));

        let req = test::TestRequest::get()
            .uri("/api/gnap/tx/token")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers().get("allow").unwrap(), "POST, DELETE");
    }

    #[actix_web::test]
    async fn a_grant_without_a_client_key_through_the_as_app_is_401() {
        let http = Arc::new(crate::protocols::gnap_as_http::tests::handler());
        let app = test::init_service(
            App::new().configure(move |cfg| gnap_as_configure(cfg, http.clone())),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/api/gnap/tx")
            .set_payload(r#"{"access_token":{"access":[{"type":"read"}]}}"#)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = test::read_body(resp).await;
        assert!(!String::from_utf8_lossy(&body).contains("access_token"));
    }

    #[actix_web::test]
    async fn the_as_app_routes_continuation() {
        let http = Arc::new(crate::protocols::gnap_as_http::tests::handler());
        let app = test::init_service(
            App::new().configure(move |cfg| gnap_as_configure(cfg, http.clone())),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/api/gnap/tx/continue/abc")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers().get("allow").unwrap(), "POST");
        let req = test::TestRequest::post()
            .uri("/api/gnap/tx/continue/abc")
            .insert_header(("Authorization", "GNAP nope"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let doc: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(doc["error"]["code"], "invalid_continuation");
    }
}
