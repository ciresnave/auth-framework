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

use crate::protocols::gnap_http::{GnapHttpRequest, GnapRsHttp, MAX_BODY_BYTES};
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
    let headers = req
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let request = GnapHttpRequest {
        method: req.method().to_string(),
        uri: req.uri().to_string(),
        headers,
        body: body.to_vec(),
    };
    let r = http.handle(&request).await;
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
}
