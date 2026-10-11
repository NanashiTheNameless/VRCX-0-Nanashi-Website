pub mod collections;
pub mod v1;
pub mod web;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use vrcx_0_nanashi_website_protocol::api::MAX_REQUEST_BYTES;

use crate::state::Shared;

const API_NOT_FOUND_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>404 - RemoteSync API</title>
<style>
:root{color-scheme:dark;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;background:#080809;color:#f4f1f1}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}
main{width:min(100%,560px);padding:clamp(24px,6vw,48px);border:1px solid #29292d;background:#101012}
.brand{color:#e63b45;font-size:12px;font-weight:700;letter-spacing:.12em}
h1{margin:28px 0 10px;font-size:clamp(30px,7vw,48px);letter-spacing:-.05em}
p{color:#aaa5a7;line-height:1.7}
a{display:inline-block;margin-top:14px;padding:11px 15px;border:1px solid #e63b45;border-radius:4px;background:#e63b45;color:#fff;text-decoration:none;font-weight:700}
</style>
</head>
<body><main><div class="brand">REMOTESYNC API</div><h1>404</h1><p>This page does not exist or has moved.</p><a href="https://vrcx.namelessnanashi.dev/">Open RemoteSync</a></main></body>
</html>"#;

pub async fn api_not_found(headers: HeaderMap) -> Response {
    let accepts_html = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().split(';').next() == Some("text/html"))
        });

    if accepts_html {
        (StatusCode::NOT_FOUND, Html(API_NOT_FOUND_HTML)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(vrcx_0_nanashi_website_protocol::api::ApiError::new(
                "route_not_found",
                "No API route matches this URL.",
            )),
        )
            .into_response()
    }
}

fn website_cors(state: &Shared) -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};
    let origins: Vec<HeaderValue> = state
        .config
        .web_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            HeaderName::from_static("x-chunk-id"),
            HeaderName::from_static("x-manifest-seq"),
            HeaderName::from_static("if-match-seq"),
        ])
        .expose_headers([
            HeaderName::from_static("x-manifest-seq"),
            HeaderName::from_static("x-live-seq"),
            HeaderName::from_static("x-live-age"),
            HeaderName::from_static("x-max-seq"),
            HeaderName::from_static("x-has-more"),
            axum::http::header::RETRY_AFTER,
        ])
        .max_age(std::time::Duration::from_secs(600))
}

pub fn api_router(state: Shared) -> Router {
    Router::new()
        .nest("/v1", v1::router())
        .nest("/web/v1", web::router().layer(website_cors(&state)))
        .nest(
            "/public/v1",
            collections::public_router().layer(website_cors(&state)),
        )
        .fallback(api_not_found)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

pub fn collector_router(state: Shared) -> Router {
    Router::new()
        .route(
            "/live/{account_id}/{vault_id}",
            axum::routing::put(v1::publish_live).delete(v1::delete_live),
        )
        .route(
            "/chunks/{account_id}/{vault_id}/{chunk_id}",
            axum::routing::put(v1::collector_store_chunk),
        )
        .with_state(state)
}
