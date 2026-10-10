pub mod collections;
pub mod v1;
pub mod web;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use vrcx_0_nanashi_website_protocol::api::MAX_REQUEST_BYTES;

use crate::state::Shared;

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
