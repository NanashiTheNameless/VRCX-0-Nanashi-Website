use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use vrcx_0_nanashi_website_protocol::blob::{
    self, DeletePrefixRequest, DeletePrefixResponse, Health, ListResponse,
};

use crate::backend::Backend;

pub const MAX_OBJECT: usize = 4 * 1024 * 1024 + 4096;

type Shared = Arc<Backend>;

pub fn router(backend: Shared) -> Router {
    Router::new()
        .route(
            "/objects/{*key}",
            get(get_object).put(put_object).delete(delete_object),
        )
        .route("/delete-prefix", post(delete_prefix))
        .route("/list", get(list))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_OBJECT))
        .with_state(backend)
}

fn failure(context: &str, error: impl std::fmt::Display) -> Response {
    tracing::error!("{context}: {error}");
    (StatusCode::BAD_GATEWAY, format!("{context} failed")).into_response()
}

fn bad_key() -> Response {
    (StatusCode::BAD_REQUEST, "invalid object key").into_response()
}

async fn put_object(
    State(backend): State<Shared>,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    if !blob::is_object_key(&key) {
        return bad_key();
    }
    if body.is_empty() || body.len() > MAX_OBJECT {
        return (StatusCode::PAYLOAD_TOO_LARGE, "object size out of range").into_response();
    }
    match backend.put(&key, body.to_vec()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => failure("put", error),
    }
}

async fn get_object(State(backend): State<Shared>, Path(key): Path<String>) -> Response {
    if !blob::is_object_key(&key) {
        return bad_key();
    }
    match backend.get(&key).await {
        Ok(Some(data)) => data.into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => failure("get", error),
    }
}

async fn delete_object(State(backend): State<Shared>, Path(key): Path<String>) -> Response {
    if !blob::is_object_key(&key) {
        return bad_key();
    }
    match backend.delete(&key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => failure("delete", error),
    }
}

async fn delete_prefix(
    State(backend): State<Shared>,
    Json(request): Json<DeletePrefixRequest>,
) -> Response {
    if !blob::is_prefix(&request.prefix) {
        return (StatusCode::BAD_REQUEST, "invalid prefix").into_response();
    }
    match backend.delete_prefix(&request.prefix).await {
        Ok(deleted) => Json(DeletePrefixResponse { deleted }).into_response(),
        Err(error) => failure("delete prefix", error),
    }
}

#[derive(Deserialize)]
struct ListQuery {
    prefix: String,
    token: Option<String>,
}

async fn list(State(backend): State<Shared>, Query(query): Query<ListQuery>) -> Response {
    if !blob::is_prefix(&query.prefix) {
        return (StatusCode::BAD_REQUEST, "invalid prefix").into_response();
    }
    match backend.list(&query.prefix, query.token).await {
        Ok((objects, next)) => Json(ListResponse { objects, next }).into_response(),
        Err(error) => failure("list", error),
    }
}

async fn health(State(backend): State<Shared>) -> Response {
    let result = backend.health().await;
    let ok = result.is_ok();
    let body = Health {
        backend: backend.name().into(),
        ok,
        detail: result.err().map(|e| e.0),
    };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalBackend;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    const P: &str = "0123456789abcdef0123456789abcdef";

    fn key(id: u8) -> String {
        blob::object_key(P, &format!("{id:032x}"))
    }

    async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn local_backend_round_trip_list_and_prefix_delete() {
        let dir = tempfile::tempdir().unwrap();
        let router = router(Arc::new(Backend::Local(LocalBackend::new(
            dir.path().to_path_buf(),
        ))));
        for id in 1..=3 {
            let (status, _) = call(
                &router,
                Method::PUT,
                &format!("/objects/{}", key(id)),
                vec![id; 10],
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        let (status, body) = call(
            &router,
            Method::GET,
            &format!("/objects/{}", key(2)),
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, vec![2; 10]);
        let (status, _) = call(
            &router,
            Method::GET,
            &format!("/objects/{}", key(9)),
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, body) = call(
            &router,
            Method::GET,
            &format!("/list?prefix={}", blob::prefix(P)),
            vec![],
        )
        .await;
        let listed: ListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed.objects.len(), 3);
        assert_eq!(listed.objects[0].key, key(1));
        assert!(listed.objects[0].last_modified > 0);

        let (status, _) = call(
            &router,
            Method::DELETE,
            &format!("/objects/{}", key(1)),
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = call(
            &router,
            Method::DELETE,
            &format!("/objects/{}", key(1)),
            vec![],
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "deleting twice is fine");

        let request = serde_json::to_vec(&DeletePrefixRequest {
            prefix: blob::prefix(P),
        })
        .unwrap();
        let (_, body) = call(&router, Method::POST, "/delete-prefix", request).await;
        let deleted: DeletePrefixResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(deleted.deleted, 2);
        let (_, body) = call(
            &router,
            Method::GET,
            &format!("/list?prefix={}", blob::prefix(P)),
            vec![],
        )
        .await;
        assert!(
            serde_json::from_slice::<ListResponse>(&body)
                .unwrap()
                .objects
                .is_empty()
        );

        let (_, body) = call(&router, Method::GET, "/health", vec![]).await;
        assert!(serde_json::from_slice::<Health>(&body).unwrap().ok);
    }

    #[tokio::test]
    async fn rejects_bad_keys_and_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let router = router(Arc::new(Backend::Local(LocalBackend::new(
            dir.path().to_path_buf(),
        ))));
        for uri in [
            "/objects/v1/../../etc/passwd".to_owned(),
            format!("/objects/v1/{P}/not-hex"),
            "/objects/anything".to_owned(),
        ] {
            let (status, _) = call(&router, Method::PUT, &uri, b"x".to_vec()).await;
            assert_ne!(status, StatusCode::NO_CONTENT, "{uri}");
        }
        let (status, _) = call(&router, Method::GET, "/list?prefix=v1/", vec![]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
