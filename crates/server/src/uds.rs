use std::path::Path;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct UdsError(pub String);

pub async fn call(
    path: &Path,
    method: Method,
    uri: &str,
    body: Vec<u8>,
    json: bool,
) -> Result<(StatusCode, Bytes), UdsError> {
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| UdsError(format!("connect to {}: {e}", path.display())))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| UdsError(format!("handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost");
    if json {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| UdsError(format!("request: {e}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| UdsError(format!("request: {e}")))?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| UdsError(format!("response: {e}")))?
        .to_bytes();
    Ok((status, bytes))
}
