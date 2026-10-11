use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::UnixListener;
use vrcx_0_nanashi_website_protocol::mail::{SendRequest, SendResponse};

struct Mailer {
    client: reqwest::Client,
    endpoint: url::Url,
    api_key: String,
    from: String,
}

#[derive(Serialize)]
struct ResendEmail<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct ResendResponse {
    id: String,
}

impl Mailer {
    async fn send(&self, request: &SendRequest) -> Result<String, String> {
        let url = self.endpoint.join("emails").map_err(|e| e.to_string())?;
        let body = ResendEmail {
            from: &self.from,
            to: [request.to.trim()],
            subject: &request.subject,
            text: &request.text,
            html: None,
        };
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.api_key)
            .header("Idempotency-Key", &request.idempotency_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("request: {}", e.without_url()))?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            let name = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_owned))
                .unwrap_or_default();
            return Err(format!("Resend returned HTTP {status} {name}"));
        }
        let parsed: ResendResponse = response
            .json()
            .await
            .map_err(|e| format!("response: {}", e.without_url()))?;
        Ok(parsed.id)
    }
}

type Shared = Arc<Mailer>;

fn router(mailer: Shared) -> Router {
    Router::new()
        .route("/send", post(send))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(mailer)
}

async fn send(State(mailer): State<Shared>, Json(request): Json<SendRequest>) -> Response {
    if let Err(reason) = request.validate() {
        return (StatusCode::BAD_REQUEST, reason).into_response();
    }
    match mailer.send(&request).await {
        Ok(id) => (StatusCode::ACCEPTED, Json(SendResponse { id })).into_response(),
        Err(error) => {
            tracing::error!(%error, "sending email failed");
            (StatusCode::BAD_GATEWAY, "sending failed").into_response()
        }
    }
}

fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn config() -> Result<(PathBuf, Mailer), String> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let socket: PathBuf = get("REMOTESYNC_MAIL_SOCKET")
        .unwrap_or_else(|| "/run/remotesync/mail/mail.sock".into())
        .into();
    let from = get("REMOTESYNC_MAIL_FROM").ok_or("REMOTESYNC_MAIL_FROM is required")?;
    if from.contains(['\r', '\n']) {
        return Err("REMOTESYNC_MAIL_FROM is invalid".into());
    }
    let key_file =
        get("REMOTESYNC_RESEND_KEY_FILE").unwrap_or_else(|| "/run/secrets/resend_api_key".into());
    let api_key = std::fs::read_to_string(&key_file)
        .map_err(|e| format!("cannot read the Resend API key: {e}"))?
        .trim()
        .to_owned();
    if api_key.is_empty() {
        return Err("the Resend API key file is empty".into());
    }
    let endpoint = url::Url::parse(
        &get("REMOTESYNC_RESEND_ENDPOINT").unwrap_or_else(|| "https://api.resend.com/".into()),
    )
    .map_err(|e| format!("REMOTESYNC_RESEND_ENDPOINT: {e}"))?;
    if endpoint.scheme() != "https" {
        return Err("REMOTESYNC_RESEND_ENDPOINT must be https://".into());
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    Ok((
        socket,
        Mailer {
            client,
            endpoint,
            api_key,
            from,
        },
    ))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (socket, mailer) = match config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("remotesync-mailer: {error}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match bind(&socket) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("remotesync-mailer: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(socket = %socket.display(), "listening");
    let result = axum::serve(listener, router(Arc::new(mailer)))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("remotesync-mailer: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn mailer() -> Shared {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Arc::new(Mailer {
            client: reqwest::Client::builder().https_only(true).build().unwrap(),
            endpoint: "https://127.0.0.1:1/".parse().unwrap(),
            api_key: "re_test".into(),
            from: "Test <test@example.com>".into(),
        })
    }

    async fn post(body: serde_json::Value) -> StatusCode {
        let request = Request::post("/send")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        router(mailer()).oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn rejects_header_injection_and_reports_failures() {
        let bad = serde_json::json!({"to": "a@b.c\r\nBcc: x@y.z", "subject": "s", "text": "t", "idempotencyKey": "k"});
        assert_eq!(post(bad).await, StatusCode::BAD_REQUEST);
        let good =
            serde_json::json!({"to": "a@b.c", "subject": "s", "text": "t", "idempotencyKey": "k"});
        assert_eq!(
            post(good).await,
            StatusCode::BAD_GATEWAY,
            "unreachable Resend is a failure, not a success"
        );
    }
}
