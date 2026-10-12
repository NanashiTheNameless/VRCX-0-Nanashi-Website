use std::{
    collections::HashMap,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    response::Response,
    routing::get,
};
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::UnixListener;

mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

#[derive(Parser)]
#[command(name = "remotesync-web", about = "RemoteSync static website server")]
struct Config {
    #[arg(
        long,
        env = "REMOTESYNC_WEB_SOCKET",
        default_value = "/run/remotesync/web-sock/web.sock"
    )]
    socket: String,
    #[arg(long, env = "REMOTESYNC_API_ORIGIN")]
    api_origin: String,
    #[arg(long, env = "REMOTESYNC_WEB_VERSION", default_value = "dev")]
    web_version: String,
    #[arg(long, env = "REMOTESYNC_INSTANCE_STATEMENT", default_value = "")]
    instance_statement: String,
    #[arg(long, env = "REMOTESYNC_INSTANCE_SIGNATURE", default_value = "")]
    instance_signature: String,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    version: String,
    #[serde(default, rename = "sourceCommit")]
    source_commit: String,
    files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    path: String,
    sha256: String,
}

struct App {
    api_origin: String,
    web_version: String,
    source_commit: String,
    manifest_hash: String,
    assets: HashMap<&'static str, &'static [u8]>,
    csp: HeaderValue,
    themes_csp: HeaderValue,
    instance_statement: String,
    instance_signature: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let config = Config::parse();
    let api_origin = validate_origin(&config.api_origin)?;
    let assets: HashMap<_, _> = assets::ASSETS.iter().copied().collect();
    let (manifest_version, source_commit, manifest_hash) = validate_assets(&assets)?;
    let web_version = if config.web_version == "dev" && !manifest_version.is_empty() {
        manifest_version
    } else {
        config.web_version
    };
    let csp = content_security_policy(&api_origin, "")?;
    let themes_csp = content_security_policy(&api_origin, " https://raw.githubusercontent.com")?;
    let app = Arc::new(App {
        api_origin,
        web_version,
        source_commit,
        manifest_hash,
        assets,
        csp,
        themes_csp,
        instance_statement: config.instance_statement.trim().to_owned(),
        instance_signature: config.instance_signature.trim().to_owned(),
    });
    let socket_path = Path::new(&config.socket);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(socket_path)?,
        Ok(_) => {
            return Err(format!("{} exists and is not a socket", socket_path.display()).into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    tracing::info!(socket = %socket_path.display(), files = app.assets.len(), "verified website assets; listening");
    let router = Router::new()
        .route("/config.json", get(config_json))
        .route("/build.json", get(build_json))
        .route("/instance.json", get(instance_json))
        .route("/instance.sig", get(instance_sig))
        .fallback(get(serve_asset))
        .with_state(app);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn validate_origin(origin: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = http::Uri::try_from(origin)?;
    if url.scheme_str() != Some("https")
        || url.authority().is_none()
        || url.path_and_query().is_some_and(|p| p.as_str() != "/")
    {
        return Err("REMOTESYNC_API_ORIGIN must be an https origin without a path".into());
    }
    Ok(origin.trim_end_matches('/').to_owned())
}

fn validate_assets(
    assets: &HashMap<&'static str, &'static [u8]>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let raw = assets
        .get("web-manifest.json")
        .ok_or("missing web-manifest.json")?;
    let manifest: Manifest = serde_json::from_slice(raw)?;
    let manifest_version = manifest.version.clone();
    let source_commit = manifest.source_commit.clone();
    let manifest_hash = hex_digest(Sha256::digest(raw).as_slice());
    let mut seen = std::collections::HashSet::new();
    for entry in manifest.files {
        if entry.path.starts_with('/')
            || entry.path.split('/').any(|part| part == "..")
            || !seen.insert(entry.path.clone())
        {
            return Err(
                format!("invalid or duplicate path in web manifest: {}", entry.path).into(),
            );
        }
        let data = assets
            .get(entry.path.as_str())
            .ok_or_else(|| format!("manifest file is missing: {}", entry.path))?;
        let digest = hex_digest(Sha256::digest(data).as_slice());
        if digest != entry.sha256 {
            return Err(format!("website asset hash mismatch: {}", entry.path).into());
        }
    }
    for path in assets
        .keys()
        .copied()
        .filter(|path| *path != "web-manifest.json" && *path != "web-manifest.sig")
    {
        if !seen.contains(path) {
            return Err(format!("website asset is absent from manifest: {path}").into());
        }
    }
    Ok((manifest_version, source_commit, manifest_hash))
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing into a string cannot fail");
    }
    out
}

async fn config_json(State(app): State<Arc<App>>) -> Response {
    make_response(
        &app,
        "/config.json",
        serde_json::to_vec(&serde_json::json!({"apiOrigin":app.api_origin})).unwrap_or_default(),
    )
}

async fn instance_json(State(app): State<Arc<App>>) -> Response {
    instance_file(&app, "instance.json", &app.instance_statement)
}

async fn instance_sig(State(app): State<Arc<App>>) -> Response {
    instance_file(&app, "instance.sig", &app.instance_signature)
}

fn instance_file(app: &App, path: &str, content: &str) -> Response {
    if app.instance_statement.is_empty() || app.instance_signature.is_empty() {
        return status(StatusCode::NOT_FOUND);
    }
    make_response(app, path, content.as_bytes().to_vec())
}

async fn build_json(State(app): State<Arc<App>>) -> Response {
    make_response(
        &app,
        "build.json",
        serde_json::to_vec(&serde_json::json!({
            "version": app.web_version,
            "sourceCommit": app.source_commit,
            "manifestSha256": app.manifest_hash,
        }))
        .unwrap_or_default(),
    )
}

async fn serve_asset(State(app): State<Arc<App>>, request: Request<Body>) -> Response {
    let path = request.uri().path();
    let normalized = path.trim_start_matches('/');
    let candidate = if normalized.is_empty() {
        "index.html"
    } else {
        normalized
    };
    let accepts_html = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().starts_with("text/html"))
        });
    if candidate.split('/').any(|part| part == "..") || candidate.contains('\\') {
        return status(StatusCode::BAD_REQUEST);
    }
    let asset = app
        .assets
        .get(candidate)
        .map(|bytes| (candidate, *bytes))
        .or_else(|| {
            if !candidate.contains('.') || accepts_html {
                app.assets
                    .get("index.html")
                    .map(|bytes| ("index.html", *bytes))
            } else {
                None
            }
        });
    match asset {
        Some((asset_path, bytes)) => {
            let mut response = make_response(&app, asset_path, bytes.to_vec());
            if asset_path == "index.html" && !is_app_route(path) {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
            if path == "/themes" {
                response
                    .headers_mut()
                    .insert("content-security-policy", app.themes_csp.clone());
            }
            response
        }
        None => status(StatusCode::NOT_FOUND),
    }
}

fn is_app_route(path: &str) -> bool {
    matches!(
        path,
        "/" | "/privacy"
            | "/dashboard"
            | "/dashboard/home"
            | "/dashboard/devices"
            | "/dashboard/pair"
            | "/dashboard/data"
            | "/dashboard/collections"
            | "/dashboard/security"
            | "/dashboard/collector"
            | "/dashboard/admin"
            | "/themes"
            | "/licenses"
            | "/collections"
            | "/pair"
            | "/invite"
            | "/verify"
            | "/reset"
    ) || path.starts_with("/open/")
        || path.starts_with("/c/")
}

fn content_security_policy(
    api_origin: &str,
    extra_sources: &str,
) -> Result<HeaderValue, axum::http::header::InvalidHeaderValue> {
    HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' https://api.vrchat.cloud https://files.vrchat.cloud https://assets.vrchat.com data:{extra_sources}; font-src 'self'; connect-src 'self' {api_origin}{extra_sources}; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'"
    ))
}

fn make_response(app: &App, path: &str, bytes: Vec<u8>) -> Response {
    let content_type = match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "sig" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000"),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert("permissions-policy", HeaderValue::from_static("accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)"));
    headers.insert("content-security-policy", app.csp.clone());
    let cache = if path.trim_start_matches('/').starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else if path.trim_start_matches('/') == "index.html" {
        "no-cache, no-transform"
    } else {
        "no-cache"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response
}

fn status(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}
