mod backend;
mod config;
mod local;
mod routes;
mod s3;

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::UnixListener;

use crate::backend::Backend;
use crate::config::Config;

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

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("remotesync-blobstore: {error}");
            return ExitCode::FAILURE;
        }
    };
    let backend = match Backend::from_config(&config.backend) {
        Ok(backend) => Arc::new(backend),
        Err(error) => {
            eprintln!("remotesync-blobstore: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = backend.health().await {
        tracing::warn!(backend = backend.name(), %error, "storage backend is not reachable yet");
    }
    let listener = match bind(&config.socket) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("remotesync-blobstore: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(socket = %config.socket.display(), backend = backend.name(), "listening");
    let result = axum::serve(listener, routes::router(backend))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("remotesync-blobstore: {error}");
            ExitCode::FAILURE
        }
    }
}
