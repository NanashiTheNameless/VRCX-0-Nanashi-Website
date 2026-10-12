use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use tokio::net::UnixListener;

use crate::state::Shared;
use crate::util::{DAY_MS, now_ms};

pub const CLIENT_IP_RETENTION_MS: i64 = 90 * DAY_MS;

pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
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

pub fn spawn_maintenance(state: Shared) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(60);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        let mut minutes = 0_u64;
        loop {
            tick.tick().await;
            let run_daily = minutes.is_multiple_of(60 * 24);
            minutes += 1;
            let result = state
                .run(move |state| {
                    let now = now_ms();
                    let registry = state.registry();
                    registry.prune_expired(now)?;
                    if run_daily {
                        let removed = registry.prune_client_ips(now - CLIENT_IP_RETENTION_MS)?;
                        if removed > 0 {
                            tracing::info!(removed, "pruned connection history older than 90 days");
                        }
                    }
                    Ok(())
                })
                .await;
            if let Err(error) = result {
                tracing::error!(?error, "maintenance failed");
            }
            if let Err(error) = state.process_deletions().await {
                tracing::error!(?error, "object deletion queue failed");
            }
            if run_daily {
                match state.sweep_orphans().await {
                    Ok(0) => {}
                    Ok(deleted) => tracing::info!(deleted, "deleted orphaned objects"),
                    Err(error) => tracing::error!(?error, "orphan sweep failed"),
                }
            }
        }
    });
}

pub async fn serve(state: Shared) -> std::io::Result<()> {
    let listener = bind(&state.config.api_socket)?;
    let collector_listener = bind(&state.config.collector_ingest_socket)?;
    tracing::info!(socket = %state.config.api_socket.display(), "listening");
    tracing::info!(socket = %state.config.collector_ingest_socket.display(), "collector ingestion socket listening");
    spawn_maintenance(state.clone());
    let router = crate::routes::api_router(state.clone());
    let collector_router = crate::routes::collector_router(state);
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = signal_tx.send(true);
    });
    let mut api_shutdown = shutdown_tx.subscribe();
    let mut collector_shutdown = shutdown_tx.subscribe();
    let api = axum::serve(listener, router).with_graceful_shutdown(async move {
        let _ = api_shutdown.changed().await;
    });
    let collector =
        axum::serve(collector_listener, collector_router).with_graceful_shutdown(async move {
            let _ = collector_shutdown.changed().await;
        });
    tokio::try_join!(api, collector)?;
    Ok(())
}
