mod auth;
mod cli;
mod config;
mod crypto;
mod db;
mod http;
mod mail;
mod objects;
mod passwords;
mod rate;
mod recovery;
mod routes;
mod server;
mod state;
#[cfg(test)]
mod tests;
mod totp;
mod uds;
mod util;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::crypto::ServerKeys;
use crate::db::registry::Registry;
use crate::state::AppState;

#[derive(Parser)]
#[command(
    name = "remotesync",
    version,
    about = "VRCX-0-Nanashi RemoteSync backend"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Admin {
        #[arg(long, global = true)]
        json: bool,
        #[command(subcommand)]
        command: cli::AdminCommand,
    },
}

fn open_state() -> Result<state::Shared, String> {
    let config = Config::from_env().map_err(|e| e.to_string())?;
    let keys = ServerKeys::load(&config.master_key_file).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("data directory: {e}"))?;
    let registry = Registry::open(&config.data_dir.join("registry.db"), keys.registry_key())
        .map_err(|e| e.to_string())?;
    let objects = objects::ObjectStore::socket(config.blob_socket.clone());
    let mailer = mail::Mailer::socket(config.mail_socket.clone());
    Ok(AppState::new(config, keys, registry, objects, mailer))
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let json_output = matches!(&cli.command, Some(Command::Admin { json: true, .. }));
    let state = match open_state() {
        Ok(state) => state,
        Err(error) => {
            if json_output {
                eprintln!(
                    "{{\"error\":{}}}",
                    serde_json::to_string(&error).unwrap_or_else(|_| "\"unknown error\"".into())
                );
            } else {
                eprintln!("remotesync: {error}");
            }
            return ExitCode::FAILURE;
        }
    };
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("remotesync: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = runtime.block_on(server::serve(state)) {
                eprintln!("remotesync: {error}");
                return ExitCode::FAILURE;
            }
        }
        Command::Admin { command, json } => {
            if let Err(error) = cli::run_with_json(&state, command, json) {
                if json {
                    eprintln!(
                        "{{\"error\":{}}}",
                        serde_json::to_string(&error)
                            .unwrap_or_else(|_| "\"unknown error\"".into())
                    );
                } else {
                    eprintln!("remotesync: {error}");
                }
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
