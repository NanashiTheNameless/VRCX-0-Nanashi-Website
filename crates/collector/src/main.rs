use std::{
    collections::HashMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt, symlink},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use data_encoding::BASE64URL_NOPAD;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode as HyperStatus};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::oneshot,
};
use vrcx_0_nanashi_website_protocol::api::{ApiError, codes};
use vrcx_0_nanashi_website_protocol::{
    b64,
    chunk::{self, ChunkBody, ChunkDraft, ChunkKind, CoveragePeriod},
    ids::{SourceId, VaultId},
    keys::SignerKey,
    live::{self, LiveFriend, LiveInstance, LiveSelf, LiveSnapshot},
    seal::{self, SealPrivateKey, SealPublicKey},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_BUFFERED_ROWS: usize = 100_000;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;
const CHILD_UID_BASE: u32 = 20_000;
const CHILD_UID_COUNT: u32 = 256;
const LIVE_INTERVAL: Duration = Duration::from_secs(30);
const HEADLESS_BINARY: &str = "/usr/local/bin/vrcx-0-nanashi-headless";
const HEADLESS_METADATA: &str = "/usr/local/share/remotesync/collector-runtime.json";
const RUNTIME_DIR: &str = "/run/vrcx-runtime";
const RUNTIME_UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_RUNTIME_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUNTIME_METADATA_BYTES: usize = 16 * 1024;
const VRCX_RELEASE_BASE: &str =
    "https://github.com/NanashiTheNameless/VRCX-0-Nanashi/releases/download";
const COLLECTOR_UNAVAILABLE_EXIT_CODE: i32 = 78;

#[derive(Parser, Clone)]
#[command(
    name = "remotesync-collector",
    about = "RemoteSync collector supervisor"
)]
struct Config {
    #[arg(
        long,
        env = "REMOTESYNC_COLLECTOR_SOCKET",
        default_value = "/run/remotesync/collector/ctl.sock"
    )]
    socket: PathBuf,
    #[arg(
        long,
        env = "REMOTESYNC_COLLECTOR_API_SOCKET",
        default_value = "/run/remotesync/collector-api/api.sock"
    )]
    api_socket: PathBuf,
    #[arg(
        long,
        env = "REMOTESYNC_COLLECTOR_TMPFS",
        default_value = "/run/collector"
    )]
    tmpfs: PathBuf,
    #[arg(long, env = "REMOTESYNC_COLLECTOR_MAX_SESSIONS", default_value_t = 64)]
    max_sessions: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    available: bool,
    unlock_key: String,
    signing_key: String,
    keys_valid_since_ms: i64,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct CollectorRuntimeMetadata {
    app_version: String,
    app_commit: String,
    compatibility_version: String,
    compatibility_commit: String,
    architecture: String,
    format: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct UnlockPayload {
    version: u8,
    vault_pk: String,
    vrchat_user_id: String,
    cookies: Cookies,
    expires_at: Option<i64>,
    interval_seconds: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Cookies {
    auth: String,
    #[serde(default)]
    two_factor_auth: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionStatus {
    state: String,
    since: Option<i64>,
    last_chunk_at: Option<i64>,
    last_error: Option<String>,
}

struct RunningSession {
    child_uid: u32,
    stop: oneshot::Sender<()>,
    status: Arc<Mutex<SessionStatus>>,
    task: tokio::task::JoinHandle<()>,
    data_dir: PathBuf,
}

struct Supervisor {
    config: Config,
    unlock: SealPrivateKey,
    signer: SignerKey,
    available: AtomicBool,
    keys_valid_since_ms: i64,
    max_sessions: usize,
    unlock_guard: tokio::sync::Mutex<()>,
    sessions: Mutex<HashMap<String, RunningSession>>,
    finished: Mutex<HashMap<String, SessionStatus>>,
}

struct FlushBatch {
    rows: Vec<ChildRow>,
    pending: Option<(u64, String, Vec<u8>, u64)>,
    source_seq: u64,
    last_seen_row_id: u64,
    dropped_rows: u64,
    control_id: u64,
}

struct FlushContext<'a> {
    supervisor: &'a Supervisor,
    account: &'a str,
    vault: VaultId,
    source: SourceId,
    vault_pk: &'a SealPublicKey,
}

struct ChildSession {
    supervisor: Shared,
    account: String,
    vault: VaultId,
    payload: UnlockPayload,
    vault_pk: SealPublicKey,
    status: Arc<Mutex<SessionStatus>>,
    data_dir: PathBuf,
    child_uid: u32,
}

type Shared = Arc<Supervisor>;

fn key(account: &str, vault: &str) -> String {
    format!("{account}/{vault}")
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

fn compatible_collector_available() -> bool {
    let (binary_path, metadata_path) = active_runtime_paths();
    let Ok(metadata) = std::fs::read(metadata_path) else {
        return false;
    };
    let Ok(metadata) = serde_json::from_slice::<CollectorRuntimeMetadata>(&metadata) else {
        return false;
    };
    let Ok(binary) = std::fs::metadata(&binary_path) else {
        return false;
    };
    let Ok(mut file) = std::fs::File::open(&binary_path) else {
        return false;
    };
    let mut header = [0u8; 20];
    if std::io::Read::read_exact(&mut file, &mut header).is_err()
        || header[..4] != [0x7f, b'E', b'L', b'F']
        || header[4] != 2
        || header[5] != 1
        || u16::from_le_bytes([header[18], header[19]]) != 62
    {
        return false;
    }
    metadata.app_version == metadata.compatibility_version
        && metadata.app_commit == metadata.compatibility_commit
        && metadata.architecture == "linux/amd64"
        && metadata.format == "ELF64 x86-64"
        && binary.is_file()
        && binary.permissions().mode() & 0o111 == 0o111
        && binary.permissions().mode() & 0o6000 == 0
}

fn active_runtime_paths() -> (PathBuf, PathBuf) {
    let runtime_root = Path::new(RUNTIME_DIR);
    let current = runtime_root.join("current");
    if let Ok(target) = std::fs::read_link(&current) {
        let release_dir = if target.is_absolute() {
            target
        } else {
            runtime_root.join(target)
        };
        let binary = release_dir.join("vrcx-0-nanashi-headless");
        let metadata = release_dir.join("collector-runtime.json");
        if binary.is_file() && metadata.is_file() {
            return (binary, metadata);
        }
    }
    (
        PathBuf::from(HEADLESS_BINARY),
        PathBuf::from(HEADLESS_METADATA),
    )
}

fn valid_nightly_version(version: &str) -> bool {
    if version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return false;
    }
    let Some((base, commit)) = version.split_once("-Nightly-") else {
        return false;
    };
    let mut parts = base.split('.');
    let valid_number = |part: Option<&str>, max_len: usize| {
        part.is_some_and(|part| {
            !part.is_empty()
                && part.len() <= max_len
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'))
        })
    };
    valid_number(parts.next(), 2)
        && valid_number(parts.next(), 3)
        && valid_number(parts.next(), 3)
        && parts.next().is_none()
        && commit.len() == 7
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_runtime_metadata(metadata: &CollectorRuntimeMetadata) -> bool {
    valid_nightly_version(&metadata.app_version)
        && metadata.app_version == metadata.compatibility_version
        && metadata.app_commit.len() == 40
        && metadata
            .app_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        && metadata
            .app_version
            .rsplit_once('-')
            .is_some_and(|(_, short_commit)| metadata.app_commit.starts_with(short_commit))
        && metadata.app_commit == metadata.compatibility_commit
        && metadata.architecture == "linux/amd64"
        && metadata.format == "ELF64 x86-64"
}

async fn read_runtime_metadata(
    client: &reqwest::Client,
    url: &str,
) -> Result<(CollectorRuntimeMetadata, Vec<u8>), String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.without_url().to_string())?
        .error_for_status()
        .map_err(|error| error.without_url().to_string())?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RUNTIME_METADATA_BYTES as u64)
    {
        return Err("runtime metadata exceeds size limit".into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| error.without_url().to_string())?;
    if bytes.len() > MAX_RUNTIME_METADATA_BYTES {
        return Err("runtime metadata exceeds size limit".into());
    }
    let metadata = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    Ok((metadata, bytes.to_vec()))
}

async fn update_headless_runtime(client: &reqwest::Client) -> Result<Option<String>, String> {
    let rolling_metadata_url =
        format!("{VRCX_RELEASE_BASE}/Nightly-Rolling/vrcx-0-nanashi-headless-linux-amd64.json");
    let (rolling_metadata, _) = read_runtime_metadata(client, &rolling_metadata_url).await?;
    if !valid_runtime_metadata(&rolling_metadata) {
        return Err("rolling release has invalid collector metadata".into());
    }
    let (_, current_metadata) = active_runtime_paths();
    if let Ok(bytes) = std::fs::read(current_metadata)
        && let Ok(current) = serde_json::from_slice::<CollectorRuntimeMetadata>(&bytes)
        && current.app_version == rolling_metadata.app_version
        && current.app_commit == rolling_metadata.app_commit
    {
        return Ok(None);
    }

    let immutable_base = format!("{VRCX_RELEASE_BASE}/v{}", rolling_metadata.app_version);
    let metadata_url = format!("{immutable_base}/vrcx-0-nanashi-headless-linux-amd64.json");
    let (immutable_metadata, metadata_bytes) = read_runtime_metadata(client, &metadata_url).await?;
    if immutable_metadata != rolling_metadata {
        return Err("rolling and immutable collector metadata differ".into());
    }

    let runtime_root = Path::new(RUNTIME_DIR);
    if !tmpfs(runtime_root).map_err(|error| error.to_string())? {
        return Err(format!("{} must be a tmpfs mount", runtime_root.display()));
    }
    let releases_dir = runtime_root.join("releases");
    std::fs::create_dir_all(&releases_dir).map_err(|error| error.to_string())?;
    for entry in std::fs::read_dir(runtime_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_name().to_string_lossy().starts_with(".staging-") {
            std::fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    let release_dir = releases_dir.join(&rolling_metadata.app_version);
    let binary_path = release_dir.join("vrcx-0-nanashi-headless");
    let metadata_path = release_dir.join("collector-runtime.json");
    if !release_dir.is_dir() {
        let staging_dir = runtime_root.join(format!(
            ".staging-{}-{}",
            rolling_metadata.app_version,
            std::process::id()
        ));
        if staging_dir.exists() {
            std::fs::remove_dir_all(&staging_dir).map_err(|error| error.to_string())?;
        }
        std::fs::create_dir(&staging_dir).map_err(|error| error.to_string())?;
        let staging_binary = staging_dir.join("vrcx-0-nanashi-headless");
        let mut output = tokio::fs::File::create(&staging_binary)
            .await
            .map_err(|error| error.to_string())?;
        let binary_url = format!("{immutable_base}/vrcx-0-nanashi-headless-linux-amd64");
        let mut response = client
            .get(binary_url)
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?
            .error_for_status()
            .map_err(|error| error.without_url().to_string())?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RUNTIME_BINARY_BYTES)
        {
            return Err("runtime binary exceeds size limit".into());
        }
        let mut downloaded = 0u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| error.without_url().to_string())?
        {
            downloaded = downloaded.saturating_add(chunk.len() as u64);
            if downloaded > MAX_RUNTIME_BINARY_BYTES {
                return Err("runtime binary exceeds size limit".into());
            }
            output
                .write_all(&chunk)
                .await
                .map_err(|error| error.to_string())?;
        }
        output.flush().await.map_err(|error| error.to_string())?;
        drop(output);
        std::fs::write(staging_dir.join("collector-runtime.json"), &metadata_bytes)
            .map_err(|error| error.to_string())?;
        std::fs::set_permissions(&staging_binary, std::fs::Permissions::from_mode(0o555))
            .map_err(|error| error.to_string())?;
        let mut header_file =
            std::fs::File::open(&staging_binary).map_err(|error| error.to_string())?;
        let mut header = [0u8; 20];
        std::io::Read::read_exact(&mut header_file, &mut header)
            .map_err(|error| error.to_string())?;
        if header[..4] != [0x7f, b'E', b'L', b'F']
            || header[4] != 2
            || header[5] != 1
            || u16::from_le_bytes([header[18], header[19]]) != 62
        {
            std::fs::remove_dir_all(&staging_dir).ok();
            return Err("downloaded runtime is not an ELF64 x86-64 binary".into());
        }
        std::fs::rename(&staging_dir, &release_dir).map_err(|error| error.to_string())?;
    }

    let mut current_metadata_file =
        std::fs::File::open(&metadata_path).map_err(|error| error.to_string())?;
    let mut stored_metadata_bytes = Vec::new();
    std::io::Read::read_to_end(&mut current_metadata_file, &mut stored_metadata_bytes)
        .map_err(|error| error.to_string())?;
    let stored_metadata: CollectorRuntimeMetadata =
        serde_json::from_slice(&stored_metadata_bytes).map_err(|error| error.to_string())?;
    let binary = std::fs::metadata(&binary_path).map_err(|error| error.to_string())?;
    if stored_metadata != rolling_metadata
        || !binary.is_file()
        || binary.permissions().mode() & 0o111 == 0
        || binary.permissions().mode() & 0o6000 != 0
    {
        return Err("staged collector runtime failed validation".into());
    }

    let current_link = runtime_root.join("current");
    let next_link = runtime_root.join("current.next");
    let _ = std::fs::remove_file(&next_link);
    symlink(
        Path::new("releases").join(&rolling_metadata.app_version),
        &next_link,
    )
    .map_err(|error| error.to_string())?;
    std::fs::rename(&next_link, &current_link).map_err(|error| error.to_string())?;
    let (active_binary, _) = active_runtime_paths();
    if active_binary != binary_path {
        return Err("activated collector runtime is unavailable".into());
    }
    if !compatible_collector_available() {
        return Err("activated collector runtime is incompatible".into());
    }
    for entry in std::fs::read_dir(&releases_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path() != release_dir {
            std::fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
        }
    }
    Ok(Some(rolling_metadata.app_version))
}

fn tmpfs(path: &Path) -> std::io::Result<bool> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(std::io::Error::other)?;
    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        if libc::statfs(path.as_ptr(), &mut stat) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stat.f_type as u64 == 0x0102_1994)
    }
}

fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "collector socket path is not a socket",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn fd_high(fd: RawFd) -> std::io::Result<RawFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicated < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(duplicated)
    }
}

fn child_fd(stream: &std::os::unix::net::UnixStream) -> std::io::Result<RawFd> {
    fd_high(stream.as_raw_fd())
}

fn launch_child(
    data_dir: &Path,
    child_uid: u32,
    session_child: &std::os::unix::net::UnixStream,
    rows_child: &std::os::unix::net::UnixStream,
    control_child: &std::os::unix::net::UnixStream,
) -> std::io::Result<tokio::process::Child> {
    let session_owned = unsafe { OwnedFd::from_raw_fd(child_fd(session_child)?) };
    let rows_owned = unsafe { OwnedFd::from_raw_fd(child_fd(rows_child)?) };
    let control_owned = unsafe { OwnedFd::from_raw_fd(child_fd(control_child)?) };
    let session_fd = session_owned.as_raw_fd();
    let rows_fd = rows_owned.as_raw_fd();
    let control_fd = control_owned.as_raw_fd();
    let mut command = Command::new(HEADLESS_BINARY);
    command
        .args([
            "--collector-mode",
            "--session-fd",
            "3",
            "--rows-fd",
            "4",
            "--control-fd",
            "5",
            "--data-dir",
        ])
        .arg(data_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    unsafe {
        command.as_std_mut().pre_exec(move || {
            for (source, target) in [(session_fd, 3), (rows_fd, 4), (control_fd, 5)] {
                if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresgid(child_uid, child_uid, child_uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresuid(child_uid, child_uid, child_uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionFrame<'a> {
    v: u8,
    auth: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_factor_auth: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChildRow {
    v: u8,
    row_id: u64,
    stream: String,
    row: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChildSnapshot {
    #[serde(default)]
    own: LiveSelf,
    #[serde(default)]
    friends: Vec<LiveFriend>,
    #[serde(default)]
    instances: Vec<LiveInstance>,
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid collector child frame length",
        ));
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid collector child frame size",
        ));
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn control(
    stream: &mut UnixStream,
    id: u64,
    op: &str,
    row_id: Option<u64>,
) -> Result<serde_json::Value, String> {
    let mut request = serde_json::json!({"v":1,"id":id,"op":op});
    if let Some(row_id) = row_id {
        request["throughRowId"] = serde_json::json!(row_id);
    }
    let bytes = cbor(&request)?;
    write_frame(stream, &bytes)
        .await
        .map_err(|e| e.to_string())?;
    let response = read_frame(stream).await.map_err(|e| e.to_string())?;
    let value: serde_json::Value = from_cbor(&response)?;
    if value["id"].as_u64() != Some(id) || value["v"].as_u64() != Some(1) {
        return Err("invalid child control response identity".into());
    }
    if value["ok"] != true {
        let error_code = value["error"]["code"]
            .as_str()
            .or_else(|| value["error"].as_str())
            .or_else(|| value["code"].as_str());
        if error_code == Some(codes::COLLECTOR_UNAVAILABLE) {
            return Err(codes::COLLECTOR_UNAVAILABLE.into());
        }
        if error_code == Some("auth_failed") {
            return Err("auth_failed".into());
        }
        return Err("child control operation failed".into());
    }
    Ok(value)
}

async fn uds_call(
    config: &Config,
    method: Method,
    uri: &str,
    body: Vec<u8>,
    headers: &[(&str, String)],
) -> Result<(HyperStatus, Vec<u8>), String> {
    let stream = UnixStream::connect(&config.api_socket)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder
        .body(Full::new(hyper::body::Bytes::from(body)))
        .map_err(|e| e.to_string())?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes()
        .to_vec();
    Ok((status, bytes))
}

async fn flush_rows(
    context: &FlushContext<'_>,
    batch: &mut FlushBatch,
    control_stream: &mut UnixStream,
    status: &Arc<Mutex<SessionStatus>>,
) -> Result<(), String> {
    let supervisor = context.supervisor;
    let account = context.account;
    let vault = context.vault;
    let source = context.source;
    let vault_pk = context.vault_pk;
    let rows = &mut batch.rows;
    let pending = &mut batch.pending;
    let source_seq = &mut batch.source_seq;
    let last_seen_row_id = &mut batch.last_seen_row_id;
    let dropped_rows = &mut batch.dropped_rows;
    let control_id = &mut batch.control_id;
    if rows.is_empty() && *dropped_rows == 0 && pending.is_none() {
        return Ok(());
    }
    if pending.is_none() {
        let mut streams = std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
        for row in rows.iter() {
            if row.v != 1 {
                return Err("unsupported child row version".into());
            }
            streams
                .entry(row.stream.clone())
                .or_default()
                .push(row.row.clone());
        }
        let body = ChunkBody { streams };
        let now = now_ms();
        let oldest = rows.first().map_or(now, |_| now.saturating_sub(30_000));
        let draft = ChunkDraft {
            vault_id: vault,
            source_id: source,
            source_seq: *source_seq,
            kind: ChunkKind::Rows,
            created_at_ms: now,
            app_version: "collector-headless".into(),
            coverage: vec![CoveragePeriod {
                start_ms: oldest,
                end_ms: now,
            }],
            dropped_rows: *dropped_rows,
            body,
        };
        let sealed =
            chunk::seal_chunk(&draft, &supervisor.signer, vault_pk).map_err(|e| e.to_string())?;
        let chunk_id = sealed.chunk_id.to_string();
        *pending = Some((*last_seen_row_id, chunk_id, sealed.blob, *dropped_rows));
    }
    let (through_row_id, chunk_id, blob, _) = pending.as_ref().expect("pending initialized");
    let response = uds_call(
        &supervisor.config,
        Method::PUT,
        &format!("/chunks/{account}/{vault}/{chunk_id}"),
        blob.clone(),
        &[],
    )
    .await?;
    if !response.0.is_success() {
        return Err(format!("API rejected collector chunk ({})", response.0));
    }
    *control_id += 1;
    control(
        control_stream,
        *control_id,
        "pruneRows",
        Some(*through_row_id),
    )
    .await?;
    rows.retain(|row| row.row_id > *through_row_id);
    *source_seq += 1;
    *last_seen_row_id = rows.last().map_or(0, |row| row.row_id);
    *dropped_rows = 0;
    *pending = None;
    let mut status = status.lock().unwrap_or_else(|p| p.into_inner());
    status.last_chunk_at = Some(now_ms());
    status.last_error = None;
    Ok(())
}

async fn publish_live(
    supervisor: &Supervisor,
    account: &str,
    vault: VaultId,
    vault_pk: &SealPublicKey,
    control_stream: &mut UnixStream,
    control_id: &mut u64,
) -> Result<(), String> {
    *control_id += 1;
    let response = control(control_stream, *control_id, "getSnapshot", None).await?;
    let child: ChildSnapshot =
        serde_json::from_value(response["snapshot"].clone()).map_err(|e| e.to_string())?;
    let live_seq = now_ms().max(0) as u64;
    let snapshot = LiveSnapshot {
        v: live::VERSION,
        vault_id: vault,
        live_seq,
        created_at_ms: now_ms(),
        signer_key_id: supervisor.signer.key_id(),
        own: child.own,
        friends: child.friends,
        instances: child.instances,
    };
    let blob =
        live::seal_live(&snapshot, &supervisor.signer, vault_pk).map_err(|e| e.to_string())?;
    let response = uds_call(
        &supervisor.config,
        Method::PUT,
        &format!("/live/{account}/{vault}"),
        blob,
        &[("x-live-seq", snapshot.live_seq.to_string())],
    )
    .await?;
    if !response.0.is_success() {
        return Err(format!("API rejected live snapshot ({})", response.0));
    }
    Ok(())
}

async fn run_child(mut session: ChildSession, mut stop: oneshot::Receiver<()>) {
    let result = run_child_inner(&mut session, &mut stop).await;
    let failed_status = if let Err(error) = result {
        let mut state = session.status.lock().unwrap_or_else(|p| p.into_inner());
        state.state = if error == codes::COLLECTOR_UNAVAILABLE {
            session.supervisor.available.store(false, Ordering::Relaxed);
            codes::COLLECTOR_UNAVAILABLE.into()
        } else if error.contains("auth") {
            "auth_failed".into()
        } else {
            "needs_unlock".into()
        };
        state.last_error = Some(error.chars().take(240).collect());
        Some(state.clone())
    } else {
        None
    };
    let _ = uds_call(
        &session.supervisor.config,
        Method::DELETE,
        &format!("/live/{}/{}", session.account, session.vault),
        Vec::new(),
        &[],
    )
    .await;
    let _ = std::fs::remove_dir_all(&session.data_dir);
    let session_key = key(&session.account, &session.vault.to_string());
    if let Some(status) = failed_status {
        let mut finished = session
            .supervisor
            .finished
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        finished.insert(session_key.clone(), status);
        while finished.len() > 256 {
            let Some(oldest_key) = finished.keys().next().cloned() else {
                break;
            };
            finished.remove(&oldest_key);
        }
    }
    let mut sessions = session
        .supervisor
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if sessions
        .get(&session_key)
        .is_some_and(|running| Arc::ptr_eq(&running.status, &session.status))
    {
        sessions.remove(&session_key);
    }
}

async fn run_child_inner(
    session: &mut ChildSession,
    stop: &mut oneshot::Receiver<()>,
) -> Result<(), String> {
    let ChildSession {
        supervisor,
        account,
        vault,
        payload,
        vault_pk,
        status,
        data_dir,
        child_uid,
    } = session;
    let data_dir = data_dir.as_path();
    let (session_parent, session_child) =
        std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    let (rows_parent, rows_child) =
        std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    let (control_parent, control_child) =
        std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    for stream in [&session_parent, &rows_parent, &control_parent] {
        stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let data_dir_c = CString::new(data_dir.as_os_str().as_encoded_bytes())
        .map_err(std::io::Error::other)
        .map_err(|e| e.to_string())?;
    if unsafe { libc::chown(data_dir_c.as_ptr(), *child_uid, *child_uid) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if !tmpfs(data_dir).map_err(|e| e.to_string())? {
        return Err("collector child data directory is not on tmpfs".into());
    }
    let mut child = launch_child(
        data_dir,
        *child_uid,
        &session_child,
        &rows_child,
        &control_child,
    )
    .map_err(|e| format!("start headless runtime: {e}"))?;
    status.lock().unwrap_or_else(|p| p.into_inner()).state = "running".into();
    drop(session_child);
    drop(rows_child);
    drop(control_child);
    let mut session =
        tokio::net::UnixStream::from_std(session_parent).map_err(|e| e.to_string())?;
    let frame = Zeroizing::new(cbor(&SessionFrame {
        v: 1,
        auth: &payload.cookies.auth,
        two_factor_auth: payload.cookies.two_factor_auth.as_deref(),
    })?);
    let expires_at = payload.expires_at;
    let flush = Duration::from_secs(payload.interval_seconds);
    let mut framed = Zeroizing::new(Vec::with_capacity(frame.len() + 4));
    framed.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    framed.extend_from_slice(&frame);
    session
        .write_all(&framed)
        .await
        .map_err(|e| e.to_string())?;
    session.shutdown().await.map_err(|e| e.to_string())?;
    framed.zeroize();
    payload.zeroize();
    let mut rows_stream =
        tokio::net::UnixStream::from_std(rows_parent).map_err(|e| e.to_string())?;
    let mut control_stream =
        tokio::net::UnixStream::from_std(control_parent).map_err(|e| e.to_string())?;
    let mut batch = FlushBatch {
        rows: Vec::new(),
        pending: None,
        source_seq: 1,
        last_seen_row_id: 0,
        dropped_rows: 0,
        control_id: 0,
    };
    let mut buffered_bytes = 0usize;
    let source = SourceId::random().map_err(|e| e.to_string())?;
    let flush_context = FlushContext {
        supervisor,
        account,
        vault: *vault,
        source,
        vault_pk,
    };
    let mut flush_tick = tokio::time::interval(flush);
    let mut live_tick = tokio::time::interval(LIVE_INTERVAL);
    flush_tick.tick().await;
    live_tick.tick().await;
    loop {
        tokio::select! {
            _ = &mut *stop => { break; }
            result = child.wait() => {
                return Err(match result {
                    Ok(status) if status.code() == Some(COLLECTOR_UNAVAILABLE_EXIT_CODE) => codes::COLLECTOR_UNAVAILABLE.into(),
                    Ok(status) => format!("headless runtime exited: {status}"),
                    Err(error) => error.to_string(),
                });
            }
            result = read_frame(&mut rows_stream), if batch.pending.is_none() => {
                let frame = result.map_err(|e| format!("read child row: {e}"))?;
                let row: ChildRow = from_cbor(&frame)?;
                if row.v != 1 { return Err("unsupported child row version".into()); }
                if row.row_id <= batch.last_seen_row_id { return Err("child row ids must increase".into()); }
                batch.last_seen_row_id = row.row_id;
                let row_bytes = frame.len();
                if batch.rows.len() >= MAX_BUFFERED_ROWS || buffered_bytes.saturating_add(row_bytes) > MAX_BUFFERED_BYTES {
                    batch.dropped_rows = batch.dropped_rows.saturating_add(1);
                    status.lock().unwrap_or_else(|p| p.into_inner()).last_error = Some("collector buffer reached its 32 MiB limit; waiting for API recovery".into());
                } else {
                    buffered_bytes = buffered_bytes.saturating_add(row_bytes);
                    batch.rows.push(row);
                }
            }
            _ = flush_tick.tick() => {
                if let Err(error) = flush_rows(&flush_context, &mut batch, &mut control_stream, status).await {
                    status.lock().unwrap_or_else(|p| p.into_inner()).last_error = Some(error.chars().take(240).collect());
                }
                buffered_bytes = 0;
                for row in &batch.rows { buffered_bytes += row.stream.len() + row.row.to_string().len() + 64; }
            }
            _ = live_tick.tick() => {
                if let Err(error) = publish_live(supervisor, account, *vault, vault_pk, &mut control_stream, &mut batch.control_id).await {
                    status.lock().unwrap_or_else(|p| p.into_inner()).last_error = Some(error.chars().take(240).collect());
                }
            }
        }
        if expires_at.is_some_and(|expiry| now_ms() >= expiry) {
            break;
        }
    }
    let _ = child.kill().await;
    let _ = flush_rows(&flush_context, &mut batch, &mut control_stream, status).await;
    Ok(())
}

async fn capabilities(State(state): State<Shared>) -> axum::Json<Capabilities> {
    axum::Json(Capabilities {
        available: state.available.load(Ordering::Relaxed),
        unlock_key: b64::encode(state.unlock.public().as_bytes()),
        signing_key: b64::encode(state.signer.public().as_bytes()),
        keys_valid_since_ms: state.keys_valid_since_ms,
    })
}

async fn status(
    State(state): State<Shared>,
    AxumPath((account, vault)): AxumPath<(String, String)>,
) -> axum::Json<SessionStatus> {
    let sessions = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
    let session_key = key(&account, &vault);
    let status = sessions
        .get(&key(&account, &vault))
        .map(|session| {
            session
                .status
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        })
        .or_else(|| {
            state
                .finished
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&session_key)
                .cloned()
        })
        .unwrap_or_else(|| {
            let available = state.available.load(Ordering::Relaxed);
            SessionStatus {
                state: if available {
                    "locked"
                } else {
                    codes::COLLECTOR_UNAVAILABLE
                }
                .into(),
                since: None,
                last_chunk_at: None,
                last_error: (!available).then(|| codes::COLLECTOR_UNAVAILABLE.into()),
            }
        });
    axum::Json(status)
}

async fn unlock(
    State(state): State<Shared>,
    AxumPath((account, vault_text)): AxumPath<(String, String)>,
    body: Bytes,
) -> Response {
    if !state.available.load(Ordering::Relaxed) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(ApiError::new(
                codes::COLLECTOR_UNAVAILABLE,
                codes::COLLECTOR_UNAVAILABLE,
            )),
        )
            .into_response();
    }
    let vault: VaultId = match vault_text.parse() {
        Ok(vault) => vault,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid vault id").into_response(),
    };
    let aad = [account.as_bytes(), vault.as_bytes()].concat();
    let plaintext = match seal::open(&state.unlock, b"remotesync/v1/unlock", &aad, &body) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid sealed unlock payload").into_response();
        }
    };
    let mut payload: UnlockPayload = match serde_json::from_slice(&plaintext) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid unlock payload").into_response(),
    };
    if payload.version != 1
        || payload.expires_at.is_some_and(|expiry| {
            expiry <= now_ms() || expiry > now_ms() + 30 * 24 * 60 * 60 * 1000
        })
        || !(60..=900).contains(&payload.interval_seconds)
        || payload.vrchat_user_id.is_empty()
        || payload.vrchat_user_id.len() > 128
        || payload.cookies.auth.is_empty()
        || payload.cookies.auth.len() > 16 * 1024
        || payload
            .cookies
            .two_factor_auth
            .as_ref()
            .is_some_and(|cookie| cookie.is_empty() || cookie.len() > 16 * 1024)
        || payload.vault_pk.len() > 128
    {
        payload.zeroize();
        return (StatusCode::BAD_REQUEST, "unlock payload fields are invalid").into_response();
    }
    let pk_bytes = match BASE64URL_NOPAD.decode(payload.vault_pk.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            payload.zeroize();
            return (StatusCode::BAD_REQUEST, "invalid vault public key").into_response();
        }
    };
    let vault_pk = match SealPublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            payload.zeroize();
            return (StatusCode::BAD_REQUEST, "invalid vault public key").into_response();
        }
    };
    let session_key = key(&account, &vault.to_string());
    let _unlock_guard = state.unlock_guard.lock().await;
    let old = {
        state
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&session_key)
    };
    if let Some(old) = old {
        let _ = old.stop.send(());
        let _ = old.task.await;
        let _ = std::fs::remove_dir_all(old.data_dir);
    }
    if state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
        >= state.max_sessions
    {
        payload.zeroize();
        return (StatusCode::SERVICE_UNAVAILABLE, "collector is at capacity").into_response();
    }
    let child_uid = {
        let sessions = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let occupied: std::collections::HashSet<u32> =
            sessions.values().map(|session| session.child_uid).collect();
        (CHILD_UID_BASE..CHILD_UID_BASE + CHILD_UID_COUNT).find(|uid| !occupied.contains(uid))
    };
    let Some(child_uid) = child_uid else {
        payload.zeroize();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "collector child identity pool is exhausted",
        )
            .into_response();
    };
    let data_dir = state.config.tmpfs.join(format!(
        "{}-{}",
        account,
        BASE64URL_NOPAD
            .encode(&vrcx_0_nanashi_website_protocol::rand::bytes::<12>().unwrap_or([0; 12]))
    ));
    let status = Arc::new(Mutex::new(SessionStatus {
        state: "starting".into(),
        since: Some(now_ms()),
        last_chunk_at: None,
        last_error: None,
    }));
    let (stop, receiver) = oneshot::channel();
    let shared = state.clone();
    let account_for_task = account.clone();
    let payload_for_task = payload;
    let status_for_task = status.clone();
    let dir_for_task = data_dir.clone();
    let (ready, start) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = start.await;
        run_child(
            ChildSession {
                supervisor: shared,
                account: account_for_task,
                vault,
                payload: payload_for_task,
                vault_pk,
                status: status_for_task,
                data_dir: dir_for_task,
                child_uid,
            },
            receiver,
        )
        .await;
    });
    state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            session_key,
            RunningSession {
                child_uid,
                stop,
                status,
                task,
                data_dir,
            },
        );
    state
        .finished
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&key(&account, &vault.to_string()));
    let _ = ready.send(());
    (StatusCode::ACCEPTED, "").into_response()
}

async fn lock(
    State(state): State<Shared>,
    AxumPath((account, vault)): AxumPath<(String, String)>,
) -> StatusCode {
    let session = {
        state
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key(&account, &vault))
    };
    if let Some(session) = session {
        let _ = session.stop.send(());
        let _ = session.task.await;
        let _ = std::fs::remove_dir_all(session.data_dir);
    }
    StatusCode::NO_CONTENT
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    std::fs::create_dir_all(&config.tmpfs)?;
    if !tmpfs(&config.tmpfs)? {
        return Err(format!("{} must be a tmpfs mount", config.tmpfs.display()).into());
    }
    let available = compatible_collector_available();
    if !available {
        tracing::warn!(
            binary = HEADLESS_BINARY,
            metadata = HEADLESS_METADATA,
            "compatible headless runtime unavailable; collector disabled"
        );
    }
    let state = Arc::new(Supervisor {
        config: config.clone(),
        unlock: SealPrivateKey::generate(),
        signer: SignerKey::generate()?,
        available: AtomicBool::new(available),
        keys_valid_since_ms: now_ms(),
        max_sessions: config.max_sessions.clamp(1, 256),
        unlock_guard: tokio::sync::Mutex::new(()),
        sessions: Mutex::new(HashMap::new()),
        finished: Mutex::new(HashMap::new()),
    });
    let update_state = state.clone();
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(5 * 60))
            .user_agent("VRCX-0-Nanashi-RemoteSync-Collector")
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "collector runtime updater could not start");
                return;
            }
        };
        loop {
            match update_headless_runtime(&client).await {
                Ok(Some(version)) => {
                    update_state
                        .available
                        .store(compatible_collector_available(), Ordering::Relaxed);
                    tracing::info!(%version, "updated VRCX headless collector runtime");
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, "VRCX headless collector update check failed"),
            }
            tokio::time::sleep(RUNTIME_UPDATE_INTERVAL).await;
        }
    });
    let listener = bind(&config.socket)?;
    tracing::info!(socket=%config.socket.display(), available, "collector supervisor listening");
    let app = Router::new()
        .route("/capabilities", get(capabilities))
        .route("/status/{account}/{vault}", get(status))
        .route("/unlock/{account}/{vault}", post(unlock))
        .route("/lock/{account}/{vault}", post(lock))
        .route("/lock-account/{account}", post(lock_account))
        .with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn lock_account(
    State(state): State<Shared>,
    AxumPath(account): AxumPath<String>,
) -> StatusCode {
    let vaults = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .keys()
        .filter_map(|session| {
            session
                .strip_prefix(&format!("{account}/"))
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    for vault in vaults {
        let _ = lock(State(state.clone()), AxumPath((account.clone(), vault))).await;
    }
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    run(Config::parse()).await
}
