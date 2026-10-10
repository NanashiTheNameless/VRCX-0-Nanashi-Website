use std::path::PathBuf;

use vrcx_0_nanashi_website_protocol::api::Registration;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub api_socket: PathBuf,
    pub collector_ingest_socket: PathBuf,
    pub collector_socket: PathBuf,
    pub blob_socket: PathBuf,
    pub mail_socket: PathBuf,
    pub master_key_file: PathBuf,
    pub registration: Registration,
    pub default_quota_bytes: Option<u64>,
    pub collector_default_allowed: bool,
    pub web_origins: Vec<String>,
    pub api_origin: String,
    pub policy_url: Option<String>,
    pub instance_statement: Option<String>,
    pub instance_signature: Option<String>,
    pub commit: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is invalid: {1}")]
    Invalid(&'static str, String),
}

pub fn parse_size(value: &str) -> Result<Option<u64>, String> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("unlimited") {
        return Ok(None);
    }
    let units = [
        ("TiB", 1_u64 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (suffix, factor) in units {
        if let Some(number) = value.strip_suffix(suffix) {
            let number: u64 = number
                .trim()
                .parse()
                .map_err(|_| format!("bad number in {value:?}"))?;
            return number
                .checked_mul(factor)
                .map(Some)
                .ok_or_else(|| "too large".to_owned());
        }
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| format!("expected a size like 1GiB, got {value:?}"))
}

pub fn format_size(bytes: Option<u64>) -> String {
    match bytes {
        None => "unlimited".into(),
        Some(b) if b >= 1 << 40 && b % (1 << 40) == 0 => format!("{}TiB", b >> 40),
        Some(b) if b >= 1 << 30 && b % (1 << 30) == 0 => format!("{}GiB", b >> 30),
        Some(b) if b >= 1 << 20 && b % (1 << 20) == 0 => format!("{}MiB", b >> 20),
        Some(b) => format!("{b}B"),
    }
}

pub const MIN_QUOTA: u64 = 16 << 20;
pub const MAX_QUOTA: u64 = 1 << 40;

pub fn validate_quota(quota: Option<u64>) -> Result<(), String> {
    match quota {
        Some(q) if !(MIN_QUOTA..=MAX_QUOTA).contains(&q) => {
            Err("size limit must be 16MiB to 1TiB, or unlimited".into())
        }
        _ => Ok(()),
    }
}

fn origin(name: &'static str, value: &str) -> Result<String, ConfigError> {
    let value = value.trim().trim_end_matches('/').to_ascii_lowercase();
    let rest = value
        .strip_prefix("https://")
        .ok_or_else(|| ConfigError::Invalid(name, "must start with https://".into()))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(ConfigError::Invalid(
            name,
            "must be an origin (https://host[:port])".into(),
        ));
    }
    Ok(value)
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let registration = match get("REMOTESYNC_REGISTRATION")
            .as_deref()
            .unwrap_or("closed")
        {
            "request" => Registration::Request,
            "closed" => Registration::Closed,
            other => {
                return Err(ConfigError::Invalid(
                    "REMOTESYNC_REGISTRATION",
                    other.into(),
                ));
            }
        };
        let default_quota_bytes =
            parse_size(&get("REMOTESYNC_DEFAULT_QUOTA").unwrap_or_else(|| "1GiB".into()))
                .map_err(|e| ConfigError::Invalid("REMOTESYNC_DEFAULT_QUOTA", e))?;
        validate_quota(default_quota_bytes)
            .map_err(|e| ConfigError::Invalid("REMOTESYNC_DEFAULT_QUOTA", e))?;
        let web_origins = get("REMOTESYNC_WEB_ORIGINS")
            .unwrap_or_else(|| "https://vrcx.namelessnanashi.dev".into())
            .split(',')
            .filter(|v| !v.trim().is_empty())
            .map(|v| origin("REMOTESYNC_WEB_ORIGINS", v))
            .collect::<Result<_, _>>()?;
        let api_origin = origin(
            "REMOTESYNC_API_ORIGIN",
            &get("REMOTESYNC_API_ORIGIN")
                .unwrap_or_else(|| "https://vrcx-api.namelessnanashi.dev".into()),
        )?;
        let collector_default_allowed = match get("REMOTESYNC_COLLECTOR_DEFAULT_ALLOWED").as_deref()
        {
            None | Some("true") => true,
            Some("false") => false,
            Some(other) => {
                return Err(ConfigError::Invalid(
                    "REMOTESYNC_COLLECTOR_DEFAULT_ALLOWED",
                    other.into(),
                ));
            }
        };
        Ok(Self {
            data_dir: get("REMOTESYNC_DATA_DIR")
                .unwrap_or_else(|| "/data".into())
                .into(),
            api_socket: get("REMOTESYNC_API_SOCKET")
                .unwrap_or_else(|| "/run/remotesync/api-sock/api.sock".into())
                .into(),
            collector_ingest_socket: get("REMOTESYNC_COLLECTOR_API_SOCKET")
                .unwrap_or_else(|| "/run/remotesync/collector-sock/api.sock".into())
                .into(),
            collector_socket: get("REMOTESYNC_COLLECTOR_SOCKET")
                .unwrap_or_else(|| "/run/remotesync/collector/ctl.sock".into())
                .into(),
            mail_socket: get("REMOTESYNC_MAIL_SOCKET")
                .unwrap_or_else(|| "/run/remotesync/mail/mail.sock".into())
                .into(),
            blob_socket: get("REMOTESYNC_BLOB_SOCKET")
                .unwrap_or_else(|| "/run/remotesync/blob/blob.sock".into())
                .into(),
            master_key_file: get("REMOTESYNC_MASTER_KEY_FILE")
                .unwrap_or_else(|| "/run/secrets/remotesync_master_key".into())
                .into(),
            registration,
            default_quota_bytes,
            collector_default_allowed,
            web_origins,
            api_origin,
            policy_url: get("REMOTESYNC_POLICY_URL"),
            instance_statement: get("REMOTESYNC_INSTANCE_STATEMENT"),
            instance_signature: get("REMOTESYNC_INSTANCE_SIGNATURE"),
            commit: option_env!("REMOTESYNC_COMMIT").unwrap_or("unknown").into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("1GiB").unwrap(), Some(1 << 30));
        assert_eq!(parse_size(" 512MiB ").unwrap(), Some(512 << 20));
        assert_eq!(parse_size("unlimited").unwrap(), None);
        assert_eq!(parse_size("42").unwrap(), Some(42));
        assert!(parse_size("1GB").is_err());
        assert_eq!(format_size(Some(1 << 30)), "1GiB");
        assert_eq!(format_size(None), "unlimited");
        assert!(validate_quota(Some(1 << 20)).is_err());
        assert!(validate_quota(Some(1 << 30)).is_ok());
        assert!(validate_quota(None).is_ok());
    }

    #[test]
    fn origins_must_be_https_origins() {
        assert_eq!(
            origin("x", "https://VRCX.namelessnanashi.dev/").unwrap(),
            "https://vrcx.namelessnanashi.dev"
        );
        assert!(origin("x", "http://example.com").is_err());
        assert!(origin("x", "https://example.com/path").is_err());
        assert!(origin("x", "https://user@example.com").is_err());
    }
}
