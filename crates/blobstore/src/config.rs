use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum BackendConfig {
    Local { dir: PathBuf },
    S3(S3Config),
}

#[derive(Clone, Debug)]
pub struct S3Config {
    pub endpoint: url::Url,
    pub bucket: String,
    pub region: String,
    pub path_style: bool,
    pub access_key: String,
    pub secret_key: String,
    pub extra_ca_pem: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub socket: PathBuf,
    pub backend: BackendConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is invalid: {1}")]
    Invalid(&'static str, String),
}

pub fn parse_credentials(text: &str) -> Result<(String, String), ConfigError> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    match (lines.next(), lines.next(), lines.next()) {
        (Some(key), Some(secret), None) => Ok((key.to_owned(), secret.to_owned())),
        _ => Err(ConfigError::Invalid(
            "blob_credentials",
            "expected two lines: access key id, secret access key".into(),
        )),
    }
}

pub fn parse_endpoint(value: &str) -> Result<url::Url, ConfigError> {
    let url = url::Url::parse(value.trim())
        .map_err(|e| ConfigError::Invalid("REMOTESYNC_S3_ENDPOINT", e.to_string()))?;
    if url.scheme() != "https" {
        return Err(ConfigError::Invalid(
            "REMOTESYNC_S3_ENDPOINT",
            "must be https://".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
        return Err(ConfigError::Invalid(
            "REMOTESYNC_S3_ENDPOINT",
            "must not contain credentials or a query".into(),
        ));
    }
    Ok(url)
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let socket = get("REMOTESYNC_BLOB_SOCKET")
            .unwrap_or_else(|| "/run/remotesync/blob/blob.sock".into())
            .into();
        let backend = match get("REMOTESYNC_BLOB_BACKEND").as_deref().unwrap_or("s3") {
            "local" => BackendConfig::Local {
                dir: get("REMOTESYNC_BLOB_DIR")
                    .unwrap_or_else(|| "/blobs".into())
                    .into(),
            },
            "s3" => {
                let endpoint = parse_endpoint(
                    &get("REMOTESYNC_S3_ENDPOINT")
                        .ok_or(ConfigError::Missing("REMOTESYNC_S3_ENDPOINT"))?,
                )?;
                let bucket = get("REMOTESYNC_S3_BUCKET")
                    .ok_or(ConfigError::Missing("REMOTESYNC_S3_BUCKET"))?;
                let path_style = match get("REMOTESYNC_S3_PATH_STYLE").as_deref().unwrap_or("true")
                {
                    "true" => true,
                    "false" => false,
                    other => {
                        return Err(ConfigError::Invalid(
                            "REMOTESYNC_S3_PATH_STYLE",
                            other.into(),
                        ));
                    }
                };
                let credentials_file = get("REMOTESYNC_BLOB_CREDENTIALS_FILE")
                    .unwrap_or_else(|| "/run/secrets/blob_credentials".into());
                let text = std::fs::read_to_string(&credentials_file)
                    .map_err(|e| ConfigError::Invalid("blob_credentials", e.to_string()))?;
                let (access_key, secret_key) = parse_credentials(&text)?;
                let extra_ca_pem = match get("REMOTESYNC_S3_CA_FILE") {
                    Some(path) => Some(std::fs::read(&path).map_err(|e| {
                        ConfigError::Invalid("REMOTESYNC_S3_CA_FILE", e.to_string())
                    })?),
                    None => None,
                };
                BackendConfig::S3(S3Config {
                    endpoint,
                    bucket,
                    region: get("REMOTESYNC_S3_REGION").unwrap_or_else(|| "auto".into()),
                    path_style,
                    access_key,
                    secret_key,
                    extra_ca_pem,
                })
            }
            other => {
                return Err(ConfigError::Invalid(
                    "REMOTESYNC_BLOB_BACKEND",
                    other.into(),
                ));
            }
        };
        Ok(Self { socket, backend })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_and_endpoint() {
        assert_eq!(
            parse_credentials("AKID\nsecret\n").unwrap(),
            ("AKID".to_owned(), "secret".to_owned())
        );
        assert!(parse_credentials("only-one").is_err());
        assert!(parse_credentials("a\nb\nc").is_err());
        assert!(parse_endpoint("https://acct.r2.cloudflarestorage.com").is_ok());
        assert!(parse_endpoint("http://minio.local:9000").is_err());
        assert!(parse_endpoint("https://user:pw@example.com").is_err());
    }
}
