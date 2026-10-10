use vrcx_0_nanashi_website_protocol::blob::ListEntry;

use crate::config::BackendConfig;
use crate::local::LocalBackend;
use crate::s3::S3Backend;

pub const LIST_PAGE: usize = 1000;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

impl BackendError {
    pub fn io(error: std::io::Error) -> Self {
        Self(format!("filesystem: {error}"))
    }

    pub fn task(error: tokio::task::JoinError) -> Self {
        Self(format!("task: {error}"))
    }
}

pub type BackendResult<T> = Result<T, BackendError>;

pub enum Backend {
    Local(LocalBackend),
    S3(S3Backend),
}

impl Backend {
    pub fn from_config(config: &BackendConfig) -> BackendResult<Self> {
        Ok(match config {
            BackendConfig::Local { dir } => Self::Local(LocalBackend::new(dir.clone())),
            BackendConfig::S3(s3) => Self::S3(S3Backend::new(s3)?),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::S3(_) => "s3",
        }
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> BackendResult<()> {
        match self {
            Self::Local(b) => b.put(key, data).await,
            Self::S3(b) => b.put(key, data).await,
        }
    }

    pub async fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        match self {
            Self::Local(b) => b.get(key).await,
            Self::S3(b) => b.get(key).await,
        }
    }

    pub async fn delete(&self, key: &str) -> BackendResult<()> {
        match self {
            Self::Local(b) => b.delete(key).await,
            Self::S3(b) => b.delete(key).await,
        }
    }

    pub async fn delete_prefix(&self, prefix: &str) -> BackendResult<u64> {
        match self {
            Self::Local(b) => b.delete_prefix(prefix).await,
            Self::S3(b) => b.delete_prefix(prefix).await,
        }
    }

    pub async fn list(
        &self,
        prefix: &str,
        token: Option<String>,
    ) -> BackendResult<(Vec<ListEntry>, Option<String>)> {
        match self {
            Self::Local(b) => b.list(prefix, token).await,
            Self::S3(b) => b.list(prefix, token).await,
        }
    }

    pub async fn health(&self) -> BackendResult<()> {
        match self {
            Self::Local(b) => b.health().await,
            Self::S3(b) => b.health().await,
        }
    }
}
