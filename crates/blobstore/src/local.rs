use std::path::{Path, PathBuf};

use vrcx_0_nanashi_website_protocol::blob::ListEntry;

use crate::backend::{BackendError, BackendResult, LIST_PAGE};

pub struct LocalBackend {
    dir: PathBuf,
}

impl LocalBackend {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> BackendResult<()> {
        let path = self.path(key);
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let parent = path.parent().expect("object keys have a parent");
            std::fs::create_dir_all(parent)?;
            let temp = parent.join(format!(
                ".tmp-{}",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("object")
            ));
            {
                use std::io::Write;
                let mut file = std::fs::File::create(&temp)?;
                file.write_all(&data)?;
                file.sync_all()?;
            }
            std::fs::rename(&temp, &path)?;
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })
        .await
        .map_err(BackendError::task)?
        .map_err(BackendError::io)
    }

    pub async fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(key)).await {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(BackendError::io(error)),
        }
    }

    pub async fn delete(&self, key: &str) -> BackendResult<()> {
        match tokio::fs::remove_file(self.path(key)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(BackendError::io(error)),
        }
    }

    pub async fn delete_prefix(&self, prefix: &str) -> BackendResult<u64> {
        let dir = self.path(prefix.trim_end_matches('/'));
        tokio::task::spawn_blocking(move || -> std::io::Result<u64> {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(error) => return Err(error),
            };
            let mut deleted = 0;
            for entry in entries {
                std::fs::remove_file(entry?.path())?;
                deleted += 1;
            }
            std::fs::remove_dir(&dir)?;
            Ok(deleted)
        })
        .await
        .map_err(BackendError::task)?
        .map_err(BackendError::io)
    }

    pub async fn list(
        &self,
        prefix: &str,
        token: Option<String>,
    ) -> BackendResult<(Vec<ListEntry>, Option<String>)> {
        let dir = self.path(prefix.trim_end_matches('/'));
        let prefix = prefix.to_owned();
        tokio::task::spawn_blocking(
            move || -> std::io::Result<(Vec<ListEntry>, Option<String>)> {
                let mut names: Vec<String> = match std::fs::read_dir(&dir) {
                    Ok(entries) => entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| e.file_name().into_string().ok())
                        .filter(|name| !name.starts_with('.'))
                        .collect(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Err(error) => return Err(error),
                };
                names.sort();
                let mut objects = Vec::new();
                for name in names {
                    let key = format!("{prefix}{name}");
                    if token.as_deref().is_some_and(|after| key.as_str() <= after) {
                        continue;
                    }
                    if objects.len() == LIST_PAGE {
                        let next = objects.last().map(|e: &ListEntry| e.key.clone());
                        return Ok((objects, next));
                    }
                    let meta = std::fs::metadata(dir.join(&name))?;
                    let modified = vrcx_0_nanashi_website_protocol::time::system_time_seconds(
                        meta.modified()?,
                    );
                    objects.push(ListEntry {
                        key,
                        size: meta.len(),
                        last_modified: modified,
                    });
                }
                Ok((objects, None))
            },
        )
        .await
        .map_err(BackendError::task)?
        .map_err(BackendError::io)
    }

    pub async fn health(&self) -> BackendResult<()> {
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || check_writable(&dir))
            .await
            .map_err(BackendError::task)?
            .map_err(BackendError::io)
    }
}

fn check_writable(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let probe = dir.join(".health");
    std::fs::write(&probe, b"ok")?;
    std::fs::remove_file(probe)
}
