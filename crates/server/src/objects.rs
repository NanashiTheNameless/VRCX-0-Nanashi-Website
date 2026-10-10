#[cfg(test)]
use std::collections::BTreeMap;
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Mutex;

use hyper::{Method, StatusCode};
use vrcx_0_nanashi_website_protocol::blob::{
    DeletePrefixRequest, DeletePrefixResponse, Health, ListEntry, ListResponse,
};

#[derive(Debug, thiserror::Error)]
#[error("object storage: {0}")]
pub struct ObjectError(pub String);

pub type ObjectResult<T> = Result<T, ObjectError>;

pub enum ObjectStore {
    Socket {
        path: PathBuf,
    },
    #[cfg(test)]
    Memory(Mutex<BTreeMap<String, (Vec<u8>, i64)>>),
}

fn err(context: &str, error: impl std::fmt::Display) -> ObjectError {
    ObjectError(format!("{context}: {error}"))
}

impl From<crate::uds::UdsError> for ObjectError {
    fn from(error: crate::uds::UdsError) -> Self {
        Self(error.0)
    }
}

impl ObjectStore {
    pub fn socket(path: PathBuf) -> Self {
        Self::Socket { path }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self::Memory(Mutex::new(BTreeMap::new()))
    }

    #[cfg(test)]
    fn memory_map(
        map: &Mutex<BTreeMap<String, (Vec<u8>, i64)>>,
    ) -> std::sync::MutexGuard<'_, BTreeMap<String, (Vec<u8>, i64)>> {
        map.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> ObjectResult<()> {
        match self {
            Self::Socket { path } => {
                let (status, _) =
                    crate::uds::call(path, Method::PUT, &format!("/objects/{key}"), data, false)
                        .await?;
                if status.is_success() {
                    Ok(())
                } else {
                    Err(ObjectError(format!("put: HTTP {status}")))
                }
            }
            #[cfg(test)]
            Self::Memory(map) => {
                Self::memory_map(map).insert(key.to_owned(), (data, crate::util::now_ms()));
                Ok(())
            }
        }
    }

    pub async fn get(&self, key: &str) -> ObjectResult<Option<Vec<u8>>> {
        match self {
            Self::Socket { path } => {
                let (status, body) = crate::uds::call(
                    path,
                    Method::GET,
                    &format!("/objects/{key}"),
                    Vec::new(),
                    false,
                )
                .await?;
                match status {
                    StatusCode::NOT_FOUND => Ok(None),
                    s if s.is_success() => Ok(Some(body.to_vec())),
                    s => Err(ObjectError(format!("get: HTTP {s}"))),
                }
            }
            #[cfg(test)]
            Self::Memory(map) => Ok(Self::memory_map(map).get(key).map(|(data, _)| data.clone())),
        }
    }

    pub async fn delete(&self, key: &str) -> ObjectResult<()> {
        match self {
            Self::Socket { path } => {
                let (status, _) = crate::uds::call(
                    path,
                    Method::DELETE,
                    &format!("/objects/{key}"),
                    Vec::new(),
                    false,
                )
                .await?;
                if status.is_success() {
                    Ok(())
                } else {
                    Err(ObjectError(format!("delete: HTTP {status}")))
                }
            }
            #[cfg(test)]
            Self::Memory(map) => {
                Self::memory_map(map).remove(key);
                Ok(())
            }
        }
    }

    pub async fn delete_prefix(&self, prefix: &str) -> ObjectResult<u64> {
        match self {
            Self::Socket { path } => {
                let body = serde_json::to_vec(&DeletePrefixRequest {
                    prefix: prefix.to_owned(),
                })
                .map_err(|e| err("encode", e))?;
                let (status, body) =
                    crate::uds::call(path, Method::POST, "/delete-prefix", body, true).await?;
                if !status.is_success() {
                    return Err(ObjectError(format!("delete prefix: HTTP {status}")));
                }
                let response: DeletePrefixResponse =
                    serde_json::from_slice(&body).map_err(|e| err("decode", e))?;
                Ok(response.deleted)
            }
            #[cfg(test)]
            Self::Memory(map) => {
                let mut map = Self::memory_map(map);
                let before = map.len();
                map.retain(|key, _| !key.starts_with(prefix));
                Ok((before - map.len()) as u64)
            }
        }
    }

    pub async fn list_all(&self, prefix: &str) -> ObjectResult<Vec<ListEntry>> {
        match self {
            Self::Socket { path } => {
                let mut out = Vec::new();
                let mut token: Option<String> = None;
                loop {
                    let mut uri = format!("/list?prefix={prefix}");
                    if let Some(t) = &token {
                        uri.push_str("&token=");
                        uri.push_str(&encode_query(t));
                    }
                    let (status, body) =
                        crate::uds::call(path, Method::GET, &uri, Vec::new(), false).await?;
                    if !status.is_success() {
                        return Err(ObjectError(format!("list: HTTP {status}")));
                    }
                    let page: ListResponse =
                        serde_json::from_slice(&body).map_err(|e| err("decode", e))?;
                    out.extend(page.objects);
                    match page.next {
                        Some(next) => token = Some(next),
                        None => return Ok(out),
                    }
                }
            }
            #[cfg(test)]
            Self::Memory(map) => Ok(Self::memory_map(map)
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, (data, at))| ListEntry {
                    key: key.clone(),
                    size: data.len() as u64,
                    last_modified_ms: *at,
                })
                .collect()),
        }
    }

    pub async fn health(&self) -> ObjectResult<Health> {
        match self {
            Self::Socket { path } => {
                let (_, body) =
                    crate::uds::call(path, Method::GET, "/health", Vec::new(), false).await?;
                serde_json::from_slice(&body).map_err(|e| err("decode", e))
            }
            #[cfg(test)]
            Self::Memory(_) => Ok(Health {
                backend: "memory".into(),
                ok: true,
                detail: None,
            }),
        }
    }

    #[cfg(test)]
    pub fn memory_keys(&self) -> Vec<String> {
        match self {
            Self::Memory(map) => Self::memory_map(map).keys().cloned().collect(),
            Self::Socket { .. } => Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn memory_insert(&self, key: &str, data: Vec<u8>, at_ms: i64) {
        if let Self::Memory(map) = self {
            Self::memory_map(map).insert(key.to_owned(), (data, at_ms));
        }
    }
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
