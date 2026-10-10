use std::time::Duration;

use reqwest::StatusCode;
use rusty_s3::actions::{ListObjectsV2, ObjectIdentifier};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use vrcx_0_nanashi_website_protocol::blob::ListEntry;

use crate::backend::{BackendError, BackendResult, LIST_PAGE};
use crate::config::S3Config;

const SIGNATURE_LIFETIME: Duration = Duration::from_secs(300);

pub struct S3Backend {
    bucket: Bucket,
    credentials: Credentials,
    client: reqwest::Client,
}

fn http_error(context: &str, error: reqwest::Error) -> BackendError {
    BackendError(format!("{context}: {}", error.without_url()))
}

async fn status_error(context: &str, response: reqwest::Response) -> BackendError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let code = body
        .split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or("");
    BackendError(format!("{context}: HTTP {status} {code}"))
}

pub fn parse_last_modified(value: &str) -> i64 {
    value
        .parse::<jiff::Timestamp>()
        .map(|t| t.as_millisecond())
        .unwrap_or(0)
}

impl S3Backend {
    pub fn new(config: &S3Config) -> BackendResult<Self> {
        let style = if config.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let bucket = Bucket::new(
            config.endpoint.clone(),
            style,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|e| BackendError(format!("bucket: {e}")))?;
        let mut builder = reqwest::Client::builder();
        if let Some(pem) = &config.extra_ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| BackendError(format!("REMOTESYNC_S3_CA_FILE: {}", e.without_url())))?;
            if certs.is_empty() {
                return Err(BackendError(
                    "REMOTESYNC_S3_CA_FILE contains no certificates".into(),
                ));
            }
            builder = builder.tls_certs_merge(certs);
        }
        let client = builder
            .https_only(true)
            .tls_version_min(reqwest::tls::Version::TLS_1_2)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| http_error("http client", e))?;
        Ok(Self {
            bucket,
            credentials: Credentials::new(config.access_key.clone(), config.secret_key.clone()),
            client,
        })
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> BackendResult<()> {
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGNATURE_LIFETIME);
        let response = self
            .client
            .put(url)
            .body(data)
            .send()
            .await
            .map_err(|e| http_error("put", e))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(status_error("put", response).await)
        }
    }

    pub async fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGNATURE_LIFETIME);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| http_error("get", e))?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => Ok(Some(
                response
                    .bytes()
                    .await
                    .map_err(|e| http_error("get body", e))?
                    .to_vec(),
            )),
            _ => Err(status_error("get", response).await),
        }
    }

    pub async fn delete(&self, key: &str) -> BackendResult<()> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGNATURE_LIFETIME);
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(|e| http_error("delete", e))?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(status_error("delete", response).await)
        }
    }

    pub async fn list(
        &self,
        prefix: &str,
        token: Option<String>,
    ) -> BackendResult<(Vec<ListEntry>, Option<String>)> {
        let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
        action.with_prefix(prefix);
        action.with_max_keys(LIST_PAGE);
        if let Some(token) = &token {
            action.with_continuation_token(token.as_str());
        }
        let url = action.sign(SIGNATURE_LIFETIME);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| http_error("list", e))?;
        if !response.status().is_success() {
            return Err(status_error("list", response).await);
        }
        let text = response
            .text()
            .await
            .map_err(|e| http_error("list body", e))?;
        let parsed =
            ListObjectsV2::parse_response(&text).map_err(|e| BackendError(format!("list: {e}")))?;
        let objects = parsed
            .contents
            .into_iter()
            .map(|item| ListEntry {
                last_modified_ms: parse_last_modified(&item.last_modified),
                key: item.key,
                size: item.size,
            })
            .collect();
        Ok((objects, parsed.next_continuation_token))
    }

    pub async fn delete_prefix(&self, prefix: &str) -> BackendResult<u64> {
        let mut deleted = 0;
        loop {
            let (objects, next) = self.list(prefix, None).await?;
            if objects.is_empty() {
                return Ok(deleted);
            }
            let identifiers: Vec<ObjectIdentifier> = objects
                .iter()
                .map(|o| ObjectIdentifier::new(o.key.clone()))
                .collect();
            let mut action = self
                .bucket
                .delete_objects(Some(&self.credentials), identifiers.iter());
            action.set_quiet(true);
            let url = action.sign(SIGNATURE_LIFETIME);
            let (body, content_md5) = action.body_with_md5();
            let response = self
                .client
                .post(url)
                .header("Content-MD5", content_md5)
                .body(body)
                .send()
                .await
                .map_err(|e| http_error("delete objects", e))?;
            if !response.status().is_success() {
                return Err(status_error("delete objects", response).await);
            }
            let text = response.text().await.unwrap_or_default();
            if text.contains("<Error>") {
                return Err(BackendError(
                    "delete objects: some objects could not be deleted".into(),
                ));
            }
            deleted += objects.len() as u64;
            if next.is_none() && objects.len() < LIST_PAGE {
                return Ok(deleted);
            }
        }
    }

    pub async fn health(&self) -> BackendResult<()> {
        let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
        action.with_prefix("v1/");
        action.with_max_keys(1);
        let url = action.sign(SIGNATURE_LIFETIME);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| http_error("health", e))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(status_error("health", response).await)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_modified_parsing() {
        assert_eq!(
            parse_last_modified("2026-10-08T12:00:00.000Z"),
            1_791_460_800_000
        );
        assert_eq!(parse_last_modified("garbage"), 0);
    }

    #[test]
    fn refuses_plain_http_endpoints_at_request_time() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let backend = S3Backend::new(&S3Config {
            endpoint: "http://127.0.0.1:1".parse().unwrap(),
            bucket: "b".into(),
            region: "auto".into(),
            path_style: true,
            access_key: "k".into(),
            secret_key: "s".into(),
            extra_ca_pem: None,
        })
        .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime.block_on(backend.get("v1/x/y")).unwrap_err();
        assert!(
            !error.0.contains("X-Amz-Signature"),
            "errors must not leak signatures: {}",
            error.0
        );
    }
}
