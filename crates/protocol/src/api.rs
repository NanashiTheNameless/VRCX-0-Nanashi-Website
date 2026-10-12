use serde::{Deserialize, Serialize};

use crate::ids::{AccountId, ChunkId, VaultId};

pub const PROTOCOL_VERSION: u32 = 1;
pub const SERVER_NAME: &str = "vrcx-0-nanashi-website";

pub mod headers {
    pub const CHUNK_ID: &str = "x-chunk-id";
    pub const MANIFEST_SEQ: &str = "x-manifest-seq";
    pub const IF_MATCH_SEQ: &str = "if-match-seq";
    pub const LIVE_SEQ: &str = "x-live-seq";
    pub const LIVE_AGE: &str = "x-live-age";
    pub const CLIENT: &str = "x-rs-client";
}

pub const MAX_CHUNK_BYTES: usize = crate::padding::MAX_PADDED + crate::seal::OVERHEAD;
pub const MAX_REQUEST_BYTES: usize = 5 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

pub mod codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const FORBIDDEN_SCOPE: &str = "forbidden_scope";
    pub const FEATURE_DISABLED: &str = "feature_disabled";
    pub const REAUTH_REQUIRED: &str = "reauth_required";
    pub const SYNC_DISABLED: &str = "sync_disabled";
    pub const STORAGE_UNAVAILABLE: &str = "storage_unavailable";
    pub const VAULT_NOT_FOUND: &str = "vault_not_found";
    pub const CHUNK_NOT_FOUND: &str = "chunk_not_found";
    pub const MANIFEST_NOT_FOUND: &str = "manifest_not_found";
    pub const LIVE_NOT_FOUND: &str = "live_not_found";
    pub const TRANSFER_NOT_FOUND: &str = "transfer_not_found";
    pub const CLIENT_NOT_FOUND: &str = "client_not_found";
    pub const COLLECTION_NOT_FOUND: &str = "collection_not_found";
    pub const MANIFEST_SEQ_CONFLICT: &str = "manifest_seq_conflict";
    pub const CHUNK_ID_EXISTS: &str = "chunk_id_exists";
    pub const VAULT_EXISTS: &str = "vault_exists";
    pub const TOO_LARGE: &str = "too_large";
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const COLLECTOR_UNAVAILABLE: &str = "collector_unavailable";
    pub const AUTHORIZATION_PENDING: &str = "authorization_pending";
    pub const SLOW_DOWN: &str = "slow_down";
    pub const ACCESS_DENIED: &str = "access_denied";
    pub const EXPIRED_TOKEN: &str = "expired_token";
    pub const INTERNAL: &str = "internal";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Sync,
    Collector,
    Share,
    Account,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    Request,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub server: String,
    pub version: String,
    pub commit: String,
    pub protocol: Vec<u32>,
    pub web_api: Vec<u32>,
    pub registration: Registration,
    pub website_origins: Vec<String>,
    pub collector: Option<CollectorCapabilities>,
    pub limits: Limits,
    #[serde(default)]
    pub policy_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorCapabilities {
    pub available: bool,
    pub unlock_key: String,
    pub signing_key: String,
    pub keys_valid_since_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_chunk_bytes: u64,
    pub max_request_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuthorizeRequest {
    pub device_label: String,
    pub requested_scopes: Vec<Scope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAuthorizeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u32,
    pub interval: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceTokenResponse {
    pub account_id: AccountId,
    pub token: String,
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub account_id: AccountId,
    pub usage_bytes: u64,
    pub quota_bytes: Option<u64>,
    pub collector_allowed: bool,
    pub sync_allowed: bool,
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReauthMethod {
    Totp,
    Email,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthRequest {
    pub method: ReauthMethod,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientKind {
    Desktop,
    WebSession,
    ManualToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientLocation {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientIpEntry {
    pub ip: String,
    pub location: ClientLocation,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub client_id: String,
    pub kind: ClientKind,
    pub label: String,
    pub client_version: Option<String>,
    pub scopes: Vec<Scope>,
    pub current: bool,
    pub active_now: bool,
    pub revoked_at_ms: Option<i64>,
    pub first_seen_ms: Option<i64>,
    pub last_seen_ms: Option<i64>,
    pub current_ip: Option<ClientIpEntry>,
    #[serde(default)]
    pub history: Vec<ClientIpEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub vault_id: VaultId,
    pub vault_pk: String,
    pub manifest_pk: String,
    pub created_at_ms: i64,
    pub max_seq: u64,
    pub manifest_seq: u64,
    pub usage_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequest {
    pub vault_id: VaultId,
    pub vault_pk: String,
    pub manifest_pk: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkStored {
    pub seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkListItem {
    pub seq: u64,
    pub chunk_id: ChunkId,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkList {
    pub chunks: Vec<ChunkListItem>,
    pub max_seq: u64,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompactRequest {
    pub replaces_up_to_seq: u64,
    pub chunk_ids: Vec<ChunkId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    Locked,
    Starting,
    Running,
    NeedsUnlock,
    AuthFailed,
    Failed,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectorStatus {
    pub state: CollectorState,
    pub since_ms: Option<i64>,
    pub last_chunk_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCreateRequest {
    pub epk: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCreated {
    pub transfer_id: String,
    pub expires_in: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferKey {
    pub epk: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionWorld {
    pub world_id: String,
    pub name: String,
    pub author_name: String,
    pub image_url: String,
    pub description: String,
    pub comment: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionSnapshot {
    pub id: String,
    pub title: String,
    pub note: Option<String>,
    pub author_name: String,
    pub author_profile: Option<String>,
    pub category: Option<String>,
    pub listed: bool,
    pub updated_at: i64,
    pub worlds: Vec<CollectionWorld>,
}

pub mod batch {
    use crate::ids::{ChunkId, ID_LEN};
    use crate::{Error, Result};

    const HEADER: usize = 8 + ID_LEN + 4;

    pub fn encode_frame(
        out: &mut Vec<u8>,
        seq: u64,
        chunk_id: &ChunkId,
        blob: &[u8],
    ) -> Result<()> {
        let len = u32::try_from(blob.len()).map_err(|_| Error::TooLarge("chunk"))?;
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(chunk_id.as_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(blob);
        Ok(())
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct Frame<'a> {
        pub seq: u64,
        pub chunk_id: ChunkId,
        pub blob: &'a [u8],
    }

    pub fn decode(mut data: &[u8]) -> Result<Vec<Frame<'_>>> {
        let mut frames = Vec::new();
        while !data.is_empty() {
            if data.len() < HEADER {
                return Err(Error::Malformed("batch"));
            }
            let seq = u64::from_be_bytes(data[..8].try_into().expect("8 bytes"));
            let chunk_id = ChunkId::from_bytes(data[8..8 + ID_LEN].try_into().expect("16 bytes"));
            let len =
                u32::from_be_bytes(data[8 + ID_LEN..HEADER].try_into().expect("4 bytes")) as usize;
            let rest = &data[HEADER..];
            if rest.len() < len || len > super::MAX_CHUNK_BYTES {
                return Err(Error::Malformed("batch"));
            }
            frames.push(Frame {
                seq,
                chunk_id,
                blob: &rest[..len],
            });
            data = &rest[len..];
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_round_trip() {
        let a = ChunkId::random().unwrap();
        let b = ChunkId::random().unwrap();
        let mut body = Vec::new();
        batch::encode_frame(&mut body, 1, &a, b"first").unwrap();
        batch::encode_frame(&mut body, 2, &b, b"").unwrap();
        let frames = batch::decode(&body).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0],
            batch::Frame {
                seq: 1,
                chunk_id: a,
                blob: b"first"
            }
        );
        assert_eq!(frames[1].seq, 2);
        assert!(batch::decode(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn json_shapes() {
        let error = ApiError::new(codes::VAULT_NOT_FOUND, "Vault not found.");
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::json!({"error": {"code": "vault_not_found", "message": "Vault not found."}})
        );
        assert_eq!(serde_json::to_value(Scope::Account).unwrap(), "account");
        assert_eq!(
            serde_json::to_value(CollectorState::NeedsUnlock).unwrap(),
            "needs_unlock"
        );
        assert_eq!(
            serde_json::to_value(ClientKind::WebSession).unwrap(),
            "web-session"
        );
    }

    #[test]
    fn collection_snapshot_matches_upstream_shape() {
        let json = serde_json::json!({
            "id": "AbC123z", "title": "t", "note": null, "author_name": "a",
            "author_profile": null, "category": null, "listed": true, "updated_at": 5,
            "worlds": [{"world_id": "wrld_1", "name": "n", "author_name": "x",
                        "image_url": "", "description": "", "comment": ""}]
        });
        let parsed: CollectionSnapshot = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json);
    }

    #[test]
    fn max_chunk_bytes_includes_overhead() {
        assert_eq!(MAX_CHUNK_BYTES, 4 * 1024 * 1024 + 48);
    }
}
