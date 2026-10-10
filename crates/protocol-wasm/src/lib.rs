#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};
use vrcx_0_nanashi_website_protocol::chunk::{self, ChunkHeader, SignerLookup};
use vrcx_0_nanashi_website_protocol::ids::{ChunkId, VaultId};
use vrcx_0_nanashi_website_protocol::keys::{self, VaultKeys};
use vrcx_0_nanashi_website_protocol::manifest::{self, Manifest};
use vrcx_0_nanashi_website_protocol::secret::SyncSecret;

static OUTPUT_LEN: AtomicU32 = AtomicU32::new(0);

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod random {
    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        fn rs_random(pointer: *mut u8, length: usize);
    }

    #[unsafe(no_mangle)]
    unsafe extern "Rust" fn __getrandom_v03_custom(
        pointer: *mut u8,
        length: usize,
    ) -> Result<(), getrandom::Error> {
        unsafe { rs_random(pointer, length) };
        Ok(())
    }
}
const MAX_INPUT: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenBatch {
    sync_key_hex: String,
    vault_id: String,
    manifest_seq: u64,
    #[serde(default)]
    highest_manifest_seq: Option<u64>,
    manifest: String,
    chunks: Vec<OpenChunk>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenLive {
    sync_key_hex: String,
    vault_id: String,
    manifest_seq: u64,
    #[serde(default)]
    highest_manifest_seq: Option<u64>,
    manifest: String,
    live_seq: u64,
    blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenChunk {
    chunk_id: String,
    blob: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Opened {
    header: ChunkHeader,
    body: chunk::ChunkBody,
}

struct ManifestSigners<'a>(&'a Manifest);

impl SignerLookup for ManifestSigners<'_> {
    fn signer(&self, id: &str, at_ms: i64) -> Option<ed25519_dalek::VerifyingKey> {
        const SKEW_MS: i64 = manifest::CLOCK_SKEW_MS;
        self.0.signers.iter().find_map(|entry| {
            if entry.key_id != id
                || entry.added_at_ms > at_ms.saturating_add(SKEW_MS)
                || entry
                    .expires_at_ms
                    .is_some_and(|expires| expires.saturating_add(SKEW_MS) < at_ms)
            {
                return None;
            }
            let key = keys::verifying_key(entry.public_key.as_ref()).ok()?;
            (keys::key_id(&key) == entry.key_id).then_some(key)
        })
    }
}

fn process(input: &[u8]) -> Vec<u8> {
    let result = (|| -> Result<serde_json::Value, String> {
        let value: serde_json::Value = serde_json::from_slice(input).map_err(|e| e.to_string())?;
        if value.get("op").and_then(serde_json::Value::as_str) == Some("openLive") {
            let request: OpenLive = serde_json::from_value(value).map_err(|e| e.to_string())?;
            let vault_id: VaultId = request.vault_id.parse().map_err(|e| format!("{e}"))?;
            let secret =
                SyncSecret::parse_own_key(&request.sync_key_hex).map_err(|e| e.to_string())?;
            let keys = VaultKeys::derive(&secret, vault_id);
            let manifest_blob = vrcx_0_nanashi_website_protocol::b64::decode(&request.manifest)
                .map_err(|e| e.to_string())?;
            let opened_manifest = manifest::open_manifest(
                &manifest_blob,
                request.manifest_seq,
                &keys,
                request.highest_manifest_seq,
            )
            .map_err(|e| e.to_string())?;
            let blob = vrcx_0_nanashi_website_protocol::b64::decode(&request.blob)
                .map_err(|e| e.to_string())?;
            let snapshot = vrcx_0_nanashi_website_protocol::live::open_live(
                &blob,
                request.live_seq,
                &keys,
                &ManifestSigners(&opened_manifest),
            )
            .map_err(|e| e.to_string())?;
            return serde_json::to_value(snapshot).map_err(|e| e.to_string());
        }
        if let Some(op) = value
            .get("op")
            .and_then(serde_json::Value::as_str)
            .filter(|op| op.starts_with("transfer"))
        {
            return transfer_op(op, &value);
        }
        if let Some(op) = value
            .get("op")
            .and_then(serde_json::Value::as_str)
            .filter(|op| op.starts_with("manifest"))
        {
            return manifest_op(op, value.clone());
        }
        let request: OpenBatch = serde_json::from_slice(input).map_err(|e| e.to_string())?;
        let vault_id: VaultId = request.vault_id.parse().map_err(|e| format!("{e}"))?;
        let secret = SyncSecret::parse_own_key(&request.sync_key_hex).map_err(|e| e.to_string())?;
        let keys = VaultKeys::derive(&secret, vault_id);
        let manifest_blob = vrcx_0_nanashi_website_protocol::b64::decode(&request.manifest)
            .map_err(|e| e.to_string())?;
        let opened_manifest = manifest::open_manifest(
            &manifest_blob,
            request.manifest_seq,
            &keys,
            request.highest_manifest_seq,
        )
        .map_err(|e| e.to_string())?;
        let signers = ManifestSigners(&opened_manifest);
        let opened = request
            .chunks
            .into_iter()
            .map(|item| {
                let chunk_id: ChunkId = item.chunk_id.parse().map_err(|e| format!("{e}"))?;
                let blob = vrcx_0_nanashi_website_protocol::b64::decode(&item.blob)
                    .map_err(|e| e.to_string())?;
                let opened = chunk::open_chunk(&blob, vault_id, chunk_id, &keys, &signers)
                    .map_err(|e| e.to_string())?;
                Ok(Opened {
                    header: opened.header,
                    body: opened.body,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        serde_json::to_value(opened).map_err(|e| e.to_string())
    })();
    match result {
        Ok(opened) => serde_json::to_vec(&opened).unwrap_or_else(|e| error_json(&e.to_string())),
        Err(error) => error_json(&error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestRequest {
    sync_key_hex: String,
    vault_id: String,
    manifest_seq: u64,
    manifest: String,
    #[serde(default)]
    max_age_days: Option<u32>,
    #[serde(default)]
    keep_below_limit_margin_pct: Option<u32>,
}

fn manifest_op(op: &str, value: serde_json::Value) -> Result<serde_json::Value, String> {
    let request: ManifestRequest = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let vault_id: VaultId = request.vault_id.parse().map_err(|e| format!("{e}"))?;
    let secret = SyncSecret::parse_own_key(&request.sync_key_hex).map_err(|e| e.to_string())?;
    let keys = VaultKeys::derive(&secret, vault_id);
    let blob = vrcx_0_nanashi_website_protocol::b64::decode(&request.manifest)
        .map_err(|e| e.to_string())?;
    let current = manifest::open_manifest(&blob, request.manifest_seq, &keys, None)
        .map_err(|e| e.to_string())?;
    match op {
        "manifestInfo" => Ok(serde_json::json!({
            "subject": current.subject,
            "retention": current.retention,
            "signers": current.signers.iter().map(|signer| serde_json::json!({
                "label": signer.label,
                "kind": signer.kind,
                "addedAtMs": signer.added_at_ms,
                "expiresAtMs": signer.expires_at_ms,
            })).collect::<Vec<_>>(),
        })),
        "manifestRetention" => {
            let mut next = current.next();
            next.retention = manifest::RetentionSettings {
                max_age_days: request.max_age_days,
                keep_below_limit_margin_pct: request.keep_below_limit_margin_pct,
            };
            let sealed = manifest::seal_manifest(&next, &keys).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "manifest": vrcx_0_nanashi_website_protocol::b64::encode(&sealed),
                "manifestSeq": next.manifest_seq,
            }))
        }
        _ => Err("unsupported operation".into()),
    }
}

fn transfer_op(op: &str, value: &serde_json::Value) -> Result<serde_json::Value, String> {
    use vrcx_0_nanashi_website_protocol::ids::AccountId;
    use vrcx_0_nanashi_website_protocol::seal::{SealPrivateKey, SealPublicKey};
    use vrcx_0_nanashi_website_protocol::{b64, transfer};

    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("missing {name}"))
    };
    let private_key = || -> Result<SealPrivateKey, String> {
        let seed = SyncSecret::parse_own_key(field("seedHex")?).map_err(|e| e.to_string())?;
        Ok(SealPrivateKey::derive(seed.expose()))
    };
    let account = || {
        field("accountId")?
            .parse::<AccountId>()
            .map_err(|e| e.to_string())
    };
    match op {
        "transferPublic" => Ok(serde_json::json!({
            "epk": b64::encode(private_key()?.public().as_bytes()),
        })),
        "transferCode" => Ok(serde_json::json!({
            "code": transfer::display_code(field("transferId")?, &private_key()?.public())
                .map_err(|e| e.to_string())?,
        })),
        "transferParse" => {
            let (transfer_id, _) =
                transfer::parse_code(field("code")?).map_err(|e| e.to_string())?;
            Ok(serde_json::json!({ "transferId": transfer_id }))
        }
        "transferSeal" => {
            let (transfer_id, fingerprint) =
                transfer::parse_code(field("code")?).map_err(|e| e.to_string())?;
            let epk =
                SealPublicKey::from_bytes(&b64::decode(field("epk")?).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let secret =
                SyncSecret::parse_own_key(field("syncKeyHex")?).map_err(|e| e.to_string())?;
            let blob =
                transfer::seal_secret(&epk, &fingerprint, &account()?, &transfer_id, &secret)
                    .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({ "blob": b64::encode(&blob) }))
        }
        "transferOpen" => {
            let blob = b64::decode(field("blob")?).map_err(|e| e.to_string())?;
            let secret =
                transfer::open_secret(&private_key()?, &account()?, field("transferId")?, &blob)
                    .map_err(|e| e.to_string())?;
            let hex = secret
                .expose()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            Ok(serde_json::json!({ "syncKeyHex": hex }))
        }
        _ => Err("unsupported operation".into()),
    }
}

fn error_json(error: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "error": error }))
        .unwrap_or_else(|_| b"{\"error\":\"serialization failed\"}".to_vec())
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_alloc(len: u32) -> u32 {
    let mut buffer = Vec::<u8>::with_capacity(len as usize);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr as u32
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn rs_dealloc(ptr: u32, len: u32) {
    if ptr != 0 && len != 0 {
        unsafe { drop(Vec::from_raw_parts(ptr as *mut u8, 0, len as usize)) };
    }
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn rs_process(ptr: u32, len: u32) -> u32 {
    if ptr == 0 || len == 0 || len as usize > MAX_INPUT {
        let output = error_json("invalid or oversized request");
        return leak_output(output);
    }
    let input = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let output = process(input);
    leak_output(output)
}

fn leak_output(output: Vec<u8>) -> u32 {
    let boxed = output.into_boxed_slice();
    let len = boxed.len() as u32;
    let ptr = Box::into_raw(boxed) as *mut u8;
    OUTPUT_LEN.store(len, Ordering::SeqCst);
    ptr as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_output_len() -> u32 {
    OUTPUT_LEN.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn rs_free_output(ptr: u32, len: u32) {
    if ptr != 0 && len != 0 {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                ptr as *mut u8,
                len as usize,
            )))
        };
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use vrcx_0_nanashi_website_protocol::b64;
    use vrcx_0_nanashi_website_protocol::manifest::ManifestSubject;

    fn call(value: serde_json::Value) -> serde_json::Value {
        serde_json::from_slice(&process(&serde_json::to_vec(&value).unwrap())).unwrap()
    }

    #[test]
    fn retention_is_written_into_the_next_signed_manifest() {
        let key = "11".repeat(32);
        let secret = SyncSecret::parse_own_key(&key).unwrap();
        let vault_id = VaultId::random().unwrap();
        let keys = VaultKeys::derive(&secret, vault_id);
        let first = Manifest::new(
            vault_id,
            Some(ManifestSubject {
                vrchat_user_id: "usr_test".into(),
                display_name: "Tester".into(),
            }),
        );
        let sealed = b64::encode(&manifest::seal_manifest(&first, &keys).unwrap());

        let info = call(serde_json::json!({
            "op": "manifestInfo", "syncKeyHex": key, "vaultId": vault_id.to_string(),
            "manifestSeq": 1, "manifest": sealed,
        }));
        assert_eq!(info["subject"]["displayName"], "Tester");
        assert!(info["retention"]["maxAgeDays"].is_null());

        let updated = call(serde_json::json!({
            "op": "manifestRetention", "syncKeyHex": key, "vaultId": vault_id.to_string(),
            "manifestSeq": 1, "manifest": sealed, "maxAgeDays": 90,
        }));
        assert_eq!(updated["manifestSeq"], 2);
        let blob = b64::decode(updated["manifest"].as_str().unwrap()).unwrap();
        let reopened = manifest::open_manifest(&blob, 2, &keys, Some(1)).unwrap();
        assert_eq!(reopened.retention.max_age_days, Some(90));
        assert_eq!(reopened.subject, first.subject);

        let wrong_key = call(serde_json::json!({
            "op": "manifestInfo", "syncKeyHex": "22".repeat(32), "vaultId": vault_id.to_string(),
            "manifestSeq": 1, "manifest": sealed,
        }));
        assert!(wrong_key["error"].is_string());

        let invalid = call(serde_json::json!({
            "op": "manifestRetention", "syncKeyHex": key, "vaultId": vault_id.to_string(),
            "manifestSeq": 1, "manifest": sealed, "maxAgeDays": 0,
        }));
        assert!(invalid["error"].is_string());
    }
}
