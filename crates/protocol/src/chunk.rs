use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::framing::{self, Signing};
use crate::ids::{ChunkId, SourceId, VaultId};
use crate::keys::{SignerKey, VaultKeys};
use crate::seal::SealPublicKey;
use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"remotesync/v1/chunk";
pub const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChunkKind {
    Rows,
    Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoveragePeriod {
    pub start_ms: i64,
    pub end_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkHeader {
    pub v: u8,
    pub vault_id: VaultId,
    pub chunk_id: ChunkId,
    pub source_id: SourceId,
    pub source_seq: u64,
    pub signer_key_id: String,
    pub kind: ChunkKind,
    pub created_at_ms: i64,
    pub app_version: String,
    #[serde(default)]
    pub coverage: Vec<CoveragePeriod>,
    #[serde(default)]
    pub dropped_rows: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChunkBody {
    pub streams: BTreeMap<String, Vec<serde_json::Value>>,
}

impl ChunkBody {
    pub fn row_count(&self) -> usize {
        self.streams.values().map(Vec::len).sum()
    }
}

#[derive(Clone, Debug)]
pub struct ChunkDraft {
    pub vault_id: VaultId,
    pub source_id: SourceId,
    pub source_seq: u64,
    pub kind: ChunkKind,
    pub created_at_ms: i64,
    pub app_version: String,
    pub coverage: Vec<CoveragePeriod>,
    pub dropped_rows: u64,
    pub body: ChunkBody,
}

#[derive(Clone, Debug)]
pub struct SealedChunk {
    pub chunk_id: ChunkId,
    pub blob: Vec<u8>,
}

pub trait SignerLookup {
    fn signer(&self, key_id: &str, at_ms: i64) -> Option<VerifyingKey>;
}

fn binding(vault_id: &VaultId, chunk_id: &ChunkId) -> Vec<u8> {
    [vault_id.as_bytes().as_slice(), chunk_id.as_bytes()].concat()
}

pub fn seal_chunk(
    draft: &ChunkDraft,
    signer: &SignerKey,
    vault_pk: &SealPublicKey,
) -> Result<SealedChunk> {
    let chunk_id = ChunkId::random()?;
    let header = ChunkHeader {
        v: VERSION,
        vault_id: draft.vault_id,
        chunk_id,
        source_id: draft.source_id,
        source_seq: draft.source_seq,
        signer_key_id: signer.key_id(),
        kind: draft.kind,
        created_at_ms: draft.created_at_ms,
        app_version: draft.app_version.clone(),
        coverage: draft.coverage.clone(),
        dropped_rows: draft.dropped_rows,
    };
    let header_bytes = framing::to_cbor(&header)?;
    let body_bytes = framing::compress(&framing::to_cbor(&draft.body)?);
    let blob = framing::seal_signed(
        DOMAIN,
        &binding(&draft.vault_id, &chunk_id),
        &header_bytes,
        &body_bytes,
        Signing::Signer(signer),
        vault_pk,
    )?;
    Ok(SealedChunk { chunk_id, blob })
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenedChunk {
    pub header: ChunkHeader,
    pub body: ChunkBody,
}

pub fn open_chunk(
    blob: &[u8],
    vault_id: VaultId,
    chunk_id: ChunkId,
    keys: &VaultKeys,
    signers: &impl SignerLookup,
) -> Result<OpenedChunk> {
    if keys.vault_id() != vault_id {
        return Err(Error::Mismatch("vault keys"));
    }
    let unverified = framing::open_signed(
        DOMAIN,
        binding(&vault_id, &chunk_id),
        keys.seal_private(),
        blob,
    )?;
    let claimed: ChunkHeader = framing::from_cbor(&unverified.header, "chunk header")?;
    let public = signers
        .signer(&claimed.signer_key_id, claimed.created_at_ms)
        .ok_or(Error::UnknownSigner)?;
    let (header_bytes, body_bytes) = unverified.verify(&public)?;
    let header: ChunkHeader = framing::from_cbor(&header_bytes, "chunk header")?;
    if header.v != VERSION {
        return Err(Error::Invalid("chunk version"));
    }
    if header.vault_id != vault_id || header.chunk_id != chunk_id {
        return Err(Error::Mismatch("chunk id"));
    }
    let body: ChunkBody = framing::from_cbor(&framing::decompress(&body_bytes)?, "chunk body")?;
    Ok(OpenedChunk { header, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::key_id;
    use crate::secret::SyncSecret;
    use serde_json::json;

    struct OneSigner(VerifyingKey);

    impl SignerLookup for OneSigner {
        fn signer(&self, id: &str, _at_ms: i64) -> Option<VerifyingKey> {
            (key_id(&self.0) == id).then_some(self.0)
        }
    }

    fn setup() -> (VaultKeys, SignerKey, ChunkDraft) {
        let vault_id = VaultId::random().unwrap();
        let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), vault_id);
        let signer = SignerKey::generate().unwrap();
        let mut body = ChunkBody::default();
        body.streams.insert(
            "feed_gps".into(),
            vec![json!({"created_at": "2026-10-08T12:00:00Z", "user_id": "usr_1", "location": "wrld_1:1"})],
        );
        let draft = ChunkDraft {
            vault_id,
            source_id: SourceId::random().unwrap(),
            source_seq: 7,
            kind: ChunkKind::Rows,
            created_at_ms: 1_791_000_000_000,
            app_version: "test".into(),
            coverage: vec![CoveragePeriod {
                start_ms: 1,
                end_ms: 2,
            }],
            dropped_rows: 0,
            body,
        };
        (keys, signer, draft)
    }

    #[test]
    fn round_trip() {
        let (keys, signer, draft) = setup();
        let sealed = seal_chunk(&draft, &signer, &keys.public().vault_pk).unwrap();
        assert_eq!(sealed.blob.len() % 4096, crate::seal::OVERHEAD);
        let opened = open_chunk(
            &sealed.blob,
            draft.vault_id,
            sealed.chunk_id,
            &keys,
            &OneSigner(signer.public()),
        )
        .unwrap();
        assert_eq!(opened.body, draft.body);
        assert_eq!(opened.header.source_seq, 7);
        assert_eq!(opened.header.signer_key_id, signer.key_id());
        assert_eq!(opened.body.row_count(), 1);
    }

    #[test]
    fn rejects_unknown_signer() {
        let (keys, signer, draft) = setup();
        let sealed = seal_chunk(&draft, &signer, &keys.public().vault_pk).unwrap();
        let other = SignerKey::generate().unwrap();
        assert_eq!(
            open_chunk(
                &sealed.blob,
                draft.vault_id,
                sealed.chunk_id,
                &keys,
                &OneSigner(other.public())
            ),
            Err(Error::UnknownSigner)
        );
    }

    #[test]
    fn rejects_chunk_under_another_id_or_vault() {
        let (keys, signer, draft) = setup();
        let sealed = seal_chunk(&draft, &signer, &keys.public().vault_pk).unwrap();
        let lookup = OneSigner(signer.public());
        assert_eq!(
            open_chunk(
                &sealed.blob,
                draft.vault_id,
                ChunkId::random().unwrap(),
                &keys,
                &lookup
            ),
            Err(Error::Decrypt)
        );
        let other_keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), draft.vault_id);
        assert_eq!(
            open_chunk(
                &sealed.blob,
                draft.vault_id,
                sealed.chunk_id,
                &other_keys,
                &lookup
            ),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn rejects_forgery_by_someone_with_only_the_public_key() {
        let (keys, signer, draft) = setup();
        let forger = SignerKey::generate().unwrap();
        let mut forged = draft.clone();
        forged.source_seq = 99;
        let sealed = seal_chunk(&forged, &forger, &keys.public().vault_pk).unwrap();
        assert_eq!(
            open_chunk(
                &sealed.blob,
                draft.vault_id,
                sealed.chunk_id,
                &keys,
                &OneSigner(signer.public())
            ),
            Err(Error::UnknownSigner)
        );
    }
}
