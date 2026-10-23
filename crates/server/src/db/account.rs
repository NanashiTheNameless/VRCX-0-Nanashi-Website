use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use vrcx_0_nanashi_website_protocol::ids::{AccountId, ChunkId, VaultId};

use super::{DbError, migrate, open_encrypted, remove_files};

pub(super) const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE vaults (
    vault_id TEXT PRIMARY KEY,
    vault_pk BLOB NOT NULL,
    manifest_pk BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    manifest_seq INTEGER NOT NULL DEFAULT 0,
    manifest BLOB,
    max_seq INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE chunks (
    vault_id TEXT NOT NULL REFERENCES vaults ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    chunk_id BLOB NOT NULL,
    object_id BLOB NOT NULL UNIQUE,
    blob_hash BLOB NOT NULL,
    size INTEGER NOT NULL,
    PRIMARY KEY (vault_id, seq),
    UNIQUE (vault_id, chunk_id)
);

CREATE TABLE envelopes (
    envelope_id TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE collections (
    code TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    size INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
"#,
    r#"
ALTER TABLE vaults RENAME COLUMN created_at_ms TO created_at;
UPDATE vaults SET created_at = created_at / 1000 - CASE WHEN created_at < 0 AND created_at % 1000 != 0 THEN 1 ELSE 0 END;
ALTER TABLE envelopes RENAME COLUMN created_at_ms TO created_at;
UPDATE envelopes SET created_at = created_at / 1000 - CASE WHEN created_at < 0 AND created_at % 1000 != 0 THEN 1 ELSE 0 END;
ALTER TABLE collections RENAME COLUMN updated_at_ms TO updated_at;
UPDATE collections SET updated_at = updated_at / 1000 - CASE WHEN updated_at < 0 AND updated_at % 1000 != 0 THEN 1 ELSE 0 END;
"#,
];

pub fn account_db_path(data_dir: &Path, account_id: &AccountId) -> PathBuf {
    data_dir
        .join("accounts")
        .join(format!("{}.db", account_id.as_str()))
}

pub fn delete_account_db(data_dir: &Path, account_id: &AccountId) -> std::io::Result<()> {
    remove_files(&account_db_path(data_dir, account_id))
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("vault not found")]
    VaultNotFound,
    #[error("vault already exists")]
    VaultExists,
    #[error("vault limit reached")]
    VaultLimit,
    #[error("chunk not found")]
    ChunkNotFound,
    #[error("chunk id already used with different contents")]
    ChunkIdExists,
    #[error("manifest sequence conflict")]
    ManifestConflict,
    #[error("database size limit exceeded")]
    QuotaExceeded,
    #[error("{0}")]
    Invalid(&'static str),
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(DbError::Sqlite(error))
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRow {
    pub vault_id: VaultId,
    pub vault_pk: Vec<u8>,
    pub manifest_pk: Vec<u8>,
    pub created_at: i64,
    pub max_seq: u64,
    pub manifest_seq: u64,
    pub usage_bytes: u64,
}

pub type ObjectId = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkMeta {
    pub seq: u64,
    pub chunk_id: ChunkId,
    pub object_id: ObjectId,
    pub size: u64,
}

pub struct ChunkPage {
    pub chunks: Vec<ChunkMeta>,
    pub max_seq: u64,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkCheck {
    New,
    Existing(u64),
}

pub struct NewChunk<'a> {
    pub chunk_id: &'a ChunkId,
    pub object_id: ObjectId,
    pub blob_hash: [u8; 32],
    pub size: u64,
}

fn object_id_from(bytes: Vec<u8>) -> StoreResult<ObjectId> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Invalid("stored object id"))
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub quota_bytes: Option<u64>,
    pub max_vaults: u32,
}

pub struct AccountStore {
    conn: Connection,
}

fn vault_key(vault_id: &VaultId) -> String {
    vault_id.to_string()
}

impl AccountStore {
    pub fn open(data_dir: &Path, account_id: &AccountId, key: &[u8; 32]) -> StoreResult<Self> {
        let path = account_db_path(data_dir, account_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| StoreError::Invalid("cannot create accounts directory"))?;
        }
        let mut conn = open_encrypted(&path, key)?;
        migrate(&mut conn, MIGRATIONS)?;
        Ok(Self { conn })
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn usage(&self) -> StoreResult<u64> {
        Ok(Self::usage_in(&self.conn)?)
    }

    fn usage_in(conn: &Connection) -> rusqlite::Result<u64> {
        let total: i64 = conn.query_row(
            "SELECT (SELECT COALESCE(SUM(size), 0) FROM chunks)
                  + (SELECT COALESCE(SUM(length(manifest)), 0) FROM vaults)
                  + (SELECT COALESCE(SUM(size), 0) FROM envelopes)
                  + (SELECT COALESCE(SUM(size), 0) FROM collections)",
            [],
            |row| row.get(0),
        )?;
        Ok(total.max(0) as u64)
    }

    fn check_quota(conn: &Connection, limits: Limits, adding: u64) -> StoreResult<()> {
        if let Some(quota) = limits.quota_bytes
            && Self::usage_in(conn)?.saturating_add(adding) > quota
        {
            return Err(StoreError::QuotaExceeded);
        }
        Ok(())
    }

    fn reclaim(&self) {
        let _ = self.conn.execute_batch("PRAGMA incremental_vacuum;");
    }

    pub fn envelopes(&self) -> StoreResult<Vec<(String, String, i64)>> {
        let mut statement = self
            .conn
            .prepare("SELECT envelope_id, body, created_at FROM envelopes ORDER BY created_at")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn envelope(&self, envelope_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT body FROM envelopes WHERE envelope_id = ?1",
                [envelope_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn put_envelope(
        &mut self,
        envelope_id: &str,
        body: &str,
        created_at: i64,
        limits: Limits,
        max_count: i64,
    ) -> StoreResult<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM envelopes", [], |row| row.get(0))?;
        if count >= max_count {
            return Err(StoreError::Invalid(
                "too many key envelopes; delete one first",
            ));
        }
        Self::check_quota(&tx, limits, body.len() as u64)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO envelopes (envelope_id, body, size, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![envelope_id, body, body.len() as i64, created_at],
        )?;
        if inserted == 0 {
            return Err(StoreError::Invalid(
                "an envelope with this id already exists",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_envelope(&mut self, envelope_id: &str) -> StoreResult<bool> {
        let removed = self.conn.execute(
            "DELETE FROM envelopes WHERE envelope_id = ?1",
            [envelope_id],
        )? == 1;
        self.reclaim();
        Ok(removed)
    }

    pub fn delete_all_envelopes(&mut self) -> StoreResult<u64> {
        let removed = self.conn.execute("DELETE FROM envelopes", [])? as u64;
        self.reclaim();
        Ok(removed)
    }

    pub fn collection(&self, code: &str) -> StoreResult<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT body FROM collections WHERE code = ?1",
                [code],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn collections(&self) -> StoreResult<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT body FROM collections ORDER BY updated_at DESC")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn put_collection(
        &mut self,
        code: &str,
        body: &str,
        updated_at: i64,
        limits: Limits,
        max_count: i64,
    ) -> StoreResult<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<i64> = tx
            .query_row(
                "SELECT size FROM collections WHERE code = ?1",
                [code],
                |row| row.get(0),
            )
            .optional()?;
        if old.is_none() {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM collections", [], |row| row.get(0))?;
            if count >= max_count {
                return Err(StoreError::Invalid("collection limit reached"));
            }
        }
        let size = body.len() as i64;
        let adding = size.saturating_sub(old.unwrap_or(0)).max(0) as u64;
        Self::check_quota(&tx, limits, adding)?;
        tx.execute("INSERT INTO collections (code, body, size, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(code) DO UPDATE SET body=excluded.body, size=excluded.size, updated_at=excluded.updated_at", params![code, body, size, updated_at])?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_collection(&mut self, code: &str) -> StoreResult<bool> {
        let removed = self
            .conn
            .execute("DELETE FROM collections WHERE code = ?1", [code])?
            == 1;
        if removed {
            self.reclaim();
        }
        Ok(removed)
    }

    pub fn export_collections(&self) -> StoreResult<Vec<(String, String, i64, i64)>> {
        let mut statement = self
            .conn
            .prepare("SELECT code, body, size, updated_at FROM collections")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn import_collections(&mut self, rows: &[(String, String, i64, i64)]) -> StoreResult<()> {
        let tx = self.conn.transaction()?;
        for (code, body, size, updated_at) in rows {
            tx.execute(
                "INSERT INTO collections (code, body, size, updated_at) VALUES (?1, ?2, ?3, ?4)",
                params![code, body, size, updated_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }

    pub fn create_vault(
        &mut self,
        vault_id: &VaultId,
        vault_pk: &[u8],
        manifest_pk: &[u8],
        now: i64,
        limits: Limits,
    ) -> StoreResult<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM vaults", [], |row| row.get(0))?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM vaults WHERE vault_id = ?1",
                [vault_key(vault_id)],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Err(StoreError::VaultExists);
        }
        if count >= i64::from(limits.max_vaults) {
            return Err(StoreError::VaultLimit);
        }
        tx.execute(
            "INSERT INTO vaults (vault_id, vault_pk, manifest_pk, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![vault_key(vault_id), vault_pk, manifest_pk, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn vaults(&self) -> StoreResult<Vec<VaultRow>> {
        let mut statement = self.conn.prepare(
            "SELECT v.vault_id, v.vault_pk, v.manifest_pk, v.created_at, v.max_seq, v.manifest_seq,
                    COALESCE((SELECT SUM(size) FROM chunks c WHERE c.vault_id = v.vault_id), 0)
                      + COALESCE(length(v.manifest), 0)
             FROM vaults v ORDER BY v.created_at",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, vault_pk, manifest_pk, created_at, max_seq, manifest_seq, usage) = row?;
            out.push(VaultRow {
                vault_id: id
                    .parse()
                    .map_err(|_| StoreError::Invalid("stored vault id"))?,
                vault_pk,
                manifest_pk,
                created_at,
                max_seq: max_seq.max(0) as u64,
                manifest_seq: manifest_seq.max(0) as u64,
                usage_bytes: usage.max(0) as u64,
            });
        }
        Ok(out)
    }

    fn require_vault(conn: &Connection, vault_id: &VaultId) -> StoreResult<()> {
        conn.query_row(
            "SELECT 1 FROM vaults WHERE vault_id = ?1",
            [vault_key(vault_id)],
            |_| Ok(()),
        )
        .optional()?
        .ok_or(StoreError::VaultNotFound)
    }

    pub fn delete_vault(&mut self, vault_id: &VaultId) -> StoreResult<Vec<ObjectId>> {
        let tx = self.conn.transaction()?;
        let objects = Self::object_ids_where(
            &tx,
            "SELECT object_id FROM chunks WHERE vault_id = ?1",
            [vault_key(vault_id)],
        )?;
        let removed = tx.execute(
            "DELETE FROM vaults WHERE vault_id = ?1",
            [vault_key(vault_id)],
        )?;
        if removed == 0 {
            return Err(StoreError::VaultNotFound);
        }
        tx.commit()?;
        self.reclaim();
        Ok(objects)
    }

    pub fn manifest(&self, vault_id: &VaultId) -> StoreResult<Option<(u64, Vec<u8>)>> {
        Self::require_vault(&self.conn, vault_id)?;
        Ok(self
            .conn
            .query_row(
                "SELECT manifest_seq, manifest FROM vaults WHERE vault_id = ?1 AND manifest IS NOT NULL",
                [vault_key(vault_id)],
                |row| Ok((row.get::<_, i64>(0)?.max(0) as u64, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn put_manifest(
        &mut self,
        vault_id: &VaultId,
        seq: u64,
        blob: &[u8],
        limits: Limits,
    ) -> StoreResult<()> {
        if seq == 0 {
            return Err(StoreError::Invalid("manifest seq"));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (current, old_len): (i64, i64) = tx
            .query_row(
                "SELECT manifest_seq, COALESCE(length(manifest), 0) FROM vaults WHERE vault_id = ?1",
                [vault_key(vault_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::VaultNotFound)?;
        if current.max(0) as u64 + 1 != seq {
            return Err(StoreError::ManifestConflict);
        }
        let growth = (blob.len() as u64).saturating_sub(old_len.max(0) as u64);
        Self::check_quota(&tx, limits, growth)?;
        tx.execute(
            "UPDATE vaults SET manifest_seq = ?2, manifest = ?3 WHERE vault_id = ?1",
            params![vault_key(vault_id), seq as i64, blob],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn existing_chunk(
        conn: &Connection,
        vault_id: &VaultId,
        chunk_id: &ChunkId,
    ) -> StoreResult<Option<(i64, Vec<u8>)>> {
        Ok(conn
            .query_row(
                "SELECT seq, blob_hash FROM chunks WHERE vault_id = ?1 AND chunk_id = ?2",
                params![vault_key(vault_id), chunk_id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn check_chunk(
        &self,
        vault_id: &VaultId,
        chunk_id: &ChunkId,
        blob_hash: &[u8; 32],
        size: u64,
        limits: Limits,
    ) -> StoreResult<ChunkCheck> {
        Self::require_vault(&self.conn, vault_id)?;
        if let Some((seq, stored)) = Self::existing_chunk(&self.conn, vault_id, chunk_id)? {
            return if stored == blob_hash {
                Ok(ChunkCheck::Existing(seq as u64))
            } else {
                Err(StoreError::ChunkIdExists)
            };
        }
        Self::check_quota(&self.conn, limits, size)?;
        Ok(ChunkCheck::New)
    }

    pub fn insert_chunk(
        &mut self,
        vault_id: &VaultId,
        chunk: &NewChunk<'_>,
        limits: Limits,
    ) -> StoreResult<(u64, bool)> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::require_vault(&tx, vault_id)?;
        if let Some((seq, stored)) = Self::existing_chunk(&tx, vault_id, chunk.chunk_id)? {
            return if stored == chunk.blob_hash {
                Ok((seq as u64, true))
            } else {
                Err(StoreError::ChunkIdExists)
            };
        }
        Self::check_quota(&tx, limits, chunk.size)?;
        let seq: i64 = tx.query_row(
            "UPDATE vaults SET max_seq = max_seq + 1 WHERE vault_id = ?1 RETURNING max_seq",
            [vault_key(vault_id)],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO chunks (vault_id, seq, chunk_id, object_id, blob_hash, size)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                vault_key(vault_id),
                seq,
                chunk.chunk_id.as_bytes().as_slice(),
                chunk.object_id.as_slice(),
                chunk.blob_hash.as_slice(),
                chunk.size as i64
            ],
        )?;
        tx.commit()?;
        Ok((seq as u64, false))
    }

    pub fn chunk_page(
        &self,
        vault_id: &VaultId,
        after: u64,
        limit: u32,
        byte_cap: u64,
    ) -> StoreResult<ChunkPage> {
        Self::require_vault(&self.conn, vault_id)?;
        let max_seq: i64 = self.conn.query_row(
            "SELECT max_seq FROM vaults WHERE vault_id = ?1",
            [vault_key(vault_id)],
            |row| row.get(0),
        )?;
        let mut statement = self.conn.prepare(
            "SELECT seq, chunk_id, object_id, size FROM chunks
             WHERE vault_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![vault_key(vault_id), after as i64, i64::from(limit) + 1],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let mut chunks = Vec::new();
        let mut bytes = 0_u64;
        let mut has_more = false;
        for row in rows {
            let (seq, chunk_id, object_id, size) = row?;
            let size = size.max(0) as u64;
            if chunks.len() as u32 == limit || (!chunks.is_empty() && bytes + size > byte_cap) {
                has_more = true;
                break;
            }
            bytes += size;
            let chunk_id: [u8; 16] = chunk_id
                .try_into()
                .map_err(|_| StoreError::Invalid("stored chunk id"))?;
            chunks.push(ChunkMeta {
                seq: seq as u64,
                chunk_id: ChunkId::from_bytes(chunk_id),
                object_id: object_id_from(object_id)?,
                size,
            });
        }
        Ok(ChunkPage {
            chunks,
            max_seq: max_seq.max(0) as u64,
            has_more,
        })
    }

    pub fn chunk_page_before(
        &self,
        vault_id: &VaultId,
        before: u64,
        limit: u32,
        byte_cap: u64,
    ) -> StoreResult<ChunkPage> {
        Self::require_vault(&self.conn, vault_id)?;
        let max_seq: i64 = self.conn.query_row(
            "SELECT max_seq FROM vaults WHERE vault_id = ?1",
            [vault_key(vault_id)],
            |row| row.get(0),
        )?;
        let mut statement = self.conn.prepare(
            "SELECT seq, chunk_id, object_id, size FROM chunks
             WHERE vault_id = ?1 AND seq < ?2 ORDER BY seq DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![vault_key(vault_id), before as i64, i64::from(limit) + 1],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?;
        let mut chunks = Vec::new();
        let mut bytes = 0_u64;
        let mut has_more = false;
        for row in rows {
            let (seq, chunk_id, object_id, size) = row?;
            let size = size.max(0) as u64;
            if chunks.len() as u32 == limit || (!chunks.is_empty() && bytes + size > byte_cap) {
                has_more = true;
                break;
            }
            bytes += size;
            let chunk_id: [u8; 16] = chunk_id
                .try_into()
                .map_err(|_| StoreError::Invalid("stored chunk id"))?;
            chunks.push(ChunkMeta {
                seq: seq as u64,
                chunk_id: ChunkId::from_bytes(chunk_id),
                object_id: object_id_from(object_id)?,
                size,
            });
        }
        Ok(ChunkPage {
            chunks,
            max_seq: max_seq.max(0) as u64,
            has_more,
        })
    }

    pub fn chunk(&self, vault_id: &VaultId, seq: u64) -> StoreResult<ChunkMeta> {
        Self::require_vault(&self.conn, vault_id)?;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT chunk_id, object_id, size FROM chunks WHERE vault_id = ?1 AND seq = ?2",
                params![vault_key(vault_id), seq as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (chunk_id, object_id, size) = row.ok_or(StoreError::ChunkNotFound)?;
        let chunk_id: [u8; 16] = chunk_id
            .try_into()
            .map_err(|_| StoreError::Invalid("stored chunk id"))?;
        Ok(ChunkMeta {
            seq,
            chunk_id: ChunkId::from_bytes(chunk_id),
            object_id: object_id_from(object_id)?,
            size: size.max(0) as u64,
        })
    }

    pub fn all_object_ids(&self) -> StoreResult<Vec<ObjectId>> {
        let mut statement = self.conn.prepare("SELECT object_id FROM chunks")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| object_id_from(row?)).collect()
    }

    fn object_ids_where(
        tx: &rusqlite::Transaction<'_>,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> StoreResult<Vec<ObjectId>> {
        let mut statement = tx.prepare(sql)?;
        let rows = statement.query_map(params, |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| object_id_from(row?)).collect()
    }

    pub fn compact(
        &mut self,
        vault_id: &VaultId,
        replaces_up_to_seq: u64,
        replacements: &[ChunkId],
    ) -> StoreResult<Vec<ObjectId>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::require_vault(&tx, vault_id)?;
        for chunk_id in replacements {
            let seq: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM chunks WHERE vault_id = ?1 AND chunk_id = ?2",
                    params![vault_key(vault_id), chunk_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            match seq {
                Some(seq) if seq as u64 > replaces_up_to_seq => {}
                Some(_) => {
                    return Err(StoreError::Invalid(
                        "replacement chunk is not newer than the compacted range",
                    ));
                }
                None => return Err(StoreError::ChunkNotFound),
            }
        }
        let removed = Self::object_ids_where(
            &tx,
            "SELECT object_id FROM chunks WHERE vault_id = ?1 AND seq <= ?2",
            params![vault_key(vault_id), replaces_up_to_seq as i64],
        )?;
        tx.execute(
            "DELETE FROM chunks WHERE vault_id = ?1 AND seq <= ?2",
            params![vault_key(vault_id), replaces_up_to_seq as i64],
        )?;
        tx.commit()?;
        self.reclaim();
        Ok(removed)
    }

    pub fn replace_chunks(
        &mut self,
        vault_id: &VaultId,
        remove_seqs: &[u64],
        replacements: &[ChunkId],
    ) -> StoreResult<Vec<ObjectId>> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::require_vault(&tx, vault_id)?;
        for chunk_id in replacements {
            let seq: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM chunks WHERE vault_id = ?1 AND chunk_id = ?2",
                    params![vault_key(vault_id), chunk_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            match seq {
                Some(seq) if !remove_seqs.contains(&(seq as u64)) => {}
                Some(_) => {
                    return Err(StoreError::Invalid(
                        "replacement chunk is listed for removal",
                    ));
                }
                None => return Err(StoreError::ChunkNotFound),
            }
        }
        let mut removed = Vec::new();
        for seq in remove_seqs {
            removed.extend(Self::object_ids_where(
                &tx,
                "SELECT object_id FROM chunks WHERE vault_id = ?1 AND seq = ?2",
                params![vault_key(vault_id), *seq as i64],
            )?);
            tx.execute(
                "DELETE FROM chunks WHERE vault_id = ?1 AND seq = ?2",
                params![vault_key(vault_id), *seq as i64],
            )?;
        }
        tx.commit()?;
        self.reclaim();
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: Limits = Limits {
        quota_bytes: None,
        max_vaults: 5,
    };

    fn store() -> (tempfile::TempDir, AccountId, AccountStore) {
        let dir = tempfile::tempdir().unwrap();
        let id = AccountId::random().unwrap();
        let store = AccountStore::open(dir.path(), &id, &[4; 32]).unwrap();
        (dir, id, store)
    }

    fn vault(store: &mut AccountStore) -> VaultId {
        let id = VaultId::random().unwrap();
        store
            .create_vault(&id, &[1; 32], &[2; 32], 10, OPEN)
            .unwrap();
        id
    }

    fn put(
        store: &mut AccountStore,
        vault: &VaultId,
        chunk_id: &ChunkId,
        hash: u8,
        size: u64,
        limits: Limits,
    ) -> StoreResult<(u64, bool)> {
        let object_id: ObjectId = vrcx_0_nanashi_website_protocol::rand::bytes().unwrap();
        store.insert_chunk(
            vault,
            &NewChunk {
                chunk_id,
                object_id,
                blob_hash: [hash; 32],
                size,
            },
            limits,
        )
    }

    #[test]
    fn chunks_get_increasing_seqs_and_retries_are_detected() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        let a = ChunkId::random().unwrap();
        let b = ChunkId::random().unwrap();
        assert_eq!(
            store.check_chunk(&vault, &a, &[1; 32], 3, OPEN).unwrap(),
            ChunkCheck::New
        );
        assert_eq!(put(&mut store, &vault, &a, 1, 3, OPEN).unwrap(), (1, false));
        assert_eq!(put(&mut store, &vault, &b, 2, 4, OPEN).unwrap(), (2, false));
        assert_eq!(
            store.check_chunk(&vault, &a, &[1; 32], 3, OPEN).unwrap(),
            ChunkCheck::Existing(1)
        );
        assert!(matches!(
            store.check_chunk(&vault, &a, &[9; 32], 3, OPEN),
            Err(StoreError::ChunkIdExists)
        ));
        assert_eq!(
            put(&mut store, &vault, &a, 1, 3, OPEN).unwrap(),
            (1, true),
            "concurrent duplicate"
        );
        assert!(matches!(
            put(&mut store, &vault, &a, 9, 3, OPEN),
            Err(StoreError::ChunkIdExists)
        ));
        assert_eq!(store.chunk(&vault, 2).unwrap().chunk_id, b);
        assert_eq!(store.usage().unwrap(), 7);
        assert_eq!(store.all_object_ids().unwrap().len(), 2);
        let page = store.chunk_page(&vault, 0, 1, u64::MAX).unwrap();
        assert_eq!(page.chunks.len(), 1);
        assert!(page.has_more);
        assert_eq!(page.max_seq, 2);
        let page = store.chunk_page(&vault, 1, 10, u64::MAX).unwrap();
        assert_eq!(page.chunks[0].seq, 2);
        assert!(!page.has_more);
    }

    #[test]
    fn byte_cap_limits_pages_but_always_returns_one() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        for hash in 0..3 {
            put(
                &mut store,
                &vault,
                &ChunkId::random().unwrap(),
                hash,
                100,
                OPEN,
            )
            .unwrap();
        }
        let page = store.chunk_page(&vault, 0, 10, 150).unwrap();
        assert_eq!(page.chunks.len(), 1);
        assert!(page.has_more);
        let page = store.chunk_page(&vault, 0, 10, 50).unwrap();
        assert_eq!(page.chunks.len(), 1);
    }

    #[test]
    fn quota_is_enforced_before_writing() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        let limits = Limits {
            quota_bytes: Some(10),
            max_vaults: 5,
        };
        put(
            &mut store,
            &vault,
            &ChunkId::random().unwrap(),
            1,
            8,
            limits,
        )
        .unwrap();
        let next = ChunkId::random().unwrap();
        assert!(matches!(
            store.check_chunk(&vault, &next, &[2; 32], 3, limits),
            Err(StoreError::QuotaExceeded)
        ));
        assert!(matches!(
            put(&mut store, &vault, &next, 2, 3, limits),
            Err(StoreError::QuotaExceeded)
        ));
        assert_eq!(store.usage().unwrap(), 8);
        assert!(matches!(
            store.put_manifest(&vault, 1, &[0; 3], limits),
            Err(StoreError::QuotaExceeded)
        ));
        store.put_manifest(&vault, 1, &[0; 2], limits).unwrap();
    }

    #[test]
    fn vault_limit_and_duplicates() {
        let (_dir, _, mut store) = store();
        let limits = Limits {
            quota_bytes: None,
            max_vaults: 1,
        };
        let id = VaultId::random().unwrap();
        store.create_vault(&id, &[1], &[2], 0, limits).unwrap();
        assert!(matches!(
            store.create_vault(&id, &[1], &[2], 0, OPEN),
            Err(StoreError::VaultExists)
        ));
        assert!(matches!(
            store.create_vault(&VaultId::random().unwrap(), &[1], &[2], 0, limits),
            Err(StoreError::VaultLimit)
        ));
    }

    #[test]
    fn manifest_sequence_must_advance_by_one() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        assert!(store.manifest(&vault).unwrap().is_none());
        assert!(matches!(
            store.put_manifest(&vault, 2, b"m", OPEN),
            Err(StoreError::ManifestConflict)
        ));
        store.put_manifest(&vault, 1, b"m1", OPEN).unwrap();
        assert!(matches!(
            store.put_manifest(&vault, 1, b"m", OPEN),
            Err(StoreError::ManifestConflict)
        ));
        store.put_manifest(&vault, 2, b"m2", OPEN).unwrap();
        assert_eq!(store.manifest(&vault).unwrap(), Some((2, b"m2".to_vec())));
    }

    #[test]
    fn compaction_requires_newer_replacements_and_returns_objects() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        let old = ChunkId::random().unwrap();
        put(&mut store, &vault, &old, 1, 4, OPEN).unwrap();
        put(&mut store, &vault, &ChunkId::random().unwrap(), 2, 4, OPEN).unwrap();
        let new = ChunkId::random().unwrap();
        put(&mut store, &vault, &new, 3, 3, OPEN).unwrap();
        let old_objects: Vec<ObjectId> = store
            .chunk_page(&vault, 0, 2, u64::MAX)
            .unwrap()
            .chunks
            .iter()
            .map(|c| c.object_id)
            .collect();
        assert!(store.compact(&vault, 2, &[old]).is_err());
        assert!(matches!(
            store.compact(&vault, 2, &[ChunkId::random().unwrap()]),
            Err(StoreError::ChunkNotFound)
        ));
        assert_eq!(store.compact(&vault, 2, &[new]).unwrap(), old_objects);
        let page = store.chunk_page(&vault, 0, 10, u64::MAX).unwrap();
        assert_eq!(page.chunks.len(), 1);
        assert_eq!(page.max_seq, 3);
        assert_eq!(
            put(&mut store, &vault, &ChunkId::random().unwrap(), 4, 1, OPEN)
                .unwrap()
                .0,
            4
        );
    }

    #[test]
    fn replacing_chunks_removes_only_the_listed_ones_and_keeps_sequence_numbers() {
        let (_dir, _, mut store) = store();
        let vault = vault(&mut store);
        let first = ChunkId::random().unwrap();
        put(&mut store, &vault, &first, 1, 4, OPEN).unwrap();
        put(&mut store, &vault, &ChunkId::random().unwrap(), 2, 4, OPEN).unwrap();
        put(&mut store, &vault, &ChunkId::random().unwrap(), 3, 4, OPEN).unwrap();
        let replacement = ChunkId::random().unwrap();
        put(&mut store, &vault, &replacement, 4, 2, OPEN).unwrap();
        let second_object = store.chunk_page(&vault, 1, 1, u64::MAX).unwrap().chunks[0].object_id;

        assert!(matches!(
            store.replace_chunks(&vault, &[2], &[ChunkId::random().unwrap()]),
            Err(StoreError::ChunkNotFound)
        ));
        assert!(store.replace_chunks(&vault, &[1, 2], &[first]).is_err());
        assert_eq!(
            store
                .chunk_page(&vault, 0, 10, u64::MAX)
                .unwrap()
                .chunks
                .len(),
            4
        );

        assert_eq!(
            store.replace_chunks(&vault, &[2], &[replacement]).unwrap(),
            vec![second_object]
        );
        let page = store.chunk_page(&vault, 0, 10, u64::MAX).unwrap();
        assert_eq!(
            page.chunks
                .iter()
                .map(|chunk| chunk.seq)
                .collect::<Vec<_>>(),
            [1, 3, 4]
        );
        assert!(
            store
                .replace_chunks(&vault, &[2], &[replacement])
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.replace_chunks(&vault, &[4], &[]).unwrap().len(), 1);
        assert_eq!(
            put(&mut store, &vault, &ChunkId::random().unwrap(), 5, 1, OPEN)
                .unwrap()
                .0,
            5
        );
    }

    #[test]
    fn deleting_vault_returns_objects_and_account_file_goes() {
        let (dir, id, mut store) = store();
        let vault = vault(&mut store);
        put(&mut store, &vault, &ChunkId::random().unwrap(), 1, 1, OPEN).unwrap();
        assert_eq!(store.delete_vault(&vault).unwrap().len(), 1);
        assert_eq!(store.usage().unwrap(), 0);
        assert!(matches!(
            store.delete_vault(&vault),
            Err(StoreError::VaultNotFound)
        ));
        drop(store);
        delete_account_db(dir.path(), &id).unwrap();
        assert!(!account_db_path(dir.path(), &id).exists());
    }

    #[test]
    fn unknown_vault_is_not_found_everywhere() {
        let (_dir, _, mut store) = store();
        let missing = VaultId::random().unwrap();
        assert!(matches!(
            store.chunk(&missing, 1),
            Err(StoreError::VaultNotFound)
        ));
        assert!(matches!(
            store.manifest(&missing),
            Err(StoreError::VaultNotFound)
        ));
        assert!(matches!(
            put(
                &mut store,
                &missing,
                &ChunkId::random().unwrap(),
                1,
                1,
                OPEN
            ),
            Err(StoreError::VaultNotFound)
        ));
    }
}

#[cfg(test)]
mod epoch_upgrade_tests {
    use super::*;
    #[test]
    fn upgrades_signed_dates_without_changing_durations_or_rerunning() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection, &MIGRATIONS[..1]).unwrap();
        connection.execute("INSERT INTO envelopes (envelope_id, body, size, created_at_ms) VALUES ('old', x'01', 1, -1)", []).unwrap();
        migrate(&mut connection, MIGRATIONS).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT created_at FROM envelopes", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            -1
        );
        migrate(&mut connection, MIGRATIONS).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM envelopes", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
