use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use vrcx_0_nanashi_website_protocol::ids::AccountId;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto::ServerKeys;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::HEXLOWER;
use vrcx_0_nanashi_website_protocol::blob;
use vrcx_0_nanashi_website_protocol::keys::hkdf32;

use crate::db::account::{AccountStore, Limits, ObjectId};
use crate::db::registry::{AccountRow, AccountState, DeletionKind, Registry};
use crate::http::{ApiErr, ApiResult};
use crate::objects::ObjectStore;
use crate::util::{DAY_MS, now_epoch, random_bytes};

pub const INFO_BLOB: &[u8] = b"remotesync/v1/blob";
pub const INFO_BLOB_PREFIX: &[u8] = b"remotesync/v1/blob-prefix";
const OBJECT_NONCE: usize = 24;
const MAX_LIVE_SNAPSHOTS: usize = 256;
const MAX_LIVE_SNAPSHOT_BYTES: usize = 1024 * 1024;

pub struct AccountKeys {
    db: Zeroizing<[u8; 32]>,
    blob: Zeroizing<[u8; 32]>,
    prefix_hex: String,
}

impl AccountKeys {
    fn derive(adk: &[u8; 32]) -> Self {
        let prefix = hkdf32(&[], adk, INFO_BLOB_PREFIX);
        Self {
            db: Zeroizing::new(*adk),
            blob: hkdf32(&[], adk, INFO_BLOB),
            prefix_hex: HEXLOWER.encode(&prefix[..16]),
        }
    }

    pub fn prefix(&self) -> String {
        blob::prefix(&self.prefix_hex)
    }

    pub(crate) fn db_key(&self) -> &[u8; 32] {
        &self.db
    }

    pub fn object_key(&self, object_id: &ObjectId) -> String {
        blob::object_key(&self.prefix_hex, &HEXLOWER.encode(object_id))
    }

    fn aad(key: &str) -> Vec<u8> {
        [INFO_BLOB, &[0], key.as_bytes()].concat()
    }

    pub fn seal_object(&self, key: &str, data: &[u8]) -> Vec<u8> {
        let nonce: [u8; OBJECT_NONCE] = random_bytes();
        let ciphertext = XChaCha20Poly1305::new((&*self.blob).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: data,
                    aad: &Self::aad(key),
                },
            )
            .expect("XChaCha20Poly1305 encryption cannot fail for chunk sizes");
        [nonce.as_slice(), &ciphertext].concat()
    }

    pub fn open_object(&self, key: &str, sealed: &[u8]) -> ApiResult<Vec<u8>> {
        if sealed.len() < OBJECT_NONCE {
            return Err(ApiErr::internal("object storage", "object too short"));
        }
        let (nonce, ciphertext) = sealed.split_at(OBJECT_NONCE);
        let nonce: [u8; OBJECT_NONCE] = nonce.try_into().expect("24 bytes");
        XChaCha20Poly1305::new((&*self.blob).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &Self::aad(key),
                },
            )
            .map_err(|_| ApiErr::internal("object storage", "object failed authentication"))
    }
}

pub struct AppState {
    pub config: Config,
    pub keys: ServerKeys,
    registry: Mutex<Registry>,
    client_writes: Mutex<HashMap<(String, String), i64>>,
    pub limiter: crate::rate::RateLimiter,
    pub objects: ObjectStore,
    pub mailer: crate::mail::Mailer,
    live_snapshots: Mutex<HashMap<(String, String), LiveSnapshotRecord>>,
}

#[derive(Clone)]
pub struct LiveSnapshotRecord {
    pub seq: u64,
    pub published_at: i64,
    pub blob: Vec<u8>,
}

pub type Shared = Arc<AppState>;

pub const CLIENT_WRITE_INTERVAL_MS: i64 = 5 * 60 * 1000;

impl AppState {
    pub fn new(
        config: Config,
        keys: ServerKeys,
        registry: Registry,
        objects: ObjectStore,
        mailer: crate::mail::Mailer,
    ) -> Shared {
        Arc::new(Self {
            config,
            keys,
            registry: Mutex::new(registry),
            client_writes: Mutex::new(HashMap::new()),
            limiter: crate::rate::RateLimiter::default(),
            objects,
            mailer,
            live_snapshots: Mutex::new(HashMap::new()),
        })
    }

    pub fn publish_live_snapshot(
        &self,
        account_id: &str,
        vault_id: &str,
        seq: u64,
        blob: Vec<u8>,
    ) -> bool {
        if blob.len() > MAX_LIVE_SNAPSHOT_BYTES {
            return false;
        }
        let mut snapshots = self
            .live_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (account_id.to_owned(), vault_id.to_owned());
        if snapshots.get(&key).is_some_and(|old| old.seq >= seq) {
            return false;
        }
        if !snapshots.contains_key(&key)
            && snapshots.len() >= MAX_LIVE_SNAPSHOTS
            && let Some(oldest) = snapshots
                .iter()
                .min_by_key(|(_, snapshot)| snapshot.published_at)
                .map(|(key, _)| key.clone())
        {
            snapshots.remove(&oldest);
        }
        snapshots.insert(
            key,
            LiveSnapshotRecord {
                seq,
                published_at: now_epoch(),
                blob,
            },
        );
        true
    }

    pub fn live_snapshot(&self, account_id: &str, vault_id: &str) -> Option<LiveSnapshotRecord> {
        self.live_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(account_id.to_owned(), vault_id.to_owned()))
            .cloned()
    }

    pub fn clear_live_snapshot(&self, account_id: &str, vault_id: Option<&str>) {
        let mut snapshots = self
            .live_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match vault_id {
            Some(vault_id) => {
                snapshots.remove(&(account_id.to_owned(), vault_id.to_owned()));
            }
            None => snapshots.retain(|(account, _), _| account != account_id),
        }
    }

    pub fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce(&AppState) -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || work(&state))
            .await
            .map_err(|error| ApiErr::internal("blocking task", error))?
    }

    pub fn should_write_client(&self, client_id: &str, ip: &str, now: i64) -> bool {
        let mut writes = self.client_writes.lock().unwrap_or_else(|p| p.into_inner());
        let key = (client_id.to_owned(), ip.to_owned());
        match writes.get(&key) {
            Some(last) if now - last < (CLIENT_WRITE_INTERVAL_MS / 1000) => false,
            _ => {
                writes.insert(key, now);
                if writes.len() > 100_000 {
                    writes.retain(|_, last| now - *last < (CLIENT_WRITE_INTERVAL_MS / 1000));
                }
                true
            }
        }
    }

    pub fn forget_client_writes(&self, client_id: Option<&str>) {
        let mut writes = self.client_writes.lock().unwrap_or_else(|p| p.into_inner());
        match client_id {
            Some(id) => writes.retain(|(client, _), _| client != id),
            None => writes.clear(),
        }
    }

    pub fn open_store(&self, account: &AccountRow) -> ApiResult<AccountStore> {
        Ok(self.open_store_with_keys(account)?.0)
    }

    pub fn open_store_with_keys(
        &self,
        account: &AccountRow,
    ) -> ApiResult<(AccountStore, AccountKeys)> {
        let keys = AccountKeys::derive(&*self.account_key(account)?);
        let store = AccountStore::open(&self.config.data_dir, &account.account_id, &keys.db)?;
        Ok((store, keys))
    }

    fn existing_keys(&self, account_id: &AccountId) -> ApiResult<Option<AccountKeys>> {
        let Some(account) = self.registry().account(account_id)? else {
            return Ok(None);
        };
        if account.wrapped_adk.is_none() {
            return Ok(None);
        }
        Ok(Some(AccountKeys::derive(&*self.account_key(&account)?)))
    }

    pub fn enqueue_object_deletions(
        &self,
        keys: &AccountKeys,
        objects: &[ObjectId],
    ) -> ApiResult<()> {
        if objects.is_empty() {
            return Ok(());
        }
        let items: Vec<_> = objects
            .iter()
            .map(|id| (DeletionKind::Object, keys.object_key(id)))
            .collect();
        self.registry().enqueue_deletions(&items)?;
        Ok(())
    }

    fn account_key(&self, account: &AccountRow) -> ApiResult<Zeroizing<[u8; 32]>> {
        let context = account.account_id.as_str();
        let wrapped = match &account.wrapped_adk {
            Some(wrapped) => wrapped.clone(),
            None => {
                let registry = self.registry();
                let current = registry
                    .account(&account.account_id)?
                    .ok_or_else(|| ApiErr::internal("account key", "account vanished"))?;
                match current.wrapped_adk {
                    Some(wrapped) => wrapped,
                    None => {
                        let adk = Zeroizing::new(random_bytes::<32>());
                        let wrapped = self.keys.wrap(context, adk.as_slice());
                        registry.set_wrapped_adk(&account.account_id, Some(&wrapped))?;
                        wrapped
                    }
                }
            }
        };
        let plain = self
            .keys
            .unwrap(context, &wrapped)
            .map_err(|error| ApiErr::internal("account key", error))?;
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| ApiErr::internal("account key", "wrong length"))?;
        Ok(Zeroizing::new(key))
    }

    pub fn rate(&self, rule: crate::rate::Rule, key: &str) -> ApiResult<()> {
        self.limiter
            .take(rule, key, now_epoch())
            .map_err(ApiErr::rate_limited)
    }

    pub fn limits(account: &AccountRow) -> Limits {
        Limits {
            quota_bytes: account.effective_quota(),
            max_vaults: account.effective_max_vaults(),
        }
    }

    pub fn refresh_usage(&self, account_id: &AccountId, store: &AccountStore) -> ApiResult<u64> {
        let usage = store.usage()?;
        self.registry().set_usage(account_id, usage)?;
        Ok(usage)
    }

    pub fn delete_account_data(&self, account_id: &AccountId) -> ApiResult<()> {
        self.clear_live_snapshot(account_id.as_str(), None);
        if let Some(keys) = self.existing_keys(account_id)? {
            self.registry()
                .enqueue_deletions(&[(DeletionKind::Prefix, keys.prefix())])?;
        }
        let registry = self.registry();
        crate::db::account::delete_account_db(&self.config.data_dir, account_id)
            .map_err(|error| ApiErr::internal("delete account file", error))?;
        registry.set_wrapped_adk(account_id, None)?;
        registry.set_usage(account_id, 0)?;
        registry
            .conn()
            .execute(
                "DELETE FROM collection_index WHERE account_id = ?1",
                [account_id.as_str()],
            )
            .map_err(crate::db::DbError::from)?;
        Ok(())
    }

    pub fn forbid_sync(&self, account_id: &AccountId, actor: &str) -> ApiResult<()> {
        self.clear_live_snapshot(account_id.as_str(), None);
        let account = self
            .registry()
            .account(account_id)?
            .ok_or_else(|| ApiErr::internal("forbid sync", "account vanished"))?;
        let collections = if account.wrapped_adk.is_some() {
            let (store, keys) = self.open_store_with_keys(&account)?;
            self.registry()
                .enqueue_deletions(&[(DeletionKind::Prefix, keys.prefix())])?;
            store.export_collections()?
        } else {
            Vec::new()
        };
        {
            let registry = self.registry();
            registry.set_sync_allowed(account_id, false)?;
            crate::db::account::delete_account_db(&self.config.data_dir, account_id)
                .map_err(|error| ApiErr::internal("delete account file", error))?;
            registry.set_wrapped_adk(account_id, None)?;
            registry.set_usage(account_id, 0)?;
            registry.audit(actor, "forbid-sync", Some(account_id), now_epoch())?;
        }
        if !collections.is_empty() {
            let account = self
                .registry()
                .account(account_id)?
                .ok_or_else(|| ApiErr::internal("forbid sync", "account vanished"))?;
            let mut store = self.open_store(&account)?;
            store.import_collections(&collections)?;
            self.refresh_usage(account_id, &store)?;
        }
        Ok(())
    }

    pub fn allow_sync(&self, account_id: &AccountId, actor: &str) -> ApiResult<()> {
        let registry = self.registry();
        registry.set_sync_allowed(account_id, true)?;
        registry.audit(actor, "allow-sync", Some(account_id), now_epoch())?;
        Ok(())
    }

    pub fn delete_account(&self, account_id: &AccountId) -> ApiResult<()> {
        self.delete_account_data(account_id)?;
        self.registry().delete_account(account_id)?;
        self.forget_client_writes(None);
        Ok(())
    }

    pub async fn process_deletions(self: &Arc<Self>) -> ApiResult<()> {
        loop {
            let due = self
                .run(|state| Ok(state.registry().due_deletions(now_epoch(), 100)?))
                .await?;
            if due.is_empty() {
                return Ok(());
            }
            for (kind, target, attempts) in due {
                let result = match kind {
                    DeletionKind::Object => self.objects.delete(&target).await.map(|()| 1),
                    DeletionKind::Prefix => self.objects.delete_prefix(&target).await,
                };
                let target_for_db = target.clone();
                match result {
                    Ok(_) => {
                        self.run(move |state| {
                            Ok(state.registry().finish_deletion(&target_for_db)?)
                        })
                        .await?;
                    }
                    Err(error) => {
                        tracing::warn!(%error, attempts, "object deletion failed, will retry");
                        let backoff = (60_000_i64 << attempts.clamp(0, 6)).min(3_600_000);
                        self.run(move |state| {
                            Ok(state
                                .registry()
                                .retry_deletion(&target_for_db, now_epoch() + backoff / 1000)?)
                        })
                        .await?;
                        return Ok(());
                    }
                }
            }
        }
    }

    pub async fn send_email(
        &self,
        to: &str,
        email: crate::mail::Email,
        key: String,
    ) -> ApiResult<()> {
        self.mailer.send(email.to(to, key)).await.map_err(|error| {
            tracing::error!("{error}");
            ApiErr::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "email_unavailable",
                "Email could not be sent. Try again later.",
            )
        })
    }

    pub fn send_email_later(self: &Arc<Self>, to: String, email: crate::mail::Email, key: String) {
        let state = self.clone();
        tokio::spawn(async move {
            let _ = state.send_email(&to, email, key).await;
        });
    }

    pub fn kick_deletions(self: &Arc<Self>) {
        let state = self.clone();
        tokio::spawn(async move {
            if let Err(error) = state.process_deletions().await {
                tracing::error!(?error, "processing object deletions failed");
            }
        });
    }

    pub async fn sweep_orphans(self: &Arc<Self>) -> ApiResult<u64> {
        let accounts = self
            .run(|state| Ok(state.registry().list_accounts(None)?))
            .await?;
        let mut deleted = 0;
        for account in accounts.into_iter().filter(|a| a.wrapped_adk.is_some()) {
            let (keys, referenced) = self
                .run(move |state| {
                    let (store, keys) = state.open_store_with_keys(&account)?;
                    let referenced: std::collections::HashSet<String> = store
                        .all_object_ids()?
                        .iter()
                        .map(|id| keys.object_key(id))
                        .collect();
                    Ok((keys, referenced))
                })
                .await?;
            let listed = self
                .objects
                .list_all(&keys.prefix())
                .await
                .map_err(ApiErr::storage)?;
            let cutoff = now_epoch() - (DAY_MS / 1000);
            for entry in listed {
                if !referenced.contains(&entry.key) && entry.last_modified < cutoff {
                    self.objects
                        .delete(&entry.key)
                        .await
                        .map_err(ApiErr::storage)?;
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    }

    pub fn approve_account(&self, account_id: &AccountId, actor: &str) -> ApiResult<bool> {
        let registry = self.registry();
        let changed = registry.set_state(account_id, AccountState::Active)?;
        if changed {
            registry.audit(actor, "approve", Some(account_id), now_epoch())?;
        }
        Ok(changed)
    }
}
