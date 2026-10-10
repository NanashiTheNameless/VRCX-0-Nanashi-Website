use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::chunk::SignerLookup;
use crate::framing::{self, Signing};
use crate::ids::VaultId;
use crate::keys::{self, VaultKeys};
use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"remotesync/v1/manifest";
pub const VERSION: u8 = 1;
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignerKind {
    Device,
    Collector,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerEntry {
    pub key_id: String,
    pub public_key: ByteBuf,
    pub kind: SignerKind,
    pub label: String,
    pub added_at_ms: i64,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
}

impl SignerEntry {
    pub fn new(
        public: &VerifyingKey,
        kind: SignerKind,
        label: impl Into<String>,
        added_at_ms: i64,
    ) -> Self {
        Self {
            key_id: keys::key_id(public),
            public_key: ByteBuf::from(public.as_bytes().to_vec()),
            kind,
            label: label.into(),
            added_at_ms,
            expires_at_ms: None,
        }
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        let key = keys::verifying_key(&self.public_key)?;
        if keys::key_id(&key) != self.key_id {
            return Err(Error::Mismatch("signer key id"));
        }
        Ok(key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSubject {
    pub vrchat_user_id: String,
    pub display_name: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionSettings {
    #[serde(default)]
    pub max_age_days: Option<u32>,
    #[serde(default)]
    pub keep_below_limit_margin_pct: Option<u32>,
}

impl RetentionSettings {
    pub const MAX_AGE_DAYS: core::ops::RangeInclusive<u32> = 1..=3650;
    pub const MARGIN_PCT: core::ops::RangeInclusive<u32> = 1..=90;

    pub fn is_valid(&self) -> bool {
        self.max_age_days
            .is_none_or(|days| Self::MAX_AGE_DAYS.contains(&days))
            && self
                .keep_below_limit_margin_pct
                .is_none_or(|pct| Self::MARGIN_PCT.contains(&pct))
    }

    pub fn size_target(&self, limit_bytes: u64) -> Option<u64> {
        self.keep_below_limit_margin_pct
            .map(|pct| limit_bytes / 100 * u64::from(100 - pct.min(100)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub v: u8,
    pub vault_id: VaultId,
    pub manifest_seq: u64,
    #[serde(default)]
    pub compacted_through_seq: u64,
    #[serde(default)]
    pub subject: Option<ManifestSubject>,
    #[serde(default)]
    pub retention: RetentionSettings,
    pub signers: Vec<SignerEntry>,
}

impl Manifest {
    pub fn new(vault_id: VaultId, subject: Option<ManifestSubject>) -> Self {
        Self {
            v: VERSION,
            vault_id,
            manifest_seq: 1,
            compacted_through_seq: 0,
            subject,
            retention: RetentionSettings::default(),
            signers: Vec::new(),
        }
    }

    pub fn next(&self) -> Self {
        let mut next = self.clone();
        next.manifest_seq += 1;
        next
    }

    pub fn add_signer(&mut self, entry: SignerEntry) {
        self.signers
            .retain(|existing| existing.key_id != entry.key_id);
        self.signers.push(entry);
    }

    pub fn remove_signer(&mut self, key_id: &str) -> bool {
        let before = self.signers.len();
        self.signers.retain(|existing| existing.key_id != key_id);
        before != self.signers.len()
    }
}

impl SignerLookup for Manifest {
    fn signer(&self, key_id: &str, at_ms: i64) -> Option<VerifyingKey> {
        let entry = self.signers.iter().find(|entry| entry.key_id == key_id)?;
        if at_ms < entry.added_at_ms - CLOCK_SKEW_MS {
            return None;
        }
        if entry
            .expires_at_ms
            .is_some_and(|expires| at_ms > expires + CLOCK_SKEW_MS)
        {
            return None;
        }
        entry.verifying_key().ok()
    }
}

fn binding(vault_id: &VaultId, manifest_seq: u64) -> Vec<u8> {
    [vault_id.as_bytes().as_slice(), &manifest_seq.to_be_bytes()].concat()
}

pub fn seal_manifest(manifest: &Manifest, keys: &VaultKeys) -> Result<Vec<u8>> {
    if manifest.vault_id != keys.vault_id() {
        return Err(Error::Mismatch("vault keys"));
    }
    if !manifest.retention.is_valid() {
        return Err(Error::Invalid("retention settings"));
    }
    for entry in &manifest.signers {
        entry.verifying_key()?;
    }
    let header = framing::to_cbor(manifest)?;
    framing::seal_signed(
        DOMAIN,
        &binding(&manifest.vault_id, manifest.manifest_seq),
        &header,
        &[],
        Signing::Manifest(keys.manifest_signing()),
        &keys.public().vault_pk,
    )
}

pub fn open_manifest(
    blob: &[u8],
    server_seq: u64,
    keys: &VaultKeys,
    highest_seen: Option<u64>,
) -> Result<Manifest> {
    let vault_id = keys.vault_id();
    let unverified = framing::open_signed(
        DOMAIN,
        binding(&vault_id, server_seq),
        keys.seal_private(),
        blob,
    )?;
    let (header, _) = unverified.verify(&keys.public().manifest_pk)?;
    let manifest: Manifest = framing::from_cbor(&header, "manifest")?;
    if manifest.v != VERSION {
        return Err(Error::Invalid("manifest version"));
    }
    if manifest.vault_id != vault_id || manifest.manifest_seq != server_seq {
        return Err(Error::Mismatch("manifest"));
    }
    if highest_seen.is_some_and(|seen| manifest.manifest_seq < seen) {
        return Err(Error::Rollback("manifest"));
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SignerKey;
    use crate::secret::SyncSecret;

    fn keys() -> VaultKeys {
        VaultKeys::derive(&SyncSecret::generate().unwrap(), VaultId::random().unwrap())
    }

    #[test]
    fn round_trip_and_lookup() {
        let keys = keys();
        let device = SignerKey::generate().unwrap();
        let mut manifest = Manifest::new(
            keys.vault_id(),
            Some(ManifestSubject {
                vrchat_user_id: "usr_1".into(),
                display_name: "me".into(),
            }),
        );
        manifest.add_signer(SignerEntry::new(
            &device.public(),
            SignerKind::Device,
            "PC",
            1_000_000,
        ));
        let blob = seal_manifest(&manifest, &keys).unwrap();
        let opened = open_manifest(&blob, 1, &keys, None).unwrap();
        assert_eq!(opened, manifest);
        assert_eq!(
            opened.signer(&device.key_id(), 1_000_000),
            Some(device.public())
        );
        assert_eq!(opened.signer("nope", 1_000_000), None);
    }

    #[test]
    fn signer_validity_window() {
        let device = SignerKey::generate().unwrap();
        let mut manifest = Manifest::new(VaultId::random().unwrap(), None);
        let mut entry = SignerEntry::new(
            &device.public(),
            SignerKind::Collector,
            "collector",
            10_000_000,
        );
        entry.expires_at_ms = Some(20_000_000);
        manifest.add_signer(entry);
        let id = device.key_id();
        assert!(
            manifest
                .signer(&id, 10_000_000 - CLOCK_SKEW_MS - 1)
                .is_none()
        );
        assert!(manifest.signer(&id, 15_000_000).is_some());
        assert!(
            manifest
                .signer(&id, 20_000_000 + CLOCK_SKEW_MS + 1)
                .is_none()
        );
        assert!(manifest.remove_signer(&id));
        assert!(manifest.signer(&id, 15_000_000).is_none());
    }

    #[test]
    fn rejects_rollback_and_seq_mismatch() {
        let keys = keys();
        let manifest = Manifest::new(keys.vault_id(), None).next().next();
        let blob = seal_manifest(&manifest, &keys).unwrap();
        assert!(open_manifest(&blob, 3, &keys, Some(3)).is_ok());
        assert_eq!(
            open_manifest(&blob, 3, &keys, Some(4)),
            Err(Error::Rollback("manifest"))
        );
        assert_eq!(open_manifest(&blob, 2, &keys, None), Err(Error::Decrypt));
    }

    #[test]
    fn rejects_manifest_signed_without_the_manifest_key() {
        let keys = keys();
        let manifest = Manifest::new(keys.vault_id(), None);
        let header = framing::to_cbor(&manifest).unwrap();
        let attacker = SignerKey::generate().unwrap();
        let blob = framing::seal_signed(
            DOMAIN,
            &binding(&manifest.vault_id, 1),
            &header,
            &[],
            Signing::Signer(&attacker),
            &keys.public().vault_pk,
        )
        .unwrap();
        assert_eq!(open_manifest(&blob, 1, &keys, None), Err(Error::Signature));
    }

    #[test]
    fn retention_settings_travel_in_the_manifest() {
        let keys = keys();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        manifest.retention = RetentionSettings {
            max_age_days: Some(90),
            keep_below_limit_margin_pct: Some(10),
        };
        let blob = seal_manifest(&manifest, &keys).unwrap();
        assert_eq!(
            open_manifest(&blob, 1, &keys, None).unwrap().retention,
            manifest.retention
        );
        assert_eq!(manifest.retention.size_target(1000), Some(900));
        manifest.retention.max_age_days = Some(0);
        assert_eq!(
            seal_manifest(&manifest, &keys),
            Err(Error::Invalid("retention settings"))
        );
    }

    #[test]
    fn rejects_tampered_key_id() {
        let keys = keys();
        let device = SignerKey::generate().unwrap();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        let mut entry = SignerEntry::new(&device.public(), SignerKind::Device, "PC", 0);
        entry.key_id = "something-else".into();
        manifest.signers.push(entry);
        assert_eq!(
            seal_manifest(&manifest, &keys),
            Err(Error::Mismatch("signer key id"))
        );
    }
}
