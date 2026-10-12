use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::chunk::SignerLookup;
use crate::framing::{self, Signing};
use crate::ids::{SourceId, VaultId};
use crate::keys::{self, VaultKeys};
use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"remotesync/v1/manifest";
pub const VERSION: u8 = 3;
const OLDEST_VERSION: u8 = 1;
pub const MAX_REPLACED_RANGES: usize = 512;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqRange {
    pub first: u64,
    pub last: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSeqRanges {
    pub source_id: SourceId,
    pub ranges: Vec<SeqRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSeq {
    pub source_id: SourceId,
    pub seq: u64,
}

fn ranges_are_valid(ranges: &[SeqRange]) -> bool {
    ranges.iter().all(|range| range.first <= range.last)
        && ranges
            .windows(2)
            .all(|pair| pair[0].last.saturating_add(1) < pair[1].first)
}

fn ranges_contain(ranges: &[SeqRange], seq: u64) -> bool {
    let index = ranges.partition_point(|range| range.last < seq);
    ranges.get(index).is_some_and(|range| range.first <= seq)
}

fn ranges_insert(ranges: &mut Vec<SeqRange>, seq: u64) {
    if ranges_contain(ranges, seq) {
        return;
    }
    let index = ranges.partition_point(|range| range.last < seq);
    let joins_previous = index > 0 && ranges[index - 1].last.saturating_add(1) == seq;
    let joins_next = index < ranges.len() && seq.saturating_add(1) == ranges[index].first;
    match (joins_previous, joins_next) {
        (true, true) => {
            ranges[index - 1].last = ranges[index].last;
            ranges.remove(index);
        }
        (true, false) => ranges[index - 1].last = seq,
        (false, true) => ranges[index].first = seq,
        (false, false) => ranges.insert(
            index,
            SeqRange {
                first: seq,
                last: seq,
            },
        ),
    }
}

fn ranges_missing(ranges: &[SeqRange], first: u64, last: u64) -> Vec<SeqRange> {
    let mut missing = Vec::new();
    let mut next = first;
    for range in &ranges[ranges.partition_point(|range| range.last < first)..] {
        if next > last || range.first > last {
            break;
        }
        if range.first > next {
            missing.push(SeqRange {
                first: next,
                last: range.first - 1,
            });
        }
        next = next.max(range.last.saturating_add(1));
        if range.last == u64::MAX {
            return missing;
        }
    }
    if next <= last {
        missing.push(SeqRange { first: next, last });
    }
    missing
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
    /// Device that is allowed to compact the merged vault history.
    #[serde(default)]
    pub dedupe_device_key_id: Option<String>,
    #[serde(default)]
    pub replaced_seqs: Vec<SeqRange>,
    #[serde(default)]
    pub replaced_source_seqs: Vec<SourceSeqRanges>,
    #[serde(default)]
    pub compacted_source_seqs: Vec<SourceSeq>,
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
            dedupe_device_key_id: None,
            replaced_seqs: Vec::new(),
            replaced_source_seqs: Vec::new(),
            compacted_source_seqs: Vec::new(),
            signers: Vec::new(),
        }
    }

    pub fn next(&self) -> Self {
        let mut next = self.clone();
        next.v = VERSION;
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
        if self.dedupe_device_key_id.as_deref() == Some(key_id) {
            self.dedupe_device_key_id = None;
        }
        before != self.signers.len()
    }

    pub fn mark_replaced(&mut self, seq: u64, source_id: SourceId, source_seq: u64) {
        if seq > self.compacted_through_seq {
            ranges_insert(&mut self.replaced_seqs, seq);
        }
        if source_seq <= self.compacted_source_seq(&source_id) {
            return;
        }
        let index = match self
            .replaced_source_seqs
            .binary_search_by(|entry| entry.source_id.cmp(&source_id))
        {
            Ok(index) => index,
            Err(index) => {
                self.replaced_source_seqs.insert(
                    index,
                    SourceSeqRanges {
                        source_id,
                        ranges: Vec::new(),
                    },
                );
                index
            }
        };
        ranges_insert(&mut self.replaced_source_seqs[index].ranges, source_seq);
    }

    pub fn compact_through(
        &mut self,
        seq: u64,
        source_seqs: impl IntoIterator<Item = (SourceId, u64)>,
    ) {
        self.compacted_through_seq = self.compacted_through_seq.max(seq);
        let compacted = self.compacted_through_seq;
        self.replaced_seqs.retain(|range| range.last > compacted);
        if let Some(range) = self.replaced_seqs.first_mut() {
            range.first = range.first.max(compacted.saturating_add(1));
        }
        let mut floors: std::collections::BTreeMap<SourceId, u64> = self
            .compacted_source_seqs
            .iter()
            .map(|entry| (entry.source_id, entry.seq))
            .collect();
        for (source_id, last) in source_seqs {
            let floor = floors.entry(source_id).or_insert(0);
            *floor = (*floor).max(last);
        }
        floors.retain(|_, seq| *seq > 0);
        for entry in &mut self.replaced_source_seqs {
            let floor = floors.get(&entry.source_id).copied().unwrap_or(0);
            entry.ranges.retain(|range| range.last > floor);
            if let Some(range) = entry.ranges.first_mut() {
                range.first = range.first.max(floor.saturating_add(1));
            }
        }
        self.replaced_source_seqs
            .retain(|entry| !entry.ranges.is_empty());
        self.compacted_source_seqs = floors
            .into_iter()
            .map(|(source_id, seq)| SourceSeq { source_id, seq })
            .collect();
    }

    pub fn compacted_source_seq(&self, source_id: &SourceId) -> u64 {
        self.compacted_source_seqs
            .binary_search_by(|entry| entry.source_id.cmp(source_id))
            .map(|index| self.compacted_source_seqs[index].seq)
            .unwrap_or(0)
    }

    fn replaced_source_ranges(&self, source_id: &SourceId) -> &[SeqRange] {
        self.replaced_source_seqs
            .binary_search_by(|entry| entry.source_id.cmp(source_id))
            .map(|index| self.replaced_source_seqs[index].ranges.as_slice())
            .unwrap_or(&[])
    }

    pub fn seq_is_replaced(&self, seq: u64) -> bool {
        ranges_contain(&self.replaced_seqs, seq)
    }

    pub fn source_seq_is_replaced(&self, source_id: &SourceId, source_seq: u64) -> bool {
        ranges_contain(self.replaced_source_ranges(source_id), source_seq)
    }

    pub fn source_has_replaced_seqs(&self, source_id: &SourceId) -> bool {
        !self.replaced_source_ranges(source_id).is_empty()
    }

    pub fn missing_seqs(&self, first: u64, last: u64) -> Vec<SeqRange> {
        ranges_missing(&self.replaced_seqs, first, last)
    }

    pub fn missing_source_seqs(
        &self,
        source_id: &SourceId,
        first: u64,
        last: u64,
    ) -> Vec<SeqRange> {
        let first = first.max(self.compacted_source_seq(source_id).saturating_add(1));
        if first > last {
            return Vec::new();
        }
        ranges_missing(self.replaced_source_ranges(source_id), first, last)
    }

    pub fn replaced_range_count(&self) -> usize {
        self.replaced_seqs.len()
            + self
                .replaced_source_seqs
                .iter()
                .map(|entry| entry.ranges.len())
                .sum::<usize>()
    }

    pub fn replaced_ranges_are_valid(&self) -> bool {
        ranges_are_valid(&self.replaced_seqs)
            && self
                .replaced_seqs
                .first()
                .is_none_or(|range| range.first > self.compacted_through_seq)
            && self
                .replaced_source_seqs
                .windows(2)
                .all(|pair| pair[0].source_id < pair[1].source_id)
            && self.replaced_source_seqs.iter().all(|entry| {
                !entry.ranges.is_empty()
                    && ranges_are_valid(&entry.ranges)
                    && entry.ranges[0].first > self.compacted_source_seq(&entry.source_id)
            })
            && self
                .compacted_source_seqs
                .windows(2)
                .all(|pair| pair[0].source_id < pair[1].source_id)
    }

    pub fn dedupe_device_is_valid(&self) -> bool {
        self.dedupe_device_key_id.as_ref().is_none_or(|key_id| {
            self.signers
                .iter()
                .any(|signer| signer.key_id == *key_id && signer.kind == SignerKind::Device)
        })
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
    if manifest.v != VERSION {
        return Err(Error::Invalid("manifest version"));
    }
    if manifest.vault_id != keys.vault_id() {
        return Err(Error::Mismatch("vault keys"));
    }
    if !manifest.retention.is_valid() {
        return Err(Error::Invalid("retention settings"));
    }
    if !manifest.dedupe_device_is_valid() {
        return Err(Error::Invalid("dedupe device"));
    }
    if !manifest.replaced_ranges_are_valid()
        || manifest.replaced_range_count() > MAX_REPLACED_RANGES
    {
        return Err(Error::Invalid("replaced chunk ranges"));
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
    if !(OLDEST_VERSION..=VERSION).contains(&manifest.v) {
        return Err(Error::Invalid("manifest version"));
    }
    if manifest.vault_id != vault_id || manifest.manifest_seq != server_seq {
        return Err(Error::Mismatch("manifest"));
    }
    if !manifest.dedupe_device_is_valid() {
        return Err(Error::Invalid("dedupe device"));
    }
    if !manifest.replaced_ranges_are_valid() {
        return Err(Error::Invalid("replaced chunk ranges"));
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
    fn replaced_chunks_are_listed_as_merged_ranges_and_explain_gaps() {
        let keys = keys();
        let source = SourceId::random().unwrap();
        let other = SourceId::random().unwrap();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        for (seq, source_seq) in [(7, 3), (5, 1), (6, 2), (12, 9), (7, 3)] {
            manifest.mark_replaced(seq, source, source_seq);
        }
        assert_eq!(
            manifest.replaced_seqs,
            [
                SeqRange { first: 5, last: 7 },
                SeqRange {
                    first: 12,
                    last: 12
                }
            ]
        );
        assert_eq!(manifest.replaced_range_count(), 4);
        assert!(manifest.seq_is_replaced(6) && !manifest.seq_is_replaced(8));
        assert_eq!(manifest.missing_seqs(5, 7), []);
        assert_eq!(
            manifest.missing_seqs(4, 13),
            [
                SeqRange { first: 4, last: 4 },
                SeqRange { first: 8, last: 11 },
                SeqRange {
                    first: 13,
                    last: 13
                }
            ]
        );
        assert_eq!(manifest.missing_source_seqs(&source, 1, 3), []);
        assert_eq!(
            manifest.missing_source_seqs(&source, 1, 9),
            [SeqRange { first: 4, last: 8 }]
        );
        assert_eq!(
            manifest.missing_source_seqs(&other, 2, 3),
            [SeqRange { first: 2, last: 3 }]
        );
        let blob = seal_manifest(&manifest, &keys).unwrap();
        assert_eq!(open_manifest(&blob, 1, &keys, None).unwrap(), manifest);
    }

    #[test]
    fn a_full_compaction_keeps_one_floor_per_source_and_later_replacements_apart() {
        let keys = keys();
        let source = SourceId::random().unwrap();
        let other = SourceId::random().unwrap();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        manifest.mark_replaced(5, source, 2);
        manifest.mark_replaced(30, source, 8);
        assert!(manifest.source_seq_is_replaced(&source, 2));
        manifest.compact_through(20, [(source, 6), (other, 4)]);
        assert_eq!(manifest.compacted_through_seq, 20);
        assert_eq!(
            manifest.replaced_seqs,
            [SeqRange {
                first: 30,
                last: 30
            }]
        );
        assert_eq!(manifest.compacted_source_seq(&source), 6);
        assert!(!manifest.source_seq_is_replaced(&source, 2));
        assert!(manifest.source_seq_is_replaced(&source, 8));
        assert!(manifest.source_has_replaced_seqs(&source));
        assert!(!manifest.source_has_replaced_seqs(&other));
        assert_eq!(
            manifest.missing_source_seqs(&source, 1, 8),
            [SeqRange { first: 7, last: 7 }]
        );
        assert_eq!(manifest.missing_source_seqs(&other, 1, 4), []);
        assert_eq!(
            manifest.missing_source_seqs(&other, 1, 5),
            [SeqRange { first: 5, last: 5 }]
        );
        manifest.mark_replaced(3, source, 4);
        assert_eq!(
            manifest.replaced_seqs,
            [SeqRange {
                first: 30,
                last: 30
            }]
        );
        assert!(!manifest.source_seq_is_replaced(&source, 4));
        manifest.compact_through(40, [(source, 5)]);
        assert_eq!(manifest.compacted_source_seq(&source), 6);
        assert!(manifest.replaced_seqs.is_empty());
        assert!(manifest.source_seq_is_replaced(&source, 8));
        let blob = seal_manifest(&manifest, &keys).unwrap();
        assert_eq!(open_manifest(&blob, 1, &keys, None).unwrap(), manifest);
    }

    #[test]
    fn rejects_unordered_or_oversized_replaced_ranges_and_reads_older_manifests() {
        let keys = keys();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        manifest.replaced_seqs = vec![
            SeqRange { first: 9, last: 9 },
            SeqRange { first: 4, last: 5 },
        ];
        assert_eq!(
            seal_manifest(&manifest, &keys),
            Err(Error::Invalid("replaced chunk ranges"))
        );
        manifest.replaced_seqs = (0..=MAX_REPLACED_RANGES as u64)
            .map(|index| SeqRange {
                first: index * 2 + 1,
                last: index * 2 + 1,
            })
            .collect();
        assert_eq!(
            seal_manifest(&manifest, &keys),
            Err(Error::Invalid("replaced chunk ranges"))
        );

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Older {
            v: u8,
            vault_id: VaultId,
            manifest_seq: u64,
            signers: Vec<SignerEntry>,
        }
        let header = framing::to_cbor(&Older {
            v: 2,
            vault_id: keys.vault_id(),
            manifest_seq: 1,
            signers: Vec::new(),
        })
        .unwrap();
        let blob = framing::seal_signed(
            DOMAIN,
            &binding(&keys.vault_id(), 1),
            &header,
            &[],
            Signing::Manifest(keys.manifest_signing()),
            &keys.public().vault_pk,
        )
        .unwrap();
        let opened = open_manifest(&blob, 1, &keys, None).unwrap();
        assert!(opened.replaced_seqs.is_empty() && opened.replaced_source_seqs.is_empty());
        assert!(opened.compacted_source_seqs.is_empty());
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
