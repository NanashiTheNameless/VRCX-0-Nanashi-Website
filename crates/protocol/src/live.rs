use serde::{Deserialize, Serialize};

use crate::chunk::SignerLookup;
use crate::framing::{self, Signing};
use crate::ids::VaultId;
use crate::keys::{SignerKey, VaultKeys};
use crate::seal::SealPublicKey;
use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"remotesync/v1/live";
pub const VERSION: u8 = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveSelf {
    pub status: String,
    pub status_description: String,
    pub location: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ciborium::Value")]
pub struct LiveFriend {
    pub user_id: String,
    pub display_name: String,
    pub status: String,
    pub status_description: String,
    pub location: String,
    pub platform: String,
    pub last_seen_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveInstance {
    pub location: String,
    pub occupants: Vec<String>,
    #[serde(default)]
    pub capacity: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ciborium::Value")]
pub struct LiveSnapshot {
    pub v: u8,
    pub vault_id: VaultId,
    pub live_seq: u64,
    pub created_at: i64,
    pub signer_key_id: String,
    pub own: LiveSelf,
    pub friends: Vec<LiveFriend>,
    pub instances: Vec<LiveInstance>,
}

fn binding(vault_id: &VaultId, live_seq: u64) -> Vec<u8> {
    [vault_id.as_bytes().as_slice(), &live_seq.to_be_bytes()].concat()
}

pub fn seal_live(
    snapshot: &LiveSnapshot,
    signer: &SignerKey,
    vault_pk: &SealPublicKey,
) -> Result<Vec<u8>> {
    if snapshot.v != VERSION {
        return Err(Error::Invalid("live snapshot version"));
    }
    if snapshot.signer_key_id != signer.key_id() {
        return Err(Error::Mismatch("signer key id"));
    }
    let body = framing::compress(&framing::to_cbor(snapshot)?);
    framing::seal_signed(
        DOMAIN,
        &binding(&snapshot.vault_id, snapshot.live_seq),
        &[],
        &body,
        Signing::Signer(signer),
        vault_pk,
    )
}

pub fn open_live(
    blob: &[u8],
    live_seq: u64,
    keys: &VaultKeys,
    signers: &impl SignerLookup,
) -> Result<LiveSnapshot> {
    let vault_id = keys.vault_id();
    let unverified = framing::open_signed(
        DOMAIN,
        binding(&vault_id, live_seq),
        keys.seal_private(),
        blob,
    )?;
    let body_bytes = unverified.body_for_peek().to_vec();
    let claimed: LiveSnapshot =
        framing::from_cbor(&framing::decompress(&body_bytes)?, "live snapshot")?;
    let public = signers
        .signer(&claimed.signer_key_id, claimed.created_at)
        .ok_or(Error::UnknownSigner)?;
    let (_, body) = unverified.verify(&public)?;
    let snapshot: LiveSnapshot = framing::from_cbor(&framing::decompress(&body)?, "live snapshot")?;
    if !(1..=VERSION).contains(&snapshot.v) {
        return Err(Error::Invalid("live snapshot version"));
    }
    if snapshot.vault_id != vault_id || snapshot.live_seq != live_seq {
        return Err(Error::Mismatch("live snapshot"));
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Manifest, SignerEntry, SignerKind};
    use crate::secret::SyncSecret;

    #[test]
    fn round_trip_with_manifest_lookup() {
        let keys = VaultKeys::derive(&SyncSecret::generate().unwrap(), VaultId::random().unwrap());
        let collector = SignerKey::generate().unwrap();
        let mut manifest = Manifest::new(keys.vault_id(), None);
        manifest.add_signer(SignerEntry::new(
            &collector.public(),
            SignerKind::Collector,
            "collector",
            0,
        ));
        let snapshot = LiveSnapshot {
            v: VERSION,
            vault_id: keys.vault_id(),
            live_seq: 4,
            created_at: 1000,
            signer_key_id: collector.key_id(),
            own: LiveSelf::default(),
            friends: vec![LiveFriend {
                user_id: "usr_1".into(),
                display_name: "friend".into(),
                status: "active".into(),
                status_description: String::new(),
                location: "wrld_1:1".into(),
                platform: "standalonewindows".into(),
                last_seen_at: 1000,
            }],
            instances: vec![],
        };
        let blob = seal_live(&snapshot, &collector, &keys.public().vault_pk).unwrap();
        assert_eq!(open_live(&blob, 4, &keys, &manifest).unwrap(), snapshot);
        let mut legacy = snapshot.clone();
        legacy.v = 1;
        let body =
            framing::compress(&framing::to_cbor(&crate::time::legacy_value(&legacy)).unwrap());
        let legacy_blob = framing::seal_signed(
            DOMAIN,
            &binding(&keys.vault_id(), legacy.live_seq),
            &[],
            &body,
            Signing::Signer(&collector),
            &keys.public().vault_pk,
        )
        .unwrap();
        assert_eq!(
            open_live(&legacy_blob, 4, &keys, &manifest).unwrap(),
            legacy
        );

        assert_eq!(open_live(&blob, 5, &keys, &manifest), Err(Error::Decrypt));
        let empty = Manifest::new(keys.vault_id(), None);
        assert_eq!(
            open_live(&blob, 4, &keys, &empty),
            Err(Error::UnknownSigner)
        );
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveFriendEpochFields {
    pub user_id: String,
    pub display_name: String,
    pub status: String,
    pub status_description: String,
    pub location: String,
    pub platform: String,
    pub last_seen_at: i64,
}

impl TryFrom<ciborium::Value> for LiveFriend {
    type Error = String;
    fn try_from(mut value: ciborium::Value) -> core::result::Result<Self, Self::Error> {
        crate::time::convert_legacy_fields(&mut value, &[("lastSeenAtMs", "lastSeenAt")])?;
        let LiveFriendEpochFields {
            user_id,
            display_name,
            status,
            status_description,
            location,
            platform,
            last_seen_at,
        } = value.deserialized().map_err(|error| error.to_string())?;
        Ok(Self {
            user_id,
            display_name,
            status,
            status_description,
            location,
            platform,
            last_seen_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveSnapshotEpochFields {
    pub v: u8,
    pub vault_id: VaultId,
    pub live_seq: u64,
    pub created_at: i64,
    pub signer_key_id: String,
    pub own: LiveSelf,
    pub friends: Vec<LiveFriend>,
    pub instances: Vec<LiveInstance>,
}

impl TryFrom<ciborium::Value> for LiveSnapshot {
    type Error = String;
    fn try_from(mut value: ciborium::Value) -> core::result::Result<Self, Self::Error> {
        crate::time::convert_legacy_fields(&mut value, &[("createdAtMs", "createdAt")])?;
        let LiveSnapshotEpochFields {
            v,
            vault_id,
            live_seq,
            created_at,
            signer_key_id,
            own,
            friends,
            instances,
        } = value.deserialized().map_err(|error| error.to_string())?;
        Ok(Self {
            v,
            vault_id,
            live_seq,
            created_at,
            signer_key_id,
            own,
            friends,
            instances,
        })
    }
}
