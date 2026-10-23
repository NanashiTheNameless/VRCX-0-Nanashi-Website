use serde::{Deserialize, Serialize};

pub const KEY_VERSION: &str = "v1";
const HEX_LEN: usize = 32;

fn is_hex(part: &str) -> bool {
    part.len() == HEX_LEN
        && part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_object_key(key: &str) -> bool {
    let mut parts = key.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(KEY_VERSION), Some(prefix), Some(id), None) if is_hex(prefix) && is_hex(id)
    )
}

pub fn is_prefix(prefix: &str) -> bool {
    prefix
        .strip_prefix("v1/")
        .and_then(|rest| rest.strip_suffix('/'))
        .is_some_and(is_hex)
}

pub fn object_key(prefix_hex: &str, object_id_hex: &str) -> String {
    format!("{KEY_VERSION}/{prefix_hex}/{object_id_hex}")
}

pub fn prefix(prefix_hex: &str) -> String {
    format!("{KEY_VERSION}/{prefix_hex}/")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "ciborium::Value")]
pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub last_modified: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub objects: Vec<ListEntry>,
    pub next: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePrefixRequest {
    pub prefix: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePrefixResponse {
    pub deleted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub backend: String,
    pub ok: bool,
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        let p = "0123456789abcdef0123456789abcdef";
        let id = "fedcba9876543210fedcba9876543210";
        assert!(is_object_key(&object_key(p, id)));
        assert!(is_prefix(&prefix(p)));
        assert!(!is_object_key(&format!("v1/{p}/../{id}")));
        assert!(!is_object_key(&format!("v1/{p}/{id}/x")));
        assert!(!is_object_key(&format!("v2/{p}/{id}")));
        assert!(!is_object_key(&format!("v1/{}/{id}", p.to_uppercase())));
        assert!(!is_prefix("v1/"));
        assert!(!is_prefix(&format!("v1/{p}")));
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListEntryEpochFields {
    pub key: String,
    pub size: u64,
    pub last_modified: i64,
}

impl TryFrom<ciborium::Value> for ListEntry {
    type Error = String;
    fn try_from(mut value: ciborium::Value) -> core::result::Result<Self, Self::Error> {
        crate::time::convert_legacy_fields(&mut value, &[("lastModifiedMs", "lastModified")])?;
        let ListEntryEpochFields {
            key,
            size,
            last_modified,
        } = value.deserialized().map_err(|error| error.to_string())?;
        Ok(Self {
            key,
            size,
            last_modified,
        })
    }
}
