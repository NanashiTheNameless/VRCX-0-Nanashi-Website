use core::fmt;
use core::str::FromStr;

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result, rand};

pub const ID_LEN: usize = 16;

macro_rules! random_id {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            pub fn random() -> Result<Self> {
                Ok(Self(rand::bytes()?))
            }

            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&BASE64URL_NOPAD.encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                let bytes = BASE64URL_NOPAD
                    .decode(value.as_bytes())
                    .map_err(|_| Error::Invalid($what))?;
                let bytes: [u8; ID_LEN] = bytes.try_into().map_err(|_| Error::Invalid($what))?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

random_id!(VaultId, "vault id");
random_id!(ChunkId, "chunk id");
random_id!(SourceId, "source id");

const ACCOUNT_PREFIX: &str = "acc_";

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId(String);

impl AccountId {
    pub fn random() -> Result<Self> {
        let bytes: [u8; ID_LEN] = rand::bytes()?;
        Ok(Self(format!(
            "{ACCOUNT_PREFIX}{}",
            BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", self.0)
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let body = value
            .strip_prefix(ACCOUNT_PREFIX)
            .ok_or(Error::Invalid("account id"))?;
        let decoded = BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::Invalid("account id"))?;
        if decoded.len() != ID_LEN || body.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(Error::Invalid("account id"));
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for AccountId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<AccountId> for String {
    fn from(value: AccountId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_id_round_trips_as_22_chars() {
        let id = VaultId::random().unwrap();
        let text = id.to_string();
        assert_eq!(text.len(), 22);
        assert_eq!(text.parse::<VaultId>().unwrap(), id);
    }

    #[test]
    fn ids_reject_wrong_length_and_alphabet() {
        assert!("abc".parse::<ChunkId>().is_err());
        assert!("++++++++++++++++++++++".parse::<ChunkId>().is_err());
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(SourceId::random().unwrap(), SourceId::random().unwrap());
    }

    #[test]
    fn account_id_format() {
        let id = AccountId::random().unwrap();
        assert!(id.as_str().starts_with("acc_"));
        assert_eq!(id.as_str().len(), 4 + 26);
        assert_eq!(id.as_str().parse::<AccountId>().unwrap(), id);
        assert!("acc_ABC".parse::<AccountId>().is_err());
        assert!(
            id.as_str()
                .to_ascii_uppercase()
                .replace("ACC_", "acc_")
                .parse::<AccountId>()
                .is_err()
        );
        assert!("usr_aaaa".parse::<AccountId>().is_err());
    }

    #[test]
    fn ids_serialize_as_strings() {
        let id = VaultId::from_bytes([7; ID_LEN]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<VaultId>(&json).unwrap(), id);
    }
}
