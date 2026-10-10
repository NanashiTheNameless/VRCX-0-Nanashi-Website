use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&BASE64URL_NOPAD.encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        let text = String::deserialize(deserializer)?;
        BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    } else {
        Ok(serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec())
    }
}

pub fn encode(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn decode(text: &str) -> crate::Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(text.as_bytes())
        .map_err(|_| crate::Error::Invalid("base64url"))
}
