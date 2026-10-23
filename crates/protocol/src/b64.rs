use data_encoding::BASE64URL_NOPAD;
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&BASE64URL_NOPAD.encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> serde::de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("base64url text or a byte string")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            BASE64URL_NOPAD.decode(value.as_bytes()).map_err(E::custom)
        }

        fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(value)
        }
    }
    deserializer.deserialize_any(Bytes)
}

pub fn encode(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn decode(text: &str) -> crate::Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(text.as_bytes())
        .map_err(|_| crate::Error::Invalid("base64url"))
}
