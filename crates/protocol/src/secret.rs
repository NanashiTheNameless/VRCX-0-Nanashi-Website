use core::fmt;

use data_encoding::{BASE32_NOPAD, HEXLOWER_PERMISSIVE};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result, rand};

pub const SECRET_LEN: usize = 32;
const RECOVERY_PREFIX: &str = "rss1-";
const GROUP: usize = 4;

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SyncSecret([u8; SECRET_LEN]);

impl SyncSecret {
    pub fn generate() -> Result<Self> {
        Ok(Self(rand::bytes()?))
    }

    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    pub fn parse_own_key(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.to_ascii_lowercase().starts_with(RECOVERY_PREFIX) {
            return Self::from_recovery_string(trimmed);
        }
        let compact: Zeroizing<String> =
            Zeroizing::new(trimmed.chars().filter(|c| !c.is_whitespace()).collect());
        let decoded = Zeroizing::new(if compact.len() == 64 {
            HEXLOWER_PERMISSIVE
                .decode(compact.as_bytes())
                .map_err(|_| Error::Invalid("key"))?
        } else if compact.len() == 52 {
            BASE32_NOPAD
                .decode(compact.to_ascii_uppercase().as_bytes())
                .map_err(|_| Error::Invalid("key"))?
        } else {
            return Err(Error::Invalid("key length (must be exactly 256 bits)"));
        });
        let bytes: [u8; SECRET_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("key length (must be exactly 256 bits)"))?;
        Ok(Self(bytes))
    }

    pub fn to_recovery_string(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0_u8; SECRET_LEN + 4]);
        payload[..SECRET_LEN].copy_from_slice(&self.0);
        payload[SECRET_LEN..].copy_from_slice(&crc32fast::hash(&self.0).to_be_bytes());
        let encoded = Zeroizing::new(BASE32_NOPAD.encode(payload.as_slice()));
        let mut out = Zeroizing::new(String::with_capacity(80));
        out.push_str(RECOVERY_PREFIX);
        for (index, chunk) in encoded.as_bytes().chunks(GROUP).enumerate() {
            if index > 0 {
                out.push('-');
            }
            out.push_str(core::str::from_utf8(chunk).expect("base32 is ascii"));
        }
        out
    }

    pub fn from_recovery_string(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed
            .get(..RECOVERY_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(RECOVERY_PREFIX))
            .map(|_| &trimmed[RECOVERY_PREFIX.len()..])
            .ok_or(Error::Invalid("recovery string prefix"))?;
        let normalized: Zeroizing<String> = Zeroizing::new(
            body.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let decoded = Zeroizing::new(
            BASE32_NOPAD
                .decode(normalized.as_bytes())
                .map_err(|_| Error::Invalid("recovery string"))?,
        );
        if decoded.len() != SECRET_LEN + 4 {
            return Err(Error::Invalid("recovery string length"));
        }
        let (secret, checksum) = decoded.split_at(SECRET_LEN);
        if crc32fast::hash(secret).to_be_bytes() != checksum {
            return Err(Error::Checksum("recovery string"));
        }
        let mut bytes = [0_u8; SECRET_LEN];
        bytes.copy_from_slice(secret);
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SyncSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_string_round_trips() {
        let secret = SyncSecret::generate().unwrap();
        let text = secret.to_recovery_string();
        assert!(text.starts_with("rss1-"));
        assert_eq!(SyncSecret::from_recovery_string(&text).unwrap(), secret);
    }

    #[test]
    fn recovery_string_tolerates_case_and_spacing_only() {
        let secret = SyncSecret::from_bytes([0xAB; SECRET_LEN]);
        let text = secret.to_recovery_string();
        let messy = text.to_ascii_lowercase().replace('-', " ");
        let messy = format!("  RSS1-{}  ", &messy[5..]);
        assert_eq!(SyncSecret::from_recovery_string(&messy).unwrap(), secret);
        let body = &text[5..];
        let index = body
            .find('O')
            .or_else(|| body.find('I'))
            .expect("some O or I in the string");
        let swapped: String = body
            .char_indices()
            .map(|(i, c)| {
                if i == index {
                    if c == 'O' { '0' } else { '1' }
                } else {
                    c
                }
            })
            .collect();
        assert!(SyncSecret::from_recovery_string(&format!("rss1-{swapped}")).is_err());
    }

    #[test]
    fn recovery_string_detects_typos() {
        let secret = SyncSecret::from_bytes([3; SECRET_LEN]);
        let mut text = secret.to_recovery_string().to_string();
        let index = 7;
        let replacement = if &text[index..=index] == "A" {
            "C"
        } else {
            "A"
        };
        text.replace_range(index..=index, replacement);
        assert_eq!(
            SyncSecret::from_recovery_string(&text),
            Err(Error::Checksum("recovery string"))
        );
    }

    #[test]
    fn own_key_accepts_exactly_256_bits() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
        let secret = SyncSecret::parse_own_key(hex).unwrap();
        assert_eq!(secret.expose()[1], 0x11);
        let base32 = BASE32_NOPAD.encode(secret.expose());
        assert_eq!(SyncSecret::parse_own_key(&base32).unwrap(), secret);
        let recovery = secret.to_recovery_string();
        assert_eq!(SyncSecret::parse_own_key(&recovery).unwrap(), secret);
    }

    #[test]
    fn own_key_rejects_passwords_and_wrong_lengths() {
        assert!(SyncSecret::parse_own_key("correct horse battery staple").is_err());
        assert!(SyncSecret::parse_own_key(&"ab".repeat(31)).is_err());
        assert!(SyncSecret::parse_own_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let secret = SyncSecret::from_bytes([9; SECRET_LEN]);
        assert_eq!(format!("{secret:?}"), "SyncSecret(<redacted>)");
    }
}
