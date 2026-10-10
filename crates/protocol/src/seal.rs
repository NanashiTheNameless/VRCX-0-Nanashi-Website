use core::fmt;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

use crate::{Error, Result};

type Kem = X25519HkdfSha256;
pub const ENC_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const OVERHEAD: usize = ENC_LEN + TAG_LEN;

#[derive(Clone, PartialEq, Eq)]
pub struct SealPublicKey([u8; 32]);

impl SealPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let parsed = <Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map_err(|_| Error::Invalid("public key"))?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(&parsed.to_bytes());
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn hpke(&self) -> <Kem as hpke::Kem>::PublicKey {
        <Kem as hpke::Kem>::PublicKey::from_bytes(&self.0).expect("validated on construction")
    }
}

impl fmt::Debug for SealPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SealPublicKey({})",
            data_encoding::BASE64URL_NOPAD.encode(&self.0)
        )
    }
}

pub struct SealPrivateKey(<Kem as hpke::Kem>::PrivateKey);

impl SealPrivateKey {
    pub fn derive(ikm: &[u8]) -> Self {
        Self(Kem::derive_keypair(ikm).0)
    }

    pub fn generate() -> Self {
        Self(Kem::gen_keypair().0)
    }

    pub fn public(&self) -> SealPublicKey {
        let public = <Kem as hpke::Kem>::sk_to_pk(&self.0);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&public.to_bytes());
        SealPublicKey(out)
    }
}

impl fmt::Debug for SealPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealPrivateKey(<redacted>)")
    }
}

pub fn seal(
    recipient: &SealPublicKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient.hpke(),
        info,
        plaintext,
        aad,
    )
    .map_err(|_| Error::Encrypt)?;
    let mut out = Vec::with_capacity(ENC_LEN + ciphertext.len());
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(recipient: &SealPrivateKey, info: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return Err(Error::Decrypt);
    }
    let (enc, ciphertext) = sealed.split_at(ENC_LEN);
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::Decrypt)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &recipient.0,
        &enc,
        info,
        ciphertext,
        aad,
    )
    .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip() {
        let key = SealPrivateKey::generate();
        let blob = seal(&key.public(), b"info", b"aad", b"hello").unwrap();
        assert_eq!(blob.len(), 5 + OVERHEAD);
        assert_eq!(open(&key, b"info", b"aad", &blob).unwrap(), b"hello");
    }

    #[test]
    fn open_fails_on_any_context_change() {
        let key = SealPrivateKey::generate();
        let blob = seal(&key.public(), b"info", b"aad", b"hello").unwrap();
        assert_eq!(open(&key, b"other", b"aad", &blob), Err(Error::Decrypt));
        assert_eq!(open(&key, b"info", b"other", &blob), Err(Error::Decrypt));
        assert_eq!(
            open(&SealPrivateKey::generate(), b"info", b"aad", &blob),
            Err(Error::Decrypt)
        );
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, b"info", b"aad", &tampered), Err(Error::Decrypt));
        assert_eq!(
            open(&key, b"info", b"aad", &blob[..10]),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn derived_keys_are_deterministic() {
        assert_eq!(
            SealPrivateKey::derive(&[1; 32]).public(),
            SealPrivateKey::derive(&[1; 32]).public()
        );
        assert_ne!(
            SealPrivateKey::derive(&[1; 32]).public(),
            SealPrivateKey::derive(&[2; 32]).public()
        );
    }

    #[test]
    fn public_key_parsing() {
        let key = SealPrivateKey::generate().public();
        assert_eq!(SealPublicKey::from_bytes(key.as_bytes()).unwrap(), key);
        assert!(SealPublicKey::from_bytes(&[0; 31]).is_err());
    }
}
