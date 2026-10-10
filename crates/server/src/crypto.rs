use std::path::Path;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::HEXLOWER_PERMISSIVE;
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::Sha256;
use vrcx_0_nanashi_website_protocol::keys::hkdf32;
use zeroize::Zeroizing;

use crate::util::random_bytes;

pub const INFO_REGISTRY: &[u8] = b"remotesync/v1/registry";
pub const INFO_KWK: &[u8] = b"remotesync/v1/kwk";
pub const INFO_PEPPER: &[u8] = b"remotesync/v1/pepper";
const WRAP_AAD_DOMAIN: &[u8] = b"remotesync/v1/adk-wrap";
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("cannot read master key file: {0}")]
    Read(std::io::Error),
    #[error("master key must be 64 hex characters (32 bytes)")]
    Format,
    #[error("wrapped account key is invalid")]
    Unwrap,
}

pub struct ServerKeys {
    registry: Zeroizing<[u8; 32]>,
    kwk: Zeroizing<[u8; 32]>,
    pepper: Zeroizing<[u8; 32]>,
}

impl ServerKeys {
    pub fn from_master(master: &[u8; 32]) -> Self {
        Self {
            registry: hkdf32(&[], master, INFO_REGISTRY),
            kwk: hkdf32(&[], master, INFO_KWK),
            pepper: hkdf32(&[], master, INFO_PEPPER),
        }
    }

    pub fn load(path: &Path) -> Result<Self, KeyError> {
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(KeyError::Read)?);
        let decoded = Zeroizing::new(
            HEXLOWER_PERMISSIVE
                .decode(text.trim().as_bytes())
                .map_err(|_| KeyError::Format)?,
        );
        let master: Zeroizing<[u8; 32]> = Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| KeyError::Format)?,
        );
        Ok(Self::from_master(&master))
    }

    pub fn registry_key(&self) -> &[u8; 32] {
        &self.registry
    }

    pub fn hmac(&self, purpose: &str, data: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.pepper.as_slice()).expect("any key length");
        mac.update(purpose.as_bytes());
        mac.update(&[0]);
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.kwk).into())
    }

    fn aad(context: &str) -> Vec<u8> {
        [WRAP_AAD_DOMAIN, &[0], context.as_bytes()].concat()
    }

    pub fn wrap(&self, context: &str, secret: &[u8]) -> Vec<u8> {
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &Self::aad(context),
                },
            )
            .expect("XChaCha20Poly1305 encryption cannot fail for small inputs");
        [nonce.as_slice(), &ciphertext].concat()
    }

    pub fn unwrap(&self, context: &str, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if wrapped.len() < NONCE_LEN {
            return Err(KeyError::Unwrap);
        }
        let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyError::Unwrap)?;
        self.cipher()
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &Self::aad(context),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| KeyError::Unwrap)
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_round_trip_bound_to_context() {
        let keys = ServerKeys::from_master(&[1; 32]);
        let wrapped = keys.wrap("acc_a", b"secret");
        assert_eq!(
            keys.unwrap("acc_a", &wrapped).unwrap().as_slice(),
            b"secret"
        );
        assert!(keys.unwrap("acc_b", &wrapped).is_err());
        assert!(
            ServerKeys::from_master(&[2; 32])
                .unwrap("acc_a", &wrapped)
                .is_err()
        );
    }

    #[test]
    fn hmac_depends_on_purpose_and_key() {
        let keys = ServerKeys::from_master(&[1; 32]);
        assert_ne!(keys.hmac("token", b"x"), keys.hmac("code", b"x"));
        assert_ne!(
            keys.hmac("token", b"x"),
            ServerKeys::from_master(&[2; 32]).hmac("token", b"x")
        );
    }

    #[test]
    fn load_master_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        let keys = ServerKeys::load(&path).unwrap();
        assert_eq!(
            keys.registry_key(),
            ServerKeys::from_master(&[0xab; 32]).registry_key()
        );
        std::fs::write(&path, "short").unwrap();
        assert!(matches!(ServerKeys::load(&path), Err(KeyError::Format)));
    }
}
