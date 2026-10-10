use core::fmt;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ids::VaultId;
use crate::seal::{SealPrivateKey, SealPublicKey};
use crate::secret::SyncSecret;
use crate::{Error, Result, rand};

pub const INFO_VAULT: &[u8] = b"remotesync/v1/vault";
pub const INFO_VAULT_KEM: &[u8] = b"remotesync/v1/vault-kem";
pub const INFO_VAULT_SIGN: &[u8] = b"remotesync/v1/vault-sign";

pub fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct VaultSecret([u8; 32]);

pub struct VaultKeys {
    vault_id: VaultId,
    seal: SealPrivateKey,
    manifest: SigningKey,
}

impl VaultKeys {
    pub fn derive(secret: &SyncSecret, vault_id: VaultId) -> Self {
        let vault = VaultSecret(*hkdf32(vault_id.as_bytes(), secret.expose(), INFO_VAULT));
        let kem_ikm = hkdf32(&[], &vault.0, INFO_VAULT_KEM);
        let sign_seed = hkdf32(&[], &vault.0, INFO_VAULT_SIGN);
        Self {
            vault_id,
            seal: SealPrivateKey::derive(kem_ikm.as_slice()),
            manifest: SigningKey::from_bytes(&sign_seed),
        }
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn seal_private(&self) -> &SealPrivateKey {
        &self.seal
    }

    pub fn manifest_signing(&self) -> &SigningKey {
        &self.manifest
    }

    pub fn public(&self) -> VaultPublicKeys {
        VaultPublicKeys {
            vault_pk: self.seal.public(),
            manifest_pk: self.manifest.verifying_key(),
        }
    }
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultKeys({}, <redacted>)", self.vault_id)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VaultPublicKeys {
    pub vault_pk: SealPublicKey,
    pub manifest_pk: VerifyingKey,
}

pub fn key_id(public: &VerifyingKey) -> String {
    let digest = Sha256::digest(public.as_bytes());
    BASE64URL_NOPAD.encode(&digest[..12])
}

pub struct SignerKey(SigningKey);

impl SignerKey {
    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(rand::bytes::<32>()?);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }
}

impl fmt::Debug for SignerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignerKey({}, <redacted>)", self.key_id())
    }
}

pub fn verify(public: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::Signature)?;
    public
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::Signature)
}

pub fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::Invalid("public key"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Invalid("public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_keys_are_deterministic_per_secret_and_vault() {
        let secret = SyncSecret::from_bytes([1; 32]);
        let vault = VaultId::from_bytes([2; 16]);
        assert_eq!(
            VaultKeys::derive(&secret, vault).public(),
            VaultKeys::derive(&secret, vault).public()
        );
        let other_vault = VaultId::from_bytes([3; 16]);
        assert_ne!(
            VaultKeys::derive(&secret, vault).public(),
            VaultKeys::derive(&secret, other_vault).public()
        );
        let other_secret = SyncSecret::from_bytes([4; 32]);
        assert_ne!(
            VaultKeys::derive(&secret, vault).public(),
            VaultKeys::derive(&other_secret, vault).public()
        );
    }

    #[test]
    fn signatures_verify_only_for_the_right_key_and_message() {
        let key = SignerKey::generate().unwrap();
        let signature = key.sign(b"message").to_bytes();
        assert!(verify(&key.public(), b"message", &signature).is_ok());
        assert!(verify(&key.public(), b"other", &signature).is_err());
        let other = SignerKey::generate().unwrap();
        assert!(verify(&other.public(), b"message", &signature).is_err());
        assert!(verify(&key.public(), b"message", &signature[..63]).is_err());
    }

    #[test]
    fn key_id_is_stable_and_short() {
        let key = SignerKey::from_seed(&[5; 32]);
        assert_eq!(key.key_id().len(), 16);
        assert_eq!(
            key.key_id(),
            key_id(&SignerKey::from_seed(&[5; 32]).public())
        );
    }
}
