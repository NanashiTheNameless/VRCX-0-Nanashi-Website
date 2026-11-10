//! Public and password follow links.
//!
//! The app seals its own current location under a key that only exists in
//! the link fragment (and, for password links, in the password), so the
//! server stores and serves ciphertext it cannot read. For password links
//! the server additionally releases the ciphertext only to someone who shows
//! the auth value, so guessing a password means asking the rate-limited
//! server, unless someone holds both the link and the server's data.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::envelope::Argon2Cost;
use crate::keys::hkdf32;
use crate::{Error, Result, rand};

pub const VERSION: u8 = 1;
pub const LINK_KEY_LEN: usize = 32;
pub const AUTH_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
const AAD_DOMAIN: &[u8] = b"remotesync/v1/follow";
const HKDF_SALT: &[u8] = b"remotesync/v1/follow-salt";
const INFO_CONTENT: &[u8] = b"remotesync/v1/follow-content";
const INFO_AUTH: &[u8] = b"remotesync/v1/follow-auth";
/// Largest sealed location the server accepts.
pub const MAX_SEALED_LEN: usize = 2048;
pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_CHARS: usize = 256;

/// Lighter than the account envelope: viewers derive it in a browser,
/// often on a phone, and the link key is a second, random secret.
pub const PASSWORD_COST: Argon2Cost = Argon2Cost {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FollowState {
    Offline,
    /// The sharer is in an instance whose location works as a join ticket
    /// (invite and invite+); it is never published.
    Private,
    #[serde(rename_all = "camelCase")]
    Instance {
        world_id: String,
        instance_id: String,
        world_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FollowLocation {
    pub v: u8,
    pub state: FollowState,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordLock {
    pub cost: Argon2Cost,
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
}

impl PasswordLock {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            cost: PASSWORD_COST,
            salt: rand::bytes::<SALT_LEN>()?.to_vec(),
        })
    }

    pub fn check(&self) -> Result<()> {
        if self.salt.len() != SALT_LEN {
            return Err(Error::Invalid("follow password salt"));
        }
        if self.cost.m_kib < PASSWORD_COST.m_kib
            || self.cost.t < PASSWORD_COST.t
            || self.cost.p < PASSWORD_COST.p
        {
            return Err(Error::WeakParameters);
        }
        if self.cost.m_kib > 1024 * 1024 || self.cost.t > 16 || self.cost.p > 4 {
            return Err(Error::Invalid("follow password cost"));
        }
        Ok(())
    }
}

pub struct LinkKey(Zeroizing<[u8; LINK_KEY_LEN]>);

impl LinkKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(rand::bytes::<LINK_KEY_LEN>()?)))
    }

    pub fn to_fragment(&self) -> String {
        BASE64URL_NOPAD.encode(self.0.as_slice())
    }

    pub fn from_fragment(value: &str) -> Result<Self> {
        let bytes = BASE64URL_NOPAD
            .decode(value.trim().as_bytes())
            .map_err(|_| Error::Invalid("follow link key"))?;
        let key: [u8; LINK_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::Invalid("follow link key"))?;
        Ok(Self(Zeroizing::new(key)))
    }
}

pub struct FollowKeys {
    content: Zeroizing<[u8; 32]>,
    pub auth: Option<Zeroizing<[u8; AUTH_LEN]>>,
}

impl FollowKeys {
    /// The derived content key, so a viewer can derive once (the password
    /// stretch is slow) and open later updates with it.
    pub fn content_key(&self) -> &[u8; 32] {
        &self.content
    }

    pub fn from_content_key(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Invalid("follow content key"))?;
        Ok(Self {
            content: Zeroizing::new(key),
            auth: None,
        })
    }
}

/// Derives the content key, plus the auth value for password links. Both
/// mix in the link key, so the server's copy of the auth verifier cannot be
/// used to guess the password without the link.
pub fn derive_keys(
    link_key: &LinkKey,
    password: Option<(&str, &PasswordLock)>,
) -> Result<FollowKeys> {
    let Some((password, lock)) = password else {
        return Ok(FollowKeys {
            content: hkdf32(HKDF_SALT, link_key.0.as_slice(), INFO_CONTENT),
            auth: None,
        });
    };
    lock.check()?;
    let chars = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&chars) {
        return Err(Error::Invalid("follow password length"));
    }
    let params = Params::new(lock.cost.m_kib, lock.cost.t, lock.cost.p, Some(32))
        .map_err(|_| Error::Invalid("argon2 parameters"))?;
    let mut stretched = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &lock.salt, stretched.as_mut_slice())
        .map_err(|_| Error::Invalid("argon2"))?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(LINK_KEY_LEN + 32));
    ikm.extend_from_slice(link_key.0.as_slice());
    ikm.extend_from_slice(stretched.as_slice());
    Ok(FollowKeys {
        content: hkdf32(HKDF_SALT, &ikm, INFO_CONTENT),
        auth: Some(hkdf32(HKDF_SALT, &ikm, INFO_AUTH)),
    })
}

fn aad(code: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 1 + code.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(VERSION);
    aad.extend_from_slice(code.as_bytes());
    aad
}

/// Seals a location for one share code; it will not open under another code.
pub fn seal(keys: &FollowKeys, code: &str, location: &FollowLocation) -> Result<Vec<u8>> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(location).map_err(|_| Error::Invalid("follow location"))?,
    );
    let nonce = rand::bytes::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new((&*keys.content).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(code),
            },
        )
        .map_err(|_| Error::Invalid("follow seal"))?;
    let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    sealed.push(VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    if sealed.len() > MAX_SEALED_LEN {
        return Err(Error::Invalid("follow location too large"));
    }
    Ok(sealed)
}

pub fn open(keys: &FollowKeys, code: &str, sealed: &[u8]) -> Result<FollowLocation> {
    if sealed.len() <= 1 + NONCE_LEN || sealed.len() > MAX_SEALED_LEN || sealed[0] != VERSION {
        return Err(Error::Invalid("follow sealed location"));
    }
    let nonce: [u8; NONCE_LEN] = sealed[1..1 + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::Invalid("follow sealed location"))?;
    let cipher = XChaCha20Poly1305::new((&*keys.content).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &sealed[1 + NONCE_LEN..],
                    aad: &aad(code),
                },
            )
            .map_err(|_| Error::Invalid("follow sealed location"))?,
    );
    let location: FollowLocation =
        serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid("follow location"))?;
    if location.v != VERSION {
        return Err(Error::Invalid("follow location version"));
    }
    Ok(location)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap_lock() -> PasswordLock {
        PasswordLock {
            cost: PASSWORD_COST,
            salt: vec![7; SALT_LEN],
        }
    }

    fn location() -> FollowLocation {
        FollowLocation {
            v: VERSION,
            state: FollowState::Instance {
                world_id: "wrld_x".into(),
                instance_id: "1~region(eu)".into(),
                world_name: "World".into(),
            },
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn public_links_round_trip_and_bind_to_their_code() {
        let link = LinkKey::generate().unwrap();
        let keys = derive_keys(&link, None).unwrap();
        assert!(keys.auth.is_none());
        let sealed = seal(&keys, "ABCD1234", &location()).unwrap();
        assert_eq!(open(&keys, "ABCD1234", &sealed).unwrap(), location());
        assert!(open(&keys, "OTHER123", &sealed).is_err());

        let restored = LinkKey::from_fragment(&link.to_fragment()).unwrap();
        let keys = derive_keys(&restored, None).unwrap();
        assert_eq!(open(&keys, "ABCD1234", &sealed).unwrap(), location());

        let other = derive_keys(&LinkKey::generate().unwrap(), None).unwrap();
        assert!(open(&other, "ABCD1234", &sealed).is_err());
    }

    #[test]
    fn password_links_need_both_the_link_and_the_password() {
        let link = LinkKey::generate().unwrap();
        let lock = cheap_lock();
        let keys = derive_keys(&link, Some(("correct horse", &lock))).unwrap();
        let sealed = seal(&keys, "ABCD1234", &location()).unwrap();

        let same = derive_keys(&link, Some(("correct horse", &lock))).unwrap();
        assert_eq!(open(&same, "ABCD1234", &sealed).unwrap(), location());
        assert_eq!(same.auth.as_deref(), keys.auth.as_deref());

        let wrong = derive_keys(&link, Some(("wrong horse", &lock))).unwrap();
        assert!(open(&wrong, "ABCD1234", &sealed).is_err());
        assert_ne!(wrong.auth.as_deref(), keys.auth.as_deref());

        let other_link = derive_keys(
            &LinkKey::generate().unwrap(),
            Some(("correct horse", &lock)),
        )
        .unwrap();
        assert!(open(&other_link, "ABCD1234", &sealed).is_err());
        assert_ne!(other_link.auth.as_deref(), keys.auth.as_deref());

        assert!(open(&derive_keys(&link, None).unwrap(), "ABCD1234", &sealed).is_err());
    }

    #[test]
    fn rejects_short_passwords_weak_locks_and_bad_link_keys() {
        let link = LinkKey::generate().unwrap();
        assert!(derive_keys(&link, Some(("short", &cheap_lock()))).is_err());
        let weak = PasswordLock {
            cost: Argon2Cost {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
            salt: vec![1; SALT_LEN],
        };
        assert!(derive_keys(&link, Some(("long enough", &weak))).is_err());
        assert!(LinkKey::from_fragment("not-a-key").is_err());
        assert!(PasswordLock::generate().unwrap().check().is_ok());
    }

    #[test]
    fn private_and_offline_states_serialize_without_a_location() {
        for state in [FollowState::Offline, FollowState::Private] {
            let text = serde_json::to_string(&FollowLocation {
                v: VERSION,
                state,
                updated_at: 1,
            })
            .unwrap();
            assert!(!text.contains("wrld_"));
        }
    }
}
