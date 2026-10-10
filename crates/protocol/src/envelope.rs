use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ids::AccountId;
use crate::keys::hkdf32;
use crate::secret::{SECRET_LEN, SyncSecret};
use crate::{Error, Result, rand};

pub const AAD_DOMAIN: &[u8] = b"remotesync/v1/envelope";
pub const INFO_KEK: &[u8] = b"remotesync/v1/envelope-kek";
pub const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;
pub const PRF_SALT_LEN: usize = 32;
pub const PRF_OUTPUT_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Argon2Cost {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Cost {
    pub const RECOMMENDED: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 1,
    };
    #[cfg(not(test))]
    pub const MINIMUM: Self = Self::RECOMMENDED;
    #[cfg(test)]
    pub const MINIMUM: Self = Self {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn check(&self) -> Result<()> {
        let min = Self::MINIMUM;
        if self.m_kib < min.m_kib || self.t < min.t || self.p < min.p {
            return Err(Error::WeakParameters);
        }
        if self.m_kib > 4 * 1024 * 1024 || self.t > 64 || self.p > 16 {
            return Err(Error::Invalid("argon2 parameters"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnvelopeLock {
    Passphrase {
        cost: Argon2Cost,
        #[serde(with = "crate::b64")]
        salt: Vec<u8>,
        generated: bool,
    },
    PasskeyPrf {
        #[serde(with = "crate::b64")]
        credential_id: Vec<u8>,
        #[serde(with = "crate::b64")]
        prf_salt: Vec<u8>,
    },
}

impl EnvelopeLock {
    fn kind(&self) -> &'static str {
        match self {
            Self::Passphrase { .. } => "passphrase",
            Self::PasskeyPrf { .. } => "passkey-prf",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEnvelope {
    pub v: u8,
    pub envelope_id: String,
    pub label: String,
    pub created_at_ms: i64,
    pub lock: EnvelopeLock,
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
}

fn aad(account_id: &AccountId, envelope_id: &str, kind: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [
        AAD_DOMAIN,
        account_id.as_str().as_bytes(),
        envelope_id.as_bytes(),
        kind.as_bytes(),
    ] {
        out.extend_from_slice(part);
        out.push(0);
    }
    out
}

fn new_envelope_id() -> Result<String> {
    Ok(crate::b64::encode(&rand::bytes::<16>()?))
}

fn encrypt(
    kek: &[u8; 32],
    secret: &SyncSecret,
    account_id: &AccountId,
    label: String,
    created_at_ms: i64,
    envelope_id: String,
    lock: EnvelopeLock,
) -> Result<KeyEnvelope> {
    let nonce: [u8; NONCE_LEN] = rand::bytes()?;
    let ciphertext = XChaCha20Poly1305::new(kek.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret.expose(),
                aad: &aad(account_id, &envelope_id, lock.kind()),
            },
        )
        .map_err(|_| Error::Encrypt)?;
    Ok(KeyEnvelope {
        v: VERSION,
        envelope_id,
        label,
        created_at_ms,
        lock,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

fn decrypt(kek: &[u8; 32], envelope: &KeyEnvelope, account_id: &AccountId) -> Result<SyncSecret> {
    if envelope.v != VERSION {
        return Err(Error::Invalid("envelope version"));
    }
    let nonce: [u8; NONCE_LEN] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("envelope"))?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(kek.into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad(account_id, &envelope.envelope_id, envelope.lock.kind()),
                },
            )
            .map_err(|_| Error::Decrypt)?,
    );
    let bytes: [u8; SECRET_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("envelope"))?;
    Ok(SyncSecret::from_bytes(bytes))
}

fn normalize_generated(passphrase: &str) -> Zeroizing<String> {
    Zeroizing::new(
        passphrase
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    )
}

fn stretch(passphrase: &[u8], salt: &[u8], cost: Argon2Cost) -> Result<Zeroizing<[u8; 32]>> {
    cost.check()?;
    let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32))
        .map_err(|_| Error::Invalid("argon2 parameters"))?;
    let mut out = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, out.as_mut_slice())
        .map_err(|_| Error::Invalid("argon2 input"))?;
    Ok(out)
}

pub fn generate_passphrase() -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(rand::bytes::<17>()?);
    let encoded = Zeroizing::new(BASE32_NOPAD.encode(bytes.as_slice()));
    let chars = &encoded[..26];
    let mut out = Zeroizing::new(String::with_capacity(32));
    for (index, group) in chars.as_bytes().chunks(5).enumerate() {
        if index > 0 {
            out.push('-');
        }
        out.push_str(core::str::from_utf8(group).expect("ascii"));
    }
    Ok(out)
}

pub fn seal_with_passphrase(
    secret: &SyncSecret,
    account_id: &AccountId,
    label: impl Into<String>,
    passphrase: &str,
    generated: bool,
    created_at_ms: i64,
) -> Result<KeyEnvelope> {
    seal_with_passphrase_cost(
        secret,
        account_id,
        label,
        passphrase,
        generated,
        created_at_ms,
        Argon2Cost::RECOMMENDED,
    )
}

fn seal_with_passphrase_cost(
    secret: &SyncSecret,
    account_id: &AccountId,
    label: impl Into<String>,
    passphrase: &str,
    generated: bool,
    created_at_ms: i64,
    cost: Argon2Cost,
) -> Result<KeyEnvelope> {
    if passphrase.is_empty() {
        return Err(Error::Invalid("passphrase"));
    }
    let salt: [u8; SALT_LEN] = rand::bytes()?;
    let input = if generated {
        normalize_generated(passphrase)
    } else {
        Zeroizing::new(passphrase.to_owned())
    };
    let stretched = stretch(input.as_bytes(), &salt, cost)?;
    let kek = hkdf32(&[], stretched.as_slice(), INFO_KEK);
    encrypt(
        &kek,
        secret,
        account_id,
        label.into(),
        created_at_ms,
        new_envelope_id()?,
        EnvelopeLock::Passphrase {
            cost,
            salt: salt.to_vec(),
            generated,
        },
    )
}

pub fn open_with_passphrase(
    envelope: &KeyEnvelope,
    account_id: &AccountId,
    passphrase: &str,
) -> Result<SyncSecret> {
    let EnvelopeLock::Passphrase {
        cost,
        salt,
        generated,
    } = &envelope.lock
    else {
        return Err(Error::Mismatch("envelope kind"));
    };
    if salt.len() != SALT_LEN {
        return Err(Error::Malformed("envelope"));
    }
    let input = if *generated {
        normalize_generated(passphrase)
    } else {
        Zeroizing::new(passphrase.to_owned())
    };
    let stretched = stretch(input.as_bytes(), salt, *cost)?;
    let kek = hkdf32(&[], stretched.as_slice(), INFO_KEK);
    decrypt(&kek, envelope, account_id)
}

pub fn new_prf_salt() -> Result<[u8; PRF_SALT_LEN]> {
    rand::bytes()
}

pub fn seal_with_prf(
    secret: &SyncSecret,
    account_id: &AccountId,
    label: impl Into<String>,
    credential_id: &[u8],
    prf_salt: &[u8; PRF_SALT_LEN],
    prf_output: &[u8; PRF_OUTPUT_LEN],
    created_at_ms: i64,
) -> Result<KeyEnvelope> {
    let kek = hkdf32(&[], prf_output, INFO_KEK);
    encrypt(
        &kek,
        secret,
        account_id,
        label.into(),
        created_at_ms,
        new_envelope_id()?,
        EnvelopeLock::PasskeyPrf {
            credential_id: credential_id.to_vec(),
            prf_salt: prf_salt.to_vec(),
        },
    )
}

pub fn open_with_prf(
    envelope: &KeyEnvelope,
    account_id: &AccountId,
    prf_output: &[u8; PRF_OUTPUT_LEN],
) -> Result<SyncSecret> {
    if !matches!(envelope.lock, EnvelopeLock::PasskeyPrf { .. }) {
        return Err(Error::Mismatch("envelope kind"));
    }
    let kek = hkdf32(&[], prf_output, INFO_KEK);
    decrypt(&kek, envelope, account_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Argon2Cost = Argon2Cost {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn new_account() -> AccountId {
        AccountId::random().unwrap()
    }

    #[test]
    fn recommended_cost_matches_spec() {
        assert_eq!(
            Argon2Cost::RECOMMENDED,
            Argon2Cost {
                m_kib: 262_144,
                t: 3,
                p: 1
            }
        );
    }

    #[test]
    fn chosen_passphrase_round_trip_and_wrong_passphrase() {
        let secret = SyncSecret::generate().unwrap();
        let account = new_account();
        let envelope = seal_with_passphrase_cost(
            &secret,
            &account,
            "laptop",
            "Hunter2 but Long!",
            false,
            0,
            FAST,
        )
        .unwrap();
        assert_eq!(
            open_with_passphrase(&envelope, &account, "Hunter2 but Long!").unwrap(),
            secret
        );
        assert_eq!(
            open_with_passphrase(&envelope, &account, "hunter2 but long!"),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open_with_passphrase(&envelope, &new_account(), "Hunter2 but Long!"),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn generated_passphrase_is_normalized() {
        let secret = SyncSecret::generate().unwrap();
        let account = new_account();
        let passphrase = generate_passphrase().unwrap();
        assert_eq!(passphrase.replace('-', "").len(), 26);
        let envelope =
            seal_with_passphrase_cost(&secret, &account, "gen", &passphrase, true, 0, FAST)
                .unwrap();
        let typed = passphrase.to_ascii_lowercase().replace('-', " ");
        assert_eq!(
            open_with_passphrase(&envelope, &account, &typed).unwrap(),
            secret
        );
    }

    #[test]
    fn refuses_downgraded_cost() {
        let secret = SyncSecret::generate().unwrap();
        let account = new_account();
        let mut envelope =
            seal_with_passphrase_cost(&secret, &account, "x", "passphrase", false, 0, FAST)
                .unwrap();
        if let EnvelopeLock::Passphrase { cost, .. } = &mut envelope.lock {
            cost.m_kib = 8;
        }
        assert_eq!(
            open_with_passphrase(&envelope, &account, "passphrase"),
            Err(Error::WeakParameters)
        );
    }

    #[test]
    fn prf_round_trip_and_kind_mismatch() {
        let secret = SyncSecret::generate().unwrap();
        let account = new_account();
        let salt = new_prf_salt().unwrap();
        let output = [9_u8; 32];
        let envelope =
            seal_with_prf(&secret, &account, "passkey", b"cred", &salt, &output, 0).unwrap();
        assert_eq!(open_with_prf(&envelope, &account, &output).unwrap(), secret);
        assert_eq!(
            open_with_prf(&envelope, &account, &[8; 32]),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open_with_passphrase(&envelope, &account, "x"),
            Err(Error::Mismatch("envelope kind"))
        );
    }

    #[test]
    fn tampering_with_metadata_breaks_decryption() {
        let secret = SyncSecret::generate().unwrap();
        let account = new_account();
        let output = [1_u8; 32];
        let mut envelope =
            seal_with_prf(&secret, &account, "p", b"c", &[2; 32], &output, 0).unwrap();
        envelope.envelope_id = "other".into();
        assert_eq!(
            open_with_prf(&envelope, &account, &output),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn json_uses_base64_strings() {
        let secret = SyncSecret::generate().unwrap();
        let envelope =
            seal_with_prf(&secret, &new_account(), "p", b"cred", &[2; 32], &[1; 32], 5).unwrap();
        let json = serde_json::to_value(&envelope).unwrap();
        assert!(json["ciphertext"].is_string());
        assert_eq!(json["lock"]["kind"], "passkey-prf");
        let back: KeyEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(back, envelope);
    }
}
