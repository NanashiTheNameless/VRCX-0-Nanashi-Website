use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

use crate::ids::AccountId;
use crate::seal::{self, SealPrivateKey, SealPublicKey};
use crate::secret::{SECRET_LEN, SyncSecret};
use crate::{Error, Result, rand};

pub const DOMAIN: &[u8] = b"remotesync/v1/transfer";
pub const FINGERPRINT_LEN: usize = 10;
const TRANSFER_ID_BYTES: usize = 5;
const TRANSFER_ID_CHARS: usize = 8;
const FINGERPRINT_CHARS: usize = 16;

pub fn new_transfer_id() -> Result<String> {
    Ok(BASE32_NOPAD.encode(&rand::bytes::<TRANSFER_ID_BYTES>()?))
}

pub fn validate_transfer_id(id: &str) -> Result<()> {
    let ok = id.len() == TRANSFER_ID_CHARS
        && BASE32_NOPAD
            .decode(id.as_bytes())
            .is_ok_and(|bytes| bytes.len() == TRANSFER_ID_BYTES);
    ok.then_some(()).ok_or(Error::Invalid("transfer id"))
}

pub fn fingerprint(epk: &SealPublicKey) -> [u8; FINGERPRINT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(epk.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0_u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest[..FINGERPRINT_LEN]);
    out
}

pub fn display_code(transfer_id: &str, epk: &SealPublicKey) -> Result<String> {
    validate_transfer_id(transfer_id)?;
    let text = format!("{transfer_id}{}", BASE32_NOPAD.encode(&fingerprint(epk)));
    Ok(text
        .as_bytes()
        .chunks(4)
        .map(|group| core::str::from_utf8(group).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-"))
}

pub fn parse_code(code: &str) -> Result<(String, [u8; FINGERPRINT_LEN])> {
    let compact: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() != TRANSFER_ID_CHARS + FINGERPRINT_CHARS {
        return Err(Error::Invalid("transfer code"));
    }
    let (id, fp) = compact.split_at(TRANSFER_ID_CHARS);
    validate_transfer_id(id)?;
    let fp = BASE32_NOPAD
        .decode(fp.as_bytes())
        .map_err(|_| Error::Invalid("transfer code"))?;
    let fp: [u8; FINGERPRINT_LEN] = fp.try_into().map_err(|_| Error::Invalid("transfer code"))?;
    Ok((id.to_owned(), fp))
}

pub fn verify_epk(epk: &SealPublicKey, expected: &[u8; FINGERPRINT_LEN]) -> Result<()> {
    let actual = fingerprint(epk);
    let diff = actual
        .iter()
        .zip(expected)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
    (diff == 0)
        .then_some(())
        .ok_or(Error::Mismatch("transfer fingerprint"))
}

fn aad(account_id: &AccountId, transfer_id: &str) -> Vec<u8> {
    [account_id.as_str().as_bytes(), &[0], transfer_id.as_bytes()].concat()
}

pub fn seal_secret(
    epk: &SealPublicKey,
    expected_fingerprint: &[u8; FINGERPRINT_LEN],
    account_id: &AccountId,
    transfer_id: &str,
    secret: &SyncSecret,
) -> Result<Vec<u8>> {
    verify_epk(epk, expected_fingerprint)?;
    seal::seal(epk, DOMAIN, &aad(account_id, transfer_id), secret.expose())
}

pub fn open_secret(
    sk: &SealPrivateKey,
    account_id: &AccountId,
    transfer_id: &str,
    blob: &[u8],
) -> Result<SyncSecret> {
    let plain =
        zeroize::Zeroizing::new(seal::open(sk, DOMAIN, &aad(account_id, transfer_id), blob)?);
    let bytes: [u8; SECRET_LEN] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("transfer"))?;
    Ok(SyncSecret::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_transfer() {
        let account = AccountId::random().unwrap();
        let secret = SyncSecret::generate().unwrap();
        let new_device = SealPrivateKey::generate();
        let transfer_id = new_transfer_id().unwrap();
        let code = display_code(&transfer_id, &new_device.public()).unwrap();
        assert_eq!(code.len(), 24 + 5);
        let (parsed_id, fp) = parse_code(&code.to_ascii_lowercase()).unwrap();
        assert_eq!(parsed_id, transfer_id);
        let blob = seal_secret(&new_device.public(), &fp, &account, &parsed_id, &secret).unwrap();
        assert_eq!(
            open_secret(&new_device, &account, &transfer_id, &blob).unwrap(),
            secret
        );
    }

    #[test]
    fn substituted_key_is_detected() {
        let account = AccountId::random().unwrap();
        let secret = SyncSecret::generate().unwrap();
        let new_device = SealPrivateKey::generate();
        let attacker = SealPrivateKey::generate();
        let transfer_id = new_transfer_id().unwrap();
        let (_, fp) =
            parse_code(&display_code(&transfer_id, &new_device.public()).unwrap()).unwrap();
        assert_eq!(
            seal_secret(&attacker.public(), &fp, &account, &transfer_id, &secret),
            Err(Error::Mismatch("transfer fingerprint"))
        );
    }

    #[test]
    fn rejects_bad_codes() {
        assert!(parse_code("ABCD-EFGH").is_err());
        assert!(parse_code("!!!!-!!!!-!!!!-!!!!-!!!!-!!!!").is_err());
        assert!(validate_transfer_id("abc").is_err());
    }

    #[test]
    fn blob_is_bound_to_account_and_transfer() {
        let account = AccountId::random().unwrap();
        let secret = SyncSecret::generate().unwrap();
        let new_device = SealPrivateKey::generate();
        let id = new_transfer_id().unwrap();
        let fp = fingerprint(&new_device.public());
        let blob = seal_secret(&new_device.public(), &fp, &account, &id, &secret).unwrap();
        assert!(open_secret(&new_device, &AccountId::random().unwrap(), &id, &blob).is_err());
        assert!(open_secret(&new_device, &account, &new_transfer_id().unwrap(), &blob).is_err());
    }
}
