use crate::{Error, Result};

const KIB: usize = 1024;
const SMALL_STEP: usize = 4 * KIB;
const SMALL_LIMIT: usize = 64 * KIB;
const LARGE_STEP: usize = 64 * KIB;
pub const MAX_PADDED: usize = 4 * KIB * KIB;
const LEN_PREFIX: usize = 4;

pub fn bucket(len: usize) -> Result<usize> {
    let size = if len <= SMALL_LIMIT {
        len.div_ceil(SMALL_STEP).max(1) * SMALL_STEP
    } else {
        len.div_ceil(LARGE_STEP) * LARGE_STEP
    };
    if size > MAX_PADDED {
        return Err(Error::TooLarge("chunk"));
    }
    Ok(size)
}

pub fn pad(data: &[u8]) -> Result<Vec<u8>> {
    let total = bucket(LEN_PREFIX + data.len())?;
    let len = u32::try_from(data.len()).map_err(|_| Error::TooLarge("chunk"))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    Ok(out)
}

pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < LEN_PREFIX || padded.len() > MAX_PADDED {
        return Err(Error::Malformed("padding"));
    }
    let (prefix, rest) = padded.split_at(LEN_PREFIX);
    let len = u32::from_be_bytes(prefix.try_into().expect("4 bytes")) as usize;
    if len > rest.len() || rest[len..].iter().any(|byte| *byte != 0) {
        return Err(Error::Malformed("padding"));
    }
    Ok(&rest[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(bucket(0).unwrap(), 4096);
        assert_eq!(bucket(1).unwrap(), 4096);
        assert_eq!(bucket(4096).unwrap(), 4096);
        assert_eq!(bucket(4097).unwrap(), 8192);
        assert_eq!(bucket(65536).unwrap(), 65536);
        assert_eq!(bucket(65537).unwrap(), 131072);
        assert_eq!(bucket(MAX_PADDED).unwrap(), MAX_PADDED);
        assert!(bucket(MAX_PADDED + 1).is_err());
    }

    #[test]
    fn pad_round_trip() {
        for len in [0, 1, 4091, 4092, 4093, 70_000] {
            let data = vec![7_u8; len];
            let padded = pad(&data).unwrap();
            assert_eq!(padded.len(), bucket(len + 4).unwrap());
            assert_eq!(unpad(&padded).unwrap(), data.as_slice());
        }
    }

    #[test]
    fn unpad_rejects_bad_input() {
        let mut padded = pad(b"abc").unwrap();
        padded[0] = 0xff;
        assert!(unpad(&padded).is_err());
        let mut padded = pad(b"abc").unwrap();
        *padded.last_mut().unwrap() = 1;
        assert!(unpad(&padded).is_err());
        assert!(unpad(&[0, 0]).is_err());
    }
}
