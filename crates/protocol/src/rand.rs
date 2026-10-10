use crate::{Error, Result};

pub fn fill(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|_| Error::Rng)
}

pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}
