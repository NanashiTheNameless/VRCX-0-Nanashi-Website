use std::io::Read;

use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use crate::keys::{self, SignerKey};
use crate::padding;
use crate::seal::{self, SealPrivateKey, SealPublicKey};
use crate::{Error, Result};

pub const MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Inner {
    h: ByteBuf,
    b: ByteBuf,
    s: ByteBuf,
}

pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|_| Error::Malformed("cbor encoding"))?;
    Ok(out)
}

pub(crate) fn from_cbor<T: DeserializeOwned>(bytes: &[u8], what: &'static str) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|_| Error::Malformed(what))
}

pub(crate) fn compress(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut source = data;
    let decoder = ruzstd::decoding::StreamingDecoder::new(&mut source)
        .map_err(|_| Error::Malformed("compressed body"))?;
    let mut out = Vec::new();
    decoder
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| Error::Malformed("compressed body"))?;
    if out.len() > MAX_BODY {
        return Err(Error::TooLarge("body"));
    }
    Ok(out)
}

fn signed_message(domain: &[u8], binding: &[u8], header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 1 + binding.len() + 64);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(binding);
    message.extend_from_slice(&Sha256::digest(header));
    message.extend_from_slice(&Sha256::digest(body));
    message
}

pub(crate) enum Signing<'a> {
    Signer(&'a SignerKey),
    Manifest(&'a ed25519_dalek::SigningKey),
}

pub(crate) fn seal_signed(
    domain: &[u8],
    binding: &[u8],
    header: &[u8],
    body: &[u8],
    signing: Signing<'_>,
    recipient: &SealPublicKey,
) -> Result<Vec<u8>> {
    let message = signed_message(domain, binding, header, body);
    let signature = match signing {
        Signing::Signer(key) => key.sign(&message).to_bytes(),
        Signing::Manifest(key) => {
            use ed25519_dalek::Signer as _;
            key.sign(&message).to_bytes()
        }
    };
    let inner = to_cbor(&Inner {
        h: ByteBuf::from(header.to_vec()),
        b: ByteBuf::from(body.to_vec()),
        s: ByteBuf::from(signature.to_vec()),
    })?;
    let padded = padding::pad(&inner)?;
    seal::seal(recipient, domain, binding, &padded)
}

pub(crate) struct Unverified {
    domain: &'static [u8],
    binding: Vec<u8>,
    pub header: Vec<u8>,
    body: Vec<u8>,
    signature: Vec<u8>,
}

impl Unverified {
    pub fn body_for_peek(&self) -> &[u8] {
        &self.body
    }

    pub fn verify(self, public: &VerifyingKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let message = signed_message(self.domain, &self.binding, &self.header, &self.body);
        keys::verify(public, &message, &self.signature)?;
        Ok((self.header, self.body))
    }
}

pub(crate) fn open_signed(
    domain: &'static [u8],
    binding: Vec<u8>,
    recipient: &SealPrivateKey,
    blob: &[u8],
) -> Result<Unverified> {
    let padded = seal::open(recipient, domain, &binding, blob)?;
    let inner: Inner = from_cbor(padding::unpad(&padded)?, "sealed document")?;
    Ok(Unverified {
        domain,
        binding,
        header: inner.h.into_vec(),
        body: inner.b.into_vec(),
        signature: inner.s.into_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_round_trip_and_garbage() {
        let data = b"hello hello hello hello".repeat(100);
        assert_eq!(decompress(&compress(&data)).unwrap(), data);
        assert!(decompress(b"not zstd").is_err());
    }
}
