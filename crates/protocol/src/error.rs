use thiserror::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("random number generator failed")]
    Rng,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("checksum mismatch in {0}")]
    Checksum(&'static str),
    #[error("decryption failed")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("signature invalid")]
    Signature,
    #[error("signer is not authorized for this vault")]
    UnknownSigner,
    #[error("{0} too large")]
    TooLarge(&'static str),
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("{0} does not match")]
    Mismatch(&'static str),
    #[error("rollback detected in {0}")]
    Rollback(&'static str),
    #[error("parameters below the required minimum")]
    WeakParameters,
}
