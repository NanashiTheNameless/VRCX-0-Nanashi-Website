use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};

use crate::util::random_bytes;

#[cfg(not(test))]
const MEMORY_KIB: u32 = 64 * 1024;
#[cfg(test)]
const MEMORY_KIB: u32 = 64;
#[cfg(not(test))]
const ITERATIONS: u32 = 3;
#[cfg(test)]
const ITERATIONS: u32 = 1;

pub const MIN_LENGTH: usize = 12;
pub const MAX_LENGTH: usize = 256;

const COMMON: &[&str] = &[
    "123456789012",
    "1234567890123",
    "password1234",
    "passwordpassword",
    "qwertyuiopas",
    "qwerty123456",
    "111111111111",
    "000000000000",
    "123123123123",
    "iloveyou1234",
    "letmein12345",
    "welcome12345",
    "administrator",
    "abcdefghijkl",
    "abc123abc123",
    "qwertyqwerty",
    "aaaaaaaaaaaa",
    "passw0rdpassw0rd",
    "changemechangeme",
    "vrchatvrchat",
];

fn hasher() -> Argon2<'static> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, 1, Some(32)).expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordProblem {
    Short,
    Long,
    Common,
}

impl PasswordProblem {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Short => "Passwords must be at least 12 characters.",
            Self::Long => "Passwords can be at most 256 characters.",
            Self::Common => "This password is too common. Choose another.",
        }
    }
}

pub fn check(password: &str) -> Result<(), PasswordProblem> {
    let length = password.chars().count();
    if length < MIN_LENGTH {
        return Err(PasswordProblem::Short);
    }
    if length > MAX_LENGTH {
        return Err(PasswordProblem::Long);
    }
    let lower = password.to_lowercase();
    let first = lower.chars().next();
    if COMMON.contains(&lower.as_str())
        || first.is_some_and(|first| lower.chars().all(|c| c == first))
    {
        return Err(PasswordProblem::Common);
    }
    Ok(())
}

pub fn hash(password: &str) -> String {
    let salt: [u8; 16] = random_bytes();
    hasher()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .expect("hashing with valid parameters cannot fail")
        .to_string()
}

pub fn verify(stored: &str, password: &str) -> bool {
    hasher()
        .verify_password(password.as_bytes(), stored)
        .is_ok()
}

pub fn verify_dummy(password: &str) {
    let mut out = [0_u8; 32];
    let _ = hasher().hash_password_into(password.as_bytes(), b"remotesync-dummy-salt", &mut out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let stored = hash("correct horse battery");
        assert!(stored.starts_with("$argon2id$"));
        assert!(verify(&stored, "correct horse battery"));
        assert!(!verify(&stored, "correct horse batterY"));
        assert_ne!(hash("correct horse battery"), stored, "random salt");
        assert!(!verify("garbage", "x"));
    }

    #[test]
    fn rules() {
        assert_eq!(check("short"), Err(PasswordProblem::Short));
        assert_eq!(check(&"xy".repeat(129)), Err(PasswordProblem::Long));
        assert_eq!(check("PasswordPassword"), Err(PasswordProblem::Common));
        assert_eq!(check("zzzzzzzzzzzzzz"), Err(PasswordProblem::Common));
        assert!(check("my unusual sentence 42").is_ok());
        let twelve_non_ascii = "\u{e4}\u{f6}\u{fc}".repeat(4);
        assert!(
            check(&twelve_non_ascii).is_ok(),
            "length in characters, not bytes"
        );
    }
}
