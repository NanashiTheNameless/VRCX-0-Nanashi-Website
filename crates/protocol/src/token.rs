use core::fmt;

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use zeroize::Zeroizing;

use crate::{Error, Result, rand};

const ID_BYTES: usize = 10;
const ID_CHARS: usize = 16;
const SECRET_BYTES: usize = 32;
const SECRET_CHARS: usize = 43;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Api,
    Session,
}

impl TokenKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Api => "rs1",
            Self::Session => "rsw1",
        }
    }
}

pub struct ParsedToken {
    pub kind: TokenKind,
    pub id: String,
    pub secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ParsedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ParsedToken({:?}, {}, <redacted>)", self.kind, self.id)
    }
}

pub fn generate(kind: TokenKind) -> Result<(Zeroizing<String>, ParsedToken)> {
    let id = BASE32_NOPAD
        .encode(&rand::bytes::<ID_BYTES>()?)
        .to_ascii_lowercase();
    let secret = Zeroizing::new(rand::bytes::<SECRET_BYTES>()?.to_vec());
    let full = Zeroizing::new(format!(
        "{}_{id}_{}",
        kind.prefix(),
        BASE64URL_NOPAD.encode(&secret)
    ));
    Ok((full, ParsedToken { kind, id, secret }))
}

pub fn parse(token: &str, expected: TokenKind) -> Result<ParsedToken> {
    let rest = token
        .strip_prefix(expected.prefix())
        .and_then(|rest| rest.strip_prefix('_'))
        .ok_or(Error::Invalid("token"))?;
    let (id, secret) = rest
        .split_at_checked(ID_CHARS)
        .ok_or(Error::Invalid("token"))?;
    let secret = secret.strip_prefix('_').ok_or(Error::Invalid("token"))?;
    if secret.len() != SECRET_CHARS
        || id.bytes().any(|b| b.is_ascii_uppercase())
        || BASE32_NOPAD
            .decode(id.to_ascii_uppercase().as_bytes())
            .map(|b| b.len())
            != Ok(ID_BYTES)
    {
        return Err(Error::Invalid("token"));
    }
    let secret = Zeroizing::new(
        BASE64URL_NOPAD
            .decode(secret.as_bytes())
            .map_err(|_| Error::Invalid("token"))?,
    );
    if secret.len() != SECRET_BYTES {
        return Err(Error::Invalid("token"));
    }
    Ok(ParsedToken {
        kind: expected,
        id: id.to_owned(),
        secret,
    })
}

const USER_CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const USER_CODE_LEN: usize = 8;

pub fn generate_user_code() -> Result<String> {
    let mut out = String::with_capacity(USER_CODE_LEN + 1);
    let mut produced = 0;
    while produced < USER_CODE_LEN {
        let [byte] = rand::bytes::<1>()?;
        if usize::from(byte) >= 252 {
            continue;
        }
        if produced == 4 {
            out.push('-');
        }
        out.push(char::from(
            USER_CODE_ALPHABET[usize::from(byte) % USER_CODE_ALPHABET.len()],
        ));
        produced += 1;
    }
    Ok(out)
}

pub fn normalize_user_code(input: &str) -> Result<String> {
    let compact: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.len() != USER_CODE_LEN || !compact.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)) {
        return Err(Error::Invalid("user code"));
    }
    Ok(format!("{}-{}", &compact[..4], &compact[4..]))
}

pub fn generate_device_code() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        BASE64URL_NOPAD.encode(&rand::bytes::<32>()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip() {
        for kind in [TokenKind::Api, TokenKind::Session] {
            let (full, parts) = generate(kind).unwrap();
            assert!(full.starts_with(&format!("{}_", kind.prefix())));
            let parsed = parse(&full, kind).unwrap();
            assert_eq!(parsed.id, parts.id);
            assert_eq!(*parsed.secret, *parts.secret);
        }
    }

    #[test]
    fn token_kinds_do_not_mix() {
        let (full, _) = generate(TokenKind::Api).unwrap();
        assert!(parse(&full, TokenKind::Session).is_err());
    }

    #[test]
    fn rejects_malformed_tokens() {
        let (full, _) = generate(TokenKind::Api).unwrap();
        assert!(parse(&full[..full.len() - 1], TokenKind::Api).is_err());
        assert!(parse(&full.to_ascii_uppercase(), TokenKind::Api).is_err());
        assert!(parse("rs1_short_x", TokenKind::Api).is_err());
        assert!(parse("", TokenKind::Api).is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let (_, parts) = generate(TokenKind::Api).unwrap();
        assert!(format!("{parts:?}").contains("<redacted>"));
    }

    #[test]
    fn user_codes() {
        let code = generate_user_code().unwrap();
        assert_eq!(code.len(), 9);
        assert_eq!(
            normalize_user_code(&code.to_ascii_lowercase().replace('-', " ")).unwrap(),
            code
        );
        assert_eq!(normalize_user_code("0o1i-ab2z").unwrap(), "0O1I-AB2Z");
        assert!(normalize_user_code("AAAA-AAA!").is_err());
        assert_eq!(normalize_user_code("4k7m x9qd").unwrap(), "4K7M-X9QD");
        assert!(normalize_user_code("BCD").is_err());
    }
}
