use crate::crypto::ServerKeys;
use crate::util::random_bytes;

pub const COUNT: usize = 10;
pub const LENGTH: usize = 10;
const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const HMAC_PURPOSE: &str = "recovery-code";

pub fn generate(keys: &ServerKeys) -> (Vec<String>, Vec<[u8; 32]>) {
    let mut plain = Vec::with_capacity(COUNT);
    let mut hashes = Vec::with_capacity(COUNT);
    while plain.len() < COUNT {
        let bytes: [u8; LENGTH] = random_bytes();
        let code: String = bytes
            .iter()
            .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
            .collect();
        let hash = hash(keys, &code);
        if hashes.contains(&hash) {
            continue;
        }
        plain.push(format!("{}-{}", &code[..5], &code[5..]));
        hashes.push(hash);
    }
    (plain, hashes)
}

pub fn normalize(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (code.len() == LENGTH && code.bytes().all(|b| ALPHABET.contains(&b))).then_some(code)
}

pub fn hash(keys: &ServerKeys, normalized: &str) -> [u8; 32] {
    keys.hmac(HMAC_PURPOSE, normalized.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ten_distinct_formatted_codes() {
        let keys = ServerKeys::from_master(&[1; 32]);
        let (plain, hashes) = generate(&keys);
        assert_eq!(plain.len(), COUNT);
        assert_eq!(hashes.len(), COUNT);
        for (code, stored) in plain.iter().zip(&hashes) {
            assert_eq!(code.len(), 11);
            assert_eq!(&code[5..6], "-");
            assert_eq!(hash(&keys, &normalize(code).unwrap()), *stored);
        }
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), COUNT);
    }

    #[test]
    fn normalization_only_folds_case_and_separators() {
        assert_eq!(normalize("ABCDE-FGH1J").unwrap(), "abcdefgh1j");
        assert_eq!(normalize(" abcde fghIj ").unwrap(), "abcdefghij");
        assert_eq!(normalize("0o0o0-lLiI1").unwrap(), "0o0o0llii1");
        assert_ne!(normalize("iiiii-iiiii"), normalize("lllll-lllll"));
        assert_ne!(normalize("iiiii-iiiii"), normalize("11111-11111"));
        assert_ne!(normalize("ooooo-ooooo"), normalize("00000-00000"));
        assert!(normalize("abcde-fgh!1").is_none());
        assert!(normalize("short").is_none());
    }
}
