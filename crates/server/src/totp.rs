use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const STEP_SECONDS: i64 = 30;
pub const DIGITS: u32 = 6;

pub(crate) fn code_at(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    binary % 10_u32.pow(DIGITS)
}

pub fn format_code(code: u32) -> String {
    format!("{code:06}")
}

pub fn verify(secret: &[u8], code: &str, now_ms: i64, last_step: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let current = now_ms.div_euclid(1000) / STEP_SECONDS;
    (current - 1..=current + 1)
        .filter(|step| *step > last_step)
        .find(|step| {
            crate::crypto::constant_time_eq(
                format_code(code_at(secret, *step)).as_bytes(),
                format_code(wanted).as_bytes(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc_6238_vectors() {
        assert_eq!(code_at(SECRET, 59 / 30), 287_082);
        assert_eq!(code_at(SECRET, 1_111_111_109 / 30), 81_804);
        assert_eq!(code_at(SECRET, 2_000_000_000 / 30), 279_037);
    }

    #[test]
    fn accepts_drift_and_rejects_replay() {
        let now_ms = 1_111_111_109_000;
        let step = now_ms / 1000 / STEP_SECONDS;
        let code = format_code(code_at(SECRET, step));
        assert_eq!(verify(SECRET, &code, now_ms, 0), Some(step));
        assert_eq!(verify(SECRET, &code, now_ms + 30_000, 0), Some(step));
        assert_eq!(verify(SECRET, &code, now_ms + 90_000, 0), None);
        assert_eq!(verify(SECRET, &code, now_ms, step), None);
        assert_eq!(verify(SECRET, "12345", now_ms, 0), None);
        assert_eq!(verify(SECRET, "abcdef", now_ms, 0), None);
    }
}
