use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).expect("operating system random number generator");
    out
}

pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;
