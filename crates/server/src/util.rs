use std::time::SystemTime;

pub fn now_epoch() -> i64 {
    vrcx_0_nanashi_website_protocol::time::system_time_seconds(SystemTime::now())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).expect("operating system random number generator");
    out
}

pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;
