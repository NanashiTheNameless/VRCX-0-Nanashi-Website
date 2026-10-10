use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub name: &'static str,
    pub capacity: f64,
    pub per_second: f64,
}

impl Rule {
    pub const fn per_minute(name: &'static str, capacity: u32) -> Self {
        Self {
            name,
            capacity: capacity as f64,
            per_second: capacity as f64 / 60.0,
        }
    }
}

pub const CAPABILITIES: Rule = Rule::per_minute("capabilities", 120);
pub const DEVICE_AUTHORIZE: Rule = Rule::per_minute("device-authorize", 10);
pub const DEVICE_TOKEN: Rule = Rule::per_minute("device-token", 60);
pub const AUTH_FAILURES_IP: Rule = Rule {
    name: "auth-fail-ip",
    capacity: 20.0,
    per_second: 1.0 / 30.0,
};
pub const AUTH_FAILURES_TOKEN: Rule = Rule {
    name: "auth-fail-token",
    capacity: 5.0,
    per_second: 1.0 / 60.0,
};
pub const AUTH_START: Rule = Rule::per_minute("auth-start", 20);
pub const LOGIN_EMAIL: Rule = Rule {
    name: "login-email",
    capacity: 10.0,
    per_second: 1.0 / 60.0,
};
pub const EMAIL_SEND: Rule = Rule {
    name: "email-send",
    capacity: 3.0,
    per_second: 1.0 / 180.0,
};
pub const ENVELOPE_FETCH: Rule = Rule {
    name: "envelope-fetch",
    capacity: 10.0,
    per_second: 10.0 / 86_400.0,
};
pub const REAUTH: Rule = Rule {
    name: "reauth",
    capacity: 5.0,
    per_second: 1.0 / 60.0,
};

type Buckets = HashMap<(&'static str, String), (f64, i64)>;

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
}

impl RateLimiter {
    fn level(&self, rule: Rule, key: &str, now_ms: i64, take: bool) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if buckets.len() > 200_000 {
            buckets.retain(|_, (tokens, _)| *tokens < 1.0);
        }
        let entry = buckets
            .entry((rule.name, key.to_owned()))
            .or_insert((rule.capacity, now_ms));
        let elapsed = (now_ms - entry.1).max(0) as f64 / 1000.0;
        entry.0 = (entry.0 + elapsed * rule.per_second).min(rule.capacity);
        entry.1 = now_ms;
        if entry.0 < 1.0 {
            let wait = ((1.0 - entry.0) / rule.per_second).ceil() as u64;
            return Err(wait.max(1));
        }
        if take {
            entry.0 -= 1.0;
        }
        Ok(())
    }

    pub fn take(&self, rule: Rule, key: &str, now_ms: i64) -> Result<(), u64> {
        self.level(rule, key, now_ms, true)
    }

    pub fn check(&self, rule: Rule, key: &str, now_ms: i64) -> Result<(), u64> {
        self.level(rule, key, now_ms, false)
    }

    pub fn fail(&self, rule: Rule, key: &str, now_ms: i64) {
        let _ = self.take(rule, key, now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_empties_and_refills() {
        let limiter = RateLimiter::default();
        let rule = Rule::per_minute("t", 2);
        assert!(limiter.take(rule, "ip", 0).is_ok());
        assert!(limiter.take(rule, "ip", 0).is_ok());
        assert_eq!(limiter.take(rule, "ip", 0), Err(30));
        assert!(limiter.take(rule, "other", 0).is_ok());
        assert!(limiter.take(rule, "ip", 30_000).is_ok());
    }

    #[test]
    fn check_does_not_consume() {
        let limiter = RateLimiter::default();
        let rule = Rule::per_minute("t", 1);
        assert!(limiter.check(rule, "k", 0).is_ok());
        assert!(limiter.check(rule, "k", 0).is_ok());
        limiter.fail(rule, "k", 0);
        assert!(limiter.check(rule, "k", 0).is_err());
    }
}
