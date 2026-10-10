use serde::{Deserialize, Serialize};

pub const MAX_SUBJECT: usize = 200;
pub const MAX_BODY: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub to: String,
    pub subject: String,
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
    pub idempotency_key: String,
}

impl SendRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        let to = self.to.trim();
        if to.is_empty()
            || to.len() > 254
            || !to.contains('@')
            || to.contains([',', ';', '<', '>', '\r', '\n', ' '])
        {
            return Err("invalid recipient");
        }
        if self.subject.is_empty()
            || self.subject.len() > MAX_SUBJECT
            || self.subject.contains(['\r', '\n'])
        {
            return Err("invalid subject");
        }
        if self.text.is_empty()
            || self.text.len() > MAX_BODY
            || self.html.as_ref().is_some_and(|h| h.len() > MAX_BODY)
        {
            return Err("invalid body");
        }
        if self.idempotency_key.is_empty() || self.idempotency_key.len() > 256 {
            return Err("invalid idempotency key");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResponse {
    pub id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SendRequest {
        SendRequest {
            to: "me@example.com".into(),
            subject: "Hi".into(),
            text: "Body".into(),
            html: None,
            idempotency_key: "k".into(),
        }
    }

    #[test]
    fn validation() {
        assert!(request().validate().is_ok());
        for to in [
            "",
            "no-at",
            "a@b.c, x@y.z",
            "a@b.c\r\nBcc: x@y.z",
            "Name <a@b.c>",
        ] {
            let mut r = request();
            r.to = to.into();
            assert!(r.validate().is_err(), "{to:?}");
        }
        let mut r = request();
        r.subject = "a\r\nb".into();
        assert!(r.validate().is_err());
    }
}
