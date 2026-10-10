use std::path::PathBuf;
#[cfg(test)]
use std::sync::Mutex;

use hyper::Method;
use vrcx_0_nanashi_website_protocol::mail::SendRequest;

pub enum Mailer {
    Socket {
        path: PathBuf,
    },
    #[cfg(test)]
    Memory(Mutex<Vec<SendRequest>>),
}

#[derive(Debug, thiserror::Error)]
#[error("email: {0}")]
pub struct MailError(pub String);

impl Mailer {
    pub fn socket(path: PathBuf) -> Self {
        Self::Socket { path }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self::Memory(Mutex::new(Vec::new()))
    }

    pub async fn send(&self, message: SendRequest) -> Result<(), MailError> {
        message.validate().map_err(|e| MailError(e.into()))?;
        match self {
            Self::Socket { path } => {
                let body = serde_json::to_vec(&message).map_err(|e| MailError(e.to_string()))?;
                let (status, _) = crate::uds::call(path, Method::POST, "/send", body, true)
                    .await
                    .map_err(|e| MailError(e.0))?;
                if status.is_success() {
                    Ok(())
                } else {
                    Err(MailError(format!("mailer returned HTTP {status}")))
                }
            }
            #[cfg(test)]
            Self::Memory(sent) => {
                sent.lock().unwrap_or_else(|p| p.into_inner()).push(message);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn sent(&self) -> Vec<SendRequest> {
        match self {
            #[cfg(test)]
            Self::Memory(sent) => sent.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            Self::Socket { .. } => Vec::new(),
        }
    }
}

pub struct Email {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Email {
    pub fn to(self, address: &str, idempotency_key: String) -> SendRequest {
        SendRequest {
            to: address.to_owned(),
            subject: self.subject,
            text: self.text,
            html: Some(self.html),
            idempotency_key,
        }
    }
}

const FOOTER: &str =
    "This is an automatic message from VRCX-0-Nanashi RemoteSync. Replies are not read.";

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render(subject: &str, paragraphs: &[String]) -> Email {
    let mut text = String::new();
    let mut html = String::from("<!doctype html><html><body style=\"font-family: monospace\">");
    for paragraph in paragraphs {
        text.push_str(paragraph);
        text.push_str("\n\n");
        if paragraph.starts_with("https://") && !paragraph.contains(char::is_whitespace) {
            let url = escape(paragraph);
            html.push_str(&format!("<p><a href=\"{url}\">{url}</a></p>"));
        } else {
            html.push_str(&format!(
                "<p>{}</p>",
                escape(paragraph).replace('\n', "<br>")
            ));
        }
    }
    text.push_str("-- \n");
    text.push_str(FOOTER);
    text.push('\n');
    html.push_str(&format!(
        "<hr><p><small>{}</small></p></body></html>",
        escape(FOOTER)
    ));
    Email {
        subject: subject.to_owned(),
        text,
        html,
    }
}

pub fn verify_address(link: &str) -> Email {
    render(
        "Confirm your email address",
        &[
            "Open this link to confirm your email address for VRCX-0-Nanashi RemoteSync. It works once and expires in 30 minutes.".into(),
            link.into(),
            "If you did not sign up, ignore this email.".into(),
        ],
    )
}

pub fn signup_existing_account() -> Email {
    render(
        "Sign-up attempt with your email address",
        &["Someone tried to sign up for VRCX-0-Nanashi RemoteSync with this email address, which already has an account. Nothing was changed. If it was you, sign in instead, or reset your password.".into()],
    )
}

pub fn email_code(code: &str) -> Email {
    render(
        "Your sign-in code",
        &[
            format!("Your VRCX-0-Nanashi RemoteSync code is: {code}"),
            "It works once and expires in 10 minutes. If you did not try to sign in, change your password.".into(),
        ],
    )
}

pub fn password_reset(link: &str) -> Email {
    render(
        "Reset your password",
        &[
            "Open this link to set a new password. It works once and expires in 30 minutes. You will still need your second factor.".into(),
            link.into(),
            "If you did not ask for this, ignore this email; your password is unchanged.".into(),
        ],
    )
}

pub fn notice(subject: &str, what: &str) -> Email {
    render(
        subject,
        &[
            what.into(),
            "If this was not you, sign in, end your other sessions, and change your password."
                .into(),
        ],
    )
}

pub fn new_sign_in(client: &str, ip: Option<&str>, place: Option<&str>) -> Email {
    let mut lines = vec![format!(
        "New sign-in to your VRCX-0-Nanashi RemoteSync account: {client}."
    )];
    if let Some(ip) = ip {
        lines.push(format!(
            "IP address: {ip}{}",
            place.map(|p| format!(" ({p})")).unwrap_or_default()
        ));
    }
    lines.push("If this was not you, sign in, end that session, and change your password.".into());
    render("New sign-in", &lines)
}

pub fn recovery_code_used(left: i64) -> Email {
    render(
        "A recovery code was used",
        &[
            format!("A recovery code was used for your account. {left} left."),
            "If this was not you, sign in with another code or your authenticator, generate new codes, and change your password.".into(),
        ],
    )
}

pub fn access_decided(approved: bool, note: Option<&str>) -> Email {
    let mut lines = vec![if approved {
        "Your VRCX-0-Nanashi RemoteSync account was approved. You can now sign in and pair VRCX-0-Nanashi.".to_owned()
    } else {
        "Your request for a VRCX-0-Nanashi RemoteSync account was not approved, and the account was deleted.".to_owned()
    }];
    if let Some(note) = note.filter(|n| !n.trim().is_empty()) {
        lines.push(format!("Note from the administrator: {note}"));
    }
    render(
        if approved {
            "Account approved"
        } else {
            "Account request declined"
        },
        &lines,
    )
}

pub fn invite(link: &str) -> Email {
    render(
        "You are invited to VRCX-0-Nanashi RemoteSync",
        &[
            "An administrator created an invitation for this email address. Open the link to choose a password and set up 2FA. It expires in 7 days.".into(),
            link.into(),
        ],
    )
}

pub fn sync_disabled() -> Email {
    render(
        "RemoteSync was disabled for your account",
        &["An administrator disabled RemoteSync for your account and deleted its synced data. Your history on your PCs is not affected, and your account and shared collections remain.".into()],
    )
}

pub fn data_deleted(whole_account: bool) -> Email {
    render(
        if whole_account {
            "Your account was deleted"
        } else {
            "Your synced data was deleted"
        },
        &[if whole_account {
            "Your VRCX-0-Nanashi RemoteSync account and all of its data were deleted.".to_owned()
        } else {
            "All synced data of your VRCX-0-Nanashi RemoteSync account was deleted. Your account remains.".to_owned()
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_escaped_and_links_are_plain() {
        let email = render(
            "S",
            &[
                "<script>x</script>".into(),
                "https://vrcx.namelessnanashi.dev/verify?t=a&b".into(),
            ],
        );
        assert!(email.html.contains("&lt;script&gt;"));
        assert!(
            email
                .html
                .contains("href=\"https://vrcx.namelessnanashi.dev/verify?t=a&amp;b\"")
        );
        assert!(!email.html.contains("<img"));
        assert!(email.text.contains(FOOTER));
    }
}
