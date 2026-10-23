use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::time::{epoch_from_json, from_millis, parse_epoch_seconds};

pub fn legacy_event_discriminator(value: &Value) -> String {
    let numeric;
    let text = match value {
        Value::String(text) => text.as_str(),
        Value::Number(number) => {
            let Some(integer) = number.as_i64() else {
                return String::new();
            };
            if integer.unsigned_abs() < 100_000_000_000 || integer % 1000 == 0 {
                return String::new();
            }
            numeric = integer.to_string();
            numeric.as_str()
        }
        _ => return String::new(),
    };
    if parse_epoch_seconds(text)
        .and_then(|seconds| jiff::Timestamp::from_second(seconds).ok())
        .is_some_and(|date| date.strftime("%Y-%m-%dT%H:%M:%S.000Z").to_string() == text)
    {
        return String::new();
    }
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn normalize_row(stream: &str, row: &Value) -> Value {
    let Some(object) = row.as_object() else {
        return row.clone();
    };
    let mut normalized = object.clone();
    if stream.starts_with("gamelog_") && !normalized.contains_key("event_discriminator") {
        let original = object
            .get("created_at")
            .or_else(|| object.get("created_at_ms"))
            .unwrap_or(&Value::Null);
        normalized.insert(
            "event_discriminator".into(),
            legacy_event_discriminator(original).into(),
        );
    }
    for (column, value) in object {
        let (name, legacy) = if let Some(name) = column
            .strip_suffix("_ms")
            .filter(|name| name.ends_with("_at"))
        {
            (name, true)
        } else if column.ends_with("_at") {
            (column.as_str(), false)
        } else {
            continue;
        };
        if legacy && object.contains_key(name) {
            continue;
        }
        let seconds = if legacy {
            value
                .as_i64()
                .or_else(|| value.as_str()?.trim().parse().ok())
                .map(from_millis)
                .or_else(|| value.as_str().and_then(parse_epoch_seconds))
        } else {
            epoch_from_json(value)
        };
        if let Some(seconds) = seconds {
            normalized.remove(column);
            normalized.insert(name.into(), seconds.into());
        }
    }
    normalized.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_collision_identity_matches_desktop_and_repeat_import_is_stable() {
        let fixtures: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/legacy-events.json")).unwrap();
        for fixture in fixtures {
            let imported = normalize_row("gamelog_event", &fixture["legacy"]);
            assert_eq!(imported, fixture["imported"]);
            assert_eq!(normalize_row("gamelog_event", &imported), imported);
        }
        let explicit = serde_json::json!({"created_at": "2026-07-21T10:30:15.125Z", "event_discriminator": "opaque"});
        assert_eq!(
            normalize_row("gamelog_event", &explicit)["event_discriminator"],
            "opaque"
        );
        assert_eq!(
            legacy_event_discriminator(&serde_json::json!(1784629815000_i64)),
            ""
        );
        assert_eq!(
            legacy_event_discriminator(&serde_json::json!(1784629815)),
            ""
        );
        assert_ne!(
            legacy_event_discriminator(&serde_json::json!(1784629815125_i64)),
            ""
        );
        assert_eq!(
            normalize_row(
                "feed_gps",
                &serde_json::json!({"created_at_ms": -1, "idle_timeout_ms": 500})
            ),
            serde_json::json!({"created_at": -1, "idle_timeout_ms": 500})
        );
    }
}
