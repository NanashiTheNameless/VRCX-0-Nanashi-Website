pub fn from_millis(value: i64) -> i64 {
    value.div_euclid(1000)
}

pub fn normalize_integer(value: i64) -> i64 {
    if value.unsigned_abs() >= 100_000_000_000 {
        from_millis(value)
    } else {
        value
    }
}

pub fn parse_epoch_seconds(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(value) = text.parse::<i64>() {
        return Some(normalize_integer(value));
    }
    if let Ok(value) = text.parse::<jiff::Timestamp>() {
        return Some(value.as_nanosecond().div_euclid(1_000_000_000) as i64);
    }
    let datetime = text.parse::<jiff::civil::DateTime>().ok().or_else(|| {
        text.parse::<jiff::civil::Date>()
            .ok()
            .map(|date| date.at(0, 0, 0, 0))
    })?;
    Some(
        datetime
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()?
            .timestamp()
            .as_nanosecond()
            .div_euclid(1_000_000_000) as i64,
    )
}

pub fn epoch_from_json(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|value| {
                        value.is_finite()
                            && *value >= i64::MIN as f64
                            && *value < -(i64::MIN as f64)
                    })
                    .map(|value| value.floor() as i64)
            })
            .map(normalize_integer),
        serde_json::Value::String(text) => parse_epoch_seconds(text),
        _ => None,
    }
}

pub fn deserialize_optional_epoch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    epoch_from_json(&value)
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("invalid epoch timestamp"))
}

pub fn system_time_seconds(value: std::time::SystemTime) -> i64 {
    match value.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(error) => {
            let duration = error.duration();
            let magnitude =
                i128::from(duration.as_secs()) + i128::from(duration.subsec_nanos() != 0);
            (-magnitude).max(i128::from(i64::MIN)) as i64
        }
    }
}

pub(crate) fn convert_legacy_fields(
    value: &mut ciborium::Value,
    fields: &[(&str, &str)],
) -> Result<(), String> {
    let object = value
        .as_map_mut()
        .ok_or_else(|| "expected timestamp object".to_string())?;
    for (old, new) in fields {
        if let Some(index) = object
            .iter()
            .position(|(key, _)| key.as_text() == Some(*old))
        {
            if object.iter().any(|(key, _)| key.as_text() == Some(*new)) {
                return Err(format!("duplicate date fields: {old}, {new}"));
            }
            let converted = match &object[index].1 {
                ciborium::Value::Null => ciborium::Value::Null,
                ciborium::Value::Integer(number) => {
                    let integer: i64 = (*number)
                        .try_into()
                        .map_err(|_| "timestamp is outside signed INT64")?;
                    ciborium::Value::Integer(from_millis(integer).into())
                }
                ciborium::Value::Text(text) => {
                    let seconds = text
                        .trim()
                        .parse::<i64>()
                        .ok()
                        .map(from_millis)
                        .or_else(|| parse_epoch_seconds(text))
                        .ok_or("invalid legacy date text")?;
                    ciborium::Value::Integer(seconds.into())
                }
                _ => return Err("legacy timestamp must be signed INT64 milliseconds".to_string()),
            };
            object[index] = (ciborium::Value::Text((*new).to_string()), converted);
        } else if let Some((_, candidate)) = object
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some(*new))
        {
            let seconds = match candidate {
                ciborium::Value::Null => continue,
                ciborium::Value::Integer(number) => {
                    let integer: i64 = (*number)
                        .try_into()
                        .map_err(|_| "timestamp is outside signed INT64")?;
                    normalize_integer(integer)
                }
                ciborium::Value::Text(text) => {
                    parse_epoch_seconds(text).ok_or("invalid date text")?
                }
                _ => return Err("timestamp must be an integer or date text".to_string()),
            };
            *candidate = ciborium::Value::Integer(seconds.into());
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn legacy_value<T: serde::Serialize>(value: &T) -> ciborium::Value {
    fn visit(value: &mut ciborium::Value) {
        match value {
            ciborium::Value::Map(fields) => {
                for (key, value) in fields {
                    if let Some(name) = key.as_text()
                        && [
                            "createdAt",
                            "addedAt",
                            "expiresAt",
                            "lastSeenAt",
                            "start",
                            "end",
                        ]
                        .contains(&name)
                    {
                        *key = ciborium::Value::Text(format!("{name}Ms"));
                        if let ciborium::Value::Integer(integer) = value {
                            let seconds: i64 = (*integer).try_into().unwrap();
                            *value = ciborium::Value::Integer((seconds * 1000).into());
                        }
                    }
                    visit(value);
                }
            }
            ciborium::Value::Array(values) => values.iter_mut().for_each(visit),
            _ => {}
        }
    }
    let mut raw = ciborium::Value::serialized(value).unwrap();
    visit(&mut raw);
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_milliseconds_round_down_and_normalization_has_a_fixed_boundary() {
        assert_eq!(from_millis(-1), -1);
        assert_eq!(from_millis(i64::MIN), -9223372036854776);
        assert_eq!(normalize_integer(99_999_999_999), 99_999_999_999);
        assert_eq!(normalize_integer(100_000_000_000), 100_000_000);
        assert_eq!(normalize_integer(-100_000_000_001), -100_000_001);
    }

    #[test]
    fn reads_text_json_and_pre_epoch_times_with_floor_rounding() {
        for text in [
            "2026-07-21T10:30:15.250Z",
            "2026-07-21T05:30:15-05:00",
            "2026-07-21 10:30:15.250",
            "1784629815250",
        ] {
            assert_eq!(parse_epoch_seconds(text), Some(1784629815), "{text}");
            assert_eq!(epoch_from_json(&serde_json::json!(text)), Some(1784629815));
        }
        for text in ["1969-12-31T23:59:59.999Z", "1969-12-31 23:59:59.999", "-1"] {
            assert_eq!(parse_epoch_seconds(text), Some(-1));
        }
        assert_eq!(normalize_integer(-99_999_999_999), -99_999_999_999);
        assert_eq!(normalize_integer(-100_000_000_000), -100_000_000);
        assert_eq!(epoch_from_json(&serde_json::json!(-0.5)), Some(-1));
        assert_eq!(parse_epoch_seconds("not a date"), None);
        assert_eq!(epoch_from_json(&serde_json::json!(true)), None);
        assert_eq!(
            system_time_seconds(std::time::UNIX_EPOCH - std::time::Duration::from_millis(1)),
            -1
        );
    }
}
