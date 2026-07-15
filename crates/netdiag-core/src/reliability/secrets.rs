use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

mod key;
mod url;
use key::is_sensitive_document_key;
pub(crate) use key::{is_sensitive_parameter_key, query_contains_sensitive_or_ambiguous_syntax};
use url::{is_redacted_value, looks_like_secret_value};
pub use url::{redact_string, redact_url};

pub(super) const SECRET_PLACEHOLDER: &str = "[redacted]";

pub fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if is_sensitive_document_key(key) {
                    if !item.is_null() {
                        *item = Value::String(SECRET_PLACEHOLDER.to_string());
                    }
                } else {
                    redact_json_value(item);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        Value::String(text) => *text = redact_string(text),
        _ => {}
    }
}

pub(super) fn inspect_document(path: &Path, body: &str) -> Result<bool, String> {
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("json") => {
            let value =
                crate::strict_json::parse_unique_value(body.as_bytes()).map_err(|error| {
                    format!(
                        "invalid JSON in {}: {}",
                        path.display(),
                        crate::strict_json::error_summary(&error)
                    )
                })?;
            Ok(contains_secret_value(&value))
        }
        Some(extension)
            if extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml") =>
        {
            let value = serde_yaml::from_str::<serde_yaml::Value>(body)
                .map_err(|error| format!("invalid YAML in {}: {error}", path.display()))?;
            let value = serde_json::to_value(value).map_err(|error| {
                format!(
                    "could not normalize YAML from {} for secret inspection: {error}",
                    path.display()
                )
            })?;
            Ok(contains_secret_value(&value))
        }
        _ => Ok(contains_secret_like_text(body)),
    }
}

fn contains_secret_value(value: &Value) -> bool {
    let mut leaks = BTreeSet::new();
    collect_secret_leaks(value, None, &mut leaks);
    !leaks.is_empty()
}

fn contains_secret_like_text(body: &str) -> bool {
    body.lines().any(|line| {
        if redact_string(line) != line {
            return true;
        }
        let Some((key, value)) = line.split_once(':') else {
            return looks_like_secret_value(line.trim());
        };
        is_sensitive_parameter_key(key)
            && !value.trim().is_empty()
            && !is_redacted_value(value.trim())
    })
}

fn collect_secret_leaks(value: &Value, key: Option<&str>, leaks: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                collect_secret_leaks(child, Some(child_key), leaks);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_secret_leaks(item, key, leaks);
            }
        }
        Value::String(text)
            if (key.is_some_and(is_sensitive_document_key) || redact_string(text) != *text)
                && !is_redacted_value(text)
                && !text.is_empty() =>
        {
            leaks.insert(text.clone());
        }
        Value::String(_) => {}
        _ => {}
    }
}
