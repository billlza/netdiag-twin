use crate::error::{NetdiagError, Result};
use crate::reliability::redact_string;
use serde_json::{Map, Value};

pub(super) fn redact_adapter_value(value: &mut Value, secrets: &[String]) -> Result<()> {
    match value {
        Value::Object(map) => redact_object(map, secrets),
        Value::Array(values) => {
            for value in values {
                redact_adapter_value(value, secrets)?;
            }
            Ok(())
        }
        Value::String(text) => {
            *text = redact_text(text, secrets);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn redact_object(map: &mut Map<String, Value>, secrets: &[String]) -> Result<()> {
    let entries = std::mem::take(map);
    for (key, mut value) in entries {
        let key = redact_text(&key, secrets);
        redact_adapter_value(&mut value, secrets)?;
        if map.insert(key.clone(), value).is_some() {
            return Err(NetdiagError::Connector(format!(
                "adapter payload keys collide after secret redaction: {key:?}"
            )));
        }
    }
    Ok(())
}

fn redact_text(text: &str, secrets: &[String]) -> String {
    let mut redacted = text.to_string();
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        redacted = redacted.replace(secret, "[redacted]");
    }
    redact_string(&redacted)
}

#[cfg(test)]
mod tests;
