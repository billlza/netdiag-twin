use crate::error::{NetdiagError, Result};
use serde_json::Value;

pub(super) fn require_non_empty_string(payload: &Value, field: &str, missing: &mut Vec<String>) {
    if payload
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        missing.push(field.to_string());
    }
}

pub(super) fn contract_result(missing: Vec<String>) -> Result<()> {
    if missing.is_empty() {
        Ok(())
    } else {
        Err(NetdiagError::Connector(format!(
            "adapter payload contract missing or invalid required fields: {}",
            missing.join(", ")
        )))
    }
}
