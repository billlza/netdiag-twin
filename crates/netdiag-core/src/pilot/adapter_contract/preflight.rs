use super::super::PilotAdapterMode;
use crate::error::{NetdiagError, Result};
use serde_json::Value;

mod structure;
use structure::validate_report_structure;

pub(in crate::pilot) fn validate_adapter_preflight(
    preflight: &Value,
    expected_mode: PilotAdapterMode,
    expected_adapter: &str,
) -> Result<()> {
    let report = preflight.as_object().ok_or_else(|| {
        NetdiagError::Connector("adapter preflight must emit a JSON object".to_string())
    })?;
    if preflight.get("schema").and_then(Value::as_str) != Some("netdiag-adapter-preflight/v1") {
        return Err(NetdiagError::Connector(
            "adapter preflight emitted an unsupported schema".to_string(),
        ));
    }
    if preflight.get("adapter").and_then(Value::as_str) != Some(expected_adapter) {
        return Err(NetdiagError::Connector(format!(
            "adapter preflight identity must be {expected_adapter:?}"
        )));
    }
    let passed = preflight
        .get("passed")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            NetdiagError::Connector("adapter preflight passed must be a boolean".to_string())
        })?;
    if preflight.get("collection_mode").and_then(Value::as_str) != Some(expected_mode.as_str()) {
        return Err(NetdiagError::Connector(format!(
            "adapter preflight collection_mode must match requested {} mode",
            expected_mode.as_str()
        )));
    }
    validate_report_structure(report, passed)?;
    if !passed {
        return Err(NetdiagError::Connector(
            "adapter preflight did not pass".to_string(),
        ));
    }
    Ok(())
}
