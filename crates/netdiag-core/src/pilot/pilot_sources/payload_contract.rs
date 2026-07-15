use super::super::PilotAdapterMode;
use crate::error::Result;
use crate::metric_quality::{ADAPTER_PAYLOAD_SCHEMA_V1, ADAPTER_PAYLOAD_SCHEMA_V2};
use serde_json::Value;

mod validation;

use validation::{contract_result, require_non_empty_string};

pub(super) fn validate_adapter_payload_contract(
    payload: &Value,
    expected_mode: PilotAdapterMode,
) -> Result<()> {
    let mut missing = Vec::new();
    if !matches!(
        payload.get("schema").and_then(Value::as_str),
        Some(ADAPTER_PAYLOAD_SCHEMA_V1 | ADAPTER_PAYLOAD_SCHEMA_V2)
    ) {
        missing.push("schema=netdiag-adapter-payload/v1 or netdiag-adapter-payload/v2".to_string());
    }
    require_non_empty_string(payload, "sample", &mut missing);
    require_non_empty_string(payload, "protocol", &mut missing);
    if payload.get("collection_mode").and_then(Value::as_str) != Some(expected_mode.as_str()) {
        missing.push(format!(
            "collection_mode={} matching the requested adapter mode",
            expected_mode.as_str()
        ));
    }
    if payload.get("flow_count").and_then(Value::as_u64).is_none() {
        missing.push("flow_count".to_string());
    }
    if payload
        .get("records")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        missing.push("records".to_string());
    }
    let Some(experiment) = payload.get("experiment").and_then(Value::as_object) else {
        missing.push("experiment".to_string());
        return contract_result(missing);
    };
    for field in ["scenario_id", "fault_start", "fault_end", "ground_truth"] {
        if experiment
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            missing.push(format!("experiment.{field}"));
        }
    }
    contract_result(missing)
}
