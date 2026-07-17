use super::*;
use serde_json::json;

#[test]
fn metadata_limits_are_inclusive() {
    let entries = (0..MAX_CONNECTOR_FLOW_METADATA_ITEMS)
        .map(|_| {
            json!({
                "label": "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES),
                "bytes": 0,
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "sample": "s".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES),
        "protocol": "p".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES),
        "flows": entries,
    });

    validate_http_json_metadata(&value).expect("exact metadata limits");
}

#[test]
fn metadata_rejects_one_item_or_byte_above_each_limit_without_echoing_values() {
    let sensitive = "sensitive-metadata-sentinel";
    let oversized_entries = vec![json!({}); MAX_CONNECTOR_FLOW_METADATA_ITEMS + 1];
    let oversized_text = sensitive.repeat(
        MAX_CONNECTOR_METADATA_STRING_BYTES
            .checked_div(sensitive.len())
            .expect("non-empty sentinel")
            + 1,
    );
    for value in [
        json!({ "flows": oversized_entries }),
        json!({ "sample": oversized_text }),
        json!({ "top_talkers": [{ "label": oversized_text }] }),
    ] {
        let error = validate_http_json_metadata(&value)
            .expect_err("metadata above a resource limit must fail closed");
        let message = error.to_string();
        assert!(message.contains("metadata validation failed"), "{message}");
        assert!(!message.contains(sensitive), "{message}");
    }
}

#[test]
fn metadata_string_budget_counts_utf8_bytes() {
    let exact = format!(
        "{}x",
        "界".repeat((MAX_CONNECTOR_METADATA_STRING_BYTES - 1) / 3)
    );
    assert_eq!(exact.len(), MAX_CONNECTOR_METADATA_STRING_BYTES);
    validate_http_json_metadata(&json!({ "sample": exact })).expect("exact UTF-8 byte limit");

    let oversized = format!("{exact}x");
    let error = validate_http_json_metadata(&json!({ "sample": oversized }))
        .expect_err("one UTF-8 byte above the limit must fail");
    assert!(error.to_string().contains("byte limit"), "{error}");
}

#[test]
fn every_known_metadata_string_field_uses_the_inclusive_byte_budget() {
    let exact = "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES);
    let oversized = "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES + 1);
    for field in ["sample", "protocol", "schema", "collection_mode"] {
        let mut exact_value = serde_json::Map::new();
        exact_value.insert(field.to_string(), Value::String(exact.clone()));
        validate_http_json_metadata(&Value::Object(exact_value))
            .expect("exact top-level string budget");

        let mut oversized_value = serde_json::Map::new();
        oversized_value.insert(field.to_string(), Value::String(oversized.clone()));
        assert!(
            validate_http_json_metadata(&Value::Object(oversized_value)).is_err(),
            "{field} must reject one byte above the limit"
        );
    }

    for field in ["src", "dst", "label", "protocol"] {
        let flow = flow_with_string_field(field, exact.clone());
        validate_http_json_metadata(&json!({ "flows": [flow] })).expect("exact flow string budget");

        let flow = flow_with_string_field(field, oversized.clone());
        assert!(
            validate_http_json_metadata(&json!({ "flows": [flow] })).is_err(),
            "flows[].{field} must reject one byte above the limit"
        );
    }
}

#[test]
fn aggregate_string_budget_is_inclusive_and_fail_closed() {
    let exact_text = "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES);
    let flows = (0..MAX_CONNECTOR_FLOW_METADATA_ITEMS)
        .map(|_| {
            json!({
                "label": exact_text.clone(),
                "protocol": exact_text.clone(),
                "bytes": 0,
            })
        })
        .collect::<Vec<_>>();
    let exact = json!({ "flows": flows });
    validate_http_json_metadata(&exact).expect("exact aggregate string budget");

    let sensitive = "sensitive-aggregate-sentinel";
    let mut oversized = exact;
    oversized["sample"] = Value::String(sensitive.to_string());
    let message = validate_http_json_metadata(&oversized)
        .expect_err("aggregate string budget plus one must fail")
        .to_string();
    assert!(message.contains("aggregate string size"), "{message}");
    assert!(!message.contains(sensitive), "{message}");
}

#[test]
fn experiment_metadata_is_complete_and_bounded() {
    validate_http_json_metadata(&json!({
        "experiment": {
            "scenario_id": "scenario-1",
            "fault_start": "2026-07-15T00:00:00Z",
            "fault_end": "2026-07-15T00:01:00Z",
            "ground_truth": "normal",
        }
    }))
    .expect("complete experiment metadata");

    let error = validate_http_json_metadata(&json!({
        "experiment": { "scenario_id": "scenario-1" }
    }))
    .expect_err("partial experiment metadata must fail");
    assert!(
        error
            .to_string()
            .contains("experiment.fault_start is required"),
        "{error}"
    );
}

#[test]
fn flows_require_bytes_and_explicit_identity_without_control_characters() {
    for value in [
        json!({ "flows": [{ "label": "client" }] }),
        json!({ "flows": [{ "bytes": 1 }] }),
        json!({ "flows": [{ "src": "client", "bytes": 1 }] }),
        json!({ "flows": [{ "label": "client\nsecret", "bytes": 1 }] }),
    ] {
        let message = validate_http_json_metadata(&value)
            .expect_err("incomplete or unsafe flow metadata must fail")
            .to_string();
        assert!(message.contains("metadata validation failed"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    validate_http_json_metadata(&json!({
        "flows": [{ "src": "client", "dst": "server", "bytes": 1 }]
    }))
    .expect("complete endpoint identity");
}

fn flow_with_string_field(field: &str, value: String) -> Value {
    let mut flow = serde_json::Map::from_iter([
        ("label".to_string(), Value::String("flow".to_string())),
        ("bytes".to_string(), Value::from(1)),
    ]);
    if matches!(field, "src" | "dst") {
        flow.remove("label");
        flow.insert("src".to_string(), Value::String("client".to_string()));
        flow.insert("dst".to_string(), Value::String("server".to_string()));
    }
    flow.insert(field.to_string(), Value::String(value));
    Value::Object(flow)
}

#[test]
fn malformed_metadata_types_fail_without_echoing_response_values() {
    let sensitive = "sensitive-type-sentinel";
    for value in [
        json!({ "sample": { "secret": sensitive } }),
        json!({ "flows": sensitive }),
        json!({ "flows": [{ "label": { "secret": sensitive } }] }),
    ] {
        let message = validate_http_json_metadata(&value)
            .expect_err("malformed metadata must fail closed")
            .to_string();
        assert!(message.contains("metadata validation failed"), "{message}");
        assert!(!message.contains(sensitive), "{message}");
    }
}

#[test]
fn ambiguous_parallel_flow_arrays_are_rejected() {
    let error = validate_http_json_metadata(&json!({
        "flows": [],
        "top_talkers": [],
    }))
    .expect_err("parallel flow arrays must not use implicit precedence");
    assert!(
        error.to_string().contains("cannot both be present"),
        "{error}"
    );
}
