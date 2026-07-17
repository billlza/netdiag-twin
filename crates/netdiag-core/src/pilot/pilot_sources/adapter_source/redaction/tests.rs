use super::*;

#[test]
fn opaque_secret_is_removed_from_keys_and_values() {
    let secret = "opaque-sentinel".to_string();
    let mut value = serde_json::json!({
        "ordinary_field": format!("prefix-{secret}-suffix"),
        format!("key-{secret}"): {"nested": secret}
    });

    redact_adapter_value(&mut value, std::slice::from_ref(&secret)).expect("redaction");
    let encoded = serde_json::to_string(&value).expect("json");
    assert!(!encoded.contains(&secret));
    assert!(encoded.contains("[redacted]"));
}

#[test]
fn opaque_secret_cannot_leak_through_contract_or_ingest_errors() {
    let secret = "opaque-contract-sentinel".to_string();
    let mut invalid = serde_json::json!({
        "schema": "netdiag-adapter-payload/v1",
        "collection_mode": secret,
        "sample": "sample",
        "protocol": "test",
        "flow_count": 1,
        "records": [{"timestamp": "2026-01-01T00:00:00Z"}],
        "experiment": {
            "scenario_id": "scenario",
            "fault_start": "2026-01-01T00:00:00Z",
            "fault_end": "2026-01-01T00:00:01Z",
            "ground_truth": "normal"
        }
    });
    redact_adapter_value(&mut invalid, std::slice::from_ref(&secret)).expect("redaction");
    let error = super::super::validate_adapter_payload_contract(
        &invalid,
        crate::pilot::PilotAdapterMode::Sample,
    )
    .expect_err("redacted mode cannot satisfy the sample contract");
    assert!(!error.to_string().contains(&secret));

    let mut ingest_payload = invalid;
    ingest_payload["collection_mode"] = Value::String("sample".to_string());
    let ingest_error = crate::ingest::ingest_json_value(ingest_payload.clone(), "redacted")
        .expect_err("incomplete payload must fail ingestion");
    assert!(!ingest_error.to_string().contains(&secret));
    assert!(
        !serde_json::to_string(&ingest_payload)
            .expect("json")
            .contains(&secret)
    );
}
