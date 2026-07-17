use super::*;
use crate::{MAX_CONNECTOR_FLOW_METADATA_ITEMS, MAX_CONNECTOR_METADATA_STRING_BYTES};
use serde_json::json;

#[test]
fn bare_array_decodes_records_without_retaining_record_json() {
    let body = serde_json::to_vec(&json!([record()])).expect("bare response");
    let decoded = decode_response(&body).expect("bare record array");

    assert_eq!(decoded.records.len(), 1);
    assert_eq!(decoded.sample, "http_json");
    assert_eq!(decoded.metadata, json!({}));
}

#[test]
fn wrapper_moves_allowlisted_metadata_without_records_or_unknown_fields() {
    let unknown = "x".repeat(4 * 1024 * 1024);
    let body = serde_json::to_vec(&json!({
        "schema": "netdiag-adapter-payload/v1",
        "collection_mode": "sample",
        "sample": "router-window",
        "protocol": "TCP",
        "flow_count": 1,
        "flows": [{ "label": "client", "bytes": 42 }],
        "experiment": {
            "scenario_id": "scenario-1",
            "fault_start": "2026-07-15T00:00:00Z",
            "fault_end": "2026-07-15T00:01:00Z",
            "ground_truth": "normal",
            "unknown_nested": unknown.clone(),
        },
        "unknown_metadata": unknown,
        "records": [record()],
    }))
    .expect("wrapped response");

    let decoded = decode_response(&body).expect("wrapped record response");
    assert_eq!(decoded.records.len(), 1);
    assert_eq!(decoded.sample, "router-window");
    assert!(decoded.metadata.get("records").is_none());
    assert!(decoded.metadata.get("unknown_metadata").is_none());
    assert!(
        decoded.metadata["experiment"]
            .get("unknown_nested")
            .is_none()
    );
    assert_eq!(decoded.metadata["flows"][0]["bytes"], 42);
    assert!(
        serde_json::to_vec(&decoded.metadata)
            .expect("metadata")
            .len()
            < 2 * 1024
    );
}

#[test]
fn wrapper_preserves_only_typed_canonical_measurement_quality() {
    let body = serde_json::to_vec(&json!({
        "schema": "netdiag-adapter-payload/v1",
        "measurement_quality": {
            "retransmission_rate": "missing",
            "retry_events": "estimated",
            "throughput_mbps": "measured"
        },
        "records": [record()],
    }))
    .expect("quality response");

    let decoded = decode_response(&body).expect("typed metric quality");
    assert_eq!(
        decoded.measurement_quality.entries().collect::<Vec<_>>(),
        vec![
            ("retransmission_rate", crate::models::MetricQuality::Missing),
            ("retry_events", crate::models::MetricQuality::Estimated),
            ("throughput_mbps", crate::models::MetricQuality::Measured),
        ]
    );
    assert_eq!(
        decoded.metadata["measurement_quality"],
        json!({
            "retransmission_rate": "missing",
            "retry_events": "estimated",
            "throughput_mbps": "measured"
        })
    );
}

#[test]
fn measurement_quality_rejects_unknown_metrics_nulls_and_untyped_details() {
    for measurement_quality in [
        json!({ "unknown_metric": "missing" }),
        json!({ "retransmission_rate": null }),
        json!({ "retransmission_rate": "unobserved" }),
        json!({ "retransmission_rate": { "quality": "missing" } }),
    ] {
        let sensitive = "quality-sensitive-sentinel";
        let body = serde_json::to_vec(&json!({
            "measurement_quality": measurement_quality,
            "unknown_metadata": sensitive,
            "records": [record()],
        }))
        .expect("invalid quality response");
        let message = decode_response(&body)
            .expect_err("invalid quality must fail closed")
            .to_string();
        assert!(message.contains("required response schema"), "{message}");
        assert!(!message.contains(sensitive), "{message}");
    }
}

#[test]
fn experiment_quality_text_cannot_override_canonical_quality() {
    let body = serde_json::to_vec(&json!({
        "experiment": {
            "scenario_id": "scenario-1",
            "fault_start": "2026-07-15T00:00:00Z",
            "fault_end": "2026-07-15T00:01:00Z",
            "ground_truth": "normal",
            "measurement_quality": { "retransmission_rate": "measured" }
        },
        "measurement_quality": { "retransmission_rate": "missing" },
        "records": [record()],
    }))
    .expect("quality response");

    let decoded = decode_response(&body).expect("typed metric quality");
    assert_eq!(
        decoded.measurement_quality.entries().collect::<Vec<_>>(),
        vec![("retransmission_rate", crate::models::MetricQuality::Missing)]
    );
    assert!(
        decoded.metadata["experiment"]
            .get("measurement_quality")
            .is_none()
    );
}

#[test]
fn flow_item_limit_is_enforced_during_typed_decode() {
    let flows = vec![json!({ "label": "flow", "bytes": 0 }); MAX_CONNECTOR_FLOW_METADATA_ITEMS + 1];
    let body = serde_json::to_vec(&json!({
        "flows": flows,
        "records": [record()],
    }))
    .expect("oversized flow response");

    let error = decode_response(&body).expect_err("flow item limit plus one");
    assert!(error.to_string().contains("flow metadata count"), "{error}");
}

#[test]
fn schema_errors_do_not_echo_known_or_unknown_response_values() {
    let sensitive = "sensitive-decode-sentinel";
    for value in [
        json!({ "sample": { "secret": sensitive }, "records": [record()] }),
        json!({ "records": [{ "timestamp": sensitive }] }),
        json!({ "flows": [{ "label": sensitive, "bytes": "invalid" }], "records": [record()] }),
    ] {
        let body = serde_json::to_vec(&value).expect("invalid response");
        let message = decode_response(&body)
            .expect_err("invalid response schema")
            .to_string();
        assert!(message.contains("required response schema"), "{message}");
        assert!(!message.contains(sensitive), "{message}");
    }
}

#[test]
fn duplicate_known_fields_fail_without_echoing_response_values() {
    let sensitive = "sensitive-duplicate-sentinel";
    let record = serde_json::to_string(&record()).expect("record JSON");
    let body = format!(r#"{{"sample":"{sensitive}","records":[{record}],"records":[{record}]}}"#);

    let message = decode_response(body.as_bytes())
        .expect_err("duplicate records field must fail closed")
        .to_string();

    assert!(message.contains("required response schema"), "{message}");
    assert!(!message.contains(sensitive), "{message}");
}

#[test]
fn response_values_cannot_forge_internal_limit_classification() {
    let forged = format!("{LIMIT_ERROR_MARKER}:{MAX_CONNECTOR_FLOW_METADATA_ITEMS}");
    let body = serde_json::to_vec(&json!({
        "flows": [{ "label": "flow", "bytes": forged }],
        "records": [record()],
    }))
    .expect("forged marker response");

    let message = decode_response(&body)
        .expect_err("wrong bytes type must remain a schema error")
        .to_string();
    assert!(message.contains("required response schema"), "{message}");
    assert!(!message.contains("flow metadata count"), "{message}");
}

#[test]
fn metadata_string_limit_is_not_weakened_by_typed_decode() {
    let oversized = "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES + 1);
    let body = serde_json::to_vec(&json!({
        "sample": oversized,
        "records": [record()],
    }))
    .expect("oversized metadata response");
    let error = decode_response(&body).expect_err("metadata string limit plus one");
    assert!(error.to_string().contains("byte limit"), "{error}");
}

fn record() -> Value {
    json!({
        "timestamp": "2026-07-15T00:00:00Z",
        "latency_ms": 1.0,
        "jitter_ms": 1.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": 0.0,
        "retry_events": 0.0,
        "throughput_mbps": 100.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0
    })
}
