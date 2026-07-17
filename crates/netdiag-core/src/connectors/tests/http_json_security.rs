use super::super::*;
use crate::{MAX_CONNECTOR_FLOW_METADATA_ITEMS, MAX_CONNECTOR_METADATA_STRING_BYTES};
use std::time::Duration;

#[test]
fn http_json_schema_errors_never_echo_response_values() {
    let secret = "secret-sentinel-7f2c";
    let body = serde_json::json!({
        "records": [{
            "timestamp": "2026-07-15T00:00:00Z",
            "latency_ms": secret,
            "jitter_ms": 1.0,
            "packet_loss_rate": 0.0,
            "retransmission_rate": 0.0,
            "timeout_events": 0.0,
            "retry_events": 0.0,
            "throughput_mbps": 100.0,
            "dns_failure_events": 0.0,
            "tls_failure_events": 0.0,
            "quic_blocked_ratio": 0.0
        }]
    })
    .to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, body, None);

    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect_err("invalid TraceRecord field type must fail closed");
    handle.join().expect("server thread");

    let message = error.to_string();
    assert!(message.contains("required response schema"));
    assert!(!message.contains(secret));
}

#[test]
fn http_json_metadata_limits_are_enforced_before_payload_is_returned() {
    let exact_sample = "s".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES);
    let exact_flows =
        vec![serde_json::json!({ "label": "flow", "bytes": 0 }); MAX_CONNECTOR_FLOW_METADATA_ITEMS];
    let exact_body = serde_json::json!({
        "sample": exact_sample.clone(),
        "flows": exact_flows,
        "records": [valid_record()],
    })
    .to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, exact_body, None);
    let loaded = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("exact metadata limits must be accepted");
    handle.join().expect("server thread");
    assert_eq!(loaded.sample, exact_sample);
    let metadata = loaded.payload.expect("bounded metadata payload");
    assert!(metadata.get("records").is_none());
    assert_eq!(
        metadata["flows"].as_array().map(Vec::len),
        Some(MAX_CONNECTOR_FLOW_METADATA_ITEMS)
    );

    let sensitive = "metadata-secret-sentinel";
    let oversized_sample = sensitive.repeat(
        MAX_CONNECTOR_METADATA_STRING_BYTES
            .checked_div(sensitive.len())
            .expect("non-empty sentinel")
            + 1,
    );
    let oversized_flows = vec![serde_json::json!({}); MAX_CONNECTOR_FLOW_METADATA_ITEMS + 1];
    for body in [
        serde_json::json!({ "sample": oversized_sample, "records": [valid_record()] }),
        serde_json::json!({ "flows": oversized_flows, "records": [valid_record()] }),
        serde_json::json!({ "sample": { "secret": sensitive }, "records": [valid_record()] }),
        serde_json::json!({
            "flows": [{ "label": sensitive }],
            "records": [valid_record()]
        }),
        serde_json::json!({
            "flows": [{ "bytes": 1 }],
            "records": [valid_record()]
        }),
    ] {
        let (url, handle) = super::http_prometheus::serve_once(200, body.to_string(), None);
        let message = load_http_json(
            &HttpJsonConfig {
                endpoint: url,
                timeout: Duration::from_secs(2),
            },
            None,
        )
        .expect_err("invalid metadata must fail instead of falling back")
        .to_string();
        handle.join().expect("server thread");
        assert!(
            message.contains("HTTP/JSON")
                && (message.contains("metadata validation failed")
                    || message.contains("required response schema")),
            "{message}"
        );
        assert!(!message.contains(sensitive), "{message}");
    }
}

#[test]
fn http_json_discards_unknown_metadata_and_record_dom_after_single_decode() {
    let body = serde_json::json!({
        "sample": "bounded-metadata",
        "unknown_blob": "x".repeat(4 * 1024 * 1024),
        "records": [valid_record()],
    })
    .to_string();
    let input_bytes = u64::try_from(body.len()).expect("body size");
    let (url, handle) = super::http_prometheus::serve_once(200, body, None);

    let loaded = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("unknown metadata must be skipped without retaining its DOM");
    handle.join().expect("server thread");

    assert_eq!(loaded.resource_usage.input_bytes, input_bytes);
    assert_eq!(loaded.ingest.records.len(), 1);
    let metadata = loaded.payload.expect("metadata payload");
    assert_eq!(
        metadata,
        serde_json::json!({ "sample": "bounded-metadata" })
    );
}

#[test]
fn adapter_envelope_quality_distinguishes_missing_from_measured_zero() {
    let body = serde_json::json!({
        "schema": "netdiag-adapter-payload/v1",
        "sample": "iperf-quality",
        "measurement_quality": {
            "retransmission_rate": "missing",
            "retry_events": "estimated",
            "throughput_mbps": "measured"
        },
        "records": [valid_record()],
    })
    .to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, body, None);
    let loaded = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("typed adapter quality");
    handle.join().expect("server thread");

    assert_eq!(
        super::quality(&loaded.ingest, "retransmission_rate"),
        MetricQuality::Missing
    );
    assert_eq!(
        super::quality(&loaded.ingest, "retry_events"),
        MetricQuality::Estimated
    );
    assert_eq!(
        super::quality(&loaded.ingest, "throughput_mbps"),
        MetricQuality::Measured
    );
    assert_eq!(
        super::quality(&loaded.ingest, "latency_ms"),
        MetricQuality::Missing,
        "undeclared adapter metrics must fail closed"
    );

    let generic_body = serde_json::json!({ "records": [valid_record()] }).to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, generic_body, None);
    let generic = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("generic HTTP records");
    handle.join().expect("server thread");
    assert_eq!(
        super::quality(&generic.ingest, "retransmission_rate"),
        MetricQuality::Measured,
        "an explicit generic numeric zero remains distinct from adapter missingness"
    );
}

#[test]
fn adapter_v2_requires_complete_quality_before_returning_records() {
    let partial = serde_json::json!({
        "schema": "netdiag-adapter-payload/v2",
        "measurement_quality": { "throughput_mbps": "measured" },
        "records": [valid_record()],
    })
    .to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, partial, None);
    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect_err("partial v2 quality must fail closed");
    handle.join().expect("server thread");
    assert!(error.to_string().contains("requires measurement_quality"));

    let complete = serde_json::json!({
        "schema": "netdiag-adapter-payload/v2",
        "measurement_quality": complete_measurement_quality(),
        "records": [valid_record()],
    })
    .to_string();
    let (url, handle) = super::http_prometheus::serve_once(200, complete, None);
    let loaded = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("complete v2 quality");
    handle.join().expect("server thread");
    assert_eq!(
        super::quality(&loaded.ingest, "retransmission_rate"),
        MetricQuality::Missing
    );
}

fn valid_record() -> serde_json::Value {
    serde_json::json!({
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

fn complete_measurement_quality() -> serde_json::Value {
    serde_json::json!({
        "latency_ms": "measured",
        "jitter_ms": "measured",
        "packet_loss_rate": "measured",
        "retransmission_rate": "missing",
        "timeout_events": "missing",
        "retry_events": "estimated",
        "throughput_mbps": "measured",
        "dns_failure_events": "missing",
        "tls_failure_events": "missing",
        "quic_blocked_ratio": "missing"
    })
}
