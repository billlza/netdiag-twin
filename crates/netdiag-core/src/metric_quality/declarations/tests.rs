use super::*;
use serde_json::json;

fn complete_quality() -> Value {
    json!({
        "latency_ms": "measured",
        "jitter_ms": "measured",
        "packet_loss_rate": "fallback",
        "retransmission_rate": "missing",
        "timeout_events": "missing",
        "retry_events": "estimated",
        "throughput_mbps": "measured",
        "dns_failure_events": "missing",
        "tls_failure_events": "missing",
        "quic_blocked_ratio": "missing"
    })
}

#[test]
fn v2_requires_complete_quality_while_v1_compatibility_fails_closed() {
    let complete_payload = json!({ "measurement_quality": complete_quality() });
    let complete = MetricQualityDeclarations::from_payload(&complete_payload).expect("complete");
    assert_eq!(
        metric_quality_policy_for_schema(Some(ADAPTER_PAYLOAD_SCHEMA_V2), &complete)
            .expect("v2 complete"),
        UndeclaredMetricPolicy::Missing
    );

    let partial_payload = json!({
        "measurement_quality": { "throughput_mbps": "measured" }
    });
    let partial = MetricQualityDeclarations::from_payload(&partial_payload).expect("partial");
    assert!(metric_quality_policy_for_schema(Some(ADAPTER_PAYLOAD_SCHEMA_V2), &partial).is_err());
    assert_eq!(
        metric_quality_policy_for_schema(Some(ADAPTER_PAYLOAD_SCHEMA_V1), &partial)
            .expect("v1 compatibility"),
        UndeclaredMetricPolicy::Missing
    );
    assert_eq!(
        metric_quality_policy_for_schema(None, &partial).expect("generic HTTP"),
        UndeclaredMetricPolicy::Preserve
    );
}

#[test]
fn declarations_reject_unknown_metrics_values_and_nulls_without_echoing_them() {
    let sensitive = "quality-sensitive-sentinel";
    for measurement_quality in [
        json!({ (sensitive): "missing" }),
        json!({ "latency_ms": sensitive }),
        json!({ "latency_ms": null }),
    ] {
        let error = MetricQualityDeclarations::from_payload(
            &json!({ "measurement_quality": measurement_quality }),
        )
        .expect_err("invalid declaration");
        assert!(!error.to_string().contains(sensitive), "{error}");
    }
}
