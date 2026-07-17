use super::*;
use chrono::{Duration, TimeZone, Utc};
use netdiag_core::{MAX_CONNECTOR_FLOW_METADATA_ITEMS, MAX_CONNECTOR_METADATA_STRING_BYTES};

#[test]
fn malformed_flow_metadata_is_rejected() {
    let sensitive = "sensitive-flow-value";
    let payload = serde_json::json!({
        "flows": [{"label": "client", "bytes": sensitive}]
    });
    let error = parse_api_flow_summary(&payload, Some("TCP".to_string()))
        .expect_err("malformed flow metadata must not become an empty summary");
    let message = error.to_string();
    assert!(message.contains("unsigned 64-bit integer"), "{message}");
    assert!(!message.contains(sensitive), "{message}");
}

#[test]
fn api_flow_metadata_limits_are_inclusive_and_reject_overflow() {
    let exact_label = "x".repeat(MAX_CONNECTOR_METADATA_STRING_BYTES);
    let exact = (0..MAX_CONNECTOR_FLOW_METADATA_ITEMS)
        .map(|_| {
            serde_json::json!({
                "label": exact_label.clone(),
                "bytes": 0,
            })
        })
        .collect::<Vec<_>>();
    let exact_payload = serde_json::json!({ "flows": exact });
    let summary = parse_api_flow_summary(&exact_payload, Some("TCP".to_string()))
        .expect("exact flow metadata limits");
    assert_eq!(summary.top_talkers.len(), MAX_CONNECTOR_FLOW_METADATA_ITEMS);
    assert_eq!(summary.top_talkers[0].label, exact_label);

    let too_many = vec![serde_json::json!({}); MAX_CONNECTOR_FLOW_METADATA_ITEMS + 1];
    let error = parse_api_flow_summary(
        &serde_json::json!({ "top_talkers": too_many }),
        Some("TCP".to_string()),
    )
    .expect_err("one flow metadata entry above the limit must fail");
    assert!(error.to_string().contains("count"), "{error}");

    let sensitive = "sensitive-label-sentinel";
    let oversized = sensitive.repeat(
        MAX_CONNECTOR_METADATA_STRING_BYTES
            .checked_div(sensitive.len())
            .expect("non-empty sentinel")
            + 1,
    );
    let error = parse_api_flow_summary(
        &serde_json::json!({ "flows": [{ "label": oversized, "bytes": 0 }] }),
        Some("TCP".to_string()),
    )
    .expect_err("one metadata byte above the limit must fail");
    let message = error.to_string();
    assert!(message.contains("byte limit"), "{message}");
    assert!(!message.contains(sensitive), "{message}");
}

#[test]
fn api_flows_never_drop_incomplete_items_or_invent_unknown_identity() {
    for payload in [
        serde_json::json!({ "flows": [{ "label": "client" }] }),
        serde_json::json!({ "flows": [{ "bytes": 1 }] }),
        serde_json::json!({ "flows": [{ "src": "client", "bytes": 1 }] }),
    ] {
        let error = parse_api_flow_summary(&payload, Some("TCP".to_string()))
            .expect_err("incomplete API flow metadata must fail closed");
        assert!(
            error.to_string().contains("metadata validation failed"),
            "{error}"
        );
    }
}

#[test]
fn top_talker_byte_aggregation_distinguishes_empty_zero_boundary_and_overflow() {
    assert_eq!(
        FlowSummary::checked_top_talker_bytes(&[]).expect("empty aggregate"),
        None
    );
    assert_eq!(
        FlowSummary::checked_top_talker_bytes(&[TopTalker {
            label: "zero".to_string(),
            bytes: 0,
        }])
        .expect("known zero-byte aggregate"),
        Some(0)
    );

    let exact = [
        TopTalker {
            label: "maximum".to_string(),
            bytes: u64::MAX,
        },
        TopTalker {
            label: "zero".to_string(),
            bytes: 0,
        },
    ];
    assert_eq!(
        FlowSummary::checked_top_talker_bytes(&exact).expect("exact boundary"),
        Some(u64::MAX)
    );

    let overflowing = [
        TopTalker {
            label: "maximum".to_string(),
            bytes: u64::MAX,
        },
        TopTalker {
            label: "one more".to_string(),
            bytes: 1,
        },
    ];
    let error =
        FlowSummary::checked_top_talker_bytes(&overflowing).expect_err("u64::MAX + 1 must fail");
    assert!(error.to_string().contains("exceeds u64::MAX"), "{error}");
}

#[test]
fn byte_estimation_is_checked_for_zero_huge_and_overflowing_totals() {
    let records = |throughput_mbps: f64, elapsed_ms: i64| {
        let first = record(throughput_mbps);
        let mut second = first.clone();
        second.timestamp += Duration::milliseconds(elapsed_ms);
        [first, second]
    };

    assert_eq!(
        estimate_bytes_from_records(&[]).expect("empty estimate"),
        None
    );
    assert_eq!(
        estimate_bytes_from_records(&records(8.0, 1_000)).expect("normal estimate"),
        Some(1_000_000)
    );
    assert_eq!(
        estimate_bytes_from_records(&records(0.0, 1_000)).expect("known zero estimate"),
        Some(0)
    );

    let huge_bytes = 1_u64 << 63;
    let huge_throughput = huge_bytes as f64 / 125.0;
    assert_eq!(
        estimate_bytes_from_records(&records(huge_throughput, 1)).expect("in-range huge estimate"),
        Some(huge_bytes)
    );

    let overflowing_throughput = 18_446_744_073_709_551_616.0 / 125.0;
    let overflow = estimate_bytes_from_records(&records(overflowing_throughput, 1))
        .expect_err("an estimate above u64::MAX must fail");
    assert!(
        overflow.to_string().contains("exceeds u64::MAX"),
        "{overflow}"
    );

    let non_finite = estimate_bytes_from_records(&records(f64::INFINITY, 1))
        .expect_err("non-finite throughput must fail");
    assert!(
        non_finite.to_string().contains("not finite"),
        "{non_finite}"
    );

    let negative =
        estimate_bytes_from_records(&records(-1.0, 1)).expect_err("negative throughput must fail");
    assert!(negative.to_string().contains("non-negative"), "{negative}");

    let reversed = estimate_bytes_from_records(&records(1.0, -1))
        .expect_err("non-monotonic timestamps must fail");
    assert!(reversed.to_string().contains("precedes"), "{reversed}");
}

#[test]
fn api_flow_count_preserves_values_beyond_the_32_bit_usize_boundary() {
    let flow_count = u64::from(u32::MAX) + 1;
    let payload = serde_json::json!({ "flow_count": flow_count });

    let summary = parse_api_flow_summary(&payload, Some("TCP".to_string()))
        .expect("u64 flow count must remain platform independent");

    assert_eq!(summary.flows, Some(flow_count));
}

#[test]
fn api_flow_summary_exposes_byte_total_overflow() {
    let payload = serde_json::json!({
        "flows": [
            { "label": "maximum", "bytes": u64::MAX },
            { "label": "one-more", "bytes": 1 }
        ]
    });

    let error = parse_api_flow_summary(&payload, Some("TCP".to_string()))
        .expect_err("overflowing API flow bytes must fail the loader");

    assert!(error.to_string().contains("exceeds u64::MAX"), "{error}");
}

fn record(throughput_mbps: f64) -> TraceRecord {
    TraceRecord {
        timestamp: Utc
            .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
            .single()
            .expect("timestamp"),
        latency_ms: 1.0,
        jitter_ms: 1.0,
        packet_loss_rate: 0.0,
        retransmission_rate: 0.0,
        timeout_events: 0.0,
        retry_events: 0.0,
        throughput_mbps,
        dns_failure_events: 0.0,
        tls_failure_events: 0.0,
        quic_blocked_ratio: 0.0,
    }
}
