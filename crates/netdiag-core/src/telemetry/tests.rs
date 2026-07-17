use super::*;

fn record(timestamp_seconds: i64) -> TraceRecord {
    TraceRecord {
        timestamp: Utc
            .timestamp_opt(timestamp_seconds, 0)
            .single()
            .expect("timestamp"),
        latency_ms: 1.0,
        jitter_ms: 1.0,
        packet_loss_rate: 1.0,
        retransmission_rate: 1.0,
        timeout_events: 1.0,
        retry_events: 1.0,
        throughput_mbps: 1.0,
        dns_failure_events: 1.0,
        tls_failure_events: 1.0,
        quic_blocked_ratio: 1.0,
    }
}

#[test]
fn finite_extreme_metrics_remain_finite_when_the_result_is_representable() {
    let mut first = record(0);
    let mut second = record(1);
    for candidate in [&mut first, &mut second] {
        candidate.latency_ms = f64::MAX;
        candidate.jitter_ms = f64::MAX;
        candidate.throughput_mbps = f64::MAX;
    }

    let summary = summarize_telemetry(&[first, second], 5).expect("finite summary");
    let features = extract_features_from_windows(&summary.windows);

    assert!(summary.overall.latency.mean.is_finite());
    assert!(summary.overall.latency.std.is_finite());
    assert!(summary.overall.jitter_ms.mean.is_finite());
    assert!(summary.overall.throughput_mbps.mean.is_finite());
    assert!(features.iter().all(|value| value.is_finite()));
}

#[test]
fn unrepresentable_event_totals_fail_with_metric_context() {
    let mut first = record(0);
    let mut second = record(1);
    first.timeout_events = f64::MAX;
    second.timeout_events = f64::MAX;

    let error =
        summarize_telemetry(&[first, second], 5).expect_err("event aggregation overflow must fail");

    assert!(error.to_string().contains("timeout_events"), "{error}");
    assert!(error.to_string().contains("overflowed"), "{error}");
}

#[test]
fn non_finite_input_is_rejected_before_aggregation() {
    let mut invalid = record(0);
    invalid.throughput_mbps = f64::INFINITY;

    let error = summarize_telemetry(&[invalid], 5).expect_err("infinite input must fail");

    assert!(error.to_string().contains("throughput_mbps"), "{error}");
    assert!(error.to_string().contains("finite"), "{error}");
}

#[test]
fn aggregation_enforces_canonical_ratio_ranges_at_its_public_boundary() {
    let mut exact = record(0);
    exact.packet_loss_rate = 100.0;
    exact.retransmission_rate = 100.0;
    exact.quic_blocked_ratio = 1.0;
    summarize_telemetry(&[exact.clone()], 5).expect("inclusive maxima");
    aggregate_by_window(&[exact.clone()], 5).expect("direct aggregation inclusive maxima");

    for (field, invalid) in [
        (
            "packet_loss_rate",
            TraceRecord {
                packet_loss_rate: 100.000_001,
                ..exact.clone()
            },
        ),
        (
            "retransmission_rate",
            TraceRecord {
                retransmission_rate: 100.000_001,
                ..exact.clone()
            },
        ),
        (
            "quic_blocked_ratio",
            TraceRecord {
                quic_blocked_ratio: 1.000_001,
                ..exact.clone()
            },
        ),
    ] {
        let error = aggregate_by_window(&[invalid], 5)
            .expect_err("aggregation maximum plus epsilon must fail");
        assert!(error.to_string().contains(field), "{error}");
    }
}

#[test]
fn invalid_window_sizes_are_explicit_errors() {
    let records = [record(0)];
    for window_seconds in [0, -1, i64::MAX] {
        let error = summarize_telemetry(&records, window_seconds)
            .expect_err("invalid window size must fail");
        assert!(error.to_string().contains("window size"), "{error}");
    }
}
