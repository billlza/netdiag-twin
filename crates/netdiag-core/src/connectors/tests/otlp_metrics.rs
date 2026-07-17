use super::super::*;
use opentelemetry_proto::tonic as otlp;
use otlp::collector::metrics::v1::ExportMetricsServiceRequest;
use otlp::metrics::v1::{Metric, metric, number_data_point};

#[test]
fn otlp_receiver_rejects_unbounded_timeout_before_binding() {
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        let error = OtlpReceiverSession::start(&OtlpGrpcReceiverConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            timeout,
            metrics: default_prometheus_mapping(),
            sample: "invalid-timeout".to_string(),
        })
        .expect_err("invalid timeout must fail before listener startup");
        assert!(error.to_string().contains("between 1 and 300"));
    }
}

#[test]
fn otlp_receiver_rejects_duplicate_wire_metric_names_without_disclosure() {
    let sensitive_wire_name = "private-tenant-metric-name";
    let error = OtlpReceiverSession::start(&OtlpGrpcReceiverConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        timeout: Duration::from_secs(1),
        metrics: BTreeMap::from([
            ("latency_ms".to_string(), sensitive_wire_name.to_string()),
            ("jitter_ms".to_string(), sensitive_wire_name.to_string()),
        ]),
        sample: "duplicate-mapping".to_string(),
    })
    .expect_err("duplicate wire metric names must fail before listener startup");
    let message = error.to_string();
    assert!(message.contains("wire metric names must be unique"));
    assert!(!message.contains(sensitive_wire_name));
}

#[test]
fn otlp_metrics_parse_required_matrix_and_warn_for_optional_events() {
    let timestamp = 1_777_000_000_000_000_000;
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![otlp::metrics::v1::ResourceMetrics {
            scope_metrics: vec![otlp::metrics::v1::ScopeMetrics {
                metrics: vec![
                    otlp_metric("netdiag_latency_ms", 41.0, timestamp),
                    otlp_metric("netdiag_jitter_ms", 2.0, timestamp),
                    otlp_metric("netdiag_packet_loss_rate", 0.1, timestamp),
                    otlp_metric("netdiag_retransmission_rate", 0.3, timestamp),
                    otlp_metric("netdiag_throughput_mbps", 88.0, timestamp),
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let (values, timestamp_ms) =
        parse_otlp_metrics_request(&request, &default_prometheus_mapping()).expect("otlp values");
    let warnings = fallback_warnings_for_missing_events(&values, "OTLP metric is missing");

    assert_eq!(values["latency_ms"], 41.0);
    assert_eq!(timestamp_ms, (timestamp / 1_000_000) as i64);
    assert_eq!(warnings.len(), EVENT_METRICS.len());
}

#[test]
fn otlp_metrics_use_latest_numeric_sum_point() {
    let early = 1_777_000_000_000_000_000;
    let late = early + 1_000_000;
    let request = ExportMetricsServiceRequest {
        resource_metrics: vec![otlp::metrics::v1::ResourceMetrics {
            scope_metrics: vec![otlp::metrics::v1::ScopeMetrics {
                metrics: vec![otlp_sum_metric("netdiag_latency_ms", 40, early, 42, late)],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let (values, timestamp_ms) =
        parse_otlp_metrics_request(&request, &default_prometheus_mapping()).expect("otlp values");

    assert_eq!(values["latency_ms"], 42.0);
    assert_eq!(timestamp_ms, (late / 1_000_000) as i64);
}

fn otlp_metric(name: &str, value: f64, timestamp: u64) -> Metric {
    Metric {
        name: name.to_string(),
        data: Some(metric::Data::Gauge(otlp::metrics::v1::Gauge {
            data_points: vec![otlp::metrics::v1::NumberDataPoint {
                time_unix_nano: timestamp,
                value: Some(number_data_point::Value::AsDouble(value)),
                ..Default::default()
            }],
        })),
        ..Default::default()
    }
}

fn otlp_sum_metric(
    name: &str,
    early_value: i64,
    early_timestamp: u64,
    late_value: i64,
    late_timestamp: u64,
) -> Metric {
    Metric {
        name: name.to_string(),
        data: Some(metric::Data::Sum(otlp::metrics::v1::Sum {
            data_points: vec![
                otlp::metrics::v1::NumberDataPoint {
                    time_unix_nano: early_timestamp,
                    value: Some(number_data_point::Value::AsInt(early_value)),
                    ..Default::default()
                },
                otlp::metrics::v1::NumberDataPoint {
                    time_unix_nano: late_timestamp,
                    value: Some(number_data_point::Value::AsInt(late_value)),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })),
        ..Default::default()
    }
}
