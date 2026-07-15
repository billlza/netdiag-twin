use super::buffer::{MAX_BUFFERED_BYTES, MAX_BUFFERED_FRAMES};
use super::projection::{MAX_DECODING_MESSAGE_BYTES, OtlpProjectionSchema};
use super::*;
use opentelemetry_proto::tonic as otlp;
use otlp::common::v1::{AnyValue, ArrayValue, KeyValue, any_value};
use otlp::metrics::v1::{Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric};
use tonic::Code;

mod projection_cases;
mod server_cases;

#[tokio::test]
async fn decoded_message_byte_limit_rejects_without_queueing() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let mut request = numeric_request("netdiag_latency_ms", 1.0, 1);
    request.resource_metrics[0].scope_metrics[0].metrics[0].description =
        "x".repeat(MAX_DECODING_MESSAGE_BYTES + 1);

    let error = receiver
        .export(Request::new(request))
        .await
        .expect_err("oversized decoded request must fail");

    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_queue_unchanged(&buffer, 0, buffer_base_bytes(&buffer));
}

#[tokio::test]
async fn overlong_strings_and_wide_shapes_do_not_enter_queue() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let base_bytes = buffer_base_bytes(&buffer);
    let mut overlong = numeric_request("netdiag_latency_ms", 1.0, 1);
    overlong.resource_metrics[0].scope_metrics[0].metrics[0].description = "x".repeat(1_025);
    let string_error = receiver
        .export(Request::new(overlong))
        .await
        .expect_err("overlong field must fail");
    assert_eq!(string_error.code(), Code::InvalidArgument);
    assert_queue_unchanged(&buffer, 0, base_bytes);

    let mut wide = numeric_request("netdiag_latency_ms", 1.0, 1);
    wide.resource_metrics = vec![ResourceMetrics::default(); 33];
    let shape_error = receiver
        .export(Request::new(wide))
        .await
        .expect_err("wide resource shape must fail");
    assert_eq!(shape_error.code(), Code::ResourceExhausted);
    assert_queue_unchanged(&buffer, 0, base_bytes);
}

#[tokio::test]
async fn deep_attributes_and_excessive_datapoints_do_not_enter_queue() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let base_bytes = buffer_base_bytes(&buffer);
    let mut deep = numeric_request("netdiag_latency_ms", 1.0, 1);
    deep.resource_metrics[0].resource = Some(otlp::resource::v1::Resource {
        attributes: vec![KeyValue {
            key: "nested".to_string(),
            value: Some(nested_array_value(9)),
        }],
        ..Default::default()
    });
    let depth_error = receiver
        .export(Request::new(deep))
        .await
        .expect_err("deep attributes must fail");
    assert_eq!(depth_error.code(), Code::InvalidArgument);
    assert_queue_unchanged(&buffer, 0, base_bytes);

    let mut many_points = numeric_request("netdiag_latency_ms", 1.0, 1);
    many_points.resource_metrics[0].scope_metrics[0].metrics[0].data =
        Some(metric::Data::Gauge(otlp::metrics::v1::Gauge {
            data_points: vec![NumberDataPoint::default(); 4_097],
        }));
    let point_error = receiver
        .export(Request::new(many_points))
        .await
        .expect_err("excessive datapoints must fail");
    assert_eq!(point_error.code(), Code::ResourceExhausted);
    assert_queue_unchanged(&buffer, 0, base_bytes);
}

#[tokio::test]
async fn frame_capacity_is_fail_closed_without_eviction() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    for timestamp in 0..MAX_BUFFERED_FRAMES {
        receiver
            .export(Request::new(complete_numeric_request(timestamp as u64 + 1)))
            .await
            .expect("frame within capacity");
    }
    let before = buffer_state(&buffer);
    let error = receiver
        .export(Request::new(complete_numeric_request(999)))
        .await
        .expect_err("frame above capacity must fail");

    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(before.0, MAX_BUFFERED_FRAMES);
    assert_queue_unchanged(&buffer, before.0, before.1);
    assert!(before.1 <= MAX_BUFFERED_BYTES);
}

fn receiver(
    mapping: BTreeMap<String, String>,
) -> (OtlpMetricsReceiver, Arc<Mutex<OtlpFrameBuffer>>) {
    let schema = Arc::new(OtlpProjectionSchema::new(mapping).expect("test mapping"));
    let buffer = Arc::new(Mutex::new(OtlpFrameBuffer::default()));
    (
        OtlpMetricsReceiver {
            buffer: Arc::clone(&buffer),
            schema,
        },
        buffer,
    )
}

fn default_mapping_schema() -> BTreeMap<String, String> {
    super::super::default_prometheus_mapping()
}

fn numeric_request(name: &str, value: f64, timestamp: u64) -> ExportMetricsServiceRequest {
    request_with_metrics(vec![numeric_metric(name, value, timestamp)])
}

fn complete_numeric_request(timestamp: u64) -> ExportMetricsServiceRequest {
    request_with_metrics(vec![
        numeric_metric("netdiag_latency_ms", 1.0, timestamp),
        numeric_metric("netdiag_jitter_ms", 2.0, timestamp),
        numeric_metric("netdiag_packet_loss_rate", 0.01, timestamp),
        numeric_metric("netdiag_retransmission_rate", 0.02, timestamp),
        numeric_metric("netdiag_throughput_mbps", 100.0, timestamp),
    ])
}

fn request_with_metrics(metrics: Vec<Metric>) -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            scope_metrics: vec![ScopeMetrics {
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

fn numeric_metric(name: &str, value: f64, timestamp: u64) -> Metric {
    Metric {
        name: name.to_string(),
        data: Some(metric::Data::Gauge(otlp::metrics::v1::Gauge {
            data_points: vec![NumberDataPoint {
                time_unix_nano: timestamp,
                value: Some(otlp::metrics::v1::number_data_point::Value::AsDouble(value)),
                ..Default::default()
            }],
        })),
        ..Default::default()
    }
}

fn nested_array_value(depth: usize) -> AnyValue {
    if depth == 0 {
        return AnyValue {
            value: Some(any_value::Value::StringValue("leaf".to_string())),
        };
    }
    AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue {
            values: vec![nested_array_value(depth - 1)],
        })),
    }
}

fn buffer_state(buffer: &Arc<Mutex<OtlpFrameBuffer>>) -> (usize, usize) {
    let buffer = buffer.lock().expect("test receiver buffer");
    (buffer.len(), buffer.retained_bytes())
}

fn buffer_base_bytes(buffer: &Arc<Mutex<OtlpFrameBuffer>>) -> usize {
    buffer_state(buffer).1
}

fn assert_queue_unchanged(
    buffer: &Arc<Mutex<OtlpFrameBuffer>>,
    expected_frames: usize,
    expected_bytes: usize,
) {
    assert_eq!(buffer_state(buffer), (expected_frames, expected_bytes));
}
