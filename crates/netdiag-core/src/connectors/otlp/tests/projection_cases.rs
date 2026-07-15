use super::*;

#[tokio::test]
async fn incomplete_observation_is_rejected_before_queueing() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let base_bytes = buffer_base_bytes(&buffer);
    let error = receiver
        .export(Request::new(numeric_request("netdiag_latency_ms", 1.0, 1)))
        .await
        .expect_err("incomplete observation must fail");

    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(error.message().contains("missing"));
    assert_queue_unchanged(&buffer, 0, base_bytes);
}

#[tokio::test]
async fn largest_exact_integer_value_is_accepted() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let mut request = complete_numeric_request(10);
    numeric_points_mut(&mut request.resource_metrics[0].scope_metrics[0].metrics[0])[0].value =
        Some(otlp::metrics::v1::number_data_point::Value::AsInt(
            9_007_199_254_740_992,
        ));

    receiver
        .export(Request::new(request))
        .await
        .expect("largest exactly representable integer must be accepted");
    assert_eq!(buffer_state(&buffer).0, 1);
}

#[tokio::test]
async fn cross_resource_and_cross_series_observations_are_rejected_without_disclosure() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let base_bytes = buffer_base_bytes(&buffer);
    let sensitive = "private-tenant-value";

    let mut cross_resource = complete_numeric_request(10);
    let throughput = cross_resource.resource_metrics[0].scope_metrics[0]
        .metrics
        .pop()
        .expect("throughput metric");
    cross_resource.resource_metrics.push(ResourceMetrics {
        resource: Some(otlp::resource::v1::Resource {
            attributes: vec![text_attribute("tenant", sensitive)],
            ..Default::default()
        }),
        scope_metrics: vec![ScopeMetrics {
            metrics: vec![throughput],
            ..Default::default()
        }],
        ..Default::default()
    });
    assert_rejected_without_queueing(
        &receiver,
        &buffer,
        base_bytes,
        cross_resource,
        "observation context",
        sensitive,
    )
    .await;

    let mut cross_scope = complete_numeric_request(10);
    let throughput = cross_scope.resource_metrics[0].scope_metrics[0]
        .metrics
        .pop()
        .expect("throughput metric");
    cross_scope.resource_metrics[0]
        .scope_metrics
        .push(ScopeMetrics {
            metrics: vec![throughput],
            ..Default::default()
        });
    assert_rejected_without_queueing(
        &receiver,
        &buffer,
        base_bytes,
        cross_scope,
        "observation context",
        sensitive,
    )
    .await;

    let mut cross_series = complete_numeric_request(10);
    for (index, metric) in cross_series.resource_metrics[0].scope_metrics[0]
        .metrics
        .iter_mut()
        .enumerate()
    {
        let point = numeric_points_mut(metric)
            .first_mut()
            .expect("numeric data point");
        point.attributes = vec![text_attribute(
            "tenant",
            if index == 0 { "tenant-a" } else { sensitive },
        )];
    }
    assert_rejected_without_queueing(
        &receiver,
        &buffer,
        base_bytes,
        cross_series,
        "observation context",
        sensitive,
    )
    .await;
}

#[tokio::test]
async fn ambiguous_or_invalid_numeric_series_never_enter_the_queue() {
    let (receiver, buffer) = receiver(default_mapping_schema());
    let base_bytes = buffer_base_bytes(&buffer);

    let mut duplicate_timestamp = complete_numeric_request(10);
    let latency = &mut duplicate_timestamp.resource_metrics[0].scope_metrics[0].metrics[0];
    let duplicate = numeric_points_mut(latency)[0].clone();
    numeric_points_mut(latency).push(duplicate);

    let mut inconsistent_timestamp = complete_numeric_request(10);
    numeric_points_mut(
        &mut inconsistent_timestamp.resource_metrics[0].scope_metrics[0].metrics[0],
    )[0]
    .time_unix_nano = 11;

    let mut mixed_series = complete_numeric_request(10);
    let latency = &mut mixed_series.resource_metrics[0].scope_metrics[0].metrics[0];
    let mut second = numeric_points_mut(latency)[0].clone();
    second.time_unix_nano = 11;
    second.attributes = vec![text_attribute("series", "two")];
    numeric_points_mut(latency).push(second);

    let mut negative_value = complete_numeric_request(10);
    numeric_points_mut(&mut negative_value.resource_metrics[0].scope_metrics[0].metrics[0])[0]
        .value = Some(otlp::metrics::v1::number_data_point::Value::AsDouble(-1.0));

    let mut imprecise_integer = complete_numeric_request(10);
    numeric_points_mut(&mut imprecise_integer.resource_metrics[0].scope_metrics[0].metrics[0])[0]
        .value = Some(otlp::metrics::v1::number_data_point::Value::AsInt(
        9_007_199_254_740_993,
    ));

    let mut duplicate_attribute = complete_numeric_request(10);
    numeric_points_mut(&mut duplicate_attribute.resource_metrics[0].scope_metrics[0].metrics[0])
        [0]
    .attributes = vec![text_attribute("tenant", "a"), text_attribute("tenant", "b")];

    let mut unsupported_data = complete_numeric_request(10);
    unsupported_data.resource_metrics[0].scope_metrics[0].metrics[0].data = Some(
        metric::Data::Histogram(otlp::metrics::v1::Histogram::default()),
    );

    for (request, expected) in [
        (duplicate_timestamp, "duplicate data point timestamps"),
        (inconsistent_timestamp, "consistent observation timestamp"),
        (mixed_series, "multiple attribute series"),
        (negative_value, "finite and non-negative"),
        (imprecise_integer, "exactly representable"),
        (duplicate_attribute, "duplicate attribute keys"),
        (unsupported_data, "numeric Gauge or Sum"),
    ] {
        assert_rejected_without_queueing(
            &receiver,
            &buffer,
            base_bytes,
            request,
            expected,
            "never-present-secret",
        )
        .await;
    }
}

async fn assert_rejected_without_queueing(
    receiver: &OtlpMetricsReceiver,
    buffer: &Arc<Mutex<OtlpFrameBuffer>>,
    base_bytes: usize,
    request: ExportMetricsServiceRequest,
    expected: &str,
    sensitive: &str,
) {
    let error = receiver
        .export(Request::new(request))
        .await
        .expect_err("ambiguous OTLP observation must fail");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(error.message().contains(expected));
    assert!(!error.message().contains(sensitive));
    assert_queue_unchanged(buffer, 0, base_bytes);
}

fn numeric_points_mut(metric: &mut Metric) -> &mut Vec<NumberDataPoint> {
    match metric.data.as_mut().expect("metric data") {
        metric::Data::Gauge(gauge) => &mut gauge.data_points,
        metric::Data::Sum(sum) => &mut sum.data_points,
        _ => panic!("test metric must be numeric"),
    }
}

fn text_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
    }
}
