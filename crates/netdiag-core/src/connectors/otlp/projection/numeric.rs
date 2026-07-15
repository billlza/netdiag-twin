use super::budget::RequestShapeBudget;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::metrics::v1::{NumberDataPoint, metric, number_data_point};
use std::collections::{BTreeMap, BTreeSet};
use tonic::Status;

const MAX_EXACT_F64_INTEGER: i64 = 9_007_199_254_740_992;

#[derive(Debug)]
pub(super) struct MappedNumericProjection {
    pub(super) value: f64,
    pub(super) timestamp: u64,
    pub(super) attributes: Box<[KeyValue]>,
}

pub(super) fn validate_mapped_metric_data(
    budget: &mut RequestShapeBudget,
    data: Option<&metric::Data>,
) -> Result<MappedNumericProjection, Status> {
    let points = match data {
        Some(metric::Data::Gauge(gauge)) => &gauge.data_points,
        Some(metric::Data::Sum(sum)) => &sum.data_points,
        Some(_) => {
            return Err(Status::invalid_argument(
                "mapped OTLP metrics must use numeric Gauge or Sum data",
            ));
        }
        None => {
            return Err(Status::invalid_argument(
                "mapped OTLP metric has no recorded data",
            ));
        }
    };
    budget.reserve_data_points(points.len())?;
    if points.is_empty() {
        return Err(Status::invalid_argument(
            "mapped OTLP metrics must contain at least one numeric data point",
        ));
    }
    let expected_attributes = canonical_attributes(&points[0].attributes)?;
    let mut timestamps = BTreeSet::new();
    let mut latest = None;
    for point in points {
        budget.validate_attributes(&point.attributes)?;
        budget.validate_exemplars(&point.exemplars)?;
        if canonical_attributes(&point.attributes)? != expected_attributes {
            return Err(Status::invalid_argument(
                "mapped OTLP metric contains multiple attribute series",
            ));
        }
        let (value, timestamp) = number_point_value(point)?.ok_or_else(|| {
            Status::invalid_argument("mapped OTLP numeric data point has no recorded value")
        })?;
        if !value.is_finite() || value < 0.0 {
            return Err(Status::invalid_argument(
                "mapped OTLP numeric data must be finite and non-negative",
            ));
        }
        if points.len() > 1 && timestamp == 0 {
            return Err(Status::invalid_argument(
                "multi-point mapped OTLP metrics require explicit timestamps",
            ));
        }
        if !timestamps.insert(timestamp) {
            return Err(Status::invalid_argument(
                "mapped OTLP metric contains duplicate data point timestamps",
            ));
        }
        if latest.is_none_or(|(_, latest_timestamp)| timestamp > latest_timestamp) {
            latest = Some((value, timestamp));
        }
    }
    let (value, timestamp) = latest.ok_or_else(|| {
        Status::invalid_argument("mapped OTLP metric has no usable numeric data point")
    })?;
    Ok(MappedNumericProjection {
        value,
        timestamp,
        attributes: expected_attributes,
    })
}

fn number_point_value(point: &NumberDataPoint) -> Result<Option<(f64, u64)>, Status> {
    let Some(value) = point.value.as_ref() else {
        return Ok(None);
    };
    let value = match value {
        number_data_point::Value::AsDouble(value) => *value,
        number_data_point::Value::AsInt(value) if (0..=MAX_EXACT_F64_INTEGER).contains(value) => {
            *value as f64
        }
        number_data_point::Value::AsInt(_) => {
            return Err(Status::invalid_argument(
                "mapped OTLP integer data must be non-negative and exactly representable",
            ));
        }
    };
    Ok(Some((value, point.time_unix_nano)))
}

fn canonical_attributes(attributes: &[KeyValue]) -> Result<Box<[KeyValue]>, Status> {
    let mut canonical = BTreeMap::new();
    for attribute in attributes {
        if canonical
            .insert(attribute.key.as_str(), attribute)
            .is_some()
        {
            return Err(Status::invalid_argument(
                "OTLP data point contains duplicate attribute keys",
            ));
        }
    }
    Ok(canonical
        .into_values()
        .cloned()
        .collect::<Vec<_>>()
        .into_boxed_slice())
}
