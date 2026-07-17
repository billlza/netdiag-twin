use super::default_prometheus_mapping;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_WIRE_METRIC_NAME_BYTES: usize = 256;
const MAX_PROMETHEUS_QUERY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MetricMappingError {
    #[error("metric mapping contains an unsupported canonical field")]
    UnsupportedCanonicalField,
    #[error("Prometheus query mapping values must be non-empty")]
    EmptyPrometheusQuery,
    #[error("Prometheus query mapping values exceed the 16384-byte limit")]
    PrometheusQueryTooLong,
    #[error("wire metric names must be non-empty and have no surrounding whitespace")]
    InvalidWireMetricName,
    #[error("wire metric names exceed the 256-byte limit")]
    WireMetricNameTooLong,
    #[error("wire metric names must be unique")]
    DuplicateWireMetricName,
}

pub fn validate_prometheus_query_mapping(
    overrides: &BTreeMap<String, String>,
) -> Result<(), MetricMappingError> {
    merge_prometheus_query_mapping(overrides).map(drop)
}

pub fn validate_wire_metric_mapping(
    overrides: &BTreeMap<String, String>,
) -> Result<(), MetricMappingError> {
    merge_wire_metric_mapping(overrides).map(drop)
}

pub(super) fn merge_prometheus_query_mapping(
    overrides: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, MetricMappingError> {
    validate_canonical_fields(overrides)?;
    let mut mapping = default_prometheus_mapping();
    for (canonical, query) in overrides {
        if query.trim().is_empty() {
            return Err(MetricMappingError::EmptyPrometheusQuery);
        }
        if query.len() > MAX_PROMETHEUS_QUERY_BYTES {
            return Err(MetricMappingError::PrometheusQueryTooLong);
        }
        mapping.insert(canonical.clone(), query.clone());
    }
    Ok(mapping)
}

pub(super) fn merge_wire_metric_mapping(
    overrides: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, MetricMappingError> {
    validate_canonical_fields(overrides)?;
    let mut mapping = default_prometheus_mapping();
    for (canonical, wire_name) in overrides {
        if wire_name.is_empty() || wire_name.trim() != wire_name {
            return Err(MetricMappingError::InvalidWireMetricName);
        }
        if wire_name.len() > MAX_WIRE_METRIC_NAME_BYTES {
            return Err(MetricMappingError::WireMetricNameTooLong);
        }
        mapping.insert(canonical.clone(), wire_name.clone());
    }
    let mut wire_names = BTreeSet::new();
    if mapping
        .values()
        .any(|wire_name| !wire_names.insert(wire_name.as_str()))
    {
        return Err(MetricMappingError::DuplicateWireMetricName);
    }
    Ok(mapping)
}

pub(super) fn validate_canonical_fields(
    mapping: &BTreeMap<String, String>,
) -> Result<(), MetricMappingError> {
    let supported = default_prometheus_mapping();
    if mapping.keys().any(|key| !supported.contains_key(key)) {
        return Err(MetricMappingError::UnsupportedCanonicalField);
    }
    Ok(())
}
