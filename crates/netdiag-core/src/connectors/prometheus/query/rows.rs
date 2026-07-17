use super::super::super::{EVENT_METRICS, record_from_values, required_payload_metrics};
use crate::error::{NetdiagError, Result};
use crate::models::{IngestWarning, TraceRecord};
use std::collections::BTreeMap;

pub(in crate::connectors::prometheus) fn complete_query_records(
    row_values: BTreeMap<i64, BTreeMap<String, f64>>,
    warnings: &mut Vec<IngestWarning>,
) -> Result<Vec<TraceRecord>> {
    append_partial_event_warnings(&row_values, warnings);
    let mut dropped_rows = 0usize;
    let mut records = Vec::new();
    for (timestamp_ms, values) in row_values {
        if !required_payload_metrics()
            .iter()
            .all(|metric| values.contains_key(*metric))
        {
            dropped_rows += 1;
            continue;
        }
        records.push(record_from_values(timestamp_ms, &values)?);
    }
    if dropped_rows > 0 {
        warnings.push(IngestWarning {
            row: None,
            column: "timestamp".to_string(),
            reason: format!(
                "Prometheus rows missing required metrics were dropped: {dropped_rows}"
            ),
            fallback: "drop row".to_string(),
        });
    }
    if records.is_empty() {
        return Err(NetdiagError::Connector(
            "Prometheus query_range produced no complete TraceRecord rows".to_string(),
        ));
    }
    Ok(records)
}

fn append_partial_event_warnings(
    row_values: &BTreeMap<i64, BTreeMap<String, f64>>,
    warnings: &mut Vec<IngestWarning>,
) {
    let total_rows = row_values.len();
    for metric in EVENT_METRICS {
        let present_rows = row_values
            .values()
            .filter(|values| values.contains_key(metric))
            .count();
        if present_rows > 0 && present_rows < total_rows {
            warnings.push(IngestWarning {
                row: None,
                column: metric.to_string(),
                reason: format!(
                    "Prometheus query omitted {metric} at {} timestamps",
                    total_rows - present_rows
                ),
                fallback: "0.0".to_string(),
            });
        }
    }
}
