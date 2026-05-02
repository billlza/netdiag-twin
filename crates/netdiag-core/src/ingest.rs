use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    IngestResult, IngestWarning, MetricProvenance, MetricQuality, TraceRecord, TraceSchema,
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub const CANONICAL_COLUMNS: [&str; 11] = [
    "timestamp",
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "timeout_events",
    "retry_events",
    "throughput_mbps",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
];

const REQUIRED_COLUMNS: [&str; 6] = [
    "timestamp",
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "throughput_mbps",
];

const EVENT_COLUMNS: [&str; 5] = [
    "timeout_events",
    "retry_events",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
];

fn alias(column: &str) -> String {
    match column.trim().to_ascii_lowercase().as_str() {
        "time" | "ts" => "timestamp".to_string(),
        "latency" | "rtt_ms" => "latency_ms".to_string(),
        "jitter" => "jitter_ms".to_string(),
        "loss" | "loss_rate" => "packet_loss_rate".to_string(),
        "retrans" => "retransmission_rate".to_string(),
        "throughput" => "throughput_mbps".to_string(),
        "dns_errors" => "dns_failure_events".to_string(),
        "tls_errors" => "tls_failure_events".to_string(),
        "quic_blocked" => "quic_blocked_ratio".to_string(),
        other => other.to_string(),
    }
}

#[derive(Debug, Default)]
struct RawRecord {
    timestamp: Option<String>,
    values: HashMap<&'static str, String>,
}

#[derive(Debug)]
struct RawTrace {
    rows: Vec<RawRecord>,
    present_columns: Vec<&'static str>,
    warnings: Vec<IngestWarning>,
}

pub fn ingest_trace(path: impl AsRef<Path>) -> Result<IngestResult> {
    let path = path.as_ref();
    let sample = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("uploaded")
        .to_string();
    let raw_trace = if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        load_json(path)?
    } else {
        load_csv(path)?
    };
    normalize(raw_trace, sample)
}

pub fn build_ingest_result(
    records: Vec<TraceRecord>,
    sample: impl Into<String>,
) -> Result<IngestResult> {
    if records.is_empty() {
        return Err(NetdiagError::EmptyTrace);
    }
    let start_time = records
        .iter()
        .map(|record| record.timestamp)
        .min()
        .ok_or(NetdiagError::EmptyTrace)?;
    let end_time = records
        .iter()
        .map(|record| record.timestamp)
        .max()
        .ok_or(NetdiagError::EmptyTrace)?;
    validate_records(&records)?;
    let schema = TraceSchema {
        columns: CANONICAL_COLUMNS
            .iter()
            .map(|column| (*column).to_string())
            .collect(),
        rows: records.len(),
        start_time,
        end_time,
        sample: sample.into(),
        ingested_at: Utc::now(),
    };
    Ok(IngestResult {
        records,
        schema,
        warnings: Vec::new(),
        metric_provenance: measured_metric_provenance("ingest"),
    })
}

pub fn measured_metric_provenance(source: &str) -> Vec<MetricProvenance> {
    CANONICAL_COLUMNS
        .iter()
        .filter(|column| **column != "timestamp")
        .map(|column| MetricProvenance {
            field: (*column).to_string(),
            quality: MetricQuality::Measured,
            source: source.to_string(),
            reason: "provided by source payload".to_string(),
        })
        .collect()
}

pub fn finalize_warning_metric_provenance(ingest: &mut IngestResult, source: &str) {
    let warnings = ingest.warnings.clone();
    for warning in warnings {
        set_metric_provenance(
            ingest,
            &warning.column,
            MetricQuality::Fallback,
            source,
            &warning.reason,
        );
    }
}

pub fn set_metric_provenance(
    ingest: &mut IngestResult,
    field: &str,
    quality: MetricQuality,
    source: &str,
    reason: &str,
) {
    if field == "timestamp" {
        return;
    }
    if let Some(item) = ingest
        .metric_provenance
        .iter_mut()
        .find(|item| item.field == field)
    {
        item.quality = quality;
        item.source = source.to_string();
        item.reason = reason.to_string();
        return;
    }
    ingest.metric_provenance.push(MetricProvenance {
        field: field.to_string(),
        quality,
        source: source.to_string(),
        reason: reason.to_string(),
    });
}

fn load_csv(path: &Path) -> Result<RawTrace> {
    let file = File::open(path).with_path(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(BufReader::new(file));
    let headers = reader.headers()?.clone();
    let canonical: Vec<String> = headers.iter().map(alias).collect();
    let present_columns = present_columns(&canonical);
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record?;
        let mut row = RawRecord::default();
        for (idx, value) in record.iter().enumerate() {
            let Some(column) = canonical.get(idx).map(String::as_str) else {
                continue;
            };
            if column == "timestamp" {
                row.timestamp = Some(value.to_string());
            } else if let Some(name) = canonical_metric(column) {
                row.values.insert(name, value.to_string());
            }
        }
        rows.push(row);
    }
    Ok(RawTrace {
        rows,
        present_columns,
        warnings: Vec::new(),
    })
}

fn load_json(path: &Path) -> Result<RawTrace> {
    let file = File::open(path).with_path(path)?;
    let value: Value = serde_json::from_reader(BufReader::new(file))?;
    let rows = match value {
        Value::Array(items) => items,
        Value::Object(mut object) => object
            .remove("records")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let mut records = Vec::new();
    let mut present_columns = Vec::new();
    for item in rows {
        let mut row = RawRecord::default();
        let Value::Object(object) = item else {
            continue;
        };
        for (column, value) in object {
            let canonical = alias(&column);
            if canonical == "timestamp" {
                row.timestamp = match value {
                    Value::String(text) => Some(text),
                    _ => None,
                };
                add_present_column(&mut present_columns, "timestamp");
            } else if let Some(name) = canonical_metric(&canonical) {
                row.values.insert(name, json_number_text(&value));
                add_present_column(&mut present_columns, name);
            }
        }
        records.push(row);
    }
    Ok(RawTrace {
        rows: records,
        present_columns,
        warnings: Vec::new(),
    })
}

fn normalize(mut raw_trace: RawTrace, sample: String) -> Result<IngestResult> {
    if raw_trace.rows.is_empty() {
        return Err(NetdiagError::EmptyTrace);
    }
    validate_columns(&raw_trace.present_columns)?;

    for event_column in EVENT_COLUMNS {
        if !raw_trace.present_columns.contains(&event_column) {
            raw_trace.warnings.push(IngestWarning {
                row: None,
                column: event_column.to_string(),
                reason: "missing event column".to_string(),
                fallback: "0.0".to_string(),
            });
        }
    }

    let records: Vec<TraceRecord> = raw_trace
        .rows
        .into_iter()
        .enumerate()
        .map(|(idx, row)| {
            let row_number = idx + 1;
            let timestamp_text = row.timestamp.as_deref().ok_or_else(|| {
                NetdiagError::InvalidTrace(format!("missing timestamp at row {row_number}"))
            })?;
            let timestamp =
                parse_timestamp(timestamp_text).map_err(|_| NetdiagError::InvalidTimestamp {
                    row: row_number,
                    value: timestamp_text.to_string(),
                })?;
            Ok(TraceRecord {
                timestamp,
                latency_ms: metric(&row, row_number, "latency_ms")?,
                jitter_ms: metric(&row, row_number, "jitter_ms")?,
                packet_loss_rate: metric(&row, row_number, "packet_loss_rate")?,
                retransmission_rate: metric(&row, row_number, "retransmission_rate")?,
                timeout_events: optional_metric(&row, row_number, "timeout_events")?,
                retry_events: optional_metric(&row, row_number, "retry_events")?,
                throughput_mbps: metric(&row, row_number, "throughput_mbps")?,
                dns_failure_events: optional_metric(&row, row_number, "dns_failure_events")?,
                tls_failure_events: optional_metric(&row, row_number, "tls_failure_events")?,
                quic_blocked_ratio: optional_metric(&row, row_number, "quic_blocked_ratio")?,
            })
        })
        .collect::<Result<_>>()?;

    let mut ingest = build_ingest_result(records, sample)?;
    ingest.warnings = raw_trace.warnings;
    finalize_warning_metric_provenance(&mut ingest, "ingest");
    Ok(ingest)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(parsed.with_timezone(&Utc));
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(trimmed, format) {
            return Ok(Utc.from_utc_datetime(&parsed));
        }
    }
    Err(NetdiagError::Timestamp(trimmed.to_string()))
}

fn canonical_metric(column: &str) -> Option<&'static str> {
    CANONICAL_COLUMNS
        .iter()
        .copied()
        .find(|name| *name == column && *name != "timestamp")
}

fn present_columns(canonical: &[String]) -> Vec<&'static str> {
    let mut columns = Vec::new();
    for column in canonical {
        if column == "timestamp" {
            add_present_column(&mut columns, "timestamp");
        } else if let Some(name) = canonical_metric(column) {
            add_present_column(&mut columns, name);
        }
    }
    columns
}

fn add_present_column(columns: &mut Vec<&'static str>, column: &'static str) {
    if !columns.contains(&column) {
        columns.push(column);
    }
}

fn validate_columns(columns: &[&'static str]) -> Result<()> {
    for column in REQUIRED_COLUMNS {
        if !columns.contains(&column) {
            return Err(NetdiagError::MissingColumn(column.to_string()));
        }
    }
    Ok(())
}

fn validate_records(records: &[TraceRecord]) -> Result<()> {
    for (idx, record) in records.iter().enumerate() {
        let row = idx + 1;
        for (column, value) in [
            ("latency_ms", record.latency_ms),
            ("jitter_ms", record.jitter_ms),
            ("packet_loss_rate", record.packet_loss_rate),
            ("retransmission_rate", record.retransmission_rate),
            ("timeout_events", record.timeout_events),
            ("retry_events", record.retry_events),
            ("throughput_mbps", record.throughput_mbps),
            ("dns_failure_events", record.dns_failure_events),
            ("tls_failure_events", record.tls_failure_events),
            ("quic_blocked_ratio", record.quic_blocked_ratio),
        ] {
            validate_finite_non_negative(row, column, value)?;
        }
    }
    Ok(())
}

fn metric(row: &RawRecord, row_number: usize, name: &'static str) -> Result<f64> {
    let value = row
        .values
        .get(name)
        .ok_or_else(|| NetdiagError::InvalidTrace(format!("missing {name} at row {row_number}")))?;
    parse_f64(row_number, name, value)
}

fn optional_metric(row: &RawRecord, row_number: usize, name: &'static str) -> Result<f64> {
    row.values
        .get(name)
        .map(|value| parse_f64(row_number, name, value))
        .unwrap_or(Ok(0.0))
}

fn json_number_text(value: &Value) -> String {
    match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn parse_f64(row: usize, column: &str, value: &str) -> Result<f64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NetdiagError::InvalidNumber {
            row,
            column: column.to_string(),
            value: value.to_string(),
        });
    }
    let parsed = trimmed
        .parse::<f64>()
        .map_err(|_| NetdiagError::InvalidNumber {
            row,
            column: column.to_string(),
            value: value.to_string(),
        })?;
    validate_finite_non_negative(row, column, parsed)?;
    Ok(parsed)
}

fn validate_finite_non_negative(row: usize, column: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value < 0.0 {
        return Err(NetdiagError::InvalidNumber {
            row,
            column: column.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn metric_quality(ingest: &IngestResult, field: &str) -> Option<MetricQuality> {
        ingest
            .metric_provenance
            .iter()
            .find(|item| item.field == field)
            .map(|item| item.quality)
    }

    #[test]
    fn ingest_missing_optional_events_are_marked_fallback_provenance() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("minimal.csv");
        let mut file = File::create(&path).expect("csv");
        writeln!(
            file,
            "timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps"
        )
        .expect("header");
        writeln!(file, "2026-05-02T00:00:00Z,10,1,0,0,100").expect("row");

        let ingest = ingest_trace(&path).expect("ingest");

        assert_eq!(ingest.warnings.len(), EVENT_COLUMNS.len());
        assert_eq!(
            metric_quality(&ingest, "timeout_events"),
            Some(MetricQuality::Fallback)
        );
        assert_eq!(
            metric_quality(&ingest, "dns_failure_events"),
            Some(MetricQuality::Fallback)
        );
        assert_eq!(
            metric_quality(&ingest, "quic_blocked_ratio"),
            Some(MetricQuality::Fallback)
        );
        assert_eq!(
            metric_quality(&ingest, "latency_ms"),
            Some(MetricQuality::Measured)
        );
    }
}
