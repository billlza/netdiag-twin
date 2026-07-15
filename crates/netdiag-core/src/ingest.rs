use crate::error::{NetdiagError, Result};
use crate::models::{
    IngestResult, IngestWarning, MetricProvenance, MetricQuality, TraceRecord, TraceSchema,
};
use crate::resource_limits::{MAX_SOURCE_INPUT_BYTES, MAX_SOURCE_RECORDS};
use crate::storage::read_stable_regular_file_bounded;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Cursor;
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

#[derive(Debug)]
pub(crate) struct TraceIngestLoad {
    pub(crate) ingest: IngestResult,
    pub(crate) input_bytes: u64,
}

pub fn ingest_trace(path: impl AsRef<Path>) -> Result<IngestResult> {
    Ok(ingest_trace_with_usage(path)?.ingest)
}

pub(crate) fn ingest_trace_with_usage(path: impl AsRef<Path>) -> Result<TraceIngestLoad> {
    let path = path.as_ref();
    let sample = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("uploaded")
        .to_string();
    let bytes =
        read_stable_regular_file_bounded(path, MAX_SOURCE_INPUT_BYTES)?.ok_or_else(|| {
            NetdiagError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "trace input is missing"),
            }
        })?;
    let input_bytes = u64::try_from(bytes.len()).map_err(|_| {
        NetdiagError::InvalidTrace("trace input byte count cannot fit in u64".to_string())
    })?;
    let raw_trace = if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        load_json(&bytes)?
    } else {
        load_csv(&bytes)?
    };
    Ok(TraceIngestLoad {
        ingest: normalize(raw_trace, sample)?,
        input_bytes,
    })
}

pub fn ingest_json_value(value: Value, sample: impl Into<String>) -> Result<IngestResult> {
    normalize(raw_trace_from_json(value)?, sample.into())
}

pub fn build_ingest_result(
    records: Vec<TraceRecord>,
    sample: impl Into<String>,
) -> Result<IngestResult> {
    if records.is_empty() {
        return Err(NetdiagError::EmptyTrace);
    }
    validate_trace_record_count(records.len(), MAX_SOURCE_RECORDS)?;
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
    validate_trace_records(&records)?;
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

fn load_csv(bytes: &[u8]) -> Result<RawTrace> {
    load_csv_bounded(bytes, MAX_SOURCE_RECORDS)
}

fn load_csv_bounded(bytes: &[u8], max_records: usize) -> Result<RawTrace> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(Cursor::new(bytes));
    let headers = reader.headers()?.clone();
    let canonical: Vec<String> = headers.iter().map(alias).collect();
    let present_columns = present_columns(&canonical);
    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record?;
        let next_count = rows.len().checked_add(1).ok_or_else(|| {
            NetdiagError::InvalidTrace("trace record count overflowed".to_string())
        })?;
        validate_trace_record_count(next_count, max_records)?;
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

fn load_json(bytes: &[u8]) -> Result<RawTrace> {
    let value = crate::strict_json::parse_unique_value(bytes)?;
    raw_trace_from_json(value)
}

fn raw_trace_from_json(value: Value) -> Result<RawTrace> {
    raw_trace_from_json_bounded(value, MAX_SOURCE_RECORDS)
}

fn raw_trace_from_json_bounded(value: Value, max_records: usize) -> Result<RawTrace> {
    let rows = match value {
        Value::Array(items) => items,
        Value::Object(mut object) => match object.remove("records") {
            Some(Value::Array(items)) => items,
            Some(_) => {
                return Err(NetdiagError::InvalidTrace(
                    "JSON field records must be an array".to_string(),
                ));
            }
            None => {
                return Err(NetdiagError::InvalidTrace(
                    "JSON object is missing records array".to_string(),
                ));
            }
        },
        _ => {
            return Err(NetdiagError::InvalidTrace(
                "JSON trace root must be an array or an object with records".to_string(),
            ));
        }
    };
    validate_trace_record_count(rows.len(), max_records)?;
    let mut records = Vec::new();
    let mut present_columns = Vec::new();
    for (index, item) in rows.into_iter().enumerate() {
        let mut row = RawRecord::default();
        let Value::Object(object) = item else {
            return Err(NetdiagError::InvalidTrace(format!(
                "JSON trace row {} must be an object",
                index + 1
            )));
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

fn validate_trace_record_count(records: usize, max_records: usize) -> Result<()> {
    if records > max_records {
        return Err(NetdiagError::InvalidTrace(format!(
            "trace record count {records} exceeds the {max_records}-record source limit"
        )));
    }
    Ok(())
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

pub(crate) fn validate_trace_records(records: &[TraceRecord]) -> Result<()> {
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
            validate_canonical_metric_range(row, column, value)?;
        }
    }
    Ok(())
}

fn validate_canonical_metric_range(row: usize, column: &str, value: f64) -> Result<()> {
    let maximum = match column {
        "packet_loss_rate" | "retransmission_rate" => 100.0,
        "quic_blocked_ratio" => 1.0,
        _ => return Ok(()),
    };
    if value > maximum {
        return Err(NetdiagError::InvalidTrace(format!(
            "row {row} {column} exceeds the canonical maximum {maximum}"
        )));
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
    use std::fs::File;
    use std::io::Write;

    const MINIMAL_HEADER: &str =
        "timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps";

    fn minimal_csv() -> String {
        format!("{MINIMAL_HEADER}\n2026-05-02T00:00:00Z,10,1,0,0,100\n")
    }

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

    #[test]
    fn trace_file_ingest_reports_exact_snapshot_resource_usage() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("trace.csv");
        let csv = minimal_csv();
        std::fs::write(&path, csv.as_bytes()).expect("trace");

        let loaded = ingest_trace_with_usage(&path).expect("bounded trace snapshot");

        assert_eq!(loaded.input_bytes, csv.len() as u64);
        assert_eq!(loaded.ingest.schema.rows, 1);
    }

    #[test]
    fn trace_file_ingest_distinguishes_missing_corrupt_and_oversized_inputs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing.csv");
        let missing_error = ingest_trace(&missing).expect_err("missing trace must fail");
        assert!(matches!(
            missing_error,
            NetdiagError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound
        ));

        let corrupt = temp.path().join("corrupt.json");
        std::fs::write(&corrupt, b"{").expect("corrupt trace");
        assert!(matches!(
            ingest_trace(&corrupt).expect_err("corrupt JSON must fail"),
            NetdiagError::Json(_)
        ));

        let oversized = temp.path().join("oversized.csv");
        let file = File::create(&oversized).expect("oversized trace");
        file.set_len(MAX_SOURCE_INPUT_BYTES + 1)
            .expect("sparse oversized trace");
        let limit_error = ingest_trace(&oversized).expect_err("oversized trace must fail");
        assert!(
            matches!(limit_error, NetdiagError::InvalidTrace(_)),
            "{limit_error}"
        );
        assert!(limit_error.to_string().contains("byte read limit"));
    }

    #[test]
    fn trace_file_ingest_rejects_duplicate_json_keys_without_echoing_them() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("duplicate.json");
        std::fs::write(
            &path,
            br#"{"records":[{"private-metric":1,"private-metric":2}]}"#,
        )
        .expect("duplicate JSON trace");

        let error = ingest_trace(&path).expect_err("duplicate JSON key must fail");
        assert!(matches!(error, NetdiagError::Json(_)), "{error}");
        let message = error.to_string();
        assert!(message.contains("duplicate key"), "{message}");
        assert!(!message.contains("private-metric"), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn trace_file_ingest_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target.csv");
        let link = temp.path().join("trace.csv");
        std::fs::write(&target, minimal_csv()).expect("trace target");
        symlink(&target, &link).expect("trace symlink");

        let error = ingest_trace(&link).expect_err("symlink must fail closed");

        assert!(matches!(error, NetdiagError::InvalidTrace(_)), "{error}");
        assert!(error.to_string().contains("non-symlink file required"));
    }

    #[test]
    fn csv_and_json_record_limits_fail_before_retaining_excess_rows() {
        let csv = format!(
            "{MINIMAL_HEADER}\n2026-05-02T00:00:00Z,10,1,0,0,100\n2026-05-02T00:00:01Z,11,1,0,0,100\n"
        );
        let csv_error = load_csv_bounded(csv.as_bytes(), 1).expect_err("CSV row limit");
        assert!(csv_error.to_string().contains("2 exceeds the 1-record"));

        let json_error = raw_trace_from_json_bounded(
            serde_json::json!([{"timestamp": "a"}, {"timestamp": "b"}]),
            1,
        )
        .expect_err("JSON row limit");
        assert!(json_error.to_string().contains("2 exceeds the 1-record"));
    }

    #[test]
    fn canonical_ratio_ranges_are_enforced_for_records_csv_and_json() {
        let exact = TraceRecord {
            timestamp: Utc
                .timestamp_opt(1_800_000_000, 0)
                .single()
                .expect("timestamp"),
            latency_ms: 1.0,
            jitter_ms: 1.0,
            packet_loss_rate: 100.0,
            retransmission_rate: 100.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: 1.0,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 1.0,
        };
        build_ingest_result(vec![exact.clone()], "exact-ranges").expect("inclusive maxima");

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
            let error = build_ingest_result(vec![invalid], "invalid-range")
                .expect_err("canonical maximum plus epsilon must fail");
            assert!(error.to_string().contains(field), "{error}");
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let csv_path = temp.path().join("invalid.csv");
        std::fs::write(
            &csv_path,
            format!(
                "{MINIMAL_HEADER},quic_blocked_ratio\n2026-05-02T00:00:00Z,10,1,100.1,0,100,0\n"
            ),
        )
        .expect("invalid CSV");
        assert!(
            ingest_trace(&csv_path)
                .expect_err("CSV range violation")
                .to_string()
                .contains("packet_loss_rate")
        );

        let mut json_record = serde_json::to_value(exact).expect("record JSON");
        json_record["quic_blocked_ratio"] = serde_json::json!(1.1);
        assert!(
            ingest_json_value(
                serde_json::json!({ "records": [json_record] }),
                "invalid-json"
            )
            .expect_err("JSON range violation")
            .to_string()
            .contains("quic_blocked_ratio")
        );
    }

    #[test]
    fn json_ingest_rejects_missing_or_malformed_record_envelopes() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"records": {}}),
            serde_json::json!({"records": ["not-an-object"]}),
            serde_json::json!("not-a-trace"),
        ] {
            assert!(
                ingest_json_value(value, "invalid-json-trace").is_err(),
                "malformed JSON shape must fail explicitly"
            );
        }
    }
}
