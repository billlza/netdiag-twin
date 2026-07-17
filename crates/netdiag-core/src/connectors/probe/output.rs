use super::measurement::ProbeMeasurement;
use crate::connectors::{ConnectorLoadResult, ConnectorResourceUsage};
use crate::error::{NetdiagError, Result};
use crate::ingest::{build_ingest_result, set_metric_provenance};
use crate::models::{IngestWarning, MetricQuality, TraceRecord};
use chrono::{Duration as ChronoDuration, Utc};
use std::collections::BTreeMap;

pub(super) fn build_probe_result(
    measurements: Vec<ProbeMeasurement>,
    target_count: usize,
    samples_per_target: usize,
    sample: &str,
) -> Result<ConnectorLoadResult> {
    let row_count = measurements.len();
    let row_count_i64 = i64::try_from(row_count)
        .map_err(|_| NetdiagError::Connector("active probe row count overflowed".to_string()))?;
    let started_at = Utc::now() - ChronoDuration::seconds(row_count_i64);
    let mut previous_latency = vec![None; target_count];
    let mut records = Vec::with_capacity(row_count);
    for (row_index, measurement) in measurements.into_iter().enumerate() {
        let previous = previous_latency
            .get_mut(measurement.target_index)
            .ok_or_else(|| {
                NetdiagError::Connector("active probe returned an invalid target index".to_string())
            })?;
        let jitter_ms = previous
            .map(|latency: f64| (measurement.latency_ms - latency).abs())
            .unwrap_or(0.0);
        *previous = Some(measurement.latency_ms);
        let offset = i64::try_from(row_index).map_err(|_| {
            NetdiagError::Connector("active probe row index overflowed".to_string())
        })?;
        records.push(TraceRecord {
            timestamp: started_at + ChronoDuration::seconds(offset),
            latency_ms: measurement.latency_ms,
            jitter_ms,
            packet_loss_rate: if measurement.success { 0.0 } else { 100.0 },
            retransmission_rate: 0.0,
            timeout_events: metric_bool(measurement.timeout),
            retry_events: 0.0,
            throughput_mbps: 0.0,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        });
    }

    let mut ingest = build_ingest_result(records, sample)?;
    ingest.warnings.extend(probe_warnings());
    set_probe_provenance(&mut ingest, sample);
    Ok(ConnectorLoadResult {
        ingest,
        sample: sample.to_string(),
        provenance: BTreeMap::from([
            ("target_count".to_string(), target_count.to_string()),
            (
                "samples_per_target".to_string(),
                samples_per_target.to_string(),
            ),
        ]),
        payload: None,
        resource_usage: ConnectorResourceUsage {
            input_bytes: 0,
            records: row_count,
        },
    })
}

fn set_probe_provenance(ingest: &mut crate::models::IngestResult, source: &str) {
    for (field, quality, reason) in [
        (
            "latency_ms",
            MetricQuality::Measured,
            "measured wall-clock duration of the active probe attempt",
        ),
        (
            "jitter_ms",
            MetricQuality::Estimated,
            "absolute latency change from the previous sample of the same target; the first sample uses 0 because history is unavailable",
        ),
        (
            "packet_loss_rate",
            MetricQuality::Estimated,
            "binary probe success or failure mapped to 0 or 100 percent",
        ),
        (
            "timeout_events",
            MetricQuality::Measured,
            "transport timeout outcome observed by the active probe",
        ),
    ] {
        set_metric_provenance(ingest, field, quality, source, reason);
    }
    for (field, reason) in fallback_metrics() {
        set_metric_provenance(ingest, field, MetricQuality::Fallback, source, reason);
    }
}

fn probe_warnings() -> Vec<IngestWarning> {
    let mut warnings = vec![IngestWarning {
        row: None,
        column: "jitter_ms".to_string(),
        reason: "the first sample for each target has insufficient history for jitter".to_string(),
        fallback: "0.0 for each target's first sample".to_string(),
    }];
    warnings.extend(
        fallback_metrics()
            .into_iter()
            .map(|(column, reason)| IngestWarning {
                row: None,
                column: column.to_string(),
                reason: reason.to_string(),
                fallback: "0.0".to_string(),
            }),
    );
    warnings
}

fn fallback_metrics() -> [(&'static str, &'static str); 6] {
    [
        (
            "throughput_mbps",
            "active probe does not measure sustained payload throughput",
        ),
        (
            "retransmission_rate",
            "active probe does not observe TCP retransmission counters",
        ),
        (
            "retry_events",
            "active probe does not perform automatic retries",
        ),
        (
            "dns_failure_events",
            "transport errors are not heuristically classified as DNS failures",
        ),
        (
            "tls_failure_events",
            "transport errors are not heuristically classified as TLS failures",
        ),
        (
            "quic_blocked_ratio",
            "active probe does not perform UDP or QUIC policy probing",
        ),
    ]
}

fn metric_bool(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}
