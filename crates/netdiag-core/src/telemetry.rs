use crate::error::{NetdiagError, Result};
use crate::models::{
    DistributionStats, IngestResult, OverallTelemetry, TelemetrySummary, TelemetryWindow,
    ThroughputStats, TraceRecord, WindowLatencyStats,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::collections::BTreeMap;

pub fn summarize_telemetry(
    records: &[TraceRecord],
    window_seconds: i64,
) -> Result<TelemetrySummary> {
    if records.is_empty() {
        return Err(NetdiagError::EmptyTrace);
    }
    let windows = aggregate_by_window(records, window_seconds);
    let timestamps: Vec<DateTime<Utc>> = records.iter().map(|record| record.timestamp).collect();
    let latency: Vec<f64> = records.iter().map(|record| record.latency_ms).collect();
    let jitter: Vec<f64> = records.iter().map(|record| record.jitter_ms).collect();
    let throughput: Vec<f64> = records
        .iter()
        .map(|record| record.throughput_mbps)
        .collect();
    let start = timestamps
        .iter()
        .min()
        .copied()
        .ok_or(NetdiagError::EmptyTrace)?;
    let end = timestamps
        .iter()
        .max()
        .copied()
        .ok_or(NetdiagError::EmptyTrace)?;

    let overall = OverallTelemetry {
        duration_s: (end - start).num_milliseconds() as f64 / 1000.0,
        samples: records.len(),
        latency: distribution(&latency),
        jitter_ms: distribution(&jitter),
        packet_loss_rate: mean(records.iter().map(|record| record.packet_loss_rate)),
        retransmission_rate: mean(records.iter().map(|record| record.retransmission_rate)),
        timeout_events: records.iter().map(|record| record.timeout_events).sum(),
        retry_events: records.iter().map(|record| record.retry_events).sum(),
        throughput_mbps: ThroughputStats {
            mean: mean(throughput.iter().copied()),
            p95: quantile(&throughput, 0.95),
            min: Some(throughput.iter().copied().fold(f64::INFINITY, f64::min)),
        },
        dns_failure_events: records.iter().map(|record| record.dns_failure_events).sum(),
        tls_failure_events: records.iter().map(|record| record.tls_failure_events).sum(),
        quic_blocked_ratio: mean(records.iter().map(|record| record.quic_blocked_ratio)),
        window_count: windows.len(),
    };
    Ok(TelemetrySummary {
        overall,
        windows,
        metric_provenance: Vec::new(),
    })
}

pub fn summarize_ingest(ingest: &IngestResult, window_seconds: i64) -> Result<TelemetrySummary> {
    let mut summary = summarize_telemetry(&ingest.records, window_seconds)?;
    summary.metric_provenance = ingest.metric_provenance.clone();
    Ok(summary)
}

pub fn aggregate_by_window(records: &[TraceRecord], window_seconds: i64) -> Vec<TelemetryWindow> {
    let mut grouped: BTreeMap<DateTime<Utc>, Vec<&TraceRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry(floor_time(record.timestamp, window_seconds))
            .or_default()
            .push(record);
    }

    grouped
        .into_iter()
        .map(|(start_ts, chunk)| {
            let latency: Vec<f64> = chunk.iter().map(|record| record.latency_ms).collect();
            let jitter: Vec<f64> = chunk.iter().map(|record| record.jitter_ms).collect();
            let throughput: Vec<f64> = chunk.iter().map(|record| record.throughput_mbps).collect();
            TelemetryWindow {
                start_ts,
                end_ts: start_ts + Duration::seconds(window_seconds),
                count: chunk.len(),
                latency_ms: WindowLatencyStats {
                    p50: quantile(&latency, 0.50),
                    mean: mean(latency.iter().copied()),
                    p95: quantile(&latency, 0.95),
                    p99: quantile(&latency, 0.99),
                    std: stddev(&latency),
                },
                jitter_ms: distribution(&jitter),
                packet_loss_rate: mean(chunk.iter().map(|record| record.packet_loss_rate)),
                retransmission_rate: mean(chunk.iter().map(|record| record.retransmission_rate)),
                timeout_events: chunk.iter().map(|record| record.timeout_events).sum(),
                retry_events: chunk.iter().map(|record| record.retry_events).sum(),
                throughput_mbps: ThroughputStats {
                    mean: mean(throughput.iter().copied()),
                    p95: quantile(&throughput, 0.95),
                    min: None,
                },
                dns_failure_events: chunk.iter().map(|record| record.dns_failure_events).sum(),
                tls_failure_events: chunk.iter().map(|record| record.tls_failure_events).sum(),
                quic_blocked_ratio: mean(chunk.iter().map(|record| record.quic_blocked_ratio)),
                raw_rows: chunk.len(),
            }
        })
        .collect()
}

pub fn extract_features_from_windows(windows: &[TelemetryWindow]) -> Vec<f64> {
    if windows.is_empty() {
        return vec![0.0; 11];
    }
    vec![
        mean(windows.iter().map(|window| window.latency_ms.mean)),
        mean(windows.iter().map(|window| window.latency_ms.p95)),
        mean(windows.iter().map(|window| window.jitter_ms.std)),
        mean(windows.iter().map(|window| window.packet_loss_rate)),
        mean(windows.iter().map(|window| window.retransmission_rate)),
        mean(windows.iter().map(|window| window.timeout_events)),
        mean(windows.iter().map(|window| window.retry_events)),
        mean(windows.iter().map(|window| window.throughput_mbps.mean)),
        mean(windows.iter().map(|window| window.dns_failure_events)),
        mean(windows.iter().map(|window| window.tls_failure_events)),
        mean(windows.iter().map(|window| window.quic_blocked_ratio)),
    ]
}

pub fn distribution(values: &[f64]) -> DistributionStats {
    if values.is_empty() {
        return DistributionStats::default();
    }
    DistributionStats {
        p50: quantile(values, 0.50),
        p95: quantile(values, 0.95),
        p99: quantile(values, 0.99),
        mean: mean(values.iter().copied()),
        std: stddev(values),
        min: values.iter().copied().fold(f64::INFINITY, f64::min),
        max: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    }
}

pub fn quantile(values: &[f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<f64> = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect();
    if sorted.is_empty() {
        return 0.0;
    }
    sorted.sort_by(f64::total_cmp);
    let position = (sorted.len() - 1) as f64 * q.clamp(0.0, 1.0);
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let fraction = position - lower as f64;
        sorted[lower] + (sorted[upper] - sorted[lower]) * fraction
    }
}

pub fn mean(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut count = 0usize;
    let mut sum = 0.0;
    for value in values {
        count += 1;
        sum += value;
    }
    if count == 0 { 0.0 } else { sum / count as f64 }
}

pub fn stddev(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let avg = mean(values.iter().copied());
    let variance = mean(values.iter().map(|value| (value - avg).powi(2)));
    variance.sqrt()
}

fn floor_time(timestamp: DateTime<Utc>, window_seconds: i64) -> DateTime<Utc> {
    let seconds = timestamp.timestamp();
    let floor = seconds - seconds.rem_euclid(window_seconds.max(1));
    Utc.timestamp_opt(floor, 0).single().unwrap_or(timestamp)
}
