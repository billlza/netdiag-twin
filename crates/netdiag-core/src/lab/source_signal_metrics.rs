use crate::models::IngestResult;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SourceSignalMetrics {
    pub(super) latency_mean: f64,
    pub(super) packet_loss_rate: f64,
    pub(super) retransmission_rate: f64,
    pub(super) throughput_mbps: f64,
    pub(super) dns_failure_events: f64,
    pub(super) tls_failure_events: f64,
    pub(super) quic_blocked_ratio: f64,
}

pub(super) fn source_signal_metrics(ingest: &IngestResult) -> Option<SourceSignalMetrics> {
    let count = ingest.records.len() as f64;
    if count == 0.0 {
        return None;
    }
    let mut metrics = SourceSignalMetrics::default();
    for record in &ingest.records {
        metrics.latency_mean += record.latency_ms;
        metrics.packet_loss_rate += record.packet_loss_rate;
        metrics.retransmission_rate += record.retransmission_rate;
        metrics.throughput_mbps += record.throughput_mbps;
        metrics.dns_failure_events += record.dns_failure_events;
        metrics.tls_failure_events += record.tls_failure_events;
        metrics.quic_blocked_ratio += record.quic_blocked_ratio;
    }
    metrics.latency_mean /= count;
    metrics.packet_loss_rate /= count;
    metrics.retransmission_rate /= count;
    metrics.throughput_mbps /= count;
    metrics.dns_failure_events /= count;
    metrics.tls_failure_events /= count;
    metrics.quic_blocked_ratio /= count;
    Some(metrics)
}

pub(super) fn metrics_are_trustworthy(ingest: &IngestResult, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| metric_is_trustworthy(ingest, field))
}

pub(super) fn metric_is_trustworthy(ingest: &IngestResult, field: &str) -> bool {
    ingest
        .metric_provenance
        .iter()
        .find(|item| item.field == field)
        .is_some_and(|item| item.quality.is_trustworthy())
}
