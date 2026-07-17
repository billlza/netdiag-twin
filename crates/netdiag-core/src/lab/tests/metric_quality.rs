use super::super::*;
use crate::ingest::{build_ingest_result, set_metric_provenance};
use crate::models::TraceRecord;
use chrono::TimeZone;

fn corroborating_source(ingest: IngestResult) -> LoadedLabSource {
    let source = LabDataSource {
        name: Some("quality-corroborator".to_string()),
        role: LabDataSourceRole::Corroborating,
        kind: LabDataSourceKind::HttpJson,
        endpoint: "https://example.test/metrics".to_string(),
        bearer_token_env: None,
        mapping: None,
    };
    let loaded = ConnectorLoadResult {
        sample: ingest.schema.sample.clone(),
        resource_usage: ConnectorResourceUsage {
            input_bytes: 0,
            records: ingest.records.len(),
        },
        provenance: BTreeMap::new(),
        payload: None,
        ingest,
    };
    let health = ConnectorHealthSnapshot::from_ingest(
        source.kind.as_str(),
        source.name.as_deref().expect("source name"),
        &loaded.sample,
        &loaded.ingest,
    );
    LoadedLabSource {
        source,
        loaded,
        health,
    }
}

#[test]
fn corroboration_requires_trustworthy_quality_for_every_metric_it_uses() {
    let record = TraceRecord {
        timestamp: Utc
            .timestamp_opt(1_800_000_000, 0)
            .single()
            .expect("timestamp"),
        latency_ms: 200.0,
        jitter_ms: 1.0,
        packet_loss_rate: 2.0,
        retransmission_rate: 2.0,
        timeout_events: 0.0,
        retry_events: 0.0,
        throughput_mbps: 10.0,
        dns_failure_events: 1.0,
        tls_failure_events: 0.0,
        quic_blocked_ratio: 0.0,
    };
    let measured = build_ingest_result(vec![record.clone()], "measured").expect("ingest");
    let measured_signals = collect_corroboration_signals(&[corroborating_source(measured)]);
    assert!(
        measured_signals
            .iter()
            .any(|signal| signal.supports == Some(FaultLabel::Congestion))
    );
    assert!(
        measured_signals
            .iter()
            .any(|signal| signal.supports == Some(FaultLabel::RandomLoss))
    );

    let mut degraded = build_ingest_result(vec![record], "degraded").expect("ingest");
    for field in [
        "throughput_mbps",
        "retransmission_rate",
        "dns_failure_events",
    ] {
        set_metric_provenance(
            &mut degraded,
            field,
            MetricQuality::Missing,
            "test",
            "unavailable",
        );
    }
    let degraded_signals = collect_corroboration_signals(&[corroborating_source(degraded)]);
    assert!(degraded_signals.is_empty(), "{degraded_signals:?}");
}
