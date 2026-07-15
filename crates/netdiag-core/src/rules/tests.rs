use super::*;
use crate::ingest::build_ingest_result;
use crate::models::TraceRecord;
use crate::telemetry::{summarize_ingest, summarize_telemetry};
use chrono::{TimeZone, Utc};

fn dns_failure_record() -> TraceRecord {
    TraceRecord {
        timestamp: Utc
            .timestamp_opt(1_800_000_000, 0)
            .single()
            .expect("timestamp"),
        latency_ms: 10.0,
        jitter_ms: 1.0,
        packet_loss_rate: 0.0,
        retransmission_rate: 0.0,
        timeout_events: 1.0,
        retry_events: 1.0,
        throughput_mbps: 100.0,
        dns_failure_events: 2.0,
        tls_failure_events: 0.0,
        quic_blocked_ratio: 0.0,
    }
}

#[test]
fn missing_provenance_fails_closed_instead_of_treating_values_as_measured() {
    let record = dns_failure_record();
    let without_provenance =
        summarize_telemetry(std::slice::from_ref(&record), 5).expect("summary");
    let unproven = diagnose_rules(&without_provenance, "missing-provenance");
    assert_eq!(unproven.len(), 1, "{unproven:?}");
    assert_eq!(unproven[0].evidence.symptom, FaultLabel::Normal);

    let ingest = build_ingest_result(vec![record], "measured-source").expect("ingest");
    let measured = summarize_ingest(&ingest, 5).expect("measured summary");
    assert!(
        diagnose_rules(&measured, "measured-provenance")
            .iter()
            .any(|event| event.evidence.symptom == FaultLabel::DnsFailure),
        "the same numeric value with measured provenance remains actionable"
    );
}
