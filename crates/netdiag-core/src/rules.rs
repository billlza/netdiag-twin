use crate::models::{
    DiagnosisEvent, EvidenceRecord, EvidenceRef, FaultLabel, HilState, MetricPoint, Severity,
    TelemetrySummary, TelemetryWindow, TimeWindow,
};
use crate::telemetry::quantile;
use uuid::Uuid;

pub fn diagnose_rules(summary: &TelemetrySummary, run_id: &str) -> Vec<DiagnosisEvent> {
    let mut events = Vec::new();
    let overall = &summary.overall;

    if overall.dns_failure_events > 0.0
        || overall.dns_failure_events > overall.samples as f64 * 0.01
    {
        let score = (overall.dns_failure_events / overall.samples.max(1) as f64 * 20.0).min(1.0);
        if let Some(window) = summary
            .windows
            .iter()
            .find(|window| window.dns_failure_events > 0.0)
        {
            events.push(window_evidence(
                run_id,
                FaultLabel::DnsFailure,
                window,
                "DNS exceptions detected in consecutive windows. Retry and timeout events are elevated together.",
                severity_for_ratio(score),
                score.min(0.95).round_to_2(),
                &["If DNS counters are isolated while loss is stable, this should be deprioritized."],
            ));
        }
    }

    if overall.tls_failure_events > 0.0
        || overall.tls_failure_events > overall.samples as f64 * 0.01
    {
        let score = (overall.tls_failure_events / overall.samples.max(1) as f64 * 25.0).min(1.0);
        if let Some(window) = summary
            .windows
            .iter()
            .find(|window| window.tls_failure_events > 0.0)
        {
            events.push(window_evidence(
                run_id,
                FaultLabel::TlsFailure,
                window,
                "TLS handshake-related failures observed with non-zero TLS failure counter and no stable recovery window.",
                severity_for_ratio(score),
                score.min(0.97).round_to_2(),
                &["If loss-only recovery pattern is present, this is likely not pure TLS path failure."],
            ));
        }
    }

    if overall.quic_blocked_ratio > 0.25 {
        let score = overall.quic_blocked_ratio.min(1.0);
        if let Some(window) = summary
            .windows
            .iter()
            .find(|window| window.quic_blocked_ratio > 0.25)
        {
            events.push(window_evidence(
                run_id,
                FaultLabel::UdpQuicBlocked,
                window,
                "Sustained QUIC blocked ratio indicates possible UDP/QUIC egress filtering or path block.",
                severity_for_ratio(score),
                score.min(0.96).round_to_2(),
                &["Check endpoint UDP policy and fallback availability before forcing reroute."],
            ));
        }
    }

    let throughput_means: Vec<f64> = summary
        .windows
        .iter()
        .map(|window| window.throughput_mbps.mean)
        .collect();
    let throughput_floor = quantile(&throughput_means, 0.2);
    for window in &summary.windows {
        let loss = window.packet_loss_rate;
        let rtt = window.latency_ms.mean;
        let retrans = window.retransmission_rate;
        let throughput = window.throughput_mbps.mean;
        if throughput > 0.0
            && (loss > 0.8 || retrans > 1.5)
            && rtt > 120.0
            && throughput <= throughput_floor
        {
            events.push(window_evidence(
                run_id,
                FaultLabel::Congestion,
                window,
                "RTT and retransmission increase while throughput drops below expected baseline windows.",
                severity_for_ratio(((loss + retrans) / 3.0).min(1.0)),
                0.86,
                &["A sustained throughput recovery in neighboring windows would weaken the congestion inference."],
            ));
            break;
        }
    }

    if overall.packet_loss_rate > 0.5 && overall.latency.std > 10.0 {
        for window in &summary.windows {
            if window.packet_loss_rate > 0.5 && window.jitter_ms.std > 8.0 {
                events.push(window_evidence(
                    run_id,
                    FaultLabel::RandomLoss,
                    window,
                    "Loss is elevated but loss bursts are irregular with jitter spikes; indicates stochastic packet drops.",
                    severity_for_ratio((window.packet_loss_rate / 2.0).min(1.0)),
                    0.81,
                    &["Stable queue-occupancy growth with aligned jitter peaks suggests congestion instead of random loss."],
                ));
                break;
            }
        }
    }

    if events.is_empty()
        && let Some(window) = summary.windows.first()
    {
        events.push(window_evidence(
            run_id,
            FaultLabel::Normal,
            window,
            "No abnormal indicator exceeded thresholds over the trace window.",
            Severity::Low,
            0.95,
            &["No high-risk metrics; monitor latency and retransmissions in next window."],
        ));
    }

    let mut deduped = Vec::new();
    for event in events {
        if deduped
            .iter()
            .any(|existing: &DiagnosisEvent| existing.evidence.symptom == event.evidence.symptom)
        {
            continue;
        }
        deduped.push(event);
    }
    deduped
}

fn severity_for_ratio(ratio: f64) -> Severity {
    if ratio >= 0.8 {
        Severity::Critical
    } else if ratio >= 0.6 {
        Severity::High
    } else if ratio >= 0.3 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn window_evidence(
    run_id: &str,
    label: FaultLabel,
    window: &TelemetryWindow,
    why: &str,
    severity: Severity,
    confidence: f64,
    counter_evidence: &[&str],
) -> DiagnosisEvent {
    let support = vec![
        metric("latency_p95_ms", window.latency_ms.p95, "ms"),
        metric("jitter_std_ms", window.jitter_ms.std, "ms"),
        metric("loss_rate_pct", window.packet_loss_rate, "%"),
        metric("retransmission_rate_pct", window.retransmission_rate, "%"),
        metric("throughput_mbps", window.throughput_mbps.mean, "Mbps"),
    ];
    let offset = format!(
        "{}..{}",
        window.start_ts.to_rfc3339(),
        window.end_ts.to_rfc3339()
    );
    let record = EvidenceRecord {
        run_id: run_id.to_string(),
        method: "rule".to_string(),
        symptom: label,
        severity,
        confidence,
        window: TimeWindow {
            start_ts: window.start_ts,
            end_ts: window.end_ts,
            bucket: "5s".to_string(),
        },
        supporting_metrics: support,
        raw_evidence_refs: vec![EvidenceRef {
            source: "telemetry_window".to_string(),
            artifact: "telemetry_windows.json".to_string(),
            offset: Some(offset),
            details: Default::default(),
        }],
        counter_evidence: counter_evidence
            .iter()
            .map(|text| (*text).to_string())
            .collect(),
        recommendation_need_approval: true,
        hil_state: HilState::Unreviewed,
        why: why.to_string(),
    };
    DiagnosisEvent {
        event_id: format!(
            "{}-{}",
            label.as_str(),
            &Uuid::new_v4().simple().to_string()[..8]
        ),
        evidence: record,
        source: "rule".to_string(),
        model_probability: None,
    }
}

fn metric(name: &str, value: f64, unit: &str) -> MetricPoint {
    MetricPoint {
        name: name.to_string(),
        value,
        unit: unit.to_string(),
        baseline: None,
        delta_pct: None,
        note: None,
    }
}

trait RoundTo2 {
    fn round_to_2(self) -> f64;
}

impl RoundTo2 for f64 {
    fn round_to_2(self) -> f64 {
        (self * 100.0).round() / 100.0
    }
}
