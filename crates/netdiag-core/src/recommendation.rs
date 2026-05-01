use crate::models::{
    DiagnosisEvent, FaultLabel, HilState, Recommendation, RecommendationKind, WhatIfResult,
};

pub fn recommend_actions(
    rule_events: &[DiagnosisEvent],
    whatif: Option<&WhatIfResult>,
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();
    for event in rule_events {
        let symptom = event.evidence.symptom;
        recommendations.push(Recommendation {
            recommendation_id: format!("rule-{}", event.event_id),
            run_id: event.evidence.run_id.clone(),
            kind: if symptom == FaultLabel::Normal {
                RecommendationKind::Monitoring
            } else {
                RecommendationKind::DiagnosisMitigation
            },
            source_event_id: Some(event.event_id.clone()),
            what_if_action_id: None,
            diagnosis_symptom: Some(symptom),
            recommended_action: action_for_symptom(symptom).to_string(),
            expected_effect: expected_effect(symptom, whatif),
            risk_level: risk_for_symptom(symptom).to_string(),
            confidence: (event.evidence.confidence * 0.9).clamp(0.0, 1.0),
            recommendation_need_approval: true,
            hil_state: HilState::Unreviewed,
            review: None,
        });
    }

    if let Some(whatif) = whatif {
        let proposed = whatif
            .proposed
            .get("throughput_mbps")
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0);
        let baseline = whatif
            .baseline
            .get("throughput_mbps")
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0);
        if proposed > baseline {
            recommendations.push(Recommendation {
                run_id: rule_events
                    .first()
                    .map(|event| event.evidence.run_id.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                recommendation_id: format!("whatif-{}", whatif.action_id),
                kind: RecommendationKind::WhatIfAction,
                source_event_id: None,
                what_if_action_id: Some(whatif.action_id.clone()),
                diagnosis_symptom: None,
                recommended_action: format!(
                    "Execute what-if action: {} ({})",
                    whatif.action_id, whatif.action_notes
                ),
                expected_effect: "Expected latency/throughput changes validated in simulation."
                    .to_string(),
                risk_level: whatif
                    .proposed
                    .get("qoe_risk")
                    .and_then(|value| value.as_str())
                    .unwrap_or("medium")
                    .to_string(),
                confidence: 0.85,
                recommendation_need_approval: true,
                hil_state: HilState::Unreviewed,
                review: None,
            });
        }
    }
    recommendations
}

fn risk_for_symptom(symptom: FaultLabel) -> &'static str {
    match symptom {
        FaultLabel::Congestion | FaultLabel::RandomLoss => "medium",
        FaultLabel::DnsFailure | FaultLabel::TlsFailure | FaultLabel::UdpQuicBlocked => "high",
        FaultLabel::Normal => "low",
    }
}

fn action_for_symptom(symptom: FaultLabel) -> &'static str {
    match symptom {
        FaultLabel::Congestion => {
            "Reroute traffic window + check queue limits and active queue management."
        }
        FaultLabel::RandomLoss => {
            "Enable packet-loss mitigation profile and inspect underlay noise source."
        }
        FaultLabel::DnsFailure => "Check DNS resolver health and confirm certificate trust path.",
        FaultLabel::TlsFailure => {
            "Validate TLS versions/ciphers and retry handshake after cert rotation."
        }
        FaultLabel::UdpQuicBlocked => {
            "Fall back to TCP transport or alternative relay while verifying UDP policy."
        }
        FaultLabel::Normal => "No action required; continue monitoring.",
    }
}

fn expected_effect(symptom: FaultLabel, whatif: Option<&WhatIfResult>) -> String {
    if let Some(whatif) = whatif {
        let throughput_delta = whatif.delta.get("throughput_pct").copied().unwrap_or(0.0);
        let latency_delta = whatif.delta.get("latency_pct").copied().unwrap_or(0.0);
        if throughput_delta >= 0.0 {
            return format!(
                "What-if expects throughput improve by {throughput_delta:.1}% with latency {latency_delta:.1}% change."
            );
        }
        return format!(
            "What-if expects potential throughput drop {:.1}% and latency {latency_delta:.1}%.",
            -throughput_delta
        );
    }
    match symptom {
        FaultLabel::Normal => {
            "Keep configuration and continue to observe in next telemetry cycle.".to_string()
        }
        FaultLabel::Congestion => {
            "Throughput should recover after queue and path adjustments.".to_string()
        }
        FaultLabel::RandomLoss => {
            "Packet retransmission events should reduce after mitigation.".to_string()
        }
        FaultLabel::DnsFailure => "DNS resolution success rate should increase.".to_string(),
        FaultLabel::TlsFailure => "TLS handshake retry failures should reduce.".to_string(),
        FaultLabel::UdpQuicBlocked => {
            "Fallback transport should restore user flow if QUIC is blocked.".to_string()
        }
    }
}
