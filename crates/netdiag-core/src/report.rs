use crate::models::{
    DiagnosisCandidate, DiagnosisDecision, DiagnosisEvent, DiagnosisStatus, FaultLabel,
    HilReviewSummary, MetricProvenance, MlResult, ModelManifest, MultiSourceEvidenceSummary,
    Recommendation, TelemetrySummary, UncertaintyAssessment, UncertaintyReasonCode, WhatIfResult,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub run_id: String,
    pub generated_at: DateTime<Utc>,
    pub trace_summary: TelemetrySummary,
    #[serde(default)]
    pub measurement_quality: Vec<MetricProvenance>,
    #[serde(default)]
    pub diagnosis_status: DiagnosisStatus,
    #[serde(default)]
    pub uncertainty: UncertaintyAssessment,
    #[serde(default)]
    pub diagnosis_decision: DiagnosisDecision,
    pub root_causes: Vec<RootCause>,
    pub rule_vs_ml: RuleMlComparison,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest: Option<ModelManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_file_hash: Option<String>,
    pub what_if: Option<WhatIfResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_source_evidence: Option<MultiSourceEvidenceSummary>,
    pub recommendations: Vec<Recommendation>,
    #[serde(default)]
    pub hil_summary: HilReviewSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub symptom: String,
    pub severity: String,
    pub confidence: f64,
    pub why: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub suspected_corroboration: bool,
    #[serde(default)]
    pub diagnosis_status: DiagnosisStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMlComparison {
    pub rule_labels: Vec<String>,
    pub ml_top: String,
    pub ml_top_prob: f64,
    #[serde(default)]
    pub diagnosis_status: DiagnosisStatus,
    #[serde(default)]
    pub uncertainty: UncertaintyAssessment,
    pub agreement: bool,
    pub agreement_text: String,
    pub rule_missing: Vec<String>,
    pub rule_only: Vec<String>,
}

pub fn compare_rule_ml(events: &[DiagnosisEvent], ml: &MlResult) -> RuleMlComparison {
    let rule_labels: Vec<String> = events
        .iter()
        .filter(|event| !event_is_suspected_corroboration(event))
        .map(|event| event.evidence.symptom.as_str().to_string())
        .collect();
    let ml_top = ml
        .top_predictions
        .first()
        .map(|prediction| prediction.label.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let ml_top_prob = ml
        .top_predictions
        .first()
        .map(|prediction| prediction.prob)
        .unwrap_or(0.0);
    let agreement = ml.uncertainty.status == DiagnosisStatus::Known
        && rule_labels.iter().any(|label| label == &ml_top);
    let ml_top3: Vec<String> = ml
        .top_predictions
        .iter()
        .take(3)
        .map(|prediction| prediction.label.as_str().to_string())
        .collect();
    RuleMlComparison {
        rule_labels: rule_labels.clone(),
        ml_top,
        ml_top_prob,
        diagnosis_status: ml.uncertainty.status,
        uncertainty: ml.uncertainty.clone(),
        agreement,
        agreement_text: if ml.uncertainty.status == DiagnosisStatus::OutOfDistribution {
            "ML abstained as out-of-distribution; treat the top class as a candidate only."
                .to_string()
        } else if ml.uncertainty.status == DiagnosisStatus::Uncertain {
            "ML confidence is uncertain; treat the top class as a candidate and gather more evidence."
                .to_string()
        } else if agreement {
            "Rule and ML agree on the leading known fault class.".to_string()
        } else {
            "Rule and ML disagree on the top prediction; check confidence and supporting evidence."
                .to_string()
        },
        rule_missing: ml_top3
            .iter()
            .filter(|label| !rule_labels.contains(label))
            .cloned()
            .collect(),
        rule_only: rule_labels
            .iter()
            .filter(|label| !ml_top3.contains(label))
            .cloned()
            .collect(),
    }
}

fn event_is_suspected_corroboration(event: &DiagnosisEvent) -> bool {
    event.source == "corroboration" || event.evidence.method == "corroboration"
}

pub fn decide_diagnosis(events: &[DiagnosisEvent], ml: &MlResult) -> DiagnosisDecision {
    let mut candidates = Vec::new();
    let mut reasons = Vec::new();

    for event in events
        .iter()
        .filter(|event| !event_is_suspected_corroboration(event))
    {
        candidates.push(DiagnosisCandidate {
            label: event.evidence.symptom,
            source: "rule".to_string(),
            confidence: event.evidence.confidence,
            reasons: vec![event.evidence.why.clone()],
        });
    }
    for prediction in ml.top_predictions.iter().take(3) {
        candidates.push(DiagnosisCandidate {
            label: prediction.label,
            source: "ml".to_string(),
            confidence: prediction.prob,
            reasons: ml.uncertainty.reasons.clone(),
        });
    }

    let strong_rule = events
        .iter()
        .filter(|event| !event_is_suspected_corroboration(event))
        .filter(|event| event.evidence.symptom != FaultLabel::Normal)
        .filter(|event| event.evidence.confidence >= 0.85)
        .max_by(|left, right| {
            left.evidence
                .confidence
                .total_cmp(&right.evidence.confidence)
        });
    let ml_top = ml.top_predictions.first();

    let insufficient_evidence = ml
        .uncertainty
        .reason_codes
        .contains(&UncertaintyReasonCode::InsufficientEvidence);
    if let Some(rule) = strong_rule
        && ml.uncertainty.status != DiagnosisStatus::Known
        && !insufficient_evidence
    {
        reasons.push(format!(
            "strong rule evidence for {} overrides ML {} status",
            rule.evidence.symptom, ml.uncertainty.status
        ));
        reasons.push(rule.evidence.why.clone());
        return DiagnosisDecision {
            status: DiagnosisStatus::Known,
            status_source: "rule".to_string(),
            primary_label: Some(rule.evidence.symptom),
            candidates,
            reasons,
        };
    }
    if insufficient_evidence && strong_rule.is_some() {
        reasons.push(
            "strong rule evidence was kept as a candidate because ML inputs had insufficient evidence"
                .to_string(),
        );
    }

    if ml.uncertainty.status == DiagnosisStatus::Known {
        if let Some(prediction) = ml_top {
            let combined =
                strong_rule.is_some_and(|rule| rule.evidence.symptom == prediction.label);
            if combined {
                reasons.push("rule and ML support the same known fault".to_string());
            } else {
                reasons.push("ML is inside the model envelope and leads the diagnosis".to_string());
            }
            return DiagnosisDecision {
                status: DiagnosisStatus::Known,
                status_source: if combined { "combined" } else { "ml" }.to_string(),
                primary_label: Some(prediction.label),
                candidates,
                reasons,
            };
        }
        if let Some(rule) = strong_rule {
            reasons.push("ML returned no top prediction; strong rule evidence leads".to_string());
            return DiagnosisDecision {
                status: DiagnosisStatus::Known,
                status_source: "rule".to_string(),
                primary_label: Some(rule.evidence.symptom),
                candidates,
                reasons,
            };
        }
    }

    reasons.extend(ml.uncertainty.reasons.clone());
    DiagnosisDecision {
        status: ml.uncertainty.status,
        status_source: "ml".to_string(),
        primary_label: ml_top.map(|prediction| prediction.label),
        candidates,
        reasons,
    }
}

pub fn render_report(
    run_id: &str,
    summary: &TelemetrySummary,
    events: &[DiagnosisEvent],
    ml: &MlResult,
    diagnosis_decision: &DiagnosisDecision,
    what_if: Option<WhatIfResult>,
    recommendations: &[Recommendation],
) -> Report {
    let diagnosis_status = diagnosis_decision.status;
    Report {
        run_id: run_id.to_string(),
        generated_at: Utc::now(),
        trace_summary: summary.clone(),
        measurement_quality: summary.metric_provenance.clone(),
        diagnosis_status,
        uncertainty: ml.uncertainty.clone(),
        diagnosis_decision: diagnosis_decision.clone(),
        root_causes: events
            .iter()
            .map(|event| RootCause {
                symptom: event.evidence.symptom.as_str().to_string(),
                severity: format!("{:?}", event.evidence.severity).to_ascii_lowercase(),
                confidence: event.evidence.confidence,
                why: status_aware_root_cause_why(diagnosis_status, &event.evidence.why),
                source: event.source.clone(),
                method: event.evidence.method.clone(),
                suspected_corroboration: event_is_suspected_corroboration(event),
                diagnosis_status,
            })
            .collect(),
        rule_vs_ml: compare_rule_ml(events, ml),
        model_manifest: ml.model_manifest.clone(),
        model_manifest_hash: ml.model_manifest_hash.clone(),
        model_file_hash: ml.model_file_hash.clone(),
        what_if,
        multi_source_evidence: None,
        recommendations: recommendations.to_vec(),
        hil_summary: HilReviewSummary::from_recommendations(recommendations),
    }
}

fn status_aware_root_cause_why(status: DiagnosisStatus, why: &str) -> String {
    match status {
        DiagnosisStatus::Known => why.to_string(),
        DiagnosisStatus::Uncertain => {
            format!("Candidate finding; ML status is uncertain and needs more evidence. {why}")
        }
        DiagnosisStatus::OutOfDistribution => {
            format!(
                "Candidate finding; ML detected out-of-distribution telemetry and needs independent evidence. {why}"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        EvidenceRecord, EvidenceRef, MetricPoint, MetricQuality, Prediction, Severity, TimeWindow,
    };
    use std::collections::BTreeMap;

    fn event(label: FaultLabel, confidence: f64) -> DiagnosisEvent {
        DiagnosisEvent {
            event_id: format!("rule-{}", label.as_str()),
            source: "rule".to_string(),
            evidence: EvidenceRecord {
                run_id: "run-test".to_string(),
                method: "rule".to_string(),
                symptom: label,
                severity: Severity::High,
                confidence,
                window: TimeWindow {
                    start_ts: Utc::now(),
                    end_ts: Utc::now(),
                    bucket: "5s".to_string(),
                },
                supporting_metrics: vec![MetricPoint {
                    name: "dns_failure_events".to_string(),
                    value: 10.0,
                    unit: "count".to_string(),
                    baseline: None,
                    delta_pct: None,
                    note: None,
                }],
                raw_evidence_refs: vec![EvidenceRef {
                    source: "test".to_string(),
                    artifact: "test.json".to_string(),
                    offset: None,
                    details: BTreeMap::new(),
                }],
                counter_evidence: Vec::new(),
                recommendation_need_approval: true,
                hil_state: Default::default(),
                why: "strong rule evidence".to_string(),
            },
            model_probability: None,
        }
    }

    fn ml(status: DiagnosisStatus, reason_codes: Vec<UncertaintyReasonCode>) -> MlResult {
        MlResult {
            method: "test".to_string(),
            run_id: "run-test".to_string(),
            top_predictions: vec![Prediction {
                label: FaultLabel::Normal,
                prob: 0.91,
            }],
            top_features: Vec::new(),
            features: BTreeMap::new(),
            feature_quality: BTreeMap::from([("latency_p95".to_string(), MetricQuality::Measured)]),
            uncertainty: UncertaintyAssessment {
                status,
                reasons: vec![format!("ml {status}")],
                reason_codes,
                ..Default::default()
            },
            model_manifest: None,
            model_manifest_hash: None,
            model_file_hash: None,
        }
    }

    #[test]
    fn diagnosis_decision_allows_strong_rule_to_override_ml_ood() {
        let decision = decide_diagnosis(
            &[event(FaultLabel::DnsFailure, 0.96)],
            &ml(
                DiagnosisStatus::OutOfDistribution,
                vec![UncertaintyReasonCode::ExtremeFeatureDistance],
            ),
        );

        assert_eq!(decision.status, DiagnosisStatus::Known);
        assert_eq!(decision.status_source, "rule");
        assert_eq!(decision.primary_label, Some(FaultLabel::DnsFailure));
    }

    #[test]
    fn diagnosis_decision_keeps_insufficient_evidence_as_ml_status() {
        let decision = decide_diagnosis(
            &[event(FaultLabel::DnsFailure, 0.96)],
            &ml(
                DiagnosisStatus::Uncertain,
                vec![UncertaintyReasonCode::InsufficientEvidence],
            ),
        );

        assert_eq!(decision.status, DiagnosisStatus::Uncertain);
        assert_eq!(decision.status_source, "ml");
    }
}
