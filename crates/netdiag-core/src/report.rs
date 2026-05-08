use crate::models::{
    DiagnosisEvent, DiagnosisStatus, HilReviewSummary, MetricProvenance, MlResult, ModelManifest,
    MultiSourceEvidenceSummary, Recommendation, TelemetrySummary, UncertaintyAssessment,
    WhatIfResult,
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

pub fn render_report(
    run_id: &str,
    summary: &TelemetrySummary,
    events: &[DiagnosisEvent],
    ml: &MlResult,
    what_if: Option<WhatIfResult>,
    recommendations: &[Recommendation],
) -> Report {
    let diagnosis_status = ml.uncertainty.status;
    Report {
        run_id: run_id.to_string(),
        generated_at: Utc::now(),
        trace_summary: summary.clone(),
        measurement_quality: summary.metric_provenance.clone(),
        diagnosis_status,
        uncertainty: ml.uncertainty.clone(),
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
