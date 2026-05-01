use crate::models::{
    DiagnosisEvent, HilReviewSummary, MlResult, ModelManifest, Recommendation, TelemetrySummary,
    WhatIfResult,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub run_id: String,
    pub generated_at: DateTime<Utc>,
    pub trace_summary: TelemetrySummary,
    pub root_causes: Vec<RootCause>,
    pub rule_vs_ml: RuleMlComparison,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest: Option<ModelManifest>,
    pub what_if: Option<WhatIfResult>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMlComparison {
    pub rule_labels: Vec<String>,
    pub ml_top: String,
    pub ml_top_prob: f64,
    pub agreement: bool,
    pub agreement_text: String,
    pub rule_missing: Vec<String>,
    pub rule_only: Vec<String>,
}

pub fn compare_rule_ml(events: &[DiagnosisEvent], ml: &MlResult) -> RuleMlComparison {
    let rule_labels: Vec<String> = events
        .iter()
        .map(|event| event.evidence.symptom.as_str().to_string())
        .collect();
    let ml_top = ml
        .top_predictions
        .first()
        .map(|prediction| prediction.label.as_str().to_string())
        .unwrap_or_else(|| "normal".to_string());
    let ml_top_prob = ml
        .top_predictions
        .first()
        .map(|prediction| prediction.prob)
        .unwrap_or(0.0);
    let agreement = rule_labels.iter().any(|label| label == &ml_top);
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
        agreement,
        agreement_text: if agreement {
            "Rule and ML agree on the leading fault class.".to_string()
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

pub fn render_report(
    run_id: &str,
    summary: &TelemetrySummary,
    events: &[DiagnosisEvent],
    ml: &MlResult,
    what_if: Option<WhatIfResult>,
    recommendations: &[Recommendation],
) -> Report {
    Report {
        run_id: run_id.to_string(),
        generated_at: Utc::now(),
        trace_summary: summary.clone(),
        root_causes: events
            .iter()
            .map(|event| RootCause {
                symptom: event.evidence.symptom.as_str().to_string(),
                severity: format!("{:?}", event.evidence.severity).to_ascii_lowercase(),
                confidence: event.evidence.confidence,
                why: event.evidence.why.clone(),
            })
            .collect(),
        rule_vs_ml: compare_rule_ml(events, ml),
        model_manifest: ml.model_manifest.clone(),
        what_if,
        recommendations: recommendations.to_vec(),
        hil_summary: HilReviewSummary::from_recommendations(recommendations),
    }
}
