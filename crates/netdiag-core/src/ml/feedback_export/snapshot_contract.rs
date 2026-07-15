use crate::error::{NetdiagError, Result};
use crate::models::{
    FaultLabel, HilFeedbackRecord, HilState, MlResult, Recommendation, RecommendationKind,
};
use crate::report::Report;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_snapshot_contract(
    run_id: &str,
    report: &Report,
    ml: &MlResult,
    feedback: &BTreeMap<String, HilFeedbackRecord>,
) -> Result<()> {
    if report.run_id != run_id {
        return Err(contract_error(run_id, "report", &report.run_id));
    }
    if ml.run_id != run_id {
        return Err(contract_error(run_id, "ML result", &ml.run_id));
    }
    if report.model_manifest_hash != ml.model_manifest_hash
        || report.model_file_hash != ml.model_file_hash
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "feedback export run {run_id} has inconsistent report and ML model identity"
        )));
    }
    validate_ml_projection(run_id, report, ml)?;
    validate_recommendations(run_id, &report.recommendations, feedback)
}

fn validate_recommendations(
    run_id: &str,
    recommendations: &[Recommendation],
    feedback: &BTreeMap<String, HilFeedbackRecord>,
) -> Result<()> {
    let mut recommendation_ids = BTreeSet::new();
    for recommendation in recommendations {
        if recommendation.run_id != run_id {
            return Err(contract_error(
                run_id,
                "recommendation",
                &recommendation.run_id,
            ));
        }
        if recommendation.recommendation_id.is_empty()
            || !recommendation_ids.insert(recommendation.recommendation_id.as_str())
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "feedback export run {run_id} has an empty or duplicate recommendation id {:?}",
                recommendation.recommendation_id
            )));
        }
    }
    for recommendation_id in feedback.keys() {
        if !recommendation_ids.contains(recommendation_id.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "HIL feedback recommendation id {recommendation_id:?} is absent from report for run {run_id}"
            )));
        }
    }
    Ok(())
}

fn validate_ml_projection(run_id: &str, report: &Report, ml: &MlResult) -> Result<()> {
    let expected = ml.top_predictions.first();
    let expected_label = expected
        .map(|prediction| prediction.label.as_str())
        .unwrap_or("unknown");
    let expected_probability = expected.map(|prediction| prediction.prob).unwrap_or(0.0);
    if report.rule_vs_ml.ml_top != expected_label
        || report.rule_vs_ml.ml_top_prob.to_bits() != expected_probability.to_bits()
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "feedback export run {run_id} has an inconsistent report projection of the ML result"
        )));
    }
    Ok(())
}

fn contract_error(run_id: &str, kind: &str, actual_run_id: &str) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "feedback export {kind} run id {actual_run_id} does not match locked run id {run_id}"
    ))
}

pub(super) fn accepted_feedback_label(
    recommendations: &[Recommendation],
    feedback: &BTreeMap<String, HilFeedbackRecord>,
) -> Option<(FaultLabel, Recommendation, HilFeedbackRecord)> {
    let mut selected = None;
    for record in feedback.values() {
        if record.review.state != HilState::Accepted {
            continue;
        }
        let recommendation = recommendations
            .iter()
            .find(|item| item.recommendation_id == record.recommendation_id)?;
        let final_label = record.review.final_label.or_else(|| {
            matches!(
                recommendation.kind,
                RecommendationKind::DiagnosisMitigation | RecommendationKind::Monitoring
            )
            .then_some(recommendation.diagnosis_symptom)
            .flatten()
        });
        let Some(final_label) = final_label else {
            continue;
        };
        if selected.as_ref().is_none_or(
            |(_, best, _): &(FaultLabel, Recommendation, HilFeedbackRecord)| {
                recommendation.confidence > best.confidence
            },
        ) {
            selected = Some((final_label, recommendation.clone(), record.clone()));
        }
    }
    selected
}
