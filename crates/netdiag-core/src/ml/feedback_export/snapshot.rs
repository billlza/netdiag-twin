use super::super::feature_map_to_vec;
use super::FeedbackTrainingRow;
use super::snapshot_contract::{accepted_feedback_label, validate_snapshot_contract};
use crate::error::{NetdiagError, Result};
use crate::models::MlResult;
use crate::report::Report;
use crate::storage::hil_transaction::read_optional_hil_feedback;
use crate::storage::typed_json::{
    MAX_ML_RESULT_BYTES, MAX_RUN_REPORT_BYTES, read_optional_stable_json_bounded,
};
use crate::storage::{
    RunLocation, ensure_run_has_no_pending_transaction, read_manifest_at_location,
};

pub(super) fn load_locked_snapshot(
    listed: &RunLocation,
    locked: &RunLocation,
    run_id: &str,
) -> Result<Option<FeedbackTrainingRow>> {
    ensure_same_location_paths(listed, locked, run_id)?;
    ensure_run_has_no_pending_transaction(&locked.run_dir, run_id)?;
    let manifest = read_manifest_at_location(locked)?;
    if manifest.run_id != run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "feedback export manifest run id {} does not match locked run id {run_id}",
            manifest.run_id
        )));
    }
    let report = read_optional_stable_json_bounded::<Report>(
        &locked.run_dir.join("report.json"),
        MAX_RUN_REPORT_BYTES,
        "run report",
    )?;
    let ml = read_optional_stable_json_bounded::<MlResult>(
        &locked.run_dir.join("ml_result.json"),
        MAX_ML_RESULT_BYTES,
        "ML result",
    )?;
    let feedback = read_optional_hil_feedback(&locked.run_dir.join("hil_feedback.json"), run_id)?;
    let (Some(report), Some(ml), Some(feedback)) = (report, ml, feedback) else {
        return Ok(None);
    };
    validate_snapshot_contract(run_id, &report, &ml, &feedback)?;
    feature_map_to_vec(&ml.features)?;
    let Some((final_label, recommendation, feedback_record)) =
        accepted_feedback_label(&report.recommendations, &feedback)
    else {
        return Ok(None);
    };
    Ok(Some(FeedbackTrainingRow {
        label: final_label,
        final_label,
        run_id: run_id.to_string(),
        source: "hil_accepted".to_string(),
        features: ml.features,
        rule_labels: report.rule_vs_ml.rule_labels,
        ml_top: report.rule_vs_ml.ml_top,
        ml_top_prob: report.rule_vs_ml.ml_top_prob,
        recommendation_id: recommendation.recommendation_id,
        feedback_state: feedback_record.review.state,
        feedback_notes: feedback_record.review.notes,
        reviewer: feedback_record.review.reviewer,
    }))
}

fn ensure_same_location_paths(
    listed: &RunLocation,
    locked: &RunLocation,
    run_id: &str,
) -> Result<()> {
    if listed.artifact_root == locked.artifact_root
        && listed.run_dir == locked.run_dir
        && listed.lab_run_dir == locked.lab_run_dir
        && listed.lab_index_root == locked.lab_index_root
    {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "feedback export run {run_id} resolved to a different location while acquiring snapshot locks"
    )))
}
