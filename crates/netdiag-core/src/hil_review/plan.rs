use crate::error::{NetdiagError, Result};
use crate::models::{HilFeedbackRecord, RunIndexEntry, RunManifest};
use crate::report::Report;
use crate::storage::RunLocation;
use crate::storage::hil_transaction::{HilReviewJournal, read_optional_hil_feedback};
use crate::storage::typed_json::{
    MAX_RUN_INDEX_BYTES, MAX_RUN_INDEX_ENTRIES, MAX_RUN_MANIFEST_BYTES, MAX_RUN_REPORT_BYTES,
    ensure_collection_limit, read_required_stable_json_bounded,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(super) struct PipelineReviewPlan {
    pub recommendations_path: PathBuf,
    pub report_path: PathBuf,
    pub report: Report,
    pub feedback_path: PathBuf,
    pub feedback: BTreeMap<String, HilFeedbackRecord>,
    pub manifest_path: PathBuf,
    pub manifest: RunManifest,
    pub run_index_path: PathBuf,
    pub run_index: Vec<RunIndexEntry>,
}

pub(super) fn plan_pipeline_review(
    location: &RunLocation,
    journal: &HilReviewJournal,
) -> Result<PipelineReviewPlan> {
    let recommendations_path = location.run_dir.join("recommendations.json");
    let report_path = location.run_dir.join("report.json");
    let mut report =
        read_required_stable_json_bounded::<Report>(&report_path, MAX_RUN_REPORT_BYTES, "report")?;
    if report.run_id != journal.run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "report run id {} does not match HIL transaction run id {}",
            report.run_id, journal.run_id
        )));
    }
    report.recommendations = journal.recommendations.clone();
    report.hil_summary =
        crate::models::HilReviewSummary::from_recommendations(&journal.recommendations);

    let feedback_path = location.run_dir.join("hil_feedback.json");
    let mut feedback =
        read_optional_hil_feedback(&feedback_path, &journal.run_id)?.unwrap_or_default();
    feedback.insert(
        journal.recommendation_id.clone(),
        HilFeedbackRecord {
            run_id: journal.run_id.clone(),
            recommendation_id: journal.recommendation_id.clone(),
            review: journal.review.clone(),
        },
    );

    let manifest_path = location.run_dir.join("manifest.json");
    let mut manifest = read_required_stable_json_bounded::<RunManifest>(
        &manifest_path,
        MAX_RUN_MANIFEST_BYTES,
        "run manifest",
    )?;
    if manifest.run_id != journal.run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest run id {} does not match HIL transaction run id {}",
            manifest.run_id, journal.run_id
        )));
    }
    manifest
        .artifact_paths
        .insert("hil_feedback".to_string(), "hil_feedback.json".to_string());
    crate::storage::ensure_manifest_artifact_limit(&manifest)?;

    let run_index_path = location.artifact_root.join("run_index.json");
    let mut run_index = read_required_stable_json_bounded::<Vec<RunIndexEntry>>(
        &run_index_path,
        MAX_RUN_INDEX_BYTES,
        "run index",
    )?;
    ensure_collection_limit("run index", run_index.len(), MAX_RUN_INDEX_ENTRIES)?;
    let entry = run_index
        .iter_mut()
        .find(|entry| entry.run_id == journal.run_id)
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "cannot persist HIL review because run {} is absent from {}",
                journal.run_id,
                run_index_path.display()
            ))
        })?;
    entry.status = journal.status.clone();

    Ok(PipelineReviewPlan {
        recommendations_path,
        report_path,
        report,
        feedback_path,
        feedback,
        manifest_path,
        manifest,
        run_index_path,
        run_index,
    })
}

pub(super) fn read_recommendations(run_dir: &Path) -> Result<Vec<crate::models::Recommendation>> {
    read_required_stable_json_bounded(
        &run_dir.join("recommendations.json"),
        super::MAX_TRANSACTION_JSON_BYTES,
        "recommendations",
    )
}
