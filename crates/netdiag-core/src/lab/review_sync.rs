use super::index_update::plan_lab_run_index_passed;
use super::{
    LabAcceptanceReport, LabRunComparison, LabRunIndex, LabValidationContext, lab_artifact_keys,
    lab_model_hashes, lab_run_comparison, load_lab_scenario, read_lab_connector_health,
    validate_lab_report,
};
use crate::error::{NetdiagError, Result};
use crate::models::{HilReviewSummary, Recommendation};
use crate::report::Report;
use crate::storage::typed_json::{MAX_RUN_REPORT_BYTES, read_required_stable_json_bounded};
use crate::storage::{RunLocation, optional_regular_file};
use chrono::{DateTime, Utc};
use std::path::PathBuf;

pub(crate) struct LabReviewArtifactPlan {
    pub report_path: PathBuf,
    pub report: Report,
    pub acceptance_path: PathBuf,
    pub acceptance: LabAcceptanceReport,
    pub comparison_path: PathBuf,
    pub comparison: LabRunComparison,
    pub archive_path: PathBuf,
    pub bundle_manifest_path: PathBuf,
    pub index: Option<(PathBuf, LabRunIndex)>,
}

pub(crate) fn preflight_lab_review_artifacts(
    location: &RunLocation,
    run_id: &str,
    recommendations: &[Recommendation],
    reviewed_at: DateTime<Utc>,
) -> Result<()> {
    plan_lab_review_artifacts(location, run_id, recommendations, reviewed_at).map(drop)
}

pub(crate) fn plan_lab_review_artifacts(
    location: &RunLocation,
    run_id: &str,
    recommendations: &[Recommendation],
    reviewed_at: DateTime<Utc>,
) -> Result<Option<LabReviewArtifactPlan>> {
    let Some(lab_run_dir) = location.lab_run_dir.as_deref() else {
        return Ok(None);
    };
    let report_path = lab_run_dir.join("report.json");
    let scenario_path = lab_run_dir.join("scenario.yaml");
    let report_exists = optional_regular_file(&report_path, "lab report")?;
    let scenario_exists = optional_regular_file(&scenario_path, "lab scenario")?;
    match (report_exists, scenario_exists) {
        (false, false) => return Ok(None),
        (false, true) => {
            return Err(NetdiagError::InvalidTrace(format!(
                "cannot persist lab review because report is missing: {}",
                report_path.display()
            )));
        }
        (true, false) => {
            return Err(NetdiagError::InvalidTrace(format!(
                "cannot persist lab review because scenario is missing: {}",
                scenario_path.display()
            )));
        }
        (true, true) => {}
    }

    let mut report: Report =
        read_required_stable_json_bounded(&report_path, MAX_RUN_REPORT_BYTES, "lab report")?;
    if report.run_id != run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab report run id {} does not match requested run id {run_id}",
            report.run_id
        )));
    }
    report.recommendations = recommendations.to_vec();
    report.hil_summary = HilReviewSummary::from_recommendations(recommendations);
    let scenario = load_lab_scenario(&scenario_path)?;
    let model_root = location
        .lab_index_root
        .as_deref()
        .unwrap_or(location.artifact_root.as_path());
    let (model_manifest_hash, model_file_hash) = lab_model_hashes(model_root, &report)?;
    let acceptance = validate_lab_report(
        &scenario,
        &report,
        &LabValidationContext {
            connector_health: read_lab_connector_health(lab_run_dir, run_id)?,
            artifact_keys: lab_artifact_keys(lab_run_dir, run_id)?,
            model_manifest_hash,
            model_file_hash,
        },
    )?;
    let comparison = lab_run_comparison(&scenario, &report, &acceptance, None);
    let index = location
        .lab_index_root
        .as_deref()
        .map(|root| plan_lab_run_index_passed(root, run_id, acceptance.passed, reviewed_at))
        .transpose()?;
    Ok(Some(LabReviewArtifactPlan {
        report_path,
        report,
        acceptance_path: lab_run_dir.join("acceptance.json"),
        acceptance,
        comparison_path: lab_run_dir.join("comparison.json"),
        comparison,
        archive_path: lab_run_dir.join(format!("netdiag-evidence-{run_id}.zip")),
        bundle_manifest_path: lab_run_dir.join("evidence_bundle.json"),
        index,
    }))
}
