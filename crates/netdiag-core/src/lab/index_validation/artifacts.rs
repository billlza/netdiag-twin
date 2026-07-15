use crate::error::{IoContext, NetdiagError, Result};
use crate::lab::evidence_identity::{validate_acceptance_identity, validate_comparison_identity};
use crate::lab::{LabAcceptanceReport, LabRunComparison, LabRunIndex, load_lab_scenario};
use crate::models::RunIndexEntry;
use crate::storage::typed_json::{
    MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES, read_required_stable_json_bounded,
};
use crate::storage::{
    PathStatus, path_status, read_manifest, read_report, resolve_stored_path, run_history_entry,
};
use std::path::Path;

pub(crate) fn validate_legacy_run_index_artifacts(
    artifact_root: &Path,
    index: &LabRunIndex,
) -> Result<bool> {
    if index.runs.is_empty() {
        return Ok(false);
    }
    for entry in &index.runs {
        let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir)?;
        require_path_type(
            &lab_run_dir,
            PathStatus::Directory,
            "indexed lab run directory",
        )?;
        let pipeline_run_dir = resolve_stored_path(artifact_root, &entry.pipeline_run_dir)?;
        require_path_type(
            &pipeline_run_dir,
            PathStatus::Directory,
            "indexed pipeline run directory",
        )?;
        let expected_pipeline_run_dir = lab_run_dir.join("runs").join(&entry.run_id);
        require_same_directory(&pipeline_run_dir, &expected_pipeline_run_dir)?;

        let manifest = read_manifest(&lab_run_dir, &entry.run_id)?;
        let report = read_report(&lab_run_dir, &entry.run_id)?;
        run_history_entry(
            &lab_run_dir,
            RunIndexEntry {
                run_id: entry.run_id.clone(),
                sample: manifest.sample.clone(),
                created_at: manifest.created_at,
                status: report.hil_summary.run_status().to_string(),
                run_dir: format!("runs/{}", entry.run_id),
            },
        )?;

        let acceptance_path = resolve_stored_path(artifact_root, &entry.acceptance_path)?;
        let acceptance = read_required_stable_json_bounded::<LabAcceptanceReport>(
            &acceptance_path,
            MAX_LAB_ACCEPTANCE_BYTES,
            "legacy lab acceptance report",
        )?;
        validate_acceptance_identity(entry, &acceptance)?;
        let comparison_path = resolve_stored_path(artifact_root, &entry.comparison_path)?;
        let comparison = read_required_stable_json_bounded::<LabRunComparison>(
            &comparison_path,
            MAX_LAB_COMPARISON_BYTES,
            "legacy lab comparison",
        )?;
        validate_comparison_identity(entry, &acceptance, &comparison)?;

        let scenario_path = resolve_stored_path(artifact_root, &entry.scenario_path)?;
        let scenario = load_lab_scenario(&scenario_path)?;
        if scenario.id != entry.scenario_id || scenario.name != entry.scenario_name {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab indexed run {} scenario identity does not match its trusted scenario",
                entry.run_id
            )));
        }
    }
    Ok(true)
}

fn require_path_type(path: &Path, expected: PathStatus, kind: &str) -> Result<()> {
    let actual = path_status(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "{kind} has invalid filesystem type at {}",
            path.display()
        )))
    }
}

fn require_same_directory(actual: &Path, expected: &Path) -> Result<()> {
    let actual_identity = std::fs::canonicalize(actual).with_path(actual)?;
    let expected_identity = std::fs::canonicalize(expected).with_path(expected)?;
    if actual_identity == expected_identity {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "indexed pipeline run directory does not match its lab run: {}",
            actual.display()
        )))
    }
}
