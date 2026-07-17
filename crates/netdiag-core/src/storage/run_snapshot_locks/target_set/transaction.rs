use crate::storage::RunLocation;
use std::path::PathBuf;

pub(in crate::storage::run_snapshot_locks) fn transaction_targets(
    location: &RunLocation,
    run_id: &str,
) -> Vec<PathBuf> {
    let mut targets = vec![
        location.run_dir.join("recommendations.json"),
        location.run_dir.join("report.json"),
        location.run_dir.join("hil_feedback.json"),
        location.run_dir.join("manifest.json"),
        location.run_dir.join("ml_result.json"),
        location.artifact_root.join("run_index.json"),
    ];
    if let Some(lab_run_dir) = location.lab_run_dir.as_deref() {
        targets.extend([
            lab_run_dir.join("report.json"),
            lab_run_dir.join("acceptance.json"),
            lab_run_dir.join("comparison.json"),
            lab_run_dir.join(format!("netdiag-evidence-{run_id}.zip")),
            lab_run_dir.join("evidence_bundle.json"),
        ]);
    }
    if let Some(lab_index_root) = location.lab_index_root.as_deref() {
        targets.push(lab_index_root.join("lab_run_index.json"));
    }
    targets
}

pub(in crate::storage::run_snapshot_locks) fn transaction_directory_targets(
    location: &RunLocation,
) -> Vec<PathBuf> {
    let mut targets = vec![location.run_dir.join("report.json")];
    if let Some(lab_run_dir) = location.lab_run_dir.as_deref() {
        targets.push(lab_run_dir.join("report.json"));
    }
    targets
}
