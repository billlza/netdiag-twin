use crate::error::Result;
use crate::models::{FaultLabel, HilState};
use crate::storage::typed_json::ensure_collection_limit;
use crate::storage::{
    MAX_DISCOVERED_RUN_LOCATIONS, SnapshotOutputTarget, list_run_locations,
    read_manifest_at_location, with_resolved_run_snapshot_locks,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

mod publication;
mod snapshot;
mod snapshot_contract;
use publication::{checked_serialized_size, publish_dataset};
use snapshot::load_locked_snapshot;

const MAX_FEEDBACK_EXPORT_RUNS: usize = MAX_DISCOVERED_RUN_LOCATIONS;
const MAX_FEEDBACK_EXPORT_ROWS: usize = MAX_FEEDBACK_EXPORT_RUNS;
pub(super) const MAX_FEEDBACK_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackTrainingRow {
    pub label: FaultLabel,
    pub final_label: FaultLabel,
    pub run_id: String,
    pub source: String,
    pub features: BTreeMap<String, f64>,
    pub rule_labels: Vec<String>,
    pub ml_top: String,
    pub ml_top_prob: f64,
    pub recommendation_id: String,
    pub feedback_state: HilState,
    pub feedback_notes: String,
    pub reviewer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackExportSummary {
    pub output: String,
    pub rows: usize,
    pub skipped_runs: usize,
    pub dataset_hash_sha256: String,
}

pub fn export_feedback_training_dataset(
    artifact_root: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<FeedbackExportSummary> {
    let artifact_root = artifact_root.as_ref();
    let output_path = output_path.as_ref();
    let mut output_target = SnapshotOutputTarget::prepare(artifact_root, output_path)?;
    let locations = list_run_locations(artifact_root)?;
    ensure_collection_limit(
        "feedback export run locations",
        locations.len(),
        MAX_FEEDBACK_EXPORT_RUNS,
    )?;
    let runs = locations
        .into_iter()
        .map(|location| {
            let run_id = read_manifest_at_location(&location)?.run_id;
            output_target.validate_for_run(&location, &run_id)?;
            Ok((location, run_id))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::new();
    let mut skipped_runs = 0usize;
    let mut serialized_bytes = 0_u64;

    for (listed_location, run_id) in runs {
        let outcome =
            with_resolved_run_snapshot_locks(&listed_location, &run_id, |locked_location| {
                load_locked_snapshot(&listed_location, locked_location, &run_id)
            })?;
        match outcome {
            Some(row) => {
                ensure_collection_limit(
                    "feedback export rows",
                    rows.len() + 1,
                    MAX_FEEDBACK_EXPORT_ROWS,
                )?;
                serialized_bytes = checked_serialized_size(serialized_bytes, &row)?;
                rows.push(row);
            }
            None => skipped_runs += 1,
        }
    }

    rows.sort_by(|left, right| {
        left.run_id
            .cmp(&right.run_id)
            .then_with(|| left.recommendation_id.cmp(&right.recommendation_id))
    });
    let bound_output = output_target.bind_for_publication()?;
    let dataset_hash_sha256 = publish_dataset(&output_target, &bound_output, &rows)?;
    Ok(FeedbackExportSummary {
        output: output_path.display().to_string(),
        rows: rows.len(),
        skipped_runs,
        dataset_hash_sha256,
    })
}

#[cfg(test)]
mod tests;
