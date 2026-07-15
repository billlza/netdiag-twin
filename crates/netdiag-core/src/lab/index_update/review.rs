use crate::error::{NetdiagError, Result};
use crate::lab::LabRunIndex;
use crate::lab::index_contract::validate_lab_run_index_contract;
use crate::storage::typed_json::{MAX_LAB_RUN_INDEX_BYTES, read_required_stable_json_bounded};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

pub(in crate::lab) fn plan_lab_run_index_passed(
    artifact_root: &Path,
    run_id: &str,
    passed: bool,
    generated_at: DateTime<Utc>,
) -> Result<(PathBuf, LabRunIndex)> {
    let index_path = artifact_root.join("lab_run_index.json");
    let mut index = read_required_stable_json_bounded::<LabRunIndex>(
        &index_path,
        MAX_LAB_RUN_INDEX_BYTES,
        "lab run index",
    )?;
    validate_lab_run_index_contract(&index)?;
    let entry = index
        .runs
        .iter_mut()
        .find(|entry| entry.run_id == run_id)
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "cannot persist lab review because run {run_id} is absent from {}",
                index_path.display()
            ))
        })?;
    entry.passed = passed;
    index.generated_at = generated_at;
    Ok((index_path, index))
}
