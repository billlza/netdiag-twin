use super::super::{plan_lab_run_index_passed, updated_lab_run_index};
use crate::error::Result;
use crate::lab::{LabRunIndex, LabRunIndexEntry};
use crate::storage::typed_json::{
    MAX_LAB_RUN_INDEX_BYTES, read_optional_stable_json_bounded, save_json_atomic_bounded,
};
use crate::storage::with_exclusive_file_lock;
use chrono::Utc;
use std::path::Path;

pub(in crate::lab) fn update_lab_run_index(
    artifact_root: &Path,
    entry: LabRunIndexEntry,
) -> Result<()> {
    let index_path = artifact_root.join("lab_run_index.json");
    with_exclusive_file_lock(&index_path, || {
        let existing = read_optional_stable_json_bounded::<LabRunIndex>(
            &index_path,
            MAX_LAB_RUN_INDEX_BYTES,
            "lab run index",
        )?;
        let index = updated_lab_run_index(existing, entry)?;
        save_lab_run_index(&index_path, &index)
    })
}

pub(in crate::lab) fn update_lab_run_index_passed(
    artifact_root: &Path,
    run_id: &str,
    passed: bool,
) -> Result<()> {
    let index_path = artifact_root.join("lab_run_index.json");
    with_exclusive_file_lock(&index_path, || {
        let (_, index) = plan_lab_run_index_passed(artifact_root, run_id, passed, Utc::now())?;
        save_lab_run_index(&index_path, &index)
    })
}

fn save_lab_run_index(path: &Path, index: &LabRunIndex) -> Result<()> {
    save_json_atomic_bounded(path, index, MAX_LAB_RUN_INDEX_BYTES, "lab run index").map(drop)
}
