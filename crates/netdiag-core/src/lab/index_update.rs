use super::index_contract::{LAB_RUN_INDEX_SCHEMA, validate_lab_run_index_contract};
use super::{LabRunIndex, LabRunIndexEntry};
use crate::error::Result;
use crate::storage::typed_json::{
    MAX_LAB_RUN_INDEX_BYTES, MAX_LAB_RUN_INDEX_ENTRIES, prepare_json_bounded,
    read_optional_stable_json_bounded_at, save_prepared_json_atomic_to_bound,
};
use crate::storage::{BoundAtomicFileTarget, OwnedArtifactRoot, with_exclusive_bound_file_lock};
use chrono::Utc;
use std::ffi::OsStr;
use std::sync::Arc;

mod review;
pub(in crate::lab) use review::plan_lab_run_index_passed;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(in crate::lab) use tests::{update_lab_run_index, update_lab_run_index_passed};

pub(in crate::lab) fn update_lab_run_index_owned(
    owned: &OwnedArtifactRoot,
    entry: LabRunIndexEntry,
) -> Result<()> {
    let target = BoundAtomicFileTarget::from_directory(
        Arc::clone(owned.directory()),
        OsStr::new("lab_run_index.json"),
    )?;
    with_exclusive_bound_file_lock(&target, || {
        let existing = read_optional_stable_json_bounded_at::<LabRunIndex>(
            &target,
            MAX_LAB_RUN_INDEX_BYTES,
            "lab run index",
        )?;
        let index = updated_lab_run_index(existing, entry)?;
        save_prepared_json_atomic_to_bound(
            &target,
            prepare_json_bounded(&index, MAX_LAB_RUN_INDEX_BYTES, "lab run index")?,
        )
    })
}

fn updated_lab_run_index(
    existing: Option<LabRunIndex>,
    entry: LabRunIndexEntry,
) -> Result<LabRunIndex> {
    let mut index = match existing {
        Some(index) => {
            validate_lab_run_index_contract(&index)?;
            index
        }
        None => LabRunIndex {
            schema: LAB_RUN_INDEX_SCHEMA.to_string(),
            generated_at: Utc::now(),
            runs: Vec::new(),
        },
    };
    index.generated_at = Utc::now();
    index
        .runs
        .retain(|existing| existing.run_id != entry.run_id);
    index.runs.insert(0, entry);
    index.runs.truncate(MAX_LAB_RUN_INDEX_ENTRIES);
    Ok(index)
}
