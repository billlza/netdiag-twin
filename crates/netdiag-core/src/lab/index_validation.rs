use super::LabRunIndex;
use super::index_contract::validate_lab_run_index_contract;
use crate::error::{NetdiagError, Result};
use crate::storage::typed_json::{
    MAX_LAB_RUN_INDEX_BYTES, read_optional_stable_json_bounded as read_optional_index,
};
use crate::storage::{ensure_run_has_no_pending_transaction, resolve_stored_path};
use crate::validate_portable_id;
use std::path::Path;

mod artifacts;
pub(crate) use artifacts::validate_legacy_run_index_artifacts;

pub fn read_lab_run_index(artifact_root: &Path) -> Result<Option<LabRunIndex>> {
    let index_path = artifact_root.join("lab_run_index.json");
    let Some(index) =
        read_optional_index::<LabRunIndex>(&index_path, MAX_LAB_RUN_INDEX_BYTES, "lab run index")?
    else {
        return Ok(None);
    };
    validate_lab_run_index_contract(&index)?;
    let mut run_ids = std::collections::BTreeSet::new();
    for entry in &index.runs {
        validate_portable_id("indexed lab run id", &entry.run_id)?;
        validate_portable_id("indexed lab scenario id", &entry.scenario_id)?;
        if !run_ids.insert(entry.run_id.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate lab run id in index: {}",
                entry.run_id
            )));
        }
        for stored_path in [
            &entry.lab_run_dir,
            &entry.pipeline_run_dir,
            &entry.acceptance_path,
            &entry.comparison_path,
            &entry.scenario_path,
        ] {
            resolve_stored_path(artifact_root, stored_path)?;
        }
        let pipeline_run_dir = resolve_stored_path(artifact_root, &entry.pipeline_run_dir)?;
        ensure_run_has_no_pending_transaction(&pipeline_run_dir, &entry.run_id)?;
    }
    Ok(Some(index))
}
