use super::LabRunIndex;
use crate::error::{NetdiagError, Result};
use crate::storage::typed_json::{MAX_LAB_RUN_INDEX_ENTRIES, ensure_collection_limit};

pub(super) const LAB_RUN_INDEX_SCHEMA: &str = "netdiag-lab-run-index/v1";

pub(super) fn validate_lab_run_index_contract(index: &LabRunIndex) -> Result<()> {
    if index.schema != LAB_RUN_INDEX_SCHEMA {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported lab run index schema: {}",
            index.schema
        )));
    }
    ensure_collection_limit("lab run index", index.runs.len(), MAX_LAB_RUN_INDEX_ENTRIES)
}
