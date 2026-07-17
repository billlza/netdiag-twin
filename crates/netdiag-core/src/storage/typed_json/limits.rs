use crate::error::{NetdiagError, Result};

pub(crate) const MAX_RUN_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_RUN_REPORT_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_RUN_INDEX_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_CONNECTOR_HEALTH_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_LAB_CONNECTOR_HEALTH_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_LAB_RUN_INDEX_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_LAB_ACCEPTANCE_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_LAB_COMPARISON_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_ML_RESULT_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_DATASET_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_DATASET_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_GENERIC_JSON_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_RUN_MANIFEST_ARTIFACTS: usize = 4_096;
pub(crate) const MAX_RUN_INDEX_ENTRIES: usize = 50;
pub(crate) const MAX_LAB_RUN_INDEX_ENTRIES: usize = 200;
pub(crate) const MAX_DATASET_REGISTRY_ENTRIES: usize = 200;

pub(crate) fn ensure_collection_limit(kind: &str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(NetdiagError::InvalidTrace(format!(
            "{kind} contains {actual} entries, exceeding the {max}-entry limit"
        )));
    }
    Ok(())
}

pub(crate) fn ensure_manifest_artifact_limit(manifest: &crate::models::RunManifest) -> Result<()> {
    ensure_collection_limit(
        "run manifest artifact paths",
        manifest.artifact_paths.len(),
        MAX_RUN_MANIFEST_ARTIFACTS,
    )
}
