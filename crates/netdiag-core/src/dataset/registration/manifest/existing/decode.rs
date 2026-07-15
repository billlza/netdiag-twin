use crate::dataset::DatasetManifest;
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;

pub(super) fn manifest(target: &BoundAtomicFileTarget, bytes: &[u8]) -> Result<DatasetManifest> {
    crate::strict_json::from_slice(bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "registered dataset manifest is invalid at {}: {}",
            target.resolved_path().display(),
            crate::strict_json::error_summary(&source)
        ))
    })
}
