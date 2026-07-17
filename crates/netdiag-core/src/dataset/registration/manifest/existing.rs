use super::super::super::DatasetManifest;
use crate::error::{NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, read_stable_regular_file_bounded_at,
    typed_json::MAX_DATASET_MANIFEST_BYTES,
};

mod decode;

pub(in crate::dataset::registration) fn existing_compatible(
    target: &BoundAtomicFileTarget,
    expected: &DatasetManifest,
) -> Result<DatasetManifest> {
    let bytes = read_stable_regular_file_bounded_at(target, MAX_DATASET_MANIFEST_BYTES)?
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "registered dataset manifest is missing: {}",
                target.resolved_path().display()
            ))
        })?;
    validate_compatible(target, expected, &bytes)
}

pub(in crate::dataset::registration) fn ensure_existing_compatible_if_present(
    target: &BoundAtomicFileTarget,
    expected: &DatasetManifest,
) -> Result<()> {
    let Some(bytes) = read_stable_regular_file_bounded_at(target, MAX_DATASET_MANIFEST_BYTES)?
    else {
        return Ok(());
    };
    validate_compatible(target, expected, &bytes).map(|_| ())
}

fn validate_compatible(
    target: &BoundAtomicFileTarget,
    expected: &DatasetManifest,
    bytes: &[u8],
) -> Result<DatasetManifest> {
    let existing = decode::manifest(target, bytes)?;
    let mut expected_with_existing_timestamp = expected.clone();
    expected_with_existing_timestamp.created_at = existing.created_at;
    if existing != expected_with_existing_timestamp {
        return Err(NetdiagError::InvalidTrace(format!(
            "registered dataset manifest conflicts with immutable artifact at {}",
            target.resolved_path().display()
        )));
    }
    Ok(existing)
}
