use super::bounded_digest::MAX_REGISTRATION_DATASET_BYTES;
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, NoClobberDisposition, StagedAtomicFile,
    sha256_stable_regular_file_bounded_at,
};

pub(super) fn publish_snapshot(
    root: &TrustedDatasetRoot,
    staged: StagedAtomicFile,
    target: &BoundAtomicFileTarget,
    expected_hash: &str,
) -> Result<NoClobberDisposition> {
    let disposition = staged.publish_noclobber(target)?;
    if let Err(error) = verify_existing_hash(target, expected_hash) {
        return match disposition {
            NoClobberDisposition::Created => {
                root.remove_created_file_after_error(target, AtomicPublishPhase::Published, error)
            }
            NoClobberDisposition::Existing => Err(error),
        };
    }
    Ok(disposition)
}

fn verify_existing_hash(target: &BoundAtomicFileTarget, expected_hash: &str) -> Result<()> {
    let actual_hash = sha256_stable_regular_file_bounded_at(
        target,
        MAX_REGISTRATION_DATASET_BYTES,
    )?
    .ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "registered dataset file disappeared before its immutable hash could be verified: {}",
            target.resolved_path().display()
        ))
    })?;
    ensure_hash_matches(target, expected_hash, &actual_hash)
}

pub(super) fn verify_existing_hash_if_present(
    target: &BoundAtomicFileTarget,
    expected_hash: &str,
) -> Result<()> {
    let Some(actual_hash) =
        sha256_stable_regular_file_bounded_at(target, MAX_REGISTRATION_DATASET_BYTES)?
    else {
        return Ok(());
    };
    ensure_hash_matches(target, expected_hash, &actual_hash)
}

fn ensure_hash_matches(
    target: &BoundAtomicFileTarget,
    expected_hash: &str,
    actual_hash: &str,
) -> Result<()> {
    if actual_hash != expected_hash {
        return Err(NetdiagError::InvalidTrace(format!(
            "registered dataset file hash mismatch at {}",
            target.resolved_path().display()
        )));
    }
    Ok(())
}
