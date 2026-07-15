use super::transaction::{transaction_directory_targets, transaction_targets};
use crate::error::Result;
use crate::storage::RunLocation;
use crate::storage::run_snapshot_locks::target_path::resolve_target_path;
use std::path::PathBuf;

pub(in crate::storage::run_snapshot_locks) struct ProtectedTargetSet {
    pub(in crate::storage::run_snapshot_locks) files: Vec<PathBuf>,
    pub(in crate::storage::run_snapshot_locks) directories: Vec<PathBuf>,
}

pub(in crate::storage::run_snapshot_locks) fn protected_target_set(
    location: &RunLocation,
    run_id: &str,
) -> Result<ProtectedTargetSet> {
    let mut files = transaction_targets(location, run_id)
        .iter()
        .map(|target| resolve_target_path(target))
        .collect::<Result<Vec<_>>>()?;
    files.push(resolve_target_path(&location.run_dir.join(
        crate::storage::run_snapshot_locks::HIL_REVIEW_JOURNAL_FILE_NAME,
    ))?);
    files.push(resolve_target_path(&location.run_dir.join(
        crate::storage::run_snapshot_locks::ACTION_VERIFICATION_JOURNAL_FILE_NAME,
    ))?);
    let directories = transaction_directory_targets(location)
        .iter()
        .map(|target| resolve_target_path(target))
        .collect::<Result<Vec<_>>>()?;
    Ok(ProtectedTargetSet { files, directories })
}
