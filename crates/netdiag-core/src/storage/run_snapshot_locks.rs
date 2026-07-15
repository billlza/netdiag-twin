use self::location_identity::ResolvedRunLocation;
use self::output_validation::ensure_not_protected as validate_output;
use self::target_path::resolve_target_path;
use crate::error::Result;
use crate::storage::{RunLocation, with_exclusive_file_locks};
use std::path::{Path, PathBuf};

mod location_identity;
mod output_validation;
mod target_path;
mod target_set;
pub(crate) use target_set::SnapshotOutputTarget;

pub(crate) use target_path::{ACTION_VERIFICATION_JOURNAL_FILE_NAME, HIL_REVIEW_JOURNAL_FILE_NAME};

pub(crate) fn with_run_snapshot_locks<T>(
    artifact_root: &Path,
    run_id: &str,
    extra_targets: &[&Path],
    action: impl FnOnce(&RunLocation) -> Result<T>,
) -> Result<T> {
    let initial = ResolvedRunLocation::capture(artifact_root, run_id)?;
    let targets = snapshot_targets(&initial.location, run_id, extra_targets, true)?;
    with_sorted_target_locks(&targets, || {
        let locked = ResolvedRunLocation::capture(artifact_root, run_id)?;
        initial.ensure_same_location(&locked)?;
        action(&locked.location)
    })
}

pub(crate) fn with_resolved_run_snapshot_locks<T>(
    location: &RunLocation,
    run_id: &str,
    action: impl FnOnce(&RunLocation) -> Result<T>,
) -> Result<T> {
    let initial = ResolvedRunLocation::capture_resolved(location, run_id)?;
    let targets = snapshot_targets(location, run_id, &[], false)?;
    with_sorted_target_locks(&targets, || {
        let locked = ResolvedRunLocation::capture_resolved(location, run_id)?;
        initial.ensure_same_location(&locked)?;
        action(&locked.location)
    })
}

pub(crate) fn with_transaction_target_locks<T>(
    location: &RunLocation,
    run_id: &str,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let targets = snapshot_targets(location, run_id, &[], false)?;
    with_sorted_target_locks(&targets, action)
}

fn snapshot_targets(
    location: &RunLocation,
    run_id: &str,
    extra_targets: &[&Path],
    allow_lab_archive: bool,
) -> Result<Vec<PathBuf>> {
    let protected = target_set::protected_target_set(location, run_id)?;
    let mut targets = protected.files.clone();
    let allowed_archive = allow_lab_archive
        .then_some(location.lab_run_dir.as_deref())
        .flatten()
        .map(|root| resolve_target_path(&root.join(format!("netdiag-evidence-{run_id}.zip"))))
        .transpose()?;
    for extra in extra_targets {
        let resolved = resolve_target_path(extra)?;
        validate_output(
            &resolved,
            extra,
            &protected.files,
            &protected.directories,
            allowed_archive.as_deref(),
        )?;
        targets.push(resolved);
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn with_sorted_target_locks<T>(
    targets: &[PathBuf],
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_exclusive_file_locks(targets, action)
}

#[cfg(test)]
mod tests;
