use crate::error::{NetdiagError, Result};
use crate::models::{ActionVerification, RunManifest};
use crate::storage::{
    RecoveredActionVerificationTransaction, action_verification_journal_path,
    ensure_run_has_no_pending_hil_transaction, publish_action_verification_transaction,
    read_stable_regular_file_bounded, recover_action_verification_transaction,
    with_exclusive_file_locks,
};
use std::path::Path;

const MAX_TRANSACTION_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn record_action_verification_artifact(
    run_dir: &Path,
    after_run_id: &str,
    verification: &ActionVerification,
) -> Result<()> {
    validate_verification_identity(run_dir, after_run_id, verification)?;
    let manifest_path = run_dir.join("manifest.json");
    let journal_path = action_verification_journal_path(run_dir);
    with_exclusive_file_locks(&[manifest_path.clone(), journal_path], || {
        ensure_run_has_no_pending_hil_transaction(run_dir, &verification.before_run_id)?;
        let recovered =
            recover_action_verification_transaction(run_dir, &verification.before_run_id)?;
        record_under_manifest_lock(
            run_dir,
            &manifest_path,
            after_run_id,
            verification,
            recovered,
        )
    })
}

fn record_under_manifest_lock(
    run_dir: &Path,
    manifest_path: &Path,
    after_run_id: &str,
    verification: &ActionVerification,
    recovered: RecoveredActionVerificationTransaction,
) -> Result<()> {
    let manifest_preimage = read_required_regular_file(manifest_path, "run manifest")?;
    let mut manifest: RunManifest =
        crate::strict_json::from_slice(&manifest_preimage).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "invalid run manifest at {}: {}",
                manifest_path.display(),
                crate::strict_json::error_summary(&error)
            ))
        })?;
    validate_manifest_identity(run_dir, &manifest, verification)?;
    crate::storage::ensure_manifest_artifact_limit(&manifest)?;

    let artifact_key = format!("action_verification_{after_run_id}");
    let file_name = format!("{artifact_key}.json");
    validate_manifest_artifact_slot(&manifest, &artifact_key, &file_name)?;
    manifest.artifact_paths.insert(artifact_key, file_name);
    crate::storage::ensure_manifest_artifact_limit(&manifest)?;
    publish_action_verification_transaction(
        run_dir,
        verification,
        &manifest,
        &manifest_preimage,
        recovered,
    )
}

fn validate_verification_identity(
    run_dir: &Path,
    after_run_id: &str,
    verification: &ActionVerification,
) -> Result<()> {
    crate::identifiers::validate_portable_id("before run id", &verification.before_run_id)?;
    crate::identifiers::validate_portable_id("after run id", after_run_id)?;
    if verification.after_run_id != after_run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "action verification after run id {} does not match requested run id {after_run_id}",
            verification.after_run_id
        )));
    }
    let directory_run_id = run_dir
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "run directory has no portable file name: {}",
                run_dir.display()
            ))
        })?;
    crate::identifiers::validate_portable_id("run directory id", directory_run_id)?;
    if directory_run_id != verification.before_run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "action verification before run id {} does not match directory {directory_run_id}",
            verification.before_run_id
        )));
    }
    Ok(())
}

fn validate_manifest_identity(
    run_dir: &Path,
    manifest: &RunManifest,
    verification: &ActionVerification,
) -> Result<()> {
    crate::identifiers::validate_portable_id("manifest run id", &manifest.run_id)?;
    if manifest.run_id != verification.before_run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest run id {} does not match action verification before run id {} at {}",
            manifest.run_id,
            verification.before_run_id,
            run_dir.display()
        )));
    }
    if verification.observed_comparison.left.run_id != verification.before_run_id
        || verification.observed_comparison.right.run_id != verification.after_run_id
    {
        return Err(NetdiagError::InvalidTrace(
            "action verification comparison run ids do not match its before/after run ids"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest_artifact_slot(
    manifest: &RunManifest,
    artifact_key: &str,
    file_name: &str,
) -> Result<()> {
    if let Some(existing) = manifest.artifact_paths.get(artifact_key)
        && existing != file_name
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest artifact key {artifact_key} points to {existing}, expected {file_name}"
        )));
    }
    if let Some((existing_key, _)) = manifest
        .artifact_paths
        .iter()
        .find(|(key, value)| key.as_str() != artifact_key && value.as_str() == file_name)
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest artifact path {file_name} is already owned by key {existing_key}"
        )));
    }
    Ok(())
}

fn read_required_regular_file(path: &Path, description: &str) -> Result<Vec<u8>> {
    read_stable_regular_file_bounded(path, MAX_TRANSACTION_FILE_BYTES)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!("{description} is missing: {}", path.display()))
    })
}

#[cfg(test)]
pub(super) fn fail_next_manifest_update() {
    crate::storage::fail_next_action_verification_manifest_update();
}

#[cfg(test)]
mod tests;
