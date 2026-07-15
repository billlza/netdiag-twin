use super::journal::{ActionVerificationJournal, TransactionPhase, save_journal};
use super::{
    MAX_ACTION_VERIFICATION_BYTES, MAX_ACTION_VERIFICATION_TOTAL_BYTES, invalid_journal,
    transaction_conflict,
};
use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;
use crate::storage::sha256_stable_regular_file_bounded;
use crate::storage::typed_json::{
    MAX_RUN_MANIFEST_BYTES, read_required_stable_json_bounded, save_json_atomic_bounded,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetState {
    Old,
    New,
    Unchanged,
}

pub(super) fn execute_transaction(
    run_dir: &Path,
    journal: &mut ActionVerificationJournal,
) -> Result<()> {
    journal.validate(run_dir)?;
    if journal.phase != TransactionPhase::Committing {
        return verify_committed_targets(run_dir, journal);
    }
    verify_artifact_receipts(run_dir, journal, false)?;
    let artifact_path = journal.artifact_path(run_dir);
    let manifest_path = run_dir.join("manifest.json");
    let artifact_state = target_state(
        &artifact_path,
        MAX_ACTION_VERIFICATION_BYTES,
        journal.expected_artifact_sha256.as_deref(),
        &journal.artifact_sha256,
        "action verification",
    )?;
    let manifest_state = target_state(
        &manifest_path,
        MAX_RUN_MANIFEST_BYTES,
        Some(&journal.expected_manifest_sha256),
        &journal.manifest_sha256,
        "run manifest",
    )?;
    if artifact_state == TargetState::Old && manifest_state == TargetState::New {
        return Err(transaction_conflict(
            "manifest contains the new artifact reference while the artifact still has its old content",
        ));
    }
    if artifact_state == TargetState::Old {
        let verification = journal
            .verification
            .as_ref()
            .ok_or_else(|| invalid_journal("committing transaction has no verification payload"))?;
        save_json_atomic_bounded(
            &artifact_path,
            verification,
            MAX_ACTION_VERIFICATION_BYTES,
            "action verification",
        )?;
        verify_target_hash(
            &artifact_path,
            MAX_ACTION_VERIFICATION_BYTES,
            &journal.artifact_sha256,
            "action verification",
        )?;
        maybe_crash_after_artifact_publish();
    }
    if manifest_state == TargetState::Old {
        let manifest = journal
            .manifest
            .as_ref()
            .ok_or_else(|| invalid_journal("committing transaction has no manifest payload"))?;
        maybe_fail_manifest_update()?;
        save_json_atomic_bounded(
            &manifest_path,
            manifest,
            MAX_RUN_MANIFEST_BYTES,
            "run manifest",
        )?;
        verify_target_hash(
            &manifest_path,
            MAX_RUN_MANIFEST_BYTES,
            &journal.manifest_sha256,
            "run manifest",
        )?;
        maybe_crash_after_manifest_publish();
    }
    journal.phase = TransactionPhase::Committed;
    journal.verification = None;
    journal.manifest = None;
    save_journal(run_dir, journal)
}

pub(super) fn verify_committed_targets(
    run_dir: &Path,
    journal: &ActionVerificationJournal,
) -> Result<()> {
    verify_artifact_receipts(run_dir, journal, true)
}

fn verify_artifact_receipts(
    run_dir: &Path,
    journal: &ActionVerificationJournal,
    include_current: bool,
) -> Result<()> {
    let manifest_path = run_dir.join("manifest.json");
    let manifest = read_required_stable_json_bounded::<RunManifest>(
        &manifest_path,
        MAX_RUN_MANIFEST_BYTES,
        "run manifest",
    )?;
    crate::storage::ensure_manifest_artifact_limit(&manifest)?;
    if manifest.run_id != journal.run_id {
        return Err(transaction_conflict(format!(
            "run manifest at {} belongs to {}, expected {}",
            manifest_path.display(),
            manifest.run_id,
            journal.run_id
        )));
    }
    let mut total_bytes = 0_u64;
    for (key, receipt) in &journal.artifacts {
        if !include_current && key == &journal.artifact_key {
            continue;
        }
        if manifest.artifact_paths.get(key).map(String::as_str) != Some(receipt.file_name.as_str())
        {
            return Err(transaction_conflict(format!(
                "run manifest at {} no longer owns {key} as {}",
                manifest_path.display(),
                receipt.file_name
            )));
        }
        let path = run_dir.join(&receipt.file_name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| NetdiagError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.len() != receipt.bytes {
            return Err(transaction_conflict(format!(
                "action artifact {key} at {} has {} bytes, expected {}",
                path.display(),
                metadata.len(),
                receipt.bytes
            )));
        }
        total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
            transaction_conflict("cumulative action artifact byte length overflow")
        })?;
        if total_bytes > MAX_ACTION_VERIFICATION_TOTAL_BYTES {
            return Err(transaction_conflict(format!(
                "cumulative action artifacts exceed the {MAX_ACTION_VERIFICATION_TOTAL_BYTES}-byte verification limit"
            )));
        }
        verify_target_hash(
            &path,
            MAX_ACTION_VERIFICATION_BYTES,
            &receipt.sha256,
            &format!("action artifact {key}"),
        )?;
    }
    Ok(())
}

fn target_state(
    path: &Path,
    max_bytes: u64,
    expected_old: Option<&str>,
    expected_new: &str,
    description: &str,
) -> Result<TargetState> {
    let current = sha256_stable_regular_file_bounded(path, max_bytes)?;
    if expected_old == Some(expected_new) && current.as_deref() == Some(expected_new) {
        return Ok(TargetState::Unchanged);
    }
    if current.as_deref() == Some(expected_new) {
        return Ok(TargetState::New);
    }
    if current.as_deref() == expected_old {
        return Ok(TargetState::Old);
    }
    Err(transaction_conflict(format!(
        "{description} at {} changed outside the transaction (expected old {:?} or new {expected_new}, found {:?})",
        path.display(),
        expected_old,
        current
    )))
}

fn verify_target_hash(
    path: &Path,
    max_bytes: u64,
    expected: &str,
    description: &str,
) -> Result<()> {
    let actual = sha256_stable_regular_file_bounded(path, max_bytes)?;
    if actual.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(transaction_conflict(format!(
            "{description} at {} does not match its committed hash {expected} (found {:?})",
            path.display(),
            actual
        )))
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_MANIFEST_UPDATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_manifest_update() {
    FAIL_MANIFEST_UPDATE.with(|fail| fail.set(true));
}

fn maybe_fail_manifest_update() -> Result<()> {
    #[cfg(test)]
    if FAIL_MANIFEST_UPDATE.with(|fail| fail.replace(false)) {
        return Err(NetdiagError::InvalidTrace(
            "injected action verification manifest update failure".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn maybe_crash_after_artifact_publish() {
    if std::env::var("NETDIAG_TEST_ACTION_VERIFICATION_CRASH_POINT").as_deref()
        == Ok("after_artifact")
    {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn maybe_crash_after_artifact_publish() {}

#[cfg(test)]
fn maybe_crash_after_manifest_publish() {
    if std::env::var("NETDIAG_TEST_ACTION_VERIFICATION_CRASH_POINT").as_deref()
        == Ok("after_manifest")
    {
        std::process::exit(87);
    }
}

#[cfg(not(test))]
fn maybe_crash_after_manifest_publish() {}
