use crate::error::{NetdiagError, Result};
use crate::models::{ActionVerification, RunManifest};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod journal;
mod publisher;

use journal::{ActionVerificationJournal, TransactionPhase, load_journal, save_journal};
use publisher::{execute_transaction, verify_committed_targets};

pub(super) const MAX_ACTION_VERIFICATION_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_ACTION_VERIFICATION_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_ACTION_VERIFICATION_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) struct RecoveredActionVerificationTransaction {
    artifacts: BTreeMap<String, journal::ActionArtifactReceipt>,
}

#[cfg(test)]
pub(crate) use publisher::fail_next_manifest_update;

pub(crate) fn action_verification_journal_path(run_dir: &Path) -> PathBuf {
    run_dir.join(super::run_snapshot_locks::ACTION_VERIFICATION_JOURNAL_FILE_NAME)
}

pub(crate) fn ensure_no_pending_transaction(run_dir: &Path, run_id: &str) -> Result<()> {
    if let Some(journal) = load_journal(run_dir, run_id)?
        && journal.phase == TransactionPhase::Committing
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "run {run_id} has pending action verification transaction {}; retry the verify-action command to recover it",
            journal.transaction_id
        )));
    }
    Ok(())
}

pub(crate) fn recover_transaction(
    run_dir: &Path,
    run_id: &str,
) -> Result<RecoveredActionVerificationTransaction> {
    let Some(mut journal) = load_journal(run_dir, run_id)? else {
        return Ok(RecoveredActionVerificationTransaction {
            artifacts: BTreeMap::new(),
        });
    };
    match journal.phase {
        TransactionPhase::Committing => execute_transaction(run_dir, &mut journal)?,
        TransactionPhase::Committed => verify_committed_targets(run_dir, &journal)?,
    }
    Ok(RecoveredActionVerificationTransaction {
        artifacts: journal.artifacts.clone(),
    })
}

pub(crate) fn publish_transaction(
    run_dir: &Path,
    verification: &ActionVerification,
    manifest: &RunManifest,
    manifest_preimage: &[u8],
    recovered: RecoveredActionVerificationTransaction,
) -> Result<()> {
    let mut journal = ActionVerificationJournal::new(
        run_dir,
        verification,
        manifest,
        manifest_preimage,
        recovered.artifacts,
    )?;
    save_journal(run_dir, &journal)?;
    execute_transaction(run_dir, &mut journal)
}

pub(super) fn invalid_journal(message: impl std::fmt::Display) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "invalid action verification transaction journal: {message}"
    ))
}

pub(super) fn transaction_conflict(message: impl std::fmt::Display) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "action verification transaction conflict: {message}"
    ))
}
