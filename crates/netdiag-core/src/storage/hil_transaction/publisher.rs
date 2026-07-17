use super::durability::{publish_staged_file, remove_file_durably};
use super::journal::{HilReviewJournal, JournalPhase, JournalTarget, save_journal};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::sha256_stable_regular_file_bounded;
use crate::storage::typed_json::{
    MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES, MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES,
    MAX_RUN_INDEX_BYTES, save_json_atomic_bounded,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_EVIDENCE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) struct PreparedTarget {
    key: String,
    target: PathBuf,
    staged: PathBuf,
    expected_old_sha256: Option<String>,
    new_sha256: String,
    result: Option<Value>,
}

impl PreparedTarget {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn staged(&self) -> &Path {
        &self.staged
    }

    fn journal_target(&self) -> JournalTarget {
        JournalTarget {
            key: self.key.clone(),
            target_path: self.target.display().to_string(),
            expected_old_sha256: self.expected_old_sha256.clone(),
            new_sha256: self.new_sha256.clone(),
            result: self.result.clone(),
        }
    }
}

pub(crate) struct JournalPublisher<'a> {
    run_dir: &'a Path,
    journal: &'a mut HilReviewJournal,
}

impl<'a> JournalPublisher<'a> {
    pub fn new(run_dir: &'a Path, journal: &'a mut HilReviewJournal) -> Self {
        Self { run_dir, journal }
    }

    pub fn has_no_targets(&self) -> bool {
        self.journal.targets.is_empty()
    }

    pub fn prepare_json<T: Serialize + ?Sized>(
        &self,
        key: &str,
        target: &Path,
        value: &T,
    ) -> Result<PreparedTarget> {
        let target = canonical_target_path(target)?;
        let staged = stage_path(&target, &self.journal.transaction_id, key)?;
        save_json_atomic_bounded(&staged, value, hash_limit_for_key(key), key)?;
        self.prepared_target(key, target, staged, None)
    }

    pub fn prepare_generated<T, F>(
        &self,
        key: &str,
        target: &Path,
        generate: F,
    ) -> Result<(PreparedTarget, T)>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce(&Path) -> Result<T>,
    {
        let target = canonical_target_path(target)?;
        let staged = stage_path(&target, &self.journal.transaction_id, key)?;
        remove_file_durably(&staged)?;
        let generated = generate(&staged)?;
        let result = serde_json::to_value(&generated)?;
        let prepared = self.prepared_target(key, target, staged, Some(result))?;
        Ok((prepared, generated))
    }

    fn prepared_target(
        &self,
        key: &str,
        target: PathBuf,
        staged: PathBuf,
        result: Option<Value>,
    ) -> Result<PreparedTarget> {
        validate_key(key)?;
        Ok(PreparedTarget {
            key: key.to_string(),
            expected_old_sha256: optional_file_hash(&target, hash_limit_for_key(key))?,
            new_sha256: required_file_hash(&staged, hash_limit_for_key(key))?,
            target,
            staged,
            result,
        })
    }

    pub fn register_all(&mut self, prepared: &[PreparedTarget]) -> Result<()> {
        if self.journal.phase != JournalPhase::Prepared || !self.journal.targets.is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "HIL transaction targets can only be registered once while prepared".to_string(),
            ));
        }
        validate_prepared_set(prepared)?;
        self.journal.targets = prepared
            .iter()
            .map(PreparedTarget::journal_target)
            .collect();
        save_journal(self.run_dir, self.journal)
    }

    pub fn begin_commit(&mut self) -> Result<()> {
        if self.journal.phase == JournalPhase::Prepared {
            if self.journal.targets.is_empty() {
                return Err(NetdiagError::InvalidTrace(
                    "HIL transaction cannot commit without registered targets".to_string(),
                ));
            }
            self.journal.phase = JournalPhase::Committing;
            save_journal(self.run_dir, self.journal)?;
        }
        Ok(())
    }

    pub fn verify_or_publish_all(&self, expected: &[(&str, &Path)]) -> Result<()> {
        validate_expected_targets(self.journal, expected)?;
        for (key, target) in expected {
            maybe_inject_failure(key)?;
            let target = canonical_target_path(target)?;
            let registered =
                self.journal.target(key).cloned().ok_or_else(|| {
                    transaction_conflict(format!("journal target {key} is missing"))
                })?;
            validate_registered_target(&registered, &target)?;
            let staged = stage_path(&target, &self.journal.transaction_id, key)?;
            self.recover_registered_target(&registered, &target, &staged)?;
        }
        Ok(())
    }

    pub fn finish_commit(&mut self) -> Result<()> {
        #[cfg(test)]
        tests::maybe_crash_before_commit_receipt();
        self.journal.phase = JournalPhase::Committed;
        save_journal(self.run_dir, self.journal)
    }

    fn recover_registered_target(
        &self,
        registered: &JournalTarget,
        target: &Path,
        staged: &Path,
    ) -> Result<()> {
        let hash_limit = hash_limit_for_key(&registered.key);
        let current = optional_file_hash(target, hash_limit)?;
        if current.as_deref() == Some(registered.new_sha256.as_str()) {
            remove_file_durably(staged)?;
            return Ok(());
        }
        if current != registered.expected_old_sha256 {
            return Err(transaction_conflict(format!(
                "target {} changed outside transaction {} (expected old {:?}, found {:?})",
                target.display(),
                self.journal.transaction_id,
                registered.expected_old_sha256,
                current
            )));
        }
        publish_staged_file(staged, target, hash_limit, &registered.new_sha256)
    }
}

fn validate_prepared_set(prepared: &[PreparedTarget]) -> Result<()> {
    if prepared.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "HIL transaction prepared no targets".to_string(),
        ));
    }
    let mut keys = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for target in prepared {
        if !keys.insert(target.key.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate prepared HIL target key: {}",
                target.key
            )));
        }
        if !paths.insert(target.target.as_path()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate prepared HIL target path: {}",
                target.target.display()
            )));
        }
    }
    Ok(())
}

fn validate_expected_targets(journal: &HilReviewJournal, expected: &[(&str, &Path)]) -> Result<()> {
    if journal.targets.len() != expected.len() {
        return Err(transaction_conflict(format!(
            "journal has {} targets, expected {}",
            journal.targets.len(),
            expected.len()
        )));
    }
    let mut keys = BTreeSet::new();
    for (key, path) in expected {
        if !keys.insert(*key) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate expected HIL target key: {key}"
            )));
        }
        let target = canonical_target_path(path)?;
        let registered = journal
            .target(key)
            .ok_or_else(|| transaction_conflict(format!("journal target {key} is missing")))?;
        validate_registered_target(registered, &target)?;
    }
    Ok(())
}

fn canonical_target_path(target: &Path) -> Result<PathBuf> {
    let parent = target.parent().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "HIL transaction target has no parent: {}",
            target.display()
        ))
    })?;
    let file_name = target.file_name().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "HIL transaction target has no file name: {}",
            target.display()
        ))
    })?;
    let canonical_parent = fs::canonicalize(parent).with_path(parent)?;
    let canonical_target = canonical_parent.join(file_name);
    if fs::symlink_metadata(&canonical_target)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "HIL transaction target must not be a symbolic link: {}",
            canonical_target.display()
        )));
    }
    Ok(canonical_target)
}

fn stage_path(target: &Path, transaction_id: &str, key: &str) -> Result<PathBuf> {
    validate_key(key)?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "HIL transaction target file name is not UTF-8: {}",
                target.display()
            ))
        })?;
    Ok(target.with_file_name(format!(".{file_name}.hil-{transaction_id}-{key}.stage")))
}

fn validate_registered_target(registered: &JournalTarget, target: &Path) -> Result<()> {
    if registered.target_path == target.display().to_string() {
        Ok(())
    } else {
        Err(transaction_conflict(format!(
            "journal target {} points to {}, expected {}",
            registered.key,
            registered.target_path,
            target.display()
        )))
    }
}

fn validate_key(key: &str) -> Result<()> {
    if !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "invalid HIL transaction target key: {key:?}"
        )))
    }
}

fn optional_file_hash(path: &Path, max_bytes: u64) -> Result<Option<String>> {
    sha256_stable_regular_file_bounded(path, max_bytes)
}

fn required_file_hash(path: &Path, max_bytes: u64) -> Result<String> {
    optional_file_hash(path, max_bytes)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "HIL transaction staged file is missing: {}",
            path.display()
        ))
    })
}

fn hash_limit_for_key(key: &str) -> u64 {
    match key {
        "run_index" => MAX_RUN_INDEX_BYTES,
        "lab_acceptance" => MAX_LAB_ACCEPTANCE_BYTES,
        "lab_comparison" => MAX_LAB_COMPARISON_BYTES,
        "lab_evidence_manifest" => MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES,
        "lab_evidence_archive" => MAX_EVIDENCE_ARCHIVE_BYTES,
        _ => super::MAX_TRANSACTION_JSON_BYTES,
    }
}

fn transaction_conflict(message: String) -> NetdiagError {
    NetdiagError::InvalidTrace(format!("HIL transaction conflict: {message}"))
}

#[cfg(test)]
thread_local! {
    static FAIL_BEFORE_PUBLISHING: std::cell::RefCell<Option<String>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn fail_before_publishing(key: &str) {
    FAIL_BEFORE_PUBLISHING.with(|target| *target.borrow_mut() = Some(key.to_string()));
}

fn maybe_inject_failure(key: &str) -> Result<()> {
    #[cfg(not(test))]
    let _ = key;
    #[cfg(test)]
    {
        let should_fail = FAIL_BEFORE_PUBLISHING.with(|target| {
            let mut target = target.borrow_mut();
            (target.as_deref() == Some(key))
                .then(|| target.take())
                .is_some()
        });
        if should_fail {
            return Err(NetdiagError::InvalidTrace(format!(
                "injected HIL transaction failure before publishing {key}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    pub(super) fn maybe_crash_before_commit_receipt() {
        if std::env::var("NETDIAG_TEST_HIL_CRASH_POINT").as_deref() == Ok("before_commit_receipt") {
            std::process::exit(88);
        }
    }
}
