use super::{
    MAX_ACTION_VERIFICATION_BYTES, MAX_ACTION_VERIFICATION_JOURNAL_BYTES,
    MAX_ACTION_VERIFICATION_TOTAL_BYTES, action_verification_journal_path, invalid_journal,
    transaction_conflict,
};
use crate::error::{NetdiagError, Result};
use crate::models::{ActionVerification, RunManifest};
use crate::storage::typed_json::{
    MAX_RUN_MANIFEST_BYTES, prepare_json_bounded, save_json_atomic_bounded,
};
use crate::storage::{read_stable_regular_file_bounded, sha256_stable_regular_file_bounded};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const JOURNAL_SCHEMA: &str = "netdiag-action-verification-transaction/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransactionPhase {
    Committing,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionArtifactReceipt {
    pub(super) file_name: String,
    pub(super) sha256: String,
    pub(super) bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionVerificationJournal {
    pub(super) schema: String,
    pub(super) transaction_id: String,
    pub(super) phase: TransactionPhase,
    pub(super) run_id: String,
    pub(super) after_run_id: String,
    pub(super) artifact_key: String,
    pub(super) artifact_file_name: String,
    pub(super) expected_artifact_sha256: Option<String>,
    pub(super) expected_manifest_sha256: String,
    pub(super) artifact_sha256: String,
    pub(super) manifest_sha256: String,
    pub(super) artifacts: BTreeMap<String, ActionArtifactReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) verification: Option<ActionVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) manifest: Option<RunManifest>,
}

impl ActionVerificationJournal {
    pub(super) fn new(
        run_dir: &Path,
        verification: &ActionVerification,
        manifest: &RunManifest,
        manifest_preimage: &[u8],
        mut artifacts: BTreeMap<String, ActionArtifactReceipt>,
    ) -> Result<Self> {
        let artifact_key = artifact_key(&verification.after_run_id);
        let artifact_file_name = format!("{artifact_key}.json");
        let artifact_path = run_dir.join(&artifact_file_name);
        let manifest_path = run_dir.join("manifest.json");
        let artifact_bytes = prepare_json_bounded(
            verification,
            MAX_ACTION_VERIFICATION_BYTES,
            "action verification",
        )?;
        let manifest_bytes =
            prepare_json_bounded(manifest, MAX_RUN_MANIFEST_BYTES, "run manifest")?;
        let expected_artifact_sha256 =
            sha256_stable_regular_file_bounded(&artifact_path, MAX_ACTION_VERIFICATION_BYTES)?;
        let expected_manifest_sha256 = sha256_bytes(manifest_preimage);
        let current_manifest_sha256 =
            sha256_stable_regular_file_bounded(&manifest_path, MAX_RUN_MANIFEST_BYTES)?
                .ok_or_else(|| {
                    NetdiagError::InvalidTrace(format!(
                        "run manifest is missing: {}",
                        manifest_path.display()
                    ))
                })?;
        if current_manifest_sha256 != expected_manifest_sha256 {
            return Err(transaction_conflict(format!(
                "run manifest at {} changed after it was validated",
                manifest_path.display()
            )));
        }
        let artifact_sha256 = sha256_bytes(artifact_bytes.as_bytes());
        artifacts.insert(
            artifact_key.clone(),
            ActionArtifactReceipt {
                file_name: artifact_file_name.clone(),
                sha256: artifact_sha256.clone(),
                bytes: artifact_bytes.as_bytes().len() as u64,
            },
        );
        let journal = Self {
            schema: JOURNAL_SCHEMA.to_string(),
            transaction_id: uuid::Uuid::new_v4().to_string(),
            phase: TransactionPhase::Committing,
            run_id: verification.before_run_id.clone(),
            after_run_id: verification.after_run_id.clone(),
            artifact_key,
            artifact_file_name,
            expected_artifact_sha256,
            expected_manifest_sha256,
            artifact_sha256,
            manifest_sha256: sha256_bytes(manifest_bytes.as_bytes()),
            artifacts,
            verification: Some(verification.clone()),
            manifest: Some(manifest.clone()),
        };
        journal.validate(run_dir)?;
        Ok(journal)
    }

    pub(super) fn validate(&self, run_dir: &Path) -> Result<()> {
        if self.schema != JOURNAL_SCHEMA {
            return Err(invalid_journal(format!(
                "unsupported schema {}",
                self.schema
            )));
        }
        uuid::Uuid::parse_str(&self.transaction_id).map_err(|error| {
            invalid_journal(format!(
                "invalid transaction id {}: {error}",
                self.transaction_id
            ))
        })?;
        crate::identifiers::validate_portable_id("action transaction run id", &self.run_id)?;
        crate::identifiers::validate_portable_id(
            "action transaction after run id",
            &self.after_run_id,
        )?;
        validate_run_directory_identity(run_dir, &self.run_id)?;
        let expected_key = artifact_key(&self.after_run_id);
        let expected_file_name = format!("{expected_key}.json");
        if self.artifact_key != expected_key || self.artifact_file_name != expected_file_name {
            return Err(invalid_journal(
                "artifact key or file name does not match the after run id",
            ));
        }
        validate_hash("expected manifest", &self.expected_manifest_sha256)?;
        validate_hash("artifact", &self.artifact_sha256)?;
        validate_hash("manifest", &self.manifest_sha256)?;
        if let Some(hash) = &self.expected_artifact_sha256 {
            validate_hash("expected artifact", hash)?;
        }
        validate_artifact_receipts(&self.artifacts)?;
        let current_receipt = self.artifacts.get(&self.artifact_key).ok_or_else(|| {
            invalid_journal("current action artifact is absent from the cumulative receipt")
        })?;
        if current_receipt.file_name != self.artifact_file_name
            || current_receipt.sha256 != self.artifact_sha256
        {
            return Err(invalid_journal(
                "current action artifact does not match the cumulative receipt",
            ));
        }
        match self.phase {
            TransactionPhase::Committing => self.validate_committing_payloads()?,
            TransactionPhase::Committed => {
                if self.verification.is_some() || self.manifest.is_some() {
                    return Err(invalid_journal(
                        "committed receipt must not retain transaction payloads",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn artifact_path(&self, run_dir: &Path) -> PathBuf {
        run_dir.join(&self.artifact_file_name)
    }

    fn validate_committing_payloads(&self) -> Result<()> {
        let verification = self
            .verification
            .as_ref()
            .ok_or_else(|| invalid_journal("committing transaction has no verification payload"))?;
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| invalid_journal("committing transaction has no manifest payload"))?;
        if verification.schema != "netdiag-action-verification/v1"
            || verification.before_run_id != self.run_id
            || verification.after_run_id != self.after_run_id
            || verification.observed_comparison.left.run_id != self.run_id
            || verification.observed_comparison.right.run_id != self.after_run_id
        {
            return Err(invalid_journal(
                "verification identity does not match the transaction",
            ));
        }
        if manifest.run_id != self.run_id
            || manifest
                .artifact_paths
                .get(&self.artifact_key)
                .map(String::as_str)
                != Some(self.artifact_file_name.as_str())
        {
            return Err(invalid_journal(
                "manifest identity or artifact slot does not match the transaction",
            ));
        }
        for (key, receipt) in &self.artifacts {
            if manifest.artifact_paths.get(key).map(String::as_str)
                != Some(receipt.file_name.as_str())
            {
                return Err(invalid_journal(format!(
                    "manifest does not retain cumulative action artifact {key} as {}",
                    receipt.file_name
                )));
            }
        }
        let artifact_bytes = prepare_json_bounded(
            verification,
            MAX_ACTION_VERIFICATION_BYTES,
            "action verification",
        )?;
        let current_receipt = self.artifacts.get(&self.artifact_key).ok_or_else(|| {
            invalid_journal("current action artifact is absent from the cumulative receipt")
        })?;
        if current_receipt.bytes != artifact_bytes.as_bytes().len() as u64 {
            return Err(invalid_journal(
                "current action artifact byte length does not match its payload",
            ));
        }
        let manifest_bytes =
            prepare_json_bounded(manifest, MAX_RUN_MANIFEST_BYTES, "run manifest")?;
        if sha256_bytes(artifact_bytes.as_bytes()) != self.artifact_sha256
            || sha256_bytes(manifest_bytes.as_bytes()) != self.manifest_sha256
        {
            return Err(invalid_journal(
                "payload hash does not match the serialized transaction content",
            ));
        }
        Ok(())
    }
}

fn validate_artifact_receipts(artifacts: &BTreeMap<String, ActionArtifactReceipt>) -> Result<()> {
    crate::storage::typed_json::ensure_collection_limit(
        "action verification transaction artifacts",
        artifacts.len(),
        crate::storage::typed_json::MAX_RUN_MANIFEST_ARTIFACTS,
    )?;
    let mut total_bytes = 0_u64;
    for (key, receipt) in artifacts {
        let after_run_id = key.strip_prefix("action_verification_").ok_or_else(|| {
            invalid_journal(format!("invalid cumulative action artifact key {key:?}"))
        })?;
        crate::identifiers::validate_portable_id(
            "cumulative action artifact after run id",
            after_run_id,
        )?;
        let expected_file_name = format!("{key}.json");
        if receipt.file_name != expected_file_name {
            return Err(invalid_journal(format!(
                "cumulative action artifact {key} names {}, expected {expected_file_name}",
                receipt.file_name
            )));
        }
        validate_hash("cumulative artifact", &receipt.sha256)?;
        if receipt.bytes == 0 || receipt.bytes > MAX_ACTION_VERIFICATION_BYTES {
            return Err(invalid_journal(format!(
                "cumulative action artifact {key} has invalid byte length {}",
                receipt.bytes
            )));
        }
        total_bytes = total_bytes
            .checked_add(receipt.bytes)
            .ok_or_else(|| invalid_journal("cumulative action artifact byte length overflow"))?;
        if total_bytes > MAX_ACTION_VERIFICATION_TOTAL_BYTES {
            return Err(invalid_journal(format!(
                "cumulative action artifacts exceed the {MAX_ACTION_VERIFICATION_TOTAL_BYTES}-byte verification limit"
            )));
        }
    }
    Ok(())
}

pub(super) fn load_journal(
    run_dir: &Path,
    run_id: &str,
) -> Result<Option<ActionVerificationJournal>> {
    let path = action_verification_journal_path(run_dir);
    let Some(bytes) =
        read_stable_regular_file_bounded(&path, MAX_ACTION_VERIFICATION_JOURNAL_BYTES)?
    else {
        return Ok(None);
    };
    let raw = crate::strict_json::parse_unique_value(&bytes).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "invalid action verification transaction journal at {}: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })?;
    let journal: ActionVerificationJournal =
        serde_json::from_value(raw.clone()).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "invalid action verification transaction journal at {}: {}",
                path.display(),
                crate::strict_json::error_summary(&error)
            ))
        })?;
    let canonical = serde_json::to_value(&journal)?;
    if raw != canonical {
        return Err(invalid_journal(
            "journal contains unknown, omitted, or non-canonical payload fields",
        ));
    }
    if journal.run_id != run_id {
        return Err(invalid_journal(format!(
            "run id {} does not match requested run id {run_id}",
            journal.run_id
        )));
    }
    journal.validate(run_dir)?;
    Ok(Some(journal))
}

pub(super) fn save_journal(run_dir: &Path, journal: &ActionVerificationJournal) -> Result<()> {
    journal.validate(run_dir)?;
    save_json_atomic_bounded(
        action_verification_journal_path(run_dir),
        journal,
        MAX_ACTION_VERIFICATION_JOURNAL_BYTES,
        "action verification transaction journal",
    )
    .map(drop)
}

fn artifact_key(after_run_id: &str) -> String {
    format!("action_verification_{after_run_id}")
}

fn validate_run_directory_identity(run_dir: &Path, run_id: &str) -> Result<()> {
    let directory_run_id = run_dir
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            invalid_journal(format!(
                "run directory has no portable file name: {}",
                run_dir.display()
            ))
        })?;
    crate::identifiers::validate_portable_id("action transaction directory id", directory_run_id)?;
    if directory_run_id == run_id {
        Ok(())
    } else {
        Err(invalid_journal(format!(
            "run id {run_id} does not match directory {directory_run_id}"
        )))
    }
}

fn validate_hash(description: &str, hash: &str) -> Result<()> {
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid_journal(format!(
            "invalid {description} SHA-256 digest"
        )))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(index: usize, bytes: u64) -> (String, ActionArtifactReceipt) {
        let key = format!("action_verification_after-{index}");
        (
            key.clone(),
            ActionArtifactReceipt {
                file_name: format!("{key}.json"),
                sha256: "0".repeat(64),
                bytes,
            },
        )
    }

    #[test]
    fn cumulative_receipts_bound_entry_count_and_total_artifact_bytes() {
        let too_many = (0..=crate::storage::typed_json::MAX_RUN_MANIFEST_ARTIFACTS)
            .map(|index| receipt(index, 1))
            .collect::<BTreeMap<_, _>>();
        let count_error =
            validate_artifact_receipts(&too_many).expect_err("receipt count must be bounded");
        assert!(count_error.to_string().contains("4097 entries"));

        let too_large = (0..17)
            .map(|index| receipt(index, MAX_ACTION_VERIFICATION_BYTES))
            .collect::<BTreeMap<_, _>>();
        let byte_error = validate_artifact_receipts(&too_large)
            .expect_err("receipt verification bytes must be bounded");
        assert!(byte_error.to_string().contains("268435456-byte"));
    }
}
