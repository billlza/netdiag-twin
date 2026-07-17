use crate::error::{NetdiagError, Result};
use crate::models::{HilReview, Recommendation};
use crate::storage::typed_json::save_json_atomic_bounded;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

mod file;
use file::read_optional_journal;
mod validation;

pub(super) const JOURNAL_SCHEMA: &str = "netdiag-hil-review-transaction/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalPhase {
    Prepared,
    Committing,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JournalTarget {
    pub key: String,
    pub target_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_old_sha256: Option<String>,
    pub new_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HilReviewJournal {
    pub schema: String,
    pub transaction_id: String,
    pub phase: JournalPhase,
    pub run_id: String,
    pub recommendation_id: String,
    pub review: HilReview,
    pub recommendations: Vec<Recommendation>,
    pub status: String,
    #[serde(default)]
    pub targets: Vec<JournalTarget>,
}

impl HilReviewJournal {
    pub fn new(
        run_id: &str,
        recommendation_id: &str,
        review: HilReview,
        recommendations: Vec<Recommendation>,
        status: String,
    ) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            transaction_id: uuid::Uuid::new_v4().to_string(),
            phase: JournalPhase::Prepared,
            run_id: run_id.to_string(),
            recommendation_id: recommendation_id.to_string(),
            review,
            recommendations,
            status,
            targets: Vec::new(),
        }
    }

    pub fn target(&self, key: &str) -> Option<&JournalTarget> {
        self.targets.iter().find(|target| target.key == key)
    }
}

pub(crate) fn journal_path(run_dir: &Path) -> PathBuf {
    run_dir.join(crate::storage::run_snapshot_locks::HIL_REVIEW_JOURNAL_FILE_NAME)
}

pub(crate) fn load_journal(run_dir: &Path, run_id: &str) -> Result<Option<HilReviewJournal>> {
    let path = journal_path(run_dir);
    let Some(journal) = read_optional_journal(&path)? else {
        return Ok(None);
    };
    journal.validate(run_id)?;
    Ok(Some(journal))
}

pub(crate) fn save_journal(run_dir: &Path, journal: &HilReviewJournal) -> Result<()> {
    journal.validate(&journal.run_id)?;
    save_json_atomic_bounded(
        journal_path(run_dir),
        journal,
        super::MAX_TRANSACTION_JSON_BYTES,
        "HIL transaction journal",
    )
    .map(drop)
}

pub(crate) fn ensure_no_pending_transaction(run_dir: &Path, run_id: &str) -> Result<()> {
    if let Some(journal) = load_journal(run_dir, run_id)?
        && journal.phase != JournalPhase::Committed
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "run {run_id} has pending HIL transaction {}; retry the review command to recover it",
            journal.transaction_id
        )));
    }
    Ok(())
}
