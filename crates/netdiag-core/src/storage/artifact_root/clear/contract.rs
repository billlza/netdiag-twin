use super::{RUN_INDEX_NAME, RUNS_NAME};
use crate::error::{NetdiagError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;

pub(super) const CLEAR_JOURNAL_SCHEMA: u32 = 1;
pub(super) const MAX_CLEAR_JOURNAL_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ClearPhase {
    Prepared,
    Committed,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryRecord {
    pub(super) coordination_identity: [u8; 32],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileRecord {
    pub(super) byte_len: u64,
    pub(super) sha256: String,
}

impl FileRecord {
    pub(super) fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            byte_len: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    pub(super) fn matches(&self, bytes: &[u8]) -> bool {
        self.byte_len == bytes.len() as u64 && self.sha256 == format!("{:x}", Sha256::digest(bytes))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClearJournal {
    schema_version: u32,
    pub(super) root_id: String,
    pub(super) phase: ClearPhase,
    pub(super) runs: Option<DirectoryRecord>,
    pub(super) index: Option<FileRecord>,
}

impl ClearJournal {
    pub(super) fn prepared(
        root_id: &str,
        runs: Option<DirectoryRecord>,
        index: Option<FileRecord>,
    ) -> Self {
        Self {
            schema_version: CLEAR_JOURNAL_SCHEMA,
            root_id: root_id.to_string(),
            phase: ClearPhase::Prepared,
            runs,
            index,
        }
    }

    pub(super) fn committed(&self) -> Self {
        let mut committed = self.clone();
        committed.phase = ClearPhase::Committed;
        committed
    }

    pub(super) fn validate(&self, expected_root_id: &str) -> Result<()> {
        if self.schema_version != CLEAR_JOURNAL_SCHEMA || self.root_id != expected_root_id {
            return Err(NetdiagError::InvalidTrace(
                "run history clear journal does not match the owned artifact root".to_string(),
            ));
        }
        if let Some(index) = &self.index
            && (index.sha256.len() != 64
                || !index
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(NetdiagError::InvalidTrace(
                "run history clear journal contains an invalid index digest".to_string(),
            ));
        }
        Ok(())
    }
}

pub(super) fn journal_name(root_id: &str) -> OsString {
    OsString::from(format!(".netdiag-clear-{root_id}.json"))
}

pub(super) fn runs_tombstone_name(root_id: &str) -> OsString {
    OsString::from(format!(".netdiag-clear-{root_id}-{RUNS_NAME}"))
}

pub(super) fn index_tombstone_name(root_id: &str) -> OsString {
    OsString::from(format!(".netdiag-clear-{root_id}-{RUN_INDEX_NAME}"))
}
