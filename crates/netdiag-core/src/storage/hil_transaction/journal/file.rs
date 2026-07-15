use super::HilReviewJournal;
use crate::error::{NetdiagError, Result};
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

pub(super) fn read_optional_journal(path: &Path) -> Result<Option<HilReviewJournal>> {
    let Some(bytes) =
        read_stable_regular_file_bounded(path, super::super::MAX_TRANSACTION_JSON_BYTES)?
    else {
        return Ok(None);
    };
    crate::strict_json::from_slice::<HilReviewJournal>(&bytes)
        .map(Some)
        .map_err(|source| {
            NetdiagError::InvalidTrace(format!(
                "HIL transaction journal is invalid at {}: {}",
                path.display(),
                crate::strict_json::error_summary(&source)
            ))
        })
}

#[cfg(test)]
mod tests;
