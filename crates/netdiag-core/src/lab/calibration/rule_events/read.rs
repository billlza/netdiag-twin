use crate::error::{NetdiagError, Result};
use crate::models::DiagnosisEvent;
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

mod error;
use error::{invalid_json, read_error};

pub(super) const MAX_DIAGNOSIS_EVENTS_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn read_rule_events(
    path: &Path,
    required_for_accepted_known_run: bool,
) -> Result<Option<Vec<DiagnosisEvent>>> {
    let bytes = read_stable_regular_file_bounded(path, MAX_DIAGNOSIS_EVENTS_BYTES)
        .map_err(|error| read_error(path, required_for_accepted_known_run, error))?;
    let Some(bytes) = bytes else {
        if required_for_accepted_known_run {
            return Err(read_error(
                path,
                true,
                NetdiagError::InvalidTrace("required file does not exist".to_string()),
            ));
        }
        return Ok(None);
    };
    crate::strict_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| invalid_json(path, required_for_accepted_known_run, source))
}
