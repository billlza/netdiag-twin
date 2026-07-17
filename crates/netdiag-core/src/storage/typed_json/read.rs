use crate::error::{NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, read_stable_regular_file_bounded, read_stable_regular_file_bounded_at,
};
use serde::de::DeserializeOwned;
use std::path::Path;

mod required;
pub(crate) use required::{
    read_required_stable_json_bounded, read_required_stable_json_bounded_at,
};

pub(crate) fn read_optional_stable_json_bounded<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
    kind: &str,
) -> Result<Option<T>> {
    let Some(bytes) = read_stable_regular_file_bounded(path, max_bytes)? else {
        return Ok(None);
    };
    crate::strict_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| invalid_json(path, kind, source))
}

pub(crate) fn read_optional_stable_json_bounded_at<T: DeserializeOwned>(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
    kind: &str,
) -> Result<Option<T>> {
    let Some(bytes) = read_stable_regular_file_bounded_at(target, max_bytes)? else {
        return Ok(None);
    };
    crate::strict_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| invalid_json(target.resolved_path(), kind, source))
}

pub(super) fn invalid_json(path: &Path, kind: &str, source: serde_json::Error) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "invalid {kind} at {}: {}",
        path.display(),
        crate::strict_json::error_summary(&source)
    ))
}
