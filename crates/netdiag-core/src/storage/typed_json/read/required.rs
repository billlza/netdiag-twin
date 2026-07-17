use super::{read_optional_stable_json_bounded, read_optional_stable_json_bounded_at};
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;
use serde::de::DeserializeOwned;
use std::path::Path;

pub(crate) fn read_required_stable_json_bounded<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
    kind: &str,
) -> Result<T> {
    required(
        read_optional_stable_json_bounded(path, max_bytes, kind)?,
        path,
        kind,
    )
}

pub(crate) fn read_required_stable_json_bounded_at<T: DeserializeOwned>(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
    kind: &str,
) -> Result<T> {
    required(
        read_optional_stable_json_bounded_at(target, max_bytes, kind)?,
        target.resolved_path(),
        kind,
    )
}

fn required<T>(value: Option<T>, path: &Path, kind: &str) -> Result<T> {
    value
        .ok_or_else(|| NetdiagError::InvalidTrace(format!("{kind} is missing: {}", path.display())))
}
