use super::bound::read_with_hook as read_bound_with_hook;
use super::read_stable_with;
use crate::error::Result;
use crate::storage::BoundAtomicFileTarget;
use std::path::Path;

mod pass;
use pass::hash_pass;

/// Streams two bounded SHA-256 passes from one no-follow handle and verifies
/// that the path still names that same, unchanged regular file.
pub(crate) fn sha256_stable_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Option<String>> {
    hash_with_hook(path, max_bytes, || {})
}

pub(crate) fn sha256_stable_regular_file_bounded_at(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
) -> Result<Option<String>> {
    read_bound_with_hook(target, max_bytes, || {}, hash_pass)
}

pub(super) fn hash_with_hook(
    path: &Path,
    max_bytes: u64,
    between_reads: impl FnOnce(),
) -> Result<Option<String>> {
    read_stable_with(path, max_bytes, between_reads, hash_pass)
}
