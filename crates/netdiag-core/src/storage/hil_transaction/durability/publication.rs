use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::atomic_file::publish::{
    AtomicPublishFailure, PublishResult, publish_temporary_file,
};
use crate::storage::{BoundAtomicFileTarget, sha256_stable_regular_file_bounded_at};
use std::ffi::OsStr;
use std::path::Path;

pub(in crate::storage::hil_transaction) fn publish_staged_file(
    staged: &Path,
    target: &Path,
    max_bytes: u64,
    expected_sha256: &str,
) -> Result<()> {
    publish_staged_file_with(
        staged,
        target,
        max_bytes,
        expected_sha256,
        publish_temporary_file,
    )
}

pub(super) fn publish_staged_file_with(
    staged: &Path,
    target: &Path,
    max_bytes: u64,
    expected_sha256: &str,
    publish: impl FnOnce(&BoundAtomicFileTarget, &OsStr) -> PublishResult,
) -> Result<()> {
    let target = BoundAtomicFileTarget::bind_existing_parent(target)
        .map_err(|source| not_published(target, source))?;
    let staged_name = staged.file_name().ok_or_else(|| {
        not_published(
            target.resolved_path(),
            NetdiagError::InvalidTrace(format!(
                "HIL staged target has no file name: {}",
                staged.display()
            )),
        )
    })?;
    let staged_parent = staged.parent().ok_or_else(|| {
        not_published(
            target.resolved_path(),
            NetdiagError::InvalidTrace(format!(
                "HIL staged target has no parent: {}",
                staged.display()
            )),
        )
    })?;
    let resolved_staged_parent = std::fs::canonicalize(staged_parent).map_err(|source| {
        not_published(
            target.resolved_path(),
            NetdiagError::Io {
                path: staged_parent.to_path_buf(),
                source,
            },
        )
    })?;
    if resolved_staged_parent != target.directory().resolved_path() {
        return Err(not_published(
            target.resolved_path(),
            NetdiagError::InvalidTrace(format!(
                "HIL staged target is outside the retained publication directory: {}",
                staged.display()
            )),
        ));
    }
    let staged_target = BoundAtomicFileTarget::from_directory(target.directory_arc(), staged_name)
        .map_err(|source| not_published(target.resolved_path(), source))?;
    verify_hash(&staged_target, max_bytes, expected_sha256)
        .map_err(|source| not_published(target.resolved_path(), source))?;
    publish(&target, staged_name).map_err(|failure| publication_failure(&target, failure))?;
    verify_hash(&target, max_bytes, expected_sha256)
        .map_err(|source| published(target.resolved_path(), source))
}

fn verify_hash(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
    expected_sha256: &str,
) -> Result<()> {
    let actual = sha256_stable_regular_file_bounded_at(target, max_bytes)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "HIL transaction file is missing: {}",
            target.resolved_path().display()
        ))
    })?;
    if actual == expected_sha256 {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "HIL transaction file {} hash {actual} does not match {expected_sha256}",
            target.resolved_path().display()
        )))
    }
}

fn publication_failure(
    target: &BoundAtomicFileTarget,
    failure: AtomicPublishFailure,
) -> NetdiagError {
    NetdiagError::atomic_publish(
        target.resolved_path().to_path_buf(),
        failure.phase,
        *failure.source,
    )
}

fn not_published(target: &Path, source: NetdiagError) -> NetdiagError {
    NetdiagError::atomic_publish(
        target.to_path_buf(),
        AtomicPublishPhase::NotPublished,
        source,
    )
}

fn published(target: &Path, source: NetdiagError) -> NetdiagError {
    NetdiagError::atomic_publish(target.to_path_buf(), AtomicPublishPhase::Published, source)
}
