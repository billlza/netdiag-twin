use super::error::publish_error;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::atomic_file::publish::PublishResult;
use crate::storage::atomic_file::target::BoundAtomicFileTarget;
use crate::storage::atomic_file::temporary::StagedAtomicFile;
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};

pub(super) fn write_bound_file_atomically_with<T>(
    bound: &BoundAtomicFileTarget,
    reported_target: &Path,
    default_extension: &str,
    write: impl FnOnce(&mut File) -> Result<T>,
    publish: impl FnOnce(&BoundAtomicFileTarget, &OsStr) -> PublishResult,
    after_reservation: impl FnOnce() -> Result<()>,
) -> Result<(PathBuf, T)> {
    let mut staged = StagedAtomicFile::reserve_in(
        bound.directory_arc(),
        bound.target_name(),
        default_extension,
    )
    .map_err(|source| {
        NetdiagError::atomic_publish(
            reported_target.to_path_buf(),
            AtomicPublishPhase::NotPublished,
            source,
        )
    })?;
    if let Err(source) = after_reservation() {
        return Err(cleanup_error(staged, reported_target, source));
    }
    let value = match write(staged.file_mut()) {
        Ok(value) => value,
        Err(source) => return Err(cleanup_error(staged, reported_target, source)),
    };
    if let Err(source) = staged.sync() {
        return Err(cleanup_error(staged, reported_target, source));
    }
    staged.close_file();
    if let Err(failure) = publish(bound, staged.name()) {
        let temporary_name = staged.name().to_os_string();
        let temporary_path = staged.path().to_path_buf();
        staged.disarm_cleanup();
        return Err(publish_error(
            bound,
            reported_target,
            &temporary_name,
            &temporary_path,
            failure,
        ));
    }
    staged.disarm_cleanup();
    Ok((reported_target.to_path_buf(), value))
}

fn cleanup_error(staged: StagedAtomicFile, target: &Path, source: NetdiagError) -> NetdiagError {
    let source = staged.abort(source);
    NetdiagError::atomic_publish(
        target.to_path_buf(),
        AtomicPublishPhase::NotPublished,
        source,
    )
}
