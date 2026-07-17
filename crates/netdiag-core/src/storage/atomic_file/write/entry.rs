use super::execute::write_bound_file_atomically_with;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::atomic_file::publish::{PublishResult, publish_temporary_file};
use crate::storage::atomic_file::target::BoundAtomicFileTarget;
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};

pub(crate) fn write_file_atomically<T>(
    target: &Path,
    default_extension: &str,
    write: impl FnOnce(&mut File) -> Result<T>,
) -> Result<(PathBuf, T)> {
    write_file_atomically_with(
        target,
        default_extension,
        write,
        publish_temporary_file,
        || Ok(()),
    )
}

pub(crate) fn write_file_atomically_to_bound<T>(
    bound: &BoundAtomicFileTarget,
    reported_target: &Path,
    default_extension: &str,
    write: impl FnOnce(&mut File) -> Result<T>,
) -> Result<(PathBuf, T)> {
    write_bound_file_atomically_with(
        bound,
        reported_target,
        default_extension,
        write,
        publish_temporary_file,
        || Ok(()),
    )
}

pub(crate) fn write_file_atomically_with<T>(
    target: &Path,
    default_extension: &str,
    write: impl FnOnce(&mut File) -> Result<T>,
    publish: impl FnOnce(&BoundAtomicFileTarget, &OsStr) -> PublishResult,
    after_reservation: impl FnOnce() -> Result<()>,
) -> Result<(PathBuf, T)> {
    let bound = BoundAtomicFileTarget::bind(target).map_err(|source| {
        NetdiagError::atomic_publish(
            target.to_path_buf(),
            AtomicPublishPhase::NotPublished,
            source,
        )
    })?;
    write_bound_file_atomically_with(
        &bound,
        target,
        default_extension,
        write,
        publish,
        after_reservation,
    )
}
