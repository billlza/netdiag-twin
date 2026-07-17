use crate::trusted_directory::unix::DirectoryTrustError;
use rustix::fs::{AtFlags, unlinkat};
use std::{ffi::OsStr, fs::File, path::PathBuf};

pub(super) fn after_validation_failure(
    parent: &File,
    name: &OsStr,
    path: PathBuf,
    validation: DirectoryTrustError,
) -> DirectoryTrustError {
    match unlinkat(parent, name, AtFlags::REMOVEDIR) {
        Ok(()) => validation,
        Err(cleanup) => DirectoryTrustError::ValidationAndCleanup {
            path,
            validation: Box::new(validation),
            cleanup: cleanup.into(),
        },
    }
}
