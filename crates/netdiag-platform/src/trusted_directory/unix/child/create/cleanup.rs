use crate::trusted_directory::unix::{DirectoryTrustError, TrustedDirectory};
use std::{ffi::OsStr, fs::File, path::PathBuf};

mod error;

pub(super) fn finish_preparation(
    parent: &File,
    name: &OsStr,
    path: PathBuf,
    prepared: Result<TrustedDirectory, DirectoryTrustError>,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    match prepared {
        Ok(directory) => Ok(directory),
        Err(validation) => Err(error::after_validation_failure(
            parent, name, path, validation,
        )),
    }
}

#[cfg(test)]
mod tests;
