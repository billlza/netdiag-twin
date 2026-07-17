use super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::path::Path;

#[derive(Debug)]
pub(in crate::trusted_temp_directory) struct ChildDirectory;

pub(in crate::trusted_temp_directory) fn open(
    _: &TrustedDirectory,
    _: &Path,
) -> Result<ChildDirectory, TrustedTempDirectoryError> {
    Err(TrustedTempDirectoryError::UnsupportedPlatform)
}

pub(in crate::trusted_temp_directory) fn validate(
    _: &TrustedDirectory,
    _: &ChildDirectory,
    _: &Path,
) -> Result<(), TrustedTempDirectoryError> {
    Err(TrustedTempDirectoryError::UnsupportedPlatform)
}
