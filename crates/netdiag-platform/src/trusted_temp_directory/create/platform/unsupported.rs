use super::super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::path::Path;

pub(in crate::trusted_temp_directory) fn validate_root(
    _: &TrustedDirectory,
) -> Result<(), TrustedTempDirectoryError> {
    Err(TrustedTempDirectoryError::UnsupportedPlatform)
}

pub(in crate::trusted_temp_directory) fn create_candidate(
    _: &Path,
) -> Result<bool, TrustedTempDirectoryError> {
    Err(TrustedTempDirectoryError::UnsupportedPlatform)
}
