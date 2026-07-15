use super::super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::path::Path;

pub(in crate::trusted_temp_directory) fn validate_root(
    root: &TrustedDirectory,
) -> Result<(), TrustedTempDirectoryError> {
    root.validate_private_security()
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary root security validation",
            path: root.resolved_path().to_path_buf(),
            source,
        })
}

pub(in crate::trusted_temp_directory) fn create_candidate(
    path: &Path,
) -> Result<bool, TrustedTempDirectoryError> {
    crate::windows::create_private_directory(path).map_err(|source| TrustedTempDirectoryError::Io {
        context: "trusted temporary directory creation",
        path: path.to_path_buf(),
        source,
    })
}
