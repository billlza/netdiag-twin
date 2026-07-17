use super::super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;

pub(in crate::trusted_temp_directory) fn validate_root(
    root: &TrustedDirectory,
) -> Result<(), TrustedTempDirectoryError> {
    root.validate_private_security()
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary root security validation",
            path: root.resolved_path().to_path_buf(),
            source,
        })?;
    validate_root_metadata(root, root.as_file().metadata())
}

pub(in crate::trusted_temp_directory) fn validate_root_metadata(
    root: &TrustedDirectory,
    metadata: std::io::Result<std::fs::Metadata>,
) -> Result<(), TrustedTempDirectoryError> {
    let metadata = metadata.map_err(|source| TrustedTempDirectoryError::Io {
        context: "trusted temporary root metadata inspection",
        path: root.resolved_path().to_path_buf(),
        source,
    })?;
    if metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err(TrustedTempDirectoryError::RootPolicy {
            path: root.resolved_path().to_path_buf(),
            detail: "Unix temporary root must be root-owned and sticky",
        });
    }
    Ok(())
}

pub(in crate::trusted_temp_directory) fn create_candidate(
    path: &Path,
) -> Result<bool, TrustedTempDirectoryError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(TrustedTempDirectoryError::Io {
            context: "trusted temporary directory creation",
            path: path.to_path_buf(),
            source,
        }),
    }
}
