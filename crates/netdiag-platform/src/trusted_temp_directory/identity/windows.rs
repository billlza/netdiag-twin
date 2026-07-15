use super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::path::Path;

#[derive(Debug)]
pub(in crate::trusted_temp_directory) struct ChildDirectory {
    directory: TrustedDirectory,
}

pub(in crate::trusted_temp_directory) fn open(
    _: &TrustedDirectory,
    path: &Path,
) -> Result<ChildDirectory, TrustedTempDirectoryError> {
    let directory = crate::open_trusted_directory_chain(path).map_err(|source| {
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary child open",
            path: path.to_path_buf(),
            source,
        }
    })?;
    directory
        .validate_coordination_security()
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary child security validation",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(ChildDirectory { directory })
}

pub(in crate::trusted_temp_directory) fn validate(
    root: &TrustedDirectory,
    child: &ChildDirectory,
    path: &Path,
) -> Result<(), TrustedTempDirectoryError> {
    validate_root(root)?;
    child
        .directory
        .validate_identity()
        .and_then(|()| child.directory.validate_coordination_security())
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary child identity validation",
            path: path.to_path_buf(),
            source,
        })?;
    validate_root(root)
}

fn validate_root(root: &TrustedDirectory) -> Result<(), TrustedTempDirectoryError> {
    root.validate_identity()
        .and_then(|()| root.validate_private_security())
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary root identity validation",
            path: root.resolved_path().to_path_buf(),
            source,
        })
}
