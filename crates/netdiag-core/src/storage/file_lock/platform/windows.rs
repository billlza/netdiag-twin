use super::super::errors::trust_error;
use crate::error::{IoContext, NetdiagError, Result};
use netdiag_platform::TrustedDirectory;
use std::fs::File;
use std::path::Path;

pub(in crate::storage::file_lock) fn validate_namespace(
    namespace: &TrustedDirectory,
) -> Result<()> {
    namespace.validate_identity().map_err(trust_error)?;
    namespace
        .validate_coordination_security()
        .map_err(trust_error)
}

pub(in crate::storage::file_lock) fn open_coordination_file(
    _namespace: &TrustedDirectory,
    path: &Path,
) -> Result<File> {
    netdiag_platform::open_private_coordination_file(path).with_path(path)
}

pub(in crate::storage::file_lock) fn validate_coordination_file(
    _namespace: &TrustedDirectory,
    path: &Path,
    file: &File,
) -> Result<()> {
    netdiag_platform::validate_private_coordination_file(path, file).map_err(|source| {
        NetdiagError::CoordinationFileValidation {
            path: path.to_path_buf(),
            source,
        }
    })
}
