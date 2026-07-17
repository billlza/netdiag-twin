mod buffer;
mod cleanup;
mod create;
mod descriptor;
mod sid;
mod validation;

use crate::PrivateFileCreationError;
pub(crate) use create::create_private_directory;
use std::{fs::File, io, path::Path};
pub(crate) use validation::{validate_mutable_parent_security, validate_private_object_security};

/// Returns the process-token user SID as binary hash material. Callers must not
/// log or expose these bytes; coordination namespace names hash them with a
/// domain separator.
pub fn current_user_sid_bytes() -> io::Result<Vec<u8>> {
    sid::SidBuffer::current_user().map(|sid| sid.bytes().to_vec())
}

/// Exclusively creates a non-reparse file with a protected DACL granting
/// access only to the current user, SYSTEM, and Administrators.
pub fn create_new_private_file(path: &Path) -> Result<File, PrivateFileCreationError> {
    let file = create::create_new_private_file(path).map_err(PrivateFileCreationError::from)?;
    if let Err(source) = validate_private_object_security(&file) {
        drop(file);
        return Err(cleanup::after_validation_failure(
            source,
            std::fs::remove_file(path),
        ));
    }
    Ok(file)
}

pub(crate) fn open_and_validate_private_file(path: &Path) -> io::Result<File> {
    let file = create::open_private_file(path)?;
    validate_private_object_security(&file)?;
    Ok(file)
}
