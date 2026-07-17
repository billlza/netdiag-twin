use super::identity::same_file;
use super::security::{open_and_validate_private_file, validate_private_object_security};
use std::fs::{File, Metadata};
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

/// Opens a persistent coordination file without delete sharing and with an
/// explicit protected DACL for the current SID, SYSTEM, and Administrators.
pub fn open_private_coordination_file(path: &Path) -> io::Result<File> {
    open_and_validate_private_file(path)
}

/// Confirms that `file` is the regular, non-reparse file still named by `path`.
pub fn validate_private_coordination_file(path: &Path, file: &File) -> io::Result<()> {
    validate_regular_non_reparse(&file.metadata()?)?;
    validate_private_object_security(file)?;
    let current = open_private_coordination_file(path)?;
    validate_regular_non_reparse(&current.metadata()?)?;
    if !same_file(file, &current)? {
        return Err(io::Error::other("coordination file identity changed"));
    }
    Ok(())
}

fn validate_regular_non_reparse(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other(
            "coordination object is not a non-reparse regular file",
        ));
    }
    Ok(())
}
