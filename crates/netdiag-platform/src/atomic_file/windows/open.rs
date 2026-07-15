use crate::{PrivateFileCreationError, TrustedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

pub(in crate::atomic_file) fn create(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> Result<File, PrivateFileCreationError> {
    // TrustedDirectory owns the complete opened path chain. Those handles do
    // not share FILE_SHARE_DELETE, so no component can be renamed, deleted, or
    // replaced by a reparse point while these path-based Windows calls run.
    crate::create_new_private_file(&directory.resolved_path().join(name))
}

pub(in crate::atomic_file) fn read_only(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<File> {
    let file = crate::open_file_read_only_no_follow(&directory.resolved_path().join(name))?;
    let metadata = file.metadata()?;
    if crate::metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic file leaf is not a regular file or is a symlink/reparse point",
        ));
    }
    Ok(file)
}
