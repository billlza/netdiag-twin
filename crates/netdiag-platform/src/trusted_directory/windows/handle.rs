use super::{DirectoryTrustError, inspect};
use std::fs::{File, Metadata, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

pub(super) fn open_directory(path: &Path) -> Result<File, DirectoryTrustError> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| inspect(path, source))
}

pub(super) fn validate_metadata(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), DirectoryTrustError> {
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DirectoryTrustError::UntrustedSymlink {
            path: path.to_path_buf(),
            detail: "Windows reparse points are not permitted in a coordination target chain"
                .to_string(),
        });
    }
    if !metadata.is_dir() {
        return Err(DirectoryTrustError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}
