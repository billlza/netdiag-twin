use super::{DirectoryTrustError, TrustedDirectory, unix};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::path::Path;

/// Opens an absolute Unix directory chain without following any symlink and
/// without the root-owned sticky-directory exception used for system paths.
pub fn open_strict_directory_chain_no_follow(
    path: &Path,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    unix::open_strict(path)
}

/// Opens and validates an absolute regular file through a strict directory chain.
pub fn open_strict_regular_file_no_follow(
    path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    unix::open_strict_regular_file(path)
}

/// Opens one strict directory component relative to an already-open directory.
pub fn open_strict_directory_at(
    parent: &File,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    unix::open_strict_directory_at(parent, name, display_path)
}

/// Opens one strict regular-file component relative to an already-open directory.
pub fn open_strict_regular_file_at(
    parent: &File,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    unix::open_strict_regular_file_at(parent, name, display_path)
}

/// Validates the type, owner, mode, and ACL of an already-open directory.
///
/// This validates the handle only. Use a strict open function when pathname
/// no-follow guarantees are also required.
pub fn validate_opened_strict_directory(
    display_path: &Path,
    directory: &File,
) -> Result<Metadata, DirectoryTrustError> {
    unix::validate_opened_strict_directory(display_path, directory)
}

/// Validates the type, owner, mode, and ACL of an already-open regular file.
///
/// This validates the handle only. Use a strict open function when pathname
/// no-follow guarantees are also required.
pub fn validate_opened_strict_regular_file(
    display_path: &Path,
    file: &File,
) -> Result<Metadata, DirectoryTrustError> {
    unix::validate_opened_strict_regular_file(display_path, file)
}
