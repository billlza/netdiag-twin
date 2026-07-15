use super::root::ScanRoot;
use crate::file_identity::{OpenedFileIdentity, identity, open_directory};
use crate::reliability::file_scan::{FileScanIssue, file_too_large};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileSnapshot {
    len: u64,
    modified: SystemTime,
}

impl FileSnapshot {
    pub(super) fn len(self) -> u64 {
        self.len
    }
}

pub(super) fn verify_directory_path(
    path: &Path,
    expected_canonical: &Path,
    root: &ScanRoot,
    expected_identity: OpenedFileIdentity,
) -> Result<(), FileScanIssue> {
    root.validate()?;
    reject_path_link(path, root.path())?;
    if confined_canonical_path(path, root.path())? != expected_canonical {
        return Err(FileScanIssue::changed(path, root.path()));
    }
    let current = open_directory(path).map_err(|error| {
        FileScanIssue::netdiag(path, "reopen directory without following links", error)
    })?;
    validate_directory_metadata(
        path,
        &current
            .metadata()
            .map_err(|error| FileScanIssue::io(path, "read directory handle metadata", error))?,
    )?;
    if identity(&current, path)
        .map_err(|error| FileScanIssue::netdiag(path, "read directory handle identity", error))?
        != expected_identity
    {
        return Err(FileScanIssue::changed(path, root.path()));
    }
    root.validate()
}

pub(super) fn confined_canonical_path(path: &Path, root: &Path) -> Result<PathBuf, FileScanIssue> {
    let canonical =
        fs::canonicalize(path).map_err(|error| FileScanIssue::io(path, "canonicalize", error))?;
    if !canonical.starts_with(root) {
        return Err(FileScanIssue::escaped(path, root));
    }
    Ok(canonical)
}

pub(super) fn reject_path_link(path: &Path, root: &Path) -> Result<(), FileScanIssue> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| FileScanIssue::io(path, "inspect entry without following links", error))?;
    if metadata.file_type().is_symlink() || netdiag_platform::metadata_is_reparse_point(&metadata) {
        return Err(FileScanIssue::unsafe_link(path, root));
    }
    Ok(())
}

pub(super) fn validate_directory_metadata(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), FileScanIssue> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || netdiag_platform::metadata_is_reparse_point(metadata)
    {
        return Err(FileScanIssue::malformed(
            path,
            format!(
                "scan entry is not a non-reparse directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn file_snapshot(
    path: &Path,
    metadata: &Metadata,
    max_bytes: u64,
) -> Result<FileSnapshot, FileScanIssue> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || netdiag_platform::metadata_is_reparse_point(metadata)
    {
        return Err(FileScanIssue::malformed(
            path,
            format!(
                "scan entry is not a non-reparse regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(file_too_large(path, metadata.len(), max_bytes));
    }
    let modified = metadata
        .modified()
        .map_err(|error| FileScanIssue::io(path, "read file modification time", error))?;
    Ok(FileSnapshot {
        len: metadata.len(),
        modified,
    })
}
