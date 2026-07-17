use super::ReliabilityReasonCode;
use crate::error::{NetdiagError, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

mod access;
mod binding;
mod budget;
mod directory;
mod traversal;

pub(super) use access::{confined_modified_time, read_confined_text};
use binding::FileBinding;
use traversal::{ScanLimits, scan, scan_matching};

const MAX_SCANNED_ENTRIES: usize = 8_192;
const MAX_SCANNED_FILES: usize = 4_096;
const MAX_SCANNED_FILE_BYTES: u64 = 16 * 1024 * 1024;
// Accepted payload bytes are hashed once during binding and read once through
// consuming ScannedFile values, bounding total content I/O to twice this value.
const MAX_TOTAL_SCANNED_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct FileScanIssue {
    pub path: PathBuf,
    pub reason: ReliabilityReasonCode,
    pub message: String,
    source: Option<std::io::Error>,
}

impl FileScanIssue {
    fn io(path: &Path, operation: &str, error: std::io::Error) -> Self {
        let reason = reason_for_io_error(&error);
        let message = format!("{operation} failed for {}: {error}", path.display());
        Self {
            path: path.to_path_buf(),
            reason,
            message,
            source: Some(error),
        }
    }

    fn malformed(path: &Path, message: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: ReliabilityReasonCode::MalformedPayload,
            message: message.into(),
            source: None,
        }
    }

    fn netdiag(path: &Path, operation: &str, error: NetdiagError) -> Self {
        match error {
            NetdiagError::Io { source, .. } => Self::io(path, operation, source),
            error => Self::malformed(
                path,
                format!("{operation} failed for {}: {error}", path.display()),
            ),
        }
    }

    fn escaped(path: &Path, root: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: ReliabilityReasonCode::PathEscapesArtifactRoot,
            message: format!(
                "{} resolves outside scan root {}",
                path.display(),
                root.display()
            ),
            source: None,
        }
    }

    fn unsafe_link(path: &Path, root: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: ReliabilityReasonCode::PathEscapesArtifactRoot,
            message: format!(
                "{} is a symbolic link or reparse point and cannot be scanned beneath {}",
                path.display(),
                root.display()
            ),
            source: None,
        }
    }

    fn changed(path: &Path, root: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: ReliabilityReasonCode::PathEscapesArtifactRoot,
            message: format!(
                "{} changed identity or confinement while being scanned beneath {}",
                path.display(),
                root.display()
            ),
            source: None,
        }
    }

    fn content_changed(path: &Path, root: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: ReliabilityReasonCode::PathEscapesArtifactRoot,
            message: format!(
                "{} content digest changed after it was bound beneath {}",
                path.display(),
                root.display()
            ),
            source: None,
        }
    }

    fn into_netdiag(self) -> NetdiagError {
        match self.source {
            Some(source) => NetdiagError::Io {
                path: self.path,
                source,
            },
            None => NetdiagError::InvalidTrace(self.message),
        }
    }
}

#[derive(Debug)]
pub(super) struct ScannedFile {
    binding: FileBinding,
}

impl ScannedFile {
    pub fn path(&self) -> &Path {
        self.binding.path()
    }
}

/// A regular file whose identity, confinement, size, and initial digest were
/// bound during a strict scan. Reading consumes the value and revalidates all
/// of those properties before returning content.
#[derive(Debug)]
pub(crate) struct StrictScannedFile(ScannedFile);

impl StrictScannedFile {
    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }

    pub(crate) fn read_text(self) -> Result<String> {
        self.0.read_text().map_err(FileScanIssue::into_netdiag)
    }
}

#[derive(Debug, Default)]
pub(super) struct FileScan {
    pub files: Vec<ScannedFile>,
    pub issues: Vec<FileScanIssue>,
}

pub(super) fn scan_recursive(root: &Path, extensions: &[&str]) -> FileScan {
    scan(root, extensions, true, ScanLimits::default())
}

pub(super) fn scan_top_level(root: &Path, extensions: &[&str]) -> FileScan {
    scan(root, extensions, false, ScanLimits::default())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StrictNamedScanLimits {
    pub(crate) max_entries: usize,
    pub(crate) max_files: usize,
    pub(crate) max_matches: usize,
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_file_bytes: u64,
}

/// Recursively binds only files with the exact requested leaf name.
///
/// Every filesystem entry and regular file still consumes the traversal
/// budgets, while only matching files consume the match and payload-byte
/// budgets. Any issue fails the scan instead of returning a partial result.
pub(crate) fn scan_named_files_strict(
    root: &Path,
    file_name: &OsStr,
    limits: StrictNamedScanLimits,
) -> Result<Vec<StrictScannedFile>> {
    let scan = scan_matching(
        root,
        true,
        ScanLimits {
            max_entries: limits.max_entries,
            max_files: limits.max_files,
            max_selected_files: limits.max_matches,
            max_file_bytes: limits.max_file_bytes,
            max_total_file_bytes: limits.max_total_file_bytes,
        },
        |path| path.file_name().is_some_and(|name| name == file_name),
    );
    if let Some(issue) = scan.issues.into_iter().next() {
        return Err(issue.into_netdiag());
    }
    Ok(scan.files.into_iter().map(StrictScannedFile).collect())
}

pub(super) fn reason_for_io_error(error: &std::io::Error) -> ReliabilityReasonCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => ReliabilityReasonCode::ArtifactMissing,
        std::io::ErrorKind::PermissionDenied => ReliabilityReasonCode::PermissionDenied,
        _ => ReliabilityReasonCode::MalformedPayload,
    }
}

fn file_too_large(path: &Path, size: u64, limit: u64) -> FileScanIssue {
    let message = format!(
        "{} is {size} bytes, exceeding the {limit} byte scan limit",
        path.display()
    );
    FileScanIssue::malformed(path, message)
}

#[cfg(test)]
mod tests;
