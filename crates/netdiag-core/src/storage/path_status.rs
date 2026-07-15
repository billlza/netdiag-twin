use crate::error::{NetdiagError, Result};
use std::fs::{self, Metadata};
use std::io;
use std::path::Path;

/// The non-following filesystem state of a path at a validation boundary.
///
/// Keeping `Missing` distinct from every I/O failure prevents permission,
/// corruption, and transient filesystem errors from being mistaken for an
/// absent path. Symbolic links and Windows reparse points are intentionally
/// classified as `Other` so callers do not silently cross a filesystem trust
/// boundary while checking a path's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathStatus {
    Missing,
    RegularFile,
    Directory,
    Other,
}

impl PathStatus {
    pub(crate) fn exists(self) -> bool {
        self != Self::Missing
    }
}

pub(crate) fn path_status(path: &Path) -> Result<PathStatus> {
    path_status_with(path, |candidate| fs::symlink_metadata(candidate))
}

pub(crate) fn optional_regular_file(path: &Path, description: &str) -> Result<bool> {
    match path_status(path)? {
        PathStatus::Missing => Ok(false),
        PathStatus::RegularFile => Ok(true),
        _ => Err(NetdiagError::InvalidTrace(format!(
            "{description} is not a regular file: {}",
            path.display()
        ))),
    }
}

fn path_status_with(
    path: &Path,
    metadata: impl FnOnce(&Path) -> io::Result<Metadata>,
) -> Result<PathStatus> {
    match metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && !netdiag_platform::metadata_is_reparse_point(&metadata)
                && metadata.is_file() =>
        {
            Ok(PathStatus::RegularFile)
        }
        Ok(metadata)
            if !metadata.file_type().is_symlink()
                && !netdiag_platform::metadata_is_reparse_point(&metadata)
                && metadata.is_dir() =>
        {
            Ok(PathStatus::Directory)
        }
        Ok(_) => Ok(PathStatus::Other),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(PathStatus::Missing),
        Err(source) => Err(NetdiagError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_failures_are_not_classified_as_missing() {
        let path = Path::new("protected/path");
        let error = path_status_with(path, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access denied",
            ))
        })
        .expect_err("permission failure must remain visible");

        match error {
            NetdiagError::Io {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, path);
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn only_not_found_is_classified_as_missing() {
        let status = path_status_with(Path::new("missing"), |_| {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
        })
        .expect("not found is a valid missing state");

        assert_eq!(status, PathStatus::Missing);
    }

    #[test]
    fn filesystem_entry_kinds_and_optional_regular_files_are_distinguished() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let file = temp.path().join("document.json");
        let directory = temp.path().join("nested");
        let missing = temp.path().join("missing.json");
        fs::write(&file, b"{}").expect("regular file fixture");
        fs::create_dir(&directory).expect("directory fixture");

        assert_eq!(
            path_status(&file).expect("file status"),
            PathStatus::RegularFile
        );
        assert_eq!(
            path_status(&directory).expect("directory status"),
            PathStatus::Directory
        );
        assert_eq!(
            path_status(&missing).expect("missing status"),
            PathStatus::Missing
        );
        assert!(optional_regular_file(&file, "document").expect("optional file"));
        assert!(!optional_regular_file(&missing, "document").expect("optional missing file"));
        let error = optional_regular_file(&directory, "document")
            .expect_err("a directory must not pass as an optional file");
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_classified_as_other_and_rejected_as_optional_files() {
        use std::os::unix::fs::symlink;

        assert_link_is_other(|target, link| symlink(target, link));
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_reparse_points_are_classified_as_other() {
        use std::os::windows::fs::symlink_file;

        assert_link_is_other(|target, link| symlink_file(target, link));
    }

    #[cfg(any(unix, windows))]
    fn assert_link_is_other(create_link: impl FnOnce(&Path, &Path) -> io::Result<()>) {
        let temp = tempfile::tempdir().expect("temporary directory");
        let target = temp.path().join("target.json");
        let link = temp.path().join("linked.json");
        fs::write(&target, b"{}").expect("target fixture");
        create_link(&target, &link).expect("file link fixture");

        assert_eq!(path_status(&link).expect("link status"), PathStatus::Other);
        let error = optional_regular_file(&link, "linked document")
            .expect_err("a link must not pass as an optional file");
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }
}
