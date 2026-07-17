use super::FileScanIssue;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) enum DirectoryRead {
    Entries {
        paths: Vec<PathBuf>,
        entries_seen: usize,
    },
    Unreadable,
    LimitExceeded,
}

pub(super) fn read_bounded(
    directory: &Path,
    remaining_entries: usize,
    issues: &mut Vec<FileScanIssue>,
) -> DirectoryRead {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            issues.push(FileScanIssue::io(directory, "read directory", error));
            return DirectoryRead::Unreadable;
        }
    };
    let mut paths = Vec::new();
    let mut entries_seen = 0;
    for entry in entries {
        entries_seen += 1;
        if entries_seen > remaining_entries {
            issues.push(FileScanIssue::malformed(
                directory,
                format!(
                    "scan exceeded its entry limit while reading {}",
                    directory.display()
                ),
            ));
            return DirectoryRead::LimitExceeded;
        }
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(error) => issues.push(FileScanIssue::io(directory, "read directory entry", error)),
        }
    }
    paths.sort();
    DirectoryRead::Entries {
        paths,
        entries_seen,
    }
}
