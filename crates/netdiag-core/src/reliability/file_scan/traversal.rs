use super::binding::{ScanRoot, ScannedDirectory};
use super::budget::ScanByteBudget;
use super::directory::{DirectoryRead, read_bounded};
use super::{
    FileScan, FileScanIssue, MAX_SCANNED_ENTRIES, MAX_SCANNED_FILE_BYTES, MAX_SCANNED_FILES,
    MAX_TOTAL_SCANNED_FILE_BYTES, ScannedFile,
};
use crate::file_identity::OpenedFileIdentity;
use std::collections::HashSet;
use std::fs;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub(super) struct ScanLimits {
    pub(super) max_entries: usize,
    pub(super) max_files: usize,
    pub(super) max_selected_files: usize,
    pub(super) max_file_bytes: u64,
    pub(super) max_total_file_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_SCANNED_ENTRIES,
            max_files: MAX_SCANNED_FILES,
            max_selected_files: MAX_SCANNED_FILES,
            max_file_bytes: MAX_SCANNED_FILE_BYTES,
            max_total_file_bytes: MAX_TOTAL_SCANNED_FILE_BYTES,
        }
    }
}

pub(super) fn scan(
    root: &Path,
    extensions: &[&str],
    recursive: bool,
    limits: ScanLimits,
) -> FileScan {
    scan_matching(root, recursive, limits, |path| {
        has_extension(path, extensions)
    })
}

pub(super) fn scan_matching(
    root: &Path,
    recursive: bool,
    limits: ScanLimits,
    matches: impl Fn(&Path) -> bool,
) -> FileScan {
    let mut scan = match ScanProgress::start(root, limits.max_total_file_bytes) {
        Ok(scan) => scan,
        Err(issue) => {
            let mut result = FileScan::default();
            result.issues.push(issue);
            return result;
        }
    };
    while let Some(directory) = scan.pending.pop() {
        if !scan.visited.insert(directory.identity()) {
            continue;
        }
        if let Err(issue) = directory.validate(&scan.root) {
            scan.result.issues.push(issue);
            continue;
        }
        let remaining_entries = limits.max_entries.saturating_sub(scan.entry_count);
        let paths = match read_bounded(directory.path(), remaining_entries, &mut scan.result.issues)
        {
            DirectoryRead::Entries {
                paths,
                entries_seen,
            } => {
                scan.entry_count += entries_seen;
                paths
            }
            DirectoryRead::Unreadable => continue,
            DirectoryRead::LimitExceeded => return scan.finish(),
        };
        if let Err(issue) = directory.validate(&scan.root) {
            scan.result.issues.push(issue);
            continue;
        }
        for path in paths {
            if scan
                .process_entry(path, recursive, limits, &matches)
                .is_break()
            {
                return scan.finish();
            }
        }
    }
    scan.finish()
}

struct ScanProgress {
    root: ScanRoot,
    pending: Vec<ScannedDirectory>,
    visited: HashSet<OpenedFileIdentity>,
    entry_count: usize,
    file_count: usize,
    selected_file_count: usize,
    byte_budget: ScanByteBudget,
    result: FileScan,
}

impl ScanProgress {
    fn start(root: &Path, max_total_file_bytes: u64) -> std::result::Result<Self, FileScanIssue> {
        let root = ScanRoot::capture(root)?;
        let root_directory = root.capture_directory(root.path())?;
        Ok(Self {
            root,
            pending: vec![root_directory],
            visited: HashSet::new(),
            entry_count: 0,
            file_count: 0,
            selected_file_count: 0,
            byte_budget: ScanByteBudget::new(max_total_file_bytes),
            result: FileScan::default(),
        })
    }

    fn process_entry(
        &mut self,
        path: PathBuf,
        recursive: bool,
        limits: ScanLimits,
        matches: &impl Fn(&Path) -> bool,
    ) -> ControlFlow<()> {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.result.issues.push(FileScanIssue::io(
                    &path,
                    "inspect entry without following links",
                    error,
                ));
                return ControlFlow::Continue(());
            }
        };
        if metadata.file_type().is_symlink()
            || netdiag_platform::metadata_is_reparse_point(&metadata)
        {
            self.result
                .issues
                .push(FileScanIssue::unsafe_link(&path, self.root.path()));
            return ControlFlow::Continue(());
        }
        if metadata.is_dir() {
            if recursive {
                match self.root.capture_directory(&path) {
                    Ok(directory) => self.pending.push(directory),
                    Err(issue) => self.result.issues.push(issue),
                }
            }
            return ControlFlow::Continue(());
        }
        if !metadata.is_file() {
            self.result.issues.push(FileScanIssue::malformed(
                &path,
                format!("unsupported filesystem entry: {}", path.display()),
            ));
            return ControlFlow::Continue(());
        }
        self.file_count += 1;
        if self.file_count > limits.max_files {
            self.result.issues.push(FileScanIssue::malformed(
                self.root.path(),
                format!("scan exceeded the {} file limit", limits.max_files),
            ));
            return ControlFlow::Break(());
        }
        if !matches(&path) {
            return ControlFlow::Continue(());
        }
        self.selected_file_count += 1;
        if self.selected_file_count > limits.max_selected_files {
            self.result.issues.push(FileScanIssue::malformed(
                self.root.path(),
                format!(
                    "scan exceeded the {} selected-file limit",
                    limits.max_selected_files
                ),
            ));
            return ControlFlow::Break(());
        }
        match self
            .root
            .capture_file(&path, limits.max_file_bytes, &mut self.byte_budget)
        {
            Ok(binding) => self.result.files.push(ScannedFile { binding }),
            Err(issue) => self.result.issues.push(issue),
        }
        ControlFlow::Continue(())
    }

    fn finish(mut self) -> FileScan {
        self.result
            .files
            .sort_by(|left, right| left.path().cmp(right.path()));
        self.result
    }
}

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            extensions
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}
