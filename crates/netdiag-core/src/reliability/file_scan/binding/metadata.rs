use super::root::ScanRoot;
use super::validation::{FileSnapshot, confined_canonical_path, file_snapshot, reject_path_link};
use crate::file_identity::{OpenedFileIdentity, identity, open_file};
use crate::reliability::file_scan::FileScanIssue;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug)]
pub(super) struct MetadataBinding {
    display_path: PathBuf,
    canonical_path: PathBuf,
    root: ScanRoot,
    identity: OpenedFileIdentity,
    snapshot: FileSnapshot,
    max_bytes: u64,
}

impl ScanRoot {
    pub(super) fn capture_metadata(
        &self,
        path: &Path,
        max_bytes: u64,
    ) -> Result<(MetadataBinding, File), FileScanIssue> {
        self.validate()?;
        reject_path_link(path, self.path())?;
        let canonical_path = confined_canonical_path(path, self.path())?;
        let file = open_file(path).map_err(|error| {
            FileScanIssue::netdiag(path, "open file without following links", error)
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| FileScanIssue::io(path, "read file handle metadata", error))?;
        let snapshot = file_snapshot(path, &metadata, max_bytes)?;
        let identity = identity(&file, path)
            .map_err(|error| FileScanIssue::netdiag(path, "read file handle identity", error))?;
        let binding = MetadataBinding {
            display_path: path.to_path_buf(),
            canonical_path,
            root: self.clone(),
            identity,
            snapshot,
            max_bytes,
        };
        binding.verify_path()?;
        Ok((binding, file))
    }
}

impl MetadataBinding {
    pub(super) fn path(&self) -> &Path {
        &self.display_path
    }

    pub(super) fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub(super) fn byte_len(&self) -> u64 {
        self.snapshot.len()
    }

    pub(super) fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub(super) fn open_current(&self) -> Result<(File, Metadata), FileScanIssue> {
        self.root.validate()?;
        let (file, metadata) = self.open_current_once()?;
        if file_snapshot(&self.display_path, &metadata, self.max_bytes)? != self.snapshot
            || identity(&file, &self.display_path).map_err(|error| {
                FileScanIssue::netdiag(&self.display_path, "read file handle identity", error)
            })? != self.identity
        {
            return Err(FileScanIssue::changed(&self.display_path, self.root.path()));
        }
        Ok((file, metadata))
    }

    pub(super) fn verify_opened(&self, file: &File) -> Result<(), FileScanIssue> {
        let metadata = file.metadata().map_err(|error| {
            FileScanIssue::io(&self.display_path, "reread file handle metadata", error)
        })?;
        if file_snapshot(&self.display_path, &metadata, self.max_bytes)? != self.snapshot {
            return Err(FileScanIssue::changed(&self.display_path, self.root.path()));
        }
        self.verify_path()
    }

    fn verify_path(&self) -> Result<(), FileScanIssue> {
        let (current, metadata) = self.open_current_once()?;
        if file_snapshot(&self.display_path, &metadata, self.max_bytes)? != self.snapshot
            || identity(&current, &self.display_path).map_err(|error| {
                FileScanIssue::netdiag(&self.display_path, "read file handle identity", error)
            })? != self.identity
        {
            return Err(FileScanIssue::changed(&self.display_path, self.root.path()));
        }
        self.root.validate()
    }

    fn open_current_once(&self) -> Result<(File, Metadata), FileScanIssue> {
        reject_path_link(&self.display_path, self.root.path())?;
        let canonical = confined_canonical_path(&self.display_path, self.root.path())?;
        if canonical != self.canonical_path {
            return Err(FileScanIssue::changed(&self.display_path, self.root.path()));
        }
        let file = open_file(&self.display_path).map_err(|error| {
            FileScanIssue::netdiag(
                &self.display_path,
                "reopen file without following links",
                error,
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            FileScanIssue::io(&self.display_path, "read file handle metadata", error)
        })?;
        Ok((file, metadata))
    }
}

pub(in crate::reliability::file_scan) fn read_confined_modified_time(
    root: &Path,
    path: &Path,
) -> Result<SystemTime, FileScanIssue> {
    let root = ScanRoot::capture(root)?;
    let (binding, file) = root.capture_metadata(path, u64::MAX)?;
    let modified = file
        .metadata()
        .and_then(|metadata| metadata.modified())
        .map_err(|error| FileScanIssue::io(path, "read modification time", error))?;
    binding.verify_opened(&file)?;
    Ok(modified)
}
