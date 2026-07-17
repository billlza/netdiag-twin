use super::validation::{
    confined_canonical_path, reject_path_link, validate_directory_metadata, verify_directory_path,
};
use crate::file_identity::{OpenedFileIdentity, identity, open_directory};
use crate::reliability::file_scan::FileScanIssue;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(in crate::reliability::file_scan) struct ScanRoot {
    pub(super) canonical_path: PathBuf,
    pub(super) identity: OpenedFileIdentity,
}

#[derive(Debug)]
pub(in crate::reliability::file_scan) struct ScannedDirectory {
    canonical_path: PathBuf,
    identity: OpenedFileIdentity,
}

impl ScanRoot {
    pub(in crate::reliability::file_scan) fn capture(path: &Path) -> Result<Self, FileScanIssue> {
        reject_path_link(path, path)?;
        let selected = open_directory(path).map_err(|error| {
            FileScanIssue::netdiag(path, "open scan root without following links", error)
        })?;
        validate_directory_metadata(
            path,
            &selected.metadata().map_err(|error| {
                FileScanIssue::io(path, "read scan root handle metadata", error)
            })?,
        )?;
        let selected_identity = identity(&selected, path).map_err(|error| {
            FileScanIssue::netdiag(path, "read scan root handle identity", error)
        })?;
        let canonical_path = fs::canonicalize(path)
            .map_err(|error| FileScanIssue::io(path, "canonicalize scan root", error))?;
        let directory = open_directory(&canonical_path).map_err(|error| {
            FileScanIssue::netdiag(
                &canonical_path,
                "open scan root without following links",
                error,
            )
        })?;
        validate_directory_metadata(
            &canonical_path,
            &directory.metadata().map_err(|error| {
                FileScanIssue::io(&canonical_path, "read scan root handle metadata", error)
            })?,
        )?;
        let identity = identity(&directory, &canonical_path).map_err(|error| {
            FileScanIssue::netdiag(&canonical_path, "read scan root handle identity", error)
        })?;
        if identity != selected_identity {
            return Err(FileScanIssue::changed(path, &canonical_path));
        }
        let root = Self {
            canonical_path,
            identity,
        };
        root.validate()?;
        Ok(root)
    }

    pub(in crate::reliability::file_scan) fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub(in crate::reliability::file_scan) fn validate(&self) -> Result<(), FileScanIssue> {
        let current = open_directory(&self.canonical_path).map_err(|error| {
            FileScanIssue::netdiag(
                &self.canonical_path,
                "reopen scan root without following links",
                error,
            )
        })?;
        validate_directory_metadata(
            &self.canonical_path,
            &current.metadata().map_err(|error| {
                FileScanIssue::io(
                    &self.canonical_path,
                    "read scan root handle metadata",
                    error,
                )
            })?,
        )?;
        let current_identity = identity(&current, &self.canonical_path).map_err(|error| {
            FileScanIssue::netdiag(
                &self.canonical_path,
                "read scan root handle identity",
                error,
            )
        })?;
        if current_identity != self.identity {
            return Err(FileScanIssue::changed(
                &self.canonical_path,
                &self.canonical_path,
            ));
        }
        Ok(())
    }

    pub(in crate::reliability::file_scan) fn capture_directory(
        &self,
        path: &Path,
    ) -> Result<ScannedDirectory, FileScanIssue> {
        self.validate()?;
        reject_path_link(path, self.path())?;
        let canonical_path = confined_canonical_path(path, self.path())?;
        let directory = open_directory(path).map_err(|error| {
            FileScanIssue::netdiag(path, "open directory without following links", error)
        })?;
        validate_directory_metadata(
            path,
            &directory.metadata().map_err(|error| {
                FileScanIssue::io(path, "read directory handle metadata", error)
            })?,
        )?;
        let identity = identity(&directory, path).map_err(|error| {
            FileScanIssue::netdiag(path, "read directory handle identity", error)
        })?;
        verify_directory_path(path, &canonical_path, self, identity)?;
        Ok(ScannedDirectory {
            canonical_path,
            identity,
        })
    }
}

impl ScannedDirectory {
    pub(in crate::reliability::file_scan) fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub(in crate::reliability::file_scan) fn validate(
        &self,
        root: &ScanRoot,
    ) -> Result<(), FileScanIssue> {
        verify_directory_path(
            &self.canonical_path,
            &self.canonical_path,
            root,
            self.identity,
        )
    }

    pub(in crate::reliability::file_scan) fn identity(&self) -> OpenedFileIdentity {
        self.identity
    }
}
