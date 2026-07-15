use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity, open_directory};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct PathIdentity {
    canonical_path: PathBuf,
    identity: OpenedFileIdentity,
}

impl PathIdentity {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        let canonical_path = fs::canonicalize(path).with_path(path)?;
        let directory = open_directory(&canonical_path)?;
        let metadata = directory.metadata().with_path(&canonical_path)?;
        if !metadata.is_dir() || netdiag_platform::metadata_is_reparse_point(&metadata) {
            return Err(NetdiagError::InvalidTrace(format!(
                "run location component is not a non-reparse directory: {}",
                path.display()
            )));
        }
        let opened_identity = identity(&directory, &canonical_path)?;
        let current = open_directory(&canonical_path)?;
        if identity(&current, &canonical_path)? != opened_identity {
            return Err(NetdiagError::InvalidTrace(format!(
                "run location component changed while it was opened: {}",
                path.display()
            )));
        }
        Ok(Self {
            canonical_path,
            identity: opened_identity,
        })
    }

    pub(super) fn same_as(&self, current: &Self) -> bool {
        self.canonical_path == current.canonical_path && self.identity == current.identity
    }
}
