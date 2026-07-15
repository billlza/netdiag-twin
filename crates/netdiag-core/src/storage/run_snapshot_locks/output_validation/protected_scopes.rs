use super::{overlap_error, protected_parent_scope};
use crate::error::Result;
use crate::storage::{BoundAtomicFileTarget, CoordinationParentScope, prospective_component_alias};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(in crate::storage::run_snapshot_locks) struct ProtectedOutputScopes {
    files: Vec<ProtectedFileScope>,
    directories: Vec<CoordinationParentScope>,
}

#[derive(Debug)]
struct ProtectedFileScope {
    parent: CoordinationParentScope,
    leaf: std::ffi::OsString,
}

impl ProtectedOutputScopes {
    pub(in crate::storage::run_snapshot_locks) fn capture(
        protected_files: &[PathBuf],
        protected_directories: &[PathBuf],
        reported: &Path,
    ) -> Result<Self> {
        let files = protected_files
            .iter()
            .map(|path| {
                let leaf = path.file_name().ok_or_else(|| overlap_error(reported))?;
                Ok(ProtectedFileScope {
                    parent: protected_parent_scope(path, reported)?,
                    leaf: leaf.to_os_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let directories = protected_directories
            .iter()
            .map(|path| protected_parent_scope(path, reported))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { files, directories })
    }

    pub(in crate::storage::run_snapshot_locks) fn extend(&mut self, other: Self) {
        self.files.extend(other.files);
        self.directories.extend(other.directories);
    }

    pub(in crate::storage::run_snapshot_locks) fn validate_bound(
        &self,
        target: &BoundAtomicFileTarget,
        reported: &Path,
    ) -> Result<()> {
        let output_parent =
            CoordinationParentScope::for_existing_identity(target.parent_identity()?);
        let protected_file = self.files.iter().any(|protected| {
            prospective_component_alias(target.target_name(), &protected.leaf)
                && protected.parent.overlaps(&output_parent)
        });
        let protected_directory = self
            .directories
            .iter()
            .any(|protected| protected.overlaps(&output_parent));
        if protected_file || protected_directory {
            return Err(overlap_error(reported));
        }
        Ok(())
    }
}
