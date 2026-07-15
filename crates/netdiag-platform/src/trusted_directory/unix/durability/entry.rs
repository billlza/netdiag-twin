use super::super::{DirectoryPersistenceStage, DirectoryTrustError};
use super::persist_error;
use std::fs::File;
use std::path::Path;

pub(in crate::trusted_directory::unix) fn persist_directory_entry(
    parent: &File,
    parent_path: &Path,
    directory: &File,
    directory_path: &Path,
) -> Result<(), DirectoryTrustError> {
    persist_directory_entry_with(
        parent_path,
        directory_path,
        || directory.sync_all(),
        || parent.sync_all(),
    )
}

fn persist_directory_entry_with(
    parent_path: &Path,
    directory_path: &Path,
    sync_directory: impl FnOnce() -> std::io::Result<()>,
    sync_parent: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), DirectoryTrustError> {
    sync_directory().map_err(|source| {
        persist_error(directory_path, DirectoryPersistenceStage::Directory, source)
    })?;
    sync_parent().map_err(|source| {
        persist_error(
            parent_path,
            DirectoryPersistenceStage::ParentDirectory,
            source,
        )
    })
}

#[cfg(test)]
mod tests;
