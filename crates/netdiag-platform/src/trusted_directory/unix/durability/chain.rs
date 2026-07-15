use super::super::{DirectoryPersistenceStage, DirectoryTrustError};
use super::persist_error;
use std::fs::File;
use std::path::{Path, PathBuf};

pub(in crate::trusted_directory::unix) fn persist_directory_chain_if_required(
    durable: bool,
    directory: &File,
    directory_path: &Path,
    ancestors: &[(File, PathBuf)],
) -> Result<(), DirectoryTrustError> {
    persist_if_required(durable, || {
        persist_directory_chain_with(directory, directory_path, ancestors, |directory, _, _| {
            directory.sync_all()
        })
    })
}

fn persist_if_required(
    durable: bool,
    persist: impl FnOnce() -> Result<(), DirectoryTrustError>,
) -> Result<(), DirectoryTrustError> {
    if durable { persist() } else { Ok(()) }
}

fn persist_directory_chain_with<T>(
    directory: &T,
    directory_path: &Path,
    ancestors: &[(T, PathBuf)],
    mut sync: impl FnMut(&T, &Path, DirectoryPersistenceStage) -> std::io::Result<()>,
) -> Result<(), DirectoryTrustError> {
    sync(
        directory,
        directory_path,
        DirectoryPersistenceStage::Directory,
    )
    .map_err(|source| {
        persist_error(directory_path, DirectoryPersistenceStage::Directory, source)
    })?;
    for (ancestor, path) in ancestors.iter().rev() {
        sync(ancestor, path, DirectoryPersistenceStage::ParentDirectory).map_err(|source| {
            persist_error(path, DirectoryPersistenceStage::ParentDirectory, source)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
