use crate::error::{NetdiagError, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use super::MAX_ADAPTER_FILE_BYTES;
#[cfg(unix)]
use crate::managed_temp_directory::ManagedTempDirectory;

#[cfg(unix)]
mod copy;
#[cfg(unix)]
mod file_security;
mod prepare;
#[cfg(unix)]
mod source_validation;
#[cfg(unix)]
mod stage;
#[cfg(unix)]
mod trusted_root;

#[derive(Debug)]
pub(super) struct StagedAdapters {
    #[cfg(unix)]
    directory: ManagedTempDirectory,
    adapters: BTreeMap<String, StagedAdapter>,
}

#[derive(Debug)]
struct StagedAdapter {
    original_path: PathBuf,
    staged_path: PathBuf,
    identity: String,
}

impl StagedAdapters {
    pub(in crate::pilot) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        #[cfg(unix)]
        {
            let Self {
                directory,
                adapters,
            } = self;
            drop(adapters);
            directory.finish(operation)
        }
        #[cfg(not(unix))]
        {
            let _ = self;
            operation
        }
    }

    pub(super) fn staged_path(&self, source_name: &str) -> Result<&Path> {
        self.adapters
            .get(source_name)
            .map(|adapter| adapter.staged_path.as_path())
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "prepared adapter is missing for source {source_name}"
                ))
            })
    }

    pub(super) fn original_path(&self, source_name: &str) -> Result<&Path> {
        self.adapters
            .get(source_name)
            .map(|adapter| adapter.original_path.as_path())
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "prepared adapter is missing for source {source_name}"
                ))
            })
    }

    pub(super) fn identity(&self, source_name: &str) -> Result<&str> {
        self.adapters
            .get(source_name)
            .map(|adapter| adapter.identity.as_str())
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "prepared adapter is missing for source {source_name}"
                ))
            })
    }
}

#[cfg(all(test, unix))]
mod tests;
