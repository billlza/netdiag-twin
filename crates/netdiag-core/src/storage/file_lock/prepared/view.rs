use super::super::platform::open_coordination_file;
use super::PreparedLock;
use crate::error::Result;
use std::fs::File;
use std::path::Path;

impl PreparedLock {
    pub(in crate::storage::file_lock) fn key(&self) -> &str {
        &self.key
    }

    pub(in crate::storage::file_lock) fn target(&self) -> &Path {
        &self.target
    }

    pub(in crate::storage::file_lock) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub(in crate::storage::file_lock) fn open_lock_file(&self) -> Result<File> {
        open_coordination_file(&self.namespace, &self.lock_path)
    }
}
