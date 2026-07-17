use super::StagedAtomicDirectory;
use crate::error::{IoContext, Result};

impl StagedAtomicDirectory {
    pub(in crate::storage::atomic_directory) fn remove_stage(self) -> Result<()> {
        let stage_path = self.parent.resolved_path().join(&self.staging_name);
        match netdiag_platform::remove_directory_tree_at(
            &self.parent,
            &self.directory,
            &self.staging_name,
        ) {
            Ok(()) => self
                .parent
                .as_file()
                .sync_all()
                .with_path(self.parent.resolved_path()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(crate::error::NetdiagError::Io {
                path: stage_path,
                source,
            }),
        }
    }
}
