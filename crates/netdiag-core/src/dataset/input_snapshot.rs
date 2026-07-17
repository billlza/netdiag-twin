use super::registration_snapshot::RegistrationSnapshot;
use super::trusted_root::TrustedDatasetRoot;
use crate::error::Result;
use crate::managed_temp_directory::ManagedTempDirectory;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

mod capture;
#[cfg(test)]
mod tests;

pub(super) struct DatasetInputSnapshot {
    snapshot: RegistrationSnapshot,
    trusted_root: TrustedDatasetRoot,
    staging: ManagedTempDirectory,
}

impl DatasetInputSnapshot {
    pub(super) fn capture(source: &Path) -> Result<Self> {
        Self::capture_with_staging_observer(source, |_| {})
    }

    fn capture_with_staging_observer(
        source: &Path,
        after_staging_created: impl FnOnce(&Path),
    ) -> Result<Self> {
        capture::capture(source, after_staging_created)
    }

    pub(super) fn hash_sha256(&self) -> &str {
        &self.snapshot.hash_sha256
    }

    pub(super) fn read<T>(&self, action: impl FnOnce(BufReader<File>) -> Result<T>) -> Result<T> {
        self.trusted_root.validate()?;
        let result = self
            .snapshot
            .reopen()
            .and_then(|file| action(BufReader::new(file)));
        self.trusted_root.finish(result)
    }

    pub(super) fn finish<T>(self, result: Result<T>) -> Result<T> {
        let Self {
            snapshot,
            trusted_root,
            staging,
        } = self;
        let result = snapshot.finish(result);
        let result = trusted_root.finish(result);
        drop(trusted_root);
        staging.finish(result)
    }
}
