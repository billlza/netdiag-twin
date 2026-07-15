use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{NetdiagError, Result};
use crate::storage::{BoundAtomicFileTarget, NoClobberDisposition, StagedAtomicFile};
use std::path::Path;

mod bounded_digest;
mod digest;
mod lifecycle;
mod publication;
mod source;

pub(super) struct RegistrationSnapshot {
    file: Option<StagedAtomicFile>,
    pub(super) hash_sha256: String,
}

impl RegistrationSnapshot {
    pub(super) fn capture(
        source_path: &Path,
        root: &TrustedDatasetRoot,
        source_opened: impl FnOnce(),
        copy_completed: impl FnOnce(),
    ) -> Result<Self> {
        let captured = source::capture(source_path, root, source_opened, copy_completed)?;
        Ok(Self {
            file: Some(captured.file),
            hash_sha256: captured.hash_sha256,
        })
    }

    pub(super) fn publish(
        &mut self,
        root: &TrustedDatasetRoot,
        target: &BoundAtomicFileTarget,
        expected_hash: &str,
    ) -> Result<NoClobberDisposition> {
        let staged = self.file.take().ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "dataset registration snapshot was already published or aborted".to_string(),
            )
        })?;
        publication::publish_snapshot(root, staged, target, expected_hash)
    }

    pub(super) fn validate_existing_target_if_present(
        &self,
        target: &BoundAtomicFileTarget,
    ) -> Result<()> {
        publication::verify_existing_hash_if_present(target, &self.hash_sha256)
    }
}
