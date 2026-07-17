use super::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;

mod removal;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn rollback_created_files(
        &self,
        targets: &[BoundAtomicFileTarget],
        original: NetdiagError,
    ) -> NetdiagError {
        targets.iter().rev().fold(original, |primary, target| {
            match self.remove_created(target, AtomicPublishPhase::Published) {
                Ok(()) => primary,
                Err(cleanup) => primary.with_secondary_failure(
                    "dataset registration failed",
                    "rollback of an immutable dependency also failed",
                    cleanup,
                ),
            }
        })
    }

    pub(in crate::dataset) fn remove_created_file_after_error<T>(
        &self,
        target: &BoundAtomicFileTarget,
        phase_before_rollback: AtomicPublishPhase,
        original: NetdiagError,
    ) -> Result<T> {
        match self.remove_created(target, phase_before_rollback) {
            Ok(()) => Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::NotPublished,
                original,
            )),
            Err(cleanup) => {
                let phase = cleanup
                    .atomic_publish_phase()
                    .unwrap_or(AtomicPublishPhase::PublishedButDurabilityUncertain);
                Err(NetdiagError::atomic_publish(
                    target.resolved_path().to_path_buf(),
                    phase,
                    original.with_secondary_failure(
                        "dataset publication failed",
                        "rollback of the created file also failed",
                        cleanup,
                    ),
                ))
            }
        }
    }
}
