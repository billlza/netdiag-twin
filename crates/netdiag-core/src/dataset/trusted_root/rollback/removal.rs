use super::super::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::{BoundAtomicFileTarget, BoundFileRemovalFailure, remove_bound_file_durably};

impl TrustedDatasetRoot {
    pub(super) fn remove_created(
        &self,
        target: &BoundAtomicFileTarget,
        phase_before_rollback: AtomicPublishPhase,
    ) -> Result<()> {
        if !self.owns_target(target) {
            return Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::PublishedButDurabilityUncertain,
                NetdiagError::InvalidTrace(
                    "dataset rollback target is not bound to the trusted dataset root".to_string(),
                ),
            ));
        }
        match remove_bound_file_durably(target) {
            Ok(()) => Ok(()),
            Err(BoundFileRemovalFailure::OriginalRetained(source)) => {
                Err(NetdiagError::atomic_publish(
                    target.resolved_path().to_path_buf(),
                    phase_before_rollback,
                    source,
                ))
            }
            Err(BoundFileRemovalFailure::StateUncertain(source)) => {
                Err(NetdiagError::atomic_publish(
                    target.resolved_path().to_path_buf(),
                    AtomicPublishPhase::PublishedButDurabilityUncertain,
                    source,
                ))
            }
            Err(BoundFileRemovalFailure::RemovedButCleanupFailed(source)) => {
                Err(NetdiagError::atomic_publish(
                    target.resolved_path().to_path_buf(),
                    AtomicPublishPhase::NotPublished,
                    source,
                ))
            }
        }
    }
}
