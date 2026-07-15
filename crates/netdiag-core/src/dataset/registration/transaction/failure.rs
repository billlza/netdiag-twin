use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::BoundAtomicFileTarget;

pub(super) fn preserve_after_publication_failure(
    root: &TrustedDatasetRoot,
    expected_target: &BoundAtomicFileTarget,
    created: &[BoundAtomicFileTarget],
    error: NetdiagError,
) -> NetdiagError {
    match &error {
        NetdiagError::AtomicPublish { path, phase, .. }
            if path == expected_target.resolved_path() =>
        {
            match phase {
                AtomicPublishPhase::NotPublished => root.rollback_created_files(created, error),
                AtomicPublishPhase::PublishedButDurabilityUncertain
                | AtomicPublishPhase::Published => error,
            }
        }
        _ => NetdiagError::PublicationStateIndeterminate {
            path: expected_target.resolved_path().to_path_buf(),
            source: Box::new(error),
        },
    }
}
