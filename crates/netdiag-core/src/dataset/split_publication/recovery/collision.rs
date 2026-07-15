use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::BoundAtomicFileTarget;

pub(in crate::dataset::split_publication) fn preserve_failed_noclobber_state(
    target: &BoundAtomicFileTarget,
    error: NetdiagError,
    validate_existing: impl FnOnce() -> crate::error::Result<()>,
) -> NetdiagError {
    if !is_confirmed_existing_cleanup_failure(&error, target) {
        return error;
    }
    match validate_existing() {
        Ok(()) => NetdiagError::atomic_publish(
            target.resolved_path().to_path_buf(),
            AtomicPublishPhase::Published,
            error,
        ),
        Err(validation) => NetdiagError::PublicationStateIndeterminate {
            path: target.resolved_path().to_path_buf(),
            source: Box::new(error.with_secondary_failure(
                "existing immutable target collision cleanup failed",
                "existing target validation also failed",
                validation,
            )),
        },
    }
}

fn is_confirmed_existing_cleanup_failure(
    error: &NetdiagError,
    target: &BoundAtomicFileTarget,
) -> bool {
    let NetdiagError::AtomicPublish {
        path,
        phase: AtomicPublishPhase::NotPublished,
        source,
    } = error
    else {
        return false;
    };
    if path != target.resolved_path() {
        return false;
    }
    matches!(
        source.as_ref(),
        NetdiagError::ExistingTargetCollisionCleanup { path, .. }
            if path == target.resolved_path()
    )
}

#[cfg(test)]
mod tests;
