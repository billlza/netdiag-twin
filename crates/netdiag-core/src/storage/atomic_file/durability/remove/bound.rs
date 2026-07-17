use super::super::super::target::BoundAtomicFileTarget;
use super::super::super::temporary::temporary_name;
use crate::error::NetdiagError;

#[derive(Debug)]
pub(crate) enum BoundFileRemovalFailure {
    OriginalRetained(NetdiagError),
    StateUncertain(NetdiagError),
    RemovedButCleanupFailed(NetdiagError),
}

pub(crate) fn remove_bound_file_durably(
    target: &BoundAtomicFileTarget,
) -> std::result::Result<(), BoundFileRemovalFailure> {
    let tombstone = temporary_name(target.target_name(), "rollback");
    let tombstone_path = target.directory().resolved_path().join(&tombstone);
    match netdiag_platform::publish_file_noclobber_at(
        target.directory(),
        target.target_name(),
        &tombstone,
    ) {
        Ok(()) => match netdiag_platform::remove_file_at(target.directory(), &tombstone) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(BoundFileRemovalFailure::RemovedButCleanupFailed(
                NetdiagError::Io {
                    path: tombstone_path,
                    source,
                },
            )),
        },
        Err(source) => classify_publication_failure(target, source),
    }
}

fn classify_publication_failure(
    target: &BoundAtomicFileTarget,
    source: netdiag_platform::AtomicPublicationError,
) -> std::result::Result<(), BoundFileRemovalFailure> {
    let state = source.state();
    let missing = source.kind() == std::io::ErrorKind::NotFound;
    let error = NetdiagError::PlatformAtomicPublication {
        path: target.resolved_path().to_path_buf(),
        source,
    };
    match state {
        netdiag_platform::AtomicPublicationState::NotPublished if !missing => {
            Err(BoundFileRemovalFailure::OriginalRetained(error))
        }
        netdiag_platform::AtomicPublicationState::NotPublished
        | netdiag_platform::AtomicPublicationState::PublishedButDurabilityUncertain => {
            Err(BoundFileRemovalFailure::StateUncertain(error))
        }
    }
}
