use crate::error::{AtomicPublishPhase, NetdiagError};
use std::path::Path;

#[cfg(any(unix, windows))]
pub(super) fn trust_error(source: netdiag_platform::DirectoryTrustError) -> NetdiagError {
    NetdiagError::FilesystemTrust {
        context: "dataset directory",
        source,
    }
}

pub(super) fn published_but_durability_uncertain(
    target: &Path,
    source: NetdiagError,
) -> NetdiagError {
    NetdiagError::atomic_publish(
        target.to_path_buf(),
        AtomicPublishPhase::PublishedButDurabilityUncertain,
        source,
    )
}

pub(super) fn published(target: &Path, source: NetdiagError) -> NetdiagError {
    NetdiagError::atomic_publish(target.to_path_buf(), AtomicPublishPhase::Published, source)
}

pub(super) fn combine_operation_and_identity_failure(
    primary: NetdiagError,
    identity: NetdiagError,
) -> NetdiagError {
    primary.with_secondary_failure(
        "dataset operation failed",
        "dataset directory identity validation also failed",
        identity,
    )
}
