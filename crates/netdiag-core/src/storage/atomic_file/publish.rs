use super::target::BoundAtomicFileTarget;
use crate::error::{AtomicPublishPhase, NetdiagError};
use netdiag_platform::AtomicPublicationError;
use std::ffi::OsStr;

#[derive(Debug)]
pub(crate) struct AtomicPublishFailure {
    pub(crate) phase: AtomicPublishPhase,
    pub(crate) source: Box<NetdiagError>,
}

pub(crate) type PublishResult = std::result::Result<(), AtomicPublishFailure>;

pub(crate) fn publish_temporary_file(
    target: &BoundAtomicFileTarget,
    temporary: &OsStr,
) -> PublishResult {
    netdiag_platform::publish_file_replace_at(target.directory(), temporary, target.target_name())
        .map_err(|source| platform_failure(target, source))
}

#[cfg(test)]
pub(crate) fn published_uncertain(source: NetdiagError) -> AtomicPublishFailure {
    AtomicPublishFailure {
        phase: AtomicPublishPhase::PublishedButDurabilityUncertain,
        source: Box::new(source),
    }
}

pub(super) fn platform_failure(
    target: &BoundAtomicFileTarget,
    failure: AtomicPublicationError,
) -> AtomicPublishFailure {
    let phase = AtomicPublishPhase::from(failure.state());
    AtomicPublishFailure {
        phase,
        source: Box::new(NetdiagError::PlatformAtomicPublication {
            path: target.resolved_path().to_path_buf(),
            source: failure,
        }),
    }
}

#[cfg(test)]
mod tests;
