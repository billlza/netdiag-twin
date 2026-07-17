use super::super::durability::cleanup_failed_write;
use super::super::publish::AtomicPublishFailure;
use super::super::target::BoundAtomicFileTarget;
use crate::error::{AtomicPublishPhase, NetdiagError};
use std::ffi::OsStr;
use std::path::Path;

pub(super) fn publish_error(
    bound_target: &BoundAtomicFileTarget,
    target: &Path,
    temporary_name: &OsStr,
    temporary_path: &Path,
    failure: AtomicPublishFailure,
) -> NetdiagError {
    let AtomicPublishFailure { phase, source } = failure;
    let source = match phase {
        AtomicPublishPhase::NotPublished => {
            cleanup_failed_write(bound_target, temporary_name, temporary_path, *source)
        }
        AtomicPublishPhase::PublishedButDurabilityUncertain | AtomicPublishPhase::Published => {
            *source
        }
    };
    NetdiagError::atomic_publish(target.to_path_buf(), phase, source)
}
