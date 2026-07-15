use super::{NoClobberDisposition, StagedAtomicFile};
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;
use crate::storage::atomic_file::publish::platform_failure;

mod existing;
use existing::is_existing_target;

impl StagedAtomicFile {
    pub(crate) fn publish_noclobber(
        mut self,
        target: &BoundAtomicFileTarget,
    ) -> Result<NoClobberDisposition> {
        if !target.shares_directory_arc(&self.directory) {
            let source = self.abort(NetdiagError::InvalidTrace(format!(
                "staged atomic file and publication target do not share one trusted directory handle: {}",
                target.resolved_path().display()
            )));
            return Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::NotPublished,
                source,
            ));
        }
        if let Err(source) = self.sync() {
            let source = self.abort(source);
            return Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::NotPublished,
                source,
            ));
        }
        self.close_file();
        match netdiag_platform::publish_file_noclobber_at(
            target.directory(),
            &self.name,
            target.target_name(),
        ) {
            Ok(()) => {
                self.cleanup_armed = false;
                Ok(NoClobberDisposition::Created)
            }
            Err(failure) if is_existing_target(&failure) => self.resolve_existing(target, failure),
            Err(failure) => Err(self.map_publication_failure(target, failure)),
        }
    }

    fn resolve_existing(
        mut self,
        target: &BoundAtomicFileTarget,
        failure: netdiag_platform::AtomicPublicationError,
    ) -> Result<NoClobberDisposition> {
        let collision = NetdiagError::PlatformAtomicPublication {
            path: target.resolved_path().to_path_buf(),
            source: failure,
        };
        match self.cleanup() {
            Ok(()) => Ok(NoClobberDisposition::Existing),
            Err(cleanup) => Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::NotPublished,
                NetdiagError::ExistingTargetCollisionCleanup {
                    path: target.resolved_path().to_path_buf(),
                    collision: Box::new(collision),
                    cleanup: Box::new(cleanup),
                },
            )),
        }
    }

    fn map_publication_failure(
        mut self,
        target: &BoundAtomicFileTarget,
        failure: netdiag_platform::AtomicPublicationError,
    ) -> NetdiagError {
        let failure = platform_failure(target, failure);
        let phase = failure.phase;
        let source = match phase {
            AtomicPublishPhase::NotPublished => self.abort(*failure.source),
            AtomicPublishPhase::PublishedButDurabilityUncertain | AtomicPublishPhase::Published => {
                self.cleanup_armed = false;
                *failure.source
            }
        };
        NetdiagError::atomic_publish(target.resolved_path().to_path_buf(), phase, source)
    }
}
