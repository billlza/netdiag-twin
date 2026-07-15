use super::StagedAtomicDirectory;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use std::path::{Path, PathBuf};

pub(crate) fn preserve_published_directory<T>(target: &Path, result: Result<T>) -> Result<T> {
    result.map_err(|source| {
        NetdiagError::atomic_publish(target, AtomicPublishPhase::Published, source)
    })
}

impl StagedAtomicDirectory {
    pub(crate) fn abort(self, source: NetdiagError) -> NetdiagError {
        let target_path = self.target_path.clone();
        let source = self.cleanup(source);
        NetdiagError::atomic_publish(target_path, AtomicPublishPhase::NotPublished, source)
    }

    pub(crate) fn finish<T>(self, operation: Result<T>) -> Result<(T, PathBuf)> {
        match operation {
            Ok(value) => self.publish().map(|path| (value, path)),
            Err(source) => Err(self.abort(source)),
        }
    }

    pub(crate) fn discard<T>(self, operation: Result<T>) -> Result<T> {
        match operation {
            Err(source) => Err(self.abort(source)),
            Ok(value) => {
                let target_path = self.target_path.clone();
                self.remove_stage().map_err(|source| {
                    NetdiagError::atomic_publish(
                        target_path,
                        AtomicPublishPhase::NotPublished,
                        source,
                    )
                })?;
                Ok(value)
            }
        }
    }

    pub(crate) fn publish(self) -> Result<PathBuf> {
        self.publish_with(|| Ok(()))
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn publish_after(
        self,
        before_publish: impl FnOnce() -> Result<()>,
    ) -> Result<PathBuf> {
        self.publish_with(before_publish)
    }

    fn publish_with(self, before_publish: impl FnOnce() -> Result<()>) -> Result<PathBuf> {
        if let Err(source) = before_publish() {
            return Err(self.abort(source));
        }
        match netdiag_platform::publish_directory_noclobber_at(
            &self.parent,
            &self.directory,
            &self.staging_name,
            &self.target_name,
        ) {
            Ok(()) => Ok(self.target_path),
            Err(failure) => self.map_publication_failure(failure),
        }
    }

    fn map_publication_failure(
        self,
        failure: netdiag_platform::AtomicPublicationError,
    ) -> Result<PathBuf> {
        let phase = AtomicPublishPhase::from(failure.state());
        let source = NetdiagError::PlatformAtomicPublication {
            path: self.target_path.clone(),
            source: failure,
        };
        self.handle_publication_failure(phase, source)
    }

    fn handle_publication_failure(
        self,
        phase: AtomicPublishPhase,
        source: NetdiagError,
    ) -> Result<PathBuf> {
        match phase {
            AtomicPublishPhase::NotPublished => Err(self.abort(source)),
            AtomicPublishPhase::PublishedButDurabilityUncertain => Err(
                NetdiagError::atomic_publish(self.target_path, phase, source),
            ),
            AtomicPublishPhase::Published => {
                unreachable!("platform publication failures never report fully published state")
            }
        }
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    pub(super) fn fail_with_publication_phase(
        self,
        phase: AtomicPublishPhase,
        source: NetdiagError,
    ) -> Result<PathBuf> {
        self.handle_publication_failure(phase, source)
    }
}
