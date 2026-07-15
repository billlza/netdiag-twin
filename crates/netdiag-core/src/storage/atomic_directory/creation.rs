use super::StagedAtomicDirectory;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

impl StagedAtomicDirectory {
    pub(crate) fn create_unique_in(
        parent: Arc<netdiag_platform::TrustedDirectory>,
        target_name: OsString,
        context: &'static str,
    ) -> Result<Self> {
        let requested_target = parent.resolved_path().join(&target_name);
        netdiag_platform::ensure_directory_noclobber_publication_supported().map_err(|source| {
            let phase = AtomicPublishPhase::from(source.state());
            let source = NetdiagError::PlatformAtomicPublication {
                path: requested_target.clone(),
                source,
            };
            NetdiagError::atomic_publish(requested_target.clone(), phase, source)
        })?;
        let staging_name = format!(".staged-{}.tmp", uuid::Uuid::new_v4().simple()).into();
        Self::create(
            parent,
            staging_name,
            target_name,
            requested_target.clone(),
            context,
        )
        .map_err(|source| {
            NetdiagError::atomic_publish(requested_target, AtomicPublishPhase::NotPublished, source)
        })
    }

    pub(super) fn create(
        parent: Arc<netdiag_platform::TrustedDirectory>,
        staging_name: OsString,
        target_name: OsString,
        target_path: PathBuf,
        context: &'static str,
    ) -> Result<Self> {
        let directory =
            netdiag_platform::create_new_private_trusted_subdirectory(&parent, &staging_name)
                .map_err(|source| NetdiagError::FilesystemTrust { context, source })?;
        Ok(Self {
            parent,
            directory: Arc::new(directory),
            staging_name,
            target_name,
            target_path,
            context,
        })
    }
}
