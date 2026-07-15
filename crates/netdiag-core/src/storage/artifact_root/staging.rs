use super::ownership::OwnedArtifactRoot;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::StagedAtomicDirectory;
use std::ffi::OsString;
use std::path::{Component, Path};
use std::sync::Arc;

mod lifecycle;
pub(crate) use lifecycle::{discard, finish};

pub(crate) fn create(
    owned: &OwnedArtifactRoot,
    relative_parent: &Path,
    target_name: OsString,
    context: &'static str,
) -> Result<StagedAtomicDirectory> {
    let target = owned
        .directory()
        .resolved_path()
        .join(relative_parent)
        .join(&target_name);
    netdiag_platform::ensure_directory_noclobber_publication_supported().map_err(|source| {
        NetdiagError::atomic_publish(
            &target,
            AtomicPublishPhase::from(source.state()),
            NetdiagError::PlatformAtomicPublication {
                path: target.clone(),
                source,
            },
        )
    })?;
    let parent = open_relative_parent(owned, relative_parent, context)?;
    StagedAtomicDirectory::create_unique_in(parent, target_name, context)
}

fn open_relative_parent(
    owned: &OwnedArtifactRoot,
    relative: &Path,
    context: &'static str,
) -> Result<Arc<netdiag_platform::TrustedDirectory>> {
    let mut directory = Arc::clone(owned.directory());
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(NetdiagError::InvalidTrace(format!(
                "artifact staging parent must be a relative child path: {}",
                relative.display()
            )));
        };
        directory = Arc::new(
            netdiag_platform::open_or_create_durable_trusted_subdirectory(&directory, name)
                .map_err(|source| NetdiagError::FilesystemTrust { context, source })?,
        );
    }
    Ok(directory)
}
