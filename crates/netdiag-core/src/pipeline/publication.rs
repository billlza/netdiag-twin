use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::{OwnedArtifactRoot, StagedAtomicDirectory};
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

pub(super) type StagedRunDirectory = StagedAtomicDirectory;

pub(super) fn ensure_supported(target: &Path) -> Result<()> {
    netdiag_platform::ensure_directory_noclobber_publication_supported()
        .map_err(|source| platform_publication_error(target, source))
}

pub(super) fn preflight(artifact_root: &Path) -> Result<()> {
    let target = if artifact_root.is_absolute() {
        artifact_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| NetdiagError::Io {
                path: Path::new(".").to_path_buf(),
                source,
            })?
            .join(artifact_root)
    }
    .join("runs")
    .join("pending-run");
    ensure_supported(&target)
}

#[derive(Clone, Copy)]
pub(super) enum RunPublicationRoot<'a> {
    Owned(&'a OwnedArtifactRoot),
    Nested(&'a StagedAtomicDirectory),
}

impl RunPublicationRoot<'_> {
    pub(super) fn directory(&self) -> &Arc<netdiag_platform::TrustedDirectory> {
        match self {
            Self::Owned(owned) => owned.directory(),
            Self::Nested(staged) => staged.trusted_directory(),
        }
    }
}

pub(super) struct PendingRunPublication {
    run_id: String,
}

impl PendingRunPublication {
    pub(super) fn prepare() -> Self {
        Self {
            run_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub(super) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(super) fn stage(self, root: RunPublicationRoot<'_>) -> Result<StagedRunDirectory> {
        let target_path = root
            .directory()
            .resolved_path()
            .join("runs")
            .join(&self.run_id);
        ensure_supported(&target_path)?;
        let runs_root = netdiag_platform::open_or_create_durable_trusted_subdirectory(
            root.directory(),
            OsStr::new("runs"),
        )
        .map_err(|source| {
            NetdiagError::atomic_publish(
                &target_path,
                AtomicPublishPhase::NotPublished,
                NetdiagError::FilesystemTrust {
                    context: "pipeline run staging",
                    source,
                },
            )
        })?;
        StagedRunDirectory::create_unique_in(
            Arc::new(runs_root),
            self.run_id.into(),
            "pipeline run staging failed",
        )
    }
}

fn platform_publication_error(
    target: &Path,
    failure: netdiag_platform::AtomicPublicationError,
) -> NetdiagError {
    let phase = AtomicPublishPhase::from(failure.state());
    let source = NetdiagError::PlatformAtomicPublication {
        path: target.to_path_buf(),
        source: failure,
    };
    NetdiagError::atomic_publish(target, phase, source)
}

#[cfg(test)]
mod tests;
