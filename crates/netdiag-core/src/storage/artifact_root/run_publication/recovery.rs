use super::super::ownership::OwnedArtifactRoot;
use super::contract::RunPublicationJournal;
use super::{index, io};
use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;
use crate::storage::typed_json::MAX_RUN_MANIFEST_BYTES;
use crate::storage::{
    BoundAtomicFileTarget, PathStatus, path_status, read_stable_regular_file_bounded_at,
};
use std::ffi::OsStr;
use std::sync::Arc;

pub(super) fn recover(owned: &OwnedArtifactRoot) -> Result<()> {
    let Some(journal) = io::read(owned)? else {
        return Ok(());
    };
    let runs_path = owned.directory().resolved_path().join("runs");
    let runs = netdiag_platform::open_trusted_directory_chain(&runs_path).map_err(|source| {
        NetdiagError::FilesystemTrust {
            context: "run publication recovery",
            source,
        }
    })?;
    let staging = inspect_directory(&runs, &journal.staging_name, &journal)?;
    let published = inspect_directory(&runs, &journal.run_id, &journal)?;
    let published = match (staging, published) {
        (Some(staging), None) => {
            netdiag_platform::publish_directory_noclobber_at(
                &runs,
                &staging,
                OsStr::new(&journal.staging_name),
                OsStr::new(&journal.run_id),
            )
            .map_err(|source| NetdiagError::PlatformAtomicPublication {
                path: runs_path.join(&journal.run_id),
                source,
            })?;
            inspect_directory(&runs, &journal.run_id, &journal)?.ok_or_else(|| {
                NetdiagError::InvalidTrace(
                    "recovered run publication disappeared after atomic rename".to_string(),
                )
            })?
        }
        (None, Some(published)) => published,
        (Some(_), Some(_)) => {
            return Err(NetdiagError::InvalidTrace(
                "run publication recovery found both staged and published directories".to_string(),
            ));
        }
        (None, None) => {
            return Err(NetdiagError::InvalidTrace(
                "run publication journal references no recoverable directory".to_string(),
            ));
        }
    };
    validate_manifest(&published, &journal)?;
    index::upsert_at(owned.directory(), &journal.index_entry)?;
    io::remove(owned)
}

fn inspect_directory(
    runs: &netdiag_platform::TrustedDirectory,
    name: &str,
    journal: &RunPublicationJournal,
) -> Result<Option<Arc<netdiag_platform::TrustedDirectory>>> {
    let path = runs.resolved_path().join(name);
    match path_status(&path)? {
        PathStatus::Missing => Ok(None),
        PathStatus::Directory => {
            let directory =
                netdiag_platform::open_trusted_directory_chain(&path).map_err(|source| {
                    NetdiagError::FilesystemTrust {
                        context: "run publication recovery",
                        source,
                    }
                })?;
            let identity = directory.coordination_identity().map_err(|source| {
                NetdiagError::FilesystemTrust {
                    context: "run publication recovery",
                    source,
                }
            })?;
            if identity != journal.directory_identity {
                return Err(NetdiagError::InvalidTrace(format!(
                    "journaled run directory identity changed: {}",
                    path.display()
                )));
            }
            let directory = Arc::new(directory);
            validate_manifest(&directory, journal)?;
            Ok(Some(directory))
        }
        _ => Err(NetdiagError::InvalidTrace(format!(
            "journaled run path is not a trusted directory: {}",
            path.display()
        ))),
    }
}

fn validate_manifest(
    directory: &Arc<netdiag_platform::TrustedDirectory>,
    journal: &RunPublicationJournal,
) -> Result<RunManifest> {
    let target =
        BoundAtomicFileTarget::from_directory(Arc::clone(directory), OsStr::new("manifest.json"))?;
    let bytes =
        read_stable_regular_file_bounded_at(&target, MAX_RUN_MANIFEST_BYTES)?.ok_or_else(|| {
            NetdiagError::InvalidTrace("journaled run manifest is missing".to_string())
        })?;
    journal.validate_manifest(&bytes)
}
