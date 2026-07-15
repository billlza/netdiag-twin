use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, NoClobberDisposition, read_stable_regular_file_bounded_at,
    with_exclusive_bound_file_lock, write_file_atomically_noclobber_or_existing_to_bound,
};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) const OWNERSHIP_FILE_NAME: &str = ".netdiag-artifact-root.json";
const OWNERSHIP_SCHEMA_VERSION: u32 = 1;
const OWNERSHIP_PRODUCT_ID: &str = "netdiag_twin";
const MAX_OWNERSHIP_BYTES: u64 = 1024;
const OWNERSHIP_CONTEXT: &str = "artifact root ownership";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipMarker {
    schema_version: u32,
    product_id: String,
    root_id: String,
}

pub(crate) struct OwnedArtifactRoot {
    directory: Arc<netdiag_platform::TrustedDirectory>,
    marker: BoundAtomicFileTarget,
    root_id: String,
}

#[derive(Clone)]
pub(crate) struct ArtifactRootCapability {
    path: PathBuf,
    directory: Arc<netdiag_platform::TrustedDirectory>,
    marker: BoundAtomicFileTarget,
    root_id: String,
    directory_identity: [u8; 32],
}

impl ArtifactRootCapability {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl OwnedArtifactRoot {
    pub(crate) fn directory(&self) -> &Arc<netdiag_platform::TrustedDirectory> {
        &self.directory
    }

    pub(super) fn root_id(&self) -> &str {
        &self.root_id
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_directory_identity(&self.directory)?;
        let marker = read_marker(&self.marker)?.ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "artifact root ownership marker disappeared: {}",
                self.marker.resolved_path().display()
            ))
        })?;
        if marker.root_id != self.root_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "artifact root ownership changed while the operation was in progress: {}",
                self.directory.resolved_path().display()
            )));
        }
        validate_directory_identity(&self.directory)
    }

    fn capability(&self) -> Result<ArtifactRootCapability> {
        Ok(ArtifactRootCapability {
            path: self.directory.resolved_path().to_path_buf(),
            directory: Arc::clone(&self.directory),
            marker: self.marker.clone(),
            root_id: self.root_id.clone(),
            directory_identity: coordination_identity(&self.directory)?,
        })
    }
}

pub fn ensure_artifact_root_owned(path: impl AsRef<Path>) -> Result<()> {
    with_owned_artifact_root(path.as_ref(), |_| Ok(()))
}

pub(crate) fn migrate_legacy_artifact_root_with_validator(
    path: impl AsRef<Path>,
    validate_artifacts: impl Fn(&netdiag_platform::TrustedDirectory) -> Result<()>,
) -> Result<()> {
    let directory = open_existing_root(path.as_ref())?;
    let marker = BoundAtomicFileTarget::from_directory(
        Arc::clone(&directory),
        OsStr::new(OWNERSHIP_FILE_NAME),
    )?;
    with_exclusive_bound_file_lock(&marker, || {
        validate_directory_identity(&directory)?;
        if let Some(existing) = read_marker(&marker)? {
            let owned = owned_root(&directory, &marker, existing);
            owned.validate()?;
            super::run_publication::recover(&owned)?;
            super::clear::recover_interrupted_clear(&owned)?;
            return owned.validate();
        }
        super::migration::validate_layout(&directory, false)?;
        validate_artifacts(&directory)?;
        let ownership = new_marker();
        let disposition = publish_marker(&marker, &ownership)?;
        match disposition {
            NoClobberDisposition::Created => {
                let validation = super::migration::validate_layout(&directory, true)
                    .and_then(|()| validate_artifacts(&directory));
                if let Err(error) = validation {
                    return Err(rollback_created_marker(&directory, &marker, error));
                }
            }
            NoClobberDisposition::Existing => {
                return Err(NetdiagError::InvalidTrace(format!(
                    "artifact root ownership marker appeared during explicit migration: {}",
                    marker.resolved_path().display()
                )));
            }
        }
        let persisted = read_marker(&marker)?.ok_or_else(|| {
            NetdiagError::InvalidTrace("migrated artifact root marker disappeared".to_string())
        })?;
        if persisted != ownership {
            return Err(NetdiagError::InvalidTrace(
                "migrated artifact root marker changed during publication".to_string(),
            ));
        }
        validate_directory_identity(&directory)
    })
}

pub(crate) fn prepare_artifact_root(path: impl AsRef<Path>) -> Result<ArtifactRootCapability> {
    with_owned_artifact_root(path.as_ref(), OwnedArtifactRoot::capability)
}

pub(crate) fn with_artifact_root_capability<T>(
    capability: &ArtifactRootCapability,
    action: impl FnOnce(&OwnedArtifactRoot) -> Result<T>,
) -> Result<T> {
    let directory = Arc::clone(&capability.directory);
    let marker = capability.marker.clone();
    with_exclusive_bound_file_lock(&marker, || {
        validate_directory_identity(&directory)?;
        let ownership = read_marker(&marker)?.ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "authorized artifact root no longer has an ownership marker: {}",
                capability.path.display()
            ))
        })?;
        let owned = owned_root(&directory, &marker, ownership);
        execute_owned_artifact_root(
            owned,
            |owned| {
                if owned.root_id != capability.root_id
                    || coordination_identity(&owned.directory)? != capability.directory_identity
                {
                    return Err(NetdiagError::InvalidTrace(format!(
                        "artifact root identity changed after it was authorized: {}",
                        capability.path.display()
                    )));
                }
                Ok(())
            },
            action,
        )
    })
}

pub(crate) fn with_owned_artifact_root<T>(
    path: &Path,
    action: impl FnOnce(&OwnedArtifactRoot) -> Result<T>,
) -> Result<T> {
    let directory = open_root(path)?;
    let marker = BoundAtomicFileTarget::from_directory(
        Arc::clone(&directory),
        OsStr::new(OWNERSHIP_FILE_NAME),
    )?;
    with_exclusive_bound_file_lock(&marker, || {
        validate_directory_identity(&directory)?;
        let ownership = match read_marker(&marker)? {
            Some(marker) => marker,
            None => claim_empty_root(&directory, &marker)?,
        };
        let owned = owned_root(&directory, &marker, ownership);
        execute_owned_artifact_root(owned, |_| Ok(()), action)
    })
}

fn execute_owned_artifact_root<T>(
    owned: OwnedArtifactRoot,
    authorize: impl FnOnce(&OwnedArtifactRoot) -> Result<()>,
    action: impl FnOnce(&OwnedArtifactRoot) -> Result<T>,
) -> Result<T> {
    owned.validate()?;
    authorize(&owned)?;
    super::run_publication::recover(&owned)?;
    super::clear::recover_interrupted_clear(&owned)?;
    owned.validate()?;
    let result = action(&owned);
    let completion = owned.validate();
    match (result, completion) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(identity)) => Err(identity),
        (Err(error), Err(identity)) => Err(error.with_secondary_failure(
            "artifact root operation failed",
            "artifact root ownership validation also failed",
            identity,
        )),
    }
}

fn open_root(path: &Path) -> Result<Arc<netdiag_platform::TrustedDirectory>> {
    let path = absolute(path)?;
    let directory =
        netdiag_platform::open_or_create_trusted_directory_chain(&path).map_err(|source| {
            NetdiagError::FilesystemTrust {
                context: OWNERSHIP_CONTEXT,
                source,
            }
        })?;
    directory
        .validate_private_security()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: OWNERSHIP_CONTEXT,
            source,
        })?;
    Ok(Arc::new(directory))
}

fn open_existing_root(path: &Path) -> Result<Arc<netdiag_platform::TrustedDirectory>> {
    let path = absolute(path)?;
    let directory = netdiag_platform::open_trusted_directory_chain(&path).map_err(|source| {
        NetdiagError::FilesystemTrust {
            context: OWNERSHIP_CONTEXT,
            source,
        }
    })?;
    directory
        .validate_private_security()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: OWNERSHIP_CONTEXT,
            source,
        })?;
    Ok(Arc::new(directory))
}

fn claim_empty_root(
    directory: &Arc<netdiag_platform::TrustedDirectory>,
    target: &BoundAtomicFileTarget,
) -> Result<OwnershipMarker> {
    ensure_root_empty(directory)?;
    let marker = new_marker();
    let disposition = publish_marker(target, &marker)?;
    match disposition {
        NoClobberDisposition::Created => match ensure_root_contains_only_marker(directory) {
            Ok(()) => Ok(marker),
            Err(error) => Err(rollback_created_marker(directory, target, error)),
        },
        NoClobberDisposition::Existing => read_marker(target)?.ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "artifact root ownership marker collision could not be resolved: {}",
                target.resolved_path().display()
            ))
        }),
    }
}

fn new_marker() -> OwnershipMarker {
    OwnershipMarker {
        schema_version: OWNERSHIP_SCHEMA_VERSION,
        product_id: OWNERSHIP_PRODUCT_ID.to_string(),
        root_id: uuid::Uuid::new_v4().to_string(),
    }
}

fn publish_marker(
    target: &BoundAtomicFileTarget,
    marker: &OwnershipMarker,
) -> Result<NoClobberDisposition> {
    let bytes = serde_json::to_vec_pretty(marker)?;
    if bytes.len() as u64 > MAX_OWNERSHIP_BYTES {
        return Err(NetdiagError::InvalidTrace(
            "artifact root ownership marker exceeds its fixed byte budget".to_string(),
        ));
    }
    write_file_atomically_noclobber_or_existing_to_bound(target, "json", |file| {
        file.write_all(&bytes).with_path(target.resolved_path())
    })
    .map(|(disposition, ())| disposition)
}

fn owned_root(
    directory: &Arc<netdiag_platform::TrustedDirectory>,
    marker: &BoundAtomicFileTarget,
    ownership: OwnershipMarker,
) -> OwnedArtifactRoot {
    OwnedArtifactRoot {
        directory: Arc::clone(directory),
        marker: marker.clone(),
        root_id: ownership.root_id,
    }
}

fn rollback_created_marker(
    directory: &netdiag_platform::TrustedDirectory,
    target: &BoundAtomicFileTarget,
    primary: NetdiagError,
) -> NetdiagError {
    let removal = netdiag_platform::remove_file_at(directory, target.target_name())
        .map_err(|source| NetdiagError::Io {
            path: target.resolved_path().to_path_buf(),
            source,
        })
        .and_then(|()| {
            directory
                .as_file()
                .sync_all()
                .with_path(directory.resolved_path())
        });
    match removal {
        Ok(()) => primary,
        Err(cleanup) => primary.with_secondary_failure(
            "artifact root ownership claim failed",
            "ownership marker rollback also failed",
            cleanup,
        ),
    }
}

fn ensure_root_empty(directory: &netdiag_platform::TrustedDirectory) -> Result<()> {
    validate_directory_identity(directory)?;
    let mut entries =
        fs::read_dir(directory.resolved_path()).with_path(directory.resolved_path())?;
    if let Some(entry) = entries.next() {
        let entry = entry.with_path(directory.resolved_path())?;
        return Err(NetdiagError::InvalidTrace(format!(
            "artifact root is non-empty but has no ownership marker; explicit migration is required before writing or clearing it: {}",
            entry.path().display()
        )));
    }
    validate_directory_identity(directory)
}

fn ensure_root_contains_only_marker(directory: &netdiag_platform::TrustedDirectory) -> Result<()> {
    validate_directory_identity(directory)?;
    let mut names = fs::read_dir(directory.resolved_path())
        .with_path(directory.resolved_path())?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .with_path(directory.resolved_path())
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    if names.as_slice() != [std::ffi::OsString::from(OWNERSHIP_FILE_NAME)] {
        return Err(NetdiagError::InvalidTrace(format!(
            "artifact root changed while its ownership marker was being created: {}",
            directory.resolved_path().display()
        )));
    }
    validate_directory_identity(directory)
}

fn read_marker(target: &BoundAtomicFileTarget) -> Result<Option<OwnershipMarker>> {
    let Some(bytes) = read_stable_regular_file_bounded_at(target, MAX_OWNERSHIP_BYTES)? else {
        return Ok(None);
    };
    let marker = crate::strict_json::from_slice::<OwnershipMarker>(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "artifact root ownership marker is invalid at {}: {}",
            target.resolved_path().display(),
            crate::strict_json::error_summary(&source)
        ))
    })?;
    validate_marker(marker, target.resolved_path()).map(Some)
}

fn validate_marker(marker: OwnershipMarker, path: &Path) -> Result<OwnershipMarker> {
    if marker.schema_version != OWNERSHIP_SCHEMA_VERSION {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported artifact root ownership schema {} at {}",
            marker.schema_version,
            path.display()
        )));
    }
    if marker.product_id != OWNERSHIP_PRODUCT_ID {
        return Err(NetdiagError::InvalidTrace(format!(
            "artifact root ownership product id is invalid at {}",
            path.display()
        )));
    }
    let parsed = uuid::Uuid::parse_str(&marker.root_id).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "artifact root ownership id is invalid at {}: {source}",
            path.display()
        ))
    })?;
    if parsed.to_string() != marker.root_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "artifact root ownership id is not canonical at {}",
            path.display()
        )));
    }
    Ok(marker)
}

fn validate_directory_identity(directory: &netdiag_platform::TrustedDirectory) -> Result<()> {
    directory
        .validate_identity()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: OWNERSHIP_CONTEXT,
            source,
        })
}

fn coordination_identity(directory: &netdiag_platform::TrustedDirectory) -> Result<[u8; 32]> {
    directory
        .coordination_identity()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: OWNERSHIP_CONTEXT,
            source,
        })
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .with_path(Path::new("."))?
        .join(path))
}
