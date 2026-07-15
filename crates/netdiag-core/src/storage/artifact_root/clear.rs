use super::ownership::{OwnedArtifactRoot, with_owned_artifact_root};
use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity};
use crate::storage::typed_json::MAX_RUN_INDEX_BYTES;
use crate::storage::{
    BoundAtomicFileTarget, PathStatus, path_status, read_stable_regular_file_bounded_at,
};
use contract::{
    ClearJournal, DirectoryRecord, FileRecord, index_tombstone_name, runs_tombstone_name,
};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const RUNS_NAME: &str = "runs";
const RUN_INDEX_NAME: &str = "run_index.json";

mod contract;
mod journal;
mod recovery;

struct CapturedDirectory {
    directory: netdiag_platform::TrustedDirectory,
    identity: [u8; 32],
    path: PathBuf,
}

struct CapturedFile {
    target: BoundAtomicFileTarget,
    identity: OpenedFileIdentity,
    record: FileRecord,
}

struct ClearPlan {
    runs: Option<CapturedDirectory>,
    index: Option<CapturedFile>,
    runs_tombstone: OsString,
    index_tombstone: OsString,
}

struct IndexTombstoneFailure {
    error: Box<NetdiagError>,
    original_retained: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ClearCrashPoint {
    JournalPrepared,
    RunsTombstoned,
    IndexTombstoned,
    JournalCommitted,
    IndexDeleted,
    RunsDeleted,
}

pub fn clear_run_history(artifact_root: impl AsRef<Path>) -> Result<()> {
    clear_run_history_with_execution_hooks(artifact_root.as_ref(), || Ok(()), || Ok(()), |_| Ok(()))
}

pub(super) fn recover_interrupted_clear(owned: &OwnedArtifactRoot) -> Result<()> {
    recovery::recover(owned)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn clear_run_history_with_hooks(
    artifact_root: &Path,
    after_capture: impl FnOnce() -> Result<()>,
    after_runs_tombstoned: impl FnOnce() -> Result<()>,
) -> Result<()> {
    clear_run_history_with_execution_hooks(
        artifact_root,
        after_capture,
        after_runs_tombstoned,
        |_| Ok(()),
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn clear_run_history_with_crash(
    artifact_root: &Path,
    crash_at: ClearCrashPoint,
) -> Result<()> {
    clear_run_history_with_execution_hooks(
        artifact_root,
        || Ok(()),
        || Ok(()),
        |point| {
            if point == crash_at {
                Err(NetdiagError::InvalidTrace(
                    "injected run history clear crash".to_string(),
                ))
            } else {
                Ok(())
            }
        },
    )
}

fn clear_run_history_with_execution_hooks(
    artifact_root: &Path,
    after_capture: impl FnOnce() -> Result<()>,
    after_runs_tombstoned: impl FnOnce() -> Result<()>,
    crash_hook: impl FnMut(ClearCrashPoint) -> Result<()>,
) -> Result<()> {
    with_owned_artifact_root(artifact_root, |owned| {
        let plan = ClearPlan::capture(owned)?;
        after_capture()?;
        plan.validate(owned)?;
        plan.execute(owned, after_runs_tombstoned, crash_hook)
    })
}

impl ClearPlan {
    fn capture(owned: &OwnedArtifactRoot) -> Result<Self> {
        let runs_tombstone = runs_tombstone_name(owned.root_id());
        let index_tombstone = index_tombstone_name(owned.root_id());
        ensure_missing(owned, &runs_tombstone, "runs tombstone")?;
        ensure_missing(owned, &index_tombstone, "run index tombstone")?;
        Ok(Self {
            runs: capture_runs(owned)?,
            index: capture_index(owned)?,
            runs_tombstone,
            index_tombstone,
        })
    }

    fn validate(&self, owned: &OwnedArtifactRoot) -> Result<()> {
        owned.validate()?;
        ensure_missing(owned, &self.runs_tombstone, "runs tombstone")?;
        ensure_missing(owned, &self.index_tombstone, "run index tombstone")?;
        validate_runs_capture(owned, self.runs.as_ref())?;
        validate_index_capture(owned, self.index.as_ref())?;
        owned.validate()
    }

    fn execute(
        self,
        owned: &OwnedArtifactRoot,
        after_runs_tombstoned: impl FnOnce() -> Result<()>,
        mut crash_hook: impl FnMut(ClearCrashPoint) -> Result<()>,
    ) -> Result<()> {
        if self.runs.is_some() {
            netdiag_platform::ensure_directory_noclobber_publication_supported().map_err(
                |source| {
                    directory_publication_error(
                        owned.directory().resolved_path().join(RUNS_NAME),
                        source,
                    )
                },
            )?;
        }
        let prepared = self.journal(owned);
        journal::create(owned, &prepared)?;
        crash_hook(ClearCrashPoint::JournalPrepared)?;
        let runs_tombstoned = self.tombstone_runs(owned)?;
        if let Err(error) = after_runs_tombstoned() {
            let error = self.rollback_runs(owned, runs_tombstoned, error);
            return Err(remove_journal_after_rollback(owned, error));
        }
        crash_hook(ClearCrashPoint::RunsTombstoned)?;
        if let Err(failure) = self.tombstone_index(owned) {
            if failure.original_retained {
                let error = self.rollback_runs(owned, runs_tombstoned, *failure.error);
                return Err(remove_journal_after_rollback(owned, error));
            }
            return Err(*failure.error);
        }
        crash_hook(ClearCrashPoint::IndexTombstoned)?;
        self.validate_committed(owned)?;
        let committed = prepared.committed();
        journal::replace(owned, &committed)?;
        crash_hook(ClearCrashPoint::JournalCommitted)?;
        owned
            .directory()
            .as_file()
            .sync_all()
            .with_path(owned.directory().resolved_path())?;
        self.delete_tombstones(owned, &mut crash_hook)?;
        journal::remove(owned)
    }

    fn journal(&self, owned: &OwnedArtifactRoot) -> ClearJournal {
        ClearJournal::prepared(
            owned.root_id(),
            self.runs.as_ref().map(|runs| DirectoryRecord {
                coordination_identity: runs.identity,
            }),
            self.index.as_ref().map(|index| index.record.clone()),
        )
    }

    fn tombstone_runs(&self, owned: &OwnedArtifactRoot) -> Result<bool> {
        let Some(runs) = &self.runs else {
            return Ok(false);
        };
        netdiag_platform::publish_directory_noclobber_at(
            owned.directory(),
            &runs.directory,
            OsStr::new(RUNS_NAME),
            &self.runs_tombstone,
        )
        .map_err(|source| directory_publication_error(&runs.path, source))?;
        Ok(true)
    }

    fn tombstone_index(
        &self,
        owned: &OwnedArtifactRoot,
    ) -> std::result::Result<(), IndexTombstoneFailure> {
        let Some(index) = &self.index else {
            return Ok(());
        };
        match netdiag_platform::publish_file_noclobber_at(
            owned.directory(),
            index.target.target_name(),
            &self.index_tombstone,
        ) {
            Ok(()) => validate_file_identity_at(
                owned,
                &self.index_tombstone,
                index.identity,
                "run index tombstone",
            )
            .map_err(|error| IndexTombstoneFailure {
                error: Box::new(error),
                original_retained: false,
            }),
            Err(source) => {
                let original_retained =
                    source.state() == netdiag_platform::AtomicPublicationState::NotPublished;
                let error = file_publication_error(index.target.resolved_path(), source);
                Err(IndexTombstoneFailure {
                    error: Box::new(error),
                    original_retained,
                })
            }
        }
    }

    fn rollback_runs(
        &self,
        owned: &OwnedArtifactRoot,
        runs_tombstoned: bool,
        primary: NetdiagError,
    ) -> NetdiagError {
        if !runs_tombstoned {
            return primary;
        }
        let runs = self
            .runs
            .as_ref()
            .expect("a tombstoned runs directory retains its captured handle");
        match netdiag_platform::publish_directory_noclobber_at(
            owned.directory(),
            &runs.directory,
            &self.runs_tombstone,
            OsStr::new(RUNS_NAME),
        ) {
            Ok(()) => primary,
            Err(source) => primary.with_secondary_failure(
                "run history clear transaction failed",
                "runs directory rollback also failed",
                directory_publication_error(&runs.path, source),
            ),
        }
    }

    fn validate_committed(&self, owned: &OwnedArtifactRoot) -> Result<()> {
        owned.validate()?;
        ensure_original_missing(owned, RUNS_NAME, self.runs.is_some(), "runs directory")?;
        ensure_original_missing(owned, RUN_INDEX_NAME, self.index.is_some(), "run index")?;
        if let Some(runs) = &self.runs {
            validate_directory_identity_at(
                owned,
                &self.runs_tombstone,
                runs.identity,
                "run history tombstone",
            )?;
        }
        if let Some(index) = &self.index {
            validate_captured_file_at(owned, &self.index_tombstone, index, "run index tombstone")?;
        }
        owned.validate()
    }

    fn delete_tombstones(
        &self,
        owned: &OwnedArtifactRoot,
        crash_hook: &mut impl FnMut(ClearCrashPoint) -> Result<()>,
    ) -> Result<()> {
        if let Some(index) = &self.index {
            validate_captured_file_at(owned, &self.index_tombstone, index, "run index tombstone")?;
            netdiag_platform::remove_file_at(owned.directory(), &self.index_tombstone).map_err(
                |source| NetdiagError::Io {
                    path: owned
                        .directory()
                        .resolved_path()
                        .join(&self.index_tombstone),
                    source,
                },
            )?;
            owned
                .directory()
                .as_file()
                .sync_all()
                .with_path(owned.directory().resolved_path())?;
        }
        crash_hook(ClearCrashPoint::IndexDeleted)?;
        if let Some(runs) = &self.runs {
            netdiag_platform::remove_directory_tree_at(
                owned.directory(),
                &runs.directory,
                &self.runs_tombstone,
            )
            .map_err(|source| NetdiagError::Io {
                path: owned.directory().resolved_path().join(&self.runs_tombstone),
                source,
            })?;
            owned
                .directory()
                .as_file()
                .sync_all()
                .with_path(owned.directory().resolved_path())?;
        }
        crash_hook(ClearCrashPoint::RunsDeleted)?;
        owned.validate()
    }
}

fn capture_runs(owned: &OwnedArtifactRoot) -> Result<Option<CapturedDirectory>> {
    let path = owned.directory().resolved_path().join(RUNS_NAME);
    match path_status(&path)? {
        PathStatus::Missing => Ok(None),
        PathStatus::Directory => {
            let directory =
                netdiag_platform::open_trusted_directory_chain(&path).map_err(|source| {
                    NetdiagError::FilesystemTrust {
                        context: "run history directory",
                        source,
                    }
                })?;
            let identity = directory.coordination_identity().map_err(|source| {
                NetdiagError::FilesystemTrust {
                    context: "run history directory",
                    source,
                }
            })?;
            Ok(Some(CapturedDirectory {
                directory,
                identity,
                path,
            }))
        }
        _ => Err(NetdiagError::InvalidTrace(format!(
            "run history path is not a regular directory: {}",
            path.display()
        ))),
    }
}

fn capture_index(owned: &OwnedArtifactRoot) -> Result<Option<CapturedFile>> {
    let target = BoundAtomicFileTarget::from_directory(
        Arc::clone(owned.directory()),
        OsStr::new(RUN_INDEX_NAME),
    )?;
    let Some(bytes) = read_stable_regular_file_bounded_at(&target, MAX_RUN_INDEX_BYTES)? else {
        return Ok(None);
    };
    let file = open_file_at(&target, "run index")?;
    let identity = identity(&file, target.resolved_path())?;
    let captured = CapturedFile {
        target,
        identity,
        record: FileRecord::from_bytes(&bytes),
    };
    validate_captured_file_at(owned, OsStr::new(RUN_INDEX_NAME), &captured, "run index")?;
    Ok(Some(captured))
}

fn remove_journal_after_rollback(owned: &OwnedArtifactRoot, primary: NetdiagError) -> NetdiagError {
    match journal::remove(owned) {
        Ok(()) => primary,
        Err(cleanup) => primary.with_secondary_failure(
            "run history clear transaction failed",
            "clear journal cleanup also failed",
            cleanup,
        ),
    }
}

fn validate_runs_capture(
    owned: &OwnedArtifactRoot,
    captured: Option<&CapturedDirectory>,
) -> Result<()> {
    let path = owned.directory().resolved_path().join(RUNS_NAME);
    match captured {
        Some(captured) => {
            captured
                .directory
                .validate_identity()
                .map_err(|source| NetdiagError::FilesystemTrust {
                    context: "run history directory",
                    source,
                })
        }
        None if path_status(&path)? == PathStatus::Missing => Ok(()),
        None => Err(changed(&path, "runs directory")),
    }
}

fn validate_index_capture(
    owned: &OwnedArtifactRoot,
    captured: Option<&CapturedFile>,
) -> Result<()> {
    let path = owned.directory().resolved_path().join(RUN_INDEX_NAME);
    match captured {
        Some(captured) => {
            validate_captured_file_at(owned, OsStr::new(RUN_INDEX_NAME), captured, "run index")
        }
        None if path_status(&path)? == PathStatus::Missing => Ok(()),
        None => Err(changed(&path, "run index")),
    }
}

fn validate_file_identity_at(
    owned: &OwnedArtifactRoot,
    name: &OsStr,
    expected: OpenedFileIdentity,
    description: &str,
) -> Result<()> {
    let target = BoundAtomicFileTarget::from_directory(Arc::clone(owned.directory()), name)?;
    let file = open_file_at(&target, description)?;
    if identity(&file, target.resolved_path())? != expected {
        return Err(changed(target.resolved_path(), description));
    }
    Ok(())
}

fn validate_captured_file_at(
    owned: &OwnedArtifactRoot,
    name: &OsStr,
    captured: &CapturedFile,
    description: &str,
) -> Result<()> {
    validate_file_identity_at(owned, name, captured.identity, description)?;
    let target = BoundAtomicFileTarget::from_directory(Arc::clone(owned.directory()), name)?;
    let bytes = read_stable_regular_file_bounded_at(&target, MAX_RUN_INDEX_BYTES)?
        .ok_or_else(|| changed(target.resolved_path(), description))?;
    if !captured.record.matches(&bytes) {
        return Err(changed(target.resolved_path(), description));
    }
    validate_file_identity_at(owned, name, captured.identity, description)
}

fn validate_directory_identity_at(
    owned: &OwnedArtifactRoot,
    name: &OsStr,
    expected: [u8; 32],
    description: &str,
) -> Result<()> {
    let path = owned.directory().resolved_path().join(name);
    let directory = netdiag_platform::open_trusted_directory_chain(&path).map_err(|source| {
        NetdiagError::FilesystemTrust {
            context: "run history tombstone",
            source,
        }
    })?;
    let current =
        directory
            .coordination_identity()
            .map_err(|source| NetdiagError::FilesystemTrust {
                context: "run history tombstone",
                source,
            })?;
    if current != expected {
        return Err(changed(&path, description));
    }
    Ok(())
}

fn open_file_at(target: &BoundAtomicFileTarget, description: &str) -> Result<File> {
    netdiag_platform::open_file_read_only_at(target.directory(), target.target_name()).map_err(
        |source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                return changed(target.resolved_path(), description);
            }
            NetdiagError::Io {
                path: target.resolved_path().to_path_buf(),
                source,
            }
        },
    )
}

fn ensure_missing(owned: &OwnedArtifactRoot, name: &OsStr, description: &str) -> Result<()> {
    let path = owned.directory().resolved_path().join(name);
    if path_status(&path)? == PathStatus::Missing {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "{description} already exists; run history cleanup requires explicit recovery before retrying: {}",
        path.display()
    )))
}

fn ensure_original_missing(
    owned: &OwnedArtifactRoot,
    name: &str,
    was_present: bool,
    description: &str,
) -> Result<()> {
    let path = owned.directory().resolved_path().join(name);
    let status = path_status(&path)?;
    if status == PathStatus::Missing {
        return Ok(());
    }
    let detail = if was_present {
        "was replaced after being tombstoned"
    } else {
        "appeared during the clear transaction"
    };
    Err(NetdiagError::InvalidTrace(format!(
        "{description} {detail}: {}",
        path.display()
    )))
}

fn changed(path: &Path, description: &str) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "{description} changed while run history cleanup was in progress: {}",
        path.display()
    ))
}

fn directory_publication_error(
    path: impl Into<PathBuf>,
    source: netdiag_platform::AtomicPublicationError,
) -> NetdiagError {
    NetdiagError::PlatformAtomicPublication {
        path: path.into(),
        source,
    }
}

fn file_publication_error(
    path: &Path,
    source: netdiag_platform::AtomicPublicationError,
) -> NetdiagError {
    NetdiagError::PlatformAtomicPublication {
        path: path.to_path_buf(),
        source,
    }
}
