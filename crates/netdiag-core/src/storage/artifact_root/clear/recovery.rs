use super::contract::{
    ClearJournal, ClearPhase, DirectoryRecord, FileRecord, index_tombstone_name,
    runs_tombstone_name,
};
use super::journal;
use super::{CapturedDirectory, RUN_INDEX_NAME, RUNS_NAME, changed, directory_publication_error};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::typed_json::MAX_RUN_INDEX_BYTES;
use crate::storage::{
    BoundAtomicFileTarget, PathStatus, path_status, read_stable_regular_file_bounded_at,
};
use std::ffi::OsStr;

use super::super::ownership::OwnedArtifactRoot;

struct DirectorySlots {
    original: Option<CapturedDirectory>,
    tombstone: Option<CapturedDirectory>,
}

#[derive(Clone, Copy)]
struct FileSlots {
    original: bool,
    tombstone: bool,
}

pub(super) fn recover(owned: &OwnedArtifactRoot) -> Result<()> {
    let Some(current) = journal::read(owned)? else {
        reject_orphaned_tombstones(owned)?;
        return Ok(());
    };
    let runs_name = runs_tombstone_name(owned.root_id());
    let index_name = index_tombstone_name(owned.root_id());
    let runs = directory_slots(owned, current.runs.as_ref(), &runs_name)?;
    let index = file_slots(owned, current.index.as_ref(), &index_name)?;
    match current.phase {
        ClearPhase::Prepared => recover_prepared(owned, &current, runs, index),
        ClearPhase::Committed => recover_committed(owned, &current, runs, index),
    }
}

fn recover_prepared(
    owned: &OwnedArtifactRoot,
    current: &ClearJournal,
    runs: DirectorySlots,
    index: FileSlots,
) -> Result<()> {
    let runs_original = slot_is_original(current.runs.is_some(), &runs);
    let runs_staged = slot_is_staged(current.runs.is_some(), &runs);
    let index_original = file_is_original(current.index.is_some(), index);
    let index_staged = file_is_staged(current.index.is_some(), index);

    if runs_original && index_original {
        return journal::remove(owned);
    }
    if runs_staged && index_staged {
        let committed = current.committed();
        journal::replace(owned, &committed)?;
        return cleanup_committed(owned, &committed, runs, index);
    }
    if runs_staged && index_original {
        rollback_runs(owned, current, runs)?;
        return journal::remove(owned);
    }
    Err(NetdiagError::InvalidTrace(format!(
        "run history clear journal has an impossible prepared layout at {}",
        owned.directory().resolved_path().display()
    )))
}

fn recover_committed(
    owned: &OwnedArtifactRoot,
    current: &ClearJournal,
    runs: DirectorySlots,
    index: FileSlots,
) -> Result<()> {
    if runs.original.is_some() || index.original {
        return Err(NetdiagError::InvalidTrace(format!(
            "committed run history clear transaction has replacement data at {}",
            owned.directory().resolved_path().display()
        )));
    }
    cleanup_committed(owned, current, runs, index)
}

fn cleanup_committed(
    owned: &OwnedArtifactRoot,
    current: &ClearJournal,
    runs: DirectorySlots,
    index: FileSlots,
) -> Result<()> {
    if current.index.is_none() && index.tombstone {
        return Err(changed(
            &owned
                .directory()
                .resolved_path()
                .join(index_tombstone_name(owned.root_id())),
            "unexpected run index tombstone",
        ));
    }
    if index.tombstone {
        remove_file(owned, &index_tombstone_name(owned.root_id()))?;
    }
    if let Some(directory) = runs.tombstone {
        let name = runs_tombstone_name(owned.root_id());
        netdiag_platform::remove_directory_tree_at(owned.directory(), &directory.directory, &name)
            .map_err(|source| NetdiagError::Io {
                path: owned.directory().resolved_path().join(&name),
                source,
            })?;
        sync_root(owned)?;
    } else if current.runs.is_none() {
        // The absence is part of the journaled layout.
    }
    journal::remove(owned)
}

fn rollback_runs(
    owned: &OwnedArtifactRoot,
    current: &ClearJournal,
    mut runs: DirectorySlots,
) -> Result<()> {
    let expected = current.runs.as_ref().ok_or_else(|| {
        NetdiagError::InvalidTrace("clear recovery attempted an unjournaled rollback".to_string())
    })?;
    let tombstone = runs.tombstone.take().ok_or_else(|| {
        NetdiagError::InvalidTrace("clear recovery lost the runs tombstone".to_string())
    })?;
    let tombstone_name = runs_tombstone_name(owned.root_id());
    netdiag_platform::publish_directory_noclobber_at(
        owned.directory(),
        &tombstone.directory,
        &tombstone_name,
        OsStr::new(RUNS_NAME),
    )
    .map_err(|source| directory_publication_error(&tombstone.path, source))?;
    sync_root(owned)?;
    let restored = open_directory(owned, OsStr::new(RUNS_NAME), expected)?.ok_or_else(|| {
        NetdiagError::InvalidTrace("restored runs directory disappeared".to_string())
    })?;
    if restored.identity != expected.coordination_identity {
        return Err(changed(&restored.path, "restored runs directory"));
    }
    Ok(())
}

fn directory_slots(
    owned: &OwnedArtifactRoot,
    expected: Option<&DirectoryRecord>,
    tombstone_name: &OsStr,
) -> Result<DirectorySlots> {
    let original = expected
        .map(|record| open_directory(owned, OsStr::new(RUNS_NAME), record))
        .transpose()?
        .flatten();
    let tombstone = expected
        .map(|record| open_directory(owned, tombstone_name, record))
        .transpose()?
        .flatten();
    if expected.is_none() {
        ensure_missing(owned, OsStr::new(RUNS_NAME), "unjournaled runs directory")?;
        ensure_missing(owned, tombstone_name, "unjournaled runs tombstone")?;
    }
    if original.is_some() && tombstone.is_some() {
        return Err(NetdiagError::InvalidTrace(
            "run history clear recovery found both original and tombstoned runs directories"
                .to_string(),
        ));
    }
    Ok(DirectorySlots {
        original,
        tombstone,
    })
}

fn file_slots(
    owned: &OwnedArtifactRoot,
    expected: Option<&FileRecord>,
    tombstone_name: &OsStr,
) -> Result<FileSlots> {
    let original = expected
        .map(|record| file_matches(owned, OsStr::new(RUN_INDEX_NAME), record))
        .transpose()?
        .unwrap_or(false);
    let tombstone = expected
        .map(|record| file_matches(owned, tombstone_name, record))
        .transpose()?
        .unwrap_or(false);
    if expected.is_none() {
        ensure_missing(owned, OsStr::new(RUN_INDEX_NAME), "unjournaled run index")?;
        ensure_missing(owned, tombstone_name, "unjournaled run index tombstone")?;
    }
    if original && tombstone {
        return Err(NetdiagError::InvalidTrace(
            "run history clear recovery found both original and tombstoned run indexes".to_string(),
        ));
    }
    Ok(FileSlots {
        original,
        tombstone,
    })
}

fn open_directory(
    owned: &OwnedArtifactRoot,
    name: &OsStr,
    expected: &DirectoryRecord,
) -> Result<Option<CapturedDirectory>> {
    let path = owned.directory().resolved_path().join(name);
    match path_status(&path)? {
        PathStatus::Missing => Ok(None),
        PathStatus::Directory => {
            let directory =
                netdiag_platform::open_trusted_directory_chain(&path).map_err(|source| {
                    NetdiagError::FilesystemTrust {
                        context: "run history clear recovery",
                        source,
                    }
                })?;
            let identity = directory.coordination_identity().map_err(|source| {
                NetdiagError::FilesystemTrust {
                    context: "run history clear recovery",
                    source,
                }
            })?;
            if identity != expected.coordination_identity {
                return Err(changed(&path, "journaled runs directory"));
            }
            Ok(Some(CapturedDirectory {
                directory,
                identity,
                path,
            }))
        }
        _ => Err(changed(&path, "journaled runs directory")),
    }
}

fn file_matches(owned: &OwnedArtifactRoot, name: &OsStr, expected: &FileRecord) -> Result<bool> {
    let target = BoundAtomicFileTarget::from_directory(owned.directory().clone(), name)?;
    let Some(bytes) = read_stable_regular_file_bounded_at(&target, MAX_RUN_INDEX_BYTES)? else {
        return Ok(false);
    };
    if !expected.matches(&bytes) {
        return Err(changed(target.resolved_path(), "journaled run index"));
    }
    Ok(true)
}

fn reject_orphaned_tombstones(owned: &OwnedArtifactRoot) -> Result<()> {
    for (name, description) in [
        (runs_tombstone_name(owned.root_id()), "runs tombstone"),
        (index_tombstone_name(owned.root_id()), "run index tombstone"),
    ] {
        let path = owned.directory().resolved_path().join(&name);
        if path_status(&path)? != PathStatus::Missing {
            return Err(NetdiagError::InvalidTrace(format!(
                "{description} exists without its recovery journal: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn ensure_missing(owned: &OwnedArtifactRoot, name: &OsStr, description: &str) -> Result<()> {
    let path = owned.directory().resolved_path().join(name);
    if path_status(&path)? == PathStatus::Missing {
        Ok(())
    } else {
        Err(changed(&path, description))
    }
}

fn remove_file(owned: &OwnedArtifactRoot, name: &OsStr) -> Result<()> {
    netdiag_platform::remove_file_at(owned.directory(), name).map_err(|source| {
        NetdiagError::Io {
            path: owned.directory().resolved_path().join(name),
            source,
        }
    })?;
    sync_root(owned)
}

fn sync_root(owned: &OwnedArtifactRoot) -> Result<()> {
    owned
        .directory()
        .as_file()
        .sync_all()
        .with_path(owned.directory().resolved_path())
}

fn slot_is_original(expected: bool, slots: &DirectorySlots) -> bool {
    if expected {
        slots.original.is_some() && slots.tombstone.is_none()
    } else {
        slots.original.is_none() && slots.tombstone.is_none()
    }
}

fn slot_is_staged(expected: bool, slots: &DirectorySlots) -> bool {
    if expected {
        slots.original.is_none() && slots.tombstone.is_some()
    } else {
        slots.original.is_none() && slots.tombstone.is_none()
    }
}

fn file_is_original(expected: bool, slots: FileSlots) -> bool {
    if expected {
        slots.original && !slots.tombstone
    } else {
        !slots.original && !slots.tombstone
    }
}

fn file_is_staged(expected: bool, slots: FileSlots) -> bool {
    if expected {
        !slots.original && slots.tombstone
    } else {
        !slots.original && !slots.tombstone
    }
}
