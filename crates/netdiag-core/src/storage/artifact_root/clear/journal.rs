use super::contract::{ClearJournal, MAX_CLEAR_JOURNAL_BYTES, journal_name};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, NoClobberDisposition, read_stable_regular_file_bounded_at,
    write_file_atomically_noclobber_or_existing_to_bound, write_file_atomically_to_bound,
};
use std::io::Write;

use super::super::ownership::OwnedArtifactRoot;

pub(super) fn read(owned: &OwnedArtifactRoot) -> Result<Option<ClearJournal>> {
    let target = target(owned)?;
    let Some(bytes) = read_stable_regular_file_bounded_at(&target, MAX_CLEAR_JOURNAL_BYTES)? else {
        return Ok(None);
    };
    let journal = crate::strict_json::from_slice::<ClearJournal>(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "run history clear journal is invalid at {}: {}",
            target.resolved_path().display(),
            crate::strict_json::error_summary(&source)
        ))
    })?;
    journal.validate(owned.root_id())?;
    Ok(Some(journal))
}

pub(super) fn create(owned: &OwnedArtifactRoot, journal: &ClearJournal) -> Result<()> {
    journal.validate(owned.root_id())?;
    let bytes = bytes(journal)?;
    let target = target(owned)?;
    let (disposition, ()) =
        write_file_atomically_noclobber_or_existing_to_bound(&target, "json", |file| {
            file.write_all(&bytes).with_path(target.resolved_path())
        })?;
    if disposition == NoClobberDisposition::Existing {
        return Err(NetdiagError::InvalidTrace(format!(
            "run history clear journal already exists: {}",
            target.resolved_path().display()
        )));
    }
    verify(owned, journal)
}

pub(super) fn replace(owned: &OwnedArtifactRoot, journal: &ClearJournal) -> Result<()> {
    journal.validate(owned.root_id())?;
    let bytes = bytes(journal)?;
    let target = target(owned)?;
    write_file_atomically_to_bound(&target, target.resolved_path(), "json", |file| {
        file.write_all(&bytes).with_path(target.resolved_path())
    })?;
    verify(owned, journal)
}

pub(super) fn remove(owned: &OwnedArtifactRoot) -> Result<()> {
    let target = target(owned)?;
    match netdiag_platform::remove_file_at(owned.directory(), target.target_name()) {
        Ok(()) => owned
            .directory()
            .as_file()
            .sync_all()
            .with_path(owned.directory().resolved_path()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NetdiagError::Io {
            path: target.resolved_path().to_path_buf(),
            source,
        }),
    }
}

fn verify(owned: &OwnedArtifactRoot, expected: &ClearJournal) -> Result<()> {
    let actual = read(owned)?.ok_or_else(|| {
        NetdiagError::InvalidTrace("run history clear journal disappeared".to_string())
    })?;
    if actual != *expected {
        return Err(NetdiagError::InvalidTrace(
            "run history clear journal changed during publication".to_string(),
        ));
    }
    Ok(())
}

fn target(owned: &OwnedArtifactRoot) -> Result<BoundAtomicFileTarget> {
    BoundAtomicFileTarget::from_directory(owned.directory().clone(), &journal_name(owned.root_id()))
}

fn bytes(journal: &ClearJournal) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() as u64 > MAX_CLEAR_JOURNAL_BYTES {
        return Err(NetdiagError::InvalidTrace(
            "run history clear journal exceeds its fixed byte budget".to_string(),
        ));
    }
    Ok(bytes)
}
