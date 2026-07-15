use super::super::ownership::OwnedArtifactRoot;
use super::contract::{JOURNAL_FILE_NAME, MAX_JOURNAL_BYTES, RunPublicationJournal};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, NoClobberDisposition, read_stable_regular_file_bounded_at,
    write_file_atomically_noclobber_or_existing_to_bound,
};
use std::ffi::OsStr;
use std::io::Write;

pub(super) fn read(owned: &OwnedArtifactRoot) -> Result<Option<RunPublicationJournal>> {
    let target = target(owned)?;
    let Some(bytes) = read_stable_regular_file_bounded_at(&target, MAX_JOURNAL_BYTES)? else {
        return Ok(None);
    };
    let journal =
        crate::strict_json::from_slice::<RunPublicationJournal>(&bytes).map_err(|source| {
            NetdiagError::InvalidTrace(format!(
                "run publication journal is invalid at {}: {}",
                target.resolved_path().display(),
                crate::strict_json::error_summary(&source)
            ))
        })?;
    journal.validate(owned.root_id())?;
    Ok(Some(journal))
}

pub(super) fn create(owned: &OwnedArtifactRoot, journal: &RunPublicationJournal) -> Result<()> {
    journal.validate(owned.root_id())?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(NetdiagError::InvalidTrace(
            "run publication journal exceeds its fixed byte budget".to_string(),
        ));
    }
    let target = target(owned)?;
    let (disposition, ()) =
        write_file_atomically_noclobber_or_existing_to_bound(&target, "json", |file| {
            file.write_all(&bytes).with_path(target.resolved_path())
        })?;
    if disposition == NoClobberDisposition::Existing {
        return Err(NetdiagError::InvalidTrace(format!(
            "run publication journal already exists: {}",
            target.resolved_path().display()
        )));
    }
    let persisted = read(owned)?.ok_or_else(|| {
        NetdiagError::InvalidTrace("run publication journal disappeared".to_string())
    })?;
    if persisted != *journal {
        return Err(NetdiagError::InvalidTrace(
            "run publication journal changed during publication".to_string(),
        ));
    }
    Ok(())
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

fn target(owned: &OwnedArtifactRoot) -> Result<BoundAtomicFileTarget> {
    BoundAtomicFileTarget::from_directory(owned.directory().clone(), OsStr::new(JOURNAL_FILE_NAME))
}
