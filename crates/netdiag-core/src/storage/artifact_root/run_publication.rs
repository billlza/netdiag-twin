use super::ownership::OwnedArtifactRoot;
use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;
use std::sync::Arc;

mod begin;
mod contract;
mod index;
mod io;
mod manifest;
mod recovery;

pub(crate) use begin::begin;
pub(crate) use contract::RunPublicationJournal;

pub(crate) fn reconcile_index(
    owned: &OwnedArtifactRoot,
    journal: &RunPublicationJournal,
) -> Result<()> {
    journal.validate(owned.root_id())?;
    index::upsert_at(owned.directory(), &journal.index_entry)
}

pub(crate) fn reconcile_nested_index(
    directory: &Arc<netdiag_platform::TrustedDirectory>,
    manifest: &RunManifest,
    status: String,
) -> Result<()> {
    index::upsert_at(directory, &contract::index_entry(manifest, status))
}

pub(crate) fn complete(owned: &OwnedArtifactRoot, journal: &RunPublicationJournal) -> Result<()> {
    let persisted = io::read(owned)?.ok_or_else(|| {
        NetdiagError::InvalidTrace("run publication journal disappeared".to_string())
    })?;
    if persisted != *journal {
        return Err(NetdiagError::InvalidTrace(
            "run publication journal changed before completion".to_string(),
        ));
    }
    io::remove(owned)
}

pub(super) fn recover(owned: &OwnedArtifactRoot) -> Result<()> {
    recovery::recover(owned)
}

pub(crate) fn abandon_not_published(
    owned: &OwnedArtifactRoot,
    journal: &RunPublicationJournal,
    primary: NetdiagError,
) -> NetdiagError {
    match complete(owned, journal) {
        Ok(()) => primary,
        Err(cleanup) => primary.with_secondary_failure(
            "run directory publication failed before commit",
            "run publication journal cleanup also failed",
            cleanup,
        ),
    }
}
