use super::{RunPublicationJournal, io};
use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;
use crate::storage::typed_json::MAX_RUN_MANIFEST_BYTES;
use crate::storage::{
    OwnedArtifactRoot, StagedAtomicDirectory, read_stable_regular_file_bounded_at,
};

pub(crate) fn begin(
    owned: &OwnedArtifactRoot,
    staged: &StagedAtomicDirectory,
    manifest: &RunManifest,
    status: String,
) -> Result<RunPublicationJournal> {
    let expected_parent = owned.directory().resolved_path().join("runs");
    if staged.parent_path() != expected_parent
        || staged.target_name() != std::ffi::OsStr::new(&manifest.run_id)
    {
        return Err(NetdiagError::InvalidTrace(
            "run publication is not bound to the authorized artifact root".to_string(),
        ));
    }
    let staging_name = staged
        .staging_name()
        .to_str()
        .ok_or_else(|| {
            NetdiagError::InvalidTrace("run staging name is not valid UTF-8".to_string())
        })?
        .to_string();
    let manifest_target = staged.target("manifest.json")?;
    let manifest_bytes =
        read_stable_regular_file_bounded_at(&manifest_target, MAX_RUN_MANIFEST_BYTES)?.ok_or_else(
            || NetdiagError::InvalidTrace("staged run manifest is missing".to_string()),
        )?;
    let parsed = super::manifest::parse(&manifest_bytes, "staged run manifest")?;
    if parsed != *manifest {
        return Err(NetdiagError::InvalidTrace(
            "staged run manifest changed before publication".to_string(),
        ));
    }
    let journal = RunPublicationJournal::new(
        owned.root_id(),
        staging_name,
        staged.coordination_identity()?,
        &manifest_bytes,
        manifest,
        status,
    );
    io::create(owned, &journal)?;
    Ok(journal)
}
