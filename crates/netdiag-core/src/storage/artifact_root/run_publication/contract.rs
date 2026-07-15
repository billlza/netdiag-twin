use crate::error::{NetdiagError, Result};
use crate::models::{RunIndexEntry, RunManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) const JOURNAL_FILE_NAME: &str = ".netdiag-run-publication.json";
pub(super) const JOURNAL_SCHEMA_VERSION: u32 = 1;
pub(super) const MAX_JOURNAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunPublicationJournal {
    schema_version: u32,
    pub(super) root_id: String,
    pub(super) run_id: String,
    pub(super) staging_name: String,
    pub(super) directory_identity: [u8; 32],
    pub(super) manifest_sha256: String,
    pub(super) index_entry: RunIndexEntry,
}

impl RunPublicationJournal {
    pub(super) fn new(
        root_id: &str,
        staging_name: String,
        directory_identity: [u8; 32],
        manifest_bytes: &[u8],
        manifest: &RunManifest,
        status: String,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            root_id: root_id.to_string(),
            run_id: manifest.run_id.clone(),
            staging_name,
            directory_identity,
            manifest_sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
            index_entry: index_entry(manifest, status),
        }
    }

    pub(super) fn validate(&self, expected_root_id: &str) -> Result<()> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION || self.root_id != expected_root_id {
            return Err(NetdiagError::InvalidTrace(
                "run publication journal does not match the owned artifact root".to_string(),
            ));
        }
        crate::identifiers::validate_portable_id("journaled run id", &self.run_id)?;
        if self.index_entry.run_id != self.run_id
            || Path::new(&self.index_entry.run_dir) != Path::new("runs").join(&self.run_id)
        {
            return Err(NetdiagError::InvalidTrace(
                "run publication journal contains an inconsistent index entry".to_string(),
            ));
        }
        validate_staging_name(&self.staging_name)?;
        if self.manifest_sha256.len() != 64
            || !self
                .manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NetdiagError::InvalidTrace(
                "run publication journal contains an invalid manifest digest".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_manifest(&self, bytes: &[u8]) -> Result<RunManifest> {
        if self.manifest_sha256 != format!("{:x}", Sha256::digest(bytes)) {
            return Err(NetdiagError::InvalidTrace(
                "journaled run manifest content changed".to_string(),
            ));
        }
        let manifest = super::manifest::parse(bytes, "journaled run manifest")?;
        if manifest.run_id != self.run_id
            || manifest.sample != self.index_entry.sample
            || manifest.created_at != self.index_entry.created_at
        {
            return Err(NetdiagError::InvalidTrace(
                "journaled run manifest does not match its index entry".to_string(),
            ));
        }
        Ok(manifest)
    }
}

pub(super) fn index_entry(manifest: &RunManifest, status: String) -> RunIndexEntry {
    RunIndexEntry {
        run_id: manifest.run_id.clone(),
        sample: manifest.sample.clone(),
        created_at: manifest.created_at,
        status,
        run_dir: Path::new("runs")
            .join(&manifest.run_id)
            .display()
            .to_string(),
    }
}

fn validate_staging_name(name: &str) -> Result<()> {
    let Some(uuid) = name
        .strip_prefix(".staged-")
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return Err(invalid_staging_name(name));
    };
    if uuid.len() != 32
        || !uuid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_staging_name(name));
    }
    Ok(())
}

fn invalid_staging_name(name: &str) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "run publication journal contains an invalid staging name: {name:?}"
    ))
}
