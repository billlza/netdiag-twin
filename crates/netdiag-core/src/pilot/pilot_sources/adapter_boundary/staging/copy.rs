use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity, open_file};
use std::fs::{self, File, Metadata};
use std::io::{self, Seek, SeekFrom};
use std::path::Path;

mod digest;
use digest::{copy_and_hash_bounded, hash_bounded};

pub(super) fn copy_stable_source(
    source_file: &mut File,
    opened_identity: OpenedFileIdentity,
    opened_metadata: &Metadata,
    canonical: &Path,
    staged_file: &mut File,
    staged_path: &Path,
    after_source_copy: impl FnOnce(&Path),
) -> Result<()> {
    let copied = copy_and_hash_bounded(source_file, canonical, staged_file, staged_path)?;
    staged_file.sync_all().with_path(staged_path)?;

    after_source_copy(canonical);

    source_file.seek(SeekFrom::Start(0)).with_path(canonical)?;
    let verified = hash_bounded(source_file, canonical)?;
    let final_opened_metadata = source_file.metadata().with_path(canonical)?;
    let final_path_file = open_file(canonical)?;
    let opened_modified = opened_metadata.modified().with_path(canonical)?;
    let final_modified = final_opened_metadata.modified().with_path(canonical)?;
    if copied != verified
        || copied.bytes != opened_metadata.len()
        || opened_metadata.len() != final_opened_metadata.len()
        || opened_modified != final_modified
        || identity(&final_path_file, canonical)? != opened_identity
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter endpoint changed while it was being prepared: {}",
            canonical.display()
        )));
    }
    Ok(())
}

pub(super) fn clean_up_failed_stage(staged_path: &Path, error: NetdiagError) -> NetdiagError {
    match fs::remove_file(staged_path) {
        Ok(()) => error,
        Err(cleanup_error) if cleanup_error.kind() == io::ErrorKind::NotFound => error,
        Err(source) => error.with_secondary_failure(
            "adapter staging failed",
            "cleanup of the incomplete staged adapter also failed",
            NetdiagError::Io {
                path: staged_path.to_path_buf(),
                source,
            },
        ),
    }
}

#[cfg(test)]
mod tests;
