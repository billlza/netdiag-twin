use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity, open_file};
use std::fs::{self, File, Metadata};
use std::path::{Path, PathBuf};

mod file_type;
pub(in crate::evidence_bundle) use file_type::validate_regular_non_reparse;

#[derive(Debug)]
pub(super) struct StableFile {
    pub(super) canonical_path: PathBuf,
    pub(super) file: File,
    pub(super) opened_metadata: Metadata,
    pub(super) opened_identity: OpenedFileIdentity,
}

#[cfg(any(unix, windows))]
fn ensure_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_supported() -> Result<()> {
    Err(unsupported_platform())
}

#[cfg(not(any(unix, windows)))]
fn unsupported_platform() -> NetdiagError {
    NetdiagError::InvalidTrace(
        "evidence export is disabled on this platform because no no-follow source boundary is available"
            .to_string(),
    )
}

pub(super) fn open_stable_regular_file(path: &Path) -> Result<StableFile> {
    ensure_supported()?;
    open_stable_regular_file_with_hook(path, || {})
}

fn open_stable_regular_file_with_hook(
    path: &Path,
    before_open: impl FnOnce(),
) -> Result<StableFile> {
    ensure_supported()?;
    let metadata_before = fs::symlink_metadata(path).with_path(path)?;
    validate_regular_non_reparse(path, &metadata_before)?;
    let canonical_before = fs::canonicalize(path).with_path(path)?;

    before_open();
    let file = open_file(path)?;
    let opened_metadata = file.metadata().with_path(&canonical_before)?;
    validate_regular_non_reparse(path, &opened_metadata)?;
    let opened_identity = identity(&file, path)?;
    let current = open_file(path)?;
    let current_metadata = current.metadata().with_path(path)?;
    validate_regular_non_reparse(path, &current_metadata)?;
    let canonical_after = fs::canonicalize(path).with_path(path)?;
    let metadata_after = fs::symlink_metadata(path).with_path(path)?;
    if validate_regular_non_reparse(path, &metadata_after).is_err()
        || canonical_before != canonical_after
        || identity(&current, path)? != opened_identity
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "evidence bundle source changed while it was being opened: {}",
            path.display()
        )));
    }

    Ok(StableFile {
        canonical_path: canonical_before,
        file,
        opened_metadata,
        opened_identity,
    })
}

#[cfg(test)]
mod tests;
