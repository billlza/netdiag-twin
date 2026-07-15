use super::stable_file::open_stable_regular_file;
use super::{CanonicalRoots, SourceFile};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::path_status;
use std::fs;
use std::path::{Path, PathBuf};

pub(in crate::evidence_bundle) fn open_override_source(
    staged_path: &Path,
    reported_path: &Path,
    allowed_roots: &CanonicalRoots,
) -> Result<SourceFile> {
    let stable = open_stable_regular_file(staged_path)?;
    let canonical_staged = stable.canonical_path;
    if !allowed_roots.contains(&canonical_staged) {
        return Err(NetdiagError::InvalidTrace(format!(
            "staged evidence source is outside the allowed run/lab roots: {}",
            staged_path.display()
        )));
    }
    let reported_path = canonical_logical_path(reported_path)?;
    if !allowed_roots.contains(&reported_path) {
        return Err(NetdiagError::InvalidTrace(format!(
            "reported evidence source is outside the allowed run/lab roots: {}",
            reported_path.display()
        )));
    }
    Ok(SourceFile {
        canonical_path: canonical_staged,
        reported_path,
        file: stable.file,
        opened_metadata: stable.opened_metadata,
        opened_identity: stable.opened_identity,
    })
}

pub(in crate::evidence_bundle) fn canonical_logical_path(path: &Path) -> Result<PathBuf> {
    if path_status(path)?.exists() {
        return fs::canonicalize(path).with_path(path);
    }
    let parent = path.parent().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!("evidence source has no parent: {}", path.display()))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "evidence source has no file name: {}",
            path.display()
        ))
    })?;
    Ok(fs::canonicalize(parent).with_path(parent)?.join(file_name))
}
