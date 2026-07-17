use crate::error::{NetdiagError, Result};
use std::fs::Metadata;
use std::path::Path;

pub(super) fn validate_regular(path: &Path, metadata: &Metadata, max_bytes: u64) -> Result<()> {
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(metadata)
        || !metadata.is_file()
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "bounded read source is not a regular file or is a symlink/reparse point (regular, non-symlink file required): {}",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(oversized(path, max_bytes));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(super) fn metadata_is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

pub(super) fn changed(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "regular file changed while it was being read: {}",
        path.display()
    ))
}

pub(super) fn oversized(path: &Path, max_bytes: u64) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "regular file exceeds the {max_bytes}-byte read limit: {}",
        path.display()
    ))
}
