use crate::error::{NetdiagError, Result};
use std::fs::Metadata;
use std::path::Path;

pub(in crate::evidence_bundle) fn validate_regular_non_reparse(
    path: &Path,
    metadata: &Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() || is_windows_reparse(metadata) {
        return Err(NetdiagError::InvalidTrace(format!(
            "evidence bundle source must be a non-reparse regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_metadata: &Metadata) -> bool {
    false
}
