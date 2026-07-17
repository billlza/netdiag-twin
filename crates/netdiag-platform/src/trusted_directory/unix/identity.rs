use super::DirectoryTrustError;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub(super) fn coordination(metadata: &Metadata) -> [u8; 32] {
    let mut identity = [0_u8; 32];
    identity[..8].copy_from_slice(b"unix-v1\0");
    identity[8..16].copy_from_slice(&metadata.dev().to_le_bytes());
    identity[16..24].copy_from_slice(&metadata.ino().to_le_bytes());
    identity
}

#[cfg(target_os = "macos")]
pub(super) fn resolved_path_from_handle(
    directory: &File,
    reported: PathBuf,
) -> Result<PathBuf, DirectoryTrustError> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = rustix::fs::getpath(directory)
        .map_err(|source| resolved_path_inspection_error(reported, source))?;
    Ok(PathBuf::from(OsString::from_vec(path.into_bytes())))
}

#[cfg(target_os = "macos")]
pub(super) fn resolved_path_inspection_error(
    reported: PathBuf,
    source: impl Into<std::io::Error>,
) -> DirectoryTrustError {
    DirectoryTrustError::Inspect {
        path: reported,
        source: source.into(),
    }
}

#[cfg(not(target_os = "macos"))]
pub(super) fn resolved_path_from_handle(
    _directory: &File,
    reported: PathBuf,
) -> Result<PathBuf, DirectoryTrustError> {
    Ok(reported)
}
