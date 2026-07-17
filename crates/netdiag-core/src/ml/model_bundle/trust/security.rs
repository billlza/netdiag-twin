#[cfg(unix)]
use crate::error::NetdiagError;
use crate::error::Result;
use std::path::Path;

#[cfg(unix)]
pub(super) fn validate(directory: &netdiag_platform::TrustedDirectory, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory
        .as_file()
        .metadata()
        .map_err(|source| NetdiagError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let actual = metadata.mode() & 0o7777;
    if actual != 0o700 {
        return Err(NetdiagError::PrivateDirectoryMode {
            context: "model bundle directory",
            path: path.to_path_buf(),
            expected: 0o700,
            actual,
        });
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn validate(directory: &netdiag_platform::TrustedDirectory, path: &Path) -> Result<()> {
    let _ = path;
    directory
        .validate_coordination_security()
        .map_err(super::trust_error)
}
